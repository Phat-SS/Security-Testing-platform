"""Lightweight multi-user auth (API keys + roles).

Framework-agnostic core: loads users from a JSON file, authenticates an API key,
and ranks roles. The FastAPI layer turns this into route dependencies.

Design choices that keep it safe:
  * Only a SHA-256 hash of each API key is stored — never the key itself, and
    no passwords are collected or stored anywhere.
  * Constant-time comparison on the hash.
  * Auth is OFF unless AUTH_ENABLED=true, so the local demo stays open; when off,
    every request is treated as a built-in admin (single-user mode).

Generate a user + key:
    python -m app.core.auth add alice tester
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

_ROLE_RANK = {"viewer": 1, "tester": 2, "admin": 3}


@dataclass(frozen=True)
class User:
    name: str
    role: str

    def can(self, min_role: str) -> bool:
        return _ROLE_RANK.get(self.role, 0) >= _ROLE_RANK.get(min_role, 99)


_SINGLE_USER = User(name="local-admin", role="admin")


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class AuthManager:
    def __init__(self, config_path: str | None = None) -> None:
        self._enabled = os.getenv("AUTH_ENABLED", "false").lower() == "true"
        path = config_path or os.getenv("AUTH_USERS_CONFIG", "config/users.json")
        self._by_hash: dict[str, User] = {}
        self._sessions: dict[str, tuple[User, float]] = {}
        #: Recent failures per source address, for the lockout below.
        self._failures: dict[str, list[float]] = {}
        self._session_lock = threading.RLock()
        self._session_ttl_s = max(300, int(os.getenv("AUTH_SESSION_TTL_S", "43200")))
        if self._enabled and Path(path).exists():
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for u in data.get("users", []):
                self._by_hash[u["api_key_sha256"]] = User(u["name"], u.get("role", "viewer"))

    @property
    def enabled(self) -> bool:
        return self._enabled

    #: How many failures from one source before it is asked to wait, and for how
    #: long. Not a defence against a distributed attacker — a 24-byte key is not
    #: guessable and this is not pretending otherwise. It is here so that a
    #: sustained attempt is slow, bounded, and above all *visible*: a login that
    #: failed silently and cost nothing to repeat left no trace that anyone had
    #: ever tried.
    MAX_FAILURES = 10
    LOCKOUT_S = 60

    def note_failure(self, source: str) -> None:
        """Record a rejected sign-in and log it."""
        now = time.time()
        with self._session_lock:
            failures = [t for t in self._failures.get(source, []) if now - t < self.LOCKOUT_S]
            failures.append(now)
            self._failures[source] = failures
            count = len(failures)
        # WARNING, not INFO: this is the line an operator greps for, and the
        # only signal that anyone is trying keys at all.
        _log.warning("failed sign-in attempt (%d in the last %ds) from %s",
                     count, self.LOCKOUT_S, source or "an unknown source")

    def note_success(self, source: str) -> None:
        with self._session_lock:
            self._failures.pop(source, None)

    def locked_out(self, source: str) -> float:
        """Seconds this source should wait, or 0. Counts only recent failures,
        so a lockout always expires on its own."""
        now = time.time()
        with self._session_lock:
            failures = [t for t in self._failures.get(source, []) if now - t < self.LOCKOUT_S]
            self._failures[source] = failures
        if len(failures) < self.MAX_FAILURES:
            return 0.0
        return max(0.0, self.LOCKOUT_S - (now - failures[0]))

    def authenticate(self, api_key: str | None) -> User | None:
        """Return the User for a key, or None. In disabled mode, always the
        built-in admin (single-user)."""
        if not self._enabled:
            return _SINGLE_USER
        if not api_key:
            return None
        candidate = hash_key(api_key)
        for stored, user in self._by_hash.items():
            if hmac.compare_digest(stored, candidate):
                return user
        return None

    def issue_session(self, user: User) -> str:
        """Mint an opaque browser token; the API key never enters a cookie."""
        self._evict_expired()
        token = secrets.token_urlsafe(32)
        with self._session_lock:
            self._sessions[hash_key(token)] = (user, time.time() + self._session_ttl_s)
        return token

    def _evict_expired(self) -> None:
        """Drop sessions nobody will present again.

        Expiry was only ever noticed when a token was looked up, so a process
        that ran for months accumulated one entry per login and never released
        one. Called on issue, which is the only moment the map grows.
        """
        now = time.time()
        with self._session_lock:
            for digest in [d for d, (_u, exp) in self._sessions.items() if exp <= now]:
                self._sessions.pop(digest, None)

    def authenticate_session(self, token: str | None) -> User | None:
        if not self._enabled:
            return _SINGLE_USER
        if not token:
            return None
        digest = hash_key(token)
        now = time.time()
        with self._session_lock:
            session = self._sessions.get(digest)
            if session is None:
                return None
            user, expires_at = session
            if expires_at <= now:
                self._sessions.pop(digest, None)
                return None
            return user

    def revoke_session(self, token: str | None) -> None:
        if token:
            with self._session_lock:
                self._sessions.pop(hash_key(token), None)

    @property
    def session_ttl_s(self) -> int:
        return self._session_ttl_s


def _cli() -> None:  # pragma: no cover - dev utility
    import sys

    if len(sys.argv) != 4 or sys.argv[1] != "add":
        print("usage: python -m app.core.auth add <name> <viewer|tester|admin>")
        raise SystemExit(1)
    name, role = sys.argv[2], sys.argv[3]
    key = secrets.token_urlsafe(24)
    entry = {"name": name, "role": role, "api_key_sha256": hash_key(key)}
    print("Add this to config/users.json under \"users\":")
    print(json.dumps(entry, indent=2))
    print(f"\nAPI key (store securely, shown once): {key}")


if __name__ == "__main__":  # pragma: no cover
    _cli()
