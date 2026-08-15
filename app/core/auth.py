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
from dataclasses import dataclass
from pathlib import Path

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
        if self._enabled and Path(path).exists():
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for u in data.get("users", []):
                self._by_hash[u["api_key_sha256"]] = User(u["name"], u.get("role", "viewer"))

    @property
    def enabled(self) -> bool:
        return self._enabled

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
