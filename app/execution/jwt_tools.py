"""Minimal JWT surgery for authentication attack mutations.

Dependency-free on purpose: this platform runs offline and every dependency in
the execution path is one more thing a reviewer has to trust. We only ever need
to *take a token apart and put it back together differently* — never to verify
one — so the ~40 lines below are the whole requirement.

Nothing here executes or trusts token content; a token is treated as opaque
attacker-supplied bytes that we re-shape into a specific, named probe. If a
persona's credential is not a JWT, the caller raises rather than silently
sending an unmodified request — a mutation that quietly did nothing would show
up downstream as a PASS, which is a false negative.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json


class NotAJwt(ValueError):
    """The credential is not a parseable JWT, so JWT mutations cannot apply."""


def _b64url_decode(part: str) -> bytes:
    # JWT strips '=' padding; put back however many bytes base64 needs.
    padding = "=" * (-len(part) % 4)
    try:
        return base64.urlsafe_b64decode(part + padding)
    except (ValueError, TypeError) as exc:
        raise NotAJwt(f"segment is not valid base64url: {exc}") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def encode_segment(obj: dict) -> str:
    # separators=(",", ":") — no incidental whitespace, so a re-encoded token
    # stays byte-comparable with what a normal issuer would emit.
    return _b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def split(token: str) -> tuple[dict, dict, str]:
    """Return (header, payload, signature_b64). Raises NotAJwt if unparseable."""
    parts = token.split(".")
    if len(parts) != 3:
        raise NotAJwt(f"expected 3 dot-separated segments, got {len(parts)}")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NotAJwt(f"header/payload is not JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise NotAJwt("header and payload must both be JSON objects")
    return header, payload, parts[2]


def assemble(header: dict, payload: dict, signature: str) -> str:
    return f"{encode_segment(header)}.{encode_segment(payload)}.{signature}"


def sign_hs256(header: dict, payload: dict, key: str) -> str:
    """Re-sign with HMAC-SHA256 under `key` — the algorithm-confusion probe.

    A server that reads `alg` from the (attacker-controlled) header and then
    verifies an RS256-issued token as HS256 will use its *public* key, or a
    weak shared secret, as the HMAC key. Signing with a guessable key is how
    you detect that without needing the real key material.
    """
    signing_input = f"{encode_segment(header)}.{encode_segment(payload)}".encode("ascii")
    digest = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{signing_input.decode('ascii')}.{_b64url_encode(digest)}"


def bearer_token(headers: dict[str, str]) -> tuple[str, str]:
    """Find the Authorization header and return (header_name, raw_token).

    Case-insensitive on the header name and tolerant of a missing "Bearer "
    prefix, because personas are configured by hand and a bare token is a
    common way to write one.
    """
    for name, value in headers.items():
        if name.lower() == "authorization":
            token = value.strip()
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            return name, token
    raise NotAJwt("request carries no Authorization header to mutate")
