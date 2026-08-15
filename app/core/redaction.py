"""Secret redaction.

Runs before ANYTHING is logged, stored, put in evidence, rendered into a
report, or posted to Jira. A security report that leaks the bearer token it
used is itself an incident. Fail closed: when in doubt, redact.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "********"

# Header names whose value is always a secret, matched case-insensitively.
_SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-amz-security-token",
}

# Body/text patterns: match "<key> <sep> <value>" and mask the value only.
_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "token",
    "authorization",
    "private_key",
    "session",
)

# key : "value"  |  key = value  |  key: value   (JSON, form, kv)
_KV_PATTERN = re.compile(
    r'(?i)("?(?:' + "|".join(_SENSITIVE_KEYS) + r')"?\s*[:=]\s*)("?)([^"\s,&}]+)(\2)'
)

# Bearer / Basic tokens appearing inline anywhere.
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]+")

# JWT-shaped triplets (header.payload.signature).
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def redact_text(text: str | None) -> str | None:
    if text is None:
        return None
    out = _KV_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", text)
    out = _BEARER_PATTERN.sub(lambda m: f"{m.group(1)} {MASK}", out)
    out = _JWT_PATTERN.sub(MASK, out)
    return out


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SECRET_HEADERS:
            redacted[key] = MASK
        else:
            redacted[key] = redact_text(value) or ""
    return redacted


def redact_any(value: Any) -> Any:
    """Deep-redact an arbitrary JSON-ish structure (dict/list/str)."""
    if isinstance(value, dict):
        return {
            k: (MASK if any(s in k.lower() for s in _SENSITIVE_KEYS) else redact_any(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_any(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
