"""Privacy-preserving correlation between owner and attacker responses."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass

_GENERIC = {
    "true", "false", "null", "none", "ok", "success", "error", "active",
    "inactive", "pending", "admin", "user", "customer", "unknown",
}
_IDENTITY_KEYS = (
    "id", "name", "email", "phone", "address", "account", "customer",
    "owner", "tenant", "user", "profile", "subject", "member", "ssn",
)
_VOLATILE_KEYS = ("requestid", "traceid", "correlationid", "timestamp", "version", "status")


@dataclass(frozen=True)
class CorrelationMeasurement:
    shared_fingerprints: tuple[str, ...]
    owner_value_count: int
    coverage: float
    key_id: str

    @property
    def decisive(self) -> bool:
        return len(self.shared_fingerprints) >= 3 and self.coverage >= 0.75


def correlate_bodies(owner_body: str, attack_body: str) -> CorrelationMeasurement | None:
    """HMAC scalar leaves; raw values never leave this call.

    No key means no automatic conclusion. This fails toward INCONCLUSIVE rather
    than writing unsalted hashes of emails/object ids that are easy to reverse.
    """
    secret = os.getenv("EVIDENCE_FINGERPRINT_KEY", "").encode("utf-8")
    if len(secret) < 16:
        return None
    owner = _values(owner_body)
    attacker = _values(attack_body)
    if not owner or not attacker:
        return None
    owner_fp = {_fingerprint(secret, value) for value in owner}
    attacker_fp = {_fingerprint(secret, value) for value in attacker}
    shared = tuple(sorted(owner_fp & attacker_fp))
    return CorrelationMeasurement(
        shared_fingerprints=shared,
        owner_value_count=len(owner_fp),
        coverage=round(len(shared) / len(owner_fp), 3),
        key_id=hashlib.sha256(secret).hexdigest()[:12],
    )


def _fingerprint(secret: bytes, value: str) -> str:
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _values(raw: str) -> set[str]:
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return set()
    values: set[str] = set()

    def walk(node, depth: int = 0, path: str = "") -> None:
        if depth > 8 or len(values) >= 400:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, depth + 1, f"{path}.{key}" if path else str(key))
        elif isinstance(node, list):
            for value in node[:200]:
                walk(value, depth + 1, path)
        elif isinstance(node, str):
            value = node.strip()
            if _identity_path(path) and len(value) >= 6 and value.lower() not in _GENERIC:
                values.add(value)
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            if _identity_path(path) and abs(node) >= 1000:
                values.add(str(node))

    walk(payload)
    return values


def _identity_path(path: str) -> bool:
    segments = [
        "".join(char for char in segment.lower() if char.isalnum())
        for segment in path.split(".")
    ]
    normalized = "".join(segments)
    return (
        ("id" in segments or any(key in normalized for key in _IDENTITY_KEYS if key != "id"))
        and not any(key in normalized for key in _VOLATILE_KEYS)
    )
