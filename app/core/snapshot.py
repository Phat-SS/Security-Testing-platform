"""The authorization context a run actually used, frozen and hashed.

The engagement file is the artifact that says what was authorized. The platform
read it live, at the moment someone pressed Run, and then never recorded what it
had read — so a report said *that* a host was tested and never *that the host
was authorized when it was tested*. Editing the scope five minutes later changed
what every earlier run meant, silently and retroactively.

A snapshot closes that. It is taken once per run, stored with the run, and its
hash goes into each execution — so the evidence chain that already proves "this
request and this response were not edited afterwards" now also proves "and this
is the authorization it was sent under".

**Secrets are never in here.** A persona's `auth_headers` hold resolved bearer
tokens; this records the header NAMES and the `${VAR}` references the config
declared, never a value. The snapshot is meant to be attached to a ticket and
read by people who are not entitled to the credentials.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Bumped when the captured shape changes. Stored alongside the snapshot so a
#: hash that no longer verifies can be told apart from one taken by an older
#: version — "the record was tampered with" and "the format moved on" are
#: different conclusions and must not look alike.
SNAPSHOT_VERSION = 1


def _persona_facts(persona) -> dict[str, Any]:
    """What a reader needs to judge a persona, minus anything they must not see.

    `owns` is included: it is not a secret (it is which objects this identity
    legitimately holds) and it is the whole basis of a BOLA verdict — "A read
    B's record" means nothing without knowing which records were B's.
    """
    return {
        "name": persona.name,
        "role": persona.role,
        # Names only. The values are live credentials.
        "auth_header_names": sorted(persona.auth_headers or {}),
        "owns": dict(sorted((persona.owns or {}).items())),
        # A variable the environment did not supply withholds its header, which
        # changes what the request was — so which ones were missing is part of
        # what the run means.
        "missing_env": sorted(persona.missing_env or ()),
    }


def capture(engagement, *, base_url: str, environment: str, settings=None) -> dict[str, Any]:
    """Freeze the authorization context for a run about to start."""
    policy = engagement.scope.policy
    personas = [_persona_facts(p) for p in engagement.vault.all()]
    limits = {}
    if settings is not None:
        limits = {
            "timeout_s": settings.limits.timeout_s,
            "max_response_bytes": settings.limits.max_response_bytes,
            "max_requests_per_test": settings.limits.max_requests_per_test,
        }
    return {
        "version": SNAPSHOT_VERSION,
        "environment": environment,
        "base_url": base_url,
        "scope": {
            "allowed_hosts": sorted(policy.allowed_hosts),
            "blocked_hosts": sorted(policy.blocked_hosts),
            "allow_private_ranges": bool(policy.allow_private_ranges),
        },
        "attacker": engagement.attacker,
        "victim": engagement.victim,
        "personas": sorted(personas, key=lambda p: p["name"]),
        "limits": limits,
    }


def fingerprint(snapshot: dict[str, Any]) -> str:
    """The snapshot's identity.

    `sort_keys` and no whitespace: two captures of the same configuration must
    fingerprint identically whatever order the underlying dicts happened to
    iterate in, or every run would look like a configuration change.
    """
    payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def describe(snapshot: dict[str, Any]) -> str:
    """One line for a report or an audit row."""
    if not snapshot:
        return "no authorization context recorded"
    scope = snapshot.get("scope") or {}
    hosts = scope.get("allowed_hosts") or []
    return (
        f"{snapshot.get('environment') or '(unnamed)'} "
        f"({snapshot.get('base_url') or 'no target'}) · "
        f"{len(hosts)} approved host(s) · "
        f"{snapshot.get('attacker')} attacks {snapshot.get('victim')}"
    )


def differences(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """What changed between two runs' authorization, in a reader's terms.

    Used by the regression view: a finding that appeared between two runs means
    something different if the scope or the identities moved underneath them.
    """
    if not before or not after:
        return []
    out: list[str] = []
    if before.get("base_url") != after.get("base_url"):
        out.append(f"target {before.get('base_url')} → {after.get('base_url')}")
    for role in ("attacker", "victim"):
        if before.get(role) != after.get(role):
            out.append(f"{role} {before.get(role)} → {after.get(role)}")
    b_scope, a_scope = before.get("scope") or {}, after.get("scope") or {}
    for key in ("allowed_hosts", "blocked_hosts"):
        added = sorted(set(a_scope.get(key) or []) - set(b_scope.get(key) or []))
        removed = sorted(set(b_scope.get(key) or []) - set(a_scope.get(key) or []))
        if added:
            out.append(f"{key}: +{', '.join(added)}")
        if removed:
            out.append(f"{key}: -{', '.join(removed)}")
    if b_scope.get("allow_private_ranges") != a_scope.get("allow_private_ranges"):
        out.append(f"allow_private_ranges → {a_scope.get('allow_private_ranges')}")
    b_names = {p["name"] for p in before.get("personas") or []}
    a_names = {p["name"] for p in after.get("personas") or []}
    if b_names != a_names:
        out.append(f"personas {sorted(b_names)} → {sorted(a_names)}")
    return out
