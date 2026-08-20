"""Engagement configuration loader.

An "engagement" is the authorized testing context: the approved target, the
scope allow/block lists, and the persona credentials. It is loaded from a JSON
file (never hardcoded, never from a ticket) so authorization is an explicit,
reviewable artifact. Default-deny: an empty/absent config means nothing is in
scope and no persona exists, so no test can run until a human configures it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.scope import ScopePolicy, ScopeValidator
from app.vault.personas import Persona, PersonaVault

# ${VAR} references inside a persona's auth-header values. The engagement file
# is a reviewable authorization artifact that a tester reads, diffs and pastes
# into a ticket; a live bearer token is the one thing in it that must not be
# any of those. So the file holds the *reference* and the value stays in .env,
# where the rest of the platform's secrets already live.
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def resolve_env_refs(value: str) -> tuple[str, tuple[str, ...]]:
    """Substitute ${VAR} from the process environment.

    Returns the resolved string plus the names of variables that were unset or
    empty — names only. The values must never reach a log, a report or a
    readiness detail, which is the whole reason they are not in the file.
    """
    missing: list[str] = []

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        found = os.environ.get(name)
        if not found:
            missing.append(name)
            return match.group(0)
        return found

    resolved = _ENV_REF.sub(_sub, value)
    return resolved, tuple(dict.fromkeys(missing))


def _persona_from_config(p: dict) -> Persona:
    """One persona, with its auth headers resolved against the environment.

    An unresolved reference fails closed in both available directions at once,
    because each on its own is a worse outcome than a blocked run:

    * Sending the literal ``Bearer ${VAR}`` would put a credential that cannot
      authenticate on the wire. The target answers 401, and a 401 is a *result*
      here — it reads as "the endpoint requires auth", so the run would report
      a security property of the misconfiguration rather than of the target.
    * Dropping the header silently would turn every authorization test into an
      unauthenticated one. A BOLA case is "identity A reaches B's object"; with
      no identity it becomes "anonymous reaches B's object" and a PASS would
      mean nothing it appears to mean.

    So the header is withheld *and* the variable name is recorded, letting the
    readiness panel block the run and say which variable to set.
    """
    headers: dict[str, str] = {}
    missing: list[str] = []
    for name, raw in (p.get("auth_headers") or {}).items():
        resolved, unset = resolve_env_refs(str(raw))
        if unset:
            missing.extend(unset)
            continue
        headers[name] = resolved
    return Persona(
        name=p["name"],
        auth_headers=headers,
        role=p.get("role", "user"),
        owns=p.get("owns", {}),
        secret_markers=p.get("secret_markers", []),
        missing_env=tuple(dict.fromkeys(missing)),
        scoping_headers=tuple(p.get("scoping_headers", [])),
    )


@dataclass
class Engagement:
    target_base_url: str
    scope: ScopeValidator
    vault: PersonaVault
    attacker: str
    victim: str
    environments: dict[str, str] = field(default_factory=dict)
    active_environment: str = ""
    # Raw runner-limit overrides from the config file (see RUNNER_KEYS). Empty
    # means "use the env-var defaults" — the Config UI writes here so a tester
    # can tune a run without editing .env and restarting.
    runner: dict[str, float] = field(default_factory=dict)
    # The raw config dict, so the Config UI can render exactly what is on disk
    # (personas included) without re-reading the file itself.
    raw: dict = field(default_factory=dict)


def load_engagement(path: str | None = None) -> Engagement:
    path = path or os.getenv("ENGAGEMENT_CONFIG", "")
    if not path or not Path(path).exists():
        # Safe empty engagement: no scope, no personas → nothing can run.
        return Engagement(
            target_base_url="",
            scope=ScopeValidator(ScopePolicy()),
            vault=PersonaVault([]),
            attacker="agent_A",
            victim="agent_B",
        )

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    scope_cfg = data.get("scope", {})
    policy = ScopePolicy(
        allowed_hosts=set(scope_cfg.get("allowed_hosts", [])),
        blocked_hosts=set(scope_cfg.get("blocked_hosts", [])),
        allow_private_ranges=bool(scope_cfg.get("allow_private_ranges", False)),
    )
    personas = [_persona_from_config(p) for p in data.get("personas", [])]


    # Named environments: multiple target URLs, one shared scope/persona set (an
    # environment is just "which host", not a separate authorization context).
    # A legacy config with only `target_base_url` becomes a single "default"
    # environment, so old configs keep working with zero migration.
    legacy_url = data.get("target_base_url", "")
    environments = materialize_environments(data)
    active_environment = data.get("active_environment") or next(iter(environments), "")

    return Engagement(
        target_base_url=environments.get(active_environment, legacy_url),
        scope=ScopeValidator(policy),
        vault=PersonaVault(personas),
        attacker=data.get("attacker", "agent_A"),
        victim=data.get("victim", "agent_B"),
        environments=environments,
        active_environment=active_environment,
        runner={k: v for k, v in (data.get("runner") or {}).items() if k in RUNNER_KEYS},
        raw=data,
    )


# -- raw config read/write --------------------------------------------------
#
# The Config UI edits the same JSON file `load_engagement` reads. Every writer
# below follows one rule: read the whole document, change only the keys it owns,
# write it back. Nothing else in the file is ever dropped, so an unknown future
# key, a hand-written `_comment`, or a section this UI does not expose all
# survive a save made through the browser.

# Runner limits a tester may override per engagement. Anything not listed here
# stays env-only on purpose (e.g. the user agent, which is an attribution
# string rather than a knob).
RUNNER_KEYS = (
    "timeout_s",
    "max_response_bytes",
    "max_requests_per_test",
)


def read_config(path: str) -> dict:
    """The raw engagement document, or {} when the file does not exist yet."""
    if not path or not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_config(path: str, data: dict) -> None:
    """Write the document back, creating the parent directory if needed."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def materialize_environments(data: dict) -> dict[str, str]:
    """The environment map as the rest of the platform sees it, with a legacy
    bare `target_base_url` surfaced as a synthetic "default" entry.

    Both the loader and every writer go through this, which is what makes the
    synthetic entry deletable: a writer that only popped from the stored
    `environments` map would leave `target_base_url` behind, and the very next
    load would resurrect "default" — the delete would silently undo itself.

    The URL is only synthesised into an entry when no stored environment
    already points at it. `_sync_legacy_target` keeps the key mirroring the
    active environment for the CLI and older configs that still read it, so
    without that condition deleting "default" would just rename the surviving
    environment's URL back into a fresh "default" row.
    """
    environments = dict(data.get("environments") or {})
    legacy_url = data.get("target_base_url", "")
    if legacy_url and "default" not in environments and legacy_url not in environments.values():
        environments = {"default": legacy_url, **environments}
    return environments


def _sync_legacy_target(data: dict, environments: dict[str, str]) -> None:
    """Keep the legacy `target_base_url` key pointing at the active environment.

    It is still the loader's fallback and what older configs, the CLI and
    exported reports read, so leaving it stale would mean the file disagrees
    with the UI. When the last environment is deleted it is removed outright —
    otherwise it would immediately come back as a "default" environment.
    """
    active = data.get("active_environment") or ""
    if active and active in environments:
        data["target_base_url"] = environments[active]
    elif environments:
        data["target_base_url"] = next(iter(environments.values()))
    else:
        data.pop("target_base_url", None)


def save_environment(path: str, name: str, url: str, make_active: bool = False) -> None:
    """Add or update a named environment in the engagement config, preserving
    every other key (scope, personas, attacker, victim, ...) untouched."""
    data = read_config(path)
    environments = materialize_environments(data)
    environments[name] = url
    data["environments"] = environments
    if make_active or not data.get("active_environment"):
        data["active_environment"] = name
    _sync_legacy_target(data, environments)
    write_config(path, data)


def delete_environment(path: str, name: str) -> None:
    """Remove a named environment. A no-op if the file or the name doesn't exist."""
    if not Path(path).exists():
        return
    data = read_config(path)
    environments = materialize_environments(data)
    environments.pop(name, None)
    data["environments"] = environments
    if data.get("active_environment") not in environments:
        data["active_environment"] = next(iter(environments), "")
    _sync_legacy_target(data, environments)
    write_config(path, data)


def set_active_environment(path: str, name: str) -> None:
    """Point the engagement at an existing environment. An unknown name is
    ignored rather than written, so a stale form post cannot aim the platform
    at an environment that no longer exists."""
    data = read_config(path)
    environments = materialize_environments(data)
    if name not in environments:
        return
    data["environments"] = environments
    data["active_environment"] = name
    _sync_legacy_target(data, environments)
    write_config(path, data)


def save_scope(
    path: str,
    allowed_hosts: list[str],
    blocked_hosts: list[str],
    allow_private_ranges: bool,
) -> None:
    """Replace the scope block. This is the authorization boundary, so it is
    written verbatim from what the human submitted — merging with the previous
    value would make *removing* a host from the allow-list impossible through
    the UI, which is the wrong direction for a control like this to fail in."""
    data = read_config(path)
    data["scope"] = {
        "allowed_hosts": _dedupe(allowed_hosts),
        "blocked_hosts": _dedupe(blocked_hosts),
        "allow_private_ranges": bool(allow_private_ranges),
    }
    write_config(path, data)


def allow_host(path: str, host: str) -> None:
    """Add one host to `scope.allowed_hosts`, leaving the rest of the scope
    alone. Backs the one-click fix on the readiness panel: by far the most
    common reason an entire run comes back BLOCKED is the target's host never
    having been added here."""
    host = host.strip().lower()
    if not host:
        return
    data = read_config(path)
    scope = dict(data.get("scope") or {})
    allowed = list(scope.get("allowed_hosts") or [])
    if host not in allowed:
        allowed.append(host)
    scope["allowed_hosts"] = allowed
    scope.setdefault("blocked_hosts", [])
    scope.setdefault("allow_private_ranges", False)
    data["scope"] = scope
    write_config(path, data)


def save_persona(
    path: str,
    name: str,
    auth_headers: dict[str, str],
    role: str = "user",
    owns: dict[str, str] | None = None,
    secret_markers: list[str] | None = None,
    scoping_headers: list[str] | None = None,
) -> None:
    """Add or replace one persona by name, keeping the order of the others."""
    data = read_config(path)
    personas = list(data.get("personas") or [])
    entry = {
        "name": name,
        "auth_headers": auth_headers,
        "role": role,
        "owns": owns or {},
        "secret_markers": secret_markers or [],
        "scoping_headers": scoping_headers or [],
    }
    for i, p in enumerate(personas):
        if p.get("name") == name:
            personas[i] = entry
            break
    else:
        personas.append(entry)
    data["personas"] = personas
    write_config(path, data)


def delete_persona(path: str, name: str) -> None:
    """Remove a persona. The attacker/victim pointers are deliberately left
    alone: silently repointing them at some other identity would change what
    every generated test actually attacks. The readiness panel surfaces the
    dangling reference instead, so a human picks the replacement."""
    data = read_config(path)
    data["personas"] = [p for p in (data.get("personas") or []) if p.get("name") != name]
    write_config(path, data)


def save_identities(path: str, attacker: str, victim: str) -> None:
    """Set which personas play attacker and victim in generated BOLA tests."""
    data = read_config(path)
    data["attacker"] = attacker
    data["victim"] = victim
    write_config(path, data)


def save_runner_limits(path: str, limits: dict[str, float]) -> None:
    """Persist per-engagement runner-limit overrides. An omitted value means
    "fall back to the env var", so clearing a field in the UI restores the
    .env default rather than writing a zero."""
    data = read_config(path)
    kept = {k: v for k, v in limits.items() if k in RUNNER_KEYS and v is not None}
    if kept:
        data["runner"] = kept
    else:
        data.pop("runner", None)
    write_config(path, data)


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving dedupe of trimmed, lowercased hostnames. Scope matching
    is case-insensitive (ScopeValidator lowercases the host before comparing),
    so storing two casings of one host would be two rows saying the same thing.
    """
    seen: list[str] = []
    for v in values:
        v = v.strip().lower()
        if v and v not in seen:
            seen.append(v)
    return seen
