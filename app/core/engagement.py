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
from dataclasses import dataclass, field
from pathlib import Path

from app.core.scope import ScopePolicy, ScopeValidator
from app.vault.personas import Persona, PersonaVault


@dataclass
class Engagement:
    target_base_url: str
    scope: ScopeValidator
    vault: PersonaVault
    attacker: str
    victim: str
    environments: dict[str, str] = field(default_factory=dict)
    active_environment: str = ""


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
    personas = [
        Persona(
            name=p["name"],
            auth_headers=p.get("auth_headers", {}),
            role=p.get("role", "user"),
            owns=p.get("owns", {}),
            secret_markers=p.get("secret_markers", []),
        )
        for p in data.get("personas", [])
    ]

    # Named environments: multiple target URLs, one shared scope/persona set (an
    # environment is just "which host", not a separate authorization context).
    # A legacy config with only `target_base_url` becomes a single "default"
    # environment, so old configs keep working with zero migration.
    legacy_url = data.get("target_base_url", "")
    environments = dict(data.get("environments") or {})
    if legacy_url and "default" not in environments:
        environments = {"default": legacy_url, **environments}
    active_environment = data.get("active_environment") or next(iter(environments), "")

    return Engagement(
        target_base_url=environments.get(active_environment, legacy_url),
        scope=ScopeValidator(policy),
        vault=PersonaVault(personas),
        attacker=data.get("attacker", "agent_A"),
        victim=data.get("victim", "agent_B"),
        environments=environments,
        active_environment=active_environment,
    )


def save_environment(path: str, name: str, url: str, make_active: bool = False) -> None:
    """Add or update a named environment in the engagement config, preserving
    every other key (scope, personas, attacker, victim, ...) untouched."""
    data = json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {}
    environments = dict(data.get("environments") or {})
    environments[name] = url
    data["environments"] = environments
    if make_active or not data.get("active_environment"):
        data["active_environment"] = name
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def delete_environment(path: str, name: str) -> None:
    """Remove a named environment. A no-op if the file or the name doesn't exist."""
    if not Path(path).exists():
        return
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    environments = dict(data.get("environments") or {})
    environments.pop(name, None)
    data["environments"] = environments
    if data.get("active_environment") == name:
        data["active_environment"] = next(iter(environments), "")
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
