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
from dataclasses import dataclass
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
    return Engagement(
        target_base_url=data.get("target_base_url", ""),
        scope=ScopeValidator(policy),
        vault=PersonaVault(personas),
        attacker=data.get("attacker", "agent_A"),
        victim=data.get("victim", "agent_B"),
    )
