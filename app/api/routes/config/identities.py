"""Personas and which two of them attack each other.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form

from app.api.deps import require
from app.api.runtime import state
from app.core.auth import User
from app.core.engagement import (
    delete_persona,
    save_identities,
    save_persona,
)
from .shared import _lines, _parse_kv_lines, config_redirect

logger = logging.getLogger(__name__)


router = APIRouter()


@router.post("/config/personas")
async def save_persona_route(
    name: str = Form(...),
    role: str = Form("user"),
    auth_headers: str = Form(""),
    owns: str = Form(""),
    secret_markers: str = Form(""),
    scoping_headers: str = Form(""),
    user: User = Depends(require("tester")),
):
    name = name.strip()
    # Same character rule as environment names, for the same reason: the name
    # becomes a path segment in its own delete/edit URL, and it is also the
    # identifier generated test cases carry instead of a credential.
    if not name or not all(c.isalnum() or c in "-_." for c in name):
        return config_redirect(
            "personas",
            f"{name or '(blank)'} is not a valid persona name — letters, digits, - _ . only",
        )
    save_persona(
        state.engagement_path,
        name=name,
        auth_headers=_parse_kv_lines(auth_headers, ":"),
        role=role.strip() or "user",
        owns=_parse_kv_lines(owns, "="),
        secret_markers=_lines(secret_markers),
        scoping_headers=_lines(scoping_headers),
    )
    state.reload_engagement()
    return config_redirect("personas", f"Saved persona {name}")


@router.post("/config/personas/{name}/delete")
async def delete_persona_route(name: str, user: User = Depends(require("tester"))):
    delete_persona(state.engagement_path, name)
    state.reload_engagement()
    return config_redirect("personas", f"Removed persona {name}")


@router.post("/config/identities")
async def save_identities_route(
    attacker: str = Form(...), victim: str = Form(...),
    user: User = Depends(require("tester")),
):
    save_identities(state.engagement_path, attacker.strip(), victim.strip())
    state.reload_engagement()
    return config_redirect("personas", f"Attacker {attacker}, victim {victim}")
