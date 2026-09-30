"""The authorization boundary: which hosts may be tested at all.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form

from app.api.deps import require
from app.api.runtime import state
from app.core.auth import User
from app.core.engagement import (
    allow_host,
    save_scope,
)
from .shared import _lines, config_redirect

logger = logging.getLogger(__name__)


router = APIRouter()


@router.post("/config/scope")
async def save_scope_route(
    allowed_hosts: str = Form(""),
    blocked_hosts: str = Form(""),
    allow_private_ranges: bool = Form(False),
    allowed_ports: str = Form(""),
    user: User = Depends(require("admin")),
):
    # The authorization boundary: admin-only and audited, because widening it
    # (or flipping allow_private_ranges) is what turns the runner into a weapon.
    ports = [int(p) for p in _lines(allowed_ports.replace(",", "\n")) if p.isdigit()]
    save_scope(state.engagement_path, _lines(allowed_hosts), _lines(blocked_hosts),
               allow_private_ranges, ports)
    state.repo.audit(
        "scope_change", actor=user.name,
        detail=f"allowed={_lines(allowed_hosts)} blocked={_lines(blocked_hosts)} "
               f"private={bool(allow_private_ranges)} ports={ports}")
    state.reload_engagement()
    return config_redirect("scope", "Scope saved")


@router.post("/config/scope/allow-host")
async def allow_host_route(host: str = Form(...), user: User = Depends(require("admin"))):
    allow_host(state.engagement_path, host)
    state.repo.audit("scope_allow_host", actor=user.name, detail=host.strip().lower())
    state.reload_engagement()
    return config_redirect("readiness", f"{host} added to the approved scope")
