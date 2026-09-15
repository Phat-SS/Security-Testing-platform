"""Reading the configuration: the page itself and the readiness verdict.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import (
    HTMLResponse,
)

from app.api.deps import require, require_page
from app.api.runtime import state
from app.core import preflight
from app.core.auth import User
from .shared import render_config

logger = logging.getLogger(__name__)


router = APIRouter()


@router.get("/config", response_class=HTMLResponse)
async def config_page(tab: str = "readiness", flash: str = "", error: str = "",
                      user: User = Depends(require_page())) -> str:
    return render_config(tab=tab, flash=flash, error=error)


@router.get("/config/environments", response_class=HTMLResponse)
async def environments_page(flash: str = "",
                            user: User = Depends(require_page())) -> str:
    # Kept as its own URL (it predates the unified page and is linked from
    # older reports/bookmarks); it just opens the config page on that pane.
    return render_config(tab="environments", flash=flash)


@router.get("/api/readiness")
async def api_readiness(user: User = Depends(require("viewer"))):
    """The pre-run checklist as JSON, so a CI job can refuse to start a run for
    the same reasons the UI would have shown a human."""
    r = preflight.evaluate(state.engagement, state.engagement_path)
    return {
        "can_run": r.can_run,
        "state": r.state,
        "checks": [
            {"key": c.key, "label": c.label, "state": c.state, "detail": c.detail}
            for c in r.checks
        ],
        "environments": [
            {"name": e.name, "url": e.url, "host": e.host, "active": e.is_active,
             "allowed": e.state == preflight.OK, "reason": e.reason}
            for e in r.environments
        ],
    }
