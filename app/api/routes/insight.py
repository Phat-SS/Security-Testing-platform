"""The two cross-assessment screens: what was found, and what was done.

Both scoped to the current engagement — a findings list mixing two clients'
results would be worse than not having one.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from app.api import views
from app.api.deps import require_page
from app.api.runtime import state
from app.core.auth import User

router = APIRouter()


@router.get("/findings", response_class=HTMLResponse)
async def findings(q: str = "", sev: str = "", fp: str = "",
                   user: User = Depends(require_page())) -> str:
    current = state.engagements.current_name
    return views.findings_page(
        state.repo.findings_across(current), engagement=current,
        triage=state.repo.get_finding_triage_across(current),
        q=q, sev=sev, show_fp=bool(fp),
    )


@router.get("/activity", response_class=HTMLResponse)
async def activity(user: User = Depends(require_page())) -> str:
    current = state.engagements.current_name
    return views.activity_page(state.repo.recent_activity(current), engagement=current)
