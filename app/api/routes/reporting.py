"""Reports, exports, the regression diff, and the Jira comment.
"""

from __future__ import annotations

import hashlib
import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, Header
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    Response,
)

from app.api import views
from app.api.deps import require, require_page
from app.api.errors import comment_error
from app.api.jobs import create_operation_job
from app.api.runtime import state
from app.core import i18n
from app.core.auth import User

from app.core.redaction import redact_text
logger = logging.getLogger(__name__)

router = APIRouter()


def _audit_export(aid: str, fmt: str, user: User) -> None:
    """An export leaves the platform carrying captured evidence, so who took a
    copy and when is itself worth recording — the audit log already covers every
    write, and this was the one way data left without a trace.

    Called AFTER the bytes exist. Recording the intent instead would log
    "downloaded pdf" for a request that 404'd or raised, and an audit trail that
    overstates what happened is not usable in the dispute it exists for.
    """
    state.repo.audit("export", aid, actor=user.name, detail=f"downloaded {fmt}")


@router.get("/assessment/{aid}/report", response_class=HTMLResponse)
async def report(aid: str, user: User = Depends(require_page())) -> str:
    return state.orch.build_report_html(aid, lang=i18n.get_lang())


@router.get("/assessment/{aid}/export.html")
async def export_html(aid: str, user: User = Depends(require_page())):
    # Exported/downloaded copy: freeze it in whichever language the operator
    # was viewing, same as the live report at the moment they clicked export.
    html = state.orch.build_report_html(aid, lang=i18n.get_lang())
    _audit_export(aid, "html", user)
    return Response(html, media_type="text/html",
                    headers={"Content-Disposition": f"attachment; filename={aid}.html"})


@router.get("/assessment/{aid}/export.json")
async def export_json(aid: str, user: User = Depends(require_page())):
    from fastapi.responses import Response

    payload = state.orch.export_json(aid)
    _audit_export(aid, "json", user)
    return Response(payload, media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={aid}.json"})


@router.get("/assessment/{aid}/export.xlsx")
async def export_xlsx(aid: str, user: User = Depends(require_page())):
    payload = state.orch.export_xlsx(aid)
    _audit_export(aid, "xlsx", user)
    return Response(
        payload,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={aid}.xlsx"},
    )


@router.get("/assessment/{aid}/export.pdf")
async def export_pdf(aid: str, user: User = Depends(require_page())):
    payload = state.orch.export_pdf(aid)
    _audit_export(aid, "pdf", user)
    return Response(payload, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={aid}.pdf"})


@router.get("/assessment/{aid}/export.postman")
async def export_postman(aid: str, user: User = Depends(require_page())):
    payload = state.orch.export_postman(aid)
    _audit_export(aid, "postman", user)
    return Response(payload, media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={aid}.postman_collection.json"})


@router.get("/assessment/{aid}/regression", response_class=HTMLResponse)
async def regression(aid: str, flash: str = "",
                     user: User = Depends(require_page())) -> str:
    from app.pipeline.history import render_diff_comment

    a = state.orch.require_assessment(aid)
    diff, prev_id = state.orch.regression_diff(aid)
    # A re-run lands here rather than on the assessment page: "what changed since
    # last time" is the question it was started to answer.
    return views.regression_page(aid, a.issue_key, prev_id, diff,
                                 render_diff_comment(a.issue_key, diff), flash=flash)


@router.get("/assessment/{aid}/comment", response_class=HTMLResponse)
async def comment_preview(aid: str, user: User = Depends(require_page())) -> str:
    a = state.orch.require_assessment(aid)
    return views.comment_preview_page(aid, a.issue_key, state.orch.comment_preview(aid))


@router.post("/assessment/{aid}/comment")
async def comment_post(aid: str, user: User = Depends(require("tester")),
                       idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    a = state.orch.require_assessment(aid)
    preview = state.orch.comment_preview(aid)
    stable_key = idempotency_key or hashlib.sha256(preview.encode("utf-8")).hexdigest()
    job, created = create_operation_job(aid, "jira_comment", stable_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Jira comment job {job.job_id}: {job.state}')}",
            status_code=303,
        )
    state.repo.transition_job(job.job_id, "RUNNING")
    try:
        await state.orch.post_comment(aid, actor=user.name)
    except Exception as exc:
        state.repo.transition_job(
            job.job_id, "FAILED", error=redact_text(f"{type(exc).__name__}: {exc}")[:2000]
        )
        headline, hint = comment_error(a.issue_key if a else aid, exc)
        return HTMLResponse(
            views.error_page("Posting to Jira failed", headline, hint,
                             back_href=f"/assessment/{aid}", back_label="← Back to assessment"),
            status_code=400,
        )
    state.repo.transition_job(job.job_id, "SUCCEEDED", result={"posted": True})
    target = f"/assessment/{aid}?flash=Posted+to+Jira"
    # Only the live client can resolve a real browse URL (JIRA_SITE_URL
    # configured) — the offline mock has no site to link to, so this is
    # absent for it and the assessment page just shows the flash text alone.
    url = state.jira.browse_url(a.issue_key) if a else None
    if url:
        target += f"&ticket_url={quote(url, safe='')}"
    return RedirectResponse(target, status_code=303)
