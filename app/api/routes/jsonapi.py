"""The JSON API for automation.

Separate from the HTML routes because the failure modes differ: a script wants a
status code it can branch on, not a redirect to a login form.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import (
    JSONResponse,
)

from app.api.deps import optional_user, require
from app.api.runtime import state
from app.core.auth import User
from app.mcp import MockJiraMCPClient, available_issue_keys, describe_jira_client

logger = logging.getLogger(__name__)

router = APIRouter()


# -- JSON API (automation) --------------------------------------------------


@router.get("/api/jobs/{job_id}")
async def api_job(job_id: str, user: User = Depends(require("viewer"))):
    job = state.repo.get_job(job_id)
    if job is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return job.model_dump(mode="json")


@router.get("/api/assessments/{aid}/run")
async def api_run_progress(aid: str, user: User = Depends(require("viewer"))):
    """This assessment's most recent run, as it happens.

    The Run phase polls this rather than `/api/jobs/{id}` so that a browser
    arriving without the job id — a refresh, a second tab, someone opening the
    link a colleague sent — still finds the run that is in flight.
    """
    job = state.repo.latest_job(aid, "execute")
    if job is None:
        return {"state": "NONE", "assessment_id": aid}
    payload = job.model_dump(mode="json")
    payload["progress"] = payload.pop("result", {}) or {}
    return payload


@router.post("/api/assessments")
async def api_create(issue_key: str, user: User = Depends(require("tester"))):
    try:
        aid = await state.orch.import_and_analyze(
            issue_key, engagement=state.engagements.current_name)
    except (KeyError, ValueError) as exc:
        return JSONResponse(
            {
                "error": "issue_not_found" if isinstance(exc, KeyError) else "invalid_issue_key",
                "detail": str(exc).strip('"'),
                "available_issue_keys": available_issue_keys(state.jira),
            },
            status_code=404 if isinstance(exc, KeyError) else 400,
        )
    except RuntimeError as exc:
        return JSONResponse({"error": "jira_unavailable", "detail": str(exc)}, status_code=503)
    return {"assessment_id": aid}


@router.get("/api/assessments/{aid}")
async def api_get(aid: str, user: User = Depends(require("viewer"))):
    a = state.repo.get_assessment(aid)
    if not a:
        return JSONResponse({"error": "not found"}, status_code=404)
    return {
        "assessment_id": aid,
        "issue_key": a.issue_key,
        "status": a.status,
        "analysis": a.analysis_json,
        "coverage": a.coverage_json,
        "tests": [t.model_dump(mode="json") for t in state.repo.get_test_cases(aid)],
        "findings": [f.model_dump(mode="json") for f in state.repo.get_findings(aid)],
    }


@router.get("/api/health")
async def health(user: User | None = Depends(optional_user)):
    """Liveness, plus the configuration detail an operator needs — but only for
    a caller entitled to it.

    This stays reachable unauthenticated because the container healthcheck
    (docker/Dockerfile) probes it with no credentials and only reads the status
    code. What it *says* to an anonymous caller is now just "ok": the Jira
    connector's identity and the list of importable issue keys are engagement
    detail, and they were the one place a reader with no session could still
    learn something about the target.
    """
    if not (user and user.can("viewer")):
        return {"status": "ok"}
    return {
        "status": "ok",
        "engagement_configured": bool(state.engagement.target_base_url),
        "jira": describe_jira_client(state.jira),
        "jira_live": not isinstance(state.jira, MockJiraMCPClient),
        "jira_warning": state.jira_warning,
        "available_issue_keys": available_issue_keys(state.jira),
    }
