"""FastAPI app — the platform UI + JSON API.

Wires the orchestrator to a web workflow: import → analyze → design → approve →
execute → report → Jira comment. Server-rendered HTML (no frontend build). The
same routes back a small JSON API for automation.

Run:  uvicorn app.api.main:app --reload
"""

from __future__ import annotations

import html
import os

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from app.analysis import TestDesigner, build_analyzer
from app.analysis.claude_analyzer import ClaudeAnalyzer
from app.api import views
from app.core.auth import AuthManager, User
from app.core.config import Settings
from app.core.engagement import load_engagement
from app.database import Repository, init_db, make_engine, make_session_factory
from app.mcp import (
    MockJiraMCPClient,
    available_issue_keys,
    build_jira_client,
    describe_jira_client,
)
from app.mcp.jira import parse_issue_ref
from app.orchestrator import Orchestrator
from app.schemas.analysis import IssueAnalysis

class State:
    def __init__(self) -> None:
        engine = make_engine()
        init_db(engine)
        self.repo = Repository(make_session_factory(engine))
        self.jira = build_jira_client()
        self.jira_warning = ""
        self.engagement = load_engagement()
        self.auth = AuthManager()
        self.orch = Orchestrator(
            self.repo,
            self.jira,
            analyzer=build_analyzer(),
            designer=TestDesigner(self.engagement.attacker, self.engagement.victim),
        )

    def _rebind_jira(self, client) -> None:
        self.jira = client
        self.orch.set_jira_client(client)


state: State | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global state
    state = State()
    try:
        await state.jira.connect()
    except Exception as exc:
        # A misconfigured or unreachable live MCP server must not take the whole
        # platform down — everything except Jira import still works offline.
        # Fall back to the mock and say so in the UI rather than failing to boot.
        if isinstance(state.jira, MockJiraMCPClient):
            raise
        state.jira_warning = f"Live Jira MCP unavailable ({type(exc).__name__}: {exc}) — using the offline mock."
        fallback = MockJiraMCPClient()
        await fallback.connect()
        state._rebind_jira(fallback)
    yield


app = FastAPI(title="AI-assisted API Security Testing Platform", lifespan=lifespan)


# -- auth dependency --------------------------------------------------------


def _current_user(x_api_key: str | None = Header(None),
                  authorization: str | None = Header(None)) -> User:
    key = x_api_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization.split(" ", 1)[1]
    user = state.auth.authenticate(key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return user


def require(min_role: str):
    def _dep(user: User = Depends(_current_user)) -> User:
        if not user.can(min_role):
            raise HTTPException(status_code=403, detail=f"Requires role >= {min_role}")
        return user
    return _dep


# -- UI routes --------------------------------------------------------------


def _import_error(issue_key: str, exc: Exception) -> tuple[str, str]:
    """Map an import failure to (headline, hint). Never a bare 500.

    KeyError is the "no such issue" contract shared by the mock and the live
    client; ValueError comes from parse_issue_ref; RuntimeError is a
    misconfigured live connector (missing `mcp` package, bad headers).
    """
    keys = available_issue_keys(state.jira)
    if isinstance(exc, ValueError):
        return (
            f"{issue_key!r} is not a valid Jira issue reference.",
            "Use a key like <code>CRM-1234</code>, or paste a Jira URL "
            "(<code>https://…/browse/CRM-1234</code>).",
        )
    if isinstance(exc, KeyError):
        if keys:
            listed = ", ".join(f"<code>{html.escape(k)}</code>" for k in keys)
            return (
                f"Issue {issue_key} does not exist in the offline mock Jira.",
                f"Available sample issues: {listed}. To import your own tickets, "
                "point the platform at a real Jira MCP server "
                "(<code>JIRA_MCP_URL</code> + <code>JIRA_CLOUD_ID</code> + "
                "<code>JIRA_MCP_TOKEN</code>).",
            )
        return (
            f"Jira returned no issue for {issue_key}.",
            "Check the key spelling, the configured cloud id, and that the "
            "token has access to that project.",
        )
    if isinstance(exc, RuntimeError):
        return (
            f"The Jira connector is not usable: {exc}",
            "This is a configuration problem, not a bad issue key.",
        )
    return (
        f"Import of {issue_key} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return views.dashboard(
        state.repo.list_assessments(),
        state.engagement.target_base_url,
        ai_on=ClaudeAnalyzer.is_enabled(),
        jira_mode=describe_jira_client(state.jira),
        available_keys=available_issue_keys(state.jira),
        warning=state.jira_warning,
    )


@app.post("/import")
async def import_issue(issue_key: str = Form(...), user: User = Depends(require("tester"))):
    try:
        # Always validate: a Jira key is PROJECT-123, and parse_issue_ref also
        # accepts a pasted browse URL. Passing unparseable text straight through
        # used to surface as a confusing "issue does not exist".
        _, key = parse_issue_ref(issue_key)
        aid = await state.orch.import_and_analyze(key)
    except Exception as exc:
        headline, hint = _import_error(issue_key, exc)
        return HTMLResponse(views.import_error_page(headline, hint), status_code=400)
    return RedirectResponse(f"/assessment/{aid}", status_code=303)


@app.get("/assessment/{aid}", response_class=HTMLResponse)
async def view_assessment(aid: str, flash: str = "") -> str:
    a = state.repo.get_assessment(aid)
    if not a:
        return views.page("Not found", "<p>Assessment not found.</p>")
    tests = state.repo.get_test_cases(aid)
    return views.assessment_page(
        a,
        a.analysis_json or {},
        a.coverage_json or [],
        tests,
        n_executions=len(state.repo.get_executions(aid)),
        n_findings=len(state.repo.get_findings(aid)),
        engagement_target=state.engagement.target_base_url,
        flash=flash,
    )


@app.post("/assessment/{aid}/design")
async def design(aid: str, poc_python: str = Form(""), poc_postman: str = Form(""),
                 burp_xml: str = Form(""), jmeter_xml: str = Form(""),
                 user: User = Depends(require("tester"))):
    state.orch.design(aid, poc_python=poc_python or None, poc_postman=poc_postman or None,
                      burp_xml=burp_xml or None, jmeter_xml=jmeter_xml or None)
    return RedirectResponse(f"/assessment/{aid}?flash=Test+plan+generated", status_code=303)


@app.post("/assessment/{aid}/approve")
async def approve(request: Request, aid: str, user: User = Depends(require("tester"))):
    form = await request.form()
    test_ids = form.getlist("test_ids")
    if test_ids:
        state.orch.approve(aid, test_ids, actor=user.name)
        flash = f"Approved {len(test_ids)} test(s)"
    else:
        flash = "No tests selected"
    return RedirectResponse(f"/assessment/{aid}?flash={flash.replace(' ', '+')}", status_code=303)


@app.post("/assessment/{aid}/execute")
async def execute(aid: str, user: User = Depends(require("tester"))):
    eng = state.engagement
    if not eng.target_base_url:
        return RedirectResponse(f"/assessment/{aid}?flash=Execution+disabled:+no+engagement+configured",
                                status_code=303)
    execs = state.orch.execute(aid, eng.target_base_url, eng.scope, eng.vault, Settings.from_env())
    n_fail = sum(1 for e in execs if e.verdict.result.value == "FAIL")
    flash = f"Executed {len(execs)} tests, {n_fail} FAIL".replace(" ", "+")
    return RedirectResponse(f"/assessment/{aid}?flash={flash}", status_code=303)


@app.get("/assessment/{aid}/report", response_class=HTMLResponse)
async def report(aid: str) -> str:
    return state.orch.build_report_html(aid)


@app.get("/assessment/{aid}/export.json")
async def export_json(aid: str):
    from fastapi.responses import Response

    return Response(state.orch.export_json(aid), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={aid}.json"})


@app.get("/assessment/{aid}/export.xlsx")
async def export_xlsx(aid: str):
    return Response(
        state.orch.export_xlsx(aid),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={aid}.xlsx"},
    )


@app.get("/assessment/{aid}/export.pdf")
async def export_pdf(aid: str):
    return Response(state.orch.export_pdf(aid), media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={aid}.pdf"})


@app.get("/assessment/{aid}/export.postman")
async def export_postman(aid: str):
    return Response(state.orch.export_postman(aid), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={aid}.postman_collection.json"})


@app.get("/assessment/{aid}/regression", response_class=HTMLResponse)
async def regression(aid: str) -> str:
    from app.pipeline.history import render_diff_comment

    diff, prev_id = state.orch.regression_diff(aid)
    a = state.repo.get_assessment(aid)
    return views.regression_page(aid, a.issue_key, prev_id, diff,
                                 render_diff_comment(a.issue_key, diff))


@app.get("/assessment/{aid}/comment", response_class=HTMLResponse)
async def comment_preview(aid: str) -> str:
    a = state.repo.get_assessment(aid)
    return views.comment_preview_page(aid, a.issue_key, state.orch.comment_preview(aid))


@app.post("/assessment/{aid}/comment")
async def comment_post(aid: str, user: User = Depends(require("tester"))):
    await state.orch.post_comment(aid, actor=user.name)
    return RedirectResponse(f"/assessment/{aid}?flash=Posted+to+Jira", status_code=303)


# -- JSON API (automation) --------------------------------------------------


@app.post("/api/assessments")
async def api_create(issue_key: str, user: User = Depends(require("tester"))):
    try:
        aid = await state.orch.import_and_analyze(issue_key)
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


@app.get("/api/assessments/{aid}")
async def api_get(aid: str):
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


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "engagement_configured": bool(state.engagement.target_base_url),
        "jira": describe_jira_client(state.jira),
        "jira_live": not isinstance(state.jira, MockJiraMCPClient),
        "jira_warning": state.jira_warning,
        "available_issue_keys": available_issue_keys(state.jira),
    }
