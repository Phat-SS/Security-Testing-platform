"""FastAPI app — the platform UI + JSON API.

Wires the orchestrator to a web workflow: import → analyze → design → approve →
execute → report → Jira comment. Server-rendered HTML (no frontend build). The
same routes back a small JSON API for automation.

Run:  uvicorn app.api.main:app --reload
"""

from __future__ import annotations

import html
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

from contextlib import asynccontextmanager

import psutil
from fastapi import Cookie, Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from app.analysis import TestDesigner, build_analyzer
from app.analysis.claude_analyzer import ClaudeAnalyzer
from app.api import views
from app.core.auth import AuthManager, User
from app.core.config import Settings
from app.core.engagement import delete_environment, load_engagement, save_environment
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
from app.schemas.testcase import RequestSpec

class State:
    def __init__(self) -> None:
        engine = make_engine()
        init_db(engine)
        self.repo = Repository(make_session_factory(engine))
        self.jira = build_jira_client()
        self.jira_warning = ""
        self.engagement = load_engagement()
        # Write target for the environments UI. Independent of whether
        # ENGAGEMENT_CONFIG was set at startup (that only gates what gets
        # auto-loaded on boot, per the default-deny design above).
        self.engagement_path = os.getenv("ENGAGEMENT_CONFIG", "") or "config/engagement.json"
        self.auth = AuthManager()
        views.configure(auth_enabled=self.auth.enabled)
        self.orch = Orchestrator(
            self.repo,
            self.jira,
            analyzer=build_analyzer(),
            designer=TestDesigner(self.engagement.attacker, self.engagement.victim),
        )

    def _rebind_jira(self, client) -> None:
        self.jira = client
        self.orch.set_jira_client(client)

    def reload_engagement(self) -> None:
        # Explicit path bypasses the ENGAGEMENT_CONFIG gate on purpose: a human
        # just saved through the UI, which is itself the deliberate-configuration
        # step the default-deny design requires.
        self.engagement = load_engagement(self.engagement_path)


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


# -- CSRF guard --------------------------------------------------------------
#
# The web UI is plain HTML forms — no JS framework, no CORS opt-in anywhere in
# this app. That means a genuine cross-origin browser request can never carry
# a custom header or trigger a preflight the server would have to approve, so
# the browser's own Sec-Fetch-Site / Origin / Referer headers are reliable
# signals a same-origin request cannot forge. This closes the gap where
# AUTH_ENABLED=false (the default) treats every request as the built-in
# admin: without this, any page a user's browser visits could silently POST
# to /assessment/{aid}/execute, /admin/shutdown, etc.
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _same_site_request(request: Request) -> bool:
    sec_fetch_site = request.headers.get("sec-fetch-site")
    if sec_fetch_site is not None:
        # "cross-site" is the one value a genuine cross-origin page produces;
        # same-origin/same-site/none (direct navigation) are all legitimate.
        return sec_fetch_site != "cross-site"
    origin = request.headers.get("origin")
    if origin is not None:
        return origin.rstrip("/") == str(request.base_url).rstrip("/")
    referer = request.headers.get("referer")
    if referer is not None:
        return urlsplit(referer).netloc == request.url.netloc
    # No browser-origin signal at all: a plain script/CLI/curl client, not a
    # browser a CSRF attack could puppet. Ambient-cookie/browser auth is the
    # thing CSRF exploits — a client with none of these headers has none.
    return True


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    if request.method in _UNSAFE_METHODS and not _same_site_request(request):
        return PlainTextResponse(
            "Cross-site request blocked (CSRF guard): this request's Origin/"
            "Sec-Fetch-Site did not match this server. Automate via the JSON "
            "API with an API key instead of a cross-site form/script.",
            status_code=403,
        )
    return await call_next(request)


# -- auth dependency --------------------------------------------------------


def _current_user(x_api_key: str | None = Header(None),
                  authorization: str | None = Header(None),
                  session_key: str | None = Cookie(None)) -> User:
    key = x_api_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization.split(" ", 1)[1]
    if not key:
        key = session_key
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


@app.get("/login", response_class=HTMLResponse)
async def login_page(flash: str = "") -> str:
    return views.login_page(flash=flash)


@app.post("/login")
async def login_submit(api_key: str = Form(...)):
    user = state.auth.authenticate(api_key)
    # Only meaningful when AUTH_ENABLED=true; when auth is off, authenticate()
    # always returns the built-in admin regardless of the key, so this can't
    # be used to probe for valid keys in that mode.
    if not user or not state.auth.enabled:
        return RedirectResponse("/login?flash=Invalid+API+key", status_code=303)
    resp = RedirectResponse(f"/?flash=Logged+in+as+{quote(user.name, safe='')}", status_code=303)
    resp.set_cookie(
        "session_key", api_key, httponly=True, samesite="lax",
        max_age=60 * 60 * 12,  # 12h; re-login after that rather than an eternal cookie
    )
    return resp


@app.post("/logout")
async def logout():
    resp = RedirectResponse("/?flash=Logged+out", status_code=303)
    resp.delete_cookie("session_key")
    return resp


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


def _comment_error(issue_key: str, exc: Exception) -> tuple[str, str]:
    """Map a post-to-Jira failure to (headline, hint). Never a bare 500.

    Same exception contract as _import_error: KeyError means the issue is
    unknown to the connector (the mock's fixed sample set, or a real key the
    live token can't see), RuntimeError is a misconfigured live connector.
    """
    if isinstance(exc, KeyError):
        return (
            f"Jira rejected the comment: unknown issue {issue_key}.",
            "The offline mock only accepts its sample issue keys "
            f"({', '.join(f'<code>{html.escape(k)}</code>' for k in available_issue_keys(state.jira))}). "
            "To post to a real ticket, configure a live Jira MCP server "
            "(<code>JIRA_MCP_URL</code> + <code>JIRA_CLOUD_ID</code> + "
            "<code>JIRA_MCP_TOKEN</code>).",
        )
    if isinstance(exc, RuntimeError):
        return (
            f"The Jira connector is not usable: {exc}",
            "This is a configuration problem (missing `mcp` package, bad "
            "headers, or an unreachable MCP server), not a bad comment.",
        )
    return (
        f"Posting to {issue_key} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )


def _execute_error(base_url: str, exc: Exception) -> tuple[str, str]:
    """Map an execution failure to (headline, hint). Never a bare 500.

    Scope violations on a per-test basis are already handled inside
    HttpRunner.run() as a BLOCKED verdict, not an exception — this is mostly a
    backstop for genuinely unexpected errors (e.g. a malformed request the
    transpiler let through). The one *expected* exception is a KeyError from
    PersonaVault.get(): the Environments page only ever writes `environments`/
    `active_environment` (see environments_page's own on-page hint), so an
    engagement.json built purely through that page has no `personas` —
    HttpRunner.run() resolves the attacker persona before scope is even
    checked, so this fires before a BLOCKED verdict ever gets a chance to.
    """
    if isinstance(exc, KeyError):
        # str(KeyError("x")) renders as "'x'" (single quotes from repr, not
        # the double quotes this used to strip) — strip either.
        detail = str(exc).strip("'\"")
        return (
            f"Running tests against {base_url} failed: {detail}",
            "The Environments page only manages target URLs. Personas "
            "(<code>attacker</code>/<code>victim</code> credentials referenced by "
            "the generated tests) must be added directly to "
            "<code>config/engagement.json</code> — copy the <code>personas</code> "
            "section from <code>config/engagement.example.json</code> and fill in "
            "real test-account tokens, then restart the server (or re-save any "
            "environment) so it reloads.",
        )
    return (
        f"Running tests against {base_url} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )


@app.get("/", response_class=HTMLResponse)
async def dashboard(flash: str = "") -> str:
    return views.dashboard(
        state.repo.list_assessments(),
        state.engagement.target_base_url,
        ai_on=ClaudeAnalyzer.is_enabled(),
        jira_mode=describe_jira_client(state.jira),
        available_keys=available_issue_keys(state.jira),
        warning=state.jira_warning,
        flash=flash,
    )


@app.get("/config/environments", response_class=HTMLResponse)
async def environments_page(flash: str = "") -> str:
    eng = state.engagement
    return views.environments_page(eng.environments, eng.active_environment, flash=flash)


@app.post("/config/environments")
async def save_environment_route(
    name: str = Form(...),
    url: str = Form(...),
    make_active: bool = Form(False),
    user: User = Depends(require("tester")),
):
    name = name.strip()
    url = url.strip().rstrip("/")
    if not name or not all(c.isalnum() or c in "-_" for c in name):
        return HTMLResponse(
            views.error_page(
                "Invalid environment name",
                f"{name!r} is not a valid environment name.",
                "Use letters, digits, <code>-</code> or <code>_</code> only "
                "(e.g. <code>dev</code>, <code>staging</code>).",
                back_href="/config/environments", back_label="← Back to environments",
            ),
            status_code=400,
        )
    if not (url.startswith("http://") or url.startswith("https://")):
        return HTMLResponse(
            views.error_page(
                "Invalid URL",
                f"{url!r} is not a valid base URL.",
                "It must start with <code>http://</code> or <code>https://</code>.",
                back_href="/config/environments", back_label="← Back to environments",
            ),
            status_code=400,
        )
    save_environment(state.engagement_path, name, url, make_active=make_active)
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash=Saved+{name}", status_code=303)


@app.post("/config/environments/{name}/delete")
async def delete_environment_route(name: str, user: User = Depends(require("tester"))):
    delete_environment(state.engagement_path, name)
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash=Removed+{name}", status_code=303)


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
        return HTMLResponse(views.error_page("Import failed", headline, hint), status_code=400)
    return RedirectResponse(f"/assessment/{aid}", status_code=303)


@app.get("/assessment/{aid}", response_class=HTMLResponse)
async def view_assessment(aid: str, flash: str = "", ticket_url: str = "") -> str:
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
        environments=state.engagement.environments,
        active_environment=state.engagement.active_environment,
        flash=flash,
        ticket_url=ticket_url,
    )


@app.post("/assessment/{aid}/delete")
async def delete_assessment(aid: str, user: User = Depends(require("tester"))):
    state.orch.delete_assessment(aid, actor=user.name)
    return RedirectResponse("/?flash=Deleted+assessment", status_code=303)


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


def _parse_kv_lines(text: str, sep: str) -> dict[str, str]:
    """'Key: Value' or 'key=value' per line -> dict. Blank lines and lines
    without the separator are skipped rather than rejected, so a stray blank
    line at the end of a textarea doesn't turn into a validation error."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or sep not in line:
            continue
        k, v = line.split(sep, 1)
        k = k.strip()
        if k:
            result[k] = v.strip()
    return result


def _parse_body_text(text: str):
    """JSON if it parses (so an edited object/array payload round-trips as
    structured data), otherwise the raw string as typed."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


@app.get("/assessment/{aid}/test/{test_id}", response_class=HTMLResponse)
async def test_detail(aid: str, test_id: str, flash: str = "") -> str:
    a = state.repo.get_assessment(aid)
    test = state.repo.get_test_case(aid, test_id)
    if not a or not test:
        return views.page("Not found", "<p>Test not found.</p>")
    return views.test_detail_page(a, test, flash=flash)


@app.post("/assessment/{aid}/test/{test_id}")
async def test_detail_save(
    aid: str, test_id: str,
    method: str = Form(...), path: str = Form(...),
    headers_text: str = Form(""), query_text: str = Form(""), body_text: str = Form(""),
    user: User = Depends(require("tester")),
):
    existing = state.repo.get_test_case(aid, test_id)
    if not existing:
        return views.page("Not found", "<p>Test not found.</p>")
    request = RequestSpec(
        method=method.strip().upper() or existing.request.method,
        path=path.strip() or existing.request.path,
        headers=_parse_kv_lines(headers_text, ":"),
        query=_parse_kv_lines(query_text, "="),
        body=_parse_body_text(body_text),
        capture=existing.request.capture,  # not exposed for edit; preserved as-is
    )
    state.orch.edit_test_request(aid, test_id, request, actor=user.name)
    flash = "Saved — approval reset to PENDING".replace(" ", "+")
    return RedirectResponse(f"/assessment/{aid}/test/{test_id}?flash={flash}", status_code=303)


@app.post("/assessment/{aid}/execute")
async def execute(aid: str, environment: str = Form(""), include_destructive: bool = Form(False),
                  user: User = Depends(require("tester"))):
    eng = state.engagement
    base_url = eng.environments.get(environment or eng.active_environment, eng.target_base_url)
    if not base_url:
        return RedirectResponse(f"/assessment/{aid}?flash=Execution+disabled:+no+engagement+configured",
                                status_code=303)
    try:
        execs = state.orch.execute(aid, base_url, eng.scope, eng.vault, Settings.from_env(),
                                   include_destructive=include_destructive)
    except Exception as exc:
        headline, hint = _execute_error(base_url, exc)
        return HTMLResponse(
            views.error_page("Execution failed", headline, hint,
                             back_href=f"/assessment/{aid}", back_label="← Back to assessment"),
            status_code=400,
        )
    n_fail = sum(1 for e in execs if e.verdict.result.value == "FAIL")
    # execute() now uses HttpRunner.run_safe(), which converts a per-test
    # exception (e.g. a persona missing from the vault) into an ERROR
    # execution instead of raising — the whole batch no longer aborts, but
    # that also means it can no longer reach the `except Exception` branch
    # above, so an ERROR must be surfaced here or it goes unnoticed.
    n_error = sum(1 for e in execs if e.verdict.result.value == "ERROR")
    flash = f"Executed {len(execs)} tests, {n_fail} FAIL"
    if n_error:
        flash += f", {n_error} ERROR (open a test's detail page for the reason)"
    flash = flash.replace(" ", "+")
    return RedirectResponse(f"/assessment/{aid}?flash={flash}", status_code=303)


@app.get("/assessment/{aid}/report", response_class=HTMLResponse)
async def report(aid: str) -> str:
    return state.orch.build_report_html(aid)


@app.get("/assessment/{aid}/export.html")
async def export_html(aid: str):
    return Response(state.orch.build_report_html(aid), media_type="text/html",
                    headers={"Content-Disposition": f"attachment; filename={aid}.html"})


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
    a = state.repo.get_assessment(aid)
    try:
        await state.orch.post_comment(aid, actor=user.name)
    except Exception as exc:
        headline, hint = _comment_error(a.issue_key if a else aid, exc)
        return HTMLResponse(
            views.error_page("Posting to Jira failed", headline, hint,
                             back_href=f"/assessment/{aid}", back_label="← Back to assessment"),
            status_code=400,
        )
    target = f"/assessment/{aid}?flash=Posted+to+Jira"
    # Only the live client can resolve a real browse URL (JIRA_SITE_URL
    # configured) — the offline mock has no site to link to, so this is
    # absent for it and the assessment page just shows the flash text alone.
    url = state.jira.browse_url(a.issue_key) if a else None
    if url:
        target += f"&ticket_url={quote(url, safe='')}"
    return RedirectResponse(target, status_code=303)


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


# -- shutdown -----------------------------------------------------------


# app/api/main.py -> app/api -> app -> project root. Everything this project
# runs (this server, the demo vulnerable target, stray CLI/pytest runs) does
# so through the project's own virtualenv interpreter, so "process uses an
# exe path under this .venv" is a precise, safe way to find *only* this
# project's processes — never an unrelated python process on the machine.
_VENV_DIR = Path(__file__).resolve().parent.parent.parent / ".venv"


def _project_processes() -> list[psutil.Process]:
    try:
        venv_dir = _VENV_DIR.resolve()
    except OSError:
        return []
    matched: dict[int, psutil.Process] = {}
    for proc in psutil.process_iter(["pid", "exe"]):
        try:
            exe = proc.info.get("exe") or ""
            if exe and Path(exe).resolve().is_relative_to(venv_dir):
                matched[proc.pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            continue
    # On Windows this venv's python.exe is itself a launcher stub that spawns
    # the real base interpreter as a *child* process — the child is the one
    # that actually holds the listening socket, and its own exe path is the
    # base install, not this venv, so it would never match above. Sweep
    # descendants of every match so the real worker is never left behind.
    for proc in list(matched.values()):
        try:
            for child in proc.children(recursive=True):
                matched[child.pid] = child
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return list(matched.values())


def _shutdown_everything(other_procs: list[psutil.Process]) -> None:
    time.sleep(0.4)  # let the HTTP response below reach the browser first
    for p in other_procs:
        try:
            p.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, alive = psutil.wait_procs(other_procs, timeout=3)
    for p in alive:
        try:
            p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    os._exit(0)  # this process last, unconditionally — a hard stop, not a request


@app.post("/admin/shutdown")
async def shutdown(
    x_confirm_shutdown: str | None = Header(None),
    user: User = Depends(require("admin")),
):
    # This kills every process on the machine running under this project's
    # venv — the most destructive single action the platform can take.
    # require("admin") (not "tester") plus a custom header the dashboard's
    # own fetch() sets are both defense-in-depth on top of the global CSRF
    # guard above: a plain cross-site <form> cannot set a custom header at
    # all (doing so from script triggers a CORS preflight this server never
    # approves), so this can only be reached from the dashboard button.
    if x_confirm_shutdown != "security-testing-platform-ui":
        raise HTTPException(
            status_code=400,
            detail="Missing confirmation header; use the dashboard's Shutdown server button.",
        )
    others = [p for p in _project_processes() if p.pid != os.getpid()]
    threading.Thread(target=_shutdown_everything, args=(others,), daemon=True).start()
    return {"status": "shutting down", "other_processes_stopped": len(others)}
