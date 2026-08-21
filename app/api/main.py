"""FastAPI app — the platform UI + JSON API.

Wires the orchestrator to a web workflow: import → analyze → design → approve →
execute → report → Jira comment. Server-rendered HTML (no frontend build). The
same routes back a small JSON API for automation.

Run:  uvicorn app.api.main:app --reload
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from functools import partial
from pathlib import Path
from urllib.parse import quote, urlsplit

from contextlib import asynccontextmanager

import psutil
from fastapi import Cookie, Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.analysis import TestDesigner, build_analyzer
from app.analysis.attack_planner import build_planner
from app.analysis.adjudicator import build_adjudicator
from app.analysis.claude_analyzer import ClaudeAnalyzer
from app.analysis.plan_reviewer import build_reviewer
from app.api import views
from app.core.auth import AuthManager, User
from app.core.config import settings_with_overrides
from app.core import i18n, preflight
from app.core.i18n import normalize_lang
from app.core.logging_config import configure_error_tracking, configure_logging
from app.core.redaction import redact_text
from app.core.engagement import (
    allow_host,
    delete_environment,
    delete_persona,
    load_engagement,
    save_environment,
    save_identities,
    save_persona,
    save_runner_limits,
    save_scope,
    set_active_environment,
)
from app.database import Repository, init_db, make_engine, make_session_factory
from app.execution.adaptive import AdaptiveBudget
from app.mcp import (
    MockJiraMCPClient,
    available_issue_keys,
    build_jira_client,
    describe_jira_client,
)
from app.mcp.jira import parse_issue_ref
from app.orchestrator import Orchestrator
from app.schemas.analysis import Endpoint
from app.schemas.testcase import RequestSpec

logger = logging.getLogger(__name__)


def _create_operation_job(aid: str, kind: str, idempotency_key: str | None):
    key = (idempotency_key or f"ui-{uuid.uuid4().hex}").strip()[:128]
    return state.repo.create_job(aid, kind, key)


async def _run_operation_job(job, operation):
    state.repo.transition_job(job.job_id, "RUNNING")
    try:
        result = await run_in_threadpool(operation)
    except Exception as exc:
        state.repo.transition_job(
            job.job_id, "FAILED",
            error=redact_text(f"{type(exc).__name__}: {exc}")[:2000],
        )
        raise
    state.repo.transition_job(job.job_id, "SUCCEEDED", result={"completed": True})
    return result


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
        self.runtime_env_path = os.getenv("RUNTIME_ENV_PATH", ".env")
        self.auth = AuthManager()
        planner = build_planner(self.engagement.vault.names())
        views.configure(auth_enabled=self.auth.enabled, planner_enabled=planner is not None)
        self.orch = Orchestrator(
            self.repo,
            self.jira,
            analyzer=build_analyzer(),
            designer=TestDesigner(self.engagement.attacker, self.engagement.victim),
            # The planner validates proposed persona names against the vault, so
            # it can only be built once the engagement is loaded. Returns None
            # unless USE_AI is set and the claude CLI is available, in which
            # case the platform behaves exactly as it did before.
            planner=planner,
        )

    def _rebind_jira(self, client) -> None:
        self.jira = client
        self.orch.set_jira_client(client)

    def reload_engagement(self) -> None:
        # Explicit path bypasses the ENGAGEMENT_CONFIG gate on purpose: a human
        # just saved through the UI, which is itself the deliberate-configuration
        # step the default-deny design requires.
        self.engagement = load_engagement(self.engagement_path)
        # The planner rejects persona names it does not know, so a stale one
        # would reject every proposal referencing a persona added in this very
        # save — silently, as "not defined in the engagement vault".
        self.orch.set_planner(build_planner(self.engagement.vault.names()))

    def reload_ai_runtime(self) -> None:
        """Rebuild every Claude-backed component after a UI runtime save."""
        planner = build_planner(self.engagement.vault.names())
        self.orch.set_analyzer(build_analyzer())
        self.orch.set_planner(planner)
        self.orch.set_reviewer(build_reviewer())
        self.orch.set_adjudicator(build_adjudicator())
        views.configure(auth_enabled=self.auth.enabled, planner_enabled=planner is not None)


state: State | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Before anything reads a setting: `uvicorn app.api.main:app` is a
    # first-class way to start this app, and it does not go through the Node
    # launcher that used to be the only thing parsing .env.
    loaded = preflight.load_dotenv(os.getenv("RUNTIME_ENV_PATH", ".env"))
    configure_logging()
    if loaded:
        logger.info("loaded %d setting(s) from the .env file", len(loaded))
    configure_error_tracking()
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
    # Shut the connector down in the task that owns it. See _close_quietly.
    await _close_quietly(state.jira)


app = FastAPI(title="AI-assisted API Security Testing Platform", lifespan=lifespan)


@app.exception_handler(Exception)
async def _log_unhandled_exception(request: Request, exc: Exception) -> Response:
    """FastAPI's own default for an unhandled exception is an opaque 500 with
    the traceback going wherever uvicorn's logger happens to be pointed —
    unredacted, unstructured, and easy to lose in production. This puts it
    through the same configured (and redacting — see logging_config.py)
    logger as everything else, then re-raises so Starlette's own
    ServerErrorMiddleware still produces the standard response; this handler
    only adds visibility, it does not change what the client receives.
    """
    logger.exception("unhandled exception on %s %s", request.method, request.url.path)
    raise exc


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


@app.middleware("http")
async def lang_middleware(request: Request, call_next):
    """Resolve the page language once per request, from `?lang=` if the
    toggle was just clicked (see ui.LANG_TOGGLE_HTML), else the `lang` cookie,
    else English. views.py/views_assessment.py read it back via
    `app.core.i18n.get_lang()` rather than taking it as a parameter — see the
    ContextVar's docstring in i18n.py for why.

    A `?lang=` on the request is also the one signal that the user just chose
    a language, which is the only time this needs to (re-)set the cookie —
    every other request just carries the existing cookie forward unchanged.
    """
    query_lang = request.query_params.get("lang")
    lang = normalize_lang(query_lang or request.cookies.get(i18n.COOKIE_NAME))
    i18n.set_lang(lang)
    response = await call_next(request)
    if query_lang:
        response.set_cookie(
            i18n.COOKIE_NAME, lang, samesite="lax", max_age=365 * 24 * 3600,
        )
    return response


# -- auth dependency --------------------------------------------------------


def _current_user(x_api_key: str | None = Header(None),
                  authorization: str | None = Header(None),
                  session_key: str | None = Cookie(None)) -> User:
    key = x_api_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization.split(" ", 1)[1]
    user = state.auth.authenticate(key) if key else state.auth.authenticate_session(session_key)
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
    session_token = state.auth.issue_session(user)
    resp = RedirectResponse(f"/?flash=Logged+in+as+{quote(user.name, safe='')}", status_code=303)
    resp.set_cookie(
        "session_key", session_token, httponly=True, samesite="lax",
        secure=(os.getenv("AUTH_COOKIE_SECURE", "").lower() == "true"
                or os.getenv("PLATFORM_BASE_URL", "").lower().startswith("https://")),
        max_age=state.auth.session_ttl_s,
    )
    return resp


@app.post("/logout")
async def logout(session_key: str | None = Cookie(None)):
    state.auth.revoke_session(session_key)
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
    PersonaVault.get(), which fires when the attacker/victim names point at
    personas the vault does not hold: HttpRunner.run() resolves the persona
    before scope is even checked, so it lands here rather than as a BLOCKED
    verdict. The readiness panel flags exactly this ahead of a run, so this
    path is now the case where someone ran before looking at it.
    """
    if isinstance(exc, KeyError):
        # str(KeyError("x")) renders as "'x'" (single quotes from repr, not
        # the double quotes this used to strip) — strip either.
        detail = str(exc).strip("'\"")
        return (
            f"Running tests against {base_url} failed: {detail}",
            "Generated tests reference identities by name, and this one is not "
            "in the persona vault. Add it under "
            "<a href='/config?tab=identities'>Configuration &rarr; Identities</a> "
            "(name, auth headers, and the object ids it owns), or point the "
            "attacker/victim roles at personas that already exist. "
            "<a href='/config'>Readiness</a> lists every setting a run needs "
            "before you start one.",
        )
    return (
        f"Running tests against {base_url} failed: {type(exc).__name__}: {exc}",
        "See the server log for the full traceback.",
    )


_DASH_SORTS = {"recent", "oldest", "issue", "findings"}


@app.get("/", response_class=HTMLResponse)
async def dashboard(flash: str = "", q: str = "", status: str = "",
                    sort: str = "recent", page: int = 1, per: int = 24) -> str:
    everything = state.repo.list_assessments()
    # Counts per card, from one query each rather than loading every test case of
    # every assessment: a card that says only "Executed" tells you the one thing
    # you already knew and nothing about what the run found.
    rows = [state.repo.assessment_summary(a.id) for a in everything]
    by_id = {r["id"]: r for r in rows}

    needle = q.strip().lower()
    shown = [
        a for a in everything
        if (not needle or needle in a.issue_key.lower() or needle in a.id.lower())
        and (not status or a.status == status)
    ]
    if sort not in _DASH_SORTS:
        sort = "recent"
    if sort == "oldest":
        shown = list(reversed(shown))
    elif sort == "issue":
        shown = sorted(shown, key=lambda a: a.issue_key)
    elif sort == "findings":
        shown = sorted(shown, key=lambda a: -by_id[a.id]["n_findings"])

    per = max(1, min(per, 96))
    page = max(1, page)
    window = shown[(page - 1) * per: page * per]

    return views.dashboard(
        window,
        state.engagement.target_base_url,
        ai_on=ClaudeAnalyzer.is_enabled(),
        jira_mode=describe_jira_client(state.jira),
        available_keys=available_issue_keys(state.jira),
        warning=state.jira_warning,
        flash=flash,
        rows=[by_id[a.id] for a in window],
        q=q,
        status=status,
        sort=sort,
        page_no=page,
        per=per,
    )


# -- configuration ----------------------------------------------------------
#
# Everything a run depends on is editable here, because the alternative was a
# results table full of BLOCKED rows and a README paragraph naming a JSON file.
# Each writer touches only the keys it owns and then reloads state, so the next
# run picks the change up without a restart.


def _render_config(tab: str = "readiness", flash: str = "", error: str = "") -> str:
    eng = state.engagement
    readiness = preflight.evaluate(eng, state.engagement_path)
    return views.config_page(
        readiness=readiness,
        engagement=eng,
        engagement_path=state.engagement_path,
        limits=settings_with_overrides(eng.runner).limits,
        runtime=preflight.runtime_facts(),
        ai_evidence=preflight.ai_evidence_config_state(),
        jira_mode=describe_jira_client(state.jira),
        jira_live=not isinstance(state.jira, MockJiraMCPClient),
        jira_warning=state.jira_warning,
        jira_env=preflight.jira_env_facts(),
        jira_keys=available_issue_keys(state.jira),
        tab=tab,
        flash=flash,
        error=error,
    )


def _config_redirect(tab: str, flash: str) -> RedirectResponse:
    return RedirectResponse(f"/config?tab={tab}&flash={quote(flash, safe='')}", status_code=303)


@app.get("/config", response_class=HTMLResponse)
async def config_page(tab: str = "readiness", flash: str = "", error: str = "") -> str:
    return _render_config(tab=tab, flash=flash, error=error)


@app.get("/config/environments", response_class=HTMLResponse)
async def environments_page(flash: str = "") -> str:
    # Kept as its own URL (it predates the unified page and is linked from
    # older reports/bookmarks); it just opens the config page on that pane.
    return _render_config(tab="environments", flash=flash)


@app.get("/api/readiness")
async def api_readiness():
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


@app.post("/config/environments")
async def save_environment_route(
    name: str = Form(...),
    url: str = Form(...),
    make_active: bool = Form(False),
    authorize_host: bool = Form(False),
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
                back_href="/config?tab=target", back_label="← Back to target",
            ),
            status_code=400,
        )
    if not (url.startswith("http://") or url.startswith("https://")):
        return HTMLResponse(
            views.error_page(
                "Invalid URL",
                f"{url!r} is not a valid base URL.",
                "It must start with <code>http://</code> or <code>https://</code>.",
                back_href="/config?tab=target", back_label="← Back to target",
            ),
            status_code=400,
        )
    save_environment(state.engagement_path, name, url, make_active=make_active)
    flash = f"Saved {name}"
    # Adding the URL without authorizing its host is the exact combination that
    # produces an all-BLOCKED run, so the form offers both in one step — opt-in,
    # never implied, since this is the authorization boundary.
    host = preflight.host_of(url)
    if authorize_host and host:
        allow_host(state.engagement_path, host)
        flash += f" and authorized {host}"
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash={quote(flash, safe='')}", status_code=303)


@app.post("/config/environments/{name}/delete")
async def delete_environment_route(name: str, user: User = Depends(require("tester"))):
    delete_environment(state.engagement_path, name)
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash=Removed+{quote(name, safe='')}",
                            status_code=303)


@app.post("/config/environments/{name}/activate")
async def activate_environment_route(name: str, user: User = Depends(require("tester"))):
    set_active_environment(state.engagement_path, name)
    state.reload_engagement()
    return RedirectResponse(f"/config/environments?flash={quote(name + ' is now the default', safe='')}",
                            status_code=303)


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]

# The token variable names the quick setup writes. They match
# config/engagement.example.json and .env.example, so a config produced here and
# one copied from the examples are the same shape.
_QUICK_SETUP_VARS = {"agent_A": "PERSONA_A_TOKEN", "agent_B": "PERSONA_B_TOKEN"}


@app.post("/config/quick-setup")
async def quick_setup_route(
    env_name: str = Form("staging"),
    url: str = Form(...),
    attacker_token: str = Form(...),
    victim_token: str = Form(...),
    owns_key: str = Form("customer_id"),
    owns_value: str = Form(""),
    user: User = Depends(require("admin")),
):
    """Everything an empty engagement needs, written in one submit.

    Admin rather than tester because it writes credentials to .env, the same
    reason /config/ai-evidence does. The order matters: the tokens land in the
    environment *before* the personas that reference them are saved, so the
    readiness panel this redirects to evaluates the finished state rather than
    reporting two unset variables it is about to be given.
    """
    env_name = env_name.strip()
    url = url.strip().rstrip("/")
    owns_key = owns_key.strip()
    owns_value = owns_value.strip()

    def fail(message: str) -> RedirectResponse:
        return _config_redirect("readiness", message)

    if not env_name or not all(c.isalnum() or c in "-_" for c in env_name):
        return fail(f"{env_name or '(blank)'} is not a valid environment name — letters, digits, - _ only")
    if not (url.startswith("http://") or url.startswith("https://")):
        return fail("The base URL must start with http:// or https://")
    host = preflight.host_of(url)
    if not host:
        return fail("That base URL has no hostname")
    if not attacker_token.strip() or not victim_token.strip():
        return fail("Both tokens are required — an unset one blocks every run anyway")

    try:
        preflight.update_dotenv_values(
            {
                _QUICK_SETUP_VARS["agent_A"]: attacker_token.strip(),
                _QUICK_SETUP_VARS["agent_B"]: victim_token.strip(),
            },
            state.runtime_env_path,
            apply_to_environ=True,
        )
    except (OSError, ValueError) as exc:
        # ValueError here means a token with a newline in it, which would have
        # smuggled extra assignments into .env. Nothing is written on either.
        return fail(f"The tokens were not saved: {type(exc).__name__}")

    save_environment(state.engagement_path, env_name, url, make_active=True)
    allow_host(state.engagement_path, host)
    for name, variable in _QUICK_SETUP_VARS.items():
        save_persona(
            state.engagement_path,
            name=name,
            auth_headers={"Authorization": f"Bearer ${{{variable}}}"},
            role="user",
            owns=({owns_key: owns_value} if name == "agent_B" and owns_key and owns_value else {}),
        )
    save_identities(state.engagement_path, "agent_A", "agent_B")
    state.reload_engagement()
    state.repo.audit(
        "quick_setup", actor=user.name,
        detail=f"Created environment {env_name} ({host}), personas agent_A/agent_B; token values omitted.",
    )
    return _config_redirect(
        "readiness", f"Engagement created — {env_name} authorized, agent_A attacks agent_B"
    )




@app.post("/config/scope")
async def save_scope_route(
    allowed_hosts: str = Form(""),
    blocked_hosts: str = Form(""),
    allow_private_ranges: bool = Form(False),
    user: User = Depends(require("tester")),
):
    save_scope(state.engagement_path, _lines(allowed_hosts), _lines(blocked_hosts),
               allow_private_ranges)
    state.reload_engagement()
    return _config_redirect("scope", "Scope saved")


@app.post("/config/scope/allow-host")
async def allow_host_route(host: str = Form(...), user: User = Depends(require("tester"))):
    allow_host(state.engagement_path, host)
    state.reload_engagement()
    return _config_redirect("readiness", f"{host} added to the approved scope")


@app.post("/config/personas")
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
        return _config_redirect(
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
    return _config_redirect("personas", f"Saved persona {name}")


@app.post("/config/personas/{name}/delete")
async def delete_persona_route(name: str, user: User = Depends(require("tester"))):
    delete_persona(state.engagement_path, name)
    state.reload_engagement()
    return _config_redirect("personas", f"Removed persona {name}")


@app.post("/config/identities")
async def save_identities_route(
    attacker: str = Form(...), victim: str = Form(...),
    user: User = Depends(require("tester")),
):
    save_identities(state.engagement_path, attacker.strip(), victim.strip())
    state.reload_engagement()
    return _config_redirect("personas", f"Attacker {attacker}, victim {victim}")


@app.post("/config/runner")
async def save_runner_route(
    timeout_s: str = Form(""),
    max_response_bytes: str = Form(""),
    max_requests_per_test: str = Form(""),
    reset: str = Form(""),
    user: User = Depends(require("tester")),
):
    if reset:
        save_runner_limits(state.engagement_path, {})
        state.reload_engagement()
        return _config_redirect("runner", "Runner limits reset to the .env defaults")
    submitted = {
        "timeout_s": timeout_s,
        "max_response_bytes": max_response_bytes,
        "max_requests_per_test": max_requests_per_test,
    }
    limits: dict[str, float] = {}
    for key, raw in submitted.items():
        raw = raw.strip()
        if not raw:
            continue  # blank means "fall back to the env var", not zero
        try:
            value = float(raw) if key == "timeout_s" else int(float(raw))
        except ValueError:
            return _config_redirect("runner", f"{key} must be a number — nothing saved")
        if value < 0:
            return _config_redirect("runner", f"{key} cannot be negative — nothing saved")
        limits[key] = value
    save_runner_limits(state.engagement_path, limits)
    state.reload_engagement()
    return _config_redirect("runner", "Runner limits saved")


@app.post("/config/ai-evidence")
async def save_ai_evidence_route(
    request: Request,
    user: User = Depends(require("admin")),
):
    """Save AI/evidence runtime settings without ever echoing stored secrets."""
    form = await request.form()
    secret_keys = (
        "EVIDENCE_FINGERPRINT_KEY", "REPORT_SIGNING_KEY", "OAST_API_TOKEN",
    )
    public_keys = (
        "ANTHROPIC_MODEL", "AI_MAX_BUDGET_USD", "AI_EFFORT",
        "REPORT_SIGNING_KEY_ID", "OAST_PUBLIC_URL", "OAST_POLL_URL", "OAST_TIMEOUT_S",
    )
    changes: dict[str, str | None] = {
        key: "true" if form.get(key) else "false"
        for key in ("USE_AI", "AI_REQUIRE_PINNED_MODEL", "AUTH_COOKIE_SECURE")
    }

    for key in public_keys:
        value = str(form.get(key, "")).strip()
        changes[key] = value or None
    for key in secret_keys:
        value = str(form.get(key, "")).strip()
        clear = bool(form.get(f"clear_{key}"))
        if value and clear:
            return _config_redirect("ai-evidence", f"Choose set or clear for {key}, not both")
        if value:
            changes[key] = value
        elif clear:
            changes[key] = None
        # blank without explicit clear deliberately preserves the secret

    def prospective(key: str) -> str:
        if key in changes:
            return changes[key] or ""
        return os.getenv(key, "")

    fingerprint = prospective("EVIDENCE_FINGERPRINT_KEY")
    if fingerprint and len(fingerprint) < 16:
        return _config_redirect(
            "ai-evidence", "EVIDENCE_FINGERPRINT_KEY must be at least 16 characters"
        )
    signing = prospective("REPORT_SIGNING_KEY")
    if signing and len(signing) < 32:
        return _config_redirect(
            "ai-evidence", "REPORT_SIGNING_KEY must be at least 32 characters"
        )

    public_url = prospective("OAST_PUBLIC_URL")
    poll_url = prospective("OAST_POLL_URL")
    if bool(public_url) != bool(poll_url):
        return _config_redirect(
            "ai-evidence", "OAST public and poll URLs must be configured together"
        )
    for label, value in (("OAST_PUBLIC_URL", public_url), ("OAST_POLL_URL", poll_url)):
        parsed = urlsplit(value) if value else None
        if value and (parsed.scheme != "https" or not parsed.hostname):
            return _config_redirect("ai-evidence", f"{label} must be an absolute HTTPS URL")

    model = prospective("ANTHROPIC_MODEL")
    if prospective("AI_REQUIRE_PINNED_MODEL") == "true" and not any(c.isdigit() for c in model):
        return _config_redirect(
            "ai-evidence", "Pinned-model mode requires a versioned ANTHROPIC_MODEL"
        )
    budget = prospective("AI_MAX_BUDGET_USD")
    timeout = prospective("OAST_TIMEOUT_S")
    for key, raw in (("AI_MAX_BUDGET_USD", budget), ("OAST_TIMEOUT_S", timeout)):
        if not raw:
            continue
        try:
            if float(raw) <= 0:
                raise ValueError
        except ValueError:
            return _config_redirect("ai-evidence", f"{key} must be a positive number")
    effort = prospective("AI_EFFORT")
    if effort and not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", effort):
        return _config_redirect("ai-evidence", "AI_EFFORT contains unsupported characters")

    try:
        preflight.update_dotenv_values(
            changes, state.runtime_env_path, apply_to_environ=True
        )
        state.reload_ai_runtime()
    except (OSError, ValueError) as exc:
        return _config_redirect(
            "ai-evidence", f"Runtime configuration was not saved: {type(exc).__name__}"
        )
    changed_names = sorted(changes)
    state.repo.audit(
        "runtime_config", actor=user.name,
        detail=f"Updated {len(changed_names)} allowlisted AI/evidence setting(s); values omitted.",
    )
    return _config_redirect("ai-evidence", "AI and evidence configuration saved")


async def _close_quietly(client) -> None:
    """Release a Jira client we have stopped using.

    Not optional hygiene: a live client holds an open HTTP transport and a task
    running its receive loop (see LiveJiraMCPClient.close). Merely dropping the
    reference on every Reconnect leaks both, and leaves the teardown to the
    garbage collector at an arbitrary later moment.

    Best-effort by design — a client we have already replaced failing to hang up
    is not worth failing the request that replaced it.
    """
    close = getattr(client, "close", None)
    if not callable(close):
        return  # the mock holds no transport
    try:
        await close()
    except BaseException:
        logger.debug("ignoring error while closing the previous Jira client", exc_info=True)


async def _reconnect_jira() -> RedirectResponse:
    # Re-read .env first: a running process's os.environ is fixed at spawn
    # time, so a token refreshed on disk (npm run jira:token, or the
    # refresh-token route below) is otherwise invisible until a full restart.
    # This is the one thing a restart would have done that a plain
    # build_jira_client() call here would not.
    preflight.reload_dotenv()
    # The client being replaced, closed only once its successor is bound — a
    # failed connect must not leave the platform with no Jira client at all.
    previous = state.jira
    new_client = build_jira_client()
    try:
        await new_client.connect()
    except Exception as exc:
        if isinstance(new_client, MockJiraMCPClient):
            raise
        state.jira_warning = f"Live Jira MCP unavailable ({type(exc).__name__}: {exc}) — using the offline mock."
        fallback = MockJiraMCPClient()
        await fallback.connect()
        state._rebind_jira(fallback)
        await _close_quietly(previous)
        return RedirectResponse(
            f"/config?tab=advanced&error={quote(state.jira_warning, safe='')}", status_code=303
        )
    state.jira_warning = ""
    state._rebind_jira(new_client)
    await _close_quietly(previous)
    return _config_redirect("mcp", f"Reconnected — {describe_jira_client(new_client)}")


@app.post("/config/mcp/jira/reconnect")
async def mcp_jira_reconnect_route(user: User = Depends(require("tester"))):
    return await _reconnect_jira()


@app.post("/config/mcp/jira/refresh-token")
async def mcp_jira_refresh_token_route(user: User = Depends(require("tester"))):
    """Package the manual refresh dance (npx mcp-remote -> npm run jira:token ->
    Reconnect) into one click: open the Atlassian OAuth login in the user's
    browser, wait for the token it writes, save it, then reconnect.

    Only works where this process itself runs with Node.js and a browser
    available — the same requirement the manual flow already has. Degrades to
    a clear `error=` redirect rather than hanging or 500ing when npx is
    missing, the login times out, or the token file is unusable.
    """
    mcp_url = os.getenv("JIRA_MCP_URL", "").strip() or "https://mcp.atlassian.com/v1/mcp"
    npx = shutil.which("npx")
    if not npx:
        return RedirectResponse(
            "/config?tab=advanced&error=" + quote(
                "npx not found on PATH — install Node.js, or refresh the token "
                "manually (see below).", safe=""),
            status_code=303,
        )

    started_at = time.time()
    mcp_auth_dir = Path.home() / ".mcp-auth"
    try:
        # shell=True is deliberate here, not a shortcut: Windows cannot exec a
        # .cmd shim (npx) via CreateProcess without going through the shell,
        # and both interpolated values are the operator's own server-side
        # config (JIRA_MCP_URL from .env, npx resolved from PATH) — never
        # request-supplied — so there is nothing here for a caller to inject.
        proc = subprocess.Popen(
            f'"{npx}" -y mcp-remote "{mcp_url}"',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        return RedirectResponse(
            "/config?tab=advanced&error=" + quote(f"Could not start mcp-remote: {exc}", safe=""),
            status_code=303,
        )

    token_path = None
    try:
        while time.time() < started_at + 90:
            token_path = preflight.newest_mcp_auth_token(mcp_auth_dir, newer_than=started_at)
            if token_path:
                break
            await asyncio.sleep(1.5)
    finally:
        proc.terminate()  # its job (writing the token file) is done either way

    if not token_path:
        return RedirectResponse(
            "/config?tab=advanced&error=" + quote(
                "Timed out waiting for the Atlassian login in your browser — try "
                "again and finish it there within 90s.", safe=""),
            status_code=303,
        )

    token = json.loads(token_path.read_text(encoding="utf-8")).get("access_token", "")
    if not token:
        return RedirectResponse(
            "/config?tab=advanced&error=" + quote(f"{token_path} had no access_token", safe=""),
            status_code=303,
        )
    preflight.write_dotenv_value("JIRA_MCP_URL", mcp_url)
    preflight.write_dotenv_value("JIRA_MCP_TOKEN", token)
    return await _reconnect_jira()


@app.post("/import")
async def import_issue(issue_key: str = Form(...), mode: str = Form(""),
                       plan: str = Form("false"), depth: str = Form("standard"),
                       user: User = Depends(require("tester"))):
    """Import a ticket and, depending on `mode`, come back with a plan to approve.

    `mode` is one of:
    - "analyze" (default, and what an empty/missing `mode` falls back to): analyze
      only. What you want when the endpoint list needs correcting before any plan
      is worth generating.
    - "auto_plan": the planning agent runs — analyze the ticket and its embedded
      PoC, design, let the AI planner add depth, have the reviewing agent audit
      the result against the ticket's requirements, feed its gaps back for a
      revision round, and land the tester on step 4 with something to read.
    - "ticket_poc": run exactly the PoC embedded in the ticket as the test plan —
      no invented attacks. The plan reviewer still runs once (read-only); the
      result adjudicator still runs at the assess step. If the ticket has no
      embedded PoC, redirects with a flash telling the tester to use auto_plan or
      paste one by hand instead.

    `plan=true` with no `mode` is kept working exactly as before (maps to
    "auto_plan") so any existing scripted `POST /import` behaves as it always has.

    Nothing about the approval gate moves: every test this produces is PENDING.
    """
    try:
        # Always validate: a Jira key is PROJECT-123, and parse_issue_ref also
        # accepts a pasted browse URL. Passing unparseable text straight through
        # used to surface as a confusing "issue does not exist".
        _, key = parse_issue_ref(issue_key)
        effective_mode = mode or ("auto_plan" if plan == "true" else "analyze")
        if effective_mode == "ticket_poc":
            aid, _review, poc_found = await state.orch.import_and_run_poc_plan(key)
            if not poc_found:
                flash = ("No PoC script found in this ticket description — "
                         "use Auto-plan or paste one manually in Design.")
                return RedirectResponse(
                    f"/assessment/{aid}?flash={quote(flash, safe='')}", status_code=303
                )
        elif effective_mode == "auto_plan":
            aid, _review = await state.orch.import_and_plan(key, depth=depth or "standard")
        else:
            aid = await state.orch.import_and_analyze(key)
    except Exception as exc:
        headline, hint = _import_error(issue_key, exc)
        return HTMLResponse(views.error_page("Import failed", headline, hint), status_code=400)
    return RedirectResponse(f"/assessment/{aid}", status_code=303)


@app.get("/assessment/{aid}", response_class=HTMLResponse)
async def view_assessment(
    aid: str,
    flash: str = "",
    ticket_url: str = "",
    # The test-plan filter lives in the query string so it survives a redirect,
    # can be linked to (the coverage table links straight into a category) and is
    # the same thing a bulk action resolves "all matching" against.
    q: str = "",
    cat: str = "",
    sev: str = "",
    appr: str = "",
    dest: str = "",
    src: str = "",
    sort: str = "id",
    page: int = 1,
    per: int = 25,
) -> str:
    a = state.repo.get_assessment(aid)
    if not a:
        return views.page("Not found", "<p>Assessment not found.</p>")
    filters = {"q": q, "cat": cat, "sev": sev, "appr": appr, "dest": dest, "src": src,
               "sort": sort or "id", "per": per}
    plan = state.repo.query_test_cases(aid, page=max(1, page), **filters)
    findings = state.repo.get_findings(aid)
    # Loaded once and used twice: the execution count and the triage summary both
    # need every row, and this page is the one a tester leaves open.
    executions = state.repo.get_executions(aid)
    # Triage is deterministic, needs no key and costs nothing, so the page can
    # say "4 of these need you, 2 need re-running" before anyone asks for a
    # review. The review itself is a POST, because it costs API calls.
    triage_counts = state.orch.triage_counts(aid, executions=executions)
    return views.assessment_page(
        a,
        a.analysis_json or {},
        a.coverage_json or [],
        plan=plan,
        filters=filters,
        n_executions=len(executions),
        n_findings=len(findings),
        findings=findings,
        verdicts=state.repo.execution_verdicts(aid),
        plan_review=state.orch.plan_review(aid),
        run_assessment=state.orch.run_assessment(aid),
        triage=triage_counts,
        uncovered_poc_endpoints=state.orch.uncovered_poc_endpoints(aid),
        environments=state.engagement.environments,
        active_environment=state.engagement.active_environment,
        readiness=preflight.evaluate(state.engagement, state.engagement_path),
        flash=flash,
        ticket_url=ticket_url,
    )


@app.post("/assessment/{aid}/delete")
async def delete_assessment(aid: str, user: User = Depends(require("tester"))):
    state.orch.delete_assessment(aid, actor=user.name)
    return RedirectResponse("/?flash=Deleted+assessment", status_code=303)



# -- editing the attack surface ---------------------------------------------
#
# The endpoint list drives the whole plan, and the extractor that produces it is
# a regex over ticket prose. Before these routes, a missed endpoint or a wrong
# auth flag could only be fixed by editing the Jira ticket and importing again,
# which discarded the plan and every approval along with it.
#
# The endpoint being edited is identified by a form field, not a path segment:
# its identity is "METHOD /path", and a path like `POST /orders/delete` put in
# the URL would be swallowed by the delete route.


def _csv(text: str) -> list[str]:
    """Comma- or space-separated parameter names, de-duplicated, order kept."""
    parts = [p.strip() for p in (text or "").replace(",", " ").split()]
    return list(dict.fromkeys(p for p in parts if p))


def _endpoints_redirect(aid: str, flash: str) -> RedirectResponse:
    return RedirectResponse(
        f"/assessment/{aid}?flash={quote(flash)}#s-endpoints", status_code=303
    )


def _first_error(exc: Exception) -> str:
    """A pydantic ValidationError reads as a stack of dicts; a form needs one
    sentence naming the field that was wrong."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        detail = errors()
        if detail:
            loc = ".".join(str(p) for p in detail[0].get("loc", ())) or "value"
            return f"{loc}: {detail[0].get('msg', 'invalid')}"
    return str(exc)


@app.post("/assessment/{aid}/endpoints")
async def save_endpoint(aid: str, method: str = Form("GET"), path: str = Form(""),
                        replaces: str = Form(""),
                        auth_required: bool = Form(False),
                        expected_public: bool = Form(False),
                        object_id_params: str = Form(""),
                        writes_properties: bool = Form(False),
                        url_fields: str = Form(""),
                        user: User = Depends(require("tester"))):
    """Add an endpoint, or replace the one named by `replaces`."""
    verb = "saved" if replaces else "added"
    try:
        endpoint = Endpoint(
            method=(method or "GET").strip().upper(),
            path=(path or "").strip(),
            auth_required=auth_required,
            expected_public=expected_public,
            object_id_params=_csv(object_id_params),
            writes_properties=writes_properties,
            url_fields=_csv(url_fields),
            manual=True,
        )
        if not endpoint.path.startswith("/"):
            raise ValueError("path must start with '/' — it is joined onto the "
                             "approved base URL, so it cannot carry its own host")
        state.orch.upsert_endpoint(aid, endpoint, replaces=replaces, actor=user.name)
    except Orchestrator.EndpointConflict as exc:
        return _endpoints_redirect(aid, f"Not {verb}: {exc}")
    except (ValidationError, ValueError) as exc:
        return _endpoints_redirect(aid, f"Not {verb}: {_first_error(exc)}")
    return _endpoints_redirect(aid, f"{verb.capitalize()} {endpoint.signature}")


@app.post("/assessment/{aid}/endpoints/delete")
async def remove_endpoint(aid: str, signature: str = Form(...),
                          user: User = Depends(require("tester"))):
    removed = state.orch.delete_endpoint(aid, signature, actor=user.name)
    return _endpoints_redirect(
        aid, f"Removed {signature}" if removed else "Endpoint not found"
    )


@app.post("/assessment/{aid}/reanalyze")
async def reanalyze(aid: str, user: User = Depends(require("tester"))):
    a = state.repo.get_assessment(aid)
    if not a:
        return RedirectResponse("/?flash=Assessment+not+found", status_code=303)
    try:
        await state.orch.reanalyze(aid, actor=user.name)
    except Exception as exc:
        headline, hint = _import_error(a.issue_key, exc)
        return HTMLResponse(
            views.error_page("Re-analysis failed", headline, hint,
                             back_href=f"/assessment/{aid}", back_label="← Back to assessment"),
            status_code=400,
        )
    return _endpoints_redirect(aid, "Re-analyzed from the ticket")


@app.post("/assessment/{aid}/design")
async def design(aid: str, poc_python: str = Form(""), poc_postman: str = Form(""),
                 burp_xml: str = Form(""), jmeter_xml: str = Form(""),
                 depth: str = Form("standard"),
                 user: User = Depends(require("tester"))):
    # Anything other than the two known depths falls back to "standard" inside
    # TestDesigner rather than erroring: a form value is user input, and the
    # safe direction for an unrecognised one is the narrower test plan.
    state.orch.design(aid, poc_python=poc_python or None, poc_postman=poc_postman or None,
                      burp_xml=burp_xml or None, jmeter_xml=jmeter_xml or None,
                      depth=depth or "standard")
    return RedirectResponse(f"/assessment/{aid}?flash=Test+plan+generated", status_code=303)



_PLAN_ACTIONS = {
    "approve": ("approve", "Approved"),
    "reject": ("reject", "Rejected"),
    "reset": ("reset_approval", "Reset to PENDING"),
}


def _plan_filters(form) -> dict:
    """The filter the tester was looking at, echoed back from the form.

    "Approve all 312 matching" has to mean the filter on screen, so the bulk
    action re-runs the same query server-side rather than trusting a list of ids
    the page happened to render.
    """
    def get(name, default=""):
        value = form.get(name, default)
        return value if value is not None else default

    try:
        per = int(get("per", "25") or 25)
    except ValueError:
        per = 25
    return {"q": get("q"), "cat": get("cat"), "sev": get("sev"), "appr": get("appr"),
            "dest": get("dest"), "src": get("src"), "sort": get("sort", "id") or "id",
            "per": per}


@app.post("/assessment/{aid}/agent-plan")
async def agent_plan(aid: str, depth: str = Form("standard"), rounds: int = Form(1),
                     user: User = Depends(require("tester")),
                     idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    """Re-run the planning pipeline: design → plan → review → revise → re-review.

    Replaces the plan, exactly as the Design step does, and carries an approval
    across for any test that comes back byte-for-byte unchanged. Rounds are
    capped at 2 whatever is posted: each one is another LLM call and another
    batch a human has to read, and a reviewer that is never satisfied would
    otherwise loop until the batch cap swallowed the plan.
    """
    job, created = _create_operation_job(aid, "agent_plan", idempotency_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Existing job {job.job_id}: {job.state}')}#s-plan",
            status_code=303,
        )
    try:
        _tests, review = await _run_operation_job(
            job,
            partial(
                state.orch.agent_plan, aid, depth=depth or "standard",
                max_rounds=max(0, min(2, rounds)), actor=user.name,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - report it, do not 500 the page
        return HTMLResponse(
            views.error_page(
                "Planning agent failed",
                f"The planning agent could not complete: {type(exc).__name__}: {exc}",
                "<p>The assessment is unchanged. Generate a plan from step 2 to "
                "continue without the agent.</p>",
            ),
            status_code=500,
        )
    flash = (f"Plan reviewed: {review.verdict}, {len(review.tests_added)} test(s) added"
             if review else "Plan generated (no review was recorded)")
    return RedirectResponse(f"/assessment/{aid}?flash={quote(flash)}#s-plan", status_code=303)


@app.post("/assessment/{aid}/adjudicate")
async def adjudicate(request: Request, aid: str, user: User = Depends(require("tester")),
                     idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    """Review the results: triage, measure, cluster, then answer pass/fail.

    Sends nothing by default. It reads evidence that already exists, which is why
    it is safe to run, disagree with, and run again — and why it is a separate
    button from Execute rather than something that happens automatically at the
    end of a run.

    The one exception is explicit and comes from its own button: `rerun_transient`
    re-sends the results that carry no security signal at all (a 5xx during the
    attack, a runner error). That fires real requests, bounded and audited, and
    only ever from a form that says so — never as a side effect of asking for a
    review.
    """
    form = await request.form()
    rerun_transient = bool(form.get("rerun_transient"))
    eng = state.engagement
    job, created = _create_operation_job(aid, "adjudicate", idempotency_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Existing job {job.job_id}: {job.state}')}#s-results",
            status_code=303,
        )
    try:
        run = await _run_operation_job(
            job,
            partial(
                state.orch.adjudicate, aid, actor=user.name,
                rerun_transient=rerun_transient,
                scope=eng.scope if rerun_transient else None,
                vault=eng.vault if rerun_transient else None,
                settings=settings_with_overrides(eng.runner) if rerun_transient else None,
            ),
        )
    except ValueError as exc:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(str(exc))}#s-results", status_code=303
        )
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(
            views.error_page(
                "Result review failed",
                f"The reviewing agent could not complete: {type(exc).__name__}: {exc}",
                "<p>Nothing was changed. The sealed verdicts and findings are "
                "untouched — this pass only ever reads them.</p>",
            ),
            status_code=500,
        )
    settled = (f"{run.n_auto_resolved} settled by review "
               f"({run.n_measured} by measurement)") if run.n_auto_resolved else "none settled"
    flash = (f"Reviewed: {run.overall}, {run.coverage_pct}% of the ticket covered, "
             f"{settled}, {run.n_manual_review} still need you"
             + (f", {run.n_reran} re-sent" if run.n_reran else ""))
    return RedirectResponse(f"/assessment/{aid}?flash={quote(flash)}#s-results",
                            status_code=303)


@app.post("/assessment/{aid}/plan")
async def plan_action(request: Request, aid: str, user: User = Depends(require("tester"))):
    form = await request.form()
    action = str(form.get("action", "approve"))
    if action not in _PLAN_ACTIONS:
        return RedirectResponse(f"/assessment/{aid}?flash=Unknown+action#s-plan", status_code=303)
    method_name, word = _PLAN_ACTIONS[action]

    if form.get("select_all"):
        filters = _plan_filters(form)
        filters.pop("per", None)
        test_ids = state.repo.query_test_cases(aid, per=500, **filters)["matched_ids"]
        scope = "matching the current filter"
    else:
        test_ids = [str(v) for v in form.getlist("test_ids")]
        scope = "selected"

    if not test_ids:
        return RedirectResponse(f"/assessment/{aid}?flash=Nothing+selected#s-plan", status_code=303)

    n = getattr(state.orch, method_name)(aid, test_ids, actor=user.name)
    flash = f"{word} {n} test(s) {scope}"
    query = _preserve_plan_query(form)
    return RedirectResponse(
        f"/assessment/{aid}?flash={quote(flash)}{query}#s-plan", status_code=303
    )


def _preserve_plan_query(form) -> str:
    """Keep the filter across the redirect: landing back on an unfiltered page
    after acting on a filtered one loses the tester's place."""
    keep = ("q", "cat", "sev", "appr", "dest", "src", "sort", "per", "page")
    parts = [f"{k}={quote(str(form.get(k)))}" for k in keep if form.get(k)]
    return ("&" + "&".join(parts)) if parts else ""


@app.post("/assessment/{aid}/approve")
async def approve(request: Request, aid: str, user: User = Depends(require("tester"))):
    """The plain approve endpoint, kept because scripts and the JSON-ish
    automation path post to it. Bulk actions go through /plan."""
    form = await request.form()
    test_ids = [str(v) for v in form.getlist("test_ids")]
    if test_ids:
        n = state.orch.approve(aid, test_ids, actor=user.name)
        flash = f"Approved {n} test(s)"
    else:
        flash = "No tests selected"
    return RedirectResponse(
        f"/assessment/{aid}?flash={quote(flash)}#s-plan", status_code=303
    )


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
                  adaptive: bool = Form(False),
                  user: User = Depends(require("tester")),
                  idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    eng = state.engagement
    base_url = eng.environments.get(environment or eng.active_environment, eng.target_base_url)
    if not base_url:
        return RedirectResponse(f"/assessment/{aid}?flash=Execution+disabled:+no+engagement+configured",
                                status_code=303)
    # Adaptive follow-ups are generated and run without a human reading them,
    # so the destructive exclusion is inherited from this run's setting rather
    # than being independently switchable: a tester who kept write probes out
    # of a reviewed plan did not thereby consent to unreviewed ones.
    budget = AdaptiveBudget(allow_destructive=include_destructive) if adaptive else None
    job, created = _create_operation_job(aid, "execute", idempotency_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Existing job {job.job_id}: {job.state}')}",
            status_code=303,
        )
    try:
        execs = await _run_operation_job(
            job,
            partial(
                state.orch.execute, aid, base_url, eng.scope, eng.vault,
                settings_with_overrides(eng.runner),
                include_destructive=include_destructive, adaptive=budget,
            ),
        )
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



# -- re-running a single execution -------------------------------------------
#
# Called by fetch() from the report's Execution Log, so it answers JSON: the
# report is a standalone document that must not navigate away to settle one
# undecided row. The execution id travels in the form body rather than the path
# because it contains "#" (the run tag), which is a fragment delimiter in a URL
# and never reaches the server intact from a hand-built link.


@app.post("/assessment/{aid}/execution/rerun")
async def rerun_execution(aid: str, execution_id: str = Form(...),
                          environment: str = Form(""), confirm: str = Form(""),
                          user: User = Depends(require("tester")),
                          idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    assessment = state.repo.get_assessment(aid)
    if not assessment:
        return JSONResponse({"ok": False, "error": "Assessment not found."}, status_code=404)

    eng = state.engagement
    # Default to the target this assessment actually ran against — re-running a
    # request against a different environment answers a different question. A
    # name that is not configured is refused rather than quietly falling back:
    # silently sending to a different host than the caller named is the one
    # outcome worse than not sending at all.
    base_url = ""
    if environment:
        base_url = eng.environments.get(environment, "")
        if not base_url:
            return JSONResponse(
                {"ok": False, "error": f"No environment named {environment!r} is configured."},
                status_code=409,
            )

    # The destructive speed bump is a UI policy (type the issue key), so it is
    # checked here where the issue key lives; the orchestrator keeps the hard
    # gate and refuses without an explicit confirmation either way.
    confirmed = confirm.strip() == assessment.issue_key

    job, created = _create_operation_job(aid, "rerun_execution", idempotency_key)
    if not created:
        return JSONResponse({"ok": job.state == "SUCCEEDED", "job_id": job.job_id,
                             "state": job.state, "duplicate": True}, status_code=200)

    try:
        original, replay = await _run_operation_job(
            job,
            partial(
                state.orch.rerun_execution, aid, execution_id, eng.scope, eng.vault,
                settings_with_overrides(eng.runner), base_url=base_url,
                confirm_destructive=confirmed, actor=user.name,
            ),
        )
    except Orchestrator.RerunRefused as exc:
        return JSONResponse(
            {"ok": False, "error": str(exc), "issue_key": assessment.issue_key},
            status_code=409,
        )
    except Exception as exc:
        headline, hint = _execute_error(base_url or assessment.target_base_url, exc)
        return JSONResponse(
            {"ok": False, "error": f"{headline} {html.unescape(_strip_tags(hint))}".strip()},
            status_code=400,
        )

    response = replay.response
    return JSONResponse({
        "ok": True,
        "test_id": replay.test_id,
        "execution_id": replay.execution_id,
        "previous_result": original.verdict.result.value,
        "result": replay.verdict.result.value,
        "confidence": replay.verdict.confidence.value,
        "reason": replay.verdict.reason,
        "status_code": response.status_code if response else None,
        "elapsed_ms": response.elapsed_ms if response else None,
        "changed": replay.verdict.result.value != original.verdict.result.value,
    })


def _strip_tags(markup: str) -> str:
    """The error hints in this module are small HTML fragments; a JSON client
    wants the sentence, not the <a href>."""
    return re.sub(r"<[^>]+>", "", markup)


# -- copying one execution as a curl command ----------------------------------
#
# Deliberately live, never baked into the static report: the report's stored
# request is redacted (see redaction.py), so a curl command that actually
# authenticates has to have the persona's real credential resolved from the
# vault at the moment someone clicks Copy — same trust boundary as re-run
# (requires this endpoint, i.e. the running platform, not a saved copy of the
# report). execution_id travels in the form body for the same reason it does
# on rerun: it contains "#", a URL fragment delimiter.


@app.post("/assessment/{aid}/execution/curl")
async def execution_curl(aid: str, execution_id: str = Form(...),
                         user: User = Depends(require("tester"))):
    assessment = state.repo.get_assessment(aid)
    if not assessment:
        return JSONResponse({"ok": False, "error": "Assessment not found."}, status_code=404)

    try:
        curl = state.orch.build_curl(aid, execution_id, state.engagement.vault, actor=user.name)
    except Orchestrator.RerunRefused as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)

    return JSONResponse({"ok": True, "curl": curl})



# -- re-running --------------------------------------------------------------
#
# "Run it again" is a new assessment of the same issue, not a second pass over
# the old one: regression only exists between assessments, and re-running in
# place would rewrite the conclusions attached to evidence that was already
# reported. Two modes, because they answer different questions:
#
#   same     — did anything change on the target? Same plan, same approvals.
#   reimport — the ticket changed; re-read it and analyze from scratch.


@app.post("/assessment/{aid}/rerun")
async def rerun(aid: str, mode: str = Form("same"), environment: str = Form(""),
                user: User = Depends(require("tester"))):
    source = state.repo.get_assessment(aid)
    if not source:
        return RedirectResponse("/?flash=Assessment+not+found", status_code=303)

    if mode == "reimport":
        try:
            new_id = await state.orch.import_and_analyze(source.issue_key)
        except Exception as exc:
            headline, hint = _import_error(source.issue_key, exc)
            return HTMLResponse(views.error_page("Re-import failed", headline, hint),
                                status_code=400)
        return RedirectResponse(
            f"/assessment/{new_id}?flash={quote('Re-imported ' + source.issue_key + ' — design a plan')}",
            status_code=303,
        )

    new_id = state.orch.clone_for_rerun(aid, actor=user.name)
    eng = state.engagement
    base_url = eng.environments.get(environment or eng.active_environment, eng.target_base_url)

    # A re-run stops short of executing when it would be pointless or unsafe, and
    # says why on the new assessment rather than reporting a run that never
    # happened. The new plan is already sitting there for the tester to fix and
    # run themselves.
    approved = state.repo.query_test_cases(new_id, appr="APPROVED", per=1)["total"]
    readiness = preflight.evaluate(eng, state.engagement_path)
    if not base_url:
        return _rerun_landing(new_id, "Cloned the plan. Execution is disabled: no "
                                      "environment is configured.")
    if not approved:
        return _rerun_landing(new_id, "Cloned the plan. Nothing ran: no test in it was "
                                      "approved.")
    if readiness.n_blocking:
        return _rerun_landing(new_id, f"Cloned the plan. Nothing ran: "
                                      f"{readiness.n_blocking} blocking configuration "
                                      f"issue(s).")

    try:
        # Destructive tests are never carried into an automatic re-run. Approving a
        # write probe once, for a run you watched, is not consent to it firing
        # again from a button on a list page.
        execs = state.orch.execute(new_id, base_url, eng.scope, eng.vault,
                                   settings_with_overrides(eng.runner),
                                   include_destructive=False)
    except Exception as exc:
        headline, hint = _execute_error(base_url, exc)
        return HTMLResponse(
            views.error_page("Re-run failed", headline, hint,
                             back_href=f"/assessment/{new_id}",
                             back_label="← Back to the new assessment"),
            status_code=400,
        )

    n_fail = sum(1 for ex in execs if ex.verdict.result.value == "FAIL")
    flash = f"Re-ran {len(execs)} test(s), {n_fail} FAIL"
    return RedirectResponse(
        f"/assessment/{new_id}/regression?flash={quote(flash)}", status_code=303
    )


def _rerun_landing(new_id: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"/assessment/{new_id}?flash={quote(message)}", status_code=303)


@app.get("/assessment/{aid}/report", response_class=HTMLResponse)
async def report(aid: str) -> str:
    return state.orch.build_report_html(aid, lang=i18n.get_lang())


@app.get("/assessment/{aid}/export.html")
async def export_html(aid: str):
    # Exported/downloaded copy: freeze it in whichever language the operator
    # was viewing, same as the live report at the moment they clicked export.
    html = state.orch.build_report_html(aid, lang=i18n.get_lang())
    return Response(html, media_type="text/html",
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
async def regression(aid: str, flash: str = "") -> str:
    from app.pipeline.history import render_diff_comment

    diff, prev_id = state.orch.regression_diff(aid)
    a = state.repo.get_assessment(aid)
    # A re-run lands here rather than on the assessment page: "what changed since
    # last time" is the question it was started to answer.
    return views.regression_page(aid, a.issue_key, prev_id, diff,
                                 render_diff_comment(a.issue_key, diff), flash=flash)


@app.get("/assessment/{aid}/comment", response_class=HTMLResponse)
async def comment_preview(aid: str) -> str:
    a = state.repo.get_assessment(aid)
    return views.comment_preview_page(aid, a.issue_key, state.orch.comment_preview(aid))


@app.post("/assessment/{aid}/comment")
async def comment_post(aid: str, user: User = Depends(require("tester")),
                       idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    a = state.repo.get_assessment(aid)
    preview = state.orch.comment_preview(aid)
    stable_key = idempotency_key or hashlib.sha256(preview.encode("utf-8")).hexdigest()
    job, created = _create_operation_job(aid, "jira_comment", stable_key)
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
        headline, hint = _comment_error(a.issue_key if a else aid, exc)
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


# -- JSON API (automation) --------------------------------------------------


@app.get("/api/jobs/{job_id}")
async def api_job(job_id: str, user: User = Depends(require("viewer"))):
    job = state.repo.get_job(job_id)
    if job is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return job.model_dump(mode="json")


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
