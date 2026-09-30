"""FastAPI app — the platform UI + JSON API.

Wires the orchestrator to a web workflow: import → analyze → design → approve →
execute → report → Jira comment. Server-rendered HTML (no frontend build). The
same routes back a small JSON API for automation.

This module is now only the assembly: lifespan, the error handler, the
middleware stack and the routers. The handlers themselves live in
`app/api/routes/`, the shared state in `app/api/runtime.py`, and the
dependencies in `app/api/deps.py`.

Run:  uvicorn app.api.main:app --reload
"""

from __future__ import annotations

import html
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from app.api import middleware, routes, runtime, views
from app.api.routes.integrations import close_quietly
from app.api.runtime import State, state  # noqa: F401  (re-exported: see below)
from app.core import preflight
from app.core.logging_config import configure_error_tracking, configure_logging
from app.mcp import MockJiraMCPClient
from app.orchestrator import Orchestrator

logger = logging.getLogger(__name__)

# `from app.api.main import state` stays the way to reach the running state —
# it is what the tests use, and what every doc and script referred to before
# the split. `runtime.state` is the same object; see its docstring for why it
# is a proxy rather than a plain module global.


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
    st = runtime.init()
    if not st.auth.enabled:
        logger.warning(
            "AUTH_ENABLED is off: every request is the built-in admin. Keep this "
            "bound to loopback, or set AUTH_ENABLED=true before exposing it."
        )
    orphaned = st.repo.fail_orphaned_jobs(
        "The server restarted while this job was running; it did not finish."
    )
    if orphaned:
        logger.warning("settled %d job(s) left running by a previous process", orphaned)
    try:
        await st.jira.connect()
    except Exception as exc:
        # A misconfigured or unreachable live MCP server must not take the whole
        # platform down — everything except Jira import still works offline.
        # Fall back to the mock and say so in the UI rather than failing to boot.
        if isinstance(st.jira, MockJiraMCPClient):
            raise
        st.jira_warning = (
            f"Live Jira MCP unavailable ({type(exc).__name__}: {exc}) — using the offline mock."
        )
        fallback = MockJiraMCPClient()
        await fallback.connect()
        st._rebind_jira(fallback)
    yield
    # Shut the connector down in the task that owns it. See close_quietly.
    await close_quietly(st.jira)


def create_app() -> FastAPI:
    app = FastAPI(title="AI-assisted API Security Testing Platform", lifespan=lifespan)

    @app.exception_handler(Orchestrator.UnknownAssessment)
    async def _unknown_assessment(request: Request, exc: Orchestrator.UnknownAssessment):
        """A mistyped id is a wrong address, not a server fault.

        Registered once for the whole app rather than caught in each of the
        eight routes that load an assessment: every one of them read a field off
        the row immediately, so an unknown id was an AttributeError, a 500, and
        a stack trace in front of someone who mistyped a URL.
        """
        aid = html.escape(str(exc.args[0]) if exc.args else "")
        return HTMLResponse(
            views.error_page(
                "No such assessment",
                f"There is no assessment {aid}.",
                "Check the link, or pick it from the list.",
                back_href="/", back_label="← All assessments",
            ),
            status_code=404,
        )

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

    middleware.register(app)
    routes.register(app)
    return app


app = create_app()
