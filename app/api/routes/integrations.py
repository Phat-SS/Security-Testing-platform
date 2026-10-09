"""The Jira MCP connector: reconnecting it, and refreshing its token.

Kept out of `config.py` because these two do something the other config routes
never do — they reach outside the process (an OAuth login in the operator's
browser, an MCP handshake) and have to degrade to a readable message rather
than hang or 500.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends
from fastapi.responses import (
    RedirectResponse,
)

from app.api.deps import require
from app.api.routes.config import config_redirect
from app.api.runtime import state
from app.core import preflight
from app.core.auth import User
from app.mcp import MockJiraMCPClient, build_jira_client, describe_jira_client

logger = logging.getLogger(__name__)

router = APIRouter()


async def close_quietly(client) -> None:
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
        await close_quietly(previous)
        return RedirectResponse(
            f"/config?tab=advanced&error={quote(state.jira_warning, safe='')}", status_code=303
        )
    state.jira_warning = ""
    state._rebind_jira(new_client)
    await close_quietly(previous)
    return config_redirect("mcp", f"Reconnected — {describe_jira_client(new_client)}")


@router.post("/config/mcp/jira/reconnect")
async def mcp_jira_reconnect_route(user: User = Depends(require("tester"))):
    return await _reconnect_jira()


@router.post("/config/mcp/jira/refresh-token")
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
    # No shell: an argv list reaches npx with the URL as one argument, so a
    # quote or metacharacter in JIRA_MCP_URL cannot become a second command.
    # On Windows the .cmd shim still runs (CreateProcess hands it to cmd), and
    # cmd would still interpret metacharacters inside an argument, so the URL
    # is held to plain https URL characters first.
    if not re.fullmatch(r"https://[A-Za-z0-9._~:/?#\[\]@=+-]+", mcp_url):
        return RedirectResponse(
            "/config?tab=advanced&error=" + quote(
                "JIRA_MCP_URL must be a plain https:// URL.", safe=""),
            status_code=303,
        )
    try:
        proc = subprocess.Popen(
            [npx, "-y", "mcp-remote", mcp_url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
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
