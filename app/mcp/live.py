"""Live Jira MCP client (official MCP Python SDK).

Talks to an MCP server (e.g. Atlassian's) over Streamable HTTP and maps tool
results into NormalizedIssue via the tested `normalize_issue`. The SDK is a lazy
/ optional import so the platform still runs offline with the mock client.

Integration requires live credentials and a running MCP server, so the I/O layer
here is intentionally thin — all the parsing logic lives in normalize.py where it
is unit-tested. Configure via env:
    JIRA_MCP_URL     Streamable-HTTP endpoint of the MCP server
    JIRA_CLOUD_ID    Atlassian cloud id (from getAccessibleAtlassianResources)
    JIRA_MCP_TOKEN   OAuth access token, sent as `Authorization: Bearer …`
    JIRA_MCP_HEADERS Extra headers as a JSON object, for servers that want
                     something other than a bearer token
    JIRA_TOOL_GET / JIRA_TOOL_SEARCH / JIRA_TOOL_COMMENT  (tool-name overrides)
    JIRA_SITE_URL    Human browse URL, e.g. https://yourcompany.atlassian.net —
                     JIRA_CLOUD_ID is a UUID the MCP transport uses, not a
                     hostname, so it can't build a clickable link on its own

The token is read from the environment and never persisted or logged — the
platform's redaction layer only covers what it stores, so credentials must not
land in engagement.json or a report.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from app.mcp.jira import NormalizedIssue
from app.mcp.normalize import normalize_issue

logger = logging.getLogger(__name__)


class LiveJiraMCPClient:
    def __init__(
        self,
        url: str | None = None,
        cloud_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = url or os.getenv("JIRA_MCP_URL", "")
        self._cloud_id = cloud_id or os.getenv("JIRA_CLOUD_ID", "")
        self._headers = headers if headers is not None else _headers_from_env()
        self._tool_get = os.getenv("JIRA_TOOL_GET", "getJiraIssue")
        self._tool_search = os.getenv("JIRA_TOOL_SEARCH", "searchJiraIssuesUsingJql")
        self._tool_comment = os.getenv("JIRA_TOOL_COMMENT", "addCommentToJiraIssue")
        self._site_url = os.getenv("JIRA_SITE_URL", "").rstrip("/")
        self._session = None
        self._ctx = None
        self._http_client = None  # only set on SDK 2.x, where we own the client
        self._runner = None  # task that owns the transport for its whole life
        self._stop = None  # set to ask that task to shut the transport down

    @staticmethod
    def is_configured() -> bool:
        return bool(os.getenv("JIRA_MCP_URL"))

    def describe(self) -> str:
        """Non-secret one-liner for the UI. Never includes the token."""
        auth = "bearer token" if "Authorization" in self._headers else "no auth header"
        return f"live MCP {self._url} (cloud {self._cloud_id or '?'}, {auth})"

    async def connect(self) -> None:
        # Lazy import: the SDK is optional. Absence is a clear, actionable error
        # rather than an import failure at module load.
        try:
            from mcp.client.session import ClientSession
            from mcp.client import streamable_http as transport
        except ImportError as exc:  # pragma: no cover - depends on optional dep
            raise RuntimeError(
                "Live Jira MCP requires the 'mcp' package: pip install mcp"
            ) from exc

        # The streamable-HTTP factory differs across SDK generations: 2.x renamed
        # it and moved headers onto a pre-built httpx client, 1.x took `headers=`
        # directly. Support both rather than pinning one, and say so plainly if
        # neither is present — "package missing" and "package incompatible" are
        # different problems and used to report as the same message.
        if hasattr(transport, "streamable_http_client"):  # SDK 2.x
            self._http_client = transport.create_mcp_http_client(headers=self._headers)
            self._ctx = transport.streamable_http_client(
                self._url, http_client=self._http_client
            )
        elif hasattr(transport, "streamablehttp_client"):  # SDK 1.x
            self._ctx = transport.streamablehttp_client(self._url, headers=self._headers)
        else:  # pragma: no cover - unknown future SDK
            import importlib.metadata as md

            raise RuntimeError(
                f"Installed 'mcp' package ({md.version('mcp')}) exposes no "
                f"streamable-HTTP client factory this connector understands"
            )

        # The transport is entered, held and exited inside one dedicated task,
        # never by the caller. anyio binds a cancel scope to the task that
        # entered it, and the SDK's streamable-HTTP client and ClientSession are
        # both built on one; enter them in a task that then ends — a request
        # handler — and anyio raises "Attempted to exit a cancel scope that
        # isn't the current task's" as that task unwinds, failing the request
        # even though the handshake itself succeeded. That is what made
        # Reconnect / Refresh token answer 500 while the boot-time connection
        # (whose task, the ASGI lifespan, happens to live as long as the app)
        # worked fine. Owning the connection in its own task makes both paths
        # the same, and makes close() the only way it ever comes down.
        self._stop = asyncio.Event()
        ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._runner = asyncio.create_task(
            self._serve(ClientSession, ready), name=f"jira-mcp:{self._url}"
        )
        try:
            await ready
        except BaseException as exc:
            await self.close()  # reap the runner before reporting the failure
            if isinstance(exc, Exception):
                raise await self._explain(exc) from exc
            raise  # cancellation / KeyboardInterrupt is not ours to reinterpret

    async def _serve(self, ClientSession, ready: asyncio.Future) -> None:
        """Hold the transport open until close() asks for it back.

        Resolves `ready` as soon as the handshake lands, so connect() reports a
        rejected token as its own error rather than leaving a task to fail in
        the background.
        """
        try:
            # 1.x yielded (read, write, get_session_id); 2.x yields (read, write).
            async with self._ctx as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    self._session = session
                    ready.set_result(None)
                    await self._stop.wait()
        except BaseException as exc:
            # Before the handshake: connect()'s error to raise. After it: the
            # connection dropped under us and nobody is waiting on `ready` to be
            # told, so log it — otherwise the only trace is the "Not connected"
            # error the next call happens to raise.
            if not ready.done():
                ready.set_exception(exc)
            else:
                logger.debug("live Jira MCP transport ended: %r", exc)
        finally:
            self._session = None
            if self._http_client is not None:
                # We built it, so we close it — the transport only owns the
                # client it creates itself.
                try:
                    await self._http_client.aclose()
                except BaseException:
                    pass
                self._http_client = None
            if not ready.done():  # `async with` returned without initialize()
                ready.set_exception(RuntimeError("Jira MCP transport closed during connect"))

    async def _explain(self, exc: Exception) -> Exception:
        """Re-raise a failed handshake with the HTTP status attached.

        The SDK turns every non-2xx except 404 into the JSON-RPC stand-in
        "Server returned an error response" — the status code, the only part an
        operator can act on, never reaches us. An expired token and an
        unreachable server therefore read identically, and the banner sends
        people to press "Refresh Token" over and over for what may not be a
        token problem at all. One extra request on the failure path buys the
        real answer.
        """
        status = await self._probe_status()
        if status is None:
            return exc
        hint = {
            401: "JIRA_MCP_TOKEN is expired or rejected — Atlassian's MCP tokens "
                 "last about an hour; press \"Refresh Token\" in Settings → Jira Connector",
            403: "the token authenticates but is not allowed here — check its "
                 "scopes (read:jira-work / write:jira-work) and site access",
            404: f"no MCP endpoint at {self._url} — check JIRA_MCP_URL",
        }.get(status, "see the server's response for details")
        return RuntimeError(f"Jira MCP handshake failed: HTTP {status} — {hint}")

    async def _probe_status(self) -> int | None:
        """HTTP status the MCP endpoint answers an `initialize` with, or None if
        the probe itself could not get an answer (in which case the original
        error is already the better description)."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=8) as client:
                response = await client.post(
                    self._url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "sectest-probe", "version": "0"},
                        },
                    },
                    headers={
                        "Accept": "application/json, text/event-stream",
                        **self._headers,
                    },
                )
        except Exception:
            return None
        return response.status_code if response.status_code >= 400 else None

    async def test_connection(self) -> bool:
        if not self._session:
            return False
        await self._session.list_tools()
        return True

    async def get_issue(self, issue_key: str) -> NormalizedIssue:
        raw = await self._call_tool(
            self._tool_get,
            {"cloudId": self._cloud_id, "issueIdOrKey": issue_key},
        )
        # A missing issue comes back as an empty/keyless payload. Raise the same
        # KeyError the mock raises so callers handle one contract, and so we
        # never create an assessment with a blank issue key.
        if not raw or not raw.get("key"):
            raise KeyError(
                f"Unknown issue {issue_key}: Jira MCP returned no issue "
                f"(check the key, the cloud id, and the token's project access)"
            )
        issue = normalize_issue(raw)
        if issue.attachments:
            issue.attachments_complete = False
            issue.completeness_warnings.append(
                "The Jira MCP connector listed attachments but cannot download their content."
            )
        return issue

    async def list_project_issues(self, project_key: str) -> list[NormalizedIssue]:
        raw = await self._call_tool(
            self._tool_search,
            {"cloudId": self._cloud_id, "jql": f"project = {project_key} ORDER BY updated DESC"},
        )
        issues = raw.get("issues", raw if isinstance(raw, list) else [])
        return [normalize_issue(i) for i in issues]

    async def get_comments(self, issue_key: str) -> list[str]:
        return (await self.get_issue(issue_key)).comments

    async def add_comment(self, issue_key: str, comment: str) -> None:
        await self._call_tool(
            self._tool_comment,
            {"cloudId": self._cloud_id, "issueIdOrKey": issue_key, "commentBody": comment},
        )

    async def get_attachments(self, issue_key: str) -> list[bytes]:
        return []

    def browse_url(self, issue_key: str) -> str | None:
        return f"{self._site_url}/browse/{issue_key}" if self._site_url else None

    async def close(self) -> None:
        """Ask the runner task to unwind, and wait for it.

        Safe to call from any task and more than once — the teardown itself
        happens inside _serve, in the task that opened the transport, which is
        the only place anyio permits it.
        """
        runner, self._runner = self._runner, None
        if self._stop is not None:
            self._stop.set()
        if runner is not None and not runner.done():
            try:
                await asyncio.wait_for(asyncio.shield(runner), timeout=10)
            except TimeoutError:
                # A wedged transport must not hold up a shutdown or a reconnect.
                runner.cancel()
            except BaseException:
                pass  # _serve already reported anything worth reporting
        self._session = self._ctx = self._stop = None

    # -- internals ----------------------------------------------------------

    async def _call_tool(self, name: str, arguments: dict) -> dict:  # pragma: no cover - live only
        if not self._session:
            raise RuntimeError("Not connected. Call connect() first.")
        result = await self._session.call_tool(name, arguments)
        return _parse_tool_result(result)


def _headers_from_env() -> dict[str, str]:
    """Auth headers for the MCP transport, from env only.

    JIRA_MCP_HEADERS (JSON object) wins over JIRA_MCP_TOKEN for the same header,
    so an instance wanting a non-bearer scheme can override cleanly. A malformed
    JSON blob is a configuration error worth failing loudly on — silently
    sending no auth would surface later as a confusing empty-issue error.
    """
    headers: dict[str, str] = {}
    token = os.getenv("JIRA_MCP_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw = os.getenv("JIRA_MCP_HEADERS", "").strip()
    if raw:
        try:
            extra = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"JIRA_MCP_HEADERS is not valid JSON: {exc}") from exc
        if not isinstance(extra, dict):
            raise RuntimeError("JIRA_MCP_HEADERS must be a JSON object")
        headers.update({str(k): str(v) for k, v in extra.items()})
    return headers


def _parse_tool_result(result) -> dict:
    """Extract a JSON object from an MCP tool result's content blocks.

    Separated out (and tolerant of plain dicts) so it can be unit-tested with a
    stub result without a live server.
    """
    if isinstance(result, dict):
        return result
    content = getattr(result, "content", None) or []
    for block in content:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                continue
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    return {}
