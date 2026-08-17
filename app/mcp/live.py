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

import json
import os

from app.mcp.jira import NormalizedIssue
from app.mcp.normalize import normalize_issue


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

        try:
            # 1.x yielded (read, write, get_session_id); 2.x yields (read, write).
            streams = await self._ctx.__aenter__()
            self._session = ClientSession(streams[0], streams[1])
            await self._session.__aenter__()
            await self._session.initialize()
        except BaseException as exc:
            # A half-open transport must be unwound here, in the task that opened
            # it. Left to the garbage collector it is resumed from a different
            # task and anyio raises "Attempted to exit cancel scope in a
            # different task", which surfaces at app shutdown and buries the real
            # cause (usually a rejected token).
            await self._unwind(exc)
            raise

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
        return normalize_issue(raw)

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

    async def close(self) -> None:  # pragma: no cover - live only
        await self._unwind(None)

    async def _unwind(self, exc: BaseException | None) -> None:
        """Tear down session → transport → http client, innermost first.

        Best-effort: a teardown error must never replace the error that caused
        the teardown. Passing `exc` on lets the transport's task group cancel as
        if the failure had propagated through the `async with` normally.
        """
        info = (type(exc), exc, exc.__traceback__) if exc else (None, None, None)
        for ctx in (self._session, self._ctx):
            if ctx is not None:
                try:
                    await ctx.__aexit__(*info)
                except BaseException:
                    pass
        if self._http_client is not None:
            # We built it, so we close it — the transport only owns the client it
            # creates itself.
            try:
                await self._http_client.aclose()
            except BaseException:
                pass
        self._session = self._ctx = self._http_client = None

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
