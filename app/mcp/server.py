"""A read-only MCP server over stdio: the platform, as tools for another agent.

Run it from an MCP client's config:

    {"command": "python", "args": ["-m", "app.mcp.server"],
     "cwd": "<this repo>", "env": {"DATABASE_URL": "sqlite:///sectest.db"}}

What an agent can do here is READ: list assessments, read one, read its
findings, and read (or rebuild) its Copilot brief. Nothing here sends a request
to a target, approves a test, starts a run or posts to Jira — those stay behind
the web UI's role checks and a human. A Copilot refresh writes one advisory
record and, with USE_AI on, spends one CLI call; it is still not traffic.

Implemented directly on the protocol (newline-delimited JSON-RPC 2.0) rather
than the optional MCP SDK: the surface is four tools, and a server that works
without an optional dependency is one fewer thing to break.

`MCP_ENGAGEMENT` limits every tool to one engagement's assessments, the same
isolation the web UI applies per user.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import sys
from typing import Any

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "sentinel-security-testing", "version": "1.0.0"}

TOOLS = [
    {
        "name": "list_assessments",
        "description": "List assessments, newest first, with test/finding counts.",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25}}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "get_assessment",
        "description": "One assessment: endpoints, plan counts, verdict counts, coverage.",
        "inputSchema": {"type": "object", "required": ["assessment_id"], "properties": {
            "assessment_id": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "list_findings",
        "description": "Confirmed findings for one assessment (no captured bodies or credentials).",
        "inputSchema": {"type": "object", "required": ["assessment_id"], "properties": {
            "assessment_id": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "get_copilot_brief",
        "description": ("The Copilot's hypotheses and next steps for one assessment. "
                        "refresh=true rebuilds it (advisory only; sends nothing to the target)."),
        "inputSchema": {"type": "object", "required": ["assessment_id"], "properties": {
            "assessment_id": {"type": "string"},
            "refresh": {"type": "boolean", "default": False},
            "question": {"type": "string", "maxLength": 1000}}},
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]


class ToolError(Exception):
    """Reported to the client as a tool result with isError, not a crash."""


class PlatformTools:
    def __init__(self, repo, orchestrator, engagement: str = "") -> None:
        self._repo = repo
        self._orch = orchestrator
        self._engagement = engagement

    def _assessment(self, aid: str):
        a = self._repo.get_assessment(str(aid or ""))
        if a is None or (self._engagement and self._repo.assessment_engagement(a.id) != self._engagement):
            raise ToolError(f"No assessment {aid!r}")
        return a

    def list_assessments(self, limit: int = 25) -> list[dict]:
        out = []
        for a in self._repo.list_assessments():
            if self._engagement and self._repo.assessment_engagement(a.id) != self._engagement:
                continue
            summary = self._repo.assessment_summary(a.id)
            out.append({"assessment_id": a.id, "issue_key": a.issue_key, "status": a.status,
                        "tests": summary["n_tests"], "approved": summary["n_approved"],
                        "executions": summary["n_executions"], "findings": summary["severities"]})
            if len(out) >= max(1, min(200, int(limit or 25))):
                break
        return out

    def get_assessment(self, assessment_id: str) -> dict:
        a = self._assessment(assessment_id)
        analysis = a.analysis_json or {}
        return {
            "assessment_id": a.id, "issue_key": a.issue_key, "status": a.status,
            "business_summary": analysis.get("business_summary", ""),
            "endpoints": [f"{str(e.get('method', '')).upper()} {e.get('path', '')}"
                          for e in analysis.get("endpoints") or []],
            "plan": self._repo.assessment_summary(a.id),
            "verdicts": self._repo.execution_verdicts(a.id),
            "coverage": [{"category": r.get("category"), "state": r.get("state")}
                         for r in a.coverage_json or [] if r.get("applicable")],
        }

    def list_findings(self, assessment_id: str) -> list[dict]:
        a = self._assessment(assessment_id)
        return [{"finding_id": f.finding_id, "severity": f.severity.value, "title": f.title,
                 "owasp": f.owasp_category.value, "endpoint": f.endpoint,
                 "confidence": f.confidence.value, "impact": f.impact,
                 "recommendation": f.recommendation}
                for f in self._repo.get_findings(a.id)]

    def get_copilot_brief(self, assessment_id: str, refresh: bool = False,
                          question: str = "") -> dict:
        a = self._assessment(assessment_id)
        if refresh or question:
            try:
                brief = self._orch.copilot_brief(a.id, question=str(question or "")[:1000],
                                                 actor="mcp")
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
        else:
            brief = self._orch.latest_copilot(a.id)
            if brief is None:
                return {"note": "No brief yet. Call again with refresh=true."}
        return brief.model_dump(mode="json")

    def call(self, name: str, arguments: dict) -> Any:
        handler = {"list_assessments": self.list_assessments,
                   "get_assessment": self.get_assessment,
                   "list_findings": self.list_findings,
                   "get_copilot_brief": self.get_copilot_brief}.get(name)
        if handler is None:
            raise ToolError(f"Unknown tool {name!r}")
        try:
            inspect.signature(handler).bind(**(arguments or {}))
        except TypeError as exc:
            raise ToolError(f"Bad arguments for {name}: {exc}") from exc
        return handler(**(arguments or {}))


def handle(message: dict, tools: PlatformTools) -> dict | None:
    """One JSON-RPC message in, at most one out (notifications get none)."""
    method = message.get("method")
    msg_id = message.get("id")
    if msg_id is None:
        return None  # a notification, e.g. notifications/initialized

    def ok(result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    if method == "initialize":
        requested = (message.get("params") or {}).get("protocolVersion") or PROTOCOL_VERSION
        return ok({"protocolVersion": requested, "serverInfo": SERVER_INFO,
                   "capabilities": {"tools": {"listChanged": False}},
                   "instructions": "Read-only access to API security assessments. "
                                   "Nothing here sends traffic to a target."})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params") or {}
        try:
            result = tools.call(str(params.get("name", "")), params.get("arguments") or {})
            return ok({"content": [{"type": "text",
                                    "text": json.dumps(result, ensure_ascii=False, default=str)}],
                       "structuredContent": result if isinstance(result, dict) else {"items": result},
                       "isError": False})
        except ToolError as exc:
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})
        except Exception as exc:  # noqa: BLE001 - never kill the session on one bad call
            logger.exception("mcp tool %s failed", params.get("name"))
            return ok({"content": [{"type": "text", "text": f"{type(exc).__name__}"}],
                       "isError": True})
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


def build_tools() -> PlatformTools:
    from app.database import Repository, init_db, make_engine, make_session_factory
    from app.orchestrator import Orchestrator

    engine = make_engine()
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    return PlatformTools(repo, Orchestrator(repo, jira_client=None),
                         engagement=os.getenv("MCP_ENGAGEMENT", "").strip())


def serve(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    tools = build_tools()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "Parse error"}}
        else:
            reply = handle(message, tools) if isinstance(message, dict) else None
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False, default=str) + "\n")
            stdout.flush()


if __name__ == "__main__":  # pragma: no cover
    # Logs go to stderr: stdout is the protocol channel.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    serve()
