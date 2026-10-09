"""The read-only MCP server: protocol shape, tool results, and what it refuses."""

from __future__ import annotations

import io
import json

import pytest
from starlette.testclient import TestClient

from app.mcp.server import TOOLS, PlatformTools, handle, serve


@pytest.fixture()
def tools(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"dev": "https://api.acme.test"}, "active_environment": "dev",
        "scope": {"allowed_hosts": ["api.acme.test"]},
        "attacker": "agent_A", "victim": "agent_B",
        "personas": [{"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
                     {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}}],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'mcp.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app, state

    with TestClient(app) as client:
        aid = client.post("/import", data={"issue_key": "CRM-1234"},
                          follow_redirects=True).url.path.rsplit("/", 1)[-1]
        client.post(f"/assessment/{aid}/design")
        yield PlatformTools(state.repo, state.orch), aid, state


def _call(tools, name, **arguments):
    reply = handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}}, tools)
    assert reply["id"] == 7
    return reply["result"]


def test_initialize_echoes_the_protocol_and_declares_tools(tools):
    t, _, _ = tools
    reply = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26"}}, t)
    assert reply["result"]["protocolVersion"] == "2025-03-26"
    assert "tools" in reply["result"]["capabilities"]
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, t) is None


def test_only_read_tools_are_offered():
    names = {tool["name"] for tool in TOOLS}
    assert names == {"list_assessments", "get_assessment", "list_findings", "get_copilot_brief"}
    for forbidden in ("execute", "approve", "run", "post", "delete"):
        assert not any(forbidden in n for n in names)


def test_list_and_get_assessment(tools):
    t, aid, _ = tools
    listed = _call(t, "list_assessments", limit=5)
    assert listed["isError"] is False
    items = listed["structuredContent"]["items"]
    assert items[0]["assessment_id"] == aid and items[0]["tests"] > 0

    one = _call(t, "get_assessment", assessment_id=aid)["structuredContent"]
    assert one["issue_key"] == "CRM-1234" and one["endpoints"]


def test_copilot_brief_can_be_built_and_read_back(tools):
    t, aid, state = tools
    empty = _call(t, "get_copilot_brief", assessment_id=aid)["structuredContent"]
    assert "refresh=true" in empty["note"]
    built = _call(t, "get_copilot_brief", assessment_id=aid, refresh=True)["structuredContent"]
    assert built["source"] == "deterministic"
    assert any(a.actor == "mcp" and a.action == "copilot_brief" for a in state.repo.get_audit(aid))


def test_unknown_assessment_and_tool_are_tool_errors_not_crashes(tools):
    t, _, _ = tools
    assert _call(t, "get_assessment", assessment_id="A-nope")["isError"] is True
    assert _call(t, "execute_tests", assessment_id="x")["isError"] is True
    assert _call(t, "get_assessment", bogus=1)["isError"] is True


def test_another_engagement_cannot_see_the_assessment(tools):
    t, aid, state = tools
    fenced = PlatformTools(state.repo, state.orch, engagement="someone-else")
    assert _call(fenced, "get_assessment", assessment_id=aid)["isError"] is True
    assert _call(fenced, "list_assessments")["structuredContent"]["items"] == []


def test_the_stdio_loop_answers_line_by_line(tools, monkeypatch):
    t, _, _ = tools
    monkeypatch.setattr("app.mcp.server.build_tools", lambda: t)
    out = io.StringIO()
    serve(io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\nnot json\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["result"]["tools"] and lines[1]["error"]["code"] == -32700
