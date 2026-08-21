"""LiveJiraMCPClient.connect() error reporting.

The MCP SDK collapses every non-2xx except 404 into the JSON-RPC stand-in
"Server returned an error response", so the HTTP status — the only part an
operator can act on — never reaches the caller. `_explain` re-asks the endpoint
once on the failure path and turns that into a message that names the fix.

Sync tests driving asyncio.run, matching the rest of the suite: no
pytest-asyncio plugin is configured.
"""

import asyncio

from app.mcp.live import LiveJiraMCPClient


def _client(monkeypatch, url="https://mcp.example/v1/mcp"):
    monkeypatch.setenv("JIRA_MCP_URL", url)
    monkeypatch.setenv("JIRA_MCP_TOKEN", "tok")
    monkeypatch.delenv("JIRA_MCP_HEADERS", raising=False)
    return LiveJiraMCPClient()


def _explain(monkeypatch, exc, status, url="https://mcp.example/v1/mcp"):
    client = _client(monkeypatch, url=url)

    async def probe():
        return status

    monkeypatch.setattr(client, "_probe_status", probe)
    return asyncio.run(client._explain(exc))


def test_explain_names_the_expired_token_on_401(monkeypatch):
    message = str(
        _explain(monkeypatch, RuntimeError("Server returned an error response"), 401)
    )

    assert "401" in message
    assert "JIRA_MCP_TOKEN" in message
    assert "Refresh token" in message


def test_explain_distinguishes_403_scopes_from_401(monkeypatch):
    message = str(
        _explain(monkeypatch, RuntimeError("Server returned an error response"), 403)
    )

    assert "403" in message
    assert "scopes" in message
    assert "expired" not in message


def test_explain_names_the_url_on_404(monkeypatch):
    message = str(
        _explain(monkeypatch, RuntimeError("Not Found"), 404, url="https://mcp.example/wrong")
    )

    assert "https://mcp.example/wrong" in message
    assert "JIRA_MCP_URL" in message


def test_explain_keeps_the_original_error_when_the_probe_learns_nothing(monkeypatch):
    """A probe that cannot reach the server (or gets a 2xx, i.e. the failure was
    not HTTP-level) must not paper over the real exception."""
    original = RuntimeError("some transport-level failure")

    assert _explain(monkeypatch, original, None) is original


def test_probe_status_returns_none_when_unreachable(monkeypatch):
    """No live server here: the probe must swallow its own failure rather than
    replace the connect error with a connection error of its own."""
    client = _client(monkeypatch, url="http://127.0.0.1:1/mcp")

    assert asyncio.run(client._probe_status()) is None
