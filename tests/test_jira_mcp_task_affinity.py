"""The live Jira MCP transport must live in exactly one task.

anyio binds a cancel scope to the task that entered it, and both the SDK's
streamable-HTTP client and ClientSession are built on one. Enter them in a task
that then ends — a FastAPI request handler — and anyio raises "Attempted to exit
a cancel scope that isn't the current task's" as that task unwinds, so
POST /config/mcp/jira/reconnect answered 500 even when the handshake had just
succeeded. LiveJiraMCPClient therefore hands the transport to a dedicated runner
task; connect() and close() only signal it.

These tests substitute fakes for the SDK so the invariant is checked without a
server: each fake records which task ran each half of its `async with`.
"""

import asyncio

import pytest

# The live connector's SDK is optional (commented out in requirements.txt).
pytest.importorskip("mcp")

from app.mcp.live import LiveJiraMCPClient


class _FakeHTTPClient:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _FakeTransport:
    def __init__(self, record: dict) -> None:
        self._record = record

    async def __aenter__(self):
        self._record["entered_in"] = asyncio.current_task()
        return (object(), object())

    async def __aexit__(self, *exc) -> bool:
        self._record["exited_in"] = asyncio.current_task()
        return False


class _FakeSession:
    boom: BaseException | None = None

    def __init__(self, *streams) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def initialize(self) -> None:
        if type(self).boom is not None:
            raise type(self).boom

    async def list_tools(self):
        return []


@pytest.fixture
def wired(monkeypatch):
    """Point LiveJiraMCPClient at the fakes and hand back the recording dict."""
    from mcp.client import session as session_module
    from mcp.client import streamable_http as transport

    record: dict = {}
    monkeypatch.setattr(
        transport, "create_mcp_http_client",
        lambda **kwargs: record.setdefault("http", _FakeHTTPClient()),
    )
    monkeypatch.setattr(
        transport, "streamable_http_client",
        lambda url, http_client=None: _FakeTransport(record),
    )
    monkeypatch.setattr(session_module, "ClientSession", _FakeSession)
    monkeypatch.setattr(_FakeSession, "boom", None)
    monkeypatch.setenv("JIRA_MCP_URL", "https://mcp.example/v1/mcp")
    monkeypatch.setenv("JIRA_MCP_TOKEN", "tok")
    monkeypatch.delenv("JIRA_MCP_HEADERS", raising=False)
    return record


def test_transport_is_entered_and_exited_in_one_task(wired):
    """The regression itself: connecting and closing from two unrelated tasks —
    what two HTTP requests are — must not move the transport's lifetime."""

    async def scenario():
        client = LiveJiraMCPClient()
        await asyncio.create_task(client.connect())  # "request" 1
        assert await client.test_connection()
        await asyncio.create_task(client.close())  # "request" 2

    asyncio.run(scenario())

    assert wired["entered_in"] is not None
    assert wired["exited_in"] is wired["entered_in"]
    # Neither half ran in a caller's task: the runner owns both.
    assert wired["entered_in"].get_name().startswith("jira-mcp:")


def test_close_releases_the_http_client_we_built(wired):
    async def scenario():
        client = LiveJiraMCPClient()
        await client.connect()
        await client.close()

    asyncio.run(scenario())

    assert wired["http"].closed is True


def test_close_is_idempotent_and_safe_before_connect(wired):
    async def scenario():
        client = LiveJiraMCPClient()
        await client.close()  # never connected
        await client.connect()
        await client.close()
        await client.close()

    asyncio.run(scenario())  # must not raise

    assert wired["exited_in"] is wired["entered_in"]


def test_a_rejected_handshake_surfaces_from_connect_and_unwinds(wired, monkeypatch):
    """A 401 has to reach the caller of connect(), not a background task — and
    the transport still has to come down in the task that opened it."""
    monkeypatch.setattr(_FakeSession, "boom", RuntimeError("Server returned an error response"))

    async def _no_probe(self):
        return None  # no live endpoint to ask; keep the original error

    monkeypatch.setattr(LiveJiraMCPClient, "_probe_status", _no_probe)

    async def scenario():
        client = LiveJiraMCPClient()
        with pytest.raises(RuntimeError, match="Server returned an error response"):
            await client.connect()
        assert await client.test_connection() is False

    asyncio.run(scenario())

    assert wired["exited_in"] is wired["entered_in"]
    assert wired["http"].closed is True


def test_a_rejected_handshake_is_explained_with_its_http_status(wired, monkeypatch):
    """End to end through connect(): the opaque SDK error is replaced by the
    status and the fix, which is what the Config → MCP banner shows."""
    monkeypatch.setattr(_FakeSession, "boom", RuntimeError("Server returned an error response"))

    async def _probe(self):
        return 401

    monkeypatch.setattr(LiveJiraMCPClient, "_probe_status", _probe)

    async def scenario():
        client = LiveJiraMCPClient()
        with pytest.raises(RuntimeError, match="HTTP 401"):
            await client.connect()

    asyncio.run(scenario())
