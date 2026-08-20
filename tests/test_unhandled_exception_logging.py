"""An unhandled exception in a route used to have nowhere reliable to land —
whatever uvicorn's own logger happened to do with it, unredacted, un-
structured, easy to lose in production. The global handler in app/api/main.py
logs it through the app's own (redacting) logger and then re-raises so the
response Starlette sends is unchanged; this only adds visibility.
"""

import logging

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'exc.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    # raise_server_exceptions=False: this test wants the HTTP response Starlette
    # actually sends a real client would see, not the exception re-raised into
    # the test process the way TestClient's debugging default would.
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_unhandled_exception_is_logged_with_a_traceback_and_still_returns_500(
    client, monkeypatch, caplog
):
    import app.api.main as main

    def boom():
        raise RuntimeError("simulated database outage, token=eyJhbGciOiJIUzI1NiJ9.x.y")

    monkeypatch.setattr(main.state.repo, "list_assessments", boom)

    with caplog.at_level(logging.ERROR, logger="app.api.main"):
        resp = client.get("/")

    assert resp.status_code == 500
    records = [r for r in caplog.records if r.name == "app.api.main"]
    assert records, "expected the unhandled exception to be logged"
    assert records[0].exc_info is not None
    assert "GET" in records[0].getMessage()
