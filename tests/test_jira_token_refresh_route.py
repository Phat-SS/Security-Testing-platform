"""POST /config/mcp/jira/refresh-token — the one-click OAuth refresh route.

No live OAuth server in tests, so this only covers the paths that don't need
one: the route must degrade to a clear error, never hang or 500, when the
tooling it depends on isn't there.
"""

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'refresh.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_missing_npx_redirects_with_a_clear_error_not_a_500(client, monkeypatch):
    from app.api.routes import integrations

    monkeypatch.setattr(integrations.shutil, "which", lambda _name: None)

    r = client.post("/config/mcp/jira/refresh-token", follow_redirects=True)

    assert r.status_code == 200
    assert "npx not found" in r.text
