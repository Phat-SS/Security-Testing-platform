"""Web-layer auth: with AUTH_ENABLED, mutating routes require a valid tester key."""

import json

import pytest
from starlette.testclient import TestClient

from app.core.auth import hash_key


@pytest.fixture()
def client(tmp_path, monkeypatch):
    key = "tester-key-123"
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "alice", "role": "tester", "api_key_sha256": hash_key(key)},
        {"name": "bob", "role": "viewer", "api_key_sha256": hash_key("viewer-key")},
    ]}))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'auth.db'}")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        c._key = key
        yield c


def test_import_rejected_without_key(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=False)
    assert r.status_code == 401


def test_import_rejected_for_viewer(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"},
                    headers={"X-API-Key": "viewer-key"}, follow_redirects=False)
    assert r.status_code == 403


def test_import_allowed_for_tester(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"},
                    headers={"X-API-Key": client._key}, follow_redirects=True)
    assert r.status_code == 200
    assert "CRM-1234" in r.text


def test_reads_stay_open(client):
    # dashboard + health are not gated, so monitoring/UX still works
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 200
