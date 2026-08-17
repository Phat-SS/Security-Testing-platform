"""Web-layer auth: with AUTH_ENABLED, mutating routes require a valid tester key."""

import json

import pytest
from starlette.testclient import TestClient

from app.core.auth import hash_key


@pytest.fixture()
def client(tmp_path, monkeypatch):
    key = "tester-key-123"
    admin_key = "admin-key-456"
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "alice", "role": "tester", "api_key_sha256": hash_key(key)},
        {"name": "bob", "role": "viewer", "api_key_sha256": hash_key("viewer-key")},
        {"name": "carol", "role": "admin", "api_key_sha256": hash_key(admin_key)},
    ]}))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'auth.db'}")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        c._key = key
        c._admin_key = admin_key
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


def test_login_with_valid_key_unlocks_the_ui_via_cookie(client):
    # The browser form-based UI can't set X-API-Key/Authorization headers —
    # /login must let it authenticate the whole browser session instead.
    r = client.post("/login", data={"api_key": client._key}, follow_redirects=False)
    assert r.status_code == 303
    assert "session_key" in r.cookies
    # No explicit header now — the cookie set by /login must be sufficient.
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True)
    assert r.status_code == 200
    assert "CRM-1234" in r.text


def test_login_with_invalid_key_is_rejected(client):
    r = client.post("/login", data={"api_key": "not-a-real-key"}, follow_redirects=False)
    assert r.status_code == 303
    assert "session_key" not in r.cookies
    assert "Invalid" in r.headers["location"]


def test_shutdown_requires_admin_not_just_tester(client):
    r = client.post("/admin/shutdown", headers={
        "X-API-Key": client._key,  # tester, not admin
        "X-Confirm-Shutdown": "security-testing-platform-ui",
    })
    assert r.status_code == 403


def test_shutdown_requires_confirmation_header_even_for_admin(client):
    r = client.post("/admin/shutdown", headers={"X-API-Key": client._admin_key})
    assert r.status_code == 400
