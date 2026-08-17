"""Named environments: save/list/delete a target URL, pick one at execute time.

Every test points ENGAGEMENT_CONFIG at a tmp_path file so nothing ever touches
the real repo's config/engagement.json (mirrors the DATABASE_URL isolation
pattern used throughout tests/test_api.py).
"""

import json

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(tmp_path / "engagement.json"))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def client_with_scope(tmp_path, monkeypatch):
    """A config with scope/personas pre-set (shared across all environments),
    so an actual execute() run resolves personas and only fails to *connect*
    (nothing is listening on these ports) rather than raising KeyError."""
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:19191",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "agent", "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {}, "role": "agent", "owns": {"customer_id": "2002"}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        c._cfg_path = str(cfg)
        yield c


def test_environments_page_empty_by_default(client):
    r = client.get("/config/environments")
    assert r.status_code == 200
    assert "No environments configured yet" in r.text


def test_save_and_list_environment(client):
    r = client.post("/config/environments", data={"name": "dev", "url": "http://127.0.0.1:8000"},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "<b>dev</b>" in r.text
    assert "http://127.0.0.1:8000" in r.text
    assert "default" in r.text  # first saved environment becomes the default


def test_invalid_name_rejected(client):
    r = client.post("/config/environments", data={"name": "bad name!", "url": "http://x"})
    assert r.status_code == 400
    assert "not a valid environment name" in r.text


def test_invalid_url_rejected(client):
    r = client.post("/config/environments", data={"name": "dev", "url": "ftp://x"})
    assert r.status_code == 400
    assert "not a valid base URL" in r.text


def test_delete_environment_reassigns_active(client):
    client.post("/config/environments", data={"name": "dev", "url": "http://127.0.0.1:8000"})
    client.post("/config/environments", data={"name": "staging", "url": "https://staging.example.com"})
    r = client.post("/config/environments/dev/delete", follow_redirects=True)
    assert r.status_code == 200
    assert "<b>dev</b>" not in r.text
    assert "<b>staging</b>" in r.text
    assert "No environments configured yet" not in r.text


def test_execute_dropdown_shows_saved_environments(client):
    client.post("/config/environments", data={"name": "dev", "url": "http://127.0.0.1:8000"})
    client.post("/config/environments", data={"name": "staging", "url": "https://staging.example.com"})
    aid = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True).url.path.rsplit("/", 1)[-1]
    r = client.get(f"/assessment/{aid}")
    assert r.status_code == 200
    assert "value='dev'" in r.text
    assert "value='staging'" in r.text
    assert "Run approved tests" in r.text
    assert "disabled" not in r.text.split("Run approved tests")[0].rsplit("<button", 1)[-1]


def test_execute_targets_the_selected_environment(client_with_scope):
    client = client_with_scope
    client.post("/config/environments", data={"name": "staging", "url": "http://127.0.0.1:19192", "make_active": "true"})

    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True)
    aid = r.url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")

    from app.api.main import state as app_state

    test_ids = [t.test_id for t in app_state.repo.get_test_cases(aid) if not t.is_destructive][:1]
    assert test_ids, "expected at least one non-destructive generated test"
    client.post(f"/assessment/{aid}/approve", data={"test_ids": test_ids})

    r = client.post(f"/assessment/{aid}/execute", data={"environment": "staging"}, follow_redirects=True)
    assert r.status_code == 200

    assessment = app_state.repo.get_assessment(aid)
    assert assessment.target_base_url == "http://127.0.0.1:19192"


def test_legacy_target_base_url_becomes_default_environment(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({"target_base_url": "http://127.0.0.1:8000"}))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        r = c.get("/config/environments")
        assert "default" in r.text
        assert "http://127.0.0.1:8000" in r.text
