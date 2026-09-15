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


@pytest.mark.parametrize("bad", ["bad/name", "  ", "pct%20name", "a" * 65])
def test_invalid_name_rejected(client, bad):
    r = client.post("/config/environments", data={"name": bad, "url": "http://x"})
    assert r.status_code == 400
    assert "not a valid environment name" in r.text


def test_name_with_spaces_is_saved_and_deletable(client):
    """Real engagements name environments after the client ("DEV_BMW AU").
    The name is a label and a URL-encoded path segment, never a filename, so a
    space is allowed — and the row it produces must still round-trip."""
    r = client.post("/config/environments",
                    data={"name": "  DEV_BMW   AU ", "url": "https://dev.bmw.example.com"},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "<b>DEV_BMW AU</b>" in r.text  # trimmed, inner whitespace collapsed

    from app.api.main import state as app_state

    assert "DEV_BMW AU" in app_state.engagement.environments

    r = client.post("/config/environments/DEV_BMW%20AU/delete", follow_redirects=True)
    assert r.status_code == 200
    assert "No environments configured yet" in r.text


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
    client.post(f"/assessment/{aid}/design")

    from app.api.main import state as app_state

    test_ids = [t.test_id for t in app_state.repo.get_test_cases(aid)][:1]
    client.post(f"/assessment/{aid}/approve", data={"test_ids": test_ids})

    r = client.get(f"/assessment/{aid}")
    assert r.status_code == 200
    assert "value='dev'" in r.text
    assert "value='staging'" in r.text
    assert "Run approved tests" in r.text
    assert "disabled" not in r.text.split("Run approved tests")[0].rsplit("<button", 1)[-1]


def test_run_button_is_disabled_until_something_is_approved(client):
    """An empty run sends no requests but still flipped the assessment to
    EXECUTED, which reads afterwards as "tested, nothing found"."""
    client.post("/config/environments", data={"name": "dev", "url": "http://127.0.0.1:8000"})
    aid = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True).url.path.rsplit("/", 1)[-1]

    # The run controls live on the Run phase; a fresh ticket lands on Scope.
    r = client.get(f"/assessment/{aid}?phase=run")

    assert "no approved tests" in r.text
    assert "disabled" in r.text.split("Run approved tests")[0].rsplit("<button", 1)[-1]


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


def test_delete_removes_a_legacy_default_environment_for_good(tmp_path, monkeypatch):
    """The regression this exists for: a config carrying a bare
    `target_base_url` shows a synthetic "default" environment, and deleting it
    used to appear to work and then silently undo itself.

    The delete popped from the stored `environments` map — where "default"
    never was — and left `target_base_url` untouched, so the very next load
    re-synthesised the entry. The row came back on refresh, and nothing said
    why.
    """
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:8000",
        "environments": {"staging": "https://staging.example.com"},
        "active_environment": "staging",
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        assert "<b>default</b>" in c.get("/config/environments").text

        r = c.post("/config/environments/default/delete", follow_redirects=True)
        assert r.status_code == 200
        assert "<b>default</b>" not in r.text
        # It must also be gone on a fresh read of the file, not just in the
        # response rendered from the in-memory state right after the write.
        assert "<b>default</b>" not in c.get("/config/environments").text

    saved = json.loads(cfg.read_text(encoding="utf-8"))
    assert "default" not in saved["environments"]
    assert saved["target_base_url"] == "https://staging.example.com"


def test_deleting_the_last_environment_leaves_nothing_behind(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({"target_base_url": "http://127.0.0.1:8000"}))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        r = c.post("/config/environments/default/delete", follow_redirects=True)
        assert "No environments configured yet" in r.text

    saved = json.loads(cfg.read_text(encoding="utf-8"))
    # target_base_url has to go too — left behind it would immediately come
    # back as a "default" environment on the next load.
    assert "target_base_url" not in saved
    assert saved["environments"] == {}
    assert saved["active_environment"] == ""


def test_delete_keeps_scope_and_personas(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"dev": "https://dev.example.com", "stg": "https://stg.example.com"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["dev.example.com"], "blocked_hosts": [],
                  "allow_private_ranges": False},
        "personas": [{"name": "agent_A", "auth_headers": {"Authorization": "Bearer t"}}],
        "attacker": "agent_A",
        "victim": "agent_A",
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        c.post("/config/environments/dev/delete")

    saved = json.loads(cfg.read_text(encoding="utf-8"))
    assert saved["environments"] == {"stg": "https://stg.example.com"}
    assert saved["active_environment"] == "stg"
    assert saved["scope"]["allowed_hosts"] == ["dev.example.com"]
    assert saved["personas"][0]["name"] == "agent_A"


def test_make_default_switches_the_active_environment(client):
    client.post("/config/environments", data={"name": "dev", "url": "http://127.0.0.1:8000"})
    client.post("/config/environments", data={"name": "staging", "url": "https://staging.example.com"})
    r = client.post("/config/environments/staging/activate", follow_redirects=True)
    assert r.status_code == 200
    assert "staging is now the default" in r.text


@pytest.mark.parametrize("dots", [".", ".."])
def test_a_dot_only_name_is_rejected(client, dots):
    """Percent-encoding leaves a dot alone, so `..` stays a live path segment:
    the browser collapses /config/environments/../delete to
    /config/environments/delete before sending it, and such an environment
    could never be deleted or made default again."""
    r = client.post("/config/environments", data={"name": dots, "url": "http://x.example.com"})
    assert r.status_code == 400
    assert "not a valid environment name" in r.text
