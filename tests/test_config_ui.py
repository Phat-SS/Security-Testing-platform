"""The Configuration tab: readiness checks plus editing scope, personas and
runner limits from the browser.

The behaviour under test is the one the platform previously had no answer for:
a run comes back entirely BLOCKED, and nothing in the UI says which setting
caused it or where to change it.
"""

import json

import pytest
from starlette.testclient import TestClient

from app.core.engagement import load_engagement


@pytest.fixture()
def cfg(tmp_path):
    return tmp_path / "engagement.json"


@pytest.fixture()
def client(tmp_path, cfg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        c._cfg = cfg
        yield c


def _read(cfg) -> dict:
    return json.loads(cfg.read_text(encoding="utf-8"))


# -- readiness ---------------------------------------------------------------


def test_readiness_names_the_scope_setting_that_blocks_a_run(client, cfg):
    client.post("/config/environments",
                data={"name": "dev", "url": "https://api.example.com"})
    r = client.get("/config")
    assert r.status_code == 200
    assert "not in the approved testing scope" in r.text
    # …and offers the fix inline rather than naming a file to go and edit.
    assert "/config/scope/allow-host" in r.text
    assert "Authorize api.example.com" in r.text


def test_authorize_host_fix_writes_the_scope_entry(client, cfg):
    client.post("/config/environments",
                data={"name": "dev", "url": "https://api.example.com"})
    client.post("/config/scope/allow-host", data={"host": "api.example.com"})
    assert _read(cfg)["scope"]["allowed_hosts"] == ["api.example.com"]


def test_saving_an_environment_can_authorize_its_host_in_one_step(client, cfg):
    client.post("/config/environments", data={
        "name": "dev", "url": "https://api.example.com", "authorize_host": "true",
    })
    assert _read(cfg)["scope"]["allowed_hosts"] == ["api.example.com"]


def test_authorizing_the_host_is_opt_in(client, cfg):
    client.post("/config/environments",
                data={"name": "dev", "url": "https://api.example.com"})
    assert _read(cfg).get("scope", {}).get("allowed_hosts", []) == []


def test_readiness_json_api(client, cfg):
    r = client.get("/api/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["can_run"] is False  # nothing configured yet
    assert any(c["key"] == "environments" and c["state"] == "fail" for c in body["checks"])


def test_readiness_flags_a_missing_persona(client, cfg):
    cfg.write_text(json.dumps({
        "environments": {"dev": "http://127.0.0.1:8000"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
    }))
    from app.api.main import state

    state.reload_engagement()
    body = client.get("/api/readiness").json()
    assert body["can_run"] is False
    missing = [c for c in body["checks"] if c["key"] in ("persona_attacker", "persona_victim")]
    assert len(missing) == 2
    assert all(c["state"] == "fail" for c in missing)


# -- scope -------------------------------------------------------------------


def test_save_scope_replaces_rather_than_merges(client, cfg):
    client.post("/config/scope", data={
        "allowed_hosts": "a.example.com\nb.example.com",
        "blocked_hosts": "production.example.com",
        "allow_private_ranges": "true",
    })
    scope = _read(cfg)["scope"]
    assert scope["allowed_hosts"] == ["a.example.com", "b.example.com"]
    assert scope["allow_private_ranges"] is True

    # Removing a host from the textarea has to actually remove it — a merging
    # writer would make the allow-list append-only through the UI.
    client.post("/config/scope", data={"allowed_hosts": "a.example.com",
                                       "blocked_hosts": ""})
    scope = _read(cfg)["scope"]
    assert scope["allowed_hosts"] == ["a.example.com"]
    assert scope["allow_private_ranges"] is False


def test_scope_hosts_are_deduped_and_lowercased(client, cfg):
    client.post("/config/scope",
                data={"allowed_hosts": "API.Example.com\napi.example.com\n  \n"})
    assert _read(cfg)["scope"]["allowed_hosts"] == ["api.example.com"]


# -- personas ----------------------------------------------------------------


def test_add_edit_and_delete_a_persona(client, cfg):
    client.post("/config/personas", data={
        "name": "agent_A", "role": "agent",
        "auth_headers": "Authorization: Bearer tokenA",
        "owns": "customer_id=1001",
        "secret_markers": "alice@example.com",
        "scoping_headers": "entity-context",
    })
    personas = _read(cfg)["personas"]
    assert personas == [{
        "name": "agent_A",
        "auth_headers": {"Authorization": "Bearer tokenA"},
        "role": "agent",
        "owns": {"customer_id": "1001"},
        "secret_markers": ["alice@example.com"],
        "scoping_headers": ["entity-context"],
    }]

    # Saving the same name edits in place instead of appending a duplicate.
    client.post("/config/personas", data={
        "name": "agent_A", "role": "admin", "auth_headers": "Authorization: Bearer new",
    })
    personas = _read(cfg)["personas"]
    assert len(personas) == 1
    assert personas[0]["role"] == "admin"

    client.post("/config/personas/agent_A/delete")
    assert _read(cfg)["personas"] == []


def test_deleting_a_persona_leaves_the_role_pointer_for_a_human(client, cfg):
    client.post("/config/personas", data={"name": "agent_A", "auth_headers": ""})
    client.post("/config/personas", data={"name": "agent_B", "auth_headers": ""})
    client.post("/config/identities", data={"attacker": "agent_A", "victim": "agent_B"})
    client.post("/config/personas/agent_B/delete")

    data = _read(cfg)
    # Silently repointing `victim` would change what every generated test
    # attacks; the readiness panel raises it instead.
    assert data["victim"] == "agent_B"
    body = client.get("/api/readiness").json()
    assert any(c["key"] == "persona_victim" and c["state"] == "fail" for c in body["checks"])


def test_save_identities(client, cfg):
    client.post("/config/personas", data={"name": "agent_A", "auth_headers": ""})
    client.post("/config/personas", data={"name": "agent_B", "auth_headers": ""})
    client.post("/config/identities", data={"attacker": "agent_A", "victim": "agent_B"})
    data = _read(cfg)
    assert (data["attacker"], data["victim"]) == ("agent_A", "agent_B")


# -- runner limits -----------------------------------------------------------


def test_runner_limits_round_trip_and_reach_execution(client, cfg):
    from app.core.config import settings_with_overrides

    client.post("/config/runner", data={"timeout_s": "45", "max_requests_per_test": "5",
                                        "max_response_bytes": ""})
    assert _read(cfg)["runner"] == {"timeout_s": 45.0, "max_requests_per_test": 5}

    eng = load_engagement(str(cfg))
    limits = settings_with_overrides(eng.runner).limits
    assert limits.timeout_s == 45.0
    assert limits.max_requests_per_test == 5
    assert limits.max_response_bytes == 2_000_000  # blank fell back to the env default


def test_runner_limits_reset(client, cfg):
    client.post("/config/runner", data={"timeout_s": "45"})
    client.post("/config/runner", data={"reset": "true"})
    assert "runner" not in _read(cfg)


def test_runner_limits_reject_non_numeric_without_writing(client, cfg):
    client.post("/config/runner", data={"timeout_s": "45"})
    r = client.post("/config/runner", data={"timeout_s": "soon"}, follow_redirects=False)
    assert r.status_code == 303
    assert "must+be+a+number" in r.headers["location"] or "must%20be%20a%20number" in r.headers["location"]
    assert _read(cfg)["runner"] == {"timeout_s": 45.0}  # the good value survived


# -- config writers never clobber unrelated keys -----------------------------


def test_every_writer_preserves_unknown_keys(client, cfg):
    cfg.write_text(json.dumps({
        "_comment": "hand-written note",
        "some_future_key": {"kept": True},
    }))
    from app.api.main import state

    state.reload_engagement()
    client.post("/config/environments", data={"name": "dev", "url": "https://a.example.com"})
    client.post("/config/scope", data={"allowed_hosts": "a.example.com"})
    client.post("/config/personas", data={"name": "agent_A", "auth_headers": ""})
    client.post("/config/identities", data={"attacker": "agent_A", "victim": "agent_A"})
    client.post("/config/runner", data={"timeout_s": "20"})

    data = _read(cfg)
    assert data["_comment"] == "hand-written note"
    assert data["some_future_key"] == {"kept": True}


# -- the warning reaches the page where the run is actually started -----------


def test_assessment_page_warns_before_the_run_not_after(client, cfg):
    cfg.write_text(json.dumps({
        "environments": {"dev": "https://api.example.com"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": [], "blocked_hosts": [], "allow_private_ranges": False},
    }))
    from app.api.main import state

    state.reload_engagement()
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    r = client.get(f"/assessment/{aid}")
    assert r.status_code == 200
    assert "will block this run before any request is sent" in r.text
    assert "not in the approved testing scope" in r.text
    assert "Open configuration" in r.text


def test_assessment_page_is_quiet_when_everything_checks_out(client, cfg):
    cfg.write_text(json.dumps({
        "environments": {"dev": "http://127.0.0.1:8000"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["127.0.0.1"], "blocked_hosts": [],
                  "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {"Authorization": "Bearer a"},
             "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {"Authorization": "Bearer b"},
             "owns": {"customer_id": "2002"}},
        ],
    }))
    from app.api.main import state

    state.reload_engagement()
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    r = client.get(f"/assessment/{aid}")
    # A banner that is always present is a banner nobody reads.
    assert "will block this run" not in r.text
    assert "Open configuration" not in r.text


def test_persona_name_must_be_url_safe(client, cfg):
    r = client.post("/config/personas", data={"name": "bad/name", "auth_headers": ""},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "is not a valid persona name" in r.text
    # Rejected before any write — the config file is not even created.
    assert not cfg.exists()
