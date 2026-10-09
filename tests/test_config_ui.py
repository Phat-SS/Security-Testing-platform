"""The Configuration tab: readiness checks plus editing scope, personas and
runner limits from the browser.

The behaviour under test is the one the platform previously had no answer for:
a run comes back entirely BLOCKED, and nothing in the UI says which setting
caused it or where to change it.
"""

import json
import os

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
    runtime_env = tmp_path / ".env"
    monkeypatch.setenv("RUNTIME_ENV_PATH", str(runtime_env))
    runtime_keys = (
        "USE_AI", "AI_REQUIRE_PINNED_MODEL", "AUTH_COOKIE_SECURE", "ANTHROPIC_MODEL",
        "AI_MAX_BUDGET_USD", "AI_EFFORT", "EVIDENCE_FINGERPRINT_KEY",
        "REPORT_SIGNING_KEY", "REPORT_SIGNING_KEY_ID", "OAST_PUBLIC_URL",
        "OAST_POLL_URL", "OAST_API_TOKEN", "OAST_TIMEOUT_S",
        # Written by quick setup, which puts persona credentials in .env and
        # applies them to this process so readiness sees the finished state.
        "PERSONA_A_TOKEN", "PERSONA_B_TOKEN",
    )
    original_runtime = {key: os.environ.get(key) for key in runtime_keys}
    for key in runtime_keys:
        monkeypatch.delenv(key, raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        c._cfg = cfg
        c._runtime_env = runtime_env
        yield c
    # The UI intentionally updates os.environ directly so a production save is
    # live immediately. Restore it here because monkeypatch cannot observe
    # assignments performed inside application code.
    for key, original in original_runtime.items():
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original


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


# -- AI and evidence secrets -------------------------------------------------


def test_ai_evidence_secrets_can_be_saved_without_being_echoed(client):
    fingerprint = "fingerprint-key-0123456789"
    signing = "report-signing-key-0123456789abcdef"
    oast_token = "oast-private-token"
    response = client.post("/config/ai-evidence", data={
        "USE_AI": "true",
        "AI_REQUIRE_PINNED_MODEL": "true",
        "ANTHROPIC_MODEL": "claude-sonnet-4-20260514",
        "AI_MAX_BUDGET_USD": "1.50",
        "AI_EFFORT": "high",
        "EVIDENCE_FINGERPRINT_KEY": fingerprint,
        "REPORT_SIGNING_KEY": signing,
        "REPORT_SIGNING_KEY_ID": "prod-2026",
        "OAST_PUBLIC_URL": "https://oast.example/c",
        "OAST_POLL_URL": "https://oast.example/events",
        "OAST_API_TOKEN": oast_token,
        "OAST_TIMEOUT_S": "7",
    }, follow_redirects=True)

    assert response.status_code == 200
    dotenv = client._runtime_env.read_text(encoding="utf-8")
    assert f"EVIDENCE_FINGERPRINT_KEY={fingerprint}" in dotenv
    assert f"REPORT_SIGNING_KEY={signing}" in dotenv
    assert "ANTHROPIC_MODEL=claude-sonnet-4-20260514" in dotenv
    assert os.environ["REPORT_SIGNING_KEY"] == signing
    page = client.get("/config?tab=ai-evidence").text
    assert "AI &amp; Evidence" in page or "AI & Evidence" in page
    # Each of the three secrets reports that it is set, and none of the three
    # values reaches the browser. The wording of the badges is the pane's own
    # business; that they SAY something and leak nothing is the contract.
    assert "ACTIVE" in page          # the two evidence keys
    assert "CONFIGURED" in page      # the OAST collaborator
    assert "OFF" not in page.split("Evidence Keys")[1].split("Optional Integration")[0]
    assert fingerprint not in page
    assert signing not in page
    assert oast_token not in page


def test_blank_secret_keeps_it_and_explicit_clear_removes_it(client):
    secret = "report-signing-key-0123456789abcdef"
    client.post("/config/ai-evidence", data={"REPORT_SIGNING_KEY": secret})
    client.post("/config/ai-evidence", data={"REPORT_SIGNING_KEY": ""})
    assert f"REPORT_SIGNING_KEY={secret}" in client._runtime_env.read_text(encoding="utf-8")

    client.post("/config/ai-evidence", data={"clear_REPORT_SIGNING_KEY": "true"})
    assert "REPORT_SIGNING_KEY=" not in client._runtime_env.read_text(encoding="utf-8")


def test_ai_evidence_config_rejects_weak_keys_and_partial_oast(client):
    response = client.post(
        "/config/ai-evidence", data={"REPORT_SIGNING_KEY": "too-short"},
        follow_redirects=True,
    )
    assert "at least 32 characters" in response.text
    assert not client._runtime_env.exists()

    response = client.post(
        "/config/ai-evidence", data={"OAST_PUBLIC_URL": "https://oast.example/c"},
        follow_redirects=True,
    )
    assert "must be configured together" in response.text
    assert not client._runtime_env.exists()


def test_ai_evidence_config_rejects_env_line_injection(client):
    response = client.post("/config/ai-evidence", data={
        "EVIDENCE_FINGERPRINT_KEY": "0123456789abcdef\nDATABASE_URL=attacker",
    }, follow_redirects=True)

    assert "was not saved" in response.text
    assert not client._runtime_env.exists()


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
    assert "Open Configuration" in r.text


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
    assert "Open Configuration" not in r.text


def test_persona_name_must_be_url_safe(client, cfg):
    r = client.post("/config/personas", data={"name": "bad/name", "auth_headers": ""},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "is not a valid persona name" in r.text
    # Rejected before any write — the config file is not even created.
    assert not cfg.exists()


# -- quick setup -------------------------------------------------------------


def test_quick_setup_creates_a_runnable_engagement(client):
    """One submit has to produce a config that actually runs.

    Every field it fills used to be a separate pane, and skipping any one of
    them (most often authorizing the host) produces a config that looks
    complete and returns an entirely BLOCKED run.
    """
    response = client.post("/config/quick-setup", data={
        "env_name": "staging",
        "url": "https://staging-api.example.com/",
        "attacker_token": "token-a-value",
        "victim_token": "token-b-value",
        "owns_key": "customer_id",
        "owns_value": "2002",
    }, follow_redirects=True)
    assert response.status_code == 200

    data = _read(client._cfg)
    assert data["environments"] == {"staging": "https://staging-api.example.com"}
    assert data["active_environment"] == "staging"
    assert data["scope"]["allowed_hosts"] == ["staging-api.example.com"]
    assert data["attacker"] == "agent_A" and data["victim"] == "agent_B"
    names = [p["name"] for p in data["personas"]]
    assert names == ["agent_A", "agent_B"]
    victim = data["personas"][1]
    assert victim["owns"] == {"customer_id": "2002"}

    # The credential is a reference in the artifact and a value in .env.
    assert data["personas"][0]["auth_headers"] == {
        "Authorization": "Bearer ${PERSONA_A_TOKEN}"
    }
    dotenv = client._runtime_env.read_text(encoding="utf-8")
    assert "PERSONA_A_TOKEN=token-a-value" in dotenv
    assert "token-a-value" not in client._cfg.read_text(encoding="utf-8")

    # ...and it is live in this process, so readiness reflects the finished
    # state instead of reporting two variables it was just given.
    engagement = load_engagement(str(client._cfg))
    assert engagement.vault.get("agent_A").auth_headers == {
        "Authorization": "Bearer token-a-value"
    }
    checks = {c["key"]: c for c in client.get("/api/readiness").json()["checks"]}
    # Scope is deliberately left out: its verdict depends on a live DNS lookup
    # of a host that does not exist. Everything the form itself is responsible
    # for has to come back clean.
    assert checks["config_file"]["state"] == "ok"
    assert checks["environments"]["state"] == "ok"
    assert checks["persona_attacker"]["state"] == "ok"
    assert checks["persona_victim"]["state"] == "ok"
    assert checks["persona_pair"]["state"] == "ok"


def test_quick_setup_rejects_a_bad_url_without_writing_anything(client):
    response = client.post("/config/quick-setup", data={
        "env_name": "staging", "url": "staging-api.example.com",
        "attacker_token": "a", "victim_token": "b",
    }, follow_redirects=True)
    assert "must start with http" in response.text
    assert not client._cfg.exists()
    assert not client._runtime_env.exists()


# -- tab layout --------------------------------------------------------------


def test_old_tab_names_open_the_tab_that_absorbed_them(client):
    """Bookmarks, older reports and the config writers' own redirects all carry
    the pre-merge tab names; each must land on the pane it moved into rather
    than silently falling back to Readiness."""
    from app.api.views import resolve_config_tab

    assert resolve_config_tab("scope") == "target"
    assert resolve_config_tab("environments") == "target"
    assert resolve_config_tab("personas") == "identities"
    assert resolve_config_tab("runner") == "advanced"
    assert resolve_config_tab("mcp") == "advanced"
    assert resolve_config_tab("nonsense") == "readiness"

    page = client.get("/config?tab=scope").text
    assert "class='tabpane active' id='cfg-target'" in page
    assert "class='tabpane ' id='cfg-advanced'" in page
