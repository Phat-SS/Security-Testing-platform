"""Persona tokens live in .env; engagement.json only references them.

The engagement file is the artifact a tester reads, diffs and attaches to a
ticket, so a live bearer token must not be in it. `${VAR}` in an auth-header
value is resolved from the environment at load time.

The interesting case is the *unset* variable, because both obvious fallbacks
are worse than refusing to run: sending the literal `${VAR}` produces a 401
that reads like a finding, and dropping the header silently downgrades every
authorization test to an unauthenticated one. Load withholds the header AND
records the variable name so readiness blocks the run.
"""

import json

import pytest

from app.core.engagement import load_engagement, resolve_env_refs
from app.core.preflight import evaluate


def write_cfg(tmp_path, token_a="Bearer ${PERSONA_A_TOKEN}"):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:8000",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {"Authorization": token_a},
             "role": "agent", "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {"Authorization": "Bearer static-b"},
             "role": "agent", "owns": {"customer_id": "2002"}},
        ],
    }), encoding="utf-8")
    return cfg


def test_reference_is_resolved_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PERSONA_A_TOKEN", "eyJreal.token.value")
    cfg = write_cfg(tmp_path)

    eng = load_engagement(str(cfg))
    agent_a = eng.vault.get("agent_A")

    assert agent_a.auth_headers["Authorization"] == "Bearer eyJreal.token.value"
    assert agent_a.missing_env == ()
    # The file itself still holds only the reference.
    assert "eyJreal.token.value" not in cfg.read_text(encoding="utf-8")


def test_value_without_a_reference_is_untouched(tmp_path, monkeypatch):
    """Existing configs that hold a literal token keep working unchanged."""
    monkeypatch.delenv("PERSONA_A_TOKEN", raising=False)
    cfg = write_cfg(tmp_path, token_a="Bearer literal-token")

    eng = load_engagement(str(cfg))

    assert eng.vault.get("agent_A").auth_headers == {"Authorization": "Bearer literal-token"}
    assert eng.vault.get("agent_A").missing_env == ()


@pytest.mark.parametrize("value", ["", None])
def test_unset_or_empty_reference_withholds_the_header(tmp_path, monkeypatch, value):
    if value is None:
        monkeypatch.delenv("PERSONA_A_TOKEN", raising=False)
    else:
        monkeypatch.setenv("PERSONA_A_TOKEN", value)
    cfg = write_cfg(tmp_path)

    agent_a = load_engagement(str(cfg)).vault.get("agent_A")

    # Not sent as a literal, and not silently replaced by something plausible.
    assert "Authorization" not in agent_a.auth_headers
    assert agent_a.missing_env == ("PERSONA_A_TOKEN",)


def test_unset_reference_blocks_the_run_and_names_the_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("PERSONA_A_TOKEN", raising=False)
    cfg = write_cfg(tmp_path)
    eng = load_engagement(str(cfg))

    readiness = evaluate(eng, str(cfg))
    attacker = next(c for c in readiness.checks if c.key == "persona_attacker")

    assert not readiness.can_run
    assert attacker.state == "fail"
    # Names the variable to set, so the tester is not sent to the Personas pane.
    assert "PERSONA_A_TOKEN" in attacker.hint_html
    # A persona whose reference resolved is unaffected.
    assert load_engagement(str(cfg)).vault.get("agent_B").missing_env == ()


def test_resolved_reference_does_not_block_the_run(tmp_path, monkeypatch):
    monkeypatch.setenv("PERSONA_A_TOKEN", "tok")
    cfg = write_cfg(tmp_path)

    readiness = evaluate(load_engagement(str(cfg)), str(cfg))
    attacker = next(c for c in readiness.checks if c.key == "persona_attacker")

    assert attacker.state == "ok"


def test_readiness_never_echoes_the_token(tmp_path, monkeypatch):
    """The reason the value is in .env is that it must not be rendered."""
    monkeypatch.setenv("PERSONA_A_TOKEN", "supersecret-value")
    cfg = write_cfg(tmp_path)

    readiness = evaluate(load_engagement(str(cfg)), str(cfg))

    rendered = " ".join(c.detail + c.hint_html for c in readiness.checks)
    assert "supersecret-value" not in rendered


def test_several_references_in_one_value_report_every_unset_name(monkeypatch):
    monkeypatch.setenv("SET_ONE", "a")
    monkeypatch.delenv("UNSET_ONE", raising=False)
    monkeypatch.delenv("UNSET_TWO", raising=False)

    resolved, missing = resolve_env_refs("${SET_ONE}/${UNSET_ONE}/${UNSET_TWO}")

    assert resolved == "a/${UNSET_ONE}/${UNSET_TWO}"
    assert missing == ("UNSET_ONE", "UNSET_TWO")
