"""Changing the attacker/victim pair must reach the test designer immediately.

The designer takes those two persona names at construction and every generated
test's `auth_context` is built from them, so a reload that refreshed only the
planner left new plans describing the *previous* pair. That failure is silent
whenever the old personas still exist: the run completes, and each PASS/FAIL
reports a cross-tenant relationship the operator never configured.
"""

import json

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:19191",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "old_A",
        "victim": "old_B",
        "personas": [
            {"name": "old_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1"}},
            {"name": "old_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2"}},
            {"name": "new_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "3"}},
            {"name": "new_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "4"}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _personas_in_plan(aid) -> set[str]:
    from app.api.main import state

    tests = state.repo.get_test_cases(aid)
    assert tests, "the designer produced no tests at all"
    used = {t.auth_context.persona for t in tests}
    used |= {t.auth_context.target_persona for t in tests if t.auth_context.target_persona}
    # "anonymous" is the unauthenticated identity every API2 test uses; it is
    # not drawn from the engagement's attacker/victim pair.
    return used - {"anonymous"}


def test_saved_identities_reach_the_designer(client):
    from app.api.main import state

    client.post("/config/identities", data={"attacker": "new_A", "victim": "new_B"})
    assert (state.engagement.attacker, state.engagement.victim) == ("new_A", "new_B")

    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")

    used = _personas_in_plan(aid)
    assert used <= {"new_A", "new_B"}, f"the plan still references the old pair: {sorted(used)}"


def test_saving_a_persona_also_refreshes_the_designer(client):
    """`/config/personas` reloads the engagement too, so it must not reinstate
    a designer built from the pre-save document."""
    from app.api.main import state

    client.post("/config/identities", data={"attacker": "new_A", "victim": "new_B"})
    client.post("/config/personas", data={
        "name": "new_B", "role": "user", "auth_headers": "", "owns": "customer_id=4444",
    })
    assert (state.engagement.attacker, state.engagement.victim) == ("new_A", "new_B")

    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")

    assert _personas_in_plan(aid) <= {"new_A", "new_B"}
