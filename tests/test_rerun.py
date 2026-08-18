"""Re-running an assessment.

A re-run is a NEW assessment of the same issue, not a second pass over the old
one. Regression only exists between assessments (`previous_assessment_for_issue`
is the baseline lookup), and findings are derived from every execution an
assessment holds — so re-running in place would rewrite the conclusions attached
to evidence that had already been reported.
"""

import json

import pytest
from starlette.testclient import TestClient

from app.schemas.enums import ApprovalStatus, TestSource


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'rerun.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _repo():
    import app.api.main as main

    return main.state.repo


def _orch():
    import app.api.main as main

    return main.state.orch


def _designed(client) -> str:
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design", follow_redirects=True)
    return aid


def _ids(aid) -> list[str]:
    return sorted(t.test_id for t in _repo().get_test_cases(aid))


# -- cloning ----------------------------------------------------------------


def test_clone_copies_the_plan_into_a_new_assessment(client):
    aid = _designed(client)
    client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                data={"action": "approve", "select_all": "true"})

    new_id = _orch().clone_for_rerun(aid)

    assert new_id != aid
    assert _repo().get_assessment(new_id).issue_key == _repo().get_assessment(aid).issue_key
    assert _ids(new_id) == _ids(aid)


def test_clone_carries_approvals(client):
    """The cloned test is byte-for-byte the test that was approved, so making the
    tester re-approve an identical plan would be ceremony, not review."""
    aid = _designed(client)
    approved = _ids(aid)[:3]
    client.post(f"/assessment/{aid}/plan",
                data={"action": "approve", "test_ids": approved}, follow_redirects=True)

    new_id = _orch().clone_for_rerun(aid)

    carried = {t.test_id for t in _repo().get_test_cases(new_id)
               if t.approval_status == ApprovalStatus.APPROVED}
    assert carried == set(approved)


def test_clone_copies_hand_edited_endpoints(client):
    aid = _designed(client)
    client.post(f"/assessment/{aid}/endpoints", follow_redirects=True,
                data={"method": "GET", "path": "/v2/hand-typed", "auth_required": "true"})

    new_id = _orch().clone_for_rerun(aid)

    paths = {ep["path"] for ep in _repo().get_assessment(new_id).analysis_json["endpoints"]}
    assert "/v2/hand-typed" in paths, (
        "a re-run must start from the endpoint list the tester curated"
    )


def test_clone_leaves_the_previous_run_untouched(client):
    aid = _designed(client)
    before = _ids(aid)

    _orch().clone_for_rerun(aid)

    assert _ids(aid) == before
    assert _repo().get_executions(aid) == []


def test_clone_does_not_carry_a_policy_approved_adaptive_followup(client):
    """An adaptive follow-up was authorised by policy mid-run, not read by a
    person. Copying it into a plan a human is about to run would launder "a policy
    permitted this" into "a human approved this"."""
    aid = _designed(client)
    tests = _repo().get_test_cases(aid)
    followup = tests[0].model_copy(deep=True)
    followup.test_id = "AI1-followup"
    followup.source = TestSource.ADAPTIVE_PLANNER
    followup.approval_status = ApprovalStatus.APPROVED
    _repo().save_test_cases(aid, [followup])
    assert "AI1-followup" in _ids(aid)

    new_id = _orch().clone_for_rerun(aid)

    assert "AI1-followup" not in _ids(new_id)


def test_cloning_a_missing_assessment_is_an_error_not_a_silent_empty_run(client):
    with pytest.raises(ValueError):
        _orch().clone_for_rerun("A-does-not-exist")


# -- the route --------------------------------------------------------------


def test_rerun_without_an_environment_clones_but_does_not_pretend_to_run(client):
    aid = _designed(client)
    client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                data={"action": "approve", "select_all": "true"})

    r = client.post(f"/assessment/{aid}/rerun", data={"mode": "same"},
                    follow_redirects=True)

    assert "no environment is configured" in r.text
    new_id = r.url.path.rsplit("/", 1)[-1]
    assert new_id != aid
    assert _ids(new_id) == _ids(aid)
    assert _repo().get_executions(new_id) == []


def test_rerun_with_nothing_approved_says_so(client):
    aid = _designed(client)
    client.post("/config/environments", data={"name": "dev", "url": "http://127.0.0.1:8000"})

    r = client.post(f"/assessment/{aid}/rerun", data={"mode": "same"},
                    follow_redirects=True)

    assert "no test in it was approved" in r.text


def test_reimport_makes_a_fresh_assessment_with_no_plan(client):
    aid = _designed(client)
    assert _ids(aid)

    r = client.post(f"/assessment/{aid}/rerun", data={"mode": "reimport"},
                    follow_redirects=True)

    new_id = r.url.path.rsplit("/", 1)[-1]
    assert new_id != aid
    assert _ids(new_id) == [], "a re-import re-reads the ticket; it does not design"
    assert "Re-imported" in r.text


def test_rerun_of_a_missing_assessment_does_not_500(client):
    r = client.post("/assessment/A-nope/rerun", data={"mode": "same"},
                    follow_redirects=True)

    assert r.status_code == 200
    assert "Assessment not found" in r.text


def test_the_rerun_is_audited_on_both_assessments(client):
    aid = _designed(client)

    new_id = _orch().clone_for_rerun(aid)

    old_actions = {a.action: a.detail for a in _repo().get_audit(aid)}
    new_actions = {a.action: a.detail for a in _repo().get_audit(new_id)}
    assert new_id in old_actions["rerun_started"]
    assert aid in new_actions["clone_for_rerun"]


# -- the dashboard affordance -----------------------------------------------


def test_the_card_offers_rerun_once_a_plan_is_approved(client):
    aid = _designed(client)
    client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                data={"action": "approve", "select_all": "true"})

    card = client.get("/").text

    assert f'action="/assessment/{aid}/rerun"' in card
    assert 'value="same"' in card


def test_the_card_offers_reimport_when_nothing_is_approved(client):
    aid = _designed(client)

    card = client.get("/").text

    assert f'action="/assessment/{aid}/rerun"' in card
    assert 'value="reimport"' in card


def test_a_freshly_imported_assessment_is_not_offered_a_rerun(client):
    """Before a plan exists the honest next action is "open it and design one"."""
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]

    card = client.get("/").text

    assert f'action="/assessment/{aid}/rerun"' not in card


def test_the_card_shows_what_the_run_found(client):
    aid = _designed(client)
    client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                data={"action": "approve", "test_ids": _ids(aid)[:2]})

    card = client.get("/").text

    assert "2 approved" in card
    assert f"{len(_ids(aid))} test(s)" in card


# -- a re-run that actually executes ----------------------------------------


@pytest.fixture()
def client_with_scope(tmp_path, monkeypatch):
    """Scope and personas pre-set, so an execute() resolves personas and only
    fails to *connect* (nothing listens on this port) instead of raising."""
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:19191",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "agent",
             "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {}, "role": "agent",
             "owns": {"customer_id": "2002"}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'rerun2.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_a_rerun_executes_and_lands_on_the_regression_diff(client_with_scope):
    """The question a re-run is started to answer is "what changed since last
    time", so it ends on the diff rather than back on the assessment page."""
    client = client_with_scope
    aid = _designed(client)
    non_destructive = [t.test_id for t in _repo().get_test_cases(aid) if not t.is_destructive]
    assert non_destructive
    client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                data={"action": "approve", "test_ids": non_destructive})
    client.post(f"/assessment/{aid}/execute", follow_redirects=True)
    assert _repo().get_executions(aid), "the baseline run has to have happened"

    r = client.post(f"/assessment/{aid}/rerun", data={"mode": "same"}, follow_redirects=True)

    assert r.status_code == 200
    assert "Regression diff" in r.text
    new_id = r.url.path.split("/assessment/")[1].split("/")[0]
    assert new_id != aid
    assert _repo().get_executions(new_id), "the re-run should have executed"


def test_a_rerun_never_fires_destructive_tests(client_with_scope):
    """Approving a write probe once, for a run you watched, is not consent to it
    firing again from a button on a list page."""
    client = client_with_scope
    aid = _designed(client)
    client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                data={"action": "approve", "select_all": "true"})
    destructive = {t.test_id for t in _repo().get_test_cases(aid) if t.is_destructive}
    assert destructive, "fixture ticket should include at least one write probe"

    r = client.post(f"/assessment/{aid}/rerun", data={"mode": "same"}, follow_redirects=True)
    new_id = r.url.path.split("/assessment/")[1].split("/")[0]

    ran = {ex.test_id for ex in _repo().get_executions(new_id)}
    assert not (ran & destructive), f"a re-run executed write probes: {ran & destructive}"


def test_a_blocking_configuration_stops_the_rerun_before_it_sends_anything(tmp_path, monkeypatch):
    """Better to land on the cloned plan saying why than to report a run that was
    entirely BLOCKED."""
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:19191",
        # no allowed_hosts and no personas: preflight has blocking checks
        "scope": {"allowed_hosts": [], "allow_private_ranges": False},
        "personas": [],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'blocked.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as client:
        aid = _designed(client)
        client.post(f"/assessment/{aid}/plan", follow_redirects=True,
                    data={"action": "approve", "select_all": "true"})

        r = client.post(f"/assessment/{aid}/rerun", data={"mode": "same"},
                        follow_redirects=True)

        assert "blocking configuration issue" in r.text
        new_id = r.url.path.rsplit("/", 1)[-1]
        assert _repo().get_executions(new_id) == []
