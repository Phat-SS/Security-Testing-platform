"""The agent features as a tester meets them: on the screen and through the routes.

The unit tests prove the agents behave; these prove a person can reach them, and
that what they read is honest about what it is. Two claims get most of the
attention:

  * pressing **Import** with the box ticked lands on a plan to approve, and
    unticking it does not silently do the same thing (an unchecked HTML checkbox
    sends nothing, which is exactly how a "default true" becomes a lie);
  * an agent's reading of a result is never presented as the verdict the runner
    sealed, anywhere it is rendered.
"""

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'agent_ui.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _orch():
    import app.api.main as main

    return main.state.orch


def _import(client, **data) -> str:
    payload = {"issue_key": "CRM-1234"}
    payload.update(data)
    return client.post("/import", data=payload,
                       follow_redirects=True).url.path.rsplit("/", 1)[-1]


# -- import ---------------------------------------------------------------------


def test_the_import_form_offers_the_planning_pass_and_explains_it():
    from app.api import views

    page = views.dashboard([], "http://t", ai_on=False)
    assert 'name="plan"' in page
    assert "Plan &amp; review on import" in page
    assert "every test arrives PENDING" in page


def test_importing_with_the_box_ticked_produces_a_plan_to_approve(client):
    aid = _import(client, plan="true")
    tests = _orch()._repo.get_test_cases(aid)
    assert tests
    assert all(t.approval_status.value == "PENDING" for t in tests)
    assert _orch().plan_review(aid) is not None


def test_importing_with_the_box_unticked_analyzes_only(client):
    """An unchecked checkbox sends nothing at all, so this is the case a "default
    true" would have broken: unticking would have planned anyway."""
    aid = _import(client)
    assert _orch()._repo.get_test_cases(aid) == []
    assert _orch().plan_review(aid) is None


def test_the_page_shows_the_review_beside_the_plan_it_reviewed(client):
    aid = _import(client, plan="true")
    page = client.get(f"/assessment/{aid}").text
    assert "Coverage" in page
    assert "decidable" in page
    # And it says which reviewer produced it, so a structural review is never
    # mistaken for an AI one.
    assert "structural review (no AI)" in page


def test_the_requirements_read_from_the_ticket_are_shown(client):
    aid = _import(client, plan="true")
    page = client.get(f"/assessment/{aid}").text
    assert "Requirements read from the ticket" in page
    assert "R-01" in page
    # ui.section escapes the title it is given, so the ampersand arrives as
    # &amp; exactly once. It used to be pre-escaped and rendered as literal
    # "&amp;" in the heading.
    assert "Requirements &amp; endpoints" in page
    assert "&amp;amp;" not in page


def test_an_unreviewed_plan_offers_the_review_rather_than_pretending(client):
    aid = _import(client)                       # analyze only
    client.post(f"/assessment/{aid}/design", data={"depth": "standard"})
    page = client.get(f"/assessment/{aid}").text
    assert "This plan has not been reviewed." in page
    assert f"/assessment/{aid}/agent-plan" in page


def test_the_agent_plan_route_reviews_and_reports_what_it_did(client):
    aid = _import(client)
    response = client.post(f"/assessment/{aid}/agent-plan", data={"depth": "standard"},
                           follow_redirects=False)
    assert response.status_code == 303
    assert "Plan%20reviewed" in response.headers["location"]
    assert _orch().plan_review(aid) is not None


# -- results --------------------------------------------------------------------


def test_the_results_step_offers_a_review_only_once_something_has_run(client):
    aid = _import(client, plan="true")
    page = client.get(f"/assessment/{aid}").text
    assert "These results have not been reviewed." not in page


def test_adjudicating_an_analyzed_only_assessment_is_refused_without_a_500(client):
    """The route has to survive being reached early — a tester exploring the page
    should not be able to produce a stack trace."""
    aid = _import(client)
    response = client.post(f"/assessment/{aid}/adjudicate", follow_redirects=False)
    assert response.status_code == 303


def test_the_review_panel_names_the_agent_and_the_advisory_status():
    """Rendered directly: the panel must carry the caveat with the value, in
    whatever state the run is."""
    from app.api import views_assessment as va
    from app.schemas.agent import Adjudication, RunAssessment
    from app.schemas.enums import Confidence, TestStatus

    run = RunAssessment(
        assessment_id="A-1", issue_key="CRM-1", overall="FAILED",
        coverage_pct=50, decided_pct=100, n_executions=2,
        n_auto_resolved=1, n_manual_review=1,
        summary="FAILED: one control broke.",
        reviewer="ai",
        adjudications=[
            Adjudication(execution_id="E-1", test_id="API1-001",
                         sealed_result=TestStatus.INCONCLUSIVE,
                         needs_manual_review=False, assessed_result="FAIL",
                         confidence=Confidence.HIGH, adjudicator="ai",
                         rationale="The body holds the victim's record."),
            Adjudication(execution_id="E-2", test_id="API2-001",
                         sealed_result=TestStatus.INCONCLUSIVE,
                         needs_manual_review=True,
                         triage_reason="The positive control failed.",
                         recommended_action="Fix the object id and re-run."),
        ],
    )
    state = va._State(2, {"total": 4, "approved": 4}, 2)
    html = va._assessment_panel("A-1", run, state, {})

    assert "FAILED" in html
    assert "50% of the ticket covered" in html
    assert "AI reviewer" in html
    assert "advisory" in html
    assert "the finding count" in html
    # The one needing a person is shown as that, not as a verdict.
    assert "The positive control failed." in html
    assert "Fix the object id and re-run." in html


def test_the_triage_counts_are_shown_before_any_review_is_asked_for():
    from app.api import views_assessment as va

    state = va._State(2, {"total": 4, "approved": 4}, 4)
    html = va._assessment_panel("A-1", None, state, {"manual": 2, "rerun": 1})
    assert "need a person" in html
    assert "need only a re-run" in html
