"""The other half of the Jira comment's diet.

The comment stopped carrying the per-test explanation, which is only defensible
if the explanation is actually somewhere. These tests assert the report renders
every piece that was removed — and renders it beside the captured request and
response, which is the reason it was moved rather than deleted.

They also cover the two agent sections, and the one rendering rule that matters
most in the whole feature: an agent's reading of a result must never be
presentable as the verdict the runner sealed.
"""

from app.reporting.html import render_report
from app.schemas.agent import (
    Adjudication,
    PlanReview,
    PlanReviewGap,
    RequirementCoverage,
    RunAssessment,
)
from app.schemas.enums import Confidence, OwaspApiCategory, Severity, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    Execution,
    RepeatStats,
    SupportingExchange,
    Verdict,
)
from app.schemas.finding import CorrelationEvidence, Finding
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)


def _test():
    return TestCase(
        test_id="API1-001", title="BOLA on the customer endpoint", objective="o",
        owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path="/customers/{customerId}"),
        attack_mutation=Mutation(kind="swap_object_id", detail={"id_field": "customerId"}),
        expected=ExpectedResult(status_in=[403, 404]),
    )


def _execution(test, result=TestStatus.FAIL, status=200, supporting=None, repeat=None):
    return Execution(
        execution_id=f"E-{test.test_id}", test_id=test.test_id,
        owasp_category=test.owasp_category.value, scope_validated=True,
        request=CapturedRequest(
            method="GET", url="http://target.test/customers/2002",
            resolved_ip="203.0.113.10", headers={"Authorization": "********"},
            timestamp="2026-08-18T00:00:00Z",
        ),
        response=CapturedResponse(status_code=status, headers={}, body="{}",
                                  elapsed_ms=12, size_bytes=2),
        verdict=Verdict(
            result=result, confidence=Confidence.HIGH,
            expected_summary="status in [403, 404]",
            actual_summary="HTTP 200; the response disclosed 1 protected marker(s)",
            reason="The mutated request returned data belonging to another identity.",
        ),
        attack_note="targeted object id 2002 owned by another identity",
        supporting=supporting or [],
        repeat=repeat,
    )


def _finding():
    return Finding(
        finding_id="SEC-001", title="Broken Object Level Authorization",
        owasp_category=OwaspApiCategory.API1, severity=Severity.HIGH,
        confidence=Confidence.HIGH, endpoint="GET /customers/{customerId}",
        dedup_key="k", affected_tests=["API1-001"],
        correlation=CorrelationEvidence(
            baseline_summary="agent_B owns the object",
            attack_summary="agent_A GET → HTTP 200",
            expected="status in [403, 404]",
            actual="HTTP 200; the response disclosed 1 protected marker(s)",
        ),
        impact="An authenticated user can read another user's data.",
        reproduction=["Authenticate as agent_A.", "Request the victim's object id."],
        recommendation="Enforce server-side object ownership checks.",
        references=["https://owasp.org/API-Security/"],
    )


def _render(**kwargs):
    test = kwargs.pop("test", None) or _test()
    executions = kwargs.pop("executions", None) or [_execution(test)]
    return render_report(
        title="Security Assessment — CRM-1234", target="http://target.test",
        tests={test.test_id: test}, executions=executions,
        findings=kwargs.pop("findings", None) or [], **kwargs,
    )


# -- everything the comment stopped carrying is here ---------------------------


def test_the_report_carries_the_attack_and_its_parameters():
    html = _render()
    assert "Attack Performed" in html
    assert "swap_object_id" in html
    assert "targeted object id 2002 owned by another identity" in html
    assert "Attack Parameters" in html
    assert "id_field" in html


def test_the_report_carries_expected_versus_observed():
    """A verdict is a comparison. Printing only its conclusion asks a reader to
    take on trust that the comparison happened."""
    html = _render()
    assert "Expected" in html
    assert "status in [403, 404]" in html
    assert "Observed" in html
    assert "1 protected marker(s)" in html


def test_the_report_carries_the_verdicts_reasoning_next_to_the_evidence():
    html = _render()
    assert "returned data belonging to another identity" in html
    # ...and the request/response panels the reasoning refers to.
    assert "http://target.test/customers/2002" in html
    assert "<h4>Request" in html
    assert "<h4>Response " in html


def test_the_report_carries_a_findings_impact_reproduction_and_fix():
    # Assertions avoid apostrophes: `_e()` escapes them to &#x27;, so matching
    # the source sentence verbatim would fail for a rendering that is correct.
    html = _render(findings=[_finding()])
    assert "An authenticated user can read another user" in html
    assert "Authenticate as agent_A." in html
    assert "Enforce server-side object ownership checks." in html


def test_the_report_carries_the_supporting_exchanges():
    test = _test()
    supporting = [SupportingExchange(
        kind="baseline", as_persona="agent_B",
        request=CapturedRequest(method="GET", url="http://target.test/customers/2002",
                                resolved_ip="203.0.113.10", headers={}, timestamp="t"),
        response=CapturedResponse(status_code=200, headers={}, body="{}",
                                  elapsed_ms=5, size_bytes=2),
        note="positive control succeeded: the target is reachable",
    )]
    repeat = RepeatStats(sent=10, succeeded=10, status_counts={"200": 10},
                         throttled=False, concurrent=True)
    html = _render(test=test,
                   executions=[_execution(test, supporting=supporting, repeat=repeat)])
    assert "Positive Control" in html
    assert "the target is reachable" in html
    assert "Multi-request probe" in html


def test_a_blocked_test_still_explains_what_the_attack_would_have_done():
    """`attack_note` is empty when the mutation never ran, and that is exactly
    when the reader has no other way to find out what was meant to happen."""
    test = _test()
    execution = _execution(test, result=TestStatus.BLOCKED)
    execution.attack_note = ""
    html = _render(test=test, executions=[execution])
    assert "Attack Performed" in html
    assert "swap_object_id" in html


# -- the run assessment section ------------------------------------------------


def _run(**kwargs):
    defaults = dict(
        assessment_id="A-1", issue_key="CRM-1234", overall="FAILED",
        coverage_pct=67, decided_pct=80,
        items=[
            RequirementCoverage(item_id="R-01", text="An agent must not read another "
                                                    "agent customer record",
                                state="COVERED_FAIL", tests=["API1-001"],
                                note="A test for this requirement failed."),
            RequirementCoverage(item_id="R-02", text="Admins may re-assign a customer",
                                state="NOT_TESTED", tests=[],
                                note="No test in API5:2023 addresses this."),
        ],
        n_executions=1, n_fail=1, n_manual_review=0,
        summary="FAILED: one control broke.",
    )
    defaults.update(kwargs)
    return RunAssessment(**defaults)


def test_the_run_assessment_shows_pass_fail_and_coverage_with_its_workings():
    html = _render(run_assessment=_run())
    assert "Assessment of This Run" in html
    assert "FAILED" in html
    assert "67%" in html
    # The percentage is decomposable: every item and what the run proved about it.
    assert "R-01" in html
    assert "R-02" in html
    assert "NOT TESTED" in html
    assert "No test in API5:2023 addresses this." in html


def test_the_run_assessment_says_a_reviewed_result_is_advisory():
    html = _render(run_assessment=_run())
    assert "advisory" in html
    assert "never overwrites the verdict the runner sealed" in html


def test_a_report_without_an_assessment_omits_the_section():
    html = _render()
    assert "Assessment of This Run" not in html


# -- adjudications -------------------------------------------------------------


def _adjudication(**kwargs):
    defaults = dict(
        execution_id="E-API1-001", test_id="API1-001",
        sealed_result=TestStatus.INCONCLUSIVE, needs_manual_review=False,
        triage_reason="The attack was accepted and the response has a body.",
        assessed_result="FAIL", confidence=Confidence.HIGH, adjudicator="ai",
        rationale="The body holds a customer record the attacking persona does not own.",
        evidence_cited=["a customer record belonging to the victim persona"],
        recommended_action="Confirm by hand, then re-run with a read-back.",
    )
    defaults.update(kwargs)
    return Adjudication(**defaults)


def test_an_adjudication_is_rendered_on_the_row_it_judges():
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE)
    html = _render(test=test, executions=[execution],
                   run_assessment=_run(adjudications=[_adjudication()]))
    assert "Reviewed as FAIL" in html
    assert "a customer record belonging to the victim persona" in html
    assert "Confirm by hand" in html


def test_an_adjudication_always_names_who_produced_it_and_that_it_is_advisory():
    """The single most misleading thing this report could do is print an agent's
    reading in the same voice as a hashed, rule-derived verdict."""
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE)
    html = _render(test=test, executions=[execution],
                   run_assessment=_run(adjudications=[_adjudication()]))
    assert "AI Reviewer" in html
    assert "does not change the sealed verdict or create a finding" in html
    # And the sealed verdict is still the one in the Result column.
    assert "INCONCLUSIVE" in html


def test_a_deterministic_adjudication_says_so_rather_than_claiming_a_reviewer():
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE)
    html = _render(test=test, executions=[execution],
                   run_assessment=_run(adjudications=[
                       _adjudication(adjudicator="deterministic")]))
    assert "deterministic triage" in html
    assert "AI Reviewer" not in html


def test_a_result_needing_a_person_says_that_instead_of_a_verdict():
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE)
    html = _render(test=test, executions=[execution],
                   run_assessment=_run(adjudications=[_adjudication(
                       needs_manual_review=True, assessed_result="INCONCLUSIVE",
                       triage_reason="The positive control failed.",
                   )]))
    assert "Needs Manual Review" in html
    assert "The positive control failed." in html
    assert "Reviewed as" not in html


# -- the plan review section ---------------------------------------------------


def _review(**kwargs):
    defaults = dict(
        verdict="REVISE", coverage_score=80, quality_score=60,
        gaps=[PlanReviewGap(description="No test for admin re-assignment.",
                            category=OwaspApiCategory.API5, severity="blocking",
                            requirement_id="R-02")],
        unresolved_gaps=[],
        strengths=["6/7 applicable OWASP categories have a test."],
        notes="Structural review of 12 test(s).",
        reviewer="ai", rounds=1, tests_before=12, tests_after=14,
        tests_added=["AIR1-API5-001", "AIR1-API5-002"],
    )
    defaults.update(kwargs)
    return PlanReview(**defaults)


def test_the_plan_review_is_part_of_the_report():
    """It is part of why this run tested what it tested — the honest answer to
    "why is there no BFLA result here" six months later."""
    html = _render(plan_review=_review())
    assert "Plan Review" in html
    assert "REVISE" in html
    assert "No test for admin re-assignment." in html
    assert "AIR1-API5-001" not in html  # ids are not the point; the count is
    assert "Added After Review" in html


def test_unresolved_gaps_are_shown_separately_from_gaps_that_were_closed():
    html = _render(plan_review=_review(
        verdict="INSUFFICIENT",
        unresolved_gaps=[PlanReviewGap(description="Still nothing tests rate limiting.",
                                       severity="blocking")],
    ))
    assert "Still Unresolved" in html
    assert "Still nothing tests rate limiting." in html


def test_a_structural_only_review_does_not_claim_an_ai_read_the_plan():
    html = _render(plan_review=_review(reviewer="deterministic"))
    assert "structural review (no AI)" in html


def test_a_report_without_a_review_omits_the_section():
    html = _render()
    assert "Plan Review" not in html


def test_a_row_awaiting_a_re_run_is_not_described_as_having_been_reviewed():
    """"Reviewed as INCONCLUSIVE" claims a reading that did not happen, and the
    confidence beside it was inherited from the sealed verdict — which reads as
    confidence in that non-reading."""
    test = _test()
    execution = _execution(test, result=TestStatus.ERROR)
    html = _render(test=test, executions=[execution],
                   run_assessment=_run(adjudications=[_adjudication(
                       adjudicator="deterministic", needs_manual_review=False,
                       assessed_result="INCONCLUSIVE", confidence=Confidence.HIGH,
                       triage_reason="The runner itself failed.",
                       evidence_cited=[], rationale="",
                   )]))
    assert "Still undecided" in html
    assert "Reviewed as INCONCLUSIVE" not in html
    assert "HIGH confidence" not in html


def test_a_decided_reading_still_carries_its_confidence():
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE)
    html = _render(test=test, executions=[execution],
                   run_assessment=_run(adjudications=[_adjudication()]))
    assert "HIGH confidence" in html
