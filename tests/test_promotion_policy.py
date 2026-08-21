from app.analysis.promotion import evaluate_promotion
from app.execution.evidence import seal
from app.pipeline.findings import build_findings
from app.schemas.agent import Adjudication
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import CapturedRequest, CapturedResponse, Execution, Verdict
from app.schemas.testcase import AuthContext, ExpectedResult, Mutation, RequestSpec, TestCase


def _test() -> TestCase:
    return TestCase(
        test_id="API2-001",
        title="Authentication boundary",
        objective="Reject an invalid credential.",
        owasp_category="API2:2023",
        severity="HIGH",
        auth_context=AuthContext(persona="attacker"),
        request=RequestSpec(method="GET", path="/account"),
        attack_mutation=Mutation(kind="drop_auth"),
        expected=ExpectedResult(status_in=[401, 403]),
    )


def _execution() -> Execution:
    return seal(Execution(
        execution_id="E-1",
        test_id="API2-001",
        owasp_category="API2:2023",
        scope_validated=True,
        request=CapturedRequest(
            method="GET", url="https://api.example/account", resolved_ip="203.0.113.5",
            headers={}, timestamp="2026-01-01T00:00:00Z",
        ),
        response=CapturedResponse(
            status_code=422, headers={}, body='{"error":"business validation"}',
            elapsed_ms=3, size_bytes=31,
        ),
        verdict=Verdict(
            result=TestStatus.INCONCLUSIVE,
            confidence=Confidence.MEDIUM,
            expected_summary="HTTP 401/403",
            actual_summary="HTTP 422",
            reason="Status alone cannot prove authentication bypass.",
        ),
    ), None)


def test_named_measurement_can_promote_without_mutating_sealed_execution():
    execution = _execution()
    original_hash = execution.evidence_hash
    adjudication = Adjudication(
        execution_id=execution.execution_id,
        test_id=execution.test_id,
        sealed_result=TestStatus.INCONCLUSIVE,
        needs_manual_review=False,
        assessed_result="FAIL",
        confidence=Confidence.HIGH,
        resolution="measured",
        rule="credential_removed_reached_business_logic",
        signals=["attack HTTP 422 differs from baseline HTTP 200"],
    )

    event = evaluate_promotion(execution, adjudication)

    assert event is not None and event.promoted is True
    assert execution.verdict.result == TestStatus.INCONCLUSIVE
    assert execution.evidence_hash == original_hash
    findings = build_findings({_test().test_id: _test()}, [execution], [event])
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_ai_opinion_without_challenge_and_provenance_is_not_promoted():
    execution = _execution()
    event = evaluate_promotion(execution, Adjudication(
        execution_id=execution.execution_id,
        test_id=execution.test_id,
        sealed_result=TestStatus.INCONCLUSIVE,
        needs_manual_review=False,
        assessed_result="FAIL",
        confidence=Confidence.HIGH,
        adjudicator="ai",
        resolution="ai_consensus",
        evidence_cited=["HTTP 422 after credential removal"],
    ))

    assert event is not None and event.promoted is False
    assert build_findings({_test().test_id: _test()}, [execution], [event]) == []


def test_grounded_high_confidence_ai_consensus_can_be_promoted():
    execution = _execution()
    event = evaluate_promotion(execution, Adjudication(
        execution_id=execution.execution_id,
        test_id=execution.test_id,
        sealed_result=TestStatus.INCONCLUSIVE,
        needs_manual_review=False,
        assessed_result="FAIL",
        confidence=Confidence.HIGH,
        adjudicator="ai",
        resolution="ai_consensus",
        challenged=True,
        challenge_agreed=True,
        challenge_note="A second pass tried to refute this reading and could not.",
        evidence_cited=["HTTP 422 reached business validation"],
        model_id="claude-sonnet-4-20260514",
        prompt_hash="abc123",
    ))

    assert event is not None and event.promoted is True


def test_tampered_derived_event_cannot_mint_a_finding():
    execution = _execution()
    adjudication = Adjudication(
        execution_id=execution.execution_id,
        test_id=execution.test_id,
        sealed_result=TestStatus.INCONCLUSIVE,
        needs_manual_review=False,
        assessed_result="FAIL",
        confidence=Confidence.HIGH,
        resolution="measured",
        rule="credential_removed_reached_business_logic",
        signals=["decisive differential"],
    )
    event = evaluate_promotion(execution, adjudication)
    assert event is not None
    event.reason = "tampered after signing"

    assert build_findings({_test().test_id: _test()}, [execution], [event]) == []
