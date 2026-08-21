from app.reporting.quality import build_finding_drafts, verify_report
from app.schemas.enums import Confidence, OwaspApiCategory, Severity, TestStatus
from app.schemas.execution import CapturedRequest, CapturedResponse, Execution, Verdict
from app.schemas.finding import CorrelationEvidence, Finding


def _execution() -> Execution:
    return Execution(
        execution_id="E-1", test_id="T-1", owasp_category="API1", scope_validated=True,
        request=CapturedRequest(method="GET", url="https://api.example/customer/2",
                                resolved_ip="203.0.113.2", headers={},
                                timestamp="2026-01-01T00:00:00Z"),
        response=CapturedResponse(status_code=200, headers={}, body="{}",
                                  elapsed_ms=1, size_bytes=2),
        verdict=Verdict(result=TestStatus.FAIL, confidence=Confidence.HIGH,
                        expected_summary="deny", actual_summary="victim data returned",
                        reason="correlated disclosure"),
        evidence_hash="abc123",
    )


def _finding() -> Finding:
    return Finding(
        finding_id="SEC-001", title="Cross-tenant customer read",
        owasp_category=OwaspApiCategory.API1, severity=Severity.HIGH,
        confidence=Confidence.HIGH, endpoint="GET /customer/{id}",
        dedup_key="API1|GET /customer/{id}|missing_object_authorization",
        affected_tests=["T-1"],
        correlation=CorrelationEvidence(baseline_summary="owner succeeds",
                                        attack_summary="attacker succeeds",
                                        expected="deny", actual="victim data returned"),
        impact="Another tenant's customer record is exposed.",
        reproduction=["Authenticate as the attacker.", "Request the victim id."],
        recommendation="Authorize every object read.",
    )


def test_deterministic_draft_is_grounded_in_the_execution():
    execution = _execution()
    finding = _finding()
    drafts = build_finding_drafts([finding], {}, [execution])

    result = verify_report([finding], drafts, [execution])

    assert result.ok
    assert result.checked_references == 1
    assert drafts[0].evidence[0].execution_id == execution.execution_id


def test_verifier_rejects_a_reference_whose_hash_does_not_match():
    execution = _execution()
    finding = _finding()
    drafts = build_finding_drafts([finding], {}, [execution])
    drafts[0].evidence[0].evidence_hash = "forged"

    result = verify_report([finding], drafts, [execution])

    assert not result.ok
    assert any(issue.code == "evidence_hash_mismatch" for issue in result.issues)


def test_verifier_rejects_secret_shaped_narrative_text():
    execution = _execution()
    finding = _finding()
    drafts = build_finding_drafts([finding], {}, [execution])
    drafts[0].impact = "Leaked Bearer eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJ"

    result = verify_report([finding], drafts, [execution])

    assert not result.ok
    assert any(issue.code == "unredacted_secret" for issue in result.issues)
