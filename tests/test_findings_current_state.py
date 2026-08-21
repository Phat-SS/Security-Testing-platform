from app.pipeline.findings import build_findings
from app.schemas.enums import (
    ApprovalStatus,
    Confidence,
    OwaspApiCategory,
    Severity,
    TestStatus,
)
from app.schemas.execution import CapturedRequest, CapturedResponse, Execution, Verdict
from app.schemas.testcase import AuthContext, ExpectedResult, Mutation, RequestSpec, TestCase


def _test(test_id: str, mutation: str) -> TestCase:
    return TestCase(
        test_id=test_id,
        title="Authentication boundary",
        objective="The endpoint must reject an invalid identity.",
        owasp_category=OwaspApiCategory.API2,
        severity=Severity.HIGH,
        auth_context=AuthContext(persona="attacker"),
        request=RequestSpec(method="GET", path="/account"),
        attack_mutation=Mutation(kind=mutation),
        expected=ExpectedResult(status_in=[401, 403]),
        approval_status=ApprovalStatus.APPROVED,
    )


def _execution(test_id: str, execution_id: str, result: TestStatus) -> Execution:
    return Execution(
        execution_id=execution_id,
        test_id=test_id,
        owasp_category=OwaspApiCategory.API2.value,
        scope_validated=True,
        request=CapturedRequest(
            method="GET",
            url="https://api.example/account",
            resolved_ip="203.0.113.10",
            headers={},
            timestamp="2026-01-01T00:00:00Z",
        ),
        response=CapturedResponse(
            status_code=200 if result == TestStatus.FAIL else 403,
            headers={},
            body="{}",
            elapsed_ms=10,
            size_bytes=2,
        ),
        verdict=Verdict(
            result=result,
            confidence=Confidence.HIGH,
            expected_summary="authentication refusal",
            actual_summary=result.value,
            reason="fixture",
        ),
    )


def test_later_pass_closes_an_older_fail_for_the_same_test():
    test = _test("AUTH-1", "drop_auth")

    findings = build_findings(
        {test.test_id: test},
        [
            _execution(test.test_id, "E-1", TestStatus.FAIL),
            _execution(test.test_id, "E-2", TestStatus.PASS),
        ],
    )

    assert findings == []


def test_a_test_omitted_from_a_partial_later_batch_keeps_its_latest_state():
    first = _test("AUTH-1", "drop_auth")
    second = _test("AUTH-2", "tamper_token")

    findings = build_findings(
        {first.test_id: first, second.test_id: second},
        [
            _execution(first.test_id, "E-1", TestStatus.FAIL),
            _execution(second.test_id, "E-2", TestStatus.PASS),
            _execution(second.test_id, "E-3", TestStatus.PASS),
        ],
    )

    assert len(findings) == 1
    assert findings[0].affected_tests == [first.test_id]


def test_mutation_variants_for_one_root_cause_are_one_finding():
    dropped = _test("AUTH-1", "drop_auth")
    malformed = _test("AUTH-2", "tamper_token")

    findings = build_findings(
        {dropped.test_id: dropped, malformed.test_id: malformed},
        [
            _execution(dropped.test_id, "E-1", TestStatus.FAIL),
            _execution(malformed.test_id, "E-2", TestStatus.FAIL),
        ],
    )

    assert len(findings) == 1
    assert findings[0].affected_tests == [dropped.test_id, malformed.test_id]
    assert findings[0].dedup_key.endswith("missing_authentication_validation")
