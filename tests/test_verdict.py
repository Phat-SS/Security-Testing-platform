"""Verdict logic — the anti-false-positive core. A 200 alone is never a vuln."""

from app.execution.verdict import evaluate
from app.schemas.enums import TestStatus
from app.schemas.execution import CapturedResponse
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)


def _test(status_in, must_not=None):
    return TestCase(
        test_id="T-1", title="t", objective="o",
        owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path="/x/{id}"),
        attack_mutation=Mutation(kind="swap_object_id"),
        expected=ExpectedResult(status_in=status_in, body_must_not_contain=must_not or []),
    )


def _resp(status, body="{}"):
    return CapturedResponse(status_code=status, headers={}, body=body,
                            elapsed_ms=5, size_bytes=len(body))


def test_rejected_attack_with_no_leak_is_pass():
    v = evaluate(_test([403, 404]), _resp(403), leaked_markers=[])
    assert v.result == TestStatus.PASS


def test_confirmed_leak_is_fail_high_confidence():
    v = evaluate(_test([403, 404]), _resp(200, '{"email":"beth@x.com"}'),
                 leaked_markers=["beth@x.com"])
    assert v.result == TestStatus.FAIL
    assert v.confidence.value == "HIGH"


def test_unexpected_200_without_confirmable_leak_is_inconclusive():
    # accepted the attack, but nothing to prove disclosure → NOT a finding.
    v = evaluate(_test([403, 404]), _resp(200, "{}"), leaked_markers=[])
    assert v.result == TestStatus.INCONCLUSIVE


def test_server_error_is_inconclusive():
    v = evaluate(_test([403, 404]), _resp(500), leaked_markers=[])
    assert v.result == TestStatus.INCONCLUSIVE


def test_no_response_is_blocked():
    v = evaluate(_test([403]), None, leaked_markers=[])
    assert v.result == TestStatus.BLOCKED


def test_every_verdict_has_reason():
    for resp, leaked in [(_resp(403), []), (_resp(200, "x"), ["x"]), (_resp(200), []),
                         (_resp(500), []), (None, [])]:
        assert evaluate(_test([403]), resp, leaked).reason
