"""M1 (identical_body) must not seal a finding for data that is simply public."""

from app.analysis.evidence_signals import analyze_evidence, measure
from app.execution.evidence import seal
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    Execution,
    SupportingExchange,
    Verdict,
)
from app.schemas.testcase import AuthContext, ExpectedResult, Mutation, RequestSpec, TestCase


def _test():
    return TestCase(
        test_id="API1-1", title="t", objective="o", owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path="/items/{id}"),
        attack_mutation=Mutation(kind="swap_object_id"),
        expected=ExpectedResult(status_in=[403, 404]),
    )


def _exec(body):
    def resp():
        return CapturedResponse(status_code=200, headers={}, body=body, elapsed_ms=2,
                                size_bytes=len(body))
    return seal(Execution(
        execution_id="E-1", test_id="API1-1", owasp_category="API1:2023", scope_validated=True,
        request=CapturedRequest(method="GET", url="https://a.example/items/2",
                                resolved_ip="203.0.113.5", headers={},
                                timestamp="2026-01-01T00:00:00Z"),
        response=resp(),
        verdict=Verdict(result=TestStatus.INCONCLUSIVE, confidence=Confidence.MEDIUM,
                        expected_summary="", actual_summary="", reason="x"),
        supporting=[SupportingExchange(kind="baseline", as_persona="agent_B",
                                       request=CapturedRequest(
                                           method="GET", url="https://a.example/items/2",
                                           resolved_ip="203.0.113.5", headers={},
                                           timestamp="2026-01-01T00:00:00Z"),
                                       response=resp())],
    ), None)


def test_identical_body_with_owner_specific_values_is_high():
    body = '{"id": 2002, "email": "beth@example.com", "name": "Beth Carter", "iban": "GB29NWBK60161331926819"}'
    reading = measure(_test(), _exec(body))
    assert reading is not None and reading.rule == "identical_body"
    assert reading.confidence == "HIGH"


def test_identical_body_with_nothing_owner_specific_is_not_high():
    body = '{"status": "ok", "version": "1.0", "items": []}' + " " * 40
    assert analyze_evidence(_test(), _exec(body)).identical_body
    reading = measure(_test(), _exec(body))
    assert reading is not None and reading.confidence == "MEDIUM"
