"""render_report's evidence-chain banner must distinguish three states:
verified (True), tampered (False), and not-checked (None) — collapsing
None into False would falsely tell a reader the evidence was tampered with
when the caller simply never verified it."""

from app.reporting.html import render_report
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import CapturedRequest, CapturedResponse, Execution, Verdict


def _execution() -> Execution:
    return Execution(
        execution_id="x1", test_id="t1", owasp_category="API1:2023", scope_validated=True,
        request=CapturedRequest(method="GET", url="http://x/y", resolved_ip="1.2.3.4",
                                headers={}, body=None, timestamp="2024-01-01T00:00:00Z"),
        response=CapturedResponse(status_code=200, headers={}, body="ok", elapsed_ms=1, size_bytes=2),
        verdict=Verdict(result=TestStatus.PASS, confidence=Confidence.HIGH,
                        expected_summary="s", actual_summary="a", reason="r"),
        evidence_hash="deadbeef",
    )


def _report(chain_ok) -> str:
    ex = _execution()
    return render_report(
        title="t", target="http://x", tests={}, executions=[ex],
        findings=[], evidence_chain_ok=chain_ok,
    )


def test_verified_chain_shows_positive_banner():
    html = _report(True)
    assert "Evidence chain verified" in html
    assert "FAILED" not in html


def test_broken_chain_shows_failure_banner():
    html = _report(False)
    assert "FAILED verification" in html


def test_unchecked_chain_shows_no_banner_at_all():
    # None means "not checked", not "checked and failed" — must not print
    # either the verified or the failed banner.
    html = _report(None)
    assert "Evidence chain verified" not in html
    assert "FAILED" not in html


def test_no_executions_shows_no_banner_regardless_of_flag():
    html = render_report(title="t", target="http://x", tests={}, executions=[], findings=[],
                         evidence_chain_ok=False)
    assert "FAILED" not in html
    assert "Evidence chain verified" not in html
