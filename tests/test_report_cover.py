"""The report's cover band states the overall risk in one word. That word must
never read as "safe" when the run did not actually decide anything."""

from app.reporting.html import render_report
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import CapturedRequest, CapturedResponse, Execution, Verdict


def _execution(result: TestStatus, n: int = 1) -> Execution:
    return Execution(
        execution_id=f"x{n}", test_id=f"t{n}", owasp_category="API1:2023", scope_validated=True,
        request=CapturedRequest(method="GET", url="http://x/y", resolved_ip="1.2.3.4",
                                headers={}, body=None, timestamp="2024-01-01T00:00:00Z"),
        response=CapturedResponse(status_code=200, headers={}, body="ok", elapsed_ms=1, size_bytes=2),
        verdict=Verdict(result=result, confidence=Confidence.HIGH,
                        expected_summary="s", actual_summary="a", reason="r"),
        evidence_hash="deadbeef",
    )


def _cover(*results: TestStatus) -> str:
    html = render_report(
        title="t", target="http://x", tests={},
        executions=[_execution(r, i) for i, r in enumerate(results)], findings=[],
    )
    return html[html.index('<header class="cover">'):html.index("</header>")]


def test_a_clean_run_says_none_found():
    assert "None Found" in _cover(TestStatus.PASS, TestStatus.PASS)


def test_an_undecided_run_is_not_presented_as_clean():
    cover = _cover(TestStatus.PASS, TestStatus.INCONCLUSIVE)
    assert "Undetermined" in cover
    assert "None Found" not in cover


def test_the_cover_counts_every_test_that_ran():
    cover = _cover(TestStatus.PASS, TestStatus.BLOCKED, TestStatus.ERROR)
    assert '<div class="k">Tests Run</div><div class="v">3</div>' in cover


def test_the_language_switch_lands_in_the_cover():
    html = render_report(title="t", target="http://x", tests={}, executions=[], findings=[])
    assert "<!--lang-->" not in html
    assert 'href="?lang=vi"' in html[:html.index("</header>")]
