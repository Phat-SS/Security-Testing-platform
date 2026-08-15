from app.analysis import HeuristicAnalyzer, TestDesigner
from app.mcp.jira import NormalizedIssue
from app.owasp.coverage import compute_coverage, coverage_summary
from app.schemas.enums import ApprovalStatus, OwaspApiCategory


def _issue(**kw):
    base = dict(issue_key="CRM-1", project_key="CRM")
    base.update(kw)
    return NormalizedIssue(**base)


def test_extracts_endpoint_and_object_id():
    issue = _issue(
        summary="Delete customer API",
        description="DELETE /customers/{customerId} removes a customer. Requires a Bearer JWT.",
    )
    analysis = HeuristicAnalyzer().analyze(issue)
    assert analysis.endpoints
    ep = analysis.endpoints[0]
    assert ep.method == "DELETE"
    assert "customerId" in ep.object_id_params
    assert OwaspApiCategory.API1 in analysis.applicable_categories()
    assert analysis.sensitive_operation is True


def test_sentence_punctuation_is_not_part_of_the_path():
    issue = _issue(
        description=(
            "PATCH /reports/{reportId} updates a report.\n"
            "Severity cannot be set through PATCH /reports/{reportId}.\n"
            "See GET /reports/{reportId} (read-only)."
        ),
    )
    analysis = HeuristicAnalyzer().analyze(issue)
    paths = [f"{e.method} {e.path}" for e in analysis.endpoints]
    assert paths == ["PATCH /reports/{reportId}", "GET /reports/{reportId}"]


def test_detects_poc_reference():
    issue = _issue(description="Run PoC: python poc_customer.py against staging")
    analysis = HeuristicAnalyzer().analyze(issue)
    assert analysis.detected_pocs


def test_ssrf_signal_from_webhook():
    issue = _issue(description="POST /notifications accepts a callback url webhook")
    analysis = HeuristicAnalyzer().analyze(issue)
    assert OwaspApiCategory.API7 in analysis.applicable_categories()


def test_designer_generates_pending_tests():
    issue = _issue(
        summary="Customer API",
        description="GET /customers/{customerId} returns a customer. Bearer JWT required.",
    )
    analysis = HeuristicAnalyzer().analyze(issue)
    tests = TestDesigner().design(analysis)
    assert tests
    assert all(t.approval_status == ApprovalStatus.PENDING for t in tests)
    assert all(not t.is_runnable() for t in tests)
    cats = {t.owasp_category for t in tests}
    assert OwaspApiCategory.API1 in cats  # BOLA generated for the id endpoint


def test_designer_marks_destructive():
    issue = _issue(description="DELETE /customers/{customerId} deletes. Bearer required.")
    analysis = HeuristicAnalyzer().analyze(issue)
    tests = TestDesigner().design(analysis)
    bola = [t for t in tests if t.owasp_category == OwaspApiCategory.API1][0]
    assert bola.is_destructive is True


def test_coverage_marks_missing_when_no_poc():
    issue = _issue(description="GET /customers/{customerId}. Bearer JWT required.")
    analysis = HeuristicAnalyzer().analyze(issue)
    generated = TestDesigner().design(analysis)
    rows = compute_coverage(analysis, existing_poc_tests=[], generated_tests=generated)
    summary = coverage_summary(rows)
    assert summary["applicable"] >= 1
    api1_row = [r for r in rows if r.category == OwaspApiCategory.API1][0]
    assert api1_row.state == "MISSING"
