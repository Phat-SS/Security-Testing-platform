"""Postman transpiler, exports, staged analyzer, and the gated Python runner."""

import json

from app.analysis.staged import StagedAnalyzer
from app.execution.python_runner import PythonRunner
from app.mcp.jira import NormalizedIssue
from app.poc.postman import postman_to_test_cases, transpile_postman
from app.reporting.exports import export_json, export_xlsx

COLLECTION = {
    "info": {"name": "CRM", "schema": "v2.1.0"},
    "item": [
        {"name": "Get customer", "request": {
            "method": "GET",
            "header": [{"key": "Authorization", "value": "Bearer tokenA"}],
            "url": {"raw": "https://api-staging.company.com/customers/2002",
                    "host": ["api-staging", "company", "com"], "path": ["customers", "2002"]}}},
        {"name": "folder", "item": [
            {"name": "Create", "request": {
                "method": "POST",
                "url": {"raw": "https://api-staging.company.com/customers"},
                "body": {"mode": "raw", "raw": "{\"name\": \"x\"}"}}}]},
    ],
}


# -- Postman ---------------------------------------------------------------

def test_postman_extracts_nested_requests():
    result = transpile_postman(COLLECTION)
    methods = {r.method for r in result.requests}
    assert methods == {"GET", "POST"}


def test_postman_to_test_cases_strips_host():
    tests = postman_to_test_cases(COLLECTION)
    assert tests
    for t in tests:
        assert "company.com" not in t.request.path
        assert t.request.path.startswith("/customers")


def test_postman_accepts_json_string():
    assert transpile_postman(json.dumps(COLLECTION)).requests


# -- Exports ---------------------------------------------------------------

def _issue():
    return NormalizedIssue(issue_key="CRM-1", project_key="CRM",
                           summary="GET /customers/{customerId}. Bearer JWT.")


def _sample_tests():
    from app.analysis import HeuristicAnalyzer, TestDesigner

    analysis = HeuristicAnalyzer().analyze(_issue())
    return TestDesigner().design(analysis)


def test_export_json_valid():
    tests = _sample_tests()
    out = export_json("CRM-1", "http://t", tests, [], [], coverage=[])
    data = json.loads(out)
    assert data["issue_key"] == "CRM-1"
    assert data["test_cases"]


def test_export_xlsx_is_a_workbook():
    tests = _sample_tests()
    blob = export_xlsx("CRM-1", "http://t", tests, [], [], coverage=[])
    # xlsx files are zip archives — magic bytes PK\x03\x04
    assert blob[:2] == b"PK"
    assert len(blob) > 2000


# -- Staged analyzer (fake LLM) --------------------------------------------

class FakeLLM:
    def complete(self, system, user):
        return json.dumps({
            "business_summary": "Customer API",
            "actors": ["agent"],
            "sensitive_operation": True,
            "endpoints": [{"method": "GET", "path": "/customers/{customerId}",
                           "auth_required": True, "object_id_params": ["customerId"],
                           "writes_properties": False, "url_fields": []}],
        })


class BrokenLLM:
    def complete(self, system, user):
        return "not json at all"


def test_staged_analyzer_uses_validated_llm_output():
    analysis = StagedAnalyzer(FakeLLM()).analyze(_issue())
    from app.schemas.enums import OwaspApiCategory
    assert OwaspApiCategory.API1 in analysis.applicable_categories()
    assert analysis.endpoints[0].path == "/customers/{customerId}"


def test_staged_analyzer_falls_back_on_bad_llm_output():
    # invalid AI output must NOT crash or poison the pipeline — fall back.
    analysis = StagedAnalyzer(BrokenLLM()).analyze(_issue())
    assert analysis.issue_key == "CRM-1"
    assert analysis.endpoints  # heuristic still produced something


# -- Gated Python runner ---------------------------------------------------

SAFE = 'print("hello from poc")'
DANGEROUS = 'import os\nos.system("echo pwned")'


def test_python_runner_disabled_by_default():
    r = PythonRunner(enabled=False).run(SAFE, reviewed=True)
    assert not r.ran
    assert "disabled" in r.refused_reason


def test_python_runner_requires_review():
    r = PythonRunner(enabled=True, egress_proxy="http://proxy:8080").run(SAFE, reviewed=False)
    assert not r.ran
    assert "reviewed" in r.refused_reason


def test_python_runner_rejects_dangerous_even_when_enabled():
    r = PythonRunner(enabled=True, egress_proxy="http://proxy:8080").run(DANGEROUS, reviewed=True)
    assert not r.ran
    assert "system" in r.flagged_constructs


def test_python_runner_refuses_without_egress_proxy():
    r = PythonRunner(enabled=True, egress_proxy="").run(SAFE, reviewed=True)
    assert not r.ran
    assert "EGRESS_PROXY" in r.refused_reason


def test_python_runner_refuses_outside_sandbox_even_with_proxy():
    # Gates 1-4 satisfied, but not actually inside the isolation container —
    # an egress proxy env var alone must not be treated as a real boundary.
    r = PythonRunner(enabled=True, egress_proxy="http://127.0.0.1:9999",
                     sandboxed=False).run(SAFE, reviewed=True)
    assert not r.ran
    assert "sandbox" in r.refused_reason.lower()


def test_python_runner_runs_safe_code_when_all_gates_pass():
    # all five gates satisfied (including running inside the sandbox
    # container) → the trivial, statically-clean script runs.
    r = PythonRunner(enabled=True, egress_proxy="http://127.0.0.1:9999",
                     sandboxed=True).run(SAFE, reviewed=True)
    assert r.ran
    assert r.exit_code == 0
    assert "hello from poc" in r.stdout
