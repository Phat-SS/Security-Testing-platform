"""JSON and XLSX exporters.

Everything here is fed already-redacted data. JSON is dependency-free; XLSX uses
openpyxl. PDF is a Phase-3+ concern (weasyprint) and intentionally omitted to
avoid a heavy native dependency in the core.
"""

from __future__ import annotations

import io
import json
from collections import Counter

from app.execution.evidence import verify_chain
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.testcase import TestCase


def export_json(
    issue_key: str,
    target: str,
    tests: list[TestCase],
    executions: list[Execution],
    findings: list[Finding],
    coverage: list[dict] | None = None,
    plan_review=None,
    run_assessment=None,
) -> str:
    """The machine-readable whole. The two agent artefacts are included under
    their own keys rather than merged into `executions`: an adjudication is an
    opinion about an execution, and folding it into the execution record would
    put an unhashed, model-derived field inside the object whose hash is supposed
    to make it tamper-evident."""
    payload = {
        "issue_key": issue_key,
        "target": target,
        "summary": _summary(executions, findings),
        "coverage": coverage or [],
        "test_cases": [t.model_dump(mode="json") for t in tests],
        "executions": [e.model_dump(mode="json") for e in executions],
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    if plan_review is not None:
        payload["plan_review"] = plan_review.model_dump(mode="json")
    if run_assessment is not None:
        payload["run_assessment"] = run_assessment.model_dump(mode="json")
    return json.dumps(payload, indent=2, ensure_ascii=False)


def export_xlsx(
    issue_key: str,
    target: str,
    tests: list[TestCase],
    executions: list[Execution],
    findings: list[Finding],
    coverage: list[dict] | None = None,
) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    bold = Font(bold=True)

    # Summary
    ws = wb.active
    ws.title = "Summary"
    summary = _summary(executions, findings)
    ws.append(["Security Assessment", issue_key])
    ws.append(["Target", target])
    ws.append([])
    ws.append(["Metric", "Count"])
    ws["A4"].font = ws["B4"].font = bold
    for k, v in summary["results"].items():
        ws.append([k, v])
    ws.append([])
    ws.append(["Severity", "Count"])
    for k, v in summary["severities"].items():
        ws.append([k, v])

    # Coverage
    ws = wb.create_sheet("Coverage")
    _header(ws, ["Category", "State", "Coverage %", "Existing PoC", "Generated"], bold)
    for r in coverage or []:
        ws.append([r.get("category"), r.get("state"), r.get("pct", 0),
                   r.get("existing_tests", 0), r.get("generated_tests", 0)])

    # Test cases
    ws = wb.create_sheet("Test Cases")
    _header(ws, ["Test ID", "OWASP", "Severity", "Approval", "Destructive", "Mutation", "Title"], bold)
    for t in tests:
        ws.append([t.test_id, t.owasp_category.value, t.severity.value,
                   t.approval_status.value, t.is_destructive, t.attack_mutation.kind, t.title])

    # Executions
    ws = wb.create_sheet("Executions")
    _header(ws, ["Test ID", "OWASP", "Result", "Confidence", "Reason", "Evidence Hash"], bold)
    for e in executions:
        ws.append([e.test_id, e.owasp_category, e.verdict.result.value,
                   e.verdict.confidence.value, e.verdict.reason, e.evidence_hash[:16]])

    # Findings
    ws = wb.create_sheet("Findings")
    _header(ws, ["ID", "Title", "OWASP", "Severity", "Confidence", "Endpoint", "Recommendation"], bold)
    for f in findings:
        ws.append([f.finding_id, f.title, f.owasp_category.value, f.severity.value,
                   f.confidence.value, f.endpoint, f.recommendation])

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _summary(executions: list[Execution], findings: list[Finding]) -> dict:
    results = Counter(e.verdict.result.value for e in executions)
    sev = Counter(f.severity.value for f in findings)
    return {
        "results": {k: results.get(k, 0) for k in
                    ["PASS", "FAIL", "INCONCLUSIVE", "BLOCKED", "ERROR", "SKIPPED", "TIMEOUT"]},
        "severities": {k: sev.get(k, 0) for k in
                       ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "total_tests": len(executions),
        "total_findings": len(findings),
        "evidence_chain_ok": verify_chain(executions) if executions else None,
    }


def _header(ws, cols, bold) -> None:
    ws.append(cols)
    for cell in ws[1]:
        cell.font = bold
