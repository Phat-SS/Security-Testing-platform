"""PDF report via fpdf2 (pure Python — no native deps, works on Windows).

Built directly from the domain objects (the same redacted data as the HTML/XLSX
reports). weasyprint would give HTML-fidelity output but drags in heavy native
libraries; fpdf2 keeps the core dependency-light. Text is sanitised to the core
font's encoding so arbitrary response content can't break rendering.
"""

from __future__ import annotations

from collections import Counter

from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.testcase import TestCase


def _s(text) -> str:
    # Core PDF fonts are latin-1; drop anything else rather than crash.
    return str(text).encode("latin-1", "replace").decode("latin-1")


def export_pdf(
    issue_key: str,
    target: str,
    tests: list[TestCase],
    executions: list[Execution],
    findings: list[Finding],
    coverage: list[dict] | None = None,
) -> bytes:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, _s(f"Security Assessment - {issue_key}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 6, _s(f"Target: {target}   Baseline: OWASP API Security Top 10 (2023)"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Summary
    results = Counter(e.verdict.result.value for e in executions)
    sev = Counter(f.severity.value for f in findings)
    _heading(pdf, "Executive Summary")
    pdf.set_font("Helvetica", "", 10)
    summary = "  ".join(f"{k}: {results.get(k, 0)}" for k in
                        ["PASS", "FAIL", "INCONCLUSIVE", "BLOCKED", "ERROR"])
    pdf.multi_cell(0, 6, _s(summary), new_x="LMARGIN", new_y="NEXT")
    sevs = "  ".join(f"{k}: {sev.get(k, 0)}" for k in
                     ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    pdf.multi_cell(0, 6, _s("Findings by severity - " + sevs), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Coverage
    if coverage:
        _heading(pdf, "OWASP Coverage")
        pdf.set_font("Helvetica", "", 9)
        for r in coverage:
            if r.get("state") == "NOT_APPLICABLE":
                continue
            pdf.cell(0, 5, _s(f"{r.get('category')}: {r.get('state')} "
                              f"({r.get('pct', 0)}%)  "
                              f"[{r.get('existing_tests',0)} PoC / {r.get('generated_tests',0)} gen]"),
                     new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Findings
    _heading(pdf, f"Findings ({len(findings)})")
    if not findings:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, "No confirmed findings.", new_x="LMARGIN", new_y="NEXT")
    for f in findings:
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 6, _s(f"{f.finding_id} - {f.title} [{f.severity.value}]"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for label, value in [
            ("OWASP", f.owasp_category.value), ("Endpoint", f.endpoint),
            ("Confidence", f.confidence.value), ("Expected", f.correlation.expected),
            ("Actual", f.correlation.actual), ("Impact", f.impact),
            ("Recommendation", f.recommendation),
        ]:
            pdf.multi_cell(0, 5, _s(f"{label}: {value}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Execution log
    pdf.add_page()
    _heading(pdf, "Execution Log")
    pdf.set_font("Helvetica", "", 9)
    for e in executions:
        pdf.multi_cell(0, 5, _s(f"{e.test_id} [{e.owasp_category}] -> "
                                f"{e.verdict.result.value} ({e.verdict.confidence.value})"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(90, 90, 90)
        pdf.multi_cell(0, 5, _s(f"    {e.verdict.reason}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    out = pdf.output()
    return bytes(out)


def _heading(pdf, text: str) -> None:
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _s(text), new_x="LMARGIN", new_y="NEXT")
