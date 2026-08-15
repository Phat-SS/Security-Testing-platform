"""OWASP coverage engine.

Answers the question that is the real value of the tool: given what the ticket
needs (applicable categories) and what the existing PoCs already test, *what is
missing?* Produces the coverage matrix shown on the dashboard and used to decide
which new tests to generate.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.analysis import IssueAnalysis
from app.schemas.enums import Applicability, OwaspApiCategory
from app.schemas.testcase import TestCase


@dataclass
class CoverageRow:
    category: OwaspApiCategory
    applicable: bool
    existing_tests: int
    generated_tests: int
    state: str  # COVERED | PARTIAL | MISSING | NOT_APPLICABLE
    pct: int


def compute_coverage(
    analysis: IssueAnalysis,
    existing_poc_tests: list[TestCase],
    generated_tests: list[TestCase],
) -> list[CoverageRow]:
    applicable = set(analysis.applicable_categories())
    existing_by_cat = _count_by_cat(existing_poc_tests)
    generated_by_cat = _count_by_cat(generated_tests)

    rows: list[CoverageRow] = []
    for cat in OwaspApiCategory:
        is_applicable = cat in applicable
        existing = existing_by_cat.get(cat, 0)
        generated = generated_by_cat.get(cat, 0)

        if not is_applicable:
            state, pct = "NOT_APPLICABLE", 0
        elif existing and generated == 0:
            state, pct = "COVERED", 100
        elif existing and generated:
            # PoC touches it but the designer still found gaps → partial.
            state, pct = "PARTIAL", _pct(existing, existing + generated)
        elif generated:
            state, pct = "MISSING", 0  # a gap the designer is now filling
        else:
            state, pct = "MISSING", 0
        rows.append(CoverageRow(cat, is_applicable, existing, generated, state, pct))
    return rows


def apply_coverage_to_analysis(analysis: IssueAnalysis, rows: list[CoverageRow]) -> None:
    by_cat = {r.category: r for r in rows}
    for mapping in analysis.owasp_mappings:
        row = by_cat.get(mapping.category)
        if row and mapping.applicability == Applicability.APPLICABLE:
            mapping.existing_coverage = row.state  # type: ignore[assignment]
            mapping.coverage_pct = row.pct


def coverage_summary(rows: list[CoverageRow]) -> dict:
    applicable = [r for r in rows if r.applicable]
    if not applicable:
        return {"overall_pct": 0, "applicable": 0, "covered": 0, "missing": 0}
    covered = sum(1 for r in applicable if r.state == "COVERED")
    partial = sum(1 for r in applicable if r.state == "PARTIAL")
    missing = sum(1 for r in applicable if r.state == "MISSING")
    overall = _pct(covered + 0.5 * partial, len(applicable))
    return {
        "overall_pct": overall,
        "applicable": len(applicable),
        "covered": covered,
        "partial": partial,
        "missing": missing,
    }


def _count_by_cat(tests: list[TestCase]) -> dict[OwaspApiCategory, int]:
    counts: dict[OwaspApiCategory, int] = {}
    for t in tests:
        counts[t.owasp_category] = counts.get(t.owasp_category, 0) + 1
    return counts


def _pct(part: float, whole: float) -> int:
    return int(round(100 * part / whole)) if whole else 0
