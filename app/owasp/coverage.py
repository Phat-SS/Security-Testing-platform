"""OWASP coverage engine.

Answers the question that is the real value of the tool: given what the ticket
needs (applicable categories) and what the existing PoCs already test, *what is
missing?* Produces the coverage matrix shown on the dashboard and used to decide
which new tests to generate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.execution.mutations import kinds_for
from app.schemas.analysis import IssueAnalysis
from app.schemas.enums import Applicability, OwaspApiCategory, TestSource
from app.schemas.testcase import TestCase


@dataclass
class CoverageRow:
    category: OwaspApiCategory
    applicable: bool
    existing_tests: int
    generated_tests: int
    state: str  # COVERED | PARTIAL | MISSING | NOT_APPLICABLE
    pct: int
    #: How much of this category's technique catalogue the plan exercises. A
    #: single `drop_auth` makes API2 "COVERED", but it is one of several ways
    #: authentication fails; this is the honest "how deep" number next to it.
    depth_pct: int = 0
    techniques_missing: tuple[str, ...] = ()


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
        catalogue = kinds_for(cat) if is_applicable else []
        used = {
            t.attack_mutation.kind
            for t in (*existing_poc_tests, *generated_tests)
            if t.owasp_category == cat
        }
        missing = tuple(k for k in catalogue if k not in used)
        depth = _pct(len(catalogue) - len(missing), len(catalogue))
        rows.append(CoverageRow(cat, is_applicable, existing, generated, state, pct,
                                depth, missing))
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
        "depth_pct": _pct(sum(r.depth_pct for r in applicable), len(applicable) * 100),
        "applicable": len(applicable),
        "covered": covered,
        "partial": partial,
        "missing": missing,
    }


_ID_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z0-9_]+\}")


def uncovered_poc_endpoints(analysis: IssueAnalysis, tests: list[TestCase]) -> list[str]:
    """Endpoint signatures a PoC-derived test actually sends but that never
    made it into the endpoint list.

    The endpoint list is extracted by a regex over ticket prose
    (`extract_endpoints`, matching literal "METHOD /path" text). A PoC's real
    request is extracted by parsing its AST instead, so a request built from a
    variable (`requests.get(BASE + TARGET)`) has no literal "METHOD /path"
    text for the regex to ever see. A test plan can therefore cover more
    surface than the Endpoint panel shows — from the very first design, not
    from anyone editing anything afterwards, so `IssueAnalysis.plan_is_stale()`
    (which only compares the endpoint list against its own past self) cannot
    catch it. Recomputed from whatever the endpoint list holds right now, so
    adding the missing endpoint later clears the warning without a re-design.

    Compared with the object id generalised out of the last path segment
    (`parameterise_object_id`, the same convention `classify()` uses), then
    with any remaining `{placeholder}` name flattened to a common token:
    otherwise `/customers/{customerId}` in the endpoint list (a human's or
    the regex's own naming) would never match `/customers/2002` (the PoC's
    literal test id) or `/customers/{victim_id}` (classify's own naming),
    and every ordinary BOLA replay would misreport as "uncovered".
    """
    known = {_normalised_signature(ep.method, ep.path) for ep in analysis.endpoints}
    found: list[str] = []
    for t in tests:
        if t.source != TestSource.POC:
            continue
        sig = _normalised_signature(t.request.method, t.request.path)
        if sig not in known and sig not in found:
            found.append(f"{t.request.method.upper()} {_without_query(t.request.path)}")
    return found


def _normalised_signature(method: str, path: str) -> str:
    from app.poc.classify import parameterise_object_id

    generalised, _ = parameterise_object_id(_without_query(path))
    generalised = _ID_PLACEHOLDER_RE.sub("{id}", generalised)
    return f"{method.upper()} {generalised}"


def _without_query(path: str) -> str:
    return path.split("?", 1)[0]


def _count_by_cat(tests: list[TestCase]) -> dict[OwaspApiCategory, int]:
    counts: dict[OwaspApiCategory, int] = {}
    for t in tests:
        counts[t.owasp_category] = counts.get(t.owasp_category, 0) + 1
    return counts


def _pct(part: float, whole: float) -> int:
    return int(round(100 * part / whole)) if whole else 0
