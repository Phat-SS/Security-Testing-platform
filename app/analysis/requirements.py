"""Requirement items — the unit "% of the ticket covered" is measured over.

A percentage is only as meaningful as its denominator. "We covered 80% of the
ticket" is a claim about a set of things the ticket asked for, so that set has
to exist as data before any number can be computed, and it has to be visible
and correctable — exactly like the endpoint list, and for the same reason: it is
produced by reading prose, which is the step most likely to be wrong.

Two things live here:

  * **extraction** — acceptance criteria, then security-relevant bullets, then
    (as a floor) the summary. Deterministic, always available. The AI analyzer
    can add to it; it does not replace it.
  * **mapping** — which planned tests address which item, and what the run
    proved about it. Deterministic: an item's `owasp_hints` versus each test's
    category, tightened by endpoint mention when the item names one.

The mapping is deliberately generous about *addressing* an item and strict
about *deciding* it. A test in the right category counts as addressing the
requirement; only a PASS or FAIL verdict counts as deciding it. That asymmetry
is the anti-false-confidence rule from `verdict.py` carried up one level: a plan
that touches everything and decides nothing must not read as 100%.
"""

from __future__ import annotations

import re

from app.mcp.jira import NormalizedIssue
from app.owasp.rules import (
    AUTH_KEYWORDS,
    FLOW_KEYWORDS,
    INVENTORY_KEYWORDS,
    MISCONFIG_KEYWORDS,
    RESOURCE_KEYWORDS,
    THIRD_PARTY_KEYWORDS,
    URL_KEYWORDS,
)
from app.schemas.agent import RequirementCoverage, RequirementItem
from app.schemas.enums import OwaspApiCategory, TestStatus
from app.schemas.execution import Execution
from app.schemas.testcase import TestCase

# A bullet, a numbered line, or a checkbox — the three shapes a requirement
# takes in a Jira description.
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)]|\[[ xX]\])\s+(.{6,400})$")
# "Given/When/Then", "must", "should", "shall" — the grammar of a requirement
# as opposed to a note. Kept broad: a missed item understates coverage (safe
# direction is to *have* the item and see it uncovered), a spurious one drags
# the percentage down for no reason, so the filter leans toward requirement-ish
# language rather than accepting every bullet in the ticket.
_REQUIREMENT_WORDS = (
    "must", "should", "shall", "cannot", "can not", "must not", "never", "only",
    "require", "reject", "deny", "allow", "prevent", "enforce", "validate",
    "verify", "return", "ensure", "given", "when", "then", "expected",
)
_SECURITY_WORDS = (
    "auth", "token", "permission", "role", "own", "access", "forbidden",
    "unauthor", "403", "401", "leak", "expose", "tenant", "isolat", "privileg",
    "scope", "secret", "credential", "encrypt", "audit", "rate limit", "throttle",
)

# Object-identifier language. Deliberately phrase-level as well as `*Id`-level:
# "another agent's customer" is the BOLA requirement stated the way a ticket
# actually states it, and never contains the word "customerId".
_ID_WORDS = (
    "id", "identifier", "another user", "other user", "another agent",
    "other agents", "belongs to", "not their own", "someone else", "cross-account",
    "cross account", "cross-tenant", "different customer", "own record",
    "own data", "their own",
)
_PROPERTY_WORDS = (
    "field", "property", "attribute", "mass assignment", "read-only", "readonly",
    "role", "status", "is_admin", "isadmin", "flag", "overwrite", "payload",
)
_LIMIT_WORDS = ("rate limit", "rate-limit", "throttle", "quota", "limit", "size",
                "timeout", "concurrent", "flood")
# Function-level authorization language — deliberately NOT `owasp.rules`'
# ROLE_KEYWORDS, which includes bare role names like "agent" and "manager".
# Those are fine as a whole-ticket signal, but at the level of one sentence they
# match the actor of every requirement in a domain whose users are called agents,
# and every item then claims a BFLA gap that no test could ever close. What
# implicates API5 in a sentence is a *privilege relationship*: only-an-admin,
# permission, escalation.
_ROLE_WORDS = (
    "role", "permission", "privilege", "admin", "authoriz", "escalat", "rbac",
    "scope", "entitle", "elevated", "superuser", "staff only", "internal only",
)
_ID_PARAM_RE = re.compile(r"\b(\w+_?id|\w+Id)\b")
_PATH_RE = re.compile(r"(/[A-Za-z0-9_{}/.\-]{2,})")

# Which categories a requirement's wording implicates. Order matters only for
# readability; every matching category is kept, because one sentence often
# states two requirements ("only the owner, and only an admin may re-assign").
_HINT_RULES: list[tuple[OwaspApiCategory, tuple[str, ...]]] = [
    (OwaspApiCategory.API1, _ID_WORDS),
    (OwaspApiCategory.API2, AUTH_KEYWORDS),
    (OwaspApiCategory.API3, _PROPERTY_WORDS),
    (OwaspApiCategory.API4, RESOURCE_KEYWORDS + _LIMIT_WORDS),
    (OwaspApiCategory.API5, _ROLE_WORDS),
    (OwaspApiCategory.API6, FLOW_KEYWORDS),
    (OwaspApiCategory.API7, URL_KEYWORDS),
    (OwaspApiCategory.API8, MISCONFIG_KEYWORDS + ("header", "cors", "https", "tls")),
    (OwaspApiCategory.API9, INVENTORY_KEYWORDS + ("version", "/v1", "/v2")),
    (OwaspApiCategory.API10, THIRD_PARTY_KEYWORDS),
]


# -- extraction ---------------------------------------------------------------


def owasp_hints(text: str) -> list[OwaspApiCategory]:
    """Categories a test would have to exercise to address this sentence.

    Empty is a real answer, and the important one: an item with no hint is
    excluded from the coverage denominator rather than counted as a permanent
    gap. A ticket line about button colour is not 0% security coverage.
    """
    low = f" {text.lower()} "
    hits: list[OwaspApiCategory] = []
    for category, words in _HINT_RULES:
        if any(w in low for w in words):
            hits.append(category)
    # `*Id` parameter names imply object-level authorization even when the prose
    # says nothing about ownership — the same signal the rule engine uses.
    if OwaspApiCategory.API1 not in hits and _ID_PARAM_RE.search(text):
        hits.append(OwaspApiCategory.API1)
    return hits


def _looks_like_requirement(line: str) -> bool:
    low = line.lower()
    return any(w in low for w in _REQUIREMENT_WORDS) or any(
        w in low for w in _SECURITY_WORDS
    )


def _item(index: int, text: str, kind: str, source: str) -> RequirementItem:
    clean = " ".join(text.split())
    return RequirementItem(
        item_id=f"R-{index:02d}",
        text=clean[:400],
        kind=kind,  # type: ignore[arg-type]
        owasp_hints=owasp_hints(clean),
        source=source,
    )


def extract_requirements(issue: NormalizedIssue) -> list[RequirementItem]:
    """Read the ticket into a list of discrete asks.

    Acceptance criteria first and unfiltered — an AC line *is* a requirement by
    definition, whatever its grammar. Description bullets are filtered, because
    a description also holds context, links and reproduction notes, and counting
    those as uncovered requirements would make the percentage meaningless.
    """
    items: list[RequirementItem] = []
    seen: set[str] = set()

    def add(text: str, kind: str, source: str) -> None:
        clean = " ".join(text.split())
        # Dedup on the words, not the punctuation: a ticket that states the same
        # criterion twice, once with a full stop, states one requirement.
        key = _dedup_key(clean)
        if len(clean) < 6 or key in seen:
            return
        seen.add(key)
        items.append(_item(len(items) + 1, clean, kind, source))

    for line in issue.acceptance_criteria:
        add(_strip_bullet(line), "acceptance_criterion", "acceptance_criteria")

    for raw in (issue.description or "").splitlines():
        match = _BULLET_RE.match(raw)
        if not match:
            continue
        text = match.group(1).strip()
        if not _looks_like_requirement(text):
            continue
        kind = "security_control" if _is_security(text) else "business_rule"
        add(text, kind, "description")

    if not items and issue.summary:
        # The floor. A ticket with no criteria and no bullets still asked for
        # *something*, and an empty requirement list would report 0% coverage on
        # a run that tested exactly what the ticket described.
        add(issue.summary, "security_control" if _is_security(issue.summary) else "other",
            "summary")
    return items


def _dedup_key(text: str) -> str:
    return " ".join(
        "".join(ch for ch in text.lower() if ch.isalnum() or ch.isspace()).split()
    )[:160]


# Grammar strong enough to call a bare line a requirement. Deliberately much
# narrower than `_REQUIREMENT_WORDS`: that list runs against lines already known
# to be bullets, where a loose match costs little. Here it runs against every
# line of a ticket's prose, and a loose match turns a paragraph of context into
# eight phantom requirements that drag the coverage percentage down forever.
_STRONG_REQUIREMENT_WORDS = (
    "must not", "must ", "shall ", "cannot ", "should not", "may not",
    "is rejected", "are rejected", "is denied", "are denied",
)
_MAX_TEXT_ITEMS = 25


def extract_requirements_from_text(text: str) -> list[RequirementItem]:
    """Read requirements out of the stored ticket text rather than a live issue.

    For an analysis saved before requirement items existed. `IssueAnalysis` keeps
    `source_text` — the exact join of summary, description, acceptance criteria
    and comments the analysis was derived from — so the list can be back-filled
    without a Jira round trip, and without re-importing (which would discard the
    plan and its approvals).

    It is strictly weaker than reading the issue: the join has already flattened
    away which lines were acceptance criteria, so a criterion that is not a
    bullet and does not use requirement grammar is invisible here. Re-analyzing
    from the ticket remains the better answer; this exists so that an assessment
    somebody already ran gets a coverage figure at all rather than a permanent
    "unmeasured".
    """
    items: list[RequirementItem] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        if len(items) >= _MAX_TEXT_ITEMS:
            break
        bullet = _BULLET_RE.match(raw)
        line = (bullet.group(1) if bullet else raw).strip()
        if len(line) < 6 or len(line) > 400:
            continue
        low = f" {line.lower()} "
        if bullet:
            if not _looks_like_requirement(line):
                continue
        elif not any(w in low for w in _STRONG_REQUIREMENT_WORDS):
            continue
        key = _dedup_key(line)
        if key in seen:
            continue
        seen.add(key)
        kind = "security_control" if _is_security(line) else "business_rule"
        items.append(_item(len(items) + 1, line, kind, "source_text"))
    return items


def _strip_bullet(line: str) -> str:
    match = _BULLET_RE.match(line)
    return match.group(1).strip() if match else line.strip()


def _is_security(text: str) -> bool:
    low = text.lower()
    return any(w in low for w in _SECURITY_WORDS)


def merge_requirements(
    extracted: list[RequirementItem], existing: list[RequirementItem]
) -> list[RequirementItem]:
    """Re-extraction keeps hand-entered items.

    Same rule as the endpoint list: a manual item exists precisely because the
    extractor could not find it, so rebuilding from the ticket must not be the
    operation that deletes it.
    """
    manual = [i for i in existing if i.manual]
    out = list(extracted)
    known = {_dedup_key(i.text) for i in out}
    for item in manual:
        if _dedup_key(item.text) in known:
            continue
        out.append(item)
    # Ids are positional, so renumber after the merge rather than leaving two
    # items called R-03.
    for n, item in enumerate(out, start=1):
        item.item_id = f"R-{n:02d}"
    return out


# -- mapping ------------------------------------------------------------------


def _paths_in(text: str) -> set[str]:
    return {m.group(1).rstrip(".,;:)").lower() for m in _PATH_RE.finditer(text)}


def matching_tests(item: RequirementItem, tests: list[TestCase]) -> list[str]:
    """Which planned tests address this item.

    Category match is the rule. When the item names an endpoint path, tests on
    that path win outright — otherwise a ticket with six endpoints would report
    every BOLA test as addressing every ownership requirement, and the mapping
    would stop distinguishing "we tested this one" from "we tested one of these".
    """
    if not item.owasp_hints:
        return []
    hinted = [t for t in tests if t.owasp_category in item.owasp_hints]
    if not hinted:
        return []
    item_paths = _paths_in(item.text)
    if item_paths:
        on_path = [
            t for t in hinted
            if any(p in t.request.path.lower() or t.request.path.lower() in p
                   for p in item_paths)
        ]
        if on_path:
            return [t.test_id for t in on_path]
    return [t.test_id for t in hinted]


def coverage_for_items(
    items: list[RequirementItem],
    tests: list[TestCase],
    executions: list[Execution] | None = None,
    *,
    overrides: dict[str, str] | None = None,
) -> list[RequirementCoverage]:
    """Per-item state, from the plan and (when present) what the run decided.

    `overrides` maps execution_id → adjudicated result, so an undecided
    execution a reviewing agent read and resolved counts as decided here. The
    override only ever comes from `Adjudication.assessed_result`, and only for
    executions the runner itself left undecided — an adjudication can never
    overwrite a sealed PASS or FAIL.
    """
    overrides = overrides or {}
    by_test: dict[str, list[Execution]] = {}
    for ex in executions or []:
        by_test.setdefault(ex.test_id, []).append(ex)

    rows: list[RequirementCoverage] = []
    for item in items:
        test_ids = matching_tests(item, tests)
        if not item.owasp_hints:
            rows.append(RequirementCoverage(
                item_id=item.item_id, text=item.text, state="NOT_TESTED", tests=[],
                note="No security-relevant reading — excluded from the coverage score.",
            ))
            continue
        if not test_ids:
            rows.append(RequirementCoverage(
                item_id=item.item_id, text=item.text, state="NOT_TESTED", tests=[],
                note=("No test in "
                      f"{', '.join(c.value for c in item.owasp_hints)} addresses this."),
            ))
            continue

        results = [
            _effective_result(ex, overrides)
            for tid in test_ids for ex in by_test.get(tid, [])
        ]
        if not results:
            rows.append(RequirementCoverage(
                item_id=item.item_id, text=item.text, state="NOT_COVERED", tests=test_ids,
                note=f"{len(test_ids)} test(s) planned; none has run yet.",
            ))
            continue

        if "FAIL" in results:
            state, note = "COVERED_FAIL", "A test for this requirement failed."
        elif "PASS" in results:
            state, note = "COVERED_PASS", "At least one test decided this requirement held."
        else:
            state, note = "PARTIAL", ("Tests ran but none reached a decisive result "
                                      f"({', '.join(sorted(set(results)))}).")
        rows.append(RequirementCoverage(
            item_id=item.item_id, text=item.text, state=state,  # type: ignore[arg-type]
            tests=test_ids, note=note,
        ))
    return rows


def _effective_result(ex: Execution, overrides: dict[str, str]) -> str:
    sealed = ex.verdict.result
    if sealed == TestStatus.INCONCLUSIVE:
        return overrides.get(ex.execution_id, sealed.value)
    return sealed.value


def coverage_pct(rows: list[RequirementCoverage], items: list[RequirementItem]) -> int:
    """Weighted requirement coverage over the *security-relevant* items only.

    Items with no OWASP hint are out of the denominator: they are not things
    this platform can test, and counting them would make a perfect security run
    on a mixed ticket report 40%. The hint list, not `is_security_relevant`, is
    the criterion — an item whose wording reads as a security control but names
    no testable category is exactly the case where a percentage would be a
    fiction, and it is surfaced as an untested item instead.
    """
    scored = {i.item_id for i in items if i.owasp_hints}
    considered = [r for r in rows if r.item_id in scored]
    if not considered:
        return 0
    return round(100 * sum(r.weight for r in considered) / len(considered))
