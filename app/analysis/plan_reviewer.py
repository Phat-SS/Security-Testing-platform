"""The reviewing agent — a second opinion on a plan before a human reads it.

The planner's failure mode is not producing a bad test; every test it produces
already survives `AttackPlanner.accept()`. Its failure mode is producing a plan
that is *thin in a way nobody notices*: a ticket whose third acceptance
criterion is about admin re-assignment, and a plan with eleven BOLA probes and
no BFLA test at all. A reviewer that reads the requirement list against the plan
catches that, and catches it before the tester spends their attention approving
what is there rather than noticing what is not.

Two reviewers, same output type:

  * **deterministic** (always available) — structural. Every applicable OWASP
    category with no test is a gap; every requirement item with no test is a
    gap; authorization tests without a positive control are a quality defect,
    because a test that can only ever return INCONCLUSIVE is not coverage.
  * **AI** (when `USE_AI=true` and the claude CLI is available) — reads the ticket's intent against the plan
    and names gaps a structural check cannot see ("nothing tests that the
    *expired* coupon path is the one that must reject").

The AI reviewer runs *on top of* the deterministic one and its gaps are merged
in, never substituted for them. A model that decides everything is fine must
not be able to erase a structural gap that is measurably there — so the
deterministic verdict floors the final one: if structure says INSUFFICIENT, the
review is at best REVISE.

The AI reviewer also writes `requirement_digest`: for each security-relevant
requirement, what the ticket asks for restated as the concrete behaviour a
tester can check a response against ("PUT .../change-ownership must return
401 for an anonymous caller, not fall through to validation"), not the
ticket's own — often vaguer — wording. This is a reading task, so it is
AI-only; the deterministic review leaves it empty rather than guess at intent
from a bullet's grammar alone.

What a review cannot do, in any mode: remove a test, change an approval status,
mark a plan approved, or authorise anything. It produces gaps, which become a
prompt for another planning round, whose output goes through exactly the same
constraints as the first. Worst case for a fully prompt-injected reviewer is
that it asks the planner for extra allowlisted, non-destructive, PENDING tests.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import BaseModel, Field, ValidationError

from app.analysis.staged import LLMClient
from app.execution.mutations import MUTATION_KINDS
from app.schemas.agent import PlanReview, PlanReviewGap, RequirementDigestItem, RequirementItem
from app.schemas.analysis import IssueAnalysis
from app.schemas.enums import OwaspApiCategory
from app.schemas.testcase import TestCase

# Categories where a rejection means nothing without a positive control: the
# whole verdict turns on "the entitled identity could do this and the attacker
# could not". A test in one of these with no baseline can, at best, return
# INCONCLUSIVE — see `verdict.py` gate 4.
_NEEDS_BASELINE = {OwaspApiCategory.API1, OwaspApiCategory.API3, OwaspApiCategory.API5}
# Categories whose evidence is a persisted state change. Without a read-back an
# accepted write proves only that it was accepted.
_NEEDS_VERIFICATION = {OwaspApiCategory.API3}

_MAX_GAPS = 12


class _ProposedDigestItem(BaseModel):
    """The narrow shape the reviewing model may emit per requirement digest row."""

    item_id: str = ""
    requirement: str = ""
    expected: str = ""


class _ProposedGap(BaseModel):
    """The narrow shape the reviewing model may emit per gap."""

    description: str
    requirement_id: str = ""
    category: str = ""
    severity: str = "important"
    suggested_mutation: str = ""
    suggested_endpoint: str = ""


class _ProposedReview(BaseModel):
    verdict: str = "REVISE"
    coverage_score: int = 0
    quality_score: int = 0
    gaps: list[_ProposedGap] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)
    notes: str = ""
    requirement_digest: list[_ProposedDigestItem] = Field(default_factory=list)


_SYSTEM = """You are a review agent auditing a security test plan produced by
another agent. You are not writing tests; you are judging whether the plan
covers what the ticket asked for and whether its tests can actually be decided
from evidence.

You have no authority. You cannot approve the plan, remove a test, or run
anything. Your output is a critique that becomes a prompt for another planning
round, and a note a human reads before approving.

Judge on two axes:
1. COVERAGE — is there a test for each security-relevant thing the ticket asks
   for? Name what is missing, referencing the requirement id when you can.
2. QUALITY (decidability) — can each test produce a verdict other than
   "inconclusive"? An authorization test without a positive control (a baseline
   run as the entitled identity) cannot distinguish "access denied" from "the
   object does not exist". A state-changing probe without a read-back cannot
   prove the change persisted.

Before any of that, do a third thing the tester cannot get from a table of
category names: for each requirement listed below that is security-relevant
(it has an OWASP hint), restate it as `requirement_digest` — what the ticket
is actually asking for, and precisely what a secure system must do about it.
The ticket's own wording is often a paraphrase ("must prevent unauthorized
ownership changes"); your `expected` must be the concrete, checkable behaviour
a tester can hold a real HTTP response against — the specific status code, who
is and is not allowed to act, and what must never happen — using whatever
specifics the ticket itself gives (a status code it names, an endpoint it
names, a field it names). If the ticket names a status code, say that code, not
"an error". If it does not, say what class of response would count instead of
inventing one. Keep each `expected` to one or two sentences a tester can act on
without re-reading the ticket.

Rules, because output that breaks them is discarded:
- `severity` is one of "blocking", "important", "minor". Reserve "blocking" for
  a security-relevant requirement with NO test at all.
- `category`, when set, must be an OWASP API 2023 id like "API5:2023".
- `suggested_mutation`, when set, must be one of the catalogue entries given.
- Do not restate a gap already listed under "structural gaps already found".
- Do not invent endpoints. Reference only the ones listed.
- `requirement_digest[].item_id` must be one of the requirement ids listed
  below (e.g. "R-02"), never invented.
- Scores are integers 0-100.

Return ONLY a JSON object:
{"verdict": "APPROVE"|"REVISE"|"INSUFFICIENT", "coverage_score": int,
 "quality_score": int, "strengths": [str], "notes": str,
 "requirement_digest": [{"item_id": str, "requirement": str, "expected": str}],
 "gaps": [{"description": str, "requirement_id": str, "category": str,
           "severity": str, "suggested_mutation": str, "suggested_endpoint": str}]}"""


# -- the deterministic review -------------------------------------------------


def structural_review(
    analysis: IssueAnalysis,
    tests: list[TestCase],
    requirements: list[RequirementItem] | None = None,
) -> PlanReview:
    """The review that needs no model and always runs.

    Everything here is countable: a category the rule engine marked applicable
    either has a test or it does not. That makes it the floor under the AI
    review rather than a fallback for it — a structural gap is a fact, and a
    model's opinion does not get to clear it.
    """
    from app.analysis.requirements import matching_tests

    # None means "the ones the analysis carries". A caller who passes only the
    # analysis must not silently get a review with the requirement half switched
    # off - that half is the reason this reviewer exists.
    if requirements is None:
        requirements = list(analysis.requirements)
    gaps: list[PlanReviewGap] = []
    strengths: list[str] = []

    by_category: dict[OwaspApiCategory, list[TestCase]] = {}
    for test in tests:
        by_category.setdefault(test.owasp_category, []).append(test)

    applicable = analysis.applicable_categories()
    for category in applicable:
        if not by_category.get(category):
            gaps.append(PlanReviewGap(
                description=(
                    f"{category.value} was judged applicable to this ticket but the plan "
                    "contains no test for it."
                ),
                category=category,
                severity="blocking",
            ))
    covered_categories = [c for c in applicable if by_category.get(c)]
    if covered_categories:
        strengths.append(
            f"{len(covered_categories)}/{len(applicable)} applicable OWASP categories "
            "have at least one test."
        )

    # Requirement-level coverage: an item nothing addresses is a gap even when
    # its category is nominally covered elsewhere in the plan.
    for item in requirements:
        if not item.owasp_hints:
            continue
        if matching_tests(item, tests):
            continue
        gaps.append(PlanReviewGap(
            description=(
                f"Requirement {item.item_id} (\"{item.text[:120]}\") has no test in "
                f"{', '.join(c.value for c in item.owasp_hints)}."
            ),
            requirement_id=item.item_id,
            category=item.owasp_hints[0],
            severity="blocking",
        ))

    # Quality: tests that cannot produce a decisive result.
    missing_baseline = [
        t for t in tests
        if t.owasp_category in _NEEDS_BASELINE and t.baseline is None
    ]
    if missing_baseline:
        gaps.append(PlanReviewGap(
            description=(
                f"{len(missing_baseline)} authorization test(s) have no positive control, "
                "so a rejection cannot be distinguished from an unreachable target and the "
                "verdict can only be INCONCLUSIVE. First: "
                + ", ".join(t.test_id for t in missing_baseline[:5])
            ),
            severity="important",
        ))
    missing_verification = [
        t for t in tests
        if t.owasp_category in _NEEDS_VERIFICATION and t.verification is None
        and t.request.method.upper() in {"POST", "PUT", "PATCH"}
    ]
    if missing_verification:
        gaps.append(PlanReviewGap(
            description=(
                f"{len(missing_verification)} property-level test(s) change state with no "
                "read-back, so an accepted write cannot be shown to have persisted. First: "
                + ", ".join(t.test_id for t in missing_verification[:5])
            ),
            severity="important",
        ))

    decidable = [
        t for t in tests
        if t.baseline is not None or t.verification is not None
        or t.owasp_category not in _NEEDS_BASELINE
    ]
    coverage = _coverage_score(applicable, by_category, requirements, tests)
    quality = round(100 * len(decidable) / len(tests)) if tests else 0
    if quality >= 80 and tests:
        strengths.append(f"{quality}% of the plan's tests can reach a decisive verdict.")

    # An empty plan is INSUFFICIENT rather than merely in need of revision: there
    # is nothing to revise. Any gap at all — blocking or not — keeps it at REVISE,
    # because "approve" here means "nothing measurable is missing".
    if not tests:
        verdict = "INSUFFICIENT"
    elif gaps:
        verdict = "REVISE"
    else:
        verdict = "APPROVE"

    return PlanReview(
        verdict=verdict,  # type: ignore[arg-type]
        coverage_score=coverage,
        quality_score=quality,
        gaps=gaps[:_MAX_GAPS],
        strengths=strengths,
        notes=(
            f"Structural review of {len(tests)} test(s) against "
            f"{len(applicable)} applicable category(ies) and "
            f"{len(requirements)} requirement item(s)."
        ),
        reviewer="deterministic",
        tests_before=len(tests),
        tests_after=len(tests),
        reviewed_at=_now(),
    )


def _coverage_score(
    applicable: list[OwaspApiCategory],
    by_category: dict[OwaspApiCategory, list[TestCase]],
    requirements: list[RequirementItem],
    tests: list[TestCase],
) -> int:
    """Plan-time coverage: categories and requirement items with a test.

    Not the same number as `RunAssessment.coverage_pct`, which is measured
    against what *ran*. A plan can be 100% here and prove nothing.
    """
    from app.analysis.requirements import matching_tests

    parts: list[float] = []
    if applicable:
        parts.append(sum(1 for c in applicable if by_category.get(c)) / len(applicable))
    scored_items = [i for i in requirements if i.owasp_hints]
    if scored_items:
        parts.append(
            sum(1 for i in scored_items if matching_tests(i, tests)) / len(scored_items)
        )
    if not parts:
        return 100 if tests else 0
    return round(100 * sum(parts) / len(parts))


# -- the AI review ------------------------------------------------------------


class PlanReviewer:
    """Runs the structural review, then asks a model to look for what it missed."""

    def __init__(self, llm: LLMClient | None = None, max_gaps: int = _MAX_GAPS) -> None:
        self._llm = llm
        self._max_gaps = max_gaps

    def review(
        self,
        analysis: IssueAnalysis,
        tests: list[TestCase],
        requirements: list[RequirementItem] | None = None,
    ) -> PlanReview:
        if requirements is None:
            requirements = list(analysis.requirements)
        base = structural_review(analysis, tests, requirements)
        if self._llm is None:
            return base

        try:
            raw = self._llm.complete(
                _SYSTEM, self._prompt(analysis, tests, requirements, base)
            )
            payload = _extract_json_object(raw)
            proposed = _ProposedReview.model_validate(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            base.degraded_reason = f"reviewer output was not usable JSON: {exc}"
            return base
        except ValidationError as exc:
            base.degraded_reason = (
                f"reviewer output failed schema validation: {exc.error_count()} error(s)"
            )
            return base
        except Exception as exc:  # noqa: BLE001 - transport/auth failures too
            base.degraded_reason = f"reviewer LLM call failed — {type(exc).__name__}: {exc}"
            return base

        return self._merge(base, proposed, requirements)

    def _merge(
        self, base: PlanReview, proposed: _ProposedReview,
        requirements: list[RequirementItem],
    ) -> PlanReview:
        """Combine the two reviews, with structure as the floor.

        The model may add gaps, add strengths, and lower the scores. It may not
        clear a structural gap or raise the verdict above what structure allows:
        an applicable category with zero tests is a fact about the plan, and a
        reviewer that decided it was fine anyway would silently undo the one
        check that cannot be argued with.
        """
        merged = base.model_copy(deep=True)
        merged.reviewer = "ai"

        seen = {g.description.lower()[:120] for g in merged.gaps}
        for gap in proposed.gaps:
            if len(merged.gaps) >= self._max_gaps:
                break
            description = " ".join((gap.description or "").split())
            if len(description) < 8 or description.lower()[:120] in seen:
                continue
            seen.add(description.lower()[:120])
            merged.gaps.append(PlanReviewGap(
                description=description[:400],
                requirement_id=(gap.requirement_id or "")[:16],
                category=_as_category(gap.category),
                severity=_as_severity(gap.severity),
                # An unknown mutation is dropped rather than passed on: it would
                # reach the planner as a suggestion the runner has no handler
                # for, and be rejected there with a confusing reason.
                suggested_mutation=(gap.suggested_mutation
                                    if gap.suggested_mutation in MUTATION_KINDS else ""),
                suggested_endpoint=(gap.suggested_endpoint or "")[:200],
            ))

        for strength in proposed.strengths[:6]:
            text = " ".join(str(strength).split())[:200]
            if text and text not in merged.strengths:
                merged.strengths.append(text)
        if proposed.notes:
            merged.notes = f"{merged.notes} AI reviewer: {' '.join(proposed.notes.split())[:600]}"

        merged.coverage_score = min(base.coverage_score, _clamp(proposed.coverage_score))
        merged.quality_score = min(base.quality_score, _clamp(proposed.quality_score))
        merged.verdict = _floor_verdict(base.verdict, proposed.verdict)

        # Only for ids that are actually in this ticket's requirement list —
        # an invented id would show a tester a confident-looking restatement of
        # a requirement that does not exist. One row per id: a model asked
        # about the same item twice must not print it twice.
        known_ids = {i.item_id for i in requirements}
        by_id = {i.item_id: i for i in requirements}
        digest: list[RequirementDigestItem] = []
        seen_ids: set[str] = set()
        for row in proposed.requirement_digest:
            item_id = (row.item_id or "").strip()
            expected = " ".join((row.expected or "").split())
            if item_id not in known_ids or item_id in seen_ids or not expected:
                continue
            seen_ids.add(item_id)
            requirement_text = " ".join((row.requirement or "").split()) or by_id[item_id].text
            digest.append(RequirementDigestItem(
                item_id=item_id,
                requirement=requirement_text[:400],
                expected=expected[:400],
            ))
        merged.requirement_digest = digest

        merged.reviewed_at = _now()
        return merged

    def _prompt(
        self,
        analysis: IssueAnalysis,
        tests: list[TestCase],
        requirements: list[RequirementItem],
        base: PlanReview,
    ) -> str:
        endpoints = "\n".join(
            f"- {e.method} {e.path} (auth_required={e.auth_required}, "
            f"object_ids={e.object_id_params}, writes_properties={e.writes_properties}, "
            f"url_fields={e.url_fields})"
            for e in analysis.endpoints
        ) or "(none extracted)"
        reqs = "\n".join(
            f"- {i.item_id} [{i.kind}] {i.text}"
            + (f" → hints: {', '.join(c.value for c in i.owasp_hints)}" if i.owasp_hints else "")
            for i in requirements
        ) or "(none extracted)"
        # Capped: a 300-test plan would otherwise push the requirements out of
        # the model's attention, and the review is about the plan's *shape*.
        plan = "\n".join(
            f"- {t.test_id} [{t.owasp_category.value}] {t.request.method} {t.request.path} "
            f"via {t.attack_mutation.kind} "
            f"(persona={t.auth_context.persona}, baseline={'yes' if t.baseline else 'no'}, "
            f"read_back={'yes' if t.verification else 'no'})"
            for t in tests[:120]
        ) or "(the plan is empty)"
        omitted = (f"\n(+{len(tests) - 120} further test(s) not listed)" if len(tests) > 120 else "")
        structural = "\n".join(f"- [{g.severity}] {g.label()}" for g in base.gaps) or "(none)"

        return (
            f"Ticket: {analysis.issue_key}\n"
            f"Business summary: {analysis.business_summary}\n"
            f"Business impact: {analysis.business_impact}\n"
            f"Actors: {', '.join(analysis.actors) or '(none)'}\n"
            f"Sensitive operation: {analysis.sensitive_operation}\n\n"
            f"Requirements extracted from the ticket:\n{reqs}\n\n"
            f"Endpoints (the only ones you may reference):\n{endpoints}\n\n"
            f"OWASP categories the rule engine marked applicable: "
            f"{', '.join(c.value for c in analysis.applicable_categories()) or '(none)'}\n\n"
            f"The plan under review ({len(tests)} test(s)):\n{plan}{omitted}\n\n"
            f"Structural gaps already found (do not restate these):\n{structural}\n\n"
            f"Mutation catalogue — `suggested_mutation` must be one of these:\n"
            f"{_catalogue()}\n\n"
            "What does this plan miss that the ticket asks for, and which of its tests "
            "cannot be decided from evidence?"
        )


# -- helpers ------------------------------------------------------------------


_VERDICT_RANK = {"INSUFFICIENT": 0, "REVISE": 1, "APPROVE": 2}


def _floor_verdict(structural: str, proposed: str) -> str:
    """The stricter of the two verdicts wins."""
    candidate = proposed if proposed in _VERDICT_RANK else "REVISE"
    return structural if _VERDICT_RANK[structural] <= _VERDICT_RANK[candidate] else candidate


def _clamp(value: object) -> int:
    try:
        return max(0, min(100, int(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _as_category(value: str) -> OwaspApiCategory | None:
    try:
        return OwaspApiCategory(value)
    except ValueError:
        return None


def _as_severity(value: str) -> str:
    return value if value in ("blocking", "important", "minor") else "important"


def _catalogue() -> str:
    from app.analysis.attack_planner import mutation_catalogue

    return mutation_catalogue()


def _extract_json_object(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object in model response")
    parsed = json.loads(text[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("model response was not a JSON object")
    return parsed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_reviewer() -> PlanReviewer:
    """A reviewer that uses the model when configured, structure otherwise.

    Always returns a reviewer, unlike `build_planner`: the structural review
    costs nothing, needs nothing enabled, and is the part a tester should never
    be without — "this plan has no test for the category the ticket is about" is
    worth saying whether or not an AI is available to say it more eloquently.
    """
    from app.analysis.claude_analyzer import ClaudeAnalyzer

    if not ClaudeAnalyzer.is_enabled():
        return PlanReviewer(None)
    from app.analysis.staged import ClaudeLLM

    return PlanReviewer(ClaudeLLM())
