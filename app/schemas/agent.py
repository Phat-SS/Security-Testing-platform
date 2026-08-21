"""Agent-layer schema — what the reviewing agents are allowed to say.

Three roles were added on top of the existing "AI proposes, the platform
disposes" seam. Each one gets a validated output type here, and each type is
deliberately *advisory*: nothing in this module can approve a test, seal a
verdict, mint a finding or widen scope.

| Role | Produces | Who decides |
|---|---|---|
| **Requirement reader** | `RequirementItem[]` | extraction only — a list of things the ticket asks for |
| **Plan reviewer** | `PlanReview` | critiques a generated plan; the *tester* still approves every test |
| **Result adjudicator** | `Adjudication` | reads an undecided execution; `execution.verdict` is never rewritten |

The last one is the load-bearing distinction. `app/execution/verdict.py` is
agent-free and hashed into the evidence chain. An `Adjudication` sits beside
that sealed verdict. A separate conservative policy may emit a hash-bound
derived event after deterministic measurement or challenged AI consensus;
the original verdict is never replaced.

`RunAssessment` is where the per-execution opinions become one answer —
"passed or failed, and how much of the ticket did this cover". The mapping from
tests to requirements is a fuzzy reading task and may come from a model; the
arithmetic over that mapping is done here, in code, because a percentage a
model asserted is not a measurement.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .enums import Confidence, OwaspApiCategory, TestStatus

# Who produced a judgement. Kept on every agent artefact because "the model
# read the response" and "a rule matched the status code" are different
# assurances, and a reader must never have to guess which one they are looking
# at. Every AI path in this platform degrades to the deterministic one on any
# failure, so both labels occur in normal operation.
Reviewer = Literal["ai", "deterministic"]

RequirementKind = Literal[
    "security_control",  # "an agent must not read another agent's customer"
    "business_rule",  # "a quote expires after 30 days"
    "acceptance_criterion",  # a literal AC line
    "poc_claim",  # something the attached PoC demonstrates
    "other",
]

CoverageState = Literal[
    "COVERED_PASS",  # tested, and the control held
    "COVERED_FAIL",  # tested, and the control broke
    "PARTIAL",  # tested, but nothing decided it (undecided/blocked/errored)
    "NOT_COVERED",  # the plan has a test for it, but it never ran
    "NOT_TESTED",  # nothing in the plan addresses it
]


class RequirementItem(BaseModel):
    """One discrete thing the ticket asks for.

    The unit the "% of the ticket covered" number is computed over. A ticket's
    prose is not a checklist, so this is extracted (heuristically, or by the
    model when it is enabled) and — like the endpoint list — is meant to be
    correctable rather than trusted.
    """

    item_id: str = Field(examples=["R-01"])
    text: str
    kind: RequirementKind = "other"
    # Categories a test would have to exercise to address this item. Empty is
    # meaningful: an item with no security-relevant reading (a UI copy change,
    # say) should not drag the coverage percentage down, so it is excluded from
    # the denominator rather than counted as a gap.
    owasp_hints: list[OwaspApiCategory] = Field(default_factory=list)
    source: str = "description"
    # True when a human typed this rather than the extractor finding it. Same
    # contract as Endpoint.manual: re-extraction keeps these.
    manual: bool = False

    @property
    def is_security_relevant(self) -> bool:
        return bool(self.owasp_hints) or self.kind == "security_control"


class PlanReviewGap(BaseModel):
    """Something the reviewing agent says the plan does not yet cover.

    `suggested_mutation` is a hint for the revision round, not an instruction:
    it goes into a prompt, and whatever the planner proposes in response still
    passes every constraint in `AttackPlanner.accept()`.
    """

    description: str
    requirement_id: str = ""
    category: OwaspApiCategory | None = None
    severity: Literal["blocking", "important", "minor"] = "important"
    suggested_mutation: str = ""
    suggested_endpoint: str = ""

    def label(self) -> str:
        head = self.category.value if self.category else (self.requirement_id or "plan")
        return f"{head}: {self.description}"


class RequirementDigestItem(BaseModel):
    """One requirement, restated as what a secure system must specifically do.

    `text` on `RequirementItem` is the ticket's own wording — a bullet or AC
    line, exactly as written. That is often a paraphrase ("must prevent
    unauthorized ownership changes") rather than the concrete, checkable
    behaviour a tester can hold a test result against ("PUT
    /vehicles/{id}/change-ownership must return 401 for an anonymous caller,
    not fall through to business-logic validation"). This is that restatement
    — written once, by the reviewing agent reading the ticket, so a tester
    opening the plan review knows exactly what "the control held" is supposed
    to mean for this item before they approve anything.
    """

    item_id: str = ""
    requirement: str = ""
    expected: str = ""


class PlanReview(BaseModel):
    """The second agent's opinion of a generated plan, before a human reads it.

    Advisory by construction: it can ask for *more* tests (the revision round
    feeds its gaps back to the planner) but it cannot remove a test, change an
    approval, or mark itself satisfied on the tester's behalf. `verdict` is
    information for the person about to approve, not a gate.
    """

    verdict: Literal["APPROVE", "REVISE", "INSUFFICIENT"] = "REVISE"
    # 0..100. Coverage = how much of the requirement/OWASP surface the plan
    # touches. Quality = how much of the plan is *decidable* — a test with a
    # positive control and a read-back can produce a verdict; one without can
    # usually only produce INCONCLUSIVE.
    coverage_score: int = 0
    quality_score: int = 0
    gaps: list[PlanReviewGap] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)
    notes: str = ""
    # AI-only (empty on the deterministic review — restating intent from prose
    # is a reading task, not something a structural count can do). Read this
    # before the gap list: it says what the ticket actually needs to be true,
    # so a gap below ("no test for API2") means something concrete instead of
    # just a category name.
    requirement_digest: list[RequirementDigestItem] = Field(default_factory=list)

    reviewer: Reviewer = "deterministic"
    # Why the AI reviewer did not run, when it didn't. Same contract as
    # `ClaudeAnalyzer.last_fallback_reason`: a silently-degraded review that
    # reads like a real one is worse than no review at all.
    degraded_reason: str = ""

    # What the pipeline did with the critique.
    rounds: int = 0
    tests_before: int = 0
    tests_after: int = 0
    tests_added: list[str] = Field(default_factory=list)
    unresolved_gaps: list[PlanReviewGap] = Field(default_factory=list)
    reviewed_at: str = ""
    model_id: str = ""
    prompt_version: str = ""
    prompt_hash: str = ""

    @property
    def blocking_gaps(self) -> list[PlanReviewGap]:
        return [g for g in self.unresolved_gaps or self.gaps if g.severity == "blocking"]

    def headline(self) -> str:
        if self.verdict == "APPROVE":
            return (f"The plan covers the ticket ({self.coverage_score}% coverage, "
                    f"{self.quality_score}% decidable).")
        if self.verdict == "INSUFFICIENT":
            return (f"The plan has gaps the planner could not fill "
                    f"({len(self.unresolved_gaps)} unresolved).")
        return (f"The plan was revised after review "
                f"({len(self.tests_added)} test(s) added).")


class Adjudication(BaseModel):
    """A reading of one execution the deterministic verdict left undecided.

    `assessed_result` is an opinion, never a sealed verdict: `execution.verdict`
    stays exactly as the runner sealed it. A separate promotion policy can turn
    only sufficiently strong readings into append-only derived decisions. This
    exists to answer the question a tester was answering by hand —
    "do I actually have to look at this one?" — and to say what the answer
    would be if not.
    """

    execution_id: str
    test_id: str
    # The verdict the runner sealed, carried alongside so a reader never sees
    # the opinion without the record it is an opinion about.
    sealed_result: TestStatus

    needs_manual_review: bool = True
    triage_reason: str = ""

    assessed_result: Literal["PASS", "FAIL", "INCONCLUSIVE"] = "INCONCLUSIVE"
    confidence: Confidence = Confidence.LOW
    rationale: str = ""
    # Quotes/paraphrases of what in the evidence drove the call. Redacted on
    # the way out like every other narrative field.
    evidence_cited: list[str] = Field(default_factory=list)
    recommended_action: str = ""

    adjudicator: Reviewer = "deterministic"
    degraded_reason: str = ""
    model_id: str = ""
    prompt_version: str = ""
    prompt_hash: str = ""
    # Structurally true. A field rather than a docstring so every renderer,
    # export and comment has to carry the caveat with the value.
    advisory: bool = True

    # How this reading was arrived at. A reader must never have to guess
    # whether "PASS" came out of a measurement, a model, two models agreeing,
    # or a sibling result it was copied from — those are four different
    # assurances and they are not interchangeable.
    #   sealed      — the runner decided it; this is a deferral, not a reading
    #   measured    — a named deterministic rule over the captured evidence
    #                 (`app/analysis/evidence_signals.measure`), reproducible
    #   ai          — the model read it and no second pass was available
    #   ai_consensus— the model read it and a challenge pass failed to refute it
    #   propagated  — copied from an identical result read once for the cluster
    #   capped      — never read: the pass ran out of its model-call budget
    #   manual      — nothing settled it; a person has to look
    resolution: Literal[
        "sealed", "measured", "ai", "ai_consensus", "propagated", "capped", "manual"
    ] = "manual"
    # The deterministic rule that settled it, when `resolution` is "measured".
    # Named so a tester who disagrees knows exactly what to argue with.
    rule: str = ""

    # The measured differential the reading was made against: status-layer
    # attribution, body shape, similarity to the positive control, how many
    # distinctive values the attacker's response shares with the owner's. Facts,
    # computed with no model involved — and the same facts the model was shown.
    signals: list[str] = Field(default_factory=list)

    # The second, adversarial pass. `challenged` says one ran; `challenge_note`
    # carries its objection when it had one. An auto-resolved reading that was
    # never challenged and one that survived a challenge are different claims.
    challenged: bool = False
    challenge_agreed: bool = False
    challenge_note: str = ""

    # When several results were measurably the same reading task, one was read
    # and the rest carry that reading with the cluster it came from named. Empty
    # for a result read on its own.
    cluster_id: str = ""
    cluster_size: int = 0
    read_from: str = ""  # execution_id of the sibling actually read

    # What kind of thing is in the way, when a person is still needed. Lets a
    # queue be grouped by *what would fix it* rather than by test id: fixing one
    # stale object id can clear a dozen rows, and that is invisible when they
    # are listed one by one.
    #   test_data   — the positive control failed / wrong object id or persona
    #   config      — scope, policy or environment stopped the request
    #   no_evidence — it ran, but captured nothing readable either way
    #   ambiguous   — readable evidence that genuinely does not settle it
    #   unread      — no reader was available (no AI configured, or over budget)
    blocker: Literal["", "test_data", "config", "no_evidence", "ambiguous", "unread"] = ""

    @property
    def differs_from_sealed(self) -> bool:
        return self.assessed_result != self.sealed_result.value

    @property
    def settled(self) -> bool:
        """The adjudicator answered it and nobody has to read it again."""
        return not self.needs_manual_review and self.assessed_result in ("PASS", "FAIL")


class RequirementCoverage(BaseModel):
    """One requirement item, and what the run actually proved about it."""

    item_id: str
    text: str
    state: CoverageState = "NOT_TESTED"
    tests: list[str] = Field(default_factory=list)
    note: str = ""

    @property
    def weight(self) -> float:
        """Contribution to the coverage percentage. A PARTIAL counts as a half:
        a test that ran but decided nothing is not zero progress, and it is not
        coverage either."""
        return {"COVERED_PASS": 1.0, "COVERED_FAIL": 1.0, "PARTIAL": 0.5}.get(self.state, 0.0)


class RunAssessment(BaseModel):
    """The run-level answer: passed or failed, and how much of the ticket it covered.

    Every number here is computed in `app/analysis/adjudicator.py` from the
    per-item mapping — the model may propose the mapping, it never asserts the
    percentage.
    """

    assessment_id: str = ""
    issue_key: str = ""
    overall: Literal["PASSED", "FAILED", "INCOMPLETE"] = "INCOMPLETE"
    # Requirement coverage, weighted; PARTIAL counts as a half.
    coverage_pct: int = 0
    # Share of executions that reached a decisive result (PASS/FAIL), after
    # adjudication. The honest companion to coverage: 100% coverage where every
    # test came back INCONCLUSIVE proves nothing.
    decided_pct: int = 0

    items: list[RequirementCoverage] = Field(default_factory=list)
    adjudications: list[Adjudication] = Field(default_factory=list)

    # The percentage's own workings, so no renderer has to reconstruct them. It
    # matters that these are stored rather than re-derived per view: a report and
    # a Jira comment that each computed the fraction their own way printed "67%
    # (2/2 items)", which is not a rounding disagreement but a contradiction the
    # reader has no way to resolve.
    n_items_scored: int = 0     # the denominator: items with a testable category
    n_items_decided: int = 0    # a test for the item reached PASS or FAIL
    n_items_partial: int = 0    # a test ran but decided nothing (counts a half)

    n_executions: int = 0
    n_fail: int = 0
    n_pass: int = 0
    n_undecided: int = 0
    # A person still has to look.
    n_manual_review: int = 0
    # The adjudicator settled it: an undecided execution it read as PASS or FAIL.
    n_auto_resolved: int = 0
    # Undecided and nobody needs to read it — a 5xx or a runner error, where the
    # answer is to send the request again. Counted separately from both of the
    # above, because "no human needed" and "resolved" are not the same thing and
    # collapsing them would report a run as settled while a third of it is still
    # waiting to be re-sent.
    n_rerun: int = 0
    # Of `n_auto_resolved`, how many were settled by a named deterministic rule
    # over the evidence rather than by a model. Reported separately because it
    # is the number that says how much of the review load the platform can carry
    # with no API key at all — and because a measured reading is reproducible in
    # a way a model's is not.
    n_measured: int = 0
    # Settled by copying an identical sibling's reading (see Adjudication.cluster_id).
    n_propagated: int = 0
    # Auto-resolved readings that survived an adversarial second pass.
    n_consensus: int = 0
    # Executions re-sent during this review pass because they had errored or
    # returned a 5xx, so their result is the re-run's rather than the original's.
    n_reran: int = 0

    summary: str = ""
    reviewer: Reviewer = "deterministic"
    degraded_reason: str = ""
    assessed_at: str = ""

    @property
    def manual_review_items(self) -> list[Adjudication]:
        return [a for a in self.adjudications if a.needs_manual_review]

    @property
    def auto_resolved(self) -> list[Adjudication]:
        """Undecided executions the adjudicator actually settled.

        Deliberately not "everything that does not need a person": an execution
        awaiting a re-run needs no reader and is not resolved, and listing it
        here would make a partially-settled run read as a settled one.
        """
        return [
            a for a in self.adjudications
            if not a.needs_manual_review
            and a.sealed_result == TestStatus.INCONCLUSIVE
            and a.assessed_result in ("PASS", "FAIL")
        ]

    @property
    def awaiting_rerun(self) -> list[Adjudication]:
        return [
            a for a in self.adjudications
            if not a.needs_manual_review
            and a.assessed_result == "INCONCLUSIVE"
            and a.sealed_result not in (TestStatus.PASS, TestStatus.FAIL)
        ]
