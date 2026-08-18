"""Bounded adaptive exploitation loop.

A one-shot runner asks a question and writes down the answer. A tester reads the
answer and asks a better question. This module is the second thing, with every
dangerous degree of freedom removed.

    run seed tests → for each undecided or broken result, ask the planner for a
    follow-up → apply policy → run → repeat, until a bound is hit

What makes it safe to let a model steer this at all is that it steers nothing
that matters. Each iteration's proposals go through the same `AttackPlanner`
constraints (reviewed mutation kinds only, relative paths only, known personas
only, PENDING by default), and then through a second policy gate here before
anything is marked runnable. The `ScopeValidator` is untouched and still decides
every packet. The loop can choose *which* reviewed probe to send next; it cannot
choose where to send it, what it may do, or whether a human's approval was
required.

Prompt injection is the live threat: the target's own response body is fed back
to the planner, and a hostile target can put instructions in it. That is treated
as a given rather than something to detect. A fully compromised planner can, at
worst, select a different allowlisted, non-destructive mutation against an
in-scope host — which is the set of things a human already approved the loop to
do. It cannot widen scope, execute code, escalate to a destructive probe, or
approve anything, because none of those are decided by the model.

Bounds are wall clock, iteration count, total follow-ups, and destructiveness.
Whichever is hit first stops the loop, and the reason is recorded.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.schemas.enums import ApprovalStatus, TestSource, TestStatus
from app.schemas.execution import Execution
from app.schemas.testcase import TestCase


@dataclass(frozen=True)
class AdaptiveBudget:
    """Hard ceilings. Every one of these is a stop condition, not a hint."""

    max_iterations: int = 2
    max_followups_per_iteration: int = 4
    max_total_followups: int = 10
    max_wall_clock_s: float = 120.0
    # Off by default and deliberately awkward to turn on: a follow-up is
    # generated without a human reading it, and a destructive probe that
    # succeeds has already changed the target's data.
    allow_destructive: bool = False
    # None → the planner's own allowlist applies. Narrow it to run the loop
    # under a tighter policy than the design step.
    allowed_kinds: frozenset[str] | None = None


@dataclass
class AdaptiveResult:
    executions: list[Execution] = field(default_factory=list)
    # The test cases the loop generated and ran. Returned so the caller can
    # persist them: an execution whose test_id resolves to no stored test is
    # invisible to finding construction and renders as a blank row in the
    # report, which would quietly discard the loop's most interesting results.
    followups: list[TestCase] = field(default_factory=list)
    iterations: int = 0
    followups_run: int = 0
    stopped_because: str = "no further leads"
    # Proposals the policy refused, with reasons — surfaced rather than dropped
    # so an operator can see what the loop declined to do on their behalf.
    rejected: list[str] = field(default_factory=list)
    planner_errors: list[str] = field(default_factory=list)

    @property
    def last_hash(self) -> str | None:
        return self.executions[-1].evidence_hash if self.executions else None

    def summary(self) -> str:
        return (
            f"{len(self.executions)} execution(s) over {self.iterations} iteration(s); "
            f"{self.followups_run} adaptive follow-up(s); stopped: {self.stopped_because}"
        )


# Outcomes worth spending another request on. PASS is not here: a control that
# held is the end of that thread, and re-probing it burns budget that an
# undecided result needs.
_WORTH_PURSUING = {TestStatus.INCONCLUSIVE, TestStatus.FAIL}


class AdaptiveExecutor:
    def __init__(
        self,
        runner,
        planner,
        analysis,
        budget: AdaptiveBudget | None = None,
        clock=time.monotonic,
    ) -> None:
        self._runner = runner
        self._planner = planner
        self._analysis = analysis
        self._budget = budget or AdaptiveBudget()
        self._clock = clock

    def run(
        self,
        seed_tests: list[TestCase],
        execution_prefix: str,
        prev_hash: str | None = None,
    ) -> AdaptiveResult:
        budget = self._budget
        result = AdaptiveResult()
        started = self._clock()
        queue: list[TestCase] = list(seed_tests)
        seen_ids: set[str] = {t.test_id for t in seed_tests}
        # Follow-ups become APPROVED under policy. One that was queued but never
        # reached (an iteration or wall-clock bound stopped the loop first) must
        # NOT be reported for persistence: storing an APPROVED test that no
        # human reviewed and no run exercised would leave it sitting in the
        # database, ready to execute on the next ordinary "run approved tests".
        # Only what actually ran is recorded.
        followup_ids: set[str] = set()
        iteration = 0

        while queue:
            if iteration >= budget.max_iterations:
                result.stopped_because = f"iteration cap reached ({budget.max_iterations})"
                break
            if self._clock() - started > budget.max_wall_clock_s:
                result.stopped_because = f"wall-clock budget exhausted ({budget.max_wall_clock_s}s)"
                break

            batch, queue = queue, []
            iteration += 1
            result.iterations = iteration

            outcomes: list[tuple[TestCase, Execution]] = []
            for test in batch:
                execution_id = f"{execution_prefix}-{test.test_id}-i{iteration}"
                execution = self._runner.run_safe(test, execution_id=execution_id, prev_hash=prev_hash)
                prev_hash = execution.evidence_hash
                result.executions.append(execution)
                outcomes.append((test, execution))
                if test.test_id in followup_ids:
                    result.followups.append(test)

            # Planning happens after the whole batch so a follow-up can be
            # skipped when an earlier result in the same batch already settled
            # the question — and so the wall-clock check above sees the true
            # cost of an iteration before committing to another.
            if self._planner is None:
                result.stopped_because = "no planner configured; ran seed tests only"
                break
            if result.followups_run >= budget.max_total_followups:
                result.stopped_because = f"follow-up cap reached ({budget.max_total_followups})"
                break

            planned = 0
            for test, execution in outcomes:
                if execution.verdict.result not in _WORTH_PURSUING:
                    continue
                if planned >= budget.max_followups_per_iteration:
                    break
                if result.followups_run + planned >= budget.max_total_followups:
                    break

                # A per-iteration, per-parent prefix: ordinals restart on every
                # planner call, so a shared prefix would make iteration 2's
                # proposals collide with iteration 1's and be dropped as
                # duplicates by the seen_ids check below.
                plan = self._planner.follow_up(
                    self._analysis, test, execution,
                    id_prefix=f"AI{iteration}-{test.test_id}",
                )
                if plan.error:
                    result.planner_errors.append(f"{test.test_id}: {plan.error}")
                    continue
                result.rejected.extend(plan.rejected)

                for proposed in plan.tests:
                    if planned >= budget.max_followups_per_iteration:
                        break
                    if proposed.test_id in seen_ids:
                        continue
                    reason = self._policy_refusal(proposed)
                    if reason:
                        result.rejected.append(f"'{proposed.title}': {reason}")
                        continue
                    seen_ids.add(proposed.test_id)
                    followup_ids.add(proposed.test_id)
                    queue.append(self._authorise(proposed, test))
                    planned += 1

            result.followups_run += planned
            # Every planned follow-up is queued, so an empty queue here means
            # nothing survived planning or policy — the loop is out of leads.
            if not queue:
                result.stopped_because = "no further leads"

        return result

    # -- policy -------------------------------------------------------------

    def _policy_refusal(self, test: TestCase) -> str | None:
        """The second gate. The planner already rejected malformed proposals;
        this decides whether a well-formed one may run *without a human*."""
        budget = self._budget
        if test.is_destructive and not budget.allow_destructive:
            return (
                "destructive probes are excluded from adaptive follow-up (no human reviewed "
                "this request, and a successful write cannot be undone)"
            )
        if budget.allowed_kinds is not None and test.attack_mutation.kind not in budget.allowed_kinds:
            return f"mutation {test.attack_mutation.kind!r} is outside the adaptive policy allowlist"
        return None

    def _authorise(self, test: TestCase, parent: TestCase) -> TestCase:
        """Mark a follow-up runnable under policy, and say so in the record.

        The distinction between "a human approved this" and "a policy permitted
        this" must survive into the report — they are different assurances, and
        collapsing them would let an unattended loop's output be read as
        human-reviewed. `objective` carries it because that text is rendered in
        the report and hashed into evidence via the test case.
        """
        approved = test.model_copy(deep=True)
        approved.approval_status = ApprovalStatus.APPROVED
        # Recorded in the source too, not only in the prose below: a re-run has to
        # be able to leave these out of the plan it copies, and grepping an
        # objective string for that is not a contract.
        approved.source = TestSource.ADAPTIVE_PLANNER
        approved.objective = (
            f"{approved.objective} [AUTO-APPROVED by adaptive policy while pursuing "
            f"{parent.test_id}: non-destructive, mutation '{approved.attack_mutation.kind}' "
            "within the reviewed allowlist. Not individually reviewed by a human.]"
        )
        return approved
