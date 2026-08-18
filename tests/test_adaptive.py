"""The adaptive loop's bounds and its policy gate.

This is the one path where the platform sends a request no human read first, so
the tests here are about what it *refuses* and where it *stops*, not about how
clever the follow-ups are. A fake planner stands in for the model: what matters
is that the loop constrains whatever comes back.
"""

from app.analysis.attack_planner import PlanResult
from app.execution.adaptive import AdaptiveBudget, AdaptiveExecutor
from app.schemas.analysis import IssueAnalysis
from app.schemas.enums import ApprovalStatus, Confidence, TestStatus
from app.schemas.execution import CapturedRequest, Execution, Verdict
from app.schemas.testcase import AuthContext, ExpectedResult, Mutation, RequestSpec, TestCase


def _test(test_id="T-1", kind="drop_auth", method="GET", destructive=False) -> TestCase:
    return TestCase(
        test_id=test_id, title=f"test {test_id}", objective="o",
        owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method=method, path="/customers/{victim_id}"),
        attack_mutation=Mutation(kind=kind),
        expected=ExpectedResult(status_in=[403]),
        is_destructive=destructive,
        approval_status=ApprovalStatus.APPROVED,
    )


class _FakeRunner:
    """Records what it was asked to run and returns a chosen verdict."""

    def __init__(self, result=TestStatus.INCONCLUSIVE) -> None:
        self.result = result
        self.ran: list[str] = []

    def run_safe(self, test, execution_id, prev_hash=None):
        self.ran.append(test.test_id)
        return Execution(
            execution_id=execution_id, test_id=test.test_id,
            owasp_category=test.owasp_category.value, scope_validated=True,
            request=CapturedRequest(method="GET", url="http://t/x", resolved_ip="1.2.3.4",
                                    headers={}, timestamp="now"),
            response=None,
            verdict=Verdict(result=self.result, confidence=Confidence.MEDIUM,
                            expected_summary="", actual_summary="", reason="r"),
            evidence_hash=f"hash-{execution_id}", prev_hash=prev_hash,
        )


class _FakePlanner:
    """Proposes a fixed follow-up every time it is asked — i.e. it would loop
    forever if the executor's bounds did not stop it."""

    def __init__(self, followup_factory=None) -> None:
        self.calls = 0
        self._factory = followup_factory or (lambda n: [_test(f"F-{n}")])

    def follow_up(self, analysis, test, execution, id_prefix="AI"):
        self.calls += 1
        return PlanResult(tests=self._factory(self.calls))


_ANALYSIS = IssueAnalysis(issue_key="X-1")


def _executor(runner, planner, **budget_kwargs):
    return AdaptiveExecutor(runner, planner, _ANALYSIS, AdaptiveBudget(**budget_kwargs))


# -- bounds -------------------------------------------------------------------


def test_iteration_cap_stops_an_otherwise_endless_planner():
    runner, planner = _FakeRunner(), _FakePlanner()
    result = _executor(runner, planner, max_iterations=2).run([_test()], "E")
    assert result.iterations == 2
    assert "iteration cap" in result.stopped_because


def test_total_followup_cap_holds():
    runner, planner = _FakeRunner(), _FakePlanner()
    result = _executor(runner, planner, max_iterations=99, max_total_followups=3).run([_test()], "E")
    assert result.followups_run <= 3


def test_per_iteration_cap_limits_a_greedy_batch():
    runner = _FakeRunner()
    planner = _FakePlanner(lambda n: [_test(f"F-{n}-{i}") for i in range(10)])
    _executor(runner, planner, max_iterations=2,
              max_followups_per_iteration=2).run([_test()], "E")
    # Iteration 1 runs the seed and plans at most 2; iteration 2 runs those two.
    assert len(runner.ran) <= 1 + 2


def test_wall_clock_budget_stops_the_loop():
    ticks = iter([0.0, 0.0, 500.0, 500.0, 500.0, 500.0])
    executor = AdaptiveExecutor(_FakeRunner(), _FakePlanner(), _ANALYSIS,
                                AdaptiveBudget(max_iterations=99, max_wall_clock_s=10.0),
                                clock=lambda: next(ticks, 500.0))
    result = executor.run([_test()], "E")
    assert "wall-clock" in result.stopped_because


def test_a_control_that_held_is_not_pursued():
    """PASS ends that thread. Re-probing it burns budget an undecided result
    needs."""
    runner, planner = _FakeRunner(result=TestStatus.PASS), _FakePlanner()
    result = _executor(runner, planner, max_iterations=5).run([_test()], "E")
    assert planner.calls == 0
    assert result.followups_run == 0
    assert runner.ran == ["T-1"]


# -- the policy gate ----------------------------------------------------------


def test_destructive_followups_are_refused_by_default():
    """No human read this request, and a successful write cannot be undone."""
    runner = _FakeRunner()
    planner = _FakePlanner(lambda n: [_test(f"F-{n}", method="DELETE", destructive=True)])
    result = _executor(runner, planner, max_iterations=3).run([_test()], "E")

    assert runner.ran == ["T-1"]  # the follow-up never ran
    assert any("destructive" in r for r in result.rejected)


def test_destructive_followups_run_only_when_explicitly_allowed():
    runner = _FakeRunner()
    planner = _FakePlanner(lambda n: [_test(f"F-{n}", method="DELETE", destructive=True)])
    result = _executor(runner, planner, max_iterations=2,
                       allow_destructive=True).run([_test()], "E")
    assert "F-1" in runner.ran
    assert result.followups_run >= 1


def test_a_kind_outside_the_adaptive_allowlist_is_refused():
    runner = _FakeRunner()
    planner = _FakePlanner(lambda n: [_test(f"F-{n}", kind="race_condition")])
    result = _executor(runner, planner, max_iterations=3,
                       allowed_kinds=frozenset({"drop_auth"})).run([_test()], "E")
    assert runner.ran == ["T-1"]
    assert any("outside the adaptive policy allowlist" in r for r in result.rejected)


def test_auto_approval_is_labelled_as_policy_not_human_review():
    """'A human approved this' and 'a policy permitted this' are different
    assurances and must not read alike in the report."""
    runner, planner = _FakeRunner(), _FakePlanner()
    result = _executor(runner, planner, max_iterations=2).run([_test()], "E")

    followup = result.followups[0]
    assert followup.approval_status == ApprovalStatus.APPROVED
    assert "AUTO-APPROVED by adaptive policy" in followup.objective
    assert "Not individually reviewed by a human" in followup.objective


def test_followups_are_returned_for_persistence():
    """An execution whose test_id resolves to no stored test is invisible to
    finding construction and renders as a blank report row."""
    runner, planner = _FakeRunner(), _FakePlanner()
    result = _executor(runner, planner, max_iterations=2).run([_test()], "E")
    assert result.followups
    assert {t.test_id for t in result.followups} <= set(runner.ran)


def test_a_queued_but_never_run_followup_is_not_reported_for_persistence():
    """A follow-up is APPROVED under policy. If the loop stops before running
    one, persisting it would leave an approved-but-unreviewed test in the
    database — armed to fire on the next ordinary 'run approved tests'."""
    runner, planner = _FakeRunner(), _FakePlanner()
    # max_iterations=2: iteration 2 runs F-1 and plans F-2, which never runs.
    result = _executor(runner, planner, max_iterations=2).run([_test()], "E")

    assert "F-2" not in {t.test_id for t in result.followups}
    assert "F-2" not in runner.ran


# -- degradation --------------------------------------------------------------


def test_without_a_planner_the_loop_is_a_plain_one_shot_run():
    runner = _FakeRunner()
    result = AdaptiveExecutor(runner, None, _ANALYSIS, AdaptiveBudget()).run([_test()], "E")
    assert runner.ran == ["T-1"]
    assert "no planner configured" in result.stopped_because


def test_a_planner_error_is_recorded_and_does_not_abort_the_run():
    class _BrokenPlanner:
        def follow_up(self, analysis, test, execution, id_prefix="AI"):
            return PlanResult(error="upstream exploded")

    runner = _FakeRunner()
    result = _executor(runner, _BrokenPlanner(), max_iterations=3).run([_test()], "E")
    assert result.executions  # the seed test still ran and was recorded
    assert result.planner_errors == ["T-1: upstream exploded"]


def test_the_evidence_chain_is_threaded_through_follow_ups():
    """Adaptive results must join the same tamper-evident chain, not start a
    fresh one that would verify clean on its own."""
    runner, planner = _FakeRunner(), _FakePlanner()
    result = _executor(runner, planner, max_iterations=2).run([_test()], "E", prev_hash="seed")

    assert result.executions[0].prev_hash == "seed"
    for earlier, later in zip(result.executions, result.executions[1:]):
        assert later.prev_hash == earlier.evidence_hash
