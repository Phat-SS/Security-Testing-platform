"""The review pass as a whole: measure, cluster, read, challenge, count.

The thing being tested is not "does the adjudicator work" — `test_adjudicator.py`
holds that — but whether one click over a realistic run actually shrinks the
queue, and whether it stays honest while doing it. Three properties matter more
than the rest:

  * a result measurement can settle never costs an API call, so the review
    budget is spent only on questions that genuinely need a reader;
  * results that pose the *identical* question are read once, and every row that
    inherited a reading says which row it came from;
  * nothing here ever moves a sealed verdict or a finding count.
"""

import asyncio

from app.analysis.adjudicator import ResultAdjudicator
from app.analysis.plan_reviewer import PlanReviewer
from app.database.models import init_db, make_engine, make_session_factory
from app.database.repository import Repository
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    Execution,
    SupportingExchange,
    Verdict,
)

OWNER_BODY = (
    '{"id": 2002, "name": "Beth Halloran", "email": "beth.halloran@example.com", '
    '"phone": "+61 400 111 222", "account": "ACC-88213"}'
)


class _CountingLLM:
    """Counts model calls and always reads the row as a break."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        if "The reading you are challenging" in user:
            return '{"verdict_stands": true, "objection": ""}'
        return (
            '{"assessed_result": "FAIL", "confidence": "HIGH", '
            '"needs_manual_review": false, "rationale": "The body is the victim record.", '
            '"evidence_cited": ["a customer record belonging to the victim persona"], '
            '"recommended_action": "Re-run with a marker."}'
        )


def _setup(adjudicator=None):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    orch = Orchestrator(repo, MockJiraMCPClient(),
                        reviewer=PlanReviewer(None), adjudicator=adjudicator)
    return repo, orch


def _execution(test_id: str, execution_id: str, *, status=200, body=OWNER_BODY,
               baseline_body=None, result=TestStatus.INCONCLUSIVE,
               expected="status in [403, 404]"):
    supporting = []
    if baseline_body is not None:
        supporting.append(SupportingExchange(
            kind="baseline", as_persona="agent_B",
            request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                    resolved_ip="1.2.3.4", headers={}, timestamp="t"),
            response=CapturedResponse(status_code=200, headers={}, body=baseline_body,
                                      elapsed_ms=8, size_bytes=len(baseline_body)),
            note="positive control",
        ))
    return Execution(
        execution_id=execution_id, test_id=test_id, owasp_category="API1:2023",
        scope_validated=True,
        request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                resolved_ip="203.0.113.5",
                                headers={"Authorization": "********"}, timestamp="t"),
        response=CapturedResponse(status_code=status, headers={}, body=body,
                                  elapsed_ms=9, size_bytes=len(body)),
        verdict=Verdict(result=result, confidence=Confidence.MEDIUM,
                        expected_summary=expected,
                        actual_summary=f"HTTP {status}",
                        reason="no protected marker was available"),
        supporting=supporting,
    )


def _planned(orch, aid, n=3):
    tests = orch.design(aid)
    ids = [t.test_id for t in tests][:n]
    assert len(ids) == n
    return ids


# -- measurement carries the load, and the budget is not spent on it ----------


def test_results_measurement_can_settle_cost_no_model_calls():
    """The queue shrinks before the API key is even consulted.

    Three auth-layer refusals where the test author guessed a different code and
    nothing was disclosed — the single most common shape of avoidable review
    work. (A 403 rather than a 404 deliberately: a bare 404 is only settled when
    a positive control proves the object was there to be hidden, which is the
    point of `test_evidence_signals.py`'s own case for that rule.)
    """
    llm = _CountingLLM()
    repo, orch = _setup(ResultAdjudicator(llm))
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    ids = _planned(orch, aid)
    repo.save_executions(aid, [
        _execution(tid, f"E-{i}", status=403, body='{"detail": "Forbidden"}')
        for i, tid in enumerate(ids)
    ])

    run = orch.adjudicate(aid)

    assert llm.calls == 0, "measurement settled these; no call should have been made"
    assert run.n_auto_resolved == 3
    assert run.n_measured == 3
    assert run.n_manual_review == 0
    for adjudication in run.auto_resolved:
        assert adjudication.resolution == "measured"
        assert adjudication.assessed_result == "PASS"
        assert adjudication.advisory is True


def test_a_measured_break_becomes_a_derived_finding_without_rewriting_evidence():
    """Promotion is append-only: deterministic proof may drive the final report,
    while the runner's sealed INCONCLUSIVE verdict and hash stay untouched."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    ids = _planned(orch, aid, n=1)
    repo.save_executions(aid, [
        _execution(ids[0], "E-0", body=OWNER_BODY, baseline_body=OWNER_BODY),
    ])

    run = orch.adjudicate(aid)

    assert run.n_measured == 1
    assert run.auto_resolved[0].assessed_result == "FAIL"
    assert run.overall == "FAILED"
    # The sealed verdict stays untouched; the named measurement is independently
    # signed as a derived decision and may therefore mint the report finding.
    assert repo.get_execution(aid, "E-0").verdict.result == TestStatus.INCONCLUSIVE
    events = repo.get_derived_verdicts(aid)
    assert len(events) == 1 and events[0].promoted is True
    assert len(repo.get_findings(aid)) == 1


# -- clustering ---------------------------------------------------------------


def test_identical_reading_tasks_are_read_once_and_the_reading_is_carried():
    """Three probes, one question. The point of the whole feature: an aggressive
    run leaves dozens of rows that differ only in which id they targeted."""
    llm = _CountingLLM()
    repo, orch = _setup(ResultAdjudicator(llm, challenge=False))
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    ids = _planned(orch, aid, n=1)
    tid = ids[0]
    # Same test, three attempts, same response shape and status — one question.
    repo.save_executions(aid, [
        _execution(tid, "E-0", body='{"id": 2002, "name": "Beth Halloran"}'),
        _execution(tid, "E-1", body='{"id": 2003, "name": "Carl Dunne"}'),
        _execution(tid, "E-2", body='{"id": 2004, "name": "Dana Reeve"}'),
    ])
    # latest_executions keeps one row per test, so drive the grouping directly
    # over all three rather than through the current-state view.
    executions = repo.get_executions(aid)
    assert len(executions) == 3
    tests = {t.test_id: t for t in repo.get_test_cases(aid)}
    from app.analysis.evidence_signals import analyze_evidence

    keys = {
        orch._reading_cluster_key(
            tests[e.test_id], e, analyze_evidence(tests[e.test_id], e)
        )
        for e in executions
    }
    assert len(keys) == 1, "same mutation, status and body shape is one reading task"


def test_a_row_that_disclosed_the_owners_data_never_shares_a_cluster_with_one_that_did_not():
    """The one thing the grouping must never do: carry a PASS onto a leak."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tid = _planned(orch, aid, n=1)[0]
    clean = _execution(tid, "E-0", body='{"id": 4711, "name": "Adam Prentice"}',
                       baseline_body=OWNER_BODY)
    leaked = _execution(tid, "E-1", body=OWNER_BODY, baseline_body=OWNER_BODY)
    tests = {t.test_id: t for t in repo.get_test_cases(aid)}
    from app.analysis.evidence_signals import analyze_evidence

    key_clean = orch._reading_cluster_key(tests[tid], clean,
                                          analyze_evidence(tests[tid], clean))
    key_leaked = orch._reading_cluster_key(tests[tid], leaked,
                                            analyze_evidence(tests[tid], leaked))
    assert key_clean != key_leaked


def test_a_carried_reading_names_the_row_it_was_read_from():
    """An inherited answer that does not say it was inherited is the grouping
    lying about how much reading happened."""
    from app.orchestrator import _propagated
    from app.schemas.agent import Adjudication
    from app.analysis.evidence_signals import analyze_evidence

    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tid = _planned(orch, aid, n=1)[0]
    execution = _execution(tid, "E-9")
    leader = Adjudication(execution_id="E-1", test_id=tid,
                          sealed_result=TestStatus.INCONCLUSIVE,
                          needs_manual_review=False, assessed_result="FAIL",
                          adjudicator="ai", resolution="ai_consensus",
                          rationale="The body is the victim record.")
    tests = {t.test_id: t for t in repo.get_test_cases(aid)}
    carried = _propagated(leader, execution, analyze_evidence(tests[tid], execution),
                          "abc123", 3)
    assert carried.resolution == "propagated"
    assert carried.read_from == "E-1"
    assert carried.cluster_size == 3
    assert "Carried from E-1" in carried.rationale
    assert carried.advisory is True
    # And its own measurement, not the leader's.
    assert carried.signals


# -- re-running the transient bucket -----------------------------------------


def test_a_review_pass_sends_nothing_unless_it_is_asked_to():
    """The default has to stay read-only: a tester clicking "review results"
    must not fire traffic at the target as a side effect."""
    sent = []

    class _Refuser:
        def __call__(self, *args, **kwargs):
            sent.append(args)
            raise AssertionError("a plain review pass must not re-run anything")

    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tid = _planned(orch, aid, n=1)[0]
    repo.save_executions(aid, [
        _execution(tid, "E-0", status=503, body="upstream unavailable"),
    ])
    orch.rerun_execution = _Refuser()

    run = orch.adjudicate(aid)

    assert sent == []
    assert run.n_rerun == 1
    assert run.n_reran == 0


def test_asked_to_re_run_the_transient_bucket_it_does_and_says_so():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tid = _planned(orch, aid, n=1)[0]
    repo.save_executions(aid, [
        _execution(tid, "E-0", status=503, body="upstream unavailable"),
    ])
    calls = []

    def _fake_rerun(assessment_id, execution_id, scope, vault, **kwargs):
        calls.append(execution_id)
        # A re-run appends a new execution, exactly as the real one does.
        repo.save_executions(assessment_id, [
            _execution(tid, "E-0-rerun", status=404, body='{"detail": "Not found"}'),
        ])
        return None, None

    orch.rerun_execution = _fake_rerun
    run = orch.adjudicate(aid, rerun_transient=True, scope=object(), vault=object())

    assert calls == ["E-0"]
    assert run.n_reran == 1
    # And the answer is now about the re-run, not the 503 that carried no signal.
    assert run.n_rerun == 0
    assert run.n_auto_resolved == 1
    assert "re-sent" in run.summary


def test_a_destructive_test_is_not_re_fired_by_an_automated_pass():
    """`rerun_execution` refuses without explicit confirmation, and that refusal
    has to be honoured here rather than worked around."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tid = _planned(orch, aid, n=1)[0]
    repo.save_executions(aid, [_execution(tid, "E-0", status=503, body="down")])

    def _refuse(assessment_id, execution_id, scope, vault, **kwargs):
        raise Orchestrator.RerunRefused("it is destructive — it sends a real DELETE.")

    orch.rerun_execution = _refuse
    run = orch.adjudicate(aid, rerun_transient=True, scope=object(), vault=object())

    assert run.n_reran == 0
    assert run.n_rerun == 1
    audit = [a.detail for a in repo.get_audit(aid) if a.action == "auto_rerun_skipped"]
    assert audit and "destructive" in audit[0]
