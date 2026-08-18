"""The end-to-end agent pipeline, wired to persistence and the HTTP layer.

The unit tests cover each agent's constraints. These cover the wiring, and the
properties that only exist once the pieces are joined:

  * pressing Import produces a plan a tester can approve, with a review attached
  * the review's gaps reach the planner, and what comes back is still PENDING
  * a revision round cannot escape `AttackPlanner.accept()`
  * reviewing results never touches the sealed verdicts, the evidence chain or
    the finding count
  * both paths degrade to the deterministic one rather than failing the import
"""

import asyncio

from starlette.testclient import TestClient

from app.analysis.attack_planner import AttackPlanner
from app.analysis.plan_reviewer import PlanReviewer
from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.execution.evidence import verify_chain
from app.mcp.jira import NormalizedIssue
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.schemas.enums import ApprovalStatus, TestSource, TestStatus
from demo.sample_tests import build_vault
from demo.vulnerable_api import app as vulnerable_app


class _ScriptedLLM:
    """Replies in order; repeats the last reply once exhausted."""

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append(user)
        if len(self.replies) > 1:
            return self.replies.pop(0)
        return self.replies[0]


class _BrokenLLM:
    def complete(self, system: str, user: str) -> str:
        raise RuntimeError("no key")


class _FakeJira:
    """A ticket with an acceptance criterion the endpoint list cannot express.

    The whole reason the reviewing agent exists: "only an admin may re-assign" is
    a BFLA requirement stated in prose, and a plan built from endpoints alone
    covers it by accident or not at all.
    """

    def __init__(self, issue: NormalizedIssue | None = None) -> None:
        self.issue = issue or NormalizedIssue(
            issue_key="CRM-9001", project_key="CRM",
            summary="Customer records API — ownership and re-assignment",
            description=(
                "Agents manage their own customers through GET /customers/{customerId}.\n"
                "- An agent must not be able to read another agent's customer.\n"
                "- Only an admin role may re-assign a customer to another agent.\n"
            ),
            acceptance_criteria=[
                "An agent requesting another agent's customerId receives 403.",
            ],
        )
        self.comments: list[str] = []

    async def connect(self) -> None:
        return None

    async def test_connection(self) -> bool:
        return True

    async def get_issue(self, issue_key: str) -> NormalizedIssue:
        return self.issue

    async def list_project_issues(self, project_key: str):
        return [self.issue]

    async def get_comments(self, issue_key: str):
        return list(self.comments)

    async def add_comment(self, issue_key: str, comment: str) -> None:
        self.comments.append(comment)

    async def get_attachments(self, issue_key: str):
        return []

    def browse_url(self, issue_key: str):
        return None


def _setup(planner=None, reviewer=None, adjudicator=None, jira=None):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    orch = Orchestrator(repo, jira or _FakeJira(), planner=planner,
                        reviewer=reviewer or PlanReviewer(None),
                        adjudicator=adjudicator)
    return repo, orch


# -- import → plan → review ----------------------------------------------------


def test_import_and_plan_lands_on_a_plan_with_a_review_attached():
    repo, orch = _setup()
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))

    tests = repo.get_test_cases(aid)
    assert tests, "importing should have produced a plan to approve"
    assert review is not None
    assert repo.get_plan_review(aid) is not None
    # And the requirement list the review is measured against was extracted.
    assert orch.get_analysis(aid).requirements


def test_nothing_in_a_generated_plan_is_approved():
    """The gate does not move. An agent produced this; a person approves it."""
    repo, orch = _setup()
    aid, _review = asyncio.run(orch.import_and_plan("CRM-9001"))
    assert all(t.approval_status == ApprovalStatus.PENDING
               for t in repo.get_test_cases(aid))


def test_the_review_names_the_requirement_the_plan_misses():
    repo, orch = _setup()
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))
    gap_text = " ".join(g.description for g in review.gaps)
    # "Only an admin may re-assign" is API5, and the deterministic designer has
    # no endpoint to hang a BFLA test on.
    assert "R-0" in gap_text or "API5" in gap_text


def test_without_a_planner_the_gaps_are_reported_rather_than_silently_dropped():
    repo, orch = _setup(planner=None)
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))
    assert review.rounds == 0
    assert review.unresolved_gaps
    assert "No AI planner is configured" in review.notes


_REVISION = """{"tests": [{
  "title": "Non-admin attempts a customer re-assignment",
  "objective": "Only an admin role may re-assign a customer.",
  "owasp_category": "API5:2023",
  "persona": "anonymous",
  "method": "GET",
  "path": "/internal/agent-reassign-probe",
  "mutation_kind": "escalate_persona",
  "expected_status_in": [403]
}]}"""


def test_a_review_gap_reaches_the_planner_and_its_answer_joins_the_plan():
    llm = _ScriptedLLM('{"tests": []}', _REVISION)
    planner = AttackPlanner(llm, known_personas=["anonymous", "agent_A", "agent_B"])
    repo, orch = _setup(planner=planner)
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))

    assert review.rounds == 1
    assert review.tests_added, "the planner's answer should have joined the plan"
    added = [t for t in repo.get_test_cases(aid) if t.test_id in review.tests_added]
    assert added
    # Still a proposal: PENDING, sourced as AI, and its id marks it as a revision.
    assert all(t.approval_status == ApprovalStatus.PENDING for t in added)
    assert all(t.source == TestSource.AI for t in added)
    assert all(t.test_id.startswith("AIR") for t in added)


def test_a_revision_round_cannot_escape_the_planners_constraints():
    """A reviewer that asked for something the runner cannot send must not be
    able to get it: the revision batch goes through `accept()` like any other."""
    illegal = """{"tests": [{
      "title": "Absolute host and an invented mutation",
      "owasp_category": "API1:2023",
      "persona": "anonymous",
      "method": "GET",
      "path": "https://evil.example/steal",
      "mutation_kind": "run_arbitrary_python",
      "expected_status_in": [403]
    }]}"""
    llm = _ScriptedLLM('{"tests": []}', illegal)
    planner = AttackPlanner(llm, known_personas=["anonymous"])
    repo, orch = _setup(planner=planner)
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))

    assert review.tests_added == []
    assert not any("evil.example" in t.request.path for t in repo.get_test_cases(aid))
    # And the rejection is on the record individually, not inferable from a count.
    rejections = [a.detail for a in repo.get_audit(aid)
                  if a.action == "plan_revision_rejected"]
    assert rejections and "unknown mutation kind" in rejections[0]


def test_the_rounds_are_bounded_however_dissatisfied_the_reviewer_is():
    """A reviewer that is never satisfied must not loop until the batch cap has
    swallowed the plan."""
    llm = _ScriptedLLM(_REVISION)
    planner = AttackPlanner(llm, known_personas=["anonymous"])
    repo, orch = _setup(planner=planner)
    aid = asyncio.run(orch.import_and_analyze("CRM-9001"))
    _tests, review = orch.agent_plan(aid, max_rounds=2)
    assert review.rounds <= 2


def test_a_planning_failure_leaves_a_normal_analyzed_assessment():
    """The import succeeded and is on the record. A designer/planner/reviewer
    failure must not lose it or land the tester on an error page."""
    class _Exploding(PlanReviewer):
        def review(self, *args, **kwargs):
            raise RuntimeError("reviewer exploded")

    repo, orch = _setup(reviewer=_Exploding(None))
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))
    assert review is None
    assert repo.get_assessment(aid) is not None
    assert orch.get_analysis(aid).endpoints
    assert any(a.action == "agent_plan_failed" for a in repo.get_audit(aid))


def test_a_broken_reviewer_llm_still_produces_the_structural_review():
    repo, orch = _setup(reviewer=PlanReviewer(_BrokenLLM()))
    aid, review = asyncio.run(orch.import_and_plan("CRM-9001"))
    assert review.reviewer == "deterministic"
    assert "no key" in review.degraded_reason


def test_a_re_run_carries_the_review_that_the_approvals_were_given_against():
    repo, orch = _setup()
    aid, _review = asyncio.run(orch.import_and_plan("CRM-9001"))
    new_id = orch.clone_for_rerun(aid)
    assert repo.get_plan_review(new_id) is not None
    # The run assessment deliberately does not come along: it describes
    # executions the new assessment has not performed.
    assert repo.get_run_assessment(new_id) is None


# -- reviewing the results -----------------------------------------------------


def _client():
    c = TestClient(vulnerable_app, base_url="http://demo-target.local")
    c.follow_redirects = False
    return c


def _execute(orch, aid):
    # The resolver is stubbed for the same reason every other integration test
    # here stubs it: without it "demo-target.local" does not resolve, every
    # request comes back BLOCKED, and a test that asserts something about
    # verdicts would be asserting it about a run that never sent anything.
    scope = ScopeValidator(ScopePolicy(allowed_hosts={"demo-target.local"}),
                           resolver=lambda host: "203.0.113.5")
    return orch.execute(aid, "http://demo-target.local", scope, build_vault(),
                        Settings.from_env(), client=_client())


def _run_a_real_assessment():
    repo, orch = _setup(jira=MockJiraMCPClient())
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tests = orch.design(aid)
    orch.approve(aid, [t.test_id for t in tests if not t.is_destructive])
    _execute(orch, aid)
    return repo, orch, aid


def test_reviewing_results_answers_pass_fail_and_coverage():
    repo, orch, aid = _run_a_real_assessment()
    run = orch.adjudicate(aid)

    assert run.overall in ("PASSED", "FAILED", "INCOMPLETE")
    assert 0 <= run.coverage_pct <= 100
    assert 0 <= run.decided_pct <= 100
    assert run.n_executions == len(orch.latest_executions(aid))
    assert repo.get_run_assessment(aid) is not None


def test_reviewing_results_changes_no_verdict_no_finding_and_no_hash():
    """The line the whole design rests on. An adjudication is stored beside the
    evidence, never inside it."""
    repo, orch, aid = _run_a_real_assessment()
    before_executions = repo.get_executions(aid)
    before = [(e.execution_id, e.verdict.result, e.evidence_hash)
              for e in before_executions]
    before_findings = [f.finding_id for f in repo.get_findings(aid)]

    orch.adjudicate(aid)

    after_executions = repo.get_executions(aid)
    after = [(e.execution_id, e.verdict.result, e.evidence_hash)
             for e in after_executions]
    assert after == before
    assert [f.finding_id for f in repo.get_findings(aid)] == before_findings
    assert verify_chain(after_executions)


def test_a_decided_result_is_not_sent_to_an_agent_at_all():
    repo, orch, aid = _run_a_real_assessment()
    run = orch.adjudicate(aid)
    sealed = {e.execution_id: e.verdict.result for e in orch.latest_executions(aid)}
    for adjudication in run.adjudications:
        assert sealed[adjudication.execution_id] not in (TestStatus.PASS, TestStatus.FAIL)


def test_triage_is_available_without_asking_for_a_review():
    """It needs no key and costs nothing, so the page can say what needs a person
    before anyone spends a token."""
    repo, orch, aid = _run_a_real_assessment()
    triaged = orch.triage_results(aid)
    assert triaged
    assert all(klass in ("decided", "manual", "agent", "rerun")
               for _execution, klass, _reason in triaged)


def test_the_run_assessment_reaches_the_report_and_the_jira_comment():
    repo, orch, aid = _run_a_real_assessment()
    run = orch.adjudicate(aid)

    html = orch.build_report_html(aid)
    assert "Assessment of this run" in html
    assert f"{run.coverage_pct}%" in html

    comment = orch.comment_preview(aid)
    assert run.overall in comment
    assert "Ticket requirements covered" in comment
    # The comment stays a summary: no per-test explanation came back with it.
    assert "Expected of a secure system" not in comment


def test_adjudicating_an_assessment_with_no_analysis_is_refused_clearly():
    repo, orch = _setup()
    repo.create_assessment("A-empty", "CRM-1", "CRM")
    try:
        orch.adjudicate("A-empty")
    except ValueError as exc:
        assert "no analysis" in str(exc)
    else:  # pragma: no cover - the call must not succeed
        raise AssertionError("adjudicating without an analysis should be refused")


def test_the_json_export_carries_both_agent_artefacts_beside_the_evidence():
    """Under their own keys, never merged into an execution: an adjudication is an
    unhashed, model-derived opinion, and putting it inside the object whose hash
    makes it tamper-evident would undermine both."""
    import json

    repo, orch, aid = _run_a_real_assessment()
    orch.agent_plan(aid)
    orch.adjudicate(aid)
    payload = json.loads(orch.export_json(aid))

    assert payload["plan_review"]["verdict"]
    assert payload["run_assessment"]["overall"]
    for execution in payload["executions"]:
        assert "assessed_result" not in execution
        assert "adjudication" not in execution


class _CountingAdjudicator:
    """Counts the results that would actually have cost an API call.

    Only reading tasks reach the model — the real adjudicator returns a
    triage-only answer for the rest without calling anything — so the fake
    re-triages to count the same population the cap governs. Counting every
    `adjudicate()` call instead would make the cap look broken for doing exactly
    what it is supposed to do.
    """

    def __init__(self) -> None:
        self.model_calls = 0

    @property
    def ai_enabled(self) -> bool:
        return True

    def adjudicate(self, analysis, test, execution):
        from app.analysis.adjudicator import triage as _triage
        from app.schemas.agent import Adjudication

        klass, reason = _triage(test, execution)
        if klass == "agent":
            self.model_calls += 1
            return Adjudication(
                execution_id=execution.execution_id, test_id=execution.test_id,
                sealed_result=execution.verdict.result, needs_manual_review=False,
                assessed_result="PASS", adjudicator="ai", rationale="read it",
                triage_reason=reason,
            )
        return Adjudication(
            execution_id=execution.execution_id, test_id=execution.test_id,
            sealed_result=execution.verdict.result,
            needs_manual_review=klass == "manual", triage_reason=reason,
        )


def _reading_task(test_id: str, execution_id: str):
    """An execution that triage classes as a reading task: accepted attack, body."""
    from app.schemas.enums import Confidence
    from app.schemas.execution import (
        CapturedRequest,
        CapturedResponse,
        Execution,
        Verdict,
    )

    body = '{"id": 2002, "owner": "agent_B", "email": "beth@example.com"}'
    return Execution(
        execution_id=execution_id, test_id=test_id, owasp_category="API1:2023",
        scope_validated=True,
        request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                resolved_ip="203.0.113.5",
                                headers={"Authorization": "********"}, timestamp="t"),
        response=CapturedResponse(status_code=200, headers={}, body=body,
                                  elapsed_ms=9, size_bytes=len(body)),
        verdict=Verdict(result=TestStatus.INCONCLUSIVE, confidence=Confidence.MEDIUM,
                        expected_summary="status in [403, 404]",
                        actual_summary="HTTP 200 (expected a rejection)",
                        reason="no protected marker was available to confirm disclosure"),
    )


def test_a_review_pass_is_capped_and_says_what_it_did_not_read():
    """One click must not become dozens of API calls, and an unread result must
    not be indistinguishable from one that was read and found unclear."""
    adjudicator = _CountingAdjudicator()
    repo, orch = _setup(jira=MockJiraMCPClient(), adjudicator=adjudicator)
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tests = orch.design(aid)

    # Three undecided results that are all reading tasks — the population the cap
    # governs. Built directly rather than run: the demo target answers decisively,
    # so a real run produces no reading task to cap.
    ids = [t.test_id for t in tests][:3]
    assert len(ids) == 3
    repo.save_executions(aid, [_reading_task(tid, f"E-{i}") for i, tid in enumerate(ids)])

    run = orch.adjudicate(aid, max_ai_calls=1)

    assert adjudicator.model_calls == 1
    unread = [a for a in run.adjudications if "reached its cap" in a.degraded_reason]
    assert len(unread) == 2
    for adjudication in unread:
        # Reported as needing a person, with the reason, rather than as a reading.
        assert adjudication.needs_manual_review is True
        assert adjudication.assessed_result == "INCONCLUSIVE"
    assert any(a.action == "adjudicate_capped" for a in repo.get_audit(aid))
    # And the run-level answer counts them as work outstanding, not as settled.
    assert run.n_manual_review >= 2
    assert run.overall == "INCOMPLETE"
