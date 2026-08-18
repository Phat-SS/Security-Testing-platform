"""Orchestrator integration for the two AI paths.

The planner and the adaptive loop have unit tests for their constraints; these
cover the wiring — that a proposal reaches persistence, that a follow-up's
execution is not orphaned from its test case, and that both degrade to the
original behaviour when no planner is configured.
"""

import asyncio

from starlette.testclient import TestClient

from app.analysis.attack_planner import AttackPlanner, PlanResult
from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.execution.adaptive import AdaptiveBudget
from app.execution.evidence import verify_chain
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.schemas.enums import ApprovalStatus, TestSource
from demo.sample_tests import build_vault
from demo.vulnerable_api import app as vulnerable_app


class _ScriptedLLM:
    def __init__(self, reply: str) -> None:
        self.reply = reply

    def complete(self, system: str, user: str) -> str:
        return self.reply


# The path is deliberately one the deterministic designer never produces.
# MockJiraMCPClient stores posted comments on the issue itself and the analyzer
# reads comments, so a previous test's Jira comment can introduce new endpoints
# into this issue's analysis. A proposal on a plausible path would then collide
# with a rule-engine test and be correctly rejected as a duplicate — making this
# test fail for a reason that has nothing to do with what it checks.
_PROPOSAL = """{"tests": [{
  "title": "Unauthenticated read of the audit trail",
  "owasp_category": "API2:2023",
  "persona": "anonymous",
  "method": "GET",
  "path": "/internal/ai-proposed-audit-trail",
  "mutation_kind": "drop_auth",
  "expected_status_in": [401]
}]}"""


def _setup(planner=None):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    return repo, Orchestrator(repo, MockJiraMCPClient(), planner=planner)


def _client():
    c = TestClient(vulnerable_app, base_url="http://demo-target.local")
    c.follow_redirects = False
    return c


def _scope():
    return ScopeValidator(ScopePolicy(allowed_hosts={"demo-target.local"}),
                          resolver=lambda h: "203.0.113.5")


# -- planner wiring ------------------------------------------------------------


def test_planner_output_is_persisted_as_pending_ai_tests():
    planner = AttackPlanner(_ScriptedLLM(_PROPOSAL),
                            known_personas=["agent_A", "agent_B", "anonymous"])
    repo, orch = _setup(planner)
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)

    stored = repo.get_test_cases(aid)
    ai_tests = [t for t in stored if t.source == TestSource.AI]
    assert ai_tests, "planner proposal never reached persistence"
    assert all(t.approval_status == ApprovalStatus.PENDING for t in ai_tests)


def test_a_planner_that_proposes_nothing_usable_does_not_break_design():
    planner = AttackPlanner(_ScriptedLLM("not json at all"), known_personas=["agent_A"])
    repo, orch = _setup(planner)
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    tests = orch.design(aid)
    assert tests  # the deterministic backbone is unaffected


def test_use_planner_false_skips_it_entirely():
    planner = AttackPlanner(_ScriptedLLM(_PROPOSAL), known_personas=["anonymous"])
    repo, orch = _setup(planner)
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, use_planner=False)
    assert not [t for t in repo.get_test_cases(aid) if t.source == TestSource.AI]


# -- adaptive wiring -----------------------------------------------------------


class _FollowUpPlanner:
    """Proposes one valid follow-up the first time it is asked, then nothing."""

    def __init__(self) -> None:
        self._inner = AttackPlanner(_ScriptedLLM(_PROPOSAL),
                                    known_personas=["agent_A", "agent_B", "anonymous"])
        self.calls = 0

    def plan(self, analysis, existing=None):
        return PlanResult()

    def follow_up(self, analysis, test, execution, id_prefix="AI"):
        self.calls += 1
        if self.calls > 1:
            return PlanResult()
        return self._inner.follow_up(analysis, test, execution, id_prefix=id_prefix)


def _approve_and_run(orch, repo, aid, adaptive):
    orch.approve(aid, [t.test_id for t in repo.get_test_cases(aid)])
    return orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                        Settings.from_env(), client=_client(), adaptive=adaptive)


def test_adaptive_followups_are_persisted_so_executions_are_not_orphaned():
    """An execution whose test_id resolves to no stored test is invisible to
    finding construction and renders as a blank report row."""
    repo, orch = _setup(_FollowUpPlanner())
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    executions = _approve_and_run(orch, repo, aid, AdaptiveBudget(max_iterations=2))

    stored_ids = {t.test_id for t in repo.get_test_cases(aid)}
    assert executions
    for execution in executions:
        assert execution.test_id in stored_ids, f"{execution.test_id} has no stored test case"


def test_adaptive_execution_keeps_one_unbroken_evidence_chain():
    repo, orch = _setup(_FollowUpPlanner())
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    _approve_and_run(orch, repo, aid, AdaptiveBudget(max_iterations=2))

    assert verify_chain(repo.get_executions(aid)) is True


def test_requesting_adaptive_without_a_planner_falls_back_and_says_so():
    repo, orch = _setup(planner=None)
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    executions = _approve_and_run(orch, repo, aid, AdaptiveBudget())

    # The approved tests still ran; only the adaptive layer was unavailable.
    assert executions
    assert verify_chain(repo.get_executions(aid)) is True
