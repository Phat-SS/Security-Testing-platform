"""Regenerating a plan and re-running an assessment must not duplicate rows.

Both operations are ordinary things a tester does — regenerate after editing the
endpoint list, re-run after fixing a persona — and both used to corrupt state
silently:

  * `save_test_cases` appended, and test ids are deterministic ("API1-001"), so a
    second design created two rows per id. Every lookup below it uses
    `.one_or_none()` (set_approval, get_test_case, update_test_request), so the
    whole approval flow raised MultipleResultsFound afterwards.
  * `save_findings` appended, and `build_findings` numbers findings SEC-001..
    from scratch each time, so a second run produced a second SEC-001 and every
    report/export/Jira comment counted the same finding twice.
"""

import asyncio

from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.schemas import (
    AuthContext,
    ExpectedResult,
    Mutation,
    OwaspApiCategory,
    RequestSpec,
    Severity,
    TestCase,
    TestSource,
)
from app.schemas.enums import ApprovalStatus
from demo.sample_tests import build_vault
from demo.vulnerable_api import app as vulnerable_app

POC = '''
import requests
BASE = "https://api-staging.company.com"
requests.get(BASE + "/customers/2002", headers={"Authorization": "Bearer tokenA"})
'''


def _setup():
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    return repo, Orchestrator(repo, MockJiraMCPClient())


def _client():
    c = TestClient(vulnerable_app, base_url="http://demo-target.local")
    c.follow_redirects = False
    return c


def _scope():
    return ScopeValidator(ScopePolicy(allowed_hosts={"demo-target.local"}),
                          resolver=lambda h: "203.0.113.5")


def _test_case(test_id: str, path: str = "/customers/{victim_id}") -> TestCase:
    return TestCase(
        test_id=test_id,
        title="probe",
        objective="probe",
        owasp_category=OwaspApiCategory.API1,
        severity=Severity.HIGH,
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path=path),
        attack_mutation=Mutation(kind="swap_object_id"),
        expected=ExpectedResult(status_in=[403]),
        source=TestSource.RULE_ENGINE,
        approval_status=ApprovalStatus.PENDING,
    )


# -- designing twice --------------------------------------------------------


def test_designing_twice_replaces_the_plan_instead_of_duplicating_it():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))

    first = orch.design(aid, poc_python=POC)
    second = orch.design(aid, poc_python=POC)

    stored = repo.get_test_cases(aid)
    ids = [t.test_id for t in stored]
    assert len(ids) == len(set(ids)), f"duplicate test ids after re-design: {ids}"
    assert len(stored) == len(second) == len(first)


def test_approval_flow_still_works_after_a_re_design():
    """The regression that mattered: a duplicated test_id made every
    `.one_or_none()` lookup raise, so approving anything at all failed."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    orch.design(aid)

    target = repo.get_test_cases(aid)[0].test_id
    orch.approve(aid, [target])  # used to raise MultipleResultsFound

    assert repo.get_test_case(aid, target).approval_status == ApprovalStatus.APPROVED


def test_re_design_keeps_an_approval_given_to_an_unchanged_test():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    approved = [t.test_id for t in repo.get_test_cases(aid)][:3]
    orch.approve(aid, approved)

    orch.design(aid)  # same inputs → identical tests

    still = {t.test_id for t in repo.get_test_cases(aid)
             if t.approval_status == ApprovalStatus.APPROVED}
    assert set(approved) <= still, "re-designing threw away a decision a human made"


def test_re_design_resets_the_approval_of_a_test_whose_content_changed():
    """An approval means "I read what this test does". If what it does changed,
    the decision no longer applies — carrying it over would run something
    nobody reviewed."""
    repo, _orch = _setup()
    repo.create_assessment("A-1", "CRM-1234", "CRM")

    repo.replace_test_cases("A-1", [_test_case("API1-001")])
    repo.set_approval("A-1", "API1-001", "APPROVED")

    # same id, different request → not the test that was approved
    repo.replace_test_cases("A-1", [_test_case("API1-001", path="/orders/{victim_id}")])

    assert repo.get_test_case("A-1", "API1-001").approval_status == ApprovalStatus.PENDING


def test_replace_test_cases_drops_tests_that_are_no_longer_generated():
    repo, _orch = _setup()
    repo.create_assessment("A-1", "CRM-1234", "CRM")
    repo.replace_test_cases("A-1", [_test_case("API1-001"), _test_case("API1-002")])

    repo.replace_test_cases("A-1", [_test_case("API1-001")])

    assert [t.test_id for t in repo.get_test_cases("A-1")] == ["API1-001"]


# -- running twice ----------------------------------------------------------


def _run(orch, aid):
    return orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                        Settings.from_env(), client=_client())


def test_re_running_does_not_duplicate_findings():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)
    orch.approve(aid, [t.test_id for t in repo.get_test_cases(aid)])

    _run(orch, aid)
    first = repo.get_findings(aid)
    _run(orch, aid)
    second = repo.get_findings(aid)

    assert first, "expected the demo target to fail at least one control"
    ids = [f.finding_id for f in second]
    assert len(ids) == len(set(ids)), f"duplicate finding ids after a re-run: {ids}"
    # Same target, same tests → same conclusions, not twice as many.
    assert {f.dedup_key for f in second} == {f.dedup_key for f in first}


def test_re_running_mints_fresh_execution_ids():
    """execution_id is hashed into the evidence chain, so two runs reusing one id
    make two distinct runs indistinguishable in the evidence."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)
    orch.approve(aid, [t.test_id for t in repo.get_test_cases(aid)])

    _run(orch, aid)
    _run(orch, aid)

    ids = [e.execution_id for e in repo.get_executions(aid)]
    assert len(ids) == len(set(ids)), f"reused execution ids across runs: {ids}"


def test_first_run_keeps_the_original_execution_id_format():
    """The tag is only added from the second round on: changing round one's ids
    would change their evidence hashes and invalidate every stored chain."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)
    orch.approve(aid, [t.test_id for t in repo.get_test_cases(aid)])

    executions = _run(orch, aid)

    for e in executions:
        assert e.execution_id == f"{aid}-{e.test_id}"


def test_findings_reflect_every_execution_not_just_the_last_run():
    """Findings are recomputed over the whole history, so a control that broke in
    round one stays reported even if round two never exercised it."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)
    all_ids = [t.test_id for t in repo.get_test_cases(aid)]
    orch.approve(aid, all_ids)
    _run(orch, aid)
    round_one = {f.dedup_key for f in repo.get_findings(aid)}
    assert round_one

    # Narrow the plan to a single test and run again.
    orch.reject(aid, all_ids[1:])
    _run(orch, aid)

    assert round_one <= {f.dedup_key for f in repo.get_findings(aid)}
