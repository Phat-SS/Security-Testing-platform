"""End-to-end orchestrator test — the full vertical slice through persistence.

Offline: in-memory SQLite, mock Jira MCP, Starlette TestClient driving the
bundled vulnerable app. No network, no API key.
"""

import asyncio

from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.execution.evidence import verify_chain
from app.mcp.jira import NormalizedIssue
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
from app.schemas.enums import ApprovalStatus, TestStatus
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
    orch = Orchestrator(repo, MockJiraMCPClient())
    return repo, orch


def _client():
    c = TestClient(vulnerable_app, base_url="http://demo-target.local")
    c.follow_redirects = False
    return c


def _scope():
    policy = ScopePolicy(allowed_hosts={"demo-target.local"})
    return ScopeValidator(policy, resolver=lambda h: "203.0.113.5")


def test_full_pipeline_detects_bola_and_reports():
    repo, orch = _setup()

    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    assert repo.get_assessment(aid).status == "ANALYZED"

    tests = orch.design(aid, poc_python=POC)
    assert tests
    # PoC-sourced test present
    assert any(t.source.value == "poc" for t in tests)

    # approve everything; execute() still excludes destructive by default
    orch.approve(aid, [t.test_id for t in orch_tests(repo, aid)])

    executions = orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                              Settings.from_env(), client=_client())
    assert executions
    results = {e.verdict.result for e in executions}
    assert TestStatus.FAIL in results  # BOLA detected

    findings = repo.get_findings(aid)
    assert any("Broken Object Level Authorization" in f.title for f in findings)

    html = orch.build_report_html(aid)
    assert "OWASP API Security Coverage" in html
    assert "Broken Object Level Authorization" in html

    preview = orch.comment_preview(aid)
    assert "CRM-1234" in preview

    posted = asyncio.run(orch.post_comment(aid))
    assert "CRM-1234" in posted


def test_destructive_tests_excluded_by_default():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    orch.approve(aid, [t.test_id for t in orch_tests(repo, aid)])

    executions = orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                              Settings.from_env(), client=_client())
    executed_ids = {e.test_id for e in executions}
    # every executed test must be non-destructive
    by_id = {t.test_id: t for t in orch_tests(repo, aid)}
    assert all(not by_id[tid].is_destructive for tid in executed_ids)


def test_evidence_chain_spans_multiple_execute_runs():
    """Re-running execute() on the same assessment must continue the same
    hash chain, not start a fresh None-rooted one — otherwise deleting or
    rewriting an earlier run's rows would verify fine as an "innocent" new
    chain, hiding exactly the tampering the chain exists to catch."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)
    orch.approve(aid, [t.test_id for t in orch_tests(repo, aid)])

    first = orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                         Settings.from_env(), client=_client())
    second = orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                          Settings.from_env(), client=_client())

    assert second[0].prev_hash == first[-1].evidence_hash
    all_executions = repo.get_executions(aid)
    assert len(all_executions) == len(first) + len(second)
    assert verify_chain(all_executions)


def test_report_shows_evidence_chain_verified_banner():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)
    orch.approve(aid, [t.test_id for t in orch_tests(repo, aid)])
    orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                Settings.from_env(), client=_client())
    assert "Evidence chain verified" in orch.build_report_html(aid)


def test_one_bad_test_does_not_abort_the_whole_execution_batch():
    """A test referencing a persona missing from the vault must come back as
    an ERROR execution, not raise and discard every execution already
    computed earlier in the same batch — KeyError from PersonaVault.get()
    used to propagate straight out of HttpRunner.run(), aborting
    Orchestrator.execute() before save_executions() ever ran."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid, poc_python=POC)

    bad_test = TestCase(
        test_id="BAD-001",
        title="References a persona that does not exist",
        objective="Regression: a bad test must not abort the whole batch.",
        owasp_category=OwaspApiCategory.API1,
        severity=Severity.LOW,
        auth_context=AuthContext(persona="ghost"),
        request=RequestSpec(method="GET", path="/customers/1001"),
        attack_mutation=Mutation(kind="escalate_persona"),
        expected=ExpectedResult(status_in=[200]),
        source=TestSource.MANUAL,
        approval_status=ApprovalStatus.APPROVED,
    )
    repo.save_test_cases(aid, [bad_test])
    orch.approve(aid, [t.test_id for t in orch_tests(repo, aid)])

    executions = orch.execute(aid, "http://demo-target.local", _scope(), build_vault(),
                              Settings.from_env(), client=_client())

    by_id = {e.test_id: e for e in executions}
    assert by_id["BAD-001"].verdict.result == TestStatus.ERROR
    # the good tests in the same batch still ran and produced real verdicts
    assert any(tid != "BAD-001" for tid in by_id)


def test_editing_a_test_to_a_destructive_method_flags_it_destructive():
    """A test designed as a safe GET must not stay is_destructive=False after
    being edited to send DELETE — otherwise it would run under the default
    "Run approved tests" path (non-destructive only), completely bypassing
    the destructive-action confirmation gate."""
    from app.schemas import RequestSpec

    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    safe_test = next(t for t in orch_tests(repo, aid) if not t.is_destructive)
    assert safe_test.request.method != "DELETE"

    edited = RequestSpec(method="DELETE", path=safe_test.request.path)
    ok = orch.edit_test_request(aid, safe_test.test_id, edited)
    assert ok

    updated = repo.get_test_case(aid, safe_test.test_id)
    assert updated.request.method == "DELETE"
    assert updated.is_destructive is True


def test_audit_trail_recorded():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    actions = {a.action for a in repo.get_audit(aid)}
    assert {"import_issue", "analyze", "design_tests"} <= actions


class _FakeJiraWithEmbeddedPoc:
    """A minimal Jira client whose issue description embeds a PoC script the
    way an automated bounty-hunter tool files it: a filename line followed by
    a fenced ```python block."""

    async def get_issue(self, issue_key: str) -> NormalizedIssue:
        return NormalizedIssue(
            issue_key=issue_key,
            project_key=issue_key.split("-", 1)[0],
            summary="Auto-extract test",
            description='''
PoC scripts:

01_test.py

```python
import requests
BASE = "https://api-staging.company.com"
requests.get(BASE + "/customers/2002")
```
''',
        )


def test_embedded_poc_in_description_is_detected_not_auto_designed():
    """A PoC found in the Jira description is surfaced for human review (via
    IssueAnalysis.detected_poc_source, pre-filled into the Design step's
    textarea) but never transpiled/turned into test cases until a human
    submits the design form themselves."""
    repo, _ = _setup()
    orch = Orchestrator(repo, _FakeJiraWithEmbeddedPoc())

    aid = asyncio.run(orch.import_and_analyze("AUTO-1"))

    tests = orch_tests(repo, aid)
    assert not tests, "a detected PoC must not be auto-transpiled into test cases"

    assessment = repo.get_assessment(aid)
    assert "requests.get" in assessment.analysis_json["detected_poc_source"]

    actions = {a.action for a in repo.get_audit(aid)}
    assert "poc_detected" in actions
    assert "poc_auto_extracted" not in actions
    assert "design_tests" not in actions

    # The human now reviews and confirms via the normal design() call, using
    # the surfaced source — same path as pasting it in by hand.
    designed = orch.design(aid, poc_python=assessment.analysis_json["detected_poc_source"])
    assert any(t.source.value == "poc" for t in designed)


def orch_tests(repo, aid):
    return repo.get_test_cases(aid)


class _ScriptedLLM:
    """Would-be AttackPlanner input — used only to prove it never gets asked."""

    def __init__(self, reply: str) -> None:
        self.reply = reply

    def complete(self, system: str, user: str) -> str:
        return self.reply


_AI_PROPOSAL = """{"tests": [{
  "title": "AI-invented probe that ticket_poc mode must never run",
  "owasp_category": "API2:2023",
  "persona": "anonymous",
  "method": "GET",
  "path": "/internal/ai-invented-probe",
  "mutation_kind": "drop_auth",
  "expected_status_in": [401]
}]}"""


def test_ticket_poc_mode_runs_only_the_embedded_poc():
    """Option 1: the ticket's own PoC becomes the whole plan. The AI planner is
    attached (so it *could* add tests) but must never be asked to, and the plan
    reviewer must still run — read-only, no revision round."""
    from app.analysis.attack_planner import AttackPlanner

    repo, _ = _setup()
    planner = AttackPlanner(_ScriptedLLM(_AI_PROPOSAL), known_personas=["anonymous"])
    orch = Orchestrator(repo, _FakeJiraWithEmbeddedPoc(), planner=planner)

    aid, review, poc_found = asyncio.run(orch.import_and_run_poc_plan("AUTO-2"))
    assert poc_found is True

    tests = orch_tests(repo, aid)
    assert tests, "the ticket's embedded PoC should have produced at least one test"
    assert all(t.source.value == "poc" for t in tests), \
        "ticket_poc mode must not mix in AI-planner or rule-engine tests"
    assert not any(t.request.path == "/internal/ai-invented-probe" for t in tests), \
        "the AI planner must never be asked to add tests in this mode"

    # The host embedded in the PoC script must never survive into the test's
    # own request — execution always targets the tool's configured base URL.
    assert not any("api-staging.company.com" in t.request.path for t in tests)

    # Sent verbatim — no classify()-guessed mutation on top of the PoC's own
    # request, and no {victim_id}-style path rewrite nothing then resolves.
    assert all(t.attack_mutation.kind == "verbatim_replay" for t in tests)
    assert not any("{" in t.request.path for t in tests)

    assert review is not None, "the plan reviewer must still run, read-only"
    assert review.rounds == 0, "no revision round: the AI planner must not answer gaps"


class _FakeJiraDescriptiveTicketWithEmbeddedPoc:
    """A ticket that reads like a real BH-xxx one: prose describing an
    endpoint (which the heuristic extractor/rule engine can act on) *and* a
    PoC embedded as a fenced code block. Exercises the case
    `_FakeJiraWithEmbeddedPoc` above cannot: its description has no
    endpoint-describing prose at all, so the rule engine never had anything
    to generate tests from regardless of whether ticket_poc mode suppressed
    it — a rule-engine leak would have passed silently against that fixture."""

    async def get_issue(self, issue_key: str) -> NormalizedIssue:
        return NormalizedIssue(
            issue_key=issue_key,
            project_key=issue_key.split("-", 1)[0],
            summary="Report intake",
            description='''
GET /reports/{reportId} returns a submitted report. Bearer JWT required.

PoC scripts:

01_test.py

```python
import requests
BASE = "https://api-staging.company.com"
requests.get(BASE + "/reports/2002")
```
''',
        )


def test_ticket_poc_mode_does_not_leak_rule_engine_tests_for_endpoints_the_ticket_describes():
    """A ticket whose prose describes an endpoint (so the rule engine would
    normally generate BOLA/broken-auth tests for it) must still end up with
    only the PoC's own test in ticket_poc mode — not the PoC test plus a full
    rule-engine sweep of every endpoint the ticket happens to mention."""
    repo, _ = _setup()
    orch = Orchestrator(repo, _FakeJiraDescriptiveTicketWithEmbeddedPoc())

    aid, _review, poc_found = asyncio.run(orch.import_and_run_poc_plan("AUTO-3"))
    assert poc_found is True

    tests = orch_tests(repo, aid)
    assert tests, "the embedded PoC should have produced a test"
    assert all(t.source.value == "poc" for t in tests), \
        f"expected only PoC-sourced tests, got sources: {[t.source.value for t in tests]}"
    # /reports/2002 is exactly the id-shaped path classify() would otherwise
    # parameterise to /reports/{victim_id} for a swap_object_id mutation —
    # verbatim mode must keep the literal id since nothing resolves it back.
    assert all(t.request.path == "/reports/2002" for t in tests)
    assert all(t.attack_mutation.kind == "verbatim_replay" for t in tests)


def test_ticket_poc_mode_with_no_embedded_poc_is_reported_not_silently_skipped():
    repo, _ = _setup()
    orch = Orchestrator(repo, MockJiraMCPClient())

    aid, review, poc_found = asyncio.run(orch.import_and_run_poc_plan("CRM-1234"))
    assert poc_found is False
    assert review is None
    assert not orch_tests(repo, aid)

    actions = {a.action for a in repo.get_audit(aid)}
    assert "ticket_poc_missing" in actions
    assert "design_tests" not in actions


# -- Phase (AI memory): prior-run digest for the same ticket ------------------


def _finding(finding_id="SEC-001", title="BOLA"):
    from app.schemas.finding import CorrelationEvidence, Finding

    return Finding(
        finding_id=finding_id, title=title, owasp_category=OwaspApiCategory.API1,
        severity=Severity.HIGH, confidence="HIGH", endpoint="GET /x",
        dedup_key=f"API1:2023|GET /x|{title}",
        correlation=CorrelationEvidence(baseline_summary="b", attack_summary="a",
                                        expected="e", actual="a"),
        impact="impact", recommendation="fix it",
    )


def test_prior_run_digest_is_empty_with_no_earlier_run():
    repo, orch = _setup()
    repo.create_assessment("A-1", "CRM-9", "CRM")
    assert orch._prior_run_digest("CRM-9", "A-1") == ""


def test_prior_run_digest_reports_ruled_out_and_still_open():
    repo, orch = _setup()
    repo.create_assessment("A-1", "CRM-9", "CRM")
    repo.replace_findings("A-1", [_finding("SEC-001", "BOLA"), _finding("SEC-002", "Broken auth")])
    repo.save_executions("A-1", [])  # marks A-1 EXECUTED
    repo.set_finding_triage("A-1", "SEC-001", "k", "false_positive", note="shared account")
    repo.create_assessment("A-2", "CRM-9", "CRM")

    digest = orch._prior_run_digest("CRM-9", "A-2")

    assert "RULED OUT (false positive)" in digest
    assert "shared account" in digest
    assert "BOLA" in digest
    assert "previously confirmed, still open" in digest
    assert "Broken auth" in digest


def test_prior_run_digest_ignores_a_non_executed_assessment():
    repo, orch = _setup()
    repo.create_assessment("A-1", "CRM-9", "CRM")
    repo.replace_findings("A-1", [_finding()])  # never executed — status stays CREATED
    repo.create_assessment("A-2", "CRM-9", "CRM")

    assert orch._prior_run_digest("CRM-9", "A-2") == ""
