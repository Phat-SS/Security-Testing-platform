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
