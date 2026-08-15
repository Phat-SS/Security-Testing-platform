"""End-to-end orchestrator test — the full vertical slice through persistence.

Offline: in-memory SQLite, mock Jira MCP, Starlette TestClient driving the
bundled vulnerable app. No network, no API key.
"""

import asyncio

from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.schemas.enums import TestStatus
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


def test_audit_trail_recorded():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-1234"))
    orch.design(aid)
    actions = {a.action for a in repo.get_audit(aid)}
    assert {"import_issue", "analyze", "design_tests"} <= actions


def orch_tests(repo, aid):
    return repo.get_test_cases(aid)
