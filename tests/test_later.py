"""Tests for the 'Later' roadmap: Burp/JMeter import, Postman/Newman export,
historical diff, PDF export, and multi-user auth."""

import json

from app.adapters.burp import parse_raw_http, transpile_burp
from app.adapters.jmeter import transpile_jmeter
from app.adapters.postman_export import export_postman_collection
from app.core.auth import AuthManager, User, hash_key
from app.pipeline.history import diff_findings, render_diff_comment
from app.schemas.enums import Confidence, OwaspApiCategory, Severity
from app.schemas.finding import CorrelationEvidence, Finding

# -- Burp -------------------------------------------------------------------

BURP_XML = """<items>
  <item>
    <host>api-staging.company.com</host>
    <protocol>https</protocol>
    <request base64="false">GET /customers/2002 HTTP/1.1
Host: api-staging.company.com
Authorization: Bearer tokenA

</request>
  </item>
</items>"""


def test_burp_parses_raw_request():
    req = parse_raw_http("POST /x HTTP/1.1\nHost: h.com\nContent-Type: application/json\n\n{\"a\":1}")
    assert req.method == "POST"
    assert req.path == "/x"
    assert req.headers["Content-Type"] == "application/json"
    assert req.body == '{"a":1}'


def test_burp_xml_import():
    result = transpile_burp(BURP_XML)
    assert len(result.requests) == 1
    assert result.requests[0].method == "GET"
    assert result.requests[0].path == "/customers/2002"


# -- JMeter -----------------------------------------------------------------

JMX = """<jmeterTestPlan>
 <hashTree>
  <HTTPSamplerProxy>
    <stringProp name="HTTPSampler.domain">api-staging.company.com</stringProp>
    <stringProp name="HTTPSampler.protocol">https</stringProp>
    <stringProp name="HTTPSampler.path">/customers/2002</stringProp>
    <stringProp name="HTTPSampler.method">DELETE</stringProp>
  </HTTPSamplerProxy>
 </hashTree>
</jmeterTestPlan>"""


def test_jmeter_import():
    result = transpile_jmeter(JMX)
    assert len(result.requests) == 1
    assert result.requests[0].method == "DELETE"
    assert result.requests[0].path == "/customers/2002"


# -- Postman export (Newman) ------------------------------------------------

def _sample_tests():
    from app.analysis import HeuristicAnalyzer, TestDesigner
    from app.mcp.jira import NormalizedIssue

    issue = NormalizedIssue(issue_key="CRM-1", project_key="CRM",
                            summary="GET /customers/{customerId}. Bearer JWT.")
    return TestDesigner().design(HeuristicAnalyzer().analyze(issue))


def test_postman_export_uses_variables_not_secrets():
    coll = json.loads(export_postman_collection("CRM tests", _sample_tests()))
    assert coll["info"]["schema"].endswith("collection.json")
    assert coll["item"]
    raw = json.dumps(coll)
    # host + token are variables, never literal secrets
    assert "{{baseUrl}}" in raw
    assert "{{token_agent_A}}" in raw
    assert "tokenA" not in raw
    # assertions embedded for Newman
    assert any(item.get("event") for item in coll["item"])


# -- Historical diff --------------------------------------------------------

def _finding(fid, key):
    return Finding(
        finding_id=fid, title="BOLA", owasp_category=OwaspApiCategory.API1,
        severity=Severity.HIGH, confidence=Confidence.HIGH, endpoint="GET /x",
        dedup_key=key,
        correlation=CorrelationEvidence(baseline_summary="", attack_summary="",
                                        expected="", actual=""),
        impact="", recommendation="",
    )


def test_diff_new_fixed_persisting():
    prev = [_finding("SEC-001", "k1"), _finding("SEC-002", "k2")]
    curr = [_finding("SEC-001", "k2"), _finding("SEC-002", "k3")]  # k2 persists, k3 new, k1 fixed
    diff = diff_findings(prev, curr)
    assert {f.dedup_key for f in diff.new} == {"k3"}
    assert {f.dedup_key for f in diff.fixed} == {"k1"}
    assert {f.dedup_key for f in diff.persisting} == {"k2"}
    assert diff.regressed is True


def test_diff_no_regression():
    prev = [_finding("SEC-001", "k1")]
    curr = [_finding("SEC-001", "k1")]
    diff = diff_findings(prev, curr)
    assert not diff.regressed
    assert "No new" in render_diff_comment("CRM-1", diff)


# -- PDF --------------------------------------------------------------------

def test_pdf_sanitizer_transliterates_vietnamese_instead_of_mangling_it():
    """`encode("latin-1", "replace")` alone turns every accented character
    into "?" — a real regression against this app's own Vietnamese UI
    (app/core/i18n.py). Decompose-and-strip keeps it legible instead."""
    from app.reporting.pdf import _s

    assert _s("Kết quả đánh giá") == "Ket qua danh gia"
    assert _s("Đã duyệt") == "Da duyet"
    # A genuinely undecomposable script still degrades to "?" — documented,
    # not silently "fixed".
    assert _s("日本語") == "???"


def test_pdf_export_is_a_pdf():
    from app.reporting.pdf import export_pdf

    blob = export_pdf("CRM-1", "http://t", _sample_tests(), [], [], coverage=[
        {"category": "API1:2023", "state": "MISSING", "pct": 0,
         "existing_tests": 0, "generated_tests": 1}])
    assert blob[:4] == b"%PDF"
    assert len(blob) > 800


# -- Auth -------------------------------------------------------------------

def test_role_ranking():
    assert User("a", "admin").can("tester")
    assert User("t", "tester").can("viewer")
    assert not User("v", "viewer").can("tester")


def test_auth_disabled_is_single_user_admin(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    mgr = AuthManager()
    user = mgr.authenticate(None)
    assert user and user.role == "admin"


def test_auth_enabled_requires_valid_key(tmp_path, monkeypatch):
    key = "s3cret-key"
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "alice", "role": "tester", "api_key_sha256": hash_key(key)}]}))
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    mgr = AuthManager()
    assert mgr.authenticate(None) is None
    assert mgr.authenticate("wrong") is None
    ok = mgr.authenticate(key)
    assert ok and ok.name == "alice" and ok.role == "tester"
