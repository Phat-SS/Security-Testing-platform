"""Evidence chain integrity + the approval gate."""

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.execution.evidence import verify_chain
from app.execution.http_runner import ApprovalRequired, HttpRunner
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
from app.vault import Persona, PersonaVault
from demo.sample_tests import build_tests
from demo.vulnerable_api import app as vulnerable_app


def _runner():
    # Drive the FastAPI demo app in-process via Starlette's TestClient, which
    # runs the ASGI app synchronously — no real port, no network.
    client = TestClient(vulnerable_app, base_url="http://demo-target.local")
    client.follow_redirects = False
    # Scope resolver maps the fake host to a public IP so scope passes; the
    # transport ignores the network anyway.
    policy = ScopePolicy(allowed_hosts={"demo-target.local"})
    scope = ScopeValidator(policy, resolver=lambda h: "203.0.113.5")
    vault = PersonaVault([
        Persona("agent_A", {"Authorization": "Bearer tokenA"}, "agent", {"customer_id": "1001"},
                ["alice.buyer@example.com"]),
        Persona("agent_B", {"Authorization": "Bearer tokenB"}, "agent", {"customer_id": "2002"},
                ["beth.victim@example.com", "555-0202"]),
    ])
    runner = HttpRunner("http://demo-target.local", scope, vault, Settings.from_env(), client=client)
    return runner


def test_unapproved_test_cannot_run():
    tests = build_tests()
    tests[0].approval_status = ApprovalStatus.PENDING
    with pytest.raises(ApprovalRequired):
        _runner().run(tests[0], "exec-x")


def test_bola_detected_end_to_end():
    runner = _runner()
    bola = build_tests()[0]  # already APPROVED
    ex = runner.run(bola, "exec-bola")
    assert ex.verdict.result == TestStatus.FAIL
    # the leaked victim marker must be what drove the verdict
    assert any("DISCLOSURE" in line for line in ex.log)


def test_unauth_read_is_pass():
    runner = _runner()
    auth = build_tests()[1]
    ex = runner.run(auth, "exec-auth")
    assert ex.verdict.result == TestStatus.PASS


def test_secret_token_never_in_evidence():
    runner = _runner()
    ex = runner.run(build_tests()[0], "exec-bola")
    assert "tokenA" not in ex.request.headers.get("Authorization", "")


def test_evidence_chain_verifies_and_detects_tampering():
    runner = _runner()
    e1 = runner.run(build_tests()[0], "e1", prev_hash=None)
    e2 = runner.run(build_tests()[1], "e2", prev_hash=e1.evidence_hash)
    assert verify_chain([e1, e2])
    e2.verdict.reason = "tampered!"
    assert not verify_chain([e1, e2])


def test_captured_url_includes_query_params_injected_separately_by_a_mutation():
    """Mutations like ssrf_url/oversized_payload write into the `query` dict,
    not into `path` — httpx merges that into the final request URL, but the
    stored CapturedRequest.url used to be built from the pre-merge `url`
    string alone and silently never showed that query at all. It must
    reflect what was actually sent (and still get redact_url'd)."""
    runner = _runner()
    captured_req, _, _ = runner._send(
        "GET", "http://demo-target.local/customers/1001",
        headers={}, query={"webhook": "http://169.254.169.254/latest/meta-data/", "token": "sekret"},
        body=None, pinned_ip="203.0.113.5",
    )
    assert "169.254.169.254" in captured_req.url
    assert "sekret" not in captured_req.url  # token= is redacted


async def _leak_endpoint(request):
    return JSONResponse({"customer_id": "2002", "session_token": "sess-victim-999"})


_LEAKY_APP = Starlette(routes=[Route("/customers/{customer_id}", _leak_endpoint)])


def test_leak_detection_sees_the_raw_body_even_when_the_marker_is_secret_shaped():
    """Regression: leak detection must run against the RAW response, before
    redaction. A victim marker that is itself secret-shaped (a session
    token, an API key — exactly what a BOLA/IDOR test is likely to be
    chasing) used to be masked to "********" by redact_text() before the
    substring check ever ran, turning a real disclosure into a silent false
    negative. The stored evidence must still come out redacted."""
    client = TestClient(_LEAKY_APP, base_url="http://leak-target.local")
    client.follow_redirects = False
    policy = ScopePolicy(allowed_hosts={"leak-target.local"})
    scope = ScopeValidator(policy, resolver=lambda h: "203.0.113.7")
    vault = PersonaVault([
        Persona("attacker", {"Authorization": "Bearer attacker-token"}, "agent", {}, []),
        Persona("victim", {"Authorization": "Bearer victim-token"}, "agent",
                {"customer_id": "2002"}, ["sess-victim-999"]),
    ])
    runner = HttpRunner("http://leak-target.local", scope, vault, Settings.from_env(), client=client)

    test = TestCase(
        test_id="REGRESSION-LEAK-001",
        title="Leaked session token must be detected pre-redaction",
        objective="Verify object-level authorization does not leak another persona's session token.",
        owasp_category=OwaspApiCategory.API1,
        severity=Severity.HIGH,
        auth_context=AuthContext(persona="attacker", target_persona="victim"),
        request=RequestSpec(method="GET", path="/customers/{customer_id}"),
        attack_mutation=Mutation(kind="swap_object_id", detail={"id_field": "customer_id"}),
        expected=ExpectedResult(status_in=[403, 404], body_must_not_contain=["sess-victim-999"]),
        evidence_required=["request", "response"],
        source=TestSource.MANUAL,
        approval_status=ApprovalStatus.APPROVED,
    )

    ex = runner.run(test, "exec-leak-regression")
    assert ex.verdict.result == TestStatus.FAIL
    assert any("DISCLOSURE" in line for line in ex.log)
    # Detection sees the raw secret; what's actually stored is still masked.
    assert "sess-victim-999" not in ex.response.body
