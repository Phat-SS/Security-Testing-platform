"""Evidence chain integrity + the approval gate."""

import pytest
from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.execution.evidence import verify_chain
from app.execution.http_runner import ApprovalRequired, HttpRunner
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
