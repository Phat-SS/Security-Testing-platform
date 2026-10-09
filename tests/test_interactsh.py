"""The interactsh collaborator, against an in-process fake server.

The crypto is real: the fake encrypts each interaction exactly the way an
interactsh server does (AES-CFB, the AES key wrapped with the client's RSA
public key, RSA-OAEP/SHA-256), so a decrypt bug cannot hide behind a mock.
"""

from __future__ import annotations

import base64
import json
import os

import httpx
import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from app.execution.oast import InteractshVerifier, build_oast_verifier  # noqa: E402


class _FakeServer:
    def __init__(self) -> None:
        self.public_key = None
        self.pending: list[dict] = []
        self.registered: dict = {}
        self.auth: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.auth.append(request.headers.get("authorization", ""))
        if request.url.path == "/register":
            body = json.loads(request.content)
            self.registered = body
            self.public_key = serialization.load_pem_public_key(base64.b64decode(body["public-key"]))
            return httpx.Response(200, json={"message": "registration successful"})
        if request.url.path == "/poll":
            assert request.url.params["id"] == self.registered["correlation-id"]
            assert request.url.params["secret"] == self.registered["secret-key"]
            aes_key = os.urandom(32)
            wrapped = self.public_key.encrypt(aes_key, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            data = []
            for interaction in self.pending:
                iv = os.urandom(16)
                ct = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).encryptor().update(
                    json.dumps(interaction).encode())
                data.append(base64.b64encode(iv + ct).decode())
            self.pending = []  # like the real server: each interaction is returned once
            return httpx.Response(200, json={"data": data, "aes_key": base64.b64encode(wrapped).decode()})
        return httpx.Response(404)


def _verifier(server: _FakeServer, token: str = "") -> InteractshVerifier:
    return InteractshVerifier("oast.test", token=token, wait_s=0,
                              client=httpx.Client(transport=httpx.MockTransport(server.handler)))


def test_each_execution_gets_its_own_subdomain_of_the_server():
    server = _FakeServer()
    v = _verifier(server)
    t1, url1 = v.issue()
    t2, url2 = v.issue()
    assert t1 != t2 and len(t1) == 33
    assert url1 == f"https://{t1}.oast.test/"
    # One registration, however many callbacks are issued.
    assert server.registered["correlation-id"] == t1[:20] == t2[:20]


def test_a_dns_callback_is_observed_and_only_for_its_own_token():
    server = _FakeServer()
    v = _verifier(server)
    hit, _ = v.issue()
    miss, _ = v.issue()
    server.pending.append({"protocol": "dns", "unique-id": hit, "full-id": hit})

    assert v.observed(hit) is True
    assert v.observed(miss) is False
    # Seen once, remembered: the server will not return it again.
    assert v.observed(hit) is True


def test_an_http_callback_with_a_longer_full_id_counts():
    server = _FakeServer()
    v = _verifier(server)
    token, _ = v.issue()
    server.pending.append({"protocol": "http", "unique-id": "", "full-id": f"{token}.extra"})
    assert v.observed(token) is True


def test_the_token_header_is_sent_for_a_self_hosted_server():
    server = _FakeServer()
    _verifier(server, token="s3cret").issue()
    assert server.auth == ["s3cret"]


def test_interactsh_is_opt_in_and_wins_over_the_generic_contract(monkeypatch):
    monkeypatch.delenv("INTERACTSH_SERVER", raising=False)
    monkeypatch.delenv("OAST_PUBLIC_URL", raising=False)
    monkeypatch.delenv("OAST_POLL_URL", raising=False)
    assert build_oast_verifier() is None
    monkeypatch.setenv("INTERACTSH_SERVER", "oast.example.com")
    monkeypatch.setenv("OAST_PUBLIC_URL", "https://pub.example.com")
    monkeypatch.setenv("OAST_POLL_URL", "https://poll.example.com")
    assert isinstance(build_oast_verifier(), InteractshVerifier)


def test_a_collaborator_that_cannot_register_does_not_stop_the_probe():
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from app.core.config import Settings
    from app.core.scope import ScopePolicy, ScopeValidator
    from app.execution.http_runner import HttpRunner
    from app.schemas.enums import ApprovalStatus
    from app.schemas.testcase import (AuthContext, ExpectedResult, Mutation, OastExpectation,
                                      RequestSpec, TestCase)
    from app.vault.personas import Persona, PersonaVault

    class _Down:
        def issue(self):
            raise httpx.ConnectError("collaborator unreachable")

        def observed(self, token):  # pragma: no cover - never reached
            raise AssertionError

    async def fetch(request):
        return JSONResponse({"ok": True})

    client = TestClient(Starlette(routes=[Route("/fetch", fetch, methods=["POST"])]),
                        base_url="http://target.test")
    runner = HttpRunner(
        "http://target.test",
        ScopeValidator(ScopePolicy(allowed_hosts={"target.test"}), resolver=lambda h: "203.0.113.10"),
        PersonaVault([Persona("agent_A", {}, "user", {}, [])]), Settings.from_env(),
        client=client, oast=_Down(),
    )
    test = TestCase(
        test_id="API7-001", title="ssrf", objective="o", owasp_category="API7:2023",
        severity="HIGH", auth_context=AuthContext(persona="agent_A"),
        request=RequestSpec(method="POST", path="/fetch", body={"url": "x"}),
        attack_mutation=Mutation(kind="ssrf_url", detail={"field": "url"}),
        expected=ExpectedResult(status_in=[400, 403]),
        oast=OastExpectation(purpose="ssrf"),
        approval_status=ApprovalStatus.APPROVED,
    )
    execution = runner.run(test, "E-oast")
    assert execution.response is not None
    assert any("could not issue a callback" in line for line in execution.log)


def test_one_registration_per_process_and_configuration(monkeypatch):
    from app.execution import oast

    monkeypatch.setattr(oast, "_INTERACTSH", {})
    monkeypatch.setenv("INTERACTSH_SERVER", "oast.example.com")
    assert build_oast_verifier() is build_oast_verifier()


def test_a_failed_registration_is_not_retried_by_every_test():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(503)

    v = InteractshVerifier("oast.test", wait_s=0,
                           client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(httpx.HTTPStatusError):
        v.issue()
    with pytest.raises(RuntimeError, match="recently"):
        v.issue()
    assert calls == ["/register"]
