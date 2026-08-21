"""Deterministic proof paths for callbacks and post-attack invariants."""

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.execution.http_runner import HttpRunner
from app.schemas.enums import ApprovalStatus, TestStatus
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    InvariantAssertion,
    Mutation,
    OastExpectation,
    RequestSpec,
    TestCase,
    VerificationStep,
)
from app.vault.personas import Persona, PersonaVault

_HOST = "target.test"
_BASE = f"http://{_HOST}"
_VAULT = PersonaVault([
    Persona("attacker", {"Authorization": "Bearer attacker"}, "user", {}, []),
])


class _ObservedOast:
    token = "private-callback-token"
    callback = f"https://oast.example/{token}"

    def issue(self):
        return self.token, self.callback

    def observed(self, token: str) -> bool:
        return token == self.token


def _runner(app: Starlette, *, oast=None) -> HttpRunner:
    client = TestClient(app, base_url=_BASE)
    client.follow_redirects = False
    scope = ScopeValidator(ScopePolicy(allowed_hosts={_HOST}), resolver=lambda _h: "203.0.113.10")
    return HttpRunner(_BASE, scope, _VAULT, Settings.from_env(), client=client, oast=oast)


def _test(**overrides) -> TestCase:
    values = dict(
        test_id="API7-001",
        title="callback proof",
        objective="prove server-side interaction",
        owasp_category="API7:2023",
        severity="HIGH",
        auth_context=AuthContext(persona="attacker"),
        request=RequestSpec(method="POST", path="/fetch"),
        attack_mutation=Mutation(kind="ssrf_url", detail={"field": "url"}),
        expected=ExpectedResult(status_in=[400, 403, 422]),
        approval_status=ApprovalStatus.APPROVED,
    )
    values.update(overrides)
    return TestCase(**values)


def test_observed_oast_callback_is_high_confidence_fail_without_persisting_token():
    async def fetch(request):
        assert request.query_params["url"] == _ObservedOast.callback
        # Real fetch APIs often echo the submitted URL. The collaborator token
        # must still be absent from persisted response evidence.
        return JSONResponse(
            {"queued": True, "url": request.query_params["url"]}, status_code=202
        )

    execution = _runner(
        Starlette(routes=[Route("/fetch", fetch, methods=["POST"])]),
        oast=_ObservedOast(),
    ).run(_test(oast=OastExpectation(purpose="ssrf")), "E-oast")

    assert execution.verdict.result == TestStatus.FAIL
    assert execution.oast is not None and execution.oast.observed is True
    assert execution.oast.token_hash != _ObservedOast.token
    serialized = execution.model_dump_json()
    assert _ObservedOast.token not in serialized
    assert "<oast-token-redacted>" in serialized


def test_json_invariant_proves_a_persisted_privilege_change():
    state = {"role": "user"}

    async def mutate(request):
        state.update(await request.json())
        return JSONResponse({"accepted": True})

    async def read_back(request):
        return JSONResponse(state)

    app = Starlette(routes=[
        Route("/profile", mutate, methods=["PATCH"]),
        Route("/profile", read_back, methods=["GET"]),
    ])
    test = _test(
        test_id="API3-001",
        owasp_category="API3:2023",
        request=RequestSpec(method="PATCH", path="/profile", body={"name": "alice"}),
        attack_mutation=Mutation(
            kind="inject_property", detail={"properties": {"role": "admin"}}
        ),
        verification=VerificationStep(
            **{"as": "attacker"},
            request=RequestSpec(method="GET", path="/profile"),
            proves_exploit_when=[InvariantAssertion(
                json_path="$.role",
                operator="equals",
                expected="admin",
                description="stored role equals attacker-supplied admin role",
            )],
        ),
    )

    execution = _runner(app).run(test, "E-invariant")

    assert execution.verdict.result == TestStatus.FAIL
    assert "stored role equals attacker-supplied admin role" in execution.verdict.actual_summary
    assert [item.kind for item in execution.supporting] == ["verification"]
