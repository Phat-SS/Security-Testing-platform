"""Positive control and verification read-back — end to end through the runner.

These two mechanisms close opposite failure modes:

  * the baseline stops a 404 from an unreachable target being reported as
    "authorization enforced, HIGH confidence" (false negative);
  * the read-back turns "the server answered 200 to my mass assignment" from a
    permanent INCONCLUSIVE into a proven FAIL (undecidable → decided).

Driven against real in-process ASGI apps rather than mocks, because what is
under test is the *sequence* of requests the runner makes, not a return value.
"""

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.execution.evidence import verify_chain
from app.execution.http_runner import HttpRunner
from app.schemas.enums import ApprovalStatus, TestStatus
from app.schemas.testcase import (
    AuthContext,
    BaselineSpec,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
    VerificationStep,
)
from app.vault.personas import Persona, PersonaVault

_HOST = "target.test"
_BASE_URL = f"http://{_HOST}"

_VAULT = PersonaVault([
    Persona("agent_A", {"Authorization": "Bearer tokenA"}, "agent", {"customer_id": "1001"}, []),
    Persona("agent_B", {"Authorization": "Bearer tokenB"}, "agent", {"customer_id": "2002"},
            ["beth@x.com"]),
])


def _app(*routes) -> Starlette:
    return Starlette(routes=list(routes))


def _runner(app: Starlette) -> HttpRunner:
    client = TestClient(app, base_url=_BASE_URL)
    client.follow_redirects = False
    scope = ScopeValidator(ScopePolicy(allowed_hosts={_HOST}), resolver=lambda h: "203.0.113.10")
    return HttpRunner(_BASE_URL, scope, _VAULT, Settings.from_env(), client=client)


def _bola_test(**overrides) -> TestCase:
    fields = dict(
        test_id="API1-001", title="bola", objective="o",
        owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        baseline=BaselineSpec(as_persona="agent_B"),
        request=RequestSpec(method="GET", path="/customers/{customer_id}"),
        attack_mutation=Mutation(kind="swap_object_id", detail={"id_field": "customer_id"}),
        expected=ExpectedResult(status_in=[403, 404]),
        approval_status=ApprovalStatus.APPROVED,
    )
    fields.update(overrides)
    return TestCase(**fields)


# -- the false negative this closes -------------------------------------------


def test_stale_victim_id_is_inconclusive_not_a_confident_pass():
    """Nobody can reach this object — not even its owner. The attack's 404
    therefore says nothing about authorization, and calling it PASS/HIGH (the
    old behaviour) would be a false negative wearing the most confident label
    the system can print."""

    async def gone(request):
        return JSONResponse({"error": "not found"}, status_code=404)

    execution = _runner(_app(Route("/customers/{cid}", gone))).run(_bola_test(), "E1")

    assert execution.verdict.result == TestStatus.INCONCLUSIVE
    assert "positive control" in execution.verdict.actual_summary.lower()
    # The baseline exchange is itself evidence and must be in the record — a
    # verdict that leans on it is only as defensible as the exchange shown.
    assert [s.kind for s in execution.supporting] == ["baseline"]
    assert execution.supporting[0].response.status_code == 404


def test_baseline_success_makes_a_rejection_a_confident_pass():
    async def scoped(request):
        cid = request.path_params["cid"]
        owner = {"1001": "Bearer tokenA", "2002": "Bearer tokenB"}.get(cid)
        if request.headers.get("authorization") != owner:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"id": cid, "email": "beth@x.com" if cid == "2002" else "a@x.com"})

    execution = _runner(_app(Route("/customers/{cid}", scoped))).run(_bola_test(), "E2")

    assert execution.verdict.result == TestStatus.PASS
    assert execution.verdict.confidence.value == "HIGH"
    assert "entitled identity" in execution.verdict.reason
    assert execution.supporting[0].response.status_code == 200


def test_a_real_leak_still_fails_regardless_of_the_baseline():
    """Evidence ranking: a confirmed cross-identity disclosure outranks
    everything below it, baseline included."""

    async def broken(request):
        return JSONResponse({"id": request.path_params["cid"], "email": "beth@x.com"})

    execution = _runner(_app(Route("/customers/{cid}", broken))).run(_bola_test(), "E3")
    assert execution.verdict.result == TestStatus.FAIL
    assert "1 protected marker(s)" in execution.verdict.actual_summary


def test_the_verdict_never_repeats_the_leaked_value_it_is_reporting():
    """`actual_summary` and `reason` are narrative fields with no redaction pass
    of their own, and they are exported, rendered and posted to Jira. A leaked
    marker is often a session token, and a victim email is PII regardless — so
    naming it here would make the platform re-disclose the data it is reporting
    as disclosed. The value stays in the captured response body, which IS
    redacted before storage."""

    async def broken(request):
        return JSONResponse({"id": request.path_params["cid"], "email": "beth@x.com"})

    execution = _runner(_app(Route("/customers/{cid}", broken))).run(_bola_test(), "E3c")

    assert execution.verdict.result == TestStatus.FAIL
    for narrative in (execution.verdict.actual_summary, execution.verdict.reason):
        assert "beth@x.com" not in narrative
    # The runner's log already followed this rule; nothing regressed there.
    assert not any("beth@x.com" in line for line in execution.log)
    # But it is still findable in the evidence a reader is pointed to.
    assert "beth@x.com" in execution.response.body


def test_boilerplate_body_does_not_fabricate_a_leak_when_baseline_also_fails():
    """Regression for BH-217: an endpoint that rejects every caller — attacker
    and rightful owner alike — with the identical generic error body must not
    be sealed as a confirmed cross-identity leak just because a short/generic
    secret marker happens to be a substring of that shared boilerplate.

    Both the attack and the baseline hit the exact same handler here, so their
    bodies are identical up to nothing (there is no per-request variation at
    all) — the worst case, and the one the real bug report showed: a marker
    match that is present in literally every response this endpoint ever
    sends, including to the entitled owner's own positive-control request.
    """

    async def always_rejects(request):
        # A generic problem+json body, same shape the real target returned:
        # no path/persona-specific content, so any marker match in it is
        # necessarily unrelated to who is asking.
        return JSONResponse(
            {"type": "https://tools.ietf.org/html/rfc9110#section-15.5.16",
             "title": "Unsupported Media Type", "status": 415},
            status_code=415,
        )

    vault = PersonaVault([
        Persona("agent_A", {"Authorization": "Bearer tokenA"}, "agent", {"customer_id": "1001"}, []),
        # A short, generic marker that coincidentally substring-matches the
        # boilerplate above (present in the RFC url's version-looking text).
        Persona("agent_B", {"Authorization": "Bearer tokenB"}, "agent", {"customer_id": "2002"},
                ["9110"]),
    ])
    client = TestClient(_app(Route("/customers/{cid}", always_rejects)), base_url=_BASE_URL)
    client.follow_redirects = False
    scope = ScopeValidator(ScopePolicy(allowed_hosts={_HOST}), resolver=lambda h: "203.0.113.10")
    runner = HttpRunner(_BASE_URL, scope, vault, Settings.from_env(), client=client)

    execution = runner.run(_bola_test(), "E3d")

    assert execution.verdict.result == TestStatus.INCONCLUSIVE
    assert "positive control failed" in execution.verdict.actual_summary.lower()
    assert "protected marker" not in execution.verdict.actual_summary


def test_short_marker_alone_is_never_treated_as_a_leak():
    """A minimum-length floor on marker matching: below it, a substring hit
    proves nothing (a bare id or area code will coincidentally appear in all
    kinds of unrelated response text), mirroring the length floor the
    adjudicator already applies to its own byte-identical-body check."""

    async def scoped(request):
        cid = request.path_params["cid"]
        owner = {"1001": "Bearer tokenA", "2002": "Bearer tokenB"}.get(cid)
        if request.headers.get("authorization") != owner:
            # "2" is a substring of practically anything, including this
            # rejection's own status code rendered into the body.
            return JSONResponse({"error": "forbidden", "status": 403}, status_code=403)
        return JSONResponse({"id": cid})

    vault = PersonaVault([
        Persona("agent_A", {"Authorization": "Bearer tokenA"}, "agent", {"customer_id": "1001"}, []),
        Persona("agent_B", {"Authorization": "Bearer tokenB"}, "agent", {"customer_id": "2002"}, ["2"]),
    ])
    client = TestClient(_app(Route("/customers/{cid}", scoped)), base_url=_BASE_URL)
    client.follow_redirects = False
    scope = ScopeValidator(ScopePolicy(allowed_hosts={_HOST}), resolver=lambda h: "203.0.113.10")
    runner = HttpRunner(_BASE_URL, scope, vault, Settings.from_env(), client=client)

    execution = runner.run(_bola_test(), "E3e")

    # 403 is in the expected set and no *trustworthy* leak was found, despite
    # "2" being technically present in the response body.
    assert execution.verdict.result == TestStatus.PASS


def test_a_missing_baseline_persona_does_not_fabricate_a_result():
    """'We could not check' must not read as 'the target was unreachable', and
    neither may quietly become a PASS."""

    async def forbidden(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    test = _bola_test(baseline=BaselineSpec(as_persona="nobody_in_the_vault"))
    execution = _runner(_app(Route("/customers/{cid}", forbidden))).run(test, "E3b")

    assert execution.verdict.result == TestStatus.PASS  # 403 is in the expected set
    assert execution.supporting == []  # nothing was established, nothing claimed
    assert any("SKIPPED" in line for line in execution.log)


# -- the undecidable case this decides ----------------------------------------


def _bopla_test() -> TestCase:
    return TestCase(
        test_id="API3-001", title="mass assignment", objective="o",
        owasp_category="API3:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="PATCH", path="/customers/1001"),
        attack_mutation=Mutation(kind="inject_property",
                                 detail={"properties": {"role": "admin"}}),
        verification=VerificationStep(
            as_persona="agent_A",
            request=RequestSpec(method="GET", path="/customers/1001"),
            proves_exploit_if_contains=['"role":"admin"', '"role": "admin"'],
        ),
        expected=ExpectedResult(status_in=[400, 403, 422]),
        approval_status=ApprovalStatus.APPROVED,
    )


def test_accepted_but_not_persisted_stays_inconclusive():
    """The server answered 200 and silently dropped the field. That is not a
    vulnerability, and the read-back is what tells the two cases apart."""
    store = {"id": "1001", "role": "agent"}

    async def patch(request):
        return JSONResponse({"ok": True})  # accepts, ignores the injected field

    async def get(request):
        return JSONResponse(store)

    app = _app(
        Route("/customers/{cid}", patch, methods=["PATCH"]),
        Route("/customers/{cid}", get, methods=["GET"]),
    )
    execution = _runner(app).run(_bopla_test(), "E4")
    assert execution.verdict.result == TestStatus.INCONCLUSIVE
    assert [s.kind for s in execution.supporting] == ["verification"]


def test_persisted_injection_is_a_confirmed_fail():
    store = {"id": "1001", "role": "agent"}

    async def patch(request):
        store.update(await request.json())  # the mass-assignment bug
        return JSONResponse({"ok": True})

    async def get(request):
        return JSONResponse(store)

    app = _app(
        Route("/customers/{cid}", patch, methods=["PATCH"]),
        Route("/customers/{cid}", get, methods=["GET"]),
    )
    execution = _runner(app).run(_bopla_test(), "E5")
    assert execution.verdict.result == TestStatus.FAIL
    assert execution.verdict.confidence.value == "HIGH"
    # The distinguishing claim: decided by observed state change, not by status.
    assert "confirmed by state change" in execution.verdict.reason
    assert execution.supporting[-1].kind == "verification"
    assert any("PERSISTED" in line for line in execution.log)


def test_json_body_gets_a_content_type_so_the_probe_is_not_rejected_unsent():
    """An API that requires a declared content type answers 415 to every
    body-carrying probe, and the verdict reads that rejection as 'the control
    held' — a false negative on every mass-assignment test at once."""
    seen: dict = {}

    async def patch(request):
        seen["content_type"] = request.headers.get("content-type", "")
        return JSONResponse({"ok": True})

    async def get(request):
        return JSONResponse({"id": "1001", "role": "agent"})

    app = _app(
        Route("/customers/{cid}", patch, methods=["PATCH"]),
        Route("/customers/{cid}", get, methods=["GET"]),
    )
    _runner(app).run(_bopla_test(), "E5b")
    assert seen["content_type"] == "application/json"


# -- multi-request probes ------------------------------------------------------


def _rate_test(kind, count, ceiling) -> TestCase:
    return TestCase(
        test_id="API4-001", title="rate", objective="o",
        owasp_category="API4:2023", severity="MEDIUM",
        auth_context=AuthContext(persona="agent_A"),
        request=RequestSpec(method="GET", path="/search"),
        attack_mutation=Mutation(kind=kind, detail={"count": count}),
        expected=ExpectedResult(status_in=[200, 429], max_successful_repeats=ceiling),
        approval_status=ApprovalStatus.APPROVED,
    )


def test_unthrottled_repeats_are_a_measured_fail():
    async def search(request):
        return JSONResponse({"results": []})

    execution = _runner(_app(Route("/search", search))).run(_rate_test("rate_probe", 8, 3), "E6")
    assert execution.verdict.result == TestStatus.FAIL
    assert (execution.repeat.sent, execution.repeat.succeeded) == (8, 8)
    assert execution.repeat.throttled is False


def test_a_throttling_endpoint_is_not_reported_as_missing_the_control():
    """A limit that exists but is looser than declared is a tuning question for
    the service owner, not a confirmed missing control."""
    seen = {"n": 0}

    async def search(request):
        seen["n"] += 1
        if seen["n"] > 3:
            return JSONResponse({"error": "slow down"}, status_code=429)
        return JSONResponse({"results": []})

    execution = _runner(_app(Route("/search", search))).run(_rate_test("rate_probe", 8, 1), "E7")
    assert execution.verdict.result != TestStatus.FAIL
    assert execution.repeat.throttled is True


def test_concurrent_race_probe_completes_without_deadlocking_on_the_dns_pin():
    """The DNS pin patches a process global under a lock; the burst runs inside
    one pin block and its worker threads must not re-enter it. If they do, this
    test hangs rather than fails — which is why it exists."""

    async def redeem(request):
        return JSONResponse({"ok": True})

    test = TestCase(
        test_id="API6-001", title="race", objective="o",
        owasp_category="API6:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A"),
        request=RequestSpec(method="POST", path="/redeem"),
        attack_mutation=Mutation(kind="race_condition", detail={"count": 6}),
        expected=ExpectedResult(status_in=[200, 409], max_successful_repeats=1),
        approval_status=ApprovalStatus.APPROVED,
    )
    execution = _runner(_app(Route("/redeem", redeem, methods=["POST"]))).run(test, "E8")
    assert (execution.repeat.sent, execution.repeat.concurrent) == (6, True)
    assert execution.verdict.result == TestStatus.FAIL  # 6 commits where 1 was allowed


# -- response-header assertions ------------------------------------------------


def _header_test(**expected_kwargs) -> TestCase:
    return TestCase(
        test_id="API8-001", title="headers", objective="o",
        owasp_category="API8:2023", severity="MEDIUM",
        auth_context=AuthContext(persona="agent_A"),
        request=RequestSpec(method="GET", path="/customers/1001"),
        attack_mutation=Mutation(kind="cors_probe", detail={"origin": "https://evil.example"}),
        expected=ExpectedResult(status_in=[200, 401, 403, 404], **expected_kwargs),
        approval_status=ApprovalStatus.APPROVED,
    )


def test_origin_reflecting_cors_is_a_fail_despite_a_200():
    """The finding lives in the headers, so a legitimate 200 must not short-
    circuit evaluation into a PASS before the headers are ever inspected."""

    async def reflect(request):
        return JSONResponse({}, headers={"Access-Control-Allow-Origin":
                                         request.headers.get("origin", "")})

    test = _header_test(forbidden_response_headers={"access-control-allow-origin": "evil.example"})
    execution = _runner(_app(Route("/customers/{cid}", reflect))).run(test, "E9")
    assert execution.verdict.result == TestStatus.FAIL


def test_header_matching_is_case_insensitive():
    async def hardened(request):
        return JSONResponse({}, headers={"X-Content-Type-Options": "nosniff"})

    # Declared in a different case than the server sends it. HTTP header names
    # are case-insensitive; a literal dict lookup would report it absent and
    # manufacture a finding on a correctly hardened endpoint.
    test = _header_test(required_response_headers=["x-content-type-options"])
    execution = _runner(_app(Route("/customers/{cid}", hardened))).run(test, "E10")
    assert execution.verdict.result == TestStatus.PASS


def test_missing_hardening_header_is_reported():
    async def bare(request):
        return JSONResponse({})

    test = _header_test(required_response_headers=["X-Content-Type-Options"])
    execution = _runner(_app(Route("/customers/{cid}", bare))).run(test, "E11")
    assert execution.verdict.result == TestStatus.FAIL
    assert "X-Content-Type-Options" in execution.verdict.actual_summary


# -- evidence integrity --------------------------------------------------------


def test_supporting_exchanges_are_covered_by_the_evidence_hash():
    """Deleting a baseline must break the chain. If it did not, the edit that
    turns 'INCONCLUSIVE because the control was never exercised' into a clean
    PASS would be invisible — exactly the tampering the hash exists to catch."""

    async def ok(request):
        return JSONResponse({"id": request.path_params["cid"]})

    execution = _runner(_app(Route("/customers/{cid}", ok))).run(_bola_test(), "E12")
    assert verify_chain([execution]) is True

    execution.supporting = []
    assert verify_chain([execution]) is False


# -- template resolution: the quiet false-negative source ----------------------


def test_a_camel_case_placeholder_resolves_from_a_snake_case_persona_id():
    """Endpoint paths are written in a ticket's style (`{customerId}`) while
    persona ids are configured in the engagement's style (`customer_id`).
    Without a normalised match those never met: the literal string
    `{customerId}` went out as a path segment, drew a 404, and was recorded as
    PASS — a false negative on every non-BOLA test touching an object route."""
    seen: dict = {}

    async def capture(request):
        seen["path"] = request.url.path
        return JSONResponse({"id": "1001", "role": "agent"})

    test = TestCase(
        test_id="API8-002", title="headers", objective="o",
        owasp_category="API8:2023", severity="LOW",
        auth_context=AuthContext(persona="agent_A"),  # no victim → own ids apply
        request=RequestSpec(method="GET", path="/customers/{customerId}"),
        attack_mutation=Mutation(kind="security_headers_probe"),
        expected=ExpectedResult(status_in=[200]),
        approval_status=ApprovalStatus.APPROVED,
    )
    _runner(_app(Route("/customers/{cid}", capture))).run(test, "E13")

    assert seen["path"] == "/customers/1001"
    assert "{" not in seen["path"]


def test_a_bola_probe_never_resolves_to_the_attackers_own_object():
    """If the attacker's ids shared the template namespace, a probe for an id
    the victim does not own would resolve to the attacker's own object. The
    test would then attack itself, pass, and report authorization enforced."""
    vault = PersonaVault([
        # Only the attacker owns an order; the victim does not.
        Persona("agent_A", {"Authorization": "Bearer tokenA"}, "agent",
                {"customer_id": "1001", "order_id": "9999"}, []),
        Persona("agent_B", {"Authorization": "Bearer tokenB"}, "agent",
                {"customer_id": "2002"}, ["beth@x.com"]),
    ])
    seen: dict = {}

    async def capture(request):
        seen["path"] = request.url.path
        return JSONResponse({"ok": True})

    client = TestClient(_app(Route("/orders/{oid}", capture)), base_url=_BASE_URL)
    client.follow_redirects = False
    scope = ScopeValidator(ScopePolicy(allowed_hosts={_HOST}), resolver=lambda h: "203.0.113.10")
    runner = HttpRunner(_BASE_URL, scope, vault, Settings.from_env(), client=client)

    test = _bola_test(
        test_id="API1-002",
        request=RequestSpec(method="GET", path="/orders/{order_id}"),
        attack_mutation=Mutation(kind="swap_object_id", detail={"id_field": "order_id"}),
        baseline=None,
    )
    execution = runner.run(test, "E14")

    # The victim owns exactly one id, so that is what the probe must target —
    # never the attacker's own 9999.
    assert seen.get("path") != "/orders/9999"
    assert execution.request.url.endswith("/orders/2002")


def test_the_attackers_own_ids_stay_reachable_under_an_explicit_prefix():
    seen: dict = {}

    async def capture(request):
        seen["path"] = request.url.path
        return JSONResponse({"ok": True})

    test = _bola_test(
        request=RequestSpec(method="GET", path="/customers/{own_customer_id}"),
        baseline=None,
    )
    _runner(_app(Route("/customers/{cid}", capture))).run(test, "E15")
    assert seen["path"] == "/customers/1001"
