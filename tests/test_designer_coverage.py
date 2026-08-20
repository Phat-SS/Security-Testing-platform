"""Every applicable OWASP category can now actually produce a test.

The gap this pins shut: the rule engine used to mark API6/8/9/10 applicable
while the designer had no branch for any of them, so the coverage matrix
reported a MISSING that no amount of testing could ever close.
"""

from app.analysis import HeuristicAnalyzer, TestDesigner
from app.analysis.test_designer import AGGRESSIVE, STANDARD
from app.execution.mutations import MUTATION_KINDS
from app.execution.verdict import evaluate as evaluate_verdict
from app.mcp.jira import NormalizedIssue
from app.owasp.coverage import compute_coverage
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping
from app.schemas.enums import ApprovalStatus, Applicability, OwaspApiCategory
from app.schemas.execution import CapturedResponse


def _design(description: str, depth: str = STANDARD, summary: str = "API work"):
    issue = NormalizedIssue(issue_key="CRM-1", project_key="CRM",
                            summary=summary, description=description)
    analysis = HeuristicAnalyzer().analyze(issue)
    return analysis, TestDesigner(depth=depth).design(analysis)


def _categories(tests):
    return {t.owasp_category for t in tests}


# -- the four categories that had no generator --------------------------------


def test_business_flow_ticket_produces_api6_tests():
    analysis, tests = _design(
        "POST /checkout/redeem applies a coupon during checkout. Bearer JWT required."
    )
    assert OwaspApiCategory.API6 in analysis.applicable_categories()
    assert OwaspApiCategory.API6 in _categories(tests)


def test_misconfiguration_ticket_produces_api8_tests():
    analysis, tests = _design(
        "GET /customers/{customerId} returns data. CORS is currently permissive and "
        "debug mode was left on. Bearer JWT required."
    )
    assert OwaspApiCategory.API8 in analysis.applicable_categories()
    assert OwaspApiCategory.API8 in _categories(tests)


def test_inventory_ticket_produces_api9_tests():
    analysis, tests = _design(
        "GET /customers/{customerId} replaces a deprecated legacy endpoint. Bearer JWT."
    )
    assert OwaspApiCategory.API9 in analysis.applicable_categories()
    assert OwaspApiCategory.API9 in _categories(tests)


def test_third_party_ticket_produces_api10_tests():
    analysis, tests = _design(
        "POST /enrich calls a third-party api with a callback url. Bearer JWT required."
    )
    assert OwaspApiCategory.API10 in analysis.applicable_categories()
    assert OwaspApiCategory.API10 in _categories(tests)


def test_no_applicable_category_is_left_without_a_test():
    """The invariant, stated once: whatever the rule engine says is worth
    testing, the designer must be able to test."""
    analysis, tests = _design(
        "GET /v2/customers/{customerId} and PATCH /v2/customers/{customerId} manage a "
        "customer role. POST /checkout/redeem redeems a coupon. Search and export are "
        "supported via GET /v2/customers/search. A callback url webhook notifies a "
        "third-party api. CORS and debug settings were changed. This deprecates a "
        "legacy endpoint. Bearer JWT with admin and agent roles.",
        depth=AGGRESSIVE,
    )
    generated = _categories(tests)
    for category in analysis.applicable_categories():
        assert category in generated, f"{category.value} applicable but no test generated"


# -- evidence-carrying tests --------------------------------------------------


def test_authorization_tests_carry_a_positive_control():
    _analysis, tests = _design(
        "GET /customers/{customerId} returns a customer. Bearer JWT required."
    )
    bola = [t for t in tests if t.owasp_category == OwaspApiCategory.API1]
    assert bola and all(t.baseline is not None for t in bola)


def test_mass_assignment_tests_carry_a_read_back():
    _analysis, tests = _design(
        "PATCH /customers/{customerId} updates a customer role. Bearer JWT required."
    )
    bopla = [t for t in tests if t.owasp_category == OwaspApiCategory.API3]
    assert bopla and all(t.verification is not None for t in bopla)


# -- expected-public endpoints -------------------------------------------------


def _public_analysis() -> IssueAnalysis:
    return IssueAnalysis(
        issue_key="X-1",
        endpoints=[Endpoint(method="GET", path="/health", expected_public=True)],
        owasp_mappings=[
            OwaspMapping(category=OwaspApiCategory.API2, applicability=Applicability.APPLICABLE,
                        reason="test fixture"),
        ],
    )


def test_expected_public_endpoint_gets_one_drop_auth_test_expecting_success():
    tests = TestDesigner().design(_public_analysis())
    api2 = [t for t in tests if t.owasp_category == OwaspApiCategory.API2]
    assert len(api2) == 1
    assert api2[0].attack_mutation.kind == "drop_auth"
    assert 200 in api2[0].expected.status_in
    # No tamper_token/JWT variants — there is no credential to tamper with.
    assert {t.attack_mutation.kind for t in api2} == {"drop_auth"}


def test_expected_public_takes_precedence_over_auth_required():
    analysis = _public_analysis()
    analysis.endpoints[0].auth_required = True  # left on; expected_public still wins
    tests = TestDesigner().design(analysis)
    kinds = {t.attack_mutation.kind for t in tests if t.owasp_category == OwaspApiCategory.API2}
    assert kinds == {"drop_auth"}


def test_a_200_on_the_expected_public_test_is_a_pass_not_inconclusive():
    tests = TestDesigner().design(_public_analysis())
    test = next(t for t in tests if t.owasp_category == OwaspApiCategory.API2)
    response = CapturedResponse(status_code=200, headers={}, body="", elapsed_ms=5, size_bytes=0)
    verdict = evaluate_verdict(test, response, leaked_markers=[])
    assert verdict.result.value == "PASS"


def test_the_jwt_signature_probe_is_always_generated_for_authenticated_endpoints():
    """Accepting a token whose claims changed but whose signature did not is
    the single highest-value auth finding, so it is not gated behind depth."""
    _analysis, tests = _design(
        "GET /customers/{customerId} returns a customer. Bearer JWT required."
    )
    kinds = {t.attack_mutation.kind for t in tests}
    assert "jwt_claim_tamper" in kinds
    assert "jwt_alg_none" in kinds


# -- depth --------------------------------------------------------------------


def test_aggressive_is_a_superset_of_standard():
    description = (
        "GET /v2/customers/{customerId} and PATCH /v2/customers/{customerId}. "
        "Bearer JWT with admin role. Callback url webhook. Search and export."
    )
    _a, standard = _design(description, depth=STANDARD)
    _b, aggressive = _design(description, depth=AGGRESSIVE)
    assert len(aggressive) > len(standard)
    assert _categories(standard) <= _categories(aggressive)


def test_an_unrecognised_depth_falls_back_to_the_narrower_plan():
    # Depth arrives from a web form; the safe direction for an unknown value is
    # fewer tests, not an exception in the middle of the design step.
    assert TestDesigner(depth="ultra-mega").aggressive is False


def test_with_depth_preserves_persona_wiring():
    """Depth is a per-run choice, so callers need it without rebuilding the
    persona wiring — and without reaching into private attributes to do it."""
    designer = TestDesigner(attacker="a1", victim="v1", admin="adm").with_depth(AGGRESSIVE)
    analysis = HeuristicAnalyzer().analyze(
        NormalizedIssue(issue_key="C-1", project_key="C",
                        description="GET /customers/{customerId}. Bearer JWT required.")
    )
    tests = designer.design(analysis)
    assert tests
    assert designer.aggressive is True
    assert all(t.auth_context.persona in {"a1", "anonymous"} for t in tests)
    assert all(t.auth_context.target_persona in {"v1", None} for t in tests)


# -- invariants that must survive every generator -----------------------------


def test_everything_generated_is_pending_and_uses_a_reviewed_mutation():
    _analysis, tests = _design(
        "GET /v2/customers/{customerId}, PATCH /v2/customers/{customerId}, "
        "POST /checkout/redeem, GET /v2/customers/search with a callback url webhook "
        "to a third-party api. CORS debug. Deprecated legacy. Bearer JWT admin agent.",
        depth=AGGRESSIVE,
    )
    assert tests
    for test in tests:
        assert test.approval_status == ApprovalStatus.PENDING
        assert not test.is_runnable()
        assert test.attack_mutation.kind in MUTATION_KINDS, test.attack_mutation.kind
        assert test.request.path.startswith("/")


def test_test_ids_are_unique():
    _analysis, tests = _design(
        "GET /v2/customers/{customerId}, PATCH /v2/customers/{customerId}, "
        "POST /checkout/redeem. Callback url webhook to a third-party api. "
        "CORS debug. Deprecated legacy. Bearer JWT admin agent.",
        depth=AGGRESSIVE,
    )
    ids = [t.test_id for t in tests]
    assert len(ids) == len(set(ids))


def test_coverage_reflects_the_generated_plan():
    analysis, tests = _design(
        "POST /checkout/redeem redeems a coupon. Bearer JWT required.", depth=AGGRESSIVE
    )
    rows = {r.category: r for r in compute_coverage(analysis, [], tests)}
    api6 = rows[OwaspApiCategory.API6]
    assert api6.applicable is True
    assert api6.generated_tests > 0
