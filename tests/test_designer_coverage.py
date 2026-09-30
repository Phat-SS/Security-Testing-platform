"""Four reviewed mutations the deterministic designer could never reach.

`graphql_introspection_probe`, `graphql_batching_abuse`, `host_header_injection`
and `oauth_redirect_uri_bypass` have had reviewed handlers and a place in the
allow-list all along — but only the AI attack planner could propose them. With
`USE_AI` off, a ticket about a GraphQL endpoint produced no GraphQL test at all,
and the coverage table still read as covered because the category had *a* test
in it.

What was missing was never the attack. It was a signal telling the designer what
kind of endpoint it was looking at.
"""

from __future__ import annotations

import pytest

from app.analysis.test_designer import TestDesigner
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping
from app.schemas.enums import Applicability, OwaspApiCategory


def _plan(endpoints: list[Endpoint], *, aggressive: bool = False):
    designer = TestDesigner("agent_A", "agent_B")
    if aggressive:
        designer = designer.with_depth("aggressive")
    analysis = IssueAnalysis(
        issue_key="CRM-1",
        business_summary="s",
        endpoints=endpoints,
        owasp_mappings=[
            OwaspMapping(category=c, applicability=Applicability.APPLICABLE, reason="r")
            for c in OwaspApiCategory
        ],
    )
    return designer.design(analysis)


def _kinds(tests) -> set[str]:
    return {t.attack_mutation.kind for t in tests}


# -- GraphQL ----------------------------------------------------------------


@pytest.mark.parametrize("path", ["/graphql", "/api/graphql", "/v1/gql"])
def test_a_graphql_route_gets_an_introspection_probe(path):
    """An exposed schema is the entire inventory of a GraphQL API, and asking
    for it is one request — so this is not gated behind aggressive depth."""
    tests = _plan([Endpoint(method="POST", path=path)])

    assert "graphql_introspection_probe" in _kinds(tests)


def test_a_rest_route_gets_no_graphql_probe():
    tests = _plan([Endpoint(method="GET", path="/customers/{id}")], aggressive=True)

    assert "graphql_introspection_probe" not in _kinds(tests)
    assert "graphql_batching_abuse" not in _kinds(tests)


def test_batching_abuse_is_aggressive_only():
    """It sends 25 requests in one. Volume is not risk here — nothing runs
    without approval — but it is not the first thing to show someone."""
    endpoint = [Endpoint(method="POST", path="/graphql")]

    assert "graphql_batching_abuse" not in _kinds(_plan(endpoint))
    assert "graphql_batching_abuse" in _kinds(_plan(endpoint, aggressive=True))


# -- Host header ------------------------------------------------------------


def test_every_endpoint_gets_a_host_header_probe():
    """A forged Host reflected into a password-reset link is the classic form,
    and it is not specific to any one route."""
    tests = _plan([Endpoint(method="GET", path="/customers/{id}")])

    assert "host_header_injection" in _kinds(tests)


def test_the_host_header_probe_does_not_decide_on_the_status_line():
    """Reflecting the forged host is the finding; a 200 on its own is not."""
    tests = _plan([Endpoint(method="GET", path="/customers/{id}")])
    probe = next(t for t in tests if t.attack_mutation.kind == "host_header_injection")

    assert 200 in probe.expected.status_in, "a 200 here is not the finding"
    assert "evil.example" in probe.expected.body_must_not_contain


# -- OAuth ------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/oauth/authorize", "/connect/authorize", "/sso/start"])
def test_an_authorization_endpoint_gets_a_redirect_uri_probe(path):
    """An authorize endpoint that accepts an attacker's redirect_uri hands over
    the code it is about to issue."""
    tests = _plan([Endpoint(method="GET", path=path, url_fields=["redirect_uri"])])

    assert "oauth_redirect_uri_bypass" in _kinds(tests)


def test_a_declared_redirect_field_is_enough_on_its_own():
    """The same surface under another name — which an imported specification is
    exactly the thing that reveals."""
    tests = _plan([Endpoint(method="GET", path="/login/start",
                            url_fields=["redirectUrl"])])

    assert "oauth_redirect_uri_bypass" in _kinds(tests)


def test_an_ordinary_endpoint_gets_no_oauth_probe():
    tests = _plan([Endpoint(method="POST", path="/customers",
                            url_fields=["avatarUrl"])], aggressive=True)

    assert "oauth_redirect_uri_bypass" not in _kinds(tests)


# -- the whole point --------------------------------------------------------


def test_these_reach_a_plan_with_no_ai_configured():
    """The gap this closes: all four were reachable only through the AI
    planner, so an offline run silently tested none of them."""
    tests = _plan([
        Endpoint(method="POST", path="/graphql"),
        Endpoint(method="GET", path="/oauth/authorize", url_fields=["redirect_uri"]),
    ], aggressive=True)

    assert {
        "graphql_introspection_probe",
        "graphql_batching_abuse",
        "host_header_injection",
        "oauth_redirect_uri_bypass",
    } <= _kinds(tests)


def test_every_mutation_the_designer_emits_is_in_the_registry():
    """The vocabulary is a closed allow-list — a generated test naming a kind
    outside it is rejected at run time, which would be a plan that silently
    cannot run."""
    from app.execution.mutations import MUTATION_KINDS

    tests = _plan([
        Endpoint(method="POST", path="/graphql"),
        Endpoint(method="GET", path="/oauth/authorize", url_fields=["redirect_uri"]),
        Endpoint(method="PATCH", path="/customers/{id}", object_id_params=["id"],
                 writes_properties=True, url_fields=["callbackUrl"]),
    ], aggressive=True)

    unknown = _kinds(tests) - set(MUTATION_KINDS)
    assert not unknown, f"the designer emits kinds no handler implements: {unknown}"


# -- API6: what persisted, not what was accepted ----------------------------


def test_a_one_shot_flow_is_read_back_rather_than_trusted():
    """A redeem endpoint answering 200 five times has either committed five
    times or deduplicated four of them, and the status line cannot tell you
    which. The read-back can — and "a 200 is never a finding on its own" is the
    rule this platform applies everywhere else."""
    tests = _plan([Endpoint(method="POST", path="/coupons/{couponId}/redeem",
                            object_id_params=["couponId"])])

    chains = [t for t in tests
              if t.owasp_category.value.startswith("API6") and t.verification]
    assert chains, "the one-shot flow is decided on status codes alone"
    assert chains[0].verification.proves_exploit_when, "nothing is actually asserted"


def test_the_read_back_runs_as_the_identity_that_owns_the_object():
    """Otherwise a failure to see the duplicate could just be the attacker's own
    visibility being restricted — which is not the same as it not existing."""
    tests = _plan([Endpoint(method="POST", path="/coupons/{couponId}/redeem",
                            object_id_params=["couponId"])])

    chain = next(t for t in tests
                 if t.owasp_category.value.startswith("API6") and t.verification)
    assert chain.verification.as_persona == "agent_B"


def test_a_read_only_flow_gets_no_commit_chain():
    """Nothing commits, so there is nothing to have persisted."""
    tests = _plan([Endpoint(method="GET", path="/coupons/{couponId}/redeem",
                            object_id_params=["couponId"])], aggressive=True)

    assert not [t for t in tests
                if t.owasp_category.value.startswith("API6") and t.verification]


def test_an_ordinary_flow_gets_no_one_shot_chain():
    """Firing it at an endpoint that legitimately accepts repeats manufactures a
    false positive."""
    tests = _plan([Endpoint(method="POST", path="/orders")], aggressive=True)

    assert not [t for t in tests
                if t.owasp_category.value.startswith("API6") and t.verification]


def test_coverage_reports_technique_depth_beside_the_covered_state():
    """One drop_auth test makes API2 'COVERED', but that is one technique of
    several. The depth number is the honest companion."""
    from app.analysis import HeuristicAnalyzer, TestDesigner
    from app.mcp.jira import NormalizedIssue
    from app.owasp.coverage import compute_coverage, coverage_summary

    issue = NormalizedIssue(issue_key="C-1", project_key="C",
                            summary="GET /customers/{customerId}. Bearer JWT auth.")
    analysis = HeuristicAnalyzer().analyze(issue)
    tests = TestDesigner().design(analysis)
    rows = compute_coverage(analysis, [], tests)
    applicable = [r for r in rows if r.applicable]
    assert applicable
    assert all(0 <= r.depth_pct <= 100 for r in applicable)
    assert any(r.techniques_missing for r in applicable)  # never claims total depth
    assert 0 <= coverage_summary(rows)["depth_pct"] <= 100


# -- Phase 2: BOLA/BFLA depth additions ---------------------------------------


def test_aggressive_bola_adds_body_id_and_format_variants():
    ep = Endpoint(method="POST", path="/orders/{orderId}", object_id_params=["orderId"],
                  writes_properties=True)
    kinds = _kinds(_plan([ep], aggressive=True))
    assert "swap_id_in_body" in kinds
    assert "mutate_id_format" in kinds


def test_standard_depth_does_not_add_bola_format_variants():
    ep = Endpoint(method="GET", path="/orders/{orderId}", object_id_params=["orderId"])
    kinds = _kinds(_plan([ep], aggressive=False))
    assert "mutate_id_format" not in kinds
    assert "swap_object_id" in kinds


def test_aggressive_bfla_adds_verb_and_path_spelling_variants():
    ep = Endpoint(method="DELETE", path="/admin/users/{userId}", object_id_params=["userId"])
    kinds = _kinds(_plan([ep], aggressive=True))
    assert "method_switch" in kinds
    assert "path_normalization_bypass" in kinds


def test_method_switch_bfla_test_is_not_marked_destructive_for_a_safe_probe():
    # OPTIONS is the default verb for the BFLA method_switch probe. The
    # endpoint itself is a GET (not one of the destructive methods), so this
    # isolates the mutation-based check: switching to a non-destructive verb
    # must not require destructive-action confirmation to run.
    ep = Endpoint(method="GET", path="/admin/users/{userId}", object_id_params=["userId"])
    tests = _plan([ep], aggressive=True)
    method_switch_tests = [t for t in tests if t.attack_mutation.kind == "method_switch"]
    assert method_switch_tests and all(not t.is_destructive for t in method_switch_tests)


def test_method_switch_to_a_destructive_verb_is_marked_destructive():
    from app.schemas.testcase import is_destructive_mutation
    assert is_destructive_mutation("method_switch", {"method": "DELETE"}) is True
    assert is_destructive_mutation("method_switch", {"method": "GET"}) is False
    assert is_destructive_mutation("method_override", {"method": "DELETE"}) is True


def test_aggressive_api8_adds_type_confusion_probes():
    ep = Endpoint(method="GET", path="/search", query_params=["term"])
    kinds = _kinds(_plan([ep], aggressive=True))
    assert "type_confusion_probe" in kinds


def test_standard_depth_does_not_add_type_confusion_probes():
    ep = Endpoint(method="GET", path="/search", query_params=["term"])
    kinds = _kinds(_plan([ep], aggressive=False))
    assert "type_confusion_probe" not in kinds
