"""Turn sealed failures and policy-promoted derived failures into findings.

An INCONCLUSIVE execution alone remains a lead. It can become reportable only
through a hash-bound append-only event accepted by ``derived-verdict.v1``;
the sealed execution itself is never rewritten. Root-cause variants collapse.
"""

from __future__ import annotations

from app.owasp.api_top10_2023 import CONTROLS
from app.analysis.promotion import verify_event
from app.schemas.enums import OwaspApiCategory, TestStatus
from app.schemas.decision import DerivedVerdictEvent
from app.schemas.execution import Execution
from app.schemas.finding import CorrelationEvidence, Finding
from app.schemas.testcase import TestCase


def build_findings(
    tests: dict[str, TestCase],
    executions: list[Execution],
    derived_verdicts: list[DerivedVerdictEvent] | None = None,
) -> list[Finding]:
    grouped: dict[str, list[tuple[TestCase, Execution, int, DerivedVerdictEvent | None]]] = {}
    promoted = {
        event.execution_id: event
        for event in (derived_verdicts or [])
        if event.promoted and event.derived_result == "FAIL" and verify_event(event)
    }

    # Evidence is append-only, but findings describe current state. A test that
    # is actually re-run replaces its prior result; a test omitted from a later
    # partial batch retains its latest known result.
    latest: dict[str, tuple[Execution, int]] = {}
    for index, ex in enumerate(executions):
        latest[ex.test_id] = (ex, index)

    for ex, index in latest.values():
        decision = promoted.get(ex.execution_id)
        if ex.verdict.result != TestStatus.FAIL and decision is None:
            continue
        if decision is not None and decision.parent_evidence_hash != ex.evidence_hash:
            continue
        test = tests.get(ex.test_id)
        if not test:
            continue
        endpoint = f"{test.request.method} {test.request.path}"
        key = Finding.make_dedup_key(
            test.owasp_category, endpoint, _root_cause(test.attack_mutation.kind)
        )
        grouped.setdefault(key, []).append((test, ex, index, decision))

    findings: list[Finding] = []
    for i, (key, items) in enumerate(sorted(grouped.items()), start=1):
        # Explain the strongest current proof, with recency as a tie-breaker.
        test, ex, _, decision = max(
            items, key=lambda item: (_evidence_strength(item[1], item[3]), item[2])
        )
        control = CONTROLS[test.owasp_category]
        endpoint = f"{test.request.method} {test.request.path}"

        leaked = _leaked_from(ex)
        correlation = CorrelationEvidence(
            baseline_summary=(
                f"{test.auth_context.target_persona or 'owner'} legitimately "
                f"owns the targeted object"
            ),
            attack_summary=(
                f"{test.auth_context.persona} {endpoint} → "
                f"HTTP {ex.response.status_code if ex.response else 'n/a'}"
            ),
            expected=ex.verdict.expected_summary,
            actual=decision.reason if decision is not None else ex.verdict.actual_summary,
            leaked_markers=leaked,
        )

        findings.append(
            Finding(
                finding_id=f"SEC-{i:03d}",
                title=control.title,
                owasp_category=test.owasp_category,
                severity=test.severity,
                confidence=decision.confidence if decision is not None else ex.verdict.confidence,
                endpoint=endpoint,
                dedup_key=key,
                # dict.fromkeys, not set(): a test re-run in a later round
                # appears twice in `items` and must be listed once, in the
                # order it was first seen rather than a hash order.
                affected_tests=list(dict.fromkeys(t.test_id for t, _, _, _ in items)),
                correlation=correlation,
                impact=_impact_for(test.owasp_category, endpoint),
                reproduction=[
                    f"Authenticate as persona '{test.auth_context.persona}'.",
                    f"Send {endpoint} with mutation '{test.attack_mutation.kind}'.",
                    f"Observe: {decision.reason if decision is not None else ex.verdict.actual_summary}.",
                ],
                recommendation=_recommendation_for(test.owasp_category),
                references=list(control.references),
                decision_source=decision.source if decision is not None else "sealed_runner",
                derived_event_id=decision.event_id if decision is not None else "",
            )
        )
    return findings


def leads(tests: dict[str, TestCase], executions: list[Execution]) -> list[Execution]:
    """Current sealed INCONCLUSIVE executions, before any derived decision."""
    latest: dict[str, Execution] = {}
    for execution in executions:
        latest[execution.test_id] = execution
    return [e for e in latest.values() if e.verdict.result == TestStatus.INCONCLUSIVE]


_ROOT_CAUSE_BY_MUTATION = {
    "swap_object_id": "missing_object_authorization",
    "swap_id_in_query": "missing_object_authorization",
    "swap_id_in_header": "missing_object_authorization",
    "id_param_pollution": "missing_object_authorization",
    "wrap_id_array": "missing_object_authorization",
    "content_type_switch": "missing_object_authorization",
    "drop_auth": "missing_authentication_validation",
    "tamper_token": "missing_authentication_validation",
    "jwt_alg_none": "missing_jwt_signature_validation",
    "jwt_alg_confusion": "missing_jwt_signature_validation",
    "jwt_claim_tamper": "missing_jwt_signature_validation",
    "jwt_expired_replay": "missing_jwt_lifetime_validation",
    "jwt_kid_injection": "unsafe_jwt_key_selection",
    "borrowed_token": "missing_token_tenant_binding",
    "inject_property": "missing_property_authorization",
    "inject_nested_property": "missing_property_authorization",
    "escalate_persona": "missing_function_authorization",
    "method_override": "missing_function_authorization",
    "admin_path_swap": "missing_function_authorization",
    "repeat_flow": "missing_business_flow_invariant",
    "race_condition": "missing_business_flow_invariant",
    "ssrf_url": "unsafe_server_side_fetch",
    "ssrf_url_bypass": "unsafe_server_side_fetch",
}


def _root_cause(mutation_kind: str) -> str:
    """Unknown/future mutations remain distinct rather than over-merge."""
    return _ROOT_CAUSE_BY_MUTATION.get(mutation_kind, mutation_kind)


def _evidence_strength(
    execution: Execution, decision: DerivedVerdictEvent | None = None
) -> int:
    """Rank proof quality for the representative shown in the report."""
    score = {"HIGH": 30, "MEDIUM": 20, "LOW": 10}.get(
        execution.verdict.confidence.value, 0
    )
    kinds = {exchange.kind for exchange in execution.supporting}
    if "verification" in kinds:
        score += 100
    if any(line.startswith("DISCLOSURE:") for line in execution.log):
        score += 80
    if "baseline" in kinds:
        score += 20
    if execution.response is not None:
        score += 5
    if decision is not None:
        score += 40 if decision.source == "measured" else 25
    return score


def _leaked_from(ex: Execution) -> list[str]:
    for line in ex.log:
        if line.startswith("DISCLOSURE:"):
            return [line.split(":", 1)[1].strip()]
    return []


def _impact_for(category: OwaspApiCategory, endpoint: str) -> str:
    return {
        OwaspApiCategory.API1: (
            f"An authenticated user can access another user's data via {endpoint} "
            "by supplying a different object identifier."
        ),
        OwaspApiCategory.API5: (
            f"A lower-privileged user can invoke the privileged function {endpoint}."
        ),
        OwaspApiCategory.API3: (
            "A caller can read or set object properties beyond their authorization."
        ),
        OwaspApiCategory.API2: "Authentication controls can be bypassed.",
        OwaspApiCategory.API7: (
            "The server can be coerced into making requests to internal resources."
        ),
    }.get(category, f"Security control failure at {endpoint}.")


def _recommendation_for(category: OwaspApiCategory) -> str:
    return {
        OwaspApiCategory.API1: (
            "Enforce server-side authorization on every object access: verify "
            "the authenticated principal owns or may access the requested "
            "object id before returning it."
        ),
        OwaspApiCategory.API5: (
            "Enforce role/function-level authorization on the endpoint; deny by "
            "default and grant per role."
        ),
        OwaspApiCategory.API3: (
            "Whitelist which properties each role may read/write; reject "
            "unexpected fields (no mass assignment)."
        ),
        OwaspApiCategory.API2: (
            "Reject missing/expired/malformed tokens; validate signature, "
            "expiry and audience."
        ),
        OwaspApiCategory.API7: (
            "Validate and allow-list outbound URLs; block internal/link-local "
            "ranges and cloud metadata endpoints."
        ),
    }.get(category, "Apply the relevant OWASP API Security control.")
