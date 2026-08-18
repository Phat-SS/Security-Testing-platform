"""Turn failed executions into deduplicated findings.

A finding is only minted from an execution the runner judged FAIL (a confirmed
control break with disclosure). INCONCLUSIVE results are surfaced separately as
leads — never silently upgraded to findings. Multiple failing tests on the same
(category, endpoint, mutation) collapse into one finding.
"""

from __future__ import annotations

from app.owasp.api_top10_2023 import CONTROLS
from app.schemas.enums import OwaspApiCategory, TestStatus
from app.schemas.execution import Execution
from app.schemas.finding import CorrelationEvidence, Finding
from app.schemas.testcase import TestCase


def build_findings(
    tests: dict[str, TestCase],
    executions: list[Execution],
) -> list[Finding]:
    grouped: dict[str, list[tuple[TestCase, Execution]]] = {}

    for ex in executions:
        if ex.verdict.result != TestStatus.FAIL:
            continue
        test = tests.get(ex.test_id)
        if not test:
            continue
        endpoint = f"{test.request.method} {test.request.path}"
        key = Finding.make_dedup_key(
            test.owasp_category, endpoint, test.attack_mutation.kind
        )
        grouped.setdefault(key, []).append((test, ex))

    findings: list[Finding] = []
    for i, (key, items) in enumerate(sorted(grouped.items()), start=1):
        test, ex = items[0]  # representative
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
            actual=ex.verdict.actual_summary,
            leaked_markers=leaked,
        )

        findings.append(
            Finding(
                finding_id=f"SEC-{i:03d}",
                title=control.title,
                owasp_category=test.owasp_category,
                severity=test.severity,
                confidence=ex.verdict.confidence,
                endpoint=endpoint,
                dedup_key=key,
                # dict.fromkeys, not set(): a test re-run in a later round
                # appears twice in `items` and must be listed once, in the
                # order it was first seen rather than a hash order.
                affected_tests=list(dict.fromkeys(t.test_id for t, _ in items)),
                correlation=correlation,
                impact=_impact_for(test.owasp_category, endpoint),
                reproduction=[
                    f"Authenticate as persona '{test.auth_context.persona}'.",
                    f"Send {endpoint} with mutation '{test.attack_mutation.kind}'.",
                    f"Observe: {ex.verdict.actual_summary}.",
                ],
                recommendation=_recommendation_for(test.owasp_category),
                references=list(control.references),
            )
        )
    return findings


def leads(tests: dict[str, TestCase], executions: list[Execution]) -> list[Execution]:
    """INCONCLUSIVE executions — worth manual review, not confirmed findings."""
    return [e for e in executions if e.verdict.result == TestStatus.INCONCLUSIVE]


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
