"""Deterministic security test designer.

Turns an IssueAnalysis into concrete, declarative TestCases using the mutation
primitives the trusted runner understands. Every generated case arrives
`approval_status=PENDING` — nothing is runnable until a human approves.

This is the rule-engine-driven backbone. An AI designer can add nuance on top,
but this guarantees baseline coverage deterministically and is what the unit
tests pin down.
"""

from __future__ import annotations

from app.schemas.analysis import Endpoint, IssueAnalysis
from app.schemas.enums import (
    ApprovalStatus,
    OwaspApiCategory,
    Severity,
    TestSource,
)
from app.schemas.testcase import (
    DESTRUCTIVE_METHODS,
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)


class TestDesigner:
    def __init__(self, attacker: str = "agent_A", victim: str = "agent_B") -> None:
        # Two distinct identities are required for BOLA/BFLA. Callers pass the
        # persona names that exist in the vault.
        self._attacker = attacker
        self._victim = victim

    def design(self, analysis: IssueAnalysis) -> list[TestCase]:
        tests: list[TestCase] = []
        counters: dict[OwaspApiCategory, int] = {}
        applicable = set(analysis.applicable_categories())

        for ep in analysis.endpoints:
            if OwaspApiCategory.API1 in applicable and ep.object_id_params:
                tests.append(self._bola(ep, counters))
            if OwaspApiCategory.API2 in applicable and ep.auth_required:
                tests.append(self._no_auth(ep, counters))
                tests.append(self._bad_token(ep, counters))
            if OwaspApiCategory.API5 in applicable and self._is_privileged(ep):
                tests.append(self._bfla(ep, counters))
            if OwaspApiCategory.API3 in applicable and ep.writes_properties:
                tests.append(self._bopla(ep, counters))
            if OwaspApiCategory.API4 in applicable and self._is_expensive(ep, analysis):
                tests.append(self._resource(ep, counters))
            if OwaspApiCategory.API7 in applicable and ep.url_fields:
                tests.append(self._ssrf(ep, counters))

        return tests

    # -- generators (one per attack perspective) ----------------------------

    def _bola(self, ep: Endpoint, c) -> TestCase:
        id_field = ep.object_id_params[0]
        return self._mk(
            OwaspApiCategory.API1, c, Severity.HIGH, ep,
            title=f"BOLA: {self._attacker} accesses another identity's object via {ep.signature}",
            objective=f"Verify object-level authorization on {ep.signature}.",
            auth=AuthContext(persona=self._attacker, target_persona=self._victim),
            mutation=Mutation(kind="swap_object_id", detail={"id_field": id_field}),
            expected=ExpectedResult(status_in=[403, 404]),
            destructive=ep.method in {"DELETE", "PUT", "PATCH"},
        )

    def _no_auth(self, ep: Endpoint, c) -> TestCase:
        return self._mk(
            OwaspApiCategory.API2, c, Severity.HIGH, ep,
            title=f"Broken auth: unauthenticated {ep.signature} must be rejected",
            objective="Verify the endpoint rejects requests with no credential.",
            auth=AuthContext(persona="anonymous", target_persona=self._victim),
            mutation=Mutation(kind="drop_auth"),
            expected=ExpectedResult(status_in=[401]),
        )

    def _bad_token(self, ep: Endpoint, c) -> TestCase:
        return self._mk(
            OwaspApiCategory.API2, c, Severity.MEDIUM, ep,
            title=f"Broken auth: malformed token on {ep.signature} must be rejected",
            objective="Verify the endpoint rejects a malformed/expired token.",
            auth=AuthContext(persona=self._attacker, target_persona=self._victim),
            mutation=Mutation(kind="tamper_token"),
            expected=ExpectedResult(status_in=[401]),
        )

    def _bfla(self, ep: Endpoint, c) -> TestCase:
        return self._mk(
            OwaspApiCategory.API5, c, Severity.HIGH, ep,
            title=f"BFLA: lower-privileged user invokes {ep.signature}",
            objective="Verify function-level authorization on a privileged endpoint.",
            auth=AuthContext(persona=self._attacker, target_persona=self._victim),
            mutation=Mutation(kind="escalate_persona"),
            expected=ExpectedResult(status_in=[403]),
            destructive=ep.method in {"DELETE", "PUT", "PATCH"},
        )

    def _bopla(self, ep: Endpoint, c) -> TestCase:
        return self._mk(
            OwaspApiCategory.API3, c, Severity.HIGH, ep,
            title=f"BOPLA / mass assignment on {ep.signature}",
            objective="Verify the caller cannot set privileged object properties.",
            auth=AuthContext(persona=self._attacker, target_persona=self._victim),
            mutation=Mutation(kind="inject_property",
                              detail={"properties": {"role": "admin", "is_admin": True}}),
            expected=ExpectedResult(status_in=[400, 403, 422]),
        )

    def _resource(self, ep: Endpoint, c) -> TestCase:
        return self._mk(
            OwaspApiCategory.API4, c, Severity.MEDIUM, ep,
            title=f"Resource consumption on {ep.signature}",
            objective="Verify limits on oversized/expensive input.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="oversized_payload", detail={"field": "q", "size": 200000}),
            expected=ExpectedResult(status_in=[400, 413, 414, 422]),
        )

    def _ssrf(self, ep: Endpoint, c) -> TestCase:
        return self._mk(
            OwaspApiCategory.API7, c, Severity.HIGH, ep,
            title=f"SSRF via server-consumed URL on {ep.signature}",
            objective="Verify the server rejects internal/metadata URL targets.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="ssrf_url",
                              detail={"field": ep.url_fields[0],
                                      "value": "http://169.254.169.254/latest/meta-data/"}),
            expected=ExpectedResult(status_in=[400, 403, 422]),
        )

    # -- helpers ------------------------------------------------------------

    def _mk(self, category, counters, severity, ep, *, title, objective, auth,
            mutation, expected, destructive=False) -> TestCase:
        counters[category] = counters.get(category, 0) + 1
        num = counters[category]
        cat_num = category.value.split(":")[0]  # "API1"
        # Any state-changing method is destructive by default — a broken control
        # means the write actually happened. Gate it out of default execution.
        destructive = destructive or ep.method.upper() in DESTRUCTIVE_METHODS
        return TestCase(
            test_id=f"{cat_num}-{num:03d}",
            title=title,
            objective=objective,
            owasp_category=category,
            severity=severity,
            auth_context=auth,
            request=RequestSpec(method=ep.method, path=ep.path),
            attack_mutation=mutation,
            expected=expected,
            evidence_required=["request", "response"],
            is_destructive=destructive,
            source=TestSource.RULE_ENGINE,
            approval_status=ApprovalStatus.PENDING,
        )

    def _is_privileged(self, ep: Endpoint) -> bool:
        return ep.method in {"DELETE", "PUT", "PATCH"} or "admin" in ep.path.lower()

    def _is_expensive(self, ep: Endpoint, analysis: IssueAnalysis) -> bool:
        low = ep.path.lower()
        return any(k in low for k in ("search", "export", "bulk", "list", "report"))
