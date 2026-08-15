"""Sample approved test cases + persona vault for the demo.

In the real system these come from: OWASP rule engine → AI test designer →
human approval. Here we hand-write two, already APPROVED, to drive the runner.
"""

from __future__ import annotations

from app.schemas import (
    ApprovalStatus,
    AuthContext,
    ExpectedResult,
    Mutation,
    OwaspApiCategory,
    RequestSpec,
    Severity,
    TestCase,
    TestSource,
)
from app.vault import Persona, PersonaVault


def build_vault() -> PersonaVault:
    return PersonaVault(
        [
            Persona(
                name="agent_A",
                auth_headers={"Authorization": "Bearer tokenA"},
                role="agent",
                owns={"customer_id": "1001"},
                secret_markers=["alice.buyer@example.com"],
            ),
            Persona(
                name="agent_B",
                auth_headers={"Authorization": "Bearer tokenB"},
                role="agent",
                owns={"customer_id": "2002"},
                # If this appears in agent_A's response, data has leaked.
                secret_markers=["beth.victim@example.com", "555-0202"],
            ),
        ]
    )


def build_tests() -> list[TestCase]:
    bola = TestCase(
        test_id="API1-001",
        title="BOLA: agent_A reads agent_B's customer object",
        objective="Verify object-level authorization on GET /customers/{id}.",
        owasp_category=OwaspApiCategory.API1,
        severity=Severity.HIGH,
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        preconditions=["agent_A authenticated", "agent_B owns customer 2002"],
        request=RequestSpec(method="GET", path="/customers/{customer_id}"),
        attack_mutation=Mutation(kind="swap_object_id", detail={"id_field": "customer_id"}),
        expected=ExpectedResult(
            status_in=[403, 404],
            body_must_not_contain=["beth.victim@example.com"],
        ),
        evidence_required=["request", "response"],
        source=TestSource.MANUAL,
        approval_status=ApprovalStatus.APPROVED,
    )

    auth = TestCase(
        test_id="API2-001",
        title="Broken auth: unauthenticated read must be rejected",
        objective="Verify GET /customers/{id} rejects requests with no token.",
        owasp_category=OwaspApiCategory.API2,
        severity=Severity.HIGH,
        auth_context=AuthContext(persona="anonymous", target_persona="agent_B"),
        preconditions=["customer 2002 exists"],
        request=RequestSpec(method="GET", path="/customers/{customer_id}"),
        attack_mutation=Mutation(kind="drop_auth"),
        expected=ExpectedResult(status_in=[401], body_must_not_contain=["beth.victim@example.com"]),
        source=TestSource.MANUAL,
        approval_status=ApprovalStatus.APPROVED,
    )
    return [bola, auth]
