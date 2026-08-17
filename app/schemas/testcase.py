"""Declarative test-case schema.

A TestCase describes an attack as *data*, never as code. The trusted runner
knows how to execute this shape; the AI/rule-engine only knows how to produce
it. This separation is what keeps the platform from becoming an arbitrary code
execution engine.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .enums import (
    ApprovalStatus,
    ExecutionType,
    OwaspApiCategory,
    Severity,
    TestSource,
    TestStatus,
)

# Any state-changing HTTP method makes a test destructive — a broken control
# means the write actually happened. Shared by the test designer (initial
# classification) and the repository (re-classification when a test's
# request is edited), so the two can't silently drift apart.
DESTRUCTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Placeholders like {victim_id} are resolved at runtime from the persona vault
# or from values captured in a prior `setup` step. Templating is a fixed,
# whitelisted syntax — not eval — see execution.templating.
TemplateStr = str


class RequestSpec(BaseModel):
    """A single HTTP request, fully declarative."""

    method: str = Field(examples=["GET", "POST", "DELETE"])
    # Path (may contain {placeholders}); joined with the approved target base
    # URL at runtime. We never let a test carry its own absolute host — the
    # host comes from the approved scope, so a test cannot target off-scope.
    path: TemplateStr = Field(examples=["/customers/{victim_id}"])
    headers: dict[str, TemplateStr] = Field(default_factory=dict)
    query: dict[str, TemplateStr] = Field(default_factory=dict)
    body: dict | list | str | None = None
    # Named values to extract from the response for later steps,
    # as {name: json_path}. e.g. {"victim_id": "$.id"}
    capture: dict[str, str] = Field(default_factory=dict)


class SetupStep(BaseModel):
    """Preparation performed as a specific persona before the attack.

    Used to seed disposable objects (so destructive tests never touch real
    data) and to obtain a victim's object id for BOLA/BOPLA correlation.
    """

    as_persona: str = Field(alias="as")
    request: RequestSpec
    description: str = ""

    model_config = {"populate_by_name": True}


class Mutation(BaseModel):
    """The security-relevant transformation applied to a baseline request.

    `kind` is a controlled vocabulary the runner understands, so a finding can
    be classified by *what was changed*, not guessed from a status code.
    """

    kind: str = Field(
        examples=[
            "swap_object_id",  # API1: use another persona's object id
            "drop_auth",  # API2: remove the credential
            "tamper_token",  # API2: malformed / expired token
            "escalate_persona",  # API5: normal user hits admin function
            "inject_property",  # API3: send fields the caller shouldn't set
            "oversized_payload",  # API4: resource consumption
            "ssrf_url",  # API7: point a server-side fetch at metadata IP
        ]
    )
    detail: dict = Field(default_factory=dict)


class ExpectedResult(BaseModel):
    """What a SECURE system should do. Deviation is what we flag."""

    status_in: list[int] = Field(
        default_factory=lambda: [401, 403, 404],
        description="A secure control typically rejects the attack.",
    )
    body_must_not_contain: list[TemplateStr] = Field(
        default_factory=list,
        description="Sensitive markers whose presence proves data leaked "
        "(e.g. the victim's email captured during setup).",
    )
    max_response_ms: int | None = None


class AuthContext(BaseModel):
    """Which identity runs the attack request. References the persona vault by
    name — the actual secret never lives in the test case."""

    persona: str = Field(examples=["agent_A", "anonymous", "admin"])
    # For BOLA/BOPLA: whose object is being targeted. Enables ownership
    # correlation ("A read B's object") rather than status-code guessing.
    target_persona: str | None = None


class TestCase(BaseModel):
    test_id: str = Field(examples=["API1-001"])
    title: str
    objective: str
    owasp_category: OwaspApiCategory
    severity: Severity

    auth_context: AuthContext
    preconditions: list[str] = Field(default_factory=list)
    setup: list[SetupStep] = Field(default_factory=list)
    request: RequestSpec
    attack_mutation: Mutation
    expected: ExpectedResult
    evidence_required: list[str] = Field(default_factory=list)

    # Safety + provenance
    is_destructive: bool = Field(
        default=False,
        description="DELETE/PUT/state-changing. Requires seeded data and a "
        "separate approval gate.",
    )
    execution_type: ExecutionType = ExecutionType.HTTP
    source: TestSource = TestSource.AI

    # Lifecycle. Execution is prohibited unless approval_status == APPROVED.
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    status: TestStatus = TestStatus.NOT_RUN

    def is_runnable(self) -> bool:
        return self.approval_status == ApprovalStatus.APPROVED
