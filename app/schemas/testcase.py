"""Declarative test-case schema.

A TestCase describes an attack as *data*, never as code. The trusted runner
knows how to execute this shape; the AI/rule-engine only knows how to produce
it. This separation is what keeps the platform from becoming an arbitrary code
execution engine.
"""

from __future__ import annotations

from typing import Literal

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


def is_destructive_mutation(kind: str, detail: dict | None = None) -> bool:
    """Whether a mutation changes the request's *effective* method to a write.

    A GET probe that is re-sent as DELETE (`method_switch`, `method_override`)
    is destructive whatever its declared method says; the declared method alone
    would let it run under the default "non-destructive only" path.
    """
    detail = detail or {}
    if kind == "method_override":
        return str(detail.get("method", "DELETE")).upper() in DESTRUCTIVE_METHODS
    if kind == "method_switch":
        return str(detail.get("method", "")).upper() in DESTRUCTIVE_METHODS
    return False

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
    be classified by *what was changed*, not guessed from a status code. The
    authoritative list lives in `app.execution.mutations.MUTATION_KINDS`; an
    unknown kind is rejected by the runner rather than improvised, which is
    also what keeps an AI planner from inventing an attack the trusted runner
    has never been reviewed to perform.
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


class VerificationStep(BaseModel):
    """A follow-up request that proves the attack actually changed server state.

    Mass assignment is the motivating case: injecting `role=admin` and getting
    HTTP 200 proves nothing on its own — the property may have been silently
    dropped. Re-reading the object and finding the injected value is what turns
    a guess into evidence. Without this the verdict can only ever be
    INCONCLUSIVE, which is honest but not useful.
    """

    as_persona: str = Field(alias="as")
    request: RequestSpec
    # If any of these strings appears in the verification response body, the
    # attack's effect persisted → confirmed exploit (not merely 'accepted').
    proves_exploit_if_contains: list[TemplateStr] = Field(default_factory=list)
    proves_exploit_when: list["InvariantAssertion"] = Field(default_factory=list)
    description: str = ""

    model_config = {"populate_by_name": True}


class InvariantAssertion(BaseModel):
    """A machine-checkable post-attack state invariant."""

    json_path: str
    operator: Literal["equals", "not_equals", "gt", "gte", "lt", "lte", "contains"]
    expected: str | int | float | bool
    description: str = ""


class OastExpectation(BaseModel):
    """Out-of-band callback expected only if the target performed the fetch."""

    purpose: Literal["ssrf", "redirect", "generic"] = "ssrf"
    description: str = ""


class BaselineSpec(BaseModel):
    """Positive control — run the *same* request as an identity that legitimately
    should succeed, before concluding the attack was 'correctly rejected'.

    Why this exists: a BOLA test whose victim object id is stale/nonexistent
    returns 404, which the verdict would otherwise read as "authorization
    enforced — PASS, high confidence". That is a false negative wearing a
    confident label. If the legitimate owner *also* gets 404, the test never
    exercised the control at all and the only honest answer is INCONCLUSIVE.
    """

    as_persona: str = Field(alias="as")
    # None → reuse the test's own request (the common case: same object, but
    # requested by the identity that actually owns it).
    request: RequestSpec | None = None
    success_status_in: list[int] = Field(default_factory=lambda: [200, 201, 202, 204])
    description: str = ""

    model_config = {"populate_by_name": True}


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

    # -- response-header assertions (API8 hardening / CORS probes) -----------
    # {header_name: substring}. If the response carries that header AND its
    # value contains the substring, the control failed. Header names are
    # matched case-insensitively. e.g. {"access-control-allow-origin":
    # "evil.example"} catches an origin-reflecting CORS policy.
    forbidden_response_headers: dict[str, TemplateStr] = Field(default_factory=dict)
    # Header names that MUST be present on a hardened response.
    required_response_headers: list[str] = Field(default_factory=list)

    # -- multi-request assertions (API4 rate limits / API6 flow abuse) -------
    # When the mutation sends N requests, at most this many may succeed before
    # throttling is expected to kick in. None → no limit asserted.
    max_successful_repeats: int | None = None

    # -- observed-vulnerability assertions (injection / traversal probes) -----
    # Regular expressions that should NEVER match the attack's response. A match
    # is a directly observed fingerprint (a DB error string, an evaluated
    # template, /etc/passwd content) — the same standing as a forbidden header,
    # not an inference from a status code.
    vulnerable_body_patterns: list[str] = Field(default_factory=list)
    # Upper bound on the response size. Lets an unbounded-pagination probe be
    # measured (the server served a huge page) instead of inferred.
    max_response_bytes: int | None = None


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
    # Positive control, run BEFORE the attack. Establishes that the thing being
    # protected is actually reachable by someone entitled to it, so a rejection
    # of the attack means "the control worked" rather than "nothing was there".
    baseline: BaselineSpec | None = None
    request: RequestSpec
    attack_mutation: Mutation
    # Read-back, run AFTER the attack. Turns "the server accepted it" into
    # "the server persisted it" — the difference between a lead and a finding.
    verification: VerificationStep | None = None
    oast: OastExpectation | None = None
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
    # Which artefact this test came out of, when it came out of one:
    # "PoC 02_change_ownership.py (comment #2)", "Burp export", a Postman folder.
    # `source` says what KIND of thing proposed the test; this says WHICH one. A
    # ticket with two PoC scripts produces two groups of tests, and "which script
    # is this test replaying" is the first thing a reviewer asks of that plan —
    # a question a merged blob leaves them guessing at.
    source_ref: str = ""

    # Lifecycle. Execution is prohibited unless approval_status == APPROVED.
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    status: TestStatus = TestStatus.NOT_RUN

    def is_runnable(self) -> bool:
        return self.approval_status == ApprovalStatus.APPROVED
