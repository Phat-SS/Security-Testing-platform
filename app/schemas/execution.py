"""Execution + evidence schema.

Every execution captures the full request/response pair, the security verdict,
and a tamper-evident hash so the evidence can stand up in an audit or a
dispute. Secrets are redacted *before* anything is stored here.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .enums import Confidence, TestStatus


class CapturedRequest(BaseModel):
    method: str
    url: str  # final absolute URL actually sent (post scope-validation)
    resolved_ip: str  # the IP the host resolved to and that we pinned
    headers: dict[str, str]  # already redacted
    body: str | None = None
    timestamp: str  # ISO-8601, injected by the runner (not generated in-schema)


class CapturedResponse(BaseModel):
    status_code: int
    headers: dict[str, str]  # already redacted
    body: str  # truncated to the configured output cap
    elapsed_ms: int
    size_bytes: int


class Verdict(BaseModel):
    """The security evaluation. `reason` must always explain *why*, in terms of
    the mutation and the comparison — never just "status was 200"."""

    result: TestStatus
    confidence: Confidence
    expected_summary: str
    actual_summary: str
    reason: str


class SupportingExchange(BaseModel):
    """A non-attack request/response pair that gives the attack result meaning.

    `baseline` is the positive control (an entitled identity doing the same
    thing successfully, proving the target exists); `verification` is the
    read-back that proves the attack's effect persisted. Both are captured as
    first-class evidence because a verdict that depends on them is only as
    defensible as the exchange it depends on — an auditor must be able to see
    the baseline, not just be told it passed.
    """

    kind: Literal["baseline", "verification"]
    as_persona: str
    request: CapturedRequest
    response: CapturedResponse | None
    note: str = ""


class RepeatStats(BaseModel):
    """Aggregate of a multi-request mutation (rate-limit probe, flow abuse,
    race window). The individual responses are not all stored — the shape of
    the distribution is what the verdict reasons about."""

    sent: int
    succeeded: int
    status_counts: dict[str, int] = Field(default_factory=dict)
    throttled: bool = False  # any 429 / 503 observed
    concurrent: bool = False  # sent in parallel (race probe) vs sequentially


class CorrelationProof(BaseModel):
    """HMAC-only proof that attacker and owner responses share identity data."""

    algorithm: str = "HMAC-SHA256"
    key_id: str
    shared_fingerprints: list[str] = Field(default_factory=list)
    owner_value_count: int
    owner_coverage: float


class OastProof(BaseModel):
    token_hash: str
    callback_host: str
    observed: bool
    purpose: str = "ssrf"


class Execution(BaseModel):
    execution_id: str
    test_id: str
    owasp_category: str

    # Safety gates that MUST have passed for this record to exist.
    scope_validated: bool

    request: CapturedRequest
    response: CapturedResponse | None  # None if BLOCKED before sending
    verdict: Verdict

    # What the mutation actually did to this request, in plain language, as the
    # runner computed it ("targeted object id 2002 owned by another identity").
    # A first-class field rather than a line scraped out of `log`: every report
    # and every Jira comment has to answer "what was the attack?", and deriving
    # that by string-matching our own log prefixes would silently render blank
    # the day someone rewords a log line.
    attack_note: str = ""

    # Evidence supporting the verdict beyond the single attack exchange.
    supporting: list[SupportingExchange] = Field(default_factory=list)
    repeat: RepeatStats | None = None
    correlation: CorrelationProof | None = None
    oast: OastProof | None = None

    # Tamper-evidence: sha256 over (request, response, verdict); chained to the
    # previous execution's hash so the evidence log cannot be silently edited.
    evidence_hash: str = ""
    prev_hash: str | None = None

    # Free-form execution log lines (already redacted).
    log: list[str] = Field(default_factory=list)
