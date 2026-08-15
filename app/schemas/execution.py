"""Execution + evidence schema.

Every execution captures the full request/response pair, the security verdict,
and a tamper-evident hash so the evidence can stand up in an audit or a
dispute. Secrets are redacted *before* anything is stored here.
"""

from __future__ import annotations

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


class Execution(BaseModel):
    execution_id: str
    test_id: str
    owasp_category: str

    # Safety gates that MUST have passed for this record to exist.
    scope_validated: bool

    request: CapturedRequest
    response: CapturedResponse | None  # None if BLOCKED before sending
    verdict: Verdict

    # Tamper-evidence: sha256 over (request, response, verdict); chained to the
    # previous execution's hash so the evidence log cannot be silently edited.
    evidence_hash: str = ""
    prev_hash: str | None = None

    # Free-form execution log lines (already redacted).
    log: list[str] = Field(default_factory=list)
