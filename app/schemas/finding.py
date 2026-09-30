"""Finding schema — the deduplicated, human-facing security result.

Many test cases can point at the same underlying weakness (three BOLA tests on
the same endpoint = one finding). A Finding groups them and carries the
correlation evidence that justifies the verdict.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal

from .enums import Confidence, OwaspApiCategory, Severity


class CorrelationEvidence(BaseModel):
    """Why we believe this is real — the comparison, not a single response.

    For BOLA: two requests differing only by identity/object, and the fact that
    the attacker's response contained the victim's data. This is what stops the
    engine from calling every HTTP 200 a vulnerability.
    """

    baseline_summary: str  # e.g. "agent_B GET /customers/2002 → owns object"
    attack_summary: str  # e.g. "agent_A GET /customers/2002 → 200 + B's email"
    expected: str
    actual: str
    leaked_markers: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str = Field(examples=["SEC-001"])
    title: str
    owasp_category: OwaspApiCategory
    severity: Severity
    confidence: Confidence
    endpoint: str

    # Stable root-cause fingerprint. Mutation variants are evidence for a
    # weakness, not the weakness's identity.
    dedup_key: str
    affected_tests: list[str] = Field(default_factory=list)

    correlation: CorrelationEvidence
    impact: str
    reproduction: list[str] = Field(default_factory=list)
    recommendation: str
    references: list[str] = Field(default_factory=list)  # CWE / OWASP / ASVS
    # A deterministic estimate from severity (app.reporting.quality.cvss_estimate),
    # never a full manual per-finding assessment — this platform has no signal
    # for attack complexity/privileges/scope per finding. Still a standard,
    # familiar severity anchor for a developer/manager triaging the report,
    # rather than leaving it blank. Empty for a Finding built before this field
    # existed (an older stored assessment) — never backfilled retroactively.
    cvss_vector: str = ""
    decision_source: Literal["sealed_runner", "measured", "ai_consensus"] = "sealed_runner"
    derived_event_id: str = ""

    @staticmethod
    def make_dedup_key(category: OwaspApiCategory, endpoint: str, root_cause: str) -> str:
        return f"{category.value}|{endpoint}|{root_cause}"


# A deterministic CVSS 3.1 base vector per severity tier — not a substitute for
# a manual per-finding CVSS assessment (this platform has no signal for attack
# complexity, privileges required, or scope change per finding), but a
# standard, familiar severity anchor a developer/manager already knows how to
# read, rather than shipping the field silently unpopulated. Chosen to be a
# representative, slightly conservative vector for "an authorization/data
# control failed on an API" — the shape of nearly everything this platform
# finds — network-reachable, no user interaction, low attack complexity.
_CVSS_BY_SEVERITY: dict[Severity, tuple[str, float]] = {
    Severity.CRITICAL: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    Severity.HIGH: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
    Severity.MEDIUM: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
    Severity.LOW: ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.7),
    Severity.INFO: ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N", 2.0),
}


def cvss_estimate(severity: Severity) -> str:
    """`"<vector> (<score> estimated)"` — never presented as a precise score."""
    vector, score = _CVSS_BY_SEVERITY[severity]
    return f"{vector} ({score} estimated from severity — not a full manual assessment)"


def cvss_score(severity: Severity) -> float:
    """Just the numeric anchor, for a compact table column."""
    return _CVSS_BY_SEVERITY[severity][1]
