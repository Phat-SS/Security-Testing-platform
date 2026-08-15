"""Finding schema — the deduplicated, human-facing security result.

Many test cases can point at the same underlying weakness (three BOLA tests on
the same endpoint = one finding). A Finding groups them and carries the
correlation evidence that justifies the verdict.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

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

    # Dedup key: (owasp_category, endpoint, mutation_kind). Findings sharing a
    # key are one finding; the individual tests land in affected_tests.
    dedup_key: str
    affected_tests: list[str] = Field(default_factory=list)

    correlation: CorrelationEvidence
    impact: str
    reproduction: list[str] = Field(default_factory=list)
    recommendation: str
    references: list[str] = Field(default_factory=list)  # CWE / OWASP / ASVS

    @staticmethod
    def make_dedup_key(category: OwaspApiCategory, endpoint: str, mutation_kind: str) -> str:
        return f"{category.value}|{endpoint}|{mutation_kind}"
