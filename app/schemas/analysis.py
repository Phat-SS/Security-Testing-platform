"""Analysis schema — the structured understanding of a ticket.

Produced by the analyzer (heuristic or AI), consumed by the test designer and
the OWASP coverage dashboard. Kept as a strict Pydantic contract so an AI
implementation's output is validated before anything downstream trusts it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .enums import Applicability, OwaspApiCategory

CoverageState = Literal["COVERED", "PARTIAL", "MISSING", "NOT_APPLICABLE", "UNKNOWN"]


class Endpoint(BaseModel):
    method: str
    path: str
    auth_required: bool = True
    # Path/body params that look like object identifiers (BOLA/BOPLA surface).
    object_id_params: list[str] = Field(default_factory=list)
    # True if the request carries a body whose properties could be tampered.
    writes_properties: bool = False
    # Fields that carry a server-consumed URL (SSRF surface).
    url_fields: list[str] = Field(default_factory=list)

    @property
    def signature(self) -> str:
        return f"{self.method.upper()} {self.path}"


class OwaspMapping(BaseModel):
    category: OwaspApiCategory
    applicability: Applicability
    reason: str
    matched_signals: list[str] = Field(default_factory=list)
    # How well existing PoCs already cover this category.
    existing_coverage: CoverageState = "UNKNOWN"
    coverage_pct: int = 0


class IssueAnalysis(BaseModel):
    issue_key: str
    business_summary: str = ""
    actors: list[str] = Field(default_factory=list)
    sensitive_operation: bool = False
    business_impact: str = ""

    endpoints: list[Endpoint] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)

    # PoC signals detected in the ticket (references, not executed code).
    detected_pocs: list[str] = Field(default_factory=list)

    def applicable_categories(self) -> list[OwaspApiCategory]:
        return [
            m.category
            for m in self.owasp_mappings
            if m.applicability == Applicability.APPLICABLE
        ]
