"""Analysis schema — the structured understanding of a ticket.

Produced by the analyzer (heuristic or AI), consumed by the test designer and
the OWASP coverage dashboard. Kept as a strict Pydantic contract so an AI
implementation's output is validated before anything downstream trusts it.
"""

from __future__ import annotations

import hashlib
import json

from typing import Literal

from pydantic import BaseModel, Field

from .agent import RequirementItem
from .enums import Applicability, OwaspApiCategory

CoverageState = Literal["COVERED", "PARTIAL", "MISSING", "NOT_APPLICABLE", "UNKNOWN"]


class Endpoint(BaseModel):
    method: str
    path: str
    auth_required: bool = True
    # Declares that this route is intentionally reachable without a credential —
    # independent of `auth_required`, and takes precedence over it for API2: a
    # 200 without auth here is the correct, expected result, not a finding. Left
    # False (the default) leaves auth_required's existing behaviour untouched.
    expected_public: bool = False
    # Path/body params that look like object identifiers (BOLA/BOPLA surface).
    object_id_params: list[str] = Field(default_factory=list)
    # True if the request carries a body whose properties could be tampered.
    writes_properties: bool = False
    # Fields that carry a server-consumed URL (SSRF surface).
    url_fields: list[str] = Field(default_factory=list)
    # Declared input surface, when a spec (or a person) knows it. Injection and
    # pagination probes aim at these instead of guessing a field called "q".
    query_params: list[str] = Field(default_factory=list)
    body_fields: list[str] = Field(default_factory=list)
    # True when a human typed this endpoint in the UI rather than the analyzer
    # extracting it from the ticket. Re-analyzing the ticket rebuilds the
    # extracted rows and would otherwise silently discard hand-entered ones,
    # which are exactly the rows the analyzer's regex was unable to find.
    manual: bool = False

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


class DetectedPocScript(BaseModel):
    """One PoC script found in the ticket, kept as its own file.

    Mirrors `app.poc.jira_extract.PocScript` — a schema type rather than the
    dataclass because this is persisted inside the analysis blob and has to
    validate on the way back out of the database.
    """

    filename: str
    code: str
    # "description", "comment #2", "attachment: 02_write.py".
    origin: str = "description"
    language: str = "python"
    # The block carried no language tag and was accepted because it parses as
    # Python and calls an HTTP library. Surfaced so a reviewer gives the inferred
    # ones a harder look before approving anything generated from them.
    inferred: bool = False

    @property
    def label(self) -> str:
        return f"{self.filename} ({self.origin})"


class IssueAnalysis(BaseModel):
    issue_key: str
    business_summary: str = ""
    actors: list[str] = Field(default_factory=list)
    sensitive_operation: bool = False
    business_impact: str = ""

    endpoints: list[Endpoint] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)

    # The discrete things the ticket asks for, extracted from its acceptance
    # criteria and security-relevant bullets. The denominator of the "% of the
    # ticket covered" figure, and one of the inputs the planning and reviewing
    # agents read — so a requirement that only ever appears in prose still gets
    # a test aimed at it. Defaulted, so an analysis blob stored by an earlier
    # version still validates.
    requirements: list[RequirementItem] = Field(default_factory=list)

    # PoC signals detected in the ticket (references, not executed code).
    detected_pocs: list[str] = Field(default_factory=list)
    # Raw PoC source extracted from the ticket, pending a human's review in the
    # Design step — never transpiled/executed until the tester looks at it and
    # submits the design form themselves. Several scripts are banner-separated
    # (`app/poc/jira_extract.combined_poc_source`); this is the *presentation*
    # of the list below, which is what the transpiler is driven from.
    detected_poc_source: str = ""
    # The scripts as separate files. A ticket with two PoCs is the normal case,
    # not the edge case, and the two have to stay apart: transpiling a merged
    # blob resolves one file's requests against the other file's constants,
    # because the transpiler tracks assignments in one symbol table in source
    # order. Kept so the Design step can show "2 scripts found: 01_reach.py,
    # 02_write.py" and every generated test can name which one it came from.
    detected_poc_scripts: list[DetectedPocScript] = Field(default_factory=list)
    # `.py` files attached to the ticket whose contents the connector could not
    # download. Recorded rather than dropped: a ticket reporting one script while
    # silently missing the other reads as "this ticket has one PoC", which is
    # worse than saying a file needs pasting in by hand.
    unreachable_poc_attachments: list[str] = Field(default_factory=list)

    # The ticket text the analysis was derived from (summary + description +
    # acceptance criteria + comments, as joined by the analyzer). Kept so that
    # editing the endpoint list can re-derive the text-based OWASP signals
    # without re-fetching the issue from Jira — the alternative was to
    # recompute mappings from endpoints alone, which silently loses every
    # signal that lives in prose ("bulk export", "admin role", "JWT").
    source_text: str = ""
    # Provenance of the fuzzy extraction stage. Empty on the deterministic
    # analyzer; populated by Claude so model/prompt drift is auditable.
    ai_metadata: dict[str, object] = Field(default_factory=dict)
    # Jira input manifest (including completeness flags and content hash). A
    # coverage claim without this provenance cannot say what it covered.
    input_snapshot: dict[str, object] = Field(default_factory=dict)

    # Fingerprint of the endpoint list at the moment the current test plan was
    # generated. Compared against the live endpoints to tell a tester their
    # plan no longer matches the endpoints it was derived from, instead of
    # letting them approve and run a plan built for a stale surface.
    plan_fingerprint: str = ""

    def endpoints_fingerprint(self) -> str:
        return endpoints_fingerprint(self.endpoints)

    def plan_is_stale(self) -> bool:
        """True when a plan exists but was generated from a different endpoint
        list than the one now stored."""
        return bool(self.plan_fingerprint) and self.plan_fingerprint != self.endpoints_fingerprint()

    def applicable_categories(self) -> list[OwaspApiCategory]:
        return [
            m.category
            for m in self.owasp_mappings
            if m.applicability == Applicability.APPLICABLE
        ]


def endpoints_fingerprint(endpoints: list[Endpoint]) -> str:
    """A stable hash of everything about an endpoint list that changes what the
    designer would generate. Method/path alone is not enough: flipping
    `auth_required` or adding an `object_id_param` changes the test plan without
    changing any signature."""
    payload = [
        [
            ep.method.upper(),
            ep.path,
            ep.auth_required,
            ep.expected_public,
            sorted(ep.object_id_params),
            ep.writes_properties,
            sorted(ep.url_fields),
        ]
        for ep in endpoints
    ]
    payload.sort(key=lambda row: (row[0], row[1]))
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
