"""Staged AI analysis framework.

The spec's rule: no single giant prompt. Work is split into stages; each stage's
output is parsed and validated against a Pydantic schema before the next stage
runs, and any failure falls back to the deterministic path. Crucially, the LLM
only *extracts* (endpoints, fields, auth); the deterministic rule engine decides
*which OWASP categories apply*. That keeps consistency where it matters and uses
the model only for the fuzzy reading task.

The full 9-stage catalogue is declared in STAGES for traceability; the analysis
path wires the extraction stage. The generation/verdict/finding/report "stages"
are already implemented deterministically elsewhere (test_designer, verdict,
pipeline.findings, orchestrator.comment_preview) and are referenced here so the
architecture is legible end to end.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, Field, ValidationError

from app.analysis.extractor import HeuristicAnalyzer
from app.mcp.jira import NormalizedIssue
from app.owasp.rules import RequirementSignals, evaluate
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping


class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


@dataclass(frozen=True)
class PromptStage:
    key: str
    purpose: str
    validated_by: str  # name of the Pydantic model / deterministic component


STAGES: list[PromptStage] = [
    PromptStage("requirement", "Business flow, actors, sensitive ops", "ExtractionResult"),
    PromptStage("api", "Endpoints, params, object ids, auth, URL fields", "ExtractionResult"),
    PromptStage("poc", "Existing PoC coverage", "poc.transpiler (static)"),
    PromptStage("owasp_map", "Applicable OWASP categories + reasons", "owasp.rules (deterministic)"),
    PromptStage("generate", "Security test cases", "analysis.test_designer"),
    PromptStage("review", "Self-review of generated tests", "schema validation + human approval"),
    PromptStage("result", "Analyze execution result", "execution.verdict (deterministic)"),
    PromptStage("finding", "Generate findings", "pipeline.findings (deterministic)"),
    PromptStage("report", "Jira comment / report", "orchestrator.comment_preview"),
]

_EXTRACTION_SYSTEM = """You are an API security analyst. Read the ticket and
extract, as JSON only, the concrete HTTP surface. Do not decide vulnerabilities,
do not invent hostnames. Schema:
{"business_summary": str, "actors": [str], "sensitive_operation": bool,
 "endpoints": [{"method": str, "path": str, "auth_required": bool,
 "object_id_params": [str], "writes_properties": bool, "url_fields": [str]}]}"""


class ExtractionResult(BaseModel):
    """Validated output of the LLM extraction stage — the ONLY thing we trust
    from the model, and only after this validates."""

    business_summary: str = ""
    actors: list[str] = Field(default_factory=list)
    sensitive_operation: bool = False
    endpoints: list[Endpoint] = Field(default_factory=list)


class StagedAnalyzer:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm
        self._fallback = HeuristicAnalyzer()
        # See ClaudeAnalyzer.last_fallback_reason — same contract, read by the
        # orchestrator and written to the audit trail.
        self.last_fallback_reason: str = ""

    def analyze(self, issue: NormalizedIssue) -> IssueAnalysis:
        self.last_fallback_reason = ""
        try:
            extraction = self._extract(issue)
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            # AI output invalid → do NOT proceed with garbage; fall back.
            self.last_fallback_reason = f"extraction stage failed — {type(exc).__name__}: {exc}"
            return self._fallback.analyze(issue)
        except Exception as exc:  # noqa: BLE001 - transport/auth failures too
            # Previously these escaped and broke the whole import. A staged
            # analyzer whose first stage cannot reach the API should degrade to
            # the deterministic path like every other AI failure mode.
            self.last_fallback_reason = f"LLM call failed — {type(exc).__name__}: {exc}"
            return self._fallback.analyze(issue)

        # Deterministic OWASP mapping from the extracted surface. The model does
        # not get to choose applicability.
        signals = _signals_from(extraction, issue)
        mappings = [
            OwaspMapping(category=h.category, applicability=h.applicability,
                         reason=h.reason, matched_signals=h.matched_signals,
                         existing_coverage="MISSING")
            for h in evaluate(signals)
        ]
        return IssueAnalysis(
            issue_key=issue.issue_key,
            business_summary=extraction.business_summary or issue.summary,
            actors=extraction.actors,
            sensitive_operation=extraction.sensitive_operation,
            endpoints=extraction.endpoints,
            owasp_mappings=mappings,
        )

    def _extract(self, issue: NormalizedIssue) -> ExtractionResult:
        user = (
            f"Ticket {issue.issue_key}\nSummary: {issue.summary}\n"
            f"Description:\n{issue.description}\n"
            f"Acceptance criteria: {issue.acceptance_criteria}"
        )
        raw = self._llm.complete(_EXTRACTION_SYSTEM, user)
        payload = raw[raw.find("{"): raw.rfind("}") + 1]
        return ExtractionResult.model_validate_json(payload)


def _signals_from(extraction: ExtractionResult, issue: NormalizedIssue) -> RequirementSignals:
    ids, url_fields, writes = [], [], False
    for ep in extraction.endpoints:
        ids += ep.object_id_params
        url_fields += ep.url_fields
        writes = writes or ep.writes_properties
    text = f"{issue.summary}\n{issue.description}\n" + "\n".join(
        f"{e.method} {e.path}" for e in extraction.endpoints
    )
    low = text.lower()
    return RequirementSignals(
        text=text,
        object_identifiers=sorted(set(ids)),
        has_authentication=any(e.auth_required for e in extraction.endpoints)
        or any(k in low for k in ("token", "jwt", "bearer", "auth")),
        roles=sorted({r for r in ("admin", "manager", "agent") if r in low}),
        external_url_fields=sorted(set(url_fields)),
        writes_object_properties=writes,
        bulk_or_expensive=any(k in low for k in ("bulk", "export", "search", "pagination")),
    )


class ClaudeLLM:  # pragma: no cover - requires API key
    """Real LLM client backed by the Anthropic API."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        import os

        self._model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

    def complete(self, system: str, user: str) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self._api_key)
        msg = client.messages.create(
            model=self._model, max_tokens=2000, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if b.type == "text")
