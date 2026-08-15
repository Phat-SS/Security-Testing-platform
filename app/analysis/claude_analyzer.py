"""Claude-backed analyzer (optional, real).

Implements the same `analyze(issue) -> IssueAnalysis` shape as HeuristicAnalyzer
but uses the Anthropic API. Enabled only when USE_AI=true and ANTHROPIC_API_KEY
is set; otherwise the platform runs fully on the deterministic path.

Design guarantees preserved:
  * AI output is NEVER trusted directly — it is parsed and validated against the
    IssueAnalysis Pydantic schema before anything downstream uses it. On any
    validation failure we fall back to the heuristic analyzer rather than
    letting malformed AI output into the pipeline.
  * The AI describes; it does not execute and it does not choose a target host.
"""

from __future__ import annotations

import json
import os

from app.analysis.extractor import HeuristicAnalyzer
from app.mcp.jira import NormalizedIssue
from app.schemas.analysis import IssueAnalysis

_SYSTEM = """You are a senior API security analyst. Given a Jira ticket, extract
a structured security analysis. Identify HTTP endpoints (method + path), object
identifier parameters, whether auth is required, URL/webhook fields, and which
OWASP API Security Top 10 (2023) categories are APPLICABLE with a reason.
Return ONLY JSON matching the provided schema. Do not invent target hostnames.
Mark a category NOT_APPLICABLE rather than guessing."""


class ClaudeAnalyzer:
    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        self._model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self._fallback = HeuristicAnalyzer()

    @staticmethod
    def is_enabled() -> bool:
        return os.getenv("USE_AI", "false").lower() == "true" and bool(
            os.getenv("ANTHROPIC_API_KEY")
        )

    def analyze(self, issue: NormalizedIssue) -> IssueAnalysis:
        try:
            import anthropic  # imported lazily so the SDK is an optional dep
        except ImportError:
            return self._fallback.analyze(issue)

        if not self._api_key:
            return self._fallback.analyze(issue)

        schema = IssueAnalysis.model_json_schema()
        prompt = (
            f"Ticket {issue.issue_key}:\n"
            f"Summary: {issue.summary}\n"
            f"Description:\n{issue.description}\n"
            f"Acceptance criteria: {issue.acceptance_criteria}\n\n"
            f"Return JSON for this schema (issue_key must be {issue.issue_key!r}):\n"
            f"{json.dumps(schema)}"
        )
        try:
            client = anthropic.Anthropic(api_key=self._api_key)
            msg = client.messages.create(
                model=self._model,
                max_tokens=2000,
                system=_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in msg.content if block.type == "text")
            payload = _extract_json(text)
            analysis = IssueAnalysis.model_validate_json(payload)
            # Never trust the AI's issue_key — pin it.
            analysis.issue_key = issue.issue_key
            return analysis
        except Exception:
            # Any API/parse/validation failure → deterministic fallback.
            return self._fallback.analyze(issue)


def _extract_json(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model response")
    return text[start : end + 1]


def build_analyzer():
    """Factory: the hardened staged Claude analyzer if enabled & configured,
    else the deterministic analyzer. The staged analyzer itself falls back to
    heuristic per-issue on any AI/validation failure."""
    if ClaudeAnalyzer.is_enabled():
        from app.analysis.staged import ClaudeLLM, StagedAnalyzer

        return StagedAnalyzer(ClaudeLLM())
    return HeuristicAnalyzer()
