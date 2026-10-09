"""Claude-backed analyzer (optional, real).

Implements the same `analyze(issue) -> IssueAnalysis` shape as HeuristicAnalyzer
but uses the operator's local Claude Code CLI (see `ClaudeLLM` in
`app.analysis.staged`) rather than a separate Anthropic API key. Enabled only
when USE_AI=true and the `claude` CLI is installed and logged in; otherwise the
platform runs fully on the deterministic path.

Design guarantees preserved:
  * AI output is NEVER trusted directly — it is parsed and validated against the
    IssueAnalysis Pydantic schema before anything downstream uses it. On any
    validation failure we fall back to the heuristic analyzer rather than
    letting malformed AI output into the pipeline.
  * The AI describes; it does not execute and it does not choose a target host.
"""

from __future__ import annotations

import os

from app.mcp.jira import NormalizedIssue
from app.schemas.analysis import IssueAnalysis


class ClaudeAnalyzer:
    """Thin compatibility wrapper around `StagedAnalyzer(ClaudeLLM(...))` so
    callers that pre-date the staged pipeline (and `is_enabled()`, which every
    other AI-backed component gates on) keep a single, simple entry point."""

    def __init__(self, model: str | None = None) -> None:
        from app.analysis.staged import ClaudeLLM, StagedAnalyzer

        self._staged = StagedAnalyzer(ClaudeLLM(model=model))
        # Why the last analyze() did not use the AI, if it didn't. Read by the
        # orchestrator and written to the audit trail. Falling back silently
        # meant an operator who deliberately switched USE_AI on could not tell
        # a working AI path from a broken CLI login — both produced a
        # normal-looking analysis, just a thinner one.
        self.last_fallback_reason: str = ""

    @staticmethod
    def is_enabled() -> bool:
        from app.analysis.staged import ClaudeLLM

        return os.getenv("USE_AI", "false").lower() == "true" and ClaudeLLM.is_available()

    def analyze(self, issue: NormalizedIssue) -> IssueAnalysis:
        result = self._staged.analyze(issue)
        self.last_fallback_reason = self._staged.last_fallback_reason
        return result


def build_analyzer():
    """Factory: the hardened staged Claude analyzer if enabled & configured,
    else the deterministic analyzer. The staged analyzer itself falls back to
    heuristic per-issue on any AI/validation failure."""
    if ClaudeAnalyzer.is_enabled():
        from app.analysis.staged import ClaudeLLM, StagedAnalyzer

        # Extraction only restates the ticket, on every import: the one stage
        # where a smaller, faster model is enough. Planning, review and
        # adjudication keep ANTHROPIC_MODEL.
        fast = os.getenv("ANTHROPIC_MODEL_FAST", "").strip() or None
        return StagedAnalyzer(ClaudeLLM(model=fast))
    from app.analysis.extractor import HeuristicAnalyzer

    return HeuristicAnalyzer()
