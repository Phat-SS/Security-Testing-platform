"""AI analysis interface (Phase 2 stub).

Design rule from the spec: no single giant prompt. Nine staged calls, each
returning JSON validated by Pydantic before the next stage runs. AI output is
NEVER trusted directly — it passes JSON parse → Pydantic → security-rule
validation → scope validation → human approval before anything executes.

This module defines the seams. The real implementation calls the Claude API per
stage; a deterministic fake implements the same Protocol for tests. Note the AI
never proposes a *host* — targets come only from the approved scope.
"""

from __future__ import annotations

from typing import Protocol

from app.mcp.jira import NormalizedIssue
from app.owasp.rules import RequirementSignals
from app.schemas.testcase import TestCase


class SecurityAnalyzer(Protocol):
    async def extract_signals(self, issue: NormalizedIssue) -> RequirementSignals:
        """Stage 1-4: business + API + auth + object analysis → signals for the
        deterministic rule engine."""
        ...

    async def design_tests(
        self, issue: NormalizedIssue, signals: RequirementSignals
    ) -> list[TestCase]:
        """Stage 5-6: generate + self-review test cases. Every returned object
        must already validate against the TestCase schema; all arrive with
        approval_status=PENDING (execution is impossible until a human
        approves)."""
        ...
