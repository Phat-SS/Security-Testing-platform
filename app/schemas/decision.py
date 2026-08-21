"""Append-only decisions derived from sealed execution evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from .enums import Confidence, TestStatus


class DerivedVerdictEvent(BaseModel):
    """A policy decision beside an Execution; it never rewrites that Execution."""

    event_id: str
    execution_id: str
    test_id: str
    parent_evidence_hash: str
    sealed_result: TestStatus
    derived_result: Literal["PASS", "FAIL"]
    confidence: Confidence
    source: Literal["measured", "ai_consensus"]
    policy_version: str
    promoted: bool
    reason: str
    rule: str = ""
    evidence_cited: list[str] = Field(default_factory=list)
    model_id: str = ""
    prompt_hash: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_hash: str = ""
