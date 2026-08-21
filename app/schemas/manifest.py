from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ReportManifest(BaseModel):
    manifest_version: str = "report-manifest.v1"
    assessment_id: str
    issue_key: str
    input_snapshot_hash: str
    execution_count: int
    evidence_head_hash: str = ""
    finding_hashes: list[str] = Field(default_factory=list)
    draft_hashes: list[str] = Field(default_factory=list)
    quality_hash: str
    derived_event_hashes: list[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    algorithm: str = "HMAC-SHA256"
    key_id: str = ""
    signature: str = ""

    @property
    def signed(self) -> bool:
        return bool(self.signature)
