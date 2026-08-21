from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Job(BaseModel):
    job_id: str
    assessment_id: str
    kind: str
    state: Literal["QUEUED", "RUNNING", "SUCCEEDED", "FAILED"]
    idempotency_key: str
    result: dict = Field(default_factory=dict)
    error: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None
