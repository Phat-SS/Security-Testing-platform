"""Cryptographic manifest tying a rendered report to its structured inputs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os

from app.schemas.decision import DerivedVerdictEvent
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.manifest import ReportManifest
from app.reporting.quality import FindingDraft, ReportVerification


def build_manifest(
    assessment_id: str,
    issue_key: str,
    input_snapshot: dict,
    executions: list[Execution],
    findings: list[Finding],
    drafts: list[FindingDraft],
    verification: ReportVerification,
    derived_events: list[DerivedVerdictEvent],
) -> ReportManifest:
    manifest = ReportManifest(
        assessment_id=assessment_id,
        issue_key=issue_key,
        input_snapshot_hash=_hash(input_snapshot),
        execution_count=len(executions),
        evidence_head_hash=executions[-1].evidence_hash if executions else "",
        finding_hashes=[_hash(item.model_dump(mode="json")) for item in findings],
        draft_hashes=[_hash(item.model_dump(mode="json")) for item in drafts],
        quality_hash=_hash(verification.model_dump(mode="json")),
        derived_event_hashes=[item.event_hash for item in derived_events],
        key_id=os.getenv("REPORT_SIGNING_KEY_ID", "local-hmac").strip(),
    )
    key = os.getenv("REPORT_SIGNING_KEY", "").encode("utf-8")
    if len(key) >= 32:
        manifest.signature = hmac.new(key, _payload(manifest), hashlib.sha256).hexdigest()
    return manifest


def verify_manifest(manifest: ReportManifest, key: str | None = None) -> bool:
    secret = (key if key is not None else os.getenv("REPORT_SIGNING_KEY", "")).encode("utf-8")
    if len(secret) < 32 or not manifest.signature:
        return False
    expected = hmac.new(secret, _payload(manifest), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, manifest.signature)


def _payload(manifest: ReportManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json", exclude={"signature"}),
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _hash(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
