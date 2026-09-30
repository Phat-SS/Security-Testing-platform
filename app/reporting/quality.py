"""Structured finding narratives and machine-checkable report quality gates.

The writer (deterministic today, AI-enrichable later) produces data, never HTML.
The verifier then checks that every finding has a draft and that every claimed
piece of evidence names an execution actually present in the report. Renderers
consume the verified structure; they do not ask a model to improvise prose.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.core.redaction import redact_text
from app.schemas.enums import Confidence, Severity
from app.schemas.execution import Execution
from app.schemas.finding import Finding, cvss_estimate
from app.schemas.testcase import TestCase


class EvidenceReference(BaseModel):
    execution_id: str
    test_id: str
    source: Literal[
        "attack", "baseline", "verification", "verdict", "correlation", "oast",
        "derived_verdict",
    ]
    evidence_hash: str = ""
    claim: str


class FindingDraft(BaseModel):
    finding_id: str
    title: str
    root_cause: str
    affected_asset: str
    preconditions: list[str] = Field(default_factory=list)
    reproduction: list[str] = Field(default_factory=list)
    expected: str
    observed: str
    impact: str
    severity: Severity
    confidence: Confidence
    cwe: list[str] = Field(default_factory=list)
    cvss_vector: str = ""
    recommendation: str
    retest_criteria: list[str] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    author: Literal["deterministic", "ai"] = "deterministic"
    prompt_version: str = ""
    model_id: str = ""


class ReportQualityIssue(BaseModel):
    code: str
    finding_id: str = ""
    detail: str
    severity: Literal["error", "warning"] = "error"


class ReportVerification(BaseModel):
    ok: bool
    checked_findings: int
    checked_references: int
    issues: list[ReportQualityIssue] = Field(default_factory=list)


def build_finding_drafts(
    findings: list[Finding], tests: dict[str, TestCase], executions: list[Execution]
) -> list[FindingDraft]:
    latest: dict[str, Execution] = {}
    for execution in executions:
        latest[execution.test_id] = execution

    drafts: list[FindingDraft] = []
    for finding in findings:
        relevant = [latest[test_id] for test_id in finding.affected_tests if test_id in latest]
        preconditions: list[str] = []
        for test_id in finding.affected_tests:
            test = tests.get(test_id)
            if test is None:
                continue
            preconditions.extend(test.preconditions)
            preconditions.append(f"Authenticate as persona '{test.auth_context.persona}'.")
        evidence: list[EvidenceReference] = []
        for execution in relevant:
            evidence.append(EvidenceReference(
                execution_id=execution.execution_id,
                test_id=execution.test_id,
                source="verdict",
                evidence_hash=execution.evidence_hash,
                claim=execution.verdict.actual_summary,
            ))
            for exchange in execution.supporting:
                evidence.append(EvidenceReference(
                    execution_id=execution.execution_id,
                    test_id=execution.test_id,
                    source=exchange.kind,
                    evidence_hash=execution.evidence_hash,
                    claim=exchange.note or f"{exchange.kind} exchange captured",
                ))
            if execution.correlation is not None:
                evidence.append(EvidenceReference(
                    execution_id=execution.execution_id,
                    test_id=execution.test_id,
                    source="correlation",
                    evidence_hash=execution.evidence_hash,
                    claim=(f"HMAC correlation matched "
                           f"{len(execution.correlation.shared_fingerprints)}/"
                           f"{execution.correlation.owner_value_count} distinctive owner values"),
                ))
            if execution.oast is not None:
                evidence.append(EvidenceReference(
                    execution_id=execution.execution_id,
                    test_id=execution.test_id,
                    source="oast",
                    evidence_hash=execution.evidence_hash,
                    claim=("Out-of-band callback observed by the configured verifier."
                           if execution.oast.observed else
                           "No out-of-band callback was observed during the polling window."),
                ))
            if finding.derived_event_id:
                evidence.append(EvidenceReference(
                    execution_id=execution.execution_id,
                    test_id=execution.test_id,
                    source="derived_verdict",
                    evidence_hash=execution.evidence_hash,
                    claim=(f"{finding.decision_source} decision "
                           f"{finding.derived_event_id} derives from this sealed evidence"),
                ))
        references = [ref for ref in finding.references if ref.upper().startswith("CWE-")]
        drafts.append(FindingDraft(
            finding_id=finding.finding_id,
            title=finding.title,
            root_cause=finding.dedup_key.rsplit("|", 1)[-1],
            affected_asset=finding.endpoint,
            preconditions=list(dict.fromkeys(preconditions)),
            reproduction=finding.reproduction,
            expected=finding.correlation.expected,
            observed=finding.correlation.actual,
            impact=finding.impact,
            severity=finding.severity,
            confidence=finding.confidence,
            cwe=references,
            cvss_vector=finding.cvss_vector or cvss_estimate(finding.severity),
            recommendation=finding.recommendation,
            retest_criteria=[
                "Repeat every affected test with the same authorized personas and fixture data.",
                "Confirm the attack is rejected and the positive control still succeeds.",
                "Confirm no protected marker, persisted state change, or privileged capability is exposed.",
            ],
            evidence=evidence,
        ))
    return drafts


def verify_report(
    findings: list[Finding], drafts: list[FindingDraft], executions: list[Execution]
) -> ReportVerification:
    issues: list[ReportQualityIssue] = []
    by_execution = {execution.execution_id: execution for execution in executions}
    by_draft = {draft.finding_id: draft for draft in drafts}
    references = 0

    if len(by_draft) != len(drafts):
        issues.append(ReportQualityIssue(
            code="duplicate_finding_draft", detail="Two drafts share one finding id."
        ))

    for finding in findings:
        draft = by_draft.get(finding.finding_id)
        if draft is None:
            issues.append(ReportQualityIssue(
                code="missing_finding_draft", finding_id=finding.finding_id,
                detail="The confirmed finding has no structured report draft.",
            ))
            continue
        if draft.severity != finding.severity or draft.confidence != finding.confidence:
            issues.append(ReportQualityIssue(
                code="classification_mismatch", finding_id=finding.finding_id,
                detail="Draft severity/confidence differs from the confirmed finding.",
            ))
        if not draft.reproduction or not draft.retest_criteria:
            issues.append(ReportQualityIssue(
                code="incomplete_instructions", finding_id=finding.finding_id,
                detail="Reproduction and retest criteria are both required.",
            ))
        if not draft.evidence:
            issues.append(ReportQualityIssue(
                code="missing_evidence_reference", finding_id=finding.finding_id,
                detail="A confirmed finding must cite at least one captured execution.",
            ))
        for reference in draft.evidence:
            references += 1
            execution = by_execution.get(reference.execution_id)
            if execution is None or execution.test_id != reference.test_id:
                issues.append(ReportQualityIssue(
                    code="invalid_evidence_reference", finding_id=finding.finding_id,
                    detail=f"Evidence reference {reference.execution_id} does not resolve.",
                ))
            elif reference.evidence_hash != execution.evidence_hash:
                issues.append(ReportQualityIssue(
                    code="evidence_hash_mismatch", finding_id=finding.finding_id,
                    detail=f"Evidence reference {reference.execution_id} has the wrong hash.",
                ))

        for value in _narrative_values(draft):
            if redact_text(value) != value:
                issues.append(ReportQualityIssue(
                    code="unredacted_secret", finding_id=finding.finding_id,
                    detail="A finding narrative contains secret-shaped material.",
                ))
                break

    extra = sorted(set(by_draft) - {finding.finding_id for finding in findings})
    for finding_id in extra:
        issues.append(ReportQualityIssue(
            code="orphan_finding_draft", finding_id=finding_id,
            detail="Draft has no corresponding confirmed finding.", severity="warning",
        ))

    return ReportVerification(
        ok=not any(issue.severity == "error" for issue in issues),
        checked_findings=len(findings),
        checked_references=references,
        issues=issues,
    )


def _narrative_values(draft: FindingDraft) -> list[str]:
    return [
        draft.title, draft.root_cause, draft.affected_asset, draft.expected,
        draft.observed, draft.impact, draft.recommendation,
        *draft.preconditions, *draft.reproduction, *draft.retest_criteria,
        *(reference.claim for reference in draft.evidence),
    ]
