"""Conservative policy for turning reviewed ambiguity into derived truth."""

from __future__ import annotations

import hashlib
import json
import re

from app.schemas.agent import Adjudication
from app.schemas.decision import DerivedVerdictEvent
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import Execution

POLICY_VERSION = "derived-verdict.v1"


def evaluate_promotion(
    execution: Execution, adjudication: Adjudication
) -> DerivedVerdictEvent | None:
    """Return an auditable policy event for a settled INCONCLUSIVE result.

    Deterministic measurement is acceptable when it names its rule. Model
    output is acceptable only after a second adversarial pass agrees, at HIGH
    confidence, with concrete evidence references and full model provenance.
    """
    if execution.verdict.result != TestStatus.INCONCLUSIVE:
        return None
    if not adjudication.settled or adjudication.assessed_result not in ("PASS", "FAIL"):
        return None

    source = None
    promoted = False
    reason = "The adjudication does not satisfy the promotion policy."
    if (
        adjudication.resolution == "measured"
        and adjudication.rule
        and adjudication.confidence == Confidence.HIGH
        and adjudication.signals
    ):
        source = "measured"
        promoted = True
        reason = f"Named deterministic evidence rule passed: {adjudication.rule}."
    elif adjudication.resolution == "ai_consensus":
        source = "ai_consensus"
        required = (
            adjudication.adjudicator == "ai"
            and adjudication.challenged
            and adjudication.challenge_agreed
            and adjudication.confidence == Confidence.HIGH
            and bool(adjudication.evidence_cited)
            and _has_grounded_citation(execution, adjudication)
            and bool(adjudication.model_id)
            and bool(adjudication.prompt_hash)
        )
        promoted = bool(required)
        reason = (
            "High-confidence AI reading survived the adversarial challenge and cites evidence."
            if promoted else
            "AI consensus lacks challenge agreement, HIGH confidence, evidence, or provenance."
        )
    else:
        # AI-only, propagated, capped and manual readings never become source
        # of record. They still remain visible in the RunAssessment.
        return None

    identity = {
        "execution_id": execution.execution_id,
        "parent_evidence_hash": execution.evidence_hash,
        "derived_result": adjudication.assessed_result,
        "source": source,
        "policy_version": POLICY_VERSION,
        "rule": adjudication.rule,
        "prompt_hash": adjudication.prompt_hash,
    }
    event_id = "DV-" + hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:20]
    event = DerivedVerdictEvent(
        event_id=event_id,
        execution_id=execution.execution_id,
        test_id=execution.test_id,
        parent_evidence_hash=execution.evidence_hash,
        sealed_result=execution.verdict.result,
        derived_result=adjudication.assessed_result,
        confidence=adjudication.confidence,
        source=source,
        policy_version=POLICY_VERSION,
        promoted=promoted,
        reason=reason,
        rule=adjudication.rule,
        evidence_cited=adjudication.evidence_cited,
        model_id=adjudication.model_id,
        prompt_hash=adjudication.prompt_hash,
    )
    payload = event.model_dump(mode="json", exclude={"event_hash"})
    event.event_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return event


def promoted_by_execution(events: list[DerivedVerdictEvent]) -> dict[str, DerivedVerdictEvent]:
    """Latest valid promoted event for each immutable execution."""
    selected: dict[str, DerivedVerdictEvent] = {}
    for event in events:
        if event.promoted:
            selected[event.execution_id] = event
    return selected


def verify_event(event: DerivedVerdictEvent) -> bool:
    payload = event.model_dump(mode="json", exclude={"event_hash"})
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return bool(event.event_hash) and event.event_hash == expected


def _has_grounded_citation(execution: Execution, adjudication: Adjudication) -> bool:
    """Reject a consensus whose citations cannot be traced to captured facts."""
    corpus_parts = [*adjudication.signals]
    if execution.response is not None:
        corpus_parts += [str(execution.response.status_code), execution.response.body]
    for exchange in execution.supporting:
        corpus_parts.append(exchange.note)
        if exchange.response is not None:
            corpus_parts += [str(exchange.response.status_code), exchange.response.body]
    corpus = " ".join(corpus_parts).lower()
    corpus_tokens = _meaningful_tokens(corpus)
    statuses = set(re.findall(r"\b[1-5]\d{2}\b", corpus))
    for citation in adjudication.evidence_cited:
        lowered = citation.lower()
        if set(re.findall(r"\b[1-5]\d{2}\b", lowered)) & statuses:
            return True
        if len(_meaningful_tokens(lowered) & corpus_tokens) >= 2:
            return True
    return False


def _meaningful_tokens(value: str) -> set[str]:
    stop = {"this", "that", "with", "from", "response", "attack", "result", "http"}
    return {token for token in re.findall(r"[a-z0-9_@.-]{4,}", value) if token not in stop}
