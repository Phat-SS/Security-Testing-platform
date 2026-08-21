"""Offline, deterministic scoring for candidate agent outputs."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class GoldenCase(BaseModel):
    case_id: str
    expected_failures: set[str] = Field(default_factory=set)
    observed_failures: set[str] = Field(default_factory=set)
    valid_execution_ids: set[str] = Field(default_factory=set)
    cited_execution_ids: set[str] = Field(default_factory=set)
    manual_review_ids: set[str] = Field(default_factory=set)
    total_executions: int = 0


class EvalMetrics(BaseModel):
    cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    evidence_hallucinations: int
    evidence_citations: int
    evidence_hallucination_rate: float
    manual_review: int
    executions: int
    manual_touch_rate: float


def load_jsonl(path: str | Path) -> list[GoldenCase]:
    cases: list[GoldenCase] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            cases.append(GoldenCase.model_validate_json(line))
        except Exception as exc:  # noqa: BLE001 - include fixture location
            raise ValueError(f"Invalid golden case at line {line_number}: {exc}") from exc
    if not cases:
        raise ValueError("Golden set is empty")
    return cases


def evaluate(cases: list[GoldenCase]) -> EvalMetrics:
    tp = fp = fn = hallucinations = citations = manual = executions = 0
    for case in cases:
        tp += len(case.expected_failures & case.observed_failures)
        fp += len(case.observed_failures - case.expected_failures)
        fn += len(case.expected_failures - case.observed_failures)
        citations += len(case.cited_execution_ids)
        hallucinations += len(case.cited_execution_ids - case.valid_execution_ids)
        manual += len(case.manual_review_ids)
        executions += case.total_executions
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return EvalMetrics(
        cases=len(cases), true_positive=tp, false_positive=fp, false_negative=fn,
        precision=precision, recall=recall,
        f1=_ratio(2 * precision * recall, precision + recall),
        evidence_hallucinations=hallucinations, evidence_citations=citations,
        evidence_hallucination_rate=_ratio(hallucinations, citations),
        manual_review=manual, executions=executions,
        manual_touch_rate=_ratio(manual, executions),
    )


def regression_passes(
    candidate: EvalMetrics,
    baseline: EvalMetrics | None = None,
    *,
    min_precision: float = 0.95,
    min_recall: float = 0.90,
    max_hallucination_rate: float = 0.0,
    max_manual_touch_rate: float = 0.20,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    checks = (
        (candidate.precision < min_precision,
         f"precision {candidate.precision:.3f} < {min_precision:.3f}"),
        (candidate.recall < min_recall,
         f"recall {candidate.recall:.3f} < {min_recall:.3f}"),
        (candidate.evidence_hallucination_rate > max_hallucination_rate,
         f"evidence hallucination rate {candidate.evidence_hallucination_rate:.3f} > "
         f"{max_hallucination_rate:.3f}"),
        (candidate.manual_touch_rate > max_manual_touch_rate,
         f"manual touch rate {candidate.manual_touch_rate:.3f} > {max_manual_touch_rate:.3f}"),
    )
    failures.extend(message for failed, message in checks if failed)
    if baseline is not None:
        if candidate.precision < baseline.precision:
            failures.append("precision regressed versus baseline")
        if candidate.recall < baseline.recall:
            failures.append("recall regressed versus baseline")
        if candidate.evidence_hallucination_rate > baseline.evidence_hallucination_rate:
            failures.append("evidence hallucination rate regressed versus baseline")
        if candidate.manual_touch_rate > baseline.manual_touch_rate:
            failures.append("manual touch rate regressed versus baseline")
    return not failures, failures


def metrics_json(metrics: EvalMetrics) -> str:
    return json.dumps(metrics.model_dump(), indent=2, sort_keys=True)


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
