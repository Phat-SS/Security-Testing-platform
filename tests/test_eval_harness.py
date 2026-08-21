import json

from app.evals.harness import GoldenCase, evaluate, load_jsonl, regression_passes


def test_eval_metrics_measure_false_findings_hallucinations_and_manual_work():
    metrics = evaluate([GoldenCase(
        case_id="C-1",
        expected_failures={"T-1", "T-2"},
        observed_failures={"T-1", "T-3"},
        valid_execution_ids={"E-1", "E-2"},
        cited_execution_ids={"E-1", "invented"},
        manual_review_ids={"E-2"},
        total_executions=4,
    )])
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.evidence_hallucination_rate == 0.5
    assert metrics.manual_touch_rate == 0.25


def test_regression_gate_rejects_a_candidate_worse_than_shadow_baseline():
    baseline = evaluate([GoldenCase(
        case_id="base", expected_failures={"T"}, observed_failures={"T"},
        total_executions=1,
    )])
    candidate = baseline.model_copy(update={"precision": 0.9})
    passed, failures = regression_passes(candidate, baseline)
    assert passed is False
    assert any("precision" in failure for failure in failures)


def test_jsonl_loader_reports_the_bad_line(tmp_path):
    path = tmp_path / "golden.jsonl"
    path.write_text(json.dumps({"case_id": "ok"}) + "\nnot-json\n", encoding="utf-8")
    try:
        load_jsonl(path)
    except ValueError as exc:
        assert "line 2" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("invalid JSONL should fail closed")
