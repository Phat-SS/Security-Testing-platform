from __future__ import annotations

import argparse

from .harness import evaluate, load_jsonl, metrics_json, regression_passes


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a security-agent golden JSONL set")
    parser.add_argument("candidate")
    parser.add_argument("--baseline")
    args = parser.parse_args()
    candidate = evaluate(load_jsonl(args.candidate))
    baseline = evaluate(load_jsonl(args.baseline)) if args.baseline else None
    print(metrics_json(candidate))
    passed, failures = regression_passes(candidate, baseline)
    if not passed:
        for failure in failures:
            print(f"GATE FAILED: {failure}")
        return 1
    print("GATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
