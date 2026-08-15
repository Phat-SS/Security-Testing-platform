"""Tamper-evident evidence hashing.

Each execution is hashed over its (request, response, verdict) and chained to
the previous execution's hash. If anyone edits an evidence record after the
fact, the chain breaks and verification fails. Cheap to compute, expensive to
forge — exactly what a security report needs to be defensible.
"""

from __future__ import annotations

import hashlib
import json

from app.schemas.execution import Execution


def compute_hash(execution: Execution) -> str:
    payload = {
        "test_id": execution.test_id,
        "request": execution.request.model_dump(),
        "response": execution.response.model_dump() if execution.response else None,
        "verdict": execution.verdict.model_dump(),
        "prev_hash": execution.prev_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def seal(execution: Execution, prev_hash: str | None) -> Execution:
    """Attach prev_hash and the computed evidence_hash to an execution."""
    execution.prev_hash = prev_hash
    execution.evidence_hash = compute_hash(execution)
    return execution


def verify_chain(executions: list[Execution]) -> bool:
    """Return True iff every hash recomputes and the chain links are intact."""
    prev: str | None = None
    for ex in executions:
        if ex.prev_hash != prev:
            return False
        expected = compute_hash(ex)
        if ex.evidence_hash != expected:
            return False
        prev = ex.evidence_hash
    return True
