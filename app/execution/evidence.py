"""Tamper-evident evidence hashing.

Each execution is hashed over its full content and chained to the previous
execution's hash. Editing any stored record after the fact breaks the chain and
verification fails.

What this does and does not prove, stated plainly because the difference
matters in a dispute:

  * It DOES detect edits made without recomputing the chain — a row changed
    directly in the database, an exported record altered before it was filed,
    a verdict flipped in storage. That is the realistic tampering case and it
    is caught reliably.
  * It does NOT resist an adversary who can write to the database *and* run
    this code. The chain is self-referential and unkeyed: recompute every hash
    from the head and it verifies clean. This is tamper-EVIDENT, not
    tamper-PROOF, and "expensive to forge" would be an overstatement.

Closing that second gap needs a key this process does not hold: sign the head
hash with an external key, or anchor it to append-only storage outside the
application's own trust boundary. Until then, the chain's guarantee is exactly
as strong as the access control on the database.
"""

from __future__ import annotations

import hashlib
import json

from app.schemas.execution import Execution


def compute_hash(execution: Execution) -> str:
    # Covers every field a tamperer might want to change after the fact:
    # `log`/`scope_validated` narrate what happened and are exactly what an
    # attacker editing the DB post-hoc would target, so they must be inside
    # the hash, not just request/response/verdict.
    #
    # `supporting` (baseline / verification exchanges) and `repeat` are hashed
    # unconditionally — NOT "only when present". Omitting an empty value would
    # make a record with its baseline deleted hash identically to one that
    # never had a baseline, which is precisely the edit an attacker would make
    # to turn an INCONCLUSIVE-because-the-control-was-never-exercised into a
    # clean PASS. Coverage of a field cannot be optional.
    #
    # Consequence, accepted deliberately: adding these fields changes the
    # payload shape, so evidence sealed by an older version of this module no
    # longer verifies. That is the correct failure direction — a hash whose
    # definition silently varies proves nothing at all.
    payload = {
        "execution_id": execution.execution_id,
        "test_id": execution.test_id,
        "owasp_category": execution.owasp_category,
        "scope_validated": execution.scope_validated,
        "request": execution.request.model_dump(),
        "response": execution.response.model_dump() if execution.response else None,
        "verdict": execution.verdict.model_dump(),
        "attack_note": execution.attack_note,
        "supporting": [s.model_dump() for s in execution.supporting],
        "repeat": execution.repeat.model_dump() if execution.repeat else None,
        "correlation": execution.correlation.model_dump() if execution.correlation else None,
        "oast": execution.oast.model_dump() if execution.oast else None,
        "log": execution.log,
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
