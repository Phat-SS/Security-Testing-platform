"""Security verdict evaluation.

The core anti-pattern we refuse to commit: concluding "vulnerable" from an HTTP
200 alone. A verdict here is a function of (1) what a secure system was expected
to do, (2) what actually happened, and (3) correlation evidence — did the
attacker's response actually contain something it shouldn't?

The mirror-image anti-pattern, equally refused: concluding "safe" from an HTTP
404 alone. A rejection only means the control worked if the thing being
protected was reachable in the first place — that is what `baseline_ok` (the
positive control) establishes. Without it, a test aimed at a nonexistent object
returns 404 and would be recorded as PASS/HIGH: a false negative wearing the
most confident label the system can print.

Evidence is ranked. Strongest first:
  1. verification read-back  — the attack's effect persisted in server state
  2. correlated disclosure   — the victim's data came back in the response
  3. direct header/limit observation — the control is absent, not inferred
  4. credential-check bypass — a credential-removing mutation (API2) reached a
     business-logic rejection instead of the required auth rejection, while
     the credentialed baseline proved the endpoint works
  5. status codes            — weakest; never decisive on their own

Tier 1 needs no other identity's response to mean something: it is proven by
re-reading the object. Tier 2 is different — "the response disclosed another
identity's data" is only a meaningful claim once we know what a legitimate
response looks like, which is exactly what the positive control establishes.
So a failed positive control (`baseline_ok is False`) gates tier 2 and forces
INCONCLUSIVE even when a marker match was found: a marker "leak" against a
target that is unreachable even for its rightful owner is far more likely a
coincidental substring in shared boilerplate than a real disclosure. It does
NOT gate tier 1 (state persistence needs no baseline) or tier 3 (headers and
rate limits are observed directly, not by comparison to another identity).

Outputs the six-state result with a human-readable reason, always.
"""

from __future__ import annotations

from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import CapturedResponse, RepeatStats, Verdict
from app.schemas.testcase import TestCase

# API2 mutations that remove or invalidate the credential itself. Kept in sync
# with app.execution.mutations' API2 catalogue by hand: `borrowed_token`
# deliberately excluded — it presents another persona's VALID credential, so a
# non-401/403 response there is a different (BOLA-flavoured) question, not
# evidence the auth check itself was skipped.
_AUTH_BYPASS_MUTATION_KINDS = {
    "drop_auth",
    "tamper_token",
    "jwt_alg_none",
    "jwt_alg_confusion",
    "jwt_claim_tamper",
    "jwt_expired_replay",
    "jwt_kid_injection",
}


def evaluate(
    test: TestCase,
    response: CapturedResponse | None,
    leaked_markers: list[str],
    *,
    baseline_ok: bool | None = None,
    baseline_summary: str = "",
    verification_proof: list[str] | None = None,
    repeat: RepeatStats | None = None,
) -> Verdict:
    """`baseline_ok`: None = no positive control configured; True/False = the
    entitled identity could / could not perform the same operation.
    `verification_proof`: markers found when re-reading state after the attack.
    """
    expected = test.expected
    verification_proof = verification_proof or []
    exp_summary = _expected_summary(test)

    # No response → the request never completed (scope block, network, timeout).
    # That is BLOCKED/ERROR, decided by the runner; verdict just reflects it.
    if response is None:
        return Verdict(
            result=TestStatus.BLOCKED,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary="no response captured",
            reason="Request did not complete; nothing to evaluate.",
        )

    status_ok = response.status_code in expected.status_in

    # --- 1. The attack's effect persisted in server state. -----------------
    # Strongest possible evidence: we changed something we were not allowed to
    # change, and proved it by reading it back.
    if verification_proof:
        return Verdict(
            result=TestStatus.FAIL,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=(
                f"HTTP {response.status_code}; a follow-up read confirmed the injected "
                f"value(s) persisted: {', '.join(verification_proof)}"
            ),
            reason=(
                "The mutated request was not merely accepted — re-reading the object "
                "afterwards showed the attacker-supplied value stored on the server. "
                "The property-level control is absent, confirmed by state change "
                "rather than inferred from a status code."
            ),
        )

    # --- 3. Directly observed missing controls. ----------------------------
    # Response headers and rate limits are observed, not inferred: either the
    # header is there or it is not. These are evaluated BEFORE the status-code
    # branches because a hardening probe legitimately expects HTTP 200 — the
    # finding lives in the headers, not the status line.
    header_violations = _header_violations(test, response)
    if header_violations:
        return Verdict(
            result=TestStatus.FAIL,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=f"HTTP {response.status_code}; " + "; ".join(header_violations),
            reason=(
                "The response's own headers show the control is not configured. "
                "This is observed directly on the wire, not inferred from behaviour."
            ),
        )

    limit_violation = _limit_violation(test, repeat)
    if limit_violation:
        return Verdict(
            result=TestStatus.FAIL,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=limit_violation,
            reason=(
                "The endpoint served more successful requests than the engagement "
                "declares acceptable, with no throttling response observed. The "
                "absence of a limit is measured here, not assumed."
            ),
        )

    # --- 4. Positive control: was the attack even capable of succeeding? ---
    # This gate sits above every FAIL/PASS below EXCEPT verification_proof
    # (tier 1, checked above): that tier is state persistence, proven by
    # re-reading the object — it needs no other identity's response to mean
    # something. Correlated disclosure (tier 2, next) is not independent that
    # way: "the response disclosed another identity's data" is only a
    # meaningful claim if we know what a legitimate response looks like, and
    # that is exactly what the positive control establishes. When the
    # entitled identity could not reach the target either, a marker "match" in
    # that same unreachable response is far more likely a coincidental
    # substring in shared boilerplate (an error page, a generic template) than
    # a real leak, so it must not be allowed to silently outrank this gate.
    if baseline_ok is False:
        leak_caveat = ""
        reason_caveat = ""
        if leaked_markers:
            leak_caveat = (
                " (a marker match was also found in this response, but it is not "
                "trusted as disclosure — see reason)"
            )
            reason_caveat = (
                " A marker match was flagged in the same response, but a marker "
                "match against a target that is unreachable even for its rightful "
                "owner cannot be trusted as cross-identity disclosure — it is far "
                "more likely a coincidental substring in shared boilerplate (the "
                "same error page every caller gets) than a real leak. It is not "
                "reported as a finding here for that reason; if the marker choice "
                "itself is too short or generic, tighten it and re-run."
            )
        return Verdict(
            result=TestStatus.INCONCLUSIVE,
            confidence=Confidence.LOW,
            expected_summary=exp_summary,
            actual_summary=(
                f"HTTP {response.status_code}, but the positive control failed"
                + (f" ({baseline_summary})" if baseline_summary else "")
                + leak_caveat
            ),
            reason=(
                "The identity that legitimately owns this object/function could not "
                "perform the operation either, so the target was never reachable and "
                "the attack's rejection proves nothing about authorization. Fix the "
                "test data (stale or wrong object id, missing persona entitlement) "
                "and re-run. Reporting this as PASS would be a false negative."
                + reason_caveat
            ),
        )

    # --- 4b. Correlated cross-identity disclosure. --------------------------
    # Only reached once the positive control has NOT ruled itself out (it
    # succeeded, or none was configured) — see the gate above.
    if leaked_markers:
        # Only the COUNT, never the values. `actual_summary` and `reason` are
        # narrative fields: they are stored, exported via export.json, rendered
        # into reports and posted to Jira, and — unlike request/response — they
        # get no redact_*() pass of their own. A leaked marker is frequently a
        # session token or an API key, and a victim's email is PII either way,
        # so writing it here would make the platform re-disclose the very data
        # it is reporting as disclosed. The runner already applies exactly this
        # rule to its execution log; the verdict was the remaining hole.
        #
        # The values stay discoverable where a reader should look for them: the
        # captured response body, which IS redacted before storage.
        return Verdict(
            result=TestStatus.FAIL,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=(
                f"HTTP {response.status_code}; the response disclosed "
                f"{len(leaked_markers)} protected marker(s) belonging to another identity"
            ),
            reason=(
                "The mutated request returned data belonging to another "
                "identity/object. Server-side authorization is not enforced "
                "for the requested object — the response correlates a "
                "cross-identity data leak, not merely a success status. The "
                "disclosed values are visible in the captured response body "
                "evidence for this execution."
            ),
        )

    # --- 4c. Auth check demonstrably did not run. ---------------------------
    # Scoped narrowly to mutations that remove/tamper the credential itself
    # (API2). For these, "rejected, but not with the specific auth-rejection
    # code the expected set requires" is not ambiguous the way it is for BOLA
    # or BFLA: the positive control (baseline_ok is True, checked explicitly —
    # not merely "not False") proves the endpoint works for a credentialed
    # caller, so the only way a credential-less/tampered request reaches a
    # business-logic-style rejection (a validation 400/422, or worse a 2xx
    # handled elsewhere) instead of 401/403 is that nothing checked the
    # credential before that logic ran. That is deterministic, not inferred —
    # no AI or human needed for this specific pattern.
    if (
        baseline_ok is True
        and not status_ok
        and test.attack_mutation.kind in _AUTH_BYPASS_MUTATION_KINDS
        and response.status_code not in (401, 403)
        and response.status_code < 500
    ):
        return Verdict(
            result=TestStatus.FAIL,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=(
                f"HTTP {response.status_code} (expected {expected.status_in}); the "
                f"credentialed baseline succeeded ({baseline_summary})" if baseline_summary
                else f"HTTP {response.status_code} (expected {expected.status_in})"
            ),
            reason=(
                "The mutation removed or invalidated the credential, the endpoint is "
                "proven reachable (the credentialed positive control succeeded), and "
                f"yet the attack did not receive {expected.status_in} — it received a "
                "response that looks like business-logic processing instead of an "
                "authentication rejection. The credential was never actually checked "
                "before the request was handled."
            ),
        )

    # --- 5. The control held: attack rejected AND nothing leaked. ----------
    if status_ok:
        return Verdict(
            result=TestStatus.PASS,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=f"HTTP {response.status_code}, no sensitive data returned"
            + (f"; positive control confirmed reachable ({baseline_summary})" if baseline_ok else ""),
            reason=(
                "The endpoint rejected the attack as a secure control should "
                f"(status {response.status_code} within expected set) and no "
                "protected data was disclosed."
                + (
                    " The same operation succeeded for the entitled identity, so the "
                    "rejection reflects authorization and not an unreachable target."
                    if baseline_ok
                    else ""
                )
            ),
        )

    # --- 6. Attack got an unexpected success status, but we could not confirm
    #     a concrete leak (e.g. empty body, no marker available). Do NOT call
    #     this a confirmed vulnerability. It is a strong lead → INCONCLUSIVE.
    if _looks_like_success(response.status_code):
        return Verdict(
            result=TestStatus.INCONCLUSIVE,
            confidence=Confidence.MEDIUM,
            expected_summary=exp_summary,
            actual_summary=f"HTTP {response.status_code} (expected a rejection)",
            reason=(
                "The endpoint accepted the attack (unexpected success status) "
                "but no protected marker was available to confirm data "
                "disclosure. Manual verification required before this can be "
                "treated as a finding."
                + (
                    " Configure `secret_markers` on the target persona, or a "
                    "verification read-back on this test, to let the platform "
                    "decide this automatically."
                    if not test.verification
                    else ""
                )
            ),
        )

    # --- 7. Server errors: not a pass, not a confirmed break. --------------
    if response.status_code >= 500:
        return Verdict(
            result=TestStatus.INCONCLUSIVE,
            confidence=Confidence.LOW,
            expected_summary=exp_summary,
            actual_summary=f"HTTP {response.status_code} (server error)",
            reason="Server error during the attack; result is indeterminate.",
        )

    # --- 8. Rejected, but not with a status in the expected set, and no leak.
    # This is NOT "control held": the expected set encodes what a secure system
    # should specifically do (e.g. 401 for "no credential"), and a different
    # rejection can itself be the finding — a 400 instead of a 401 typically
    # means the request passed the authentication check and was rejected by
    # business-logic validation instead, i.e. the control being tested never
    # ran. Concluding "safe" here from the status code alone is exactly the
    # mirror-image anti-pattern this module refuses for a bare 404 (see module
    # docstring), so an unmatched status is undecided, not a confident PASS.
    return Verdict(
        result=TestStatus.INCONCLUSIVE,
        confidence=Confidence.LOW,
        expected_summary=exp_summary,
        actual_summary=f"HTTP {response.status_code} (expected {expected.status_in})",
        reason=(
            f"The attack was rejected (status {response.status_code}) but not with a "
            f"status in the expected set {expected.status_in}. No disclosure was found, "
            "but a different rejection than the one a secure system should give is not "
            "confidently 'control held' — e.g. a 400 instead of a 401 can mean the "
            "request reached business-logic validation before any authentication check "
            "ran. Manual review required."
        ),
    )


# --- helpers -----------------------------------------------------------------


def _expected_summary(test: TestCase) -> str:
    expected = test.expected
    parts = [f"status in {expected.status_in}"]
    if expected.body_must_not_contain:
        parts.append(f"body must not contain {len(expected.body_must_not_contain)} marker(s)")
    if expected.forbidden_response_headers:
        parts.append(f"{len(expected.forbidden_response_headers)} forbidden response header(s)")
    if expected.required_response_headers:
        parts.append(f"required header(s) {expected.required_response_headers}")
    if expected.max_successful_repeats is not None:
        parts.append(f"at most {expected.max_successful_repeats} successful repeat(s)")
    if expected.max_response_ms is not None:
        parts.append(f"response under {expected.max_response_ms}ms")
    return "; ".join(parts)


def _header_violations(test: TestCase, response: CapturedResponse) -> list[str]:
    """Header names are compared case-insensitively — HTTP header names are
    case-insensitive by definition, and httpx/servers disagree on casing, so a
    literal dict lookup would silently never match."""
    expected = test.expected
    lowered = {k.lower(): v for k, v in response.headers.items()}
    violations: list[str] = []

    for name, forbidden_substring in expected.forbidden_response_headers.items():
        value = lowered.get(name.lower())
        if value is None:
            continue
        if not forbidden_substring or forbidden_substring.lower() in value.lower():
            violations.append(
                f"response header '{name}' contains the disallowed value "
                f"'{forbidden_substring or value}' (got: {value!r})"
            )

    for name in expected.required_response_headers:
        if name.lower() not in lowered:
            violations.append(f"required hardening header '{name}' is absent from the response")

    if expected.max_response_ms is not None and response.elapsed_ms > expected.max_response_ms:
        violations.append(
            f"response took {response.elapsed_ms}ms, over the {expected.max_response_ms}ms budget"
        )

    return violations


def _limit_violation(test: TestCase, repeat: RepeatStats | None) -> str | None:
    ceiling = test.expected.max_successful_repeats
    if ceiling is None or repeat is None:
        return None
    if repeat.succeeded <= ceiling:
        return None
    if repeat.throttled:
        # Something did push back (429/503). The endpoint has *a* limit; it is
        # just looser than declared. That is a tuning question for the service
        # owner, not a confirmed missing control, so it does not become a FAIL.
        return None
    mode = "concurrently" if repeat.concurrent else "in sequence"
    return (
        f"{repeat.succeeded}/{repeat.sent} requests sent {mode} succeeded with no "
        f"throttling response (limit declared: {ceiling}); status spread {repeat.status_counts}"
    )


def _looks_like_success(status: int) -> bool:
    return 200 <= status < 300
