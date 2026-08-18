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
  4. status codes            — weakest; never decisive on their own

Outputs the six-state result with a human-readable reason, always.
"""

from __future__ import annotations

from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import CapturedResponse, RepeatStats, Verdict
from app.schemas.testcase import TestCase


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

    # --- 2. Correlated cross-identity disclosure. --------------------------
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
    # This gate sits above every PASS below. A control cannot be shown to hold
    # against an attack that never reached anything.
    if baseline_ok is False:
        return Verdict(
            result=TestStatus.INCONCLUSIVE,
            confidence=Confidence.LOW,
            expected_summary=exp_summary,
            actual_summary=(
                f"HTTP {response.status_code}, but the positive control failed"
                + (f" ({baseline_summary})" if baseline_summary else "")
            ),
            reason=(
                "The identity that legitimately owns this object/function could not "
                "perform the operation either, so the target was never reachable and "
                "the attack's rejection proves nothing about authorization. Fix the "
                "test data (stale or wrong object id, missing persona entitlement) "
                "and re-run. Reporting this as PASS would be a false negative."
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

    # --- 8. Anything else: rejected in a way not in the expected set, no leak.
    return Verdict(
        result=TestStatus.PASS,
        confidence=Confidence.MEDIUM,
        expected_summary=exp_summary,
        actual_summary=f"HTTP {response.status_code}, no disclosure",
        reason=(
            f"Attack was not successful (status {response.status_code}); no "
            "protected data disclosed. Treated as control-held."
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
