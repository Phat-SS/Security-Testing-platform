"""Security verdict evaluation.

The core anti-pattern we refuse to commit: concluding "vulnerable" from an HTTP
200 alone. A verdict here is a function of (1) what a secure system was expected
to do, (2) what actually happened, and (3) correlation evidence — did the
attacker's response actually contain something it shouldn't?

Outputs the six-state result with a human-readable reason, always.
"""

from __future__ import annotations

from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import CapturedResponse, Verdict
from app.schemas.testcase import TestCase


def evaluate(
    test: TestCase,
    response: CapturedResponse | None,
    leaked_markers: list[str],
) -> Verdict:
    expected = test.expected
    exp_summary = f"status in {expected.status_in}" + (
        f"; body must not contain {len(expected.body_must_not_contain)} marker(s)"
        if expected.body_must_not_contain
        else ""
    )

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
    leaked = bool(leaked_markers)

    # --- The control held: attack rejected AND nothing leaked. -------------
    if status_ok and not leaked:
        return Verdict(
            result=TestStatus.PASS,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=f"HTTP {response.status_code}, no sensitive data returned",
            reason=(
                "The endpoint rejected the attack as a secure control should "
                f"(status {response.status_code} within expected set) and no "
                "protected data was disclosed."
            ),
        )

    # --- The control broke: sensitive data actually leaked. ----------------
    # This is the strongest signal — we saw the victim's marker in the
    # attacker's response. Status code is secondary here.
    if leaked:
        return Verdict(
            result=TestStatus.FAIL,
            confidence=Confidence.HIGH,
            expected_summary=exp_summary,
            actual_summary=(
                f"HTTP {response.status_code}; response disclosed protected "
                f"marker(s): {', '.join(leaked_markers)}"
            ),
            reason=(
                "The mutated request returned data belonging to another "
                "identity/object. Server-side authorization is not enforced "
                "for the requested object — the response correlates a "
                "cross-identity data leak, not merely a success status."
            ),
        )

    # --- Attack got an unexpected success status, but we could not confirm a
    #     concrete leak (e.g. empty body, no marker available). Do NOT call
    #     this a confirmed vulnerability. It is a strong lead → INCONCLUSIVE.
    if not status_ok and _looks_like_success(response.status_code):
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
            ),
        )

    # --- Server errors: not a pass, not a confirmed break. -----------------
    if response.status_code >= 500:
        return Verdict(
            result=TestStatus.INCONCLUSIVE,
            confidence=Confidence.LOW,
            expected_summary=exp_summary,
            actual_summary=f"HTTP {response.status_code} (server error)",
            reason="Server error during the attack; result is indeterminate.",
        )

    # --- Anything else: rejected in a way not in the expected set, no leak.
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


def _looks_like_success(status: int) -> bool:
    return 200 <= status < 300
