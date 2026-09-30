"""Verdict logic — the anti-false-positive core. A 200 alone is never a vuln."""

from app.execution.verdict import evaluate
from app.schemas.enums import TestStatus
from app.schemas.execution import CapturedResponse
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)


def _test(status_in, must_not=None):
    return TestCase(
        test_id="T-1", title="t", objective="o",
        owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path="/x/{id}"),
        attack_mutation=Mutation(kind="swap_object_id"),
        expected=ExpectedResult(status_in=status_in, body_must_not_contain=must_not or []),
    )


def _resp(status, body="{}"):
    return CapturedResponse(status_code=status, headers={}, body=body,
                            elapsed_ms=5, size_bytes=len(body))


def test_rejected_attack_with_no_leak_is_pass():
    v = evaluate(_test([403, 404]), _resp(403), leaked_markers=[])
    assert v.result == TestStatus.PASS


def test_confirmed_leak_is_fail_high_confidence():
    v = evaluate(_test([403, 404]), _resp(200, '{"email":"beth@x.com"}'),
                 leaked_markers=["beth@x.com"])
    assert v.result == TestStatus.FAIL
    assert v.confidence.value == "HIGH"


def test_unexpected_200_without_confirmable_leak_is_inconclusive():
    # accepted the attack, but nothing to prove disclosure → NOT a finding.
    v = evaluate(_test([403, 404]), _resp(200, "{}"), leaked_markers=[])
    assert v.result == TestStatus.INCONCLUSIVE


def test_server_error_is_inconclusive():
    v = evaluate(_test([403, 404]), _resp(500), leaked_markers=[])
    assert v.result == TestStatus.INCONCLUSIVE


def test_wrong_rejection_status_is_inconclusive_not_pass():
    # BH-172: an auth test expects 401 specifically (no credential must be
    # rejected at the auth layer). Getting 400 instead means the request
    # passed authentication and was rejected by business-logic validation —
    # the control under test never ran. That must not read as "control held".
    # No baseline configured here, so tier 4c cannot fire either — this stays
    # an honest INCONCLUSIVE, not a guess in either direction.
    v = evaluate(_test([401]), _resp(400, '{"error":"Invalid data"}'), leaked_markers=[])
    assert v.result == TestStatus.INCONCLUSIVE
    assert v.result != TestStatus.PASS


def _auth_bypass_test(status_in=(401,), mutation_kind="drop_auth"):
    return TestCase(
        test_id="T-2", title="t", objective="o",
        owasp_category="API2:2023", severity="HIGH",
        auth_context=AuthContext(persona="anonymous", target_persona="agent_B"),
        request=RequestSpec(method="PUT", path="/dealer/vehicles/{id}/change-ownership"),
        attack_mutation=Mutation(kind=mutation_kind),
        expected=ExpectedResult(status_in=list(status_in)),
    )


def test_credential_removed_but_business_logic_ran_is_fail_when_baseline_succeeded():
    # BH-172, reproduced: dropping auth on the change-ownership endpoint gets
    # 400 "Invalid data" instead of 401, while the credentialed baseline
    # proves the endpoint works. That is deterministic evidence the
    # credential was never checked — no AI or human needed to seal this one.
    v = evaluate(
        _auth_bypass_test(),
        _resp(400, '{"error":"Invalid data"}'),
        leaked_markers=[],
        baseline_ok=True,
        baseline_summary="agent_B succeeded with a valid token",
    )
    assert v.result == TestStatus.FAIL
    assert v.confidence.value == "HIGH"


def test_credential_removed_stays_inconclusive_without_a_successful_baseline():
    # Same mutation and status mismatch, but the baseline was never confirmed
    # reachable (None) — tier 4c must not fire on an unproven endpoint.
    v = evaluate(
        _auth_bypass_test(),
        _resp(400, '{"error":"Invalid data"}'),
        leaked_markers=[],
        baseline_ok=None,
    )
    assert v.result == TestStatus.INCONCLUSIVE


def test_borrowed_token_is_excluded_from_the_auth_bypass_tier():
    # borrowed_token presents another persona's VALID credential — a non-401
    # response there is a BOLA-flavoured question, not proof auth was skipped.
    v = evaluate(
        _auth_bypass_test(mutation_kind="borrowed_token"),
        _resp(400, '{"error":"Invalid data"}'),
        leaked_markers=[],
        baseline_ok=True,
        baseline_summary="agent_B succeeded",
    )
    assert v.result == TestStatus.INCONCLUSIVE


def test_no_response_is_blocked():
    v = evaluate(_test([403]), None, leaked_markers=[])
    assert v.result == TestStatus.BLOCKED


def test_every_verdict_has_reason():
    for resp, leaked in [(_resp(403), []), (_resp(200, "x"), ["x"]), (_resp(200), []),
                         (_resp(500), []), (None, [])]:
        assert evaluate(_test([403]), resp, leaked).reason


# -- regression: a failed positive control must not be overridable by a leak --
#
# BH-217: dozens of executions against endpoints that reject almost every
# request with the same generic RFC 9110 "Unsupported Media Type" boilerplate
# were sealed as FAIL/CRITICAL with the identical narrative "the response
# disclosed 2 protected marker(s) belonging to another identity" — even though
# the positive control (the entitled persona hitting the same endpoint) got
# the exact same boilerplate rejection. A marker match against a target that
# is unreachable even for its rightful owner is not trustworthy evidence; see
# `evaluate`'s tier-2 gate.


def test_leak_signal_is_downgraded_to_inconclusive_when_baseline_failed():
    """The bug this closes: `leaked_markers` used to short-circuit to FAIL
    before `baseline_ok` was ever consulted, so a false-positive marker match
    against an unreachable target still sealed a confident finding."""
    v = evaluate(
        _test([401, 403]),
        _resp(415, '{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.16",'
                    '"title":"Unsupported Media Type","status":415}'),
        leaked_markers=["9110"],  # coincidental substring of the RFC boilerplate
        baseline_ok=False,
        baseline_summary="agent_B POST /x -> HTTP 415",
    )
    assert v.result == TestStatus.INCONCLUSIVE
    assert v.confidence.value == "LOW"
    assert "positive control failed" in v.actual_summary
    # The verdict must say plainly that it saw the marker and chose not to
    # trust it, not silently drop the signal.
    assert "marker match" in v.actual_summary
    assert "cannot be trusted as cross-identity disclosure" in v.reason


def test_leak_signal_still_fails_when_baseline_succeeded():
    """The gate must not swallow real evidence: once the positive control
    proves the target IS reachable by its rightful owner, a correlated leak
    is exactly as decisive as before this fix."""
    v = evaluate(
        _test([401, 403]),
        _resp(200, '{"email":"beth@x.com"}'),
        leaked_markers=["beth@x.com"],
        baseline_ok=True,
        baseline_summary="agent_B GET /x -> HTTP 200",
    )
    assert v.result == TestStatus.FAIL
    assert v.confidence.value == "HIGH"
    assert "disclosed 1 protected marker" in v.actual_summary


def test_leak_signal_unaffected_when_no_baseline_was_configured():
    """`baseline_ok=None` (no positive control at all) must not be confused
    with `False` (a positive control that was configured and failed)."""
    v = evaluate(
        _test([401, 403]),
        _resp(200, '{"email":"beth@x.com"}'),
        leaked_markers=["beth@x.com"],
        baseline_ok=None,
    )
    assert v.result == TestStatus.FAIL


# -- Phase 1: fewer false positives / less over-confident PASS ---------------

import pytest  # noqa: E402


@pytest.mark.parametrize("status", [404, 301, 302, 405, 429])
def test_auth_bypass_tier_ignores_statuses_that_do_not_show_the_request_was_processed(status):
    # A 404 (hidden route), a redirect to a login page, a 405 or a 429 say
    # nothing about whether the credential was checked: undecided, not a FAIL.
    v = evaluate(_auth_bypass_test(), _resp(status), leaked_markers=[],
                 baseline_ok=True, baseline_summary="agent_B succeeded")
    assert v.result == TestStatus.INCONCLUSIVE


@pytest.mark.parametrize("status", [200, 204, 400, 422])
def test_auth_bypass_tier_still_fires_when_the_request_was_processed(status):
    v = evaluate(_auth_bypass_test(), _resp(status), leaked_markers=[],
                 baseline_ok=True, baseline_summary="agent_B succeeded")
    assert v.result == TestStatus.FAIL


def test_rejection_without_positive_control_is_not_high_confidence():
    v = evaluate(_test([403, 404]), _resp(404), leaked_markers=[], baseline_ok=None)
    assert v.result == TestStatus.PASS
    assert v.confidence.value == "MEDIUM"
    assert "unverified" in v.actual_summary


def test_rejection_with_positive_control_stays_high_confidence():
    v = evaluate(_test([403, 404]), _resp(404), leaked_markers=[], baseline_ok=True,
                 baseline_summary="owner got 200")
    assert v.result == TestStatus.PASS
    assert v.confidence.value == "HIGH"
