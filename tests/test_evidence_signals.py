"""Measuring an undecided result instead of asking a person to eyeball it.

Two things are being held here. The first is that the measurements are *right*:
a status code is attributed to the layer that produced it, a body is classified
by what it actually is, and "shares distinctive values with the owner's
response" means the owner's data and not the shared field names every response
in the API has.

The second, and the one that matters more, is the boundary of what measurement
is allowed to settle. Every rule that returns PASS is a rule that can hide a
real bug, so each of them is tested from both sides: the case it settles, and
the neighbouring case it must refuse to settle. A rule that says "a 404 where
403 was expected is the same security decision" must stop dead the moment the
404's body carries the victim's record.
"""

from app.analysis.evidence_signals import (
    analyze_evidence,
    body_shape,
    classify_body,
    measure,
    status_layer,
)
from app.schemas.enums import Confidence, OwaspApiCategory, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    Execution,
    SupportingExchange,
    Verdict,
)
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)

OWNER_BODY = (
    '{"id": 2002, "name": "Beth Halloran", "email": "beth.halloran@example.com", '
    '"phone": "+61 400 111 222", "account": "ACC-88213"}'
)


def _test(expected=(403, 404), mutation="swap_object_id", category=OwaspApiCategory.API1):
    return TestCase(
        test_id="API1-001", title="BOLA on customer", objective="Prove ownership is enforced.",
        owasp_category=category, severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path="/customers/{customerId}"),
        attack_mutation=Mutation(kind=mutation, detail={"id_field": "customerId"}),
        expected=ExpectedResult(status_in=list(expected)),
    )


def _response(status=200, body=OWNER_BODY, headers=None):
    return CapturedResponse(status_code=status, headers=headers or {}, body=body,
                            elapsed_ms=11, size_bytes=len(body))


def _baseline(status=200, body=OWNER_BODY, persona="agent_B"):
    return SupportingExchange(
        kind="baseline", as_persona=persona,
        request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                resolved_ip="1.2.3.4", headers={}, timestamp="t"),
        response=_response(status, body) if status else None,
        note="positive control",
    )


def _execution(test, response=None, supporting=None, result=TestStatus.INCONCLUSIVE):
    return Execution(
        execution_id="E-1", test_id=test.test_id,
        owasp_category=test.owasp_category.value, scope_validated=True,
        request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                resolved_ip="1.2.3.4",
                                headers={"Authorization": "********"}, timestamp="t"),
        response=_response() if response is None else response,
        verdict=Verdict(result=result, confidence=Confidence.LOW,
                        expected_summary=f"status in {test.expected.status_in}",
                        actual_summary="observed", reason="nothing decided it"),
        supporting=supporting or [],
    )


# -- the measurements themselves ---------------------------------------------


def test_a_status_is_attributed_to_the_layer_that_produced_it():
    assert status_layer(200) == "success"
    assert status_layer(401) == "auth"
    assert status_layer(403) == "auth"
    assert status_layer(404) == "notfound"
    assert status_layer(422) == "validation"
    assert status_layer(429) == "throttled"
    assert status_layer(503) == "server"
    assert status_layer(None) == "none"


def test_a_www_authenticate_header_promotes_a_refusal_to_the_auth_layer():
    """The layer naming itself on the wire outranks our table of status codes."""
    assert status_layer(400, {"WWW-Authenticate": 'Bearer realm="api"'}) == "auth"


def test_a_body_is_classified_by_what_it_actually_is():
    assert classify_body("")[0] == "empty"
    assert classify_body("{}")[0] == "empty"
    assert classify_body('{"detail": "Forbidden"}')[0] == "error_envelope"
    assert classify_body(OWNER_BODY)[0] == "object"
    assert classify_body('{"data": [1, 2, 3]}')[:2] == ("collection", 3)
    assert classify_body("[]")[:2] == ("empty", 0)
    assert classify_body("<html><body>nope</body></html>")[0] == "html"


def test_two_records_of_the_same_kind_share_a_shape_and_an_error_does_not():
    """The cluster key rests on this: same shape means same reading task."""
    beth = body_shape('{"id": 2002, "name": "Beth"}')
    carl = body_shape('{"id": 2003, "name": "Carl"}')
    assert beth == carl
    assert body_shape('{"detail": "Forbidden"}') != beth


def test_a_collection_of_ten_and_a_collection_of_eleven_are_one_shape():
    assert (body_shape('{"data": [{"id": 1}, {"id": 2}]}')
            == body_shape('{"data": [{"id": 9}, {"id": 8}, {"id": 7}]}'))


def test_shared_boilerplate_is_not_counted_as_shared_data():
    """Field names, status words and short ids are in every response.

    If those counted, every pair of responses from the same API would look like
    a disclosure, and the whole measurement would be noise.
    """
    test = _test()
    execution = _execution(
        test,
        response=_response(body='{"status": "ok", "id": 7, "active": true}'),
        supporting=[_baseline(body='{"status": "ok", "id": 9, "active": true}')],
    )
    signals = analyze_evidence(test, execution)
    assert signals.shared_values == 0


def test_the_owners_distinctive_values_are_counted_when_they_do_come_back():
    test = _test()
    leaked = OWNER_BODY[:-1] + ', "request_id": "req-777"}'
    execution = _execution(test, response=_response(body=leaked),
                           supporting=[_baseline()])
    signals = analyze_evidence(test, execution)
    assert signals.shared_values >= 3
    assert signals.similarity > 0.9


# -- what measurement may settle ---------------------------------------------


def test_an_identical_body_is_a_break_with_no_model_involved():
    test = _test()
    reading = measure(test, _execution(test, supporting=[_baseline()]))
    assert reading is not None
    assert reading.result == "FAIL"
    assert reading.rule == "identical_body"


def test_a_trivially_short_identical_body_settles_nothing():
    """`{"ok":true}` is identical for every caller on earth."""
    test = _test()
    execution = _execution(test, response=_response(body='{"ok":true}'),
                           supporting=[_baseline(body='{"ok":true}')])
    assert measure(test, execution) is None


def test_a_near_identical_body_carrying_the_owners_data_is_a_break():
    """The realistic shape of a leak: one differing timestamp, everything else
    the owner's. Byte-equality misses it; this does not."""
    test = _test()
    leaked = OWNER_BODY[:-1] + ', "retrieved_at": "2026-08-21T04:00:00Z"}'
    reading = measure(test, _execution(test, response=_response(body=leaked),
                                       supporting=[_baseline()]))
    assert reading is not None
    assert reading.result == "FAIL"
    assert reading.rule == "correlated_disclosure"


def test_the_attackers_own_record_is_not_read_as_a_leak():
    """Same schema, same field names, different owner — a PASS-shaped response
    that a similarity threshold alone would call a break."""
    test = _test()
    own = ('{"id": 4711, "name": "Adam Prentice", "email": "adam.prentice@example.com", '
           '"phone": "+61 400 999 888", "account": "ACC-11007"}')
    reading = measure(test, _execution(test, response=_response(body=own),
                                       supporting=[_baseline()]))
    assert reading is None, "shared field names are not shared data"


def test_an_empty_result_set_where_the_owner_gets_records_is_the_control_holding():
    test = _test()
    execution = _execution(
        test,
        response=_response(body='{"data": []}'),
        supporting=[_baseline(body='{"data": [{"id": 2002}, {"id": 2003}]}')],
    )
    reading = measure(test, execution)
    assert reading is not None
    assert reading.result == "PASS"
    assert reading.rule == "filtered_collection"


def test_a_200_carrying_a_refusal_is_the_control_holding():
    test = _test()
    execution = _execution(test, response=_response(body='{"error": "Access denied"}'),
                           supporting=[_baseline()])
    reading = measure(test, execution)
    assert reading is not None
    assert reading.result == "PASS"
    assert reading.rule == "refusal_in_body"


def test_a_200_complaining_about_the_input_is_not_settled_as_safe():
    """A validation message means a layer AFTER authentication answered. That is
    a question for a reader, not a PASS."""
    test = _test()
    execution = _execution(
        test, response=_response(body='{"error": "customerId must be an integer"}'),
        supporting=[_baseline()],
    )
    assert measure(test, execution) is None


def test_a_rate_limiter_answering_is_a_control_pushing_back():
    test = _test()
    reading = measure(test, _execution(test, response=_response(429, body="")))
    assert reading is not None
    assert reading.result == "PASS"
    assert reading.rule == "throttled"


def test_the_same_layer_answering_with_a_different_code_is_the_same_decision():
    """The largest source of avoidable review work: which *code* the auth layer
    returns is a guess about the implementation, not a requirement. No positive
    control needed — the layer the test was aiming at is the layer that
    answered."""
    test = _test(expected=(403,))
    reading = measure(test, _execution(test, response=_response(401, body='{"error": "Unauthorized"}')))
    assert reading is not None
    assert reading.result == "PASS"
    assert reading.rule == "equivalent_refusal"


def test_an_auth_refusal_is_accepted_wherever_any_security_refusal_was():
    """401/403 is the strongest refusal available and the one that cannot
    secretly mean "there was nothing here to protect"."""
    test = _test(expected=(400, 403, 404, 422))
    reading = measure(test, _execution(test, response=_response(403, body="")))
    assert reading is not None
    assert reading.result == "PASS"


def test_a_bare_404_where_only_an_auth_refusal_was_expected_is_not_settled():
    """The mirror of the anti-pattern `verdict.py` refuses. A 404 with no
    positive control is indistinguishable from a wrong object id against which
    nothing was ever tested — reading it as PASS would be a false negative
    wearing the most confident label the system can print."""
    test = _test(expected=(403,))
    execution = _execution(test, response=_response(404, body='{"detail": "Not found"}'))
    assert measure(test, execution) is None


def test_a_404_the_positive_control_proves_is_deliberate_is_the_control_holding():
    """With the object proven reachable for its owner, hiding it from another
    identity is a decision the server made — often the better of the two, since
    a 403 confirms the object exists."""
    test = _test(expected=(403,))
    execution = _execution(test, response=_response(404, body='{"detail": "Not found"}'),
                           supporting=[_baseline()])
    reading = measure(test, execution)
    assert reading is not None
    assert reading.result == "PASS"
    assert reading.rule == "equivalent_refusal"
    assert "positive control proves" in reading.rationale


def test_a_refusal_that_still_leaked_the_owners_data_is_never_a_pass():
    """The rules above must stop dead here. A 404 with the victim's record in the
    body is a disclosure that happens to carry a refusal status."""
    test = _test(expected=(403,))
    execution = _execution(test, response=_response(404, body=OWNER_BODY),
                           supporting=[_baseline()])
    reading = measure(test, execution)
    assert reading is None or reading.result == "FAIL"


def test_a_validation_rejection_where_authentication_was_required_is_not_settled():
    """400 instead of 401 is the case where the control may never have run. It
    is exactly what a reader is for, so measurement must not answer it."""
    test = _test(expected=(401,), mutation="drop_auth")
    execution = _execution(test, response=_response(400, body='{"detail": "field required"}'))
    assert measure(test, execution) is None


def test_a_failed_positive_control_is_never_settled_by_measurement():
    """Nothing about the attacker's response can fix a target that was
    unreachable for its rightful owner — that is a test-data problem."""
    test = _test()
    execution = _execution(test, response=_response(404, body=""),
                           supporting=[_baseline(status=404, body='{"detail": "Not found"}')])
    assert measure(test, execution) is None


def test_a_result_the_runner_already_decided_is_never_re_read_as_equivalent():
    """`equivalent_refusal` is scoped to INCONCLUSIVE. A sealed verdict is the
    record; measurement does not get a second opinion on it."""
    test = _test(expected=(403,))
    execution = _execution(test, response=_response(404, body=""), result=TestStatus.FAIL)
    reading = measure(test, execution)
    assert reading is None or reading.rule != "equivalent_refusal"


def test_a_server_error_settles_nothing():
    test = _test()
    assert measure(test, _execution(test, response=_response(500, body="oops"))) is None


def test_an_echoed_injection_is_recorded_but_never_settles_anything():
    """Plenty of APIs echo the payload they were handed without storing a byte
    of it. Proving persistence is what a read-back is for."""
    test = _test(mutation="inject_property", category=OwaspApiCategory.API3)
    test.attack_mutation = Mutation(kind="inject_property",
                                    detail={"properties": {"role": "admin"}})
    body = '{"id": 4711, "role": "admin", "name": "Adam"}'
    execution = _execution(test, response=_response(body=body))
    signals = analyze_evidence(test, execution)
    assert signals.echoed_mutation
    assert any(s.key == "mutation_echoed" and s.strength == "weak" for s in signals.signals)
    assert measure(test, execution, signals) is None


def test_the_measured_differential_reaches_the_prompt_as_facts_not_conclusions():
    test = _test()
    signals = analyze_evidence(test, _execution(test, supporting=[_baseline()]))
    block = signals.as_prompt_block()
    assert "identical" in block.lower()
    assert "[FAIL/decisive]" in block
