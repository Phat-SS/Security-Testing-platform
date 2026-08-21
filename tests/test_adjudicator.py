"""The adjudicating agent: triage, reading, and the line it must not cross.

The line is the point of this file. `execution.verdict` is hashed into the
evidence chain and is the only thing that mints a finding, so an adjudication is
an opinion stored beside it — never a replacement for it. The tests below hold
that line from both sides: the adjudicator's own output shape cannot claim to be
a verdict, and the run-level aggregation cannot let an agent's reading move a
result the runner already decided.

Triage comes first because it is most of the value and needs no model: of the
undecided results, which need a person, which need only a re-run, and which are
a reading task.
"""

from app.analysis.adjudicator import ResultAdjudicator, assess_run, triage
from app.schemas.agent import Adjudication, RequirementItem
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping
from app.schemas.enums import Applicability, Confidence, OwaspApiCategory, TestStatus
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


class _ScriptedLLM:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append(user)
        return self.reply


class _BrokenLLM:
    def complete(self, system: str, user: str) -> str:
        raise RuntimeError("rate limited")


def _analysis(requirements=()):
    return IssueAnalysis(
        issue_key="CRM-1234", business_summary="Customer records API",
        endpoints=[Endpoint(method="GET", path="/customers/{customerId}",
                            object_id_params=["customerId"])],
        owasp_mappings=[OwaspMapping(category=OwaspApiCategory.API1,
                                     applicability=Applicability.APPLICABLE, reason="r")],
        requirements=list(requirements),
    )


def _test(test_id="API1-001", category="API1:2023"):
    return TestCase(
        test_id=test_id, title=test_id, objective="Prove ownership is enforced.",
        owasp_category=category, severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path="/customers/{customerId}"),
        attack_mutation=Mutation(kind="swap_object_id", detail={"id_field": "customerId"}),
        expected=ExpectedResult(status_in=[403, 404]),
    )


def _response(status=200, body='{"id": 2002, "name": "Beth"}'):
    return CapturedResponse(status_code=status, headers={}, body=body,
                            elapsed_ms=12, size_bytes=len(body))


def _baseline(status=200, body='{"id": 2002, "name": "Beth"}', persona="agent_B"):
    return SupportingExchange(
        kind="baseline", as_persona=persona,
        request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                resolved_ip="1.2.3.4", headers={}, timestamp="t"),
        response=_response(status, body) if status else None,
        note="positive control",
    )


def _execution(test, result=TestStatus.INCONCLUSIVE, response=None, supporting=None,
               reason="no protected marker was available", execution_id="E-1"):
    return Execution(
        execution_id=execution_id, test_id=test.test_id,
        owasp_category=test.owasp_category.value, scope_validated=True,
        request=CapturedRequest(method="GET", url="http://t/customers/2002",
                                resolved_ip="1.2.3.4",
                                headers={"Authorization": "********"}, timestamp="t"),
        response=_response() if response is None else response,
        verdict=Verdict(result=result, confidence=Confidence.MEDIUM,
                        expected_summary="status in [403, 404]",
                        actual_summary="HTTP 200 (expected a rejection)", reason=reason),
        supporting=supporting or [],
    )


# -- triage: who can settle this, with no model involved ----------------------


def test_a_decided_result_needs_no_review_at_all():
    for result in (TestStatus.PASS, TestStatus.FAIL):
        klass, _reason = triage(_test(), _execution(_test(), result=result))
        assert klass == "decided"


def test_a_failed_positive_control_is_a_person_not_a_reading():
    """No reading of the attacker's response can fix test data. The entitled
    identity could not perform the operation either, so the object id or the
    persona's entitlement is wrong and a human has to correct it."""
    execution = _execution(_test(), supporting=[_baseline(status=404)])
    klass, reason = triage(_test(), execution)
    assert klass == "manual"
    assert "positive control failed" in reason


def test_a_server_error_needs_a_re_run_not_a_reader():
    execution = _execution(_test(), response=_response(status=503, body="oops"))
    klass, reason = triage(_test(), execution)
    assert klass == "rerun"
    assert "transient" in reason


def test_a_runner_error_needs_a_re_run():
    klass, _reason = triage(_test(), _execution(_test(), result=TestStatus.ERROR))
    assert klass == "rerun"


def test_a_blocked_result_is_a_configuration_question_for_a_person():
    klass, reason = triage(_test(), _execution(_test(), result=TestStatus.BLOCKED))
    assert klass == "manual"
    assert "never sent" in reason


def test_an_accepted_attack_with_an_empty_body_has_nothing_to_read():
    """Being handed a reading task with nothing to read is how an agent ends up
    guessing. It is a person's problem, and the fix is configuration."""
    for body in ("", "   ", "{}", "[]", "null"):
        execution = _execution(_test(), response=_response(body=body))
        klass, reason = triage(_test(), execution)
        assert klass == "manual", body
        assert "no evidence to read" in reason or "secret_markers" in reason


def test_an_accepted_attack_with_a_body_is_a_reading_task():
    klass, reason = triage(_test(), _execution(_test()))
    assert klass == "agent"
    assert "reading task" in reason


# -- the deterministic adjudication that is a measurement ---------------------


def test_an_attacker_response_identical_to_the_baseline_is_a_break_without_a_model():
    """The strongest evidence there is, and it needs no interpretation: the
    attacker received exactly the representation the entitled owner gets."""
    body = '{"id": 2002, "name": "Beth", "email": "beth@example.com"}'
    execution = _execution(_test(), response=_response(body=body),
                           supporting=[_baseline(body=body)])
    result = ResultAdjudicator(None).adjudicate(_analysis(), _test(), execution)

    assert result.assessed_result == "FAIL"
    assert result.confidence == Confidence.HIGH
    assert result.needs_manual_review is False
    assert result.adjudicator == "deterministic"
    assert "byte-identical" in result.rationale


def test_a_trivially_short_identical_body_proves_nothing():
    """`{"ok":true}` is identical for everyone."""
    body = '{"ok":true}'
    execution = _execution(_test(), response=_response(body=body),
                           supporting=[_baseline(body=body)])
    result = ResultAdjudicator(None).adjudicate(_analysis(), _test(), execution)
    assert result.assessed_result != "FAIL"


def test_without_an_ai_a_reading_task_stays_a_human_task_and_says_so():
    result = ResultAdjudicator(None).adjudicate(_analysis(), _test(), _execution(_test()))
    assert result.needs_manual_review is True
    assert "No AI adjudicator is configured" in result.degraded_reason


def test_the_sealed_verdict_is_carried_alongside_every_opinion():
    result = ResultAdjudicator(None).adjudicate(_analysis(), _test(), _execution(_test()))
    assert result.sealed_result == TestStatus.INCONCLUSIVE
    assert result.advisory is True


# -- the AI adjudication, and its limits --------------------------------------


_FAIL_REPLY = """{"assessed_result": "FAIL", "confidence": "HIGH",
 "needs_manual_review": false,
 "rationale": "The body is a customer record owned by the victim persona.",
 "evidence_cited": ["a customer record belonging to the victim persona"],
 "recommended_action": "Re-run with a secret marker so the platform can seal it."}"""


def test_the_agent_can_settle_a_reading_task():
    result = ResultAdjudicator(_ScriptedLLM(_FAIL_REPLY)).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.assessed_result == "FAIL"
    assert result.needs_manual_review is False
    assert result.adjudicator == "ai"
    assert result.advisory is True


def test_a_fail_with_no_cited_evidence_is_downgraded_to_manual_review():
    """A FAIL assessment with nothing cited is an assertion, not a reading."""
    reply = ('{"assessed_result": "FAIL", "confidence": "HIGH", '
             '"needs_manual_review": false, "rationale": "Looks broken to me.", '
             '"evidence_cited": []}')
    result = ResultAdjudicator(_ScriptedLLM(reply)).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.assessed_result == "FAIL"
    assert result.needs_manual_review is True
    assert "Downgraded to manual review" in result.rationale


def test_an_inconclusive_reading_leaves_the_work_with_the_human():
    reply = ('{"assessed_result": "INCONCLUSIVE", "needs_manual_review": false, '
             '"rationale": "Cannot tell."}')
    result = ResultAdjudicator(_ScriptedLLM(reply)).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.needs_manual_review is True


def test_an_invented_result_word_becomes_inconclusive():
    reply = '{"assessed_result": "CATASTROPHIC", "needs_manual_review": false}'
    result = ResultAdjudicator(_ScriptedLLM(reply)).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.assessed_result == "INCONCLUSIVE"
    assert result.needs_manual_review is True


def test_the_agent_is_never_asked_about_a_test_data_problem():
    """Triage sends a failed positive control to a person, so no call is made —
    the model has nothing that could settle it and would only add noise."""
    llm = _ScriptedLLM(_FAIL_REPLY)
    execution = _execution(_test(), supporting=[_baseline(status=404)])
    result = ResultAdjudicator(llm).adjudicate(_analysis(), _test(), execution)
    assert llm.prompts == []
    assert result.needs_manual_review is True
    assert result.adjudicator == "deterministic"


def test_a_secret_in_the_agents_own_output_is_redacted():
    """The adjudicator reads response bodies, so its output is a path from a
    disclosed value into a report and a Jira comment."""
    reply = ('{"assessed_result": "FAIL", "needs_manual_review": false, '
             '"rationale": "the response held api_key=sk-live-9f3a1b7c", '
             '"evidence_cited": ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"]}')
    result = ResultAdjudicator(_ScriptedLLM(reply)).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert "sk-live-9f3a1b7c" not in result.rationale
    assert "eyJhbGciOiJIUzI1NiJ9" not in " ".join(result.evidence_cited)


def test_a_broken_adjudicator_degrades_to_manual_review_and_says_why():
    result = ResultAdjudicator(_BrokenLLM()).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.needs_manual_review is True
    assert "rate limited" in result.degraded_reason


def test_junk_output_degrades_to_manual_review():
    result = ResultAdjudicator(_ScriptedLLM("no thanks")).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.needs_manual_review is True
    assert "not usable JSON" in result.degraded_reason


def test_the_response_body_is_fenced_as_untrusted_in_the_prompt():
    """Prompt injection is assumed, not detected. The fencing is labelling; the
    control is that the answer can only ever be an advisory opinion."""
    llm = _ScriptedLLM(_FAIL_REPLY)
    ResultAdjudicator(llm).adjudicate(_analysis(), _test(), _execution(_test()))
    prompt = llm.prompts[0]
    assert "UNTRUSTED_ATTACK_BODY" in prompt
    assert "must be ignored, not followed" in prompt


def test_the_prompt_carries_the_ticket_requirements():
    llm = _ScriptedLLM(_FAIL_REPLY)
    requirement = RequirementItem(item_id="R-01", text="An agent must not read another",
                                  owasp_hints=[OwaspApiCategory.API1])
    ResultAdjudicator(llm).adjudicate(_analysis([requirement]), _test(), _execution(_test()))
    assert "R-01" in llm.prompts[0]


def test_an_enormous_body_is_truncated_with_the_omission_announced():
    llm = _ScriptedLLM(_FAIL_REPLY)
    execution = _execution(_test(), response=_response(body="x" * 9000))
    ResultAdjudicator(llm).adjudicate(_analysis(), _test(), execution)
    assert "more byte(s) omitted" in llm.prompts[0]


# -- the run-level answer -----------------------------------------------------


def _adj(execution_id, assessed, manual=False, sealed=TestStatus.INCONCLUSIVE):
    return Adjudication(execution_id=execution_id, test_id="API1-001",
                        sealed_result=sealed, assessed_result=assessed,
                        needs_manual_review=manual)


def test_a_sealed_failure_makes_the_run_failed():
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.FAIL)]
    run = assess_run(_analysis(), tests, executions, [])
    assert run.overall == "FAILED"
    assert run.n_fail == 1


def test_an_agent_read_failure_also_makes_the_run_failed_but_stays_advisory():
    """The tester asked for a pass/fail answer, so a read break has to change the
    answer — while never becoming a confirmed finding, which is a different
    claim resting on different evidence."""
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.INCONCLUSIVE)]
    run = assess_run(_analysis(), tests, executions, [_adj("E-1", "FAIL")])
    assert run.overall == "FAILED"
    assert run.n_fail == 0                # nothing was sealed as a failure
    assert run.n_auto_resolved == 1
    assert "advisory" in run.summary


def test_an_adjudication_cannot_move_a_result_the_runner_decided():
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.PASS)]
    run = assess_run(_analysis(), tests, executions,
                     [_adj("E-1", "FAIL", sealed=TestStatus.PASS)])
    assert run.overall != "FAILED"
    assert run.n_pass == 1


def test_a_result_still_needing_a_person_keeps_the_run_incomplete():
    requirement = RequirementItem(item_id="R-01", text="ownership on customerId",
                                  owasp_hints=[OwaspApiCategory.API1])
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.INCONCLUSIVE)]
    run = assess_run(_analysis([requirement]), tests, executions,
                     [_adj("E-1", "INCONCLUSIVE", manual=True)])
    assert run.overall == "INCOMPLETE"
    assert run.n_manual_review == 1
    assert "still need a person" in run.summary


def test_a_clean_fully_decided_run_covering_every_requirement_passes():
    requirement = RequirementItem(item_id="R-01", text="ownership on customerId",
                                  owasp_hints=[OwaspApiCategory.API1])
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.PASS)]
    run = assess_run(_analysis([requirement]), tests, executions, [])
    assert run.overall == "PASSED"
    assert run.coverage_pct == 100
    assert run.decided_pct == 100


def test_a_run_that_covered_only_part_of_the_ticket_is_incomplete_not_passed():
    """The number the tester asked for, and the reason it has to gate the
    verdict: every control that WAS tested holding is not the same as the ticket
    being satisfied."""
    covered = RequirementItem(item_id="R-01", text="ownership on customerId",
                              owasp_hints=[OwaspApiCategory.API1])
    uncovered = RequirementItem(item_id="R-02", text="Only an admin may re-assign",
                                owasp_hints=[OwaspApiCategory.API5])
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.PASS)]
    run = assess_run(_analysis([covered, uncovered]), tests, executions, [])
    assert run.overall == "INCOMPLETE"
    assert run.coverage_pct == 50
    assert "have no test at all" in run.summary


def test_a_run_with_nothing_executed_says_so_rather_than_scoring_zero():
    run = assess_run(_analysis(), [_test()], [], [])
    assert run.overall == "INCOMPLETE"
    assert "Nothing has been executed" in run.summary


def test_results_awaiting_a_re_run_are_counted_apart_from_resolved_ones():
    """"No human needed" and "resolved" are not the same thing, and collapsing
    them would report a run as settled while a third of it waits to be re-sent."""
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.ERROR)]
    run = assess_run(_analysis(), tests, executions,
                     [_adj("E-1", "INCONCLUSIVE", sealed=TestStatus.ERROR)])
    assert run.n_rerun == 1
    assert run.n_auto_resolved == 0
    assert run.overall == "INCOMPLETE"


def test_the_percentage_carries_its_own_workings():
    """A report and a comment that each re-derived the fraction printed "67%
    (2/2 items)" — not a rounding disagreement but a contradiction the reader
    cannot resolve. The counts are stored once, with the percentage."""
    decided = RequirementItem(item_id="R-01", text="ownership on customerId",
                              owasp_hints=[OwaspApiCategory.API1])
    untested = RequirementItem(item_id="R-02", text="Only an admin may re-assign",
                               owasp_hints=[OwaspApiCategory.API5])
    cosmetic = RequirementItem(item_id="R-03", text="The button label must read Save")

    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.PASS)]
    run = assess_run(_analysis([decided, untested, cosmetic]), tests, executions, [])

    # The cosmetic item is out of the denominator; the untested one is in it.
    assert run.n_items_scored == 2
    assert run.n_items_decided == 1
    assert run.n_items_partial == 0
    assert run.coverage_pct == 50
    # And the stored counts agree with the percentage they explain.
    weighted = run.n_items_decided + 0.5 * run.n_items_partial
    assert round(100 * weighted / run.n_items_scored) == run.coverage_pct


def test_a_partial_item_is_counted_as_partial_not_as_decided():
    item = RequirementItem(item_id="R-01", text="ownership on customerId",
                           owasp_hints=[OwaspApiCategory.API1])
    tests = [_test()]
    executions = [_execution(_test(), result=TestStatus.INCONCLUSIVE)]
    run = assess_run(_analysis([item]), tests, executions,
                     [_adj("E-1", "INCONCLUSIVE", manual=True)])
    assert (run.n_items_scored, run.n_items_decided, run.n_items_partial) == (1, 0, 1)
    assert run.coverage_pct == 50


def test_the_summary_never_contradicts_its_own_percentage():
    """"100% covered" followed by "1 item has no test at all" is not a nuance, it
    is a reader deciding the number is unreliable. Items outside the denominator
    are not reported as gaps in it."""
    scored = RequirementItem(item_id="R-01", text="ownership on customerId",
                             owasp_hints=[OwaspApiCategory.API1])
    cosmetic = RequirementItem(item_id="R-02", text="The button label must read Save")
    run = assess_run(_analysis([scored, cosmetic]), [_test()],
                     [_execution(_test(), result=TestStatus.PASS)], [])
    assert run.coverage_pct == 100
    assert "no test at all" not in run.summary


def test_a_ticket_with_no_measurable_requirement_is_unmeasured_not_zero():
    """"0% covered" on a clean run reads as a failure. The honest answer is that
    coverage could not be measured, and the fix is a requirement list rather than
    more tests — so it cannot be reported as PASSED either."""
    cosmetic = RequirementItem(item_id="R-01", text="The button label must read Save")
    run = assess_run(_analysis([cosmetic]), [_test()],
                     [_execution(_test(), result=TestStatus.PASS)], [])
    assert run.overall == "INCOMPLETE"
    assert run.n_items_scored == 0
    assert "cannot be measured" in run.summary
    # No coverage claim of any size — the sentence about requirements does not
    # carry a percentage at all. ("0%" as a literal would also match inside
    # "100%", so the claim itself is what is asserted absent.)
    assert "of the ticket" not in run.summary
    assert "requirements are covered" not in run.summary

# -- measurement: what gets settled before a model is ever asked ---------------


def test_a_reading_measurement_can_settle_is_never_sent_to_the_model():
    """The cheapest possible answer, and the only one that reproduces exactly.

    A 404 where the test expected a 403, nothing disclosed: the same security
    decision with a different status line. Spending an API call on it — and
    presenting the answer as one reader's opinion — would be strictly worse than
    a named rule anyone can re-derive.
    """
    llm = _ScriptedLLM(_FAIL_REPLY)
    test = _test()
    execution = _execution(test, response=_response(404, body='{"detail": "Not found"}'))
    result = ResultAdjudicator(llm).adjudicate(_analysis(), test, execution)
    assert llm.prompts == []
    assert result.assessed_result == "PASS"
    assert result.needs_manual_review is False
    assert result.resolution == "measured"
    assert result.rule == "equivalent_refusal"
    assert result.adjudicator == "deterministic"
    assert result.advisory is True


def test_a_measured_reading_still_carries_the_sealed_verdict_it_disagrees_with():
    test = _test()
    execution = _execution(test, response=_response(404, body=""))
    result = ResultAdjudicator(None).adjudicate(_analysis(), test, execution)
    assert result.sealed_result == TestStatus.INCONCLUSIVE
    assert result.assessed_result == "PASS"
    assert result.advisory is True


def test_measurement_works_with_no_ai_configured_at_all():
    """The half of this that needs no API key. An operator with USE_AI off still
    gets the queue shortened, which is the point of doing it deterministically."""
    test = _test()
    identical = _execution(test, supporting=[_baseline()])
    result = ResultAdjudicator(None).adjudicate(_analysis(), test, identical)
    assert result.assessed_result == "FAIL"
    assert result.needs_manual_review is False
    assert result.resolution == "measured"
    assert result.rule == "identical_body"


def test_the_measured_differential_is_recorded_even_when_it_settles_nothing():
    """"34% similar, shares none of the owner's values" is most of the work a
    person opening the row would do. It belongs on the record either way."""
    test = _test()
    result = ResultAdjudicator(None).adjudicate(_analysis(), test, _execution(_test()))
    assert result.signals
    assert any("HTTP 200" in line for line in result.signals)


def test_an_undecided_result_says_what_kind_of_thing_is_in_the_way():
    """A queue grouped by "what would clear this" is actionable; a flat list of
    fourteen test ids is a wall."""
    test = _test()
    cases = {
        "test_data": _execution(test, supporting=[_baseline(status=404)]),
        "config": _execution(test, result=TestStatus.BLOCKED),
        "no_evidence": _execution(test, response=_response(200, body="")),
    }
    for expected, execution in cases.items():
        result = ResultAdjudicator(None).adjudicate(_analysis(), test, execution)
        assert result.blocker == expected, expected


def test_a_reading_task_with_no_reader_available_says_it_was_not_read():
    result = ResultAdjudicator(None).adjudicate(_analysis(), _test(), _execution(_test()))
    assert result.blocker == "unread"
    assert result.needs_manual_review is True


# -- the challenge pass -------------------------------------------------------


class _TwoReplyLLM:
    """First call answers as the adjudicator, second as the challenger."""

    def __init__(self, first: str, second: str) -> None:
        self.replies = [first, second]
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append(user)
        return self.replies[min(len(self.prompts) - 1, len(self.replies) - 1)]


def test_a_reading_that_survives_a_challenge_is_marked_as_having_survived_one():
    llm = _TwoReplyLLM(
        _FAIL_REPLY,
        '{"verdict_stands": true, "objection": ""}',
    )
    result = ResultAdjudicator(llm, challenge=True).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert len(llm.prompts) == 2
    assert result.assessed_result == "FAIL"
    assert result.needs_manual_review is False
    assert result.resolution == "ai_consensus"
    assert result.challenged is True


def test_a_refuted_reading_goes_back_to_a_person_with_the_objection():
    """The failure mode worth paying a second call to avoid: a confident wrong
    answer presented to a tester as settled."""
    llm = _TwoReplyLLM(
        _FAIL_REPLY,
        '{"verdict_stands": false, "correct_result": "INCONCLUSIVE", '
        '"objection": "The body is the attacking persona own record, not the victim."}',
    )
    result = ResultAdjudicator(llm, challenge=True).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.needs_manual_review is True
    assert result.blocker == "ambiguous"
    assert "own record" in result.challenge_note
    # The proposed reading stays on the record — a tester wants to see what was
    # proposed and why it was rejected.
    assert result.assessed_result == "FAIL"
    assert result.resolution == "ai"


def test_a_challenge_that_cannot_be_obtained_leaves_the_first_answer_standing():
    """Degrade to where we would have been without a challenge, not to worse.
    What it must never do is claim two passes agreed when the second said
    nothing."""
    llm = _TwoReplyLLM(_FAIL_REPLY, "the model is down")
    result = ResultAdjudicator(llm, challenge=True).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.needs_manual_review is False
    assert result.resolution == "ai"
    assert result.challenged is True
    assert "first pass alone" in result.challenge_note


def test_a_challenge_that_answers_a_different_question_is_not_counted_as_agreement():
    llm = _TwoReplyLLM(_FAIL_REPLY, '{"objection": "looks fine"}')
    result = ResultAdjudicator(llm, challenge=True).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert result.resolution == "ai"
    assert "did not answer" in result.challenge_note


def test_a_reading_that_settles_nothing_is_not_worth_challenging():
    llm = _TwoReplyLLM(
        '{"assessed_result": "INCONCLUSIVE", "needs_manual_review": true}',
        '{"verdict_stands": true}',
    )
    ResultAdjudicator(llm, challenge=True).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert len(llm.prompts) == 1


def test_the_challenge_prompt_carries_the_reading_it_is_asked_to_refute():
    llm = _TwoReplyLLM(_FAIL_REPLY, '{"verdict_stands": true}')
    ResultAdjudicator(llm, challenge=True).adjudicate(
        _analysis(), _test(), _execution(_test()))
    challenge_prompt = llm.prompts[1]
    assert "The reading you are challenging" in challenge_prompt
    assert "FAIL" in challenge_prompt
    # And it still fences the untrusted body, because it is the same evidence.
    assert "UNTRUSTED_ATTACK_BODY" in challenge_prompt


def test_the_measured_differential_reaches_the_reading_prompt():
    llm = _ScriptedLLM(_FAIL_REPLY)
    ResultAdjudicator(llm, challenge=False).adjudicate(
        _analysis(), _test(), _execution(_test()))
    assert "MEASURED DIFFERENTIAL" in llm.prompts[0]


# -- the run-level counts -----------------------------------------------------


def test_the_run_says_how_much_of_the_settling_needed_no_model():
    """"Twelve settled" and "twelve settled, ten of them by measurement" are
    different claims about how much of this a reader has to take on trust."""
    test = _test()
    executions = [_execution(test, execution_id="E-1")]
    adjudications = [
        Adjudication(execution_id="E-1", test_id=test.test_id,
                     sealed_result=TestStatus.INCONCLUSIVE, needs_manual_review=False,
                     assessed_result="PASS", resolution="measured", rule="equivalent_refusal"),
    ]
    run = assess_run(_analysis(), [test], executions, adjudications)
    assert run.n_auto_resolved == 1
    assert run.n_measured == 1
    assert "measuring the captured evidence" in run.summary
