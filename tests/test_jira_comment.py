"""The Jira comment: does it say enough, does it say too much, and is the rest
somewhere a reader can find it?

Three halves now, because the comment's job narrowed. It carries **the summary**
and **the full results table**; the per-test explanation moved to the HTML
report. So the tests come in three groups:

1. **content** — the summary and the table must answer "what ran, what broke,
   did this pass, how much of the ticket did it cover".
2. **restraint** — the explanation must NOT be here, and the comment must say
   where it is. A comment that quietly kept half the detail would be neither a
   summary nor a report.
3. **containment** — this text leaves the platform for a system with a different
   audience and access-control model, so a secret or a victim's PII reaching it
   is an incident, not a formatting bug. Unchanged, and the reason these tests
   were written in the first place.

`test_report_detail.py` holds the other side of (2): that everything removed
from here is rendered by `reporting/html.py`.
"""

from app.reporting.jira_comment import build_comment
from app.schemas.agent import Adjudication, RequirementCoverage, RunAssessment
from app.schemas.enums import Confidence, OwaspApiCategory, Severity, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    Execution,
    RepeatStats,
    SupportingExchange,
    Verdict,
)
from app.schemas.finding import CorrelationEvidence, Finding
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)


def _test(test_id="API1-001", kind="swap_object_id", path="/customers/{customerId}",
          detail=None, title="BOLA on the customer endpoint"):
    return TestCase(
        test_id=test_id, title=title, objective="o",
        owasp_category="API1:2023", severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path=path),
        attack_mutation=Mutation(kind=kind, detail=detail or {"id_field": "customerId"}),
        expected=ExpectedResult(status_in=[403, 404]),
    )


def _execution(test, result=TestStatus.FAIL, status=200, body="{}", url=None,
               attack_note="targeted object id 2002 owned by another identity",
               supporting=None, repeat=None, actual="HTTP 200; the response disclosed "
                                                    "1 protected marker(s) belonging to another identity"):
    return Execution(
        execution_id=f"E-{test.test_id}", test_id=test.test_id,
        owasp_category=test.owasp_category.value, scope_validated=True,
        request=CapturedRequest(
            method="GET", url=url or "http://target.test/customers/2002",
            resolved_ip="203.0.113.10", headers={"Authorization": "********"},
            timestamp="2026-08-18T00:00:00Z",
        ),
        response=(CapturedResponse(status_code=status, headers={}, body=body,
                                   elapsed_ms=12, size_bytes=len(body))
                  if status else None),
        verdict=Verdict(result=result, confidence=Confidence.HIGH,
                        expected_summary="status in [403, 404]",
                        actual_summary=actual,
                        reason="The mutated request returned data belonging to another identity."),
        attack_note=attack_note,
        supporting=supporting or [],
        repeat=repeat,
    )


def _finding():
    return Finding(
        finding_id="SEC-001", title="Broken Object Level Authorization",
        owasp_category=OwaspApiCategory.API1, severity=Severity.HIGH,
        confidence=Confidence.HIGH, endpoint="GET /customers/{customerId}",
        dedup_key="k", affected_tests=["API1-001"],
        correlation=CorrelationEvidence(
            baseline_summary="agent_B owns the object",
            attack_summary="agent_A GET /customers/{customerId} → HTTP 200",
            expected="status in [403, 404]",
            actual="HTTP 200; the response disclosed 1 protected marker(s)",
            leaked_markers=[],
        ),
        impact="An authenticated user can read another user's data.",
        reproduction=["Authenticate as agent_A.", "Request the victim's object id.",
                      "Observe the victim's record in the response."],
        recommendation="Enforce server-side object ownership checks.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    )


def _run_assessment(**kwargs):
    defaults = dict(
        assessment_id="A-1", issue_key="CRM-1234", overall="FAILED",
        coverage_pct=67, decided_pct=80,
        items=[RequirementCoverage(item_id="R-01", text="An agent must not read "
                                                       "another agent's customer",
                                  state="COVERED_FAIL", tests=["API1-001"])],
        n_executions=5, n_fail=1, n_pass=3, n_undecided=1, n_manual_review=1,
        summary="FAILED: one control broke.",
    )
    defaults.update(kwargs)
    return RunAssessment(**defaults)


def _build(tests, executions, findings=None, **kwargs):
    return build_comment(
        issue_key="CRM-1234", target="http://target.test",
        tests={t.test_id: t for t in tests}, executions=executions,
        findings=findings or [], evidence_chain_ok=True, **kwargs,
    )


# -- 1. content: what the summary and the table have to answer -----------------


def test_every_executed_test_gets_a_row_in_the_results_table():
    """The table is the comment's substance now, so it is the thing that must be
    complete: one row per test, whatever the verdict."""
    failing, passing = _test("API1-001"), _test("API2-001")
    comment = _build(
        [failing, passing],
        [_execution(failing),
         _execution(passing, result=TestStatus.PASS, status=403, actual="HTTP 403")],
    )
    assert "### All test results" in comment
    assert "| API1-001 " in comment
    assert "| API2-001 " in comment


def test_a_row_names_the_attack_and_the_request_that_was_sent():
    test = _test()
    comment = _build([test], [_execution(test)])
    assert "swap_object_id" in comment          # which technique
    assert "GET /customers/2002" in comment     # against what, query included
    assert "HTTP 200" in comment                # what came back
    assert "FAIL" in comment                    # and the verdict


def test_findings_are_summarised_as_rows_with_severity_and_endpoint():
    comment = _build([_test()], [_execution(_test())], [_finding()])
    assert "SEC-001" in comment
    assert "Broken Object Level Authorization" in comment
    assert "HIGH" in comment
    assert "GET /customers/{customerId}" in comment
    assert "API1-001" in comment  # which test confirmed it


def test_findings_come_before_the_table_of_everything():
    """A reader who stops after the first screen must have seen the confirmed
    breaks, not a list of things that worked."""
    comment = _build([_test()], [_execution(_test())], [_finding()])
    assert comment.index("Confirmed findings") < comment.index("All test results")


def test_no_findings_explains_why_rather_than_just_saying_none():
    test = _test()
    comment = _build([test], [_execution(test, result=TestStatus.PASS, status=403,
                                        actual="HTTP 403")])
    assert "No confirmed findings" in comment
    assert "correlated evidence" in comment


def test_the_run_verdict_and_requirement_coverage_are_in_the_summary():
    """Passed or failed, and how much of the ticket it covered — the two things a
    stakeholder reading the ticket asks for."""
    test = _test()
    comment = _build([test], [_execution(test)], [_finding()],
                     run_assessment=_run_assessment())
    assert "FAILED" in comment
    assert "67%" in comment
    assert "Still needs manual review" in comment


def test_the_summary_omits_the_assessment_rows_when_nobody_asked_for_one():
    """No adjudication run means no coverage figure. Inventing one would be worse
    than leaving the question open."""
    test = _test()
    comment = _build([test], [_execution(test)])
    assert "Ticket requirements covered" not in comment
    assert "Overall assessment" not in comment


def test_an_agent_reviewed_row_says_that_it_was_the_agent():
    """"The runner sealed this as a break" and "an agent read this as a break" are
    different claims and must never print alike."""
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE, status=200,
                           actual="HTTP 200 (expected a rejection)")
    run = _run_assessment(n_auto_resolved=1, adjudications=[Adjudication(
        execution_id=execution.execution_id, test_id=test.test_id,
        sealed_result=TestStatus.INCONCLUSIVE, needs_manual_review=False,
        assessed_result="FAIL", confidence=Confidence.HIGH, adjudicator="ai",
        rationale="The body holds the victim's record.",
        evidence_cited=["a customer record belonging to the victim persona"],
    )])
    comment = _build([test], [execution], run_assessment=run)
    assert "| Review |" in comment
    assert "FAIL (agent, advisory)" in comment
    assert "not counted as confirmed findings" in comment


def test_the_review_column_is_absent_when_nothing_was_reviewed():
    test = _test()
    comment = _build([test], [_execution(test)])
    assert "| Review |" not in comment


def test_an_empty_run_does_not_crash():
    comment = _build([], [])
    assert "Tests executed | 0" in comment


# -- 2. restraint: the explanation is elsewhere, and the comment says so -------


def test_the_per_test_explanation_is_not_in_the_comment():
    """The whole reason this changed. A block per test — attack note, expected
    versus observed, the verdict's reasoning, the supporting exchanges — turned a
    60-test run into a wall of text in the one place people skim."""
    test = _test()
    supporting = [SupportingExchange(
        kind="baseline", as_persona="agent_B",
        request=CapturedRequest(method="GET", url="http://target.test/customers/2002",
                                resolved_ip="203.0.113.10", headers={}, timestamp="t"),
        response=CapturedResponse(status_code=200, headers={}, body="{}",
                                  elapsed_ms=5, size_bytes=2),
        note="positive control succeeded: the target is reachable",
    )]
    repeat = RepeatStats(sent=10, succeeded=10, status_counts={"200": 10},
                         throttled=False, concurrent=True)
    comment = _build([test], [_execution(test, supporting=supporting, repeat=repeat)],
                     [_finding()])

    assert "Expected of a secure system" not in comment
    assert "Actually observed" not in comment
    assert "Attack Parameters" not in comment
    assert "targeted object id 2002" not in comment       # the runtime attack note
    assert "returned data belonging to another identity" not in comment  # the reason
    assert "Positive Control" not in comment
    assert "request(s) sent concurrently" not in comment


def test_a_findings_impact_and_reproduction_are_not_in_the_comment():
    comment = _build([_test()], [_execution(_test())], [_finding()])
    assert "An authenticated user can read another user's data." not in comment
    assert "1. Authenticate as agent_A." not in comment
    assert "Enforce server-side object ownership checks." not in comment


def test_the_comment_says_where_the_detail_went():
    """Otherwise it reads as if it were the whole result."""
    comment = _build([_test()], [_execution(_test())])
    assert "Full detail" in comment
    assert "exact request as sent" in comment
    assert "report" in comment


def test_the_report_is_linked_when_the_platform_knows_its_own_url():
    comment = _build([_test()], [_execution(_test())],
                     report_url="https://sectest.example/assessment/A-1/report")
    assert "[the report](https://sectest.example/assessment/A-1/report)" in comment


def test_no_link_is_offered_when_the_platform_has_no_public_url():
    """A localhost link 404s for every reader but its author, which costs more
    trust than an absent one."""
    comment = _build([_test()], [_execution(_test())])
    assert "](" not in comment.split("### Full detail")[1].split("###")[0]


def test_undecided_results_are_counted_and_pointed_at_the_report():
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE, status=200,
                           actual="HTTP 200 (expected a rejection)")
    comment = _build([test], [execution])
    assert "INCONCLUSIVE (needs review) | 1" in comment
    assert "1 result(s) here are undecided" in comment


# -- 3. containment: what must never leave the platform ------------------------


def test_a_disclosed_value_is_never_reproduced_in_the_comment():
    """The whole point of a BOLA finding is that a victim's data came back.
    Repeating that data in a Jira comment — a system with a different audience
    and a different access-control model — would re-disclose it wholesale."""
    test = _test()
    execution = _execution(
        test,
        body='{"id": "2002", "email": "beth.victim@example.com", "phone": "555-0202"}',
    )
    comment = _build([test], [execution], [_finding()])

    assert "beth.victim@example.com" not in comment
    assert "555-0202" not in comment
    # And the reader is told where the evidence is.
    assert "captured response body evidence" in comment


def test_credentials_appearing_anywhere_are_redacted():
    test = _test()
    execution = _execution(
        test,
        url="http://target.test/reset?api_key=sk-live-9f3a1b7c&x=1",
    )
    comment = _build([test], [execution])

    assert "sk-live-9f3a1b7c" not in comment
    assert "********" in comment


def test_an_adjudicators_rationale_cannot_smuggle_a_secret_into_the_table():
    """The reviewing agent reads the response body, so its own output is a path
    from a disclosed value to a Jira comment. `Adjudication` fields are redacted
    where they are built, and the comment renders only the verdict word — but a
    row that quoted the rationale would reopen exactly that path."""
    test = _test()
    execution = _execution(test, result=TestStatus.INCONCLUSIVE, status=200)
    run = _run_assessment(adjudications=[Adjudication(
        execution_id=execution.execution_id, test_id=test.test_id,
        sealed_result=TestStatus.INCONCLUSIVE, needs_manual_review=False,
        assessed_result="FAIL", adjudicator="ai",
        rationale="the body contained beth.victim@example.com",
        evidence_cited=["api_key=sk-live-9f3a1b7c"],
    )])
    comment = _build([test], [execution], run_assessment=run)
    assert "beth.victim@example.com" not in comment
    assert "sk-live-9f3a1b7c" not in comment


def test_an_unsent_request_says_so_instead_of_showing_a_placeholder_url():
    """The runner stores "(error)" as the URL when it never built one. Rendering
    that verbatim reads as a request to a host called "(error)"."""
    test = _test()
    execution = _execution(test, result=TestStatus.ERROR, status=None, url="(error)",
                           attack_note="", actual="runner error")
    comment = _build([test], [execution])
    assert "not sent" in comment
    assert "GET (error)" not in comment


def test_a_pipe_in_a_path_cannot_corrupt_the_results_table():
    """Paths come from tickets and imported PoCs, so they are attacker-adjacent
    input. An unescaped pipe shifts every following column by one and silently
    misattributes results to the wrong test."""
    test = _test(path="/search?q=a|b|c")
    execution = _execution(test, url="http://target.test/search?q=a|b|c")
    comment = _build([test], [execution])

    table_rows = [ln for ln in comment.splitlines()
                  if ln.startswith("| API1-001 ")]
    assert table_rows, "the test's row is missing from the results table"
    # 6 columns → 7 pipe-delimited segments, and the literal pipes are escaped.
    assert len(table_rows[0].replace("\\|", "\x00").split("|")) == 8


def test_a_newline_in_a_title_cannot_break_the_table():
    test = _test(title="BOLA\non two lines\n| and a pipe")
    comment = _build([test], [_execution(test)])
    assert "| API1-001 " in comment
    for line in comment.splitlines():
        assert not line.startswith("on two lines")


def test_an_oversized_run_is_truncated_with_an_explicit_notice():
    """Silent truncation would present a partial result set as the whole one."""
    tests = [_test(f"API1-{i:03d}") for i in range(200)]
    executions = [_execution(t) for t in tests]
    comment = _build(tests, executions, max_chars=4000)

    assert len(comment) < 4600
    assert "truncated" in comment


def test_omitted_table_rows_are_announced():
    tests = [_test(f"API1-{i:03d}") for i in range(80)]
    executions = [_execution(t) for t in tests]
    comment = _build(tests, executions, max_table_rows=10, max_chars=200_000)
    assert "70 more row(s) omitted" in comment


def test_omitted_finding_rows_are_announced():
    findings = []
    for i in range(30):
        f = _finding()
        f.finding_id = f"SEC-{i:03d}"
        findings.append(f)
    comment = _build([_test()], [_execution(_test())], findings,
                     max_finding_rows=5, max_chars=200_000)
    assert "25 more not shown" in comment


def test_a_broken_evidence_chain_is_flagged_loudly():
    test = _test()
    comment = build_comment(
        issue_key="CRM-1", target="http://t", tests={test.test_id: test},
        executions=[_execution(test)], findings=[], evidence_chain_ok=False,
    )
    assert "Evidence chain FAILED" in comment
    assert "non-authoritative" in comment
