"""Requirement extraction and the coverage figure computed over it.

The percentage the whole feature reports rests on this list, so the tests are
about the denominator as much as the arithmetic: an item nobody can test must
not drag the score down, an item nothing tests must not be invisible, and a plan
that touches everything while deciding nothing must not score 100%.
"""

from app.analysis.requirements import (
    coverage_for_items,
    coverage_pct,
    extract_requirements,
    extract_requirements_from_text,
    merge_requirements,
    owasp_hints,
    matching_tests,
)
from app.mcp.jira import NormalizedIssue
from app.schemas.agent import RequirementItem
from app.schemas.enums import Confidence, OwaspApiCategory, TestStatus
from app.schemas.execution import CapturedRequest, CapturedResponse, Execution, Verdict
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)


def _issue(**kwargs):
    defaults = dict(
        issue_key="CRM-1234", project_key="CRM",
        summary="Customer records API",
        description="",
        acceptance_criteria=[],
    )
    defaults.update(kwargs)
    return NormalizedIssue(**defaults)


def _test(test_id, category, path="/customers/{customerId}", baseline=None,
          verification=None):
    return TestCase(
        test_id=test_id, title=test_id, objective="o",
        owasp_category=category, severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        request=RequestSpec(method="GET", path=path),
        attack_mutation=Mutation(kind="swap_object_id"),
        expected=ExpectedResult(status_in=[403]),
        baseline=baseline, verification=verification,
    )


def _execution(test_id, result, execution_id=None):
    return Execution(
        execution_id=execution_id or f"E-{test_id}", test_id=test_id,
        owasp_category="API1:2023", scope_validated=True,
        request=CapturedRequest(method="GET", url="http://t/x", resolved_ip="1.2.3.4",
                                headers={}, timestamp="t"),
        response=CapturedResponse(status_code=200, headers={}, body="{}", elapsed_ms=1,
                                  size_bytes=2),
        verdict=Verdict(result=result, confidence=Confidence.HIGH, expected_summary="e",
                        actual_summary="a", reason="r"),
    )


# -- extraction ----------------------------------------------------------------


def test_acceptance_criteria_become_requirement_items_verbatim():
    """An AC line *is* a requirement by definition, whatever its grammar — so it
    is taken unfiltered, unlike a description bullet."""
    issue = _issue(acceptance_criteria=[
        "An agent must not be able to read another agent's customer.",
        "Pagination is capped at 100 records.",
    ])
    items = extract_requirements(issue)
    assert [i.item_id for i in items] == ["R-01", "R-02"]
    assert items[0].kind == "acceptance_criterion"
    assert "another agent" in items[0].text


def test_security_relevant_description_bullets_are_picked_up():
    issue = _issue(description=(
        "Background: the CRM team owns this.\n"
        "- The endpoint must reject a request with no bearer token.\n"
        "- See the Confluence page for the data model.\n"
    ))
    items = extract_requirements(issue)
    texts = [i.text for i in items]
    assert any("reject a request with no bearer token" in t for t in texts)
    # Context is not a requirement, and counting it as one uncovered would make
    # the percentage meaningless.
    assert not any("Confluence" in t for t in texts)


def test_a_ticket_with_no_criteria_and_no_bullets_still_yields_one_item():
    """Otherwise coverage is computed over an empty set and reports 0% for a run
    that tested exactly what the ticket described."""
    items = extract_requirements(_issue(summary="Restrict customer access by owner"))
    assert len(items) == 1
    assert items[0].source == "summary"


def test_duplicate_lines_are_not_counted_twice():
    issue = _issue(acceptance_criteria=["Must reject an expired token.",
                                        "must reject an expired token"])
    assert len(extract_requirements(issue)) == 1


def test_hints_come_from_the_wording_a_ticket_actually_uses():
    """"another agent's customer" is the BOLA requirement as stated by a human,
    and never contains the word customerId."""
    assert OwaspApiCategory.API1 in owasp_hints("An agent must not read another agent's customer")
    assert OwaspApiCategory.API2 in owasp_hints("Reject a request with an expired JWT")
    assert OwaspApiCategory.API5 in owasp_hints("Only an admin may re-assign an account")
    assert OwaspApiCategory.API7 in owasp_hints("The avatar callback url is fetched server-side")


def test_a_non_security_requirement_gets_no_hints():
    assert owasp_hints("The button label must read Save") == []


def test_manual_items_survive_re_extraction():
    extracted = [RequirementItem(item_id="R-01", text="From the ticket")]
    existing = [RequirementItem(item_id="R-09", text="Typed by a tester", manual=True)]
    merged = merge_requirements(extracted, existing)
    assert [i.text for i in merged] == ["From the ticket", "Typed by a tester"]
    # Ids are positional, so they are renumbered rather than left colliding.
    assert [i.item_id for i in merged] == ["R-01", "R-02"]


# -- mapping -------------------------------------------------------------------


def test_a_test_addresses_an_item_when_their_categories_match():
    item = RequirementItem(item_id="R-01", text="An agent must not read another agent's customer",
                           owasp_hints=[OwaspApiCategory.API1])
    tests = [_test("API1-001", "API1:2023"), _test("API2-001", "API2:2023")]
    assert matching_tests(item, tests) == ["API1-001"]


def test_naming_an_endpoint_narrows_the_mapping_to_that_endpoint():
    """Without this, a ticket with six endpoints reports every BOLA test as
    addressing every ownership requirement, and the mapping stops telling you
    which one was tested."""
    item = RequirementItem(item_id="R-01", text="GET /invoices/{id} must check ownership",
                           owasp_hints=[OwaspApiCategory.API1])
    tests = [_test("API1-001", "API1:2023", path="/customers/{customerId}"),
             _test("API1-002", "API1:2023", path="/invoices/{id}")]
    assert matching_tests(item, tests) == ["API1-002"]


def test_an_item_with_no_hints_addresses_nothing_and_scores_nothing():
    item = RequirementItem(item_id="R-01", text="The button label must read Save")
    tests = [_test("API1-001", "API1:2023")]
    rows = coverage_for_items([item], tests)
    assert rows[0].state == "NOT_TESTED"
    assert "excluded from the coverage score" in rows[0].note
    # Out of the denominator entirely, not counted as a permanent gap.
    assert coverage_pct(rows, [item]) == 0
    assert coverage_pct(rows, []) == 0


def test_an_untested_requirement_is_named_with_the_category_that_would_test_it():
    item = RequirementItem(item_id="R-01", text="Only an admin may re-assign",
                           owasp_hints=[OwaspApiCategory.API5])
    rows = coverage_for_items([item], [_test("API1-001", "API1:2023")])
    assert rows[0].state == "NOT_TESTED"
    assert "API5:2023" in rows[0].note


def test_a_planned_but_unexecuted_test_is_not_coverage():
    item = RequirementItem(item_id="R-01", text="ownership on customerId",
                           owasp_hints=[OwaspApiCategory.API1])
    rows = coverage_for_items([item], [_test("API1-001", "API1:2023")], executions=[])
    assert rows[0].state == "NOT_COVERED"
    assert coverage_pct(rows, [item]) == 0


def test_an_undecided_execution_is_half_coverage_not_full():
    """The anti-false-confidence rule, one level up: a plan that touches
    everything and decides nothing must not report 100%."""
    item = RequirementItem(item_id="R-01", text="ownership on customerId",
                           owasp_hints=[OwaspApiCategory.API1])
    rows = coverage_for_items([item], [_test("API1-001", "API1:2023")],
                             executions=[_execution("API1-001", TestStatus.INCONCLUSIVE)])
    assert rows[0].state == "PARTIAL"
    assert coverage_pct(rows, [item]) == 50


def test_a_decided_execution_is_full_coverage_whichever_way_it_went():
    item = RequirementItem(item_id="R-01", text="ownership on customerId",
                           owasp_hints=[OwaspApiCategory.API1])
    tests = [_test("API1-001", "API1:2023")]
    for result, state in ((TestStatus.PASS, "COVERED_PASS"), (TestStatus.FAIL, "COVERED_FAIL")):
        rows = coverage_for_items([item], tests,
                                  executions=[_execution("API1-001", result)])
        assert rows[0].state == state
        assert coverage_pct(rows, [item]) == 100


def test_a_failure_outranks_a_pass_on_the_same_requirement():
    item = RequirementItem(item_id="R-01", text="ownership on customerId",
                           owasp_hints=[OwaspApiCategory.API1])
    tests = [_test("API1-001", "API1:2023"), _test("API1-002", "API1:2023")]
    rows = coverage_for_items([item], tests, executions=[
        _execution("API1-001", TestStatus.PASS),
        _execution("API1-002", TestStatus.FAIL),
    ])
    assert rows[0].state == "COVERED_FAIL"


def test_an_adjudicated_result_can_settle_an_item_but_only_an_undecided_one():
    """An override exists so a result an agent read counts as decided. It must
    never be able to move a verdict the runner sealed."""
    item = RequirementItem(item_id="R-01", text="ownership on customerId",
                           owasp_hints=[OwaspApiCategory.API1])
    tests = [_test("API1-001", "API1:2023")]

    undecided = _execution("API1-001", TestStatus.INCONCLUSIVE, execution_id="E-1")
    rows = coverage_for_items([item], tests, executions=[undecided],
                              overrides={"E-1": "FAIL"})
    assert rows[0].state == "COVERED_FAIL"

    sealed_pass = _execution("API1-001", TestStatus.PASS, execution_id="E-2")
    rows = coverage_for_items([item], tests, executions=[sealed_pass],
                              overrides={"E-2": "FAIL"})
    assert rows[0].state == "COVERED_PASS"


# -- back-filling an analysis saved before requirement items existed ------------


def test_requirements_can_be_read_back_out_of_the_stored_ticket_text():
    """So an assessment somebody already ran gets a coverage figure, instead of a
    permanent "unmeasured" or a re-import that discards its approvals."""
    text = (
        "Customer records API\n"
        "Agents manage their own customers.\n"
        "- An agent must not read another agent's customer.\n"
        "Unauthenticated requests must be rejected with 401.\n"
    )
    items = extract_requirements_from_text(text)
    texts = [i.text for i in items]
    assert any("must not read another" in t for t in texts)
    assert any("must be rejected with 401" in t for t in texts)


def test_prose_without_requirement_grammar_is_not_invented_into_requirements():
    """A loose match here turns a paragraph of context into phantom requirements
    that drag the percentage down forever."""
    text = (
        "Background: the CRM team owns this service.\n"
        "It was migrated from the legacy stack last quarter.\n"
        "See the Confluence page for the data model.\n"
    )
    assert extract_requirements_from_text(text) == []


def test_the_text_extractor_is_bounded():
    text = "\n".join(f"Rule {i} must hold." for i in range(60))
    assert len(extract_requirements_from_text(text)) <= 25
