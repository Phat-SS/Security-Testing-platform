"""The reviewing agent, and the limits on what its opinion can do.

Two things are being tested. First, that the structural review finds the gaps
that are facts about the plan — an applicable category with no test, a
requirement nothing addresses, an authorization probe with no positive control.
Second, and more important, that the AI half cannot *undo* any of that: a model
that says everything is fine must not be able to clear a gap that is
measurably there, and its output must survive validation before it is believed
at all.
"""

from app.analysis.plan_reviewer import PlanReviewer, structural_review
from app.schemas.agent import RequirementItem
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping
from app.schemas.enums import Applicability, OwaspApiCategory
from app.schemas.testcase import (
    AuthContext,
    BaselineSpec,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
    VerificationStep,
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
        raise RuntimeError("upstream said no")


def _analysis(categories=(OwaspApiCategory.API1,), requirements=()):
    return IssueAnalysis(
        issue_key="CRM-1234",
        business_summary="Customer records API",
        endpoints=[Endpoint(method="GET", path="/customers/{customerId}",
                            object_id_params=["customerId"])],
        owasp_mappings=[
            OwaspMapping(category=c, applicability=Applicability.APPLICABLE,
                         reason="r", matched_signals=[])
            for c in categories
        ],
        requirements=list(requirements),
    )


def _test(test_id="API1-001", category="API1:2023", baseline=True, verification=None,
          method="GET", path="/customers/{customerId}"):
    return TestCase(
        test_id=test_id, title=test_id, objective="o",
        owasp_category=category, severity="HIGH",
        auth_context=AuthContext(persona="agent_A", target_persona="agent_B"),
        baseline=BaselineSpec(**{"as": "agent_B"}) if baseline else None,
        request=RequestSpec(method=method, path=path),
        attack_mutation=Mutation(kind="swap_object_id"),
        verification=verification,
        expected=ExpectedResult(status_in=[403]),
    )


# -- the structural review: the part that is a fact ---------------------------


def test_an_applicable_category_with_no_test_is_a_blocking_gap():
    review = structural_review(
        _analysis(categories=(OwaspApiCategory.API1, OwaspApiCategory.API5)),
        [_test()],
    )
    assert review.verdict == "REVISE"
    assert any(g.category == OwaspApiCategory.API5 and g.severity == "blocking"
               for g in review.gaps)


def test_a_requirement_nothing_addresses_is_a_blocking_gap():
    """The gap the whole feature exists for: a plan can cover every category the
    rule engine named and still miss the ticket's third acceptance criterion."""
    requirement = RequirementItem(item_id="R-02", text="Only an admin may re-assign",
                                  owasp_hints=[OwaspApiCategory.API5])
    review = structural_review(_analysis(requirements=[requirement]), [_test()])
    gaps = [g for g in review.gaps if g.requirement_id == "R-02"]
    assert gaps and gaps[0].severity == "blocking"


def test_an_authorization_test_without_a_positive_control_is_a_quality_gap():
    """It can only ever come back INCONCLUSIVE, so counting it as coverage would
    be counting a test that cannot decide anything."""
    review = structural_review(_analysis(), [_test(baseline=False)])
    assert any("no positive control" in g.description for g in review.gaps)
    assert review.quality_score < 100


def test_a_state_changing_property_test_without_a_read_back_is_a_quality_gap():
    review = structural_review(
        _analysis(categories=(OwaspApiCategory.API3,)),
        [_test(test_id="API3-001", category="API3:2023", method="PATCH", baseline=True)],
    )
    assert any("no read-back" in g.description for g in review.gaps)


def test_a_plan_that_covers_everything_decidably_is_approved():
    verification = VerificationStep(**{"as": "agent_A",
                                       "request": RequestSpec(method="GET", path="/x")})
    review = structural_review(_analysis(), [_test(verification=verification)])
    assert review.verdict == "APPROVE"
    assert review.gaps == []
    assert review.coverage_score == 100


def test_an_empty_plan_is_insufficient_not_merely_in_need_of_revision():
    review = structural_review(_analysis(), [])
    assert review.verdict == "INSUFFICIENT"


def test_the_structural_review_labels_itself_as_having_no_ai():
    review = structural_review(_analysis(), [_test()])
    assert review.reviewer == "deterministic"


# -- the AI review: additive, and floored by structure ------------------------


_AI_REPLY = """{"verdict": "REVISE", "coverage_score": 70, "quality_score": 90,
 "strengths": ["baselines are set on the authorization probes"],
 "notes": "The expiry path is the interesting one.",
 "gaps": [{"description": "Nothing tests that an EXPIRED coupon is the case that must reject.",
           "category": "API6:2023", "severity": "important",
           "suggested_mutation": "repeat_flow"}]}"""


def test_the_ai_reviewer_adds_gaps_a_structural_check_cannot_see():
    llm = _ScriptedLLM(_AI_REPLY)
    review = PlanReviewer(llm).review(_analysis(), [_test()])
    assert review.reviewer == "ai"
    assert any("EXPIRED coupon" in g.description for g in review.gaps)
    assert "baselines are set" in " ".join(review.strengths)


def test_the_ai_reviewer_cannot_clear_a_structural_gap():
    """A model that decides everything is fine must not be able to erase a gap
    that is measurably there."""
    llm = _ScriptedLLM('{"verdict": "APPROVE", "coverage_score": 100, '
                       '"quality_score": 100, "gaps": []}')
    review = PlanReviewer(llm).review(
        _analysis(categories=(OwaspApiCategory.API1, OwaspApiCategory.API5)),
        [_test()],
    )
    assert review.verdict == "REVISE"
    assert any(g.category == OwaspApiCategory.API5 for g in review.gaps)
    # And it cannot inflate the scores above what structure measured.
    assert review.coverage_score <= 50


def test_the_stricter_of_the_two_verdicts_wins_in_both_directions():
    approving_plan = [_test(verification=VerificationStep(
        **{"as": "agent_A", "request": RequestSpec(method="GET", path="/x")}))]
    llm = _ScriptedLLM('{"verdict": "INSUFFICIENT", "coverage_score": 20, '
                       '"quality_score": 20, "gaps": []}')
    review = PlanReviewer(llm).review(_analysis(), approving_plan)
    assert review.verdict == "INSUFFICIENT"


def test_an_invented_mutation_is_dropped_from_a_gaps_hint():
    """It would reach the planner as a suggestion the runner has no handler for,
    and be rejected there with a reason that reads like the planner's fault."""
    llm = _ScriptedLLM('{"verdict": "REVISE", "gaps": [{"description": "try harder", '
                       '"suggested_mutation": "sql_injection_everywhere"}]}')
    review = PlanReviewer(llm).review(_analysis(), [_test()])
    proposed = [g for g in review.gaps if g.description == "try harder"]
    assert proposed and proposed[0].suggested_mutation == ""


def test_an_unknown_category_or_severity_is_normalised_rather_than_trusted():
    llm = _ScriptedLLM('{"verdict": "REVISE", "gaps": [{"description": "a gap the model '
                       'found", "category": "API99:2023", "severity": "catastrophic"}]}')
    review = PlanReviewer(llm).review(_analysis(), [_test()])
    gap = [g for g in review.gaps if g.description == "a gap the model found"][0]
    assert gap.category is None
    assert gap.severity == "important"


def test_a_duplicate_of_a_structural_gap_is_not_listed_twice():
    llm = _ScriptedLLM(
        '{"verdict": "REVISE", "gaps": [{"description": "API5:2023 was judged applicable '
        'to this ticket but the plan contains no test for it."}]}'
    )
    review = PlanReviewer(llm).review(
        _analysis(categories=(OwaspApiCategory.API1, OwaspApiCategory.API5)), [_test()])
    matching = [g for g in review.gaps if "no test for it" in g.description]
    assert len(matching) == 1


def test_a_reviewer_that_returns_junk_degrades_to_the_structural_review():
    review = PlanReviewer(_ScriptedLLM("I would rather not.")).review(_analysis(), [_test()])
    assert review.reviewer == "deterministic"
    assert "not usable JSON" in review.degraded_reason


def test_a_reviewer_whose_api_call_fails_degrades_and_says_why():
    """Silently falling back produces a review that reads exactly like a real
    one, which is worse than no review at all."""
    review = PlanReviewer(_BrokenLLM()).review(_analysis(), [_test()])
    assert review.reviewer == "deterministic"
    assert "upstream said no" in review.degraded_reason


def test_the_prompt_shows_the_reviewer_the_requirements_and_the_structural_gaps():
    llm = _ScriptedLLM(_AI_REPLY)
    requirement = RequirementItem(item_id="R-02", text="Only an admin may re-assign",
                                  owasp_hints=[OwaspApiCategory.API5])
    PlanReviewer(llm).review(_analysis(requirements=[requirement]), [_test()],
                             [requirement])
    prompt = llm.prompts[0]
    assert "R-02" in prompt
    assert "Only an admin may re-assign" in prompt
    assert "Structural gaps already found" in prompt
    # It must not be asked to re-find what has already been found.
    assert "do not restate these" in prompt.lower()
