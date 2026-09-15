"""The assessment screen's entry point.

The screen itself is built in `app/api/views/assessment/`, one module per
phase; this is the thin adapter the route calls.
"""

from __future__ import annotations

from app.api.views.assessment import body as assessment_body
from app.api.views.shell import _PLANNER_ENABLED, page
from app.database.models import Assessment
from app.schemas.testcase import TestCase

def _plan_from_tests(tests: list[TestCase]) -> dict:
    """A one-page, unfiltered plan result, for a caller that has the test list
    but did not go through the repository's query."""
    return {
        "tests": tests,
        "matched_ids": [t.test_id for t in tests],
        "total": len(tests),
        "unfiltered_total": len(tests),
        "page": 1,
        "pages": 1,
        "per": max(len(tests), 1),
        "facets": {},
        "meta": {
            "total": len(tests),
            "approved": sum(1 for t in tests if t.approval_status.value == "APPROVED"),
            "rejected": sum(1 for t in tests if t.approval_status.value == "REJECTED"),
            "pending": sum(1 for t in tests if t.approval_status.value == "PENDING"),
            "approved_destructive": sum(
                1 for t in tests
                if t.approval_status.value == "APPROVED" and t.is_destructive
            ),
        },
    }


def assessment_page(
    assessment: Assessment,
    analysis: dict,
    coverage: list[dict],
    tests: list[TestCase] | None = None,
    n_executions: int = 0,
    n_findings: int = 0,
    environments: dict[str, str] | None = None,
    active_environment: str = "",
    readiness=None,
    flash: str = "",
    ticket_url: str = "",
    findings: list | None = None,
    plan: dict | None = None,
    filters: dict | None = None,
    verdicts: dict | None = None,
    plan_review=None,
    run_assessment=None,
    triage: dict | None = None,
    uncovered_poc_endpoints: list[str] | None = None,
    phase: str = "",
    run_job=None,
) -> str:
    """The assessment screen. Its structure lives in `views/assessment/`, one
    module per phase — it is the one page with enough moving parts to be worth
    a package, and keeping it here made this file a place you searched rather
    than read.

    `n_findings` is kept for callers that only counted them; when the findings
    themselves are passed they are shown, since "3 findings" without their
    severities is a number a tester has to click through to act on.
    """
    body = assessment_body(
        assessment,
        analysis or {},
        coverage or [],
        plan if plan is not None else _plan_from_tests(tests or []),
        filters=filters or {},
        n_executions=n_executions,
        findings=findings if findings is not None else [],
        environments=environments or {},
        active_environment=active_environment,
        readiness=readiness,
        planner_enabled=_PLANNER_ENABLED,
        verdicts=verdicts or {},
        # The two reviewing agents' output. Both optional: a page for an
        # assessment nobody has asked an agent about renders exactly as it did
        # before, with the button that asks.
        plan_review=plan_review,
        run_assessment=run_assessment,
        triage=triage or {},
        flash=flash,
        ticket_url=ticket_url,
        uncovered_poc_endpoints=uncovered_poc_endpoints or [],
        phase=phase,
        run_job=run_job,
    )
    return page(f"Assessment {assessment.issue_key}", body, active="assessment")
