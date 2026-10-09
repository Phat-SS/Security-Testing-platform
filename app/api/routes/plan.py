"""Designing, reviewing and approving the test plan.
"""

from __future__ import annotations

import json
import logging
from functools import partial
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Header, Request
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)

from app.api import views
from app.api.deps import require, require_page
from app.api.jobs import create_operation_job, run_operation_job
from app.api.runtime import state
from app.core.auth import User
from app.core.config import settings_with_overrides
from app.schemas.testcase import RequestSpec

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/assessment/{aid}/design")
async def design(aid: str, poc_python: str = Form(""), poc_postman: str = Form(""),
                 burp_xml: str = Form(""), jmeter_xml: str = Form(""),
                 depth: str = Form("standard"),
                 user: User = Depends(require("tester"))):
    # Anything other than the two known depths falls back to "standard" inside
    # TestDesigner rather than erroring: a form value is user input, and the
    # safe direction for an unrecognised one is the narrower test plan.
    state.orch.design(aid, poc_python=poc_python or None, poc_postman=poc_postman or None,
                      burp_xml=burp_xml or None, jmeter_xml=jmeter_xml or None,
                      depth=depth or "standard")
    return RedirectResponse(f"/assessment/{aid}?flash=Test+plan+generated", status_code=303)



_PLAN_ACTIONS = {
    "approve": ("approve", "Approved"),
    "reject": ("reject", "Rejected"),
    "reset": ("reset_approval", "Reset to PENDING"),
}


def _plan_filters(form) -> dict:
    """The filter the tester was looking at, echoed back from the form.

    "Approve all 312 matching" has to mean the filter on screen, so the bulk
    action re-runs the same query server-side rather than trusting a list of ids
    the page happened to render.
    """
    def get(name, default=""):
        value = form.get(name, default)
        return value if value is not None else default

    try:
        per = int(get("per", "25") or 25)
    except ValueError:
        per = 25
    return {"q": get("q"), "cat": get("cat"), "sev": get("sev"), "appr": get("appr"),
            "dest": get("dest"), "src": get("src"), "sort": get("sort", "id") or "id",
            "per": per}


@router.post("/assessment/{aid}/agent-plan")
async def agent_plan(aid: str, depth: str = Form("standard"), rounds: int = Form(1),
                     user: User = Depends(require("tester")),
                     idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    """Re-run the planning pipeline: design → plan → review → revise → re-review.

    Replaces the plan, exactly as the Design step does, and carries an approval
    across for any test that comes back byte-for-byte unchanged. Rounds are
    capped at 2 whatever is posted: each one is another LLM call and another
    batch a human has to read, and a reviewer that is never satisfied would
    otherwise loop until the batch cap swallowed the plan.
    """
    job, created = create_operation_job(aid, "agent_plan", idempotency_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Existing job {job.job_id}: {job.state}')}&phase=plan",
            status_code=303,
        )
    try:
        _tests, review = await run_operation_job(
            job,
            partial(
                state.orch.agent_plan, aid, depth=depth or "standard",
                max_rounds=max(0, min(2, rounds)), actor=user.name,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - report it, do not 500 the page
        return HTMLResponse(
            views.error_page(
                "Planning agent failed",
                f"The planning agent could not complete: {type(exc).__name__}: {exc}",
                "<p>The assessment is unchanged. Generate a plan from step 2 to "
                "continue without the agent.</p>",
            ),
            status_code=500,
        )
    flash = (f"Plan reviewed: {review.verdict}, {len(review.tests_added)} test(s) added"
             if review else "Plan generated (no review was recorded)")
    return RedirectResponse(f"/assessment/{aid}?flash={quote(flash)}&phase=plan", status_code=303)


@router.post("/assessment/{aid}/adjudicate")
async def adjudicate(request: Request, aid: str, user: User = Depends(require("tester")),
                     idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    """Review the results: triage, measure, cluster, then answer pass/fail.

    Sends nothing by default. It reads evidence that already exists, which is why
    it is safe to run, disagree with, and run again — and why it is a separate
    button from Execute rather than something that happens automatically at the
    end of a run.

    The one exception is explicit and comes from its own button: `rerun_transient`
    re-sends the results that carry no security signal at all (a 5xx during the
    attack, a runner error). That fires real requests, bounded and audited, and
    only ever from a form that says so — never as a side effect of asking for a
    review.
    """
    form = await request.form()
    rerun_transient = bool(form.get("rerun_transient"))
    eng = state.engagement
    job, created = create_operation_job(aid, "adjudicate", idempotency_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Existing job {job.job_id}: {job.state}')}&phase=results",
            status_code=303,
        )
    try:
        run = await run_operation_job(
            job,
            partial(
                state.orch.adjudicate, aid, actor=user.name,
                rerun_transient=rerun_transient,
                scope=eng.scope if rerun_transient else None,
                vault=eng.vault if rerun_transient else None,
                settings=settings_with_overrides(eng.runner) if rerun_transient else None,
            ),
        )
    except ValueError as exc:
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(str(exc))}&phase=results", status_code=303
        )
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(
            views.error_page(
                "Result review failed",
                f"The reviewing agent could not complete: {type(exc).__name__}: {exc}",
                "<p>Nothing was changed. The sealed verdicts and findings are "
                "untouched — this pass only ever reads them.</p>",
            ),
            status_code=500,
        )
    settled = (f"{run.n_auto_resolved} settled by review "
               f"({run.n_measured} by measurement)") if run.n_auto_resolved else "none settled"
    flash = (f"Reviewed: {run.overall}, {run.coverage_pct}% of the ticket covered, "
             f"{settled}, {run.n_manual_review} still need you"
             + (f", {run.n_reran} re-sent" if run.n_reran else ""))
    return RedirectResponse(f"/assessment/{aid}?flash={quote(flash)}&phase=results",
                            status_code=303)


@router.post("/assessment/{aid}/copilot")
async def copilot(aid: str, question: str = Form(""), phase: str = Form(""),
                  user: User = Depends(require("tester")),
                  idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    """Refresh the Copilot brief, optionally asking it a question.

    Reads what the assessment already holds and sends nothing to the target.
    A job like the other agent calls, so a double-submit does not pay for the
    same CLI call twice.
    """
    back = f"/assessment/{aid}?phase={quote(phase or 'results')}"
    job, created = create_operation_job(aid, "copilot", idempotency_key)
    if not created:
        return RedirectResponse(f"{back}&flash={quote(f'Existing job {job.job_id}: {job.state}')}",
                                status_code=303)
    try:
        brief = await run_operation_job(
            job, partial(state.orch.copilot_brief, aid, question=question[:1000],
                         actor=user.name),
        )
    except ValueError as exc:
        return RedirectResponse(f"{back}&flash={quote(str(exc))}", status_code=303)
    flash = ("Copilot updated" if not brief.degraded_reason
             else f"Copilot updated (deterministic only: {brief.degraded_reason})")
    return RedirectResponse(f"{back}&flash={quote(flash)}#copilot", status_code=303)


@router.post("/assessment/{aid}/copilot/accept")
async def copilot_accept(aid: str, step: int = Form(...), brief: str = Form(""),
                         user: User = Depends(require("tester")),
                         idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    """Hand one Copilot next step to the planner. Whatever it proposes is
    validated like any planner output and lands PENDING: nothing runs."""
    job, created = create_operation_job(aid, "copilot_accept", idempotency_key)
    if not created:
        return RedirectResponse(
            f"/assessment/{aid}?phase=plan&flash={quote(f'Existing job {job.job_id}: {job.state}')}",
            status_code=303)
    try:
        added, rejected = await run_operation_job(
            job, partial(state.orch.copilot_accept, aid, step, actor=user.name, brief_id=brief),
        )
    except (ValueError, RuntimeError) as exc:
        return RedirectResponse(f"/assessment/{aid}?phase=plan&flash={quote(str(exc))}",
                                status_code=303)
    flash = f"{added} test(s) added for review" + (f", {len(rejected)} rejected" if rejected else "")
    return RedirectResponse(f"/assessment/{aid}?phase=plan&flash={quote(flash)}", status_code=303)


@router.post("/assessment/{aid}/plan")
async def plan_action(request: Request, aid: str, user: User = Depends(require("tester"))):
    form = await request.form()
    action = str(form.get("action", "approve"))
    if action not in _PLAN_ACTIONS:
        return RedirectResponse(f"/assessment/{aid}?flash=Unknown+action&phase=plan", status_code=303)
    method_name, word = _PLAN_ACTIONS[action]

    if form.get("select_all"):
        filters = _plan_filters(form)
        filters.pop("per", None)
        test_ids = state.repo.query_test_cases(aid, per=500, **filters)["matched_ids"]
        scope = "matching the current filter"
    else:
        test_ids = [str(v) for v in form.getlist("test_ids")]
        scope = "selected"

    if not test_ids:
        return RedirectResponse(f"/assessment/{aid}?flash=Nothing+selected&phase=plan", status_code=303)

    n = getattr(state.orch, method_name)(aid, test_ids, actor=user.name)
    flash = f"{word} {n} test(s) {scope}"
    if action == "approve" and n:
        # Approving is the last thing the Plan phase is for, so it hands over to
        # Run rather than returning to a list the tester has finished with. The
        # filter is not carried across: it describes a plan view, and Run has no
        # use for it.
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(flash)}&phase=run", status_code=303
        )
    query = _preserve_plan_query(form)
    return RedirectResponse(
        f"/assessment/{aid}?flash={quote(flash)}{query}&phase=plan", status_code=303
    )


def _preserve_plan_query(form) -> str:
    """Keep the filter across the redirect: landing back on an unfiltered page
    after acting on a filtered one loses the tester's place."""
    keep = ("q", "cat", "sev", "appr", "dest", "src", "sort", "per", "page")
    parts = [f"{k}={quote(str(form.get(k)))}" for k in keep if form.get(k)]
    return ("&" + "&".join(parts)) if parts else ""


@router.post("/assessment/{aid}/approve")
async def approve(request: Request, aid: str, user: User = Depends(require("tester"))):
    """The plain approve endpoint, kept because scripts and the JSON-ish
    automation path post to it. Bulk actions go through /plan."""
    form = await request.form()
    test_ids = [str(v) for v in form.getlist("test_ids")]
    if test_ids:
        n = state.orch.approve(aid, test_ids, actor=user.name)
        return RedirectResponse(
            f"/assessment/{aid}?flash={quote(f'Approved {n} test(s)')}&phase=run",
            status_code=303,
        )
    return RedirectResponse(
        f"/assessment/{aid}?flash=No+tests+selected&phase=plan", status_code=303
    )


def _parse_kv_lines(text: str, sep: str) -> dict[str, str]:
    """'Key: Value' or 'key=value' per line -> dict. Blank lines and lines
    without the separator are skipped rather than rejected, so a stray blank
    line at the end of a textarea doesn't turn into a validation error."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or sep not in line:
            continue
        k, v = line.split(sep, 1)
        k = k.strip()
        if k:
            result[k] = v.strip()
    return result


def _parse_body_text(text: str):
    """JSON if it parses (so an edited object/array payload round-trips as
    structured data), otherwise the raw string as typed."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


@router.get("/assessment/{aid}/test/{test_id}", response_class=HTMLResponse)
async def test_detail(aid: str, test_id: str, flash: str = "",
                      user: User = Depends(require_page())) -> str:
    a = state.repo.get_assessment(aid)
    test = state.repo.get_test_case(aid, test_id)
    if not a or not test:
        return views.page("Not found", "<p>Test not found.</p>")
    return views.test_detail_page(a, test, flash=flash)


@router.post("/assessment/{aid}/test/{test_id}")
async def test_detail_save(
    aid: str, test_id: str,
    method: str = Form(...), path: str = Form(...),
    headers_text: str = Form(""), query_text: str = Form(""), body_text: str = Form(""),
    user: User = Depends(require("tester")),
):
    existing = state.repo.get_test_case(aid, test_id)
    if not existing:
        return views.page("Not found", "<p>Test not found.</p>")
    request = RequestSpec(
        method=method.strip().upper() or existing.request.method,
        path=path.strip() or existing.request.path,
        headers=_parse_kv_lines(headers_text, ":"),
        query=_parse_kv_lines(query_text, "="),
        body=_parse_body_text(body_text),
        capture=existing.request.capture,  # not exposed for edit; preserved as-is
    )
    state.orch.edit_test_request(aid, test_id, request, actor=user.name)
    flash = "Saved — approval reset to PENDING".replace(" ", "+")
    return RedirectResponse(f"/assessment/{aid}/test/{test_id}?flash={flash}", status_code=303)
