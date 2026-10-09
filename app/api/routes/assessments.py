"""Importing a ticket, viewing an assessment, and editing its attack surface.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)
from pydantic import ValidationError

from app.api import views
from app.api.deps import require, require_page
from app.api.errors import import_error
from app.adapters import har, openapi
from app.api.runtime import state
from app.core import preflight
from app.core.auth import User
from app.mcp.jira import parse_issue_ref
from app.schemas.analysis import Endpoint

from app.orchestrator import Orchestrator
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/import")
async def import_issue(issue_key: str = Form(...), mode: str = Form(""),
                       plan: str = Form("false"), depth: str = Form("standard"),
                       user: User = Depends(require("tester"))):
    """Import a ticket and, depending on `mode`, come back with a plan to approve.

    `mode` is one of:
    - "analyze" (default, and what an empty/missing `mode` falls back to): analyze
      only. What you want when the endpoint list needs correcting before any plan
      is worth generating.
    - "auto_plan": the planning agent runs — analyze the ticket and its embedded
      PoC, design, let the AI planner add depth, have the reviewing agent audit
      the result against the ticket's requirements, feed its gaps back for a
      revision round, and land the tester on step 4 with something to read.
    - "ticket_poc": run exactly the PoC embedded in the ticket as the test plan —
      no invented attacks. The plan reviewer still runs once (read-only); the
      result adjudicator still runs at the assess step. If the ticket has no
      embedded PoC, redirects with a flash telling the tester to use auto_plan or
      paste one by hand instead.

    `plan=true` with no `mode` is kept working exactly as before (maps to
    "auto_plan") so any existing scripted `POST /import` behaves as it always has.

    Nothing about the approval gate moves: every test this produces is PENDING.
    """
    try:
        # Always validate: a Jira key is PROJECT-123, and parse_issue_ref also
        # accepts a pasted browse URL. Passing unparseable text straight through
        # used to surface as a confusing "issue does not exist".
        _, key = parse_issue_ref(issue_key)
        effective_mode = mode or ("auto_plan" if plan == "true" else "analyze")
        # Stamped on every import path, not just the analyze one. An assessment
        # created without it is invisible to /findings and /activity, which scope
        # themselves to the current engagement.
        engagement = state.engagements.current_name
        if effective_mode == "ticket_poc":
            aid, _review, poc_found = await state.orch.import_and_run_poc_plan(
                key, engagement=engagement)
            if not poc_found:
                flash = ("No PoC script found in this ticket description — "
                         "use Auto-plan or paste one manually in Design.")
                return RedirectResponse(
                    f"/assessment/{aid}?flash={quote(flash, safe='')}", status_code=303
                )
        elif effective_mode == "auto_plan":
            aid, _review = await state.orch.import_and_plan(
                key, depth=depth or "standard", engagement=engagement)
        else:
            aid = await state.orch.import_and_analyze(key, engagement=engagement)
    except Exception as exc:
        headline, hint = import_error(issue_key, exc)
        return HTMLResponse(views.error_page("Import failed", headline, hint), status_code=400)
    return RedirectResponse(f"/assessment/{aid}", status_code=303)


@router.get("/assessment/{aid}", response_class=HTMLResponse)
async def view_assessment(
    aid: str,
    user: User = Depends(require_page()),
    # Which of the four phases to render. Empty means "wherever this assessment
    # actually is" — see `_State.default_phase`.
    phase: str = "",
    flash: str = "",
    ticket_url: str = "",
    # Set by the redirect that starts a run, and by nothing else. It says "this
    # request is the handover from pressing Run", which is what lets a finished
    # run go straight to Results without a page that already finished bouncing
    # every time someone opens it.
    job: str = "",
    # The test-plan filter lives in the query string so it survives a redirect,
    # can be linked to (the coverage table links straight into a category) and is
    # the same thing a bulk action resolves "all matching" against.
    q: str = "",
    cat: str = "",
    sev: str = "",
    appr: str = "",
    dest: str = "",
    src: str = "",
    sort: str = "id",
    page: int = 1,
    per: int = 25,
) -> str:
    a = state.repo.get_assessment(aid)
    if not a:
        return views.page("Not found", "<p>Assessment not found.</p>")
    # A short run can be over before this redirect is even served, and then the
    # Run panel renders finished, starts no poll, and nothing carries the tester
    # to what the run just produced. A failed run stays put: its error is on the
    # panel, and the report has nothing to show for it.
    if job:
        started = state.repo.get_job(job)
        if (started is not None and started.assessment_id == aid
                and started.kind == "execute" and started.state == "SUCCEEDED"):
            return RedirectResponse(f"/assessment/{aid}/report", status_code=303)
    filters = {"q": q, "cat": cat, "sev": sev, "appr": appr, "dest": dest, "src": src,
               "sort": sort or "id", "per": per}
    plan = state.repo.query_test_cases(aid, page=max(1, page), **filters)
    findings = state.repo.get_findings(aid)
    # Loaded once and used twice: the execution count and the triage summary both
    # need every row, and this page is the one a tester leaves open.
    executions = state.repo.get_executions(aid)
    # Triage is deterministic, needs no key and costs nothing, so the page can
    # say "4 of these need you, 2 need re-running" before anyone asks for a
    # review. The review itself is a POST, because it costs API calls.
    triage_counts = state.orch.triage_counts(aid, executions=executions)
    return views.assessment_page(
        a,
        a.analysis_json or {},
        a.coverage_json or [],
        plan=plan,
        filters=filters,
        n_executions=len(executions),
        n_findings=len(findings),
        findings=findings,
        verdicts=state.repo.execution_verdicts(aid),
        plan_review=state.orch.plan_review(aid),
        run_assessment=state.orch.run_assessment(aid),
        triage=triage_counts,
        finding_triage=state.repo.get_finding_triage(aid),
        uncovered_poc_endpoints=state.orch.uncovered_poc_endpoints(aid),
        environments=state.engagement.environments,
        active_environment=state.engagement.active_environment,
        readiness=preflight.evaluate(state.engagement, state.engagement_path),
        flash=flash,
        ticket_url=ticket_url,
        phase=phase,
        # A run started in another tab is still this assessment's run, so the
        # panel is looked up by assessment rather than by the job id in the URL.
        run_job=state.repo.latest_job(aid, "execute"),
        copilot=state.orch.latest_copilot(aid),
    )


@router.post("/assessment/{aid}/delete")
async def delete_assessment(aid: str, user: User = Depends(require("tester"))):
    state.orch.delete_assessment(aid, actor=user.name)
    return RedirectResponse("/?flash=Deleted+assessment", status_code=303)


#: A ceiling on one bulk delete. The list shows at most 96 per page, so this
#: only ever bites a hand-crafted request — which is the request to bound.
_MAX_BULK_DELETE = 200


@router.post("/assessments/delete")
async def delete_assessments(request: Request, user: User = Depends(require("tester"))):
    """Delete several assessments at once (the list's selection bar).

    This path is NOT under `/assessment/{aid}`, so the engagement middleware
    cannot see which assessments it touches. Each id is therefore checked here,
    the same way the middleware would: it must exist, and with auth on the
    caller must be allowed to see the engagement it was opened under. An id
    that fails either check is skipped and counted, never deleted.
    """
    form = await request.form()
    ids = list(dict.fromkeys(str(v) for v in form.getlist("ids") if str(v).strip()))
    if not ids:
        return RedirectResponse(f"/?flash={quote('Nothing selected')}", status_code=303)
    if len(ids) > _MAX_BULK_DELETE:
        return RedirectResponse(
            f"/?flash={quote(f'Select at most {_MAX_BULK_DELETE} assessments at once')}",
            status_code=303)
    deleted = refused = 0
    for aid in ids:
        if state.repo.get_assessment(aid) is None:
            refused += 1
            continue
        if state.auth.enabled and not user.may_see_engagement(state.repo.assessment_engagement(aid)):
            refused += 1
            continue
        state.orch.delete_assessment(aid, actor=user.name)
        deleted += 1
    flash = f"Deleted {deleted} assessment(s)" + (f", {refused} skipped" if refused else "")
    return RedirectResponse(f"/?flash={quote(flash)}", status_code=303)



# -- editing the attack surface ---------------------------------------------
#
# The endpoint list drives the whole plan, and the extractor that produces it is
# a regex over ticket prose. Before these routes, a missed endpoint or a wrong
# auth flag could only be fixed by editing the Jira ticket and importing again,
# which discarded the plan and every approval along with it.
#
# The endpoint being edited is identified by a form field, not a path segment:
# its identity is "METHOD /path", and a path like `POST /orders/delete` put in
# the URL would be swallowed by the delete route.


def _csv(text: str) -> list[str]:
    """Comma- or space-separated parameter names, de-duplicated, order kept."""
    parts = [p.strip() for p in (text or "").replace(",", " ").split()]
    return list(dict.fromkeys(p for p in parts if p))


def _endpoints_redirect(aid: str, flash: str) -> RedirectResponse:
    return RedirectResponse(
        f"/assessment/{aid}?flash={quote(flash)}&phase=scope", status_code=303
    )


def _first_error(exc: Exception) -> str:
    """A pydantic ValidationError reads as a stack of dicts; a form needs one
    sentence naming the field that was wrong."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        detail = errors()
        if detail:
            loc = ".".join(str(p) for p in detail[0].get("loc", ())) or "value"
            return f"{loc}: {detail[0].get('msg', 'invalid')}"
    return str(exc)


@router.post("/assessment/{aid}/endpoints")
async def save_endpoint(aid: str, method: str = Form("GET"), path: str = Form(""),
                        replaces: str = Form(""),
                        auth_required: bool = Form(False),
                        expected_public: bool = Form(False),
                        object_id_params: str = Form(""),
                        writes_properties: bool = Form(False),
                        url_fields: str = Form(""),
                        user: User = Depends(require("tester"))):
    """Add an endpoint, or replace the one named by `replaces`."""
    verb = "saved" if replaces else "added"
    try:
        endpoint = Endpoint(
            method=(method or "GET").strip().upper(),
            path=(path or "").strip(),
            auth_required=auth_required,
            expected_public=expected_public,
            object_id_params=_csv(object_id_params),
            writes_properties=writes_properties,
            url_fields=_csv(url_fields),
            manual=True,
        )
        if not endpoint.path.startswith("/"):
            raise ValueError("path must start with '/' — it is joined onto the "
                             "approved base URL, so it cannot carry its own host")
        state.orch.upsert_endpoint(aid, endpoint, replaces=replaces, actor=user.name)
    except Orchestrator.EndpointConflict as exc:
        return _endpoints_redirect(aid, f"Not {verb}: {exc}")
    except (ValidationError, ValueError) as exc:
        return _endpoints_redirect(aid, f"Not {verb}: {_first_error(exc)}")
    return _endpoints_redirect(aid, f"{verb.capitalize()} {endpoint.signature}")


#: A real OpenAPI document is well under this; the cap exists so one upload (or
#: a YAML alias bomb) cannot exhaust memory before the parser ever sees it.
_MAX_SPEC_BYTES = 5 * 1024 * 1024


@router.post("/assessment/{aid}/openapi")
async def import_openapi(aid: str, spec: str = Form(""), spec_file: UploadFile | None = File(None),
                         user: User = Depends(require("tester"))):
    """Take the endpoint list from a specification instead of from prose.

    Parsed as data and never fetched: a URL inside a spec names a host somebody
    else chose, and this platform does not send requests anywhere the engagement
    did not authorize. `servers:` is read for information only.
    """
    text = spec or ""
    if len(text.encode("utf-8", "ignore")) > _MAX_SPEC_BYTES:
        return _endpoints_redirect(
            aid, f"Not imported: the spec is larger than {_MAX_SPEC_BYTES // (1024 * 1024)} MiB")
    if spec_file is not None and spec_file.filename:
        raw = await spec_file.read(_MAX_SPEC_BYTES + 1)
        if len(raw) > _MAX_SPEC_BYTES:
            return _endpoints_redirect(
                aid, f"Not imported: the spec is larger than {_MAX_SPEC_BYTES // (1024 * 1024)} MiB")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return _endpoints_redirect(aid, "Not imported: the file is not UTF-8 text")
    if not text.strip():
        return _endpoints_redirect(aid, "Not imported: paste a spec or choose a file")

    try:
        result = state.orch.import_openapi(aid, text, actor=user.name)
    except (openapi.SpecError, har.HarError) as exc:
        return _endpoints_redirect(aid, f"Not imported: {exc}")
    except (ValidationError, ValueError) as exc:
        return _endpoints_redirect(aid, f"Not imported: {_first_error(exc)}")

    flash = (f"Imported {result['title']}: {len(result['added'])} endpoint(s) added, "
             f"{len(result['enriched'])} corrected")
    if result["n_public"]:
        # The fact the prose extractor could never know, and the one that stops
        # an intentionally public route from becoming a false API2 finding.
        flash += f", {result['n_public']} marked public by the spec"
    return _endpoints_redirect(aid, flash)


@router.post("/assessment/{aid}/endpoints/delete")
async def remove_endpoint(aid: str, signature: str = Form(...),
                          user: User = Depends(require("tester"))):
    removed = state.orch.delete_endpoint(aid, signature, actor=user.name)
    return _endpoints_redirect(
        aid, f"Removed {signature}" if removed else "Endpoint not found"
    )


@router.post("/assessment/{aid}/reanalyze")
async def reanalyze(aid: str, user: User = Depends(require("tester"))):
    a = state.repo.get_assessment(aid)
    if not a:
        return RedirectResponse("/?flash=Assessment+not+found", status_code=303)
    try:
        await state.orch.reanalyze(aid, actor=user.name)
    except Exception as exc:
        headline, hint = import_error(a.issue_key, exc)
        return HTMLResponse(
            views.error_page("Re-analysis failed", headline, hint,
                             back_href=f"/assessment/{aid}", back_label="← Back to Assessment"),
            status_code=400,
        )
    return _endpoints_redirect(aid, "Re-analyzed from the ticket")
