"""Running approved tests, and re-running one execution or a whole assessment.
"""

from __future__ import annotations

import html
import logging
import re
from functools import partial
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Header
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)

from app.api import views
from app.api.deps import require
from app.api.errors import execute_error, import_error
from app.api.jobs import RunProgress, create_operation_job, run_operation_job, start_operation_job
from app.api.runtime import state
from app.api.views.assessment import progress as progress_view
from app.core import preflight
from app.core import snapshot
from app.core.auth import User
from app.core.config import settings_with_overrides
from app.execution.adaptive import AdaptiveBudget

from app.orchestrator import Orchestrator
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/assessment/{aid}/run-panel", response_class=HTMLResponse)
async def run_panel(aid: str, user: User = Depends(require("viewer"))) -> str:
    """The live panel's markup, for the poll to swap in.

    HTML rather than JSON so there is one renderer: the panel served with the
    page and the panel served to the poll are produced by the same function, in
    the language the viewer chose.
    """
    return progress_view.panel_fragment(aid, state.repo.latest_job(aid, "execute"))


@router.post("/assessment/{aid}/execute")
async def execute(aid: str, environment: str = Form(""), include_destructive: bool = Form(False),
                  adaptive: bool = Form(False),
                  user: User = Depends(require("tester")),
                  idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    eng = state.engagement
    base_url = eng.environments.get(environment or eng.active_environment, eng.target_base_url)
    if not base_url:
        return RedirectResponse(f"/assessment/{aid}?flash=Execution+disabled:+no+engagement+configured",
                                status_code=303)
    # Adaptive follow-ups are generated and run without a human reading them,
    # and the planner that writes them has just read the target's own response
    # body — attacker-controlled text. So an unattended follow-up is never a
    # write, whatever this run allows: approving destructive tests a human READ
    # is not consent to destructive tests nobody read, and a hostile response
    # must not be able to steer the loop into one.
    budget = AdaptiveBudget(allow_destructive=False) if adaptive else None
    job, created = create_operation_job(aid, "execute", idempotency_key)
    if not created:
        # The same Idempotency-Key twice is a resubmit, not a second run. Send
        # the browser to watch the job it already started.
        return RedirectResponse(
            f"/assessment/{aid}?phase=run&job={quote(job.job_id, safe='')}", status_code=303
        )
    settings = settings_with_overrides(eng.runner)
    # Captured here, not inside the orchestrator: this layer is the one that can
    # see the engagement and which environment was chosen for this run.
    context = snapshot.capture(
        eng, base_url=base_url, environment=environment or eng.active_environment,
        settings=settings,
    )
    progress = RunProgress(job.job_id)

    def _summarise(execs) -> dict:
        # `execute()` uses HttpRunner.run_safe(), which turns a per-test
        # exception (a persona missing from the vault, say) into an ERROR
        # execution rather than raising — the batch no longer aborts, but that
        # also means an ERROR is only ever visible if it is counted here.
        counts: dict[str, int] = {}
        for ex in execs:
            key = ex.verdict.result.value
            counts[key] = counts.get(key, 0) + 1
        return {**progress.payload(), "completed": True, "verdicts": counts,
                "n_executions": len(execs)}

    start_operation_job(
        job,
        partial(
            state.orch.execute, aid, base_url, eng.scope, eng.vault, settings,
            include_destructive=include_destructive, adaptive=budget,
            on_progress=progress, engagement_snapshot=context,
        ),
        on_done=_summarise,
    )
    # Straight back to the Run phase, which now polls this job. Waiting here
    # for a 300-test run meant a blank tab for five minutes and a gateway
    # timeout that left the run going with nobody able to watch it.
    return RedirectResponse(
        f"/assessment/{aid}?phase=run&job={quote(job.job_id, safe='')}", status_code=303
    )



# -- re-running a single execution -------------------------------------------
#
# Called by fetch() from the report's Execution Log, so it answers JSON: the
# report is a standalone document that must not navigate away to settle one
# undecided row. The execution id travels in the form body rather than the path
# because it contains "#" (the run tag), which is a fragment delimiter in a URL
# and never reaches the server intact from a hand-built link.


@router.post("/assessment/{aid}/execution/rerun")
async def rerun_execution(aid: str, execution_id: str = Form(...),
                          environment: str = Form(""), confirm: str = Form(""),
                          user: User = Depends(require("tester")),
                          idempotency_key: str | None = Header(None, alias="Idempotency-Key")):
    assessment = state.repo.get_assessment(aid)
    if not assessment:
        return JSONResponse({"ok": False, "error": "Assessment not found."}, status_code=404)

    eng = state.engagement
    # Default to the target this assessment actually ran against — re-running a
    # request against a different environment answers a different question. A
    # name that is not configured is refused rather than quietly falling back:
    # silently sending to a different host than the caller named is the one
    # outcome worse than not sending at all.
    base_url = ""
    if environment:
        base_url = eng.environments.get(environment, "")
        if not base_url:
            return JSONResponse(
                {"ok": False, "error": f"No environment named {environment!r} is configured."},
                status_code=409,
            )

    # The destructive speed bump is a UI policy (type the issue key), so it is
    # checked here where the issue key lives; the orchestrator keeps the hard
    # gate and refuses without an explicit confirmation either way.
    confirmed = confirm.strip() == assessment.issue_key

    job, created = create_operation_job(aid, "rerun_execution", idempotency_key)
    if not created:
        return JSONResponse({"ok": job.state == "SUCCEEDED", "job_id": job.job_id,
                             "state": job.state, "duplicate": True}, status_code=200)

    try:
        original, replay = await run_operation_job(
            job,
            partial(
                state.orch.rerun_execution, aid, execution_id, eng.scope, eng.vault,
                settings_with_overrides(eng.runner), base_url=base_url,
                confirm_destructive=confirmed, actor=user.name,
            ),
        )
    except Orchestrator.RerunRefused as exc:
        return JSONResponse(
            {"ok": False, "error": str(exc), "issue_key": assessment.issue_key},
            status_code=409,
        )
    except Exception as exc:
        headline, hint = execute_error(base_url or assessment.target_base_url, exc)
        return JSONResponse(
            {"ok": False, "error": f"{headline} {html.unescape(_strip_tags(hint))}".strip()},
            status_code=400,
        )

    response = replay.response
    return JSONResponse({
        "ok": True,
        "test_id": replay.test_id,
        "execution_id": replay.execution_id,
        "previous_result": original.verdict.result.value,
        "result": replay.verdict.result.value,
        "confidence": replay.verdict.confidence.value,
        "reason": replay.verdict.reason,
        "status_code": response.status_code if response else None,
        "elapsed_ms": response.elapsed_ms if response else None,
        "changed": replay.verdict.result.value != original.verdict.result.value,
    })


def _strip_tags(markup: str) -> str:
    """The error hints in this module are small HTML fragments; a JSON client
    wants the sentence, not the <a href>."""
    return re.sub(r"<[^>]+>", "", markup)


# -- copying one execution as a curl command ----------------------------------
#
# Deliberately live, never baked into the static report: the report's stored
# request is redacted (see redaction.py), so a curl command that actually
# authenticates has to have the persona's real credential resolved from the
# vault at the moment someone clicks Copy — same trust boundary as re-run
# (requires this endpoint, i.e. the running platform, not a saved copy of the
# report). execution_id travels in the form body for the same reason it does
# on rerun: it contains "#", a URL fragment delimiter.


@router.post("/assessment/{aid}/execution/curl")
async def execution_curl(aid: str, execution_id: str = Form(...),
                         user: User = Depends(require("tester"))):
    assessment = state.repo.get_assessment(aid)
    if not assessment:
        return JSONResponse({"ok": False, "error": "Assessment not found."}, status_code=404)

    try:
        curl = state.orch.build_curl(aid, execution_id, state.engagement.vault, actor=user.name)
    except Orchestrator.RerunRefused as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)

    return JSONResponse({"ok": True, "curl": curl})



# -- re-running --------------------------------------------------------------
#
# "Run it again" is a new assessment of the same issue, not a second pass over
# the old one: regression only exists between assessments, and re-running in
# place would rewrite the conclusions attached to evidence that was already
# reported. Two modes, because they answer different questions:
#
#   same     — did anything change on the target? Same plan, same approvals.
#   reimport — the ticket changed; re-read it and analyze from scratch.


@router.post("/assessment/{aid}/rerun")
async def rerun(aid: str, mode: str = Form("same"), environment: str = Form(""),
                user: User = Depends(require("tester"))):
    source = state.repo.get_assessment(aid)
    if not source:
        return RedirectResponse("/?flash=Assessment+not+found", status_code=303)

    if mode == "reimport":
        try:
            new_id = await state.orch.import_and_analyze(
                source.issue_key,
                engagement=state.repo.assessment_engagement(aid))
        except Exception as exc:
            headline, hint = import_error(source.issue_key, exc)
            return HTMLResponse(views.error_page("Re-import failed", headline, hint),
                                status_code=400)
        return RedirectResponse(
            f"/assessment/{new_id}?flash={quote('Re-imported ' + source.issue_key + ' — design a plan')}",
            status_code=303,
        )

    new_id = state.orch.clone_for_rerun(aid, actor=user.name)
    eng = state.engagement
    base_url = eng.environments.get(environment or eng.active_environment, eng.target_base_url)

    # A re-run stops short of executing when it would be pointless or unsafe, and
    # says why on the new assessment rather than reporting a run that never
    # happened. The new plan is already sitting there for the tester to fix and
    # run themselves.
    approved = state.repo.query_test_cases(new_id, appr="APPROVED", per=1)["total"]
    readiness = preflight.evaluate(eng, state.engagement_path)
    if not base_url:
        return _rerun_landing(new_id, "Cloned the plan. Execution is disabled: no "
                                      "environment is configured.")
    if not approved:
        return _rerun_landing(new_id, "Cloned the plan. Nothing ran: no test in it was "
                                      "approved.")
    if readiness.n_blocking:
        return _rerun_landing(new_id, f"Cloned the plan. Nothing ran: "
                                      f"{readiness.n_blocking} blocking configuration "
                                      f"issue(s).")

    rerun_settings = settings_with_overrides(eng.runner)
    try:
        # Destructive tests are never carried into an automatic re-run. Approving a
        # write probe once, for a run you watched, is not consent to it firing
        # again from a button on a list page.
        execs = state.orch.execute(new_id, base_url, eng.scope, eng.vault, rerun_settings,
                                   include_destructive=False,
                                   # A re-run is a run: it sends packets under
                                   # whatever the authorization is NOW, which is
                                   # exactly the thing a regression diff has to be
                                   # able to tell apart from a real change.
                                   engagement_snapshot=snapshot.capture(
                                       eng, base_url=base_url,
                                       environment=environment or eng.active_environment,
                                       settings=rerun_settings,
                                   ))
    except Exception as exc:
        headline, hint = execute_error(base_url, exc)
        return HTMLResponse(
            views.error_page("Re-run failed", headline, hint,
                             back_href=f"/assessment/{new_id}",
                             back_label="← Back to the new assessment"),
            status_code=400,
        )

    n_fail = sum(1 for ex in execs if ex.verdict.result.value == "FAIL")
    flash = f"Re-ran {len(execs)} test(s), {n_fail} FAIL"
    return RedirectResponse(
        f"/assessment/{new_id}/regression?flash={quote(flash)}", status_code=303
    )


def _rerun_landing(new_id: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"/assessment/{new_id}?flash={quote(message)}", status_code=303)
