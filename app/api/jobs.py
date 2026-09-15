"""Long operations, recorded as jobs.

A design, a plan round and a run all take long enough that a browser can
resubmit them; the job row is what makes the second submit idempotent rather
than a second run against the target.

A run is also long enough that waiting for it inside the request was wrong.
Three hundred approved tests at a second each is five minutes of a blank tab,
and any proxy or gateway between the browser and this process is entitled to
give up first — at which point the run is still going but nobody can see it.
`start_operation_job` hands the work to a background task and returns
immediately; the page polls `/api/jobs/{job_id}` for the progress the run
writes as it goes.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid

from starlette.concurrency import run_in_threadpool

from app.api.runtime import state
from app.core.redaction import redact_text

logger = logging.getLogger(__name__)

#: Background tasks, held so the event loop does not garbage-collect a run
#: mid-flight — `asyncio.create_task` keeps only a weak reference.
_RUNNING: set[asyncio.Task] = set()


def create_operation_job(aid: str, kind: str, idempotency_key: str | None):
    key = (idempotency_key or f"ui-{uuid.uuid4().hex}").strip()[:128]
    return state.repo.create_job(aid, kind, key)


async def run_operation_job(job, operation):
    """Run `operation` to completion and return its result.

    Still used by the operations a person waits for (designing a plan, a review
    round): they are seconds, not minutes, and a redirect that lands on the
    finished result is better there than a progress bar.
    """
    state.repo.transition_job(job.job_id, "RUNNING")
    try:
        result = await run_in_threadpool(operation)
    except Exception as exc:
        state.repo.transition_job(
            job.job_id, "FAILED",
            error=redact_text(f"{type(exc).__name__}: {exc}")[:2000],
        )
        raise
    state.repo.transition_job(job.job_id, "SUCCEEDED", result={"completed": True})
    return result


def start_operation_job(job, operation, *, on_done=None) -> None:
    """Run `operation` in the background; return as soon as it is queued.

    The job row is marked RUNNING here, before the task is scheduled, so a poll
    that arrives between the redirect and the first line of work sees RUNNING
    rather than QUEUED-forever.
    """
    state.repo.transition_job(job.job_id, "RUNNING")

    async def _run() -> None:
        try:
            result = await run_in_threadpool(operation)
        except Exception as exc:
            logger.exception("background job %s failed", job.job_id)
            state.repo.transition_job(
                job.job_id, "FAILED",
                error=redact_text(f"{type(exc).__name__}: {exc}")[:2000],
            )
            return
        summary = {"completed": True}
        if on_done is not None:
            try:
                summary = on_done(result) or summary
            except Exception:  # pragma: no cover - defensive
                logger.exception("job %s completed but its summary failed", job.job_id)
        state.repo.transition_job(job.job_id, "SUCCEEDED", result=summary)

    task = asyncio.create_task(_run())
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


#: How many finished tests the progress payload carries. Enough to read the
#: last screenful; the executions themselves are on the assessment once the run
#: ends, so this is a live feed, not a second copy of the record.
_RECENT = 40

#: Seconds between progress writes. A run is network-bound, so one row update
#: per test is affordable — but a burst of fast BLOCKED verdicts (a whole plan
#: aimed at an unauthorized host) would otherwise write hundreds of times a
#: second for no one's benefit. A FAIL always writes immediately: that is the
#: line a person watching the run is waiting for.
_THROTTLE_S = 0.4


class RunProgress:
    """Accumulates what a running execution job should say about itself."""

    def __init__(self, job_id: str) -> None:
        self._job_id = job_id
        self._verdicts: dict[str, int] = {}
        self._recent: list[dict] = []
        self._total = 0
        self._done = 0
        self._started = time.monotonic()
        self._last_write = 0.0

    def __call__(self, done: int, total: int, execution) -> None:
        self._done, self._total = done, total
        urgent = execution is None
        if execution is not None:
            result = execution.verdict.result.value
            self._verdicts[result] = self._verdicts.get(result, 0) + 1
            self._recent.append(self._row(execution))
            del self._recent[:-_RECENT]
            urgent = result in ("FAIL", "ERROR") or done == total
        now = time.monotonic()
        if urgent or now - self._last_write >= _THROTTLE_S:
            self._last_write = now
            state.repo.set_job_progress(self._job_id, self.payload())

    @staticmethod
    def _row(execution) -> dict:
        response = execution.response
        return {
            "test_id": execution.test_id,
            "result": execution.verdict.result.value,
            # Already redacted upstream: `HttpRunner` redacts before it seals
            # evidence, so nothing here can carry a token the report would not.
            "reason": (execution.verdict.reason or "")[:180],
            "status": getattr(response, "status_code", None),
            "ms": getattr(response, "elapsed_ms", None),
            "category": execution.owasp_category,
        }

    def payload(self) -> dict:
        elapsed = time.monotonic() - self._started
        remaining = None
        if self._done and self._done < self._total:
            remaining = round(elapsed / self._done * (self._total - self._done))
        return {
            "done": self._done,
            "total": self._total,
            "verdicts": dict(self._verdicts),
            "recent": list(self._recent),
            "elapsed_s": round(elapsed),
            "eta_s": remaining,
        }
