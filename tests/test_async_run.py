"""A run happens in the background, and the page can watch it.

Before this, `/execute` held the request open until the last test had been
sent. Three hundred approved tests at a second each is five minutes of a blank
tab, and any proxy between the browser and this process is entitled to give up
first — leaving the run going with nobody able to see it.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from conftest import wait_for_run


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        # Nothing listens here, so every test comes back ERROR quickly and
        # deterministically — this is about the run's lifecycle, not verdicts.
        "environments": {"dev": "http://127.0.0.1:19197"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1"}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2"}},
        ],
        "runner": {"timeout_s": 1},
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'run.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def approved(client) -> str:
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")
    from app.api.main import state

    ids = [t.test_id for t in state.repo.get_test_cases(aid) if not t.is_destructive][:2]
    client.post(f"/assessment/{aid}/approve", data={"test_ids": ids})
    return aid


def test_execute_answers_immediately_and_lands_on_the_run_phase(client, approved):
    r = client.post(f"/assessment/{approved}/execute", follow_redirects=False)

    assert r.status_code == 303
    location = r.headers["location"]
    assert "phase=run" in location
    assert "job=J-" in location

    wait_for_run(client, approved)


def test_the_run_is_visible_before_it_finishes(client, approved):
    """The whole point: the state of a run in flight is readable, by a browser
    that never saw the redirect as much as by the one that did."""
    client.post(f"/assessment/{approved}/execute", follow_redirects=False)

    job = client.get(f"/api/assessments/{approved}/run").json()
    assert job["state"] in ("QUEUED", "RUNNING", "SUCCEEDED")
    assert job["kind"] == "execute"
    assert "progress" in job

    wait_for_run(client, approved)


def test_a_finished_run_reports_what_it_did(client, approved):
    client.post(f"/assessment/{approved}/execute", follow_redirects=False)
    job = wait_for_run(client, approved)

    assert job["state"] == "SUCCEEDED", job
    progress = job["progress"]
    assert progress["done"] == progress["total"] > 0
    assert sum(progress["verdicts"].values()) == progress["done"]
    assert progress["recent"], "the feed should carry the results it saw"

    from app.api.main import state

    assert len(state.repo.get_executions(approved)) == progress["done"]


def test_the_panel_says_what_the_job_says(client, approved):
    client.post(f"/assessment/{approved}/execute", follow_redirects=False)
    wait_for_run(client, approved)

    panel = client.get(f"/assessment/{approved}/run-panel").text
    assert "Run Finished" in panel
    assert 'id="run-finished"' in panel, "the poll needs its stop marker"

    # And the same markup is on the Run phase itself, not only behind the poll.
    page = client.get(f"/assessment/{approved}?phase=run").text
    assert "Run Finished" in page
    assert 'id="run-live"' in page


def test_a_second_run_is_not_offered_while_one_is_in_flight(approved):
    """Two concurrent runs would interleave in one evidence chain and send twice
    what the tester approved once.

    The section is rendered directly against a RUNNING job rather than racing a
    real one: timing this against a live run is how a test comes to pass simply
    because the run had already finished.
    """
    from app.api.views.assessment.run import _execute_section
    from app.api.views.assessment.state import _State
    from app.schemas.job import Job

    st = _State(2, {"total": 4, "approved": 2}, 0)
    args = ("A-1", "CRM-1", st, {"dev": "http://127.0.0.1:19197"}, "dev", False, True)

    running = Job(job_id="J-1", assessment_id="A-1", kind="execute", state="RUNNING",
                  idempotency_key="k", result={"done": 1, "total": 2}, error="")
    html = _execute_section(*args, job=running)
    assert "disabled" in html.split('id="execute-btn"')[1][:40], "a second run is offered"
    assert "Running" in html

    done = running.model_copy(update={"state": "SUCCEEDED"})
    finished = _execute_section(*args, job=done)
    assert "disabled" not in finished.split('id="execute-btn"')[1][:40]


def test_the_same_idempotency_key_watches_the_first_run(client, approved):
    """A resubmitted form is a resubmit, not consent to a second run."""
    headers = {"Idempotency-Key": "same-key"}
    first = client.post(f"/assessment/{approved}/execute", headers=headers,
                        follow_redirects=False)
    second = client.post(f"/assessment/{approved}/execute", headers=headers,
                         follow_redirects=False)

    assert second.status_code == 303
    assert first.headers["location"].split("job=")[1] == \
           second.headers["location"].split("job=")[1]

    wait_for_run(client, approved)

    from app.api.main import state

    executions = state.repo.get_executions(approved)
    assert len(executions) == len({x.execution_id for x in executions}), "a test ran twice"


def test_progress_is_not_reported_for_an_assessment_that_never_ran(client, approved):
    job = client.get(f"/api/assessments/{approved}/run").json()
    assert job == {"state": "NONE", "assessment_id": approved}

    assert client.get(f"/assessment/{approved}/run-panel").text == ""


def test_a_run_orphaned_by_a_restart_is_settled_at_startup(tmp_path, monkeypatch):
    """A run lives in a background task, so a restart leaves its row RUNNING
    with nothing to advance it — and the page polls that row forever."""
    db = f"sqlite:///{tmp_path/'orphan.db'}"
    monkeypatch.setenv("DATABASE_URL", db)
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(tmp_path / "engagement.json"))
    from app.api.main import app

    with TestClient(app):
        from app.api.main import state

        state.repo.create_assessment("A-orphan", "CRM-1234", "CRM")
        job, _ = state.repo.create_job("A-orphan", "execute", "k")
        state.repo.transition_job(job.job_id, "RUNNING")
        assert state.repo.get_job(job.job_id).state == "RUNNING"

    # A second startup against the same database is the restart.
    with TestClient(app) as c:
        from app.api.main import state

        settled = state.repo.get_job(job.job_id)
        assert settled.state == "FAILED"
        assert "restarted" in settled.error

        panel = c.get("/assessment/A-orphan/run-panel").text
        assert "Run Failed" in panel
        assert 'id="run-finished"' in panel, "the poll must be able to stop"


# -- concurrency ------------------------------------------------------------


def _sequential_plan(n: int = 6):
    """A plan and a runner that records the order things happened in."""
    import threading
    import time

    from app.schemas.enums import Confidence, TestStatus
    from app.schemas.execution import CapturedRequest, Execution, Verdict

    started, finished = [], []
    lock = threading.Lock()

    class SlowRunner:
        def run_safe(self, test, execution_id, prev_hash=None):
            with lock:
                started.append(test.test_id)
            time.sleep(0.05)
            with lock:
                finished.append(test.test_id)
            return Execution(
                execution_id=execution_id, test_id=test.test_id,
                owasp_category="API1:2023", scope_validated=True,
                request=CapturedRequest(method="GET", url="http://x/1", resolved_ip="1.2.3.4",
                                        headers={}, timestamp="2026-01-01T00:00:00+00:00"),
                response=None,
                verdict=Verdict(result=TestStatus.BLOCKED, reason="r",
                                confidence=Confidence.HIGH,
                                expected_summary="", actual_summary=""),
            )

    class FakeTest:
        def __init__(self, i):
            self.test_id = f"T{i:02d}"

    return SlowRunner(), [FakeTest(i) for i in range(n)], started, finished


def _orchestrator():
    from app.orchestrator import Orchestrator

    return Orchestrator.__new__(Orchestrator)


def test_one_worker_keeps_a_run_strictly_sequential():
    """The default. Concurrency against someone's API is request rate, and rate
    is a blast-radius decision for whoever signed the authorization."""
    runner, tests, started, finished = _sequential_plan()

    _orchestrator()._run_all(runner, tests, prefix="A-1", workers=1, on_progress=None)

    assert started == finished, "something overlapped at one worker"


def test_more_workers_actually_overlap():
    runner, tests, started, finished = _sequential_plan()

    _orchestrator()._run_all(runner, tests, prefix="A-1", workers=4, on_progress=None)

    assert started != finished or len(set(started[:4])) == 4, "nothing overlapped"


def test_results_come_back_in_plan_order_however_they_finish():
    """A run has to be reproducible: the evidence chain is built over this list,
    and it must not depend on which request happened to be fastest."""
    runner, tests, _started, _finished = _sequential_plan(8)

    executions = _orchestrator()._run_all(runner, tests, prefix="A-1", workers=4,
                                          on_progress=None)

    assert [x.test_id for x in executions] == [t.test_id for t in tests]


def test_the_chain_still_verifies_over_a_parallel_run():
    """Running and sealing used to be one step, which is what forced one test at
    a time. Sealing afterwards in plan order has to produce the same intact
    chain."""
    from app.execution.evidence import seal, verify_chain

    runner, tests, _s, _f = _sequential_plan(6)
    executions = _orchestrator()._run_all(runner, tests, prefix="A-1", workers=4,
                                          on_progress=None)

    prev = None
    for ex in executions:
        prev = seal(ex, prev).evidence_hash

    assert verify_chain(executions)


def test_progress_is_reported_once_per_test():
    seen = []
    runner, tests, _s, _f = _sequential_plan(6)

    _orchestrator()._run_all(runner, tests, prefix="A-1", workers=3,
                             on_progress=lambda done, total, ex: seen.append(done))

    assert sorted(seen) == [1, 2, 3, 4, 5, 6]


def test_adaptive_follow_ups_are_never_destructive_even_when_the_run_is(client, approved,
                                                                         monkeypatch):
    """The adaptive planner reads the target's response body before proposing
    the next probe, and nobody reviews what it proposes. A run that includes
    destructive tests a human READ must not hand that consent to probes nobody
    read — otherwise a hostile response could steer the loop into a write."""
    from app.api.main import state

    seen = {}

    def fake_execute(aid, *args, include_destructive=False, adaptive=None, **kwargs):
        seen["include_destructive"] = include_destructive
        seen["budget"] = adaptive
        return []

    monkeypatch.setattr(state.orch, "execute", fake_execute)
    client.post(f"/assessment/{approved}/execute",
                data={"include_destructive": "true", "adaptive": "true"},
                follow_redirects=False)
    wait_for_run(client, approved)

    assert seen["include_destructive"] is True
    assert seen["budget"] is not None
    assert seen["budget"].allow_destructive is False
