"""Being carried to the next phase instead of left in the finished one.

The four phases are a sequence, and two points in it are handovers rather than
places to linger: approving is the last thing Plan is for, and a finished run is
the last thing Run is for. Before this, both dropped the tester back where they
already were — on an approval table they had just emptied, or on a run panel
showing counts whose detail lives elsewhere. Approving hands over to Run; a
finished run opens its HTML report.

The run handover is the fragile one. It was written as a poll that navigates
when the job settles, which works only for a run still in flight when the page
renders. A six-test run against a local target is over before the redirect is
served, so the panel arrived already finished, started no poll, and the handover
never happened for exactly the runs that finish fastest.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"dev": "http://127.0.0.1:19193"},
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
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'handover.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def designed(client) -> str:
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")
    return aid


def _some_test_ids(aid: str, n: int = 2) -> list[str]:
    from app.api.main import state

    return [t.test_id for t in state.repo.get_test_cases(aid) if not t.is_destructive][:n]


# -- plan -> run ------------------------------------------------------------


def test_approving_hands_over_to_the_run_phase(client, designed):
    r = client.post(f"/assessment/{designed}/plan", follow_redirects=False,
                    data={"action": "approve", "test_ids": _some_test_ids(designed)})

    assert "phase=run" in r.headers["location"]


def test_the_plain_approve_endpoint_hands_over_too(client, designed):
    """Scripts and the older form post here rather than to /plan, and a tester
    following either should end up in the same place."""
    r = client.post(f"/assessment/{designed}/approve", follow_redirects=False,
                    data={"test_ids": _some_test_ids(designed)})

    assert "phase=run" in r.headers["location"]


def test_approving_all_matching_a_filter_hands_over_too(client, designed):
    r = client.post(f"/assessment/{designed}/plan", follow_redirects=False,
                    data={"action": "approve", "select_all": "1"})

    assert "phase=run" in r.headers["location"]


@pytest.mark.parametrize("action", ["reject", "reset"])
def test_only_approving_leaves_the_plan(client, designed, action):
    """Rejecting is a plan edit, not the end of the phase — the tester is still
    reading the table and has to stay on it."""
    r = client.post(f"/assessment/{designed}/plan", follow_redirects=False,
                    data={"action": action, "test_ids": _some_test_ids(designed)})

    assert "phase=plan" in r.headers["location"]


def test_approving_nothing_stays_put(client, designed):
    """Nothing was approved, so there is nothing to run: sending the tester to
    the Run phase would be telling them a lie about what just happened."""
    r = client.post(f"/assessment/{designed}/plan", follow_redirects=False,
                    data={"action": "approve"})

    assert "phase=plan" in r.headers["location"]


def test_the_handover_does_not_carry_the_plan_filter(client, designed):
    """The filter describes a view of the plan. Run has no use for it, and
    carrying it would put a stale query string on every later plan link."""
    r = client.post(f"/assessment/{designed}/plan", follow_redirects=False,
                    data={"action": "approve", "test_ids": _some_test_ids(designed),
                          "cat": "API1:2023", "sev": "HIGH"})

    assert "cat=" not in r.headers["location"]


# -- run -> report ----------------------------------------------------------


def _finished_run(client, aid: str) -> str:
    """Start a run, wait for it, and answer the job id the redirect carried."""
    from conftest import wait_for_run

    client.post(f"/assessment/{aid}/approve", data={"test_ids": _some_test_ids(aid)})
    r = client.post(f"/assessment/{aid}/execute", follow_redirects=False)
    wait_for_run(client, aid)
    return r.headers["location"].split("job=")[-1]


def test_starting_a_run_carries_the_job_id(client, designed):
    """The whole handover hangs off this parameter: it is what distinguishes
    "I just pressed Run" from "I opened this page"."""
    client.post(f"/assessment/{designed}/approve", data={"test_ids": _some_test_ids(designed)})

    r = client.post(f"/assessment/{designed}/execute", follow_redirects=False)

    assert "phase=run" in r.headers["location"]
    assert "job=" in r.headers["location"]


def test_a_run_that_finished_before_the_page_rendered_still_hands_over(client, designed):
    """The case the poll cannot cover: by the time the browser follows the
    redirect the job has already settled, so no poll starts and nothing would
    carry the tester to what the run produced."""
    job_id = _finished_run(client, designed)

    r = client.get(f"/assessment/{designed}?phase=run&job={job_id}", follow_redirects=False)

    assert r.status_code == 303
    assert r.headers["location"] == f"/assessment/{designed}/report"


def test_the_report_it_opens_actually_renders(client, designed):
    """The handover is only worth having if the page at the end of it is the
    report and not an error — the run has just written the rows it is built
    from."""
    job_id = _finished_run(client, designed)

    r = client.get(f"/assessment/{designed}?phase=run&job={job_id}", follow_redirects=True)

    assert r.status_code == 200
    assert "Executive Summary" in r.text


def test_both_handover_paths_agree_on_where_they_go(client, designed):
    """The poll covers the long runs and the redirect covers the short ones.
    Which one fires is a matter of timing, so they cannot disagree about the
    destination."""
    from app.api.views.assessment import progress

    assert "'/report'" in progress._POLL_JS
    assert "phase=results" not in progress._POLL_JS


def test_the_report_offers_a_way_back(client, designed):
    """The report used to be reached only by opening a new tab, so the tab it
    came from was still there. It is now where a run leaves you."""
    _finished_run(client, designed)

    html = client.get(f"/assessment/{designed}/report").text

    assert f'href="/assessment/{designed}?phase=results"' in html


def test_a_downloaded_report_carries_no_link_back(client, designed):
    """Relative, and read from disk: it would point at a server that is not
    there."""
    _finished_run(client, designed)

    html = client.get(f"/assessment/{designed}/export.html").text

    assert 'class="backlink"' not in html


def test_opening_the_run_phase_later_does_not_bounce(client, designed):
    """Without the job id this is someone opening the screen, not the handover
    from pressing Run — and being thrown to the report every time you try to
    look at the run panel would make the panel unreachable."""
    _finished_run(client, designed)

    r = client.get(f"/assessment/{designed}?phase=run", follow_redirects=False)

    assert r.status_code == 200


def test_a_failed_run_stays_on_the_panel_that_explains_it(client, designed):
    """The report has nothing to show for a run that never produced a result.
    The error does, and it is on the run panel."""
    from app.api.main import state

    job, _ = state.repo.create_job(designed, "execute", "failed-run")
    state.repo.transition_job(job.job_id, "RUNNING")
    state.repo.transition_job(job.job_id, "FAILED", error="target unreachable")

    r = client.get(f"/assessment/{designed}?phase=run&job={job.job_id}",
                   follow_redirects=False)

    assert r.status_code == 200
    assert "target unreachable" in r.text


def test_the_poll_does_not_hand_over_a_failed_run_either(client, designed):
    """Both paths to Results have to agree, or whether the tester sees the
    error depends on how fast the run failed."""
    from app.api.main import state
    from app.api.views.assessment import progress

    job, _ = state.repo.create_job(designed, "execute", "failed-poll")
    state.repo.transition_job(job.job_id, "RUNNING")
    state.repo.transition_job(job.job_id, "FAILED", error="target unreachable")

    fragment = progress.panel_fragment(designed, state.repo.get_job(job.job_id))

    assert 'id="run-finished" data-ok="0"' in fragment


def test_a_job_from_another_assessment_cannot_redirect_this_one(client, designed):
    """The job id arrives in a URL anyone can edit. It decides a redirect, so it
    is checked against the assessment it claims to belong to."""
    other = client.post("/import", data={"issue_key": "CRM-1234"},
                        follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{other}/design")
    job_id = _finished_run(client, other)

    r = client.get(f"/assessment/{designed}?phase=run&job={job_id}", follow_redirects=False)

    assert r.status_code == 200


def test_an_unknown_job_id_is_ignored_rather_than_erroring(client, designed):
    r = client.get(f"/assessment/{designed}?phase=run&job=J-nope", follow_redirects=False)

    assert r.status_code == 200
