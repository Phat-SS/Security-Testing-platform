"""Re-running ONE undecided execution from the Execution Log.

An INCONCLUSIVE verdict is the runner declining to guess: the positive control
failed, the server answered 5xx, or the attack was accepted but no protected
marker was available to prove disclosure. Several of those are transient, and
re-running a whole plan to settle one row is disproportionate.

The two properties that make this safe rather than merely convenient:

  * it re-runs the TEST, not the stored capture. Evidence is redacted before it
    is stored, so replaying those bytes would send `Authorization: ********` and
    call the resulting 401 a result.
  * it APPENDS. The original record is untouched, the new one chains onto it,
    and the evidence chain still verifies across both.
"""

import itertools

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.execution.evidence import verify_chain
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.reporting.html import render_report
from app.schemas.enums import ApprovalStatus, TestStatus
from demo.sample_tests import build_tests, build_vault

BASE = "http://demo-target.local"


# -- a target that answers differently on the second attempt ----------------
#
# The whole point of re-running an undecided row is that the answer can change,
# so the fixture has to be able to change it. First call 500s (INCONCLUSIVE:
# "server error during the attack"); every call after that leaks agent_B's
# marker to agent_A (FAIL: confirmed BOLA).


def _flaky_target():
    counter = itertools.count()

    async def customer(request):
        if next(counter) == 0:
            return JSONResponse({"error": "upstream timeout"}, status_code=502)
        return JSONResponse({
            "id": request.path_params["cid"],
            "email": "beth.victim@example.com",
            "phone": "555-0202",
        })

    return Starlette(routes=[
        Route("/customers/{cid}", customer, methods=["GET", "DELETE"]),
    ])


def _client(app):
    c = TestClient(app, base_url=BASE)
    c.follow_redirects = False
    return c


def _scope():
    return ScopeValidator(ScopePolicy(allowed_hosts={"demo-target.local"}),
                          resolver=lambda h: "203.0.113.5")


def _setup(tests=None):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    orch = Orchestrator(repo, MockJiraMCPClient())
    repo.create_assessment("A-1", "CRM-1234", "CRM")
    repo.save_test_cases("A-1", tests if tests is not None else [build_tests()[0]])
    return repo, orch


def _first_run(orch, client):
    return orch.execute("A-1", BASE, _scope(), build_vault(), Settings.from_env(),
                        client=client)


def _rerun(orch, client, execution_id, **kw):
    return orch.rerun_execution("A-1", execution_id, _scope(), build_vault(),
                                Settings.from_env(), client=client, **kw)


# -- the happy path ---------------------------------------------------------


def test_rerun_appends_a_new_execution_and_leaves_the_original_alone():
    repo, orch = _setup()
    client = _client(_flaky_target())

    first = _first_run(orch, client)[0]
    assert first.verdict.result == TestStatus.INCONCLUSIVE

    original, replay = _rerun(orch, client, first.execution_id)

    # The second attempt reached a real answer...
    assert replay.verdict.result == TestStatus.FAIL
    assert replay.execution_id != first.execution_id
    # ...and the row it came from still says exactly what it said before.
    assert original.verdict.result == TestStatus.INCONCLUSIVE
    stored = repo.get_executions("A-1")
    assert [e.verdict.result for e in stored] == [TestStatus.INCONCLUSIVE, TestStatus.FAIL]
    assert stored[0].evidence_hash == first.evidence_hash


def test_rerun_chains_onto_the_evidence_it_follows():
    _, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    _, replay = _rerun(orch, client, first.execution_id)

    assert replay.prev_hash == first.evidence_hash
    assert verify_chain([first, replay])


def test_rerun_ids_say_they_were_a_targeted_re_run():
    """An auditor reading the log must be able to tell a single re-run from a
    batch round; the id is what carries that, and it is inside the hash."""
    _, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    _, replay = _rerun(orch, client, first.execution_id)

    assert "-rerun-" in replay.execution_id
    assert replay.execution_id.endswith(first.test_id)


def test_rerun_mints_the_finding_it_just_proved():
    repo, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]
    assert repo.get_findings("A-1") == []  # INCONCLUSIVE is a lead, not a finding

    _rerun(orch, client, first.execution_id)

    findings = repo.get_findings("A-1")
    assert len(findings) == 1
    assert "Broken Object Level Authorization" in findings[0].title
    # Numbered from scratch over the whole history — never a second SEC-001.
    assert findings[0].finding_id == "SEC-001"


def test_a_second_rerun_does_not_duplicate_the_finding():
    repo, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    _rerun(orch, client, first.execution_id)
    _rerun(orch, client, first.execution_id)

    assert len(repo.get_executions("A-1")) == 3
    assert [f.finding_id for f in repo.get_findings("A-1")] == ["SEC-001"]


def test_rerun_defaults_to_the_target_the_assessment_actually_ran_against():
    """"Run it again" means the same environment. A different base URL would
    answer a different question while looking like the same button."""
    repo, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    _, replay = _rerun(orch, client, first.execution_id)

    assert repo.get_assessment("A-1").target_base_url == BASE
    assert replay.request.url.startswith(BASE)


def test_rerun_is_audited_with_both_verdicts():
    repo, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    _rerun(orch, client, first.execution_id, actor="phat")

    entry = next(a for a in repo.get_audit("A-1") if a.action == "rerun_execution")
    assert entry.actor == "phat"
    assert "INCONCLUSIVE" in entry.detail and "FAIL" in entry.detail
    assert "evidence_chain_ok=True" in entry.detail


# -- what it refuses to do --------------------------------------------------


def test_rerun_refuses_an_execution_this_assessment_does_not_have():
    _, orch = _setup()
    client = _client(_flaky_target())
    _first_run(orch, client)

    with pytest.raises(Orchestrator.RerunRefused, match="No execution"):
        _rerun(orch, client, "not-a-real-execution")


def test_rerun_refuses_a_test_whose_approval_was_reset():
    """Editing a request resets approval to PENDING. Re-running from a report
    button would then send something nobody reviewed."""
    repo, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    repo.set_approval("A-1", first.test_id, ApprovalStatus.PENDING.value)

    with pytest.raises(Orchestrator.RerunRefused, match="PENDING"):
        _rerun(orch, client, first.execution_id)


def test_rerun_refuses_a_destructive_test_without_explicit_confirmation():
    destructive = build_tests()[0]
    destructive.request.method = "DELETE"
    destructive.is_destructive = True
    _, orch = _setup([destructive])
    client = _client(_flaky_target())
    first = orch.execute("A-1", BASE, _scope(), build_vault(), Settings.from_env(),
                         client=client, include_destructive=True)[0]

    with pytest.raises(Orchestrator.RerunRefused, match="destructive"):
        _rerun(orch, client, first.execution_id)

    # ...and goes ahead once the caller says so in as many words.
    _, replay = _rerun(orch, client, first.execution_id, confirm_destructive=True)
    assert replay.execution_id != first.execution_id


def test_rerun_refuses_when_the_test_is_gone_from_the_plan():
    repo, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]

    repo.delete_test_cases("A-1")

    with pytest.raises(Orchestrator.RerunRefused, match="no longer in the plan"):
        _rerun(orch, client, first.execution_id)


# -- the Execution Log itself -----------------------------------------------


def _report(orch, aid="A-1"):
    return orch.build_report_html(aid)


def test_only_inconclusive_rows_offer_a_rerun_button():
    _, orch = _setup(build_tests())  # BOLA + unauthenticated read
    client = _client(_flaky_target())
    executions = _first_run(orch, client)

    verdicts = {e.test_id: e.verdict.result for e in executions}
    assert verdicts["API1-001"] == TestStatus.INCONCLUSIVE  # first call 502s
    assert verdicts["API2-001"] != TestStatus.INCONCLUSIVE

    html = _report(orch)
    inconclusive = next(e for e in executions
                        if e.verdict.result == TestStatus.INCONCLUSIVE)
    decided = next(e for e in executions
                   if e.verdict.result != TestStatus.INCONCLUSIVE)
    assert f'data-rerun="{inconclusive.execution_id}"' in html
    assert f'data-rerun="{decided.execution_id}"' not in html


def test_the_log_shows_the_request_that_would_be_sent_again():
    """Offering "send this one again" is only defensible if the reader can see
    what that is first."""
    _, orch = _setup()
    client = _client(_flaky_target())
    _first_run(orch, client)

    html = _report(orch)
    assert "<summary>request</summary>" in html
    assert "/customers/2002" in html  # the mutated path, query included
    assert "Credentials are masked" in html


def test_the_log_says_a_rerun_uses_live_credentials_not_the_redacted_capture():
    _, orch = _setup()
    client = _client(_flaky_target())
    _first_run(orch, client)

    html = _report(orch)
    assert "cannot be replayed byte-for-byte" in html
    assert "appended to this log as a new execution" in html


def test_a_report_with_no_assessment_behind_it_offers_no_button():
    """A CLI or demo report has no server to post back to; a button that
    silently 404s is worse than no button."""
    _, orch = _setup()
    client = _client(_flaky_target())
    executions = _first_run(orch, client)

    standalone = render_report(
        title="t", target=BASE, tests={t.test_id: t for t in build_tests()},
        executions=executions, findings=[],
    )
    assert "data-rerun" not in standalone
    assert "<th>Re-run</th>" not in standalone
    # The request panel is not a server feature, so it stays.
    assert "<summary>request</summary>" in standalone


def test_a_destructive_row_carries_the_confirmation_flag_into_the_page():
    destructive = build_tests()[0]
    destructive.request.method = "DELETE"
    destructive.is_destructive = True
    _, orch = _setup([destructive])
    client = _client(_flaky_target())
    orch.execute("A-1", BASE, _scope(), build_vault(), Settings.from_env(),
                 client=client, include_destructive=True)

    html = _report(orch)
    assert 'data-destructive="1"' in html
    assert "Type ' + ISSUE + ' to confirm" in html


# -- the HTTP endpoint the report's button posts to --------------------------
#
# The report is a standalone document, so the button posts with fetch and the
# route answers JSON. What matters here is the contract: a refusal comes back as
# a sentence the button can show verbatim, never as a bare 500.


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'rerun-exec.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)  # empty engagement
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_endpoint_404s_on_an_assessment_that_does_not_exist(api):
    r = api.post("/assessment/nope/execution/rerun", data={"execution_id": "x"})
    assert r.status_code == 404
    assert r.json() == {"ok": False, "error": "Assessment not found."}


def test_endpoint_answers_a_refusal_as_a_sentence_not_a_stack_trace(api):
    aid = api.post("/import", data={"issue_key": "CRM-1234"},
                   follow_redirects=True).url.path.rsplit("/", 1)[-1]

    r = api.post(f"/assessment/{aid}/execution/rerun",
                 data={"execution_id": "never-ran"})

    assert r.status_code == 409
    body = r.json()
    assert body["ok"] is False
    assert "No execution never-ran" in body["error"]
    assert body["issue_key"] == "CRM-1234"


def test_endpoint_reports_the_new_verdict_against_the_old_one(api, monkeypatch):
    """The button needs enough back to redraw the row without a reload."""
    import app.api.main as main

    aid = api.post("/import", data={"issue_key": "CRM-1234"},
                   follow_redirects=True).url.path.rsplit("/", 1)[-1]

    _, orch = _setup()
    client = _client(_flaky_target())
    original = _first_run(orch, client)[0]
    _, replay = _rerun(orch, client, original.execution_id)

    monkeypatch.setattr(main.state.orch, "rerun_execution",
                        lambda *a, **kw: (original, replay))

    body = api.post(f"/assessment/{aid}/execution/rerun",
                    data={"execution_id": original.execution_id}).json()

    assert body["ok"] is True
    assert body["previous_result"] == "INCONCLUSIVE"
    assert body["result"] == "FAIL"
    assert body["changed"] is True
    assert body["status_code"] == 200
    assert body["execution_id"] == replay.execution_id
    assert body["reason"]


def test_endpoint_passes_the_typed_issue_key_through_as_the_destructive_consent(api, monkeypatch):
    """The 'type the issue key' speed bump lives in the UI; the orchestrator
    only ever sees an explicit yes or no."""
    import app.api.main as main

    aid = api.post("/import", data={"issue_key": "CRM-1234"},
                   follow_redirects=True).url.path.rsplit("/", 1)[-1]
    seen = {}

    def _spy(*args, **kwargs):
        seen.update(kwargs)
        raise Orchestrator.RerunRefused("stop here")

    monkeypatch.setattr(main.state.orch, "rerun_execution", _spy)

    api.post(f"/assessment/{aid}/execution/rerun",
             data={"execution_id": "e1", "confirm": "WRONG-1"})
    assert seen["confirm_destructive"] is False

    api.post(f"/assessment/{aid}/execution/rerun",
             data={"execution_id": "e1", "confirm": "CRM-1234"})
    assert seen["confirm_destructive"] is True


# -- the whole path, over a real socket --------------------------------------
#
# Everything above stubs one seam or another. This drives the button's actual
# route against a real HTTP target, so the wiring the tester depends on —
# report renders the id → route resolves the engagement → runner re-sends →
# log grows — is exercised end to end rather than assumed.


@pytest.fixture()
def live_target():
    """A local target that 502s once, then leaks agent_B's marker."""
    import http.server
    import threading

    state = {"calls": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's contract
            state["calls"] += 1
            if state["calls"] == 1:
                payload, code = b'{"error":"upstream timeout"}', 502
            else:
                payload, code = b'{"id":"2002","email":"beth.victim@example.com"}', 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass  # keep pytest output readable

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def live_api(tmp_path, monkeypatch, live_target):
    import json as _json

    cfg = tmp_path / "engagement.json"
    cfg.write_text(_json.dumps({
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {"Authorization": "Bearer tokenA"},
             "role": "agent", "owns": {"customer_id": "1001"},
             "secret_markers": ["alice.buyer@example.com"]},
            {"name": "agent_B", "auth_headers": {"Authorization": "Bearer tokenB"},
             "role": "agent", "owns": {"customer_id": "2002"},
             "secret_markers": ["beth.victim@example.com"]},
        ],
        "environments": {"local": live_target},
        "active_environment": "local",
    }), encoding="utf-8")

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'live.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_button_in_the_report_settles_an_undecided_row_end_to_end(live_api):
    import re

    import app.api.main as main

    repo = main.state.repo
    repo.create_assessment("A-live", "CRM-1234", "CRM")
    repo.save_test_cases("A-live", [build_tests()[0]])

    live_api.post("/assessment/A-live/execute", follow_redirects=True)
    undecided = repo.get_executions("A-live")[0]
    assert undecided.verdict.result == TestStatus.INCONCLUSIVE  # the 502

    # The id the button carries is the one the route accepts — no guessing.
    report = live_api.get("/assessment/A-live/report").text
    exec_id = re.search(r'data-rerun="([^"]+)"', report).group(1)
    assert exec_id == undecided.execution_id

    body = live_api.post("/assessment/A-live/execution/rerun",
                         data={"execution_id": exec_id}).json()

    assert body["ok"] is True
    assert body["previous_result"] == "INCONCLUSIVE"
    assert body["result"] == "FAIL"

    # The log grew; it was not rewritten.
    stored = repo.get_executions("A-live")
    assert [e.verdict.result for e in stored] == [TestStatus.INCONCLUSIVE, TestStatus.FAIL]
    assert verify_chain(stored)

    # The undecided row stays in the log, but it no longer offers a button:
    # it has been answered, and the log says by what.
    settled = live_api.get("/assessment/A-live/report").text
    assert 'data-rerun="' not in settled
    assert "re-run below: <b style='color:#b4232a'>FAIL</b>" in settled


def test_an_older_undecided_row_says_what_the_re_run_came_back_with():
    """Executions accumulate, so a test appears more than once. Only the newest
    attempt is re-runnable — an older row is history, and re-sending it would
    repeat a request a later row has already answered."""
    _, orch = _setup()
    client = _client(_flaky_target())
    first = _first_run(orch, client)[0]
    _rerun(orch, client, first.execution_id)

    html = _report(orch)
    assert f'data-rerun="{first.execution_id}"' not in html
    assert "re-run below: <b style='color:#b4232a'>FAIL</b>" in html


def test_endpoint_refuses_an_environment_name_it_does_not_know(api):
    """Silently sending to a different host than the caller named is worse than
    not sending at all."""
    aid = api.post("/import", data={"issue_key": "CRM-1234"},
                   follow_redirects=True).url.path.rsplit("/", 1)[-1]

    r = api.post(f"/assessment/{aid}/execution/rerun",
                 data={"execution_id": "e1", "environment": "prod"})

    assert r.status_code == 409
    assert "No environment named 'prod'" in r.json()["error"]
