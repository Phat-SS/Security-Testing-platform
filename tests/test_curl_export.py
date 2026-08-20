"""Copying one execution as a curl command from the Execution Log.

Same redaction problem the rerun feature solves, different resolution: a copy
action must never send anything (so it cannot re-run setup/baseline steps —
real network calls — just to produce a string), so it patches the persona's
real credential back into the exact recorded request instead of re-deriving a
fresh one. Two properties that make this safe rather than merely convenient:

  * it is read-only. No request leaves the runner; nothing in the evidence
    record changes.
  * the real credential is resolved live from the vault, never baked into the
    report — a saved copy of the report cannot produce a live command.
"""

import itertools

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.config import Settings
from app.core.redaction import MASK
from app.core.scope import ScopePolicy, ScopeValidator
from app.database import Repository, init_db, make_engine, make_session_factory
from app.mcp.mock import MockJiraMCPClient
from app.orchestrator import Orchestrator
from app.reporting.curl import render_curl
from app.schemas.execution import CapturedRequest
from app.vault.personas import Persona
from demo.sample_tests import build_tests, build_vault

BASE = "http://demo-target.local"


# -- render_curl: pure, no network, no DB ------------------------------------


def _request(**kw):
    defaults = dict(
        method="GET", url="http://target.test/customers/2002?x=1",
        resolved_ip="203.0.113.10",
        headers={"Authorization": MASK, "Accept": "application/json"},
        body=None, timestamp="2026-08-19T00:00:00Z",
    )
    defaults.update(kw)
    return CapturedRequest(**defaults)


def _persona(**kw):
    defaults = dict(name="agent_A", auth_headers={"Authorization": "Bearer live-token-A"})
    defaults.update(kw)
    return Persona(**defaults)


def test_the_masked_auth_header_is_replaced_with_the_real_credential():
    curl = render_curl(_request(), _persona())
    assert "Bearer live-token-A" in curl
    assert MASK not in curl


def test_with_no_persona_the_header_stays_masked():
    curl = render_curl(_request(), None)
    assert MASK in curl
    assert "live-token-A" not in curl


def test_a_persona_with_no_matching_header_leaves_the_mask_in_place():
    """The persona exists but its auth_headers do not cover this header name —
    there is nothing to restore it from, so it must stay masked rather than be
    silently dropped or guessed at."""
    curl = render_curl(_request(), _persona(auth_headers={"X-Api-Key": "k"}))
    assert MASK in curl
    assert "X-Api-Key" not in curl  # only headers actually on the request are rendered


def test_resolved_ip_is_pinned_with_a_resolve_flag():
    curl = render_curl(_request(resolved_ip="203.0.113.10"), None)
    assert "--resolve target.test:80:203.0.113.10" in curl


def test_https_defaults_the_pinned_port_to_443():
    curl = render_curl(
        _request(url="https://target.test/customers/2002", resolved_ip="203.0.113.10"), None
    )
    assert "--resolve target.test:443:203.0.113.10" in curl


def test_no_resolved_ip_means_no_resolve_flag():
    curl = render_curl(_request(resolved_ip=""), None)
    assert "--resolve" not in curl


def test_the_body_is_included_and_shell_quoted():
    curl = render_curl(_request(body='{"a": "it'"'"'s here"}'), None)
    assert "--data-raw" in curl
    # shlex.quote must make this safe to paste into a shell as one argument —
    # a bare embedded single quote would otherwise break out of the string.
    import shlex
    body_arg = [p for p in shlex.split(curl.replace("\\\n", " ")) if "it" in p]
    assert body_arg


def test_no_body_omits_data_raw():
    curl = render_curl(_request(body=None), None)
    assert "--data-raw" not in curl


def test_method_and_url_are_present():
    curl = render_curl(_request(method="DELETE"), None)
    assert "-X DELETE" in curl
    assert "customers/2002" in curl


# -- Orchestrator.build_curl: reads the vault, never sends anything ----------


def _scope():
    return ScopeValidator(ScopePolicy(allowed_hosts={"demo-target.local"}),
                          resolver=lambda h: "203.0.113.5")


def _client(app):
    c = TestClient(app, base_url=BASE)
    c.follow_redirects = False
    return c


def _flaky_target():
    counter = itertools.count()

    async def customer(request):
        next(counter)
        return JSONResponse({
            "id": request.path_params["cid"],
            "email": "beth.victim@example.com",
            "phone": "555-0202",
        })

    return Starlette(routes=[Route("/customers/{cid}", customer, methods=["GET", "DELETE"])])


def _setup(tests=None):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    orch = Orchestrator(repo, MockJiraMCPClient())
    repo.create_assessment("A-1", "CRM-1234", "CRM")
    repo.save_test_cases("A-1", tests if tests is not None else [build_tests()[0]])
    return repo, orch


def test_build_curl_restores_the_live_credential_for_the_attacking_persona():
    repo, orch = _setup()
    client = _client(_flaky_target())
    executions = orch.execute("A-1", BASE, _scope(), build_vault(), Settings.from_env(),
                              client=client)

    curl = orch.build_curl("A-1", executions[0].execution_id, build_vault())
    assert "Bearer tokenA" in curl  # agent_A is the attacker in build_tests()[0]
    assert MASK not in curl


def test_build_curl_refuses_an_execution_that_does_not_exist():
    _, orch = _setup()
    with pytest.raises(Orchestrator.RerunRefused, match="No execution"):
        orch.build_curl("A-1", "no-such-execution", build_vault())


def test_build_curl_is_audited():
    repo, orch = _setup()
    client = _client(_flaky_target())
    executions = orch.execute("A-1", BASE, _scope(), build_vault(), Settings.from_env(),
                              client=client)

    orch.build_curl("A-1", executions[0].execution_id, build_vault(), actor="phat")
    entry = next(a for a in repo.get_audit("A-1") if a.action == "build_curl")
    assert entry.actor == "phat"
    assert "live credential" in entry.detail


def test_build_curl_does_not_send_any_request():
    """The whole point: unlike rerun, this must never touch the network — the
    fixture's own counter would move if it did."""
    repo, orch = _setup()
    client = _client(_flaky_target())
    executions = orch.execute("A-1", BASE, _scope(), build_vault(), Settings.from_env(),
                              client=client)
    calls = {"n": 0}
    real_send = client.request

    def _spy(*a, **kw):
        calls["n"] += 1
        return real_send(*a, **kw)

    client.request = _spy
    orch.build_curl("A-1", executions[0].execution_id, build_vault())
    assert calls["n"] == 0


# -- the HTTP endpoint --------------------------------------------------------


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'curl-exec.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_endpoint_404s_on_an_assessment_that_does_not_exist(api):
    r = api.post("/assessment/nope/execution/curl", data={"execution_id": "x"})
    assert r.status_code == 404
    assert r.json() == {"ok": False, "error": "Assessment not found."}


def test_endpoint_404s_on_an_execution_that_does_not_exist(api, monkeypatch):

    aid = api.post("/import", data={"issue_key": "CRM-1234"},
                   follow_redirects=True).url.path.rsplit("/", 1)[-1]

    r = api.post(f"/assessment/{aid}/execution/curl",
                 data={"execution_id": "never-ran"})

    assert r.status_code == 404
    body = r.json()
    assert body["ok"] is False
    assert "No execution never-ran" in body["error"]


def test_endpoint_returns_a_curl_command(api, monkeypatch):
    import app.api.main as main

    aid = api.post("/import", data={"issue_key": "CRM-1234"},
                   follow_redirects=True).url.path.rsplit("/", 1)[-1]

    fake_curl = "curl -sS -i -X 'GET' 'http://target.test/x'"
    monkeypatch.setattr(main.state.orch, "build_curl", lambda *a, **kw: fake_curl)

    r = api.post(f"/assessment/{aid}/execution/curl", data={"execution_id": "E-1"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "curl": fake_curl}
