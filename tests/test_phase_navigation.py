"""What has to stay true once the screen shows one phase at a time.

Splitting a long page into phases moves things out of sight, and everything
below is a case where being out of sight would be wrong: a link that lands on
nothing, a warning only the person who no longer needs it can see, or a phase
that forgets which one you were in when you saved.
"""

from __future__ import annotations

import json
import re

import pytest
from starlette.testclient import TestClient

PHASES = ("scope", "plan", "run", "results")

# `#s-plan` used to address a section on one long page. With one phase rendered
# at a time it addresses nothing: the browser lands on the default phase and the
# fragment matches no element on it.
_DEAD_ANCHOR = re.compile(r'(?:href|action)="[^"]*#s-[a-z]+"')


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"dev": "http://127.0.0.1:19191"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1"}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2"}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'ui.db'}")
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


@pytest.mark.parametrize("phase", PHASES)
def test_no_phase_links_to_a_section_anchor(client, designed, phase):
    html = client.get(f"/assessment/{designed}?phase={phase}").text
    dead = _DEAD_ANCHOR.findall(html)
    assert not dead, f"{phase} still links to sections that are not on the page: {dead}"


@pytest.mark.parametrize("phase", PHASES)
def test_the_readiness_warning_is_visible_from_every_phase(client, designed, phase):
    """A run that will come back entirely BLOCKED should be knowable while you
    are approving tests, not only once you reach the Run phase."""
    client.post("/config/scope", data={"allowed_hosts": "", "blocked_hosts": ""})

    html = client.get(f"/assessment/{designed}?phase={phase}").text
    assert "will block this run" in html, f"{phase} hides the blocking verdict"


@pytest.mark.parametrize("phase", PHASES)
def test_the_stale_plan_warning_is_visible_from_every_phase(client, designed, phase):
    """The reader this warning is for is the one approving the plan, and they
    are not on the Scope phase."""
    client.post(f"/assessment/{designed}/endpoints", follow_redirects=True,
                data={"method": "GET", "path": "/v2/new-surface", "auth_required": "true"})

    html = client.get(f"/assessment/{designed}?phase={phase}").text
    assert "different endpoint list" in html, f"{phase} hides the stale plan"


def test_saving_comes_back_to_the_phase_you_were_in(client, designed):
    """A redirect that dropped the phase would bounce a tester out of the pane
    they were working in on every save."""
    r = client.post(f"/assessment/{designed}/endpoints", follow_redirects=False,
                    data={"method": "GET", "path": "/v2/another", "auth_required": "true"})
    assert "phase=scope" in r.headers["location"]

    r = client.post(f"/assessment/{designed}/approve", follow_redirects=False,
                    data={"test_ids": []})
    assert "phase=plan" in r.headers["location"]


def test_no_section_still_claims_a_step_number(client, designed):
    """The numbers counted six steps that no longer exist — and two sections
    numbered 2 and 4 sitting together in one phase read as a rendering fault."""
    for phase in PHASES:
        html = client.get(f"/assessment/{designed}?phase={phase}").text
        assert 'class="s-num"' not in html, f"{phase} still numbers its sections"


def test_no_copy_sends_the_reader_to_a_step(client, designed):
    """"Regenerate it in step 2" pointed at a step that is now a phase called
    Plan; an instruction naming a thing that is not on screen is worse than
    none."""
    for phase in PHASES:
        html = client.get(f"/assessment/{designed}?phase={phase}").text
        for dead in ("step 1", "step 2", "in step ", "bước 1", "bước 2"):
            assert dead not in html, f"{phase} still refers to {dead!r}"


def test_the_run_phase_is_smaller_than_the_plan_it_no_longer_carries(client, designed):
    """The point of the split: someone opening the screen to press Run is not
    made to download a 64-test approval table first."""
    plan = len(client.get(f"/assessment/{designed}?phase=plan").text)
    run = len(client.get(f"/assessment/{designed}?phase=run").text)
    assert run < plan, f"run={run} is not smaller than plan={plan}"
