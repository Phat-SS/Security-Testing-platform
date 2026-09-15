"""More than one engagement, without more than one process.

The engagement is the authorized testing context for one client. There was
exactly one, held as a process-global, so a consultancy testing three clients
ran three copies of the platform — and a tester with two tickets open in two
tabs could point a run at the wrong target by saving the wrong config.

The property that matters is the last one: an assessment resolves to the
engagement it was opened under, never to whatever was last selected.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from app.core import engagements


def _write(folder, name, host, customer_id="1001"):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(json.dumps({
        "environments": {"dev": f"https://{host}"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": [host]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user",
             "owns": {"customer_id": customer_id}},
            {"name": "agent_B", "auth_headers": {}, "role": "user",
             "owns": {"customer_id": "2002"}},
        ],
    }))


@pytest.fixture()
def two_clients(tmp_path, monkeypatch):
    folder = tmp_path / "engagements"
    _write(folder, "acme", "api.acme.example.com")
    _write(folder, "globex", "api.globex.example.com")
    monkeypatch.setenv("ENGAGEMENTS_DIR", str(folder))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'multi.db'}")
    from app.api.main import app

    with TestClient(app) as c:
        yield c


# -- default deny -----------------------------------------------------------


def test_nothing_is_discovered_unless_something_names_it(tmp_path, monkeypatch):
    """A directory of config files sitting on disk beside the code is not a
    human saying where the authorization lives — it is how a checkout, or a
    stale file from another engagement, comes to authorize a run nobody asked
    for."""
    folder = tmp_path / "engagements"
    _write(folder, "acme", "api.acme.example.com")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ENGAGEMENTS_DIR", raising=False)
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)

    assert engagements.discover() == {}

    registry = engagements.Registry()
    assert registry.names() == []
    # And what every caller gets back cannot run anything.
    assert registry.current.scope.policy.allowed_hosts == set()
    assert registry.current.vault.names() == ["anonymous"]


def test_pointing_at_the_directory_is_what_opts_in(tmp_path, monkeypatch):
    folder = tmp_path / "engagements"
    _write(folder, "acme", "api.acme.example.com")
    monkeypatch.setenv("ENGAGEMENTS_DIR", str(folder))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)

    assert engagements.Registry().names() == ["acme"]


def test_a_single_file_install_still_works(tmp_path, monkeypatch):
    """Nothing has to be moved to upgrade."""
    legacy = tmp_path / "engagement.json"
    _write(tmp_path, "engagement", "api.legacy.example.com")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(legacy))
    monkeypatch.delenv("ENGAGEMENTS_DIR", raising=False)

    registry = engagements.Registry()
    assert registry.names() == [engagements.LEGACY_NAME]
    assert "api.legacy.example.com" in registry.current.environments["dev"]


# -- keeping two clients apart ----------------------------------------------


def test_each_engagement_resolves_to_its_own_target(two_clients):
    from app.api.main import state

    acme = state.engagements.get("acme")
    globex = state.engagements.get("globex")

    assert acme.scope.policy.allowed_hosts == {"api.acme.example.com"}
    assert globex.scope.policy.allowed_hosts == {"api.globex.example.com"}


def test_an_assessment_is_stamped_with_the_engagement_it_was_opened_under(two_clients):
    from app.api.main import state

    aid = two_clients.post("/import?engagement=globex", data={"issue_key": "CRM-1234"},
                           follow_redirects=True).url.path.rsplit("/", 1)[-1]

    assert state.repo.assessment_engagement(aid) == "globex"


def test_an_assessment_keeps_its_engagement_when_another_is_selected(two_clients):
    """The property the whole phase exists for: two tickets for two clients open
    in two tabs must not be able to aim one client's run at the other's
    target."""

    aid = two_clients.post("/import?engagement=acme", data={"issue_key": "CRM-1234"},
                           follow_redirects=True).url.path.rsplit("/", 1)[-1]

    # Switch the browser to the other client, then open the assessment again.
    two_clients.get("/?engagement=globex")
    page = two_clients.get(f"/assessment/{aid}").text

    assert "api.acme.example.com" in page
    assert "api.globex.example.com" not in page


def test_the_selection_follows_screens_that_are_not_about_an_assessment(two_clients):
    two_clients.get("/?engagement=globex")

    assert "api.globex.example.com" in two_clients.get("/").text
    assert "api.globex.example.com" in two_clients.get("/config?tab=target").text


def test_an_unknown_engagement_falls_back_rather_than_leaving_nothing(two_clients):
    """Every screen needs an answer; a stale link must not produce a page with
    no engagement at all."""
    page = two_clients.get("/?engagement=does-not-exist")

    assert page.status_code == 200
    assert "acme" in page.text


# -- the picker -------------------------------------------------------------


def test_the_sidebar_offers_the_other_client(two_clients):
    html = two_clients.get("/").text

    assert 'name="engagement"' in html
    assert 'value="acme"' in html and 'value="globex"' in html


def test_the_picker_is_absent_on_an_assessment(two_clients):
    """There the engagement is the one the assessment was opened under, and a
    picker would invite exactly the mistake this prevents."""
    aid = two_clients.post("/import?engagement=acme", data={"issue_key": "CRM-1234"},
                           follow_redirects=True).url.path.rsplit("/", 1)[-1]

    html = two_clients.get(f"/assessment/{aid}").text

    assert 'name="engagement"' not in html


def test_one_engagement_shows_no_picker(tmp_path, monkeypatch):
    """A switcher between one thing is furniture."""
    folder = tmp_path / "engagements"
    _write(folder, "acme", "api.acme.example.com")
    monkeypatch.setenv("ENGAGEMENTS_DIR", str(folder))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'one.db'}")
    from app.api.main import app

    with TestClient(app) as c:
        html = c.get("/").text

    assert 'name="engagement"' not in html
    assert "api.acme.example.com" in html


# -- configuring one of several ---------------------------------------------


def test_saving_config_writes_to_the_selected_engagement_only(two_clients, tmp_path):
    from app.api.main import state

    two_clients.post("/config/environments?engagement=globex",
                     data={"name": "staging", "url": "https://staging.globex.example.com"})

    assert "staging" in state.engagements.get("globex").environments
    assert "staging" not in state.engagements.get("acme").environments


def test_a_rerun_stays_inside_its_engagement(two_clients):
    """A regression diff between two assessments authorized by different
    clients would not mean anything."""
    from app.api.main import state

    aid = two_clients.post("/import?engagement=globex", data={"issue_key": "CRM-1234"},
                           follow_redirects=True).url.path.rsplit("/", 1)[-1]
    two_clients.post(f"/assessment/{aid}/design")
    two_clients.get("/?engagement=acme")  # the browser is now on the other client

    r = two_clients.post(f"/assessment/{aid}/rerun", data={"mode": "reimport"},
                         follow_redirects=False)
    new_id = r.headers["location"].split("/assessment/")[1].split("?")[0].split("/")[0]

    assert state.repo.assessment_engagement(new_id) == "globex"
