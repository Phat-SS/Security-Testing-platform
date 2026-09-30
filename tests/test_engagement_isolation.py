"""Per-user engagement scoping: a viewer/tester whose `users.json` entry names
`engagements` may only reach those — not every engagement on the box.

Before this, any authenticated user (any role) could read every engagement's
assessments, evidence and exports simply by switching the sidebar's picker or
opening an assessment id directly; role only ever gated WHAT you could do, not
WHICH client's data you were doing it to. This is opt-in per user (an absent
"engagements" key keeps seeing everything, same as before this field existed)
— see `User.may_see_engagement`.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from app.core.auth import hash_key

ACME_KEY = "acme-only-key-for-tests"
UNRESTRICTED_KEY = "unrestricted-key-for-tests"


def _write_engagement(folder, name, host):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(json.dumps({
        "environments": {"dev": f"https://{host}"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": [host]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1001"}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2002"}},
        ],
    }))


@pytest.fixture()
def scoped(tmp_path, monkeypatch):
    folder = tmp_path / "engagements"
    _write_engagement(folder, "acme", "api.acme.example.com")
    _write_engagement(folder, "globex", "api.globex.example.com")

    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "acme-viewer", "role": "viewer", "api_key_sha256": hash_key(ACME_KEY),
         "engagements": ["acme"]},
        {"name": "admin", "role": "admin", "api_key_sha256": hash_key(UNRESTRICTED_KEY)},
    ]}))

    monkeypatch.setenv("ENGAGEMENTS_DIR", str(folder))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'iso.db'}")
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _import(client, engagement, key):
    return client.post(f"/import?engagement={engagement}", data={"issue_key": "CRM-1234"},
                       headers={"X-API-Key": key}, follow_redirects=True).url.path.rsplit("/", 1)[-1]


def test_a_scoped_user_reads_their_own_engagements_assessment(scoped):
    aid = _import(scoped, "acme", ACME_KEY)
    r = scoped.get(f"/assessment/{aid}", headers={"X-API-Key": ACME_KEY})
    assert r.status_code == 200


def test_a_scoped_user_is_refused_another_engagements_assessment(scoped):
    aid = _import(scoped, "globex", UNRESTRICTED_KEY)
    r = scoped.get(f"/assessment/{aid}", headers={"X-API-Key": ACME_KEY})
    assert r.status_code == 403


def test_the_refusal_names_neither_the_engagement_nor_the_assessment(scoped):
    aid = _import(scoped, "globex", UNRESTRICTED_KEY)
    r = scoped.get(f"/assessment/{aid}", headers={"X-API-Key": ACME_KEY})
    assert "globex" not in r.text
    assert aid not in r.text


@pytest.mark.parametrize("suffix", [
    "/report", "/export.html", "/export.json", "/export.md", "/export.xlsx",
    "/export.pdf", "/export.postman", "/regression", "/comment",
])
def test_every_assessment_subroute_is_covered_by_the_same_gate(scoped, suffix):
    """The gate lives in middleware precisely so a new export format or a new
    sub-page needs no engagement check of its own to be covered."""
    aid = _import(scoped, "globex", UNRESTRICTED_KEY)
    r = scoped.get(f"/assessment/{aid}{suffix}", headers={"X-API-Key": ACME_KEY})
    assert r.status_code == 403


def test_a_scoped_user_cannot_select_another_engagement_via_query_param(scoped):
    r = scoped.get("/?engagement=globex", headers={"X-API-Key": ACME_KEY})
    assert r.status_code == 403


def test_an_unrestricted_user_is_unaffected(scoped):
    aid = _import(scoped, "globex", UNRESTRICTED_KEY)
    r = scoped.get(f"/assessment/{aid}", headers={"X-API-Key": UNRESTRICTED_KEY})
    assert r.status_code == 200


def test_the_sidebar_switcher_only_offers_the_scoped_users_own_engagements(scoped):
    # The sidebar's chrome only decorates a real browser SESSION (a cookie),
    # not a bare API-key header — same as everywhere else in the app — so a
    # login is needed to see it at all.
    scoped.post("/login", data={"api_key": ACME_KEY}, follow_redirects=False)
    html = scoped.get("/").text
    # A single-engagement user gets no picker at all (nothing to switch
    # between) — the property under test is that the OTHER engagement never
    # appears anywhere in the sidebar, picker or not.
    assert "globex" not in html
    assert "api.acme.example.com" in html


def test_a_user_with_more_than_one_allowed_engagement_gets_a_picker_limited_to_them(
    tmp_path, monkeypatch,
):
    folder = tmp_path / "engagements"
    _write_engagement(folder, "acme", "api.acme.example.com")
    _write_engagement(folder, "globex", "api.globex.example.com")
    _write_engagement(folder, "initech", "api.initech.example.com")
    key = "two-engagement-key"
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "multi", "role": "viewer", "api_key_sha256": hash_key(key),
         "engagements": ["acme", "globex"]},
    ]}))
    monkeypatch.setenv("ENGAGEMENTS_DIR", str(folder))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'multi.db'}")
    from app.api.main import app

    with TestClient(app) as c:
        c.post("/login", data={"api_key": key}, follow_redirects=False)
        html = c.get("/").text

    assert 'value="acme"' in html
    assert 'value="globex"' in html
    assert 'value="initech"' not in html


def test_an_unstamped_engagement_stays_visible_to_a_scoped_user():
    """An assessment created before engagements existed at all resolves to
    the empty string — `may_see_engagement` treats that the same way
    `_belongs_to` already treats it elsewhere: it belongs to whoever is
    looking, not to nobody."""
    from app.core.auth import User

    scoped_user = User("acme-viewer", "viewer", engagements=("acme",))
    assert scoped_user.may_see_engagement("") is True
    assert scoped_user.may_see_engagement("acme") is True
    assert scoped_user.may_see_engagement("globex") is False

    unrestricted = User("admin", "admin")
    assert unrestricted.may_see_engagement("acme") is True
    assert unrestricted.may_see_engagement("globex") is True
