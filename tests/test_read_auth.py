"""Reading is privileged too, once AUTH_ENABLED is on.

Before this, only unsafe methods carried a role dependency: every GET — the
dashboard, the config panes, an assessment's captured evidence, and all five
export formats — answered anyone who could reach the port. That made the
`viewer` role decorative and left the engagement readable by an unauthenticated
caller on a host that had deliberately turned authentication on.
"""

import json

import pytest
from starlette.testclient import TestClient

from app.core.auth import hash_key

VIEWER_KEY = "viewer-key-for-tests"
TESTER_KEY = "tester-key-for-tests"

# Every GET that renders or returns engagement data. /login, /api/health and
# the static-ish routes are deliberately absent: they answer before a session
# exists (a container healthcheck probes /api/health with no credentials).
READ_ROUTES = [
    "/",
    "/config",
    "/config/environments",
    "/api/readiness",
    "/assessment/{aid}",
    "/assessment/{aid}/report",
    "/assessment/{aid}/regression",
    "/assessment/{aid}/comment",
    "/assessment/{aid}/export.html",
    "/assessment/{aid}/export.json",
    "/assessment/{aid}/export.xlsx",
    "/assessment/{aid}/export.pdf",
    "/assessment/{aid}/export.postman",
    "/api/assessments/{aid}",
]


def _engagement(tmp_path):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "target_base_url": "http://127.0.0.1:19191",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1"}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2"}},
        ],
    }))
    return cfg


@pytest.fixture()
def secured(tmp_path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "vera", "role": "viewer", "api_key_sha256": hash_key(VIEWER_KEY)},
        {"name": "tess", "role": "tester", "api_key_sha256": hash_key(TESTER_KEY)},
    ]}))
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(_engagement(tmp_path)))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def single_user(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(_engagement(tmp_path)))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _seed_assessment(client, key: str | None = None) -> str:
    headers = {"X-API-Key": key} if key else {}
    r = client.post("/import", data={"issue_key": "CRM-1234"},
                    headers=headers, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r.headers["location"].split("?")[0].rsplit("/", 1)[-1]


@pytest.mark.parametrize("route", READ_ROUTES)
def test_read_routes_refuse_an_anonymous_caller(secured, route):
    aid = _seed_assessment(secured, TESTER_KEY)
    r = secured.get(route.format(aid=aid), follow_redirects=False)
    assert r.status_code in (303, 401), f"{route} answered anonymously with {r.status_code}"
    if r.status_code == 303:
        assert r.headers["location"].startswith("/login")


@pytest.mark.parametrize("route", READ_ROUTES)
def test_a_viewer_may_read_everything(secured, route):
    aid = _seed_assessment(secured, TESTER_KEY)
    r = secured.get(route.format(aid=aid), headers={"X-API-Key": VIEWER_KEY},
                    follow_redirects=False)
    assert r.status_code == 200, f"{route} refused a viewer: {r.status_code}"


def test_health_says_only_ok_to_an_anonymous_caller(secured):
    body = secured.get("/api/health").json()
    assert body == {"status": "ok"}

    detailed = secured.get("/api/health", headers={"X-API-Key": VIEWER_KEY}).json()
    assert "jira" in detailed and "available_issue_keys" in detailed


def test_an_export_is_recorded_in_the_audit_log(secured):
    from app.api.main import state

    aid = _seed_assessment(secured, TESTER_KEY)
    secured.get(f"/assessment/{aid}/export.json", headers={"X-API-Key": VIEWER_KEY})

    rows = [r for r in state.repo.get_audit(aid) if r.action == "export"]
    assert [(r.actor, r.detail) for r in rows] == [("vera", "downloaded json")]


@pytest.mark.parametrize("route", READ_ROUTES)
def test_single_user_mode_is_unchanged(single_user, route):
    """AUTH_ENABLED unset keeps the local demo wide open — every request is the
    built-in local admin, exactly as before."""
    aid = _seed_assessment(single_user)
    r = single_user.get(route.format(aid=aid), follow_redirects=False)
    assert r.status_code == 200, f"{route} broke single-user mode: {r.status_code}"


def test_the_login_page_names_no_engagement(secured):
    """The sidebar renders beside the login form, and the engagement's name and
    hostname are engagement data — the same data /api/health stopped handing
    out anonymously."""
    html = secured.get("/login").text
    assert "127.0.0.1" not in html
    assert "agent_A" not in html
    assert 'class="sb-eng"' not in html


def test_a_download_client_gets_401_not_the_login_page(secured):
    """`curl -L -o report.json .../export.json` would otherwise follow the
    redirect, write the login HTML into the file and exit 0."""
    aid = _seed_assessment(secured, TESTER_KEY)
    r = secured.get(f"/assessment/{aid}/export.json", headers={"Accept": "*/*"},
                    follow_redirects=False)
    assert r.status_code == 401
    assert "<html" not in r.text.lower()


def test_a_browser_navigation_still_gets_the_login_form(secured):
    aid = _seed_assessment(secured, TESTER_KEY)
    r = secured.get(f"/assessment/{aid}/report",
                    headers={"Accept": "text/html,application/xhtml+xml"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_a_failed_export_is_not_recorded_as_a_download(secured):
    """An audit trail that overstates what happened is not usable in the
    dispute it exists for.

    `raise_server_exceptions=False` because an unknown assessment id still
    reaches `orchestrator.export_json` and raises there — a separate,
    pre-existing defect (it should be a 404). What this pins is only that no
    "downloaded json" row is written for an export that never produced bytes.
    """
    from app.api.main import app, state

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/assessment/A-does-not-exist/export.json",
                  headers={"X-API-Key": VIEWER_KEY})
    assert r.status_code >= 400
    assert not [row for row in state.repo.get_audit("A-does-not-exist")
                if row.action == "export"]
