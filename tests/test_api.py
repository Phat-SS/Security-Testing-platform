"""Smoke test for the FastAPI UI + JSON API, fully offline.

Uses a temp SQLite file and the empty default engagement (so execution is
correctly disabled). The execute-against-a-live-target path is covered by
test_orchestrator and the demo.
"""

import os

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)  # empty engagement
    # import after env is set so startup builds state with this DB
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["engagement_configured"] is False
    assert body["jira_live"] is False
    assert "CRM-1234" in body["available_issue_keys"]


def test_dashboard_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Security Testing Platform" in r.text
    # the importable keys are advertised from the client, not hardcoded in HTML
    assert "MOCK-345" in r.text


def test_dashboard_has_environments_nav_tab(client):
    r = client.get("/")
    assert "/config/environments" in r.text
    assert client.get("/config/environments").status_code == 200


def test_cross_site_post_blocked_by_csrf_guard(client):
    # A cross-site page cannot forge Origin to match this server's own
    # origin, so this simulates the CSRF attack the guard exists to stop —
    # even though AUTH_ENABLED is off here (treats every request as admin).
    r = client.post("/import", data={"issue_key": "CRM-1234"},
                    headers={"Origin": "https://evil.example"}, follow_redirects=False)
    assert r.status_code == 403


def test_same_origin_post_allowed_by_csrf_guard(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"},
                    headers={"Origin": str(client.base_url).rstrip("/")}, follow_redirects=True)
    assert r.status_code == 200


def test_ticket_url_with_a_dangerous_scheme_is_not_rendered_as_a_link(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True)
    aid = r.url.path.split("/")[-1]
    r = client.get(f"/assessment/{aid}",
                   params={"flash": "Posted to Jira", "ticket_url": "javascript:alert(1)"})
    assert r.status_code == 200
    assert "javascript:" not in r.text


def test_ticket_url_with_https_is_rendered_as_a_link(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True)
    aid = r.url.path.split("/")[-1]
    r = client.get(f"/assessment/{aid}",
                   params={"flash": "Posted to Jira", "ticket_url": "https://jira.example.com/browse/CRM-1234"})
    assert r.status_code == 200
    assert "https://jira.example.com/browse/CRM-1234" in r.text


def test_delete_assessment_removes_it_from_the_dashboard(client):
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True)
    aid = r.url.path.split("/")[-1]
    assert f"'/assessment/{aid}'" in client.get("/").text

    r = client.post(f"/assessment/{aid}/delete", follow_redirects=True)
    assert r.status_code == 200
    assert "Deleted" in r.text
    assert f"'/assessment/{aid}'" not in r.text
    assert client.get(f"/assessment/{aid}").text.count("Assessment not found") == 1


def test_delete_unknown_assessment_is_a_no_op(client):
    r = client.post("/assessment/A-doesnotexist/delete", follow_redirects=True)
    assert r.status_code == 200


def test_unknown_issue_is_a_readable_400_not_a_500(client):
    r = client.post("/import", data={"issue_key": "NOPE-1"}, follow_redirects=True)
    assert r.status_code == 400
    assert "Import failed" in r.text
    assert "NOPE-1" in r.text
    assert "MOCK-345" in r.text  # tells the user what they *can* import


def test_malformed_issue_ref_is_rejected_with_a_hint(client):
    r = client.post("/import", data={"issue_key": "not a key"}, follow_redirects=True)
    assert r.status_code == 400
    assert "not a valid Jira issue reference" in r.text


def test_import_error_page_escapes_user_input(client):
    r = client.post("/import", data={"issue_key": "<script>alert(1)</script>-1"})
    assert r.status_code == 400
    assert "<script>alert(1)</script>" not in r.text


def test_json_api_unknown_issue_is_404_with_available_keys(client):
    r = client.post("/api/assessments", params={"issue_key": "NOPE-1"})
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "issue_not_found"
    assert "MOCK-345" in body["available_issue_keys"]


def test_mock_sample_covers_a_wider_owasp_surface(client):
    r = client.post("/import", data={"issue_key": "MOCK-345"}, follow_redirects=True)
    assert r.status_code == 200
    aid = r.url.path.split("/")[-1]
    analysis = client.get(f"/api/assessments/{aid}").json()["analysis"]
    paths = {e["path"] for e in analysis["endpoints"]}
    assert "/reports/{reportId}" in paths
    assert "/reports/export" in paths
    # admin role + a caller-supplied callback url must both be picked up
    assert "admin" in analysis["actors"]
    cats = {m["category"] for m in analysis["owasp_mappings"]
            if m["applicability"] == "APPLICABLE"}
    assert {"API1:2023", "API5:2023", "API7:2023"} <= cats


def test_full_ui_flow_without_execution(client):
    # import + analyze
    r = client.post("/import", data={"issue_key": "CRM-1234"}, follow_redirects=True)
    assert r.status_code == 200
    assert "CRM-1234" in r.text
    aid = r.url.path.split("/")[-1]

    # design
    r = client.post(f"/assessment/{aid}/design",
                    data={"poc_python": "import requests\nrequests.get('https://x/customers/2002')"},
                    follow_redirects=True)
    assert "OWASP Coverage" in r.text
    assert "API1:2023" in r.text

    # JSON view shows generated tests
    data = client.get(f"/api/assessments/{aid}").json()
    assert data["tests"]
    test_ids = [t["test_id"] for t in data["tests"]]

    # approve (dict with a list value → repeated form keys, like a browser)
    r = client.post(f"/assessment/{aid}/approve",
                    data={"test_ids": test_ids[:2]}, follow_redirects=True)
    assert "Approved" in r.text

    # execution is disabled (no engagement) — guarded, not crashing
    r = client.post(f"/assessment/{aid}/execute", follow_redirects=True)
    assert "Execution disabled" in r.text or "no engagement" in r.text.lower()

    # report + comment preview render
    assert client.get(f"/assessment/{aid}/report").status_code == 200
    assert "CRM-1234" in client.get(f"/assessment/{aid}/comment").text

    # HTML export downloads the same report as an attachment
    r = client.get(f"/assessment/{aid}/export.html")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == f"attachment; filename={aid}.html"
    assert "CRM-1234" in r.text
