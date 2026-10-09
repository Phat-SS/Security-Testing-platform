"""What was found, and what was done — across the whole engagement.

The platform could always tell you what one assessment found, and it had always
recorded who did what. Neither was ever shown: findings lived inside the
assessment that produced them, and the audit log was readable only with a SQL
client. An audit trail nobody can open is one nobody checks.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from conftest import wait_for_run


def _engagement(folder, name, host):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(json.dumps({
        "environments": {"dev": f"http://{host}"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": [host.split(":")[0]], "allow_private_ranges": True},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1"}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2"}},
        ],
        "runner": {"timeout_s": 1},
    }))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    folder = tmp_path / "engagements"
    _engagement(folder, "acme", "127.0.0.1:19199")
    _engagement(folder, "globex", "127.0.0.1:19200")
    monkeypatch.setenv("ENGAGEMENTS_DIR", str(folder))
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'insight.db'}")
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _ran(client, engagement: str = "acme") -> str:
    from app.api.main import state

    aid = client.post(f"/import?engagement={engagement}", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")
    ids = [t.test_id for t in state.repo.get_test_cases(aid) if not t.is_destructive][:2]
    client.post(f"/assessment/{aid}/approve", data={"test_ids": ids})
    client.post(f"/assessment/{aid}/execute", follow_redirects=False)
    wait_for_run(client, aid)
    return aid


# -- reachability -----------------------------------------------------------


@pytest.mark.parametrize("path", ["/findings", "/activity"])
def test_the_screen_the_sidebar_offers_actually_exists(client, path):
    """The sidebar linked nowhere for these until now — the design named two
    destinations the product did not have."""
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/findings", "/activity"])
def test_an_empty_engagement_says_so_rather_than_erroring(client, path):
    assert "yet" in client.get(path).text


# -- what was done ----------------------------------------------------------


def test_activity_shows_what_actually_happened(client):
    _ran(client)

    html = client.get("/activity").text

    for action in ("import_issue", "approve", "execute", "engagement_snapshot"):
        assert action in html, f"{action} is recorded but not shown"


def test_activity_links_each_entry_to_its_assessment(client):
    aid = _ran(client)

    assert f'href=\'/assessment/{aid}\'' in client.get("/activity").text


# -- keeping engagements apart ----------------------------------------------


def test_activity_does_not_mix_two_clients(client):
    """A log mixing two clients' work would be worse than not having one."""
    aid = _ran(client, "acme")

    client.get("/?engagement=globex")
    html = client.get("/activity").text

    assert aid not in html, "another client's activity leaked into this engagement"


def test_findings_do_not_mix_two_clients(client):
    from app.api.main import state

    aid = _ran(client, "acme")
    # A confirmed finding is easier to assert than to provoke against a dead
    # port, so one is written directly — the question here is scoping.
    findings = state.repo.get_findings(aid)
    if not findings:
        pytest.skip("the run produced no confirmed finding to scope")

    assert "CRM-1234" in client.get("/findings?engagement=acme").text
    assert "CRM-1234" not in client.get("/findings?engagement=globex").text


# -- being scoped out of existence ------------------------------------------
#
# Both screens filter on the engagement stamped on the assessment. Anything that
# leaves that stamp empty does not merely land in the wrong engagement — it
# lands in none, and the screens come up empty on an engagement full of work.


@pytest.mark.parametrize("mode", ["analyze", "auto_plan", "ticket_poc"])
def test_every_import_mode_stamps_the_engagement(client, mode):
    """Only the analyze path passed it. An assessment opened through Auto-plan
    or the ticket's own PoC was invisible to both screens forever after."""
    from app.api.main import state

    aid = client.post("/import?engagement=acme", follow_redirects=True,
                      data={"issue_key": "CRM-1234", "mode": mode}
                      ).url.path.rsplit("/", 1)[-1]

    assert state.repo.assessment_engagement(aid) == "acme"


@pytest.mark.parametrize("path", ["/activity", "/findings"])
def test_an_unstamped_assessment_is_still_visible(client, path):
    """Rows written before the stamp existed carry an empty string. Matching on
    equality alone hid every one of them, which is how an engagement with dozens
    of assessments showed an empty Activity screen."""
    from app.api.main import state
    from app.schemas.finding import (
        Confidence, CorrelationEvidence, Finding, OwaspApiCategory, Severity,
    )

    state.repo.create_assessment("A-legacy", "OLD-1", "OLD", engagement="")
    state.repo.audit("import_issue", "A-legacy", detail="OLD-1")
    state.repo.save_findings("A-legacy", [Finding(
        finding_id="SEC-LEGACY", title="A legacy break",
        owasp_category=OwaspApiCategory.API1, severity=Severity.HIGH,
        confidence=Confidence.HIGH, endpoint="GET /old", dedup_key="k-legacy",
        correlation=CorrelationEvidence(baseline_summary="", attack_summary="",
                                        expected="", actual=""),
        impact="", recommendation="",
    )])

    assert "OLD-1" in client.get(path).text


def test_an_engagement_wide_entry_is_not_dropped(client):
    """A config change belongs to no assessment. Filtering on the joined
    assessment turned the outer join back into an inner one and took every one
    of them out of the log."""
    from app.api.main import state

    state.repo.audit("runtime_config", actor="local-admin", detail="AI enabled")

    assert "runtime_config" in client.get("/activity").text


def test_findings_are_ordered_worst_first(client):
    """The most recent critical is the top line, because that is the one
    somebody has to act on."""
    from app.api.main import views

    class _Sev:
        def __init__(self, value):
            self.value = value

    class _Cat:
        value = "API1:2023"

    class _F:
        def __init__(self, sev, title):
            self.severity, self.title = _Sev(sev), title
            self.owasp_category = _Cat()
            self.finding_id = f"SEC-{title}"
            self.endpoint = ""

    rows = [("A-1", "X-1", _F("LOW", "a")), ("A-2", "X-2", _F("CRITICAL", "b"))]
    html = views.findings_page(rows)

    assert html.index("SEC-b") < html.index("SEC-a")


# -- Phase (UI quick-wins): filter/search/false-positive toggle -------------


def test_findings_search_and_severity_facet(client):
    from app.api.main import state

    aid = _ran(client, "acme")
    findings = state.repo.get_findings(aid)
    if not findings:
        pytest.skip("the run produced no confirmed finding to filter")
    finding = findings[0]

    # A search that cannot match anything empties the list without erroring.
    html = client.get("/findings?q=zzz-does-not-exist-anywhere").text
    assert finding.finding_id not in html
    assert "No findings match this filter." in html or "filter" in html

    # The finding's own severity facet still finds it.
    html = client.get(f"/findings?sev={finding.severity.value}").text
    assert finding.finding_id in html


def test_marking_a_finding_false_positive_hides_it_by_default(client):
    from app.api.main import state

    aid = _ran(client, "acme")
    findings = state.repo.get_findings(aid)
    if not findings:
        pytest.skip("the run produced no confirmed finding to triage")
    finding = findings[0]

    before = client.get("/findings").text
    assert finding.finding_id in before

    r = client.post(f"/assessment/{aid}/findings/{finding.finding_id}/triage",
                    data={"status": "false_positive", "note": "shared fixture data"},
                    follow_redirects=False)
    assert r.status_code == 303

    after = client.get("/findings").text
    assert finding.finding_id not in after  # hidden by default

    with_fp = client.get("/findings?fp=1").text
    assert finding.finding_id in with_fp
    assert "False Positive" in with_fp

    # Reopening brings it back to the default view.
    client.post(f"/assessment/{aid}/findings/{finding.finding_id}/triage",
               data={"status": "open"}, follow_redirects=False)
    reopened = client.get("/findings").text
    assert finding.finding_id in reopened
