"""The assessment screen's structure.

The redesign's claims, asserted rather than eyeballed: inputs come before the
things derived from them, every piece of jargon carries its own explanation, and
a step that is finished folds away instead of adding to the scroll.
"""

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'ui.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _repo():
    import app.api.main as main

    return main.state.repo


def _import(client) -> str:
    return client.post("/import", data={"issue_key": "CRM-1234"},
                       follow_redirects=True).url.path.rsplit("/", 1)[-1]


def _positions(html: str, ids: list[str]) -> list[int]:
    out = []
    for sid in ids:
        marker = f'id="{sid}"'
        assert marker in html, f"section {sid} is missing from the page"
        out.append(html.index(marker))
    return out


# -- ordering ---------------------------------------------------------------


def test_inputs_come_before_what_is_derived_from_them(client):
    """The old order opened with Endpoints and OWASP Coverage — both empty until
    you design — and put the button that designs below them."""
    page = client.get(f"/assessment/{_import(client)}").text

    order = ["s-endpoints", "s-design", "s-coverage", "s-plan", "s-execute", "s-results"]
    positions = _positions(page, order)
    assert positions == sorted(positions), f"sections are out of order: {order}"


def test_the_design_control_is_above_the_coverage_it_produces(client):
    page = client.get(f"/assessment/{_import(client)}").text

    assert page.index("Generate test plan") < page.index('id="s-coverage"')


# -- collapsing -------------------------------------------------------------


def _is_open(html: str, sid: str) -> bool:
    """Whether the <details> carrying this section id renders expanded."""
    marker = f'id="{sid}"'
    at = html.index(marker)
    start = html.rindex("<details", 0, at)
    tag = html[start:html.index(">", at) + 1]
    return " open" in tag


def test_a_freshly_analyzed_ticket_opens_the_two_steps_you_can_act_on(client):
    page = client.get(f"/assessment/{_import(client)}").text

    assert _is_open(page, "s-endpoints")
    assert _is_open(page, "s-design")
    assert not _is_open(page, "s-execute"), "nothing to execute yet"
    assert not _is_open(page, "s-results"), "nothing has run yet"


def test_once_a_plan_exists_the_page_opens_on_the_plan(client):
    aid = _import(client)
    client.post(f"/assessment/{aid}/design", follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text

    assert _is_open(page, "s-plan")
    assert not _is_open(page, "s-design"), "designing is done; it should fold away"


def test_a_collapsed_section_still_states_what_it_holds(client):
    """A folded step has to keep answering its question, or collapsing it just
    hides information."""
    aid = _import(client)
    client.post(f"/assessment/{aid}/design", follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text

    assert "endpoint(s)" in page
    assert "of" in page and "approved" in page


# -- explanations -----------------------------------------------------------


def test_every_coverage_column_carries_its_own_explanation(client):
    aid = _import(client)
    client.post(f"/assessment/{aid}/design", follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text
    coverage = page[page.index('id="s-coverage"'):page.index('id="s-plan"')]

    for header in ("Category", "State", "From PoC", "Tests"):
        assert header in coverage
    # One ⓘ per header, each with a real explanation attached.
    assert coverage.count('class="i"') >= 4
    assert "COVERED &mdash;" in coverage or "COVERED —" in coverage
    assert "NOT APPLICABLE" in coverage or "not applicable" in coverage


def test_the_from_poc_column_says_it_is_not_a_safety_score(client):
    aid = _import(client)
    client.post(f"/assessment/{aid}/design", follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text

    assert "NOT a" in page and "how secure" in page


def test_the_endpoint_columns_explain_what_they_drive(client):
    page = client.get(f"/assessment/{_import(client)}").text

    assert "BOLA/BOPLA surface" in page          # object ids
    assert "API3" in page                        # writes_properties
    assert "API7" in page or "SSRF" in page      # url fields


def test_a_tooltip_is_reachable_by_keyboard_and_survives_without_javascript(client):
    page = client.get(f"/assessment/{_import(client)}").text

    assert 'class="i" tabindex="0"' in page, "the ⓘ must be focusable"
    assert 'title="' in page, "the explanation must survive with JS disabled"


def test_the_shared_tooltip_is_position_fixed(client):
    """Every table sits in an overflow-x:auto wrapper, which forces overflow-y to
    scroll too — an absolutely positioned bubble is clipped by it."""
    page = client.get(f"/assessment/{_import(client)}").text

    assert ".tipbox{position:fixed" in page


# -- the stat strip and step nav --------------------------------------------


def test_the_stat_strip_summarises_the_run_and_links_into_the_sections(client):
    aid = _import(client)
    client.post(f"/assessment/{aid}/design", follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text

    for label in ("Endpoints", "Tests", "Approved", "Executed", "Findings", "Coverage"):
        assert label in page
    assert 'href="#s-plan"' in page
    assert 'href="#s-coverage"' in page


def test_the_step_nav_marks_where_the_assessment_actually_is(client):
    aid = _import(client)

    page = client.get(f"/assessment/{aid}").text

    assert 'data-step="analyze"' in page
    assert "current" in page.split('class="stepnav"')[1][:900]


# -- theme ------------------------------------------------------------------


def test_a_theme_choice_is_applied_before_first_paint(client):
    """Reading it after the stylesheet would flash the wrong theme on every
    navigation."""
    page = client.get("/").text

    head = page[:page.index("<style>")]
    assert "stp-theme" in head
    assert "data-theme" in head


def test_the_dark_palette_is_defined_for_both_the_media_query_and_the_toggle(client):
    css = client.get("/").text

    assert '@media (prefers-color-scheme:dark){:root:not([data-theme="light"])' in css
    assert ':root[data-theme="dark"]' in css
    assert ':root[data-theme="light"]' in css


# -- tables -----------------------------------------------------------------


def test_tables_have_a_real_header_row(client):
    page = client.get(f"/assessment/{_import(client)}").text

    assert "<thead>" in page
    assert 'scope="col"' in page


def test_a_long_plan_scrolls_inside_its_own_box(client):
    aid = client.post("/import", data={"issue_key": "MOCK-345"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design", data={"depth": "aggressive"},
                follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text

    assert 'class="tblwrap scroll"' in page
    assert ".tblwrap.scroll thead th{position:sticky" in page


# -- results ----------------------------------------------------------------


def test_verdicts_are_shown_so_blocked_does_not_read_as_clean(client):
    """"0 findings" and "every test came back BLOCKED" look identical from the
    outside, and only one of them means the target held up."""
    aid = _import(client)
    client.post(f"/assessment/{aid}/design", follow_redirects=True)
    ids = [t.test_id for t in _repo().get_test_cases(aid)][:2]
    client.post(f"/assessment/{aid}/plan",
                data={"action": "approve", "test_ids": ids}, follow_redirects=True)
    client.post("/config/environments",
                data={"name": "dev", "url": "http://127.0.0.1:19195"})
    client.post(f"/assessment/{aid}/execute", follow_redirects=True)

    page = client.get(f"/assessment/{aid}").text

    assert "Verdicts" in page
    assert _repo().execution_verdicts(aid), "the run should have produced verdicts"
    assert "BLOCKED" in page or "ERROR" in page or "PASS" in page


def test_the_page_head_does_not_reuse_the_app_topbar_class(client):
    """`.topbar` is the application chrome; using it for the page heading made the
    h1 inherit the chrome's flex layout and margins."""
    page = client.get(f"/assessment/{_import(client)}").text

    body = page[page.index('class="wrap"'):]
    assert 'class="pagehead"' in body
    assert body.count('class="topbar"') == 1, "only the app chrome should be a .topbar"
