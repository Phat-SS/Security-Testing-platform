"""Row/card actions behind `⋯`, bulk delete on the assessment list, the list's
charts, and identifiers shown as Title Case labels without being rewritten."""

from __future__ import annotations

import json
import re

import pytest
from starlette.testclient import TestClient

from app.api import ui


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"dev": "https://api.acme.test", "stage": "https://stage.acme.test"},
        "active_environment": "dev",
        "scope": {"allowed_hosts": ["api.acme.test"]},
        "attacker": "agent_A", "victim": "agent_B",
        "personas": [{"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
                     {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}}],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'act.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _import(client) -> str:
    return client.post("/import", data={"issue_key": "CRM-1234"},
                       follow_redirects=True).url.path.rsplit("/", 1)[-1]


# -- the menu component ----------------------------------------------------------


def test_destructive_items_go_last_behind_a_separator():
    html = ui.action_menu([ui.Item("Delete", action="/x/delete", danger=True),
                           ui.Item("Edit", href="/x/edit")], "Actions for X")
    assert html.index(">Edit<") < html.index('class="am-sep"') < html.index(">Delete<")
    assert 'aria-haspopup="menu"' in html and 'aria-label="Actions for X"' in html


def test_a_form_ref_item_never_nests_a_form():
    html = ui.action_menu([ui.Item("Approve", form_ref="ra-approve-T1")], "Actions")
    assert "<form" not in html and 'form="ra-approve-T1"' in html


def test_menu_text_and_attributes_are_escaped():
    html = ui.action_menu([ui.Item('<b>x</b>', action='/a"b')], 'q"<')
    assert "<b>x</b>" not in html and 'action="/a&quot;b"' in html and 'q&quot;&lt;' in html


# -- assessment list ---------------------------------------------------------------


def test_cards_have_a_selection_box_and_a_menu_not_a_delete_button(client):
    _import(client)
    page = client.get("/").text
    card = page[page.index("class='a-card'"):]
    card = card[:card.index("class='a-card'", 10)] if card.count("class='a-card'") > 1 else card
    assert "class='a-sel' form='bulk-form' name='ids'" in card
    assert 'class="am-btn"' in card
    assert "btn ghost danger" not in card  # the old inline Delete button
    assert 'id="bulk-form"' in page and 'action="/assessments/delete"' in page


def test_bulk_delete_removes_exactly_the_selected_assessments(client):
    from app.api.main import state

    a, b, c = _import(client), _import(client), _import(client)
    r = client.post("/assessments/delete", data={"ids": [a, b]})
    assert r.status_code == 200 and "Deleted 2" in r.text
    left = {x.id for x in state.repo.list_assessments()}
    assert c in left and a not in left and b not in left
    assert sum(1 for x in state.repo.get_audit(a) if x.action == "delete_assessment") <= 1


def test_bulk_delete_skips_unknown_ids_and_refuses_an_empty_or_huge_selection(client):
    a = _import(client)
    r = client.post("/assessments/delete", data={"ids": [a, "A-doesnotexist"]})
    assert "Deleted 1" in r.text and "1 skipped" in r.text
    assert "Nothing selected" in client.post("/assessments/delete", data={}).text
    many = [f"A-{i:010d}" for i in range(201)]
    assert "at most 200" in client.post("/assessments/delete", data={"ids": many}).text


def test_bulk_delete_honours_engagement_isolation(tmp_path, monkeypatch, client):
    """The route is outside /assessment/{aid}, where the middleware does the
    check, so it must make the same decision itself for every id."""
    from app.api.main import state
    from app.core.auth import User

    aid = _import(client)
    monkeypatch.setattr(state.repo, "assessment_engagement", lambda _id: "client-b")
    monkeypatch.setattr(type(state.auth), "enabled", property(lambda self: True))
    from app.api import deps
    restricted = User(name="tess", role="tester", engagements=("client-a",))
    client.app.dependency_overrides[deps.current_user] = lambda: restricted
    try:
        r = client.post("/assessments/delete", data={"ids": [aid]})
    finally:
        client.app.dependency_overrides.clear()
    assert "Deleted 0" in r.text and "1 skipped" in r.text
    assert state.repo.get_assessment(aid) is not None


# -- charts --------------------------------------------------------------------------


def test_charts_render_with_legend_tooltips_and_a_table_view():
    html = ui.charts.outcome_columns(
        [("BH-1", "/a", {"FAIL": 2, "PASS": 3, "BLOCKED": 1})], title="T", sub="S",
        labels={"FAIL": "Fail", "INCONCLUSIVE": "Review", "PASS": "Pass", "OTHER": "Blocked / Error"},
        table_label="Show as Table", empty="none")
    assert 'class="ch-legend"' in html and "Blocked / Error" in html
    assert 'data-tip="BH-1 · Fail: 2"' in html and 'data-tip="BH-1 · Blocked / Error: 1"' in html
    assert "<details class=\"ch-table\">" in html and "<td>3</td>" in html


def test_an_empty_series_says_so_instead_of_drawing_an_empty_frame():
    html = ui.charts.severity_bars([("BH-1", "/a", {})], title="T", sub="S",
                                   labels={s: s.title() for s in ui.charts.SEVERITIES},
                                   table_label="t", empty="No confirmed findings yet.")
    assert "No confirmed findings yet." in html and "ch-row" not in html


def test_chart_colours_are_tokens_defined_in_every_theme():
    for token in ("--sev-critical", "--sev-low", "--out-fail", "--out-review", "--out-pass", "--out-other"):
        assert ui.CSS.count(f"{token}:") == 4, token  # light root, dark media, both data-themes


# -- Title Case labels over identifiers ----------------------------------------------


def test_persona_names_are_labelled_in_title_case_but_never_rewritten(client):
    page = client.get("/config?tab=identities").text
    assert "<option value='agent_A' data-hint='agent_A' selected>Agent A</option>" in page
    assert "<b>Agent A</b>" in page and ">agent_A</span>" in page
    assert 'name="name" value="agent_A"' in page  # the form still posts the identifier


def test_environment_and_endpoint_rows_use_the_menu(client):
    page = client.get("/config?tab=target").text
    assert "Make Default" in page and 'class="am-btn"' in page
    assert "btn sec\" style='padding:4px 10px'>Delete" not in page
    aid = _import(client)
    scope = client.get(f"/assessment/{aid}?phase=scope").text
    assert 'class="am-item ep-edit"' in scope


def test_plan_row_actions_submit_forms_outside_the_bulk_form(client):
    aid = _import(client)
    client.post(f"/assessment/{aid}/design")
    page = client.get(f"/assessment/{aid}?phase=plan").text
    bulk = page[page.index('id="plan-form"'):page.index("</form>", page.index('id="plan-form"'))]
    ref = re.search(r'form="(ra-approve-[^"]+)"', page).group(1)
    assert f'id="{ref}"' not in bulk  # the target form is outside the bulk form
    assert f'id="{ref}"' in page


def test_selects_are_rounded_with_a_drawn_chevron():
    rule = re.search(r"\nselect\{([^}]*)\}", ui.CSS).group(1)
    assert "border-radius:10px" in rule and "appearance:none" in rule and "background-image" in rule


# -- the themed select ------------------------------------------------------------


def test_every_page_ships_the_select_enhancer_and_its_styles(client):
    page = client.get("/").text
    assert "stpEnhanceSelects" in page and ".sx-btn{" in page and ".sx-list{" in page
    # Labels for the search box and the empty state are translated server-side.
    assert 'data-lbl-search="Search Options"' in page and 'data-lbl-nomatch="No Matches"' in page


def test_the_enhancer_keeps_the_native_select_and_its_events():
    """Forms, `required`, no-JS and every page's `change` handler depend on the
    real <select> staying in the document and firing change."""
    js = ui.select.JS
    assert "c.sel.selectedIndex = index" in js
    assert "new Event('change', { bubbles: true })" in js
    assert "sel.hasAttribute('data-native')" in js and "sel.multiple" in js


def test_the_rail_engagement_picker_stays_native():
    """In the collapsed rail it is stretched invisibly over the readiness dot;
    replacing it with a button would leave a dot that does nothing."""
    from app.api.ui.shell import _engagement_card

    html = _engagement_card("A", "https://a", "READY", engagements=[("a", "x"), ("b", "y")],
                            current_engagement="a")
    assert "data-native" in html


def test_no_container_keeps_a_transform_after_its_entrance_animation():
    """`animation-fill-mode: both` keeps the final transform, which makes the
    container the containing block of position:fixed popovers inside it."""
    assert "animation:rise var(--t-slow) var(--ease) both" not in ui.CSS
    assert "animation:rise var(--t-med) var(--ease) both" not in ui.CSS


def test_the_action_menu_is_portalled_while_open():
    assert "document.body.appendChild(menu)" in ui.menu.JS
    assert "open.home.appendChild(open.menu)" in ui.menu.JS
