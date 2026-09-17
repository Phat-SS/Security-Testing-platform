"""The sidebar's collapsed rail, its overflow behaviour, and the assessment
list's search/filter bar.

Three regressions and one new affordance:

  * a long target URL painted straight through the sidebar's right edge, because
    `text-overflow:ellipsis` was asked of an INLINE box;
  * the assessment card's target used `.trunc`, which the stylesheet only ever
    defined as `td .trunc` — outside a table it was an unstyled class;
  * the footer named `local-admin`, a synthetic single-user placeholder, as
    though a person had signed in;
  * the sidebar can now collapse to an icon rail, which means every nav label
    has to survive somewhere a tester can still read it.
"""

import json
import re
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from app.api import ui
# The package re-exports the FUNCTION under this name, so the module is
# imported by its full path rather than from the package.
from app.api.views.dashboard import dashboard as render_dashboard


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"DEV AU": "https://a-very-long-subdomain.apis.example.com/api/v3"},
        "active_environment": "DEV AU",
        "scope": {"allowed_hosts": ["a-very-long-subdomain.apis.example.com"]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _rule(selector: str) -> str:
    """The declarations of the first rule whose selector list contains
    `selector`, with whitespace squashed."""
    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", ui.CSS):
        if selector in " ".join(block.group(1).split()):
            return " ".join(block.group(2).split())
    raise AssertionError(f"no rule for {selector!r}")


# -- the sidebar collapses ---------------------------------------------------

def test_the_sidebar_has_a_collapse_control_that_names_both_states(client):
    html = client.get("/").text
    assert 'id="sb-toggle"' in html
    # Both labels ship with the button: the JS swaps them, so a rail whose
    # button still says "Collapse" would be lying about what clicking does.
    assert 'data-label-collapse="Collapse sidebar"' in html
    assert 'data-label-expand="Expand sidebar"' in html
    assert 'aria-expanded="true"' in html


def test_the_collapsed_rail_is_narrower_than_the_sidebar():
    assert "var(--sidebar-w-min)" in _rule(':root[data-sb="mini"] .sidebar')


def test_the_choice_is_applied_before_the_first_paint(client):
    """Restoring it after load makes every page open wide and then snap shut."""
    head = client.get("/").text.split("</head>")[0]
    assert "stp-sidebar" in head
    assert "data-sb" in head


def test_every_nav_item_carries_its_label_for_the_rail(client):
    """With `.lbl` hidden the only thing left is the icon, so the label has to
    survive as the tooltip the rail puts back."""
    html = client.get("/").text
    items = re.findall(r'<a href="[^"]*" class="sb-item[^"]*"([^>]*)>', html)
    assert items
    for attrs in items:
        assert "data-label=" in attrs, attrs
    for label in ("Assessments", "Findings", "Activity", "Readiness"):
        assert f'data-label="{label}"' in html


def test_the_engagement_picker_stays_clickable_in_the_rail():
    """Hiding the <select> would leave a dot that looks like a control and is
    not one. It is stretched invisibly over the card instead."""
    rule = _rule(':root[data-sb="mini"] .sb-pick select')
    assert "opacity:0" in rule and "position:absolute" in rule
    assert "display:none" not in rule


def test_the_rail_does_not_exist_on_the_phone_layout():
    """Under 900px the sidebar is already a horizontal strip — there is no
    width to reclaim, and a control that does nothing is worse than none."""
    desktop = ui.CSS[ui.CSS.index("@media (min-width:901px)"):]
    assert ':root[data-sb="mini"] .sidebar' in desktop.split("\n.main{")[0]


# -- nothing overflows the sidebar ------------------------------------------

def test_the_engagement_name_and_url_are_block_boxes():
    """`text-overflow:ellipsis` is ignored on an inline box. These were plain
    <span>s inside a non-flex parent, so a long URL simply painted past the
    sidebar's edge instead of truncating."""
    rule = _rule(".sb-eng .name,.sb-eng .url")
    assert "display:block" in rule
    assert "text-overflow:ellipsis" in rule and "overflow:hidden" in rule
    assert "min-width:0" in _rule(".sb-eng .txt")
    assert "overflow-x:hidden" in _rule(".sidebar")


def test_the_untruncated_target_is_still_reachable(client):
    """Once the URL ellipsises, the tooltip is the only place the whole host
    lives — and which host a run goes to is not a detail worth hiding."""
    html = client.get("/").text
    tip = re.search(r'class="sb-eng" data-tip="([^"]*)"', html, re.S).group(1)
    assert "a-very-long-subdomain.apis.example.com" in tip
    assert "white-space:pre-line" in _rule(".tipbox")


def test_trunc_is_not_scoped_to_a_table_cell():
    """The assessment card uses `.trunc` for its target URL. While the rule was
    `td .trunc` that class did nothing at all outside a table."""
    assert "\n.trunc{" in ui.CSS
    assert "td .trunc{" not in ui.CSS


# -- the synthetic user is not a user ---------------------------------------

def test_single_user_mode_names_nobody_in_the_footer(client):
    """`local-admin` is the placeholder the auth layer uses when auth is OFF.
    Printing it claimed a signed-in identity that does not exist."""
    html = client.get("/").text
    assert "local-admin" not in html
    assert 'class="sb-av"' not in html


def test_a_real_signed_in_user_is_still_named(tmp_path, monkeypatch):
    from app.core.auth import hash_key

    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "vera nguyen", "role": "admin", "api_key_sha256": hash_key("k")},
    ]}))
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(tmp_path / "engagement.json"))
    from app.api.main import app

    with TestClient(app) as c:
        c.post("/login", data={"api_key": "k"}, follow_redirects=False)
        html = c.get("/").text
    assert "vera nguyen" in html
    assert 'class="sb-av">VN<' in html


# -- the assessment list's search and filter bar ----------------------------

def _fake(n: int, status: str = "CREATED"):
    return [SimpleNamespace(id=f"id{i}", issue_key=f"BH-{100 + i}", status=status,
                            target_base_url="https://x.example.com", created_at=None)
            for i in range(n)]


def _render(**kw):
    assessments = kw.pop("assessments", _fake(3))
    return render_dashboard(assessments, "https://x.example.com", False, **kw)


def test_the_status_filter_is_a_segmented_control_with_counts():
    """A dropdown said neither how many matched each status nor that three of
    the four matched nothing — you found out by picking one."""
    html = _render(status_counts={"CREATED": 3, "EXECUTED": 7}, total_matched=10,
                   totals={"ALL": 10, "CREATED": 3, "EXECUTED": 7})
    seg = re.search(r'<div class="seg".*?</div>', html, re.S).group(0)
    assert ">All <b>10</b><" in seg
    assert ">Imported <b>3</b><" in seg
    assert ">Executed <b>7</b><" in seg
    # nothing to find, and it says so rather than being a dead end
    assert 'class="seg-b none" href="/?status=ANALYZED">Designed <b>0</b>' in seg


def test_a_facet_click_keeps_the_search_and_the_search_keeps_the_facet():
    html = _render(q="BH-14", status="EXECUTED", sort="issue", per=48,
                   status_counts={"EXECUTED": 3}, total_matched=3,
                   totals={"ALL": 9, "EXECUTED": 3})
    # every facet link carries the query, the sort and the page size
    for link in re.findall(r'<a class="seg-b[^"]*" href="([^"]+)"', html):
        assert "q=BH-14" in link and "sort=issue" in link and "per=48" in link
    # ...and the form carries the facet, so Enter in the box does not drop it
    assert '<input type="hidden" name="status" value="EXECUTED">' in html


def test_the_count_distinguishes_the_filter_from_the_install():
    filtered = _render(q="BH", status_counts={"CREATED": 3}, total_matched=3,
                       totals={"ALL": 40, "CREATED": 40})
    assert ">3 of 40<" in filtered
    plain = _render(total_matched=40, status_counts={"CREATED": 40},
                    totals={"ALL": 40, "CREATED": 40})
    assert ">40 assessments<" in plain


def test_the_summary_strip_counts_the_install_not_the_page():
    """`assessments` is ONE WINDOW of the list. Counting it made a 40-assessment
    install read "24 Assessments" the moment paging started."""
    html = _render(assessments=_fake(24), per=24, total_matched=40,
                   totals={"ALL": 40, "CREATED": 31, "EXECUTED": 9})
    strip = re.search(r'<div class="summary-row">.*?</div></div>', html, re.S).group(0)
    assert ">40<" in strip and ">24<" not in strip


def test_clearing_is_offered_only_when_something_is_filtered():
    assert "Clear filters" in _render(status="EXECUTED", total_matched=1,
                                      totals={"ALL": 3, "CREATED": 3})
    assert "Clear filters" not in _render(total_matched=3, totals={"ALL": 3, "CREATED": 3})


def test_the_search_box_has_its_own_reset():
    with_q = _render(q="BH-142", total_matched=1, totals={"ALL": 3, "CREATED": 3})
    assert 'class="f-x"' in with_q
    assert 'class="f-x"' not in _render(total_matched=3, totals={"ALL": 3, "CREATED": 3})


def test_paging_has_a_control_at_all():
    """`per` and `page` were honoured server-side but nothing rendered them, so
    page 2 was reachable only by editing the URL — which made "Per page" a
    setting whose only visible effect was hiding assessments."""
    html = _render(assessments=_fake(12), per=12, page_no=2, total_matched=40,
                   totals={"ALL": 40, "CREATED": 40})
    pager = re.search(r'<div class="pager">.*?</div>', html, re.S).group(0)
    assert 'href="/?per=12"' in pager
    assert 'href="/?per=12&amp;page=3"' in pager
    assert '<span class="on">2</span>' in pager
    # one page needs no pager
    assert '<div class="pager">' not in _render(total_matched=3,
                                                totals={"ALL": 3, "CREATED": 3})


def test_the_pager_carries_the_filter():
    html = _render(assessments=_fake(12), q="BH", status="CREATED", per=12, page_no=1,
                   total_matched=40, totals={"ALL": 40, "CREATED": 40})
    pager = re.search(r'<div class="pager">.*?</div>', html, re.S).group(0)
    for link in re.findall(r'href="([^"]+)"', pager):
        assert "q=BH" in link and "status=CREATED" in link


def test_the_old_flat_toolbar_is_gone_from_the_list():
    html = _render(total_matched=3, totals={"ALL": 3, "CREATED": 3})
    assert 'class="toolbar"' not in html
    assert 'class="filters"' in html
