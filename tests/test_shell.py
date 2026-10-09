"""The application shell: one palette, a left sidebar, an app bar.

These lock the two properties that were easy to break before the `ui` package
existed — the palette being declared in more than one file, and a page builder
hand-rolling its own chrome.
"""

import json
import re

import pytest
from starlette.testclient import TestClient

from app.api import ui

# A `:root` block that DECLARES a custom property. `:root[...]` is also used as
# a plain state selector (the collapsed sidebar keys off `:root[data-sb=mini]`),
# and those carry no colours — the invariant below is about where the palette
# is defined, not about every rule that happens to be anchored on the root.
_ROOT_BLOCK = re.compile(r":root([^{]*)\{(?=[^{}]*--[a-z-]+:)")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"DEV_BMW AU": "https://dev.bmw.example.com"},
        "active_environment": "DEV_BMW AU",
        "scope": {"allowed_hosts": ["dev.bmw.example.com"]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {"customer_id": "1"}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"customer_id": "2"}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def test_the_palette_has_exactly_four_declaring_blocks():
    """Light on bare `:root`, the guarded dark media query, and one block per
    explicit `data-theme`. More than that means a second file started declaring
    colours again, which is how the toggle came to depend on file order."""
    selectors = [m.group(1).strip() for m in _ROOT_BLOCK.finditer(ui.CSS)]
    assert selectors == ["", ':not([data-theme="light"])', '[data-theme="dark"]',
                         '[data-theme="light"]']


def test_the_dark_media_query_is_guarded():
    """Unguarded, a tester on a dark OS who explicitly picks light does not get
    it — the media query would keep overriding their choice."""
    media = ui.CSS[ui.CSS.index("@media (prefers-color-scheme:dark)"):]
    assert media.startswith('@media (prefers-color-scheme:dark){:root:not([data-theme="light"])')


def test_every_colour_is_defined_in_the_light_root():
    """No colour may be defined ONLY inside a media query or a theme block: the
    bare `:root` has to be a complete palette on its own."""
    light = ui.CSS[:ui.CSS.index("@media")]
    declared = set(re.findall(r"(--[a-z-]+):", light))
    used = set(re.findall(r"var\((--[a-z-]+)", ui.CSS))
    assert not (used - declared), f"only themed, never defaulted: {sorted(used - declared)}"


def test_the_shell_renders_the_sidebar_and_the_app_bar(client):
    html = client.get("/").text
    assert '<aside class="sidebar">' in html
    assert 'class="appbar"' in html
    # the pre-sidebar chrome is gone, not merely hidden
    assert 'class="wrap"' not in html
    assert 'nav class="tabs"' not in html


def test_the_sidebar_names_the_active_engagement_on_every_screen(client):
    for url in ("/", "/config?tab=target", "/config?tab=advanced"):
        html = client.get(url).text
        assert "DEV_BMW AU" in html, url
        assert "dev.bmw.example.com" in html, url


def test_the_readiness_dot_turns_red_when_the_target_host_is_unauthorized(tmp_path, monkeypatch):
    """The dot is the reason the sidebar carries the engagement at all: a run
    against an unauthorized host comes back entirely BLOCKED, and that was only
    discoverable by navigating to the readiness pane."""
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"staging": "https://staging.example.com"},
        "active_environment": "staging",
        "scope": {"allowed_hosts": []},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        html = c.get("/").text
    assert 'class="dot bad"' in html
    assert 'class="dot ok"' not in html


def test_the_sidebar_deep_links_into_each_config_pane(client):
    html = client.get("/").text
    for tab in ("readiness", "target", "identities", "advanced"):
        assert f'href="/config?tab={tab}"' in html


def test_icons_are_svg_not_glyphs():
    """A dingbat in a nav label renders at a different weight in every font
    stack and cannot take `currentColor`."""
    for name in ui.icons.names():
        svg = ui.icon(name)
        assert svg.startswith("<svg") and 'stroke="currentColor"' in svg


def test_the_dot_agrees_with_the_block_list(tmp_path, monkeypatch):
    """The scope validator checks the block-list FIRST and it always wins, so a
    host on both lists is refused. A green dot over a run that will come back
    entirely BLOCKED is worse than no dot."""
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"prod": "https://payments.example.com"},
        "active_environment": "prod",
        "scope": {"allowed_hosts": ["payments.example.com"],
                  "blocked_hosts": ["payments.example.com"]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        html = c.get("/").text
    assert 'class="dot bad"' in html


def test_the_dot_is_red_for_a_private_literal_without_the_escape_hatch(tmp_path, monkeypatch):
    cfg = tmp_path / "engagement.json"
    cfg.write_text(json.dumps({
        "environments": {"lab": "http://127.0.0.1:8000"},
        "active_environment": "lab",
        "scope": {"allowed_hosts": ["127.0.0.1"], "allow_private_ranges": False},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {}},
        ],
    }))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    from app.api.main import app

    with TestClient(app) as c:
        html = c.get("/").text
    assert 'class="dot bad"' in html


def test_every_assessment_screen_highlights_the_assessments_section(client):
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")
    from app.api.main import state

    test_id = state.repo.get_test_cases(aid)[0].test_id

    for url in (f"/assessment/{aid}", f"/assessment/{aid}/test/{test_id}",
                f"/assessment/{aid}/regression", f"/assessment/{aid}/comment"):
        html = client.get(url).text
        assert 'class="sb-item on"' in html, f"{url} left the sidebar unhighlighted"


def test_no_page_uses_a_class_the_stylesheet_no_longer_defines(client):
    """`.topbar`, `.wrap` and `nav.tabs` died with the old chrome. Markup that
    still asks for them loses its layout silently — nothing errors, the row
    just stops being a row."""
    aid = client.post("/import", data={"issue_key": "CRM-1234"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design")
    from app.api.main import state

    test_id = state.repo.get_test_cases(aid)[0].test_id

    dead = ("topbar", "wrap")
    for name in dead:
        assert f".{name}{{" not in ui.CSS, f".{name} is defined again — update this test"

    for url in ("/", "/config", f"/assessment/{aid}", f"/assessment/{aid}/test/{test_id}",
                f"/assessment/{aid}/regression", f"/assessment/{aid}/comment"):
        html = client.get(url).text
        for name in dead:
            assert f'class="{name}"' not in html, f"{url} still uses the dead .{name} class"


def test_the_sidebar_claims_no_user_when_nobody_is_signed_in(tmp_path, monkeypatch):
    """`user_name or "local-admin"` fired exactly when the chrome middleware had
    deliberately suppressed the user, so the login page showed a signed-in
    identity."""
    import json as _json

    from app.core.auth import hash_key

    users = tmp_path / "users.json"
    users.write_text(_json.dumps({"users": [
        {"name": "vera", "role": "viewer", "api_key_sha256": hash_key("k")},
    ]}))
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERS_CONFIG", str(users))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(tmp_path / "engagement.json"))
    from app.api.main import app

    with TestClient(app) as c:
        html = c.get("/login").text
    assert "local-admin" not in html
    assert 'class="sb-av"' not in html


def test_engagement_and_system_pages_use_the_full_width_like_the_workspace(client):
    """The config panes (Readiness, Scope & Targets, Identities, Settings) were
    capped at 1180px while every Workspace page ran full width, so the two
    halves of the sidebar opened visibly different layouts."""
    assert ".content.narrow" not in ui.CSS
    for url in ("/", "/findings", "/activity", "/config?tab=readiness", "/config?tab=target",
                "/config?tab=identities", "/config?tab=advanced"):
        html = client.get(url).text
        assert '<div class="content">' in html, url
        assert "content narrow" not in html, url
