"""The application shell: a left sidebar, an app bar, and the content column.

Replaces the two-link topbar. The reasons it is a sidebar:

  * there are more than two destinations now (and Findings/Activity are next),
    and a horizontal bar stops scaling at about four;
  * the active ENGAGEMENT belongs on every screen. It decides where every
    request goes, and it used to be visible only after navigating to the config
    page — which is how a run gets pointed at the wrong environment;
  * the readiness verdict is the one thing that stops a run, so it is a dot in
    the nav rather than a page you have to remember to visit.

The shell owns no page content: `page()` renders the chrome and drops the
caller's body into the content column unchanged, so a view that still builds
its own heading keeps working while the screens are migrated one at a time.
"""

from __future__ import annotations

import json

from app.core.i18n import get_lang, tt as _t

from . import base, icons, tokens
from .base import attr, e

CSS = """
.app{display:flex;min-height:100vh;}
.sidebar{display:flex;flex-direction:column;width:var(--sidebar-w);flex:none;
  background:var(--sidebar);border-right:1px solid var(--border);
  position:sticky;top:0;height:100vh;overflow-y:auto;overflow-x:hidden;
  transition:width .16s ease;}
.sb-top{display:flex;align-items:center;gap:6px;padding:14px 12px 10px;}
.sb-brand{display:flex;align-items:center;gap:9px;flex:1;min-width:0;text-decoration:none;
  color:var(--fg);}
.sb-brand svg{color:var(--accent);flex:none;}
.sb-brand b{font-size:14.5px;letter-spacing:-.01em;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sb-collapse{flex:none;padding:5px;border-radius:var(--radius);border:1px solid transparent;
  background:none;color:var(--faint);cursor:pointer;line-height:0;}
.sb-collapse:hover{background:var(--bg);color:var(--fg);}

/* The engagement card. `.txt` is a flex column and `.name`/`.url` are BLOCKS:
   `text-overflow:ellipsis` is ignored on an inline box, which is how a long
   target URL used to paint straight through the sidebar's right edge. */
.sb-eng{display:flex;align-items:center;gap:9px;margin:0 12px 14px;padding:9px 11px;
  border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);
  text-decoration:none;color:var(--fg);min-width:0;overflow:hidden;}
.sb-eng:hover{border-color:var(--accent-border);}
.sb-pick{padding:6px 8px;}
.sb-pick select{flex:1;min-width:0;width:auto;max-width:100%;border:0;background:none;
  padding:2px 4px;font-size:12.5px;font-weight:600;color:var(--fg);
  text-overflow:ellipsis;}
.sb-eng .dot{width:7px;height:7px;border-radius:50%;flex:none;}
.sb-eng .dot.ok{background:var(--low);box-shadow:0 0 0 3px var(--low-soft);}
.sb-eng .dot.warn{background:var(--med);box-shadow:0 0 0 3px var(--med-soft);}
.sb-eng .dot.bad{background:var(--crit);box-shadow:0 0 0 3px var(--crit-soft);}
.sb-eng .txt{flex:1;min-width:0;display:flex;flex-direction:column;overflow:hidden;}
.sb-eng .name{font-size:12.5px;font-weight:600;}
.sb-eng .url{font-size:11px;color:var(--faint);font-family:var(--mono);}
.sb-eng .name,.sb-eng .url{display:block;max-width:100%;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sb-eng>svg{color:var(--faint);flex:none;}

.sb-nav{display:flex;flex-direction:column;gap:2px;padding:0 12px;}
.sb-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);
  font-weight:700;padding:6px 10px 5px;}
.sb-h+.sb-h,.sb-nav .sb-h:not(:first-child){padding-top:16px;}
.sb-item{position:relative;display:flex;align-items:center;gap:9px;padding:7px 10px;
  border-radius:var(--radius);font-size:13px;color:var(--muted);text-decoration:none;}
.sb-item:hover{background:var(--bg);color:var(--fg);}
.sb-item.on{background:var(--accent-soft);color:var(--accent);font-weight:600;}
.sb-item svg{flex:none;}
.sb-item .lbl{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sb-item .tag{font-size:11px;font-weight:700;font-variant-numeric:tabular-nums;color:var(--med);}
.sb-foot{margin-top:auto;display:flex;align-items:center;gap:8px;padding:12px 14px 14px;
  border-top:1px solid var(--border);flex-wrap:wrap;}
.sb-who{display:flex;align-items:center;gap:7px;flex:1;min-width:0;}
.sb-av{width:24px;height:24px;border-radius:50%;background:var(--accent-soft);color:var(--accent);
  font-size:10.5px;font-weight:700;display:flex;align-items:center;justify-content:center;flex:none;}
.sb-name{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sb-foot .btn.ghost{padding:5px 6px;}

/* Collapsed rail. Scoped to the desktop layout: under 900px the sidebar is a
   horizontal strip and there is no width left to reclaim, so the rail — and
   the control that asks for it — simply do not exist there. */
@media (min-width:901px){
  :root[data-sb="mini"] .sidebar{width:var(--sidebar-w-min);}
  :root[data-sb="mini"] .sb-top{padding:14px 8px 10px;justify-content:center;}
  :root[data-sb="mini"] .sb-brand{display:none;}
  :root[data-sb="mini"] .sb-eng{margin:0 8px 12px;padding:9px 0;justify-content:center;}
  :root[data-sb="mini"] .sb-eng .txt,
  :root[data-sb="mini"] .sb-eng>svg,
  :root[data-sb="mini"] .sb-item .lbl,
  :root[data-sb="mini"] .sb-who{display:none;}
  /* The picker keeps working in the rail: the <select> is not hidden, it is
     stretched invisibly over the dot, so clicking the rail still opens it.
     A control that silently stops being clickable is worse than a wide nav. */
  :root[data-sb="mini"] .sb-pick{position:relative;}
  :root[data-sb="mini"] .sb-pick select{position:absolute;inset:0;width:100%;
    padding:0;opacity:0;cursor:pointer;}
  :root[data-sb="mini"] .sb-foot .btn{font-size:11.5px;padding:5px 4px;}
  /* The group heading becomes the rule it was already acting as. */
  :root[data-sb="mini"] .sb-h{height:0;padding:0;margin:10px 6px;overflow:hidden;
    border-top:1px solid var(--border);}
  :root[data-sb="mini"] .sb-nav{padding:0 8px;}
  :root[data-sb="mini"] .sb-item{justify-content:center;padding:9px 0;}
  /* The readiness "!" has no room for glyph, so it becomes the dot it means. */
  :root[data-sb="mini"] .sb-item .tag{position:absolute;top:5px;right:11px;width:6px;height:6px;
    border-radius:50%;background:var(--med);font-size:0;}
  :root[data-sb="mini"] .sb-foot{flex-direction:column;gap:4px;padding:10px 6px 12px;}
  :root[data-sb="mini"] .sb-collapse svg{transform:scaleX(-1);}
}

.main{flex:1;min-width:0;display:flex;flex-direction:column;}
.appbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:11px 24px;
  background:var(--surface);border-bottom:1px solid var(--border);}
.appbar h1{font-size:18px;margin:0;}
.appbar .spacer{flex:1;}
.appbar .note{font-size:12.5px;color:var(--muted);}
.content{padding:18px 24px 72px;}
.content.narrow{max-width:1180px;}

@media (max-width:900px){
  .app{flex-direction:column;}
  .sidebar{width:100%;height:auto;position:static;flex-direction:row;flex-wrap:wrap;
    align-items:center;gap:4px;padding-bottom:8px;}
  .sb-top{padding:10px 12px 6px;}
  .sb-collapse{display:none;}
  .sb-eng{margin:0 12px;max-width:240px;}
  .sb-nav{flex-direction:row;flex-wrap:wrap;width:100%;}
  .sb-h{display:none;}
  .sb-foot{margin:0;border-top:0;}
  .content{padding:14px 16px 56px;}
}
"""

# The whole stylesheet, in the one order that makes the theme toggle work:
# tokens first (every colour), then components, then the shell.
FULL_CSS = tokens.CSS + base.CSS + CSS

# Both preferences are applied to <html> BEFORE the first paint. The theme
# already had to be, and the sidebar width has the same problem: restoring it
# from JS after load makes every page open wide and then snap to the rail.
_THEME_BOOT = (
    "<script>try{var d=document.documentElement;"
    "var t=localStorage.getItem('stp-theme');if(t)d.setAttribute('data-theme',t);"
    "var s=localStorage.getItem('stp-sidebar');"
    "if(s==='mini'||s==='full')d.setAttribute('data-sb',s);}catch(e){}</script>"
)

# The collapse control. The label is what a nav item's tooltip has to become
# once its text is gone, so the two live together: `apply()` copies each item's
# `data-label` into `data-tip` on the way in and drops it again on the way out,
# rather than shipping a redundant tooltip on a label you can already read.
SIDEBAR_JS = """
(function () {
  var root = document.documentElement;
  var btn = document.getElementById('sb-toggle');
  function apply(mini, save) {
    root.setAttribute('data-sb', mini ? 'mini' : 'full');
    if (btn) {
      var label = btn.getAttribute(mini ? 'data-label-expand' : 'data-label-collapse');
      btn.setAttribute('aria-expanded', mini ? 'false' : 'true');
      btn.setAttribute('aria-label', label);
      btn.setAttribute('data-tip', label);
    }
    document.querySelectorAll('.sidebar [data-label]').forEach(function (el) {
      if (mini) el.setAttribute('data-tip', el.getAttribute('data-label'));
      else el.removeAttribute('data-tip');
    });
    if (window.__bindTips) window.__bindTips(document);
    if (save) { try { localStorage.setItem('stp-sidebar', mini ? 'mini' : 'full'); } catch (e) {} }
  }
  apply(root.getAttribute('data-sb') === 'mini', false);
  if (btn) {
    btn.addEventListener('click', function () {
      apply(root.getAttribute('data-sb') !== 'mini', true);
    });
  }
})();
"""

_SHARED_JS = (f"<script>{base.TOOLTIP_JS}{base.THEME_JS}{SIDEBAR_JS}"
              f"{base.SECTION_JS}{base.LANG_JS}</script>")


class Nav:
    """One nav entry. `key` is what a page passes as `active`."""

    __slots__ = ("key", "label", "href", "icon", "aliases")

    def __init__(self, key: str, label: str, href: str, icon: str, aliases: tuple[str, ...] = ()):
        self.key, self.label, self.href, self.icon = key, label, href, icon
        self.aliases = aliases

    def matches(self, active: str) -> bool:
        return active == self.key or active in self.aliases


# Setup entries deep-link into the config page's existing panes, so the sidebar
# is a real table of contents today rather than a promise about a later refactor.
WORK_NAV = [
    Nav("dashboard", "Assessments", "/", "list", aliases=("assessment",)),
    Nav("findings", "Findings", "/findings", "alert"),
    Nav("activity", "Activity", "/activity", "clock"),
]
SETUP_NAV = [
    Nav("readiness", "Readiness", "/config?tab=readiness", "check", aliases=("config",)),
    Nav("target", "Target & scope", "/config?tab=target", "globe",
        aliases=("environments", "scope")),
    Nav("identities", "Identities", "/config?tab=identities", "identity", aliases=("personas",)),
    Nav("advanced", "Advanced", "/config?tab=advanced", "sliders",
        aliases=("runner", "ai-evidence", "mcp", "runtime")),
]


def _nav_item(item: Nav, active: str, tag: str = "") -> str:
    """`data-label` is the label the collapsed rail has to put back as a
    tooltip — see SIDEBAR_JS. It is not `data-tip` here, because a tooltip
    repeating a label you can already read is noise."""
    cls = "sb-item on" if item.matches(active) else "sb-item"
    label = _t(item.label)
    tag_html = f'<span class="tag">{tag}</span>' if tag else ""
    return (
        f'<a href="{attr(item.href)}" class="{cls}" data-label="{attr(label)}">'
        f'{icons.icon(item.icon)}'
        f'<span class="lbl">{e(label)}</span>{tag_html}</a>'
    )


def _engagement_card(engagement_name: str, engagement_url: str, readiness_state: str,
                     engagements: list[tuple[str, str]] | None = None,
                     current_engagement: str = "") -> str:
    """The active target, on every screen — and which client it belongs to.

    `readiness_state` is the same verdict the Readiness pane computes, reduced
    to one dot: a run that is going to come back entirely BLOCKED should be
    visible before you navigate anywhere.

    With more than one engagement configured this is also the picker. It is a
    real `<select>` that submits, not a link, because switching client is not
    navigation — and it is deliberately absent on an assessment screen, where
    the engagement is the one the assessment was opened under and is not a
    choice at all.
    """
    if not (engagement_name or engagement_url or engagements):
        # Nothing to say — on the login page, and before an engagement exists.
        # A card reading "No environment / execution disabled" beside a login
        # form is noise, and it is the slot the target name would occupy.
        return ""
    tone = {"READY": "ok", "WARN": "warn"}.get(readiness_state, "bad")
    name = engagement_name or _t("No environment")
    url = engagement_url or _t("execution disabled")

    if engagements and len(engagements) > 1:
        options = "".join(
            f'<option value="{attr(key)}"{" selected" if key == current_engagement else ""}>'
            f"{e(key)}{f' — {e(target)}' if target else ''}</option>"
            for key, target in engagements
        )
        return (
            f'<form method="get" class="sb-eng sb-pick" data-tip="'
            f'{attr(_t("Which client this work is authorized under"))}">'
            f'<span class="dot {tone}"></span>'
            f'<select name="engagement" onchange="this.form.submit()"'
            f' aria-label="{attr(_t("Engagement"))}">{options}</select></form>'
        )

    # The card ellipsises a long URL; the tooltip is where the whole one lives,
    # so truncation never hides which host a run is about to be sent to.
    tip = f"{name}\n{url}\n{_t('The environment every run is sent to')}"
    return (
        f'<a href="/config?tab=target" class="sb-eng" data-tip="{attr(tip)}">'
        f'<span class="dot {tone}"></span>'
        f'<span class="txt"><span class="name">{e(name)}</span>'
        f'<span class="url">{e(url)}</span></span>'
        f'{icons.icon("chevron-updown", 14)}</a>'
    )


def sidebar(active: str, *, engagement_name: str = "", engagement_url: str = "",
            readiness_state: str = "READY", readiness_tag: str = "",
            user_name: str = "", auth_enabled: bool = False,
            engagements: list[tuple[str, str]] | None = None,
            current_engagement: str = "") -> str:
    work = "".join(_nav_item(i, active) for i in WORK_NAV)
    setup = "".join(
        _nav_item(i, active, tag=readiness_tag if i.key == "readiness" else "")
        for i in SETUP_NAV
    )
    auth = ""
    if auth_enabled:
        auth = (
            f'<a href="/login" class="btn ghost" data-tip="{attr(_t("Log in"))}">{_t("Log in")}</a>'
            '<form method="post" action="/logout" style="margin:0">'
            f'<button type="submit" class="btn ghost">{_t("Log out")}</button></form>'
        )
    # No name means there is no real signed-in identity to show, and the chrome
    # middleware suppresses it in both cases that produce one: auth on with no
    # session (the login page), and auth off, where every request carries the
    # same synthetic `local-admin`. Rendering either names a user who is not
    # there — the second one names a placeholder nobody chose.
    who = ""
    if user_name:
        initials = "".join(part[0] for part in user_name.split()[:2]).upper() or "?"
        who = (f'<span class="sb-who"><span class="sb-av">{e(initials)}</span>'
               f'<span class="sb-name">{e(user_name)}</span></span>')
    else:
        who = '<span class="sb-who"></span>'  # keeps the footer's spacing
    collapse_label = _t("Collapse sidebar")
    expand_label = _t("Expand sidebar")
    return f"""<aside class="sidebar">
<div class="sb-top">
<a href="/" class="sb-brand">
{icons.icon("shield", 20)}<b>{_t("API Security")}</b></a>
<button type="button" class="sb-collapse" id="sb-toggle" aria-controls="sb-nav"
 aria-expanded="true" aria-label="{attr(collapse_label)}" data-tip="{attr(collapse_label)}"
 data-label-collapse="{attr(collapse_label)}" data-label-expand="{attr(expand_label)}"
>{icons.icon("panel", 17)}</button>
</div>
{_engagement_card(engagement_name, engagement_url, readiness_state, engagements, current_engagement)}
<nav class="sb-nav" id="sb-nav">
<div class="sb-h">{_t("Work")}</div>{work}
<div class="sb-h">{_t("Setup")}</div>{setup}
</nav>
<div class="sb-foot">
{who}
{base.lang_toggle_html(get_lang())}
{base.THEME_TOGGLE_HTML}
{auth}
<button type="button" class="btn ghost danger iconbtn"
 data-tip="{attr(_t("Shut down the server"))}" aria-label="{attr(_t("Shut down the server"))}"
 onclick="shutdownServer()">{icons.icon("power", 15)}</button>
</div>
</aside>"""


def appbar(title: str, *, actions: str = "", note: str = "") -> str:
    note_html = f'<span class="note">{note}</span>' if note else ""
    return (
        f'<header class="appbar"><h1>{e(title)}</h1>{note_html}'
        f'<span class="spacer"></span>{actions}</header>'
    )


def _shutdown_js() -> str:
    """Moved here with the button it belongs to.

    The confirmation text is deliberately long: this stops every process running
    from the project directory, including ones started in other terminals, and
    the button now sits in the sidebar footer where it is harder to hit by
    accident than the old top-right corner.
    """
    confirm_msg = _t(
        "Shut down the server?\n\nThis stops this app AND any other process running "
        "from this project (the demo target, stray CLI/pytest runs) — including ones "
        "started in other terminals. You will need to start it again manually."
    )
    return f"""
function shutdownServer() {{
  if (!confirm({json.dumps(confirm_msg)})) return;
  document.querySelectorAll('.danger').forEach(function (b) {{ b.disabled = true; }});
  fetch('/admin/shutdown', {{
    method: 'POST',
    headers: {{ 'X-Confirm-Shutdown': 'security-testing-platform-ui' }},
  }}).then(_shutdownDone).catch(_shutdownDone);
}}
function _shutdownDone() {{
  document.body.innerHTML =
    '<div style="max-width:520px;margin:80px auto;padding:24px">' +
    '<h1 style="font-size:18px;margin:0 0 8px">' + {json.dumps(_t("Server is shutting down"))} + '</h1>' +
    '<p style="color:#5b6b6d">' + {json.dumps(_t(
        "All processes for this project have been stopped. Start it again from a "
        "terminal to continue."))} + '</p></div>';
}}
"""


def page(title: str, body: str, active: str = "", *, chrome: dict | None = None,
         appbar_html: str = "", narrow: bool = False) -> str:
    """A complete document: shell chrome around `body`.

    `chrome` is what the sidebar needs to say (engagement, readiness, user) and
    is supplied by main.py, which is the only layer that can see the engagement
    and the auth manager. It is optional so that an error page rendered before
    state exists still has a sidebar rather than crashing.

    `appbar_html` is empty for screens that still draw their own heading inside
    the body — those are migrated one at a time, and both shapes render the
    same shell.
    """
    chrome = chrome or {}
    content_cls = "content narrow" if narrow else "content"
    return f"""<!doctype html><html lang="{get_lang()}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(title)}</title>
{_THEME_BOOT}<style>{FULL_CSS}</style></head><body>
<div class="app">
{sidebar(active, **chrome)}
<div class="main">
{appbar_html}
<div class="{content_cls}">
{body}
</div></div></div>
{_SHARED_JS}<script>{_shutdown_js()}</script>
</body></html>"""
