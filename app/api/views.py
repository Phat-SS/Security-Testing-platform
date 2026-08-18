"""Server-rendered HTML views (dependency-free, theme-aware).

Kept separate from routing. Everything shown here has passed secret redaction
upstream (executions/findings) or is non-secret metadata.
"""

from __future__ import annotations

import json

from collections import Counter

from app.api import ui, views_assessment
from app.api.ui import attr, e, info
from app.database.models import Assessment
from app.schemas.testcase import TestCase

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.
_SEV_CLASS = ui.SEV_CLASS
_STATE_CLASS = ui.STATE_CLASS
_APPROVAL_CLASS = ui.APPROVAL_CLASS
_STATUS_PILL = ui.STATUS_PILL


def _e(v) -> str:
    return e(v)


# Set once at startup from main.py's State.__init__ so the topbar knows
# whether to show the Log in / Log out links. Multi-user auth is off by
# default (single-user local-admin) — hiding these when it's off avoids
# showing a login form that has no effect.
_AUTH_ENABLED = False
_PLANNER_ENABLED = False


def configure(auth_enabled: bool, planner_enabled: bool = False) -> None:
    global _AUTH_ENABLED, _PLANNER_ENABLED
    _AUTH_ENABLED = auth_enabled
    # Gates the adaptive-execution control. Offering a checkbox that silently
    # does nothing (the orchestrator falls back to a one-shot run without a
    # planner) would be worse than not offering it at all.
    _PLANNER_ENABLED = planner_enabled


_MARK = (
    '<svg viewBox="0 0 26 26" fill="none" width="24" height="24">'
    '<path d="M13 2 L23 6 V13 C23 19 18.5 23 13 24 C7.5 23 3 19 3 13 V6 Z" '
    'stroke="currentColor" stroke-width="1.6"/>'
    '<path d="M8.5 13 L11.5 16 L17.5 9.5" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)

_CSS = """
:root{
  --bg:#f6f7f6;--surface:#ffffff;--fg:#12181b;--muted:#5b6b6d;--faint:#8a9698;
  --border:#dde3e2;--border-strong:#c7d0cf;
  --accent:#0d6e6e;--accent-ink:#ffffff;--accent-soft:#e3f2f1;--accent-border:#bfe0de;
  --crit:#b4232a;--high:#c8500f;--med:#96700a;--low:#2f7a4f;--info:#5c6b74;
  --crit-soft:#fbe6e8;--high-soft:#fbead9;--med-soft:#f7edd0;--low-soft:#e1f2e7;--info-soft:#eaecee;
  --radius:6px;--shadow:0 1px 2px rgba(20,30,30,.05),0 1px 1px rgba(20,30,30,.04);
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0b1113;--surface:#121a1c;--fg:#e6efed;--muted:#8ea3a1;--faint:#5e7472;
  --border:#223032;--border-strong:#2c3d3e;
  --accent:#34c2bd;--accent-ink:#06201f;--accent-soft:#163333;--accent-border:#1f4b48;
  --crit:#e05a68;--high:#e08a4a;--med:#d4af37;--low:#4caf7d;--info:#8b98a3;
  --crit-soft:#2a1418;--high-soft:#2a1f11;--med-soft:#2a250f;--low-soft:#122a1c;--info-soft:#1a2022;
  --shadow:0 1px 2px rgba(0,0,0,.3);
}}
*{box-sizing:border-box;}
body{font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  margin:0;background:var(--bg);color:var(--fg);-webkit-font-smoothing:antialiased;}
.wrap{max-width:1180px;margin:0 auto;padding:22px 20px 80px;}
a{color:var(--accent);}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-variant-numeric:tabular-nums;}
.muted{color:var(--muted);}
h1{font-size:20px;margin:0 0 4px;letter-spacing:-.01em;}
h2.section{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);
  font-weight:700;margin:26px 0 10px;border:0;padding:0;}
h2.section:first-child{margin-top:0;}
.sub{color:var(--muted);margin:0 0 16px;}

.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px;}
.brand{display:flex;align-items:center;gap:9px;text-decoration:none;color:var(--fg);}
.brand svg{color:var(--accent);flex:none;}
.brand b{font-size:15.5px;letter-spacing:-.01em;}
nav.tabs{display:flex;gap:4px;}
nav.tabs a{padding:6px 12px;border-radius:6px 6px 0 0;text-decoration:none;color:var(--muted);font-size:13.5px;}
nav.tabs a.active{background:var(--surface);color:var(--fg);font-weight:600;border:1px solid var(--border);
  border-bottom-color:var(--surface);margin-bottom:-1px;}
.chips{display:flex;gap:8px;flex-wrap:wrap;}
.chip{display:inline-flex;align-items:center;font-size:11.5px;color:var(--muted);background:var(--surface);
  border:1px solid var(--border);border-radius:999px;padding:4px 10px;}
.chip b{color:var(--fg);font-weight:600;margin-left:4px;}

.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);}
.pad{padding:16px 18px;}
.flash{border-color:var(--accent);margin-bottom:16px;}
.warn{border-color:var(--high);margin-bottom:16px;}
.err{border-color:var(--crit);margin-bottom:16px;}

.btn{display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:var(--accent-ink);
  border:1px solid var(--accent);border-radius:var(--radius);padding:8px 14px;font:inherit;font-size:13.5px;
  font-weight:600;cursor:pointer;text-decoration:none;line-height:1.2;}
.btn.sec{background:transparent;color:var(--fg);border-color:var(--border-strong);}
.btn.ghost{background:none;color:var(--muted);border-color:transparent;padding:8px 6px;}
.btn.danger{color:var(--crit);border-color:var(--crit);}
.btn:disabled{opacity:.45;cursor:not-allowed;}
.btn:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,
button:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}

input,textarea,select{background:var(--bg);color:var(--fg);border:1px solid var(--border-strong);
  border-radius:var(--radius);padding:8px 10px;font:inherit;font-size:13.5px;width:100%;}
label.field{display:flex;flex-direction:column;gap:5px;}
label.field span{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}

table{width:100%;border-collapse:collapse;font-size:13.5px;}
.tblwrap{overflow-x:auto;}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
th{color:var(--faint);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;}
tr:last-child td{border-bottom:0;}
code{background:var(--accent-soft);padding:1px 5px;border-radius:4px;}

.pill{display:inline-block;font-size:11px;font-weight:700;border-radius:999px;padding:2px 9px;
  letter-spacing:.02em;white-space:nowrap;}
.pill.crit{background:var(--crit-soft);color:var(--crit);}
.pill.high{background:var(--high-soft);color:var(--high);}
.pill.med{background:var(--med-soft);color:var(--med);}
.pill.low{background:var(--low-soft);color:var(--low);}
.pill.info{background:var(--info-soft);color:var(--info);}
.destr{font-size:10px;font-weight:700;color:var(--crit);border:1px solid var(--crit);border-radius:4px;
  padding:1px 5px;letter-spacing:.03em;}
.bar{background:var(--border);border-radius:4px;height:7px;width:100px;overflow:hidden;}
.fill{height:100%;}

/* dashboard */
.summary-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;
  background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:22px;}
.summary-row .cell{background:var(--surface);padding:14px 16px;}
.summary-row .num{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.01em;}
.summary-row .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);margin-top:2px;}
.grid-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;}
.a-card{position:relative;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);
  padding:14px 15px;box-shadow:var(--shadow);}
.a-card .stretch{position:absolute;inset:0;border-radius:inherit;}
.a-card .top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;}
.a-card .issue{font-weight:700;font-size:14.5px;}
.a-card .id{color:var(--faint);font-size:11px;margin-top:2px;}

.tabbar{display:flex;gap:2px;border-bottom:1px solid var(--border);}
.tabbar button{appearance:none;background:none;border:0;font:inherit;font-size:12.5px;font-weight:600;
  color:var(--muted);padding:8px 12px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;}
.tabbar button.active{color:var(--fg);border-bottom-color:var(--accent);}
.tabpane{display:none;padding-top:12px;}
.tabpane.active{display:block;}

.glabel{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);margin:14px 0 6px;}
.glabel:first-child{margin-top:0;}
.actionrow{display:flex;gap:8px;flex-wrap:wrap;}

.spinner{width:13px;height:13px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;
  border-radius:50%;display:inline-block;animation:spin .7s linear infinite;vertical-align:-2px;}
@keyframes spin{to{transform:rotate(360deg);}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:1.6s;}}
.flash.exec-flash{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
""" + ui.CSS

# Behaviour shared by every page: the tooltip bubble, the theme toggle and the
# collapsible-section memory. Emitted once at the end of <body> so it binds
# against a document that is already parsed.
_SHARED_JS = f"<script>{ui.TOOLTIP_JS}{ui.THEME_JS}{ui.SECTION_JS}</script>"

_FOOT = f"{_SHARED_JS}</div></body></html>"


def _topbar(active: str) -> str:
    auth_links = ""
    if _AUTH_ENABLED:
        auth_links = (
            "<a href=\"/login\" class=\"btn sec\">Log in</a>"
            "<form method=\"post\" action=\"/logout\" style=\"margin:0\">"
            "<button type=\"submit\" class=\"btn ghost\">Log out</button></form>"
        )
    return f"""<div class="topbar">
<a href="/" class="brand">{_MARK}<b>API Security Testing Platform</b></a>
<div class="row" style="gap:16px">
<nav class="tabs">
<a href="/" class="{"active" if active == "dashboard" else ""}">Dashboard</a>
<a href="/config" class="{"active" if active == "config" else ""}">Configuration</a>
</nav>
{ui.THEME_TOGGLE_HTML}
{auth_links}
<button type="button" class="btn sec danger" onclick="shutdownServer()">Shutdown server</button>
</div></div>
<script>
function shutdownServer() {{
  if (!confirm(
    'Shut down the server?\\n\\n' +
    'This stops this app AND any other process running from this project ' +
    '(the demo target, stray CLI/pytest runs) — including ones started in ' +
    'other terminals. You will need to start it again manually.'
  )) return;
  document.querySelectorAll('.danger').forEach(function (b) {{
    b.disabled = true;
    b.textContent = 'Shutting down…';
  }});
  fetch('/admin/shutdown', {{
    method: 'POST',
    headers: {{ 'X-Confirm-Shutdown': 'security-testing-platform-ui' }},
  }})
    .then(function () {{ _shutdownDone(); }})
    .catch(function () {{ _shutdownDone(); }});
}}
function _shutdownDone() {{
  document.body.innerHTML =
    '<div style="max-width:520px;margin:80px auto;padding:24px;font:15px -apple-system,' +
    'BlinkMacSystemFont,\\'Segoe UI\\',sans-serif">' +
    '<h1 style="font-size:18px;margin:0 0 8px">Server is shutting down</h1>' +
    '<p style="color:#5b6b6d">All processes for this project have been stopped. ' +
    'Start it again from a terminal to continue.</p></div>';
}}
</script>"""


_THEME_BOOT = (
    "<script>try{var t=localStorage.getItem('stp-theme');"
    "if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>"
)


def page(title: str, body: str, active: str = "") -> str:
    head = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{_e(title)}</title>
{_THEME_BOOT}<style>{_CSS}</style></head><body><div class="wrap">
{_topbar(active)}
"""
    return head + body + _FOOT


def dashboard(
    assessments: list[Assessment],
    engagement_target: str,
    ai_on: bool,
    jira_mode: str = "mock Jira (offline)",
    available_keys: list[str] | None = None,
    warning: str = "",
    flash: str = "",
    rows: list[dict] | None = None,
    q: str = "",
    status: str = "",
    sort: str = "recent",
    page_no: int = 1,
    per: int = 24,
) -> str:
    """The assessment list.

    `rows` carries the per-assessment counts (tests, approved, findings by
    severity) the cards show. Without them a card said only "Executed" — which is
    the one thing you already knew from having run it, and nothing about what it
    found.
    """
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""
    warn_html = f"<div class='card pad warn'>&#9888; {_e(warning)}</div>" if warning else ""

    counts = Counter(a.status for a in assessments)
    summary = ui.stats([
        (str(len(assessments)), "Assessments", "", ""),
        (str(counts.get("CREATED", 0)), "Imported", "Analyzed, no plan generated yet.", ""),
        (str(counts.get("ANALYZED", 0)), "Designed", "A plan exists; it may not be approved.", ""),
        (str(counts.get("EXECUTED", 0)), "Executed", "At least one run has happened.", ""),
    ])

    by_id = {r["id"]: r for r in (rows or [])}
    cards = "".join(_assessment_card(a, by_id.get(a.id, {})) for a in assessments)
    cards = cards or (
        "<p class='muted'>"
        + ("No assessments match this filter." if (q or status)
           else "No assessments yet — import a Jira issue above.")
        + "</p>"
    )

    target = (_e(engagement_target) if engagement_target
              else "<span class='muted'>not configured — execution disabled</span>")
    ai = "AI (Claude)" if ai_on else "deterministic (heuristic)"

    # Available keys come from the mock only; a live instance is not enumerated,
    # so the hint becomes "type your own key" rather than a stale list.
    keys = available_keys or []
    if keys:
        hint = ("importable now: "
                + ", ".join(f"<a href='#' class='keyfill'><code>{_e(k)}</code></a>" for k in keys))
        placeholder = _e(keys[0])
    else:
        hint = "enter any issue key your Jira account can read"
        placeholder = "ABC-123"

    return page("Dashboard", f"""
{flash_html}{warn_html}
<div class="chips" style="margin-bottom:18px">
<span class="chip">Analyzer <b>{ai}</b></span>
<span class="chip">Jira <b>{_e(jira_mode)}</b></span>
<span class="chip">Target <b>{target}</b></span>
</div>
<div class="card pad" style="margin-bottom:22px">
<label class="field" style="margin-bottom:8px"><span>Import a Jira issue</span></label>
<form method="post" action="/import" class="row js-busy" style="align-items:flex-end">
<input name="issue_key" id="issue_key" placeholder="{placeholder}" style="max-width:220px" required>
<label class="field" style="max-width:150px;margin:0"><span>Depth</span>
<select name="depth">
<option value="standard" selected>Standard</option>
<option value="aggressive">Aggressive</option>
</select></label>
<label class="row" style="gap:6px;align-items:center;margin:0 0 8px"
 data-tip="Analyze the ticket and its embedded PoC, design a plan, let the AI planner add
 depth, then have a reviewing agent audit the plan against the ticket&#39;s requirements and
 send its gaps back for one revision round. You land on the plan with something to approve.
 Nothing runs: every test arrives PENDING. Uncheck to analyze only &mdash; which is what you
 want when the endpoint list needs correcting first.">
<input type="checkbox" name="plan" value="true" checked style="width:auto">
<span class="muted">Plan &amp; review on import</span></label>
<button class="btn">Import</button>
</form>
<p class="muted" style="margin:8px 0 0;font-size:13px">{hint}</p></div>
{summary}
<h2 class="section">Recent assessments</h2>
{_dashboard_toolbar(q, status, sort, per, len(assessments), page_no)}
<div class="grid-cards">{cards}</div>
<script>
// Import can now include a planning + review pass, which takes tens of seconds
// with the AI path on. A button that looks idle for that long reads as broken and
// gets clicked again.
document.querySelectorAll('form.js-busy').forEach(function (f) {{
  f.addEventListener('submit', function () {{
    var btn = f.querySelector('button:not([type=button])');
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Working…';
  }});
}});
document.querySelectorAll('.keyfill').forEach(function (a) {{
  a.addEventListener('click', function (e) {{
    e.preventDefault();
    document.getElementById('issue_key').value = a.textContent.trim();
  }});
}});
document.querySelectorAll('.delete-form').forEach(function (f) {{
  f.addEventListener('submit', function (e) {{
    if (!confirm('Delete this assessment? This cannot be undone.')) e.preventDefault();
  }});
}});
document.querySelectorAll('.rerun-form').forEach(function (f) {{
  f.addEventListener('submit', function (e) {{
    var mode = f.querySelector('[name=mode]').value;
    var msg = mode === 'reimport'
      ? 'Re-import ' + f.dataset.issue + ' from Jira?\\n\\nCreates a new assessment from ' +
        'the ticket as it reads now. No tests are generated and nothing runs.'
      : 'Re-run ' + f.dataset.issue + '?\\n\\nCreates a new assessment with the same plan ' +
        'and approvals, then runs the approved non-destructive tests. Destructive tests ' +
        'are never included in a re-run. The previous run is kept as the baseline.';
    if (!confirm(msg)) {{ e.preventDefault(); return; }}
    var btn = f.querySelector('button');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Running…';
  }});
}});
</script>
""", active="dashboard")


_DASH_STATUS = [("", "Any status"), ("CREATED", "Imported"), ("ANALYZED", "Designed"),
                ("EXECUTED", "Executed")]
_DASH_SORT = [("recent", "Newest first"), ("oldest", "Oldest first"),
              ("issue", "Issue key"), ("findings", "Most findings")]


def _dashboard_toolbar(q: str, status: str, sort: str, per: int, shown: int,
                       page_no: int) -> str:
    """The list grows without bound, so it gets the same treatment as the plan:
    search, filter, sort, paging — rather than one long wall of cards."""
    def options(name, current, choices):
        opts = "".join(
            f'<option value="{attr(value)}"{" selected" if value == current else ""}>'
            f"{_e(text)}</option>" for value, text in choices
        )
        return f'<select name="{attr(name)}" style="width:auto">{opts}</select>'

    return f"""<form method="get" action="/" class="toolbar">
<label class="field grow"><span>Search issue key</span>
<input name="q" value="{attr(q)}" placeholder="BH-142" style="width:100%"></label>
<label class="field"><span>Status</span>{options("status", status, _DASH_STATUS)}</label>
<label class="field"><span>Sort</span>{options("sort", sort or "recent", _DASH_SORT)}</label>
<label class="field"><span>Per page</span>
{options("per", str(per), [(str(n), str(n)) for n in (12, 24, 48, 96)])}</label>
<div class="row" style="gap:6px;align-items:flex-end">
<button class="btn sec">Apply</button>
<a class="btn ghost" href="/">Clear</a></div>
<span class="count" style="align-self:flex-end;padding-bottom:8px">
{shown} shown{f" &middot; page {page_no}" if page_no > 1 else ""}</span>
</form>"""


def _assessment_card(a: Assessment, row: dict) -> str:
    label, cls = _STATUS_PILL.get(a.status, (a.status.title(), "info"))
    created = getattr(a, "created_at", None)
    when = created.strftime("%Y-%m-%d %H:%M") if created else ""

    facts = []
    if row.get("n_tests"):
        facts.append(f'{row["n_tests"]} test(s)')
    if row.get("n_approved"):
        facts.append(f'{row["n_approved"]} approved')
    if row.get("n_executions"):
        facts.append(f'{row["n_executions"]} run')
    facts_html = (f'<div class="muted" style="font-size:12px;margin-top:6px">'
                  f'{" &middot; ".join(facts)}</div>' if facts else "")

    sev = row.get("severities") or {}
    dots = "".join(
        f'<span style="color:var(--{ui.SEV_CLASS[s]})">{sev[s]}{s[0]}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if sev.get(s)
    )
    findings_html = (
        f'<div class="sevdots" style="margin-top:6px" '
        f'data-tip="Confirmed findings by severity" tabindex="0">{dots}</div>'
        if dots else ""
    )
    target_html = (
        f'<div class="muted mono" style="font-size:11.5px;margin-top:4px">'
        f'<span class="trunc" style="max-width:210px">{_e(a.target_base_url)}</span></div>'
        if a.target_base_url else ""
    )

    # Re-run is only offered once there is something to re-run. Before that the
    # honest action is "open it and finish designing".
    rerun = ""
    if row.get("n_tests"):
        mode = "same" if row.get("n_approved") else "reimport"
        word = "Re-run" if row.get("n_approved") else "Re-import"
        rerun = (
            f'<form method="post" action="/assessment/{_e(a.id)}/rerun" '
            f'class="rerun-form" data-issue="{attr(a.issue_key)}" style="margin:0">'
            f'<input type="hidden" name="mode" value="{mode}">'
            f'<button class="btn sec" style="padding:3px 9px;font-size:12px">'
            f'&#8635; {word}</button></form>'
        )

    return (
        f"<div class='a-card'>"
        f"<a class='stretch' href='/assessment/{_e(a.id)}' aria-label='Open {_e(a.issue_key)}'></a>"
        f"<div class='top'><div><div class='issue'>{_e(a.issue_key)}</div>"
        f"<div class='id mono'>{_e(a.id)}</div>"
        + (f"<div class='id'>{_e(when)}</div>" if when else "")
        + f"</div><span class='pill {cls}'>{_e(label)}</span></div>"
        f"{target_html}{facts_html}{findings_html}"
        f"<div class='cardact'>{rerun}"
        f"<form method='post' action='/assessment/{_e(a.id)}/delete' class='delete-form' "
        f"style='margin:0'>"
        f"<button type='submit' class='btn ghost danger' "
        f"style='padding:3px 9px;font-size:12px'>Delete</button></form></div></div>"
    )


def login_page(flash: str = "") -> str:
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""
    return page("Log in", f"""
<h1 style="font-size:19px">Log in</h1>
<p class="sub">Multi-user auth is enabled. Paste the API key printed by
<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> to authenticate this
browser for actions like designing tests, approving, and executing. Reads stay open either way.</p>
{flash_html}
<div class="card pad" style="max-width:420px">
<form method="post" action="/login">
<label class="field" style="margin-bottom:12px"><span>API key</span>
<input type="password" name="api_key" required autofocus></label>
<button class="btn">Log in</button>
</form>
</div>
""")


def error_page(title: str, headline: str, hint_html: str,
                back_href: str = "/", back_label: str = "← Back to dashboard") -> str:
    """A failure as a readable page instead of a bare 500. `headline` may
    contain user input and is escaped; `hint_html` is markup we build ourselves."""
    return page(title, f"""
<h1 style="font-size:19px">{_e(title)}</h1>
<div class="card pad err">
<p style="margin:0 0 8px"><b>{_e(headline)}</b></p>
<p class="muted" style="margin:0">{hint_html}</p>
</div>
<p><a href="{_e(back_href)}" class="btn sec">{_e(back_label)}</a></p>
""")




def _plan_from_tests(tests: list[TestCase]) -> dict:
    """A one-page, unfiltered plan result, for a caller that has the test list
    but did not go through the repository's query."""
    return {
        "tests": tests,
        "matched_ids": [t.test_id for t in tests],
        "total": len(tests),
        "unfiltered_total": len(tests),
        "page": 1,
        "pages": 1,
        "per": max(len(tests), 1),
        "facets": {},
        "meta": {
            "total": len(tests),
            "approved": sum(1 for t in tests if t.approval_status.value == "APPROVED"),
            "rejected": sum(1 for t in tests if t.approval_status.value == "REJECTED"),
            "pending": sum(1 for t in tests if t.approval_status.value == "PENDING"),
            "approved_destructive": sum(
                1 for t in tests
                if t.approval_status.value == "APPROVED" and t.is_destructive
            ),
        },
    }


def assessment_page(
    assessment: Assessment,
    analysis: dict,
    coverage: list[dict],
    tests: list[TestCase] | None = None,
    n_executions: int = 0,
    n_findings: int = 0,
    environments: dict[str, str] | None = None,
    active_environment: str = "",
    readiness=None,
    flash: str = "",
    ticket_url: str = "",
    findings: list | None = None,
    plan: dict | None = None,
    filters: dict | None = None,
    verdicts: dict | None = None,
    plan_review=None,
    run_assessment=None,
    triage: dict | None = None,
) -> str:
    """The assessment screen. Its structure lives in `views_assessment` — it is
    the one page with enough moving parts to be worth its own module, and
    keeping it here made this file a place you searched rather than read.

    `n_findings` is kept for callers that only counted them; when the findings
    themselves are passed they are shown, since "3 findings" without their
    severities is a number a tester has to click through to act on.
    """
    body = views_assessment.body(
        assessment,
        analysis or {},
        coverage or [],
        plan if plan is not None else _plan_from_tests(tests or []),
        filters=filters or {},
        n_executions=n_executions,
        findings=findings if findings is not None else [],
        environments=environments or {},
        active_environment=active_environment,
        readiness=readiness,
        planner_enabled=_PLANNER_ENABLED,
        verdicts=verdicts or {},
        # The two reviewing agents' output. Both optional: a page for an
        # assessment nobody has asked an agent about renders exactly as it did
        # before, with the button that asks.
        plan_review=plan_review,
        run_assessment=run_assessment,
        triage=triage or {},
        flash=flash,
        ticket_url=ticket_url,
    )
    return page(f"Assessment {assessment.issue_key}", body)


def test_detail_page(assessment: Assessment, test: TestCase, flash: str = "") -> str:
    aid = assessment.id
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""

    headers_text = "\n".join(f"{k}: {v}" for k, v in test.request.headers.items())
    query_text = "\n".join(f"{k}={v}" for k, v in test.request.query.items())
    body = test.request.body
    if isinstance(body, (dict, list)):
        body_text = json.dumps(body, indent=2)
    elif body is None:
        body_text = ""
    else:
        body_text = str(body)

    sev_c = _SEV_CLASS.get(test.severity.value, "info")
    appr_c = _APPROVAL_CLASS.get(test.approval_status.value, "info")
    dest = "<span class='destr'>DESTRUCTIVE</span>" if test.is_destructive else ""
    persona_line = _e(test.auth_context.persona)
    if test.auth_context.target_persona:
        persona_line += f" → {_e(test.auth_context.target_persona)}"
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    method_options = "".join(
        f"<option value='{m}' {'selected' if test.request.method.upper() == m else ''}>{m}</option>"
        for m in methods
    )

    return page(f"{test.test_id} — {assessment.issue_key}", f"""
{flash_html}
<div class="topbar" style="margin-bottom:16px">
<div>
<h1>{_e(test.test_id)}
<span class="pill {sev_c}">{_e(test.severity.value)}</span>
<span class="pill {appr_c}">{_e(test.approval_status.value)}</span> {dest}</h1>
<p class="sub" style="margin:2px 0 0">{_e(test.title)}</p>
</div>
<a href="/assessment/{_e(aid)}" class="btn ghost">← Back to {_e(assessment.issue_key)}</a>
</div>

<div class="card pad" style="margin-bottom:18px">
<div class="row" style="gap:28px;flex-wrap:wrap">
<div><div class="glabel" style="margin:0 0 3px">OWASP</div><div>{_e(test.owasp_category.value)}</div></div>
<div><div class="glabel" style="margin:0 0 3px">Mutation</div><div class="mono">{_e(test.attack_mutation.kind)}</div></div>
<div><div class="glabel" style="margin:0 0 3px">Persona</div><div class="mono">{persona_line}</div></div>
<div><div class="glabel" style="margin:0 0 3px">Expected status</div>
<div class="mono">{_e(', '.join(str(s) for s in test.expected.status_in))}</div></div>
</div>
<p class="muted" style="margin:14px 0 0">{_e(test.objective)}</p>
</div>

<div class="card pad">
<p class="muted" style="margin:0 0 16px">Saving resets this test's approval to <b>PENDING</b> — review
and re-approve it on the assessment page before it can run.</p>
<form method="post" action="/assessment/{_e(aid)}/test/{_e(test.test_id)}">
<div class="row" style="gap:10px;align-items:flex-end;margin-bottom:14px">
<label class="field" style="max-width:130px"><span>Method</span>
<select name="method">{method_options}</select></label>
<label class="field" style="flex:1"><span>Path / URL</span>
<input name="path" value="{_e(test.request.path)}" class="mono" required></label>
</div>
<label class="field" style="margin-bottom:14px"><span>Headers — one per line, "Key: Value"</span>
<textarea name="headers_text" rows="4" class="mono" placeholder="Authorization: Bearer {{token}}">{_e(headers_text)}</textarea></label>
<label class="field" style="margin-bottom:14px"><span>Query params — one per line, "key=value"</span>
<textarea name="query_text" rows="3" class="mono" placeholder="limit=10">{_e(query_text)}</textarea></label>
<label class="field" style="margin-bottom:16px"><span>Body / payload — JSON or raw text</span>
<textarea name="body_text" rows="10" class="mono">{_e(body_text)}</textarea></label>
<button class="btn">Save changes</button>
<a href="/assessment/{_e(aid)}" class="btn sec">Cancel</a>
</form>
</div>
""")


def regression_page(aid: str, issue_key: str, prev_id: str | None, diff, comment: str,
                    flash: str = "") -> str:
    s = diff.summary()
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""
    banner_cls = "err" if s["regressed"] else "flash"
    banner = "⚠️ REGRESSION — new findings since last run" if s["regressed"] else (
        "✅ No new findings since last run")
    baseline = (f"vs previous run <span class='mono'>{_e(prev_id)}</span>" if prev_id
                else "no previous executed run — showing current findings as baseline")

    def _rows(items, cls):
        return "".join(
            f"<tr><td><b>{_e(f.finding_id)}</b></td><td>{_e(f.title)}</td>"
            f"<td>{_e(f.owasp_category.value)}</td>"
            f"<td><span class='pill {cls}'>{_e(f.severity.value)}</span></td>"
            f"<td class='mono'>{_e(f.endpoint)}</td></tr>"
            for f in items
        ) or "<tr><td colspan='5' class='muted'>none</td></tr>"

    return page(f"Regression — {issue_key}", f"""
{flash_html}
<h1>Regression diff — {_e(issue_key)}</h1>
<p class="sub">{baseline}</p>
<div class="card pad {banner_cls}" style="margin-bottom:18px"><b>{banner}</b>
<br><span class="muted">new: {s['new']} · fixed: {s['fixed']} · still open: {s['persisting']}</span></div>
<h2 class="section">New (regressions)</h2>
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>ID</th><th>Title</th><th>OWASP</th><th>Sev</th><th>Endpoint</th></tr>
{_rows(diff.new, 'crit')}</table></div></div>
<h2 class="section">Fixed since last run</h2>
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>ID</th><th>Title</th><th>OWASP</th><th>Sev</th><th>Endpoint</th></tr>
{_rows(diff.fixed, 'low')}</table></div></div>
<h2 class="section">Still open</h2>
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>ID</th><th>Title</th><th>OWASP</th><th>Sev</th><th>Endpoint</th></tr>
{_rows(diff.persisting, 'high')}</table></div></div>
<h2 class="section">Jira-ready note</h2>
<div class="card pad"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(comment)}</pre></div>
<p style="margin-top:18px"><a class="btn sec" href="/assessment/{_e(aid)}">Back to assessment</a></p>
""")


def comment_preview_page(aid: str, issue_key: str, preview: str) -> str:
    return page(f"Jira comment — {issue_key}", f"""
<h1>Preview Jira comment</h1>
<p class="sub">Nothing is posted until you confirm.</p>
<div class="card pad" style="margin-bottom:18px"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(preview)}</pre></div>
<form method="post" action="/assessment/{_e(aid)}/comment">
<button class="btn">Confirm &amp; post to {_e(issue_key)}</button>
<a class="btn sec" href="/assessment/{_e(aid)}">Cancel</a>
</form>
""")


# -- Configuration -----------------------------------------------------------
#
# One page holding every setting a run depends on, because the failure mode it
# replaces was: run -> every row BLOCKED -> no indication of which file, which
# key, or which of several unrelated settings caused it. The panes are ordered
# by how a tester hits them (readiness first, then target, scope, identities),
# and the readiness pane names the exact setting behind each failure with a
# link straight to the pane that fixes it.

_READY_CLASS = {"ok": "low", "warn": "med", "fail": "crit"}
_READY_ICON = {"ok": "&#10003;", "warn": "&#9888;", "fail": "&#10007;"}
_READY_WORD = {"ok": "READY", "warn": "CHECK", "fail": "BLOCKING"}

_CONFIG_TABS = [
    ("readiness", "Readiness"),
    ("environments", "Environments"),
    ("scope", "Scope"),
    ("personas", "Personas"),
    ("runner", "Runner limits"),
    ("runtime", "Runtime (.env)"),
]


def _kv_textarea_value(mapping: dict, sep: str) -> str:
    return "\n".join(f"{k}{sep}{v}" for k, v in (mapping or {}).items())


def _readiness_pane(readiness, engagement_path: str) -> str:
    rows = ""
    for c in readiness.checks:
        cls = _READY_CLASS[c.state]
        fix = ""
        if c.fix_action:
            hidden = "".join(
                f"<input type='hidden' name='{_e(k)}' value='{_e(v)}'>"
                for k, v in c.fix_fields.items()
            )
            fix = (
                f"<form method='post' action='{_e(c.fix_action)}' style='margin:8px 0 0'>{hidden}"
                f"<button class='btn' style='padding:5px 12px'>{_e(c.fix_label)}</button></form>"
            )
        hint = f"<div class='muted' style='margin-top:4px'>{c.hint_html}</div>" if c.hint_html else ""
        rows += (
            f"<tr><td style='white-space:nowrap'>"
            f"<span class='pill {cls}'>{_READY_ICON[c.state]} {_READY_WORD[c.state]}</span></td>"
            f"<td><b>{_e(c.label)}</b><div class='muted'>{_e(c.detail)}</div>{hint}{fix}</td></tr>"
        )

    env_rows = ""
    for env in readiness.environments:
        cls = _READY_CLASS[env.state]
        star = " <span class='pill low'>default</span>" if env.is_active else ""
        ip = (f"<div class='muted mono' style='font-size:11.5px'>{_e(env.resolved_ip)}</div>"
              if env.resolved_ip else "")
        env_rows += (
            f"<tr><td><code>{_e(env.name)}</code>{star}</td>"
            f"<td class='mono' style='font-size:12.5px'>{_e(env.url)}</td>"
            f"<td><span class='pill {cls}'>{'ALLOWED' if env.state == 'ok' else 'BLOCKED'}</span>"
            f"{ip}</td>"
            f"<td class='muted'>{_e(env.reason)}</td></tr>"
        )
    env_rows = env_rows or "<tr><td colspan='4' class='muted'>No environments to check.</td></tr>"

    if readiness.can_run:
        verdict = ("<div class='card pad flash' style='margin-bottom:16px'>"
                   "<b>&#10003; Ready to run.</b> Nothing in this configuration will "
                   "stop a request from being sent.</div>")
    else:
        verdict = ("<div class='card pad err' style='margin-bottom:16px'>"
                   f"<b>&#10007; {readiness.n_blocking} blocking issue(s).</b> "
                   "A run started now comes back entirely BLOCKED or ERROR. Each row "
                   "below names the setting and the pane that fixes it.</div>")

    return f"""{verdict}
<div class="card" style="margin-bottom:22px"><div class="tblwrap"><table>
<tr><th style="width:110px">State</th><th>Check</th></tr>{rows}</table></div></div>

<h2 class="section">Scope verdict per environment</h2>
<p class="muted" style="margin:-4px 0 10px">Each base URL run through the same
<code>ScopeValidator</code> the runner calls, DNS lookup included. Whatever this table
says here is exactly what the execution log will say.</p>
<div class="card"><div class="tblwrap"><table>
<tr><th>Environment</th><th>Base URL</th><th>Verdict</th><th>Reason</th></tr>{env_rows}
</table></div></div>
<p class="muted" style="margin-top:12px">Config file: <code>{_e(engagement_path)}</code></p>"""


def _environments_pane(environments: dict[str, str], active: str) -> str:
    rows = ""
    for name, url in environments.items():
        badge = " <span class='pill low'>default</span>" if name == active else ""
        make_default = "" if name == active else (
            f"<form method='post' action='/config/environments/{_e(name)}/activate' "
            f"style='margin:0;display:inline-block'>"
            f"<button class='btn ghost' style='padding:4px 8px'>Make default</button></form>"
        )
        rows += (
            f"<tr><td><b>{_e(name)}</b>{badge}</td><td class='mono'>{_e(url)}</td>"
            f"<td style='white-space:nowrap'>{make_default}"
            f"<form method='post' action='/config/environments/{_e(name)}/delete' "
            f"style='margin:0;display:inline-block' class='confirm-delete' "
            f"data-what='environment {_e(name)}'>"
            f"<button class='btn sec' style='padding:4px 10px'>Delete</button></form></td></tr>"
        )
    rows = rows or "<tr><td colspan='3' class='muted'>No environments configured yet.</td></tr>"
    return f"""<p class="muted" style="margin:0 0 12px">Named target URLs. Only the
path/method/body of a pasted PoC survive transpiling, so whichever base URL is picked
here is what actually gets called.</p>
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>Name</th><th>Base URL</th><th></th></tr>{rows}</table></div></div>
<div class="card pad">
<form method="post" action="/config/environments" class="row">
<input name="name" placeholder="staging" style="max-width:160px" required>
<input name="url" placeholder="https://staging.company.com" style="flex:1;min-width:240px" required>
<label class="muted" style="display:flex;align-items:center;gap:4px">
<input type="checkbox" name="make_active" value="true" style="width:auto"> make default</label>
<label class="muted" style="display:flex;align-items:center;gap:4px"
 title="Adds this URL's hostname to scope.allowed_hosts. Without it every request to
 the new environment is refused before it is sent.">
<input type="checkbox" name="authorize_host" value="true" style="width:auto" checked> authorize its host</label>
<button class="btn">Save</button>
</form>
<p class="muted" style="margin:10px 0 0"><b>Authorize its host</b> adds the hostname to
<b>Scope &rarr; approved hosts</b> in the same step. Leave it off for a target the
engagement does not actually cover — the URL is then saved but every request to it stays
blocked, which is the safe direction to fail in.</p>
</div>"""


def _scope_pane(policy) -> str:
    allowed = "\n".join(sorted(policy.allowed_hosts))
    blocked = "\n".join(sorted(policy.blocked_hosts))
    priv = "checked" if policy.allow_private_ranges else ""
    return f"""<p class="muted" style="margin:0 0 12px">The authorization boundary.
Every outbound request is checked against this before it is sent, and the hostname must
appear in <b>approved hosts</b> exactly — there are no wildcards, because a wildcard in a
pentest authorization list is how an unauthorized host gets tested by accident.</p>
<div class="card pad">
<form method="post" action="/config/scope">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
<label class="field"><span>Approved hosts — one per line</span>
<textarea name="allowed_hosts" rows="7" placeholder="staging-api.company.com&#10;127.0.0.1">{_e(allowed)}</textarea></label>
<label class="field"><span>Blocked hosts — one per line (always wins)</span>
<textarea name="blocked_hosts" rows="7" placeholder="production.company.com">{_e(blocked)}</textarea></label>
</div>
<label class="row" style="gap:8px;margin-top:14px;align-items:flex-start">
<input type="checkbox" name="allow_private_ranges" value="true" style="width:auto;margin-top:3px" {priv}>
<span><b>Allow private / loopback ranges</b><br>
<span class="muted">Off by default. When off, a host that <i>resolves</i> to
127.0.0.0/8, 10/8, 172.16/12, 192.168/16 or 169.254/16 (cloud metadata) is refused even if
its name is on the approved list — that check is what stops a DNS-based SSRF from
reaching an internal service. Turn it on only for a local lab target.</span></span></label>
<div style="margin-top:14px"><button class="btn">Save scope</button></div>
</form></div>
<p class="muted" style="margin-top:12px">Hostnames only — no scheme, no port, no path.
A port is not part of the check (<code>api.example.com:8443</code> is authorized by
<code>api.example.com</code>), and DNS is resolved and the resulting IP re-checked on
every request, so a name that resolves somewhere new is caught at send time.</p>"""


def _personas_pane(personas: list[dict], attacker: str, victim: str) -> str:
    names = [p.get("name", "") for p in personas]
    cards = ""
    for p in personas:
        name = p.get("name", "")
        roles = ""
        if name == attacker:
            roles += " <span class='pill med'>attacker</span>"
        if name == victim:
            roles += " <span class='pill high'>victim</span>"
        headers = _kv_textarea_value(p.get("auth_headers") or {}, ": ")
        owns = _kv_textarea_value(p.get("owns") or {}, "=")
        markers = "\n".join(p.get("secret_markers") or [])
        cards += f"""<div class="card pad" style="margin-bottom:12px">
<div class="row" style="justify-content:space-between;margin-bottom:10px">
<div><b>{_e(name)}</b>{roles}</div>
<form method="post" action="/config/personas/{_e(name)}/delete" style="margin:0"
 class="confirm-delete" data-what="persona {_e(name)}">
<button class="btn ghost">Delete</button></form>
</div>
<form method="post" action="/config/personas">
<input type="hidden" name="name" value="{_e(name)}">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>Role label</span>
<input name="role" value="{_e(p.get('role', 'user'))}"></label>
<label class="field"><span>Owned object ids — key=value per line</span>
<textarea name="owns" rows="3" placeholder="customer_id=2002">{_e(owns)}</textarea></label>
</div>
<label class="field" style="margin-top:12px"><span>Auth headers — Header: value per line</span>
<textarea name="auth_headers" rows="3" placeholder="Authorization: Bearer eyJ...">{_e(headers)}</textarea></label>
<label class="field" style="margin-top:12px"><span>Secret markers — one per line</span>
<textarea name="secret_markers" rows="2" placeholder="beth.victim@example.com">{_e(markers)}</textarea></label>
<div style="margin-top:12px"><button class="btn">Save {_e(name)}</button></div>
</form></div>"""
    cards = cards or "<p class='muted'>No personas defined yet — add one below.</p>"

    def opts(selected: str) -> str:
        out = "".join(
            f"<option value='{_e(n)}' {'selected' if n == selected else ''}>{_e(n)}</option>"
            for n in names
        )
        if selected and selected not in names:
            out = (f"<option value='{_e(selected)}' selected>{_e(selected)} "
                   f"— not defined!</option>" + out)
        return out or "<option value=''>— no personas defined —</option>"

    return f"""<p class="muted" style="margin:0 0 12px">Test identities and their
credentials. You cannot test broken object-level authorization with one identity:
BOLA means "A reaches B's object", which needs two real accounts plus knowledge of what
each legitimately owns. Tests reference personas <i>by name</i>, so a token never lands
in a test case, an export or a report.</p>

<div class="card pad" style="margin-bottom:18px">
<form method="post" action="/config/identities" class="row" style="align-items:flex-end">
<label class="field" style="max-width:220px"><span>Attacker persona</span>
<select name="attacker">{opts(attacker)}</select></label>
<label class="field" style="max-width:220px"><span>Victim persona</span>
<select name="victim">{opts(victim)}</select></label>
<button class="btn">Save roles</button>
</form>
<p class="muted" style="margin:10px 0 0">The attacker sends the requests; generated
BOLA cases aim it at ids the victim owns. Point these at two <i>different</i> personas
or the results are inconclusive by construction.</p>
</div>

<h2 class="section">Defined personas</h2>
{cards}

<h2 class="section">Add a persona</h2>
<div class="card pad">
<form method="post" action="/config/personas">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>Name</span>
<input name="name" placeholder="agent_A" required></label>
<label class="field"><span>Role label</span>
<input name="role" placeholder="agent" value="user"></label>
</div>
<label class="field" style="margin-top:12px"><span>Auth headers — Header: value per line</span>
<textarea name="auth_headers" rows="3" placeholder="Authorization: Bearer eyJ..."></textarea></label>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px">
<label class="field"><span>Owned object ids — key=value per line</span>
<textarea name="owns" rows="2" placeholder="customer_id=1001"></textarea></label>
<label class="field"><span>Secret markers — one per line</span>
<textarea name="secret_markers" rows="2" placeholder="alice.buyer@example.com"></textarea></label>
</div>
<div style="margin-top:12px"><button class="btn">Add persona</button></div>
</form>
<p class="muted" style="margin:10px 0 0">Use dedicated test accounts. Credentials are
written to the engagement config in plain text and every response is passed through
secret redaction before it reaches a report — but a real user's token does not belong
in either.</p>
</div>"""


def _runner_pane(limits, overrides: dict) -> str:
    def field(key: str, label: str, hint: str, step: str = "1") -> str:
        value = overrides.get(key, "")
        env_default = getattr(limits, key)
        return f"""<label class="field">
<span>{label}</span>
<input type="number" name="{key}" value="{_e(value)}" step="{step}" min="0"
 placeholder="{_e(env_default)} (from .env)">
<span class="muted" style="font-size:11.5px;text-transform:none;letter-spacing:0">{hint}</span></label>"""

    return f"""<p class="muted" style="margin:0 0 12px">Hard caps the trusted runner
applies to every outbound request. Blank means "use the <code>.env</code> value" shown as
the placeholder; a value here overrides it for this engagement only, with no restart.</p>
<div class="card pad">
<form method="post" action="/config/runner">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px">
{field("timeout_s", "Request timeout (s)", "Raise it for a slow staging host.", "0.5")}
{field("max_requests_per_test", "Max requests per test", "Caps a single test's fan-out, race windows included.")}
{field("max_response_bytes", "Max response bytes", "Body larger than this is truncated before storage.")}
{field("max_redirects", "Max redirects", "0 keeps auto-follow off — every hop is re-validated against scope explicitly.")}
</div>
<div style="margin-top:14px" class="row">
<button class="btn">Save limits</button>
<button class="btn ghost" name="reset" value="true">Reset to .env defaults</button>
</div>
</form></div>
<p class="muted" style="margin-top:12px">Leaving redirects at 0 is deliberate: a 302 to an
internal host is the same SSRF wearing a hat, so the runner follows hops itself and
re-validates each one rather than letting the HTTP client do it silently.</p>"""


def _runtime_pane(facts: list[tuple[str, str, str]]) -> str:
    rows = "".join(
        f"<tr><td><b>{_e(label)}</b></td><td class='mono'>{_e(value)}</td>"
        f"<td class='muted'>{_e(hint)}</td></tr>"
        for label, value, hint in facts
    )
    return f"""<p class="muted" style="margin:0 0 12px">Read-only. These come from the
process environment (<code>.env</code>), are read at startup, and need a server restart to
change — so they are shown here rather than made editable, which would offer a save button
that quietly does nothing until the next boot.</p>
<div class="card"><div class="tblwrap"><table>
<tr><th>Setting</th><th>Current</th><th>Environment variable</th></tr>{rows}
</table></div></div>
<p class="muted" style="margin-top:12px">Secrets are never echoed here — only whether one
is present. Keep tokens in <code>.env</code>, never in <code>engagement.json</code>.</p>"""


def config_page(
    readiness,
    engagement,
    engagement_path: str,
    limits,
    runtime: list[tuple[str, str, str]],
    tab: str = "readiness",
    flash: str = "",
    error: str = "",
) -> str:
    if tab not in dict(_CONFIG_TABS):
        tab = "readiness"
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""
    error_html = f"<div class='card pad err'>&#9888; {_e(error)}</div>" if error else ""

    panes = {
        "readiness": _readiness_pane(readiness, engagement_path),
        "environments": _environments_pane(engagement.environments, engagement.active_environment),
        "scope": _scope_pane(engagement.scope.policy),
        "personas": _personas_pane(
            list(engagement.raw.get("personas") or []),
            engagement.attacker,
            engagement.victim,
        ),
        "runner": _runner_pane(limits, engagement.runner),
        "runtime": _runtime_pane(runtime),
    }

    state_cls = _READY_CLASS[readiness.state]
    if readiness.n_blocking:
        counts = f"{readiness.n_blocking} blocking"
    elif readiness.n_warnings:
        counts = f"{readiness.n_warnings} to check"
    else:
        counts = "all checks pass"

    buttons = "".join(
        f"<button class='{'active' if key == tab else ''}' data-tab='cfg-{key}'>{label}"
        + (f" <span class='pill {state_cls}' style='margin-left:6px'>{readiness.n_blocking or ''}</span>"
           if key == "readiness" and readiness.n_blocking else "")
        + "</button>"
        for key, label in _CONFIG_TABS
    )
    bodies = "".join(
        f"<div class='tabpane {'active' if key == tab else ''}' id='cfg-{key}'>{panes[key]}</div>"
        for key, _label in _CONFIG_TABS
    )

    return page("Configuration", f"""
<div class="topbar" style="margin-bottom:14px">
<div><h1>Configuration</h1>
<p class="sub" style="margin:2px 0 0">Everything a run depends on, in one place.</p></div>
<span class="chip">Status <b class="pill {state_cls}" style="margin-left:6px">{_e(counts)}</b></span>
</div>
{flash_html}{error_html}
<div class="tabbar" id="config-tabs">{buttons}</div>
<div style="padding-top:16px">{bodies}</div>
<script>
(function () {{
  var bar = document.getElementById('config-tabs');
  function show(id) {{
    bar.querySelectorAll('button').forEach(function (b) {{
      b.classList.toggle('active', b.dataset.tab === id);
    }});
    document.querySelectorAll('.tabpane').forEach(function (p) {{
      p.classList.toggle('active', p.id === id);
    }});
  }}
  bar.querySelectorAll('button').forEach(function (b) {{
    b.addEventListener('click', function () {{
      show(b.dataset.tab);
      // Keep the open pane in the URL so a save (which round-trips through a
      // redirect) comes back to the pane the tester was working in.
      history.replaceState(null, '', '/config?tab=' + b.dataset.tab.slice(4));
    }});
  }});
  document.querySelectorAll('.confirm-delete').forEach(function (f) {{
    f.addEventListener('submit', function (e) {{
      if (!confirm('Delete ' + f.dataset.what + '? This rewrites the engagement config.')) {{
        e.preventDefault();
      }}
    }});
  }});
}})();
</script>
""", active="config")
