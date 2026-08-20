"""Server-rendered HTML views (dependency-free, theme-aware).

Kept separate from routing. Everything shown here has passed secret redaction
upstream (executions/findings) or is non-secret metadata.
"""

from __future__ import annotations

import json

from collections import Counter

from app.api import ui, views_assessment
from app.api.ui import attr, e
from app.core.i18n import VI, get_lang, tt as _t
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
.wrap{max-width:1600px;margin:0 auto;padding:22px 20px 80px;}
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
.lang-switch{font-size:12.5px;color:var(--muted);white-space:nowrap;}
.lang-link{color:var(--muted);text-decoration:none;padding:2px 3px;}
.lang-link.active{color:var(--fg);font-weight:700;}
.lang-link:not(.active):hover{color:var(--fg);}
.lang-sep{margin:0 2px;color:var(--border);}
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
_SHARED_JS = f"<script>{ui.TOOLTIP_JS}{ui.THEME_JS}{ui.SECTION_JS}{ui.LANG_JS}</script>"

_FOOT = f"{_SHARED_JS}</div></body></html>"


def _topbar(active: str) -> str:
    auth_links = ""
    if _AUTH_ENABLED:
        auth_links = (
            f"<a href=\"/login\" class=\"btn sec\">{_t('Log in')}</a>"
            "<form method=\"post\" action=\"/logout\" style=\"margin:0\">"
            f"<button type=\"submit\" class=\"btn ghost\">{_t('Log out')}</button></form>"
        )
    lang_toggle = ui.lang_toggle_html(get_lang())
    confirm_msg = _t(
        "Shut down the server?\n\nThis stops this app AND any other process running "
        "from this project (the demo target, stray CLI/pytest runs) — including ones "
        "started in other terminals. You will need to start it again manually."
    )
    shutting_down = _t("Shutting down…")
    shutdown_title = _t("Server is shutting down")
    shutdown_body = _t(
        "All processes for this project have been stopped. Start it again from a "
        "terminal to continue."
    )
    return f"""<div class="topbar">
<a href="/" class="brand">{_MARK}<b>{_t("API Security Testing Platform")}</b></a>
<div class="row" style="gap:16px">
<nav class="tabs">
<a href="/" class="{"active" if active == "dashboard" else ""}">{_t("Dashboard")}</a>
<a href="/config" class="{"active" if active == "config" else ""}">{_t("Configuration")}</a>
</nav>
{lang_toggle}
{ui.THEME_TOGGLE_HTML}
{auth_links}
<button type="button" class="btn sec danger" onclick="shutdownServer()">{_t("Shutdown server")}</button>
</div></div>
<script>
function shutdownServer() {{
  if (!confirm({json.dumps(confirm_msg)})) return;
  document.querySelectorAll('.danger').forEach(function (b) {{
    b.disabled = true;
    b.textContent = {json.dumps(shutting_down)};
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
    '<h1 style="font-size:18px;margin:0 0 8px">' + {json.dumps(shutdown_title)} + '</h1>' +
    '<p style="color:#5b6b6d">' + {json.dumps(shutdown_body)} + '</p></div>';
}}
</script>"""


_THEME_BOOT = (
    "<script>try{var t=localStorage.getItem('stp-theme');"
    "if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>"
)


def page(title: str, body: str, active: str = "") -> str:
    head = f"""<!doctype html><html lang="{get_lang()}"><head><meta charset="utf-8">
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
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    warn_html = f"<div class='card pad warn'>&#9888; {_e(warning)}</div>" if warning else ""

    counts = Counter(a.status for a in assessments)
    summary = ui.stats([
        (str(len(assessments)), _t("Assessments"), "", ""),
        (str(counts.get("CREATED", 0)), _t("Imported"), _t("Analyzed, no plan generated yet."), ""),
        (str(counts.get("ANALYZED", 0)), _t("Designed"), _t("A plan exists; it may not be approved."), ""),
        (str(counts.get("EXECUTED", 0)), _t("Executed"), _t("At least one run has happened."), ""),
    ])

    by_id = {r["id"]: r for r in (rows or [])}
    cards = "".join(_assessment_card(a, by_id.get(a.id, {})) for a in assessments)
    cards = cards or (
        "<p class='muted'>"
        + (_t("No assessments match this filter.") if (q or status)
           else _t("No assessments yet — import a Jira issue above."))
        + "</p>"
    )

    target = (_e(engagement_target) if engagement_target
              else f"<span class='muted'>{_t('not configured — execution disabled')}</span>")
    ai = _t("AI (Claude)") if ai_on else _t("deterministic (heuristic)")

    # Available keys come from the mock only; a live instance is not enumerated,
    # so the hint becomes "type your own key" rather than a stale list.
    keys = available_keys or []
    if keys:
        hint = (_t("importable now:") + " "
                + ", ".join(f"<a href='#' class='keyfill'><code>{_e(k)}</code></a>" for k in keys))
        placeholder = _e(keys[0])
    else:
        hint = _t("enter any issue key your Jira account can read")
        placeholder = "ABC-123"

    plan_tip = _t(
        "Analyze only: just the endpoint list and OWASP mapping, nothing designed yet — "
        "pick this when the endpoint list needs correcting first. Auto-plan: the AI planner "
        "adds its own attacks on top of the rule engine, then a reviewing agent audits the "
        "result and sends gaps back for one revision round. Run ticket's PoC only: no "
        "invented attacks — just the PoC script embedded in the ticket's description, "
        "always sent to the target URL configured for this tool (never a host from the "
        "script itself), still reviewed by the same reviewing agent read-only. Either way, "
        "nothing runs: every test lands PENDING."
    )
    confirm_delete = _t("Delete this assessment? This cannot be undone.")
    reimport_confirm = _t(
        "Re-import {issue} from Jira?\n\nCreates a new assessment from the ticket as it "
        "reads now. No tests are generated and nothing runs."
    )
    rerun_confirm = _t(
        "Re-run {issue}?\n\nCreates a new assessment with the same plan and approvals, "
        "then runs the approved non-destructive tests. Destructive tests are never "
        "included in a re-run. The previous run is kept as the baseline."
    )
    working = _t("Working…")
    running = _t("Running…")

    return page(_t("Dashboard"), f"""
{flash_html}{warn_html}
<div class="chips" style="margin-bottom:18px">
<span class="chip">{_t("Analyzer")} <b>{ai}</b></span>
<span class="chip">Jira <b>{_e(jira_mode)}</b></span>
<span class="chip">{_t("Target")} <b>{target}</b></span>
</div>
<div class="card pad" style="margin-bottom:22px">
<label class="field" style="margin-bottom:8px"><span>{_t("Import a Jira issue")}</span></label>
<form method="post" action="/import" class="row js-busy" style="align-items:flex-end">
<input name="issue_key" id="issue_key" placeholder="{placeholder}" style="max-width:220px" required>
<label class="field" style="max-width:150px;margin:0"><span>{_t("Depth")}</span>
<select name="depth">
<option value="standard" selected>{_t("Standard")}</option>
<option value="aggressive">{_t("Aggressive")}</option>
</select></label>
<label class="field" style="max-width:190px;margin:0" data-tip="{attr(plan_tip)}">
<span>{_t("On import")}</span>
<select name="mode">
<option value="analyze">{_t("Analyze only")}</option>
<option value="auto_plan" selected>{_t("Auto-plan (AI attack planner)")}</option>
<option value="ticket_poc">{_t("Run ticket's PoC only")}</option>
</select></label>
<button class="btn">{_t("Import")}</button>
</form>
<p class="muted" style="margin:8px 0 0;font-size:13px">{hint}</p></div>
{summary}
<h2 class="section">{_t("Recent assessments")}</h2>
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
    btn.innerHTML = '<span class="spinner"></span> ' + {json.dumps(working)};
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
    if (!confirm({json.dumps(confirm_delete)})) e.preventDefault();
  }});
}});
document.querySelectorAll('.rerun-form').forEach(function (f) {{
  f.addEventListener('submit', function (e) {{
    var mode = f.querySelector('[name=mode]').value;
    var msg = mode === 'reimport'
      ? {json.dumps(reimport_confirm)}.replace('{{issue}}', f.dataset.issue)
      : {json.dumps(rerun_confirm)}.replace('{{issue}}', f.dataset.issue);
    if (!confirm(msg)) {{ e.preventDefault(); return; }}
    var btn = f.querySelector('button');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> ' + {json.dumps(running)};
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
            f"{_e(_t(text))}</option>" for value, text in choices
        )
        return f'<select name="{attr(name)}" style="width:auto">{opts}</select>'

    shown_label = _t("{n} shown").format(n=shown)
    page_label = _t(" · page {n}").format(n=page_no) if page_no > 1 else ""
    return f"""<form method="get" action="/" class="toolbar">
<label class="field grow"><span>{_t("Search issue key")}</span>
<input name="q" value="{attr(q)}" placeholder="BH-142" style="width:100%"></label>
<label class="field"><span>{_t("Status")}</span>{options("status", status, _DASH_STATUS)}</label>
<label class="field"><span>{_t("Sort")}</span>{options("sort", sort or "recent", _DASH_SORT)}</label>
<label class="field"><span>{_t("Per page")}</span>
{options("per", str(per), [(str(n), str(n)) for n in (12, 24, 48, 96)])}</label>
<div class="row" style="gap:6px;align-items:flex-end">
<button class="btn sec">{_t("Apply")}</button>
<a class="btn ghost" href="/">{_t("Clear")}</a></div>
<span class="count" style="align-self:flex-end;padding-bottom:8px">
{shown_label}{page_label}</span>
</form>"""


def _assessment_card(a: Assessment, row: dict) -> str:
    label, cls = _STATUS_PILL.get(a.status, (a.status.title(), "info"))
    created = getattr(a, "created_at", None)
    when = created.strftime("%Y-%m-%d %H:%M") if created else ""

    facts = []
    if row.get("n_tests"):
        facts.append(_t("{n} test(s)").format(n=row["n_tests"]))
    if row.get("n_approved"):
        facts.append(_t("{n} approved").format(n=row["n_approved"]))
    if row.get("n_executions"):
        facts.append(_t("{n} run").format(n=row["n_executions"]))
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
        word = _t("Re-run") if row.get("n_approved") else _t("Re-import")
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
        f"style='padding:3px 9px;font-size:12px'>{_t('Delete')}</button></form></div></div>"
    )


def login_page(flash: str = "") -> str:
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    intro = _t(
        "Multi-user auth is enabled. Paste the API key printed by "
        "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> to authenticate "
        "this browser for actions like designing tests, approving, and executing. Reads "
        "stay open either way."
    )
    return page(_t("Log in"), f"""
<h1 style="font-size:19px">{_t("Log in")}</h1>
<p class="sub">{intro}</p>
{flash_html}
<div class="card pad" style="max-width:420px">
<form method="post" action="/login">
<label class="field" style="margin-bottom:12px"><span>{_t("API key")}</span>
<input type="password" name="api_key" required autofocus></label>
<button class="btn">{_t("Log in")}</button>
</form>
</div>
""")


def error_page(title: str, headline: str, hint_html: str,
                back_href: str = "/", back_label: str | None = None) -> str:
    """A failure as a readable page instead of a bare 500. `headline` may
    contain user input and is escaped; `hint_html` is markup we build ourselves."""
    back_label = _t(back_label if back_label is not None else "← Back to dashboard")
    title = _t(title)
    return page(title, f"""
<h1 style="font-size:19px">{_e(title)}</h1>
<div class="card pad err">
<p style="margin:0 0 8px"><b>{_e(_t(headline))}</b></p>
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
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""

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
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
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
    ("mcp", "MCP"),
    ("runtime", "Runtime (.env)"),
]

VI.update({
    "Readiness": "Sẵn sàng", "Environments": "Môi trường", "Scope": "Phạm vi",
    "Personas": "Persona", "Runner limits": "Giới hạn runner", "MCP": "MCP",
    "Runtime (.env)": "Runtime (.env)",
})


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
        star = f" <span class='pill low'>{_t('default')}</span>" if env.is_active else ""
        ip = (f"<div class='muted mono' style='font-size:11.5px'>{_e(env.resolved_ip)}</div>"
              if env.resolved_ip else "")
        verdict_word = _t("ALLOWED") if env.state == "ok" else _t("BLOCKED")
        env_rows += (
            f"<tr><td><code>{_e(env.name)}</code>{star}</td>"
            f"<td class='mono' style='font-size:12.5px'>{_e(env.url)}</td>"
            f"<td><span class='pill {cls}'>{verdict_word}</span>"
            f"{ip}</td>"
            f"<td class='muted'>{_e(env.reason)}</td></tr>"
        )
    env_rows = env_rows or f"<tr><td colspan='4' class='muted'>{_t('No environments to check.')}</td></tr>"

    if readiness.can_run:
        verdict = (f"<div class='card pad flash' style='margin-bottom:16px'>"
                   f"<b>&#10003; {_t('Ready to run.')}</b> "
                   f"{_t('Nothing in this configuration will stop a request from being sent.')}</div>")
    else:
        verdict = ("<div class='card pad err' style='margin-bottom:16px'>"
                   f"<b>&#10007; {_t('{n} blocking issue(s).').format(n=readiness.n_blocking)}</b> "
                   f"{_t('A run started now comes back entirely BLOCKED or ERROR. Each row below names the setting and the pane that fixes it.')}</div>")

    return f"""{verdict}
<div class="card" style="margin-bottom:22px"><div class="tblwrap"><table>
<tr><th style="width:110px">{_t("State")}</th><th>{_t("Check")}</th></tr>{rows}</table></div></div>

<h2 class="section">{_t("Scope verdict per environment")}</h2>
<p class="muted" style="margin:-4px 0 10px">{_t(
    'Each base URL run through the same <code>ScopeValidator</code> the runner calls, DNS '
    'lookup included. Whatever this table says here is exactly what the execution log will say.'
)}</p>
<div class="card"><div class="tblwrap"><table>
<tr><th>{_t("Environment")}</th><th>{_t("Base URL")}</th><th>{_t("Verdict")}</th><th>{_t("Reason")}</th></tr>{env_rows}
</table></div></div>
<p class="muted" style="margin-top:12px">{_t("Config file:")} <code>{_e(engagement_path)}</code></p>"""


def _environments_pane(environments: dict[str, str], active: str) -> str:
    rows = ""
    for name, url in environments.items():
        badge = f" <span class='pill low'>{_t('default')}</span>" if name == active else ""
        make_default = "" if name == active else (
            f"<form method='post' action='/config/environments/{_e(name)}/activate' "
            f"style='margin:0;display:inline-block'>"
            f"<button class='btn ghost' style='padding:4px 8px'>{_t('Make default')}</button></form>"
        )
        rows += (
            f"<tr><td><b>{_e(name)}</b>{badge}</td><td class='mono'>{_e(url)}</td>"
            f"<td style='white-space:nowrap'>{make_default}"
            f"<form method='post' action='/config/environments/{_e(name)}/delete' "
            f"style='margin:0;display:inline-block' class='confirm-delete' "
            f"data-what='environment {_e(name)}'>"
            f"<button class='btn sec' style='padding:4px 10px'>{_t('Delete')}</button></form></td></tr>"
        )
    rows = rows or f"<tr><td colspan='3' class='muted'>{_t('No environments configured yet.')}</td></tr>"
    intro = _t(
        "Named target URLs. Only the path/method/body of a pasted PoC survive transpiling, "
        "so whichever base URL is picked here is what actually gets called."
    )
    authorize_tip = _t(
        "Adds this URL's hostname to scope.allowed_hosts. Without it every request to "
        "the new environment is refused before it is sent."
    )
    authorize_note = _t(
        "<b>Authorize its host</b> adds the hostname to <b>Scope &rarr; approved hosts</b> "
        "in the same step. Leave it off for a target the engagement does not actually cover "
        "— the URL is then saved but every request to it stays blocked, which is the safe "
        "direction to fail in."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>{_t("Name")}</th><th>{_t("Base URL")}</th><th></th></tr>{rows}</table></div></div>
<div class="card pad">
<form method="post" action="/config/environments" class="row">
<input name="name" placeholder="staging" style="max-width:160px" required>
<input name="url" placeholder="https://staging.company.com" style="flex:1;min-width:240px" required>
<label class="muted" style="display:flex;align-items:center;gap:4px">
<input type="checkbox" name="make_active" value="true" style="width:auto"> {_t("make default")}</label>
<label class="muted" style="display:flex;align-items:center;gap:4px"
 title="{attr(authorize_tip)}">
<input type="checkbox" name="authorize_host" value="true" style="width:auto" checked> {_t("authorize its host")}</label>
<button class="btn">{_t("Save")}</button>
</form>
<p class="muted" style="margin:10px 0 0">{authorize_note}</p>
</div>"""


def _scope_pane(policy) -> str:
    allowed = "\n".join(sorted(policy.allowed_hosts))
    blocked = "\n".join(sorted(policy.blocked_hosts))
    priv = "checked" if policy.allow_private_ranges else ""
    intro = _t(
        "The authorization boundary. Every outbound request is checked against this "
        "before it is sent, and the hostname must appear in <b>approved hosts</b> exactly "
        "— there are no wildcards, because a wildcard in a pentest authorization list is "
        "how an unauthorized host gets tested by accident."
    )
    priv_note = _t(
        "Off by default. When off, a host that <i>resolves</i> to 127.0.0.0/8, 10/8, "
        "172.16/12, 192.168/16 or 169.254/16 (cloud metadata) is refused even if its name "
        "is on the approved list — that check is what stops a DNS-based SSRF from reaching "
        "an internal service. Turn it on only for a local lab target."
    )
    footer = _t(
        "Hostnames only — no scheme, no port, no path. A port is not part of the check "
        "(<code>api.example.com:8443</code> is authorized by <code>api.example.com</code>), "
        "and DNS is resolved and the resulting IP re-checked on every request, so a name "
        "that resolves somewhere new is caught at send time."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<div class="card pad">
<form method="post" action="/config/scope">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
<label class="field"><span>{_t("Approved hosts — one per line")}</span>
<textarea name="allowed_hosts" rows="7" placeholder="staging-api.company.com&#10;127.0.0.1">{_e(allowed)}</textarea></label>
<label class="field"><span>{_t("Blocked hosts — one per line (always wins)")}</span>
<textarea name="blocked_hosts" rows="7" placeholder="production.company.com">{_e(blocked)}</textarea></label>
</div>
<label class="row" style="gap:8px;margin-top:14px;align-items:flex-start">
<input type="checkbox" name="allow_private_ranges" value="true" style="width:auto;margin-top:3px" {priv}>
<span><b>{_t("Allow private / loopback ranges")}</b><br>
<span class="muted">{priv_note}</span></span></label>
<div style="margin-top:14px"><button class="btn">{_t("Save scope")}</button></div>
</form></div>
<p class="muted" style="margin-top:12px">{footer}</p>"""


def _personas_pane(personas: list[dict], attacker: str, victim: str) -> str:
    names = [p.get("name", "") for p in personas]
    cards = ""
    for p in personas:
        name = p.get("name", "")
        roles = ""
        if name == attacker:
            roles += f" <span class='pill med'>{_t('attacker')}</span>"
        if name == victim:
            roles += f" <span class='pill high'>{_t('victim')}</span>"
        headers = _kv_textarea_value(p.get("auth_headers") or {}, ": ")
        owns = _kv_textarea_value(p.get("owns") or {}, "=")
        markers = "\n".join(p.get("secret_markers") or [])
        scoping = "\n".join(p.get("scoping_headers") or [])
        save_label = _t("Save {name}").format(name=_e(name))
        cards += f"""<div class="card pad" style="margin-bottom:12px">
<div class="row" style="justify-content:space-between;margin-bottom:10px">
<div><b>{_e(name)}</b>{roles}</div>
<form method="post" action="/config/personas/{_e(name)}/delete" style="margin:0"
 class="confirm-delete" data-what="persona {_e(name)}">
<button class="btn ghost">{_t("Delete")}</button></form>
</div>
<form method="post" action="/config/personas">
<input type="hidden" name="name" value="{_e(name)}">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>{_t("Role label")}</span>
<input name="role" value="{_e(p.get('role', 'user'))}"></label>
<label class="field"><span>{_t("Owned object ids — key=value per line")}</span>
<textarea name="owns" rows="3" placeholder="customer_id=2002">{_e(owns)}</textarea></label>
</div>
<label class="field" style="margin-top:12px"><span>{_t("Auth headers — Header: value per line")}</span>
<textarea name="auth_headers" rows="3" placeholder="Authorization: Bearer eyJ...">{_e(headers)}</textarea></label>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px">
<label class="field"><span>{_t("Secret markers — one per line")}</span>
<textarea name="secret_markers" rows="2" placeholder="beth.victim@example.com">{_e(markers)}</textarea></label>
<label class="field"><span>{_t("Scoping headers to strip on privilege-escalation tests — one per line")}</span>
<textarea name="scoping_headers" rows="2" placeholder="entity-context">{_e(scoping)}</textarea></label>
</div>
<div style="margin-top:12px"><button class="btn">{save_label}</button></div>
</form></div>"""
    cards = cards or f"<p class='muted'>{_t('No personas defined yet — add one below.')}</p>"

    def opts(selected: str) -> str:
        out = "".join(
            f"<option value='{_e(n)}' {'selected' if n == selected else ''}>{_e(n)}</option>"
            for n in names
        )
        if selected and selected not in names:
            out = (f"<option value='{_e(selected)}' selected>{_e(selected)} "
                   f"— {_t('not defined!')}</option>" + out)
        return out or f"<option value=''>— {_t('no personas defined')} —</option>"

    personas_intro = _t(
        'Test identities and their credentials. You cannot test broken object-level '
        'authorization with one identity: BOLA means "A reaches B\'s object", which needs '
        'two real accounts plus knowledge of what each legitimately owns. Tests reference '
        'personas <i>by name</i>, so a token never lands in a test case, an export or a report.'
    )
    roles_note = _t(
        "The attacker sends the requests; generated BOLA cases aim it at ids the victim "
        "owns. Point these at two <i>different</i> personas or the results are "
        "inconclusive by construction."
    )
    add_footer = _t(
        "Use dedicated test accounts. Credentials are written to the engagement config in "
        "plain text and every response is passed through secret redaction before it reaches "
        "a report — but a real user's token does not belong in either."
    )

    return f"""<p class="muted" style="margin:0 0 12px">{personas_intro}</p>

<div class="card pad" style="margin-bottom:18px">
<form method="post" action="/config/identities" class="row" style="align-items:flex-end">
<label class="field" style="max-width:220px"><span>{_t("Attacker persona")}</span>
<select name="attacker">{opts(attacker)}</select></label>
<label class="field" style="max-width:220px"><span>{_t("Victim persona")}</span>
<select name="victim">{opts(victim)}</select></label>
<button class="btn">{_t("Save roles")}</button>
</form>
<p class="muted" style="margin:10px 0 0">{roles_note}</p>
</div>

<h2 class="section">{_t("Defined personas")}</h2>
{cards}

<h2 class="section">{_t("Add a persona")}</h2>
<div class="card pad">
<form method="post" action="/config/personas">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<label class="field"><span>{_t("Name")}</span>
<input name="name" placeholder="agent_A" required></label>
<label class="field"><span>{_t("Role label")}</span>
<input name="role" placeholder="agent" value="user"></label>
</div>
<label class="field" style="margin-top:12px"><span>{_t("Auth headers — Header: value per line")}</span>
<textarea name="auth_headers" rows="3" placeholder="Authorization: Bearer eyJ..."></textarea></label>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px">
<label class="field"><span>{_t("Owned object ids — key=value per line")}</span>
<textarea name="owns" rows="2" placeholder="customer_id=1001"></textarea></label>
<label class="field"><span>{_t("Secret markers — one per line")}</span>
<textarea name="secret_markers" rows="2" placeholder="alice.buyer@example.com"></textarea></label>
</div>
<label class="field" style="margin-top:12px"><span>{_t("Scoping headers to strip on privilege-escalation tests — one per line")}</span>
<textarea name="scoping_headers" rows="2" placeholder="entity-context"></textarea></label>
<div style="margin-top:12px"><button class="btn">{_t("Add persona")}</button></div>
</form>
<p class="muted" style="margin:10px 0 0">{add_footer}</p>
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

    intro = _t(
        'Hard caps the trusted runner applies to every outbound request. Blank means '
        '"use the <code>.env</code> value" shown as the placeholder; a value here '
        'overrides it for this engagement only, with no restart.'
    )
    footer = _t(
        "The runner never auto-follows a redirect: a 302 to an internal host is the same "
        "SSRF wearing a hat, and blindly chasing it would let the HTTP client re-resolve DNS "
        "outside the scope gate. A 3xx response is captured and evaluated exactly as received "
        "— there is no redirect setting to tune here."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<div class="card pad">
<form method="post" action="/config/runner">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px">
{field("timeout_s", _t("Request timeout (s)"), _t("Raise it for a slow staging host."), "0.5")}
{field("max_requests_per_test", _t("Max requests per test"), _t("Caps a single test's fan-out, race windows included."))}
{field("max_response_bytes", _t("Max response bytes"), _t("Body larger than this is truncated before storage."))}
</div>
<div style="margin-top:14px" class="row">
<button class="btn">{_t("Save limits")}</button>
<button class="btn ghost" name="reset" value="true">{_t("Reset to .env defaults")}</button>
</div>
</form></div>
<p class="muted" style="margin-top:12px">{footer}</p>"""


def _mcp_pane(
    jira_mode: str,
    jira_live: bool,
    jira_warning: str,
    jira_env: list[tuple[str, str, str]],
    jira_keys: list[str],
) -> str:
    cls = "low" if jira_live else "med"
    word = _t("LIVE") if jira_live else _t("MOCK")
    warning_html = (
        f"<div class='muted' style='margin-top:6px;color:var(--crit)'>&#9888; {_e(jira_warning)}</div>"
        if jira_warning else ""
    )
    keys_html = (
        f"<div class='muted' style='margin-top:6px'>{_t('Serves:')} "
        + ", ".join(f"<code>{_e(k)}</code>" for k in jira_keys) + "</div>"
        if jira_keys else ""
    )
    env_rows = "".join(
        f"<tr><td class='mono'>{_e(name)}</td>"
        f"<td><span class='pill {'low' if status == 'set' else 'med'}'>{_t(status.upper())}</span></td>"
        f"<td class='muted'>{_e(hint)}</td></tr>"
        for name, status, hint in jira_env
    )
    intro = _t(
        "External MCP connectors this platform talks to. Credentials live in <code>.env</code> "
        "only — never in <code>engagement.json</code> or a report. <b>Reconnect</b> re-reads "
        "<code>.env</code> and rebinds the client in place, which is all a restart would have "
        "done anyway — useful right after refreshing a short-lived OAuth token."
    )
    refresh_note = _t(
        "<b>Refresh token</b> opens the Atlassian OAuth login in your browser, waits for it, "
        "and reconnects automatically — needs Node.js (<code>npx</code>) and a browser on the "
        "machine running this app. If that isn't available here, do it by hand instead: "
        "authorize once with <code>npx -y mcp-remote https://mcp.atlassian.com/v1/mcp</code>, "
        "run <code>npm run jira:token</code> to pull the new token into <code>.env</code>, then "
        "click <b>Reconnect</b> above."
    )
    postman_note = _t(
        "No MCP integration is wired up for this platform — there is nothing here yet to "
        "connect or reconnect. (Separately, a completed assessment can already export a "
        "Postman collection from its report page — a one-way file export, unrelated to this "
        "connector list.)"
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>

<div class="card pad" style="margin-bottom:18px">
<div class="row" style="justify-content:space-between;align-items:flex-start">
<div>
<b>Jira</b> <span class="pill {cls}" style="margin-left:6px">{word}</span>
<div class="muted" style="margin-top:4px">{_e(jira_mode)}</div>
{warning_html}{keys_html}
</div>
<div class="row" style="gap:8px;margin:0">
<form method="post" action="/config/mcp/jira/refresh-token" class="js-busy" style="margin:0">
<button class="btn ghost">{_t("Refresh token")}</button></form>
<form method="post" action="/config/mcp/jira/reconnect" style="margin:0">
<button class="btn">{_t("Reconnect")}</button></form>
</div>
</div>
</div>

<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>{_t("Environment variable")}</th><th>{_t("Status")}</th><th>{_t("Purpose")}</th></tr>{env_rows}
</table></div></div>
<p class="muted" style="margin-bottom:22px">{refresh_note}</p>

<h2 class="section">{_t("Other connectors")}</h2>
<div class="card pad">
<b>Postman</b> <span class="pill med" style="margin-left:6px">{_t("NOT CONFIGURED")}</span>
<div class="muted" style="margin-top:4px">{postman_note}</div>
</div>"""


def _runtime_pane(facts: list[tuple[str, str, str]]) -> str:
    rows = "".join(
        f"<tr><td><b>{_e(label)}</b></td><td class='mono'>{_e(value)}</td>"
        f"<td class='muted'>{_e(hint)}</td></tr>"
        for label, value, hint in facts
    )
    intro = _t(
        "Read-only. These come from the process environment (<code>.env</code>), are read "
        "at startup, and need a server restart to change — so they are shown here rather "
        "than made editable, which would offer a save button that quietly does nothing "
        "until the next boot."
    )
    footer = _t(
        "Secrets are never echoed here — only whether one is present. Keep tokens in "
        "<code>.env</code>, never in <code>engagement.json</code>."
    )
    return f"""<p class="muted" style="margin:0 0 12px">{intro}</p>
<div class="card"><div class="tblwrap"><table>
<tr><th>{_t("Setting")}</th><th>{_t("Current")}</th><th>{_t("Environment variable")}</th></tr>{rows}
</table></div></div>
<p class="muted" style="margin-top:12px">{footer}</p>"""


def config_page(
    readiness,
    engagement,
    engagement_path: str,
    limits,
    runtime: list[tuple[str, str, str]],
    jira_mode: str,
    jira_live: bool,
    jira_warning: str,
    jira_env: list[tuple[str, str, str]],
    jira_keys: list[str],
    tab: str = "readiness",
    flash: str = "",
    error: str = "",
) -> str:
    if tab not in dict(_CONFIG_TABS):
        tab = "readiness"
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    error_html = f"<div class='card pad err'>&#9888; {_e(_t(error))}</div>" if error else ""

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
        "mcp": _mcp_pane(jira_mode, jira_live, jira_warning, jira_env, jira_keys),
        "runtime": _runtime_pane(runtime),
    }

    state_cls = _READY_CLASS[readiness.state]
    if readiness.n_blocking:
        counts = _t("{n} blocking").format(n=readiness.n_blocking)
    elif readiness.n_warnings:
        counts = _t("{n} to check").format(n=readiness.n_warnings)
    else:
        counts = _t("all checks pass")

    buttons = "".join(
        f"<button class='{'active' if key == tab else ''}' data-tab='cfg-{key}'>{_t(label)}"
        + (f" <span class='pill {state_cls}' style='margin-left:6px'>{readiness.n_blocking or ''}</span>"
           if key == "readiness" and readiness.n_blocking else "")
        + "</button>"
        for key, label in _CONFIG_TABS
    )
    bodies = "".join(
        f"<div class='tabpane {'active' if key == tab else ''}' id='cfg-{key}'>{panes[key]}</div>"
        for key, _label in _CONFIG_TABS
    )

    return page(_t("Configuration"), f"""
<div class="topbar" style="margin-bottom:14px">
<div><h1>{_t("Configuration")}</h1>
<p class="sub" style="margin:2px 0 0">{_t("Everything a run depends on, in one place.")}</p></div>
<span class="chip">{_t("Status")} <b class="pill {state_cls}" style="margin-left:6px">{_e(counts)}</b></span>
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


VI.update({
    # -- shared chrome (topbar, present on every page) --
    "API Security Testing Platform": "Nền tảng kiểm thử bảo mật API",
    "Dashboard": "Trang chủ",
    "Configuration": "Cấu hình",
    "Log in": "Đăng nhập",
    "Log out": "Đăng xuất",
    "Shutdown server": "Tắt server",
    "Shutting down…": "Đang tắt…",
    "Server is shutting down": "Server đang tắt",
    "All processes for this project have been stopped. Start it again from a "
    "terminal to continue.":
        "Mọi tiến trình của dự án này đã dừng. Khởi động lại từ terminal để tiếp tục.",
    "Shut down the server?\n\nThis stops this app AND any other process running "
    "from this project (the demo target, stray CLI/pytest runs) — including ones "
    "started in other terminals. You will need to start it again manually.":
        "Tắt server?\n\nThao tác này dừng app này VÀ mọi tiến trình khác của dự án "
        "(demo target, các lệnh CLI/pytest đang chạy lẻ) — kể cả những tiến trình "
        "khởi động từ terminal khác. Bạn sẽ phải tự khởi động lại.",
    # -- dashboard --
    "Assessments": "Assessment", "Imported": "Đã nhập", "Designed": "Đã lên kế hoạch",
    "Executed": "Đã chạy",
    "Analyzed, no plan generated yet.": "Đã phân tích, chưa có kế hoạch.",
    "A plan exists; it may not be approved.": "Đã có kế hoạch; có thể chưa được duyệt.",
    "At least one run has happened.": "Đã có ít nhất một lượt chạy.",
    "No assessments match this filter.": "Không có assessment nào khớp bộ lọc này.",
    "No assessments yet — import a Jira issue above.":
        "Chưa có assessment nào — nhập một issue Jira ở trên.",
    "not configured — execution disabled": "chưa cấu hình — không thể chạy test",
    "AI (Claude)": "AI (Claude)", "deterministic (heuristic)": "tất định (heuristic)",
    "importable now:": "có thể nhập ngay:",
    "enter any issue key your Jira account can read":
        "nhập bất kỳ issue key nào tài khoản Jira của bạn đọc được",
    "Analyzer": "Bộ phân tích", "Target": "Mục tiêu",
    "Import a Jira issue": "Nhập một issue Jira",
    "Depth": "Độ sâu", "Standard": "Tiêu chuẩn", "Aggressive": "Nâng cao",
    "Analyze the ticket and its embedded PoC, design a plan, let the AI planner add "
    "depth, then have a reviewing agent audit the plan against the ticket's requirements "
    "and send its gaps back for one revision round. You land on the plan with something "
    "to approve. Nothing runs: every test arrives PENDING. Uncheck to analyze only — "
    "which is what you want when the endpoint list needs correcting first.":
        "Phân tích ticket và PoC đính kèm, lên kế hoạch, để AI planner bổ sung chiều sâu, "
        "sau đó một agent đánh giá kế hoạch so với yêu cầu của ticket và gửi lại các lỗ "
        "hổng cho một vòng chỉnh sửa. Bạn sẽ đến thẳng trang kế hoạch để duyệt. Không có "
        "gì được chạy: mọi test đều ở trạng thái PENDING. Bỏ chọn để chỉ phân tích — dùng "
        "khi cần sửa lại danh sách endpoint trước.",
    "Plan &amp; review on import": "Lên kế hoạch &amp; đánh giá khi nhập",
    "Import": "Nhập", "Recent assessments": "Assessment gần đây",
    "Working…": "Đang xử lý…", "Running…": "Đang chạy…",
    "Delete this assessment? This cannot be undone.":
        "Xoá assessment này? Không thể hoàn tác.",
    "Re-import {issue} from Jira?\n\nCreates a new assessment from the ticket as it "
    "reads now. No tests are generated and nothing runs.":
        "Nhập lại {issue} từ Jira?\n\nTạo một assessment mới từ nội dung ticket hiện tại. "
        "Không tạo test nào và không chạy gì cả.",
    "Re-run {issue}?\n\nCreates a new assessment with the same plan and approvals, "
    "then runs the approved non-destructive tests. Destructive tests are never "
    "included in a re-run. The previous run is kept as the baseline.":
        "Chạy lại {issue}?\n\nTạo một assessment mới với cùng kế hoạch và các duyệt hiện "
        "có, rồi chạy các test không phá huỷ đã duyệt. Test phá huỷ không bao giờ được "
        "đưa vào lượt chạy lại. Lượt chạy trước được giữ làm mốc so sánh.",
    # -- dashboard toolbar --
    "Any status": "Mọi trạng thái", "Newest first": "Mới nhất trước",
    "Oldest first": "Cũ nhất trước", "Issue key": "Issue key",
    "Most findings": "Nhiều phát hiện nhất",
    "Search issue key": "Tìm theo issue key",
    "Status": "Trạng thái", "Sort": "Sắp xếp", "Per page": "Mỗi trang",
    "Apply": "Áp dụng", "Clear": "Xoá bộ lọc",
    "{n} shown": "{n} đang hiển thị", " · page {n}": " · trang {n}",
    # -- assessment card --
    "{n} test(s)": "{n} test", "{n} approved": "{n} đã duyệt", "{n} run": "{n} lượt chạy",
    "Re-run": "Chạy lại", "Re-import": "Nhập lại", "Delete": "Xoá",
    # -- login / error pages --
    "API key": "API key",
    "Multi-user auth is enabled. Paste the API key printed by "
    "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> to authenticate "
    "this browser for actions like designing tests, approving, and executing. Reads "
    "stay open either way.":
        "Xác thực đa người dùng đang bật. Dán API key được in ra bởi "
        "<code>python -m app.core.auth add &lt;name&gt; &lt;role&gt;</code> để xác thực "
        "trình duyệt này cho các thao tác như thiết kế test, duyệt và chạy test. Xem dữ "
        "liệu vẫn luôn mở dù có xác thực hay không.",
    "← Back to dashboard": "← Về trang chủ",
    "← Back to assessment": "← Về assessment",
    "← Back to the new assessment": "← Về assessment mới",
    # -- main.py flash messages (static ones only — dynamic ones with names/counts
    # baked into the string are left in English, since a template-less lookup
    # cannot translate a value it has already been substituted into) --
    "Invalid API key": "API key không hợp lệ", "Logged out": "Đã đăng xuất",
    "Deleted assessment": "Đã xoá assessment", "Assessment not found": "Không tìm thấy assessment",
    "Test plan generated": "Đã tạo kế hoạch test", "Unknown action": "Hành động không xác định",
    "No tests selected": "Chưa chọn test nào",
    "Execution disabled: no engagement configured": "Không thể chạy: chưa cấu hình engagement",
    "Scope saved": "Đã lưu phạm vi",
    "Saved — approval reset to PENDING": "Đã lưu — duyệt được đặt lại về PENDING",
    "Posted to Jira": "Đã đăng lên Jira",
    # -- main.py error_page titles --
    "Invalid environment name": "Tên môi trường không hợp lệ", "Invalid URL": "URL không hợp lệ",
    "Import failed": "Nhập thất bại", "Re-analysis failed": "Phân tích lại thất bại",
    "Planning agent failed": "Agent lên kế hoạch thất bại",
    "Result review failed": "Đánh giá kết quả thất bại",
    "Execution failed": "Chạy test thất bại", "Re-import failed": "Nhập lại thất bại",
    "Re-run failed": "Chạy lại thất bại", "Posting to Jira failed": "Đăng lên Jira thất bại",
    # -- config page shell --
    "Everything a run depends on, in one place.": "Mọi thứ một lượt chạy cần, ở một nơi.",
    "{n} blocking": "{n} chặn", "{n} to check": "{n} cần kiểm tra",
    "all checks pass": "mọi kiểm tra đều đạt",
    # -- readiness pane --
    "No environments to check.": "Không có môi trường nào để kiểm tra.",
    "Ready to run.": "Sẵn sàng chạy.",
    "Nothing in this configuration will stop a request from being sent.":
        "Không có gì trong cấu hình này ngăn request được gửi đi.",
    "{n} blocking issue(s).": "{n} vấn đề chặn.",
    "A run started now comes back entirely BLOCKED or ERROR. Each row below names the "
    "setting and the pane that fixes it.":
        "Nếu chạy ngay bây giờ, kết quả sẽ toàn BỊ CHẶN hoặc LỖI. Mỗi dòng dưới đây nêu "
        "rõ cấu hình và tab cần sửa.",
    "State": "Trạng thái", "Check": "Kiểm tra",
    "Scope verdict per environment": "Kết luận phạm vi theo từng môi trường",
    "Each base URL run through the same <code>ScopeValidator</code> the runner calls, DNS "
    "lookup included. Whatever this table says here is exactly what the execution log will say.":
        "Mỗi base URL được chạy qua đúng <code>ScopeValidator</code> mà runner gọi, kể cả "
        "tra cứu DNS. Bảng này nói gì thì nhật ký thực thi cũng sẽ nói y hệt vậy.",
    "Environment": "Môi trường", "Base URL": "Base URL", "Verdict": "Kết luận",
    "Reason": "Lý do", "Config file:": "File cấu hình:",
    "default": "mặc định", "ALLOWED": "CHO PHÉP", "BLOCKED": "BỊ CHẶN",
    # -- environments pane --
    "Make default": "Đặt làm mặc định",
    "No environments configured yet.": "Chưa cấu hình môi trường nào.",
    "Named target URLs. Only the path/method/body of a pasted PoC survive transpiling, "
    "so whichever base URL is picked here is what actually gets called.":
        "Các URL mục tiêu có tên. Chỉ path/method/body của PoC dán vào còn giữ lại sau "
        "khi transpile, nên base URL chọn ở đây chính là URL thật sự được gọi.",
    "Name": "Tên",
    "make default": "đặt làm mặc định", "authorize its host": "cấp phép host này",
    "Save": "Lưu",
    "<b>Authorize its host</b> adds the hostname to <b>Scope &rarr; approved hosts</b> "
    "in the same step. Leave it off for a target the engagement does not actually cover "
    "— the URL is then saved but every request to it stays blocked, which is the safe "
    "direction to fail in.":
        "<b>Cấp phép host này</b> sẽ thêm hostname vào <b>Scope &rarr; approved hosts</b> "
        "cùng lúc. Bỏ chọn nếu mục tiêu không thực sự nằm trong phạm vi engagement — URL "
        "vẫn được lưu nhưng mọi request đến đó vẫn bị chặn, đây là hướng an toàn khi lỗi.",
    # -- scope pane --
    "The authorization boundary. Every outbound request is checked against this "
    "before it is sent, and the hostname must appear in <b>approved hosts</b> exactly "
    "— there are no wildcards, because a wildcard in a pentest authorization list is "
    "how an unauthorized host gets tested by accident.":
        "Ranh giới cấp phép. Mọi request gửi đi đều được kiểm tra với danh sách này trước "
        "khi gửi, và hostname phải khớp chính xác trong <b>approved hosts</b> — không có "
        "wildcard, vì wildcard trong danh sách cấp phép pentest chính là cách một host "
        "không được phép bị test nhầm.",
    "Approved hosts — one per line": "Host được cấp phép — mỗi dòng một host",
    "Blocked hosts — one per line (always wins)": "Host bị chặn — mỗi dòng một host (luôn ưu tiên)",
    "Allow private / loopback ranges": "Cho phép dải IP nội bộ / loopback",
    "Off by default. When off, a host that <i>resolves</i> to 127.0.0.0/8, 10/8, "
    "172.16/12, 192.168/16 or 169.254/16 (cloud metadata) is refused even if its name "
    "is on the approved list — that check is what stops a DNS-based SSRF from reaching "
    "an internal service. Turn it on only for a local lab target.":
        "Mặc định tắt. Khi tắt, một host mà DNS <i>trả về</i> 127.0.0.0/8, 10/8, "
        "172.16/12, 192.168/16 hoặc 169.254/16 (cloud metadata) sẽ bị từ chối dù tên nó "
        "có trong danh sách cấp phép — kiểm tra này ngăn SSRF qua DNS chạm tới dịch vụ "
        "nội bộ. Chỉ bật khi mục tiêu là lab nội bộ.",
    "Save scope": "Lưu phạm vi",
    "Hostnames only — no scheme, no port, no path. A port is not part of the check "
    "(<code>api.example.com:8443</code> is authorized by <code>api.example.com</code>), "
    "and DNS is resolved and the resulting IP re-checked on every request, so a name "
    "that resolves somewhere new is caught at send time.":
        "Chỉ hostname — không scheme, không port, không path. Port không nằm trong kiểm "
        "tra (<code>api.example.com:8443</code> được cấp phép bởi <code>api.example.com</code>), "
        "và DNS được resolve rồi IP kết quả được kiểm tra lại mỗi request, nên một tên miền "
        "trỏ đến nơi mới sẽ bị phát hiện ngay lúc gửi.",
    # -- personas pane --
    "attacker": "kẻ tấn công", "victim": "nạn nhân",
    "Role label": "Nhãn vai trò",
    "Owned object ids — key=value per line": "ID object sở hữu — mỗi dòng key=value",
    "Auth headers — Header: value per line": "Auth headers — mỗi dòng Header: value",
    "Secret markers — one per line": "Dấu hiệu bí mật — mỗi dòng một dấu hiệu",
    "Scoping headers to strip on privilege-escalation tests — one per line":
        "Header scoping cần loại bỏ khi test leo thang đặc quyền — mỗi dòng một header",
    "Save {name}": "Lưu {name}",
    "No personas defined yet — add one below.": "Chưa có persona nào — thêm một cái bên dưới.",
    "not defined!": "chưa định nghĩa!", "no personas defined": "chưa có persona nào",
    'Test identities and their credentials. You cannot test broken object-level '
    'authorization with one identity: BOLA means "A reaches B\'s object", which needs '
    'two real accounts plus knowledge of what each legitimately owns. Tests reference '
    'personas <i>by name</i>, so a token never lands in a test case, an export or a report.':
        'Danh tính test và thông tin xác thực của chúng. Không thể test broken '
        'object-level authorization với một danh tính duy nhất: BOLA nghĩa là "A chạm '
        'được object của B", cần hai tài khoản thật cộng với biết rõ mỗi bên sở hữu gì. '
        'Test tham chiếu persona <i>bằng tên</i>, nên token không bao giờ xuất hiện trong '
        'test case, file export hay báo cáo.',
    "Attacker persona": "Persona kẻ tấn công", "Victim persona": "Persona nạn nhân",
    "Save roles": "Lưu vai trò",
    "The attacker sends the requests; generated BOLA cases aim it at ids the victim "
    "owns. Point these at two <i>different</i> personas or the results are "
    "inconclusive by construction.":
        "Kẻ tấn công là bên gửi request; các case BOLA được tạo sẽ nhắm vào id mà nạn "
        "nhân sở hữu. Chọn hai persona <i>khác nhau</i>, nếu không kết quả sẽ luôn chưa "
        "rõ ràng do bản chất thiết kế.",
    "Defined personas": "Persona đã định nghĩa", "Add a persona": "Thêm persona",
    "Add persona": "Thêm persona",
    "Use dedicated test accounts. Credentials are written to the engagement config in "
    "plain text and every response is passed through secret redaction before it reaches "
    "a report — but a real user's token does not belong in either.":
        "Dùng tài khoản test riêng. Thông tin xác thực được ghi vào config engagement ở "
        "dạng plain text, và mọi phản hồi đều qua bước che bí mật trước khi vào báo cáo "
        "— nhưng token của một người dùng thật không nên xuất hiện ở cả hai nơi đó.",
    # -- runner pane --
    'Hard caps the trusted runner applies to every outbound request. Blank means '
    '"use the <code>.env</code> value" shown as the placeholder; a value here '
    'overrides it for this engagement only, with no restart.':
        'Giới hạn cứng mà trusted runner áp dụng cho mọi request gửi đi. Để trống nghĩa '
        'là "dùng giá trị <code>.env</code>" hiển thị làm placeholder; điền giá trị ở '
        'đây sẽ ghi đè chỉ cho engagement này, không cần restart.',
    "Request timeout (s)": "Timeout request (giây)",
    "Raise it for a slow staging host.": "Tăng lên nếu host staging phản hồi chậm.",
    "Max requests per test": "Số request tối đa mỗi test",
    "Caps a single test's fan-out, race windows included.":
        "Giới hạn số request một test có thể gửi, kể cả trong race window.",
    "Max response bytes": "Số byte phản hồi tối đa",
    "Body larger than this is truncated before storage.":
        "Body lớn hơn mức này sẽ bị cắt bớt trước khi lưu.",
    "Save limits": "Lưu giới hạn", "Reset to .env defaults": "Khôi phục mặc định .env",
    "The runner never auto-follows a redirect: a 302 to an internal host is the same "
    "SSRF wearing a hat, and blindly chasing it would let the HTTP client re-resolve DNS "
    "outside the scope gate. A 3xx response is captured and evaluated exactly as received "
    "— there is no redirect setting to tune here.":
        "Runner không bao giờ tự động theo redirect: một 302 trỏ vào host nội bộ cũng "
        "chính là SSRF đội lốt, và đi theo nó một cách mù quáng sẽ để HTTP client "
        "resolve DNS lại ngoài tầm kiểm soát của scope gate. Response 3xx được ghi nhận "
        "và đánh giá đúng như nhận được — không có tuỳ chọn redirect nào để chỉnh ở đây.",
    # -- mcp pane --
    "LIVE": "TRỰC TIẾP", "MOCK": "GIẢ LẬP", "Serves:": "Phục vụ:",
    "SET": "ĐÃ ĐẶT", "NOT SET": "CHƯA ĐẶT",
    "External MCP connectors this platform talks to. Credentials live in <code>.env</code> "
    "only — never in <code>engagement.json</code> or a report. <b>Reconnect</b> re-reads "
    "<code>.env</code> and rebinds the client in place, which is all a restart would have "
    "done anyway — useful right after refreshing a short-lived OAuth token.":
        "Các kết nối MCP bên ngoài mà nền tảng này giao tiếp. Thông tin xác thực chỉ nằm "
        "trong <code>.env</code> — không bao giờ trong <code>engagement.json</code> hay "
        "báo cáo. <b>Reconnect</b> đọc lại <code>.env</code> và gắn lại client tại chỗ, "
        "đúng bằng những gì một lần restart sẽ làm — hữu ích ngay sau khi làm mới token "
        "OAuth ngắn hạn.",
    "Reconnect": "Kết nối lại",
    "Environment variable": "Biến môi trường", "Purpose": "Mục đích",
    "To refresh an expired token: authorize once with "
    "<code>npx -y mcp-remote https://mcp.atlassian.com/v1/mcp</code> (opens the Atlassian "
    "OAuth login in your browser — only needed again once the refresh token itself is "
    "revoked or expires), then run <code>npm run jira:token</code> to pull the new token "
    "into <code>.env</code>, then click <b>Reconnect</b> above.":
        "Để làm mới token đã hết hạn: cấp phép một lần với "
        "<code>npx -y mcp-remote https://mcp.atlassian.com/v1/mcp</code> (mở màn hình đăng "
        "nhập OAuth của Atlassian trên trình duyệt — chỉ cần lặp lại khi refresh token bị "
        "thu hồi hoặc hết hạn), sau đó chạy <code>npm run jira:token</code> để lấy token "
        "mới vào <code>.env</code>, rồi bấm <b>Kết nối lại</b> ở trên.",
    "Other connectors": "Kết nối khác", "NOT CONFIGURED": "CHƯA CẤU HÌNH",
    "No MCP integration is wired up for this platform — there is nothing here yet to "
    "connect or reconnect. (Separately, a completed assessment can already export a "
    "Postman collection from its report page — a one-way file export, unrelated to this "
    "connector list.)":
        "Chưa có tích hợp MCP nào cho nền tảng này — chưa có gì để kết nối hay kết nối "
        "lại ở đây. (Tách biệt với việc này, một assessment đã hoàn tất có thể export "
        "bộ sưu tập Postman từ trang report — một file export một chiều, không liên quan "
        "đến danh sách kết nối này.)",
    # -- runtime pane --
    "Read-only. These come from the process environment (<code>.env</code>), are read "
    "at startup, and need a server restart to change — so they are shown here rather "
    "than made editable, which would offer a save button that quietly does nothing "
    "until the next boot.":
        "Chỉ đọc. Các giá trị này đến từ biến môi trường tiến trình (<code>.env</code>), "
        "được đọc lúc khởi động, và cần restart server để thay đổi — nên chỉ hiển thị ở "
        "đây thay vì cho sửa, vì nút lưu sẽ âm thầm không có tác dụng gì cho tới lần "
        "khởi động sau.",
    "Setting": "Cấu hình", "Current": "Giá trị hiện tại",
    "Secrets are never echoed here — only whether one is present. Keep tokens in "
    "<code>.env</code>, never in <code>engagement.json</code>.":
        "Bí mật không bao giờ hiển thị ở đây — chỉ báo có tồn tại hay không. Giữ token "
        "trong <code>.env</code>, không bao giờ trong <code>engagement.json</code>.",
})
