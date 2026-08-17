"""Server-rendered HTML views (dependency-free, theme-aware).

Kept separate from routing. Everything shown here has passed secret redaction
upstream (executions/findings) or is non-secret metadata.
"""

from __future__ import annotations

import html
import json

from collections import Counter

from app.database.models import Assessment
from app.schemas.testcase import TestCase

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.
_SEV_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}
_STATE_CLASS = {"COVERED": "low", "PARTIAL": "med", "MISSING": "crit", "NOT_APPLICABLE": "info"}
_APPROVAL_CLASS = {"APPROVED": "low", "PENDING": "med", "REJECTED": "crit", "DISABLED": "info"}
_STATUS_PILL = {
    "CREATED": ("Imported", "info"),
    "ANALYZED": ("Analyzed", "med"),
    "EXECUTED": ("Executed", "low"),
}


def _e(v) -> str:
    return html.escape(str(v))


# Set once at startup from main.py's State.__init__ so the topbar knows
# whether to show the Log in / Log out links. Multi-user auth is off by
# default (single-user local-admin) — hiding these when it's off avoids
# showing a login form that has no effect.
_AUTH_ENABLED = False


def configure(auth_enabled: bool) -> None:
    global _AUTH_ENABLED
    _AUTH_ENABLED = auth_enabled


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
.a-card .del{position:relative;z-index:1;float:right;margin-top:10px;background:none;border:0;
  color:var(--faint);font-size:11px;cursor:pointer;padding:2px;}

/* assessment workflow */
.workflow{display:grid;grid-template-columns:190px 1fr;gap:28px;align-items:start;}
@media (max-width:820px){.workflow{grid-template-columns:1fr;}}
.stepper{position:sticky;top:20px;display:flex;flex-direction:column;}
.step{display:flex;gap:10px;padding:8px 0;}
.step .rail{display:flex;flex-direction:column;align-items:center;width:16px;flex:none;}
.step .node{width:9px;height:9px;border-radius:50%;border:2px solid var(--border-strong);
  background:var(--surface);flex:none;margin-top:3px;}
.step .line{width:1.5px;flex:1;background:var(--border);min-height:14px;}
.step:last-child .line{display:none;}
.step.done .node{background:var(--accent);border-color:var(--accent);}
.step.done .line{background:var(--accent-border);}
.step.current .node{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);}
.step .label{font-size:12.5px;font-weight:600;color:var(--muted);}
.step.current .label,.step.done .label{color:var(--fg);}
.step .detail{font-size:11px;color:var(--faint);margin-top:1px;}

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
"""

_FOOT = "</div></body></html>"


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
<a href="/config/environments" class="{"active" if active == "environments" else ""}">Environments</a>
</nav>
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


def page(title: str, body: str, active: str = "") -> str:
    head = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{_e(title)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
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
) -> str:
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""
    warn_html = f"<div class='card pad warn'>&#9888; {_e(warning)}</div>" if warning else ""

    counts = Counter(a.status for a in assessments)
    summary = f"""<div class="summary-row">
<div class="cell"><div class="num">{len(assessments)}</div><div class="lbl">Assessments</div></div>
<div class="cell"><div class="num">{counts.get('CREATED', 0)}</div><div class="lbl">Imported</div></div>
<div class="cell"><div class="num">{counts.get('ANALYZED', 0)}</div><div class="lbl">Designed</div></div>
<div class="cell"><div class="num">{counts.get('EXECUTED', 0)}</div><div class="lbl">Executed</div></div>
</div>"""

    cards = ""
    for a in assessments:
        label, cls = _STATUS_PILL.get(a.status, (a.status.title(), "info"))
        cards += (
            f"<div class='a-card'>"
            f"<a class='stretch' href='/assessment/{_e(a.id)}' aria-label='Open {_e(a.issue_key)}'></a>"
            f"<div class='top'><div><div class='issue'>{_e(a.issue_key)}</div>"
            f"<div class='id mono'>{_e(a.id)}</div></div>"
            f"<span class='pill {cls}'>{_e(label)}</span></div>"
            f"<form method='post' action='/assessment/{_e(a.id)}/delete' class='delete-form' style='margin:0'>"
            f"<button type='submit' class='del'>Delete</button></form></div>"
        )
    cards = cards or "<p class='muted'>No assessments yet — import a Jira issue above.</p>"

    target = _e(engagement_target) if engagement_target else "<span class='muted'>not configured — execution disabled</span>"
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
<form method="post" action="/import" class="row">
<input name="issue_key" id="issue_key" placeholder="{placeholder}" style="max-width:220px" required>
<button class="btn">Import &amp; Analyze</button>
<span class="muted" style="font-size:13px">{hint}</span>
</form></div>
{summary}
<h2 class="section">Recent assessments</h2>
<div class="grid-cards">{cards}</div>
<script>
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
</script>
""", active="dashboard")


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


def environments_page(environments: dict[str, str], active: str, flash: str = "") -> str:
    flash_html = f"<div class='card pad flash'>{_e(flash)}</div>" if flash else ""
    rows = ""
    for name, url in environments.items():
        badge = " <span class='pill low'>default</span>" if name == active else ""
        rows += (
            f"<tr><td><b>{_e(name)}</b>{badge}</td><td class='mono'>{_e(url)}</td>"
            f"<td><form method='post' action='/config/environments/{_e(name)}/delete' style='margin:0'>"
            f"<button class='btn sec' style='padding:4px 10px'>Delete</button></form></td></tr>"
        )
    rows = rows or "<tr><td colspan='3' class='muted'>No environments configured yet.</td></tr>"
    return page("Environments", f"""
<h1 style="font-size:19px">Environments</h1>
<p class="sub">Named target URLs. Pick one from the dropdown next to "Run approved tests" —
only the path/method/body of a pasted PoC survive transpiling, so whichever URL you pick here
is what actually gets called.</p>
{flash_html}
<div class="card" style="margin-bottom:18px"><div class="tblwrap"><table>
<tr><th>Name</th><th>Base URL</th><th></th></tr>{rows}</table></div></div>
<div class="card pad">
<form method="post" action="/config/environments" class="row">
<input name="name" placeholder="staging" style="max-width:160px" required>
<input name="url" placeholder="https://staging.company.com" style="flex:1;min-width:240px" required>
<label class="muted" style="display:flex;align-items:center;gap:4px">
<input type="checkbox" name="make_active" value="true" style="width:auto"> make default</label>
<button class="btn">Save</button>
</form>
<p class="muted" style="margin:10px 0 0">This page only manages the URL. Scope
(<code>allowed_hosts</code>) and personas/credentials are shared across all environments and
still edited directly in <code>config/engagement.json</code>. If a run comes back all
<code>BLOCKED</code>, that host likely isn't in <code>scope.allowed_hosts</code> yet.</p>
</div>
<p style="margin-top:18px"><a href="/" class="btn sec">← Back to dashboard</a></p>
""", active="environments")


def _workflow_stepper(
    issue_key: str, n_endpoints: int, n_tests: int, n_approved: int,
    n_executions: int, n_findings: int,
) -> str:
    stages = [
        ("Import", True, _e(issue_key)),
        ("Analyze", n_endpoints > 0, f"{n_endpoints} endpoint(s) extracted" if n_endpoints else "no analysis yet"),
        ("Design", n_tests > 0, f"{n_tests} test(s) generated" if n_tests else "not designed yet"),
        ("Approve", n_approved > 0,
         f"{n_approved} of {n_tests} approved" if n_tests else "no tests to approve"),
        ("Execute", n_executions > 0,
         f"{n_executions} executed, {n_findings} finding(s)" if n_executions else "not yet run"),
        ("Report", n_executions > 0, "ready to view" if n_executions > 0 else "—"),
    ]
    current_idx = next((i for i, s in enumerate(stages) if not s[1]), len(stages) - 1)

    steps = ""
    for i, (label, done, detail) in enumerate(stages):
        cls = "done" if done and i < current_idx else ("current" if i == current_idx else "")
        steps += (
            f"<div class='step {cls}'><div class='rail'><div class='node'></div><div class='line'></div></div>"
            f"<div><div class='label'>{label}</div><div class='detail'>{detail}</div></div></div>"
        )
    return f"<nav class='stepper' aria-label='Assessment workflow'>{steps}</nav>"


def assessment_page(
    assessment: Assessment,
    analysis: dict,
    coverage: list[dict],
    tests: list[TestCase],
    n_executions: int,
    n_findings: int,
    environments: dict[str, str] | None = None,
    active_environment: str = "",
    flash: str = "",
    ticket_url: str = "",
) -> str:
    aid = assessment.id
    report_href = f"/assessment/{_e(aid)}/report"
    if flash.startswith("Executed "):
        # Land here right after a run: say what happened, then move straight to
        # the report — the natural next step — while leaving an escape hatch in
        # case the redirect is slow or the user wants to stay.
        flash_html = f"""<div class='card pad flash exec-flash' id='exec-flash'>
<b>{_e(flash)}</b> — opening the report…
<a href="{report_href}" class="btn sec">View report now</a>
</div>
<script>setTimeout(function () {{ window.location.href = {report_href!r}; }}, 1400);</script>"""
    elif flash == "Posted to Jira" and ticket_url and ticket_url.startswith(("http://", "https://")):
        # ticket_url is a client-supplied query parameter (it round-trips
        # through a redirect, not signed/verified) — html.escape() alone
        # does not block a javascript: href, so the scheme must be checked
        # before this ever becomes a clickable link.
        flash_html = f"""<div class='card pad flash exec-flash'>
<b>{_e(flash)}</b>
<a href="{_e(ticket_url)}" class="btn sec" target="_blank" rel="noopener">Open ticket ↗</a>
</div>"""
    elif flash:
        flash_html = f"<div class='card pad flash'>{_e(flash)}</div>"
    else:
        flash_html = ""

    # analysis summary
    endpoints = analysis.get("endpoints", []) if analysis else []
    ep_html = "".join(
        f"<tr><td class='mono'>{_e(e['method'])} {_e(e['path'])}</td>"
        f"<td>{_e(', '.join(e.get('object_id_params', [])) or '—')}</td>"
        f"<td>{'yes' if e.get('auth_required') else 'no'}</td></tr>"
        for e in endpoints
    ) or "<tr><td colspan='3' class='muted'>No endpoints extracted.</td></tr>"

    cov_html = "".join(
        f"<tr><td><b>{_e(r['category'])}</b></td>"
        f"<td><span class='pill {_STATE_CLASS.get(r['state'], 'info')}'>{_e(r['state'])}</span></td>"
        f"<td><div class='bar'><div class='fill' style='width:{r.get('pct', 0) if r['state'] != 'NOT_APPLICABLE' else 0}%;"
        f"background:var(--{_STATE_CLASS.get(r['state'], 'info')})'></div></div></td>"
        f"<td class='muted'>{_e(r.get('existing_tests', 0))} PoC / {_e(r.get('generated_tests', 0))} gen</td></tr>"
        for r in (coverage or [])
    ) or "<tr><td colspan='4' class='muted'>Run design to compute coverage.</td></tr>"

    # test plan with approval checkboxes
    test_rows = ""
    n_approved = 0
    n_destructive_approved = 0
    for t in tests:
        if t.approval_status.value == "APPROVED":
            n_approved += 1
            if t.is_destructive:
                n_destructive_approved += 1
        sev_c = _SEV_CLASS.get(t.severity.value, "info")
        appr_c = _APPROVAL_CLASS.get(t.approval_status.value, "info")
        checked = "checked" if t.approval_status.value == "APPROVED" else ""
        dest = "<span class='destr'>DESTRUCTIVE</span>" if t.is_destructive else ""
        test_rows += (
            f"<tr><td><input type='checkbox' name='test_ids' value='{_e(t.test_id)}' {checked}></td>"
            f"<td><b>{_e(t.test_id)}</b><br><span class='muted'>{_e(t.title)}</span> {dest}</td>"
            f"<td>{_e(t.owasp_category.value)}</td>"
            f"<td><span class='pill {sev_c}'>{_e(t.severity.value)}</span></td>"
            f"<td><span class='pill {appr_c}'>{_e(t.approval_status.value)}</span></td>"
            f"<td class='mono muted'>{_e(t.attack_mutation.kind)}</td>"
            f"<td><a class='btn sec' style='padding:4px 10px' "
            f"href='/assessment/{_e(aid)}/test/{_e(t.test_id)}'>View / Edit</a></td></tr>"
        )
    test_rows = test_rows or "<tr><td colspan='7' class='muted'>No tests yet — run Design.</td></tr>"

    environments = environments or {}
    can_execute = bool(environments)
    exec_note = (
        "" if can_execute else
        "<span class='muted'>· <a href='/config/environments'>add an environment</a> to enable execution</span>"
    )
    if environments:
        env_options = "".join(
            f"<option value='{_e(name)}' {'selected' if name == active_environment else ''}>"
            f"{_e(name)} — {_e(url)}</option>"
            for name, url in environments.items()
        )
        env_select = f"<select name='environment' style='max-width:280px;width:auto;display:inline-block'>{env_options}</select>"
    else:
        env_select = ""

    destructive_block = ""
    if can_execute and n_destructive_approved:
        # Deliberately separate from "Run approved tests" and off by default:
        # this sends real POST/PUT/PATCH/DELETE. A JS confirm() is one click to
        # blow through by habit, so this asks the tester to type the issue key
        # -- a real, if light, speed bump before mutating a live target.
        issue_key_js = repr(assessment.issue_key)
        destructive_block = f"""<div style="margin-top:14px;padding-top:14px;border-top:1px dashed var(--border-strong)">
<button type="button" class="btn sec danger" id="destructive-btn" onclick="confirmDestructive()">
Run {n_destructive_approved} destructive test(s) too</button>
<p class="muted" style="margin:8px 0 0">Sends real POST/PUT/PATCH/DELETE requests -- can create, modify, or
delete real data on the target. Requires typing the issue key to confirm.</p>
</div>
<script>
function confirmDestructive() {{
  var form = document.getElementById('execute-form');
  var sel = form.querySelector('select[name="environment"]');
  var target = sel ? sel.options[sel.selectedIndex].text : 'the configured target';
  var typed = prompt(
    'This sends real POST/PUT/PATCH/DELETE requests for {n_destructive_approved} destructive test(s) ' +
    'against ' + target + '. This can create, modify, or delete real data -- it is not reversible. ' +
    'Type ' + {issue_key_js} + ' to confirm.'
  );
  if (typed === null) return;
  if (typed.trim() !== {issue_key_js}) {{
    alert('Issue key did not match -- cancelled, nothing was run.');
    return;
  }}
  document.getElementById('include-destructive-flag').value = 'true';
  var btn = document.getElementById('destructive-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Running destructive tests...';
  form.submit();
}}
</script>"""


    stepper = _workflow_stepper(
        assessment.issue_key, len(endpoints), len(tests), n_approved, n_executions, n_findings,
    )

    detected_poc_source = (analysis.get("detected_poc_source") or "") if analysis else ""
    detected_poc_notice = ""
    if detected_poc_source:
        detected_poc_notice = (
            "<p class='muted' style='margin:0 0 10px'>"
            "\U0001F7E1 A PoC was found embedded in the Jira description and is pre-filled below "
            "— <b>review it</b>, then click Generate test plan to transpile it. Nothing runs "
            "automatically.</p>"
        )

    return page(f"Assessment {assessment.issue_key}", f"""
{flash_html}
<div class="topbar" style="margin-bottom:16px">
<div>
<h1>{_e(assessment.issue_key)} <span class="muted" style="font-size:14px">{_e(assessment.status)}</span></h1>
<p class="sub mono" style="margin:2px 0 0">{_e(aid)}</p>
</div>
<a href="/" class="btn ghost">← All assessments</a>
</div>
<p><b>{_e(analysis.get('business_summary', '') if analysis else '')}</b><br>
<span class="muted">Sensitive operation: {analysis.get('sensitive_operation') if analysis else '—'} ·
Executions: {n_executions} · Findings: {n_findings}</span></p>

<div class="workflow">
{stepper}
<div class="stage">

<h2 class="section">Endpoints</h2>
<div class="card" style="margin-bottom:22px"><div class="tblwrap"><table>
<tr><th>Endpoint</th><th>Object IDs</th><th>Auth</th></tr>{ep_html}</table></div></div>

<h2 class="section">OWASP Coverage</h2>
<div class="card" style="margin-bottom:22px"><div class="tblwrap"><table>
<tr><th>Category</th><th>State</th><th>Coverage</th><th></th></tr>{cov_html}</table></div></div>

<h2 class="section">Design tests — import a PoC</h2>
<div class="card" style="margin-bottom:22px">
<div class="tabbar">
<button class="active" data-tab="t-py-{_e(aid)}">Python PoC</button>
<button data-tab="t-pm-{_e(aid)}">Postman</button>
<button data-tab="t-burp-{_e(aid)}">Burp XML</button>
<button data-tab="t-jm-{_e(aid)}">JMeter</button>
</div>
<div class="pad" style="padding-top:12px">
<form method="post" action="/assessment/{_e(aid)}/design">
<p class="muted" style="margin:0 0 10px">Parsed statically — dangerous constructs are flagged and the PoC is never executed.</p>
{detected_poc_notice}
<div class="tabpane active" id="t-py-{_e(aid)}">
<label class="field"><span>Python PoC</span>
<textarea name="poc_python" rows="4" placeholder="import requests&#10;requests.get(BASE + '/customers/2002', ...)">{_e(detected_poc_source)}</textarea></label>
</div>
<div class="tabpane" id="t-pm-{_e(aid)}">
<label class="field"><span>Postman collection (v2.1) JSON</span>
<textarea name="poc_postman" rows="4" placeholder="Paste exported collection JSON"></textarea></label>
</div>
<div class="tabpane" id="t-burp-{_e(aid)}">
<label class="field"><span>Burp Suite XML export</span>
<textarea name="burp_xml" rows="4" placeholder="Paste raw-HTTP XML export"></textarea></label>
</div>
<div class="tabpane" id="t-jm-{_e(aid)}">
<label class="field"><span>JMeter .jmx test plan</span>
<textarea name="jmeter_xml" rows="4" placeholder="Paste .jmx XML"></textarea></label>
</div>
<div style="margin-top:12px"><button class="btn">Generate test plan</button></div>
</form>
</div>
</div>

<h2 class="section">Test plan &amp; approval</h2>
<div class="card" style="margin-bottom:22px">
<form method="post" action="/assessment/{_e(aid)}/approve">
<div class="tblwrap"><table>
<tr><th style="width:30px"><input type="checkbox" id="select-all-tests"></th><th>Test</th><th>OWASP</th>
<th>Severity</th><th>Approval</th><th>Mutation</th><th></th></tr>
{test_rows}</table></div>
<div class="pad" style="padding-top:12px;border-top:1px solid var(--border)">
<button class="btn">Approve selected</button>
</div></form>
</div>
<script>
document.getElementById('select-all-tests').addEventListener('change', function (e) {{
  document.querySelectorAll('input[name="test_ids"]').forEach(function (cb) {{
    cb.checked = e.target.checked;
  }});
}});
document.querySelectorAll('.tabbar').forEach(function (bar) {{
  bar.querySelectorAll('button').forEach(function (b) {{
    b.addEventListener('click', function () {{
      bar.querySelectorAll('button').forEach(function (x) {{ x.classList.remove('active'); }});
      bar.parentElement.querySelectorAll('.tabpane').forEach(function (x) {{ x.classList.remove('active'); }});
      b.classList.add('active');
      document.getElementById(b.dataset.tab).classList.add('active');
    }});
  }});
}});
</script>

<h2 class="section">Execute</h2>
<div class="card pad" style="margin-bottom:22px">
<div class="row" style="justify-content:space-between">
<form method="post" action="/assessment/{_e(aid)}/execute" class="row" id="execute-form">
{env_select}
<input type="hidden" name="include_destructive" id="include-destructive-flag" value="false">
<button class="btn" id="execute-btn" {'disabled' if not can_execute else ''}>Run approved tests</button>
</form>
<span class="muted">Only APPROVED, non-destructive tests run, after scope validation. {exec_note}</span>
</div>
{destructive_block}
</div>
<script>
(function () {{
  var form = document.getElementById('execute-form');
  if (!form) return;
  form.addEventListener('submit', function () {{
    var btn = document.getElementById('execute-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Running tests…';
  }});
}})();
</script>

<h2 class="section">Results</h2>
<div class="card pad">
<div class="glabel">View</div>
<div class="actionrow">
<a class="btn sec" href="/assessment/{_e(aid)}/report" target="_blank">HTML report</a>
<a class="btn sec" href="/assessment/{_e(aid)}/regression">Regression diff</a>
<a class="btn sec" href="/assessment/{_e(aid)}/comment">Preview Jira comment</a>
</div>
<div class="glabel">Export</div>
<div class="actionrow">
<a class="btn sec" href="/assessment/{_e(aid)}/export.html">HTML</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.pdf">PDF</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.xlsx">XLSX</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.json">JSON</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.postman">Postman (Newman)</a>
</div>
</div>

</div>
</div>
""")


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


def regression_page(aid: str, issue_key: str, prev_id: str | None, diff, comment: str) -> str:
    s = diff.summary()
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
