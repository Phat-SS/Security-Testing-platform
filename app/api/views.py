"""Server-rendered HTML views (dependency-free, theme-aware).

Kept separate from routing. Everything shown here has passed secret redaction
upstream (executions/findings) or is non-secret metadata.
"""

from __future__ import annotations

import html

from app.database.models import Assessment
from app.schemas.testcase import TestCase

_SEV = {"CRITICAL": "#b4232a", "HIGH": "#c8500f", "MEDIUM": "#b8860b",
        "LOW": "#2f855a", "INFO": "#4a5568"}
_STATE = {"COVERED": "#2f855a", "PARTIAL": "#b8860b", "MISSING": "#b4232a",
          "NOT_APPLICABLE": "#718096"}
_APPROVAL = {"APPROVED": "#2f855a", "PENDING": "#b8860b", "REJECTED": "#b4232a",
             "DISABLED": "#718096"}


def _e(v) -> str:
    return html.escape(str(v))


_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<style>
:root{{--bg:#fff;--fg:#1a202c;--muted:#4a5568;--card:#f7fafc;--border:#e2e8f0;--accent:#2b6cb0;--code:#f1f5f9;}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1419;--fg:#e2e8f0;--muted:#a0aec0;--card:#1a212b;--border:#2d3748;--accent:#63b3ed;--code:#161d27;}}}}
*{{box-sizing:border-box;}}
body{{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:var(--bg);color:var(--fg);}}
.wrap{{max-width:1000px;margin:0 auto;padding:24px 20px 80px;}}
a{{color:var(--accent);}} h1{{font-size:22px;margin:0 0 4px;}}
h2{{font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px;}}
.sub{{color:var(--muted);margin:0 0 16px;}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin:10px 0;}}
.btn{{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:14px;cursor:pointer;text-decoration:none;display:inline-block;}}
.btn.sec{{background:transparent;color:var(--accent);border:1px solid var(--accent);}}
input,textarea{{background:var(--bg);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:8px;font:inherit;width:100%;}}
table{{width:100%;border-collapse:collapse;font-size:13.5px;}} .tblwrap{{overflow-x:auto;}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--border);vertical-align:top;}}
th{{color:var(--muted);}} code{{background:var(--code);padding:1px 5px;border-radius:4px;}}
.pill{{color:#fff;border-radius:999px;padding:2px 9px;font-size:11.5px;font-weight:600;}}
.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}}
.bar{{background:var(--border);border-radius:6px;height:9px;width:120px;overflow:hidden;}}
.fill{{height:100%;}} .muted{{color:var(--muted);}} .mono{{font-family:ui-monospace,Consolas,monospace;}}
</style></head><body><div class="wrap">
<div class="row" style="justify-content:space-between">
<h1>🛡️ API Security Testing Platform</h1><a href="/" class="muted">Dashboard</a></div>
"""

_FOOT = "</div></body></html>"


def page(title: str, body: str) -> str:
    return _HEAD.format(title=_e(title)) + body + _FOOT


def dashboard(
    assessments: list[Assessment],
    engagement_target: str,
    ai_on: bool,
    jira_mode: str = "mock Jira (offline)",
    available_keys: list[str] | None = None,
    warning: str = "",
) -> str:
    rows = ""
    for a in assessments:
        rows += (
            f"<tr><td><a href='/assessment/{_e(a.id)}'>{_e(a.issue_key)}</a></td>"
            f"<td>{_e(a.status)}</td><td class='muted mono'>{_e(a.id)}</td></tr>"
        )
    rows = rows or "<tr><td colspan='3' class='muted'>No assessments yet.</td></tr>"
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

    warn = (f"<div class='card' style='border-color:#c8500f'>⚠ {_e(warning)}</div>"
            if warning else "")

    return page("Dashboard", f"""
<p class="sub">Analyzer: <b>{ai}</b> · Jira: <b>{_e(jira_mode)}</b> · Engagement target: {target}</p>
{warn}
<div class="card">
<h2 style="margin-top:0;border:0">Import a Jira issue</h2>
<form method="post" action="/import" class="row">
<input name="issue_key" id="issue_key" placeholder="{placeholder}" style="max-width:220px" required>
<button class="btn">Import &amp; Analyze</button>
<span class="muted">{hint}</span>
</form></div>
<h2>Recent assessments</h2>
<div class="tblwrap"><table>
<tr><th>Issue</th><th>Status</th><th>Assessment ID</th></tr>{rows}</table></div>
<script>
document.querySelectorAll('.keyfill').forEach(function (a) {{
  a.addEventListener('click', function (e) {{
    e.preventDefault();
    document.getElementById('issue_key').value = a.textContent.trim();
  }});
}});
</script>
""")


def import_error_page(headline: str, hint_html: str) -> str:
    """Import failure as a readable page. `headline` may contain user input and
    is escaped; `hint_html` is markup we build ourselves."""
    return page("Import failed", f"""
<h1 style="font-size:19px">Import failed</h1>
<div class="card" style="border-color:#b4232a">
<p style="margin:0 0 8px"><b>{_e(headline)}</b></p>
<p class="muted" style="margin:0">{hint_html}</p>
</div>
<p><a href="/" class="btn sec">← Back to dashboard</a></p>
""")


def assessment_page(
    assessment: Assessment,
    analysis: dict,
    coverage: list[dict],
    tests: list[TestCase],
    n_executions: int,
    n_findings: int,
    engagement_target: str,
    flash: str = "",
) -> str:
    aid = assessment.id
    flash_html = f"<div class='card' style='border-color:var(--accent)'>{_e(flash)}</div>" if flash else ""

    # analysis summary
    endpoints = analysis.get("endpoints", []) if analysis else []
    ep_html = "".join(
        f"<tr><td class='mono'>{_e(e['method'])} {_e(e['path'])}</td>"
        f"<td>{_e(', '.join(e.get('object_id_params', [])) or '—')}</td>"
        f"<td>{'yes' if e.get('auth_required') else 'no'}</td></tr>"
        for e in endpoints
    ) or "<tr><td colspan='3' class='muted'>No endpoints extracted.</td></tr>"

    cov_html = "".join(
        f"<tr><td><b>{_e(r['category'])}</b></td><td>{_e(r['state'])}</td>"
        f"<td><div class='bar'><div class='fill' style='width:{r.get('pct',0) if r['state']!='NOT_APPLICABLE' else 0}%;"
        f"background:{_STATE.get(r['state'],'#718096')}'></div></div></td>"
        f"<td class='muted'>{_e(r.get('existing_tests',0))} PoC / {_e(r.get('generated_tests',0))} gen</td></tr>"
        for r in (coverage or [])
    ) or "<tr><td colspan='4' class='muted'>Run design to compute coverage.</td></tr>"

    # test plan with approval checkboxes
    test_rows = ""
    for t in tests:
        sev_c = _SEV.get(t.severity.value, "#718096")
        appr_c = _APPROVAL.get(t.approval_status.value, "#718096")
        checked = "checked" if t.approval_status.value == "APPROVED" else ""
        dest = "<span class='pill' style='background:#b4232a'>DESTRUCTIVE</span>" if t.is_destructive else ""
        test_rows += (
            f"<tr><td><input type='checkbox' name='test_ids' value='{_e(t.test_id)}' {checked}></td>"
            f"<td><b>{_e(t.test_id)}</b><br><span class='muted'>{_e(t.title)}</span> {dest}</td>"
            f"<td>{_e(t.owasp_category.value)}</td>"
            f"<td><span class='pill' style='background:{sev_c}'>{_e(t.severity.value)}</span></td>"
            f"<td><span class='pill' style='background:{appr_c}'>{_e(t.approval_status.value)}</span></td>"
            f"<td class='mono muted'>{_e(t.attack_mutation.kind)}</td></tr>"
        )
    test_rows = test_rows or "<tr><td colspan='6' class='muted'>No tests yet — run Design.</td></tr>"

    can_execute = bool(engagement_target)
    exec_note = "" if can_execute else "<span class='muted'>· set ENGAGEMENT_CONFIG to enable execution</span>"

    return page(f"Assessment {assessment.issue_key}", f"""
{flash_html}
<h1 style="margin-top:8px">{_e(assessment.issue_key)} <span class="muted" style="font-size:14px">{_e(assessment.status)}</span></h1>
<p class="sub mono">{_e(aid)}</p>
<p><b>{_e(analysis.get('business_summary','') if analysis else '')}</b><br>
<span class="muted">Sensitive operation: {analysis.get('sensitive_operation') if analysis else '—'} ·
Executions: {n_executions} · Findings: {n_findings}</span></p>

<h2>Endpoints</h2>
<div class="tblwrap"><table><tr><th>Endpoint</th><th>Object IDs</th><th>Auth</th></tr>{ep_html}</table></div>

<h2>OWASP Coverage</h2>
<div class="tblwrap"><table><tr><th>Category</th><th>State</th><th>Coverage</th><th></th></tr>{cov_html}</table></div>

<h2>Design tests</h2>
<div class="card"><form method="post" action="/assessment/{_e(aid)}/design">
<p class="muted" style="margin-top:0">Optional: paste an existing Python PoC or a Postman collection — parsed statically (never executed) and transpiled into scoped tests.</p>
<textarea name="poc_python" rows="3" placeholder="Python PoC — import requests&#10;requests.get(BASE + '/customers/2002', ...)"></textarea>
<textarea name="poc_postman" rows="2" style="margin-top:8px" placeholder="Postman collection JSON (v2.1)"></textarea>
<textarea name="burp_xml" rows="2" style="margin-top:8px" placeholder="Burp Suite XML export"></textarea>
<textarea name="jmeter_xml" rows="2" style="margin-top:8px" placeholder="JMeter .jmx test plan"></textarea>
<div style="margin-top:8px"><button class="btn">Generate test plan</button></div>
</form></div>

<h2>Security Test Plan &amp; Approval</h2>
<form method="post" action="/assessment/{_e(aid)}/approve">
<div class="tblwrap"><table>
<tr><th></th><th>Test</th><th>OWASP</th><th>Severity</th><th>Approval</th><th>Mutation</th></tr>
{test_rows}</table></div>
<div class="row" style="margin-top:10px">
<button class="btn">Approve selected</button>
</div></form>

<h2>Execute</h2>
<div class="card"><div class="row">
<form method="post" action="/assessment/{_e(aid)}/execute">
<button class="btn" {'disabled' if not can_execute else ''}>Run approved tests</button>
</form>
<span class="muted">Only APPROVED, non-destructive tests run, against <code>{_e(engagement_target or '—')}</code>, after scope validation. {exec_note}</span>
</div></div>

<h2>Results</h2>
<div class="row">
<a class="btn sec" href="/assessment/{_e(aid)}/report" target="_blank">HTML report</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.pdf">PDF</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.xlsx">XLSX</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.json">JSON</a>
<a class="btn sec" href="/assessment/{_e(aid)}/export.postman">Postman (Newman)</a>
<a class="btn sec" href="/assessment/{_e(aid)}/regression">Regression diff</a>
<a class="btn sec" href="/assessment/{_e(aid)}/comment">Preview Jira comment</a>
</div>
""")


def regression_page(aid: str, issue_key: str, prev_id: str | None, diff, comment: str) -> str:
    s = diff.summary()
    banner_c = "#b4232a" if s["regressed"] else "#2f855a"
    banner = "⚠️ REGRESSION — new findings since last run" if s["regressed"] else (
        "✅ No new findings since last run")
    baseline = (f"vs previous run <span class='mono'>{_e(prev_id)}</span>" if prev_id
                else "no previous executed run — showing current findings as baseline")

    def _rows(items, color):
        return "".join(
            f"<tr><td><b>{_e(f.finding_id)}</b></td><td>{_e(f.title)}</td>"
            f"<td>{_e(f.owasp_category.value)}</td>"
            f"<td><span class='pill' style='background:{color}'>{_e(f.severity.value)}</span></td>"
            f"<td class='mono'>{_e(f.endpoint)}</td></tr>"
            for f in items
        ) or "<tr><td colspan='5' class='muted'>none</td></tr>"

    return page(f"Regression — {issue_key}", f"""
<h1>Regression diff — {_e(issue_key)}</h1>
<p class="sub">{baseline}</p>
<div class="card" style="border-color:{banner_c}"><b style="color:{banner_c}">{banner}</b>
<br><span class="muted">new: {s['new']} · fixed: {s['fixed']} · still open: {s['persisting']}</span></div>
<h2>New (regressions)</h2>
<div class="tblwrap"><table><tr><th>ID</th><th>Title</th><th>OWASP</th><th>Sev</th><th>Endpoint</th></tr>
{_rows(diff.new, '#b4232a')}</table></div>
<h2>Fixed since last run</h2>
<div class="tblwrap"><table><tr><th>ID</th><th>Title</th><th>OWASP</th><th>Sev</th><th>Endpoint</th></tr>
{_rows(diff.fixed, '#2f855a')}</table></div>
<h2>Still open</h2>
<div class="tblwrap"><table><tr><th>ID</th><th>Title</th><th>OWASP</th><th>Sev</th><th>Endpoint</th></tr>
{_rows(diff.persisting, '#c8500f')}</table></div>
<h2>Jira-ready note</h2>
<div class="card"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(comment)}</pre></div>
<a class="btn sec" href="/assessment/{_e(aid)}">Back to assessment</a>
""")


def comment_preview_page(aid: str, issue_key: str, preview: str) -> str:
    return page(f"Jira comment — {issue_key}", f"""
<h1>Preview Jira comment</h1>
<p class="sub">Nothing is posted until you confirm.</p>
<div class="card"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(preview)}</pre></div>
<form method="post" action="/assessment/{_e(aid)}/comment">
<button class="btn">Confirm &amp; post to {_e(issue_key)}</button>
<a class="btn sec" href="/assessment/{_e(aid)}">Cancel</a>
</form>
""")
