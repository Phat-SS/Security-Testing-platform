"""The regression diff between two assessments, and the Jira comment preview.
"""

from __future__ import annotations



from .shell import _e, page
from app.core.i18n import tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

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
""", active="assessment")


def comment_preview_page(aid: str, issue_key: str, preview: str) -> str:
    return page(f"Jira comment — {issue_key}", f"""
<h1>Preview Jira comment</h1>
<p class="sub">Nothing is posted until you confirm.</p>
<div class="card pad" style="margin-bottom:18px"><pre class="mono" style="white-space:pre-wrap;margin:0">{_e(preview)}</pre></div>
<form method="post" action="/assessment/{_e(aid)}/comment">
<button class="btn">Confirm &amp; post to {_e(issue_key)}</button>
<a class="btn sec" href="/assessment/{_e(aid)}">Cancel</a>
</form>
""", active="assessment")


# -- Configuration -----------------------------------------------------------
#
# One page holding every setting a run depends on, because the failure mode it
# replaces was: run -> every row BLOCKED -> no indication of which file, which
# key, or which of several unrelated settings caused it. The panes are ordered
# by how a tester hits them (readiness first, then target, scope, identities),
# and the readiness pane names the exact setting behind each failure with a
# link straight to the pane that fixes it.
