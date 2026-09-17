"""The assessment list.
"""

from __future__ import annotations

import json

from collections import Counter
from urllib.parse import quote_plus

from app.api import ui
from app.api.ui import attr
from .shell import _STATUS_PILL, _e, appbar, page
from app.core.i18n import tt as _t
from app.database.models import Assessment

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def dashboard(
    assessments: list[Assessment],
    # Kept in the signature (main.py and the tests pass it positionally) but no
    # longer rendered here: the sidebar's engagement card is where the active
    # target lives now, on every screen rather than only the dashboard.
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
    total_matched: int | None = None,
    status_counts: dict[str, int] | None = None,
    totals: dict[str, int] | None = None,
) -> str:
    """The assessment list.

    `rows` carries the per-assessment counts (tests, approved, findings by
    severity) the cards show. Without them a card said only "Executed" — which is
    the one thing you already knew from having run it, and nothing about what it
    found.
    """
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""
    warn_html = f"<div class='card pad warn'>&#9888; {_e(warning)}</div>" if warning else ""

    # Counts describe the whole list, not the page being shown. `assessments`
    # is one window of it, so a 40-assessment install used to read "24
    # Assessments" the moment paging kicked in — the strip was counting the
    # page it was sitting above.
    counts = totals if totals is not None else Counter(a.status for a in assessments)
    n_all = counts.get("ALL", len(assessments)) if totals is not None else len(assessments)
    summary = ui.stats([
        (str(n_all), _t("Assessments"), "", ""),
        (str(counts.get("CREATED", 0)), _t("Imported"), _t("Analyzed, no plan generated yet."), ""),
        (str(counts.get("ANALYZED", 0)), _t("Designed"), _t("A plan exists; it may not be approved."), ""),
        (str(counts.get("EXECUTED", 0)), _t("Executed"), _t("At least one run has happened."), ""),
    ])

    matched = total_matched if total_matched is not None else len(assessments)
    pages = max(1, -(-matched // max(1, per)))

    by_id = {r["id"]: r for r in (rows or [])}
    cards = "".join(_assessment_card(a, by_id.get(a.id, {})) for a in assessments)
    cards = cards or (
        "<p class='muted'>"
        + (_t("No assessments match this filter.") if (q or status)
           else _t("No assessments yet — import a Jira issue above."))
        + "</p>"
    )

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

    # The target moved to the sidebar's engagement card, where it is visible on
    # every screen rather than only here; analyzer and Jira mode stay, because
    # they say which *kind* of plan the next import will produce.
    bar = appbar(_t("Assessments"), actions=(
        f'<span class="chip">{_t("Analyzer")} <b>{ai}</b></span>'
        f'<span class="chip">Jira <b>{_e(jira_mode)}</b></span>'
    ))

    return page(_t("Assessments"), f"""
{flash_html}{warn_html}
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
{_dashboard_toolbar(q, status, sort, per, page_no, matched, n_all, status_counts or {})}
<div class="grid-cards">{cards}</div>
{_dashboard_pager(q, status, sort, per, page_no, pages)}
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
""", active="dashboard", appbar_html=bar)


_DASH_STATUS = [("", "All"), ("CREATED", "Imported"), ("ANALYZED", "Designed"),
                ("EXECUTED", "Executed")]
_DASH_SORT = [("recent", "Newest first"), ("oldest", "Oldest first"),
              ("issue", "Issue key"), ("findings", "Most findings")]
_DASH_PER = (12, 24, 48, 96)


def _dash_url(q: str, status: str, sort: str, per: int, page_no: int = 1) -> str:
    """One canonical link shape, so a facet click never drops the search box's
    contents and a page link never drops the facet."""
    parts = []
    if q:
        parts.append(f"q={quote_plus(q)}")
    if status:
        parts.append(f"status={quote_plus(status)}")
    if sort and sort != "recent":
        parts.append(f"sort={quote_plus(sort)}")
    if per != 24:
        parts.append(f"per={per}")
    if page_no > 1:
        parts.append(f"page={page_no}")
    # `&amp;` rather than `&`: every caller puts this straight into an href.
    return ("/?" + "&amp;".join(parts)) if parts else "/"


def _dashboard_toolbar(q: str, status: str, sort: str, per: int, page_no: int,
                       matched: int, total: int, status_counts: dict[str, int]) -> str:
    """Search on top, facets below.

    The old bar was one flat row of five labelled fields plus Apply/Clear: the
    search box — the control reached for nine times out of ten — was the same
    size and weight as "Per page", the status filter hid behind a dropdown that
    never said how many of anything there were, and nothing on screen told you
    a filter was even active. Here the query gets the full first row, status
    becomes a segmented control carrying its own counts (a facet matching
    nothing is visibly dimmed rather than a dead end you discover by picking
    it), and the view options sit to the right where they belong.

    Selects submit on change, so "Apply" is only the search box's button.
    """
    # Any status except the current one keeps its own count; the "All" chip
    # counts what the search alone matched.
    def facet(value: str, label: str) -> str:
        n = sum(status_counts.values()) if value == "" else status_counts.get(value, 0)
        current = ' aria-current="page"' if value == status else ""
        empty = " none" if not n and value else ""
        return (f'<a class="seg-b{empty}" href="{_dash_url(q, value, sort, per)}"{current}>'
                f'{_e(_t(label))} <b>{n}</b></a>')

    def select(name: str, current: str, choices, label: str) -> str:
        opts = "".join(
            f'<option value="{attr(value)}"{" selected" if value == current else ""}>'
            f"{_e(_t(text))}</option>" for value, text in choices
        )
        return (f'<label class="f-sel"><span>{_e(label)}</span>'
                f'<select name="{attr(name)}">{opts}</select></label>')

    seg = "".join(facet(value, label) for value, label in _DASH_STATUS)
    filtered = bool(q or status)
    count = (_t("{n} of {total}").format(n=matched, total=total) if filtered
             else _t("{n} assessments").format(n=total))
    if page_no > 1:
        count += " · " + _t("page {n}").format(n=page_no)
    clear = (f'<a class="f-clear" href="/">&#10005; {_t("Clear filters")}</a>'
             if filtered else "")
    # Inside the form so typing a query and pressing Enter keeps the facet;
    # the facet links carry `q` the same way in the other direction.
    keep_status = f'<input type="hidden" name="status" value="{attr(status)}">' if status else ""
    reset = (f'<a class="f-x" href="{_dash_url("", status, sort, per)}" '
             f'aria-label="{attr(_t("Clear search"))}">{ui.icon("x", 14)}</a>' if q else "")

    return f"""<form method="get" action="/" class="filters" id="dash-filter" role="search">
{keep_status}
<div class="f-top">
<div class="f-search">{ui.icon("search", 16)}
<input name="q" value="{attr(q)}" autocomplete="off" spellcheck="false"
 aria-label="{attr(_t("Search issue key or assessment id"))}"
 placeholder="{attr(_t("Search issue key or assessment id — e.g. BH-142"))}">{reset}</div>
<button class="btn sec">{_t("Search")}</button>
</div>
<div class="f-bot">
<div class="seg" role="group" aria-label="{attr(_t("Status"))}">{seg}</div>
<span class="f-spacer"></span>
{select("sort", sort or "recent", _DASH_SORT, _t("Sort"))}
{select("per", str(per), [(str(n), str(n)) for n in _DASH_PER], _t("Show"))}
<span class="count">{_e(count)}</span>
{clear}
</div>
<script>
// The selects are view options, not a query to compose: making the tester
// pick one and then reach for Apply was one click of pure ceremony.
document.querySelectorAll('#dash-filter select').forEach(function (s) {{
  s.addEventListener('change', function () {{ s.form.submit(); }});
}});
</script>
</form>"""


def _dashboard_pager(q: str, status: str, sort: str, per: int, page_no: int,
                     pages: int) -> str:
    """Paging existed server-side but had no control: page 2 was reachable only
    by editing the URL, which made "Per page" a setting with no visible effect
    other than hiding assessments."""
    if pages <= 1:
        return ""

    def link(n: int, text: str = "") -> str:
        if n == page_no:
            return f'<span class="on">{_e(text or n)}</span>'
        return f'<a href="{_dash_url(q, status, sort, per, n)}">{_e(text or n)}</a>'

    window = {1, pages, page_no}
    window.update(range(max(1, page_no - 2), min(pages, page_no + 2) + 1))
    out = []
    if page_no > 1:
        out.append(link(page_no - 1, "‹"))
    previous = 0
    for n in sorted(window):
        if previous and n > previous + 1:
            out.append('<span class="gap">…</span>')
        out.append(link(n))
        previous = n
    if page_no < pages:
        out.append(link(page_no + 1, "›"))
    return f'<div class="pager">{"".join(out)}</div>'


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
