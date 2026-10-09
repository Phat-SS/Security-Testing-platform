"""The assessment screen's chrome: the phase rail, the summary strip, the flash
line, and `body()` — which assembles the four phases.
"""

from __future__ import annotations

import json

from app.api import ui
from app.api.ui import attr, e
from .copilot import copilot_panel
from .plan import _design_section, _plan_section
from .results import _results_section
from .run import _execute_section, readiness_banner
from .scope import _coverage_section, _endpoints_section, stale_banner
from .state import PHASES, TIP, _State, _is_stale, resolve_phase
from app.core.i18n import VI, tt as _t
from app.database.models import Assessment

def _phase_rail(aid: str, st: _State, current: str, counts: dict[str, str]) -> str:
    """Four phases, one line, each carrying the single number that says whether
    there is anything to do in it.

    A link, not a tab: the phase is in the URL, so a filtered plan can be
    bookmarked and a redirect after a save comes back to the phase the tester
    was working in.
    """
    states = st.phase_state()
    out = ""
    for i, (key, label) in enumerate(PHASES, 1):
        cls = "on" if key == current else states[key]
        n = counts.get(key, "")
        # The badge is the step number until the phase is done, then a tick:
        # the rail reads as progress at a glance without a legend.
        mark = "&#10003;" if states[key] == "done" and key != current else str(i)
        out += (
            f'<a href="/assessment/{attr(aid)}?phase={key}" class="{cls}" data-phase="{key}">'
            f'<span class="dot">{mark}</span><b>{e(_t(label))}</b>'
            + (f'<span class="n">{e(n)}</span>' if n else "")
            + "</a>"
        )
    return f'<nav class="stepnav" aria-label="{attr(_t("Assessment phases"))}">{out}</nav>'


# -- stat strip -------------------------------------------------------------


def _sev_dots(findings) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [
        f'<span style="color:var(--{ui.SEV_CLASS[s]})">{counts[s]}{s[0]}</span>'
        for s in order if counts.get(s)
    ]
    return f'<span class="sevdots">{"".join(parts)}</span>' if parts else ""


def _stats(aid: str, st: _State, findings, coverage: list[dict]) -> str:
    applicable = [r for r in coverage if r.get("applicable")]
    covered = sum(1 for r in applicable if r.get("state") == "COVERED")
    partial = sum(1 for r in applicable if r.get("state") == "PARTIAL")
    cov_pct = round(100 * (covered + 0.5 * partial) / len(applicable)) if applicable else 0
    findings_cell = f"{len(findings)} {_sev_dots(findings)}" if findings else "0"
    href = f"/assessment/{attr(aid)}?phase="
    return ui.stats([
        (str(st.n_endpoints), _t("Endpoints"), "", f"{href}scope"),
        (str(st.n_tests), _t("Tests"), "", f"{href}plan"),
        (str(st.n_approved), _t("Approved"), TIP["approval"], f"{href}plan"),
        (str(st.n_executions), _t("Executed"), "", f"{href}run"),
        (findings_cell, _t("Findings"), "", f"{href}results"),
        (f"{cov_pct}%" if applicable else "—", _t("Coverage"), TIP["coverage_kpi"], f"{href}scope"),
    ])


# -- 1. endpoints -----------------------------------------------------------


def _flash(aid: str, flash: str, ticket_url: str) -> str:
    """`flash` arrives as one of a handful of fixed English signals the routes
    generate (`"Posted to Jira"`, ...) — kept in English there so this function
    can recognise them by exact match regardless of the viewer's language, then
    render its own translated sentence rather than echo the signal verbatim.

    There used to be a branch here for `"Executed N tests, M FAIL"` that
    auto-redirected to the report a second and a half later. A run no longer
    ends inside a request, so nothing emits that signal: the Run phase shows the
    run as it happens and hands over to the results when it settles.
    """
    if flash == "Posted to Jira" and ticket_url and ticket_url.startswith(("http://", "https://")):
        # ticket_url is a client-supplied query parameter (it round-trips through
        # a redirect, not signed/verified) — html.escape() alone does not block a
        # javascript: href, so the scheme must be checked before this ever
        # becomes a clickable link.
        return f"""<div class='card pad flash exec-flash'>
<b>{_t("Posted to Jira")}</b>
<a href="{e(ticket_url)}" class="btn sec" target="_blank" rel="noopener">{_t("Open Ticket")} ↗</a>
</div>"""
    if flash:
        return f"<div class='card pad flash'>{e(_t(flash))}</div>"
    return ""


# -- the page ---------------------------------------------------------------

def _body_js() -> str:
    working_label = json.dumps(_t("Working…"))
    return f"""
(function () {{
  // PoC format tabs
  document.querySelectorAll('.tabbar').forEach(function (bar) {{
    bar.querySelectorAll('button').forEach(function (b) {{
      b.addEventListener('click', function () {{
        bar.querySelectorAll('button').forEach(function (x) {{
          x.classList.remove('active');
          x.setAttribute('aria-selected', 'false');
        }});
        bar.parentElement.querySelectorAll('.tabpane').forEach(function (x) {{
          x.classList.remove('active');
        }});
        b.classList.add('active');
        b.setAttribute('aria-selected', 'true');
        var pane = document.getElementById(b.dataset.tab);
        if (pane) pane.classList.add('active');
      }});
    }});
  }});
  // Every long-running form gets the same feedback, rather than only Execute.
  document.querySelectorAll('form.js-busy').forEach(function (f) {{
    f.addEventListener('submit', function () {{
      var btn = f.querySelector('button:not([type=button])');
      if (!btn || btn.disabled) return;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> ' + {working_label};
    }});
  }});
  // Highlight the step nav entry for the section currently in view.
  var links = Array.prototype.slice.call(document.querySelectorAll('.stepnav a'));
  var targets = links.map(function (a) {{ return document.querySelector(a.getAttribute('href')); }});
  function spy() {{
    var best = -1, bestTop = -Infinity;
    targets.forEach(function (t, i) {{
      if (!t) return;
      var top = t.getBoundingClientRect().top - 80;
      if (top <= 0 && top > bestTop) {{ bestTop = top; best = i; }}
    }});
    links.forEach(function (a, i) {{ a.classList.toggle('on', i === best); }});
  }}
  spy();
  window.addEventListener('scroll', spy, {{ passive: true }});
}})();
"""


def body(
    assessment: Assessment,
    analysis: dict,
    coverage: list[dict],
    plan: dict,
    *,
    filters: dict,
    n_executions: int,
    findings: list,
    environments: dict[str, str],
    active_environment: str,
    readiness,
    planner_enabled: bool,
    verdicts: dict | None = None,
    plan_review=None,
    run_assessment=None,
    triage: dict | None = None,
    finding_triage: dict | None = None,
    flash: str = "",
    ticket_url: str = "",
    uncovered_poc_endpoints: list[str] | None = None,
    phase: str = "",
    run_job=None,
    copilot=None,
) -> str:
    verdicts = verdicts or {}
    aid = assessment.id
    analysis = analysis or {}
    endpoints = analysis.get("endpoints") or []
    st = _State(len(endpoints), plan.get("meta") or {}, n_executions)
    current = resolve_phase(phase, st)
    # st.n_tests, not the page: a filter that happens to match nothing must not
    # make a stale plan look current or relabel the design button.
    stale = (bool(analysis.get("plan_fingerprint")) and st.n_tests > 0
             and _is_stale(analysis))

    status_label, status_tone = ui.STATUS_PILL.get(
        assessment.status, (assessment.status.title(), "info")
    )
    summary_line = analysis.get("business_summary") or ""
    sensitive = analysis.get("sensitive_operation")
    target = assessment.target_base_url

    copy_tip = _t("Copy the Assessment Id")
    sensitive_label = _t("sensitive operation:") + f" <b>{_t('yes') if sensitive else _t('no')}</b>"
    last_target = (f'· {_t("last target:")} <span class="mono">{e(target)}</span>' if target else "")
    copied_label = json.dumps(_t("Copied"))
    head = f"""<div class="pagehead">
<div>
<h1>{e(assessment.issue_key)} {ui.pill(_t(status_label), status_tone)}</h1>
<p class="sub" style="margin:4px 0 0">{e(summary_line)}</p>
<p class="muted" style="margin:6px 0 0;font-size:12.5px">
<span class="mono">{e(aid)}</span>
<button type="button" class="copy" data-copy="{attr(aid)}"
 data-tip="{attr(copy_tip)}">{_t("Copy")}</button>
· {sensitive_label}
{last_target}</p>
</div>
<div class="row" style="gap:6px">
<a href="/assessment/{attr(aid)}/report" class="btn sec" target="_blank">{_t("Report")} ↗</a>
<a href="/" class="btn ghost">← {_t("All Assessments")}</a>
</div>
</div>"""

    # Only the current phase is built. Everything a section needs is cheap to
    # compute except the plan table, which is already paged server-side — so
    # this is also the point where a 300-test plan stops being rendered on a
    # page whose visitor came to read the results.
    if current == "scope":
        panes = (
            _endpoints_section(aid, endpoints, stale, True,
                               requirements=analysis.get("requirements") or [],
                               coverage_items=(run_assessment.items if run_assessment else []),
                               uncovered_poc_endpoints=uncovered_poc_endpoints or [])
            + _coverage_section(aid, coverage or [], bool(coverage))
        )
    elif current == "plan":
        panes = (
            _design_section(aid, analysis.get("detected_poc_source") or "", st.n_tests > 0,
                            st.n_tests == 0,
                            poc_scripts=analysis.get("detected_poc_scripts") or [],
                            unreachable_pocs=analysis.get("unreachable_poc_attachments") or [])
            + _plan_section(aid, plan, filters, st.n_tests > 0, review=plan_review,
                            stale=stale)
        )
    elif current == "run":
        panes = _execute_section(aid, assessment.issue_key, st, environments or {},
                                 active_environment, planner_enabled, True, job=run_job)
    else:
        panes = _results_section(aid, assessment.issue_key, st, findings, verdicts, True,
                                 run=run_assessment, triage=triage or {},
                                 finding_triage=finding_triage or {})

    counts = {
        "scope": str(st.n_endpoints or ""),
        "plan": str(st.n_tests or ""),
        "run": str(st.n_approved or ""),
        "results": str(len(findings) or ""),
    }

    # Above the rail, not inside the Run phase: a configuration problem that
    # will make every request come back BLOCKED is worth knowing while you are
    # still approving tests, not at the moment you press the button. It stays
    # silent when everything is green.
    return f"""{_flash(aid, flash, ticket_url)}
{head}
{readiness_banner(readiness)}{stale_banner(aid) if stale else ''}
{_stats(aid, st, findings, coverage)}
<div class="ws"><div class="ws-main">
{_phase_rail(aid, st, current, counts)}
{panes}
</div>
{copilot_panel(aid, copilot, phase=current, planner_enabled=planner_enabled)}
</div>
<script>
{_body_js()}
(function () {{
  document.querySelectorAll('.copy').forEach(function (b) {{
    b.addEventListener('click', function () {{
      navigator.clipboard && navigator.clipboard.writeText(b.dataset.copy);
      var was = b.textContent; b.textContent = {copied_label};
      setTimeout(function () {{ b.textContent = was; }}, 1200);
    }});
  }});
}})();
</script>"""


VI.update({
    "Working…": "Đang Xử Lý…",
    "Copy the Assessment Id": "Copy Id Của Assessment",
    "sensitive operation:": "thao tác nhạy cảm:", "yes": "có", "no": "không",
    "last target:": "mục tiêu gần nhất:",
    "Copied": "Đã Copy", "Copy": "Copy",
    "Report": "Báo Cáo", "All Assessments": "Tất Cả Assessment",
    "Analyzed": "Đã Phân Tích",
})
