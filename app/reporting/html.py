"""HTML report renderer — dependency-free (no Jinja needed for MVP).

Produces a self-contained, theme-aware report from executions + findings. Every
value shown here has already passed secret redaction upstream.
"""

from __future__ import annotations

import html
import json
from collections import Counter

from app.execution.mutations import MUTATION_KINDS
from app.schemas.execution import Execution
from app.schemas.finding import Finding
from app.schemas.testcase import TestCase

_SEV_COLOR = {
    "CRITICAL": "#b4232a",
    "HIGH": "#c8500f",
    "MEDIUM": "#b8860b",
    "LOW": "#2f855a",
    "INFO": "#4a5568",
}
_RESULT_COLOR = {
    "PASS": "#2f855a",
    "FAIL": "#b4232a",
    "INCONCLUSIVE": "#b8860b",
    "BLOCKED": "#4a5568",
    "ERROR": "#4a5568",
    "SKIPPED": "#718096",
    "TIMEOUT": "#4a5568",
}


def _e(v) -> str:
    return html.escape(str(v))


def _evidence_chain_banner(chain_ok: bool | None) -> str:
    if chain_ok is None:
        # Caller didn't check (e.g. a report built without going through
        # Orchestrator.build_report_html). Absence of a check is not the
        # same as a failed one — say nothing rather than falsely alarm.
        return ""
    if chain_ok:
        return (
            '<p style="margin:0 0 18px"><span style="color:#2f855a;font-weight:600">'
            "&#10003; Evidence chain verified</span> — every execution's SHA-256 hash "
            "recomputes and links to the previous one; nothing below has been edited "
            "since it was recorded.</p>"
        )
    return (
        '<p style="margin:0 0 18px;padding:10px 14px;border:1px solid #b4232a;'
        'border-radius:8px;background:rgba(180,35,42,.08)"><span style="color:#b4232a;'
        'font-weight:700">&#9888; Evidence chain FAILED verification</span> — at least '
        "one execution record's hash no longer matches its content, or the chain link to "
        "the previous record is broken. This report's evidence may have been altered "
        "after it was recorded; treat it as non-authoritative until investigated.</p>"
    )


def render_report(
    title: str,
    target: str,
    tests: dict[str, TestCase],
    executions: list[Execution],
    findings: list[Finding],
    coverage_rows: list[dict] | None = None,
    assessment_id: str | None = None,
    issue_key: str | None = None,
    evidence_chain_ok: bool | None = None,
    plan_review=None,
    run_assessment=None,
) -> str:
    """The full document. This is where the *explanation* lives.

    The Jira comment carries the summary and the results table; everything that
    explains a row is here, because here it can sit next to the captured request
    and response it refers to. `plan_review` and `run_assessment` are the two
    reviewing agents' output and are both optional — a report of a run nobody
    asked an agent about simply omits those sections.
    """
    result_counts = Counter(e.verdict.result.value for e in executions)
    sev_counts = Counter(f.severity.value for f in findings)
    coverage_html = _coverage_section(coverage_rows) if coverage_rows else ""
    assessment_html = _run_assessment_section(run_assessment)
    review_html = _plan_review_section(plan_review)
    adjudications = ({a.execution_id: a for a in run_assessment.adjudications}
                     if run_assessment is not None else {})
    jira_bar = _jira_bar(assessment_id, issue_key) if assessment_id and issue_key else ""
    chain_banner = _evidence_chain_banner(evidence_chain_ok) if executions else ""

    summary_cells = "".join(
        f'<div class="stat"><div class="num">{result_counts.get(k, 0)}</div>'
        f'<div class="lbl">{k}</div></div>'
        for k in ["PASS", "FAIL", "INCONCLUSIVE", "BLOCKED", "ERROR"]
    )
    sev_cells = "".join(
        f'<span class="pill" style="background:{_SEV_COLOR[k]}">{k}: '
        f'{sev_counts.get(k, 0)}</span>'
        for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    findings_html = "\n".join(_finding_block(f) for f in findings) or (
        '<p class="ok">No confirmed findings.</p>'
    )

    # The re-run control only exists when the report knows which assessment it
    # belongs to — the same gate the Jira bar uses. A report rendered by the CLI
    # or a demo script has no server to post back to, and a button that silently
    # 404s is worse than no button at all.
    rerun_enabled = bool(assessment_id and issue_key)
    # Executions accumulate, so a test can appear more than once. Only the most
    # recent attempt is re-runnable: an older row is history, and offering to
    # re-run it would send the same request a newer row has already answered.
    latest = {ex.test_id: i for i, ex in enumerate(executions)}
    exec_rows = "\n".join(
        _exec_row(tests.get(e.test_id), e, i, rerun_enabled,
                  superseded_by=(None if latest[e.test_id] == i
                                 else executions[latest[e.test_id]]),
                  adjudication=adjudications.get(e.execution_id))
        for i, e in enumerate(executions)
    )
    rerun_head = "<th>Re-run</th>" if rerun_enabled else ""
    rerun_js = _rerun_js(assessment_id, issue_key) if rerun_enabled else ""
    rerun_note = (
        _RERUN_NOTE if rerun_enabled and
        any(e.verdict.result.value == "INCONCLUSIVE" for e in executions) else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root {{ --bg:#fff; --fg:#1a202c; --muted:#4a5568; --card:#f7fafc;
           --border:#e2e8f0; --code:#f1f5f9; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#0f1419; --fg:#e2e8f0; --muted:#a0aec0; --card:#1a212b;
             --border:#2d3748; --code:#161d27; }} }}
  * {{ box-sizing:border-box; }}
  body {{ font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;
          margin:0; background:var(--bg); color:var(--fg); }}
  .wrap {{ max-width:960px; margin:0 auto; padding:28px 20px 80px; }}
  h1 {{ font-size:24px; margin:0 0 4px; }} h2 {{ font-size:19px; margin:32px 0 12px;
        border-bottom:1px solid var(--border); padding-bottom:6px; }}
  .sub {{ color:var(--muted); margin:0 0 20px; }}
  .stats {{ display:flex; gap:10px; flex-wrap:wrap; }}
  .stat {{ background:var(--card); border:1px solid var(--border); border-radius:10px;
           padding:12px 18px; min-width:96px; text-align:center; }}
  .num {{ font-size:26px; font-weight:700; }} .lbl {{ color:var(--muted); font-size:12px; }}
  .pills {{ margin:14px 0; display:flex; gap:8px; flex-wrap:wrap; }}
  .pill {{ color:#fff; border-radius:999px; padding:3px 11px; font-size:12px; font-weight:600; }}
  .finding {{ background:var(--card); border:1px solid var(--border); border-left-width:5px;
              border-radius:10px; padding:16px 18px; margin:14px 0; }}
  .finding h3 {{ margin:0 0 8px; font-size:16px; }}
  .kv {{ display:grid; grid-template-columns:130px 1fr; gap:4px 12px; font-size:14px; }}
  .kv b {{ color:var(--muted); font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .tblwrap {{ overflow-x:auto; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--border); }}
  th {{ color:var(--muted); font-weight:600; }}
  code {{ background:var(--code); padding:1px 5px; border-radius:4px; font-size:12.5px; }}
  .res {{ font-weight:700; }} .ok {{ color:#2f855a; }}
  .mono {{ font-family:ui-monospace,Menlo,Consolas,monospace; }}
  .bar {{ background:var(--border); border-radius:6px; height:10px; width:140px; overflow:hidden; }}
  .fill {{ height:100%; border-radius:6px; }}
  .jirabar {{ display:flex; align-items:center; gap:12px; margin:16px 0 26px; }}
  .jirabar button {{ background:#0d6e6e; color:#fff; border:0; border-radius:8px; padding:9px 16px;
                      font:inherit; font-size:14px; font-weight:600; cursor:pointer; }}
  .jirabar button:disabled {{ opacity:.6; cursor:default; }}
  .jira-status {{ font-size:13px; color:var(--muted); }}
  .jira-status.err {{ color:#b4232a; }}
  .muted {{ color:var(--muted); }}
  details.resp summary {{ cursor:pointer; color:var(--muted); font-size:12.5px; user-select:none; }}
  .glabel {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.03em;
             margin:0 0 2px; }}
  .respbody {{ max-height:180px; overflow:auto; background:var(--code); padding:8px 10px;
               border-radius:6px; margin:2px 0 8px; white-space:pre-wrap; word-break:break-word;
               font-size:12px; }}
  td.rerun {{ white-space:nowrap; vertical-align:top; }}
  .rerunbtn {{ background:var(--card); color:inherit; border:1px solid var(--border);
               border-radius:7px; padding:5px 11px; font:inherit; font-size:12.5px;
               font-weight:600; cursor:pointer; }}
  .rerunbtn:enabled:hover {{ border-color:#0d6e6e; color:#0d6e6e; }}
  .rerunbtn:disabled {{ opacity:.55; cursor:default; }}
  .rerunout {{ font-size:12px; line-height:1.5; margin-top:6px; max-width:220px;
               white-space:normal; }}
  /* An agent's reading of a row, set apart from the verdict above it: an
     opinion and a sealed verdict must not look like the same kind of claim. */
  .adj {{ border-left:3px solid var(--border); background:var(--card); border-radius:0 6px 6px 0;
          padding:8px 10px; margin:8px 0 4px; font-size:12.5px; }}
  .adj ul {{ font-size:12px; }}
  .rerunout .err {{ color:#b4232a; }}
  .rerunout a {{ color:#0d6e6e; }}
  .spin {{ display:inline-block; width:10px; height:10px; border:2px solid var(--border);
           border-top-color:#0d6e6e; border-radius:50%; vertical-align:-1px;
           animation:spin .7s linear infinite; }}
  @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
  @media (prefers-reduced-motion:reduce) {{ .spin {{ animation:none; }} }}
</style></head><body><div class="wrap">
<h1>{_e(title)}</h1>
<p class="sub">Target: <code>{_e(target)}</code> · Baseline: OWASP API Security Top 10 (2023)</p>
{jira_bar}
{chain_banner}
<h2>Executive Summary</h2>
<div class="stats">{summary_cells}</div>
<div class="pills">{sev_cells}</div>
{assessment_html}
{coverage_html}
{review_html}
<h2>Findings</h2>
{findings_html}

<h2>Execution Log</h2>
{rerun_note}
<div class="tblwrap"><table>
<tr><th>Test</th><th>OWASP</th><th>Result</th><th>Confidence</th><th>Status</th>
<th>Exchange</th><th>Reason</th>{rerun_head}</tr>
{exec_rows}
</table></div>
{rerun_js}
</div></body></html>"""


def _jira_bar(assessment_id: str, issue_key: str) -> str:
    """A one-click 'post this exact report's summary as a Jira comment' action.
    Uses fetch so the report — a standalone document, possibly opened in its
    own tab — never has to navigate away to post. Posts to the same endpoint
    the assessment page's "Preview Jira comment" flow uses, so it always lands
    on assessment.issue_key: the ticket this report was generated from."""
    key = _e(issue_key)
    # aid is interpolated into a JS string literal inside <script>, not HTML —
    # json.dumps is the correct escaping for that context (html.escape only
    # happens to be safe here today because assessment_id is always a
    # server-generated UUID hex, never attacker-influenced text).
    aid_js = json.dumps(assessment_id)
    return f"""<div class="jirabar">
<button id="jira-btn" onclick="postToJira()">Post this report to Jira ({key})</button>
<span id="jira-status" class="jira-status"></span>
</div>
<script>
function postToJira() {{
  var btn = document.getElementById('jira-btn');
  var status = document.getElementById('jira-status');
  var original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Posting…';
  status.className = 'jira-status';
  status.textContent = '';
  fetch('/assessment/' + {aid_js} + '/comment', {{ method: 'POST' }})
    .then(function (r) {{
      if (r.ok) {{
        btn.textContent = 'Posted to Jira';
      }} else {{
        btn.disabled = false;
        btn.textContent = original;
        status.textContent = 'Failed to post — open the assessment page for details.';
        status.className = 'jira-status err';
      }}
    }})
    .catch(function () {{
      btn.disabled = false;
      btn.textContent = original;
      status.textContent = 'Network error — try again.';
      status.className = 'jira-status err';
    }});
}}
</script>"""


_COVERAGE_COLOR = {
    "COVERED": "#2f855a", "PARTIAL": "#b8860b", "MISSING": "#b4232a",
    "NOT_APPLICABLE": "#718096",
}


def _status_color(status_code: int) -> str:
    if status_code < 300:
        return "#2f855a"
    if status_code < 400:
        return "#4a5568"
    if status_code < 500:
        return "#b8860b"
    return "#b4232a"


def _coverage_section(rows: list[dict]) -> str:
    applicable = [r for r in rows if r.get("applicable")]
    body = ""
    for r in rows:
        state = r.get("state", "UNKNOWN")
        color = _COVERAGE_COLOR.get(state, "#718096")
        pct = r.get("pct", 0)
        bar_w = pct if state != "NOT_APPLICABLE" else 0
        body += (
            f"<tr><td><b>{_e(r.get('category'))}</b></td>"
            f"<td>{_e(r.get('existing_tests', 0))}</td>"
            f"<td>{_e(r.get('generated_tests', 0))}</td>"
            f"<td style='color:{color};font-weight:700'>{_e(state)}</td>"
            f"<td><div class='bar'><div class='fill' style='width:{bar_w}%;"
            f"background:{color}'></div></div></td></tr>"
        )
    return f"""<h2>OWASP API Security Coverage ({len(applicable)} applicable)</h2>
<div class="tblwrap"><table>
<tr><th>Category</th><th>Existing PoC</th><th>Generated</th><th>State</th><th>Coverage</th></tr>
{body}</table></div>"""


def _finding_block(f: Finding) -> str:
    color = _SEV_COLOR[f.severity.value]
    repro = "".join(f"<li>{_e(s)}</li>" for s in f.reproduction)
    refs = " · ".join(f'<a href="{_e(r)}">{_e(r)}</a>' if r.startswith("http") else _e(r)
                      for r in f.references)
    return f"""<div class="finding" style="border-left-color:{color}">
<h3>{_e(f.finding_id)} — {_e(f.title)}
 <span class="pill" style="background:{color}">{_e(f.severity.value)}</span></h3>
<div class="kv">
<b>OWASP</b><span>{_e(f.owasp_category.value)}</span>
<b>Endpoint</b><span><code>{_e(f.endpoint)}</code></span>
<b>Confidence</b><span>{_e(f.confidence.value)}</span>
<b>Affected tests</b><span>{_e(', '.join(f.affected_tests))}</span>
<b>Expected</b><span>{_e(f.correlation.expected)}</span>
<b>Actual</b><span>{_e(f.correlation.actual)}</span>
<b>Impact</b><span>{_e(f.impact)}</span>
<b>Recommendation</b><span>{_e(f.recommendation)}</span>
<b>Reproduction</b><span><ol>{repro}</ol></span>
<b>References</b><span>{refs}</span>
</div></div>"""


def _exec_row(test: TestCase | None, e: Execution, index: int = 0,
              rerun_enabled: bool = False,
              superseded_by: Execution | None = None,
              adjudication=None) -> str:
    color = _RESULT_COLOR.get(e.verdict.result.value, "#4a5568")
    title = _e(test.title) if test else _e(e.test_id)
    if e.response is not None:
        r = e.response
        status_color = _status_color(r.status_code)
        status_cell = (
            f"<span class='res' style='color:{status_color}'>{r.status_code}</span>"
            f"<br><span class='muted mono' style='font-size:11px'>"
            f"{r.elapsed_ms} ms &middot; {r.size_bytes} B</span>"
        )
        headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_text = r.body if r.body else "(empty body)"
        response_cell = (
            "<details class='resp'><summary>response</summary>"
            f"<div class='glabel' style='margin-top:8px'>Headers</div>"
            f"<pre class='respbody'>{_e(headers_text) or '(none)'}</pre>"
            f"<div class='glabel'>Body</div>"
            f"<pre class='respbody'>{_e(body_text)}</pre>"
            "</details>"
        )
    else:
        status_cell = "<span class='muted'>&mdash;</span>"
        response_cell = "<span class='muted'>blocked before send</span>"

    # The request sits next to the response, not just summarised in the reason.
    # Offering "send this one again" is only defensible if a reader can first
    # see exactly what would be sent — method, URL with its query, every header,
    # the body — and the report is also where someone reproduces a result by
    # hand. Second panel, not first: the response is what a reader scans, the
    # request is what they open when they want to reproduce it.
    request_cell = _request_details(e)

    # A verdict that leans on a positive control or a read-back is only as
    # defensible as the exchange it leaned on. Rendering the conclusion while
    # hiding its evidence would ask a reader to take the strongest claims in
    # the report on trust — the opposite of why those exchanges are captured.
    # The whole explanation of this row, in one cell: what the attack actually
    # did and with what parameters, what a secure system was expected to return
    # versus what came back, the verdict's reasoning, and the exchanges that
    # reasoning leaned on. This is the material the Jira comment used to carry
    # per test; it belongs here, where the request and response it describes are
    # one click away instead of being described in prose in a ticket.
    reason_cell = (
        _attack_html(test, e)
        + _expectation_html(e)
        + f"<p style='margin:6px 0'>{_e(e.verdict.reason)}</p>"
        + _adjudication_html(adjudication)
        + _supporting_html(e)
    )
    rerun_cell = _rerun_cell(test, e, index, superseded_by) if rerun_enabled else ""
    return (
        f"<tr><td><b>{_e(e.test_id)}</b><br><span class='mono'>{title}</span></td>"
        f"<td>{_e(e.owasp_category)}</td>"
        f"<td class='res' style='color:{color}'>{_e(e.verdict.result.value)}</td>"
        f"<td>{_e(e.verdict.confidence.value)}</td>"
        f"<td>{status_cell}</td>"
        f"<td>{response_cell}{request_cell}</td>"
        f"<td>{reason_cell}</td>{rerun_cell}</tr>"
    )


def _request_details(e: Execution) -> str:
    """The attack request exactly as it was recorded — URL (query included),
    every header, the body.

    Says plainly that credentials are masked. A reader who did not know that
    would read `Authorization: ********` as "the runner sent no credential" and
    conclude the test never authenticated at all — the opposite of what
    happened, and enough to make every verdict here look unsound.
    """
    r = e.request
    headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body_text = r.body if r.body else "(no body)"
    note = (f"<p class='muted' style='margin:6px 0'>{_e(e.attack_note)}</p>"
            if e.attack_note else "")
    return (
        "<details class='resp' style='margin-top:6px'><summary>request</summary>"
        f"{note}"
        f"<div class='glabel' style='margin-top:8px'>{_e(r.method)}</div>"
        f"<pre class='respbody'>{_e(r.url)}</pre>"
        "<div class='glabel'>Headers</div>"
        f"<pre class='respbody'>{_e(headers_text) or '(none)'}</pre>"
        "<div class='glabel'>Body</div>"
        f"<pre class='respbody'>{_e(body_text)}</pre>"
        "<p class='muted' style='margin:0'>Credentials are masked "
        "(<code>********</code>) before anything is stored. The live values come "
        "from the persona vault at send time and are never written here.</p>"
        "</details>"
    )


# -- re-running one undecided request ---------------------------------------
#
# INCONCLUSIVE is the runner declining to guess, and the common ways to get
# there are transient: the positive control failed, the server answered 5xx, or
# the attack was accepted but no protected marker was available to prove
# disclosure. Re-running a whole plan to settle one row is disproportionate, so
# each undecided row can be sent again on its own.

_RERUN_NOTE = (
    '<p class="muted" style="margin:0 0 12px">Rows judged <b>INCONCLUSIVE</b> can be sent '
    "again on their own. A re-run replays the <b>test</b> through the trusted runner &mdash; "
    "the same method, path, query, headers and body, with the persona's real credential "
    "resolved from the vault at send time, because the headers and body recorded here are "
    "redacted and cannot be replayed byte-for-byte. Nothing below is overwritten: the result "
    "is appended to this log as a new execution, chained onto the previous one's evidence "
    "hash, so both attempts stay on the record. Reload the report to see the new row.</p>"
)


def _rerun_cell(test: TestCase | None, e: Execution, index: int,
                superseded_by: Execution | None = None) -> str:
    if e.verdict.result.value != "INCONCLUSIVE":
        return "<td class='rerun'><span class='muted'>&mdash;</span></td>"
    if superseded_by is not None:
        # This row was already sent again. Say what came back rather than offer
        # a button that would re-send a request a later row has answered — and
        # do not restate the row's own verdict as if it were still open.
        later = superseded_by.verdict.result.value
        color = _RESULT_COLOR.get(later, "#4a5568")
        return ("<td class='rerun'><span class='muted' style='font-size:12px'>re-run below: "
                f"<b style='color:{color}'>{_e(later)}</b></span></td>")
    if test is None:
        # The plan no longer holds this test, so there is nothing to send. Say
        # so here rather than offering a button the server would only refuse.
        return ("<td class='rerun'><span class='muted' style='font-size:12px'>"
                "no longer in the plan</span></td>")
    destructive = "1" if test.is_destructive else "0"
    return (
        "<td class='rerun'><button type='button' class='rerunbtn' "
        f"data-rerun=\"{_e(e.execution_id)}\" data-test=\"{_e(e.test_id)}\" "
        f"data-destructive=\"{destructive}\" data-slot=\"{index}\">"
        "&#8635; Re-run</button>"
        f"<div class='rerunout' id='rerun-out-{index}'></div></td>"
    )


def _rerun_js(assessment_id: str, issue_key: str) -> str:
    """Post one execution back to the platform and report the new verdict in place.

    fetch, not a form: the report is a standalone document that may be open in
    its own tab, and navigating away to settle one row would lose the reader's
    place in a log they are working through.
    """
    aid_js = json.dumps(assessment_id)
    key_js = json.dumps(issue_key)
    colors_js = json.dumps(_RESULT_COLOR)
    return f"""<script>
(function () {{
  var AID = {aid_js}, ISSUE = {key_js}, COLOR = {colors_js};

  function esc(text) {{
    var d = document.createElement('div');
    d.textContent = text === null || text === undefined ? '' : String(text);
    return d.innerHTML;
  }}

  function render(out, data) {{
    var color = COLOR[data.result] || '#4a5568';
    var meta = [data.confidence];
    if (data.status_code !== null && data.status_code !== undefined) {{
      meta.push('HTTP ' + data.status_code);
    }}
    if (data.elapsed_ms !== null && data.elapsed_ms !== undefined) {{
      meta.push(data.elapsed_ms + ' ms');
    }}
    out.innerHTML =
      '<b style="color:' + color + '">' + esc(data.result) + '</b> \u00b7 ' +
      esc(meta.join(' \u00b7 ')) +
      (data.changed
        ? '<div class="muted">was ' + esc(data.previous_result) + '</div>'
        : '<div class="muted">unchanged</div>') +
      '<div class="muted">' + esc(data.reason) + '</div>' +
      '<a href="#" onclick="location.reload();return false;">Reload the log</a>';
  }}

  document.querySelectorAll('button[data-rerun]').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      var execId = btn.getAttribute('data-rerun');
      var testId = btn.getAttribute('data-test');
      var out = document.getElementById('rerun-out-' + btn.getAttribute('data-slot'));
      var confirmToken = '';

      if (btn.getAttribute('data-destructive') === '1') {{
        // The same speed bump the assessment page puts in front of destructive
        // tests: this sends a real write, and clicking OK out of habit is not
        // the deliberate consent that needs.
        var typed = prompt(
          'Re-running ' + testId + ' sends a real state-changing request that can create, ' +
          'modify or delete data on the target. Type ' + ISSUE + ' to confirm.'
        );
        if (typed === null) return;
        if (typed.trim() !== ISSUE) {{
          alert('Issue key did not match \u2014 cancelled, nothing was sent.');
          return;
        }}
        confirmToken = typed.trim();
      }} else if (!confirm(
          'Re-run ' + testId + ' on its own?\n\n' +
          'Sends the same request again through the trusted runner, with live persona ' +
          'credentials. This record is kept exactly as it is; the result is appended to ' +
          'the log as a new execution.')) {{
        return;
      }}

      btn.disabled = true;
      out.innerHTML = '<span class="spin"></span> Sending\u2026';

      var payload = new URLSearchParams();
      payload.set('execution_id', execId);
      if (confirmToken) payload.set('confirm', confirmToken);

      fetch('/assessment/' + encodeURIComponent(AID) + '/execution/rerun', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
        body: payload.toString()
      }})
        .then(function (r) {{
          return r.json().then(function (d) {{ return {{ ok: r.ok, data: d }}; }});
        }})
        .then(function (res) {{
          btn.disabled = false;
          if (res.ok && res.data.ok) {{
            render(out, res.data);
            btn.innerHTML = '&#8635; Re-run again';
            return;
          }}
          out.innerHTML = '<span class="err">' +
            esc(res.data.error || 'The platform refused this re-run.') + '</span>';
        }})
        .catch(function () {{
          btn.disabled = false;
          out.innerHTML = '<span class="err">Could not reach the platform. Re-running ' +
            'works from a report served by the app, not from a saved copy.</span>';
        }});
    }});
  }});
}})();
</script>"""


_SUPPORTING_LABEL = {
    "baseline": "Positive control",
    "verification": "Verification read-back",
}


def _supporting_html(e) -> str:
    """Render baseline / verification exchanges and multi-request statistics."""
    blocks: list[str] = []

    for exchange in getattr(e, "supporting", []) or []:
        label = _SUPPORTING_LABEL.get(exchange.kind, exchange.kind)
        response = exchange.response
        status = f"HTTP {response.status_code}" if response else "no response"
        headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items()) if response else ""
        body_text = (response.body or "(empty body)") if response else "(request did not complete)"
        blocks.append(
            f"<details class='resp' style='margin-top:8px'>"
            f"<summary>{_e(label)} &middot; as <b>{_e(exchange.as_persona)}</b> &middot; {_e(status)}</summary>"
            f"<p class='muted' style='margin:6px 0'>{_e(exchange.note)}</p>"
            f"<div class='glabel'>Request</div>"
            f"<pre class='respbody'>{_e(exchange.request.method)} {_e(exchange.request.url)}</pre>"
            f"<div class='glabel'>Response headers</div>"
            f"<pre class='respbody'>{_e(headers_text) or '(none)'}</pre>"
            f"<div class='glabel'>Response body</div>"
            f"<pre class='respbody'>{_e(body_text)}</pre>"
            f"</details>"
        )

    repeat = getattr(e, "repeat", None)
    if repeat is not None:
        spread = ", ".join(f"{status}&times;{count}" for status, count in sorted(repeat.status_counts.items()))
        blocks.append(
            "<p class='muted' style='margin:8px 0 0'>"
            f"Multi-request probe: {repeat.sent} sent "
            f"{'concurrently' if repeat.concurrent else 'in sequence'}, "
            f"{repeat.succeeded} succeeded, throttling "
            f"{'observed' if repeat.throttled else 'not observed'}. Status spread: {spread}."
            "</p>"
        )

    return "".join(blocks)


# -- the explanation, moved here from the Jira comment ------------------------
#
# These three renderers exist because the comment stopped carrying them. A
# ticket comment is skimmed and has a length limit; a report is read by whoever
# actually has to act on a row, and it can put the explanation immediately above
# the captured request and response that justify it. Keeping the explanation in
# both places meant two renderings of the same claim, and the one in the ticket
# was the copy nobody updated.


def _attack_html(test: TestCase | None, e: Execution) -> str:
    """What the mutation did, and with which parameters.

    The runtime note is the specific one ("targeted object id 2002 owned by
    another identity"); the registry summary still describes the technique when
    a test was blocked before its mutation ever ran, which is exactly when a
    reader has no other way to find out what would have happened.
    """
    kind = test.attack_mutation.kind if test else ""
    spec = MUTATION_KINDS.get(kind)
    description = e.attack_note or (spec.summary if spec else "")
    if not kind and not description:
        return ""
    parts = []
    if kind:
        parts.append(f"<code>{_e(kind)}</code>")
    if description:
        parts.append(_e(description))
    out = (f"<div class='glabel'>Attack performed</div>"
           f"<p style='margin:2px 0 6px'>{' &mdash; '.join(parts)}</p>")
    detail = test.attack_mutation.detail if test else None
    if detail:
        try:
            rendered = json.dumps(detail, sort_keys=True, default=str)
        except (TypeError, ValueError):
            rendered = str(detail)
        out += (f"<div class='glabel'>Attack parameters</div>"
                f"<pre class='respbody'>{_e(rendered)}</pre>")
    return out


def _expectation_html(e: Execution) -> str:
    """Expected versus observed, side by side.

    A verdict is a comparison, and printing only its conclusion asks the reader
    to trust that the comparison was made. Both halves are narrative fields the
    verdict builds; neither ever names a disclosed value (see `verdict.py`).
    """
    expected = (e.verdict.expected_summary or "").strip()
    observed = (e.verdict.actual_summary or "").strip()
    if not expected and not observed:
        return ""
    rows = ""
    if expected:
        rows += f"<b>Expected</b><span>{_e(expected)}</span>"
    if observed:
        rows += f"<b>Observed</b><span>{_e(observed)}</span>"
    return (f"<div class='kv' style='font-size:12.5px;margin:0 0 6px;"
            f"grid-template-columns:74px 1fr'>{rows}</div>")


def _adjudication_html(adjudication) -> str:
    """The reviewing agent's reading of an undecided row.

    Rendered as an aside, visually distinct from the verdict above it, and it
    says who produced it every single time. "The runner sealed this as a break"
    and "an agent read this as a break" are different claims: the first is
    hashed into the evidence chain and mints a finding, the second is one
    reader's opinion of a response body. Printing them in the same voice would
    be the single most misleading thing this report could do.
    """
    if adjudication is None:
        return ""
    result = adjudication.assessed_result
    color = _RESULT_COLOR.get(result, "#4a5568")
    who = "AI reviewer" if adjudication.adjudicator == "ai" else "deterministic triage"
    decided = result in ("PASS", "FAIL")
    if adjudication.needs_manual_review:
        headline, color = "Needs manual review", "#b8860b"
    elif decided:
        headline = f"Reviewed as {result}"
    else:
        # Nobody has to read this one and nobody decided it either. "Reviewed as
        # INCONCLUSIVE" claimed a reading that did not happen, and next to it a
        # confidence inherited from the sealed verdict read as confidence in that
        # non-reading.
        headline, color = "Still undecided — re-run this one", "#b8860b"
    # Confidence is only meaningful about a decision. Printed beside a row that
    # decided nothing, it is noise at best and false assurance at worst.
    confidence = (f"{_e(adjudication.confidence.value)} confidence &middot; "
                  if decided else "")
    cited = "".join(f"<li>{_e(c)}</li>" for c in adjudication.evidence_cited)
    cited_html = (f"<div class='glabel'>Evidence cited</div>"
                  f"<ul style='margin:2px 0 6px;padding-left:18px'>{cited}</ul>"
                  if cited else "")
    action = (f"<p class='muted' style='margin:4px 0 0'><b>Next:</b> "
              f"{_e(adjudication.recommended_action)}</p>"
              if adjudication.recommended_action else "")
    degraded = (f"<p class='muted' style='margin:4px 0 0'>{_e(adjudication.degraded_reason)}</p>"
                if adjudication.degraded_reason else "")
    return (
        f"<div class='adj' style='border-left-color:{color}'>"
        f"<p style='margin:0 0 4px'><b style='color:{color}'>{_e(headline)}</b> "
        f"<span class='muted'>&middot; {_e(who)} &middot; "
        f"{confidence}advisory, does not change "
        f"the sealed verdict or create a finding</span></p>"
        f"<p style='margin:0 0 4px'>{_e(adjudication.triage_reason)}</p>"
        f"<p style='margin:0 0 4px'>{_e(adjudication.rationale)}</p>"
        f"{cited_html}{action}{degraded}</div>"
    )


def _run_assessment_section(run) -> str:
    """Passed or failed, and how much of the ticket the run actually covered.

    The percentage is computed by the platform over the requirement list, never
    asserted by a model — so the table below it lists every requirement item and
    what the run proved about it. A number nobody can decompose is a number
    nobody should act on.
    """
    if run is None:
        return ""
    tone = {"PASSED": "#2f855a", "FAILED": "#b4232a", "INCOMPLETE": "#b8860b"}.get(
        run.overall, "#4a5568")
    rows = ""
    for item in run.items:
        color = _ITEM_COLOR.get(item.state, "#718096")
        rows += (
            f"<tr><td class='mono'>{_e(item.item_id)}</td>"
            f"<td>{_e(item.text)}</td>"
            f"<td style='color:{color};font-weight:700;white-space:nowrap'>"
            f"{_e(item.state.replace('_', ' '))}</td>"
            f"<td class='mono' style='font-size:11.5px'>{_e(', '.join(item.tests)) or '&mdash;'}</td>"
            f"<td class='muted'>{_e(item.note)}</td></tr>"
        )
    items_table = (
        "<div class='tblwrap'><table>"
        "<tr><th>Item</th><th>Requirement</th><th>State</th><th>Tests</th><th>Note</th></tr>"
        f"{rows}</table></div>"
        if rows else "<p class='muted'>No requirement items were extracted from the ticket.</p>"
    )
    who = "AI reviewer" if run.reviewer == "ai" else "deterministic triage only"
    degraded = (f"<p class='muted' style='margin:6px 0 0'>{_e(run.degraded_reason)}</p>"
                if run.degraded_reason else "")
    return f"""<h2>Assessment of this run</h2>
<div class="stats">
<div class="stat"><div class="num" style="color:{tone}">{_e(run.overall)}</div>
<div class="lbl">Overall</div></div>
<div class="stat"><div class="num">{run.coverage_pct}%</div>
<div class="lbl">Ticket requirements covered</div>
<div class="lbl">{run.n_items_decided}/{run.n_items_scored} decided</div></div>
<div class="stat"><div class="num">{run.decided_pct}%</div>
<div class="lbl">Executions decided</div></div>
<div class="stat"><div class="num">{run.n_manual_review}</div>
<div class="lbl">Need a person</div></div>
<div class="stat"><div class="num">{run.n_auto_resolved}</div>
<div class="lbl">Settled by review</div></div>
</div>
<p style="margin:14px 0 4px">{_e(run.summary)}</p>
<p class="muted" style="margin:0 0 12px">Reviewed by: {_e(who)}. A reviewed result is
<b>advisory</b>: it never overwrites the verdict the runner sealed into the evidence chain,
and never creates a finding. Coverage counts a requirement as covered only when a test for
it reached a decisive result &mdash; a plan that touches everything and decides nothing
scores zero here, deliberately.</p>
{degraded}
{items_table}"""


def _plan_review_section(review) -> str:
    """What the reviewing agent said about the plan before it was approved.

    Kept in the report because it is part of why this run tested what it tested.
    An unresolved gap is the honest answer to "why is there no BFLA result here",
    and it should be in the artefact somebody reads six months later, not only in
    the UI at the moment of approval.
    """
    if review is None:
        return ""
    tone = {"APPROVE": "#2f855a", "REVISE": "#b8860b", "INSUFFICIENT": "#b4232a"}.get(
        review.verdict, "#4a5568")
    who = "AI reviewer" if review.reviewer == "ai" else "structural review (no AI)"

    def _gap_list(gaps) -> str:
        if not gaps:
            return "<p class='ok' style='margin:4px 0'>None.</p>"
        return ("<ul style='margin:4px 0 0;padding-left:18px'>"
                + "".join(f"<li><b>{_e(g.severity)}</b> &middot; {_e(g.label())}</li>"
                          for g in gaps)
                + "</ul>")

    strengths = ("<ul style='margin:4px 0 0;padding-left:18px'>"
                 + "".join(f"<li>{_e(s)}</li>" for s in review.strengths) + "</ul>"
                 if review.strengths else "")
    degraded = (f"<p class='muted' style='margin:6px 0 0'>{_e(review.degraded_reason)}</p>"
                if review.degraded_reason else "")
    return f"""<h2>Plan review</h2>
<div class="stats">
<div class="stat"><div class="num" style="color:{tone}">{_e(review.verdict)}</div>
<div class="lbl">Review verdict</div></div>
<div class="stat"><div class="num">{review.coverage_score}%</div>
<div class="lbl">Plan coverage</div></div>
<div class="stat"><div class="num">{review.quality_score}%</div>
<div class="lbl">Decidable tests</div></div>
<div class="stat"><div class="num">{len(review.tests_added)}</div>
<div class="lbl">Added after review</div></div>
</div>
<p style="margin:14px 0 4px">{_e(review.headline())} <span class="muted">Reviewed by
{_e(who)}; {review.tests_before} test(s) reviewed over {review.rounds} revision
round(s).</span></p>
<p class="muted" style="margin:0 0 10px">{_e(review.notes)}</p>
{degraded}
<div class="glabel">Gaps found at review time</div>
{_gap_list(review.gaps)}
<div class="glabel" style="margin-top:10px">Still unresolved</div>
{_gap_list(review.unresolved_gaps)}
{f'<div class="glabel" style="margin-top:10px">Strengths</div>{strengths}' if strengths else ''}"""


_ITEM_COLOR = {
    "COVERED_PASS": "#2f855a", "COVERED_FAIL": "#b4232a", "PARTIAL": "#b8860b",
    "NOT_COVERED": "#b8860b", "NOT_TESTED": "#718096",
}
