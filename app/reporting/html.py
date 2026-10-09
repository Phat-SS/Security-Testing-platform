"""HTML report renderer — dependency-free (no Jinja needed for MVP).

Produces a self-contained, theme-aware report from executions + findings. Every
value shown here has already passed secret redaction upstream.
"""

from __future__ import annotations

import html
import json
from collections import Counter

from app.api.ui.icons import logo
from app.core.i18n import DEFAULT_LANG, VI, t
from app.execution.mutations import MUTATION_KINDS
from app.schemas.execution import Execution
from app.schemas.finding import Finding, cvss_score
from app.schemas.testcase import TestCase

# The Sentinel light palette (app/api/ui/tokens.py), as literal hex: these are
# painted as fills under white text and as text on the page, and every one of
# them clears 4.5:1 against white. A pass is the brand mint and LOW is blue, so
# "low severity" can never be read as "passed".
_SEV_COLOR = {
    "CRITICAL": "#c8102e",
    "HIGH": "#a84a08",
    "MEDIUM": "#8a6400",
    "LOW": "#1d5fd1",
    "INFO": "#566173",
}
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_RESULT_COLOR = {
    "PASS": "#007a61",
    "FAIL": "#c8102e",
    "INCONCLUSIVE": "#8a6400",
    "BLOCKED": "#566173",
    "ERROR": "#566173",
    "SKIPPED": "#647083",
    "TIMEOUT": "#566173",
}


def _e(v) -> str:
    return html.escape(str(v))


def _evidence_chain_banner(chain_ok: bool | None, lang: str) -> str:
    if chain_ok is None:
        # Caller didn't check (e.g. a report built without going through
        # Orchestrator.build_report_html). Absence of a check is not the
        # same as a failed one — say nothing rather than falsely alarm.
        return ""
    if chain_ok:
        return (
            f'<span class="okchip" title="{_e(t("Every execution hash recomputes and links to the previous one.", lang))}">'
            f'&#10003; {t("Evidence Chain Verified", lang)}</span>'
        )
    return (
        '<p style="margin:0 0 18px;padding:10px 14px;border:1px solid #c8102e;'
        'border-radius:8px;background:rgba(200,16,46,.08)"><span style="color:#c8102e;'
        f'font-weight:700">&#9888; {t("Evidence chain FAILED verification", lang)}</span> — '
        + t("at least one execution record's hash no longer matches its content, or the "
            "chain link to the previous record is broken. This report's evidence may have "
            "been altered after it was recorded; treat it as non-authoritative until "
            "investigated.", lang)
        + "</p>"
    )


def _report_quality_banner(verification, lang: str) -> str:
    if verification is None:
        return ""
    if verification.ok:
        return (
            f'<span class="okchip">&#10003; {t("Claims Verified", lang)} &middot; '
            + t("{f} findings, {r} evidence refs", lang).format(
                f=verification.checked_findings, r=verification.checked_references)
            + "</span>"
        )
    errors = sum(1 for issue in verification.issues if issue.severity == "error")
    return (
        '<p style="margin:0 0 18px;padding:10px 14px;border:1px solid #c8102e;'
        'border-radius:8px;background:rgba(200,16,46,.08)"><span style="color:#c8102e;'
        f'font-weight:700">&#9888; {_e("Report quality verification failed")}</span> — '
        f'{errors} blocking issue(s). Treat finding narratives as non-authoritative '
        'until the evidence references are corrected.</p>'
    )


def _input_snapshot_banner(snapshot: dict | None) -> str:
    if not snapshot:
        return ""
    digest = str(snapshot.get("snapshot_hash", ""))[:12]
    if snapshot.get("complete", False):
        return f'<span class="okchip">&#10003; Jira Input Complete <code>{_e(digest)}</code></span>'

    warnings = snapshot.get("warnings") or ["Jira input was incomplete."]
    items = "".join(f"<li>{_e(item)}</li>" for item in warnings)
    return (
        '<div style="margin:0 0 18px;padding:10px 14px;border:1px solid #8a6400;'
        'border-radius:8px;background:rgba(138,100,0,.08)"><b>Jira input incomplete</b>'
        f' — snapshot <code>{_e(digest)}</code>. Coverage cannot be treated as exhaustive.'
        f'<ul>{items}</ul></div>'
    )


def _manifest_banner(manifest) -> str:
    if manifest is None:
        return ""
    if manifest.signed:
        # "Signed" and "verifies right now" are different claims: the former is
        # a fact about how the report was built, the latter is a fact about
        # whether the KEY CONFIGURED ON THIS SERVER, right now, still produces
        # that signature — which is what a reader actually wants to know
        # before trusting the report in front of them, and the only thing the
        # signature is actually FOR. Checking it once at build time and never
        # again would silently stop meaning anything the day the key rotates.
        from app.reporting.manifest import verify_manifest
        verified = verify_manifest(manifest)
        if verified:
            return (f'<span class="okchip">&#10003; Manifest Signed '
                    f'<code>{_e(manifest.signature[:12])}…</code> ({_e(manifest.key_id)})</span>')
        return (
            '<p class="muted" style="margin:0 0 18px">Signed report manifest '
            f'<code>{_e(manifest.signature[:20])}…</code> ({_e(manifest.key_id)}) — '
            '<span style="color:#8a6400">&#9888; does NOT verify against the '
            'currently configured signing key — the key may have rotated, or '
            'this manifest may have been altered</span>.</p>'
        )
    return (
        '<div style="margin:0 0 18px;padding:10px 14px;border:1px solid #8a6400;'
        'border-radius:8px"><b>Unsigned report manifest</b> — configure '
        '<code>REPORT_SIGNING_KEY</code> before distributing this report.</div>'
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
    report_verification=None,
    report_manifest=None,
    input_snapshot: dict | None = None,
    lang: str = DEFAULT_LANG,
    linkback: bool = False,
) -> str:
    """The full document. This is where the *explanation* lives.

    The Jira comment carries the summary and the results table; everything that
    explains a row is here, because here it can sit next to the captured request
    and response it refers to. `plan_review` and `run_assessment` are the two
    reviewing agents' output and are both optional — a report of a run nobody
    asked an agent about simply omits those sections.

    `lang`: "en" or "vi". Chosen per-request (see the language toggle in the
    report itself, `_lang_switch`) and threaded through every section — this
    function never touches a cookie or request object itself, so it stays
    callable from the CLI/demo scripts with no web context at all.
    """
    result_counts = Counter(e.verdict.result.value for e in executions)
    sev_counts = Counter(f.severity.value for f in findings)
    coverage_html = _coverage_section(coverage_rows, lang) if coverage_rows else ""
    assessment_html = _run_assessment_section(run_assessment, lang)
    review_html = _plan_review_section(plan_review, lang)
    adjudications = ({a.execution_id: a for a in run_assessment.adjudications}
                     if run_assessment is not None else {})
    jira_bar = _jira_bar(assessment_id, issue_key, lang) if assessment_id and issue_key else ""
    back_bar = _back_bar(assessment_id, lang) if linkback and assessment_id else ""
    chain_banner = _evidence_chain_banner(evidence_chain_ok, lang) if executions else ""
    quality_banner = _report_quality_banner(report_verification, lang)
    input_banner = _input_snapshot_banner(input_snapshot)
    manifest_banner = _manifest_banner(report_manifest)
    lang_switch = _lang_switch(lang)

    summary_cells = "".join(
        f'<div class="stat"><div class="num">{result_counts.get(k, 0)}</div>'
        f'<div class="lbl">{t(k, lang)}</div></div>'
        for k in ["PASS", "FAIL", "INCONCLUSIVE", "BLOCKED", "ERROR"]
    )
    sev_cells = "".join(
        f'<span class="pill" style="background:{_SEV_COLOR[k]}">{t(k, lang)}: '
        f'{sev_counts.get(k, 0)}</span>'
        for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    # Worst first: the reader of a report starts at the top and may stop
    # there, so the top has to be the thing that most needs fixing.
    ranked = sorted(findings, key=lambda f: _SEV_ORDER.index(f.severity.value)
                    if f.severity.value in _SEV_ORDER else len(_SEV_ORDER))
    findings_html = "\n".join(_finding_block(f, lang) for f in ranked) or (
        f'<p class="ok">{t("No confirmed findings.", lang)}</p>'
    )
    cover_html = _cover(title, target, ranked, result_counts, sev_counts,
                        coverage_rows or [], lang)

    # The re-run control only exists when the report knows which assessment it
    # belongs to — the same gate the Jira bar uses. A report rendered by the CLI
    # or a demo script has no server to post back to, and a button that silently
    # 404s is worse than no button at all.
    rerun_enabled = bool(assessment_id and issue_key)
    # Copying a curl command needs only the assessment (it posts to
    # /assessment/{aid}/execution/curl), not the issue key rerun also needs.
    curl_enabled = bool(assessment_id)
    colspan = 8 if rerun_enabled else 7
    # Executions accumulate, so a test can appear more than once. Only the most
    # recent attempt is re-runnable: an older row is history, and offering to
    # re-run it would send the same request a newer row has already answered.
    latest = {ex.test_id: i for i, ex in enumerate(executions)}
    exec_rows = "\n".join(
        _exec_row(tests.get(e.test_id), e, i, rerun_enabled, curl_enabled, colspan, lang,
                  superseded_by=(None if latest[e.test_id] == i
                                 else executions[latest[e.test_id]]),
                  adjudication=adjudications.get(e.execution_id))
        for i, e in enumerate(executions)
    )
    rerun_head = f"<th>{t('Re-run', lang)}</th>" if rerun_enabled else ""
    rerun_js = _rerun_js(assessment_id, issue_key, lang) if rerun_enabled else ""
    exchange_js = _exchange_js(assessment_id if curl_enabled else None, lang)
    rerun_note = (
        _rerun_note(lang) if rerun_enabled and
        any(e.verdict.result.value == "INCONCLUSIVE" for e in executions) else ""
    )

    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root {{ --bg:#f5f7fa; --paper:#fff; --fg:#0e1520; --muted:#566173; --card:#f5f7fa;
           --border:#e1e6ed; --code:#f0f3f7; --accent:#007a61; --accent-ink:#fff;
           --ink:#0a0e13; --ink-fg:#e8edf3; --ink-muted:#8b97a7; --ink-line:#222c38;
           --display:"Space Grotesk","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
           --mono-f:"JetBrains Mono","Cascadia Code",ui-monospace,Consolas,monospace; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#0a0e13; --paper:#0d1218; --fg:#e8edf3; --muted:#8b97a7; --card:#11171f;
             --border:#222c38; --code:#161e28; --accent:#2ee6b6; --accent-ink:#04221a;
             --ink:#11171f; }} }}
  /* Verdict and severity colours are written inline, from the light palette
     in the _SEV_COLOR/_RESULT_COLOR tables. On the dark page
     those text colours fall under 4.5:1, so each is remapped to its dark
     twin here. Fills under white text keep the light value, which already
     passes on both grounds. */
  @media (prefers-color-scheme: dark) {{
    [style*="color:#c8102e"] {{ color:#ff5468 !important; }}
    [style*="color:#a84a08"] {{ color:#ff9447 !important; }}
    [style*="color:#8a6400"] {{ color:#f2c14e !important; }}
    [style*="color:#1d5fd1"] {{ color:#6ca8ff !important; }}
    [style*="color:#566173"] {{ color:#8b97a7 !important; }}
    [style*="color:#647083"] {{ color:#8b97a7 !important; }}
    [style*="color:#007a61"] {{ color:#2ee6b6 !important; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ font:15px/1.6 "IBM Plex Sans","Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
          margin:0; background:var(--bg); color:var(--fg); }}
  /* clip, not hidden: `overflow:hidden` would make .doc the scroll container
     of the sticky table of contents, and it would scroll away with the page. */
  .doc {{ max-width:1280px; margin:24px auto 80px; background:var(--paper);
          border:1px solid var(--border); border-radius:18px; overflow:clip;
          box-shadow:0 12px 40px rgba(14,21,32,.08); }}
  .doc-body {{ padding:8px 40px 48px; }}
  h1,h2,h3 {{ font-family:var(--display); letter-spacing:-.01em; }}
  h1 {{ font-size:32px; line-height:1.15; margin:0 0 6px; }}
  h2 {{ font-size:21px; margin:40px 0 14px; scroll-margin-top:16px; }}
  a {{ color:var(--accent); }}
  /* cover */
  /* The band is dark in both themes, so the logo's own tokens are pinned to
     their dark values here rather than inherited from the page. */
  .cover {{ background:var(--ink); color:var(--ink-fg); padding:32px 40px 28px;
            --accent:#2ee6b6; --surface:#0a0e13; --crit:#ff5468; }}
  .cover .brand {{ display:flex; align-items:center; gap:10px; font-family:var(--display);
                   font-weight:700; font-size:17px; margin-bottom:24px; }}
  .cover .brand .sp {{ flex:1; }}
  .cover .kicker {{ font-family:var(--mono-f); font-size:12px; color:#2ee6b6; margin:0 0 8px; }}
  .cover .sub {{ color:var(--ink-muted); margin:0; }}
  .cover code {{ background:transparent; color:var(--ink-fg); padding:0; }}
  .risk {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px;
           margin:24px 0 18px; }}
  .risk .cell {{ border:1px solid var(--ink-line); border-radius:14px; padding:14px 16px;
                 background:rgba(255,255,255,.02); }}
  .risk .cell .k {{ font-size:12px; color:var(--ink-muted); }}
  .risk .cell .v {{ font-family:var(--display); font-size:26px; font-weight:700; }}
  .sevbar {{ display:flex; height:10px; border-radius:999px; overflow:hidden; background:var(--ink-line); }}
  .sevbar span {{ display:block; height:100%; animation:grow 1s cubic-bezier(.2,.8,.2,1) both;
                  transform-origin:left; }}
  .sevlegend {{ display:flex; gap:16px; flex-wrap:wrap; font-size:12px; color:var(--ink-muted);
                margin-top:8px; }}
  .toc {{ display:flex; gap:6px; flex-wrap:wrap; padding:14px 40px; border-bottom:1px solid var(--border);
          position:sticky; top:0; background:var(--paper); z-index:5; }}
  .toc a {{ padding:5px 11px; border-radius:8px; color:var(--muted); text-decoration:none;
            font-size:13px; font-weight:600; }}
  .toc a:hover {{ background:var(--card); color:var(--fg); }}
  .integrity {{ display:flex; flex-wrap:wrap; gap:8px; align-items:flex-start; margin:18px 0 0; }}
  .integrity > p, .integrity > div {{ flex-basis:100%; }}
  .okchip {{ display:inline-flex; align-items:center; gap:6px; padding:5px 11px; border-radius:999px;
             font-size:12.5px; font-weight:600; color:var(--accent); background:var(--card);
             border:1px solid var(--border); }}
  .okchip code {{ font-size:11.5px; }}
  @keyframes grow {{ from {{ transform:scaleX(0); }} to {{ transform:scaleX(1); }} }}
  @keyframes rise {{ from {{ opacity:0; transform:translateY(8px); }} to {{ opacity:1; transform:none; }} }}
  .langswitch {{ font-size:12.5px; color:var(--muted); white-space:nowrap; margin-top:4px; }}
  .langswitch a {{ color:var(--muted); text-decoration:none; padding:2px 6px; border-radius:5px; }}
  .cover .langswitch a {{ color:var(--ink-muted); }}
  .langswitch a.active, .cover .langswitch a.active {{ color:#04221a; background:#2ee6b6; font-weight:600; }}
  .langswitch a:not(.active):hover {{ background:var(--card); }}
  .cover .langswitch a:not(.active):hover {{ background:var(--ink-line); color:var(--ink-fg); }}
  .stats {{ display:flex; gap:10px; flex-wrap:wrap; }}
  .stat {{ background:var(--card); border:1px solid var(--border); border-radius:14px;
           padding:14px 18px; min-width:110px; text-align:center; animation:rise .32s cubic-bezier(.2,.8,.2,1) both; }}
  .num {{ font-family:var(--display); font-size:26px; font-weight:700; }} .lbl {{ color:var(--muted); font-size:12px; }}
  .pills {{ margin:14px 0; display:flex; gap:8px; flex-wrap:wrap; }}
  .pill {{ color:#fff; border-radius:999px; padding:3px 11px; font-size:12px; font-weight:600; }}
  .finding {{ background:var(--paper); border:1px solid var(--border);
              border-radius:14px; padding:18px 20px; margin:14px 0; break-inside:avoid;
              animation:rise .32s cubic-bezier(.2,.8,.2,1) both; }}
  .finding .fhead {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:6px; }}
  .finding .fid {{ font-family:var(--mono-f); font-size:12px; color:var(--muted); }}
  .finding h3 {{ margin:0 0 12px; font-size:18px; }}
  .kv {{ display:grid; grid-template-columns:130px 1fr; gap:4px 12px; font-size:14px; }}
  .kv b {{ color:var(--muted); font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .tblwrap {{ overflow-x:auto; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--border); }}
  th {{ color:var(--muted); font-weight:600; }}
  code {{ background:var(--code); padding:1px 5px; border-radius:4px; font-size:12.5px; }}
  .res {{ font-weight:700; }} .ok {{ color:var(--accent); }}
  .mono {{ font-family:var(--mono-f); }}
  .bar {{ background:var(--border); border-radius:6px; height:10px; width:140px; overflow:hidden; }}
  .fill {{ height:100%; border-radius:6px; }}
  .backlink {{ display:inline-block; color:var(--muted); text-decoration:none; font-size:13px;
               font-weight:600; margin:0 0 14px; }}
  .backlink:hover {{ color:var(--accent); }}
  .jirabar {{ display:flex; align-items:center; gap:12px; margin:16px 0 26px; }}
  .jirabar button {{ background:var(--accent); color:var(--accent-ink); border:0; border-radius:8px; padding:9px 16px;
                      font:inherit; font-size:14px; font-weight:600; cursor:pointer; }}
  .jirabar button:disabled {{ opacity:.6; cursor:default; }}
  .jira-status {{ font-size:13px; color:var(--muted); }}
  .jira-status.err {{ color:#c8102e; }}
  .muted {{ color:var(--muted); }}
  details.resp summary {{ cursor:pointer; color:var(--muted); font-size:12.5px; user-select:none; }}
  .glabel {{ color:var(--muted); font-size:12px; font-weight:600; margin:0 0 2px; }}
  .respbody {{ max-height:180px; overflow:auto; background:var(--code); padding:8px 10px;
               border-radius:6px; margin:2px 0 8px; white-space:pre-wrap; word-break:break-word;
               font-size:12px; }}
  /* The exchange itself (request/response for the attack row) gets its own,
     much roomier presentation: a full-width panel under the row instead of a
     collapsible sliver squeezed into one table cell next to five others. */
  .exchange-toggle {{ background:var(--card); color:inherit; border:1px solid var(--border);
                       border-radius:7px; padding:5px 11px; font:inherit; font-size:12.5px;
                       font-weight:600; cursor:pointer; white-space:nowrap; }}
  .exchange-toggle:hover {{ border-color:var(--accent); color:var(--accent); }}
  tr.exchange-row td {{ padding:0; border-bottom:1px solid var(--border); }}
  .exchange-panes {{ display:grid; grid-template-columns:1fr 1fr; }}
  @media (max-width:900px) {{ .exchange-panes {{ grid-template-columns:1fr; }} }}
  .exchange-pane {{ padding:16px 20px; border-right:1px solid var(--border); min-width:0; }}
  .exchange-pane:last-child {{ border-right:none; }}
  .exchange-pane h4 {{ margin:0 0 10px; font-size:13px; color:var(--muted); font-weight:600;
                       display:flex; justify-content:space-between; align-items:center; gap:10px; }}
  .exbody {{ max-height:55vh; overflow:auto; background:var(--code); padding:10px 12px;
             border-radius:8px; margin:2px 0 14px; white-space:pre-wrap; word-break:break-word;
             font-size:13px; line-height:1.55; }}
  .curlbtn {{ background:var(--accent); color:var(--accent-ink); border:0; border-radius:7px; padding:6px 13px;
              font:inherit; font-size:12px; font-weight:600; cursor:pointer; white-space:nowrap; }}
  .curlbtn:hover {{ opacity:.88; }} .curlbtn:disabled {{ opacity:.6; cursor:default; }}
  .curlnote {{ font-size:12px; color:var(--muted); min-height:1.4em; margin:0 0 8px; }}
  .curlnote.err {{ color:#c8102e; }}
  td.rerun {{ white-space:nowrap; vertical-align:top; }}
  .rerunbtn {{ background:var(--card); color:inherit; border:1px solid var(--border);
               border-radius:7px; padding:5px 11px; font:inherit; font-size:12.5px;
               font-weight:600; cursor:pointer; }}
  .rerunbtn:enabled:hover {{ border-color:var(--accent); color:var(--accent); }}
  .rerunbtn:disabled {{ opacity:.55; cursor:default; }}
  .rerunout {{ font-size:12px; line-height:1.5; margin-top:6px; max-width:220px;
               white-space:normal; }}
  /* An agent's reading of a row, set apart from the verdict above it: an
     opinion and a sealed verdict must not look like the same kind of claim. */
  .adj {{ border-left:3px solid var(--border); background:var(--card); border-radius:0 6px 6px 0;
          padding:8px 10px; margin:8px 0 4px; font-size:12.5px; }}
  .adj ul {{ font-size:12px; }}
  .rerunout .err {{ color:#c8102e; }}
  .rerunout a {{ color:var(--accent); }}
  .spin {{ display:inline-block; width:10px; height:10px; border:2px solid var(--border);
           border-top-color:var(--accent); border-radius:50%; vertical-align:-1px;
           animation:spin .7s linear infinite; }}
  @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
  @media (prefers-reduced-motion:reduce) {{ *, *::before {{ animation:none !important; }} }}
  @media (max-width:700px) {{ .doc-body, .cover, .toc {{ padding-left:16px; padding-right:16px; }}
    .doc {{ margin:0; border-radius:0; }} .kv {{ grid-template-columns:1fr; }} }}
  @media print {{
    body {{ background:#fff; }} .doc {{ margin:0; border:0; box-shadow:none; max-width:none; }}
    .toc, .jirabar, .langswitch, .backlink, .rerunbtn, .exchange-toggle, .curlbtn,
    td.rerun, .rerunout {{ display:none !important; }}
    .cover {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
    * {{ animation:none !important; }}
    h2 {{ break-after:avoid; }}
  }}
</style></head><body><article class="doc">
{cover_html.replace("<!--lang-->", lang_switch)}
<nav class="toc" aria-label="{t("Report Sections", lang)}">
<a href="#summary">{t("Executive Summary", lang)}</a>
<a href="#findings">{t("Findings", lang)}</a>
{f'<a href="#coverage">{t("Coverage", lang)}</a>' if coverage_html else ''}
<a href="#log">{t("Execution Log", lang)}</a>
</nav>
<div class="doc-body">
{back_bar}
{jira_bar}
<div class="integrity">{chain_banner}{quality_banner}{input_banner}{manifest_banner}</div>
<h2 id="summary">{t("Executive Summary", lang)}</h2>
<div class="stats">{summary_cells}</div>
<div class="pills">{sev_cells}</div>
{assessment_html}
<div id="coverage">{coverage_html}</div>
{review_html}
<h2 id="findings">{t("Findings", lang)}</h2>
{findings_html}

<h2 id="log">{t("Execution Log", lang)}</h2>
{rerun_note}
<div class="tblwrap"><table>
<tr><th>{t("Test", lang)}</th><th>OWASP</th><th>{t("Result", lang)}</th><th>{t("Confidence", lang)}</th><th>{t("Status", lang)}</th>
<th>{t("Exchange", lang)}</th><th>{t("Reason", lang)}</th>{rerun_head}</tr>
{exec_rows}
</table></div>
{rerun_js}
{exchange_js}
</div></article></body></html>"""


def _cover(title: str, target: str, findings: list[Finding], result_counts: Counter,
           sev_counts: Counter, coverage_rows: list[dict], lang: str) -> str:
    """The dark band at the top: what was tested, and how bad it is, in one look.

    `findings` arrives ranked worst-first, so the overall risk is simply the
    first finding's severity. A run with no confirmed finding says so in words,
    not with an empty colour.
    """
    if findings:
        worst = findings[0].severity.value
        risk = (f'<div class="v" style="color:{_SEV_COLOR.get(worst, "#e8edf3")};'
                f'filter:brightness(1.6)">{t(worst.title(), lang)}</div>')
    elif any(result_counts.get(k) for k in ("INCONCLUSIVE", "BLOCKED", "ERROR")):
        # No finding is not the same as no risk: a run whose results were not
        # decided has not shown the target is safe, and a green "None" on the
        # cover would be read as exactly that.
        risk = f'<div class="v" style="color:#f2c14e">{t("Undetermined", lang)}</div>'
    else:
        risk = f'<div class="v" style="color:#2ee6b6">{t("None Found", lang)}</div>'
    applicable = [r for r in coverage_rows if r.get("applicable")]
    covered = sum(1 for r in applicable if r.get("state") == "COVERED")
    coverage = f"{covered} / {len(applicable)}" if applicable else "&mdash;"
    total = sum(sev_counts.values())
    bar = "".join(
        f'<span style="width:{100 * sev_counts[k] / total:.1f}%;background:{_SEV_COLOR[k]};'
        f'filter:brightness(1.35)"></span>'
        for k in _SEV_ORDER if sev_counts.get(k)
    ) if total else ""
    # Every band in the bar has a legend entry; INFO only when it is there,
    # so a normal report keeps the four that matter.
    legend = "".join(
        f"<span>{t(k.title(), lang)} {sev_counts.get(k, 0)}</span>"
        for k in _SEV_ORDER if k != "INFO" or sev_counts.get(k)
    )
    return f"""<header class="cover">
<div class="brand">{logo(28)}<span>Sentinel</span><span class="sp"></span><!--lang--></div>
<p class="kicker">OWASP API Security Top 10 (2023)</p>
<h1>{_e(title)}</h1>
<p class="sub">{t("Target", lang)}: <code>{_e(target)}</code></p>
<div class="risk">
<div class="cell"><div class="k">{t("Overall Risk", lang)}</div>{risk}</div>
<div class="cell"><div class="k">{t("Findings", lang)}</div><div class="v">{len(findings)}</div></div>
<div class="cell"><div class="k">{t("Tests Run", lang)}</div><div class="v">{sum(result_counts.values())}</div></div>
<div class="cell"><div class="k">{t("Coverage", lang)}</div><div class="v">{coverage}</div></div>
</div>
{f'<div class="sevbar">{bar}</div><div class="sevlegend">{legend}</div>' if bar else ''}
</header>"""


def _lang_switch(lang: str) -> str:
    """EN/VI toggle for a report opened on its own (its own tab, a saved file,
    a link from Jira) — the report cannot rely on the main app's nav bar, so it
    carries its own switch. Reloads the SAME report with `?lang=..`; the route
    serving it (see app/api/main.py) also sets the `lang` cookie from this
    query param, so the choice carries over to the next report/page too."""
    def _link(code: str, label: str) -> str:
        cls = "active" if lang == code else ""
        return f'<a class="{cls}" href="?lang={code}">{label}</a>'

    return f'<div class="langswitch">{_link("en", "EN")} &middot; {_link("vi", "VI")}</div>'


def _back_bar(assessment_id: str, lang: str) -> str:
    """A way back to the assessment this report was built from.

    The report is a standalone document and was always *opened* as one — a new
    tab from the assessment page, a link out of Jira — so the tab it came from
    was still there to return to. A run now hands over to this page directly,
    in the tab the tester was already in, and without this there is nothing on
    the page that leads anywhere but the browser's own Back button.

    Asked for explicitly by the route that serves the live report, rather than
    gated on `assessment_id` the way the Jira bar and the re-run controls are:
    those come out dead in a downloaded copy too, but a button that does nothing
    is a smaller lie than a navigation link pointing out of a file:// document
    at a server that is not there.
    """
    return (
        f'<a class="backlink" href="/assessment/{_e(assessment_id)}?phase=results">'
        f'&larr; {t("Back to the Assessment", lang)}</a>'
    )


def _jira_bar(assessment_id: str, issue_key: str, lang: str) -> str:
    """A one-click 'post this exact report's summary as a Jira comment' action.
    Uses fetch so the report — a standalone document, possibly opened in its
    own tab — never has to navigate away to post. Posts to the same endpoint
    the assessment page's "Preview Jira Comment" flow uses, so it always lands
    on assessment.issue_key: the ticket this report was generated from."""
    key = _e(issue_key)
    # aid is interpolated into a JS string literal inside <script>, not HTML —
    # json.dumps is the correct escaping for that context (html.escape only
    # happens to be safe here today because assessment_id is always a
    # server-generated UUID hex, never attacker-influenced text).
    aid_js = json.dumps(assessment_id)
    btn_label = t("Post This Report to Jira ({key})", lang).format(key=key)
    posting = t("Posting…", lang)
    posted = t("Posted to Jira", lang)
    failed = t("Failed to post — open the assessment page for details.", lang)
    net_err = t("Network error — try again.", lang)
    return f"""<div class="jirabar">
<button id="jira-btn" onclick="postToJira()">{btn_label}</button>
<span id="jira-status" class="jira-status"></span>
</div>
<script>
function postToJira() {{
  var btn = document.getElementById('jira-btn');
  var status = document.getElementById('jira-status');
  var original = btn.textContent;
  btn.disabled = true;
  btn.textContent = {json.dumps(posting)};
  status.className = 'jira-status';
  status.textContent = '';
  fetch('/assessment/' + {aid_js} + '/comment', {{ method: 'POST' }})
    .then(function (r) {{
      if (r.ok) {{
        btn.textContent = {json.dumps(posted)};
      }} else {{
        btn.disabled = false;
        btn.textContent = original;
        status.textContent = {json.dumps(failed)};
        status.className = 'jira-status err';
      }}
    }})
    .catch(function () {{
      btn.disabled = false;
      btn.textContent = original;
      status.textContent = {json.dumps(net_err)};
      status.className = 'jira-status err';
    }});
}}
</script>"""


_COVERAGE_COLOR = {
    "COVERED": "#007a61", "PARTIAL": "#8a6400", "MISSING": "#c8102e",
    "NOT_APPLICABLE": "#647083",
}


def _status_color(status_code: int) -> str:
    if status_code < 300:
        return "#007a61"
    if status_code < 400:
        return "#566173"
    if status_code < 500:
        return "#8a6400"
    return "#c8102e"


def _coverage_section(rows: list[dict], lang: str) -> str:
    applicable = [r for r in rows if r.get("applicable")]
    body = ""
    for r in rows:
        state = r.get("state", "UNKNOWN")
        color = _COVERAGE_COLOR.get(state, "#647083")
        pct = r.get("pct", 0)
        bar_w = pct if state != "NOT_APPLICABLE" else 0
        # "COVERED" is reached by one test in the category — this is depth, the
        # honest answer to "COVERED with how many of the known techniques?".
        # Without it a single drop_auth test reads as the whole of API2.
        depth_pct = r.get("depth_pct", 0)
        missing = r.get("techniques_missing") or ()
        depth_cell = (
            f"<div class='bar' title='{_e(', '.join(missing)) or t('none — every known technique is exercised', lang)}'>"
            f"<div class='fill' style='width:{depth_pct}%;background:{color}'></div></div>"
            f"<span class='muted' style='font-size:11px'>{depth_pct}%"
            + (f" &middot; {t('missing', lang)}: {_e(', '.join(missing[:4]))}"
               + (f" (+{len(missing) - 4})" if len(missing) > 4 else "")
               if missing else "")
            + "</span>"
        ) if state != "NOT_APPLICABLE" else "<span class='muted'>&mdash;</span>"
        body += (
            f"<tr><td><b>{_e(r.get('category'))}</b></td>"
            f"<td>{_e(r.get('existing_tests', 0))}</td>"
            f"<td>{_e(r.get('generated_tests', 0))}</td>"
            f"<td style='color:{color};font-weight:700'>{t(state, lang)}</td>"
            f"<td><div class='bar'><div class='fill' style='width:{bar_w}%;"
            f"background:{color}'></div></div></td>"
            f"<td>{depth_cell}</td></tr>"
        )
    heading = t("OWASP API Security Coverage ({n} Applicable)", lang).format(n=len(applicable))
    depth_th = (
        f'<th title="{t("What share of the known attack techniques for this category were actually tried — a category can read COVERED from a single test while most of its techniques were never attempted", lang)}">'
        f"{t('Depth', lang)}</th>"
    )
    return f"""<h2>{heading}</h2>
<div class="tblwrap"><table>
<tr><th>{t("Category", lang)}</th><th>{t("Existing PoC", lang)}</th><th>{t("Generated", lang)}</th><th>{t("State", lang)}</th><th>{t("Coverage", lang)}</th>{depth_th}</tr>
{body}</table></div>"""


def _finding_block(f: Finding, lang: str) -> str:
    color = _SEV_COLOR[f.severity.value]
    repro = "".join(f"<li>{_e(s)}</li>" for s in f.reproduction)
    refs = " · ".join(f'<a href="{_e(r)}">{_e(r)}</a>' if r.startswith("http") else _e(r)
                      for r in f.references)
    score = cvss_score(f.severity)
    return f"""<div class="finding">
<div class="fhead"><span class="pill" style="background:{color}">{t(f.severity.value, lang)} &middot; {score}</span>
<span class="fid">{_e(f.finding_id)} &middot; {_e(f.owasp_category.value)}</span></div>
<h3>{_e(f.title)}</h3>
<div class="kv">
<b>OWASP</b><span>{_e(f.owasp_category.value)}</span>
<b>{t("Endpoint", lang)}</b><span><code>{_e(f.endpoint)}</code></span>
<b>{t("Confidence", lang)}</b><span>{t(f.confidence.value, lang)}</span>
{f'<b>{t("CVSS (estimated)", lang)}</b><span class="mono" style="font-size:12px">{_e(f.cvss_vector)}</span>' if f.cvss_vector else ''}
<b>{t("Affected Tests", lang)}</b><span>{_e(', '.join(f.affected_tests))}</span>
<b>{t("Expected", lang)}</b><span>{_e(f.correlation.expected)}</span>
<b>{t("Actual", lang)}</b><span>{_e(f.correlation.actual)}</span>
<b>{t("Impact", lang)}</b><span>{_e(f.impact)}</span>
<b>{t("Recommendation", lang)}</b><span>{_e(f.recommendation)}</span>
<b>{t("Reproduction", lang)}</b><span><ol>{repro}</ol></span>
<b>{t("References", lang)}</b><span>{refs}</span>
</div></div>"""


def _exec_row(test: TestCase | None, e: Execution, index: int = 0,
              rerun_enabled: bool = False, curl_enabled: bool = False,
              colspan: int = 7, lang: str = DEFAULT_LANG,
              superseded_by: Execution | None = None,
              adjudication=None) -> str:
    color = _RESULT_COLOR.get(e.verdict.result.value, "#566173")
    title = _e(test.title) if test else _e(e.test_id)
    if e.response is not None:
        r = e.response
        status_color = _status_color(r.status_code)
        status_cell = (
            f"<span class='res' style='color:{status_color}'>{r.status_code}</span>"
            f"<br><span class='muted mono' style='font-size:11px'>"
            f"{r.elapsed_ms} ms &middot; {r.size_bytes} B</span>"
        )
    else:
        status_cell = "<span class='muted'>&mdash;</span>"

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
        _attack_html(test, e, lang)
        + _expectation_html(e, lang)
        + f"<p style='margin:6px 0'>{_e(e.verdict.reason)}</p>"
        + _adjudication_html(adjudication, lang)
        + _supporting_html(e, lang)
    )
    rerun_cell = _rerun_cell(test, e, index, lang, superseded_by) if rerun_enabled else ""
    summary_row = (
        f"<tr><td><b>{_e(e.test_id)}</b><br><span class='mono'>{title}</span></td>"
        f"<td>{_e(e.owasp_category)}</td>"
        f"<td class='res' style='color:{color}'>{t(e.verdict.result.value, lang)}</td>"
        f"<td>{t(e.verdict.confidence.value, lang)}</td>"
        f"<td>{status_cell}</td>"
        f"<td><button type='button' class='exchange-toggle' "
        f"data-exchange-toggle='{index}' aria-expanded='false' "
        f"data-label-view=\"{_e(t('View Exchange', lang))}\" "
        f"data-label-hide=\"{_e(t('Hide Exchange', lang))}\">"
        f"{t('View Exchange', lang)} &#9662;</button></td>"
        f"<td>{reason_cell}</td>{rerun_cell}</tr>"
    )
    # A full-width panel under the row, not a sliver squeezed into one table
    # cell next to five others — request and response each get real room to
    # read, side by side, independently scrollable.
    return summary_row + "\n" + _exchange_row(e, index, colspan, curl_enabled, lang)


def _exchange_row(e: Execution, index: int, colspan: int, curl_enabled: bool, lang: str) -> str:
    if e.response is not None:
        r = e.response
        resp_headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        resp_body = r.body if r.body else t("(empty body)", lang)
        response_pane = (
            "<div class='exchange-pane'>"
            f"<h4>{t('Response', lang)} <span class='muted' style='font-weight:400;text-transform:none;"
            f"letter-spacing:normal'>HTTP {r.status_code} &middot; {r.elapsed_ms} ms &middot; "
            f"{r.size_bytes} B</span></h4>"
            f"<div class='glabel'>{t('Headers', lang)}</div>"
            f"<pre class='exbody'>{_e(resp_headers) or t('(none)', lang)}</pre>"
            f"<div class='glabel'>{t('Body', lang)}</div>"
            f"<pre class='exbody'>{_e(resp_body)}</pre>"
            "</div>"
        )
    else:
        response_pane = (
            f"<div class='exchange-pane'><h4>{t('Response', lang)}</h4>"
            f"<p class='muted'>{t('Blocked before send.', lang)}</p></div>"
        )

    # The attack request exactly as it was recorded — URL (query included),
    # every header, the body.
    #
    # Says plainly that credentials are masked. A reader who did not know that
    # would read `Authorization: ********` as "the runner sent no credential" and
    # conclude the test never authenticated at all — the opposite of what
    # happened, and enough to make every verdict here look unsound.
    rq = e.request
    req_headers = "\n".join(f"{k}: {v}" for k, v in rq.headers.items())
    req_body = rq.body if rq.body else t("(no body)", lang)
    note = (f"<p class='muted' style='margin:0 0 10px'>{_e(e.attack_note)}</p>"
            if e.attack_note else "")
    curl_button = (
        f"<button type='button' class='curlbtn' data-curl='{_e(e.execution_id)}' "
        f"data-curl-slot='{index}'>{t('Copy cURL', lang)}</button>"
        if curl_enabled else ""
    )
    curl_note = f"<p class='curlnote' id='curl-note-{index}'></p>" if curl_enabled else ""
    credentials_note = t(
        "Credentials are masked (<code>********</code>) above before anything is stored.", lang
    )
    copy_curl_note = (
        " " + t(
            "<b>Copy cURL</b> resolves the real credential from the persona vault live "
            "when clicked — it is never written into this report, and only works from a "
            "report the platform is currently serving, not a saved copy of it.", lang
        )
        if curl_enabled else ""
    )
    request_pane = (
        "<div class='exchange-pane'>"
        f"<h4>{t('Request', lang)}{curl_button}</h4>"
        f"{note}"
        f"<div class='glabel'>{_e(rq.method)}</div>"
        f"<pre class='exbody' style='max-height:80px'>{_e(rq.url)}</pre>"
        f"<div class='glabel'>{t('Headers', lang)}</div>"
        f"<pre class='exbody'>{_e(req_headers) or t('(none)', lang)}</pre>"
        f"<div class='glabel'>{t('Body', lang)}</div>"
        f"<pre class='exbody'>{_e(req_body)}</pre>"
        f"{curl_note}"
        f"<p class='muted' style='margin:0'>{credentials_note}{copy_curl_note}</p></div>"
    )
    return (
        f"<tr class='exchange-row' id='exchange-row-{index}' style='display:none'>"
        f"<td colspan='{colspan}'><div class='exchange-panes'>{response_pane}{request_pane}"
        "</div></td></tr>"
    )


# -- re-running one undecided request ---------------------------------------
#
# INCONCLUSIVE is the runner declining to guess, and the common ways to get
# there are transient: the positive control failed, the server answered 5xx, or
# the attack was accepted but no protected marker was available to prove
# disclosure. Re-running a whole plan to settle one row is disproportionate, so
# each undecided row can be sent again on its own.


def _rerun_note(lang: str) -> str:
    body = t(
        "Rows judged <b>INCONCLUSIVE</b> can be sent again on their own. A re-run replays "
        "the <b>test</b> through the trusted runner &mdash; the same method, path, query, "
        "headers and body, with the persona's real credential resolved from the vault at "
        "send time, because the headers and body recorded here are redacted and cannot be "
        "replayed byte-for-byte. Nothing below is overwritten: the result is appended to "
        "this log as a new execution, chained onto the previous one's evidence hash, so "
        "both attempts stay on the record. Reload the report to see the new row.", lang
    )
    return f'<p class="muted" style="margin:0 0 12px">{body}</p>'


def _rerun_cell(test: TestCase | None, e: Execution, index: int, lang: str,
                superseded_by: Execution | None = None) -> str:
    if e.verdict.result.value != "INCONCLUSIVE":
        return "<td class='rerun'><span class='muted'>&mdash;</span></td>"
    if superseded_by is not None:
        # This row was already sent again. Say what came back rather than offer
        # a button that would re-send a request a later row has answered — and
        # do not restate the row's own verdict as if it were still open.
        later = superseded_by.verdict.result.value
        color = _RESULT_COLOR.get(later, "#566173")
        label = t("re-run below:", lang)
        return (f"<td class='rerun'><span class='muted' style='font-size:12px'>{label} "
                f"<b style='color:{color}'>{t(later, lang)}</b></span></td>")
    if test is None:
        # The plan no longer holds this test, so there is nothing to send. Say
        # so here rather than offering a button the server would only refuse.
        return ("<td class='rerun'><span class='muted' style='font-size:12px'>"
                f"{t('no longer in the plan', lang)}</span></td>")
    destructive = "1" if test.is_destructive else "0"
    return (
        "<td class='rerun'><button type='button' class='rerunbtn' "
        f"data-rerun=\"{_e(e.execution_id)}\" data-test=\"{_e(e.test_id)}\" "
        f"data-destructive=\"{destructive}\" data-slot=\"{index}\">"
        f"&#8635; {t('Re-run', lang)}</button>"
        f"<div class='rerunout' id='rerun-out-{index}'></div></td>"
    )


def _rerun_js(assessment_id: str, issue_key: str, lang: str) -> str:
    """Post one execution back to the platform and report the new verdict in place.

    fetch, not a form: the report is a standalone document that may be open in
    its own tab, and navigating away to settle one row would lose the reader's
    place in a log they are working through.
    """
    aid_js = json.dumps(assessment_id)
    key_js = json.dumps(issue_key)
    colors_js = json.dumps(_RESULT_COLOR)
    strings_js = json.dumps({
        "was": t("was", lang),
        "unchanged": t("unchanged", lang),
        "reload": t("Reload the Log", lang),
        "refused": t("The platform refused this re-run.", lang),
        "destructive_confirm": t(
            "Re-running {test} sends a real state-changing request that can create, "
            "modify or delete data on the target. Type {issue} to confirm.", lang),
        "mismatch": t("Issue key did not match — cancelled, nothing was sent.", lang),
        "confirm_rerun": t(
            "Re-run {test} on its own?\n\nSends the same request again through the "
            "trusted runner, with live persona credentials. This record is kept exactly "
            "as it is; the result is appended to the log as a new execution.", lang),
        "sending": t("Sending…", lang),
        "rerun_again": t("Re-run Again", lang),
        "unreachable": t(
            "Could not reach the platform. Re-running works from a report served by the "
            "app, not from a saved copy.", lang),
    })
    return f"""<script>
(function () {{
  var AID = {aid_js}, ISSUE = {key_js}, COLOR = {colors_js}, STR = {strings_js};

  function esc(text) {{
    var d = document.createElement('div');
    d.textContent = text === null || text === undefined ? '' : String(text);
    return d.innerHTML;
  }}

  function render(out, data) {{
    var color = COLOR[data.result] || '#566173';
    var meta = [data.confidence];
    if (data.status_code !== null && data.status_code !== undefined) {{
      meta.push('HTTP ' + data.status_code);
    }}
    if (data.elapsed_ms !== null && data.elapsed_ms !== undefined) {{
      meta.push(data.elapsed_ms + ' ms');
    }}
    out.innerHTML =
      '<b style="color:' + color + '">' + esc(data.result) + '</b> · ' +
      esc(meta.join(' · ')) +
      (data.changed
        ? '<div class="muted">' + STR.was + ' ' + esc(data.previous_result) + '</div>'
        : '<div class="muted">' + STR.unchanged + '</div>') +
      '<div class="muted">' + esc(data.reason) + '</div>' +
      '<a href="#" onclick="location.reload();return false;">' + STR.reload + '</a>';
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
          STR.destructive_confirm.replace('{{test}}', testId).replace('{{issue}}', ISSUE)
        );
        if (typed === null) return;
        if (typed.trim() !== ISSUE) {{
          alert(STR.mismatch);
          return;
        }}
        confirmToken = typed.trim();
      }} else if (!confirm(STR.confirm_rerun.replace('{{test}}', testId))) {{
        return;
      }}

      btn.disabled = true;
      out.innerHTML = '<span class="spin"></span> ' + STR.sending;

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
            btn.innerHTML = '&#8635; ' + STR.rerun_again;
            return;
          }}
          out.innerHTML = '<span class="err">' +
            esc(res.data.error || STR.refused) + '</span>';
        }})
        .catch(function () {{
          btn.disabled = false;
          out.innerHTML = '<span class="err">' + STR.unreachable + '</span>';
        }});
    }});
  }});
}})();
</script>"""


# -- viewing and copying the exchange -----------------------------------------
#
# Two independent behaviours, always present regardless of rerun_enabled:
#   * the toggle is pure client-side (no server round trip, works from any
#     saved copy of the report) — every row can open its full-width panel.
#   * Copy cURL needs the live platform (AID is null in a report rendered
#     without an assessment_id, e.g. by the CLI) because building a command
#     that actually authenticates means resolving a real credential from the
#     persona vault at click time — see build_curl in orchestrator.py.


def _exchange_js(assessment_id: str | None, lang: str) -> str:
    aid_js = json.dumps(assessment_id) if assessment_id else "null"
    strings_js = json.dumps({
        "fetching": t("Fetching…", lang),
        "no_curl": t("Could not build a curl command.", lang),
        "copied": t("Copied — includes a live credential, handle it like one.", lang),
        "copy_failed": t("Could not copy automatically — command is in the console (F12).", lang),
        "unreachable": t(
            "Could not reach the platform — this only works from a report the app is "
            "serving, not a saved copy.", lang),
    })
    return f"""<script>
(function () {{
  var AID = {aid_js}, STR = {strings_js};

  document.querySelectorAll('[data-exchange-toggle]').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      var row = document.getElementById('exchange-row-' + btn.getAttribute('data-exchange-toggle'));
      if (!row) return;
      var open = row.style.display !== 'none';
      row.style.display = open ? 'none' : 'table-row';
      btn.setAttribute('aria-expanded', String(!open));
      btn.innerHTML = (open ? btn.getAttribute('data-label-view') : btn.getAttribute('data-label-hide'))
        + (open ? ' &#9662;' : ' &#9652;');
    }});
  }});

  function copyText(text) {{
    if (navigator.clipboard && window.isSecureContext) {{
      return navigator.clipboard.writeText(text);
    }}
    // Secure-context clipboard API is unavailable (e.g. plain http://) —
    // fall back to the classic hidden-textarea + execCommand trick.
    return new Promise(function (resolve, reject) {{
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      var ok = false;
      try {{ ok = document.execCommand('copy'); }} catch (e) {{ ok = false; }}
      document.body.removeChild(ta);
      if (ok) resolve(); else reject(new Error('execCommand failed'));
    }});
  }}

  document.querySelectorAll('[data-curl]').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      if (!AID) return;
      var execId = btn.getAttribute('data-curl');
      var note = document.getElementById('curl-note-' + btn.getAttribute('data-curl-slot'));
      var original = btn.textContent;
      btn.disabled = true;
      btn.textContent = STR.fetching;
      if (note) {{ note.textContent = ''; note.className = 'curlnote'; }}

      var payload = new URLSearchParams();
      payload.set('execution_id', execId);

      fetch('/assessment/' + encodeURIComponent(AID) + '/execution/curl', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
        body: payload.toString()
      }})
        .then(function (r) {{
          return r.json().then(function (d) {{ return {{ ok: r.ok, data: d }}; }});
        }})
        .then(function (res) {{
          btn.disabled = false;
          btn.textContent = original;
          if (!res.ok || !res.data.ok) {{
            if (note) {{
              note.textContent = (res.data && res.data.error) || STR.no_curl;
              note.className = 'curlnote err';
            }}
            return;
          }}
          copyText(res.data.curl).then(function () {{
            if (note) {{
              note.textContent = STR.copied;
              note.className = 'curlnote';
            }}
          }}).catch(function () {{
            if (note) {{
              note.textContent = STR.copy_failed;
              note.className = 'curlnote err';
            }}
            console.log(res.data.curl);
          }});
        }})
        .catch(function () {{
          btn.disabled = false;
          btn.textContent = original;
          if (note) {{
            note.textContent = STR.unreachable;
            note.className = 'curlnote err';
          }}
        }});
    }});
  }});
}})();
</script>"""


_SUPPORTING_LABEL = {
    "baseline": "Positive Control",
    "verification": "Verification Read-back",
}


def _supporting_html(e, lang: str) -> str:
    """Render baseline / verification exchanges and multi-request statistics."""
    blocks: list[str] = []

    for exchange in getattr(e, "supporting", []) or []:
        label = t(_SUPPORTING_LABEL.get(exchange.kind, exchange.kind), lang)
        response = exchange.response
        status = f"HTTP {response.status_code}" if response else t("no response", lang)
        headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items()) if response else ""
        body_text = (response.body or t("(empty body)", lang)) if response else t("(request did not complete)", lang)
        blocks.append(
            f"<details class='resp' style='margin-top:8px'>"
            f"<summary>{_e(label)} &middot; {t('as', lang)} <b>{_e(exchange.as_persona)}</b> &middot; {_e(status)}</summary>"
            f"<p class='muted' style='margin:6px 0'>{_e(exchange.note)}</p>"
            f"<div class='glabel'>{t('Request', lang)}</div>"
            f"<pre class='respbody'>{_e(exchange.request.method)} {_e(exchange.request.url)}</pre>"
            f"<div class='glabel'>{t('Response Headers', lang)}</div>"
            f"<pre class='respbody'>{_e(headers_text) or t('(none)', lang)}</pre>"
            f"<div class='glabel'>{t('Response Body', lang)}</div>"
            f"<pre class='respbody'>{_e(body_text)}</pre>"
            f"</details>"
        )

    repeat = getattr(e, "repeat", None)
    if repeat is not None:
        spread = ", ".join(f"{status}&times;{count}" for status, count in sorted(repeat.status_counts.items()))
        sent_word = t("concurrently", lang) if repeat.concurrent else t("in sequence", lang)
        throttle_word = t("observed", lang) if repeat.throttled else t("not observed", lang)
        text = t(
            "Multi-request probe: {sent} sent {mode}, {ok} succeeded, throttling {throttle}. "
            "Status spread: {spread}.", lang
        ).format(sent=repeat.sent, mode=sent_word, ok=repeat.succeeded,
                 throttle=throttle_word, spread=spread)
        blocks.append(f"<p class='muted' style='margin:8px 0 0'>{text}</p>")

    return "".join(blocks)


# -- the explanation, moved here from the Jira comment ------------------------
#
# These three renderers exist because the comment stopped carrying them. A
# ticket comment is skimmed and has a length limit; a report is read by whoever
# actually has to act on a row, and it can put the explanation immediately above
# the captured request and response that justify it. Keeping the explanation in
# both places meant two renderings of the same claim, and the one in the ticket
# was the copy nobody updated.


def _attack_html(test: TestCase | None, e: Execution, lang: str) -> str:
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
    out = (f"<div class='glabel'>{t('Attack Performed', lang)}</div>"
           f"<p style='margin:2px 0 6px'>{' &mdash; '.join(parts)}</p>")
    detail = test.attack_mutation.detail if test else None
    if detail:
        try:
            rendered = json.dumps(detail, sort_keys=True, default=str)
        except (TypeError, ValueError):
            rendered = str(detail)
        out += (f"<div class='glabel'>{t('Attack Parameters', lang)}</div>"
                f"<pre class='respbody'>{_e(rendered)}</pre>")
    return out


def _expectation_html(e: Execution, lang: str) -> str:
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
        rows += f"<b>{t('Expected', lang)}</b><span>{_e(expected)}</span>"
    if observed:
        rows += f"<b>{t('Observed', lang)}</b><span>{_e(observed)}</span>"
    return (f"<div class='kv' style='font-size:12.5px;margin:0 0 6px;"
            f"grid-template-columns:74px 1fr'>{rows}</div>")


def _adjudication_html(adjudication, lang: str) -> str:
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
    color = _RESULT_COLOR.get(result, "#566173")
    who = t("AI Reviewer", lang) if adjudication.adjudicator == "ai" else t("deterministic triage", lang)
    decided = result in ("PASS", "FAIL")
    if adjudication.needs_manual_review:
        headline, color = t("Needs Manual Review", lang), "#8a6400"
    elif decided:
        headline = t("Reviewed as {result}", lang).format(result=t(result, lang))
    else:
        # Nobody has to read this one and nobody decided it either. "Reviewed as
        # INCONCLUSIVE" claimed a reading that did not happen, and next to it a
        # confidence inherited from the sealed verdict read as confidence in that
        # non-reading.
        headline, color = t("Still undecided — re-run this one", lang), "#8a6400"
    # Confidence is only meaningful about a decision. Printed beside a row that
    # decided nothing, it is noise at best and false assurance at worst.
    confidence = (f"{t(adjudication.confidence.value, lang)} {t('confidence', lang)} &middot; "
                  if decided else "")
    advisory = t(
        "advisory: does not change the sealed verdict or create a finding directly; "
        "derived promotion is audited separately", lang,
    )
    cited = "".join(f"<li>{_e(c)}</li>" for c in adjudication.evidence_cited)
    cited_html = (f"<div class='glabel'>{t('Evidence Cited', lang)}</div>"
                  f"<ul style='margin:2px 0 6px;padding-left:18px'>{cited}</ul>"
                  if cited else "")
    action = (f"<p class='muted' style='margin:4px 0 0'><b>{t('Next:', lang)}</b> "
              f"{_e(adjudication.recommended_action)}</p>"
              if adjudication.recommended_action else "")
    degraded = (f"<p class='muted' style='margin:4px 0 0'>{_e(adjudication.degraded_reason)}</p>"
                if adjudication.degraded_reason else "")
    return (
        f"<div class='adj' style='border-left-color:{color}'>"
        f"<p style='margin:0 0 4px'><b style='color:{color}'>{_e(headline)}</b> "
        f"<span class='muted'>&middot; {_e(who)} &middot; "
        f"{confidence}{advisory}</span></p>"
        f"{_how_html(adjudication, lang)}"
        f"<p style='margin:0 0 4px'>{_e(adjudication.triage_reason)}</p>"
        f"<p style='margin:0 0 4px'>{_e(adjudication.rationale)}</p>"
        f"{cited_html}{_signals_html(adjudication, lang)}"
        f"{_challenge_html(adjudication, lang)}{action}{degraded}</div>"
    )


def _how_html(adjudication, lang: str) -> str:
    """How the reading was arrived at, in one line, always.

    A measured reading and a model's reading are different assurances and a
    reader must never have to infer which one they are looking at. `getattr` with
    a default because a report can be rendered from a run assessment stored
    before these fields existed.
    """
    resolution = getattr(adjudication, "resolution", "")
    rule = getattr(adjudication, "rule", "")
    read_from = getattr(adjudication, "read_from", "")
    if resolution == "measured":
        text = t("Settled by measuring the captured evidence against the positive "
                 "control — no model was involved, and the same evidence gives the "
                 "same answer every time.", lang)
        if rule:
            text += f" {t('Rule', lang)}: {_e(rule)}."
    elif resolution == "ai_consensus":
        text = t("Read by the agent, then challenged by a second adversarial pass that "
                 "tried and failed to refute it.", lang)
    elif resolution == "propagated":
        text = t("Carried from an identical reading task — same mutation, endpoint, "
                 "status, body shape and positive-control state.", lang)
        if read_from:
            text += f" ({_e(read_from)})"
    elif resolution == "capped":
        text = t("Never read: this review pass ran out of its model-call budget.", lang)
    else:
        return ""
    return f"<p class='muted' style='margin:0 0 4px'>{text}</p>"


def _signals_html(adjudication, lang: str) -> str:
    """The measured differential, whatever the reading was.

    Printed even when nothing could be settled: "the attacker's body is 34%
    similar to the owner's and shares no distinctive value with it" is most of
    the work a person opening this row would do by hand, and it is worth having
    on the page whether or not it decided anything.
    """
    signals = getattr(adjudication, "signals", None) or []
    if not signals:
        return ""
    items = "".join(f"<li>{_e(line)}</li>" for line in signals)
    return (f"<div class='glabel'>{t('Measured Differential', lang)}</div>"
            f"<ul style='margin:2px 0 6px;padding-left:18px'>{items}</ul>")


def _challenge_html(adjudication, lang: str) -> str:
    if not getattr(adjudication, "challenged", False):
        return ""
    note = getattr(adjudication, "challenge_note", "")
    if not note:
        return ""
    return (f"<p class='muted' style='margin:4px 0 0'><b>{t('Challenge pass:', lang)}</b> "
            f"{_e(note)}</p>")


def _run_assessment_section(run, lang: str) -> str:
    """Passed or failed, and how much of the ticket the run actually covered.

    The percentage is computed by the platform over the requirement list, never
    asserted by a model — so the table below it lists every requirement item and
    what the run proved about it. A number nobody can decompose is a number
    nobody should act on.
    """
    if run is None:
        return ""
    tone = {"PASSED": "#007a61", "FAILED": "#c8102e", "INCOMPLETE": "#8a6400"}.get(
        run.overall, "#566173")
    rows = ""
    for item in run.items:
        color = _ITEM_COLOR.get(item.state, "#647083")
        rows += (
            f"<tr><td class='mono'>{_e(item.item_id)}</td>"
            f"<td>{_e(item.text)}</td>"
            f"<td style='color:{color};font-weight:700;white-space:nowrap'>"
            f"{t(item.state.replace('_', ' '), lang)}</td>"
            f"<td class='mono' style='font-size:11.5px'>{_e(', '.join(item.tests)) or '&mdash;'}</td>"
            f"<td class='muted'>{_e(item.note)}</td></tr>"
        )
    items_table = (
        "<div class='tblwrap'><table>"
        f"<tr><th>{t('Item', lang)}</th><th>{t('Requirement', lang)}</th><th>{t('State', lang)}</th>"
        f"<th>{t('Tests', lang)}</th><th>{t('Note', lang)}</th></tr>"
        f"{rows}</table></div>"
        if rows else f"<p class='muted'>{t('No requirement items were extracted from the ticket.', lang)}</p>"
    )
    who = t("AI Reviewer", lang) if run.reviewer == "ai" else t("deterministic triage only", lang)
    degraded = (f"<p class='muted' style='margin:6px 0 0'>{_e(run.degraded_reason)}</p>"
                if run.degraded_reason else "")
    reviewed_by = t("Reviewed by: {who}.", lang).format(who=_e(who))
    advisory_note = t(
        "A reviewed result is <b>advisory</b>: it never overwrites the verdict the runner "
        "sealed into the evidence chain. Only a named "
        "measurement or challenged HIGH-confidence consensus can create a separate derived "
        "decision. Coverage counts a "
        "requirement as covered only when a test for it reached a decisive result &mdash; a "
        "plan that touches everything and decides nothing scores zero here, deliberately.", lang
    )
    return f"""<h2>{t("Assessment of This Run", lang)}</h2>
<div class="stats">
<div class="stat"><div class="num" style="color:{tone}">{t(run.overall, lang)}</div>
<div class="lbl">{t("Overall", lang)}</div></div>
<div class="stat"><div class="num">{run.coverage_pct}%</div>
<div class="lbl">{t("Ticket Requirements Covered", lang)}</div>
<div class="lbl">{run.n_items_decided}/{run.n_items_scored} {t("Decided", lang)}</div></div>
<div class="stat"><div class="num">{run.decided_pct}%</div>
<div class="lbl">{t("Executions Decided", lang)}</div></div>
<div class="stat"><div class="num">{run.n_manual_review}</div>
<div class="lbl">{t("Need a Person", lang)}</div></div>
<div class="stat"><div class="num">{run.n_auto_resolved}</div>
<div class="lbl">{t("Settled by Review", lang)}</div>
<div class="lbl">{getattr(run, "n_measured", 0)} {t("By Measurement", lang)}</div></div>
</div>
<p style="margin:14px 0 4px">{_e(run.summary)}</p>
<p class="muted" style="margin:0 0 12px">{reviewed_by} {advisory_note}</p>
{degraded}
{items_table}"""


def _plan_review_section(review, lang: str) -> str:
    """What the reviewing agent said about the plan before it was approved.

    Kept in the report because it is part of why this run tested what it tested.
    An unresolved gap is the honest answer to "why is there no BFLA result here",
    and it should be in the artefact somebody reads six months later, not only in
    the UI at the moment of approval.
    """
    if review is None:
        return ""
    tone = {"APPROVE": "#007a61", "REVISE": "#8a6400", "INSUFFICIENT": "#c8102e"}.get(
        review.verdict, "#566173")
    who = t("AI Reviewer", lang) if review.reviewer == "ai" else t("structural review (no AI)", lang)

    def _gap_list(gaps) -> str:
        if not gaps:
            return f"<p class='ok' style='margin:4px 0'>{t('None.', lang)}</p>"
        return ("<ul style='margin:4px 0 0;padding-left:18px'>"
                + "".join(f"<li><b>{t(g.severity, lang)}</b> &middot; {_e(g.label())}</li>"
                          for g in gaps)
                + "</ul>")

    strengths = ("<ul style='margin:4px 0 0;padding-left:18px'>"
                 + "".join(f"<li>{_e(s)}</li>" for s in review.strengths) + "</ul>"
                 if review.strengths else "")
    degraded = (f"<p class='muted' style='margin:6px 0 0'>{_e(review.degraded_reason)}</p>"
                if review.degraded_reason else "")
    reviewed_by = t("Reviewed by {who}; {n} test(s) reviewed over {rounds} revision round(s).", lang).format(
        who=_e(who), n=review.tests_before, rounds=review.rounds)
    return f"""<h2>{t("Plan Review", lang)}</h2>
<div class="stats">
<div class="stat"><div class="num" style="color:{tone}">{t(review.verdict, lang)}</div>
<div class="lbl">{t("Review Verdict", lang)}</div></div>
<div class="stat"><div class="num">{review.coverage_score}%</div>
<div class="lbl">{t("Plan Coverage", lang)}</div></div>
<div class="stat"><div class="num">{review.quality_score}%</div>
<div class="lbl">{t("Decidable Tests", lang)}</div></div>
<div class="stat"><div class="num">{len(review.tests_added)}</div>
<div class="lbl">{t("Added After Review", lang)}</div></div>
</div>
<p style="margin:14px 0 4px">{_e(review.headline())} <span class="muted">{reviewed_by}</span></p>
<p class="muted" style="margin:0 0 10px">{_e(review.notes)}</p>
{degraded}
<div class="glabel">{t("Gaps Found at Review Time", lang)}</div>
{_gap_list(review.gaps)}
<div class="glabel" style="margin-top:10px">{t("Still Unresolved", lang)}</div>
{_gap_list(review.unresolved_gaps)}
{f'<div class="glabel" style="margin-top:10px">{t("Strengths", lang)}</div>{strengths}' if strengths else ''}"""


_ITEM_COLOR = {
    "COVERED_PASS": "#007a61", "COVERED_FAIL": "#c8102e", "PARTIAL": "#8a6400",
    "NOT_COVERED": "#8a6400", "NOT_TESTED": "#647083",
}


VI.update({
    "Report Sections": "Mục Lục Báo Cáo", "Overall Risk": "Mức Rủi Ro", "Tests Run": "Số Test Đã Chạy",
    "None Found": "Không Phát Hiện", "Undetermined": "Chưa Xác Định", "Critical": "Nghiêm Trọng", "High": "Cao", "Medium": "Trung Bình",
    "Low": "Thấp", "Info": "Thông Tin",
    # -- headings / structure --
    "Executive Summary": "Tổng Quan",
    "Claims Verified": "Đã Kiểm Chứng Nội Dung",
    "{f} findings, {r} evidence refs": "{f} Phát Hiện, {r} Tham Chiếu Bằng Chứng",
    "Every execution hash recomputes and links to the previous one.":
        "Mọi hash của lượt chạy đều khớp và liên kết với bản ghi trước.",
    "Findings": "Phát Hiện",
    "Execution Log": "Nhật Ký Thực Thi",
    "Assessment of This Run": "Đánh Giá Lượt Chạy Này",
    "Plan Review": "Đánh Giá Kế Hoạch",
    "Target": "Mục Tiêu",
    "Evidence Chain Verified": "Chuỗi Bằng Chứng Đã Xác Minh",
    "Evidence chain FAILED verification": "Chuỗi Bằng Chứng KHÔNG Xác Minh Được",
    "at least one execution record's hash no longer matches its content, or the "
    "chain link to the previous record is broken. This report's evidence may have "
    "been altered after it was recorded; treat it as non-authoritative until "
    "investigated.":
        "ít nhất một bản ghi thực thi có hash không còn khớp với nội dung, hoặc "
        "liên kết chuỗi tới bản ghi trước đó đã bị đứt. Bằng chứng trong báo cáo này "
        "có thể đã bị thay đổi sau khi ghi nhận; coi là không đáng tin cho đến khi "
        "được điều tra.",
    "No confirmed findings.": "Không có phát hiện nào được xác nhận.",
    # -- result / severity / confidence enum labels --
    "PASS": "ĐẠT", "FAIL": "LỖI", "INCONCLUSIVE": "CHƯA RÕ", "BLOCKED": "BỊ CHẶN",
    "ERROR": "LỖI HỆ THỐNG", "SKIPPED": "BỎ QUA", "TIMEOUT": "HẾT GIỜ",
    "CRITICAL": "NGHIÊM TRỌNG", "HIGH": "CAO", "MEDIUM": "TRUNG BÌNH",
    "LOW": "THẤP", "INFO": "THÔNG TIN",
    "HIGH confidence": "Độ Tin Cậy CAO",
    "confidence": "độ tin cậy",
    # -- coverage section --
    "OWASP API Security Coverage ({n} Applicable)": "Độ Phủ OWASP API Security ({N} Áp Dụng)",
    "Category": "Danh Mục", "Existing PoC": "PoC Hiện Có", "Generated": "Đã Tạo",
    "State": "Trạng Thái", "Coverage": "Độ Phủ",
    "COVERED": "ĐÃ PHỦ", "PARTIAL": "MỘT PHẦN", "MISSING": "THIẾU",
    "NOT_APPLICABLE": "KHÔNG ÁP DỤNG",
    # -- findings block --
    "Endpoint": "Endpoint", "Affected Tests": "Test Bị Ảnh Hưởng",
    "Expected": "Kỳ Vọng", "Actual": "Thực Tế", "Impact": "Tác Động",
    "Recommendation": "Khuyến Nghị", "Reproduction": "Cách Tái Hiện",
    "References": "Tham Chiếu",
    # -- execution log table --
    "Test": "Test", "Result": "Kết Quả", "Confidence": "Độ Tin Cậy",
    "Status": "Trạng Thái HTTP", "Exchange": "Trao Đổi", "Reason": "Lý Do",
    "Re-run": "Chạy Lại",
    "View Exchange": "Xem Trao Đổi", "Hide Exchange": "Ẩn Trao Đổi",
    "Response": "Phản Hồi", "Request": "Yêu Cầu",
    "Headers": "Headers", "Body": "Body",
    "(empty body)": "(body rỗng)", "(no body)": "(không có body)",
    "(none)": "(không có)", "Blocked before send.": "Đã bị chặn trước khi gửi.",
    "Copy cURL": "Copy CURL",
    "Credentials are masked (<code>********</code>) above before anything is stored.":
        "Thông tin xác thực đã bị che (<code>********</code>) ở trên trước khi lưu trữ.",
    "<b>Copy cURL</b> resolves the real credential from the persona vault live "
    "when clicked — it is never written into this report, and only works from a "
    "report the platform is currently serving, not a saved copy of it.":
        "<b>Copy cURL</b> lấy thông tin xác thực thật từ persona vault ngay lúc bấm "
        "— không bao giờ ghi vào báo cáo này, và chỉ hoạt động khi báo cáo đang được "
        "chính nền tảng phục vụ, không phải một bản đã lưu.",
    "re-run below:": "đã chạy lại bên dưới:",
    "no longer in the plan": "không còn trong kế hoạch",
    "Attack Performed": "Đòn Tấn Công Đã Thực Hiện", "Attack Parameters": "Tham Số Tấn Công",
    "Observed": "Quan Sát Được",
    "as": "với vai trò", "no response": "không có phản hồi",
    "(request did not complete)": "(request chưa hoàn tất)",
    "Response Headers": "Headers Phản Hồi", "Response Body": "Body Phản Hồi",
    "Positive Control": "Đối Chứng Dương", "Verification Read-back": "Đọc Lại Xác Minh",
    "Multi-request probe: {sent} sent {mode}, {ok} succeeded, throttling {throttle}. "
    "Status spread: {spread}.":
        "Thăm dò nhiều request: đã gửi {sent} request {mode}, {ok} thành công, "
        "throttling {throttle}. Phân bố mã trạng thái: {spread}.",
    "concurrently": "đồng thời", "in sequence": "tuần tự",
    "observed": "có ghi nhận", "not observed": "không ghi nhận",
    # -- rerun --
    "Rows judged <b>INCONCLUSIVE</b> can be sent again on their own. A re-run replays "
    "the <b>test</b> through the trusted runner &mdash; the same method, path, query, "
    "headers and body, with the persona's real credential resolved from the vault at "
    "send time, because the headers and body recorded here are redacted and cannot be "
    "replayed byte-for-byte. Nothing below is overwritten: the result is appended to "
    "this log as a new execution, chained onto the previous one's evidence hash, so "
    "both attempts stay on the record. Reload the report to see the new row.":
        "Các dòng có kết quả <b>CHƯA RÕ</b> có thể được gửi lại riêng lẻ. Chạy lại sẽ "
        "phát lại <b>test</b> qua trusted runner &mdash; cùng method, path, query, "
        "headers và body, với thông tin xác thực thật của persona được lấy từ vault "
        "ngay lúc gửi, vì headers/body ghi ở đây đã bị che và không thể phát lại "
        "chính xác từng byte. Không có gì bên dưới bị ghi đè: kết quả được thêm vào "
        "nhật ký này như một lượt thực thi mới, nối vào hash bằng chứng của lượt "
        "trước, nên cả hai lần thử đều còn trên hồ sơ. Tải lại báo cáo để thấy dòng mới.",
    "Post This Report to Jira ({key})": "Đăng Báo Cáo Này Lên Jira ({Key})",
    "Back to the Assessment": "Quay Lại Assessment",
    "Posting…": "Đang Đăng…", "Posted to Jira": "Đã Đăng Lên Jira",
    "Failed to post — open the assessment page for details.":
        "Đăng thất bại — mở trang assessment để xem chi tiết.",
    "Network error — try again.": "Lỗi mạng — thử lại.",
    "was": "trước đó là", "unchanged": "không đổi", "Reload the Log": "Tải Lại Nhật Ký",
    "The platform refused this re-run.": "Nền tảng từ chối lượt chạy lại này.",
    "Re-running {test} sends a real state-changing request that can create, "
    "modify or delete data on the target. Type {issue} to confirm.":
        "Chạy lại {test} sẽ gửi một request thay đổi dữ liệu thật, có thể tạo, sửa "
        "hoặc xoá dữ liệu trên mục tiêu. Gõ {issue} để xác nhận.",
    "Issue key did not match — cancelled, nothing was sent.":
        "Issue key không khớp — đã huỷ, không có gì được gửi.",
    "Re-run {test} on its own?\n\nSends the same request again through the "
    "trusted runner, with live persona credentials. This record is kept exactly "
    "as it is; the result is appended to the log as a new execution.":
        "Chạy lại {test} riêng lẻ?\n\nGửi lại đúng request qua trusted runner, với "
        "thông tin xác thực persona còn hiệu lực. Bản ghi này được giữ nguyên; kết "
        "quả sẽ được thêm vào nhật ký như một lượt thực thi mới.",
    "Sending…": "Đang Gửi…", "Re-run Again": "Chạy Lại Lần Nữa",
    "Could not reach the platform. Re-running works from a report served by the "
    "app, not from a saved copy.":
        "Không kết nối được nền tảng. Chạy lại chỉ hoạt động trên báo cáo do app "
        "đang phục vụ, không phải bản đã lưu.",
    # -- copy curl js --
    "Fetching…": "Đang Lấy Dữ Liệu…",
    "Could not build a curl command.": "Không tạo được lệnh curl.",
    "Copied — includes a live credential, handle it like one.":
        "Đã copy — có chứa thông tin xác thực còn hiệu lực, xử lý như một bí mật thật.",
    "Could not copy automatically — command is in the console (F12).":
        "Không copy tự động được — lệnh đã in ra console (F12).",
    "Could not reach the platform — this only works from a report the app is "
    "serving, not a saved copy.":
        "Không kết nối được nền tảng — chỉ hoạt động trên báo cáo do app đang phục "
        "vụ, không phải bản đã lưu.",
    # -- adjudication --
    "AI Reviewer": "AI Reviewer", "deterministic triage": "phân loại tất định",
    "Needs Manual Review": "Cần Người Xem Lại",
    "Reviewed as {result}": "Được Đánh Giá Là {result}",
    "Still undecided — re-run this one": "Vẫn Chưa Quyết — Chạy Lại Dòng Này",
    "advisory, does not change the sealed verdict or create a finding":
        "chỉ mang tính tham khảo, không thay đổi kết luận đã niêm phong hay tạo finding",
    "sealed verdict unchanged; derived promotion audited separately":
        "kết luận niêm phong không đổi; việc nâng cấp dẫn xuất được audit riêng",
    "advisory: does not change the sealed verdict or create a finding directly; "
    "derived promotion is audited separately":
        "chỉ tham khảo: không thay đổi kết luận niêm phong hoặc trực tiếp tạo finding; "
        "việc nâng cấp dẫn xuất được audit riêng",
    "Evidence Cited": "Bằng Chứng Được Trích Dẫn", "Next:": "Tiếp theo:",
    # -- run assessment section --
    "Overall": "Tổng Thể", "Ticket Requirements Covered": "Yêu Cầu Ticket Đã Phủ",
    "Decided": "Đã Quyết", "By Measurement": "Bằng Đo Lường", "Executions Decided": "Lượt Thực Thi Đã Quyết",
    "Need a Person": "Cần Người Xử Lý", "Settled by Review": "Đã Giải Quyết Qua Đánh Giá",
    "Reviewed by: {who}.": "Người đánh giá: {who}.",
    "A reviewed result is <b>advisory</b>: it never overwrites the verdict the runner "
    "sealed into the evidence chain, and never creates a finding. Coverage counts a "
    "requirement as covered only when a test for it reached a decisive result &mdash; a "
    "plan that touches everything and decides nothing scores zero here, deliberately.":
        "Kết quả đánh giá chỉ mang tính <b>tham khảo</b>: không bao giờ ghi đè kết luận "
        "mà runner đã niêm phong vào chuỗi bằng chứng, và không tạo finding. Độ phủ chỉ "
        "tính một yêu cầu là đã phủ khi có test cho nó đạt kết quả dứt khoát &mdash; một "
        "kế hoạch chạm vào mọi thứ nhưng không quyết được gì sẽ có điểm 0 ở đây, có chủ đích.",
    "deterministic triage only": "chỉ phân loại tất định",
    "PASSED": "ĐẠT", "FAILED": "LỖI", "INCOMPLETE": "CHƯA HOÀN TẤT",
    "No requirement items were extracted from the ticket.":
        "Không trích xuất được mục yêu cầu nào từ ticket.",
    "Item": "Mục", "Requirement": "Yêu Cầu", "Tests": "Test", "Note": "Ghi Chú",
    # -- plan review section --
    "structural review (no AI)": "đánh giá cấu trúc (không AI)",
    "None.": "Không có.",
    "Review Verdict": "Kết Luận Đánh Giá", "Plan Coverage": "Độ Phủ Kế Hoạch",
    "Decidable Tests": "Test Có Thể Quyết", "Added After Review": "Đã Thêm Sau Đánh Giá",
    "Reviewed by {who}; {n} test(s) reviewed over {rounds} revision round(s).":
        "Người đánh giá: {who}; đã xem {n} test qua {rounds} vòng chỉnh sửa.",
    "Gaps Found at Review Time": "Lỗ Hổng Phát Hiện Lúc Đánh Giá",
    "Still Unresolved": "Vẫn Chưa Xử Lý", "Strengths": "Điểm Mạnh",
    "APPROVE": "DUYỆT", "REVISE": "CẦN SỬA", "INSUFFICIENT": "CHƯA ĐỦ",
    "blocking": "chặn", "advisory": "khuyến nghị",
    # -- item states (run assessment table) --
    "COVERED PASS": "ĐÃ PHỦ - ĐẠT", "COVERED FAIL": "ĐÃ PHỦ - LỖI",
    "NOT COVERED": "CHƯA PHỦ", "NOT TESTED": "CHƯA TEST",
})
