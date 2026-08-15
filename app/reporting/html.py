"""HTML report renderer — dependency-free (no Jinja needed for MVP).

Produces a self-contained, theme-aware report from executions + findings. Every
value shown here has already passed secret redaction upstream.
"""

from __future__ import annotations

import html
from collections import Counter

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


def render_report(
    title: str,
    target: str,
    tests: dict[str, TestCase],
    executions: list[Execution],
    findings: list[Finding],
    coverage_rows: list[dict] | None = None,
) -> str:
    result_counts = Counter(e.verdict.result.value for e in executions)
    sev_counts = Counter(f.severity.value for f in findings)
    coverage_html = _coverage_section(coverage_rows) if coverage_rows else ""

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
    exec_rows = "\n".join(_exec_row(tests.get(e.test_id), e) for e in executions)

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
</style></head><body><div class="wrap">
<h1>{_e(title)}</h1>
<p class="sub">Target: <code>{_e(target)}</code> · Baseline: OWASP API Security Top 10 (2023)</p>

<h2>Executive Summary</h2>
<div class="stats">{summary_cells}</div>
<div class="pills">{sev_cells}</div>
{coverage_html}
<h2>Findings</h2>
{findings_html}

<h2>Execution Log</h2>
<div class="tblwrap"><table>
<tr><th>Test</th><th>OWASP</th><th>Result</th><th>Confidence</th><th>Reason</th></tr>
{exec_rows}
</table></div>
</div></body></html>"""


_COVERAGE_COLOR = {
    "COVERED": "#2f855a", "PARTIAL": "#b8860b", "MISSING": "#b4232a",
    "NOT_APPLICABLE": "#718096",
}


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


def _exec_row(test: TestCase | None, e: Execution) -> str:
    color = _RESULT_COLOR.get(e.verdict.result.value, "#4a5568")
    title = _e(test.title) if test else _e(e.test_id)
    return (
        f"<tr><td><b>{_e(e.test_id)}</b><br><span class='mono'>{title}</span></td>"
        f"<td>{_e(e.owasp_category)}</td>"
        f"<td class='res' style='color:{color}'>{_e(e.verdict.result.value)}</td>"
        f"<td>{_e(e.verdict.confidence.value)}</td>"
        f"<td>{_e(e.verdict.reason)}</td></tr>"
    )
