"""Two small server-rendered charts for the assessment list.

No chart library and no client-side rendering: the app ships no static files,
and both charts are a handful of rectangles. Colours come from chart tokens
defined per theme below; each set was run through the dataviz validator
(lightness band, chroma, CVD and normal-vision separation, contrast) against
the light and the dark surface:

  * severity is ORDINAL, so it is one hue stepped light→dark (brighter = more
    severe on the dark surface). Four distinct hues for an ordered scale failed
    deuteranopia separation in dark mode;
  * a run's outcomes are categorical: Fail / Review / Pass, plus a neutral grey
    remainder for Blocked/Error.

Identity is never colour alone: both charts carry a legend, every mark has a
tooltip naming its series and count, totals are printed, and a table view of the
same numbers sits under each chart.
"""

from __future__ import annotations

from .base import attr, e

# Colours: the --sev-* and --out-* tokens in tokens.py, one set per theme.

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
OUTCOMES = (("FAIL", "Fail"), ("INCONCLUSIVE", "Review"), ("PASS", "Pass"), ("OTHER", "Blocked / Error"))

def _legend(entries: list[tuple[str, str]]) -> str:
    return '<div class="ch-legend">' + "".join(
        f'<span><i style="background:var({var})"></i>{e(label)}</span>' for var, label in entries
    ) + "</div>"


def _table(head: list[str], rows: list[list], caption: str) -> str:
    th = "".join(f'<th scope="col">{e(h)}</th>' for h in head)
    body = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in rows)
    return (f'<details class="ch-table"><summary>{e(caption)}</summary>'
            f'<div class="tblwrap"><table class="compact"><thead><tr>{th}</tr></thead>'
            f"<tbody>{body}</tbody></table></div></details>")


def severity_bars(rows: list[tuple[str, str, dict]], *, title: str, sub: str,
                  labels: dict[str, str], table_label: str, empty: str) -> str:
    """Horizontal stacked bars, one per assessment: (label, href, {SEV: n})."""
    rows = [r for r in rows if sum(r[2].get(s, 0) for s in SEVERITIES)]
    head = f'<div class="ch-head"><h2>{e(title)}</h2><span>{e(sub)}</span></div>'
    legend = _legend([(f"--sev-{s.lower()}", labels[s]) for s in SEVERITIES])
    if not rows:
        return f'<section class="chart">{head}<p class="muted ch-empty">{e(empty)}</p></section>'
    peak = max(sum(r[2].get(s, 0) for s in SEVERITIES) for r in rows)
    lines = []
    for label, href, counts in rows:
        total = sum(counts.get(s, 0) for s in SEVERITIES)
        segs = "".join(
            f'<span class="ch-seg" tabindex="0" style="flex-basis:{100 * counts[s] / peak:.3f}%;'
            f'background:var(--sev-{s.lower()})" data-tip="{attr(f"{label} · {labels[s]}: {counts[s]}")}"></span>'
            for s in SEVERITIES if counts.get(s)
        )
        lines.append(
            f'<a class="ch-row" href="{attr(href)}"><span class="ch-key mono">{e(label)}</span>'
            f'<span class="ch-track">{segs}</span><b class="ch-total">{total}</b></a>'
        )
    table = _table([""] + [labels[s] for s in SEVERITIES],
                   [[r[0]] + [r[2].get(s, 0) for s in SEVERITIES] for r in rows], table_label)
    return f'<section class="chart">{head}{legend}<div class="ch-rows">{"".join(lines)}</div>{table}</section>'


def outcome_columns(runs: list[tuple[str, str, dict]], *, title: str, sub: str,
                    labels: dict[str, str], table_label: str, empty: str) -> str:
    """Vertical stacked columns, one per run: (label, href, {verdict: n})."""
    def split(v: dict) -> dict:
        out = {k: v.get(k, 0) for k in ("FAIL", "INCONCLUSIVE", "PASS")}
        out["OTHER"] = sum(n for k, n in v.items() if k not in out)
        return out

    data = [(label, href, split(v)) for label, href, v in runs if sum(v.values())]
    head = f'<div class="ch-head"><h2>{e(title)}</h2><span>{e(sub)}</span></div>'
    legend = _legend([(f"--out-{k.lower() if k != 'INCONCLUSIVE' else 'review'}", labels[k])
                      for k, _ in OUTCOMES])
    if not data:
        return f'<section class="chart">{head}<p class="muted ch-empty">{e(empty)}</p></section>'
    peak = max(sum(v.values()) for _, _, v in data)
    cols = []
    for label, href, v in data:
        total = sum(v.values())
        segs = "".join(
            f'<span class="ch-cseg" tabindex="0" style="flex-basis:{100 * v[k] / total:.3f}%;'
            f'background:var(--out-{k.lower() if k != "INCONCLUSIVE" else "review"})" '
            f'data-tip="{attr(f"{label} · {labels[k]}: {v[k]}")}"></span>'
            for k, _ in OUTCOMES if v[k]
        )
        cols.append(
            f'<a class="ch-col" href="{attr(href)}"><b class="ch-total">{total}</b>'
            f'<span class="ch-stack" style="height:calc((100% - 24px) * {total / peak:.4f})">{segs}</span>'
            f'<span class="ch-key mono">{e(label)}</span></a>'
        )
    table = _table([""] + [labels[k] for k, _ in OUTCOMES],
                   [[d[0]] + [d[2][k] for k, _ in OUTCOMES] for d in data], table_label)
    return (f'<section class="chart">{head}{legend}<div class="ch-cols">{"".join(cols)}</div>'
            f"{table}</section>")


CSS = """
.charts{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr);gap:16px;margin-bottom:22px;}
@media (max-width:1100px){.charts{grid-template-columns:minmax(0,1fr);}}
.chart{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);
  box-shadow:var(--shadow);padding:16px 18px;display:flex;flex-direction:column;gap:12px;min-width:0;
  animation:rise var(--t-slow) var(--ease) backwards;}
.ch-head{display:flex;align-items:baseline;gap:10px;}
.ch-head h2{margin:0;flex:1;font-size:16px;}
.ch-head span{font-size:12px;color:var(--muted);}
.ch-legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted);}
.ch-legend span{display:inline-flex;align-items:center;gap:6px;}
.ch-legend i{width:10px;height:10px;border-radius:3px;display:inline-block;}
.ch-rows{display:flex;flex-direction:column;gap:9px;}
.ch-row{display:grid;grid-template-columns:96px minmax(0,1fr) 32px;gap:10px;align-items:center;
  text-decoration:none;color:var(--fg);border-radius:8px;}
.ch-row:hover .ch-key{color:var(--accent);}
.ch-key{font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.ch-track{display:flex;gap:2px;height:14px;}
.ch-seg{display:block;height:100%;flex:0 0 auto;transform-origin:left;
  animation:grow 1s var(--ease) both;}
.ch-seg:first-child{border-radius:4px 0 0 4px;}
.ch-seg:last-child{border-radius:0 4px 4px 0;}
.ch-seg:only-child{border-radius:4px;}
.ch-seg:hover,.ch-seg:focus,.ch-cseg:hover,.ch-cseg:focus{outline:2px solid var(--fg);outline-offset:1px;}
.ch-total{font-size:12px;font-weight:600;text-align:right;font-variant-numeric:tabular-nums;}
.ch-cols{display:flex;align-items:flex-end;gap:10px;height:190px;padding-top:6px;
  border-bottom:1px solid var(--border);}
.ch-col{flex:1;min-width:0;height:100%;display:flex;flex-direction:column;align-items:center;
  justify-content:flex-end;gap:4px;text-decoration:none;color:var(--fg);position:relative;padding-bottom:20px;}
.ch-col .ch-key{position:absolute;bottom:0;font-size:10.5px;max-width:100%;}
.ch-col:hover .ch-key{color:var(--accent);}
.ch-stack{width:min(28px,70%);display:flex;flex-direction:column-reverse;gap:2px;
  transform-origin:bottom;animation:growy 1s var(--ease) both;}
.ch-cseg{display:block;flex:0 0 auto;}
.ch-cseg:last-child{border-radius:4px 4px 0 0;}
.ch-table summary{cursor:pointer;font-size:12px;color:var(--muted);}
.ch-table table{margin-top:8px;}
.ch-empty{margin:0;font-size:13px;}
@keyframes growy{from{transform:scaleY(0);}to{transform:scaleY(1);}}
"""
