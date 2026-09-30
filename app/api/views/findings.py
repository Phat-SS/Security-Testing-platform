"""Every confirmed finding on this engagement, in one place.

The platform could always tell you what one assessment found. What it could
never answer is the question anyone running an engagement actually has — "what
is outstanding across all of it" — because findings only ever existed inside
the assessment that produced them.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from app.api import ui
from app.api.ui import attr, e
from app.core.i18n import VI, tt as _t

from .shell import _SEV_CLASS, appbar, page

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_DECISION_SOURCE_LABEL = {
    "sealed_runner": ("runner-sealed", "low"),
    "measured": ("measured", "low"),
    "ai_consensus": ("AI-adjudicated", "med"),
}


def _provenance_pill(decision_source: str) -> str:
    label, tone = _DECISION_SOURCE_LABEL.get(decision_source, (decision_source, "info"))
    return ui.pill(_t(label), tone)


def _findings_url(q: str, sev: str, show_fp: bool) -> str:
    parts = []
    if q:
        parts.append(f"q={quote_plus(q)}")
    if sev:
        parts.append(f"sev={quote_plus(sev)}")
    if show_fp:
        parts.append("fp=1")
    return "/findings" + (("?" + "&".join(parts)) if parts else "")


def _row(assessment_id: str, issue_key: str, finding, triage: dict | None) -> str:
    severity = finding.severity.value
    endpoint = getattr(finding, "endpoint", "") or ""
    is_fp = bool(triage) and triage.get("status") == "false_positive"
    fp_badge = f" {ui.pill(_t('False positive'), 'med')}" if is_fp else ""
    row_style = ' style="opacity:.55"' if is_fp else ""
    return (
        f"<tr{row_style}><td><span class='pill {_SEV_CLASS.get(severity, 'info')}'>{e(severity)}</span></td>"
        f"<td><b>{e(finding.title)}</b>{fp_badge}"
        + (f"<div class='mono muted' style='font-size:12px;margin-top:2px'>{e(endpoint)}</div>"
           if endpoint else "")
        + f"</td><td class='mono'>{e(finding.owasp_category.value)}</td>"
        f"<td>{_provenance_pill(getattr(finding, 'decision_source', 'sealed_runner'))}</td>"
        f"<td><a href='/assessment/{attr(assessment_id)}?phase=results'>{e(issue_key)}</a></td>"
        f"<td class='mono muted'>{e(finding.finding_id)}</td></tr>"
    )


def findings_page(
    rows: list[tuple], engagement: str = "", triage: dict | None = None,
    q: str = "", sev: str = "", show_fp: bool = False,
) -> str:
    """`rows` is (assessment_id, issue_key, finding), newest assessment first.

    `triage` is `{(assessment_id, finding_id): {...}}` from
    `repo.get_finding_triage_across` — a finding marked false-positive there
    is dimmed and hidden from the default view rather than deleted: the
    underlying evidence stays inspectable, only the "still outstanding" read
    changes.
    """
    triage = triage or {}
    needle = q.strip().lower()

    # Severity-agnostic: search text and the false-positive toggle narrow the
    # set every facet counts within, but never the severity facet itself —
    # each severity chip shows what it alone would match against that shared
    # set, the same convention the dashboard/plan toolbars use.
    def base_matches(aid: str, finding) -> bool:
        if not show_fp and triage.get((aid, finding.finding_id), {}).get("status") == "false_positive":
            return False
        if needle and needle not in finding.title.lower() and needle not in (finding.endpoint or "").lower():
            return False
        return True

    searched = [(aid, key, f) for aid, key, f in rows if base_matches(aid, f)]
    filtered = [r for r in searched if not sev or r[2].severity.value == sev]

    counts: dict[str, int] = {}
    for _aid, _key, finding in searched:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    chips = "".join(
        f'<a class="seg-b{" none" if not counts.get(name) else ""}" '
        f'href="{_findings_url(q, "" if sev == name else name, show_fp)}"'
        f'{" aria-current=\"page\"" if sev == name else ""}>'
        f"{e(_t(name.title()))} <b>{counts.get(name, 0)}</b></a>"
        for name in _SEV_ORDER
    )
    fp_total = sum(1 for a in triage.values() if a.get("status") == "false_positive")
    fp_toggle = (
        f'<a class="seg-b{" none" if not fp_total else ""}" '
        f'href="{_findings_url(q, sev, not show_fp)}"'
        f'{" aria-current=\"page\"" if show_fp else ""}>'
        f"{e(_t('Show false positives'))} <b>{fp_total}</b></a>"
    )

    # Severity first, then the order they came back in — which is newest
    # assessment first, so the most recent critical is the top line.
    ordered = sorted(filtered, key=lambda r: _SEV_ORDER.index(r[2].severity.value)
                     if r[2].severity.value in _SEV_ORDER else len(_SEV_ORDER))

    body_rows = "".join(
        _row(aid, key, finding, triage.get((aid, finding.finding_id)))
        for aid, key, finding in ordered
    )
    body = ui.table(
        [_t("Severity"), _t("Finding"), "OWASP", _t("Source"), _t("Assessment"), "ID"],
        body_rows,
        empty=_t("No confirmed findings on this engagement yet.")
        if not rows else _t("No findings match this filter."),
    )
    search_box = f"""<form method="get" action="/findings" role="search"
 aria-label="{attr(_t('Search findings'))}" style="margin-bottom:10px">
{f'<input type="hidden" name="sev" value="{attr(sev)}">' if sev else ''}
{'<input type="hidden" name="fp" value="1">' if show_fp else ''}
<input type="text" name="q" value="{attr(q)}"
 placeholder="{attr(_t('Search title or endpoint…'))}" style="width:260px">
<button class="btn sec">{_t('Search')}</button>
{f'<a class="btn sec" href="{_findings_url("", sev, show_fp)}">{_t("Clear")}</a>' if q else ''}
</form>"""
    toolbar = f"""{search_box}
<div class="segrow" style="margin-bottom:14px">{chips}<span style="margin-left:10px">{fp_toggle}</span></div>"""

    note = (f"{_t('Engagement')}: <b>{e(engagement)}</b>" if engagement else "")
    return page(_t("Findings"), f"{toolbar}{body}",
                active="findings",
                appbar_html=appbar(_t("Findings"), note=note))


VI.update({
    "Findings": "Phát hiện", "Severity": "Mức độ", "Finding": "Phát hiện",
    "Assessment": "Assessment", "Engagement": "Engagement", "Source": "Nguồn",
    "Nothing confirmed yet.": "Chưa có phát hiện nào được xác nhận.",
    "No confirmed findings on this engagement yet.":
        "Engagement này chưa có phát hiện nào được xác nhận.",
    "No findings match this filter.": "Không có phát hiện nào khớp bộ lọc này.",
    "Critical": "Nghiêm trọng", "High": "Cao", "Medium": "Trung bình",
    "Low": "Thấp", "Info": "Thông tin",
    "runner-sealed": "runner niêm phong", "measured": "đo lường",
    "AI-adjudicated": "AI phân xử", "False positive": "Dương tính giả",
    "Show false positives": "Hiện dương tính giả",
    "Search findings": "Tìm phát hiện", "Search title or endpoint…": "Tìm tiêu đề hoặc endpoint…",
    "Search": "Tìm", "Clear": "Xoá bộ lọc",
})
