"""The Copilot panel: a brief beside the phases, never instead of them.

Read-only until a person presses something. "Refresh" builds a new brief (an AI
call when USE_AI is on), "Add To Plan" hands one step to the planner, and both
are POSTs a tester role has to make. Every AI claim shown here already passed
`copilot.validate()`; the panel says so when claims were dropped instead of
hiding it.
"""

from __future__ import annotations

from app.api import ui
from app.api.ui import attr, e
from app.core.i18n import VI, tt as _t

_CONF_TONE = {"HIGH": "ok", "MEDIUM": "med", "LOW": "info"}


def copilot_panel(aid: str, brief, *, phase: str, planner_enabled: bool) -> str:
    refresh = (
        f'<form method="post" action="/assessment/{attr(aid)}/copilot" class="cp-ask js-busy">'
        f'<input type="hidden" name="phase" value="{attr(phase)}">'
        f'<input name="question" maxlength="1000" autocomplete="off" '
        f'placeholder="{attr(_t("Ask Copilot About This Assessment"))}" '
        f'aria-label="{attr(_t("Ask Copilot"))}">'
        f'<button class="btn sm" aria-label="{attr(_t("Ask"))}">{ui.icon("arrow-right", 14)}</button>'
        "</form>"
    )
    head = (
        f'<div class="cp-head">{ui.icon("sparkle", 16)}<h2>{_t("Copilot")}</h2>'
        + (f'<span class="cp-meta">{e(_source_label(brief))}</span>' if brief else "")
        + "</div>"
    )
    if brief is None:
        body = (f'<p class="muted cp-empty">{_t("No brief yet. Ask a question or refresh.")}</p>'
                f'<form method="post" action="/assessment/{attr(aid)}/copilot" class="js-busy">'
                f'<input type="hidden" name="phase" value="{attr(phase)}">'
                f'<button class="btn sec sm">{ui.icon("refresh", 14)}{_t("Build Brief")}</button></form>')
        return f'<aside class="copilot" id="copilot">{head}{body}{refresh}</aside>'

    parts = []
    if brief.question and brief.answer:
        parts.append(f'<div class="cp-card cp-answer"><div class="cp-k">{e(brief.question)}</div>'
                     f'<p>{e(brief.answer)}</p></div>')
    for h in brief.hypotheses:
        ev = (f'<div class="cp-ev mono">{e(", ".join(h.evidence[:4]))}'
              + (f" +{len(h.evidence) - 4}" if len(h.evidence) > 4 else "") + "</div>"
              if h.evidence else "")
        parts.append(
            f'<div class="cp-card"><div class="cp-k">{_t("Hypothesis")} '
            f'{ui.pill(_t(h.confidence.title()), _CONF_TONE.get(h.confidence, "info"))}</div>'
            f"<b>{e(h.title)}</b>"
            + (f"<p>{e(h.rationale)}</p>" if h.rationale else "") + ev + "</div>"
        )
    for i, s in enumerate(brief.next_steps):
        action = (
            f'<form method="post" action="/assessment/{attr(aid)}/copilot/accept" class="js-busy">'
            f'<input type="hidden" name="step" value="{i}">'
            f'<input type="hidden" name="brief" value="{attr(brief.generated_at)}">'
            f'<button class="btn sm">{ui.icon("plus", 13)}{_t("Add To Plan")}</button></form>'
            if planner_enabled else ""
        )
        parts.append(
            f'<div class="cp-card cp-step"><div class="cp-k">{_t("Next Step")}'
            + (f" · {e(s.category)}" if s.category else "") + "</div>"
            f"<b>{e(s.title)}</b>"
            f'<div class="cp-ev mono">{e(s.endpoint)} · {e(s.mutation_kind)}</div>'
            + (f"<p>{e(s.why)}</p>" if s.why else "") + action + "</div>"
        )
    if not parts:
        parts.append(f'<p class="muted cp-empty">{_t("Nothing to flag yet.")}</p>')
    notes = []
    if brief.next_steps and not planner_enabled:
        # Said once, not under every step.
        notes.append(_t("Turn on the AI planner to add steps automatically."))
    if brief.degraded_reason:
        notes.append(f'{_t("Deterministic only")}: {e(brief.degraded_reason)}')
    if brief.dropped:
        notes.append(_t("{n} AI claim(s) failed validation and are hidden.").format(n=len(brief.dropped)))
    note_html = "".join(f'<p class="cp-note">{n}</p>' for n in notes)
    refresh_btn = (f'<form method="post" action="/assessment/{attr(aid)}/copilot" class="js-busy cp-refresh">'
                   f'<input type="hidden" name="phase" value="{attr(phase)}">'
                   f'<button class="btn ghost sm">{ui.icon("refresh", 13)}{_t("Refresh")}</button></form>')
    return (f'<aside class="copilot" id="copilot">{head}{"".join(parts)}{note_html}'
            f"{refresh_btn}{refresh}</aside>")


def _source_label(brief) -> str:
    when = (brief.generated_at or "")[:16].replace("T", " ")
    cost = f" · ${brief.cost_usd:.2f}" if brief.cost_usd else ""
    return f"{'AI' if brief.source == 'ai' else _t('Rules')} · {when}{cost}"


VI.update({
    "Copilot": "Copilot", "Ask Copilot": "Hỏi Copilot", "Ask": "Hỏi",
    "Ask Copilot About This Assessment": "Hỏi Copilot Về Assessment Này",
    "No brief yet. Ask a question or refresh.": "Chưa có bản tóm tắt. Đặt câu hỏi hoặc làm mới.",
    "Build Brief": "Tạo Tóm Tắt", "Hypothesis": "Giả Thuyết", "Next Step": "Bước Tiếp Theo",
    "Add To Plan": "Thêm Vào Kế Hoạch",
    "Turn on the AI planner to add steps automatically.":
        "Bật AI planner để tự động thêm các bước.",
    "Nothing to flag yet.": "Chưa có gì cần lưu ý.",
    "Deterministic only": "Chỉ Dùng Rule",
    "{n} AI claim(s) failed validation and are hidden.":
        "{n} nhận định của AI không qua kiểm chứng và đã bị ẩn.",
    "Refresh": "Làm Mới", "Rules": "Rule",
    "High": "Cao", "Medium": "Trung Bình", "Low": "Thấp",
})
