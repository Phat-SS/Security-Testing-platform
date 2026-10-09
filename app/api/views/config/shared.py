"""What every configuration pane needs: the readiness vocabulary, the tab
names (including the historical ones), and the collapsible section.
"""

from __future__ import annotations



from app.core.i18n import VI, tt as _t

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

_READY_CLASS = {"ok": "ok", "warn": "med", "fail": "crit"}
_READY_ICON = {"ok": "&#10003;", "warn": "&#9888;", "fail": "&#10007;"}
_READY_WORD = {"ok": "READY", "warn": "CHECK", "fail": "BLOCKING"}

# Four tabs, in the order a new engagement needs them. There were eight — one
# per settings *file section*, which made the page a map of the implementation
# rather than of the job. Scope only ever means anything next to the target it
# authorizes, and the four panes nobody opens during a normal engagement (runner
# limits, AI/evidence secrets, the MCP connector, the read-only runtime facts)
# now share one "Advanced" tab instead of each advertising itself as a step.
#
# The labels match the sidebar entries word for word: the sidebar IS the nav
# for these panes now, so a pane titled differently from the link that opened
# it reads as having landed somewhere else.
_CONFIG_TABS = [
    ("readiness", "Readiness"),
    ("target", "Scope & Targets"),
    ("identities", "Identities"),
    ("advanced", "Settings"),
]

# Old tab names stay valid: they are in bookmarks, in older reports, and in the
# `?tab=` of every redirect the config writers issue. Each resolves to whichever
# new tab absorbed it rather than silently falling back to Readiness, which
# would drop a tester somewhere other than the pane they just saved in.
_TAB_ALIASES = {
    "environments": "target",
    "scope": "target",
    "personas": "identities",
    "runner": "advanced",
    "ai-evidence": "advanced",
    "mcp": "advanced",
    "runtime": "advanced",
}


def resolve_config_tab(tab: str) -> str:
    """The tab to open for a (possibly historical) tab name."""
    tab = _TAB_ALIASES.get(tab, tab)
    return tab if tab in dict(_CONFIG_TABS) else "readiness"


VI.update({
    "Readiness": "Sẵn Sàng", "Target": "Mục Tiêu", "Identities": "Danh Tính",
    "Advanced": "Nâng Cao",
    "Environments": "Môi Trường", "Scope": "Phạm Vi",
    "Personas": "Persona", "Runner Limits": "Giới Hạn Runner", "MCP": "MCP",
    "AI & Evidence": "AI & Bằng Chứng",
    "Runtime (.env)": "Runtime (.env)",
    "Jira Connector (MCP)": "Kết Nối Jira (MCP)",
    "Max Requests per Second": "Số Request Tối Đa Mỗi Giây",
    "Interactsh Server": "Máy Chủ Interactsh", "Interactsh Token": "Token Interactsh",
    "Or a generic collector:": "Hoặc một collector chung:",
    "Budget per Assessment (USD)": "Ngân Sách Mỗi Assessment (USD)",
    "Ceiling on the whole run's request rate. Blank or 0 means no ceiling. Probe bursts are exempt.":
        "Giới hạn tốc độ request của cả lượt chạy. Để trống hoặc 0 là không giới hạn. "
        "Các loạt request của probe được miễn.",
    "Everything here has a working default. Reference: "
    "<code>docs/configuration.md</code>.":
        "Mọi mục ở đây đều có giá trị mặc định. Tham khảo: <code>docs/configuration.md</code>.",
})


def _kv_textarea_value(mapping: dict, sep: str) -> str:
    return "\n".join(f"{k}{sep}{v}" for k, v in (mapping or {}).items())


def _section(title: str, blurb: str, body: str, open_: bool = False) -> str:
    """One collapsible block inside the Advanced tab."""
    return f"""<details class="card pad" style="margin-bottom:12px" {'open' if open_ else ''}>
<summary style="cursor:pointer;font-weight:600">{_t(title)}
<span class="muted" style="font-weight:400;margin-left:8px">{_t(blurb)}</span></summary>
<div style="padding-top:14px">{body}</div>
</details>"""
