"""Shared UI layer for the server-rendered views.

Four modules, one import surface:

  * `tokens`     the palette and scale — the single source for every colour
  * `base`       escaping, the tooltip, the toggles, and the primitives
                 (section, table, stats, pill, bar)
  * `icons`      the inline SVG set
  * `shell`      the sidebar, the app bar, and `page()`

`from app.api import ui` keeps working exactly as it did when this was one
module: every name the views already use is re-exported here, so the split is
invisible to them. `ui.CSS` is now the WHOLE stylesheet (tokens + primitives +
shell) rather than a fragment views.py had to concatenate its own copy onto —
which is what allowed the palette to be declared twice.
"""

from __future__ import annotations

from . import base, charts, icons, menu, select, shell, tokens
from .base import (
    APPROVAL_CLASS,
    LANG_JS,
    SECTION_JS,
    SEV_CLASS,
    STATE_CLASS,
    STATUS_PILL,
    THEME_JS,
    THEME_TOGGLE_HTML,
    TOOLTIP_JS,
    VERDICT_CLASS,
    attr,
    bar,
    e,
    info,
    lang_toggle_html,
    pill,
    section,
    stats,
    table,
    titleize,
)
from .icons import icon
from .menu import Item, action_menu
from .shell import Nav, appbar, page, sidebar

#: The complete stylesheet every page emits.
CSS = shell.FULL_CSS

__all__ = [
    "APPROVAL_CLASS", "CSS", "Item", "action_menu", "charts", "menu", "select", "LANG_JS", "Nav", "SECTION_JS", "SEV_CLASS", "STATE_CLASS",
    "STATUS_PILL", "THEME_JS", "THEME_TOGGLE_HTML", "TOOLTIP_JS", "VERDICT_CLASS",
    "appbar", "attr", "bar", "base", "e", "icon", "icons", "info",
    "lang_toggle_html", "page", "pill", "section", "shell", "sidebar", "stats", "table",
    "titleize", "tokens",
]
