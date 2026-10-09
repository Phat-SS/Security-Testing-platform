"""Page chrome: the stylesheet-wide class maps, the auth/planner flags,
the per-request sidebar contents, and `page()` itself.
"""

from __future__ import annotations

import contextvars


from app.api import ui
from app.api.ui import e

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

_SEV_CLASS = ui.SEV_CLASS
_STATE_CLASS = ui.STATE_CLASS
_APPROVAL_CLASS = ui.APPROVAL_CLASS
_STATUS_PILL = ui.STATUS_PILL


def _e(v) -> str:
    return e(v)


# Set once at startup from main.py's State.__init__ so the topbar knows
# whether to show the Log in / Log out links. Multi-user auth is off by
# default (single-user local-admin) — hiding these when it's off avoids
# showing a login form that has no effect.
_AUTH_ENABLED = False
_PLANNER_ENABLED = False


def configure(auth_enabled: bool, planner_enabled: bool = False) -> None:
    global _AUTH_ENABLED, _PLANNER_ENABLED
    _AUTH_ENABLED = auth_enabled
    # Gates the adaptive-execution control. Offering a checkbox that silently
    # does nothing (the orchestrator falls back to a one-shot run without a
    # planner) would be worse than not offering it at all.
    _PLANNER_ENABLED = planner_enabled


# Sidebar chrome (engagement, readiness, signed-in user) is set once per
# request by main.py, which is the only layer that can see any of it. Views
# just call `page()`; the shell reads it back from here.
#
# A ContextVar, not a plain global, for the same reason i18n's language is one:
# two requests in flight would otherwise share one value, and the second would
# render the first one's engagement in its sidebar.
_chrome: contextvars.ContextVar[dict] = contextvars.ContextVar("chrome", default={})


def set_chrome(**chrome) -> None:
    """Record what the sidebar should say for THIS request."""
    _chrome.set(chrome)


def page(title: str, body: str, active: str = "", *, appbar_html: str = "") -> str:
    chrome = dict(_chrome.get())
    chrome.setdefault("auth_enabled", _AUTH_ENABLED)
    return ui.page(title, body, active, chrome=chrome,
                   appbar_html=appbar_html)


def appbar(title: str, *, actions: str = "", note: str = "") -> str:
    return ui.appbar(title, actions=actions, note=note)
