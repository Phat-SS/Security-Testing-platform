"""Minimal Vietnamese/English UI translation.

No gettext/Babel: every user-facing string in this codebase is already a
plain Python literal, so translation is a dict lookup keyed by the literal
English text itself — no separate key names to invent or keep in sync.
Interpolated strings use `.format()`-style `{name}` placeholders instead of
an f-string, so `t("Reconnected — {detail}", lang).format(detail=...)`
replaces what would otherwise be an f-string; Vietnamese is free to reorder
the placeholder since it is only substituted after translation.

A string with no entry in VI falls back to the English literal rather than
raising or rendering blank — coverage can grow incrementally without ever
breaking a page that has not been translated yet.
"""

from __future__ import annotations

import contextvars

LANGS = ("en", "vi")
DEFAULT_LANG = "en"
COOKIE_NAME = "lang"

# Per-request language, set once by main.py's lang_middleware and read by every
# view function without threading a `lang` parameter through the ~250 small
# rendering functions in views.py/views_assessment.py — the same "set once at
# startup, read internally" shape views.py's own `configure()` already uses
# for _AUTH_ENABLED, just per-request instead of per-process. A ContextVar
# (not a plain global) is what makes that per-request-safe under async
# concurrency: each request's task gets its own value, never another
# in-flight request's.
#
# `render_report` in reporting/html.py deliberately does NOT use this — it
# takes `lang` as an explicit argument instead, because that module is also
# called from the CLI with no request/middleware in the picture at all.
_current_lang: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_lang", default=DEFAULT_LANG
)


def get_lang() -> str:
    return _current_lang.get()


def set_lang(lang: str) -> None:
    _current_lang.set(normalize_lang(lang))


def normalize_lang(value: str | None) -> str:
    return value if value in LANGS else DEFAULT_LANG


# English -> Vietnamese. Populated incrementally, file by file; see VI.update()
# calls at the bottom of each reporting/api module for the strings that
# module owns.
VI: dict[str, str] = {}


def t(text: str, lang: str) -> str:
    if lang == "vi":
        return VI.get(text, text)
    return text


def tt(text: str) -> str:
    """Like `t`, but reads the current request's language from the
    ContextVar instead of taking it as an argument — the shorthand
    views.py/views_assessment.py use so translating a string is a matter of
    wrapping it in `tt(...)`, not re-plumbing every function's signature."""
    return t(text, get_lang())
