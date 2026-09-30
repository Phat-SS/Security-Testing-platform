"""Cross-cutting request handling: CSRF, sidebar chrome, and language.

Registered by `main.create_app()` in the order they are defined here. Split out
of `main.py` with the routes; the reasoning behind each one is in its own
docstring, which is where it was already.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import PlainTextResponse

from app.api import views
from app.api import runtime
from app.api.runtime import state
from app.core import i18n, preflight
from app.core.auth import User
from app.core.i18n import normalize_lang

logger = logging.getLogger(__name__)


# -- CSRF guard --------------------------------------------------------------
#
# The web UI is plain HTML forms — no JS framework, no CORS opt-in anywhere in
# this app. That means a genuine cross-origin browser request can never carry
# a custom header or trigger a preflight the server would have to approve, so
# the browser's own Sec-Fetch-Site / Origin / Referer headers are reliable
# signals a same-origin request cannot forge. This closes the gap where
# AUTH_ENABLED=false (the default) treats every request as the built-in
# admin: without this, any page a user's browser visits could silently POST
# to /assessment/{aid}/execute, /admin/shutdown, etc.
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _same_site_request(request: Request) -> bool:
    sec_fetch_site = request.headers.get("sec-fetch-site")
    if sec_fetch_site is not None:
        # "cross-site" is the one value a genuine cross-origin page produces;
        # same-origin/same-site/none (direct navigation) are all legitimate.
        return sec_fetch_site != "cross-site"
    origin = request.headers.get("origin")
    if origin is not None:
        return origin.rstrip("/") == str(request.base_url).rstrip("/")
    referer = request.headers.get("referer")
    if referer is not None:
        return urlsplit(referer).netloc == request.url.netloc
    # No browser-origin signal at all: a plain script/CLI/curl client, not a
    # browser a CSRF attack could puppet. Ambient-cookie/browser auth is the
    # thing CSRF exploits — a client with none of these headers has none.
    return True


async def csrf_guard(request: Request, call_next):
    if request.method in _UNSAFE_METHODS and not _same_site_request(request):
        return PlainTextResponse(
            "Cross-site request blocked (CSRF guard): this request's Origin/"
            "Sec-Fetch-Site did not match this server. Automate via the JSON "
            "API with an API key instead of a cross-site form/script.",
            status_code=403,
        )
    return await call_next(request)


# -- Host allowlist (DNS-rebinding guard) -------------------------------------
#
# With auth off, the UI trusts the network path. A page on attacker.example that
# re-resolves its own name to 127.0.0.1 is *same-origin* to the browser, so the
# Sec-Fetch-Site check above passes it. The one thing it cannot forge is the
# Host header: it still says attacker.example. Refusing unknown Hosts closes it.
_DEFAULT_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "testserver"}


def _allowed_ui_hosts() -> set[str] | None:
    raw = os.getenv("UI_ALLOWED_HOSTS", "").strip()
    if raw == "*":
        return None
    return _DEFAULT_HOSTS | {h.strip().lower() for h in raw.split(",") if h.strip()}


def _host_only(header: str) -> str:
    header = header.strip().lower()
    if header.startswith("["):  # [::1]:8100
        return header.split("]")[0] + "]"
    return header.rsplit(":", 1)[0] if header.count(":") == 1 else header


async def host_guard(request: Request, call_next):
    allowed = _allowed_ui_hosts()
    if allowed is not None and _host_only(request.headers.get("host", "")) not in allowed:
        return PlainTextResponse(
            "Host header not allowed. Set UI_ALLOWED_HOSTS=<name>[,<name>] to serve "
            "this UI under another hostname.",
            status_code=400,
        )
    return await call_next(request)


_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)


async def security_headers(request: Request, call_next):
    """Defence in depth: captured target responses are rendered in reports, so
    a CSP limits what a stored-XSS slip could do. No external origins are used
    by the UI, hence 'self' only."""
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


def _is_literal_private_host(host: str) -> bool:
    """True when `host` is written as an address that the scope validator's
    always-blocked ranges cover. Returns False for a name — deciding that needs
    DNS, which does not belong on a page render."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def _sidebar_chrome(user: User | None, path: str = "") -> dict:
    """What the sidebar says, computed cheaply enough to run on every request.

    Deliberately NOT `preflight.evaluate`: that resolves DNS for every
    environment, which is right for the Readiness pane and wrong for a nav
    decoration rendered on every page load. This answers the two questions a
    dot can carry — "is there a target" and "is its host authorized" — from the
    loaded config alone. The pane remains the authority; this is the hint that
    sends you to it.
    """
    if state.auth.enabled and user is None:
        # The engagement's name and hostname ARE engagement data — the same
        # data /api/health stopped handing out. A sidebar rendered beside the
        # login form would put the target back on an unauthenticated page.
        return {"auth_enabled": True}

    eng = state.engagement
    name = eng.active_environment or ""
    url = eng.environments.get(name, eng.target_base_url)
    host = preflight.host_of(url) if url else ""
    policy = eng.scope.policy

    if not url or not host:
        readiness = "BLOCK"
    elif host in policy.blocked_hosts:
        # The block-list is checked before the allow-list and always wins, so a
        # host on both is refused. The dot has to agree with the validator.
        readiness = "BLOCK"
    elif host not in policy.allowed_hosts:
        readiness = "BLOCK"
    elif _is_literal_private_host(host) and not policy.allow_private_ranges:
        # Only a literal address is judged here — resolving a NAME is a DNS
        # lookup, and this runs on every page load. A hostname that resolves
        # somewhere private is the Readiness pane's job.
        readiness = "BLOCK"
    elif not (eng.attacker and eng.victim):
        readiness = "WARN"
    else:
        readiness = "READY"

    registry = state.engagements
    # Only offered where switching is a choice. On an assessment screen the
    # engagement is the one that assessment was opened under, and showing a
    # picker there would invite exactly the mistake this is meant to prevent.
    switchable = not _ASSESSMENT_PATH.match(path or "")
    engagements: list[tuple[str, str]] = []
    if switchable:
        engagements = [(n, registry.describe(n)) for n in registry.names()]

    return {
        "engagement_name": name or (host or ""),
        "engagement_url": host or url,
        "readiness_state": readiness,
        "readiness_tag": "" if readiness == "READY" else "!",
        # Only a REAL signed-in identity. With auth off every request is the
        # same synthetic `local-admin`, and printing that in the footer named a
        # user who does not exist and a role nobody chose — it said nothing
        # except that the single-user mode has an internal placeholder.
        "user_name": user.name if (user and state.auth.enabled) else "",
        "auth_enabled": state.auth.enabled,
        "engagements": engagements,
        "current_engagement": registry.current_name,
    }


_ASSESSMENT_PATH = re.compile(r"^/assessment/([^/]+)")


def _engagement_for(request: Request) -> str:
    """Which engagement THIS request is about.

    An assessment always resolves to the engagement it was opened under, not to
    whatever the tester last picked. That ordering is the whole safety property:
    two tickets for two clients open in two tabs must not be able to aim one
    client's run at the other's target, and a selection stored per browser is
    exactly the kind of state that would let them.

    Everything else — the dashboard, the config panes — follows the selection,
    which is a cookie because it is a preference rather than an authorization.
    """
    match = _ASSESSMENT_PATH.match(request.url.path)
    if match:
        try:
            owner = state.repo.assessment_engagement(match.group(1))
        except Exception:  # a malformed id is a 404 further down, not a 500 here
            owner = ""
        if owner:
            return owner
    return request.query_params.get("engagement") or request.cookies.get("engagement") or ""


async def engagement_middleware(request: Request, call_next):
    """Bind the engagement before anything reads `state.engagement`."""
    if runtime.ready():
        try:
            chosen = state.engagements.select(_engagement_for(request))
        except Exception:
            logger.debug("could not select an engagement", exc_info=True)
            chosen = ""
        response = await call_next(request)
        # Remember an explicit pick, so the next page keeps it. Only from the
        # query string: a cookie set from a path would make navigating to
        # someone's assessment silently change what the dashboard shows.
        picked = request.query_params.get("engagement")
        if picked and picked == chosen:
            response.set_cookie("engagement", chosen, samesite="lax",
                                max_age=365 * 24 * 3600)
        return response
    return await call_next(request)


async def chrome_middleware(request: Request, call_next):
    """Bind the sidebar's contents for this request.

    Before state exists (the very first requests during startup) the shell
    falls back to its own defaults rather than failing to render a page.
    """
    if runtime.ready():
        try:
            user = state.auth.authenticate_session(request.cookies.get("session_key"))
            views.set_chrome(**_sidebar_chrome(user, request.url.path))
        except Exception:  # a decoration must never take a page down
            logger.debug("could not build sidebar chrome", exc_info=True)
    return await call_next(request)


async def lang_middleware(request: Request, call_next):
    """Resolve the page language once per request, from `?lang=` if the
    toggle was just clicked (see ui.lang_toggle_html), else the `lang` cookie,
    else English. views.py/views_assessment.py read it back via
    `app.core.i18n.get_lang()` rather than taking it as a parameter — see the
    ContextVar's docstring in i18n.py for why.

    A `?lang=` on the request is also the one signal that the user just chose
    a language, which is the only time this needs to (re-)set the cookie —
    every other request just carries the existing cookie forward unchanged.
    """
    query_lang = request.query_params.get("lang")
    lang = normalize_lang(query_lang or request.cookies.get(i18n.COOKIE_NAME))
    i18n.set_lang(lang)
    response = await call_next(request)
    if query_lang:
        response.set_cookie(
            i18n.COOKIE_NAME, lang, samesite="lax", max_age=365 * 24 * 3600,
        )
    return response


#: Outermost first. CSRF has to refuse a forged request before anything else
#: touches it — chrome authenticates the caller and loads the engagement, which
#: is work a request that is about to be 403'd should not cause.
#:
#: `add_middleware` prepends, so each registration wraps the previous one and
#: the LAST registered ends up outermost. Registering in reverse is what makes
#: the execution order match the order written here.
#: `engagement_middleware` runs before `chrome_middleware`, which renders the
#: sidebar's engagement card and so has to be told which one first.
_MIDDLEWARE = (security_headers, host_guard, csrf_guard, engagement_middleware,
               chrome_middleware, lang_middleware)


def register(app) -> None:
    for handler in reversed(_MIDDLEWARE):
        app.middleware("http")(handler)
