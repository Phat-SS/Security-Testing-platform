"""Signing in and out.

The browser UI is plain HTML forms, so it cannot send an API key header;
`/login` exchanges the key for an opaque session cookie instead.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import quote

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)

from app.api import views
from app.api.runtime import state

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(flash: str = "") -> str:
    return views.login_page(flash=flash)


@router.post("/login")
async def login_submit(request: Request, api_key: str = Form(...)):
    # The address a rejected attempt came from, for the lockout and the log.
    # `client.host` and not a forwarded header: this decides who gets slowed
    # down, and a value the caller supplies is a value the caller chooses.
    source = request.client.host if request.client else ""

    waiting = state.auth.locked_out(source)
    if waiting:
        return RedirectResponse(
            f"/login?flash={quote(f'Too many attempts — wait {int(waiting) + 1}s', safe='')}",
            status_code=303,
        )

    user = state.auth.authenticate(api_key)
    # Only meaningful when AUTH_ENABLED=true; when auth is off, authenticate()
    # always returns the built-in admin regardless of the key, so this can't
    # be used to probe for valid keys in that mode.
    if not user or not state.auth.enabled:
        if state.auth.enabled:
            # Not counted when auth is off: every key "succeeds" there, so a
            # rejection is impossible and a count would only ever be noise.
            state.auth.note_failure(source)
        return RedirectResponse("/login?flash=Invalid+API+key", status_code=303)
    state.auth.note_success(source)
    session_token = state.auth.issue_session(user)
    resp = RedirectResponse(f"/?flash=Logged+in+as+{quote(user.name, safe='')}", status_code=303)
    resp.set_cookie(
        "session_key", session_token, httponly=True, samesite="lax",
        secure=(os.getenv("AUTH_COOKIE_SECURE", "").lower() == "true"
                or os.getenv("PLATFORM_BASE_URL", "").lower().startswith("https://")),
        max_age=state.auth.session_ttl_s,
    )
    return resp


@router.post("/logout")
async def logout(session_key: str | None = Cookie(None)):
    state.auth.revoke_session(session_key)
    resp = RedirectResponse("/?flash=Logged+out", status_code=303)
    resp.delete_cookie("session_key")
    return resp
