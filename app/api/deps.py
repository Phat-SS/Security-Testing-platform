"""Route dependencies: who the caller is, and whether they may proceed.

Split out of `main.py` so that every route module depends on the same two
functions rather than importing them from whichever module happened to define
them first.
"""

from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException

from app.api.runtime import state
from app.core.auth import User


def optional_user(x_api_key: str | None = Header(None),
                  authorization: str | None = Header(None),
                  session_key: str | None = Cookie(None)) -> User | None:
    """Resolve the caller, or None. With AUTH_ENABLED unset this is always the
    built-in local admin, so single-user mode is unchanged by any of this."""
    key = x_api_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization.split(" ", 1)[1]
    return state.auth.authenticate(key) if key else state.auth.authenticate_session(session_key)


def current_user(user: User | None = Depends(optional_user)) -> User:
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return user


def require(min_role: str):
    def _dep(user: User = Depends(current_user)) -> User:
        if not user.can(min_role):
            raise HTTPException(status_code=403, detail=f"Requires role >= {min_role}")
        return user
    return _dep


def require_page(min_role: str = "viewer"):
    """`require`, for routes a browser navigates to.

    Same decision, different failure: a bare 401 in the address bar is a dead
    end a person cannot act on, so an unauthenticated *page* request is sent to
    the login form instead. An insufficient ROLE still 403s — that one is not
    fixable by logging in again as the same user.

    Read access needs guarding at all because the answers here are the
    engagement itself: captured request/response evidence, the approved scope,
    persona names, and every export. Before this, `AUTH_ENABLED=true` protected
    only writes, which made the `viewer` role decorative and left every
    assessment readable by anyone who could reach the port.
    """

    def _dep(user: User | None = Depends(optional_user),
             accept: str | None = Header(None)) -> User:
        if user is None:
            # A browser NAVIGATION gets the login form; anything else gets 401.
            # Without the distinction `curl -L -o report.json .../export.json`
            # follows the redirect, writes the login page into the file and
            # exits 0 — a silent wrong answer, worse than a refusal.
            if not (accept and "text/html" in accept):
                raise HTTPException(status_code=401, detail="Invalid or missing API key")
            raise HTTPException(
                status_code=303, detail="Log in to continue",
                headers={"Location": "/login?flash=Log+in+to+continue"},
            )
        if not user.can(min_role):
            raise HTTPException(status_code=403, detail=f"Requires role >= {min_role}")
        return user

    return _dep
