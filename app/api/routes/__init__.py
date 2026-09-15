"""Every HTTP route, grouped by what it is for.

One module per part of the workflow, in the order a tester meets them. The
split is mechanical — the handler bodies are what they were in `main.py` — and
the suite is what proves it: no route path, status code or rendered string
changed, so any behavioural difference shows up as a failing test rather than
as a surprise in production.

Registration order is not load-bearing. A path parameter never matches across a
`/`, so `/assessment/{aid}` cannot shadow `/assessment/{aid}/report` however
the two are ordered — verified, not assumed. The order below is the order a
tester meets these screens, and nothing else depends on it.
"""

from __future__ import annotations

from fastapi import FastAPI

from . import (
    admin,
    assessments,
    auth,
    config,
    dashboard,
    execution,
    insight,
    integrations,
    jsonapi,
    plan,
    reporting,
)

_MODULES = (
    auth,
    dashboard,
    config,
    integrations,
    insight,
    assessments,
    plan,
    execution,
    reporting,
    jsonapi,
    admin,
)


def register(app: FastAPI) -> None:
    for module in _MODULES:
        app.include_router(module.router)
