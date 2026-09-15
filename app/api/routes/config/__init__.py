"""The engagement configuration screens.

Every writer here reads the whole document, changes only the keys it owns and
writes it back, so hand-written comments and keys the UI does not expose survive
a save made through the browser.

One module per pane, in the order a new engagement needs them. `shared` holds
the two things they all use: rendering the page, and redirecting back into the
pane a save came from.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import environments, identities, pages, runtime, scope
from .shared import config_redirect, render_config  # noqa: F401  (re-exported)

router = APIRouter()
for _module in (pages, environments, scope, identities, runtime):
    router.include_router(_module.router)
