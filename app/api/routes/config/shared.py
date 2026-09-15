"""Helpers every configuration pane needs.

Rendering the page and redirecting back into the pane a save came from are
shared, so they live here rather than in whichever module happened to be
imported first.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import APIRouter
from fastapi.responses import (
    RedirectResponse,
)

from app.api import views
from app.api.runtime import state
from app.core import preflight
from app.core.config import settings_with_overrides
from app.mcp import MockJiraMCPClient, available_issue_keys, describe_jira_client

logger = logging.getLogger(__name__)

router = APIRouter()


def _parse_kv_lines(text: str, sep: str) -> dict[str, str]:
    """'Key: Value' or 'key=value' per line -> dict. Blank lines and lines
    without the separator are skipped rather than rejected, so a stray blank
    line at the end of a textarea doesn't turn into a validation error."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or sep not in line:
            continue
        k, v = line.split(sep, 1)
        k = k.strip()
        if k:
            result[k] = v.strip()
    return result


# -- configuration ----------------------------------------------------------
#
# Everything a run depends on is editable here, because the alternative was a
# results table full of BLOCKED rows and a README paragraph naming a JSON file.
# Each writer touches only the keys it owns and then reloads state, so the next
# run picks the change up without a restart.


def render_config(tab: str = "readiness", flash: str = "", error: str = "") -> str:
    eng = state.engagement
    readiness = preflight.evaluate(eng, state.engagement_path)
    return views.config_page(
        readiness=readiness,
        engagement=eng,
        engagement_path=state.engagement_path,
        limits=settings_with_overrides(eng.runner).limits,
        runtime=preflight.runtime_facts(),
        ai_evidence=preflight.ai_evidence_config_state(),
        jira_mode=describe_jira_client(state.jira),
        jira_live=not isinstance(state.jira, MockJiraMCPClient),
        jira_warning=state.jira_warning,
        jira_env=preflight.jira_env_facts(),
        jira_keys=available_issue_keys(state.jira),
        tab=tab,
        flash=flash,
        error=error,
    )


def config_redirect(tab: str, flash: str) -> RedirectResponse:
    return RedirectResponse(f"/config?tab={tab}&flash={quote(flash, safe='')}", status_code=303)


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]
