"""The assessment list.
"""

from __future__ import annotations

import logging

from collections import Counter

from fastapi import APIRouter, Depends
from fastapi.responses import (
    HTMLResponse,
)

from app.analysis.claude_analyzer import ClaudeAnalyzer
from app.api import views
from app.api.deps import require_page
from app.api.runtime import state
from app.core.auth import User
from app.mcp import available_issue_keys, describe_jira_client

logger = logging.getLogger(__name__)

router = APIRouter()


_DASH_SORTS = {"recent", "oldest", "issue", "findings"}


@router.get("/", response_class=HTMLResponse)
async def dashboard(flash: str = "", q: str = "", status: str = "",
                    sort: str = "recent", page: int = 1, per: int = 24,
                    user: User = Depends(require_page())) -> str:
    # Same rule as /findings and /activity: this engagement's assessments plus
    # unstamped ones. Bulk delete and the charts are built from this list.
    current = state.engagements.current_name
    everything = [a for a in state.repo.list_assessments()
                  if not current or (a.engagement or "") in (current, "")]
    # Counts per card, from one query each rather than loading every test case of
    # every assessment: a card that says only "Executed" tells you the one thing
    # you already knew and nothing about what the run found.
    rows = [state.repo.assessment_summary(a.id) for a in everything]
    by_id = {r["id"]: r for r in rows}

    needle = q.strip().lower()
    # Two stages, because the status chips need counts: `searched` is what the
    # query alone matched (that is what each chip counts within), and `shown`
    # applies the chip on top. Counting the chips against `shown` would make
    # every chip except the selected one read 0.
    searched = [
        a for a in everything
        if not needle or needle in a.issue_key.lower() or needle in a.id.lower()
    ]
    status_counts = Counter(a.status for a in searched)
    shown = [a for a in searched if not status or a.status == status]
    if sort not in _DASH_SORTS:
        sort = "recent"
    if sort == "oldest":
        shown = list(reversed(shown))
    elif sort == "issue":
        shown = sorted(shown, key=lambda a: a.issue_key)
    elif sort == "findings":
        shown = sorted(shown, key=lambda a: -by_id[a.id]["n_findings"])

    per = max(1, min(per, 96))
    # Clamped to a page that exists. Filtering down from page 4 of the unfiltered
    # list used to land on an empty grid reading "no assessments match" when
    # several did — they were just all on page 1.
    pages = max(1, -(-len(shown) // per))
    page = min(max(1, page), pages)
    window = shown[(page - 1) * per: page * per]

    # Chart series describe the engagement, not the current page or search:
    # newest first, only assessments that have something to show.
    # The same ticket is often assessed more than once; its key alone would
    # label two different bars identically, so a repeat gets its id's tail.
    key_counts = Counter(a.issue_key for a in everything)

    def label(a) -> str:
        return a.issue_key if key_counts[a.issue_key] == 1 else f"{a.issue_key}·{a.id[-4:]}"

    severity_series = [
        (label(a), f"/assessment/{a.id}?phase=results", by_id[a.id]["severities"])
        for a in everything
        if any(by_id[a.id]["severities"].get(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    ][:6]
    outcome_series = [
        (label(a), f"/assessment/{a.id}?phase=results", state.repo.execution_verdicts(a.id))
        for a in [a for a in everything if by_id[a.id]["n_executions"]][:8]
    ]

    return views.dashboard(
        window,
        state.engagement.target_base_url,
        ai_on=ClaudeAnalyzer.is_enabled(),
        jira_mode=describe_jira_client(state.jira),
        available_keys=available_issue_keys(state.jira),
        warning=state.jira_warning,
        flash=flash,
        rows=[by_id[a.id] for a in window],
        q=q,
        status=status,
        sort=sort,
        severity_series=severity_series,
        outcome_series=list(reversed(outcome_series)),
        page_no=page,
        per=per,
        total_matched=len(shown),
        status_counts=dict(status_counts),
        # The strip above the list describes the install, not the filter — so
        # it is counted over everything, before either stage above.
        totals={"ALL": len(everything), **Counter(a.status for a in everything)},
    )
