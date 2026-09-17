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
    everything = state.repo.list_assessments()
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
        page_no=page,
        per=per,
        total_matched=len(shown),
        status_counts=dict(status_counts),
        # The strip above the list describes the install, not the filter — so
        # it is counted over everything, before either stage above.
        totals={"ALL": len(everything), **Counter(a.status for a in everything)},
    )
