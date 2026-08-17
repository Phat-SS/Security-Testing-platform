"""In-memory Jira MCP client for offline development and tests.

Implements the JiraMCPClient shape with canned tickets so the whole pipeline
runs with no Jira access. The real connector (app/mcp/live.py, Phase 2) swaps in
behind the same interface without touching anything downstream.
"""

from __future__ import annotations

from app.mcp.jira import NormalizedIssue

_SAMPLE: dict[str, NormalizedIssue] = {
    "CRM-1234": NormalizedIssue(
        issue_key="CRM-1234",
        project_key="CRM",
        summary="Customer detail and delete API",
        description=(
            "Implement customer endpoints for the CRM agent console.\n"
            "GET /customers/{customerId} returns a customer profile.\n"
            "DELETE /customers/{customerId} deletes a customer.\n"
            "All endpoints require a Bearer JWT. Only the owning agent or an "
            "admin may act on a customer.\n"
            "PoC: python poc_customer.py --env staging"
        ),
        acceptance_criteria=[
            "An agent can read customers they own.",
            "An agent cannot read or delete another agent's customer.",
            "Unauthenticated requests are rejected with 401.",
        ],
        comments=["QA: please also test with an expired token."],
        labels=["security", "api"],
        components=["crm-api"],
        environment="staging",
    ),
    "CRM-1300": NormalizedIssue(
        issue_key="CRM-1300",
        project_key="CRM",
        summary="Bulk customer export with webhook notification",
        description=(
            "POST /customers/export starts a bulk export with pagination and a "
            "search filter. On completion the service POSTs to a caller-supplied "
            "callback url (webhook). Requires Bearer JWT."
        ),
        acceptance_criteria=["Export supports pagination and filtering."],
        labels=["api"],
        components=["crm-api"],
        environment="staging",
    ),
    # A wider-surface sample: exercises BOLA, BFLA (admin), mass assignment,
    # unrestricted resource consumption and an SSRF-shaped callback field in one
    # ticket, so the coverage matrix lights up across categories.
    #
    # Deliberately keyed MOCK-*, not a real project prefix. A fake ticket sharing
    # a key with a live one would let a mock-generated report — and post_comment —
    # be filed against a genuine finding.
    "MOCK-345": NormalizedIssue(
        issue_key="MOCK-345",
        project_key="MOCK",
        summary="Bounty submission API — customer report intake and triage",
        description=(
            "Expose the report intake surface for the agent console.\n"
            "GET /customers/{customerId} returns the reporter profile.\n"
            "GET /reports/{reportId} returns a single submitted report.\n"
            "PATCH /reports/{reportId} updates title, description and severity.\n"
            "DELETE /reports/{reportId} withdraws a report.\n"
            "POST /reports/{reportId}/triage sets triage state and payout tier — "
            "admin only.\n"
            "POST /reports/export starts a bulk export with pagination and a "
            "search filter, then POSTs the result to a caller-supplied "
            "callbackUrl (webhook).\n"
            "All endpoints require a Bearer JWT. An agent may only act on "
            "reports they own; only an admin may triage or set a payout tier.\n"
            "PoC: python poc_report_access.py --env staging"
        ),
        acceptance_criteria=[
            "An agent can read and update reports they own.",
            "An agent cannot read, update or withdraw another agent's report.",
            "A non-admin agent cannot triage a report or set a payout tier.",
            "Payout tier and triage state cannot be set through PATCH /reports/{reportId}.",
            "Unauthenticated requests are rejected with 401.",
        ],
        comments=[
            "QA: the callbackUrl on export is not validated — check internal targets.",
            "QA: please also test with an expired token.",
        ],
        labels=["security", "api", "sample"],
        components=["bounty-api"],
        environment="staging",
    ),
}


def known_issue_keys() -> list[str]:
    """Issue keys the offline mock can serve — surfaced in the UI so an unknown
    key is a self-explanatory error instead of a 500."""
    return list(_SAMPLE)


class MockJiraMCPClient:
    def __init__(self) -> None:
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def test_connection(self) -> bool:
        return self._connected

    def available_keys(self) -> list[str]:
        return known_issue_keys()

    async def get_issue(self, issue_key: str) -> NormalizedIssue:
        if issue_key not in _SAMPLE:
            raise KeyError(f"Unknown issue {issue_key}. Known: {list(_SAMPLE)}")
        return _SAMPLE[issue_key]

    async def list_project_issues(self, project_key: str) -> list[NormalizedIssue]:
        return [i for i in _SAMPLE.values() if i.project_key == project_key]

    async def get_comments(self, issue_key: str) -> list[str]:
        return (await self.get_issue(issue_key)).comments

    async def add_comment(self, issue_key: str, comment: str) -> None:
        # Mock: record on the issue so tests can assert it was "posted".
        issue = await self.get_issue(issue_key)
        issue.comments.append(comment)

    async def get_attachments(self, issue_key: str) -> list[bytes]:
        return []

    def browse_url(self, issue_key: str) -> str | None:
        # No real Jira site backs these sample tickets — nothing honest to link to.
        return None
