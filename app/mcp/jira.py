"""Jira MCP connector interface (Phase 2 stub).

The UI must never see Jira API details — it talks to this abstraction. The real
implementation backs onto the official MCP Python SDK; the interface here is
what the rest of the app depends on, so it can be built and tested against a
fake before the MCP wiring exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class NormalizedIssue:
    """What the rest of the pipeline consumes — never the raw Jira payload."""

    issue_key: str
    project_key: str
    summary: str = ""
    description: str = ""
    acceptance_criteria: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    environment: str = ""
    links: list[str] = field(default_factory=list)


class JiraMCPClient(Protocol):
    async def connect(self) -> None: ...
    async def test_connection(self) -> bool: ...
    async def get_issue(self, issue_key: str) -> NormalizedIssue: ...
    async def list_project_issues(self, project_key: str) -> list[NormalizedIssue]: ...
    async def get_comments(self, issue_key: str) -> list[str]: ...
    async def add_comment(self, issue_key: str, comment: str) -> None: ...
    async def get_attachments(self, issue_key: str) -> list[bytes]: ...


def parse_issue_ref(text: str) -> tuple[str, str]:
    """Normalize a Jira URL or bare key into (project_key, issue_key).

    Accepts 'https://x/browse/CRM-1234' or 'CRM-1234'.
    """
    text = text.strip().rstrip("/")
    if "/browse/" in text:
        text = text.split("/browse/", 1)[1]
    key = text.split("?", 1)[0]
    if "-" not in key:
        raise ValueError(f"Not a valid Jira issue key: {key!r}")
    project = key.split("-", 1)[0]
    return project, key
