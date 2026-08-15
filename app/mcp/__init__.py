from .jira import JiraMCPClient, NormalizedIssue, parse_issue_ref
from .mock import MockJiraMCPClient, known_issue_keys
from .normalize import normalize_issue


def build_jira_client():
    """Factory: live MCP client if JIRA_MCP_URL is set, else the offline mock."""
    from .live import LiveJiraMCPClient

    if LiveJiraMCPClient.is_configured():
        return LiveJiraMCPClient()
    return MockJiraMCPClient()


def describe_jira_client(client) -> str:
    """Non-secret label for the UI/health endpoint. Never leaks credentials."""
    describe = getattr(client, "describe", None)
    return describe() if callable(describe) else "mock Jira (offline)"


def available_issue_keys(client) -> list[str]:
    """Keys the client can serve, when it can enumerate them (the mock can; a
    live instance is not enumerated — that would be a JQL query, not a hint)."""
    keys = getattr(client, "available_keys", None)
    return list(keys()) if callable(keys) else []


__all__ = [
    "JiraMCPClient",
    "NormalizedIssue",
    "parse_issue_ref",
    "MockJiraMCPClient",
    "known_issue_keys",
    "normalize_issue",
    "build_jira_client",
    "describe_jira_client",
    "available_issue_keys",
]
