"""Jira Cloud issue JSON → NormalizedIssue.

The seam between "whatever Jira/MCP returns" and "what our pipeline consumes".
Pure and testable: give it a raw issue dict (REST v3 / MCP shape), get back a
NormalizedIssue. The live client (live.py) does the I/O and hands the raw dict
here; the mock hardcodes NormalizedIssue directly.
"""

from __future__ import annotations

from app.mcp.adf import adf_to_text, extract_list_items
from app.mcp.jira import NormalizedIssue

# Common custom-field names people use for acceptance criteria. Real instances
# vary; this covers the usual suspects and degrades gracefully.
_AC_HINTS = ("acceptance", "acceptancecriteria")


def normalize_issue(raw: dict) -> NormalizedIssue:
    key = raw.get("key", "")
    fields = raw.get("fields", {}) or {}
    field_names = raw.get("names") or raw.get("fieldNames") or {}

    project = (fields.get("project") or {}).get("key") or key.split("-", 1)[0]
    summary = fields.get("summary", "") or ""
    description = adf_to_text(fields.get("description"))

    # Comments: Jira nests them under fields.comment.comments[].body (ADF).
    comment_block = fields.get("comment") or {}
    comments = [
        adf_to_text(c.get("body")).strip()
        for c in comment_block.get("comments", [])
        if adf_to_text(c.get("body")).strip()
    ]

    labels = list(fields.get("labels", []) or [])
    components = [c.get("name", "") for c in fields.get("components", []) or []]
    environment = adf_to_text(fields.get("environment")) or fields.get("environment") or ""
    if not isinstance(environment, str):
        environment = ""

    attachments = [a.get("filename", "") for a in fields.get("attachment", []) or []]

    # Acceptance criteria: look for a custom field whose value is a list/ADF.
    acceptance = _extract_acceptance(fields, field_names)

    links = _extract_links(fields)

    total_comments = comment_block.get("total")
    comments_complete = total_comments is None or int(total_comments) <= len(
        comment_block.get("comments", []) or []
    )
    warnings = []
    if not comments_complete:
        warnings.append(
            f"Jira returned {len(comments)} of {total_comments} comment(s); pagination is incomplete."
        )

    return NormalizedIssue(
        issue_key=key,
        project_key=project,
        summary=summary,
        description=description,
        acceptance_criteria=acceptance,
        comments=comments,
        attachments=attachments,
        labels=labels,
        components=[c for c in components if c],
        environment=environment,
        links=links,
        updated_at=str(fields.get("updated", "") or ""),
        comments_complete=comments_complete,
        fields_complete=bool(fields),
        completeness_warnings=warnings,
    )


def _extract_acceptance(fields: dict, field_names: dict | None = None) -> list[str]:
    field_names = field_names or {}
    for name, value in fields.items():
        display_name = str(field_names.get(name, name))
        normalized_name = "".join(ch for ch in display_name.lower() if ch.isalnum())
        if any(h in normalized_name for h in _AC_HINTS) and value:
            items = extract_list_items(value)
            if items:
                return items
            text = adf_to_text(value).strip()
            if text:
                return [line.strip("-• ") for line in text.splitlines() if line.strip()]
    return []


def _extract_links(fields: dict) -> list[str]:
    links: list[str] = []
    for link in fields.get("issuelinks", []) or []:
        for side in ("outwardIssue", "inwardIssue"):
            issue = link.get(side)
            if issue:
                links.append(issue.get("key", ""))
    return [key for key in links if key]
