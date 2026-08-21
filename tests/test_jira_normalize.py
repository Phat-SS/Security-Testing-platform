from app.mcp.adf import adf_to_text, extract_list_items
from app.mcp.live import _parse_tool_result
from app.mcp.normalize import normalize_issue

ADF_DESC = {
    "type": "doc", "version": 1,
    "content": [
        {"type": "paragraph", "content": [
            {"type": "text", "text": "DELETE /customers/{customerId} removes a customer. "},
            {"type": "text", "text": "Requires Bearer JWT."}]},
        {"type": "bulletList", "content": [
            {"type": "listItem", "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": "Agent can read own customers."}]}]},
            {"type": "listItem", "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": "Agent cannot read others'."}]}]},
        ]},
    ],
}

RAW_ISSUE = {
    "key": "CRM-1234",
    "fields": {
        "project": {"key": "CRM"},
        "summary": "Customer delete API",
        "description": ADF_DESC,
        "labels": ["security", "api"],
        "components": [{"name": "crm-api"}],
        "comment": {"comments": [
            {"body": {"type": "doc", "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": "Please test expired tokens."}]}]}}]},
        "customfield_10001_acceptance": ADF_DESC["content"][1],
        "issuelinks": [{"outwardIssue": {"key": "CRM-1000"}}],
    },
}


def test_adf_flattens_text():
    text = adf_to_text(ADF_DESC)
    assert "DELETE /customers/{customerId}" in text
    assert "Bearer JWT" in text


def test_adf_list_items():
    items = extract_list_items(ADF_DESC)
    assert "Agent can read own customers." in items
    assert len(items) == 2


def test_normalize_issue_full():
    issue = normalize_issue(RAW_ISSUE)
    assert issue.issue_key == "CRM-1234"
    assert issue.project_key == "CRM"
    assert "customerId" in issue.description
    assert issue.labels == ["security", "api"]
    assert issue.components == ["crm-api"]
    assert issue.comments and "expired tokens" in issue.comments[0]
    assert issue.acceptance_criteria  # pulled from the custom field
    assert "CRM-1000" in issue.links


def test_normalized_issue_feeds_analyzer():
    from app.analysis import HeuristicAnalyzer

    analysis = HeuristicAnalyzer().analyze(normalize_issue(RAW_ISSUE))
    assert analysis.endpoints
    assert analysis.applicable_categories()


def test_parse_tool_result_from_content_blocks():
    class Block:
        text = '{"key": "CRM-9", "fields": {"summary": "x"}}'

    class Result:
        content = [Block()]

    parsed = _parse_tool_result(Result())
    assert parsed["key"] == "CRM-9"


def test_parse_tool_result_plain_dict():
    assert _parse_tool_result({"key": "CRM-1"})["key"] == "CRM-1"


def test_acceptance_criteria_uses_jira_field_display_names():
    raw = {
        "key": "CRM-2",
        "names": {"customfield_12345": "Acceptance Criteria"},
        "fields": {
            "summary": "x",
            "customfield_12345": "- Must reject another tenant's object",
        },
    }

    issue = normalize_issue(raw)

    assert issue.acceptance_criteria == ["Must reject another tenant's object"]


def test_snapshot_marks_a_paginated_comment_block_incomplete():
    raw = {
        "key": "CRM-3",
        "fields": {
            "summary": "x",
            "comment": {"total": 3, "comments": [{"body": "first"}]},
        },
    }

    issue = normalize_issue(raw)
    snapshot = issue.snapshot()

    assert not issue.comments_complete
    assert not snapshot["complete"]
    assert len(snapshot["snapshot_hash"]) == 64
    assert "3 comment" in snapshot["warnings"][0]
