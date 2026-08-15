"""Atlassian Document Format (ADF) → plain text.

Jira Cloud returns rich text (description, comments) as ADF, a nested JSON tree,
not a string. This flattens it to readable text so the analyzer has something to
work with. Pure function, no I/O — fully testable with fixtures.
"""

from __future__ import annotations


def adf_to_text(node) -> str:
    """Flatten an ADF document (or any node) to plain text.

    Accepts a str (returned as-is), a dict node, or a list of nodes. Unknown
    node types degrade to their children's text rather than raising.
    """
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(adf_to_text(n) for n in node)
    if not isinstance(node, dict):
        return str(node)

    node_type = node.get("type")

    if node_type == "text":
        return node.get("text", "")
    if node_type == "hardBreak":
        return "\n"
    if node_type == "mention":
        return "@" + node.get("attrs", {}).get("text", "user")
    if node_type in ("codeBlock", "code"):
        return adf_to_text(node.get("content", []))

    children = adf_to_text(node.get("content", []))

    # Block-level nodes get separated by newlines so structure survives.
    if node_type in ("paragraph", "heading", "listItem", "blockquote"):
        return children + "\n"
    if node_type in ("bulletList", "orderedList"):
        return children
    return children


def extract_list_items(node) -> list[str]:
    """Pull top-level bullet/ordered list items as separate strings — handy for
    turning an ADF acceptance-criteria list into a Python list."""
    items: list[str] = []
    _walk_list_items(node, items)
    return [i.strip() for i in items if i.strip()]


def _walk_list_items(node, out: list[str]) -> None:
    if isinstance(node, list):
        for n in node:
            _walk_list_items(n, out)
        return
    if not isinstance(node, dict):
        return
    if node.get("type") == "listItem":
        out.append(adf_to_text(node.get("content", [])).strip())
        return
    _walk_list_items(node.get("content", []), out)
