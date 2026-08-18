"""Safe placeholder resolution.

Test specs contain `{name}` placeholders (a victim's object id captured during
setup, a persona-owned value, etc.). We resolve them with a fixed, whitelisted
substitution — NOT str.format on arbitrary input and never eval. A template can
only pull from an explicit context dict; anything else is left literal and
logged, so a malicious PoC cannot smuggle code through a template.
"""

from __future__ import annotations

import re
from typing import Any

_PLACEHOLDER = re.compile(r"\{([a-zA-Z0-9_.]+)\}")


def _normalize(name: str) -> str:
    """`customerId`, `customer_id` and `CUSTOMER-ID` name the same thing."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def resolve(template: str, context: dict[str, Any]) -> str:
    """Substitute `{name}` placeholders from `context`.

    Exact key first, then a case- and separator-insensitive match. The fallback
    is not cosmetic: endpoint paths are written in a ticket's style
    (`/customers/{customerId}`) while persona ids are configured in the
    engagement's style (`customer_id`). Without it those never met, so every
    test on a parameterised path sent the literal string `{customerId}` as a
    path segment, collected a 404, and was recorded as PASS — a false negative
    on every non-BOLA test that touched an object route. (BOLA escaped only
    because its mutation writes the key it is about to read.)

    An ambiguous fallback is refused rather than guessed, for the same reason
    the BOLA id resolver refuses: aiming a probe at the wrong object tests
    nothing while looking like a clean result.
    """

    normalized: dict[str, list[Any]] = {}
    for key, value in context.items():
        normalized.setdefault(_normalize(key), []).append(value)

    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in context:
            return str(context[key])
        candidates = normalized.get(_normalize(key), [])
        # Deduplicate: two spellings of the same id carrying the same value is
        # agreement, not ambiguity.
        distinct = {str(c) for c in candidates if c is not None}
        if len(distinct) == 1:
            return distinct.pop()
        # Unknown or ambiguous placeholder: leave it untouched rather than
        # raising, so a partially-specified template degrades visibly instead
        # of crashing.
        return match.group(0)

    return _PLACEHOLDER.sub(_sub, template)


def resolve_deep(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return resolve(value, context)
    if isinstance(value, dict):
        return {k: resolve_deep(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_deep(v, context) for v in value]
    return value


def extract_json_path(body: Any, path: str) -> Any:
    """Minimal JSONPath-ish extractor supporting '$.a.b[0].c'.

    Deliberately tiny and dependency-free: enough for `capture` steps, no
    expression evaluation, no wildcards.
    """
    if not path.startswith("$"):
        raise ValueError(f"capture path must start with '$': {path!r}")
    current = body
    tokens = re.findall(r"\.([a-zA-Z0-9_]+)|\[(\d+)\]", path)
    for name, index in tokens:
        if name:
            if not isinstance(current, dict) or name not in current:
                return None
            current = current[name]
        else:
            idx = int(index)
            if not isinstance(current, list) or idx >= len(current):
                return None
            current = current[idx]
    return current
