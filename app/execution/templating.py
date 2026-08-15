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


def resolve(template: str, context: dict[str, Any]) -> str:
    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in context:
            return str(context[key])
        # Unknown placeholder: leave it untouched rather than raising, so a
        # partially-specified template degrades visibly instead of crashing.
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
