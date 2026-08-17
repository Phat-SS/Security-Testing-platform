"""Pull PoC scripts embedded in a Jira issue's description text.

Some intake workflows (e.g. an automated bounty-hunter tool) file tickets whose
description embeds the PoC directly: a bare filename line followed by a fenced
```python code block. This scans for that shape so the platform can feed it
straight into the existing PoC transpiler instead of a human having to copy it
out of Jira by hand. Pure text parsing — nothing here executes the PoC; the
result is just handed to `transpile_python`, which only ever reads the AST.
"""

from __future__ import annotations

import re

_CODE_FENCE_RE = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_FILENAME_RE = re.compile(r"^[\w.\-]+\.py$")


def extract_poc_scripts(description: str) -> list[tuple[str, str]]:
    """Return [(filename, code), ...] for every fenced Python block found.

    A block whose immediately preceding non-blank line looks like a bare
    `some_name.py` filename uses that as its label; otherwise it gets a
    generated one. Returns an empty list if the description has no fenced
    Python code at all (the common case for tickets with no PoC).
    """
    scripts: list[tuple[str, str]] = []
    for match in _CODE_FENCE_RE.finditer(description):
        code = match.group(1).rstrip()
        if not code.strip():
            continue
        filename = _preceding_filename(description, match.start()) or f"poc_{len(scripts) + 1}.py"
        scripts.append((filename, code))
    return scripts


def _preceding_filename(text: str, fence_start: int) -> str:
    before = text[:fence_start].rstrip("\n")
    last_line = before.rsplit("\n", 1)[-1].strip()
    return last_line if _FILENAME_RE.fullmatch(last_line) else ""


def combined_poc_source(description: str) -> str:
    """Concatenate every embedded script into one source blob for
    `transpile_python`. Scripts are joined in source order with a comment
    banner per file; multiple independent scripts sharing variable names
    (e.g. every PoC defining its own `BASE`) resolve fine since the
    transpiler tracks assignments in order, same as it would within one
    file."""
    scripts = extract_poc_scripts(description)
    if not scripts:
        return ""
    return "\n\n".join(f"# --- {filename} ---\n{code}" for filename, code in scripts)
