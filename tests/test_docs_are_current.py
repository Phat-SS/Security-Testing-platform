"""The documentation describes this product, not a previous one.

Docs going stale is a process problem, not a writing one — which is why this is
a test rather than a resolution. Every setting the code reads has to be written
down somewhere a reader will find it, and the README must not still be
describing a screen that no longer exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Read by the code but not settings anybody configures.
_INTERNAL = {
    # Pointed at a nonexistent file by the test suite so the developer's own
    # .env never leaks into a run; not something an install sets.
    "RUNTIME_ENV_PATH",
    # The operating system's, read to locate a system binary — not ours to
    # document.
    "SYSTEMROOT",
}


def _documented() -> str:
    return "\n".join(
        (ROOT / name).read_text(encoding="utf-8")
        for name in ("README.md", "docs/configuration.md", ".env.example")
        if (ROOT / name).exists()
    )


def _env_vars_read_by_the_code() -> set[str]:
    found: set[str] = set()
    for path in (ROOT / "app").rglob("*.py"):
        for match in re.finditer(r'os\.(?:getenv|environ\.get)\(\s*["\']([A-Z][A-Z0-9_]+)["\']',
                                 path.read_text(encoding="utf-8")):
            found.add(match.group(1))
    return found - _INTERNAL


def test_every_setting_the_code_reads_is_written_down():
    undocumented = sorted(v for v in _env_vars_read_by_the_code() if v not in _documented())

    assert not undocumented, (
        "these are read from the environment but appear in no README, no "
        f"docs/configuration.md and no .env.example: {undocumented}"
    )


@pytest.mark.parametrize("gone", [
    "Six numbered, collapsible steps",
    "six collapsible steps",
    "in four tabs ordered",
])
def test_the_readme_does_not_describe_the_screen_it_used_to_have(gone):
    """Six stacked steps became four phases, and the configuration tab became a
    sidebar section. A README that describes a different product is worse than a
    short one."""
    assert gone not in (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_readme_covers_what_was_added():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for topic in ("ENGAGEMENTS_DIR", "OpenAPI", "max_concurrent_tests", "Scope"):
        assert topic in readme, f"{topic} is not mentioned anywhere in the README"
