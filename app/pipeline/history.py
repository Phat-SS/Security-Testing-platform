"""Historical diffing for security regression testing.

Compares the findings of two assessments of the same issue/target so a team can
see, run over run: what's newly broken, what got fixed, and what's still open.
Findings are matched by their dedup_key (owasp | endpoint | mutation), so the
comparison is stable across runs even as finding_ids get renumbered.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas.finding import Finding


@dataclass
class FindingDiff:
    new: list[Finding] = field(default_factory=list)          # regressions
    fixed: list[Finding] = field(default_factory=list)        # resolved since prev
    persisting: list[Finding] = field(default_factory=list)   # still open

    @property
    def regressed(self) -> bool:
        return bool(self.new)

    def summary(self) -> dict:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "persisting": len(self.persisting),
            "regressed": self.regressed,
        }


def diff_findings(previous: list[Finding], current: list[Finding]) -> FindingDiff:
    prev_by_key = {f.dedup_key: f for f in previous}
    curr_by_key = {f.dedup_key: f for f in current}

    diff = FindingDiff()
    for key, f in curr_by_key.items():
        (diff.persisting if key in prev_by_key else diff.new).append(f)
    for key, f in prev_by_key.items():
        if key not in curr_by_key:
            diff.fixed.append(f)
    return diff


def render_diff_comment(issue_key: str, diff: FindingDiff) -> str:
    """Jira-ready regression note."""
    verdict = "⚠️ REGRESSION" if diff.regressed else (
        "✅ No new findings" if not diff.persisting else "→ No new findings (some still open)")
    lines = [f"*Security Regression — {issue_key}*", verdict, ""]
    if diff.new:
        lines.append("New (regressions):")
        lines += [f"- {f.finding_id} {f.title} — {f.severity.value} — {f.endpoint}" for f in diff.new]
    if diff.fixed:
        lines.append("Fixed since last run:")
        lines += [f"- {f.title} — {f.endpoint}" for f in diff.fixed]
    if diff.persisting:
        lines.append("Still open:")
        lines += [f"- {f.finding_id} {f.title} — {f.severity.value}" for f in diff.persisting]
    return "\n".join(lines)
