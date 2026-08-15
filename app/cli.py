"""Command-line driver for the full pipeline (no UI).

    python -m app.cli CRM-1234 --engagement config/engagement.json --execute

Runs import -> analyze -> design -> auto-approve (non-destructive) -> execute ->
report. Auto-approval here is a convenience for automation; the UI keeps a human
in the loop. Execution only happens with --execute AND a configured engagement.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from app.analysis import TestDesigner, build_analyzer
from app.core.config import Settings
from app.core.engagement import load_engagement
from app.database import Repository, init_db, make_engine, make_session_factory
from app.mcp import build_jira_client
from app.orchestrator import Orchestrator


async def _run(args) -> None:
    engine = make_engine()
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    engagement = load_engagement(args.engagement)
    jira = build_jira_client()
    await jira.connect()
    orch = Orchestrator(
        repo, jira,
        analyzer=build_analyzer(),
        designer=TestDesigner(engagement.attacker, engagement.victim),
    )

    aid = await orch.import_and_analyze(args.issue_key)
    print(f"analyzed  -> assessment {aid}")

    poc = Path(args.poc).read_text(encoding="utf-8") if args.poc else None
    tests = orch.design(aid, poc_python=poc)
    print(f"designed  -> {len(tests)} tests")

    # auto-approve non-destructive tests for the CLI convenience path
    approved = [t.test_id for t in tests if not t.is_destructive]
    orch.approve(aid, approved)
    print(f"approved  -> {len(approved)} non-destructive tests")

    if args.execute:
        if not engagement.target_base_url:
            print("execute   -> SKIPPED (no engagement target configured)")
        else:
            execs = orch.execute(aid, engagement.target_base_url, engagement.scope,
                                 engagement.vault, Settings.from_env())
            fails = [e for e in execs if e.verdict.result.value == "FAIL"]
            print(f"executed  -> {len(execs)} tests, {len(fails)} FAIL")
            for f in repo.get_findings(aid):
                print(f"  finding -> {f.finding_id} {f.severity.value} {f.title}")

    out = Path(args.report)
    out.write_text(orch.build_report_html(aid), encoding="utf-8")
    print(f"report    -> {out.resolve()}")


def main() -> None:
    p = argparse.ArgumentParser(description="API security testing pipeline")
    p.add_argument("issue_key", help="Jira issue key, e.g. CRM-1234")
    p.add_argument("--engagement", default="", help="path to engagement.json")
    p.add_argument("--poc", default="", help="path to a Python PoC to transpile")
    p.add_argument("--execute", action="store_true", help="run approved tests")
    p.add_argument("--report", default="reports/cli_report.html")
    args = p.parse_args()
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
