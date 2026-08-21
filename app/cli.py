"""Command-line driver for the full pipeline (no UI).

    python -m app.cli CRM-1234 --engagement config/engagement.json --execute

Runs import -> analyze -> design -> review the plan -> auto-approve
(non-destructive) -> execute -> assess the results -> report. Auto-approval here
is a convenience for automation; the UI keeps a human in the loop. Execution only
happens with --execute AND a configured engagement.

Both reviewing agents run by default and both have a deterministic half that
needs no API key, so an offline run still gets "this plan has no test for the
category the ticket is about" and "4 of these results need a person". `--no-review`
reproduces the pre-agent output exactly.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from app.analysis import TestDesigner, build_analyzer
from app.analysis.attack_planner import build_planner
from app.core.config import Settings
from app.core.engagement import load_engagement
from app.core.logging_config import configure_error_tracking, configure_logging
from app.core.preflight import load_dotenv
from app.database import Repository, init_db, make_engine, make_session_factory
from app.execution.adaptive import AdaptiveBudget
from app.mcp import build_jira_client
from app.orchestrator import Orchestrator


async def _run(args) -> None:
    engine = make_engine()
    init_db(engine)
    repo = Repository(make_session_factory(engine))
    engagement = load_engagement(args.engagement)
    jira = build_jira_client()
    await jira.connect()
    planner = build_planner(engagement.vault.names())
    orch = Orchestrator(
        repo, jira,
        analyzer=build_analyzer(),
        designer=TestDesigner(engagement.attacker, engagement.victim),
        planner=planner,
    )

    aid = await orch.import_and_analyze(args.issue_key)
    print(f"analyzed  -> assessment {aid}")

    poc = Path(args.poc).read_text(encoding="utf-8") if args.poc else None
    tests = orch.design(aid, poc_python=poc, depth=args.depth,
                        review=not args.no_review, max_rounds=args.review_rounds)
    print(f"designed  -> {len(tests)} tests (depth={args.depth}"
          f"{', AI planner on' if planner else ''})")

    review = orch.plan_review(aid)
    if review is not None:
        print(f"reviewed  -> {review.verdict}: coverage {review.coverage_score}%, "
              f"decidable {review.quality_score}%, "
              f"{len(review.tests_added)} added over {review.rounds} round(s)")
        for gap in review.unresolved_gaps:
            # Printed rather than counted: an automated run that quietly dropped
            # "nothing tests the category this ticket is about" would report a
            # clean pass over a plan that never looked.
            print(f"  gap     -> [{gap.severity}] {gap.label()}")

    # auto-approve non-destructive tests for the CLI convenience path
    approved = [t.test_id for t in tests if not t.is_destructive]
    orch.approve(aid, approved)
    print(f"approved  -> {len(approved)} non-destructive tests")

    if args.execute:
        if not engagement.target_base_url:
            print("execute   -> SKIPPED (no engagement target configured)")
        else:
            budget = None
            if args.adaptive:
                if planner is None:
                    print("adaptive  -> SKIPPED (no AI planner: set USE_AI=true with the "
                          "claude CLI installed and logged in)")
                else:
                    budget = AdaptiveBudget(
                        max_iterations=args.adaptive_iterations,
                        max_total_followups=args.adaptive_followups,
                    )
            execs = orch.execute(aid, engagement.target_base_url, engagement.scope,
                                 engagement.vault, Settings.from_env(), adaptive=budget)
            fails = [e for e in execs if e.verdict.result.value == "FAIL"]
            print(f"executed  -> {len(execs)} tests, {len(fails)} FAIL")
            for f in repo.get_findings(aid):
                print(f"  finding -> {f.finding_id} {f.severity.value} {f.title}")

            if not args.no_review:
                run = orch.adjudicate(aid)
                print(f"assessed  -> {run.overall}: {run.coverage_pct}% of the ticket "
                      f"covered, {run.decided_pct}% of executions decided")
                if run.n_manual_review:
                    print(f"  review  -> {run.n_manual_review} result(s) need a person")
                for adjudication in run.auto_resolved:
                    # Labelled every time it is printed. A CI log is exactly where
                    # "an agent read this as broken" would otherwise get quoted as
                    # "the platform confirmed a break".
                    print(f"  agent   -> {adjudication.test_id} read as "
                          f"{adjudication.assessed_result} (advisory, not a finding)")

    out = Path(args.report)
    out.write_text(orch.build_report_html(aid), encoding="utf-8")
    print(f"report    -> {out.resolve()}")


def main() -> None:
    p = argparse.ArgumentParser(description="API security testing pipeline")
    p.add_argument("issue_key", help="Jira issue key, e.g. CRM-1234")
    p.add_argument("--engagement", default="", help="path to engagement.json")
    p.add_argument("--poc", default="", help="path to a Python PoC to transpile")
    p.add_argument("--execute", action="store_true", help="run approved tests")
    p.add_argument("--depth", default="standard", choices=["standard", "aggressive"],
                   help="test breadth: 'standard' is the highest-value probe per "
                        "applicable category; 'aggressive' is the full variant matrix")
    p.add_argument("--adaptive", action="store_true",
                   help="after each undecided/failed result, let the AI planner propose a "
                        "bounded follow-up probe and run it (requires USE_AI=true and the "
                        "claude CLI; never runs destructive follow-ups)")
    p.add_argument("--adaptive-iterations", type=int, default=2,
                   help="max adaptive follow-up rounds (default 2)")
    p.add_argument("--adaptive-followups", type=int, default=10,
                   help="max adaptive follow-up tests in total (default 10)")
    p.add_argument("--no-review", action="store_true",
                   help="skip both reviewing agents: do not audit the plan against the "
                        "ticket's requirements, and do not triage or assess the results. "
                        "The deterministic half of each costs nothing and needs no API "
                        "key, so this is for reproducing the pre-agent output exactly")
    p.add_argument("--review-rounds", type=int, default=1,
                   help="how many times the AI planner may answer the reviewing agent's "
                        "gaps (default 1; each round is another batch of PENDING tests)")
    p.add_argument("--report", default="reports/cli_report.html")
    args = p.parse_args()
    # Same .env load the web app does at startup, for the same reason: this
    # entry point is not launched through the Node wrapper that parses it.
    load_dotenv(os.getenv("RUNTIME_ENV_PATH", ".env"))
    configure_logging()
    configure_error_tracking()
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
