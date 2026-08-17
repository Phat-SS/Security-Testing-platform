"""End-to-end demo: the whole vertical slice in one run.

    start vulnerable target  →  approved tests  →  scope validation
    →  trusted runner        →  evidence (hash-chained)  →  findings
    →  HTML report

Run:  python -m demo.run_assessment
Then open the printed report path.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import uvicorn

from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.execution.evidence import verify_chain
from app.execution.http_runner import HttpRunner
from app.pipeline.findings import build_findings, leads
from app.reporting.html import render_report
from demo.sample_tests import build_tests, build_vault
from demo.vulnerable_api import app as vulnerable_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(port: int) -> uvicorn.Server:
    config = uvicorn.Config(vulnerable_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    return server


def main() -> None:
    port = _free_port()
    server = _serve(port)
    base_url = f"http://127.0.0.1:{port}"
    print(f"[demo] vulnerable target running at {base_url}")

    # Scope: allow ONLY the demo host, and explicitly opt into private ranges
    # (this is the deliberate, logged lab exception). Everything else is denied.
    policy = ScopePolicy(allowed_hosts={"127.0.0.1"}, allow_private_ranges=True)
    scope = ScopeValidator(policy)
    settings = Settings.from_env()
    vault = build_vault()

    runner = HttpRunner(base_url, scope, vault, settings)
    tests = {t.test_id: t for t in build_tests()}

    executions = []
    prev_hash = None
    for test in tests.values():
        ex = runner.run(test, execution_id=f"exec-{test.test_id}", prev_hash=prev_hash)
        prev_hash = ex.evidence_hash
        executions.append(ex)
        print(f"[demo] {test.test_id}: {ex.verdict.result.value} - {ex.verdict.reason[:70]}...")

    chain_ok = verify_chain(executions)
    assert chain_ok, "evidence chain failed to verify!"
    print("[demo] evidence chain verified OK")

    findings = build_findings(tests, executions)
    inconclusive = leads(tests, executions)
    print(f"[demo] findings: {len(findings)} | inconclusive leads: {len(inconclusive)}")
    for f in findings:
        print(f"        {f.finding_id} {f.severity.value} {f.title}")

    report_html = render_report(
        title="Security Assessment — CRM-DEMO",
        target=base_url,
        tests=tests,
        executions=executions,
        findings=findings,
        evidence_chain_ok=chain_ok,
    )
    out = Path(__file__).resolve().parent.parent / "reports" / "assessment_demo.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(report_html, encoding="utf-8")
    print(f"[demo] report written: {out}")

    server.should_exit = True


if __name__ == "__main__":
    main()
