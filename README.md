# AI-assisted API Security Testing Platform

Transform Jira security requirements and existing PoCs into an OWASP API
Security Top 10 (2023) aligned test plan, execute **approved** tests in a
controlled way, collect tamper-evident evidence, and report findings — with a
web UI, a CLI, and a JSON API.

> Runs **fully offline** out of the box: SQLite persistence, a deterministic
> (no-API-key) analyzer, and a mock Jira MCP. The AI (Claude) and live Jira MCP
> are feature-gated behind the same interfaces — flip them on with env vars,
> nothing below changes.

## The one design decision everything hangs on

**The AI proposes; a trusted runner disposes.**

```
Jira → Normalize → OWASP Rule Engine + AI → Declarative TestCase
     → Human Approval → Scope Validation → Trusted Runner → Evidence → Findings → Report
```

Untrusted PoC code is **never executed**. A PoC is parsed statically and
transpiled into a declarative `TestCase` (data, not code). The only thing that
sends packets is the reviewed `HttpRunner`. This removes arbitrary code
execution from the platform entirely — the biggest risk in a tool like this.

Three non-negotiable controls, each with its own tests:

| Control | Module | Why |
|---|---|---|
| **Scope validation** (DNS-aware, IP-pinned) | `app/core/scope.py` | A pentest tool aimable anywhere is a weapon. Blocks SSRF/metadata/rebinding, not just by hostname but by *resolved IP*. |
| **Secret redaction** | `app/core/redaction.py` | A report that leaks its own bearer token is an incident. Runs before any store/log/report. |
| **Approval gate + evidence chain** | `app/execution/` | No unapproved test runs; evidence is sha256-chained and tamper-evident. |

And the anti-false-positive rule: an HTTP 200 is **never** a vulnerability on
its own. A `FAIL` requires correlated disclosure (the attacker's response
actually contained the victim's data). Uncertain results are `INCONCLUSIVE`,
firewall-blocked ones are `BLOCKED` — never silently promoted to `PASS` or a
finding. See `app/execution/verdict.py`.

## Quick start (Windows / PowerShell)

```bash
cd security-testing-platform
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest                      # 53 tests: safety controls + full pipeline
```

### 1. The self-contained demo

```bash
python -m demo.run_assessment
```

Spins up a deliberately vulnerable CRM API on `127.0.0.1`, runs two approved
tests, writes `reports/assessment_demo.html`: `API1-001` (BOLA) → **FAIL** with
the correlated data leak as evidence; `API2-001` (unauth read) → **PASS**.

### 2. The web UI (import → analyze → design → approve → execute → report → Jira)

```bash
# terminal 1 — a target to test (the bundled vulnerable app)
python -m uvicorn demo.vulnerable_api:app --port 8000
# terminal 2 — the platform
cp config/engagement.example.json config/engagement.json
$env:ENGAGEMENT_CONFIG="config/engagement.json"
python -m uvicorn app.api.main:app --port 8100
```

Open `http://127.0.0.1:8100`: import `CRM-1234`, generate the plan, tick the
tests to **approve**, **Run approved tests**, then open the report or preview
the Jira comment. Destructive (write-method) tests are excluded from execution
by default.

### 3. The CLI

```bash
python -m app.cli CRM-1234 --engagement config/engagement.json --execute
```

## The engagement config = authorization as an artifact

Execution is impossible until an `engagement.json` defines the approved target,
scope allow/block lists, and persona credentials (see
`config/engagement.example.json`). No config → empty scope + no personas →
nothing runs. Authorization is explicit and reviewable, never inferred from a
ticket.

## Layout

```
app/
  schemas/     # Pydantic contract: enums, TestCase, Execution, Finding, Analysis
  core/        # config, scope validator, redaction, engagement  ← security-critical
  owasp/       # API Top 10 2023 metadata, rule engine, coverage engine
  vault/       # persona credential vault (required for BOLA/BFLA)
  analysis/    # heuristic + Claude analyzer, deterministic test designer
  poc/         # static PoC transpiler (ast-based; never executes)
  execution/   # templating, mutations, trusted HTTP runner, verdict, evidence
  pipeline/    # executions → deduplicated findings
  reporting/   # HTML report + coverage matrix (dependency-free)
  database/    # SQLAlchemy models + repository (SQLite / Postgres)
  mcp/         # Jira MCP interface + mock (live SDK connector = drop-in)
  api/         # FastAPI app: web UI + JSON API
  orchestrator.py  # the end-to-end workflow, wired to persistence
  cli.py       # command-line driver
demo/          # vulnerable target + sample tests + end-to-end runner
tests/         # 53 tests: scope, redaction, rules, verdict, evidence, approval,
               #           analysis, transpiler, orchestrator, api
```

## Feature flags

| Want | Set |
|---|---|
| Staged Claude analyzer instead of heuristic | `USE_AI=true` + `ANTHROPIC_API_KEY=…` (+ `pip install anthropic`) |
| Live Jira instead of the mock | `JIRA_MCP_URL=…` `JIRA_CLOUD_ID=…` (+ `pip install mcp`) |
| PostgreSQL instead of SQLite | `DATABASE_URL=postgresql+psycopg://…` |
| Reach a lab target on a private IP | `allow_private_ranges: true` in engagement.json (lab only) |
| Run reviewed arbitrary-Python PoCs | `ENABLE_PYTHON_RUNNER=true` **and** `EGRESS_PROXY=…` (see below) |

## Importing existing artifacts

All flow through the same "parse-as-data, never execute, strip host, run
scope-validated" path:

- **Python PoC** — `app/poc/transpiler.py`, `ast`-parsed; dangerous calls
  (`os.system`, `eval`, `subprocess`, …) are flagged and the PoC is never run.
- **Postman collection (v2.1)** — `app/poc/postman.py`, nested folders supported.
- **Burp Suite XML export** — `app/adapters/burp.py`, raw-HTTP requests parsed.
- **JMeter `.jmx`** — `app/adapters/jmeter.py`, HTTP samplers parsed.

And you can **export** the approved plan back out:

- **Postman/Newman** — `/export.postman` emits a collection with `{{baseUrl}}` +
  `{{token_*}}` variables (never real secrets) and per-request assertions.
- **Report** — HTML, **PDF** (`/export.pdf`), **XLSX**, **JSON**.

## Regression testing

Re-run an issue and open **Regression diff** (`/assessment/{id}/regression`): it
matches findings against the previous executed run by dedup key and shows
*new (regressions) / fixed / still-open*, plus a Jira-ready note. Schedule it
with OS cron or CI calling `python -m app.cli <ISSUE> --execute`.

## Multi-user auth

Off by default (single-user local-admin). To enable: create users and set
`AUTH_ENABLED=true`.

```bash
python -m app.core.auth add alice tester   # prints an entry + a one-time API key
```

Add the printed entry to `config/users.json`. Mutating routes then require
`X-API-Key` (or `Authorization: Bearer <key>`) with role ≥ tester; only the
SHA-256 hash of each key is stored. Reads stay open so the dashboard/monitoring
keep working.

For PoCs whose logic can't be expressed declaratively, the gated
`app/execution/python_runner.py` can execute them — but only with **all four
gates** satisfied (`ENABLE_PYTHON_RUNNER=true`, per-PoC `reviewed=True`, static
validation clean, and an `EGRESS_PROXY` allowlist). It fails closed and is off
by default. A subprocess is not a security boundary on its own — run it inside
container isolation with a network egress allowlist.

The real boundary ships in `docker/`: an isolated container (non-root,
read-only FS, dropped caps, no direct network) whose **only** egress is a
default-deny tinyproxy driven by `docker/allowlist` — the network-level
enforcement of your engagement scope. See `docker/docker-compose.yml`.

## Roadmap

- **Phase 1–2 (done):** schemas, scope, redaction, rule engine, vault, HTTP
  runner, verdict, evidence, findings, coverage engine, HTML report, heuristic
  analyzer + test designer, PoC transpiler, persistence, orchestrator, web UI +
  JSON API, CLI, demo. ✅
- **Phase 3 (done):** live Jira MCP connector (official MCP Python SDK) + ADF
  normalizer, staged Claude analyzer (LLM extracts, rule engine decides,
  Pydantic-validated, auto-fallback), Postman collection runner, gated isolated
  Python runner, JSON + XLSX export. ✅
- **Later (done):** Burp + JMeter importers, Postman/Newman export, PDF export
  (fpdf2), historical finding diff + regression view, multi-user API-key auth,
  Docker-composed sandbox (isolated container + egress-allowlist proxy). ✅
- **Beyond:** weasyprint HTML-fidelity PDF, cookie-login for the browser UI
  under auth, historical trend charts, notifications/scheduling UI.

## Safety

- Default-deny scope. Private/loopback/link-local ranges are blocked unless
  `ALLOW_PRIVATE_RANGES=true` (lab only).
- Only run this against systems you are explicitly authorized to test.
- The bundled `demo/vulnerable_api.py` is intentionally insecure — never deploy it.
