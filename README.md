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
Jira → Normalize → Requirements + OWASP Rule Engine + AI → Declarative TestCase
     → Plan Review (agent) → Human Approval → Scope Validation → Trusted Runner
     → Evidence → Findings → Result Review (agent) → Report
```

The two **agent** stages are advisory and bracket the human one. The plan
reviewer adds tests and names gaps; it cannot approve anything. The result
reviewer reads results the runner left undecided and says what it thinks they
are; it cannot rewrite a sealed verdict or mint a finding.

Untrusted PoC code is **never executed**. A PoC is parsed statically and
transpiled into a declarative `TestCase` (data, not code). The only thing that
sends packets is the reviewed `HttpRunner`. This removes arbitrary code
execution from the platform entirely — the biggest risk in a tool like this.

Three non-negotiable controls, each with its own tests:

| Control | Module | Why |
|---|---|---|
| **Scope validation** (DNS-aware, IP-pinned) | `app/core/scope.py` | A pentest tool aimable anywhere is a weapon. Blocks SSRF/metadata/rebinding, not just by hostname but by *resolved IP*. |
| **Secret redaction** | `app/core/redaction.py` | A report that leaks its own bearer token is an incident. Runs before any store/log/report. |
| **Approval gate + evidence chain** | `app/execution/` | No unapproved test runs; evidence is sha256-chained and tamper-evident (see the honest scope of that claim in `evidence.py`). |

### Two rules, not one

The anti-false-**positive** rule: an HTTP 200 is **never** a vulnerability on
its own. A `FAIL` requires correlated evidence — the attacker's response
actually contained the victim's data, or a read-back proved the attacker's
value persisted. Uncertain results are `INCONCLUSIVE`, firewall-blocked ones
are `BLOCKED` — never silently promoted to `PASS` or a finding.

The anti-false-**negative** rule: an HTTP 404 is **never** proof of safety on
its own either. A rejection only means the control worked if the thing being
protected was reachable to begin with. Every authorization test therefore
carries a **positive control** (`baseline`): the same request, performed by an
identity entitled to it. If the legitimate owner also gets 404, the test never
exercised the control and the result is `INCONCLUSIVE` — not a confident
`PASS`. See `app/execution/verdict.py`.

Evidence is ranked, strongest first: verification read-back → correlated
disclosure → directly observed missing header/limit → status code (weakest,
never decisive alone).

## Quick start (Windows / PowerShell)

```bash
cd security-testing-platform
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest                      # the full suite: safety controls + full pipeline;
                            # enforced on every push/PR by .github/workflows/ci.yml,
                            # so this comment can't go stale the way a hardcoded
                            # count already had (the CI job is the source of truth)
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

Open `http://127.0.0.1:8100`: import `CRM-1234`, check the extracted
**Endpoints** (edit them if the ticket's prose defeated the extractor), generate
the plan, approve the tests you want, **Run approved tests**, then open the
report or preview the Jira comment. Destructive (write-method) tests are
excluded from execution by default and gated behind a separate confirmation.

Start at the **Configuration** tab. Its **Readiness** pane runs every base URL
through the same `ScopeValidator` the runner calls and lists, ahead of a run,
each setting that would stop one — with the fix inline (one click to authorize
a host) rather than a filename to go and edit. A whole run coming back
`BLOCKED` almost always means the target's host was never added to
`scope.allowed_hosts`; that check is the first row on the panel, and the
readiness verdict is also available as JSON at `/api/readiness` for CI.


## The assessment screen

Six numbered, collapsible steps, ordered so that what a thing is *derived from*
comes before the thing itself:

| # | Step | What it is |
|---|---|---|
| 1 | **Requirements & endpoints** | What the ticket asks for, and the attack surface those asks live on. The endpoint list is **editable**: add, edit, delete. |
| 2 | **Design test plan** | Import a PoC (Python / Postman / Burp / JMeter), pick a depth, generate. |
| 3 | **OWASP Coverage** | What the ticket needs tested versus what the plan tests. |
| 4 | **Test plan & approval** | The reviewing agent's verdict and its unresolved gaps, then search / filter / sort / page, then approve, reject or reset. |
| 5 | **Execute** | Environment, adaptive toggle, run — and the destructive-run gate. |
| 6 | **Results** | Verdict counts, the run's assessment (passed/failed + % of the ticket covered), confirmed findings, re-run, report and exports. |

Each step opens according to where the assessment actually is (a freshly
analyzed ticket opens 1 and 2; a designed one opens 4), and a folded step still
states what it produced. Every column header carries an **ⓘ** with the meaning
of that column, so `PARTIAL`, `From PoC` and `swap_object_id` do not require
reading the source.

### Endpoints are editable, and that matters

`TestDesigner` builds one test set **per endpoint**, and the OWASP mapping is
computed from these parameters — so this list is the single input the whole plan
is derived from. It is produced by a regex over ticket prose, which means it
misses endpoints written in a table, marks every endpoint as requiring auth, and
only finds object ids that appear in a *path*. Correcting any of that used to
mean editing the Jira ticket and importing again, which discarded the plan and
its approvals.

Editing the list is **additive** for the OWASP mapping: a new endpoint can add
or explain a category, but nothing here silently drops one — the mapping may
have come from the Claude analyzer reading the ticket's intent, and rebuilding it
from the heuristic rules on every small edit would quietly replace that with
something weaker. **↻ Re-analyze from ticket** is the one operation allowed to
remove a category; it keeps hand-entered endpoints, because those exist
precisely because the extractor could not find them.

Changing the list marks an existing plan **stale** rather than regenerating it
behind your back. Regenerating replaces the plan and **keeps an approval given to
a test that comes back byte-for-byte unchanged**; anything whose request or
mutation differs returns to `PENDING`.

### Reviewing a large plan

Aggressive depth over a handful of endpoints is a hundred-plus tests. The plan
table filters, sorts and pages **server-side**, which is what makes *"approve all
312 matching this filter"* mean the same thing you just read on screen — the
bulk action re-runs the same query rather than trusting a list of ids the page
happened to render. Filter values come with counts and only appear if the plan
actually contains them.

`Approve` / `Reject` / `Reset to PENDING` are all available from the list.
Unchecking a box never withdrew an approval — the handler only ever read the
boxes that *were* ticked — so withdrawing one is now an explicit action.

### Re-running

**↻ Re-run** (on a card or in step 6) creates a **new assessment** of the same
issue, copies the analysis and the plan *with its approvals*, runs the approved
**non-destructive** tests, and lands on the regression diff. The previous run is
left exactly as it was, as the baseline.

It has to work that way. Regression only exists *between* assessments, and
findings are derived from every execution an assessment holds — so re-running in
place would rewrite the conclusions attached to evidence that had already been
reported. Two things deliberately do not come along: destructive tests
(approving a write probe once, for a run you watched, is not consent to it firing
again from a button on a list page) and adaptive follow-ups (authorised by policy
mid-run, never read by a person). **Re-import from Jira** is the other mode, for
when the ticket itself changed.

A re-run stops before sending anything and says why — no environment, nothing
approved, or a blocking configuration check — rather than reporting a run that
came back entirely `BLOCKED`.


### 3. The CLI

```bash
python -m app.cli CRM-1234 --engagement config/engagement.json --execute
```

Both reviewing agents run by default, and the deterministic half of each needs no
API key — so an offline CI run still prints "this plan has no test for the
category the ticket is about" and "4 of these results need a person". Every
agent-read result is printed with the word *advisory* attached, because a CI log
is exactly where that would otherwise get quoted as a confirmed break.
`--no-review` reproduces the pre-agent output exactly; `--review-rounds N` bounds
how many times the planner may answer the reviewer.

### 4. Running in Docker

```bash
cp .env.example .env
cp config/engagement.example.json config/engagement.json   # then edit it
docker compose up --build
```

Open `http://127.0.0.1:8100`. `docker-compose.yml` at the repo root builds
`docker/Dockerfile` — non-root, read-only application directory, dropped
Linux capabilities — and mounts `./config` read-only plus a named volume for
the SQLite file, so `docker compose down` never discards an assessment.
`docker compose --profile postgres up --build` adds a Postgres service
instead (see the compose file's header for the two extra `.env` lines it
needs). This is unrelated to `docker/docker-compose.yml`, which is the
isolated sandbox for `ENABLE_PYTHON_RUNNER` covered under "Multi-user auth"
below — that one exists to contain arbitrary Python, not to run the platform.

## What it can actually send

The attack vocabulary is a closed registry — `app/execution/mutations.py`,
`MUTATION_KINDS`. Every entry has a reviewed handler; there is no path from a
generated or AI-proposed test to a behaviour that isn't listed here, and an
unknown kind is rejected rather than improvised.

| Category | Mutations |
|---|---|
| **API1** BOLA | `swap_object_id`, `swap_id_in_query`, `swap_id_in_header`, `id_param_pollution`, `wrap_id_array`, `content_type_switch` |
| **API2** Auth | `drop_auth`, `tamper_token`, `jwt_alg_none`, `jwt_alg_confusion`, `jwt_claim_tamper`, `jwt_expired_replay`, `jwt_kid_injection`, `borrowed_token` |
| **API3** BOPLA | `inject_property`, `inject_nested_property` |
| **API4** Resources | `oversized_payload`, `pagination_abuse`, `json_depth_bomb`, `rate_probe`, `graphql_batching_abuse` |
| **API5** BFLA | `escalate_persona`, `method_override`, `admin_path_swap` |
| **API6** Business flows | `repeat_flow`, `race_condition` |
| **API7** SSRF | `ssrf_url`, `ssrf_url_bypass` |
| **API8** Misconfiguration | `cors_probe`, `debug_probe`, `security_headers_probe`, `host_header_injection` |
| **API9** Inventory | `version_downgrade`, `undocumented_path_probe`, `graphql_introspection_probe` |
| **API10** Unsafe consumption | `unsafe_redirect_url`, `oauth_redirect_uri_bypass` |

All ten categories have generators. `rate_probe`, `repeat_flow` and
`race_condition` send multiple requests (capped at 50); `race_condition` sends
them concurrently, inside a single DNS-pin block so every request in the burst
goes to the one already-validated address.

**Depth.** `standard` (default) emits the highest-value probe per applicable
category. `aggressive` emits the full variant matrix — every id placement, the
whole JWT suite, race windows. Choose it in the Design step, or
`--depth aggressive` on the CLI. Volume is not risk here: nothing runs without
approval, so the cost is review time.

`graphql_introspection_probe`, `graphql_batching_abuse`, `host_header_injection`
and `oauth_redirect_uri_bypass` are reviewed, registered mutations like every
other kind here — the attack planner (`USE_AI=true`) can propose them today,
validated by the same gate as any other proposal. The deterministic
`TestDesigner` does not template them into a plan on its own yet (it has no
signal for "this ticket is about GraphQL/OAuth" the way it does for BOLA/auth);
add one by hand via the API/DB or let the planner add it as a gap-filling
proposal in the meantime.

## The engagement config = authorization as an artifact

Execution is impossible until an `engagement.json` defines the approved target,
scope allow/block lists, and persona credentials (see
`config/engagement.example.json`). No config → empty scope + no personas →
nothing runs. Authorization is explicit and reviewable, never inferred from a
ticket.

The **Configuration** tab edits that same file, one pane per thing a run needs:

| Pane | Writes | Blocks a run when unset |
|---|---|---|
| Readiness | — (read-only verdict) | — |
| Environments | `environments`, `active_environment` | yes — no target, no run |
| Scope | `scope.allowed_hosts` / `blocked_hosts` / `allow_private_ranges` | yes — every request comes back `BLOCKED` |
| Personas | `personas`, `attacker`, `victim` | yes — the runner resolves the attacker before scope is even checked |
| Runner limits | `runner` (timeout, caps) | no — blank falls back to `.env` |
| Runtime | nothing (read-only) | — env-only settings, restart to change |

Every writer reads the whole document, changes only the keys it owns, and
writes it back, so hand-written comments and keys the UI does not expose
survive a save made through the browser.

**Persona tokens are references, not values.** `engagement.json` is the artifact
a tester reads, diffs and attaches to a ticket, so a live bearer token does not
belong in it. Write `"Authorization": "Bearer ${DEV_CRM_TOKEN_A}"` and keep the
token in `.env`; `load_engagement` resolves `${VAR}` from the environment at load
time. An unset or empty variable **withholds the header and fails readiness**
rather than falling back, because both fallbacks corrupt the result instead of
just weakening it: a literal `${VAR}` on the wire earns a 401 that reads in the
report exactly like a 401 the endpoint meant to return, and silently dropping the
header turns "identity A reaches B's object" into "anonymous reaches B's object",
where a PASS means nothing it appears to mean. The readiness row names the
variable to set, never its value.

## Layout

```
app/
  schemas/     # Pydantic contract: enums, TestCase, Execution, Finding, Analysis,
               #   agent.py            RequirementItem, PlanReview, Adjudication,
               #                       RunAssessment — all advisory by construction
  core/        # config, scope validator, redaction, engagement  ← security-critical
  owasp/       # API Top 10 2023 metadata, rule engine, coverage engine
  vault/       # persona credential vault (required for BOLA/BFLA)
  analysis/    # heuristic + Claude analyzer, deterministic test designer,
               #   requirements.py     what the ticket asks for (the coverage denominator)
               #   plan_reviewer.py    the reviewing agent (structural + AI)
               #   adjudicator.py      triage + reading of undecided results
  poc/         # static PoC transpiler (ast-based; never executes)
  execution/   # templating, mutations, trusted HTTP runner, verdict, evidence
  pipeline/    # executions → deduplicated findings
  reporting/   # HTML report + coverage matrix (dependency-free)
  database/    # SQLAlchemy models + repository (SQLite / Postgres)
  mcp/         # Jira MCP interface + mock (live SDK connector = drop-in)
  api/         # FastAPI app: web UI + JSON API
               #   ui.py               shared primitives: tooltip, section, table, theme
               #   views.py            dashboard, config, login, report-adjacent pages
               #   views_assessment.py the assessment screen (six collapsible steps)
  orchestrator.py  # the end-to-end workflow, wired to persistence
  cli.py       # command-line driver
demo/          # vulnerable target + sample tests + end-to-end runner
tests/         # scope, redaction, rules, verdict, evidence, approval, analysis,
               # transpiler, orchestrator, api, endpoint editing, plan filtering,
               # re-runs, plan/finding idempotency, assessment-screen structure
```

## Feature flags

| Want | Set |
|---|---|
| Staged Claude analyzer instead of heuristic, plus the AI half of both reviewing agents | `USE_AI=true` + the `claude` CLI installed and logged in (rides your Claude Code login — no API key, no extra pip package) |
| A working report link in the Jira comment | `PLATFORM_BASE_URL=https://…` |
| Live Jira instead of the mock | `JIRA_MCP_URL=…` `JIRA_CLOUD_ID=…` (+ `pip install mcp`) |
| PostgreSQL instead of SQLite | `DATABASE_URL=postgresql+psycopg://…` |
| Reach a lab target on a private IP | **Configuration → Scope → allow private ranges** (lab only) |
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

**↻ Re-run** on an assessment card clones the plan into a new assessment, runs
the approved non-destructive tests and opens **Regression diff**
(`/assessment/{id}/regression`): findings matched against the previous executed
run by dedup key, as *new (regressions) / fixed / still-open*, plus a Jira-ready
note. Schedule it with OS cron or CI calling `python -m app.cli <ISSUE>
--execute`.

Running the *same* assessment twice is also supported and appends to its
evidence chain: execution ids are tagged per round so two runs are never
indistinguishable in the evidence, and findings are recomputed over the whole
history and replaced rather than appended.

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

This is a separate image from the one that runs the platform itself
(`docker/Dockerfile`, `docker-compose.yml` at the repo root — see "Running in
Docker" below): the sandbox exists only to isolate arbitrary Python from
`ENABLE_PYTHON_RUNNER`, it is not how you'd normally deploy the app.

## The Jira comment

Most stakeholders never open the HTML report — they read the ticket. So the
comment (`app/reporting/jira_comment.py`) carries exactly two things:

- **the summary** — what was run, the verdict counts, whether the run passed and
  how much of the ticket it covered, and one row per confirmed finding;
- **the full results table** — one row per test, every test: the attack, the
  request as sent, the status, the verdict, and (once the results have been
  reviewed) what the reviewing agent made of the undecided ones.

Everything that *explains* a row lives in the HTML report: the mutation's
parameters, what a secure system was expected to return versus what came back,
the verdict's reasoning, the baseline and read-back exchanges it leaned on, and a
finding's impact, reproduction steps and recommended fix.

It used to carry all of that per test. On a 60-test run that is thousands of
words in a ticket comment, and the practical result was that the thing worth
reading sat below several screens of things that did not fail. Length is not
thoroughness in a place people skim, and two renderings of the same explanation
drift — the one in the ticket being the copy nobody updates. The report has room
for the explanation and, more to the point, has the captured request and response
the explanation refers to sitting directly beneath it.

Set `PLATFORM_BASE_URL` and the comment links to the report. Unset, it names it:
a localhost link 404s for every reader but its author, which costs more trust
than an absent one.

**What the comment deliberately withholds.** It goes to a system with a
different audience and a different access-control model than the evidence
store, so a leaked value is never reproduced in it. A BOLA finding reports
"the response disclosed 2 protected marker(s)" and points at the captured
response body; it does not paste the victim's email into the ticket. Every
string still passes `redact_text` on the way out, table cells escape pipes and
collapse newlines (paths come from tickets and imported PoCs, so they are
attacker-adjacent input), and anything dropped for length is announced rather
than silently truncated.

## Where the AI is allowed to act

Two agent roles, both bolted onto the same seam: **the AI proposes, the
platform disposes.** Both are off unless `USE_AI=true` and the `claude` CLI is
available; with them off the platform behaves exactly as the deterministic
path always did.

Every AI call (`ClaudeLLM` in `app/analysis/staged.py`) shells out to
`claude -p` with `--tools ""`, `--safe-mode` and `--no-session-persistence`,
run from outside this repo's working directory — the model only ever returns
text, it is never given the ability to run a tool, reach an MCP server, load
this or any other project's `CLAUDE.md`/hooks/skills/plugins, or persist the
turn. That matters because these prompts are built from Jira ticket text,
i.e. attacker-controlled input: without this, prompt injection in a ticket
could try to make the model *act* rather than just answer, on the same host
running this platform. `tests/test_claude_llm.py` pins the exact flags so a
refactor that quietly drops one fails CI instead of only outrunning this
paragraph.

**1. Attack planner** (`app/analysis/attack_planner.py`) — runs in the Design
step, after the rule engine, and sees what is already planned so it adds depth
rather than duplicates. Its output is refused unless: the mutation is in
`MUTATION_KINDS`, the path is relative (a proposal can never carry its own
host), every persona already exists in the vault, and the batch is under the
cap. `approval_status` is forced to `PENDING` and destructiveness is recomputed
from the HTTP method — **a proposal cannot approve itself**. Every rejection is
audited individually, so "the AI proposed 12 and 9 vanished" is never something
you have to infer from a count.

**2. Adaptive exploitation loop** (`app/execution/adaptive.py`) — the one place
a request is sent that no human read first, so it is bounded on four axes:
iterations, follow-ups per iteration, total follow-ups, and wall clock.
Destructive follow-ups are excluded by default. Each follow-up passes the
planner's constraints *and* a second policy gate, and is labelled
`[AUTO-APPROVED by adaptive policy … Not individually reviewed by a human]` in
the report — because "a human approved this" and "a policy permitted this" are
different assurances and must not read alike.

**Prompt injection is assumed, not detected.** The loop feeds the target's own
response back to the planner, and a hostile target can put instructions there.
The response is redacted, truncated and fenced as untrusted — but that is
labelling, not a control. The control is that a fully injected, fully obedient
planner can still only select a different *allowlisted, non-destructive*
mutation against an *in-scope* host. It cannot widen scope, execute code,
escalate to a destructive probe, or approve anything, because the model decides
none of those.

**3. Plan reviewer** (`app/analysis/plan_reviewer.py`) — a second opinion on a
generated plan, before a human spends their attention on it. The failure mode it
exists for is a plan that is *thin in a way nobody notices*: a ticket whose third
acceptance criterion is about admin re-assignment, and a plan with eleven BOLA
probes and no BFLA test at all. It judges two axes — **coverage** (is there a
test for each security-relevant thing the ticket asks for?) and **decidability**
(can each test produce a verdict other than INCONCLUSIVE? an authorization probe
with no positive control cannot) — and its gaps are fed back to the planner for a
bounded number of revision rounds. The revised batch passes exactly the same
constraints as any other proposal.

It runs in two halves. The **structural** half is countable and always available:
an applicable OWASP category with no test, a requirement item nothing addresses,
an authorization test with no baseline. The **AI** half reads the ticket's intent
and names what a structural check cannot see. The AI half is strictly additive —
it can add gaps and lower the scores, and the structural verdict floors the final
one, so a model that decides everything is fine cannot erase a gap that is
measurably there.

**4. Result adjudicator** (`app/analysis/adjudicator.py`) — `INCONCLUSIVE` is the
runner being honest, and the bill for that honesty is paid by a person reading
response bodies. Most of that is not judgement, it is reading. So results are
**triaged** first (deterministic, no key needed): a failed positive control is a
test-data problem only a person can fix, a 500 is transient and wants a re-run,
and an accepted attack whose response body is sitting right there is a reading
task. Then the reading tasks are decided — by measurement where possible (an
attacker response byte-identical to the positive control's *is* correlated
disclosure, no model required) and by the model otherwise.

The result is an `Adjudication`: an opinion stored **beside** the sealed verdict,
carrying `advisory=True` and the sealed value alongside its own. It never writes
`execution.verdict`, never enters the evidence hash, and `build_findings` never
reads it. An agent that reads a result as broken changes what a tester has to
read and what the run-level assessment says; it does not change what this
platform reports as a confirmed finding. Everywhere it is rendered it names its
author, because "the runner sealed this as a break" and "an agent read this as a
break" are different claims resting on different evidence.

Rolled up, that answers the two questions a stakeholder asks: **did this run pass
or fail**, and **how much of the ticket did it cover** (`RunAssessment`). The
denominator is the requirement list (`app/analysis/requirements.py`), read out of
the ticket's acceptance criteria and security-relevant bullets — visible in step 1
so the percentage can be decomposed rather than taken on faith. An assessment
imported before that list existed has it back-filled from the stored ticket text
on first review, so an old run gets a figure instead of a permanent
"unmeasured"; **↻ Re-analyze from ticket** reads it properly. The
model may propose the readings and the test↔requirement mapping; the percentage
is arithmetic over them, computed in code, because a percentage a model asserted
is not a measurement. Coverage counts a requirement only when a test for it
reached a *decisive* result — a plan that touches everything and decides nothing
scores zero, deliberately.

**Where an agent is deliberately absent:** `core/scope.py`, `core/redaction.py`,
`execution/evidence.py`, the approval gate, and `execution/verdict.py`. Putting
a model in any of those converts an auditable control into a probabilistic one.
The two reviewing agents above are exactly the shape that lets them exist at all:
one adds proposals a human still approves, the other adds an opinion beside a
verdict it cannot touch.

```bash
python -m app.cli CRM-1234 --engagement config/engagement.json \
    --depth aggressive --execute --adaptive
```

## Upgrading

The evidence hash now covers the baseline/verification exchanges, multi-request
statistics and the attack note. Records sealed by an earlier version will
therefore **fail** `verify_chain` — the payload shape changed. That is the
correct failure direction: a hash whose definition silently varies proves
nothing. Re-run affected assessments, or archive their reports before upgrading.

`Verdict.actual_summary` no longer names the values a failing test disclosed,
only how many. Those fields are exported, rendered and posted to Jira with no
redaction pass of their own, so naming a leaked session token or a victim's
email there made the platform re-disclose the data it was reporting. The values
remain in the captured response body, which *is* redacted before storage.

### Database migrations

`app.database.models.init_db` (`Base.metadata.create_all`) still creates the
schema for a brand-new database — that has not changed, and tests keep using
it directly for exactly that reason. What it cannot do is add a column to a
database that already exists, which is why a schema change from here on ships
as an [Alembic](https://alembic.sqlalchemy.org/) migration under `migrations/`
instead. It reads `DATABASE_URL` the same way the app does, so it always
targets the database a normal run would use.

| Database | Command |
|---|---|
| Existing, from before Alembic | `alembic stamp 0001_baseline && alembic upgrade head` (once) |
| Brand new | `alembic stamp head` (create_all already built the current schema — this just tells Alembic to agree), or `alembic upgrade head` on an empty database to build it from the migrations instead |

`migrations/versions/0001_baseline.py` deliberately does nothing when *run* —
it exists to be *stamped*, marking "this database already has the schema
`create_all` has always produced," so later migrations know where they're
starting from without trying to re-create tables that are already there.

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
- **Agent layer (done):** requirement extraction, the plan-reviewing agent
  (structural + AI, with a bounded revision loop back into the planner), the
  result-adjudicating agent (deterministic triage + AI reading), the run-level
  passed/failed + %-of-ticket-covered assessment, and the Jira comment reduced to
  summary + results table with the explanation moved into the report. ✅
- **Beyond:** weasyprint HTML-fidelity PDF, cookie-login for the browser UI
  under auth, historical trend charts, notifications/scheduling UI, an editable
  requirement list in the UI (the endpoint list's treatment, applied to the other
  input a plan is derived from).

## Safety

- Default-deny scope. Private/loopback/link-local ranges are blocked unless
  `ALLOW_PRIVATE_RANGES=true` (lab only).
- Only run this against systems you are explicitly authorized to test.
- The bundled `demo/vulnerable_api.py` is intentionally insecure — never deploy it.
