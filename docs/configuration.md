# Configuration reference

Three files hold everything, and they are split by *what kind of thing* the
value is — not by which feature it belongs to:

| File | Holds | Edited by |
|---|---|---|
| `.env` | Secrets and machine-level settings | you, or **Configuration → Advanced** |
| `config/engagement.json` | The authorization artifact: target, scope, personas | **Configuration → Target / Identities**, or by hand |
| `config/users.json` | API-key hashes, only when `AUTH_ENABLED=true` | `python -m app.core.auth add <name> <role>` |

A credential never belongs in `engagement.json`. It references one as
`"Authorization": "Bearer ${PERSONA_A_TOKEN}"`, resolved from the environment
at load time, so the file stays something you can diff, review and paste into a
ticket.

## Getting a first run working

Nothing below is required to start the app — every variable has a default.
The shortest path is:

```bash
cp .env.example .env                                   # set PERSONA_A_TOKEN / PERSONA_B_TOKEN
cp config/engagement.example.json config/engagement.json
npm run security:ui        # or: uvicorn app.api.main:app --port 8100
```

then open **Configuration → Readiness**. If nothing is configured yet that page
offers a quick-setup form that writes the target, the scope entry, both personas
and both tokens in one submit. Readiness is also the answer to "why did every
row come back BLOCKED" — it runs the same `ScopeValidator` the runner does.

`.env` is read at startup by the app itself (and by `python -m app.cli`), with
real environment variables taking precedence over the file. A value edited
through the UI is written back to `.env` **and** applied immediately; a value
edited by hand needs a restart.

## Where a setting lives, and why

Two settings look like they could be env vars and deliberately are not:

- **`scope.allow_private_ranges`** is in `engagement.json`. It decides whether a
  host resolving to 127.0.0.0/8, 10/8, 172.16/12, 192.168/16 or 169.254/16 may
  be reached. An env var able to widen that boundary from outside the file a
  human signed off on would be a backdoor around the authorization artifact.
- **Runner limits** may be overridden per engagement in `engagement.json`
  (`runner: {timeout_s, max_response_bytes, max_requests_per_test}`). The env
  vars below are the machine-wide default; the engagement value wins and needs
  no restart. Leaving the UI fields blank restores the env default.

## Every environment variable

### Usually set

| Variable | Default | What it does |
|---|---|---|
| `PERSONA_A_TOKEN`, `PERSONA_B_TOKEN` | — | Test-account credentials referenced from `engagement.json`. The names are yours; they only have to match the `${...}` references in that file. |
| `USE_AI` | `false` | Runs `claude -p` through your own Claude Code login for the analyzer, the plan reviewer and the result adjudicator. Each has a deterministic fallback, so `false` is fully functional. |
| `JIRA_MCP_URL` | — | Streamable-HTTP MCP endpoint, e.g. `https://mcp.atlassian.com/v1/mcp`. Unset means the offline mock. |
| `JIRA_CLOUD_ID` | — | From the MCP server's `getAccessibleAtlassianResources` tool. |
| `JIRA_MCP_TOKEN` | — | OAuth access token, sent as `Authorization: Bearer`. Short-lived: refresh with `npx -y mcp-remote https://mcp.atlassian.com/v1/mcp` then `npm run jira:token`, or the **Refresh token** button. |
| `JIRA_SITE_URL` | — | Human browse URL (`https://you.atlassian.net`) — powers the "Open ticket" link. `JIRA_CLOUD_ID` is a UUID and cannot build it. |
| `PLATFORM_BASE_URL` | — | Where this platform is reachable, used only to link the HTML report from a Jira comment. Unset means no link, rather than a `localhost` URL that 404s for every reader but its author. |
| `DATABASE_URL` | `sqlite:///sectest.db` | A Postgres DSN for a shared deployment. |

### Runner guardrails

| Variable | Default | What it does |
|---|---|---|
| `RUNNER_TIMEOUT_S` | `15` | Per-request timeout. Raise for a slow staging host. |
| `RUNNER_MAX_RESPONSE_BYTES` | `2000000` | Body larger than this is truncated before storage. |
| `RUNNER_MAX_REQUESTS_PER_TEST` | `25` | Caps one test's fan-out, race windows included. |

The runner never follows redirects — a 302 to an internal host is the same SSRF
wearing a hat, and chasing it would re-resolve DNS outside the scope gate. There
is no setting for it.

### AI analyzer

| Variable | Default | What it does |
|---|---|---|
| `ANTHROPIC_MODEL` | CLI default | Pin a specific model — an alias (`sonnet`, `opus`, `fable`) or a full versioned id. Normally left blank: the CLI then uses whatever model your Claude Code session uses. |
| `CLAUDE_CLI_PATH` | `claude` | Path to the binary if it is not on `PATH`. |
| `AI_REQUIRE_PINNED_MODEL` | `false` | Production: refuse to run without a versioned model id. |
| `AI_MAX_BUDGET_USD` | — | Hard ceiling per CLI call. |
| `AI_EFFORT` | — | Reasoning effort: `low`, `medium`, `high`, `xhigh`, `max`. Blank leaves it to the CLI. |
| `ADJUDICATOR_CHALLENGE` | `true` | A second adversarial pass tries to refute the adjudicator's own reading before a result is shown as settled; an objection sends it back to a human. Doubles the model cost of an auto-resolved row and catches the failure mode that matters — a confident wrong reading handed over as an answer. Set `false` and single-pass readings are labelled "read by the agent" instead of "read, then challenged". |

### Evidence and report integrity

| Variable | Default | What it does |
|---|---|---|
| `EVIDENCE_FINGERPRINT_KEY` | — | HMAC key correlating owner/attacker response values without storing identifiers. ≥16 random bytes; rotate between engagements. |
| `REPORT_SIGNING_KEY` | — | Signs report manifests. ≥32 chars; inject from a secret manager in production. |
| `REPORT_SIGNING_KEY_ID` | `local-hmac` | Which key signed a manifest. |
| `OAST_PUBLIC_URL` | — | Public collaborator URL the target calls back to. |
| `OAST_POLL_URL` | — | Authenticated endpoint returning `{"observed": true}` for a token. Must be set together with the public URL; both must be HTTPS. |
| `OAST_API_TOKEN` | — | Sent only to the polling endpoint, never into the callback URL. |
| `OAST_TIMEOUT_S` | `5` | Poll timeout. |

### Access control

| Variable | Default | What it does |
|---|---|---|
| `AUTH_ENABLED` | `false` | `false` runs open in single-user local-admin mode. `true` requires an API key from `config/users.json` on every mutating route. |
| `AUTH_USERS_CONFIG` | `config/users.json` | Where those SHA-256 key hashes live. |
| `AUTH_SESSION_TTL_S` | `43200` | Browser session lifetime (minimum 300). The API key itself is never stored in the cookie. |
| `AUTH_COOKIE_SECURE` | off | Required when served over HTTPS; local HTTP cannot send a `Secure` cookie. A `PLATFORM_BASE_URL` starting with `https://` sets the flag on its own. With auth on, **Readiness** checks this and offers a one-click fix. |

| `UI_ALLOWED_HOSTS` | *(loopback names only)* | Comma-separated `Host` names the UI answers to, beyond `localhost`/`127.0.0.1`/`::1`. Any other `Host` gets a 400, which is what stops a DNS-rebinding page from driving an unauthenticated local UI. `*` disables the check (only behind a proxy that already validates `Host`). |
| `PERSONA_ENV_PREFIXES` | *(empty)* | Extra prefixes a persona header's `${VAR}` may reference. Built in: `PERSONA_`, `TARGET_`, `PENTEST_`. Anything else (e.g. `JIRA_MCP_TOKEN`) is refused, because persona headers are sent to the target. |

Scope edits (`/config/scope`) need the **admin** role and are written to the audit log. Ports other than 80/443 must be listed under `scope.allowed_ports` unless the engagement is in lab mode (`allow_private_ranges`).

### Arbitrary-Python PoC runner

Off by default, and all of these must line up before arbitrary code runs.
Scope for arbitrary code is enforced by the egress proxy, not by the app.

| Variable | Default | What it does |
|---|---|---|
| `ENABLE_PYTHON_RUNNER` | `false` | Master switch. The PoC must also be marked reviewed. |
| `INSIDE_SECURITY_SANDBOX` | `false` | Set automatically by `docker/Dockerfile.sandbox`. Never set it by hand on a bare host — an egress proxy variable alone is not a boundary for arbitrary code. |
| `EGRESS_PROXY` | — | e.g. `http://egress:8888`. |
| `PYTHON_RUNNER_TIMEOUT_S` | `10` | Wall-clock cap per PoC. |
| `PYTHON_RUNNER_MAX_OUTPUT` | `100000` | Captured stdout/stderr cap, in bytes. |

### Infrastructure

| Variable | Default | What it does |
|---|---|---|
| `ENGAGEMENT_CONFIG` | `config/engagement.json` | Path to the engagement file. |
| `RUNTIME_ENV_PATH` | `.env` | The file the UI writes settings back to, and the file loaded at startup. |
| `LOG_LEVEL` | `INFO` | Every logger runs through a redaction filter regardless. |
| `SENTRY_DSN` | — | Unhandled exceptions to Sentry — only when this is set *and* `sentry-sdk` is installed. Events are redacted the same way first. |
| `DB_POOL_SIZE` | `10` | Postgres only; SQLite has no server-side pool. |
| `DB_MAX_OVERFLOW` | `20` | Postgres only. |
| `DB_POOL_RECYCLE_S` | `1800` | Lower it if a proxy in front of Postgres drops idle connections sooner. |
| `JIRA_MCP_HEADERS` | — | JSON object of extra headers, for non-bearer auth schemes. |
| `JIRA_TOOL_GET` | `getJiraIssue` | Override if your MCP server names its tools differently. |
| `JIRA_TOOL_SEARCH` | `searchJiraIssuesUsingJql` | Same. |
| `JIRA_TOOL_COMMENT` | `addCommentToJiraIssue` | Same. |
| `SECURITY_UI_PORT` | `8100` | Port used by `npm run security:ui`. |
| `POSTGRES_PASSWORD` | — | Only read by `docker-compose.yml` under the `postgres` profile. |

## The Configuration page

Four tabs, in the order you need them:

- **Readiness** — would a run work right now, and if not, which setting is at
  fault. Quick setup lives here while the engagement is empty.
- **Target** — named environments (base URLs) and the scope allow/block lists.
- **Identities** — personas, their credentials, what each owns, and which one
  plays attacker vs victim.
- **Advanced** — runner limits, AI & evidence secrets, the MCP connector, and a
  read-only view of the settings that only change with a restart. Everything
  here has a working default; a normal engagement never opens it.

The AI & evidence section writes to `.env` and requires the **admin** role when
authentication is enabled.

## Engagements

| Variable | What it does |
|---|---|
| `ENGAGEMENT_CONFIG` | A single engagement file. What an existing install already sets; it keeps working unchanged. |
| `ENGAGEMENTS_DIR` | A directory of engagement files, one per client, each named after its file stem. |

Neither set means **no engagements**: an empty scope, no personas, and nothing
that can run. That is deliberate — discovery never happens on its own, because
a config file happening to exist on disk is not the deliberate act default-deny
asks for. Saving through the configuration UI *is* that act, so an engagement
written there becomes usable immediately without a restart.

Both can be set together. A directory entry wins over the single file if they
share a name.

## Runner limits

Set per engagement under **Configuration → Advanced**, or as environment
defaults.

| Variable | Default | What it does |
|---|---|---|
| `RUNNER_TIMEOUT_S` | 15 | Per-request timeout. |
| `RUNNER_MAX_RESPONSE_BYTES` | 2000000 | Cap on stored/echoed body size. |
| `RUNNER_MAX_REQUESTS_PER_TEST` | 25 | Caps one test's fan-out, race windows included. |
| `RUNNER_MAX_CONCURRENT_TESTS` | 1 | How many approved tests run at once. |

`RUNNER_MAX_CONCURRENT_TESTS` defaults to 1 on purpose. Concurrency against
someone's API is request *rate*, and rate is a blast-radius decision for whoever
signed the authorization — not one this tool makes on their behalf. Raising it
speeds a long plan up close to linearly; the evidence chain is identical either
way, because tests are sealed in plan order after the run rather than as they
complete.

## Signing in

| Variable | Default | What it does |
|---|---|---|
| `AUTH_ENABLED` | false | Off means single-user: every request is the built-in local admin. |
| `AUTH_USERS_CONFIG` | config/users.json | Where the users and their key hashes live. |
| `AUTH_SESSION_TTL_S` | 43200 | How long a browser session lasts. |
| `AUTH_COOKIE_SECURE` | false | Force the `Secure` flag on the session cookie. |

With authentication on, **reads are privileged too**: the dashboard, the config
panes, an assessment's captured evidence and every export require a session or
an API key. A rejected sign-in is logged at WARNING (never with the key that was
tried), and ten failures from one address within a minute are refused without
checking the key at all.
