"""Test-session isolation from the developer's own `.env`.

The app loads `.env` at startup (see `preflight.load_dotenv`) so that
`uvicorn app.api.main:app` behaves like `npm run security:ui`. Under pytest
that would mean the suite ran against whatever the machine happens to have
configured — a real `JIRA_MCP_URL` would swap the offline mock for a live
connector, and an `ENGAGEMENT_CONFIG` would give tests that deliberately
`delenv` it a fully configured engagement anyway.

Pointing `RUNTIME_ENV_PATH` at a file that does not exist makes that load a
no-op for the whole session. A test that wants runtime-env behaviour (see
`tests/test_config_ui.py`) sets its own path to a tmp file.
"""

import os
from pathlib import Path

os.environ["RUNTIME_ENV_PATH"] = str(Path(__file__).with_name("no-dotenv-in-tests.env"))
