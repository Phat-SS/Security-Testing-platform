"""The AI & Evidence pane after it was cut down to the decisions it actually
contains.

What it used to be: thirteen controls at one weight, led by a "Versioned model
ID" box whose placeholder was a stale model id — which read as "you must pin a
model here" when the truth is the opposite. There is no Anthropic API key
anywhere in this platform; `ClaudeLLM` shells out to the operator's own `claude`
CLI, so the model, the login and the bill are whichever ones their Claude Code
is already using, and leaving that box empty is the right answer for almost
everyone.

What it is now: a status line that says what the AI path is bound to, a model
field that defaults visibly to the CLI's own model, two evidence keys presented
as capabilities rather than as passwords to compose, and one optional
integration folded away. AUTH_COOKIE_SECURE left entirely — it is a login
setting that was only ever here because it also lives in .env.
"""

import json
import os

import pytest
from starlette.testclient import TestClient

from app.core import preflight


@pytest.fixture()
def cfg(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({
        "environments": {"staging": "https://staging.example.com"},
        "active_environment": "staging",
        "scope": {"allowed_hosts": ["staging.example.com"]},
        "attacker": "agent_A",
        "victim": "agent_B",
        "personas": [
            {"name": "agent_A", "auth_headers": {}, "role": "user", "owns": {}},
            {"name": "agent_B", "auth_headers": {}, "role": "user", "owns": {"id": "2"}},
        ],
    }))
    return path


_RUNTIME_KEYS = (
    "USE_AI", "AI_REQUIRE_PINNED_MODEL", "AUTH_COOKIE_SECURE", "ANTHROPIC_MODEL",
    "AI_MAX_BUDGET_USD", "AI_EFFORT", "EVIDENCE_FINGERPRINT_KEY", "REPORT_SIGNING_KEY",
    "REPORT_SIGNING_KEY_ID", "OAST_PUBLIC_URL", "OAST_POLL_URL", "OAST_API_TOKEN",
    "OAST_TIMEOUT_S", "PLATFORM_BASE_URL",
)


@pytest.fixture()
def client(tmp_path, cfg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("ENGAGEMENT_CONFIG", str(cfg))
    runtime_env = tmp_path / ".env"
    monkeypatch.setenv("RUNTIME_ENV_PATH", str(runtime_env))
    original = {key: os.environ.get(key) for key in _RUNTIME_KEYS}
    for key in _RUNTIME_KEYS:
        monkeypatch.delenv(key, raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        c._runtime_env = runtime_env
        yield c
    for key, value in original.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _pane(client) -> str:
    return client.get("/config?tab=ai-evidence").text


# -- the analyzer is the CLI you are already using --------------------------

def test_the_pane_says_the_ai_runs_on_the_local_claude_cli(client):
    """The single most misleading thing about the old pane was that it never
    said this, so a model box with a versioned placeholder looked like a
    credential you had to go and find."""
    page = _pane(client)
    assert "no separate API key" in page or "CLI NOT FOUND" in page
    assert "ANTHROPIC_API_KEY" not in page


def test_no_anthropic_api_key_is_read_anywhere():
    """If one were ever introduced, this pane's promise would become a lie."""
    import pathlib

    hits = [
        path for path in pathlib.Path("app").rglob("*.py")
        if "ANTHROPIC_API_KEY" in path.read_text(encoding="utf-8")
    ]
    assert not hits, f"an API key crept in: {hits}"


def test_the_model_field_defaults_to_the_cli_and_says_so(client):
    """Empty is the recommended state, so the empty state has to read as a
    choice rather than as an unfilled requirement."""
    page = _pane(client)
    assert 'name="ANTHROPIC_MODEL"' in page
    assert "use the CLI&#x27;s model" in page or "use the CLI's model" in page
    # the stale versioned placeholder is gone, and nothing replaced it
    assert "claude-sonnet-4-20260514" not in page


def test_the_model_field_suggests_aliases_without_constraining_them(client):
    """`--model` takes an alias or a full versioned id. A closed <select> would
    go stale; a datalist suggests without forbidding."""
    page = _pane(client)
    assert 'list="ai-model-hints"' in page
    assert '<datalist id="ai-model-hints">' in page
    for alias in ("sonnet", "opus", "fable"):
        assert f'<option value="{alias}">' in page


def test_effort_is_the_cli_s_own_closed_set(client):
    """It was a free-text box behind a permissive regex, so a typo saved fine
    and failed later, at call time."""
    page = _pane(client)
    assert 'name="AI_EFFORT"' in page and "<select" in page
    for level in ("low", "medium", "high", "xhigh", "max"):
        assert f'<option value="{level}"' in page


def test_a_pinned_model_still_round_trips(client):
    client.post("/config/ai-evidence", data={
        "USE_AI": "true", "ANTHROPIC_MODEL": "claude-opus-5", "AI_EFFORT": "high",
    }, follow_redirects=True)
    dotenv = client._runtime_env.read_text(encoding="utf-8")
    assert "ANTHROPIC_MODEL=claude-opus-5" in dotenv
    assert "AI_EFFORT=high" in dotenv
    page = _pane(client)
    assert 'value="claude-opus-5"' in page
    assert 'value="high" selected' in page


def test_the_compliance_switch_is_behind_a_disclosure(client):
    """Pinning is for deployments that must name the exact model in a report —
    a minority, and it was sitting at the same weight as the on/off switch."""
    page = _pane(client)
    head, _, tail = page.partition('name="AI_REQUIRE_PINNED_MODEL"')
    assert tail, "the switch disappeared entirely"
    assert "<details" in head.rsplit("<h2", 1)[-1]


# -- the evidence keys are a capability, not a password ---------------------

def test_the_evidence_keys_say_what_is_lost_while_they_are_empty(client):
    """Their VALUES are meaningless — they only have to be random and stable.
    What a reader needs is what breaks without them."""
    page = _pane(client)
    assert "INCONCLUSIVE" in page
    assert "unsigned" in page
    assert page.count('class="pill med">OFF<') == 2


def test_the_key_boxes_move_behind_a_disclosure(client):
    """Typing a key by hand is for restoring one from a secret manager. It was
    the pane's primary affordance; now it is the fallback."""
    page = _pane(client)
    assert 'id="evidence-manual"' in page
    assert "Generate the Missing Keys" in page
    manual = page.split('id="evidence-manual"')[1]
    assert 'name="EVIDENCE_FINGERPRINT_KEY"' in manual
    assert 'name="REPORT_SIGNING_KEY"' in manual


def test_generating_never_overwrites_a_live_key(client):
    """A signing key cannot be rotated in place: change it and every manifest
    already signed with the old one stops verifying. So the generator is
    fill-if-empty, and the offer disappears once both are set."""
    from app.api.views.config import advanced

    assert "if (!el || el.value) return;" in advanced._EVIDENCE_JS

    client.post("/config/ai-evidence", data={
        "EVIDENCE_FINGERPRINT_KEY": "fingerprint-key-0123456789",
        "REPORT_SIGNING_KEY": "report-signing-key-0123456789abcdef",
    }, follow_redirects=True)
    page = _pane(client)
    assert "Generate the Missing Keys" not in page
    assert page.count('class="pill ok">ACTIVE<') == 2


# -- the optional integration is folded away --------------------------------

def test_oast_is_collapsed_until_it_is_configured(client):
    page = _pane(client)
    # the <details> immediately before the OAST heading is closed
    before = page.split("Out-of-band Collaborator")[0]
    assert before.rstrip().endswith('<summary style="cursor:pointer"><b>')
    assert "<details>" in before.rsplit("<h2", 1)[-1]
    assert "<details open>" not in before.rsplit("<h2", 1)[-1]
    assert "NOT SET UP" in page
    # the four fields still exist and still submit — they are just not the
    # first thing the pane shows
    for name in ("OAST_PUBLIC_URL", "OAST_POLL_URL", "OAST_API_TOKEN", "OAST_TIMEOUT_S"):
        assert f'name="{name}"' in page


def test_oast_opens_itself_once_it_is_set_up(client):
    client.post("/config/ai-evidence", data={
        "OAST_PUBLIC_URL": "https://oast.example/c",
        "OAST_POLL_URL": "https://oast.example/events",
    }, follow_redirects=True)
    page = _pane(client)
    assert "<details open>" in page
    assert "CONFIGURED" in page


# -- the session cookie left this pane --------------------------------------

def test_saving_ai_settings_cannot_touch_the_session_cookie(client, monkeypatch):
    """The real reason it had to move. Every save from this pane posts absent
    checkboxes back as "false", so while AUTH_COOKIE_SECURE was in its list,
    changing the AI model quietly un-secured the login cookie."""
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    client.post("/config/ai-evidence", data={"ANTHROPIC_MODEL": "claude-opus-5"},
                follow_redirects=True)
    assert os.environ["AUTH_COOKIE_SECURE"] == "true"
    assert "AUTH_COOKIE_SECURE" not in client._runtime_env.read_text(encoding="utf-8")
    assert 'name="AUTH_COOKIE_SECURE"' not in _pane(client)


def test_the_cookie_is_a_readiness_check_only_when_a_session_exists(monkeypatch, cfg):
    """With auth off the login route refuses every key and no cookie is ever
    issued, so a warning about its flags would be about a cookie that does not
    exist."""
    from app.core.engagement import load_engagement

    monkeypatch.delenv("AUTH_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("PLATFORM_BASE_URL", raising=False)
    engagement = load_engagement(str(cfg))

    monkeypatch.setenv("AUTH_ENABLED", "false")
    keys = [c.key for c in preflight.evaluate(engagement, str(cfg)).checks]
    assert "session_cookie" not in keys

    monkeypatch.setenv("AUTH_ENABLED", "true")
    check = next(c for c in preflight.evaluate(engagement, str(cfg)).checks
                 if c.key == "session_cookie")
    assert check.state == preflight.WARN
    assert check.fix_action == "/config/session-cookie"


def test_an_https_base_url_already_secures_the_cookie(monkeypatch, cfg):
    """Two signals set it (routes/auth.py). Reporting only the flag would call
    a correctly-configured HTTPS deployment misconfigured."""
    from app.core.engagement import load_engagement

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.delenv("AUTH_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://platform.example.com")
    check = next(c for c in preflight.evaluate(load_engagement(str(cfg)), str(cfg)).checks
                 if c.key == "session_cookie")
    assert check.state == preflight.OK
    assert "PLATFORM_BASE_URL" in check.detail


def test_the_readiness_fix_writes_the_flag(client, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    client.post("/config/session-cookie", data={"secure": "true"}, follow_redirects=True)
    assert "AUTH_COOKIE_SECURE=true" in client._runtime_env.read_text(encoding="utf-8")
    assert os.environ["AUTH_COOKIE_SECURE"] == "true"
    page = client.get("/config?tab=readiness").text
    assert "Login Session Cookie" in page
