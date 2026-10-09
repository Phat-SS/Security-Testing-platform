"""The process-wide application state, and the one handle every route uses.

`State` is everything built once at startup and shared by every request: the
repository, the Jira connector, the loaded engagement, the auth manager, and
the orchestrator wired to all of them.

**Why `state` is a proxy.** It used to be a module-level global in `main.py`,
rebound during `lifespan`. Splitting the routes out of that file made the
binding the problem: a route module doing `from app.api.main import state` at
import time captures `None` forever, because import happens long before
`lifespan` runs. The alternatives were worse — threading a FastAPI dependency
through ~50 route signatures, or writing `runtime.state.repo` at every call
site — so the name is bound once, to an object that forwards to whatever the
current `State` is.

That also keeps `from app.api.main import state` working for the tests, which
is what makes the route split verifiable: the suite is the safety net for a
move this large, and a refactor that requires rewriting the safety net first
is not one.
"""

from __future__ import annotations

import os
from typing import Any

from app.analysis import TestDesigner, build_analyzer
from app.analysis.attack_planner import build_planner
from app.analysis.adjudicator import build_adjudicator
from app.analysis.copilot import build_copilot
from app.analysis.plan_reviewer import build_reviewer
from app.api import views
from app.core.auth import AuthManager
from app.core.engagement import Engagement
from app.core.engagements import Registry
from app.database import Repository, init_db, make_engine, make_session_factory
from app.mcp import build_jira_client
from app.orchestrator import Orchestrator


class State:
    def __init__(self) -> None:
        engine = make_engine()
        init_db(engine)
        self.repo = Repository(make_session_factory(engine))
        self.jira = build_jira_client()
        self.jira_warning = ""
        # More than one engagement, one per client, each still its own
        # reviewable JSON file. `engagement` and `engagement_path` below read
        # whichever one THIS request is about, so every existing call site
        # keeps working while no longer meaning "the only one there is".
        self.engagements = Registry()
        self.runtime_env_path = os.getenv("RUNTIME_ENV_PATH", ".env")
        self.auth = AuthManager()
        planner = build_planner(self.engagement.vault.names())
        views.configure(auth_enabled=self.auth.enabled, planner_enabled=planner is not None)
        self.orch = Orchestrator(
            self.repo,
            self.jira,
            analyzer=build_analyzer(),
            designer=TestDesigner(self.engagement.attacker, self.engagement.victim),
            # The planner validates proposed persona names against the vault, so
            # it can only be built once the engagement is loaded. Returns None
            # unless USE_AI is set and the claude CLI is available, in which
            # case the platform behaves exactly as it did before.
            planner=planner,
        )

    @property
    def engagement(self) -> Engagement:
        """The engagement this request is about.

        A property rather than an attribute: which one that is now depends on
        the request — the assessment being viewed, or the tester's own
        selection — and a value bound once at startup is exactly how a run came
        to be aimed at whatever had last been saved.
        """
        return self.engagements.current

    @property
    def engagement_path(self) -> str:
        """Where the current engagement's file is — the config UI's write
        target."""
        return self.engagements.path()

    def _rebind_jira(self, client) -> None:
        self.jira = client
        self.orch.set_jira_client(client)

    def reload_engagement(self) -> None:
        # Explicit path bypasses the ENGAGEMENT_CONFIG gate on purpose: a human
        # just saved through the UI, which is itself the deliberate-configuration
        # step the default-deny design requires.
        self.engagements.reload()
        # The planner rejects persona names it does not know, so a stale one
        # would reject every proposal referencing a persona added in this very
        # save — silently, as "not defined in the engagement vault".
        self.orch.set_planner(build_planner(self.engagement.vault.names()))
        # The designer carries attacker/victim from construction. Leaving it
        # stale is worse than the planner case: a plan designed against the
        # previous pair still runs, and reports a cross-tenant result for two
        # identities nobody chose. See Orchestrator.set_designer.
        self.orch.set_designer(
            TestDesigner(self.engagement.attacker, self.engagement.victim)
        )

    def reload_ai_runtime(self) -> None:
        """Rebuild every Claude-backed component after a UI runtime save."""
        planner = build_planner(self.engagement.vault.names())
        self.orch.set_analyzer(build_analyzer())
        self.orch.set_planner(planner)
        self.orch.set_reviewer(build_reviewer())
        self.orch.set_adjudicator(build_adjudicator())
        self.orch.set_copilot(build_copilot())
        views.configure(auth_enabled=self.auth.enabled, planner_enabled=planner is not None)


_state: State | None = None


class _StateProxy:
    """Forwards to the live `State`, so `state.repo` works from any module.

    Attribute access before startup raises rather than returning None, because
    the only way to reach that is a bug: every route runs inside the
    application, which cannot serve a request before `lifespan` has built the
    state. `ready()` is for the one caller that legitimately asks — the chrome
    middleware, which runs on requests the test client can issue during
    startup.
    """

    __slots__ = ()

    def __getattr__(self, name: str) -> Any:
        if _state is None:
            raise RuntimeError(
                "the application state is not initialised — this is only reachable "
                "before lifespan startup has run"
            )
        return getattr(_state, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if _state is None:
            raise RuntimeError("the application state is not initialised")
        setattr(_state, name, value)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<state proxy -> {_state!r}>"


#: The handle every route and middleware imports.
state = _StateProxy()


def init() -> State:
    """Build the state. Called once, from `lifespan`."""
    global _state
    _state = State()
    return _state


def ready() -> bool:
    return _state is not None


def reset() -> None:
    """Drop the state. Only for a shutdown path or a test that wants a clean
    process; the next `init()` rebuilds everything from the environment."""
    global _state
    _state = None
