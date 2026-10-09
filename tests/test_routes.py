"""The route table, pinned.

Splitting `main.py` into `app/api/routes/` was meant to move code and change
nothing else. The risk in a move that size is not a crash — the suite catches
those — it is a route quietly failing to register: an unincluded router, or a
handler left behind in the file it was cut from. Nothing fails; the path just
starts 404ing, and only for the one workflow nobody exercised that day.

So the full table is written down here. Adding a route means adding a line,
which is the point: it makes "did I mean to add this?" a review question, and
it makes a disappearance loud.
"""

from __future__ import annotations

import pytest

from app.api.main import app

# FastAPI's own, not ours.
_BUILTIN_PREFIXES = ("/docs", "/openapi", "/redoc")

EXPECTED = [
    ("GET", "/"),
    ("GET", "/findings"),
    ("GET", "/activity"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("POST", "/logout"),
    # configuration
    ("GET", "/config"),
    ("GET", "/config/environments"),
    ("POST", "/config/environments"),
    ("POST", "/config/environments/{name}/activate"),
    ("POST", "/config/environments/{name}/delete"),
    ("POST", "/config/quick-setup"),
    ("POST", "/config/scope"),
    ("POST", "/config/scope/allow-host"),
    ("POST", "/config/personas"),
    ("POST", "/config/personas/{name}/delete"),
    ("POST", "/config/identities"),
    ("POST", "/config/runner"),
    ("POST", "/config/ai-evidence"),
    # The readiness check's one-click fix for AUTH_COOKIE_SECURE. Deliberately
    # its own writer rather than a field in /config/ai-evidence: that handler
    # posts every absent checkbox back as "false", so sharing it would let an
    # AI save silently un-secure the login cookie.
    ("POST", "/config/session-cookie"),
    ("POST", "/config/mcp/jira/reconnect"),
    ("POST", "/config/mcp/jira/refresh-token"),
    # assessments
    ("POST", "/import"),
    ("GET", "/assessment/{aid}"),
    ("POST", "/assessment/{aid}/delete"),
    ("POST", "/assessments/delete"),
    ("POST", "/assessment/{aid}/endpoints"),
    ("POST", "/assessment/{aid}/endpoints/delete"),
    ("POST", "/assessment/{aid}/openapi"),
    ("POST", "/assessment/{aid}/reanalyze"),
    # plan
    ("POST", "/assessment/{aid}/design"),
    ("POST", "/assessment/{aid}/agent-plan"),
    ("POST", "/assessment/{aid}/adjudicate"),
    ("POST", "/assessment/{aid}/copilot"),
    ("POST", "/assessment/{aid}/copilot/accept"),
    ("POST", "/assessment/{aid}/plan"),
    ("POST", "/assessment/{aid}/approve"),
    ("GET", "/assessment/{aid}/test/{test_id}"),
    ("POST", "/assessment/{aid}/test/{test_id}"),
    # execution
    ("POST", "/assessment/{aid}/execute"),
    ("POST", "/assessment/{aid}/execution/rerun"),
    ("POST", "/assessment/{aid}/execution/curl"),
    ("POST", "/assessment/{aid}/rerun"),
    ("GET", "/assessment/{aid}/run-panel"),
    # reporting
    ("GET", "/assessment/{aid}/report"),
    ("GET", "/assessment/{aid}/export.html"),
    ("GET", "/assessment/{aid}/export.json"),
    ("GET", "/assessment/{aid}/export.md"),
    ("GET", "/assessment/{aid}/export.xlsx"),
    ("GET", "/assessment/{aid}/export.pdf"),
    ("GET", "/assessment/{aid}/export.postman"),
    ("GET", "/assessment/{aid}/regression"),
    ("GET", "/assessment/{aid}/comment"),
    ("POST", "/assessment/{aid}/comment"),
    ("POST", "/assessment/{aid}/findings/{finding_id}/triage"),
    # JSON API
    ("GET", "/api/readiness"),
    ("GET", "/api/jobs/{job_id}"),
    ("POST", "/api/assessments"),
    ("GET", "/api/assessments/{aid}"),
    ("GET", "/api/assessments/{aid}/run"),
    ("GET", "/api/health"),
    # admin
    ("POST", "/admin/shutdown"),
]


def _walk(routes):
    """Included routers are wrapped rather than flattened, so this recurses
    through `original_router` instead of reading `app.routes` directly."""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _walk(inner.routes)
            continue
        methods = getattr(route, "methods", None)
        if not methods:
            continue
        for method in sorted(set(methods) - {"HEAD", "OPTIONS"}):
            yield method, route.path


def _registered() -> set[tuple[str, str]]:
    return {
        (method, path)
        for method, path in _walk(app.routes)
        if not path.startswith(_BUILTIN_PREFIXES)
    }


def test_no_route_disappeared():
    missing = sorted(set(EXPECTED) - _registered())
    assert not missing, f"these routes are no longer registered: {missing}"


def test_no_route_appeared_unnoticed():
    extra = sorted(_registered() - set(EXPECTED))
    assert not extra, (
        "new routes are registered but not listed in EXPECTED — add them there "
        f"deliberately: {extra}"
    )


def test_every_route_is_listed_once():
    assert len(EXPECTED) == len(set(EXPECTED))


@pytest.mark.parametrize("method,path", sorted(EXPECTED))
def test_each_route_resolves_to_exactly_one_handler(method, path):
    """A path registered twice is usually a handler that was copied into a new
    module without being deleted from the old one — both resolve, and which one
    answers depends on include order."""
    matches = [p for m, p in _walk(app.routes) if (m, p) == (method, path)]
    assert len(matches) == 1, f"{method} {path} is registered {len(matches)} times"


def test_the_shutdown_sweep_points_at_the_real_virtualenv():
    """`/admin/shutdown` finds this project's processes by their interpreter
    path. When `admin.py` moved a directory deeper in the route split, the
    unchanged `parent.parent.parent` started resolving to `app/.venv` — which
    does not exist, so the sweep matched nothing and the button killed only
    this process while its confirm dialog promised it had stopped the rest."""
    from app.api.routes import admin

    assert admin._VENV_DIR.name == ".venv"
    assert (admin._VENV_DIR.parent / "app" / "api").is_dir(), (
        f"_VENV_DIR resolved to {admin._VENV_DIR}, which is not beside the app package"
    )


def test_csrf_runs_before_anything_reads_the_request():
    """Chrome authenticates the caller and loads the engagement; a request CSRF
    is about to refuse should not cause that work. Starlette prepends, so the
    outermost handler is the one registered last — easy to get backwards."""
    names = [m.kwargs["dispatch"].__name__ for m in app.user_middleware]
    # security_headers is outermost so even a refused request (bad Host, CSRF)
    # still gets the hardening headers on its response; host_guard and
    # csrf_guard are the other cheap up-front refusals. All three must still
    # run before anything that authenticates the caller or loads the
    # engagement/chrome, which is the property this test actually protects.
    assert names[:3] == ["security_headers", "host_guard", "csrf_guard"], names
    gate = max(names.index(n) for n in ("security_headers", "host_guard", "csrf_guard"))
    assert gate < names.index("engagement_middleware") < names.index("chrome_middleware")


def test_each_route_module_has_exactly_one_router():
    """A second `router = APIRouter()` left over from the split would silently
    orphan any route decorated between the two assignments."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "api" / "routes"
    for path in root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assignments = len(re.findall(r"^router = APIRouter\(", source, re.M))
        assert assignments <= 1, f"{path.name} assigns `router` {assignments} times"
