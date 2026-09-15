"""The endpoint list, taken from a specification instead of from prose.

`TestDesigner` emits one test set per endpoint and the OWASP mapping is computed
from their parameters, so this list is the single input the whole plan is
derived from. It used to come from a regex over a Jira ticket: it missed any
endpoint written in a table, marked everything as requiring a credential because
it could not tell, and only found object ids that appeared in a path.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from app.adapters.openapi import SpecError, merge, parse
from app.schemas.analysis import Endpoint

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "CRM API", "version": "2.1"},
    "security": [{"bearer": []}],
    "servers": [{"url": "https://someone-elses-host.example.com/v2"}],
    "components": {"schemas": {"Customer": {
        "type": "object",
        "properties": {
            "customerId": {"type": "string"},
            "email": {"type": "string"},
            "avatarUrl": {"type": "string"},
            # Self-referential, which is ordinary in real specs and used to be
            # the shape that hangs a naive $ref resolver.
            "manager": {"$ref": "#/components/schemas/Customer"},
        },
    }}},
    "paths": {
        "/customers/{customerId}": {
            "parameters": [{"name": "customerId", "in": "path", "required": True}],
            "get": {"responses": {"200": {}}},
            "patch": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Customer"}}}}},
        },
        "/health": {"get": {"security": [], "responses": {"200": {}}}},
        "/orders": {"get": {"parameters": [
            {"name": "customer_id", "in": "query"},
            {"name": "page", "in": "query"},
        ]}},
    },
}


def _by_signature(endpoints):
    return {e.signature: e for e in endpoints}


# -- parsing ----------------------------------------------------------------


def test_every_declared_operation_becomes_an_endpoint():
    endpoints, summary = parse(json.dumps(SPEC))

    assert set(_by_signature(endpoints)) == {
        "GET /customers/{customerId}",
        "PATCH /customers/{customerId}",
        "GET /health",
        "GET /orders",
    }
    assert summary["title"] == "CRM API"
    assert summary["n_endpoints"] == 4


def test_a_path_level_parameter_reaches_every_operation_under_it():
    """Declared once for the path and inherited — miss this and the BOLA
    surface of every operation on that route disappears."""
    endpoints = _by_signature(parse(json.dumps(SPEC))[0])

    assert endpoints["GET /customers/{customerId}"].object_id_params == ["customerId"]
    assert "customerId" in endpoints["PATCH /customers/{customerId}"].object_id_params


def test_the_spec_says_which_routes_are_public():
    """The fact the prose extractor could never know. It marked everything as
    requiring auth, which turns every intentionally public route into a false
    API2 finding waiting to be triaged."""
    endpoints = _by_signature(parse(json.dumps(SPEC))[0])

    assert endpoints["GET /health"].expected_public is True
    assert endpoints["GET /health"].auth_required is False
    assert endpoints["GET /orders"].auth_required is True


def test_an_id_in_a_query_parameter_is_found():
    """The regex only ever found ids that appeared in a path."""
    endpoints = _by_signature(parse(json.dumps(SPEC))[0])

    assert endpoints["GET /orders"].object_id_params == ["customer_id"]


def test_a_paging_parameter_is_not_mistaken_for_an_object_id():
    endpoints = _by_signature(parse(json.dumps(SPEC))[0])

    assert "page" not in endpoints["GET /orders"].object_id_params


def test_a_url_carrying_body_property_is_found():
    """Without one there is nothing for the server to be coerced into
    requesting, so this is what decides whether API7 applies at all."""
    endpoints = _by_signature(parse(json.dumps(SPEC))[0])

    assert endpoints["PATCH /customers/{customerId}"].url_fields == ["avatarUrl"]


def test_a_self_referential_schema_does_not_hang():
    """`manager` points back at Customer. A resolver without cycle protection
    recurses until it dies."""
    endpoints = _by_signature(parse(json.dumps(SPEC))[0])

    assert endpoints["PATCH /customers/{customerId}"].writes_properties is True


def test_swagger_2_base_path_prefixes_every_route():
    spec = {
        "swagger": "2.0",
        "basePath": "/api/v1",
        "paths": {"/users/{userId}": {"get": {
            "parameters": [{"name": "userId", "in": "path"}]}}},
    }
    endpoints, summary = parse(json.dumps(spec))

    assert endpoints[0].signature == "GET /api/v1/users/{userId}"
    assert summary["spec_version"] == "2.0"


def test_a_server_url_is_read_but_never_becomes_a_target():
    """A URL in a spec names a host somebody else chose. It is reported so a
    reviewer can see it, and it is never somewhere a request goes."""
    endpoints, summary = parse(json.dumps(SPEC))

    assert summary["servers"] == ["https://someone-elses-host.example.com/v2"]
    assert all(e.path.startswith("/") for e in endpoints), "a host leaked into a path"


# -- YAML, and refusing what is not a spec ----------------------------------


def test_yaml_is_accepted():
    pytest.importorskip("yaml")
    endpoints, _ = parse(
        "openapi: 3.0.3\n"
        "paths:\n"
        "  /things/{thingId}:\n"
        "    get:\n"
        "      parameters:\n"
        "        - name: thingId\n"
        "          in: path\n"
    )

    assert endpoints[0].signature == "GET /things/{thingId}"
    assert endpoints[0].object_id_params == ["thingId"]


def test_yaml_is_parsed_without_constructing_python_objects():
    """`yaml.load` builds arbitrary objects from a document. These arrive from
    outside; a spec is data, and a spec that can run code is an exploit."""
    pytest.importorskip("yaml")

    with pytest.raises(SpecError):
        parse("!!python/object/apply:os.system ['echo pwned']")


@pytest.mark.parametrize("text,reason", [
    ("", "empty"),
    ("{}", "no paths"),
    ('{"paths": {}}', "no operations"),
    ('{"info": {"title": "x"}}', "no paths"),
])
def test_a_document_that_is_not_a_spec_is_refused(text, reason):
    with pytest.raises(SpecError):
        parse(text)


# -- merging ----------------------------------------------------------------


def test_a_hand_entered_endpoint_survives_an_import():
    """It exists precisely because something else could not find it."""
    manual = Endpoint(method="GET", path="/undocumented", manual=True)

    merged, changes = merge([manual], parse(json.dumps(SPEC))[0])

    assert "GET /undocumented" in _by_signature(merged)
    assert len(changes["added"]) == 4


def test_the_spec_corrects_what_was_previously_guessed():
    """auth and object ids were inferred; the spec states them."""
    guessed = Endpoint(method="GET", path="/health", auth_required=True)

    merged, changes = merge([guessed], parse(json.dumps(SPEC))[0])

    health = _by_signature(merged)["GET /health"]
    assert health.expected_public is True
    assert health.auth_required is False
    assert "GET /health" in changes["enriched"]


def test_importing_the_same_spec_twice_changes_nothing_the_second_time():
    endpoints = parse(json.dumps(SPEC))[0]
    once, _ = merge([], endpoints)
    twice, changes = merge(once, endpoints)

    assert len(twice) == len(once)
    assert changes == {"added": [], "enriched": []}


# -- through the UI ---------------------------------------------------------


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'spec.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def imported(client) -> str:
    return client.post("/import", data={"issue_key": "CRM-1234"},
                       follow_redirects=True).url.path.rsplit("/", 1)[-1]


def test_pasting_a_spec_adds_its_endpoints(client, imported):
    from app.api.main import state

    before = {e.signature for e in state.orch.get_analysis(imported).endpoints}
    client.post(f"/assessment/{imported}/openapi", data={"spec": json.dumps(SPEC)},
                follow_redirects=True)
    after = {e.signature for e in state.orch.get_analysis(imported).endpoints}

    assert before < after
    assert "GET /orders" in after


def test_uploading_a_spec_file_works_the_same(client, imported):
    from app.api.main import state

    client.post(f"/assessment/{imported}/openapi",
                files={"spec_file": ("openapi.json", json.dumps(SPEC), "application/json")},
                follow_redirects=True)

    signatures = {e.signature for e in state.orch.get_analysis(imported).endpoints}
    assert "GET /health" in signatures


def test_a_bad_spec_says_why_and_changes_nothing(client, imported):
    from app.api.main import state

    before = [e.signature for e in state.orch.get_analysis(imported).endpoints]
    page = client.post(f"/assessment/{imported}/openapi", data={"spec": "{}"},
                       follow_redirects=True).text

    assert "Not imported" in page
    assert [e.signature for e in state.orch.get_analysis(imported).endpoints] == before


def test_the_import_is_audited(client, imported):
    from app.api.main import state

    client.post(f"/assessment/{imported}/openapi", data={"spec": json.dumps(SPEC)},
                follow_redirects=True)

    rows = [r for r in state.repo.get_audit(imported) if r.action == "import_openapi"]
    assert len(rows) == 1
    assert "CRM API" in rows[0].detail


def test_the_imported_endpoints_reach_the_plan(client, imported):
    """The point of the whole phase: a plan built over the endpoints the
    service actually has, rather than the ones a regex found in prose."""
    from app.api.main import state

    client.post(f"/assessment/{imported}/openapi", data={"spec": json.dumps(SPEC)},
                follow_redirects=True)
    client.post(f"/assessment/{imported}/design", follow_redirects=True)

    paths = {t.request.path for t in state.repo.get_test_cases(imported)}
    assert any("/orders" in p for p in paths), f"the plan ignored an imported endpoint: {paths}"


def test_requirements_and_the_lock_file_agree():
    """The lock's own header warns that bumping one without regenerating the
    other leaves them silently out of sync — and a pinned direct dependency
    missing from the lock is how a reproducible install stops being one."""
    import re
    from pathlib import Path

    def pins(name: str) -> dict[str, str]:
        text = (Path(__file__).resolve().parents[1] / name).read_text(encoding="utf-8")
        found = {}
        for line in text.splitlines():
            match = re.match(r"^([A-Za-z0-9_.-]+)==([0-9][^\s#]*)", line.strip())
            if match:
                found[match.group(1).lower()] = match.group(2)
        return found

    direct, locked = pins("requirements.txt"), pins("requirements-lock.txt")

    assert not (set(direct) - set(locked)), "a direct dependency is missing from the lock"
    assert not {k: v for k, v in direct.items() if locked[k] != v}, "the two disagree on a version"
