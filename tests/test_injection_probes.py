"""Detect-only injection probes, end to end through the designer and runner.

Each probe is judged by an oracle the payload itself cannot satisfy: a database
error string, the product 6690500447 of a template evaluating 73331*91237, the first line
of /etc/passwd, or a response header that only exists if CR/LF split one. A
target that merely ECHOES the input must therefore not be reported.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from app.analysis.test_designer import TestDesigner
from app.core.config import Settings
from app.core.scope import ScopePolicy, ScopeValidator
from app.execution.http_runner import HttpRunner
from app.execution.mutations import INJECTION_PAYLOADS, MUTATION_KINDS
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping
from app.schemas.enums import Applicability, ApprovalStatus, OwaspApiCategory, TestStatus
from app.vault.personas import Persona, PersonaVault

_HOST = "target.test"
_VAULT = PersonaVault([
    Persona("agent_A", {"Authorization": "Bearer a"}, "user", {}, []),
    Persona("agent_B", {"Authorization": "Bearer b"}, "user", {}, []),
])
_KINDS = ["sqli_error_probe", "nosqli_operator_probe", "ssti_probe", "path_traversal_probe",
          "crlf_injection_probe"]


def _design(aggressive: bool):
    designer = TestDesigner("agent_A", "agent_B")
    if aggressive:
        designer = designer.with_depth("aggressive")
    analysis = IssueAnalysis(
        issue_key="X-1", business_summary="s",
        endpoints=[Endpoint(method="GET", path="/files", query_params=["file"])],
        owasp_mappings=[OwaspMapping(category=c, applicability=Applicability.APPLICABLE, reason="r")
                        for c in OwaspApiCategory],
    )
    return designer.design(analysis)


def _runner(app) -> HttpRunner:
    client = TestClient(app, base_url=f"http://{_HOST}")
    client.follow_redirects = False
    scope = ScopeValidator(ScopePolicy(allowed_hosts={_HOST}), resolver=lambda h: "203.0.113.10")
    return HttpRunner(f"http://{_HOST}", scope, _VAULT, Settings.from_env(), client=client)


def _run(app, kind: str) -> TestStatus:
    test = next(t for t in _design(True) if t.attack_mutation.kind == kind)
    test = test.model_copy(update={"approval_status": ApprovalStatus.APPROVED})
    return _runner(app).run(test, f"E-{kind}").verdict.result


async def _vulnerable(request):
    value = request.query_params.get("file", "")
    if "'" in value:
        return JSONResponse({"error": "You have an error in your SQL syntax near ''\")('"},
                            status_code=500)
    if "{{73331*91237}}" in value:
        return JSONResponse({"greeting": "Hello 6690500447"})
    if "../" in value:
        return Response("root:x:0:0:root:/root:/bin/bash\n", media_type="text/plain")
    if "\r\n" in value:
        name, _, rest = value.partition("\r\n")
        header, _, hval = rest.partition(": ")
        return JSONResponse({}, headers={header: hval})
    if "file[$ne]" in request.query_params:
        return JSONResponse({"error": "MongoServerError: unknown operator: $ne"}, status_code=500)
    return JSONResponse({"file": value})


async def _echo(request):
    """Echoes the input verbatim, the way a validation error often does."""
    return JSONResponse({"error": f"invalid file: {request.query_params.get('file', '')}"},
                        status_code=400)


def test_every_injection_kind_is_registered_under_api8():
    for kind in _KINDS:
        assert MUTATION_KINDS[kind].category == OwaspApiCategory.API8


def test_injection_probes_are_aggressive_only():
    standard = {t.attack_mutation.kind for t in _design(False)}
    aggressive = {t.attack_mutation.kind for t in _design(True)}
    assert not standard & set(_KINDS)
    assert set(_KINDS) <= aggressive  # "file" is path-like, and it is a query parameter


def test_traversal_is_only_aimed_at_a_path_like_field():
    designer = TestDesigner("agent_A", "agent_B").with_depth("aggressive")
    analysis = IssueAnalysis(
        issue_key="X-2", business_summary="s",
        endpoints=[Endpoint(method="GET", path="/search", query_params=["q"])],
        owasp_mappings=[OwaspMapping(category=OwaspApiCategory.API8,
                                     applicability=Applicability.APPLICABLE, reason="r")],
    )
    kinds = {t.attack_mutation.kind for t in designer.design(analysis)}
    assert "path_traversal_probe" not in kinds
    assert "sqli_error_probe" in kinds


def test_no_payload_carries_a_second_statement():
    for payload in INJECTION_PAYLOADS.values():
        text = str(payload).upper()
        assert "DROP" not in text and "DELETE" not in text and ";" not in text


@pytest.mark.parametrize("kind", _KINDS)
def test_a_vulnerable_target_fails_each_probe(kind):
    app = Starlette(routes=[Route("/files", _vulnerable)])
    assert _run(app, kind) == TestStatus.FAIL


@pytest.mark.parametrize("kind", _KINDS)
def test_a_target_that_only_echoes_the_input_is_not_reported(kind):
    app = Starlette(routes=[Route("/files", _echo)])
    assert _run(app, kind) != TestStatus.FAIL


def test_every_database_fingerprint_clears_the_marker_length_floor():
    from app.analysis.test_designer import _NOSQL_ERROR_FINGERPRINTS, _SQL_ERROR_FINGERPRINTS
    from app.execution.http_runner import _MIN_MARKER_LEN

    for marker in _SQL_ERROR_FINGERPRINTS + _NOSQL_ERROR_FINGERPRINTS:
        assert len(marker) >= _MIN_MARKER_LEN, marker
