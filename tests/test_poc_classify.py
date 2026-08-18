"""Imported artefacts are classified by their own shape.

Everything the platform imports — Python PoC, curl, Postman, Burp, JMeter —
used to arrive labelled API1/BOLA regardless of content, which broke two things
at once: the coverage matrix (a 40-request Burp export became forty BOLA tests
and every other category read as MISSING) and execution (`swap_object_id` with
an empty detail looked for a victim id nobody had set).
"""

from app.adapters.burp import burp_to_test_cases
from app.poc.classify import classify, parameterise_object_id
from app.poc.postman import postman_to_test_cases
from app.poc.transpiler import transpile_curl, to_test_cases
from app.schemas.enums import OwaspApiCategory


def _c(method, path, headers=None, body=None):
    return classify(method, path, headers or {}, body)


# -- signal-driven classification ---------------------------------------------


def test_a_url_field_is_recognised_as_ssrf():
    result = _c("POST", "/notifications", body={"callback_url": "https://x.test/hook"})
    assert result.category == OwaspApiCategory.API7
    assert result.mutation.kind == "ssrf_url"
    assert result.mutation.detail["field"] == "callback_url"
    assert result.confidence == "HIGH"


def test_a_privileged_property_is_recognised_as_mass_assignment():
    result = _c("PATCH", "/customers/1001", body={"name": "x", "role": "user"})
    assert result.category == OwaspApiCategory.API3
    assert result.mutation.kind == "inject_property"
    # And it arrives with the read-back that makes the category decidable.
    assert result.verification is not None
    assert result.verification.proves_exploit_if_contains


def test_an_admin_path_is_recognised_as_function_level_authorization():
    result = _c("POST", "/admin/users")
    assert result.category == OwaspApiCategory.API5
    assert result.mutation.kind == "escalate_persona"


def test_a_spec_dump_is_recognised_as_inventory():
    result = _c("GET", "/openapi.json")
    assert result.category == OwaspApiCategory.API9


def test_an_object_id_in_the_path_is_recognised_as_bola():
    result = _c("GET", "/customers/2002")
    assert result.category == OwaspApiCategory.API1
    assert result.mutation.kind == "swap_object_id"
    assert result.needs_target_persona is True


def test_an_unrecognisable_request_falls_back_honestly():
    """Guessing a category is what produced the wrong coverage matrix. Replaying
    without a credential is meaningful for any endpoint and invents nothing."""
    result = _c("GET", "/health")
    assert result.category == OwaspApiCategory.API2
    assert result.mutation.kind == "drop_auth"
    assert result.confidence == "LOW"


# -- parameterisation ---------------------------------------------------------


def test_a_literal_id_becomes_a_substitutable_placeholder():
    """A recorded request contains a literal id, and there is nothing to
    replace in a literal — so without this, an imported BOLA probe attacks the
    attacker's own object and always passes."""
    path, field = parameterise_object_id("/customers/2002")
    assert path == "/customers/{victim_id}"
    assert field == "victim_id"


def test_the_last_id_segment_is_the_one_under_test():
    # In /accounts/12/orders/98 the order is what the request is about; the
    # account is scope.
    path, _ = parameterise_object_id("/accounts/12/orders/98")
    assert path == "/accounts/12/orders/{victim_id}"


def test_uuids_are_recognised_as_identifiers():
    path, _ = parameterise_object_id("/customers/3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    assert path == "/customers/{victim_id}"


def test_an_existing_placeholder_is_kept_not_renamed():
    path, field = parameterise_object_id("/customers/{customerId}")
    assert (path, field) == ("/customers/{customerId}", "customerId")


def test_a_path_without_an_identifier_is_left_alone():
    path, field = parameterise_object_id("/customers/search")
    assert (path, field) == ("/customers/search", "")


def test_query_strings_survive_parameterisation():
    path, _ = parameterise_object_id("/customers/2002?include=orders")
    assert path == "/customers/{victim_id}?include=orders"


# -- through the importers ----------------------------------------------------


def test_a_mixed_import_no_longer_collapses_into_one_category():
    """The coverage matrix is the tool's headline answer to 'what is still
    untested'. Labelling every import API1 made that answer wrong."""
    collection = {
        "info": {"name": "mixed", "schema": "v2.1.0"},
        "item": [
            {"name": "bola", "request": {"method": "GET",
                                         "url": "https://api.test/customers/2002"}},
            {"name": "ssrf", "request": {
                "method": "POST", "url": "https://api.test/notifications",
                "body": {"mode": "raw", "raw": '{"webhook": "https://x.test/h"}'}}},
            {"name": "admin", "request": {"method": "GET",
                                          "url": "https://api.test/admin/users"}},
        ],
    }
    tests = postman_to_test_cases(collection)
    assert {t.owasp_category for t in tests} == {
        OwaspApiCategory.API1, OwaspApiCategory.API7, OwaspApiCategory.API5,
    }


def test_imported_tests_are_still_pending_and_host_stripped():
    tests = to_test_cases(transpile_curl("curl https://evil.example/customers/2002"))
    assert tests
    assert all(t.approval_status.value == "PENDING" for t in tests)
    # The host is stripped; the runner supplies the approved base URL.
    assert all(t.request.path.startswith("/") for t in tests)
    assert all("evil.example" not in t.request.path for t in tests)


def test_a_burp_export_classifies_per_request():
    xml = """<?xml version="1.0"?><items>
<item><url>https://api.test/customers/2002</url>
<request base64="false">GET /customers/2002 HTTP/1.1
Host: api.test

</request></item>
<item><url>https://api.test/admin/reset</url>
<request base64="false">POST /admin/reset HTTP/1.1
Host: api.test

</request></item>
</items>"""
    tests = burp_to_test_cases(xml)
    categories = {t.owasp_category for t in tests}
    assert OwaspApiCategory.API1 in categories
    assert OwaspApiCategory.API5 in categories


def test_a_low_confidence_classification_says_so_in_the_objective():
    tests = to_test_cases(transpile_curl("curl https://api.test/health"))
    assert "LOW confidence" in tests[0].objective
    assert "Review this classification" in tests[0].objective


def test_only_bola_family_imports_claim_a_victim_identity():
    """A spurious target_persona makes an unrelated test look like a
    cross-identity check in the report."""
    bola = to_test_cases(transpile_curl("curl https://api.test/customers/2002"))[0]
    health = to_test_cases(transpile_curl("curl https://api.test/health"))[0]
    assert bola.auth_context.target_persona is not None
    assert health.auth_context.target_persona is None
