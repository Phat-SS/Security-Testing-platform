from app.owasp.rules import RequirementSignals, evaluate
from app.schemas.enums import OwaspApiCategory


def cats(signals):
    return {h.category for h in evaluate(signals)}


def test_object_id_triggers_bola():
    s = RequirementSignals(text="DELETE /customers/{customerId} removes a customer",
                           object_identifiers=["customerId"])
    assert OwaspApiCategory.API1 in cats(s)


def test_roles_trigger_bfla():
    s = RequirementSignals(text="Only an admin or manager may approve", roles=["admin", "manager"])
    assert OwaspApiCategory.API5 in cats(s)


def test_url_field_triggers_ssrf():
    s = RequirementSignals(text="Accepts a callback webhook url for notifications",
                           external_url_fields=["callback"])
    assert OwaspApiCategory.API7 in cats(s)


def test_bulk_triggers_resource_and_business_flow():
    s = RequirementSignals(text="Bulk export with pagination and search filter",
                           bulk_or_expensive=True)
    c = cats(s)
    assert OwaspApiCategory.API4 in c
    assert OwaspApiCategory.API6 in c


def test_auth_triggers_broken_auth():
    s = RequirementSignals(text="Login returns a JWT bearer token", has_authentication=True)
    assert OwaspApiCategory.API2 in cats(s)


def test_empty_ticket_triggers_nothing():
    assert cats(RequirementSignals(text="Update the button color to blue")) == set()


def test_every_hit_has_reason_and_signals():
    s = RequirementSignals(text="admin deletes customerId via callback url",
                           object_identifiers=["customerId"], roles=["admin"],
                           external_url_fields=["callback"])
    for hit in evaluate(s):
        assert hit.reason
        assert hit.matched_signals
