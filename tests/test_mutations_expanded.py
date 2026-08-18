"""The expanded attack vocabulary: registry integrity, JWT surgery, and the
refusal-to-guess behaviour that replaced a silent false-negative source."""

import base64
import json

import pytest

from app.execution import jwt_tools
from app.execution.mutations import (
    _MAX_REPEAT,
    MUTATION_KINDS,
    MutationError,
    apply_mutation,
    kinds_for,
)
from app.schemas.enums import OwaspApiCategory
from app.schemas.testcase import Mutation, RequestSpec
from app.vault.personas import Persona, PersonaVault


def _jwt(payload: dict, alg: str = "RS256") -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        ).decode().rstrip("=")

    return f"{seg({'alg': alg, 'typ': 'JWT'})}.{seg(payload)}.originalsignature"


_TOKEN = _jwt({"sub": "1001", "role": "agent", "exp": 4102444800})
_ATTACKER = Persona("agent_A", {"Authorization": f"Bearer {_TOKEN}"}, "agent", {"customer_id": "1001"}, [])
_VICTIM = Persona("agent_B", {"Authorization": "Bearer victim"}, "agent", {"customer_id": "2002"}, ["beth@x.com"])
_VAULT = PersonaVault([_ATTACKER, _VICTIM])
_BASE = RequestSpec(method="GET", path="/customers/{customer_id}")


def _apply(kind, detail=None, base=None, target=_VICTIM, context=None):
    return apply_mutation(
        base or _BASE, Mutation(kind=kind, detail=detail or {}),
        _ATTACKER, target, _VAULT, context if context is not None else {},
    )


# -- registry -----------------------------------------------------------------


def test_every_owasp_category_has_at_least_one_mutation():
    """The gap this closes: four categories used to be flagged APPLICABLE by the
    rule engine with no mutation and no generator behind them, so the coverage
    matrix reported a permanent MISSING that nothing could ever fill."""
    for category in OwaspApiCategory:
        assert kinds_for(category), f"{category.value} has no mutation"


def test_unknown_mutation_kind_is_rejected_not_improvised():
    with pytest.raises(MutationError, match="Unknown mutation kind"):
        _apply("definitely_not_a_real_kind")


def test_registry_and_handlers_cannot_drift_apart():
    # MUTATION_KINDS is the allowlist shown to the AI planner; a kind listed
    # there without a working handler would be proposed and then die at run time.
    for kind in MUTATION_KINDS:
        try:
            _apply(kind, _plausible_detail(kind))
        except MutationError as exc:
            # A handler may legitimately refuse this synthetic request (e.g.
            # version_downgrade needs a /vN/ path). What must never happen is
            # the "unknown kind" refusal, which means no handler exists at all.
            assert "Unknown mutation kind" not in str(exc), kind


def _plausible_detail(kind: str) -> dict:
    return {
        "content_type_switch": {"to": "form"},
        "borrowed_token": {"persona": "agent_B"},
        "inject_property": {"properties": {"role": "admin"}},
        "inject_nested_property": {"path": "user.role", "value": "admin"},
        "version_downgrade": {"to": "/v1/customers"},
    }.get(kind, {})


# -- API1: refusing to guess which object to attack ---------------------------


def test_swap_object_id_prefers_a_name_matched_owned_id():
    context = {}
    _apply("swap_object_id", {"id_field": "customerId"}, context=context)
    # customerId ~ customer_id after normalisation, so no guessing is involved.
    assert context["customerId"] == "2002"


def test_swap_object_id_refuses_to_guess_between_several_owned_ids():
    """The old behaviour took the victim's FIRST owned id whatever it was, so an
    order endpoint could be sent a customer id, draw a 404, and be recorded as
    PASS — a false negative with a confident label. Refusing is the fix."""
    multi = Persona("multi", {}, "agent", {"customer_id": "2002", "order_id": "5005"}, [])
    with pytest.raises(MutationError, match="Refusing to guess"):
        apply_mutation(
            RequestSpec(method="GET", path="/invoices/{invoice_id}"),
            Mutation(kind="swap_object_id", detail={"id_field": "invoice_id"}),
            _ATTACKER, multi, _VAULT, {},
        )


def test_swap_object_id_uses_the_sole_owned_id_when_unambiguous():
    single = Persona("single", {}, "agent", {"order_id": "5005"}, [])
    context = {}
    apply_mutation(
        RequestSpec(method="GET", path="/orders/{oid}"),
        Mutation(kind="swap_object_id", detail={"id_field": "oid"}),
        _ATTACKER, single, _VAULT, context,
    )
    assert context["oid"] == "5005"


def test_bola_mutation_without_a_target_persona_is_rejected():
    with pytest.raises(MutationError, match="no auth_context.target_persona"):
        _apply("swap_object_id", target=None)


def test_param_pollution_sends_both_ids_as_a_list():
    prepared = _apply("id_param_pollution", {"field": "id", "id_field": "customer_id"})
    assert prepared.query["id"] == ["1001", "2002"]


def test_content_type_switch_needs_a_body_to_re_encode():
    with pytest.raises(MutationError, match="needs a dict body"):
        _apply("content_type_switch", {"to": "form"})


def test_content_type_switch_sets_encoding_and_header():
    base = RequestSpec(method="POST", path="/customers", body={"name": "x"})
    prepared = _apply("content_type_switch", {"to": "form"}, base=base)
    assert prepared.body_encoding == "form"
    assert prepared.headers["Content-Type"] == "application/x-www-form-urlencoded"


# -- API2: JWT suite ----------------------------------------------------------


def test_jwt_alg_none_strips_the_signature():
    prepared = _apply("jwt_alg_none")
    token = prepared.headers["Authorization"].removeprefix("Bearer ")
    header, payload, signature = jwt_tools.split(token)
    assert header["alg"] == "none"
    assert signature == ""
    assert payload["sub"] == "1001"  # claims survive; only the alg/signature change


def test_jwt_claim_tamper_keeps_the_original_signature():
    """A token whose claims changed but whose signature did not is
    cryptographically invalid — acceptance proves the signature is never
    checked. Recomputing it here would destroy exactly that property."""
    prepared = _apply("jwt_claim_tamper", {"claims": {"role": "admin"}})
    token = prepared.headers["Authorization"].removeprefix("Bearer ")
    _header, payload, signature = jwt_tools.split(token)
    assert payload["role"] == "admin"
    assert payload["sub"] == "1001"  # untouched claims survive
    assert signature == "originalsignature"


def test_jwt_alg_confusion_downgrades_and_resigns():
    prepared = _apply("jwt_alg_confusion", {"key": "secret"})
    token = prepared.headers["Authorization"].removeprefix("Bearer ")
    header, payload, _sig = jwt_tools.split(token)
    assert header["alg"] == "HS256"
    # The signature must actually verify under the guessed key, or the probe
    # tests nothing: a server that HMACs with 'secret' should accept it.
    assert jwt_tools.sign_hs256(header, payload, "secret") == token


def test_jwt_expired_replay_backdates_expiry():
    prepared = _apply("jwt_expired_replay")
    token = prepared.headers["Authorization"].removeprefix("Bearer ")
    _header, payload, _sig = jwt_tools.split(token)
    assert payload["exp"] < 1_000_000_000


def test_jwt_mutation_on_a_non_jwt_credential_errors_loudly():
    """Silently sending an unmutated request would come back as a clean PASS —
    the worst outcome, a false negative that looks like assurance."""
    opaque = Persona("opaque", {"Authorization": "Bearer not-a-jwt"}, "agent", {}, [])
    with pytest.raises(MutationError, match="needs a JWT credential"):
        apply_mutation(_BASE, Mutation(kind="jwt_alg_none"), opaque, _VICTIM, _VAULT, {})


def test_borrowed_token_replaces_the_attackers_credential():
    prepared = _apply("borrowed_token", {"persona": "agent_B"})
    assert prepared.headers["Authorization"] == "Bearer victim"


# -- API4/API6: multi-request probes and their ceilings -----------------------


def test_rate_probe_sets_a_sequential_repeat():
    prepared = _apply("rate_probe", {"count": 7})
    assert (prepared.repeat, prepared.concurrent) == (7, False)


def test_race_condition_is_concurrent():
    prepared = _apply("race_condition", {"count": 5})
    assert (prepared.repeat, prepared.concurrent) == (5, True)


def test_repeat_count_is_capped():
    # The point of a limit probe is to observe the target's ceiling, never to
    # become the outage.
    prepared = _apply("race_condition", {"count": 100_000})
    assert prepared.repeat == _MAX_REPEAT


def test_json_depth_bomb_is_capped_and_serialisable():
    prepared = _apply("json_depth_bomb", {"depth": 10_000})
    # Must survive json.dumps — a bomb that only crashes our own runner is not
    # a test of anything.
    assert json.dumps(prepared.body)


# -- API5/API9: path rewrites may never escape scope --------------------------


def test_admin_path_swap_rejects_an_absolute_url():
    with pytest.raises(MutationError, match="must be relative"):
        _apply("admin_path_swap", {"path": "https://evil.example/admin"})


def test_undocumented_path_probe_rejects_an_absolute_url():
    with pytest.raises(MutationError, match="must be relative"):
        _apply("undocumented_path_probe", {"path": "http://evil.example/.env"})


def test_version_downgrade_walks_back_one_version():
    prepared = _apply("version_downgrade", base=RequestSpec(method="GET", path="/v3/customers"))
    assert prepared.path == "/v2/customers"


def test_version_downgrade_refuses_when_there_is_nothing_older():
    with pytest.raises(MutationError, match="nothing older"):
        _apply("version_downgrade", base=RequestSpec(method="GET", path="/v1/customers"))


def test_method_override_keeps_the_outer_verb():
    prepared = _apply("method_override", {"method": "DELETE"})
    assert prepared.method == "GET"
    assert prepared.headers["X-HTTP-Method-Override"] == "DELETE"


def test_escalate_persona_strips_client_controlled_scoping_headers():
    base = RequestSpec(method="GET", path="/reports", headers={"X-Role": "agent"})
    prepared = _apply("escalate_persona")
    assert "X-Role" not in _apply("escalate_persona", base=base).headers
    assert prepared.note
