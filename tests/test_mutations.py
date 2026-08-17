from app.execution.mutations import _MAX_OVERSIZED_PAYLOAD_BYTES, apply_mutation
from app.schemas.testcase import Mutation, RequestSpec
from app.vault.personas import Persona, PersonaVault

_ATTACKER = Persona("attacker", {}, "agent", {}, [])
_BASE = RequestSpec(method="GET", path="/x")


def test_oversized_payload_is_capped_regardless_of_requested_size():
    # A hand-edited or misconfigured test spec asking for a huge size must
    # not turn this into a DoS against the very target under test.
    mutation = Mutation(kind="oversized_payload", detail={"size": 999_999_999})
    prepared = apply_mutation(_BASE, mutation, _ATTACKER, None, PersonaVault([]), {})
    assert len(prepared.query["q"]) == _MAX_OVERSIZED_PAYLOAD_BYTES


def test_oversized_payload_honors_a_reasonable_requested_size():
    mutation = Mutation(kind="oversized_payload", detail={"size": 500})
    prepared = apply_mutation(_BASE, mutation, _ATTACKER, None, PersonaVault([]), {})
    assert len(prepared.query["q"]) == 500
