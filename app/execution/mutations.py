"""Apply an attack mutation to a baseline request.

Each mutation is a named, understood transformation — the runner knows exactly
what it changed, which is what lets the verdict be explained in terms of the
attack ("swapped the object id to another persona's") instead of guessed from a
status code. Unknown mutation kinds are rejected, not improvised.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.testcase import Mutation, RequestSpec
from app.vault.personas import Persona, PersonaVault


@dataclass
class PreparedRequest:
    method: str
    path: str
    headers: dict[str, str]
    query: dict[str, str]
    body: object | None
    note: str  # human summary of what the mutation did


class MutationError(Exception):
    pass


# Hard ceiling for the oversized_payload mutation, regardless of what a test
# spec requests. 10 MB is well past what any real API4 resource-limit probe
# needs and still small enough not to be a meaningful DoS vector on its own.
_MAX_OVERSIZED_PAYLOAD_BYTES = 10_000_000


def apply_mutation(
    base: RequestSpec,
    mutation: Mutation,
    attacker: Persona,
    target: Persona | None,
    vault: PersonaVault,
    context: dict,
) -> PreparedRequest:
    headers = dict(base.headers)
    query = dict(base.query)
    path = base.path
    body = base.body
    kind = mutation.kind
    note = ""

    # Attacker's own credentials are the default identity for the request.
    headers = {**attacker.auth_headers, **headers}

    if kind == "swap_object_id":
        # API1 BOLA: attacker keeps their own auth but targets an object id
        # owned by the victim. The id comes from the target persona / context.
        id_key = mutation.detail.get("id_field", "victim_id")
        victim_id = context.get(id_key)
        if victim_id is None and target is not None:
            # fall back to the target's first owned id
            victim_id = next(iter(target.owns.values()), None)
        if victim_id is None:
            raise MutationError(
                f"swap_object_id needs a victim id (context['{id_key}'] or a "
                "target persona that owns an object)."
            )
        context[id_key] = victim_id
        note = f"targeted object id {victim_id} owned by another identity"

    elif kind == "drop_auth":
        # API2: remove all credentials — endpoint should reject with 401.
        headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        note = "removed the Authorization header (unauthenticated request)"

    elif kind == "tamper_token":
        token = mutation.detail.get("token", "Bearer invalid.tampered.token")
        headers["Authorization"] = token
        note = "replaced the credential with a malformed/expired token"

    elif kind == "escalate_persona":
        # API5 BFLA: a lower-priv persona invokes a higher-priv function. The
        # attacker persona is already low-priv; we just keep their creds and hit
        # a privileged path/method — the test spec supplies those.
        note = f"invoked a privileged function as role '{attacker.role}'"

    elif kind == "inject_property":
        # API3 BOPLA / mass assignment: add fields the caller shouldn't set.
        extra = mutation.detail.get("properties", {})
        if isinstance(body, dict):
            body = {**body, **extra}
        else:
            body = extra
        note = f"injected protected propert(ies): {sorted(extra)}"

    elif kind == "oversized_payload":
        # API4: inflate a field to test resource limits. Capped so a
        # misconfigured/hand-edited test spec can't turn this into a
        # multi-hundred-MB request that DoSes the very target under test —
        # the point is to *probe* the target's own size limit, not to
        # exceed what any reasonable API4 test needs to send.
        field = mutation.detail.get("field", "q")
        size = min(int(mutation.detail.get("size", 100_000)), _MAX_OVERSIZED_PAYLOAD_BYTES)
        query[field] = "A" * size
        note = f"sent an oversized '{field}' ({size} bytes)"

    elif kind == "ssrf_url":
        # API7: point a server-side URL field at an internal/metadata target.
        field = mutation.detail.get("field", "url")
        payload = mutation.detail.get("value", "http://169.254.169.254/latest/meta-data/")
        if isinstance(body, dict):
            body = {**body, field: payload}
        else:
            query[field] = payload
        note = f"set server-side URL field '{field}' to internal target {payload}"

    else:
        raise MutationError(f"Unknown mutation kind: {kind!r}")

    return PreparedRequest(
        method=base.method,
        path=path,
        headers=headers,
        query=query,
        body=body,
        note=note,
    )
