"""Measured facts about one execution's evidence — before anyone reads it.

`app/execution/verdict.py` seals a verdict from a small set of rules it can
defend absolutely. When those rules do not fire it says INCONCLUSIVE, which is
honest and expensive: every undecided row becomes a person opening a response
body next to a baseline and deciding by eye.

Most of that eye-work is not judgement, it is *measurement*. "Is this body the
same shape as the owner's?", "does it carry any of the owner's distinctive
values?", "is a 200 that says `{"error": "forbidden"}` a success?", "is a 401
where the test expected a 403 a different answer or the same answer with a
different status line?" — all of those are computable, and computing them does
two things:

  1. some of them settle the result outright, with no model involved at all
     (`measure` below), and
  2. the rest go into the adjudicating model's prompt as facts, so it is
     reading with the differential already done instead of eyeballing two
     JSON blobs.

Nothing here writes `execution.verdict`. The sealed verdict is hashed into the
evidence chain; this module produces signals and a reading beside it. A separate
promotion policy decides whether that reading is strong enough for a derived
event, without changing the evidence.

The two ideas that carry most of the weight:

**Status layers.** A status code is not a scalar to compare for equality — it
names which layer of the system answered. 401 and 403 are the auth layer
refusing; 404 is the object layer refusing (often the *better* refusal, since
it does not confirm the object exists); 400/422 is input validation, which runs
*after* authentication in every framework worth the name. So "expected 403, got
404, nothing leaked" is the same security decision wearing a different status
line — a PASS — while "expected 401, got 400" is a genuinely different layer
answering and stays a question. Encoding that distinction is what turns a large
slice of today's INCONCLUSIVE pile into decided results without guessing.

**Distinctive values.** Two responses can be structurally identical and mean
opposite things: the attacker seeing *their own* record is a PASS, the attacker
seeing the *owner's* record is a FAIL. Byte-equality catches only the second
when the bodies match exactly. Comparing the *set of distinctive scalar values*
(long strings, id-shaped numbers) catches the realistic case where the owner's
body carries a timestamp or a request id the attacker's does not, while still
sharing the customer name, email and object id that make it a disclosure.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from typing import Literal

from app.schemas.enums import TestStatus
from app.schemas.execution import Execution
from app.schemas.testcase import TestCase

# How much of a body is compared. Bodies are already truncated by the runner's
# output cap; this is a second bound so a pathological pair cannot turn a review
# pass into a CPU burn.
_COMPARE_LIMIT = 8000
# Below this, "the bodies are identical" proves nothing: `{"ok":true}` is
# identical for every caller on earth.
_MIN_CORRELATION_BODY = 24
# How many shared distinctive values make a match a disclosure rather than a
# coincidence of shared boilerplate.
_MIN_SHARED_VALUES = 3
# What share of the *owner's* distinctive values the attacker's response has to
# carry. This, not raw text similarity, is what makes correlated disclosure a
# measurement: appending one extra field to a small JSON record drops a
# character-diff ratio well below any threshold worth having, while "the
# attacker's response contains five of the owner's five distinctive values" is
# unaffected by how much else came back with them.
_MIN_OWNER_COVERAGE = 0.75
# A loose floor, kept only to exclude the degenerate case where a handful of
# values coincide inside two responses with nothing else in common.
_SIMILARITY_FLOOR = 0.5

Supports = Literal["FAIL", "PASS", "NEITHER"]
Strength = Literal["decisive", "strong", "weak"]

# Which layer of the system answered. Ordered loosely outermost-first; the
# ordering is not used for arithmetic, only the names are.
Layer = Literal[
    "success",     # 2xx — the request was processed
    "redirect",    # 3xx
    "auth",        # 401/403 — the authn/authz layer refused
    "notfound",    # 404/410 — the object layer refused (or hid the object)
    "validation",  # 400/415/422 — input validation refused, i.e. AFTER authn
    "method",      # 405
    "conflict",    # 409
    "toolarge",    # 413
    "throttled",   # 429 — a rate limit answered
    "server",      # 5xx
    "none",        # no response at all
]

# A refusal that reflects a security decision. 404 belongs here deliberately:
# hiding an object's existence rather than announcing it is a legitimate — often
# preferable — way to enforce object-level authorization.
_SECURITY_REFUSAL: frozenset[str] = frozenset({"auth", "notfound"})

_LAYER_BY_STATUS: dict[int, Layer] = {
    401: "auth", 403: "auth",
    404: "notfound", 410: "notfound",
    400: "validation", 415: "validation", 422: "validation",
    405: "method", 409: "conflict", 413: "toolarge", 429: "throttled",
}

# Keys under which APIs conventionally nest a collection.
_COLLECTION_KEYS = ("data", "items", "results", "records", "rows", "content",
                    "values", "list", "entries", "customers", "orders", "users")
# Keys an error envelope is built from. A body whose keys are a subset of these
# is the service explaining itself, not returning a resource.
_ERROR_KEYS = frozenset({
    "error", "errors", "message", "messages", "detail", "details", "code",
    "status", "statuscode", "status_code", "title", "type", "timestamp", "path",
    "traceid", "trace_id", "reason", "success", "ok", "result", "instance",
})
# Words that make an error envelope an *authorization* refusal rather than a
# validation complaint. Matched case-insensitively over the envelope's own
# string values only — never over a whole resource body, where "permissions"
# could be a field name in the data being disclosed.
_REFUSAL_WORDS = (
    "forbidden", "unauthorized", "unauthorised", "not authorized",
    "not authorised", "not allowed", "not permitted", "no permission",
    "permission denied", "access denied", "access is denied", "denied",
    "insufficient scope", "insufficient privilege", "insufficient permission",
    "requires authentication", "authentication required", "invalid token",
    "missing token", "missing credentials", "invalid credentials",
    "not found", "does not exist", "no such",
)
_VALIDATION_WORDS = (
    "required", "is invalid", "invalid value", "must be", "must not",
    "validation", "malformed", "cannot be null", "bad request", "unprocessable",
    "expected", "unsupported", "too long", "too short",
)

# Scalars too generic to mean anything when shared between two bodies.
_GENERIC_VALUES = frozenset({
    "true", "false", "null", "none", "ok", "success", "error", "failed",
    "active", "inactive", "pending", "enabled", "disabled", "unknown",
    "admin", "user", "customer", "string", "object", "array", "yes", "no",
})
_WORDY = re.compile(r"[A-Za-z0-9]")


@dataclass(frozen=True)
class Signal:
    """One measured fact, and which answer it points at.

    `text` is written to be read by a person in a report, so it states the
    measurement rather than the conclusion: "the attacker's body shares 6
    distinctive values with the owner's" and not "this is a leak".
    """

    key: str
    text: str
    supports: Supports = "NEITHER"
    strength: Strength = "weak"


@dataclass
class ExecutionSignals:
    """Everything measurable about one execution's evidence."""

    attack_layer: Layer = "none"
    expected_layers: tuple[Layer, ...] = ()
    status_code: int | None = None
    body_kind: str = "empty"
    n_records: int | None = None

    baseline_present: bool = False
    baseline_ok: bool | None = None
    baseline_layer: Layer = "none"
    baseline_body_kind: str = "empty"
    baseline_records: int | None = None

    similarity: float = 0.0
    shared_values: int = 0
    attack_only_values: int = 0
    baseline_only_values: int = 0
    # Share of the entitled owner's distinctive values that came back in the
    # attacker's response. 1.0 means everything identifying about the owner's
    # record was disclosed, whatever else was or was not in the payload.
    owner_coverage: float = 0.0
    identical_body: bool = False

    refusal_in_body: bool = False
    validation_in_body: bool = False
    echoed_mutation: tuple[str, ...] = ()
    auth_challenge_header: bool = False

    signals: list[Signal] = field(default_factory=list)

    # -- readable summary, for prompts and reports ------------------------

    def lines(self) -> list[str]:
        return [s.text for s in self.signals]

    def as_prompt_block(self) -> str:
        """The differential, pre-computed, for the adjudicating model.

        Deliberately facts only — no "therefore". The model is being asked to
        decide; handing it a conclusion dressed as an input is how a prompt
        talks itself into an answer.
        """
        if not self.signals:
            return "(no differential signal could be measured from this evidence)"
        return "\n".join(
            f"- [{s.supports if s.supports != 'NEITHER' else 'neutral'}/{s.strength}] {s.text}"
            for s in self.signals
        )


# -- 1. measurement -----------------------------------------------------------


def status_layer(status: int | None, headers: dict[str, str] | None = None) -> Layer:
    """Which layer of the system answered.

    A `WWW-Authenticate` header promotes an otherwise ambiguous refusal to the
    auth layer: it is the layer naming itself on the wire.
    """
    if status is None:
        return "none"
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    if "www-authenticate" in lowered and 400 <= status < 500:
        return "auth"
    if 200 <= status < 300:
        return "success"
    if 300 <= status < 400:
        return "redirect"
    if status >= 500:
        return "server"
    return _LAYER_BY_STATUS.get(status, "validation" if status < 500 else "server")


def expected_layers(test: TestCase | None) -> tuple[Layer, ...]:
    if test is None:
        return ()
    seen: list[Layer] = []
    for status in test.expected.status_in:
        layer = status_layer(status)
        if layer not in seen:
            seen.append(layer)
    return tuple(seen)


def _parse(body: str | None) -> object | None:
    text = (body or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def classify_body(body: str | None) -> tuple[str, int | None, object | None]:
    """(kind, record count, parsed payload).

    Kind is one of empty / collection / object / error_envelope / html / text.
    `n_records` is only meaningful for a collection.
    """
    text = (body or "").strip()
    if not text or text in ("{}", "[]", "null", '""'):
        return "empty", 0, None
    parsed = _parse(text)
    if isinstance(parsed, list):
        return "collection", len(parsed), parsed
    if isinstance(parsed, dict):
        lowered = {str(k).lower() for k in parsed}
        for key in _COLLECTION_KEYS:
            value = _get_ci(parsed, key)
            if isinstance(value, list):
                return "collection", len(value), parsed
        if lowered and lowered <= _ERROR_KEYS:
            return "error_envelope", None, parsed
        return "object", None, parsed
    if text[:1] == "<" or "<html" in text[:400].lower():
        return "html", None, None
    return "text", None, None


def _get_ci(payload: dict, key: str):
    for k, v in payload.items():
        if str(k).lower() == key:
            return v
    return None


def _strings(payload: object, out: list[str], depth: int = 0) -> None:
    if depth > 8 or len(out) > 400:
        return
    if isinstance(payload, dict):
        for value in payload.values():
            _strings(value, out, depth + 1)
    elif isinstance(payload, list):
        for value in payload[:200]:
            _strings(value, out, depth + 1)
    elif isinstance(payload, str):
        out.append(payload)


def _distinctive_values(payload: object, raw: str) -> set[str]:
    """Scalar leaves distinctive enough that sharing one means something.

    Falls back to word-shaped tokens for a non-JSON body, so an HTML or
    form-encoded response is still comparable rather than silently scoring zero.
    """
    values: set[str] = set()
    if payload is None:
        for token in re.findall(r"[A-Za-z0-9@._\-]{8,}", raw or "")[:400]:
            if token.lower() not in _GENERIC_VALUES:
                values.add(token)
        return values

    def walk(node: object, depth: int = 0) -> None:
        if depth > 8 or len(values) > 400:
            return
        if isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, list):
            for value in node[:200]:
                walk(value, depth + 1)
        elif isinstance(node, bool):
            return
        elif isinstance(node, str):
            text = node.strip()
            if len(text) >= 6 and text.lower() not in _GENERIC_VALUES and _WORDY.search(text):
                values.add(text)
        elif isinstance(node, (int, float)):
            # An id-shaped number. Small integers (counts, page sizes, flags)
            # are shared by everyone and carry no identity.
            if abs(node) >= 1000:
                values.add(str(node))

    walk(payload)
    return values


def body_shape(body: str | None) -> str:
    """A fingerprint of a body's *structure*, ignoring every value in it.

    Two responses with the same shape are the same kind of answer: the same
    fields, the same nesting, the same envelope. That is what makes them the
    same *reading task* even when the ids and names inside them differ, and it
    is the load-bearing part of the cluster key in
    `Orchestrator._reading_cluster_key`. Values are deliberately excluded — the
    whole point is that "customer 2002's record" and "customer 2003's record"
    cluster together, while a record and an error envelope never do.
    """
    kind, records, parsed = classify_body(body)
    if parsed is None:
        return f"{kind}:{'many' if (records or 0) > 1 else records}"
    paths: set[str] = set()

    def walk(node: object, prefix: str, depth: int = 0) -> None:
        if depth > 6 or len(paths) > 200:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{prefix}.{key}", depth + 1)
        elif isinstance(node, list):
            # Only the first element's shape: a collection of ten records and a
            # collection of eleven are the same answer, not two.
            paths.add(f"{prefix}[]")
            if node:
                walk(node[0], f"{prefix}[]", depth + 1)
        else:
            paths.add(f"{prefix}:{type(node).__name__}")

    walk(parsed, "")
    bucket = "0" if not records else ("1" if records == 1 else "many")
    return f"{kind}:{bucket}:" + ",".join(sorted(paths))


def _similarity(left: str, right: str) -> float:
    a, b = (left or "")[:_COMPARE_LIMIT], (right or "")[:_COMPARE_LIMIT]
    if not a or not b:
        return 0.0
    matcher = difflib.SequenceMatcher(None, a, b)
    # quick_ratio is an upper bound and far cheaper; if it cannot reach the
    # threshold we care about, the exact ratio is not worth computing.
    if matcher.quick_ratio() < 0.5:
        return round(matcher.quick_ratio(), 3)
    return round(matcher.ratio(), 3)


def _words_present(payload: object, raw: str, words: tuple[str, ...]) -> bool:
    collected: list[str] = []
    _strings(payload, collected)
    haystack = " ".join(collected).lower() if collected else (raw or "").lower()[:2000]
    return any(word in haystack for word in words)


def _baseline_exchange(execution: Execution):
    for exchange in execution.supporting:
        if exchange.kind == "baseline":
            return exchange
    return None


def _echoed_mutation(test: TestCase | None, raw: str) -> tuple[str, ...]:
    """Injected property names/values the response repeated back.

    Weak evidence on purpose: plenty of APIs echo the payload they were sent
    without having stored any of it. It belongs in the model's prompt and in the
    report; it must not settle anything by itself. Proving persistence is what
    `verification` (the read-back) is for, and that already seals a FAIL.
    """
    if test is None:
        return ()
    detail = test.attack_mutation.detail or {}
    properties = detail.get("properties")
    if not isinstance(properties, dict):
        return ()
    lowered = (raw or "").lower()
    echoed = [
        f"{name}={value}"
        for name, value in properties.items()
        if str(name).lower() in lowered and str(value).lower() in lowered
    ]
    return tuple(echoed[:6])


def analyze_evidence(test: TestCase | None, execution: Execution) -> ExecutionSignals:
    """Measure one execution's evidence. Pure, no model, never raises."""
    signals = ExecutionSignals()
    response = execution.response
    signals.expected_layers = expected_layers(test)

    if response is None:
        signals.attack_layer = "none"
        signals.signals.append(Signal(
            "no_response",
            "No response was captured, so there is nothing to compare.",
        ))
        return signals

    signals.status_code = response.status_code
    signals.attack_layer = status_layer(response.status_code, response.headers)
    signals.auth_challenge_header = any(
        k.lower() == "www-authenticate" for k in response.headers
    )
    attack_raw = response.body or ""
    kind, records, parsed = classify_body(attack_raw)
    signals.body_kind = kind
    signals.n_records = records

    signals.signals.append(Signal(
        "attack_layer",
        f"HTTP {response.status_code} — answered by the "
        f"{_layer_phrase(signals.attack_layer)}; the test expected "
        f"{_expected_phrase(test, signals.expected_layers)}.",
        supports="NEITHER",
    ))
    if signals.auth_challenge_header:
        signals.signals.append(Signal(
            "www_authenticate",
            "The response carries a `WWW-Authenticate` header: the "
            "authentication layer named itself as the thing that refused.",
            supports="PASS", strength="strong",
        ))

    if kind == "error_envelope":
        signals.refusal_in_body = _words_present(parsed, attack_raw, _REFUSAL_WORDS)
        signals.validation_in_body = _words_present(parsed, attack_raw, _VALIDATION_WORDS)
        if signals.refusal_in_body:
            signals.signals.append(Signal(
                "refusal_envelope",
                "The body is an error envelope whose message is a refusal "
                "(forbidden / unauthorized / not found), not a resource.",
                supports="PASS", strength="strong",
            ))
        elif signals.validation_in_body:
            signals.signals.append(Signal(
                "validation_envelope",
                "The body is an error envelope complaining about the input "
                "(a validation message), which is a layer that runs after "
                "authentication rather than the auth layer itself.",
                supports="NEITHER", strength="weak",
            ))
        else:
            signals.signals.append(Signal(
                "error_envelope",
                "The body is an error envelope rather than a resource, but its "
                "message does not say which layer refused.",
            ))
    elif kind == "empty":
        signals.signals.append(Signal(
            "empty_body", "The response carried no body.", supports="NEITHER",
        ))
    elif kind == "collection":
        signals.signals.append(Signal(
            "collection",
            f"The body is a collection of {records} record(s).",
            supports="NEITHER",
        ))

    signals.echoed_mutation = _echoed_mutation(test, attack_raw)
    if signals.echoed_mutation:
        signals.signals.append(Signal(
            "mutation_echoed",
            "The response repeated the injected propert(ies) back: "
            + ", ".join(signals.echoed_mutation)
            + ". An echo is not persistence — only a read-back proves that.",
            supports="FAIL", strength="weak",
        ))

    baseline = _baseline_exchange(execution)
    if baseline is None:
        signals.signals.append(Signal(
            "no_baseline",
            "No positive control ran, so there is no entitled-identity response "
            "to compare this against.",
        ))
        return signals

    signals.baseline_present = True
    b_response = baseline.response
    if b_response is None:
        signals.baseline_ok = False
        signals.signals.append(Signal(
            "baseline_no_response",
            "The positive control captured no response at all.",
        ))
        return signals

    signals.baseline_layer = status_layer(b_response.status_code, b_response.headers)
    signals.baseline_ok = 200 <= b_response.status_code < 300
    baseline_raw = b_response.body or ""
    b_kind, b_records, b_parsed = classify_body(baseline_raw)
    signals.baseline_body_kind = b_kind
    signals.baseline_records = b_records

    if not signals.baseline_ok:
        signals.signals.append(Signal(
            "baseline_failed",
            f"The positive control failed (HTTP {b_response.status_code} as "
            f"`{baseline.as_persona}`): the target was never reachable even for "
            "its rightful owner, so the attack's rejection proves nothing.",
            supports="NEITHER", strength="decisive",
        ))
        return signals

    attack_body = attack_raw.strip()
    owner_body = baseline_raw.strip()
    signals.identical_body = (
        len(attack_body) >= _MIN_CORRELATION_BODY and attack_body == owner_body
    )
    signals.similarity = _similarity(attack_body, owner_body)

    attack_values = _distinctive_values(parsed, attack_raw)
    owner_values = _distinctive_values(b_parsed, baseline_raw)
    shared = attack_values & owner_values
    signals.shared_values = len(shared)
    signals.attack_only_values = len(attack_values - owner_values)
    signals.baseline_only_values = len(owner_values - attack_values)
    signals.owner_coverage = (
        round(len(shared) / len(owner_values), 3) if owner_values else 0.0
    )

    if signals.identical_body:
        signals.signals.append(Signal(
            "identical_body",
            "The attacker's response body is byte-identical to the positive "
            f"control's: the attacker received exactly what `{baseline.as_persona}` "
            "gets as the entitled owner.",
            supports="FAIL", strength="decisive",
        ))
    else:
        signals.signals.append(Signal(
            "body_similarity",
            f"The attacker's body is {int(signals.similarity * 100)}% similar to the "
            f"owner's and carries {signals.shared_values} of the "
            f"{signals.shared_values + signals.baseline_only_values} distinctive value(s) "
            f"in the owner's response "
            f"({int(signals.owner_coverage * 100)}% of them); "
            f"{signals.attack_only_values} value(s) appear only in the attacker's.",
            supports=(
                "FAIL" if (signals.shared_values >= _MIN_SHARED_VALUES
                           and signals.owner_coverage >= _MIN_OWNER_COVERAGE)
                else ("PASS" if signals.shared_values == 0 else "NEITHER")
            ),
            strength="weak",
        ))

    if (signals.attack_layer == "success" and signals.body_kind == "collection"
            and signals.n_records == 0 and (b_records or 0) > 0):
        signals.signals.append(Signal(
            "filtered_collection",
            f"The attacker got an empty collection where the entitled owner gets "
            f"{b_records} record(s): the same query was filtered server-side for "
            "the attacking identity.",
            supports="PASS", strength="strong",
        ))
    return signals


def _layer_phrase(layer: Layer) -> str:
    return {
        "success": "application (the request was processed)",
        "redirect": "redirect layer",
        "auth": "authentication/authorization layer",
        "notfound": "object layer (not found / hidden)",
        "validation": "input-validation layer, which runs after authentication",
        "method": "routing layer (method not allowed)",
        "conflict": "business-logic layer (conflict)",
        "toolarge": "request-size guard",
        "throttled": "rate limiter",
        "server": "an unhandled server error",
        "none": "nothing (no response)",
    }.get(layer, layer)


def _expected_phrase(test: TestCase | None, layers: tuple[Layer, ...]) -> str:
    if test is None or not test.expected.status_in:
        return "no particular status"
    codes = ", ".join(str(s) for s in test.expected.status_in)
    if not layers:
        return f"status {codes}"
    return f"status {codes} (the {'/'.join(_layer_phrase(la) for la in layers)})"


# -- 2. readings that need no model ------------------------------------------


@dataclass(frozen=True)
class MeasuredReading:
    """A reading derived from measurement rather than opinion.

    Still advisory — it lands in an `Adjudication`, never in
    `execution.verdict`. What makes it different from the model's reading is
    reproducibility: the same evidence produces the same answer every time, and
    the rule that produced it is named in `rule` so a tester who disagrees knows
    exactly what to argue with.
    """

    result: Literal["PASS", "FAIL"]
    confidence: str  # Confidence value name
    rule: str
    rationale: str
    evidence: tuple[str, ...]
    action: str


def measure(test: TestCase | None, execution: Execution,
            signals: ExecutionSignals | None = None) -> MeasuredReading | None:
    """Settle an undecided result from measurement alone, or return None.

    Rules are ordered strongest-first and each one is deliberately narrow.
    Returning None is the normal, expected outcome — this is a filter over the
    review queue, not a replacement for reading it.
    """
    signals = signals or analyze_evidence(test, execution)
    response = execution.response
    if response is None:
        return None
    # A failed positive control is a test-data problem. Nothing measured about
    # the attacker's response can settle it, and saying otherwise is exactly the
    # false negative `verdict.py` refuses to print.
    if signals.baseline_ok is False:
        return None

    # M1 — the attacker received the owner's bytes.
    if signals.identical_body:
        return MeasuredReading(
            result="FAIL",
            confidence="HIGH",
            rule="identical_body",
            rationale=(
                "The attacker's response body is byte-identical to the positive "
                "control's: the attacking identity received exactly the representation "
                "the entitled owner gets. That is correlated cross-identity disclosure "
                "measured directly, not inferred from a status code — no protected "
                "marker was configured, which is the only reason the deterministic "
                "verdict could not say so."
            ),
            evidence=("the attacker's response body is byte-identical to the positive "
                      "control's",),
            action=(
                "Treat as a confirmed authorization break: re-run this test with a "
                "verification read-back or a target-persona secret marker so the "
                "platform's own verdict can seal it as a finding."
            ),
        )

    # M2 — near-identical, and the shared part is the owner's identifying data.
    if (signals.attack_layer == "success"
            and signals.baseline_ok
            and signals.shared_values >= _MIN_SHARED_VALUES
            and signals.owner_coverage >= _MIN_OWNER_COVERAGE
            and signals.similarity >= _SIMILARITY_FLOOR
            and len((response.body or "").strip()) >= _MIN_CORRELATION_BODY):
        return MeasuredReading(
            result="FAIL",
            confidence="MEDIUM",
            rule="correlated_disclosure",
            rationale=(
                f"The attacker's response carries {int(signals.owner_coverage * 100)}% of "
                f"the distinctive values in the entitled owner's response "
                f"({signals.shared_values} of them) — identifiers and field values "
                "specific to the owner's record, not the field names and status words "
                "every response in this API shares. The bodies are not byte-equal (a "
                "timestamp, a request id or an extra field differs), which is why the "
                "deterministic verdict could not correlate them, but what came back is "
                "the owner's data."
            ),
            evidence=(
                f"{signals.shared_values} distinctive value(s) present in both the "
                "attacker's and the entitled owner's response bodies, "
                f"{int(signals.owner_coverage * 100)}% of everything distinctive in the "
                "owner's",
                f"body similarity {int(signals.similarity * 100)}%",
            ),
            action=(
                "Confirm the shared values are the owner's data (open the two bodies in "
                "the report), then re-run with a target-persona secret marker so the "
                "platform's own verdict can seal it."
            ),
        )

    # M3 — the same query, filtered server-side for the attacker.
    if (signals.attack_layer == "success"
            and signals.baseline_ok
            and signals.body_kind == "collection"
            and signals.n_records == 0
            and (signals.baseline_records or 0) > 0):
        return MeasuredReading(
            result="PASS",
            confidence="MEDIUM",
            rule="filtered_collection",
            rationale=(
                f"The attack was accepted, but it returned an empty collection where the "
                f"entitled owner gets {signals.baseline_records} record(s) for the same "
                "query. The server applied the authorization filter and handed the "
                "attacking identity nothing — which is the control holding, expressed as "
                "an empty result set rather than as a rejection status."
            ),
            evidence=("the attacker's collection is empty while the entitled owner's "
                      f"holds {signals.baseline_records} record(s)",),
            action=(
                "None. If the endpoint should refuse rather than return an empty list, "
                "that is an API-design preference, not a security finding."
            ),
        )

    # M4 — a 2xx that is actually a refusal.
    if (signals.attack_layer == "success"
            and signals.body_kind == "error_envelope"
            and signals.refusal_in_body):
        return MeasuredReading(
            result="PASS",
            confidence="MEDIUM",
            rule="refusal_in_body",
            rationale=(
                "The status line says the request was processed, but the body is an error "
                "envelope carrying a refusal message and no resource data. The control "
                "held; the service reports its refusal in the payload instead of in the "
                "status code."
            ),
            evidence=("the response body is a refusal envelope, not a resource",),
            action=(
                "None for security. Returning 200 for a refusal is worth raising with the "
                "service owner as an API-hygiene issue — it defeats status-code-based "
                "monitoring — but it is not a broken control."
            ),
        )

    # M5 — a rate limiter answered.
    if signals.attack_layer == "throttled":
        return MeasuredReading(
            result="PASS",
            confidence="MEDIUM",
            rule="throttled",
            rationale=(
                "The request was answered by a rate limiter. A control did push back, so "
                "the attack was not processed — whatever the test expected, this is not an "
                "absent control."
            ),
            evidence=(f"HTTP {response.status_code} from the rate limiter",),
            action=(
                "Re-run when the limit window has passed if you need this specific control "
                "exercised; the throttle answered instead of the endpoint."
            ),
        )

    # M6 — the status differs from the expected set, but it is the same security
    # decision. This is the largest source of avoidable review work in a real
    # run: the expected set is one test author's guess at *which* refusal a
    # secure system gives, and 401/403/404 are all "you do not get this" with
    # different disclosure trade-offs.
    #
    # It is also the rule most able to hide a real bug, so it is three narrow
    # cases rather than one broad one, and the difference between them is which
    # false negative each could otherwise produce:
    #
    #   (a) the SAME layer answered, a different code within it (403 where 401
    #       was expected, 410 where 404 was). Nothing is being papered over —
    #       the layer the test was aiming at is the layer that refused.
    #   (b) the AUTH layer answered where the test would have accepted any
    #       security refusal. An authentication/authorization refusal is the
    #       strongest of them and is the one refusal that cannot secretly mean
    #       "there was nothing here to protect".
    #   (c) the OBJECT layer answered (404) where only an auth refusal was
    #       expected. This one needs the positive control: a bare 404 is exactly
    #       the "safe from a 404" anti-pattern `verdict.py` refuses, because it
    #       is indistinguishable from a wrong object id against which nothing
    #       was ever tested. With `baseline_ok is True` the object provably
    #       exists for its owner, so hiding it from the attacker is a decision;
    #       without that, it stays a reading task.
    #
    # All three additionally require: an INCONCLUSIVE sealed verdict (a decided
    # one is the record and gets no second opinion), a body that is not a
    # resource, and no distinctive value shared with the entitled owner. A 404
    # carrying the victim's record is a disclosure wearing a refusal status and
    # must never reach here.
    allowed = set(signals.expected_layers)
    same_layer = signals.attack_layer in allowed
    stronger_refusal = (
        signals.attack_layer == "auth" and bool(allowed & _SECURITY_REFUSAL)
    )
    hidden_object = (
        signals.attack_layer == "notfound"
        and bool(allowed & _SECURITY_REFUSAL)
        and signals.baseline_ok is True
    )
    if (execution.verdict.result == TestStatus.INCONCLUSIVE
            and allowed
            and signals.attack_layer in _SECURITY_REFUSAL
            and (same_layer or stronger_refusal or hidden_object)
            and signals.body_kind in ("empty", "error_envelope", "text", "html")
            and signals.shared_values == 0):
        expected_codes = test.expected.status_in if test else []
        if same_layer:
            why = (
                f"HTTP {response.status_code} came from the same layer the expected set "
                f"{expected_codes} was checking — the test was aiming at this control and "
                "this control is what answered. Only the specific code differs."
            )
        elif stronger_refusal:
            why = (
                f"HTTP {response.status_code} is an authentication/authorization refusal, "
                f"and the expected set {expected_codes} would have accepted a security "
                "refusal here. This is the strongest refusal available and the one that "
                "cannot secretly mean the target was not there at all."
            )
        else:
            why = (
                f"HTTP {response.status_code} hides the object rather than announcing it, "
                f"where the expected set {expected_codes} wanted a refusal. The positive "
                "control proves the object exists and is reachable for its rightful owner, "
                "so hiding it from this identity is a decision the server made — often the "
                "more defensible of the two, since a 403 confirms the object exists."
            )
        return MeasuredReading(
            result="PASS",
            confidence="MEDIUM",
            rule="equivalent_refusal",
            rationale=(
                why + " No resource data came back and the response shares no distinctive "
                "value with the entitled owner's, so there is nothing disclosed to weigh "
                "against the refusal. The status mismatch is a disagreement with the test "
                "author's guess, not a broken control."
            ),
            evidence=(
                f"HTTP {response.status_code} is a security refusal, and the expected set "
                f"{expected_codes} was checking for one",
                "the response body carries no resource data and no value belonging to the "
                "entitled owner",
            ),
            action=(
                f"Optional: widen this test's expected set to include "
                f"{response.status_code} so the runner seals it as PASS next time."
            ),
        )

    return None
