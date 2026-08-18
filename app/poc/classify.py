"""Infer what an imported request is actually testing.

Every artefact the platform imports — Python PoC, curl, Postman, Burp, JMeter —
used to arrive labelled `API1 / swap_object_id` regardless of content. Two
things broke as a result:

  * the coverage matrix, which is the tool's headline answer to "what is still
    untested", counted a 40-request Burp export as forty BOLA tests and
    declared every other category MISSING;
  * `swap_object_id` with an empty detail looked for a `victim_id` that nobody
    had set, so the imported test errored at run time instead of testing
    anything.

This module reads the request's own shape and picks the probe it implies. It is
deliberately conservative: when no attack shape is recognisable it falls back to
`drop_auth`, which is meaningful for literally any authenticated endpoint
("does this work without a credential?") and invents nothing. The alternative —
guessing a category — is what produced the wrong coverage matrix in the first
place.

Nothing here executes anything. It reads strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.schemas.enums import OwaspApiCategory, Severity
from app.schemas.testcase import (
    ExpectedResult,
    Mutation,
    RequestSpec,
    VerificationStep,
)

# A path segment that is an object identifier: numeric, UUID, or ObjectId-ish.
_NUMERIC_SEGMENT = re.compile(r"^\d{1,}$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEXID_SEGMENT = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
_PLACEHOLDER_SEGMENT = re.compile(r"^\{([A-Za-z0-9_]+)\}$")

_URL_FIELD_NAMES = (
    "url", "uri", "callback", "callback_url", "callbackurl", "webhook",
    "webhook_url", "redirect", "redirect_uri", "image_url", "imageurl",
    "external_url", "externalurl", "target", "endpoint", "fetch",
)
_PRIVILEGED_PROPERTY_NAMES = (
    "role", "roles", "is_admin", "isadmin", "admin", "permission", "permissions",
    "scope", "scopes", "privilege", "privileges", "owner", "owner_id", "user_id",
    "account_id", "tenant_id", "status", "verified", "is_verified", "balance",
    "price", "amount", "discount",
)
_ADMIN_PATH_WORDS = ("/admin", "/internal", "/manage", "/management", "/backoffice", "/root")
_INVENTORY_PATH_WORDS = (
    "openapi", "swagger", "/actuator", "/.env", "/v1/", "/v0/", "api-docs",
    "/debug", "/metrics", "/trace",
)
_EXPENSIVE_PATH_WORDS = ("search", "export", "bulk", "report", "download", "list", "query")

_ADMIN_MARKERS = [
    '"role": "admin"', '"role":"admin"',
    '"is_admin": true', '"is_admin":true',
    '"isAdmin": true', '"isAdmin":true',
]


@dataclass
class PocClassification:
    """What an imported request appears to test, and why."""

    category: OwaspApiCategory
    mutation: Mutation
    expected: ExpectedResult
    severity: Severity
    reason: str
    # HIGH  — the request carries an unmistakable signal (a URL field, a
    #         privileged property, an admin path).
    # MEDIUM— a plausible but weaker signal (an id-shaped path segment).
    # LOW   — nothing recognisable; this is the honest fallback probe.
    confidence: str = "MEDIUM"
    # Path rewritten so a mutation can substitute an identifier, e.g.
    # /customers/2001 → /customers/{victim_id}. Empty when unchanged.
    parameterised_path: str = ""
    id_field: str = ""
    needs_target_persona: bool = False
    verification: VerificationStep | None = None
    notes: list[str] = field(default_factory=list)


def _split_path(path: str) -> tuple[str, str]:
    if "?" in path:
        base, query = path.split("?", 1)
        return base, query
    return path, ""


def _body_keys(body: object | None) -> set[str]:
    if isinstance(body, dict):
        return {str(k).lower() for k in body}
    if isinstance(body, str):
        # A raw JSON/form string body: cheap key sniffing, no parsing required.
        return {m.group(1).lower() for m in re.finditer(r'["\'&]?([A-Za-z0-9_]+)["\']?\s*[:=]', body)}
    return set()


def _find_url_field(body: object | None, query: str) -> str | None:
    keys = _body_keys(body) | {
        k.lower() for k in re.findall(r"(?:^|&)([A-Za-z0-9_]+)=", query)
    }
    for candidate in _URL_FIELD_NAMES:
        if candidate in keys:
            return candidate
    return None


def _find_privileged_property(body: object | None) -> str | None:
    keys = _body_keys(body)
    for candidate in _PRIVILEGED_PROPERTY_NAMES:
        if candidate in keys:
            return candidate
    return None


def parameterise_object_id(path: str) -> tuple[str, str]:
    """Rewrite the LAST id-shaped path segment into a `{victim_id}` placeholder.

    Returns (new_path, id_field) or (path, "") if no identifier is present.
    This is what makes an imported request usable as a BOLA probe at all: a
    recorded Burp request contains a literal id, and substituting another
    identity's id into a literal is impossible — there is nothing to replace.

    The last id-shaped segment is chosen because in `/accounts/12/orders/98`
    it is the order that the request is *about*; the earlier id is scope.
    """
    base, query = _split_path(path)
    segments = base.split("/")
    for index in range(len(segments) - 1, -1, -1):
        segment = segments[index]
        if not segment:
            continue
        placeholder = _PLACEHOLDER_SEGMENT.match(segment)
        if placeholder:
            # Already parameterised by whoever wrote the PoC — keep their name.
            return path, placeholder.group(1)
        if _NUMERIC_SEGMENT.match(segment) or _UUID_SEGMENT.match(segment) or _HEXID_SEGMENT.match(segment):
            segments[index] = "{victim_id}"
            rebuilt = "/".join(segments)
            return rebuilt + (f"?{query}" if query else ""), "victim_id"
    return path, ""


def classify(method: str, path: str, headers: dict[str, str], body: object | None) -> PocClassification:
    """Infer the probe an imported request implies. Never raises."""
    method = (method or "GET").upper()
    base, query = _split_path(path or "/")
    low_path = base.lower()

    # 1. A server-consumed URL field is the least ambiguous signal there is.
    url_field = _find_url_field(body, query)
    if url_field:
        return PocClassification(
            category=OwaspApiCategory.API7,
            mutation=Mutation(kind="ssrf_url", detail={"field": url_field}),
            expected=ExpectedResult(status_in=[400, 403, 422]),
            severity=Severity.HIGH,
            confidence="HIGH",
            reason=f"the request carries a server-consumed URL field '{url_field}'",
        )

    # 2. A body that writes a privileged property is a mass-assignment probe.
    if method in {"POST", "PUT", "PATCH"}:
        privileged = _find_privileged_property(body)
        if privileged:
            param_path, id_field = parameterise_object_id(path)
            return PocClassification(
                category=OwaspApiCategory.API3,
                mutation=Mutation(
                    kind="inject_property",
                    detail={"properties": {"role": "admin", "is_admin": True}},
                ),
                expected=ExpectedResult(status_in=[400, 403, 422]),
                severity=Severity.HIGH,
                confidence="HIGH",
                reason=f"the request body writes the privileged property '{privileged}'",
                parameterised_path=param_path if param_path != path else "",
                id_field=id_field,
                verification=VerificationStep(
                    as_persona="agent_A",
                    request=RequestSpec(method="GET", path=param_path or path),
                    proves_exploit_if_contains=list(_ADMIN_MARKERS),
                    description="Read the object back to prove the injected property persisted.",
                ),
            )

    # 3. An administrative route invoked by a normal identity.
    if any(word in low_path for word in _ADMIN_PATH_WORDS):
        return PocClassification(
            category=OwaspApiCategory.API5,
            mutation=Mutation(kind="escalate_persona"),
            expected=ExpectedResult(status_in=[401, 403]),
            severity=Severity.HIGH,
            confidence="HIGH",
            reason="the request targets an administrative/internal route",
        )

    # 4. Spec dumps, actuators and retired versions are inventory questions.
    if any(word in low_path for word in _INVENTORY_PATH_WORDS):
        return PocClassification(
            category=OwaspApiCategory.API9,
            mutation=Mutation(kind="undocumented_path_probe", detail={"path": base, "method": method}),
            expected=ExpectedResult(status_in=[401, 403, 404]),
            severity=Severity.MEDIUM,
            confidence="HIGH",
            reason="the path is a documentation/diagnostic/legacy-version surface",
        )

    # 5. An object identifier in the path implies object-level authorization.
    param_path, id_field = parameterise_object_id(path)
    if id_field:
        return PocClassification(
            category=OwaspApiCategory.API1,
            mutation=Mutation(kind="swap_object_id", detail={"id_field": id_field}),
            expected=ExpectedResult(status_in=[403, 404]),
            severity=Severity.HIGH,
            confidence="MEDIUM",
            reason=f"the path addresses a specific object via '{id_field}'",
            parameterised_path=param_path if param_path != path else "",
            id_field=id_field,
            needs_target_persona=True,
        )

    # 6. Expensive collection endpoints.
    if method == "GET" and any(word in low_path for word in _EXPENSIVE_PATH_WORDS):
        return PocClassification(
            category=OwaspApiCategory.API4,
            mutation=Mutation(kind="pagination_abuse", detail={"field": "limit", "value": 1_000_000}),
            expected=ExpectedResult(status_in=[400, 413, 422]),
            severity=Severity.MEDIUM,
            confidence="MEDIUM",
            reason="the path is a collection/search endpoint whose cost scales with input",
        )

    # 7. Honest fallback. Replaying any authenticated request without its
    #    credential is always a real question and never a fabricated one.
    return PocClassification(
        category=OwaspApiCategory.API2,
        mutation=Mutation(kind="drop_auth"),
        expected=ExpectedResult(status_in=[401]),
        severity=Severity.HIGH,
        confidence="LOW",
        reason=(
            "no object id, privileged property, URL field or administrative path was "
            "recognisable, so the request is replayed without its credential — the one "
            "probe that is meaningful for any endpoint without assuming what it does"
        ),
    )
