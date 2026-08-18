"""Deterministic OWASP rule engine.

This runs *alongside* the AI, not instead of it. The AI is good at nuance and
bad at consistency; a rule engine is the opposite. We use the rules as the
reliable backbone — given signals extracted from a ticket, which OWASP
categories are provably worth testing — and let the AI add reasoning and edge
cases on top. Rules are pure data + pure functions, so they are unit-testable
and auditable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.schemas.enums import Applicability, OwaspApiCategory


@dataclass(frozen=True)
class RequirementSignals:
    """Normalized, lowercased signals extracted from a Jira ticket / API spec.

    This is the seam between "understanding the ticket" (AI/normalizer) and
    "deciding what to test" (deterministic). Keep it dumb and explicit.
    """

    text: str = ""  # full normalized description + acceptance criteria
    object_identifiers: list[str] = field(default_factory=list)  # customerId, ...
    has_authentication: bool = False
    roles: list[str] = field(default_factory=list)  # admin, manager, agent
    external_url_fields: list[str] = field(default_factory=list)  # callback, webhook
    writes_object_properties: bool = False  # PUT/PATCH/POST with a body
    bulk_or_expensive: bool = False  # search/export/pagination/upload/bulk

    @property
    def lower_text(self) -> str:
        return self.text.lower()


@dataclass(frozen=True)
class RuleHit:
    category: OwaspApiCategory
    applicability: Applicability
    reason: str
    matched_signals: list[str]


# --- keyword vocabularies (configurable) ------------------------------------

ID_KEYWORDS = re.compile(r"\b(\w*id)\b", re.IGNORECASE)  # customerId, orderId, ...
ROLE_KEYWORDS = ("role", "permission", "admin", "manager", "agent", "privilege", "scope")
URL_KEYWORDS = ("url", "callback", "webhook", "redirect", "imageurl", "externalurl", "fetch", "proxy")
RESOURCE_KEYWORDS = ("search", "export", "upload", "bulk", "pagination", "filter", "batch", "report")
# API6 is about *business* flows worth automating, which is a different question
# from API4's "is this expensive to serve". Sharing one vocabulary made every
# paginated list endpoint claim a sensitive-business-flow gap the test designer
# could never fill, so the coverage matrix showed a permanent phantom MISSING.
FLOW_KEYWORDS = (
    "purchase", "order", "checkout", "payment", "transfer", "booking", "reserve",
    "signup", "sign up", "register", "invite", "coupon", "redeem", "claim",
    "withdraw", "vote", "refund", "subscribe", "business flow", "workflow",
)
AUTH_KEYWORDS = ("login", "token", "jwt", "bearer", "session", "oauth", "authenticate", "password")
MISCONFIG_KEYWORDS = (
    "debug", "stack trace", "verbose error", "default password", "default credential",
    "cors", "misconfigur", "directory listing", "swagger ui", "exposed config",
    "default admin", "sample data", "test endpoint",
)
INVENTORY_KEYWORDS = (
    "deprecated", "legacy", "shadow api", "undocumented", "beta endpoint",
    "sunset", "decommission", "old version", "staging environment", "internal api",
)
THIRD_PARTY_KEYWORDS = (
    "third-party", "third party", "3rd-party", "external api", "external service",
    "vendor api", "partner api", "upstream service", "integration partner",
)


def _found(keywords, text: str) -> list[str]:
    return [k for k in keywords if k in text]


def evaluate(signals: RequirementSignals) -> list[RuleHit]:
    """Return one RuleHit per OWASP category the signals implicate.

    Only APPLICABLE hits are returned as APPLICABLE; categories with no signal
    are simply absent (the caller treats absence as UNKNOWN, to be confirmed by
    AI — never silently NOT_APPLICABLE)."""

    text = signals.lower_text
    hits: list[RuleHit] = []

    # API1 / API3 — object identifiers imply object-level & property-level authz.
    ids = list(signals.object_identifiers)
    if not ids:
        ids = sorted({m.group(1) for m in ID_KEYWORDS.finditer(text) if m.group(1) != "id"})
    if ids:
        hits.append(
            RuleHit(
                OwaspApiCategory.API1,
                Applicability.APPLICABLE,
                "Endpoint exposes user-controlled object identifier(s); object "
                "ownership must be enforced server-side.",
                ids,
            )
        )
        if signals.writes_object_properties or "role" in text or "status" in text:
            hits.append(
                RuleHit(
                    OwaspApiCategory.API3,
                    Applicability.APPLICABLE,
                    "Request carries object properties; caller may set fields "
                    "they should not (mass assignment / property-level authz).",
                    ids,
                )
            )

    # API2 — any authenticated endpoint is worth auth-abuse testing.
    auth_hits = _found(AUTH_KEYWORDS, text)
    if signals.has_authentication or auth_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API2,
                Applicability.APPLICABLE,
                "Endpoint is authenticated; test missing/expired/malformed "
                "credential handling.",
                auth_hits or ["authentication"],
            )
        )

    # API5 — roles/permissions imply function-level authorization tests.
    role_hits = _found(ROLE_KEYWORDS, text) + [r for r in signals.roles]
    if role_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API5,
                Applicability.APPLICABLE,
                "Multiple roles/permissions present; verify lower-privileged "
                "users cannot invoke higher-privileged functions.",
                sorted(set(role_hits)),
            )
        )

    # API7 — server-side URL handling implies SSRF surface.
    url_hits = _found(URL_KEYWORDS, text) + list(signals.external_url_fields)
    if url_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API7,
                Applicability.APPLICABLE,
                "Server consumes a user-supplied URL; test SSRF to internal "
                "services and cloud metadata.",
                sorted(set(url_hits)),
            )
        )

    # API4 — expensive or bulk operations (cost to serve).
    res_hits = _found(RESOURCE_KEYWORDS, text)
    if res_hits or signals.bulk_or_expensive:
        hits.append(
            RuleHit(
                OwaspApiCategory.API4,
                Applicability.APPLICABLE,
                "Expensive/bulk operation present; test resource-consumption "
                "limits (size, pagination, rate).",
                res_hits or ["bulk"],
            )
        )

    # API6 — business flows whose value comes from being hard to automate.
    flow_hits = _found(FLOW_KEYWORDS, text)
    if flow_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API6,
                Applicability.APPLICABLE,
                "Sensitive business flow present; test for unrestricted "
                "automation/abuse (bulk execution, race on the commit window).",
                flow_hits,
            )
        )

    # API8 — misconfiguration signals (debug mode, exposed config, CORS, ...).
    misconfig_hits = _found(MISCONFIG_KEYWORDS, text)
    if misconfig_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API8,
                Applicability.APPLICABLE,
                "Ticket mentions a configuration/debug surface that can leak internals "
                "if left enabled in a non-production state; verify hardened defaults.",
                misconfig_hits,
            )
        )

    # API9 — inventory signals (deprecated/legacy/shadow/undocumented endpoints).
    inventory_hits = _found(INVENTORY_KEYWORDS, text)
    if inventory_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API9,
                Applicability.APPLICABLE,
                "Ticket references an older/undocumented/shadow API surface; verify "
                "it is inventoried and enforces the same controls as current endpoints.",
                inventory_hits,
            )
        )

    # API10 — unsafe consumption of a third-party/upstream API's response.
    third_party_hits = _found(THIRD_PARTY_KEYWORDS, text)
    if third_party_hits:
        hits.append(
            RuleHit(
                OwaspApiCategory.API10,
                Applicability.APPLICABLE,
                "Endpoint integrates with a third-party/upstream API; verify its "
                "responses (redirects, data, TLS) are validated before being "
                "trusted, not consumed blindly.",
                third_party_hits,
            )
        )

    return hits
