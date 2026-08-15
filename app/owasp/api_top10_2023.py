"""Static metadata for the OWASP API Security Top 10 (2023).

Used for reasoning display, report rendering, default severities and
references. Kept as plain data so it is trivial to audit and extend.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.enums import OwaspApiCategory, Severity


@dataclass(frozen=True)
class OwaspControl:
    category: OwaspApiCategory
    title: str
    summary: str
    default_severity: Severity
    references: tuple[str, ...]


CONTROLS: dict[OwaspApiCategory, OwaspControl] = {
    OwaspApiCategory.API1: OwaspControl(
        OwaspApiCategory.API1,
        "Broken Object Level Authorization",
        "The API exposes object identifiers and fails to verify that the "
        "caller is authorized to act on the specific object.",
        Severity.HIGH,
        ("https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
         "CWE-639"),
    ),
    OwaspApiCategory.API2: OwaspControl(
        OwaspApiCategory.API2,
        "Broken Authentication",
        "Authentication can be bypassed, tokens are weak/mishandled, or "
        "endpoints accept missing/expired/malformed credentials.",
        Severity.HIGH,
        ("https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
         "CWE-287"),
    ),
    OwaspApiCategory.API3: OwaspControl(
        OwaspApiCategory.API3,
        "Broken Object Property Level Authorization",
        "The API lets a caller read or write object properties they should "
        "not (mass assignment / excessive data exposure).",
        Severity.HIGH,
        ("https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
         "CWE-915"),
    ),
    OwaspApiCategory.API4: OwaspControl(
        OwaspApiCategory.API4,
        "Unrestricted Resource Consumption",
        "No effective limits on payload size, pagination, rate or cost, "
        "enabling DoS or runaway billing.",
        Severity.MEDIUM,
        ("https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
         "CWE-770"),
    ),
    OwaspApiCategory.API5: OwaspControl(
        OwaspApiCategory.API5,
        "Broken Function Level Authorization",
        "A lower-privileged user can invoke functions reserved for higher "
        "roles (e.g. admin endpoints).",
        Severity.HIGH,
        ("https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
         "CWE-285"),
    ),
    OwaspApiCategory.API6: OwaspControl(
        OwaspApiCategory.API6,
        "Unrestricted Access to Sensitive Business Flows",
        "A sensitive flow (purchase, signup, booking) can be automated/abused "
        "without business-appropriate throttling.",
        Severity.MEDIUM,
        ("https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",),
    ),
    OwaspApiCategory.API7: OwaspControl(
        OwaspApiCategory.API7,
        "Server Side Request Forgery",
        "The API fetches a user-supplied URL, letting an attacker reach "
        "internal services or cloud metadata.",
        Severity.HIGH,
        ("https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
         "CWE-918"),
    ),
    OwaspApiCategory.API8: OwaspControl(
        OwaspApiCategory.API8,
        "Security Misconfiguration",
        "Missing hardening: verbose errors, permissive CORS, missing security "
        "headers, default credentials.",
        Severity.MEDIUM,
        ("https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
         "CWE-16"),
    ),
    OwaspApiCategory.API9: OwaspControl(
        OwaspApiCategory.API9,
        "Improper Inventory Management",
        "Undocumented, deprecated or non-production API versions/hosts remain "
        "exposed.",
        Severity.MEDIUM,
        ("https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",),
    ),
    OwaspApiCategory.API10: OwaspControl(
        OwaspApiCategory.API10,
        "Unsafe Consumption of APIs",
        "The service trusts data from third-party APIs without validation, "
        "inheriting their weaknesses.",
        Severity.MEDIUM,
        ("https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",),
    ),
}
