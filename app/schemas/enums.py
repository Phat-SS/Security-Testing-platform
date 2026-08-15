"""Canonical enumerations for the platform.

These are the *contract*. Everything else (AI output, rule engine, runner,
report) speaks in these terms. Keep them stable — changing a value here is a
breaking change across the whole system.
"""

from __future__ import annotations

from enum import Enum


class OwaspApiCategory(str, Enum):
    """OWASP API Security Top 10 — 2023. This is the PRIMARY baseline.

    We deliberately do not use the OWASP Web Application Top 10 as the primary
    axis: this platform reasons about endpoints, object identifiers, auth
    context and PoCs, which map far more cleanly onto the API list.
    """

    API1 = "API1:2023"  # Broken Object Level Authorization (BOLA)
    API2 = "API2:2023"  # Broken Authentication
    API3 = "API3:2023"  # Broken Object Property Level Authorization (BOPLA)
    API4 = "API4:2023"  # Unrestricted Resource Consumption
    API5 = "API5:2023"  # Broken Function Level Authorization (BFLA)
    API6 = "API6:2023"  # Unrestricted Access to Sensitive Business Flows
    API7 = "API7:2023"  # Server Side Request Forgery (SSRF)
    API8 = "API8:2023"  # Security Misconfiguration
    API9 = "API9:2023"  # Improper Inventory Management
    API10 = "API10:2023"  # Unsafe Consumption of APIs

    @property
    def title(self) -> str:
        return _OWASP_TITLES[self]


_OWASP_TITLES: dict[OwaspApiCategory, str] = {
    OwaspApiCategory.API1: "Broken Object Level Authorization",
    OwaspApiCategory.API2: "Broken Authentication",
    OwaspApiCategory.API3: "Broken Object Property Level Authorization",
    OwaspApiCategory.API4: "Unrestricted Resource Consumption",
    OwaspApiCategory.API5: "Broken Function Level Authorization",
    OwaspApiCategory.API6: "Unrestricted Access to Sensitive Business Flows",
    OwaspApiCategory.API7: "Server Side Request Forgery",
    OwaspApiCategory.API8: "Security Misconfiguration",
    OwaspApiCategory.API9: "Improper Inventory Management",
    OwaspApiCategory.API10: "Unsafe Consumption of APIs",
}


class Applicability(str, Enum):
    """Whether an OWASP category applies to a given ticket/endpoint.

    Crucial: the engine must NOT blindly generate all ten categories. Each is
    classified, with a reason, and only APPLICABLE ones produce tests.
    """

    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TestStatus(str, Enum):
    """Six-state result model.

    The distinction between FAIL, INCONCLUSIVE and BLOCKED is a first-class
    design decision: an uncertain or firewall-blocked result must NEVER be
    silently promoted to a confirmed vulnerability, nor to a clean PASS.
    """

    NOT_RUN = "NOT_RUN"
    PASS = "PASS"  # control held — attack was correctly rejected
    FAIL = "FAIL"  # control broken — attack succeeded → potential finding
    INCONCLUSIVE = "INCONCLUSIVE"  # ran, but evidence insufficient to decide
    BLOCKED = "BLOCKED"  # could not run: scope/policy/WAF prevented it
    SKIPPED = "SKIPPED"  # deliberately not run (not approved / disabled)
    ERROR = "ERROR"  # runner/tooling failure, not a security signal
    TIMEOUT = "TIMEOUT"


class ApprovalStatus(str, Enum):
    """Execution is prohibited until a human approves. Enforced by the state
    machine, not by convention."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DISABLED = "DISABLED"


class ExecutionType(str, Enum):
    """MVP intentionally supports only declarative execution types.

    There is NO `python` here. Arbitrary PoC Python is parsed statically and
    transpiled into an HTTP TestSpec; it is never executed. An arbitrary-code
    runner is a Phase-3 concern gated behind real isolation.
    """

    HTTP = "http"
    POSTMAN = "postman"


class TestSource(str, Enum):
    AI = "ai"
    RULE_ENGINE = "rule_engine"
    POC = "poc"  # transpiled from an existing PoC
    MANUAL = "manual"


class Environment(str, Enum):
    STAGING = "STAGING"
    QA = "QA"
    DEV = "DEV"
    PRODUCTION = "PRODUCTION"  # allowed to exist, but blocked by default policy
