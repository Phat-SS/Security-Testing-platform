"""AI-assisted API Security Testing Platform — MVP core.

Design invariant: the AI/rule-engine only *produce* declarative test cases; a
trusted, reviewed runner *executes* them. Untrusted PoC code is never run — it
is parsed statically and transpiled into a TestCase. Every outbound request is
scope-validated (DNS-aware, IP-pinned) and every stored value is secret-redacted.
"""

__version__ = "0.1.0"
