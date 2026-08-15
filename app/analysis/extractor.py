"""Deterministic ticket analyzer.

Extracts endpoints, object identifiers, auth/URL signals and PoC references
from a normalized Jira issue, then runs the OWASP rule engine to map applicable
categories. This is the offline, no-API-key path — always available, fully
tested. The Claude-backed analyzer (app/analysis/claude_analyzer.py) implements
the same `analyze()` shape and can replace or augment it.
"""

from __future__ import annotations

import re

from app.mcp.jira import NormalizedIssue
from app.owasp.rules import RequirementSignals, evaluate
from app.schemas.analysis import Endpoint, IssueAnalysis, OwaspMapping
from app.schemas.enums import Applicability

_ENDPOINT_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_{}/.\-]*)", re.IGNORECASE
)
_PATH_ID_RE = re.compile(r"\{([A-Za-z0-9_]*id)\}", re.IGNORECASE)
_URL_FIELD_WORDS = ("url", "callback", "webhook", "redirect", "imageurl", "externalurl")
_POC_RE = re.compile(
    r"(poc[\w\-. ]*\.py|python\s+[\w\-./]+\.py|curl\s+|postman|\.postman_collection)",
    re.IGNORECASE,
)
_ACTOR_RE = re.compile(r"\b(admin|manager|agent|customer|user|guest|anonymous)\b", re.IGNORECASE)
_WRITE_METHODS = {"POST", "PUT", "PATCH"}


class HeuristicAnalyzer:
    def analyze(self, issue: NormalizedIssue) -> IssueAnalysis:
        text = "\n".join(
            [issue.summary, issue.description, *issue.acceptance_criteria, *issue.comments]
        )
        endpoints = self._extract_endpoints(text)
        signals = self._build_signals(text, endpoints)
        mappings = self._map_owasp(signals)
        pocs = sorted({m.group(0).strip() for m in _POC_RE.finditer(text)})
        actors = sorted({m.group(1).lower() for m in _ACTOR_RE.finditer(text)})

        return IssueAnalysis(
            issue_key=issue.issue_key,
            business_summary=issue.summary,
            actors=actors,
            sensitive_operation=self._is_sensitive(text, endpoints),
            business_impact=self._impact(text, endpoints),
            endpoints=endpoints,
            owasp_mappings=mappings,
            detected_pocs=pocs,
        )

    # -- extraction ---------------------------------------------------------

    def _extract_endpoints(self, text: str) -> list[Endpoint]:
        seen: dict[str, Endpoint] = {}
        for m in _ENDPOINT_RE.finditer(text):
            method = m.group(1).upper()
            # Tickets end sentences with a path ("...through PATCH /reports/{id}.").
            # The dot/paren belongs to the prose, not the route — without this the
            # same endpoint shows up twice, once with punctuation glued on.
            path = m.group(2).rstrip(".,;:)")
            if not path or path == "/":
                continue
            sig = f"{method} {path}"
            if sig in seen:
                continue
            id_params = [g.group(1) for g in _PATH_ID_RE.finditer(path)]
            url_fields = [w for w in _URL_FIELD_WORDS if w in text.lower()]
            seen[sig] = Endpoint(
                method=method,
                path=path,
                auth_required=True,
                object_id_params=id_params,
                writes_properties=method in _WRITE_METHODS,
                url_fields=url_fields if method in _WRITE_METHODS or url_fields else [],
            )
        return list(seen.values())

    def _build_signals(self, text: str, endpoints: list[Endpoint]) -> RequirementSignals:
        ids: list[str] = []
        url_fields: list[str] = []
        writes = False
        for ep in endpoints:
            ids.extend(ep.object_id_params)
            url_fields.extend(ep.url_fields)
            writes = writes or ep.writes_properties
        low = text.lower()
        return RequirementSignals(
            text=text,
            object_identifiers=sorted(set(ids)),
            has_authentication=any(
                k in low for k in ("token", "jwt", "bearer", "login", "auth", "session")
            ),
            roles=sorted({m.group(1).lower() for m in _ACTOR_RE.finditer(text)
                          if m.group(1).lower() in {"admin", "manager", "agent"}}),
            external_url_fields=sorted(set(url_fields)),
            writes_object_properties=writes,
            bulk_or_expensive=any(
                k in low for k in ("bulk", "export", "upload", "pagination", "search", "filter")
            ),
        )

    def _map_owasp(self, signals: RequirementSignals) -> list[OwaspMapping]:
        hits = evaluate(signals)
        mappings: list[OwaspMapping] = []
        for hit in hits:
            mappings.append(
                OwaspMapping(
                    category=hit.category,
                    applicability=hit.applicability,
                    reason=hit.reason,
                    matched_signals=hit.matched_signals,
                    existing_coverage="MISSING",  # refined later by coverage engine
                    coverage_pct=0,
                )
            )
        return mappings

    def _is_sensitive(self, text: str, endpoints: list[Endpoint]) -> bool:
        low = text.lower()
        if any(ep.method in {"DELETE", "PUT", "PATCH"} for ep in endpoints):
            return True
        return any(k in low for k in ("delete", "payment", "transfer", "password", "pii", "personal"))

    def _impact(self, text: str, endpoints: list[Endpoint]) -> str:
        if any(ep.method == "DELETE" for ep in endpoints):
            return "Destructive operation on business data."
        if any(ep.object_id_params for ep in endpoints):
            return "Access to identifiable business objects / customer data."
        return "Standard business operation."
