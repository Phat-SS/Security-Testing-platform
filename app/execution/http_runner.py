"""Trusted HTTP runner.

This is code we wrote and review — the only thing allowed to send packets. It
executes a declarative TestCase. It never runs code from a PoC; a PoC has
already been reduced to this data shape upstream.

Every outbound request goes through the same gauntlet:
  approval → scope validation (DNS-aware) → IP pin → send (no auto-redirect,
  timeout, size cap) → redact → capture → verdict → seal evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from app.core.config import Settings
from app.core.redaction import redact_headers, redact_text
from app.core.scope import ScopeValidator, ScopeViolation
from app.execution.evidence import seal
from app.execution.mutations import MutationError, apply_mutation
from app.execution.templating import extract_json_path, resolve, resolve_deep
from app.execution.verdict import evaluate as evaluate_verdict
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    Execution,
    Verdict,
)
from app.schemas.testcase import RequestSpec, TestCase
from app.vault.personas import Persona, PersonaVault


class ApprovalRequired(Exception):
    """Execution attempted on a test that a human has not approved."""


class HttpRunner:
    def __init__(
        self,
        base_url: str,
        scope: ScopeValidator,
        vault: PersonaVault,
        settings: Settings,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._scope = scope
        self._vault = vault
        self._settings = settings
        # Injectable client so tests can drive an in-memory ASGI app.
        self._client = client or httpx.Client(
            follow_redirects=False,  # each redirect hop must be re-validated
            timeout=settings.limits.timeout_s,
            headers={"User-Agent": settings.limits.user_agent},
        )

    # -- public API ---------------------------------------------------------

    def run(self, test: TestCase, execution_id: str, prev_hash: str | None = None) -> Execution:
        if not test.is_runnable():
            raise ApprovalRequired(
                f"Test {test.test_id} is {test.approval_status.value}; execution "
                "is prohibited until it is APPROVED."
            )

        log: list[str] = []
        context: dict = {}

        attacker = self._vault.get(test.auth_context.persona)
        target = (
            self._vault.get(test.auth_context.target_persona)
            if test.auth_context.target_persona
            else None
        )
        # Seed context with the target's owned ids so BOLA cases have a victim.
        if target:
            context.update(target.owns)

        # 1. setup steps (seed disposable data, capture victim object ids).
        try:
            for i, step in enumerate(test.setup):
                self._run_setup(step, context, log, f"{test.test_id}.setup[{i}]")
        except ScopeViolation as exc:
            return self._blocked(test, execution_id, prev_hash, str(exc), log)

        # 2. build the attack request by applying the mutation.
        target_markers = list(target.secret_markers) if target else []
        try:
            prepared = apply_mutation(
                test.request, test.attack_mutation, attacker, target, self._vault, context
            )
        except MutationError as exc:
            return self._errored(test, execution_id, prev_hash, f"Mutation error: {exc}", log)
        log.append(f"attack mutation: {prepared.note}")

        # 3. resolve templates against the accumulated context.
        path = resolve(prepared.path, context)
        query = {k: resolve(str(v), context) for k, v in prepared.query.items()}
        headers = {k: resolve(str(v), context) for k, v in prepared.headers.items()}
        body = resolve_deep(prepared.body, context)

        url = self._absolute_url(path)

        # 4. scope validation — the hard gate. Off-scope → BLOCKED, never sent.
        result = self._scope.validate_url(url)
        if not result.allowed:
            log.append(f"SCOPE BLOCK: {result.reason}")
            return self._blocked(test, execution_id, prev_hash, result.reason, log)
        log.append(f"scope ok: {result.host} -> {result.resolved_ip} (pinned)")

        # 5. send + capture.
        captured_req, captured_resp = self._send(
            prepared.method, url, headers, query, body, result.resolved_ip
        )

        if captured_resp is None:
            verdict = Verdict(
                result=TestStatus.ERROR,
                confidence=Confidence.HIGH,
                expected_summary=str(test.expected.status_in),
                actual_summary="transport error / timeout",
                reason="The request could not be completed by the runner.",
            )
            ex = Execution(
                execution_id=execution_id,
                test_id=test.test_id,
                owasp_category=test.owasp_category.value,
                scope_validated=True,
                request=captured_req,
                response=None,
                verdict=verdict,
                log=log,
            )
            return seal(ex, prev_hash)

        # 6. correlation: did the attacker's response disclose a protected
        #    marker belonging to the victim? This is the anti-false-positive
        #    signal the verdict relies on.
        leaked = self._leaked_markers(captured_resp.body, target_markers, test.expected.body_must_not_contain, context)
        if leaked:
            log.append(f"DISCLOSURE: response contained protected marker(s): {leaked}")

        verdict = evaluate_verdict(test, captured_resp, leaked)
        log.append(f"verdict: {verdict.result.value} ({verdict.confidence.value})")

        ex = Execution(
            execution_id=execution_id,
            test_id=test.test_id,
            owasp_category=test.owasp_category.value,
            scope_validated=True,
            request=captured_req,
            response=captured_resp,
            verdict=verdict,
            log=log,
        )
        return seal(ex, prev_hash)

    # -- internals ----------------------------------------------------------

    def _run_setup(self, step, context: dict, log: list[str], tag: str) -> None:
        persona = self._vault.get(step.as_persona)
        spec: RequestSpec = step.request
        path = resolve(spec.path, context)
        url = self._absolute_url(path)

        result = self._scope.validate_url(url)
        result.raise_if_blocked()  # setup is subject to the same scope gate

        headers = {**persona.auth_headers, **{k: resolve(str(v), context) for k, v in spec.headers.items()}}
        query = {k: resolve(str(v), context) for k, v in spec.query.items()}
        body = resolve_deep(spec.body, context)

        _, resp = self._send(spec.method, url, headers, query, body, result.resolved_ip)
        if resp is None:
            raise ScopeViolation(f"{tag}: setup request failed to complete")

        # capture values for later steps
        parsed = _try_json(resp.body)
        for name, jpath in spec.capture.items():
            value = extract_json_path(parsed, jpath) if parsed is not None else None
            context[name] = value
            log.append(f"{tag}: captured {name}={value!r} as {step.as_persona}")

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        query: dict[str, str],
        body: object | None,
        pinned_ip: str | None,
    ) -> tuple[CapturedRequest, CapturedResponse | None]:
        """Send one request. Redacts everything captured. Never follows
        redirects automatically; a 3xx is returned as-is for the caller to
        re-validate if it chooses to follow."""

        req_body_text = _body_to_text(body)
        timestamp = datetime.now(timezone.utc).isoformat()

        captured_req = CapturedRequest(
            method=method,
            url=url,
            resolved_ip=pinned_ip or "",
            headers=redact_headers(headers),
            body=redact_text(req_body_text),
            timestamp=timestamp,
        )

        try:
            request = self._client.build_request(
                method, url, params=query, headers=headers,
                content=req_body_text.encode("utf-8") if req_body_text is not None else None,
            )
            response = self._client.send(request)
        except httpx.HTTPError:
            return captured_req, None

        raw = response.content[: self._settings.limits.max_response_bytes]
        text = raw.decode(response.encoding or "utf-8", errors="replace")

        captured_resp = CapturedResponse(
            status_code=response.status_code,
            headers=redact_headers(dict(response.headers)),
            body=redact_text(text) or "",
            elapsed_ms=int(response.elapsed.total_seconds() * 1000),
            size_bytes=len(response.content),
        )
        return captured_req, captured_resp

    def _leaked_markers(
        self,
        body: str,
        target_markers: list[str],
        must_not_contain: list[str],
        context: dict,
    ) -> list[str]:
        # NB: body is already redacted for OUR secrets. Victim markers are the
        # victim's data (e.g. their email), not our credentials, so they still
        # appear and can be detected here.
        candidates = list(target_markers)
        for marker in must_not_contain:
            resolved = resolve(marker, context)
            if resolved:
                candidates.append(resolved)
        return [m for m in candidates if m and m in body]

    def _absolute_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            # A test must not carry its own host; the host comes from approved
            # scope. Reject absolute paths defensively.
            raise ScopeViolation(
                "Test request path must be relative; absolute URLs bypass scope."
            )
        return f"{self._base_url}/{path.lstrip('/')}"

    def _blocked(self, test, execution_id, prev_hash, reason, log) -> Execution:
        verdict = Verdict(
            result=TestStatus.BLOCKED,
            confidence=Confidence.HIGH,
            expected_summary=str(test.expected.status_in),
            actual_summary="request not sent",
            reason=f"Blocked before sending: {reason}",
        )
        ex = Execution(
            execution_id=execution_id,
            test_id=test.test_id,
            owasp_category=test.owasp_category.value,
            scope_validated=False,
            request=CapturedRequest(
                method=test.request.method, url="(blocked)", resolved_ip="",
                headers={}, body=None, timestamp=datetime.now(timezone.utc).isoformat(),
            ),
            response=None,
            verdict=verdict,
            log=log,
        )
        return seal(ex, prev_hash)

    def _errored(self, test, execution_id, prev_hash, reason, log) -> Execution:
        verdict = Verdict(
            result=TestStatus.ERROR, confidence=Confidence.HIGH,
            expected_summary=str(test.expected.status_in),
            actual_summary="runner error", reason=reason,
        )
        ex = Execution(
            execution_id=execution_id, test_id=test.test_id,
            owasp_category=test.owasp_category.value, scope_validated=False,
            request=CapturedRequest(
                method=test.request.method, url="(error)", resolved_ip="",
                headers={}, body=None, timestamp=datetime.now(timezone.utc).isoformat(),
            ),
            response=None, verdict=verdict, log=log,
        )
        return seal(ex, prev_hash)


def _body_to_text(body: object | None) -> str | None:
    if body is None:
        return None
    if isinstance(body, str):
        return body
    return json.dumps(body)


def _try_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
