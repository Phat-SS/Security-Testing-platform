"""Trusted HTTP runner.

This is code we wrote and review — the only thing allowed to send packets. It
executes a declarative TestCase. It never runs code from a PoC; a PoC has
already been reduced to this data shape upstream.

Every outbound request goes through the same gauntlet:
  approval → scope validation (DNS-aware) → IP pin → send (no auto-redirect,
  timeout, size cap) → redact → capture → verdict → seal evidence.

An execution is up to three exchanges, not one:
  * baseline     — the positive control, proving the target is reachable by an
                   identity entitled to it (so a rejection means the control
                   worked, not that nothing was there)
  * attack       — the mutated request, optionally repeated or fired concurrently
  * verification — the read-back proving the attack's effect persisted

All three pass the same scope gate and are sealed into the same evidence record.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import socket as _socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

import httpx

from app.core.config import Settings
from app.core.redaction import redact_headers, redact_text, redact_url
from app.core.scope import ScopeValidator, ScopeViolation
from app.execution.correlation import correlate_bodies
from app.execution.evidence import seal
from app.execution.mutations import MutationError, PreparedRequest, apply_mutation
from app.execution.oast import OastVerifier
from app.execution.templating import extract_json_path, resolve, resolve_deep
from app.execution.verdict import evaluate as evaluate_verdict
from app.schemas.enums import Confidence, TestStatus
from app.schemas.execution import (
    CapturedRequest,
    CapturedResponse,
    CorrelationProof,
    Execution,
    OastProof,
    RepeatStats,
    SupportingExchange,
    Verdict,
)
from app.schemas.testcase import BaselineSpec, RequestSpec, TestCase, VerificationStep
from app.vault.personas import PersonaVault


class ApprovalRequired(Exception):
    """Execution attempted on a test that a human has not approved."""


# Guards the process-global getaddrinfo patch below. See _pin_dns.
_PIN_LOCK = threading.RLock()


@contextlib.contextmanager
def _pin_dns(host: str | None, ip: str | None):
    """Force DNS resolution of `host` to the exact `ip` ScopeValidator just
    checked, for the duration of the wrapped connection.

    Without this, scope validation and the actual TCP connect are two
    independent DNS lookups: an attacker who controls DNS for an approved
    host (short TTL, split-horizon) can answer with a public IP during
    validation and a private/metadata IP a moment later (DNS rebinding /
    TOCTOU). Pinning collapses that window to zero by reusing the exact
    address already validated, instead of letting httpx/the OS re-resolve.

    This patches `socket.getaddrinfo` process-wide, so it is serialised behind
    `_PIN_LOCK`. Two runners pinning *different* hosts concurrently would
    otherwise install competing patches and could send a request to an address
    that was validated for a different host — a scope bypass produced by our
    own safety mechanism. The lock makes that impossible rather than merely
    unlikely: the previous version relied on the runner being sequential, which
    was true by convention and stopped being true the moment concurrent
    (race-condition) probes were added.

    Requests issued in parallel *inside* one pinned block are safe and
    intended: they all target the same host and the same validated IP.
    """
    if not host or not ip:
        yield
        return
    with _PIN_LOCK:
        real_getaddrinfo = _socket.getaddrinfo

        def _pinned(node, *args, **kwargs):
            if node == host:
                node = ip
            return real_getaddrinfo(node, *args, **kwargs)

        _socket.getaddrinfo = _pinned
        try:
            yield
        finally:
            _socket.getaddrinfo = real_getaddrinfo


# A candidate shorter than this proves nothing either way: short numeric ids,
# area codes, or short words are routinely present as a coincidental substring
# of unrelated boilerplate (an RFC problem+json body, a trace id, a version
# string) that every caller — attacker and rightful owner alike — receives.
# Mirrors the same floor `adjudicator._MIN_CORRELATION_BODY` applies to the
# sibling byte-identical-body correlation check.
_MIN_MARKER_LEN = 6


class HttpRunner:
    def __init__(
        self,
        base_url: str,
        scope: ScopeValidator,
        vault: PersonaVault,
        settings: Settings,
        client: httpx.Client | None = None,
        oast: OastVerifier | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._scope = scope
        self._vault = vault
        self._settings = settings
        self._oast = oast
        # Injectable client so tests can drive an in-memory ASGI app.
        self._client = client or httpx.Client(
            follow_redirects=False,  # a 3xx is captured and evaluated as-is — see _send
            timeout=settings.limits.timeout_s,
            headers={"User-Agent": settings.limits.user_agent},
        )

    # -- public API ---------------------------------------------------------

    def run_safe(self, test: TestCase, execution_id: str, prev_hash: str | None = None) -> Execution:
        """Like run(), but never lets an unexpected exception (e.g. a persona
        referenced by the test missing from the vault) escape and abort a
        whole batch. Expected failure modes are already turned into a
        BLOCKED/ERROR verdict inside run() itself; this is the backstop for
        everything else, so one bad test can't discard every execution
        already computed earlier in the same run. ApprovalRequired is a
        caller bug (the batch should have been pre-filtered), not a per-test
        runtime issue, so it still propagates."""
        try:
            return self.run(test, execution_id, prev_hash)
        except ApprovalRequired:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberate backstop, see docstring
            return self._errored(
                test, execution_id, prev_hash,
                f"Unexpected error: {type(exc).__name__}: {exc}", [],
            )

    def run(self, test: TestCase, execution_id: str, prev_hash: str | None = None) -> Execution:
        if not test.is_runnable():
            raise ApprovalRequired(
                f"Test {test.test_id} is {test.approval_status.value}; execution "
                "is prohibited until it is APPROVED."
            )

        log: list[str] = []
        oast_token = ""
        oast_callback = ""
        if test.oast is not None:
            if self._oast is None:
                log.append("OAST: verifier is not configured; callback proof is unavailable")
            else:
                oast_token, oast_callback = self._oast.issue()
                runtime = test.model_copy(deep=True)
                runtime.attack_mutation.detail["value"] = oast_callback
                test = runtime
                log.append("OAST: issued a unique callback token for this execution")
        context: dict = {}
        supporting: list[SupportingExchange] = []

        attacker = self._vault.get(test.auth_context.persona)
        target = (
            self._vault.get(test.auth_context.target_persona)
            if test.auth_context.target_persona
            else None
        )
        # Seed the template context with object ids.
        #
        # The attacker's own ids go under an `own_` prefix and NEVER into the
        # bare namespace when a victim exists. Merging both would mean a BOLA
        # probe for `order_id` — owned by the attacker but not the victim —
        # silently resolves to the attacker's *own* order. The test then
        # attacks itself, passes, and reports that authorization is enforced.
        #
        # With no victim (mass assignment on one's own object, resource and
        # misconfiguration probes) the attacker's ids are what the path is
        # about, so they take the bare namespace.
        for key, value in attacker.owns.items():
            context[f"own_{key}"] = value
        context.update(target.owns if target else attacker.owns)

        # 1. setup steps (seed disposable data, capture victim object ids).
        try:
            for i, step in enumerate(test.setup):
                self._run_setup(step, context, log, f"{test.test_id}.setup[{i}]")
        except ScopeViolation as exc:
            return self._blocked(test, execution_id, prev_hash, str(exc), log)

        # 2. build the attack request by applying the mutation.
        #    Done BEFORE the baseline because a BOLA-family mutation is what
        #    resolves *which* object is under test; the positive control has to
        #    aim at that same object to mean anything.
        target_markers = list(target.secret_markers) if target else []
        try:
            prepared = apply_mutation(
                test.request, test.attack_mutation, attacker, target, self._vault, context
            )
        except MutationError as exc:
            return self._errored(test, execution_id, prev_hash, f"Mutation error: {exc}", log)
        log.append(f"attack mutation: {prepared.note}")

        # 3. positive control — can an entitled identity do this at all?
        baseline_ok: bool | None = None
        baseline_summary = ""
        baseline_raw_body = ""
        if test.baseline is not None:
            exchange, baseline_ok, baseline_summary, baseline_raw_body = self._run_baseline(
                test.baseline, test, context, log
            )
            if exchange is not None:
                supporting.append(exchange)

        # 4. resolve templates against the accumulated context.
        path = resolve(prepared.path, context)
        query = _resolve_query(prepared.query, context)
        headers = {k: resolve(str(v), context) for k, v in prepared.headers.items()}
        body = resolve_deep(prepared.body, context)

        try:
            url = self._absolute_url(path)
        except ScopeViolation as exc:
            log.append(f"SCOPE BLOCK: {exc}")
            return self._blocked(test, execution_id, prev_hash, str(exc), log)

        # 5. scope validation — the hard gate. Off-scope → BLOCKED, never sent.
        result = self._scope.validate_url(url)
        if not result.allowed:
            log.append(f"SCOPE BLOCK: {result.reason}")
            return self._blocked(test, execution_id, prev_hash, result.reason, log)
        log.append(f"scope ok: {result.host} -> {result.resolved_ip} (pinned)")

        # 6. send + capture (possibly N times, possibly concurrently).
        captured_req, captured_resp, raw_resp_text, repeat_stats = self._send_attack(
            prepared, url, headers, query, body, result.resolved_ip, log
        )
        if oast_token:
            # The callback token is a bearer-like correlation secret. Keep it
            # in memory only long enough to poll the provider; persisted
            # evidence carries a hash and redacted request value instead.
            captured_req = _redact_oast_token(captured_req, oast_token)
            if captured_resp is not None:
                captured_resp = captured_resp.model_copy(update={
                    "body": captured_resp.body.replace(
                        oast_token, "<oast-token-redacted>"
                    )
                })
            prepared.note = prepared.note.replace(oast_token, "<oast-token-redacted>")
            log[:] = [entry.replace(oast_token, "<oast-token-redacted>") for entry in log]

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
                attack_note=prepared.note,
                supporting=supporting,
                repeat=repeat_stats,
                log=log,
            )
            return seal(ex, prev_hash)

        # 7. correlation: did the attacker's response disclose a protected
        #    marker belonging to the victim? This is the anti-false-positive
        #    signal the verdict relies on. MUST run against the raw,
        #    pre-redaction text: a leaked marker is often itself a
        #    session/token/password-shaped string, which redact_text would
        #    mask to "********" before a substring check ever saw it.
        #
        #    The baseline's own body is only usable as an exclusion set when
        #    the baseline FAILED (`baseline_ok is False`): that response is a
        #    rejection/error for the entitled owner, so it should carry no
        #    real object data at all — a marker "found" there is boilerplate.
        #    When the baseline SUCCEEDED, its body legitimately contains the
        #    victim's own data (that is the point of the positive control),
        #    so the same marker appearing there is the expected shape of a
        #    real leak, not evidence against one, and must not be excluded.
        leaked = self._leaked_markers(
            raw_resp_text or "", target_markers, test.expected.body_must_not_contain, context,
            exclude_bodies=[baseline_raw_body] if baseline_ok is False and baseline_raw_body else None,
        )
        correlation = None
        # If the operator configured a fingerprint key, learn distinctive
        # values from the owner's successful response and correlate them with
        # the attack response without storing any raw value. Restricted to a
        # cross-identity test: the same user's generic response is not BOLA.
        if not leaked and target is not None and baseline_ok is True and baseline_raw_body:
            measured = correlate_bodies(baseline_raw_body, raw_resp_text or "")
            if measured is not None:
                correlation = CorrelationProof(
                    key_id=measured.key_id,
                    shared_fingerprints=list(measured.shared_fingerprints),
                    owner_value_count=measured.owner_value_count,
                    owner_coverage=measured.coverage,
                )
                if measured.decisive:
                    # evaluate_verdict only uses the count and never persists
                    # these values. HMAC digests are safe correlation tokens,
                    # not the owner's identifiers themselves.
                    leaked = list(measured.shared_fingerprints)
                    log.append(
                        "DISCLOSURE: HMAC correlation matched "
                        f"{len(leaked)}/{measured.owner_value_count} distinctive owner value(s)"
                    )
        if leaked:
            # Never put the raw marker value in the log: `log` is stored,
            # exported (export.json), and hashed into evidence just like
            # request/response — but unlike those, it has no redact_*() pass
            # of its own. A leaked marker is frequently itself a session
            # token/API key, so only the count goes in the narrative; the
            # actual value is visible in the response body evidence, which
            # IS redacted, exactly where a reader should look for it.
            log.append(f"DISCLOSURE: response body contained {len(leaked)} protected "
                       "marker(s) belonging to another identity")

        # 8. verification read-back — did the attack's effect persist?
        verification_proof: list[str] = []
        if test.verification is not None:
            exchange, verification_proof = self._run_verification(
                test.verification, context, log
            )
            if exchange is not None:
                supporting.append(exchange)

        oast_proof = None
        if oast_token and self._oast is not None:
            try:
                observed = self._oast.observed(oast_token)
            except Exception as exc:  # noqa: BLE001 - collaborator outage is inconclusive
                observed = False
                log.append(f"OAST: poll failed ({type(exc).__name__})")
            oast_proof = OastProof(
                token_hash=hashlib.sha256(oast_token.encode("utf-8")).hexdigest(),
                callback_host=urlparse(oast_callback).hostname or "",
                observed=observed,
                purpose=test.oast.purpose,
            )
            if observed:
                verification_proof.append("out-of-band callback observed for this execution")
                log.append("OAST: target callback observed — server-side interaction confirmed")
            else:
                log.append("OAST: no callback observed")

        verdict = evaluate_verdict(
            test, captured_resp, leaked,
            baseline_ok=baseline_ok,
            baseline_summary=baseline_summary,
            verification_proof=verification_proof,
            repeat=repeat_stats,
        )
        log.append(f"verdict: {verdict.result.value} ({verdict.confidence.value})")

        ex = Execution(
            execution_id=execution_id,
            test_id=test.test_id,
            owasp_category=test.owasp_category.value,
            scope_validated=True,
            request=captured_req,
            response=captured_resp,
            verdict=verdict,
            attack_note=prepared.note,
            supporting=supporting,
            repeat=repeat_stats,
            correlation=correlation,
            oast=oast_proof,
            log=log,
        )
        return seal(ex, prev_hash)

    # -- supporting exchanges ------------------------------------------------

    def _run_baseline(
        self, spec: BaselineSpec, test: TestCase, context: dict, log: list[str]
    ) -> tuple[SupportingExchange | None, bool | None, str, str]:
        """Run the positive control. Returns (evidence, ok, summary, raw_body).

        `ok` is None when the control could not be established at all (scope
        block, transport failure, unknown persona). That is deliberately
        distinct from False: "we could not check" must not read as "the target
        was unreachable", and neither may be silently upgraded to a PASS.

        `raw_body` is the pre-redaction text of the baseline's own response —
        the same identity/function the attack targets, minus the attack. The
        caller uses it to rule out marker matches that are really just
        boilerplate every caller gets (see `_leaked_markers`): the stored
        `SupportingExchange.response.body` is already redacted and cannot be
        used for that same-substring comparison.
        """
        tag = f"{test.test_id}.baseline"
        try:
            persona = self._vault.get(spec.as_persona)
        except KeyError as exc:
            log.append(f"{tag}: SKIPPED — {exc}")
            return None, None, "baseline persona missing from vault", ""

        # Default to the test's own (unmutated) request: same object, same
        # function — just performed by the identity entitled to it.
        base_request = spec.request or test.request
        path = resolve(base_request.path, context)
        try:
            url = self._absolute_url(path)
        except ScopeViolation as exc:
            log.append(f"{tag}: SKIPPED — {exc}")
            return None, None, "baseline path rejected by scope", ""

        result = self._scope.validate_url(url)
        if not result.allowed:
            log.append(f"{tag}: SKIPPED — scope: {result.reason}")
            return None, None, "baseline blocked by scope", ""

        headers = {
            **persona.auth_headers,
            **{k: resolve(str(v), context) for k, v in base_request.headers.items()},
        }
        query = _resolve_query(base_request.query, context)
        body = resolve_deep(base_request.body, context)

        captured_req, captured_resp, raw_text = self._send(
            base_request.method, url, headers, query, body, result.resolved_ip
        )
        if captured_resp is None:
            log.append(f"{tag}: SKIPPED — the control request did not complete")
            return (
                SupportingExchange(
                    kind="baseline", as_persona=spec.as_persona,
                    request=captured_req, response=None,
                    note="positive control did not complete",
                ),
                None,
                "baseline request did not complete",
                "",
            )

        ok = captured_resp.status_code in spec.success_status_in
        summary = (
            f"{spec.as_persona} {base_request.method} {path} -> HTTP {captured_resp.status_code}"
        )
        log.append(
            f"{tag}: {'OK' if ok else 'FAILED'} — {summary} "
            f"(expected one of {spec.success_status_in})"
        )
        return (
            SupportingExchange(
                kind="baseline", as_persona=spec.as_persona,
                request=captured_req, response=captured_resp,
                note=("positive control succeeded: the target is reachable by an entitled "
                      "identity, so a rejected attack reflects authorization"
                      if ok else
                      "positive control FAILED: the entitled identity could not perform this "
                      "operation either, so the attack never exercised the control"),
            ),
            ok,
            summary,
            raw_text or "",
        )

    def _run_verification(
        self, step: VerificationStep, context: dict, log: list[str]
    ) -> tuple[SupportingExchange | None, list[str]]:
        """Re-read state after the attack and look for the attacker's value."""
        tag = "verification"
        try:
            persona = self._vault.get(step.as_persona)
        except KeyError as exc:
            log.append(f"{tag}: SKIPPED — {exc}")
            return None, []

        path = resolve(step.request.path, context)
        try:
            url = self._absolute_url(path)
        except ScopeViolation as exc:
            log.append(f"{tag}: SKIPPED — {exc}")
            return None, []

        result = self._scope.validate_url(url)
        if not result.allowed:
            log.append(f"{tag}: SKIPPED — scope: {result.reason}")
            return None, []

        headers = {
            **persona.auth_headers,
            **{k: resolve(str(v), context) for k, v in step.request.headers.items()},
        }
        query = _resolve_query(step.request.query, context)
        body = resolve_deep(step.request.body, context)

        captured_req, captured_resp, raw_text = self._send(
            step.request.method, url, headers, query, body, result.resolved_ip
        )
        if captured_resp is None:
            log.append(f"{tag}: SKIPPED — the read-back request did not complete")
            return (
                SupportingExchange(
                    kind="verification", as_persona=step.as_persona,
                    request=captured_req, response=None,
                    note="read-back did not complete",
                ),
                [],
            )

        # Against the RAW text for the same reason leak detection is: a
        # persisted value may itself be secret-shaped and would be masked.
        proof = [
            resolved
            for marker in step.proves_exploit_if_contains
            if (resolved := resolve(marker, context)) and resolved in (raw_text or "")
        ]
        parsed = _try_json(raw_text)
        for assertion in step.proves_exploit_when:
            actual = extract_json_path(parsed, assertion.json_path) if parsed is not None else None
            expected = assertion.expected
            if isinstance(expected, str):
                expected = resolve(expected, context)
                try:
                    expected = json.loads(expected)
                except (TypeError, json.JSONDecodeError):
                    pass
            if _invariant_matches(actual, assertion.operator, expected):
                proof.append(assertion.description or f"invariant {assertion.json_path} matched")
        log.append(
            f"{tag}: {step.as_persona} {step.request.method} {path} -> "
            f"HTTP {captured_resp.status_code}; "
            + (f"{len(proof)} injected value(s) found — attack effect PERSISTED"
               if proof else "injected value(s) not present — attack did not persist")
        )
        return (
            SupportingExchange(
                kind="verification", as_persona=step.as_persona,
                request=captured_req, response=captured_resp,
                note=("read-back confirmed the attacker-supplied value is stored server-side"
                      if proof else "read-back found no attacker-supplied value stored"),
            ),
            proof,
        )

    # -- internals ----------------------------------------------------------

    def _run_setup(self, step, context: dict, log: list[str], tag: str) -> None:
        persona = self._vault.get(step.as_persona)
        spec: RequestSpec = step.request
        path = resolve(spec.path, context)
        url = self._absolute_url(path)

        result = self._scope.validate_url(url)
        result.raise_if_blocked()  # setup is subject to the same scope gate

        headers = {**persona.auth_headers, **{k: resolve(str(v), context) for k, v in spec.headers.items()}}
        query = _resolve_query(spec.query, context)
        body = resolve_deep(spec.body, context)

        _, resp, raw_text = self._send(spec.method, url, headers, query, body, result.resolved_ip)
        if resp is None:
            raise ScopeViolation(f"{tag}: setup request failed to complete")

        # capture values for later steps — from the RAW response text, not
        # the redacted `resp.body`: a captured field (e.g. a victim's token
        # reused as an Authorization header downstream) would otherwise
        # silently become the literal string "********".
        parsed = _try_json(raw_text)
        for name, jpath in spec.capture.items():
            value = extract_json_path(parsed, jpath) if parsed is not None else None
            context[name] = value
            # Never log the raw captured value: `log` has no redact_*() pass
            # of its own (see the DISCLOSURE comment in run()), and a
            # captured field is commonly a victim's token/session id — the
            # exact thing that must never end up in evidence/exports in the
            # clear. Whether it resolved is still useful without the value.
            log.append(f"{tag}: captured {name} "
                       f"({'resolved' if value is not None else 'no match'}) as {step.as_persona}")

    def _send_attack(
        self,
        prepared: PreparedRequest,
        url: str,
        headers: dict[str, str],
        query: dict,
        body: object | None,
        pinned_ip: str | None,
        log: list[str],
    ) -> tuple[CapturedRequest, CapturedResponse | None, str | None, RepeatStats | None]:
        """Send the attack once, or N times for a multi-request probe.

        For repeated probes the FIRST exchange is the one captured as evidence
        and evaluated for disclosure; the rest are summarised into RepeatStats.
        Storing N full bodies would bloat the evidence record without adding
        information — what a rate-limit or race probe asserts is the *shape* of
        the outcome distribution, not the content of attempt #7.
        """
        if prepared.repeat <= 1:
            req, resp, raw = self._send(
                prepared.method, url, headers, query, body, pinned_ip, prepared.body_encoding
            )
            return req, resp, raw, None

        count = prepared.repeat
        results: list[tuple[CapturedRequest, CapturedResponse | None, str | None]] = []

        def _one(_i: int):
            # _already_pinned=True is load-bearing, not an optimisation: the
            # burst runs inside the _pin_dns block below, which holds
            # _PIN_LOCK. A worker thread re-entering _pin_dns would block on
            # that lock forever (RLock is reentrant per-thread, and these are
            # different threads) — deadlocking the whole probe.
            return self._send(
                prepared.method, url, headers, query, body, pinned_ip,
                prepared.body_encoding, _already_pinned=True,
            )

        # One pin block wraps the whole burst: every request targets the same
        # already-validated host/IP, so parallelism inside it is safe.
        host = urlparse(url).hostname
        with _pin_dns(host, pinned_ip):
            if prepared.concurrent:
                with ThreadPoolExecutor(max_workers=min(count, 16)) as pool:
                    results = list(pool.map(_one, range(count)))
            else:
                results = [_one(i) for i in range(count)]

        status_counts: dict[str, int] = {}
        succeeded = 0
        throttled = False
        for _, resp, _raw in results:
            key = str(resp.status_code) if resp else "transport_error"
            status_counts[key] = status_counts.get(key, 0) + 1
            if resp is None:
                continue
            if 200 <= resp.status_code < 300:
                succeeded += 1
            if resp.status_code in (429, 503):
                throttled = True

        stats = RepeatStats(
            sent=count, succeeded=succeeded, status_counts=status_counts,
            throttled=throttled, concurrent=prepared.concurrent,
        )
        log.append(
            f"multi-request probe: {count} request(s) "
            f"{'concurrently' if prepared.concurrent else 'in sequence'}; "
            f"{succeeded} succeeded; throttled={throttled}; spread {status_counts}"
        )
        first_req, first_resp, first_raw = results[0]
        return first_req, first_resp, first_raw, stats

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        query: dict,
        body: object | None,
        pinned_ip: str | None,
        body_encoding: str = "json",
        _already_pinned: bool = False,
    ) -> tuple[CapturedRequest, CapturedResponse | None, str | None]:
        """Send one request. The returned CapturedRequest/CapturedResponse are
        redacted for storage; the third element is the raw (pre-redaction,
        still size-capped) response text, for callers that need to see the
        response as it actually was (leak detection, setup-value capture) —
        never follows redirects automatically; a 3xx is returned as-is for
        the caller to re-validate if it chooses to follow."""

        headers = dict(headers)
        req_body_text = _body_to_text(body, body_encoding)
        if req_body_text is not None and not any(k.lower() == "content-type" for k in headers):
            # Without this an API that requires a declared content type answers
            # 415 to every body-carrying probe, and the verdict reads that
            # rejection as "the control held" — a false negative on every
            # BOPLA/mass-assignment test at once.
            headers["Content-Type"] = (
                "application/x-www-form-urlencoded"
                if body_encoding == "form"
                else "application/json"
            )
        timestamp = datetime.now(timezone.utc).isoformat()

        # build_request is local/synchronous (no network I/O, can't raise
        # httpx.HTTPError) and merges `query` into the final URL — building
        # it before `captured_req` means the STORED url reflects what is
        # actually sent, including query values a mutation injected
        # separately (e.g. ssrf_url, oversized_payload write into `query`,
        # not into `url`/`path`), not just whatever happened to already be
        # embedded in the `url` string.
        request = self._client.build_request(
            method, url, params=query, headers=headers,
            content=req_body_text.encode("utf-8") if req_body_text is not None else None,
        )
        captured_req = CapturedRequest(
            method=method,
            url=redact_url(str(request.url)),
            resolved_ip=pinned_ip or "",
            headers=redact_headers(headers),
            body=redact_text(req_body_text),
            timestamp=timestamp,
        )

        host = urlparse(url).hostname
        try:
            if _already_pinned:
                response = self._client.send(request)
            else:
                with _pin_dns(host, pinned_ip):
                    response = self._client.send(request)
        except httpx.HTTPError:
            return captured_req, None, None

        raw = response.content[: self._settings.limits.max_response_bytes]
        text = raw.decode(response.encoding or "utf-8", errors="replace")

        captured_resp = CapturedResponse(
            status_code=response.status_code,
            headers=redact_headers(dict(response.headers)),
            body=redact_text(text) or "",
            elapsed_ms=int(response.elapsed.total_seconds() * 1000),
            size_bytes=len(response.content),
        )
        return captured_req, captured_resp, text

    def _leaked_markers(
        self,
        body: str,
        target_markers: list[str],
        must_not_contain: list[str],
        context: dict,
        *,
        exclude_bodies: list[str] | None = None,
    ) -> list[str]:
        # NB: `body` is the RAW, pre-redaction response text (see `_send`).
        # A victim marker is often itself secret-shaped (a session token, an
        # API key) — checking against the redacted copy would mask it to
        # "********" before this substring check ever ran, hiding exactly
        # the disclosure this method exists to catch.
        #
        # Two independent guards against a false "leak", both needed:
        #  - a length floor (`_MIN_MARKER_LEN`): a short marker (a bare id, an
        #    area code) is routinely a coincidental substring of unrelated
        #    boilerplate (RFC problem+json bodies, trace ids, version
        #    strings) that has nothing to do with the victim.
        #  - `exclude_bodies`: raw text from OTHER exchanges captured for this
        #    same execution that are known to carry no victim data — chiefly
        #    the positive control's own response. If the "leaked" marker is
        #    also present there, the match says nothing about this response in
        #    particular; it is present in whatever every caller receives.
        exclude_bodies = [b for b in (exclude_bodies or []) if b]
        candidates = list(target_markers)
        for marker in must_not_contain:
            resolved = resolve(marker, context)
            if resolved:
                candidates.append(resolved)
        return [
            m for m in candidates
            if m
            and len(m) >= _MIN_MARKER_LEN
            and m in body
            and not any(m in other for other in exclude_bodies)
        ]

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


def _resolve_query(query: dict, context: dict) -> dict:
    """Resolve templates in query values, preserving list values.

    A list is how parameter pollution is expressed (`?id=own&id=victim`);
    stringifying it here would send the literal text "['1', '2']" and the probe
    would silently test nothing.
    """
    resolved: dict = {}
    for key, value in query.items():
        if isinstance(value, (list, tuple)):
            resolved[key] = [resolve(str(v), context) for v in value]
        else:
            resolved[key] = resolve(str(value), context)
    return resolved


def _invariant_matches(actual, operator: str, expected) -> bool:
    """Closed operator set; comparison failure is non-proof, never an exception."""
    try:
        if operator == "equals":
            return actual == expected
        if operator == "not_equals":
            return actual != expected
        if operator == "gt":
            return actual > expected
        if operator == "gte":
            return actual >= expected
        if operator == "lt":
            return actual < expected
        if operator == "lte":
            return actual <= expected
        if operator == "contains":
            return expected in actual
    except (TypeError, ValueError):
        return False
    return False


def _redact_oast_token(request: CapturedRequest, token: str) -> CapturedRequest:
    return request.model_copy(update={
        "url": request.url.replace(token, "<oast-token-redacted>"),
        "body": request.body.replace(token, "<oast-token-redacted>") if request.body else None,
    })


def _body_to_text(body: object | None, encoding: str = "json") -> str | None:
    if body is None:
        return None
    if isinstance(body, str):
        return body
    if encoding == "form" and isinstance(body, dict):
        # doseq so a list value becomes repeated keys rather than the repr of
        # a Python list — same reasoning as _resolve_query above.
        return urlencode(body, doseq=True)
    return json.dumps(body)


def _try_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
