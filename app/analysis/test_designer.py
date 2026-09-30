"""Deterministic security test designer.

Turns an IssueAnalysis into concrete, declarative TestCases using the mutation
primitives the trusted runner understands. Every generated case arrives
`approval_status=PENDING` — nothing is runnable until a human approves.

This is the rule-engine-driven backbone. An AI designer can add nuance on top,
but this guarantees baseline coverage deterministically and is what the unit
tests pin down.

Two things every generated case carries where the category allows it, because
without them the verdict cannot reach a confident conclusion:

  * a **positive control** (`baseline`) — the same operation performed by an
    identity entitled to it. A BOLA probe that draws 404 because the object id
    is stale is indistinguishable from one that draws 404 because
    authorization worked, unless something proves the object was there.
  * a **verification read-back** (`verification`) — proof the attack's effect
    persisted. Mass assignment answered with HTTP 200 is a guess; the same
    field coming back on a subsequent read is evidence.

`depth` controls breadth. "standard" emits the highest-value probe per
applicable category; "aggressive" emits the full variant matrix (every id
placement, the whole JWT suite, race windows). Volume is not itself dangerous —
nothing runs without human approval — but an approval queue nobody reads is its
own failure mode, so the default stays reviewable.
"""

from __future__ import annotations

from app.schemas.analysis import Endpoint, IssueAnalysis
from app.schemas.enums import (
    ApprovalStatus,
    OwaspApiCategory,
    Severity,
    TestSource,
)
from app.schemas.testcase import (
    DESTRUCTIVE_METHODS,
    AuthContext,
    is_destructive_mutation,
    BaselineSpec,
    ExpectedResult,
    OastExpectation,
    Mutation,
    RequestSpec,
    TestCase,
    InvariantAssertion,
    VerificationStep,
)

STANDARD = "standard"
AGGRESSIVE = "aggressive"

# Path fragments that mark a flow as business-sensitive (API6) — the kind of
# operation whose value comes from being rate-limited, not just authorized.
_SENSITIVE_FLOW_WORDS = (
    "purchase", "order", "checkout", "payment", "transfer", "booking", "reserve",
    "signup", "register", "invite", "coupon", "redeem", "claim", "withdraw",
    "vote", "apply", "refund", "subscribe",
)

# A subset of the above where repeating the operation should be impossible, not
# merely throttled. These are the ones worth firing concurrently.
_ONE_SHOT_FLOW_WORDS = (
    "redeem", "claim", "withdraw", "transfer", "coupon", "refund", "vote", "apply",
)

_EXPENSIVE_WORDS = ("search", "export", "bulk", "list", "report", "download", "query")

# Stack-trace and debug fingerprints. Their presence in a response body is a
# correlated disclosure, so the existing leak-detection path turns them into a
# FAIL without needing any new verdict machinery.
_DEBUG_FINGERPRINTS = [
    "Traceback (most recent call last)",
    "at java.",
    "SQLSTATE",
    "Warning: mysqli",
    "System.NullReferenceException",
    "org.springframework",
    "DEBUG = True",
]

# Serialisation-tolerant spellings of an escalated role. JSON encoders differ on
# whitespace, so a single spelling would miss the very disclosure it looks for.
_ADMIN_MARKERS = [
    '"role": "admin"', '"role":"admin"',
    '"is_admin": true', '"is_admin":true',
    '"isAdmin": true', '"isAdmin":true',
]


class TestDesigner:
    def __init__(
        self,
        attacker: str = "agent_A",
        victim: str = "agent_B",
        admin: str = "admin",
        depth: str = STANDARD,
    ) -> None:
        # Two distinct identities are required for BOLA/BFLA. Callers pass the
        # persona names that exist in the vault.
        self._attacker = attacker
        self._victim = victim
        # Used only as the positive control for privileged functions. If the
        # engagement defines no such persona the runner records "control not
        # established" rather than failing — an absent baseline is honest.
        self._admin = admin
        self._depth = depth if depth in (STANDARD, AGGRESSIVE) else STANDARD

    @property
    def aggressive(self) -> bool:
        return self._depth == AGGRESSIVE

    def with_depth(self, depth: str) -> "TestDesigner":
        """A copy at a different breadth, keeping the configured persona names.

        Depth is a per-design-run choice (a quick pass now, the full matrix
        before sign-off), so callers need it without rebuilding the persona
        wiring — and without reaching into private attributes to do it.
        """
        return TestDesigner(self._attacker, self._victim, self._admin, depth)

    def design(self, analysis: IssueAnalysis) -> list[TestCase]:
        tests: list[TestCase] = []
        counters: dict[OwaspApiCategory, int] = {}
        applicable = set(analysis.applicable_categories())

        for ep in analysis.endpoints:
            if OwaspApiCategory.API1 in applicable and ep.object_id_params:
                tests += self._api1(ep, counters)
            if OwaspApiCategory.API2 in applicable:
                if ep.expected_public:
                    tests += self._api2_expected_public(ep, counters)
                elif ep.auth_required:
                    tests += self._api2(ep, counters)
            if OwaspApiCategory.API3 in applicable and ep.writes_properties:
                tests += self._api3(ep, counters)
            if OwaspApiCategory.API4 in applicable and self._is_expensive(ep):
                tests += self._api4(ep, counters)
            if OwaspApiCategory.API5 in applicable and self._is_privileged(ep):
                tests += self._api5(ep, counters)
            if OwaspApiCategory.API6 in applicable and self._is_sensitive_flow(ep):
                tests += self._api6(ep, counters)
            if OwaspApiCategory.API7 in applicable and ep.url_fields:
                tests += self._api7(ep, counters)
            if OwaspApiCategory.API10 in applicable and ep.url_fields:
                tests += self._api10(ep, counters)

        # API8/API9 are properties of the deployment, not of one route. Emitting
        # them per endpoint would multiply identical findings across a report;
        # one representative endpoint answers the question once.
        representative = analysis.endpoints[0] if analysis.endpoints else None
        if representative is not None:
            if OwaspApiCategory.API8 in applicable:
                tests += self._api8(representative, counters)
            if OwaspApiCategory.API9 in applicable:
                tests += self._api9(representative, counters)

        return tests

    # -- API1: object level authorization -----------------------------------

    def _api1(self, ep: Endpoint, c) -> list[TestCase]:
        id_field = ep.object_id_params[0]
        destructive = ep.method in {"DELETE", "PUT", "PATCH"}
        # The victim performing the same request on their own object is what
        # makes a rejection meaningful. Without it a 404 reads as "denied".
        baseline = BaselineSpec(
            as_persona=self._victim,
            description="The owning identity performs the same request, proving the "
                        "object exists and is reachable before the attack is judged.",
        )
        tests = [
            self._mk(
                OwaspApiCategory.API1, c, Severity.HIGH, ep,
                title=f"BOLA: {self._attacker} accesses another identity's object via {ep.signature}",
                objective=f"Verify object-level authorization on {ep.signature}.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="swap_object_id", detail={"id_field": id_field}),
                expected=ExpectedResult(status_in=[403, 404]),
                destructive=destructive,
                baseline=baseline,
            )
        ]
        if not self.aggressive:
            return tests

        for kind, detail, title in (
            ("swap_id_in_query", {"field": id_field, "id_field": id_field},
             "victim id supplied as a query parameter"),
            ("swap_id_in_header", {"header": "X-Account-Id", "id_field": id_field},
             "request scoped to the victim via a client-supplied header"),
            ("id_param_pollution", {"field": id_field, "id_field": id_field},
             "duplicate id parameter (own + victim)"),
            ("wrap_id_array", {"field": id_field, "id_field": id_field},
             "victim id wrapped in an array"),
        ):
            tests.append(self._mk(
                OwaspApiCategory.API1, c, Severity.HIGH, ep,
                title=f"BOLA variant on {ep.signature}: {title}",
                objective="Verify object-level authorization survives alternative "
                          "placements of the object identifier.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind=kind, detail=detail),
                expected=ExpectedResult(status_in=[400, 403, 404, 422]),
                destructive=destructive,
                baseline=baseline,
            ))

        if ep.writes_properties:
            tests.append(self._mk(
                OwaspApiCategory.API1, c, Severity.HIGH, ep,
                title=f"BOLA variant on {ep.signature}: victim id supplied in the body",
                objective="Verify object-level authorization is enforced on a body-carried "
                          "id, not only the one in the path.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="swap_id_in_body", detail={"field": id_field, "id_field": id_field}),
                expected=ExpectedResult(status_in=[400, 403, 404, 422]),
                destructive=destructive,
                baseline=baseline,
            ))
            tests.append(self._mk(
                OwaspApiCategory.API1, c, Severity.HIGH, ep,
                title=f"Authorization bypass via content-type switch on {ep.signature}",
                objective="Verify authorization is enforced regardless of body encoding.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="content_type_switch", detail={"to": "form"}),
                expected=ExpectedResult(status_in=[400, 403, 404, 415, 422]),
                destructive=destructive,
                baseline=baseline,
            ))
        for variant in ("zero", "negative", "me", "wildcard"):
            tests.append(self._mk(
                OwaspApiCategory.API1, c, Severity.MEDIUM, ep,
                title=f"BOLA id-format variant on {ep.signature}: {variant}",
                objective="Verify the authorization check and the data layer agree on "
                          "what the id means for a special-cased spelling.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="mutate_id_format", detail={"id_field": id_field, "variant": variant}),
                expected=ExpectedResult(status_in=[400, 403, 404, 422]),
                destructive=destructive,
                baseline=baseline,
            ))
        return tests

    # -- API2: authentication -----------------------------------------------

    def _api2_expected_public(self, ep: Endpoint, c) -> list[TestCase]:
        """The endpoint is declared intentionally public: the secure/correct
        behaviour IS to answer without a credential, so a 200 here is PASS and
        a 401/403 is the regression worth a look. No tamper_token/JWT variants
        — there is no credential in play to tamper with."""
        return [
            self._mk(
                OwaspApiCategory.API2, c, Severity.INFO, ep,
                title=f"Expected public: {ep.signature} answers without a credential",
                objective="Confirm the endpoint declared expected-public is still "
                          "reachable without a credential; a 401/403 here means the "
                          "declared access policy no longer matches reality (a "
                          "regression, not a fix).",
                auth=AuthContext(persona="anonymous"),
                mutation=Mutation(kind="drop_auth"),
                expected=ExpectedResult(status_in=[200, 201, 202, 204]),
            )
        ]

    def _api2(self, ep: Endpoint, c) -> list[TestCase]:
        # The endpoint answering normally for a credentialed identity is what
        # separates "auth is enforced" from "this route is simply broken".
        baseline = BaselineSpec(
            as_persona=self._victim,
            description="A credentialed identity reaches the endpoint successfully, so a "
                        "401 for the attack reflects authentication and not an outage.",
        )
        tests = [
            self._mk(
                OwaspApiCategory.API2, c, Severity.HIGH, ep,
                title=f"Broken auth: unauthenticated {ep.signature} must be rejected",
                objective="Verify the endpoint rejects requests with no credential.",
                auth=AuthContext(persona="anonymous", target_persona=self._victim),
                mutation=Mutation(kind="drop_auth"),
                expected=ExpectedResult(status_in=[401]),
                baseline=baseline,
            ),
            self._mk(
                OwaspApiCategory.API2, c, Severity.MEDIUM, ep,
                title=f"Broken auth: malformed token on {ep.signature} must be rejected",
                objective="Verify the endpoint rejects a malformed/expired token.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="tamper_token"),
                expected=ExpectedResult(status_in=[401]),
                baseline=baseline,
            ),
            # A token whose claims were rewritten but whose signature was NOT
            # recomputed is cryptographically invalid. Acceptance is proof the
            # signature is never verified — the single highest-value auth probe.
            self._mk(
                OwaspApiCategory.API2, c, Severity.CRITICAL, ep,
                title=f"JWT signature not verified: tampered claims accepted on {ep.signature}",
                objective="Verify the JWT signature is validated, not merely parsed.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="jwt_claim_tamper",
                                  detail={"claims": {"role": "admin", "is_admin": True}}),
                expected=ExpectedResult(status_in=[401, 403]),
                baseline=baseline,
            ),
            self._mk(
                OwaspApiCategory.API2, c, Severity.CRITICAL, ep,
                title=f"JWT alg=none accepted on {ep.signature}",
                objective="Verify an unsigned token declaring alg=none is rejected.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="jwt_alg_none"),
                expected=ExpectedResult(status_in=[401, 403]),
                baseline=baseline,
            ),
        ]
        if not self.aggressive:
            return tests

        for kind, detail, severity, title, objective in (
            ("jwt_expired_replay", {}, Severity.HIGH,
             "expired JWT replayed", "Verify token expiry is enforced, not merely encoded."),
            ("jwt_alg_confusion", {"key": "secret"}, Severity.CRITICAL,
             "RS256→HS256 algorithm confusion",
             "Verify the verifier pins the algorithm instead of trusting the token header."),
            ("jwt_kid_injection", {"kid": "../../dev/null"}, Severity.HIGH,
             "kid header traversal", "Verify the key-id header is not used as an unsanitised lookup."),
        ):
            tests.append(self._mk(
                OwaspApiCategory.API2, c, severity, ep,
                title=f"Broken auth on {ep.signature}: {title}",
                objective=objective,
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind=kind, detail=detail),
                expected=ExpectedResult(status_in=[401, 403]),
                baseline=baseline,
            ))
        return tests

    # -- API3: object property level authorization --------------------------

    def _api3(self, ep: Endpoint, c) -> list[TestCase]:
        # The read-back is what makes this category decidable at all.
        verification = VerificationStep(
            as_persona=self._attacker,
            request=RequestSpec(method="GET", path=ep.path),
            proves_exploit_if_contains=list(_ADMIN_MARKERS),
            description="Re-read the object as the attacker: if the injected privileged "
                        "property is stored, the write was not merely accepted but applied.",
        )
        # Deliberately NO target_persona. Mass assignment is escalation on an
        # object the caller already owns ("PATCH my own profile, set role=admin"),
        # so the path must resolve to the attacker's object — and declaring a
        # victim would put the victim's ids in the template namespace instead,
        # pointing both the attack and its read-back at the wrong object.
        auth = AuthContext(persona=self._attacker)
        tests = [
            self._mk(
                OwaspApiCategory.API3, c, Severity.HIGH, ep,
                title=f"BOPLA / mass assignment on {ep.signature}",
                objective="Verify the caller cannot set privileged object properties.",
                auth=auth,
                mutation=Mutation(kind="inject_property",
                                  detail={"properties": {"role": "admin", "is_admin": True}}),
                expected=ExpectedResult(status_in=[400, 403, 422]),
                verification=verification,
            )
        ]
        if not self.aggressive:
            return tests
        tests.append(self._mk(
            OwaspApiCategory.API3, c, Severity.HIGH, ep,
            title=f"BOPLA via nested property on {ep.signature}",
            objective="Verify property allowlists cover nested objects, not just top-level fields.",
            auth=auth,
            mutation=Mutation(kind="inject_nested_property",
                              detail={"path": "user.role", "value": "admin"}),
            expected=ExpectedResult(status_in=[400, 403, 422]),
            verification=verification,
        ))
        return tests

    # -- API4: resource consumption -----------------------------------------

    def _api4(self, ep: Endpoint, c) -> list[TestCase]:
        tests = [
            self._mk(
                OwaspApiCategory.API4, c, Severity.MEDIUM, ep,
                title=f"Resource consumption on {ep.signature}",
                objective="Verify limits on oversized/expensive input.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="oversized_payload", detail={"field": "q", "size": 200000}),
                expected=ExpectedResult(status_in=[400, 413, 414, 422]),
            ),
            self._mk(
                OwaspApiCategory.API4, c, Severity.MEDIUM, ep,
                title=f"Unbounded pagination on {ep.signature}",
                objective="Verify the server caps page size rather than honouring any limit.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="pagination_abuse",
                                  detail={"field": "limit", "value": 1_000_000}),
                expected=ExpectedResult(status_in=[400, 413, 422]),
            ),
            # The only probe in this category that measures rather than infers:
            # send N, count how many the server actually served.
            self._mk(
                OwaspApiCategory.API4, c, Severity.MEDIUM, ep,
                title=f"Missing rate limiting on {ep.signature}",
                objective="Verify repeated calls are throttled before an abusive volume lands.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="rate_probe", detail={"count": 20}),
                expected=ExpectedResult(
                    status_in=[200, 201, 400, 429],
                    max_successful_repeats=15,
                ),
            ),
        ]
        if not self.aggressive:
            return tests
        tests.append(self._mk(
            OwaspApiCategory.API4, c, Severity.MEDIUM, ep,
            title=f"Nested-JSON parser cost on {ep.signature}",
            objective="Verify deeply nested input is rejected before it is parsed recursively.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="json_depth_bomb", detail={"depth": 200}),
            expected=ExpectedResult(status_in=[400, 413, 422]),
        ))
        return tests

    # -- API5: function level authorization ---------------------------------

    def _api5(self, ep: Endpoint, c) -> list[TestCase]:
        # The privileged identity succeeding is what proves the function exists.
        baseline = BaselineSpec(
            as_persona=self._admin,
            description="A privileged identity invokes the same function successfully, so a "
                        "rejection for the low-privileged one reflects authorization.",
        )
        destructive = ep.method in {"DELETE", "PUT", "PATCH"}
        tests = [
            self._mk(
                OwaspApiCategory.API5, c, Severity.HIGH, ep,
                title=f"BFLA: lower-privileged user invokes {ep.signature}",
                objective="Verify function-level authorization on a privileged endpoint.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="escalate_persona"),
                expected=ExpectedResult(status_in=[403]),
                destructive=destructive,
                baseline=baseline,
            ),
            self._mk(
                OwaspApiCategory.API5, c, Severity.HIGH, ep,
                title=f"BFLA via verb smuggling on {ep.signature}",
                objective="Verify authorization is decided on the effective method, not the "
                          "outer one a gateway sees.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="method_override", detail={"method": "DELETE"}),
                expected=ExpectedResult(status_in=[403, 405]),
                destructive=True,
                baseline=baseline,
            ),
        ]
        if not self.aggressive:
            return tests
        tests.append(self._mk(
            OwaspApiCategory.API5, c, Severity.HIGH, ep,
            title=f"BFLA via administrative route for {ep.signature}",
            objective="Verify the administrative variant of this route enforces role checks.",
            auth=AuthContext(persona=self._attacker, target_persona=self._victim),
            mutation=Mutation(kind="admin_path_swap", detail={}),
            expected=ExpectedResult(status_in=[401, 403, 404]),
            destructive=destructive,
            baseline=baseline,
        ))
        # A verb the router may register a handler for without wiring the same
        # authorization decorator onto it (routers commonly protect POST/DELETE
        # explicitly but forget PUT, or leave OPTIONS/TRACE unprotected).
        tests.append(self._mk(
            OwaspApiCategory.API5, c, Severity.MEDIUM, ep,
            title=f"BFLA across HTTP verbs on {ep.signature}",
            objective="Verify every verb the router accepts on this path enforces the "
                      "same authorization, not just the one the ticket names.",
            auth=AuthContext(persona=self._attacker, target_persona=self._victim),
            mutation=Mutation(kind="method_switch", detail={"method": "OPTIONS"}),
            expected=ExpectedResult(status_in=[401, 403, 404, 405]),
            destructive=False,
            baseline=baseline,
        ))
        for variant in ("uppercase", "double_slash", "trailing_slash"):
            tests.append(self._mk(
                OwaspApiCategory.API5, c, Severity.MEDIUM, ep,
                title=f"BFLA via path spelling on {ep.signature}: {variant}",
                objective="Verify an authorization rule keyed on the exact path string "
                          "cannot be sidestepped by an equivalent spelling of the route.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="path_normalization_bypass", detail={"variant": variant}),
                expected=ExpectedResult(status_in=[400, 401, 403, 404]),
                destructive=destructive,
                baseline=baseline,
            ))
        return tests

    # -- API6: sensitive business flows -------------------------------------

    def _api6(self, ep: Endpoint, c) -> list[TestCase]:
        tests = [
            self._mk(
                OwaspApiCategory.API6, c, Severity.MEDIUM, ep,
                title=f"Unrestricted automation of the business flow {ep.signature}",
                objective="Verify a single identity cannot execute this sensitive flow at "
                          "machine speed without business-level throttling.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="repeat_flow", detail={"count": 10}),
                expected=ExpectedResult(
                    status_in=[200, 201, 400, 429],
                    max_successful_repeats=5,
                ),
            )
        ]
        # A one-shot flow is the case where "it was accepted" and "it actually
        # happened" come apart, and where only the second one is a finding: a
        # redeem endpoint answering 200 ten times has either committed ten
        # times or deduplicated nine of them, and the status line cannot tell
        # you which. The read-back can, and it is the same rule this platform
        # applies everywhere else — a 200 is never a finding on its own.
        if self._is_one_shot_flow(ep) and ep.method.upper() in DESTRUCTIVE_METHODS:
            tests.append(self._mk(
                OwaspApiCategory.API6, c, Severity.HIGH, ep,
                title=f"Repeated commits of the one-shot flow {ep.signature} persist",
                objective="Verify a sensitive one-shot operation commits once however many "
                          "times it is invoked — read back afterwards rather than trusting "
                          "the status code of each attempt.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="repeat_flow", detail={"count": 5}),
                # The read-back runs as the identity that owns the object, so a
                # failure to see the duplicate cannot be the attacker's own
                # visibility being restricted.
                verification=VerificationStep(
                    as_persona=self._victim if ep.object_id_params else self._attacker,
                    request=RequestSpec(method="GET", path=ep.path),
                    proves_exploit_when=[
                        InvariantAssertion(
                            json_path="$.count",
                            operator="gt",
                            expected=1,
                            description="More than one commit survived, so the flow is not "
                                        "one-shot in fact — only in its response codes.",
                        ),
                    ],
                    description="Re-read the object after the burst: what persisted is the "
                                "finding, not what was accepted.",
                ),
                expected=ExpectedResult(
                    status_in=[200, 201, 400, 409, 429],
                    max_successful_repeats=1,
                ),
            ))
        # A concurrent burst only makes sense where repetition should be
        # impossible rather than merely rate-limited; firing it at an endpoint
        # that legitimately accepts repeats manufactures a false positive.
        if self.aggressive and self._is_one_shot_flow(ep):
            tests.append(self._mk(
                OwaspApiCategory.API6, c, Severity.HIGH, ep,
                title=f"Race window on the one-shot flow {ep.signature}",
                objective="Verify the check-to-commit window is not exploitable by "
                          "concurrent requests (double-spend / reuse).",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="race_condition", detail={"count": 10}),
                expected=ExpectedResult(
                    status_in=[200, 201, 400, 409, 429],
                    # A genuinely one-shot operation must commit at most once,
                    # however many callers ask simultaneously.
                    max_successful_repeats=1,
                ),
            ))
        return tests

    # -- API7: server side request forgery ----------------------------------

    def _api7(self, ep: Endpoint, c) -> list[TestCase]:
        field = ep.url_fields[0]
        tests = [
            self._mk(
                OwaspApiCategory.API7, c, Severity.HIGH, ep,
                title=f"SSRF via server-consumed URL on {ep.signature}",
                objective="Verify the server rejects internal/metadata URL targets.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="ssrf_url",
                                  detail={"field": field,
                                          "value": "http://169.254.169.254/latest/meta-data/"}),
                oast=OastExpectation(
                    purpose="ssrf",
                    description="A callback proves the target server resolved and fetched the URL.",
                ),
                expected=ExpectedResult(status_in=[400, 403, 422]),
            )
        ]
        if not self.aggressive:
            return tests
        tests.append(self._mk(
            OwaspApiCategory.API7, c, Severity.HIGH, ep,
            title=f"SSRF blocklist evasion on {ep.signature}",
            objective="Verify the URL filter resolves destinations rather than "
                      "string-matching known-bad spellings.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="ssrf_url_bypass", detail={"field": field}),
            oast=OastExpectation(purpose="ssrf"),
            expected=ExpectedResult(status_in=[400, 403, 422]),
        ))
        return tests

    # -- what kind of endpoint is this --------------------------------------
    #
    # Matched on the path, which is the one thing every source of endpoints
    # agrees on — prose, a specification, or a hand-typed row.

    @staticmethod
    def _is_graphql(ep: Endpoint) -> bool:
        return "graphql" in ep.path.lower() or ep.path.rstrip("/").endswith("/gql")

    @staticmethod
    def _is_oauth_redirect(ep: Endpoint) -> bool:
        path = ep.path.lower()
        if any(word in path for word in ("/authorize", "/oauth", "/connect/auth", "/sso")):
            return True
        # A route taking a redirect target is the same surface under any name.
        return any("redirect" in f.lower() for f in ep.url_fields)

    # -- API8: security misconfiguration ------------------------------------

    def _api8(self, ep: Endpoint, c) -> list[TestCase]:
        # Status is deliberately permissive on these: the finding lives in the
        # response headers or body, so the status line must not decide it.
        any_status = [200, 201, 204, 400, 401, 403, 404]
        tests = [
            self._mk(
                OwaspApiCategory.API8, c, Severity.MEDIUM, ep,
                title="CORS policy reflects arbitrary origins",
                objective="Verify the API does not echo an attacker-supplied Origin back "
                          "as an allowed origin.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="cors_probe", detail={"origin": "https://evil.example"}),
                expected=ExpectedResult(
                    status_in=any_status,
                    forbidden_response_headers={
                        "access-control-allow-origin": "evil.example",
                    },
                ),
            ),
            self._mk(
                OwaspApiCategory.API8, c, Severity.LOW, ep,
                title="Response hardening headers absent",
                objective="Verify baseline security response headers are configured.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="security_headers_probe"),
                expected=ExpectedResult(
                    status_in=any_status,
                    required_response_headers=["X-Content-Type-Options"],
                ),
            ),
        ]
        tests.append(self._mk(
            OwaspApiCategory.API8, c, Severity.MEDIUM, ep,
            title="Host header is trusted for absolute URLs",
            objective="Verify a forged Host header is not reflected into links, "
                      "redirects or password-reset URLs the server generates.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="host_header_injection",
                              detail={"host": "evil.example"}),
            expected=ExpectedResult(
                status_in=any_status,
                # Reflecting the forged host into the body is the finding; a
                # 200 on its own is not, which is why the status list is open.
                body_must_not_contain=["evil.example"],
                forbidden_response_headers={"location": "evil.example"},
            ),
        ))
        if not self.aggressive:
            return tests
        tests.append(self._mk(
            OwaspApiCategory.API8, c, Severity.MEDIUM, ep,
            title="Debug/verbose output reachable",
            objective="Verify debug flags do not elicit stack traces or internal detail.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="debug_probe"),
            expected=ExpectedResult(
                status_in=any_status,
                body_must_not_contain=list(_DEBUG_FINGERPRINTS),
            ),
        ))
        return tests

    # -- API9: inventory management -----------------------------------------

    def _api9(self, ep: Endpoint, c) -> list[TestCase]:
        tests = [
            self._mk(
                OwaspApiCategory.API9, c, Severity.MEDIUM, ep,
                title="API specification served publicly",
                objective="Verify machine-readable API inventory is not exposed unauthenticated.",
                auth=AuthContext(persona="anonymous"),
                mutation=Mutation(kind="undocumented_path_probe", detail={"path": "/openapi.json"}),
                expected=ExpectedResult(
                    status_in=[401, 403, 404],
                    # Serving the document is the finding, and these strings are
                    # what a served document contains.
                    body_must_not_contain=['"openapi"', '"swagger"', '"paths"'],
                ),
            )
        ]
        if self._is_graphql(ep):
            # Not gated on `aggressive`: an exposed schema is the whole
            # inventory of a GraphQL API, and asking for it is one request.
            tests.append(self._mk(
                OwaspApiCategory.API9, c, Severity.MEDIUM, ep,
                title="GraphQL introspection enabled",
                objective="Verify the schema is not served to unauthenticated callers, "
                          "which would hand over the API's entire inventory.",
                auth=AuthContext(persona="anonymous"),
                mutation=Mutation(kind="graphql_introspection_probe"),
                expected=ExpectedResult(
                    status_in=[400, 401, 403, 404],
                    body_must_not_contain=["__schema", "__typename", "queryType"],
                ),
            ))
        if not self.aggressive:
            return tests
        if self._is_graphql(ep):
            tests.append(self._mk(
                OwaspApiCategory.API9, c, Severity.MEDIUM, ep,
                title="GraphQL query batching unbounded",
                objective="Verify a batched query array is not executed wholesale, "
                          "which turns one request into arbitrarily many.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="graphql_batching_abuse", detail={"count": 25}),
                expected=ExpectedResult(status_in=[400, 401, 403, 413, 429]),
            ))
        if "/v" in ep.path:
            tests.append(self._mk(
                OwaspApiCategory.API9, c, Severity.MEDIUM, ep,
                title=f"Superseded API version still reachable for {ep.signature}",
                objective="Verify retired versions are decommissioned rather than left "
                          "running with the previous generation's controls.",
                auth=AuthContext(persona=self._attacker, target_persona=self._victim),
                mutation=Mutation(kind="version_downgrade", detail={}),
                expected=ExpectedResult(status_in=[404, 410]),
            ))
        for path in ("/actuator/health", "/.env", "/swagger-ui.html"):
            tests.append(self._mk(
                OwaspApiCategory.API9, c, Severity.MEDIUM, ep,
                title=f"Undocumented surface reachable at {path}",
                objective="Verify administrative and diagnostic surfaces are not exposed.",
                auth=AuthContext(persona="anonymous"),
                mutation=Mutation(kind="undocumented_path_probe", detail={"path": path}),
                expected=ExpectedResult(status_in=[401, 403, 404]),
            ))
        return tests

    # -- API10: unsafe consumption of APIs ----------------------------------

    def _api10(self, ep: Endpoint, c) -> list[TestCase]:
        return [
            self._mk(
                OwaspApiCategory.API10, c, Severity.MEDIUM, ep,
                title=f"Unvalidated consumption of a third-party response on {ep.signature}",
                objective="Verify upstream responses and redirects are validated before "
                          "being trusted. For a definitive result, point the mutation "
                          "detail at a collaborator host that answers 302 to an internal "
                          "address.",
                auth=AuthContext(persona=self._attacker),
                mutation=Mutation(kind="unsafe_redirect_url",
                                  detail={"field": ep.url_fields[0]}),
                oast=OastExpectation(
                    purpose="redirect",
                    description="A callback proves the upstream redirect was followed server-side.",
                ),
                expected=ExpectedResult(status_in=[400, 403, 422]),
            )
        ] + self._oauth_redirect_tests(ep, c)

    def _oauth_redirect_tests(self, ep: Endpoint, c) -> list[TestCase]:
        """An authorization endpoint that accepts an attacker's `redirect_uri`
        hands over the code it is about to issue.

        A reviewed, registered mutation the deterministic designer could never
        reach before, because nothing told it which routes were OAuth. The path
        does, and so does a declared redirect field.
        """
        if not self._is_oauth_redirect(ep):
            return []
        return [self._mk(
            OwaspApiCategory.API10, c, Severity.HIGH, ep,
            title="Authorization redirect target is not allow-listed",
            objective="Verify redirect_uri is matched against registered values rather "
                      "than accepted from the request, which would deliver the "
                      "authorization code to an attacker.",
            auth=AuthContext(persona=self._attacker),
            mutation=Mutation(kind="oauth_redirect_uri_bypass",
                              detail={"redirect_uri": "https://evil.example/callback"}),
            expected=ExpectedResult(
                status_in=[400, 401, 403],
                forbidden_response_headers={"location": "evil.example"},
            ),
        )]

    # -- helpers ------------------------------------------------------------

    def _mk(self, category, counters, severity, ep, *, title, objective, auth,
            mutation, expected, destructive=False, baseline=None,
            verification=None, oast=None) -> TestCase:
        counters[category] = counters.get(category, 0) + 1
        num = counters[category]
        cat_num = category.value.split(":")[0]  # "API1"
        # Any state-changing method is destructive by default — a broken control
        # means the write actually happened. Gate it out of default execution.
        destructive = (destructive or ep.method.upper() in DESTRUCTIVE_METHODS
                       or is_destructive_mutation(mutation.kind, mutation.detail))
        return TestCase(
            test_id=f"{cat_num}-{num:03d}",
            title=title,
            objective=objective,
            owasp_category=category,
            severity=severity,
            auth_context=auth,
            baseline=baseline,
            request=RequestSpec(method=ep.method, path=ep.path),
            attack_mutation=mutation,
            verification=verification,
            oast=oast,
            expected=expected,
            evidence_required=["request", "response"],
            is_destructive=destructive,
            source=TestSource.RULE_ENGINE,
            approval_status=ApprovalStatus.PENDING,
        )

    def _is_privileged(self, ep: Endpoint) -> bool:
        return ep.method in {"DELETE", "PUT", "PATCH"} or "admin" in ep.path.lower()

    def _is_expensive(self, ep: Endpoint) -> bool:
        low = ep.path.lower()
        return any(k in low for k in _EXPENSIVE_WORDS)

    def _is_sensitive_flow(self, ep: Endpoint) -> bool:
        low = ep.path.lower()
        return ep.method.upper() in {"POST", "PUT", "PATCH"} and any(
            k in low for k in _SENSITIVE_FLOW_WORDS
        )

    def _is_one_shot_flow(self, ep: Endpoint) -> bool:
        low = ep.path.lower()
        return any(k in low for k in _ONE_SHOT_FLOW_WORDS)
