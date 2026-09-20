# FAPI 2.0 Security Profile conformance — findings

Scored against the OIDF conformance suite (pinned commit
`6b8b809dd07df6ca8b4481a9e921bf48b9ffbffe`), plan
`fapi2-security-profile-final-test-plan[openid=plain_oauth][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]`.

**Run of `d57a53b`+`2e37ff9` (`31d729c` lineage): 51 modules, 2992 condition
successes, 29 failures, 5 warnings.** `happy-flow` PASSES (197 checks). The
machinery (suite build, host↔container networking, private-CA TLS trust, headless
browser automation, per-client redirect URIs, response capture) is proven; what
remains are the conformance findings below.

Each finding lists the affected module(s), the exact failing condition, the
evidence (what the AS actually did vs. what the suite expected), and a
root-cause **category**: `fixture` (the conformance fixture/browser config or the
resource stub), or `core` (a genuine `oauth-as` behavior question).

---

## D1 — Browser automation cannot handle an AS error page at `/authorize`  (category: fixture)

**Modules:** `par-attempt-reuse-request_uri`, `par-attempt-to-use-expired-request_uri`,
`par-attempt-to-use-request_uri-for-different-client`,
`ensure-unsigned-authorization-request-without-using-par-fails`.

**Failing condition:** `WebRunner: Unexpected URL for non-optional task` →
`Web Runner Exception`.

**Evidence:** For `par-attempt-reuse-request_uri` the AS **correctly returned HTTP
400** to the reused `request_uri` (`WebRunner: Scripted browser HTTP response
[400]`), and the suite raised `[REVIEW] ExpectInvalidRequestUriErrorPage` ("if the
server does not return an error back to the client, it must show an error page").
The AS behaved correctly; the failure is that our single browser task
(`match: https://localhost.emobix.co.uk*`, non-optional) throws when the browser
lands on the `as.local` **error page** instead of the suite callback.

**Shape of fix (RESOLVED):** two coupled parts, both fixture-only; the library's
Direct-error decision (RFC 6749 s4.1.2.1: do not redirect to an unvalidated
`redirect_uri`) is preserved unchanged.

1. `fapi2/config.json` browser automation must not merely tolerate the error page —
   it must FILL the module's placeholder. Each rejection module sets an
   `ExpectXxxErrorPage` placeholder (via `createBrowserInteractionPlaceholder`) and
   goes to `WAITING`; the watcher in `AbstractTestModule` fires
   `fireTestFinishedInternal` only once the LAST placeholder clears. A placeholder is
   cleared only by a `wait` command whose action token is `update-image-placeholder`
   and whose selector is a real `getSelector` type (`xpath`, not `match`/`contains`)
   with a non-empty regexp (`BrowserControl.doCommand`/`updatePlaceholder` @6b8b809).
   The optional rejection task now runs
   `["wait","xpath","//*",10,"Authorization error","update-image-placeholder"]`. A
   bare checkpoint task (no command) lets WebRunner exit but never clears the
   placeholder, so the module hangs until the plan timeout — the actual root cause of
   the exit-124 run (35486195583).

2. HtmlUnit renders the library's `application/json` error body as a non-HTML
   `TextPage`, on which `By.xpath("//*")` finds no DOM, so the `wait` above could
   never match. The fixture's `authorization_errors_as_html` middleware
   (`examples/fapi2_conformance_server.rs`) re-renders a 4xx at `/authorize` as an
   HTML page carrying the fixed `<h1>Authorization error</h1>` the task waits for.
   Scoped to GET `/authorize` only, so token / PAR / resource / metadata keep the
   exact JSON bytes the suite's HTTP client parses. Verified locally: unknown
   `request_uri` and non-PAR requests both return that HTML; `/token` stays JSON.

Also covers `par-attempt-to-use-expired-request_uri`,
`par-attempt-to-use-request_uri-for-different-client` (modules [1:37], [1:40]) and any
other authorization-endpoint rejection, since the fix is generic over the error page.

---

## D2 — Fixture cannot simulate user rejection or a two-visit (deferred-auth) flow  (category: fixture for module A; fixture AND core for module B — both ACCEPTED as expected failures, NOT passes)

**Status:** both modules are recorded, one entry per failing condition, in
`crates/oauth-as-conformance/fapi2/expected-failures.json`, which
`scripts/fapi2-conformance.sh` passes to the OIDF runner as `--expected-failures-file`
(the suite's own mechanism, `scripts/run-test-plan.py` at `6b8b809`). An expected
failure is a documented gap the gate keeps in front of us, not a pass: the runner exits
1 if any listed condition STOPS failing (`EXPECTED_FAILURES_NOT_HAPPEN`), so a fix
cannot land without deleting its entries, and a stale entry cannot mask a regression
elsewhere. **This does not make the FAPI 2.0 job green.** Of the run's 29 condition
failures and 5 warnings it accounts for 5 and 2; D1, D3, D4, D5 and D7 remain (D6 is
resolved in-tree and not yet re-run), plus one un-catalogued unexpected SKIP
(`ensure-signed-client-assertion-with-RS256-fails`: "This test requires RSA keys … If
your server does not support PS256 then this will not prevent you certifying", which
needs an `--expected-skips-file` entry, not a fix). The job runs on push to `qa`
(`.github/workflows/fapi2-conformance.yml`, "GATES qa"), so `qa` stays red until those
are resolved; this is one finding closed honestly, not a green.

Both modules are REQUIRED for this plan: `FAPI2SPFinalTestPlan.fapi2SPtestModules()`
starts from `FAPI2MessageSigningFinalTestPlan.testModules` (which lists
`FAPI2SPFinalUserRejectsAuthentication` and
`FAPI2SPFinalPAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion`) and
removes only 16 request-object-signing modules, neither of which is a D2 module; both
carry only `@VariantNotApplicable(FAPI2FinalOPProfile, "fapi_client_credentials_grant")`,
which does not exclude `fapi_profile=plain_fapi`. So neither entry is optional: to
CERTIFY this profile the gaps below must actually close.

The condition and block strings in the entries were captured from the real run at
`2e37ff9` (workflow run 35477787404, artifact `fapi2-conformance-logs`, module logs
`modules/pFrvMBesALwNuke.json` and `modules/F6DDe0FNM9WGshn.json`) and checked against
the runner's own matching code, not guessed. Note the runner matches
`configuration-filename` by `fnmatch` against the config path exactly as passed on the
command line (an absolute path here), so the entries use the glob `*/fapi2/config.json`;
a bare `config.json` would never match and the entries would sit inert.

### Module A — `user-rejects-authentication`  (category: fixture)

**Failing conditions (real run):** in BOTH the first-client block `Verify authorization
endpoint response` and the second-client block `Second client: Verify authorization
endpoint response`: `EnsureErrorFromAuthorizationEndpointResponse` (FAILURE),
`CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint` (WARNING), and
`ExpectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest` (FAILURE:
"error parameter not found. When running this test, the tester MUST press 'cancel' on
the login screen or deny consent so that an error is returned"). Six entries, each
pinned to its exact block and condition with the level the suite logs it at.

**Evidence:** the AS deny path is already conformant. `ApprovalDecision::Deny` returns
`access_denied` (with `state`) at the validated redirect URI (`authorize_handler` in
`crates/oauth-as/src/http.rs`; RFC 6749 s4.1.2.1), covered in-crate by
`tests/http_surface.rs::c4_the_consent_seam_decides_what_the_authorization_endpoint_does`
and, on the PAR path, by
`tests/http_par_jar_routing.rs::a_pushed_authorization_detail_reaches_the_approval_screen`.
The fixture never drives it: `fapi2_conformance_server.rs` wires
`with_subject_resolver(|_| Some(SEEDED_SUBJECT))` and
`with_approval_resolver(|_| ApprovalDecision::Approve)`, both ignoring their input, and
renders no page, so the suite's headless HtmlUnit browser has nothing to cancel and the
AS issues a code where the module expects an error. No AS change is needed.

**What the suite offers, corrected:** the suite DOES have a per-module hook. A top-level
`"override"` object in the config, keyed by test-module name, is merged into that
module's configuration at plan creation (`info/DBTestPlanService.java:171-174` at
`6b8b809`; the suite wiki's "Authlete Automated Example Configuration" uses it), so a
module-specific `browser` task list — click "deny" for this module, "approve" for every
other — is expressible headlessly. What is missing is a page to click, and that is not
only a fixture omission: on the PAR path the crate consumes the `request_uri` before the
approval resolver runs (`ApprovalRequest::resource` docs: "the pushed record has already
been consumed by the time this resolver runs"), and `ApprovalRequest` is a borrow with no
handle to resume issuance later, so an `ApprovalDecision::Respond` consent page cannot be
completed on a later request for a pushed request. That is the same core property as
module B. Keying `Deny` off an incidental property of this module (it alone requests a
128-character `state`, `requested_state_length`) was considered and rejected: a rejection
no user made is exactly the fake signal an honest gate refuses.

**To certify:** (1) the core change described under module B, then (2) a fixture consent
page with approve/deny controls, then (3) a `config.json` `override` entry for this
module clicking deny. Headless throughout; no human step is needed once (1) exists.

### Module B — `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`  (category: fixture AND core)

**Failing condition (real run):** block `Make request to authorization endpoint`,
condition
`fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`
(FAILURE: "unexpected exception caught: java.lang.RuntimeException: The user was
authenticated on the initial visit to login page. This must not be attempted until the
second visit"). The condition is the module's own id because `processCallback()` throws
a raw `RuntimeException` and `AbstractTestModule.handleException` logs it under
`getName()`; there is no condition class to cite.

**Observed cause (fixture):** auto-approve authenticates and issues a code on the FIRST
visit; the suite's callback arrives with the authorization URL visited once, and
`processCallback` refuses. A first visit that does not authenticate is a prerequisite
for this module and the fixture cannot express one.

**Latent cause (core):** it would fail with a perfect fixture too. `authorize_handler`
calls `resolve_authorization_request` → `validate_pushed_authorization_request` →
`Storage::take_pushed_authorization_request` (an atomic remove) and receives the
validated request BEFORE `state.subject(headers)` and the approval step run
(`crates/oauth-as/src/http.rs`, `crates/oauth-as/src/par.rs`,
`crates/oauth-as/src/store.rs`). The handle is spent at the point of loading the page, so
a second pre-completion visit is answered with a DIRECT `400 invalid_request_uri` (the
redirect URI lived in the consumed record, so no redirect is possible) — which would then
land on the D1 error-page limitation as well.

**Spec, verbatim:** FAPI 2.0 Security Profile Final s5.3.2.2 NOTE 3: "It is recommended
that authorization servers that enforce one-time use of request_uri values ensure the
enforcement takes place at the point of authorization, not at the point of loading an
authorization page. This prevents user software that preloads urls from invalidating the
request_uri." RFC 9126 s4: "Authorization servers SHOULD treat request_uri values as
one-time use but MAY allow for duplicate requests due to a user reloading/refreshing
their user agent"; s7.3 (Request Object Replay): "the authorization server SHOULD make
the request URIs one-time use". The crate's consume-at-read is therefore a deliberate,
spec-PERMITTED stricter posture (a NOTE-level recommendation and a MAY declined, in
favour of one atomic take and one answer for unknown/used/expired), not a security
downgrade and not the suite being wrong. It does diverge from the FAPI recommendation the
module asserts. The `par.rs` module doc ("RFC 9126 section 4 says a client MUST use a
`request_uri` once and section 7.3 asks the server to enforce it") should be re-read
against the SHOULD+MAY server-side text above when the core change lands. The module's
own summary says it is "a recommendation and as such any failure of this test will
result in a warning" — but only for an AS that answers the second visit with a
REDIRECTABLE `invalid_request_uri` (`WarningAboutRequestUriError`), which this crate
cannot produce once the record is gone.

**To certify:** BOTH (1) a core change that keeps the pushed record resolvable until
authorization completes — enforce one-time use at code issuance per NOTE 3, which also
unlocks a consent page on the PAR path and therefore module A — AND (2) a first visit
that does not authenticate. (2) is not expressible in the suite's per-URL browser task
lists (both visits hit the same URL with the same tasks, and `BrowserControl` has no
visit counter), and the module's summary requires a screenshot upload on error, so this
module stays human-driven. Neither is done here; the entry records the gap.

---

## D3 — Protected-resource stub returns unexpected status codes  (category: fixture)

**Modules:** `access-token-type-header-case-sensitivity` (FAILURE:
`EnsureHttpStatusCodeIs200or201: resource endpoint returned a different http
status than expected`), `attempt-reuse-authorization-code-after-one-second`
(WARNING: `EnsureHttpStatusCodeIs4xx`), `dpop-negative-tests` (WARNING:
`EnsureHttpStatusCodeIs200or201`).

**Evidence:** the DPoP-verifying resource stub in the fixture returns a status the
suite did not expect — including a case-sensitivity check on the `DPoP`
authorization scheme, and 200-vs-4xx handling for reused/negative tokens.

**Shape of fix (RESOLVED):** two of the three are now PASSED and the third is a
documented expected warning.

- `access-token-type-header-case-sensitivity` ([1:5]) and `dpop-negative-tests`
  ([1:33]) PASS: the resource stub now parses the `Authorization: DPoP` scheme
  case-insensitively (RFC 9449) and returns the status the suite asserts (run
  35487826596, head c51be96).
- `attempt-reuse-authorization-code-after-one-second` ([1:26]) is an EXPECTED WARNING
  (`expected-failures.json`), not an AS defect. The AS revokes the token family on code
  reuse (server.rs ~4933; RFC 6749 s4.1.2, RFC 9700 s4.1.1), but the fixture's resource
  validates the JWT access token statelessly (no RFC 7662 introspection), so a
  still-signature-valid token is accepted until expiry. Revocation on reuse is a SHOULD;
  the suite logs the missing 4xx at WARNING and templates it as an expected warning. See
  that entry's comment for the full justification.

Separately, `ensure-signed-client-assertion-with-RS256-fails` ([1:28]) is an EXPECTED
SKIP (`expected-skips.json`, wired through `--expected-skips-file` in
`scripts/fapi2-conformance.sh`): the fixture authenticates with ES256, so the module has
no RSA/PS256 key to build its RS256 negative input from and skips itself, which the suite
states does not prevent certification.

---

## D4 — Client-assertion `aud` validation is too lenient  (category: core)

**Modules:** `par-test-array-as-audience-fails`,
`par-test-token-endpoint-url-as-audience-fails`.

**Failing conditions:** `EnsureHttpStatusCodeIs400or401` and
`CheckErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest`.

**Evidence:** with a `private_key_jwt` client assertion whose `aud` is **an array
containing the issuer plus another value**, the AS returned **201 CREATED** at PAR
(`AddArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims`
→ `[201]`). The suite expects `400`/`invalid_client`. Same class for `aud` set to
the token-endpoint URL. Note `ensure-client-assertion-with-wrong-aud-fails` and
`par-test-par-endpoint-url-as-audience-fails` already PASS, so the gap is
specifically: array `aud` with an extra member, and token-endpoint-URL `aud` at
the PAR endpoint. RFC 7523 permits array `aud`; FAPI 2.0 tightens it — the design
must resolve the exact acceptance rule (`aud` must be exactly the issuer, single
value) and cite the spec.

**Likely code:** client-assertion validation in `crates/oauth-as/src/client_assertion.rs`.

**Resolution (category: core).** The exact acceptance rule under FAPI 2.0 is: the assertion's `aud`
must be a single JSON **string** equal to the AS **issuer identifier** (RFC 8414) — the token
endpoint URL is refused, and an array is refused even when the issuer is its sole member. This is
FAPI 2.0 Security Profile Final s5.3.2.1 item 8 ("shall only accept its issuer identifier value ...
as a string in the `aud` claim") and s5.3.3.1 item 5 ("as a string not as an item in an array");
draft-ietf-oauth-rfc7523bis-11 s3 narrows the base protocol the same way. Because s5.3.2.1 is a
general AS requirement the rule is uniform across every client-authenticating endpoint, which is
why the sibling `par-test-par-endpoint-url-as-audience-fails` already passes: the accepted value is
the issuer, not "the URL of the endpoint you are at". The crate default stays RFC 7523 s3 (3) as
published (`AssertionAudience::Rfc7523`), because s3 (3) explicitly permits the token endpoint URL
and much deployed client software sends it; the strict rule is the opt-in
`AssertionAudience::IssuerOnly`, set by the conformance fixture. The FAPI2 modules build their
assertions with `CreateClientAuthenticationAssertionClaimsWithIssAudience`, which sends
`aud = server.issuer` as a plain string, so no passing module regresses under `IssuerOnly`, while
`par-test-array-as-audience-fails` and `par-test-token-endpoint-url-as-audience-fails` flip to PASS
(both refused as `invalid_client`, HTTP 401, which the suite accepts via
`EnsureHttpStatusCodeIs400or401`). Implemented on the single `verify_assertion` call site in
`authenticate_client` (`crates/oauth-as/src/server.rs`), inherited by PAR, token, and the rest by
construction.

---

## D5 — Mismatched DPoP `jkt` is not rejected  (category: core)

**Modules:** `ensure-mismatched-dpop-jkt-fails`
(`EnsurePARInvalidRequestOrInvalidDpopProof`),
`ensure-token-endpoint-fails-with-mismatched-dpop-jkt` and
`ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt`
(`CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError: Couldn't find
error field`).

**Evidence:** when the DPoP proof key thumbprint does not match the binding
established earlier in the flow, the AS should reject (PAR: invalid_request /
invalid_dpop_proof; token: invalid_dpop_proof / invalid_grant). The AS did not
return the expected error.

**Likely code:** DPoP verification in `crates/oauth-as/src/dpop.rs` and its use at
the PAR and token endpoints.

---

## D6 — Request object omitting `redirect_uri` is not rejected  (category: core — RESOLVED)

**Module:** `ensure-request-object-without-redirect-uri-fails`
(`EnsureErrorFromAuthorizationEndpointResponse`,
`CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObject`).

**Evidence:** the AS was expected to return an authorization error when the
(PAR-pushed) request omits `redirect_uri`, but it did not. Both push shapes — the
plain form body and the JAR request object — funnel through `store_pushed_request`,
which delegates to `validate_direct_authorization_request`; there the RFC 6749
s3.1.2.3 single-registered-URI fallback silently supplied the value instead of
rejecting, and the fixture registers `client` with exactly one redirect URI, so the
push was accepted (PAR 201).

**Resolution:** FAPI 2.0 SP Final s5.3.2.2 clause 6 ("the AS shall require the
`redirect_uri` parameter in pushed authorization requests") is now enforced at the
PAR push chokepoint via the opt-in `ParConfig.require_redirect_uri`, turned on in
the conformance fixture. When set it OVERRIDES the s3.1.2.3 omission for the PAR
push path only (default-off keeps plain OAuth 2.1 behaviour), and it covers both
push shapes because both reach `store_pushed_request`. The rejection is
`invalid_request` / HTTP 400 (RFC 9126 s2.3 / RFC 6749 s5.2), which the suite
accepts at the PAR endpoint via `processParErrorResponse` →
`EnsurePARInvalidRequestOrInvalidRequestObjectError` — so no `/authorize` visit
occurs and the D1 browser-error-page limitation is sidestepped entirely. This
flips `ensure-request-object-without-redirect-uri-fails` to PASS.

**Code:** `crates/oauth-as/src/par.rs` (`ParConfig.require_redirect_uri`,
`store_pushed_request`), `crates/oauth-as/examples/fapi2_conformance_server.rs`.

---

## D7 — Refresh-token grant returns an error when it should succeed  (category: core — RESOLVED)

**Module:** `refresh-token` (`CheckTokenEndpointHttpStatus200`,
`CheckIfTokenEndpointResponseError`: "the token endpoint call was expected to
succeed, but it returned an error response").

**Evidence:** the exact error was `400 invalid_dpop_proof: "this refresh token is
bound to a different DPoP key"`. The suite refreshes with a *fresh* DPoP key, and
the client is `private_key_jwt` (**confidential**). The refresh path in
`server::refresh_token` enforced DPoP key equality (`record.jkt != bound.jkt`) for
**every** client, so a confidential client presenting a new key on rotation was
rejected.

**Resolution:** RFC 9449 s5 — "refresh tokens issued to confidential clients are
not bound to the DPoP proof public key … because they are already bound to the
client through the client authentication mechanism." The equality check is now
split by client type:
- **Public client** (no credential): exact key match, unchanged — the DPoP key is
  the only thing protecting the token, so a stolen token must not be re-keyed by a
  thief. This branch is byte-identical to the previous enforcement.
- **Confidential client**: may rotate onto a *different* key (a thief cannot
  present the chain at all without the client credential), but the **presence** of
  a proof must still match the chain (`record.jkt.is_some() != bound.jkt.is_some()`),
  so a DPoP-bound chain cannot silently downgrade to bearer and a bearer chain
  cannot acquire a binding at rotation. The rotated access token binds to the
  presented proof via `issue`, keeping the chain sender-constrained to the new key.

Coverage: `crates/oauth-as/tests/dpop.rs` now has
`a_confidential_client_may_rotate_a_bound_chain_onto_a_different_key` (success +
rebind to the new key) alongside a new public-client twin
`a_public_client_refresh_chain_cannot_be_rebound_to_another_key` (strict
rejection); the no-proof-downgrade and bind-an-unbound-chain tests are unchanged
and still reject for both client types.

**Code:** `crates/oauth-as/src/server.rs` (`refresh_token`, the DPoP binding check).

---

## Passing (for reference)

`happy-flow`, discovery, PKCE required/verifier/plain-rejected, PAR mandatory,
`iss` response param, DPoP proof `nbf`/`exp`/`iat` windows, DPoP PAR/auth-code
binding success, auth-code single-use/expiry/client-binding, most client-assertion
negative tests (`wrong-aud`, `exp-in-past`, `no-sub`, `nbf` windows),
response-type restrictions, and the PAR audience test for the PAR-endpoint URL —
all PASS.
