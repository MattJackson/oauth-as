# External tooling: what has been run at this AS, and what cannot be

Written for 0.9.0, whose entire purpose (ROADMAP.md) is "prove it against the outside world". It
is a record of investigation, not a marketing page, so it records refusals and negative results in
the same detail as successes. Where a claim here is not backed by a citation to a primary source,
it says so.

An authorization server decides who gets access to everything else. The scarcest thing this
project can buy is a judgement it did not write. That is what this file is an inventory of.

## Summary

| Tool | Runnable here | Status |
| ---- | ------------- | ------ |
| Vendored RFC vectors, `crates/oauth-as-conformance` | yes | in CI, gate proven red |
| `oauth2 = "=5.0.0"` (Rust, ramosbugs) | yes | in CI, gate proven red |
| `golang.org/x/oauth2 v0.36.0` (Go project) | yes | in CI, gate proven red |
| `authgent` MCP-OAuth scanner 0.3.4 | yes, via an RFC 9728 fixture | in CI, gate proven red, 3 accepted findings |
| OIDF FAPI 2.0 Security Profile suite | not yet: see below | achievable, blocked on a named list |
| OAuch | see the OAuch section | not runnable headless |
| An OAuth 2.1 certification programme | no | does not exist |

## 1. There is still no OAuth 2.1 certification programme

Unchanged and worth restating because it frames everything else: OAuth 2.1 is an Internet Draft.
There is no certification, no official suite and no official vectors, so no implementation of
OAuth 2.1 can hold a certification, including this one.

## 2. FAPI 2.0 Security Profile: the verdict

**Verdict: a conformance RUN is achievable, headless, on a developer machine, with no public
hostname and no publicly trusted certificate. It is not achievable TODAY, and the reasons are a
short, specific list rather than a shrug. Formal CERTIFICATION is a separate paid step.**

This corrects the belief recorded in `qa.yml` and `crates/oauth-as-conformance/Cargo.toml` that
the OIDF suite "presupposes OpenID Connect semantics" and therefore cannot test this crate. It
can. The `plain_oauth` variant exists and is certifiable.

Evidence below is from the suite source (`https://gitlab.com/openid/conformance-suite`, verified
at master commit `6b8b809dd07df6ca8b4481a9e921bf48b9ffbffe`, 2026-08-07), the FAPI 2.0 Security
Profile Final specification (`https://openid.net/specs/fapi-security-profile-2_0-final.html`,
Final, 22 February 2025), and the OpenID Foundation certification pages.

### 2.1 The `plain_oauth` variant is real, and it is certifiable

Test plan ids, from the `@PublishTestPlan` annotations in the suite source:

- `fapi2-security-profile-final-test-plan`
  (`src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalTestPlan.java`)
- `fapi2-security-profile-id2-test-plan`
  (`src/main/java/net/openid/conformance/fapi2spid2/FAPI2SPID2TestPlan.java`)

The variant dimensions are declared by `@VariantParameters` on
`src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalServerTestModule.java`. The
one that matters is `openid`, from
`src/main/java/net/openid/conformance/variant/FAPIOpenIDConnect.java`, whose values are
`plain_oauth` and `openid_connect`, and whose own description reads: "If your server supports
issuing id_tokens, pick 'openid connect'. Otherwise pick plain_oauth."

Two consequences confirmed in the source rather than assumed:

- The OIDC-specific discovery checks are gated on that variant.
  `AbstractFAPI2SPFinalDiscoveryEndpointVerification.performEndpointVerification()` branches on
  `isOpenId`: OIDC goes to `/.well-known/openid-configuration`, and everything else goes through
  `CheckOauthDiscEndpointDiscoveryUrl` to **`/.well-known/oauth-authorization-server`**, checked
  against `RFC8414-3.3` and `RFC8414-6.2`. `id_token_signing_alg_values_supported` is only checked
  when `isOpenId`.
- `FAPI2SPFinalTestPlan.certificationProfileName()` returns a real certification profile name for
  `plain_oauth` (for example "FAPI2SP OP private key + DPoP") rather than refusing, so this is a
  certifiable configuration and not merely a runnable one.

The OpenID Foundation's own CI runs exactly this string (`.gitlab-ci/run-tests.sh`):

```
fapi2-security-profile-final-test-plan[openid=plain_oauth][client_auth_type=mtls][sender_constrain=mtls][fapi_profile=plain_fapi]
```

FAPI 2.0 Message Signing is a separate specification, a separate plan
(`fapi2-message-signing-final-test-plan`) and a separate certification. It is not required here.

Note also `client_auth_type` (`src/main/java/net/openid/conformance/variant/ClientAuthType.java`)
admits only `private_key_jwt` and `mtls` for FAPI 2; `none` and every `client_secret_*` method are
excluded by `@VariantNotApplicable`. And `sender_constrain`
(`FAPI2SenderConstrainMethod.java`) admits `mtls` or `dpop`. Choosing
`client_auth_type=private_key_jwt` with `sender_constrain=dpop` is a valid certification profile
and avoids mTLS entirely, which matters here because TLS termination is the host's job in this
design.

### 2.2 It runs headless and locally

- **No publicly trusted certificate is required.** The suite's outbound HTTP client trusts all
  server certificates and disables hostname verification:
  `src/main/java/net/openid/conformance/condition/AbstractCondition.java`, `createHttpClient()`,
  installs an `X509TrustManager` with an empty `checkServerTrusted` and sets
  `NoopHostnameVerifier.INSTANCE`. The suite's own front end is self-signed by default
  (`nginx/Dockerfile` generates an `openssl req -x509` cert with `CN=localhost`).
- **No public hostname is required.** The default base URL is
  `https://localhost.emobix.co.uk:8443` (`docker-compose.yml`), a public DNS name that resolves to
  `127.0.0.1`; the suite wiki has you add it to `/etc/hosts`. `docker-compose-localtest.yml`
  stands the whole thing up against a containerised provider whose certificate is self-signed for
  a Docker-internal hostname, with no inbound reachability at all. Honest caveat: that
  local-provider CI job runs OIDCC plans, not FAPI2; OIDF's own FAPI2 CI runs against Authlete's
  public sandbox. Nothing in the FAPI2 modules changes the transport assumptions, but a fully
  local FAPI2 job is not demonstrated in-repo.
- **The browser step is genuinely headless.**
  `src/main/java/net/openid/conformance/frontchannel/BrowserControl.java` drives an in-JVM
  `HtmlUnitDriver` over `org.htmlunit.WebClient` (`pom.xml` declares `selenium-java`,
  `org.htmlunit:htmlunit`, `htmlunit3-driver`). No external browser and no display. The test
  configuration JSON carries a top-level `browser` array of URL-matched task lists whose commands
  are `["text"|"click", "id"|"name"|"xpath"|"css"|"class", <selector>, <value>]`.
- **There is a supported runner and a REST API.** `scripts/run-test-plan.py`, with
  `scripts/conformance.py` as the REST client and `scripts/test_plan_parser.py` parsing the
  `plan[var=val]:module` syntax. The API is `POST api/plan`, `POST api/runner`,
  `GET api/runner/{id}/wait-state`, `GET api/plan/{plan_id}/certificationpackage`. Authentication
  is a bearer token from `CONFORMANCE_TOKEN`, and the suite wiki states a token is not necessary
  when the suite is deployed locally (`fintechlabs.devmode=true`, which `docker-compose.yml`
  already sets). There is an official tutorial repository at
  `https://gitlab.com/openid/conformance-suite-automated-testing-tutorial`.

### 2.3 What is still missing here, and this is the actual blocker

Not infrastructure. These:

1. **A resource server.** `resource.resourceUrl` is a required configuration field on
   `AbstractFAPI2SPFinalServerTestModule`, and the modules call `CallProtectedResource` tagged
   `FAPI2-SP-FINAL-5.3.4-2`. OIDF's own instructions
   (`https://openid.net/certification/certification-fapi_op_testing/`) say "A resource server URL
   must be provided. This must be a simple GET endpoint that returns JSON." This crate is an
   authorization server. The RS would have to be a fixture, exactly as the RFC 9728 fixture is,
   and it would have to actually verify a sender-constrained token, which is more than the RFC
   9728 fixture does.
2. **HTTPS.** FAPI 2.0 s5.3.2.2-8 forbids the `http` scheme outside loopback, and s5.2 requires
   TLS 1.2+ with BCP 195 cipher suites. This crate does not own a listener at all, so this is an
   example/fixture concern, but it is work that does not exist yet.
3. **Two static clients with distinct keys and certificates**, per
   `@ConfigurationFields` (`client.client_id`, `client.jwks`, `client2.client_id`, `client2.jwks`)
   and the OIDF instructions page.
4. **`require_pushed_authorization_requests` present as a boolean** in the metadata document. The
   suite's `CheckDiscRequirePushedAuthorizationRequestsIsABoolean` requires it to be present and
   boolean, not necessarily `true`; `CheckDiscEndpointPARSupported` requires
   `pushed_authorization_request_endpoint`. This crate emits both, and both are `Option`, so a
   fixture must set them.
5. **`authorization_response_iss_parameter_supported: true`.** The FAPI 2.0 text does not name
   that metadata member (s5.3.2.2-7 only says return `iss` per RFC 9207), but the suite requires
   the flag at `ConditionResult.FAILURE` via
   `EnsureAuthorizationResponseIssParameterSupportedIsTrue`. This crate already emits it as a
   plain `bool`.
6. **Two hard numbers to check against the implementation**: an authorization code lifetime of at
   most 60 seconds (s5.3.2.1-11), and a `request_uri` `expires_in` under 600 seconds (s5.3.2.2-12).
7. **A refresh-token policy inversion worth reading twice.** FAPI 2.0 s5.3.2.1-9 says the AS
   "shall not use refresh token rotation" except in extraordinary circumstances. This crate rotates
   by default and treats reuse as family revocation, which OAuth 2.1 s6.1 and RFC 9700 s4.14.2
   call for. These are in genuine tension. A FAPI 2.0 run would need rotation configurable off,
   which today it is not.
8. **PAR must be mandatory.** s5.3.2.2-3: the AS shall reject authorization requests not sent via
   PAR.

Not exercised by this plan, and therefore not a blocker: RFC 9068 JWT access tokens (the RS is
yours, so opaque is fine), RFC 8707 resource indicators, and RFC 7591 dynamic client registration
(FAPI2 SP plans have no `client_registration` variant; clients are static).

### 2.4 Certification, as distinct from running the tests

Running the suite requires no membership, no payment and no agreement; nothing in the repository
or the documentation conditions test execution on any of them.

Certification does. `https://openid.net/certification/how-to-submit-your-certification-request/`
describes: run the tests, use "Publish for certification" to produce a log ZIP, obtain a payment
code, submit at `https://submissions.openid.net/`, and sign a Declaration of Conformance via
DocuSign. `https://openid.net/certification/fees/` gives FAPI 2 certification as USD 1000 for OIDF
members and USD 5000 for non-members per new FAPI deployment, and notes that open source
implementations may qualify for a fee waiver.

One thing could NOT be confirmed from any primary source, and is stated as unknown rather than
assumed: whether OIDF accepts logs produced by a LOCALLY run suite for a certification
submission, as opposed to logs from the hosted `https://www.certification.openid.net/`. The
certification pages do not address it. Treat local runs as pre-verification.

### 2.5 The next step, precisely

Not attempted here, deliberately: a half-run reported as progress is worse than an honest "not
yet". The next step is a single, checkable piece of work, and it is item 1 above:

> Build a FAPI 2.0 fixture that serves the AS over HTTPS with a self-signed certificate, registers
> two static clients with distinct `private_key_jwt` keys, requires PAR, and stands up a protected
> resource endpoint that returns JSON only for a valid DPoP-bound access token. Then run
> `./scripts/run-test-plan.py 'fapi2-security-profile-final-test-plan[openid=plain_oauth][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]' config.json`
> against a locally deployed suite and read the failures.

That is a release's worth of work, not a task, and it is honest to say so. It is the only genuine
external certification available to a non-OIDC authorization server, and this crate is now close
enough that the remaining list is finite and written down.

## 3. `authgent`: run, and what it found

See the header of `scripts/oauth-mcp-lint.sh` for the full argument about why standing up an RFC
9728 fixture to unlock this scanner is legitimate rather than a dodge, and for the per-finding
reasoning behind `authgent-baseline.json`. In short:

- The scanner is pinned at `authgent-server==0.3.4` and wired into `qa.yml` through the composite
  action `authgent/authgent/.github/actions/mcp-lint@v0.3.4`, which was verified to resolve (the
  raw `action.yml` at that tag returns 200). Their marketplace README advertises
  `authgent/mcp-lint-action@v1`, a repository that does not exist; that reference is not used.
- **This project is not an MCP server and never claims to be.** The scanner's MCP verdict is
  quoted nowhere. What is quoted is that its RFC 8414 / RFC 7636 / RFC 9207 / RFC 8707 / RFC 7591
  checks were applied to this crate's metadata document by a tool nobody here wrote.
- Three findings, recorded rather than silenced: `MCP-AUD-001` (error) wants
  `resource_indicators_supported`, a member RFC 8707 does not register and this crate does not
  emit; `MCP-DCR-001` and `MCP-REFRESH-001` (warnings) want a registration endpoint and DPoP
  algorithms, both implemented in the crate and both deliberately off in the conformance example.
- Two limitations of the tool, found by reading its source, that stop a green here meaning more
  than it does. Its `MCP-PKCE-002` live probe only flags on a 302/303 response, so an AS that
  rejects its unknown probe client with a 400 makes that check unreachable rather than passed. And
  its composite action declares a `fail-on` input that it never passes to the CLI, so the
  threshold is always the default `error` regardless of what a workflow sets.

## 4. OAuch

See the OAuch entry in `.github/workflows/qa.yml` for the current assessment and the date it was
last checked.

## 5. Third-party clients

Two now, in two languages, both pinned exactly, both proven able to go red:

- `oauth2 = "=5.0.0"` (Rust, ramosbugs/oauth2-rs), driven by
  `crates/oauth-as-conformance/tests/client_drive.rs`: full device flow, full authorization code
  with PKCE.
- `golang.org/x/oauth2 v0.36.0` (the Go project), driven by
  `crates/oauth-as-conformance/interop/go`: device flow, authorization code with PKCE, refresh
  with rotation, and client credentials. The last two are grants the Rust drive does not cover,
  which is the point of a second judge.

Candidates evaluated and NOT adopted, with the reason, so this is not re-derived later:

- `github.com/coreos/go-oidc` and the Rust `openidconnect` crate both hardcode
  `/.well-known/openid-configuration` and exist to verify an `id_token`. This AS is not an OIDC
  provider, so neither can form an opinion about it.
- `oauth2c` (cloudentity/SecureAuthCorp) is a capable CLI covering device, PAR, DPoP and PKCE, and
  it does not require TLS. Its discovery is OIDC-only
  (`internal/oauth2/well_known.go` hardcodes `/.well-known/openid-configuration`), so it can only
  be used by naming every endpoint on the command line, which throws away the metadata document as
  a source of truth. Worth revisiting if it grows RFC 8414 discovery.
- Python `authlib` is the strongest remaining candidate and is deliberately left as future work
  rather than claimed: its `authlib.oauth2.rfc8414.AuthorizationServerMetadata.validate()` is an
  independent implementation of the RFC 8414 section 2 rules, which is a judgement of a kind
  nothing here currently makes. It also natively permits `http://127.0.0.1:` origins, so no
  insecure-transport override is needed.
