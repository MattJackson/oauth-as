# oauth-as: the gap list, and what gets built next

Written 2026-08-08. This is an honest inventory of what a mature third party
authorization server does that this crate does NOT do yet, ordered into
releases. It exists so that "what is missing" is a list rather than a feeling,
and so that nobody has to discover a gap by hitting it in production.

Each item says what it BUYS. An item that cannot answer that question does not
belong on a roadmap.

## Where 0.1.0 stands

Implemented: RFC 6749 authorization code (OAuth 2.1 constrained) and client
credentials, RFC 8628 device grant, RFC 6749 s6 refresh rotation, RFC 7636
PKCE, RFC 8414 metadata, RFC 7662 introspection, RFC 7009 revocation, RFC 9068
JWT access tokens with a JWKS behind an optional feature.

That is a complete, coherent OAuth 2.1 core. What it is NOT is the surface area
of Keycloak, Ory Hydra, Auth0 or Okta, and the difference is worth naming
precisely rather than hand waving at "enterprise features".

## The gap, by category

### 1. Client authentication we cannot do

Today: `client_secret_basic`, `client_secret_post`, and public clients (`none`).

Missing:
- **RFC 7523 JWT client assertions** (`private_key_jwt`, `client_secret_jwt`).
  This is the single biggest interop gap. It is REQUIRED by FAPI 2.0, expected
  by most enterprise deployments, and it is what lets a client authenticate
  without ever transmitting a shared secret.
- **RFC 8705 mTLS client authentication** (`tls_client_auth`,
  `self_signed_tls_client_auth`), plus certificate bound access tokens. Also
  FAPI 2.0. Needs a seam for the host to pass the verified client certificate
  in, since TLS termination is the host's job in this design.

Consequence today: a deployment whose security policy forbids shared secrets
cannot use this crate at all.

### 2. Sender constrained tokens

Today: bearer tokens only. A stolen token is usable by whoever stole it.

Missing:
- **RFC 9449 DPoP.** Application layer proof of possession, binding a token to
  a key the client holds. This is the highest value security feature not yet
  present, and it is the one that most changes the consequences of a token
  leak.
- **RFC 8705 certificate bound tokens** (the other half of mTLS).

Note the metadata validator in our own harness already accepts a `DPoP`
`token_type`, so the shape is anticipated.

### 3. Request integrity and mix-up defences

Missing:
- **RFC 9207 `iss` in the authorization response.** Cheap, small, and it is the
  standard mix-up attack countermeasure named by RFC 9700 s4.4. A client
  talking to several ASes currently cannot tell which one answered. This was
  raised as an informational finding in the security review.
- **RFC 9126 PAR (pushed authorization requests).** The client pushes the
  request to the AS and gets a handle, so authorization parameters never
  traverse the browser. Required by FAPI 2.0.
- **RFC 9101 JAR (signed request objects).** Signed, optionally encrypted
  request objects.

### 4. Audience and permission granularity

Missing:
- **RFC 8707 resource indicators.** Lets a client say which resource server a
  token is for, so the AS can scope the audience down. Without it every token
  is implicitly good at every resource server that trusts this issuer, which is
  a real blast radius problem, and it interacts directly with the RFC 9068
  `aud` claim we now emit.
- **RFC 9396 RAR (rich authorization requests).** Structured authorization
  detail beyond scope strings. Needed by anything doing payments or
  transaction level consent.

### 5. Client lifecycle

Missing:
- **RFC 7591 dynamic client registration** and **RFC 7592 registration
  management.** The code already anticipates this (`register_client` is
  documented as the layer 7591 sits on). Needed by MCP, by any multi tenant
  deployment, and by the OIDF test suites, which register clients dynamically.
- **Client secret hashing at rest.** Secrets are currently compared against
  whatever the host stored. The crate should offer a verifier seam so a host
  can store a hash rather than the secret.

### 6. Protected resource side

Missing:
- **RFC 9728 protected resource metadata.** Worth calling out specifically:
  implementing it is what would make the `authgent` MCP OAuth scanner
  applicable to this project. That scanner currently bails immediately because
  no RFC 9728 document exists, which is exactly why it could not be wired into
  CI. This is the cheapest route to an ADDITIONAL genuine third party judge,
  which is otherwise a hard thing to buy.
- **RFC 8693 token exchange.** Delegation and impersonation; the basis of most
  service to service token flows.

### 7. Operational seams the library does not offer

These came out of the adversarial security review and are not spec gaps, they
are "a real deployment needs this and we make it impossible" gaps:

- **A rate limiting seam.** RFC 8628 s5.1 makes user code entropy adequate only
  IN COMBINATION WITH rate limiting, and the library currently offers the host
  nowhere to put it.
- **An audit and event hook.** No way to observe issuance, refusal, or
  suspected replay. Every real AS deployment needs this for incident response,
  and a security feature nobody can observe is a security feature nobody can
  trust.
- **Key rotation lifecycle** for JWT signing: overlapping validity, a published
  next key, retirement.
- **Multi tenancy.** An issuer with a path component is currently mishandled at
  the well known URI (RFC 8414 s3.1 requires the well known string to be
  inserted between host and path).
- **Session and consent management**, including remembered consent and consent
  revocation.

### 8. Deliberately NOT on the roadmap

- **OpenID Connect.** id_token issuance, UserInfo, a claims model, a user
  profile store and a locale layer are all host concerns this design
  deliberately pushed out. Adding them to earn a Basic OP certification badge
  would produce a badge that is true and substantively misleading. This gets
  revisited only if this crate genuinely becomes an identity provider.
- **CIBA.** Backchannel authentication is an OIDC extension and follows the
  same reasoning.

## Release plan

The shape: **0.2.0 through 0.9.0 close the gap, one coherent slice per
release, until this crate does everything third party tooling and third party
clients expect of an OAuth 2.1 authorization server. Then we stop adding
features, test hard, and cut 1.0.0 when it is genuinely solid.**

Each release is a slice that stands on its own, so a consumer can adopt at any
point and get something coherent rather than half of two things. Breaking
changes to `Storage` and the public API are expected through the 0.x series
and are exactly what the 0.x number is for; they stop at 1.0.

### 0.2.0: operational seams, and the cheap security wins

The theme is "things a real deployment needs that we currently make
impossible". None of this is exotic; all of it is blocking.

- Rate limiting seam. RFC 8628 s5.1 makes user code entropy adequate only IN
  COMBINATION WITH rate limiting, and today the host has nowhere to put it.
- Audit and event hooks: issuance, refusal, suspected replay. A security
  feature nobody can observe is a security feature nobody can trust.
- RFC 9207 `iss` authorization response parameter (mix up defence).
- RFC 8707 resource indicators, wired into the RFC 9068 `aud` claim.
- Client secret verifier seam, so hosts can store a hash rather than a secret.
- Multi tenant issuer paths (RFC 8414 s3.1 well known placement).
- Key rotation lifecycle for the JWT feature: overlapping validity, published
  next key, retirement.

### 0.3.0: client lifecycle

- RFC 7591 dynamic client registration.
- RFC 7592 registration management.
- Registration access tokens, and the policy seam deciding who may register.

Unblocks: MCP, multi tenant deployments, and the OIDF suites, which register
clients dynamically rather than by hand.

### 0.4.0: client authentication without shared secrets

The biggest interop gap in the crate today. Until this lands, a deployment
whose security policy forbids shared secrets cannot use it at all.

- RFC 7523 `private_key_jwt` and `client_secret_jwt`.
- RFC 8705 mTLS client authentication (`tls_client_auth`,
  `self_signed_tls_client_auth`), with a seam for the host to pass in the
  verified client certificate, since TLS termination is the host's job here.

### 0.5.0: sender constrained tokens

Changes what a token leak costs, which is the highest value security work on
this list.

- RFC 9449 DPoP.
- RFC 8705 certificate bound access tokens (the other half of mTLS).
- Resource server verification helpers, so an RS can actually check the
  binding rather than being told to.

### 0.6.0: request integrity

- RFC 9126 PAR, so authorization parameters never traverse the browser.
- RFC 9101 JAR, signed and optionally encrypted request objects.

At this point FAPI 2.0 `plain_oauth` becomes an achievable target, which is
the one genuine external certification available to a non OIDC AS.

### 0.7.0: delegation, and a new external judge

- RFC 9728 protected resource metadata. Worth its own line: its ABSENCE is
  precisely why the `authgent` scanner bails on us today, so implementing it
  buys an additional independent judge, and independent judges are the hardest
  thing to buy for a plain OAuth AS.
- RFC 8693 token exchange.

### 0.8.0: granularity and session lifecycle

- RFC 9396 RAR, structured authorization detail beyond scope strings.
- Session and consent management: remembered consent, consent revocation,
  and a cascade so revoking a grant kills what it issued.
- RFC 9470 step up authentication challenges.

### 0.9.0: prove it against the outside world

No new protocol surface. This release exists to run everything external at the
crate and fix what falls out.

- FAPI 2.0 `plain_oauth` conformance run against the OIDF suite.
- The `authgent` scanner, now applicable because of 0.7.0.
- A headless OAuch spike, or a written record of why it remains impossible.
- The `Storage` conformance harness EXPORTED for hosts, so a host can prove
  its own implementation satisfies the atomicity contract. This matters more
  than it sounds: a host implementing `take_*` as read then delete gets
  undetectable refresh token double spend on a multi node deployment, and
  nothing in the crate can currently catch that.
- Interop testing against real third party clients beyond the pinned `oauth2`
  crate.

### 1.0.0: earned, not scheduled

1.0 is not a feature release and gets no new protocol surface. It is cut when
we feel solid, and "solid" is defined here so that feeling has to survive
contact with evidence:

- No breaking change to `Storage` or the public API across 0.9.x.
- Mutation testing clean: every surviving mutant killed, or recorded in
  writing as equivalent with the reason.
- Every finding from an adversarial security review resolved, and a fresh
  review run against the finished 0.9 surface.
- The full conformance suite green, including whatever external tooling 0.9.0
  proved applicable.
- Documentation complete enough that a stranger can adopt the crate without
  reading its source.

If those hold and it still does not feel solid, it does not ship. The feeling
is allowed to veto the checklist. It is not allowed to substitute for it.

## The rule this list follows

Nothing goes on this roadmap because a competitor has it. Each item is here
because it answers a question a real deployment asks, and the release it sits
in reflects how badly a deployment is blocked without it. If an item cannot
say what it buys, it comes off the list.
