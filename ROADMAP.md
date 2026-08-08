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

### 0.2.0: close the operational gaps and the cheap wins

The theme is "things a real deployment needs that we currently make
impossible", plus the two low cost specs with outsized security value.

- Rate limiting seam
- Audit and event hooks
- RFC 9207 `iss` authorization response parameter
- RFC 8707 resource indicators, wired into the RFC 9068 `aud` claim
- RFC 7591 dynamic client registration
- Client secret verifier seam, so hosts can store hashes
- Multi tenant issuer paths (RFC 8414 s3.1 well known placement)
- Key rotation lifecycle for the JWT feature

### 0.3.0: the enterprise authentication tier

The theme is "deployments whose policy forbids shared secrets". Together these
unlock FAPI 2.0 as an achievable target, which is the one genuine external
certification available to a non OIDC AS.

- RFC 7523 `private_key_jwt` and `client_secret_jwt`
- RFC 8705 mTLS client authentication and certificate bound tokens
- RFC 9449 DPoP
- RFC 9126 PAR

### 0.4.0: delegation, granularity, and a new external judge

- RFC 9728 protected resource metadata, which also makes the `authgent`
  scanner applicable and buys a third party judge we cannot otherwise get
- RFC 8693 token exchange
- RFC 9396 RAR
- RFC 9101 JAR

### 1.0.0: stability, not features

1.0 is earned by the API holding still and the evidence being complete, not by
the feature list getting longer. Criteria:

- No breaking change to `Storage` or the public API for two minor releases
- Mutation testing clean, with every survivor killed or recorded as equivalent
- A `Storage` conformance harness the crate exports, so a host can prove its
  own implementation satisfies the atomicity contract the server depends on.
  This matters more than it sounds: a host that implements `take_*` as read
  then delete gets undetectable refresh token double spend on a multi node
  deployment, and nothing in the crate can currently catch that.
- FAPI 2.0 `plain_oauth` certification attempted, if and only if a real
  consumer wants it. Pursuing a certification nobody asked for is how a
  roadmap becomes theatre.

## The rule this list follows

Nothing goes on this roadmap because a competitor has it. Each item is here
because it answers a question a real deployment asks, and the release it sits
in reflects how badly a deployment is blocked without it. If an item cannot
say what it buys, it comes off the list.
