# oauth-as

An embeddable OAuth 2.1 Authorization Server library for Rust.

This crate is the AUTHORIZATION SERVER half of OAuth: it registers clients, runs
grant state machines, issues, introspects and revokes tokens, and produces
exactly the wire shapes the RFCs define. It is a LIBRARY, not a server binary.
The host owns the HTTP listener, TLS, rate limiting, persistence, and the
consent experience. The host hands request parameters to `AuthorizationServer`
and serializes the returned response and error types, which carry their own
`serde` shapes and HTTP status codes.

An optional `http` feature ships an axum router for hosts that would rather not
write the wire layer themselves. It is off by default and nothing in the
library depends on it.

## What is implemented

Protocol:

- RFC 6749 section 4.1 authorization code grant, under the OAuth 2.1
  constraints: PKCE required, `S256` only, exact redirect URI matching, single
  use codes, and replay of a code revoking the tokens it already minted.
- RFC 8628 device authorization grant, as a full state machine:
  `authorization_pending`, `slow_down` with the mandated interval increase,
  `expired_token`, `access_denied`, single use redemption, and user code
  normalization per section 6.1.
- RFC 6749 section 6 refresh rotation: single use, absolute chain lifetime.
- RFC 6749 section 4.4 client credentials, confidential clients only, no
  refresh token (section 4.4.3).
- RFC 7636 PKCE, verified against the appendix B vector.
- RFC 8414 authorization server metadata, derived from configuration so that an
  advertised endpoint or capability is one the server actually has.
- RFC 7662 introspection and RFC 7009 revocation.

Design:

- A storage seam (`store::Storage`) the HOST implements, plus
  `store::MemoryStorage` for tests and single process embedding. This crate
  never assumes what the host's persistence looks like.
- Nothing is allocated until the host constructs an `AuthorizationServer`, so
  an embedding host pays nothing until its configuration enables the feature.
- The default build has five dependencies: `serde`, `serde_json`, `getrandom`,
  `sha2`, `base64`. None of them implies an async runtime, an HTTP stack, or a
  persistence layer.

## Minimum supported Rust version

1.75, and this is the MEASURED floor rather than a guess: 1.74 fails only on
return-position `impl Trait` in the `Storage` trait, and 1.75 and 1.80 compile
clean. Going lower would mean boxing every storage future, which is a heap
allocation on every storage call, and that is a price every consumer would pay
forever to support toolchains older than December 2023.

Optional features may carry their own higher floors, since they pull in
dependencies this crate does not control. Those are documented per feature.

## Maturity: read this before depending on it

The 0.x version number is deliberate. Honesty about what has and has not been
demonstrated matters more than polish, and for an authorization server the
standard is higher than usual.

### What IS proven, by things you can run yourself

- **RFC published test vectors, byte exact.** Inputs and expected outputs are
  taken verbatim from the RFCs, so the oracle is the spec author rather than
  this codebase.
- **Schema validation transcribed from the RFCs.** Every body the AS emits is
  validated against schemas transcribed clause by clause from RFC 6749
  section 5 and RFC 8628 sections 3.2 and 3.5.
- **An independently authored conformance harness.**
  `crates/oauth-as-conformance` was written by an author who could not see this
  crate's source. That matters because this crate's own tests were written by
  this crate's author: the judge was arms length, but the CHOICE OF WHAT TO
  TEST was not. The harness closes that gap. It drives the AS over HTTP as a
  black box and discovers every endpoint from the RFC 8414 metadata document,
  so it also proves the advertised endpoints match reality.
- **A pinned third party client as the judge.** `oauth2 = "=5.0.0"`, a widely
  used OAuth 2 CLIENT library, completes a full device flow and a full
  authorization code with PKCE flow against this AS. That library, not this
  repository's assertions, decides whether the responses are spec legal. It is
  pinned exactly on purpose: a silent client upgrade must never change what
  "conformant" means.
- **Gates proven able to fail.** `scripts/oauth-conformance.sh --selftest`
  demonstrates that a corrupted vector expectation fails the vector suite, and
  that a deliberately nonconformant stub AS fails the black box suite, BEFORE
  any green from those gates is trusted. A gate nobody has seen go red is a
  gate nobody should trust.
- **An adversarial security review**, whose findings are recorded with the RFC
  section that settles each one, and whose fixes each began as a test that
  reproduced the attack and failed.

### What is NOT proven, and will not be claimed

- **There is no OAuth 2.1 certification programme in existence.** OAuth 2.1 is
  still an Internet Draft. No implementation of it, this one included, can hold
  a certification, and any project claiming otherwise is describing something
  else.
- **No third party conformance tool has been run against this AS**, because
  none that applies exists. This was researched rather than assumed:
  - The OpenID Foundation suite tests OIDC and FAPI profiles. Its FAPI 2.0 plan
    does have a `plain_oauth` variant, so a non-OIDC AS CAN be certified, but
    that profile requires PAR, sender constrained tokens, `private_key_jwt` or
    mTLS, and a browser driven flow, and it tests none of the device grant.
  - The OIDF suite contains zero references to RFC 8628. Nothing external tests
    the device grant polling state machine at all.
  - `authgent` is an MCP OAuth scanner, not the RFC 8414 discovery linter it is
    sometimes described as. It fetches RFC 9728 protected resource metadata
    first and skips every remaining check when that is absent, which it always
    will be for a plain AS.
  - OAuch has no headless or CI mode; its device flow ends in a browser popup.
  So the independent judges here are the vendored RFC vectors and the pinned
  third party client. That is a real bar, and it is not the same thing as
  certification. We are not going to imply that it is.
- **Bolting OIDC on to earn a Basic OP badge was considered and rejected.** It
  would mean id_token issuance, a UserInfo endpoint, a claims model and a user
  profile store, all of which are host concerns this design deliberately pushes
  out. The badge would be true and substantively misleading.

If you need a battle hardened AS today, use one. If you want an embeddable,
host agnostic, storage agnostic OAuth 2.1 core with its evidence laid out in
the open and its gaps stated plainly, this is that, at the maturity the version
number states.

## Repository layout

- `crates/oauth-as` is the published library.
- `crates/oauth-as-conformance` is the independent black box harness: vendored
  RFC vectors, response shape validators, and flows driven by the pinned third
  party `oauth2` client. It contains no code from `oauth-as`, never links
  against it, and is never published.
- `scripts/oauth-conformance.sh` runs the harness. `--selftest` proves the gate
  can go red; `--check` serves the AS and runs the black box suite against it.
- `GOAL.md` states what "done" means for this project as gates that can be
  checked rather than felt.

## License

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
