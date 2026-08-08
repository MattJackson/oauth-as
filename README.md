# oauth-as

An embeddable OAuth 2.1 Authorization Server library for Rust.

This crate is the AUTHORIZATION SERVER half of OAuth: it registers clients, runs
grant state machines, issues and introspects tokens, and produces exactly the
wire shapes the RFCs define. It is a LIBRARY, not a server binary: the host owns
the HTTP listener, the routes, TLS, rate limiting, and persistence. The host
hands request parameters to `AuthorizationServer` and serializes the returned
response and error types, which carry their own `serde` shapes and HTTP status
codes.

## What is implemented

- Core protocol types mirroring the specs in this crate's own structs:
  RFC 6749 (OAuth 2.0 core, under the OAuth 2.1 constraints), RFC 8628 (device
  authorization grant), RFC 7636 (PKCE, S256 only), and RFC 8414 (authorization
  server metadata).
- The RFC 8628 device authorization grant as a full state machine:
  `authorization_pending`, `slow_down` (with the mandated 5 second interval
  increase), `expired_token`, `access_denied`, single-use redemption, and
  user-code normalization per RFC 8628 section 6.1.
- Refresh-token rotation (single use, absolute lifetime), the OAuth 2.1 stance.
- PKCE S256 primitives, verified against the RFC 7636 appendix B vector.
- A storage seam (`store::Storage`) the HOST implements, plus
  `store::MemoryStorage` for tests and single-process embedding. This crate
  never assumes what the host's persistence looks like.

Nothing is allocated until the host constructs an `AuthorizationServer`, so an
embedding host pays zero memory until its configuration enables the feature.

## Maturity: read this before depending on it

The 0.x version number is deliberate. Honesty about what has and has not been
demonstrated matters more than polish, and for an authorization server the
standard is higher than usual.

What IS proven, by tests in this repository:

- RFC-published test vectors, byte-exact: inputs and expected outputs are taken
  verbatim from the RFCs (for example the RFC 7636 appendix B PKCE vector), so
  the oracle is the spec author, not this codebase.
- Schema validation transcribed from the RFCs: every body the AS emits is
  validated against JSON Schemas transcribed clause-by-clause from RFC 6749
  section 5 and RFC 8628 sections 3.2 and 3.5.
- A pinned third-party client, `oauth2 = "=5.0.0"`, drives this AS as a black
  box through its pluggable HTTP-client seam, so that widely used CLIENT
  library, not this repository's own assertions, judges whether the responses
  and error bodies are spec-legal.

What is NOT yet proven:

- The independently authored conformance harness in
  `crates/oauth-as-conformance` (written by an author who never saw this
  crate's code) has NOT yet been run green against this AS. Its black-box half
  requires the AS to be served over HTTP under a documented launch contract
  (see `crates/oauth-as-conformance/src/lib.rs`), and that serve shim does not
  exist yet. The harness's own self-test discipline (every gate proven RED
  before its green is trusted) does run in CI.
- There is no OAuth 2.1 certification programme in existence, so no claim of
  certification is possible for this or any other implementation. The OpenID
  Foundation conformance suite covers OIDC and FAPI profiles only and cannot
  test a plain OAuth 2.1 + RFC 8628 AS.

If you need a battle-hardened AS today, use one. If you want an embeddable,
host-agnostic, storage-agnostic OAuth 2.1 core with its test evidence laid out
in the open, this is that, at the maturity the version number states.

## Repository layout

- `crates/oauth-as` is the published library.
- `crates/oauth-as-conformance` is the independent black-box conformance
  harness: vendored RFC vectors, response-shape validators, and flows driven by
  the pinned third-party `oauth2` client. It contains no code from `oauth-as`,
  never links against it, and is never published.
- `scripts/oauth-conformance.sh` runs the harness. `--selftest` proves the gate
  can go RED (a corrupted vector expectation must fail the suite; a deliberately
  nonconformant stub AS must fail the black-box suite) before any green is
  trusted. `--check` runs the black-box suite against a live AS and fails
  loudly, never vacuously, while the serve shim is absent.

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
