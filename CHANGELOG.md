# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Publishing note, so this file is not read out of context: per `GOAL.md`, the crate publishes to
crates.io at **0.9.0**, not 0.1.0. Versions 0.1.0 through 0.8.0 are built, tested, and pushed
through the `dev` -> `qa` -> `main` promotion pipeline, but they are not published; only 0.0.1 and
whatever version is current at each real crates.io release appear as published on crates.io.

## [Unreleased]

Nothing merged to `dev` since 0.1.0 as of this writing.

## [0.1.0] - 2026-08-08 (built and tested, not published to crates.io)

The first real release: a complete, coherent OAuth 2.1 core, plus the independent conformance
harness that judges it.

### Added

- RFC 6749 section 4.1 authorization code grant under OAuth 2.1 constraints: PKCE required,
  `S256` only (an absent `code_challenge_method` is refused rather than defaulted to `plain`, per
  RFC 7636 section 4.3), exact redirect URI matching, single-use codes, and replay of a spent code
  revoking the tokens it already minted (RFC 6749 section 4.1.2, RFC 9700 section 4.1.1).
- RFC 8628 device authorization grant as a full state machine: `authorization_pending`,
  `slow_down` with the mandated interval increase, `expired_token`, `access_denied`, single-use
  redemption, and user code normalization per section 6.1.
- RFC 6749 section 6 refresh token rotation: single use, absolute chain lifetime.
- RFC 6749 section 4.4 client credentials grant, confidential clients only, no refresh token
  (section 4.4.3).
- RFC 7636 PKCE primitives, verified against the RFC's Appendix B test vector.
- RFC 8414 authorization server metadata, derived from `ServerConfig` rather than hand written, so
  an advertised endpoint or capability is one the server actually has.
- RFC 7662 token introspection, and RFC 7009 token revocation (idempotent, ownership verified,
  `token_type_hint` treated as an optimization only).
- Client authentication: `client_secret_basic`, `client_secret_post`, and public clients (`none`).
- A `store::Storage` trait the host implements, plus `store::MemoryStorage` for tests and single
  process embedding.
- An optional `http` feature, off by default, adding an axum router over
  `AuthorizationServer` for hosts that would rather not write the wire layer themselves. Nothing
  in the library depends on it.
- `crates/oauth-as-conformance`: an independent black-box conformance harness, written by an
  author who could not see this crate's source, never published. Vendored RFC test vectors with
  per-entry citations, response-shape validators transcribed from RFC 6749 section 5 and RFC 8628
  sections 3.2 and 3.5, and a drive of the pinned third-party client `oauth2 = "=5.0.0"` through a
  full device flow and a full authorization-code-with-PKCE flow against the live server.
- `scripts/oauth-conformance.sh`, with `--selftest` (proves the gate can go red on both the
  hermetic vector suite and the black-box suite before any green is trusted) and `--check` (serves
  the AS and runs the black-box suite against it).
- A three-stage CI promotion pipeline: `dev` runs the fast gate (fmt, clippy, test) on every push
  and pull request; `qa` runs the full suite (MSRV verification against Rust 1.86, the conformance
  self-test, the live black-box conformance check, a packaging dry run, and a non-blocking
  mutation-testing report) on every push to `qa`; `main` publishes to crates.io only by explicit,
  manually approved `workflow_dispatch`, never on push.
- Dual license, `MIT OR Apache-2.0`, from this release onward.

### Notes

- `GOAL.md` records the honest state of the ten gates that define "done" for this project;
  several are not yet closed at 0.1.0, including the RFC 9068 JWT access token feature, the HTTP
  serve shim required for a live `--check` run, and mutation testing.
- `KICKOFF.md` and `ROADMAP.md` document research into third-party conformance tooling: there is
  no OAuth 2.1 certification programme in existence, the OpenID Foundation suite has zero
  references to RFC 8628, and neither `authgent` nor OAuch could be wired into CI honestly as of
  2026-08-08. The independent judges of this release are the vendored RFC vectors and the pinned
  `oauth2 = "=5.0.0"` client, and nothing stronger is claimed.

## [0.0.1] - 2026-08-08

Published to crates.io. A placeholder release only: it reserves the crate name, contains no
protocol implementation, and says so in its own docs and README. Superseded by the unpublished
0.1.0 and later work in this repository; do not depend on 0.0.1 for anything functional.

No comparison links for 0.1.0 or Unreleased: neither has a git tag yet, since 0.1.0 has not been
promoted through `main` or published. Links will be added once tags exist.

[0.0.1]: https://crates.io/crates/oauth-as/0.0.1
