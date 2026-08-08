# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Publishing note, so this file is not read out of context: per `GOAL.md`, the crate publishes to
crates.io at **0.9.0**, not 0.1.0. Versions 0.1.0 through 0.8.0 are built, tested, and pushed
through the `dev` -> `qa` -> `main` promotion pipeline, but they are not published; only 0.0.1 and
whatever version is current at each real crates.io release appear as published on crates.io.

## [Unreleased]

### Added

- **RFC 9068 JWT access tokens** (`at+jwt`, ES256) with an RFC 7517 JWKS document, behind an
  off-by-default `jwt` feature. Opaque tokens remain the default: RFC 9068 is an optional profile,
  not an OAuth 2.1 requirement. The AS-side record is still persisted when signing, keyed by
  whatever the client actually presents, so introspection and revocation keep working and a
  revoked JWT is genuinely dead here rather than merely deprecated. `jwks_uri` is advertised
  exactly when the server signs.
- **The independent conformance harness passes completely**: 8 of 8 black box tests, 9 of 9
  hermetic RFC vector tests, and both pinned third party `oauth2 = "=5.0.0"` client drives. No
  file in the harness was modified to achieve it.
- **RFC 9207 `iss` authorization response parameter**, the mix-up countermeasure RFC 9700 section
  4.4 names, on BOTH the success redirect and every error redirect (RFC 9207 section 2 returns it
  in the authorization response regardless of outcome). The value is the issuer identifier in the
  same spelling the RFC 8414 metadata document publishes, because section 2.4 has the client
  compare the two for equality. The metadata document advertises
  `authorization_response_iss_parameter_supported: true` (section 3); it is a plain `bool`, not an
  `Option`, and `AuthorizationResponse::iss` / `AuthorizationErrorRedirect::iss` are plain
  `String`s, so the claim and the behaviour cannot drift apart. A directly rendered (non
  redirecting) error carries no `iss`: RFC 6749 section 4.1.2.1 forbids redirecting there, so
  there is no authorization response for section 2 to apply to.
- **RFC 8707 resource indicators** at the authorization endpoint and the token endpoint. The
  parameter may be repeated (section 2), each value must be an absolute URI with no fragment (a
  query component is explicitly permitted), and a value this server will not honour is refused
  with the new `ErrorCode::InvalidTarget` (`invalid_target`). The requested resources are recorded
  on the authorization code, carried through issuance onto the access token and the refresh chain,
  and a token request may NARROW that set but never widen it, the same rule and the same shape as
  RFC 6749 section 6's scope rule for refresh. Introspection reports them as `aud` (RFC 7662
  section 2.2, array form, omitted when there is no audience), and under the `jwt` feature they
  REPLACE the configured audience in the RFC 9068 `aud` claim. RFC 8707 registers no metadata
  member, so nothing new is advertised for it.
- A CSRF seam, a consent seam, and a rate limiting obligation stated on the device approval API.
- `Storage::get_refresh_token`, `Storage::revoke_token_family`, and `Storage::sweep_expired`.
- Allocation and size gates, each proven able to fail before being trusted.

### Fixed (security)

An adversarial security review traced seventeen findings through the code. Each fix began as a
test that reproduced the attack and failed.

- **Refresh token reuse detection.** Rotation previously deleted the old record, so a replay was
  `invalid_grant` and nothing more. A thief who redeemed first kept a working chain while the
  honest client was locked out, which is precisely inverted. Tokens now carry a family, rotated
  tokens are retained as spent, and presenting one revokes the whole family (OAuth 2.1 section
  6.1, RFC 9700 section 4.14.2).
- **Cross site device approval (critical).** The verification form had no CSRF protection, so an
  auto-submitting cross-origin form plus a victim's session approved an attacker's device grant,
  yielding a token for the victim's account.
- **Silent authorization.** The authorization endpoint issued codes with no consent step. With no
  consent resolver wired it now refuses rather than approving.
- **Replay revocation ordering.** Revocation on code replay ran before the client ownership check,
  so any public client could destroy a victim's live tokens using only a leaked code.
- **Unauthenticated introspection and revocation** when the named client was public (RFC 7662
  section 2.1, RFC 7009 section 2.1).
- **Constant time comparison** folded only 16 bits of the length difference, so `"hunter2"` and
  `"hunter2"` followed by 65536 NUL bytes compared EQUAL; it also leaked the secret's length by
  loop count.
- Credential bearing types no longer print secrets under `Debug`.
- `ValidatedAuthorizationRequest` is now genuinely unconstructible outside validation, which its
  documentation had already claimed.

### Changed

- **MSRV lowered from a declared 1.86 to a measured 1.75.** 1.74 fails only on return position
  `impl Trait` in the `Storage` trait; 1.75 compiles clean. `Cargo.lock` moved to format v3, and
  `base64ct` and `zeroize` are pinned below the versions that moved to edition 2024, because a
  floor that only holds without `--locked` is not a floor.
- `Storage` gained required methods (breaking, and deliberately taken before anything is
  published rather than after).
- **Breaking, for RFC 9207 and RFC 8707** (0.x, and nothing is published yet, so these are taken
  now rather than later): `AuthorizationResponse` and `AuthorizationErrorRedirect` gained `iss`;
  `AuthorizationRequest` gained `resource: Vec<Cow<str>>` (empty by default, so
  `AuthorizationRequest::from_pairs` still allocates nothing on borrowed input);
  `ValidatedAuthorizationRequest` gained `issuer` and `resource`; `AuthorizationCodeRecord`,
  `IssuedToken` and `RefreshTokenRecord` gained `resource`; `IntrospectionResponse` gained `aud`;
  `ErrorCode` gained `InvalidTarget`. `AuthorizationServer::token_with_resources` is new and
  `token` now delegates to it with an empty list. The RFC 8707 parameter is an argument there
  rather than a field on all four `TokenRequest` variants because section 2 defines it as a
  parameter of the token request independent of `grant_type`: a field per variant would state the
  same thing four times, grow an enum every host copies, and make every future grant repeat it.
- RFC 7662 introspection now reports `iss` in the same trimmed spelling as the RFC 8414 metadata
  `issuer` and the RFC 9207 `iss` parameter, rather than the raw configured string. One server,
  one identity, in every place it states it.
- `resource` is not accepted on the RFC 8628 device authorization request, so a device token poll
  naming one is refused with `invalid_target` rather than silently ignored: there is nothing
  granted for it to narrow to, and a client that believes it holds an audience restricted token
  and does not is worse off than one told plainly it cannot have one.
- `conformance-serve.sh` excluded from the published tarball: it resolves the workspace root as
  `../..` and cannot work from an unpacked crate.

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
