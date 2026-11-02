# oauth-as

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/MattJackson)

[![CI](https://github.com/MattJackson/oauth-as/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MattJackson/oauth-as/actions/workflows/publish.yml)
[![crates.io](https://img.shields.io/crates/v/oauth-as.svg)](https://crates.io/crates/oauth-as)
[![codecov](https://codecov.io/gh/MattJackson/oauth-as/graph/badge.svg)](https://codecov.io/gh/MattJackson/oauth-as)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV 1.75](https://img.shields.io/badge/MSRV-1.75-blue.svg)](#minimum-supported-rust-version)
[![docs.rs](https://img.shields.io/docsrs/oauth-as)](https://docs.rs/oauth-as)
[![Conformance](https://img.shields.io/badge/independent%20conformance-8%2F8-brightgreen.svg)](#evidence)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/MattJackson/oauth-as/badge)](https://scorecard.dev/viewer/?uri=github.com/MattJackson/oauth-as)
[![REUSE status](https://api.reuse.software/badge/github.com/MattJackson/oauth-as)](https://api.reuse.software/info/github.com/MattJackson/oauth-as)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14738/badge)](https://www.bestpractices.dev/projects/14738)

<a href="https://openid.net/certification/"><img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certified" height="60"></a>

**oauth-as 1.0.0 is OpenID® Certified™.** Matthew Jackson has certified that oauth-as 1.0.0 conforms
to the FAPI2SP OP private key + DPoP profile of the OpenID FAPI 2.0 Security Profile
([certification listing](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/), [test results](https://www.certification.openid.net/plan-detail.html?public=true&plan=ADGRXePBZaLpa)). OpenID and OpenID Certified are
trademarks of the OpenID Foundation.

An embeddable **OAuth 2.1 Authorization Server** for Rust.

This is the authorization server half of OAuth: it registers clients, runs the grant state
machines, and issues, introspects and revokes tokens, producing exactly the wire shapes the RFCs
define. It is a **library**, not a server binary. The host owns the listener, TLS, persistence and
the consent experience; the library owns the protocol.

```toml
[dependencies]
oauth-as = "1"
```

## Status

**Stable, 1.0.** The public API is frozen; breaking changes go to 2.0. The 0.x line reached 1.0 by
being tested in earnest at every step, and each release existed because auditing it found something
worth fixing — an independent mutation sweep, real SSRF and revocation defects caught and closed, a
concurrent-refresh race hardened, and in 0.11.0 FAPI 2.0 Security Profile support with PS256 and a
FAPI-safe algorithm allow-list. What each version changed, and how to migrate across the pre-1.0
breaking points (the `Storage` change in 0.9.1 and the JWS enum / assertion-audience changes in
0.11.0), is in [`CHANGELOG.md`](CHANGELOG.md).

**SemVer, strictly.** Patch upgrades are drop-in, a minor bump adds capability without breaking
existing callers, and only a major bump breaks the API. New capabilities land opt-in and off by
default: leave the new configuration alone and the server compiles and behaves exactly as the
previous version did. A store that passes `oauth_as::storage_conformance` keeps passing it, and
persisted records decode unchanged across the upgrade.

## What it does

| Capability | Spec | Notes |
| ---------- | ---- | ----- |
| Authorization code grant | RFC 6749 s4.1 | PKCE required, `S256` only, exact redirect URI matching |
| PKCE | RFC 7636 | Verified against the appendix B vector |
| Device authorization grant | RFC 8628 | Full state machine: pending, `slow_down`, expiry, denial, single use |
| Refresh rotation | RFC 6749 s6 | Single use, absolute lifetime, reuse detection revokes the family, and the revocation cannot be undone by an issuance already in flight; an opt-in `refresh_retry_window` coalesces concurrent retries of one chain, off by default |
| Client credentials | RFC 6749 s4.4 | Confidential clients only, no refresh token |
| Server metadata | RFC 8414 | Derived from config, so an advertised endpoint is one that exists |
| Token introspection | RFC 7662 | Answers the token's own client always, and the resource server it is addressed to once that server is declared in `ServerConfig::resource_servers` (empty by default, so the resource-server channel is off until configured); unknown, expired, other clients' and other resource servers' tokens all read `{"active": false}` |
| Token revocation | RFC 7009 | Idempotent, ownership verified, no existence oracle, cascades to the grant |
| Mix-up defence | RFC 9207 | `iss` on every authorization response, success and error |
| Resource indicators | RFC 8707 | Narrowable audience, wired into the JWT `aud` claim |
| Dynamic client registration | RFC 7591 / 7592 | Off unless configured AND a host policy is installed |

Behind off-by-default features:

| Capability | Spec | Feature |
| ---------- | ---- | ------- |
| JWT access tokens and JWKS | RFC 9068 / 7517 | `jwt`, plus one of `jwt-p256` (ES256), `jwt-rsa` (RS256) or `jwt-ed25519` (EdDSA/Ed25519) |
| JWT client authentication | RFC 7523 | `client-assertion` |
| DPoP sender-constrained tokens | RFC 9449 | `dpop` |
| mTLS client auth and certificate-bound tokens | RFC 8705 | `mtls` |
| Pushed authorization requests | RFC 9126 | `par` |
| Signed request objects | RFC 9101 | `jar` |
| Token exchange | RFC 8693 | `token-exchange` |
| Rich authorization requests | RFC 9396 | `rar` |
| Protected resource metadata | RFC 9728 | `resource-metadata` |
| Consent records and step-up auth | RFC 9470 | `consent` |
| Client identifier metadata documents (validation; **the host fetches**) | `draft-ietf-oauth-client-id-metadata-document-01` | `cimd` |
| An HTTP service over all of it | | `http` |
| An axum adapter for that service | | `axum` |
| A `Storage` conformance harness for hosts | | `test-util` |

Plus the seams a real deployment needs: an audit **event sink**, a **rate limiting** hook
(RFC 8628 s5.1 makes device user code entropy adequate only in combination with one), a **client
secret verifier** so hosts store a hash rather than a secret, a **consent** seam, and **CSRF**
protection on the device verification form.

The OIDF FAPI 2.0 Security Profile Final `plain_oauth` + `private_key_jwt` + DPoP plan passes on
the OpenID Foundation's hosted suite with 0 failures (51 modules), against the fixture at
`examples/fapi2_conformance_server.rs`; CI also runs it on every push to `qa`. oauth-as 1.0.0 is
OpenID® Certified™ to the FAPI2SP OP private key + DPoP profile, listed by the OpenID Foundation on
24 September 2026 ([listing](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)). The certification covers 1.0.0 specifically; later releases
run the same plan in CI but are not themselves certified until resubmitted. See "What is not
claimed", below.

What is missing today is in "What is not claimed", below. It is written down rather than left to be
discovered.

## Quickstart

Add the crate. The default feature set is empty (see [Features](#features)); pick the wire surface
you need — for an HTTP server with ES256 JWT access tokens:

```console
cargo add oauth-as --features http,axum,jwt,jwt-p256
```

Construct an embeddable authorization server over your storage:

```rust
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;

// The issuer identifier and the RFC 8628 device verification URI (both `impl Into<String>`).
let config = ServerConfig::new(
    "https://as.example.com",
    "https://as.example.com/device",
);

// `MemoryStorage` is fine for a demo; a real deployment implements the `Storage`
// trait over its own database (atomically — see the trait docs). Add the seams a
// deployment needs with the builder: `.with_event_sink(...)`, `.with_rate_limiter(...)`, etc.
let server = AuthorizationServer::new(config, MemoryStorage::new());
```

A complete, runnable server — the HTTP wiring, JWT keys, consent, and rate limiting — is in
[`examples/production_server.rs`](crates/oauth-as/examples/production_server.rs); a FAPI 2.0 fixture
is in [`examples/fapi2_conformance_server.rs`](crates/oauth-as/examples/fapi2_conformance_server.rs).
The full API reference is on [docs.rs](https://docs.rs/oauth-as).

## Features

Eighteen features. The default set is **empty**, and stays that way.

| Feature | Adds | Implies | Cost in dependencies |
| ------- | ---- | ------- | -------------------- |
| *(default)* | The protocol core | | `serde`, `getrandom`, `sha2`, `base64` |
| `http` | An HTTP service over the server: `http::Request` in, `http::Response` out, **no web framework and no async runtime** | | `http`, `http-body`, `bytes` |
| `axum` | `impl From<AuthorizationService> for axum::Router`, plus the runtime to bind a listener with. About thirty lines, and the whole of this crate's exposure to a pre-1.0 framework | `http` | `axum` 0.8, `tokio` |
| `jwt` | RFC 9068 `at+jwt` access tokens and the RFC 7517 JWKS document, over the algorithm-tagged `JwsSigner` / `JwsVerifier` seam (`JwsAlg::{Es256,Rs256,EdDsa}`); no backend, so no key is minted or verified until one of the three below is enabled or the host installs its own | | `serde_json` |
| `jwt-p256` | The built-in ES256 backend for that seam, for a host with no opinion about where its signing key lives | `jwt` | `p256` |
| `jwt-rsa` | The built-in RS256 backend (`rsa` 0.9). Off by default: an RSA signature and key are far larger than ES256's, and in-process RSA *signing* carries RUSTSEC-2023-0071 (Marvin) — verification is unaffected, but a regulated deployment should prefer a KMS/HSM-backed async `JwsSigner` for signing | `jwt` | `rsa` |
| `jwt-ed25519` | The built-in EdDSA (Ed25519 only) backend, over `ed25519-dalek` pinned to `~2.1` for this crate's 1.75 MSRV | `jwt` | `ed25519-dalek` |
| `jwt-pkcs8` | `EcdsaP256Key::from_pkcs8_der` / `to_pkcs8_der`, for a host whose key arrives as DER rather than as a raw scalar | `jwt-p256` | one crate, `pkcs8`; `der`, `spki` and `const_oid` are already in a `jwt-p256` tree via `sec1` |
| `client-assertion` | RFC 7523 `private_key_jwt` and `client_secret_jwt` | `jwt` | none of its own |
| `dpop` | RFC 9449 sender-constrained tokens | `jwt` | none of its own |
| `jar` | RFC 9101 signed request objects | `jwt` | none of its own |
| `mtls` | RFC 8705 mTLS client auth and certificate-bound tokens | | `serde_json` |
| `par` | RFC 9126 pushed authorization requests | | none |
| `rar` | RFC 9396 rich authorization requests | | `serde_json` |
| `token-exchange` | RFC 8693 token exchange | | none |
| `consent` | Consent records, withdrawal with a revocation cascade, RFC 9470 step-up | | none |
| `resource-metadata` | The RFC 9728 document type, for a host that also runs a resource server | | none |
| `cimd` | draft-ietf-oauth-client-id-metadata-document-01 client identifier metadata documents (the module docs carry a table mapping every section number it cites onto -02's renumbering). **Validation only: this crate makes no outbound HTTP request, so the host fetches the document and hands in the bytes.** See the module docs for the duties that leaves with the host | | `serde_json` |
| `test-util` | A runnable `Storage` conformance harness for hosts to run against their own store | | none |

Five of the eighteen add NOTHING to your dependency tree, not even transitively: `par`, `consent`,
`token-exchange`, `resource-metadata` and `test-util` are serde shapes and comparisons over what is
already there. Three more (`client-assertion`, `dpop`, `jar`) add no crate of their own; they turn
on `jwt`, which brings `serde_json`. The other ten each bring at least one crate: `serde_json`
for `jwt`, `mtls`, `rar` and `cimd` (it is optional as of 0.9.0, so a default build no longer carries it),
`http`/`http-body`/`bytes` for `http`, `axum` and `tokio` for `axum`, `p256` for `jwt-p256`, `rsa`
for `jwt-rsa`, `ed25519-dalek` for `jwt-ed25519`, and `pkcs8` for `jwt-pkcs8`. `jwt-p256`,
`jwt-rsa` and `jwt-ed25519` are additive, not exclusive: a tree that enables more than one compiles
and the host's own installed signer, if any, always wins because it was installed rather than
selected by feature. `http` is deliberately **not** axum: `http` 1.x and `http-body` 1.x are 1.0 crates
whose major has never moved, so they can appear in this crate's public signatures without making a
framework upgrade in your tree a breaking change here. If you want a `Router`, turn on `axum` as
well; if you are on a different axum major, leave it off and mount the service directly.

A consumer who wants only the library gets no HTTP stack, no async runtime, and no signing code.
That is the premise of the crate, not a configuration option.

On [docs.rs](https://docs.rs/oauth-as) everything above is built and rendered, with a badge on
each item naming the feature that turns it on.

## Cost

Measured, not asserted. Run it yourself: **`scripts/size-report.sh`**.

### Linked size

What a host's binary grows by when it adds this crate and **uses** it. Each number is the
difference between two linked binaries, one with the crate and one without, built identically.

| You enable | It costs | Into a host that already has serde_json, http, bytes and sha2 |
| ---------- | -------- | ------------------------------------------------------------ |
| *(default)* the protocol core | **233 KiB** | 222 KiB |
| `jwt` | 270 KiB | 252 KiB |
| `http` | 432 KiB | not measured |
| `http` + `jwt` | 473 KiB | 400 KiB |
| `axum` (with a tokio runtime and a bound listener) | 666 KiB | not measured |
| everything, all nineteen features | 1571 KiB | 1490 KiB |

What each optional feature adds on top of the core:

| Feature | Adds | Feature | Adds |
| ------- | ---- | ------- | ---- |
| `mtls` | 6 KiB | `jwt` | 36 KiB (the seam and the JWS surface: NO curve implementation) |
| `resource-metadata` | 6 KiB | `jwt-p256` | 75 KiB (`jwt` plus the built-in backend, so 39 KiB over `jwt`) |
| `token-exchange` | 12 KiB | `rar` | 104 KiB |
| `par` | 18 KiB | `test-util` | 243 KiB |
| `consent` | 31 KiB | `http` | 199 KiB |
| `cimd` | 93 KiB | `axum` | 433 KiB (234 of it over `http`, and nearly all of that is tokio) |

and on top of `jwt-p256`: `dpop` 45 KiB, `jar` 45 KiB, `client-assertion` 53 KiB, `jwt-pkcs8`
30 KiB.

The other two built-in backends are RS256 and EdDSA, both hanging off the `jwt` seam like
`jwt-p256`. Over that seam: `jwt-ed25519` is 42 KiB (`ed25519-dalek`), and `jwt-ed25519-pkcs8`
adds a further 10 KiB for the PKCS#8 DER codec. `jwt-rsa` is by far the heaviest at 143 KiB over
the seam, almost all of it `num-bigint-dig`'s modular exponentiation: an RS256 signature is 256
bytes against ES256's 64, and it costs proportionally to link. ES256 stays the recommended
profile; RS256 is there for interop with resource servers that accept nothing else.

`cimd`'s 93 KiB is almost entirely `serde_json`'s deserializer instantiated for one more
document shape, which is the same cost `rar` pays at 104 KiB. In a build that already has
another JSON-carrying feature the marginal figure is smaller, because the parser core is already
there.

`test-util` is the largest single feature, and it is larger than the whole HTTP surface. That is
the conformance harness a host runs against its own `Storage` implementation. It is a
dev-dependency feature: nothing that ships to production should enable it, and no other row in this
table includes it.

A host that brings its own ES256 backend (a cloud KMS, an HSM, or the `ring` it already links
through `rustls`) pays 36 KiB for `jwt` and takes no elliptic curve implementation. A host
with no opinion enables `jwt-p256` and pays 75 KiB, of which 39 KiB is the built-in backend. That
split is what the signing seam bought, and it is why both rows are gated separately in CI: they are
two different consumers with two different costs.

**Read the caveats, because they change what the numbers mean.**

- **Platform and profile:** `aarch64-apple-darwin`, `rustc 1.98.0`, `lto = "fat"`,
  `codegen-units = 1`, `opt-level = 3`, `panic = "unwind"`. Code size is a property of the target's
  instruction encoding, so an x86-64 figure is a different figure. **Nothing in this repository's
  `[profile.release]` reaches you**: cargo honors profiles only for the workspace being built, so
  you compile this crate with YOUR profile and get YOUR numbers. A build without LTO will be
  larger, in some rows considerably. Every figure above is from one run on 2026-09-18 under
  `rustc 1.98.0`, re-measured for 0.10.0 when the JWS seam became algorithm-agnostic (`Jwk` is now a
  three-variant enum and verification dispatches through a `JwsVerifiers` set) and the `jwt-rsa`,
  `jwt-ed25519` and `jwt-ed25519-pkcs8` backends joined the everything row.
- **The measurement does not depend on where you cloned it.** The probe used to link absolute panic
  `Location` strings, so the byte count included the length of the checkout directory — 240 bytes
  of spread between two paths, which was enough to put this gate red on CI and green locally on the
  same target. The report now builds with `--remap-path-prefix`. Verified by building the same tree
  from six different directories: no absolute path survives in the linked image at all, and five of
  the six agreed to the byte. The sixth was 8 bytes larger, entirely in the unwind tables, because
  cargo derives a crate's symbol-hash disambiguator from its path and the table's packing is
  quantized. 8 bytes is inside every budget's headroom; 240 was not.
- **"Uses" is doing real work in that sentence.** With LTO the linker deletes whatever nothing
  calls, so a feature you switch on and never touch costs close to nothing. Every row above was
  measured with the surface actually driven: all four grants end to end, the authorization
  endpoint, introspection, revocation, dynamic registration, and for `http` a request dispatched to
  every route. `scripts/size-probe/src/` is the definition of what was exercised, per row.
- **The rows include a host's own calling code**, because something has to call the library and
  under fat LTO the two are inlined together and cannot be separated. At 0.9.1 `cargo bloat`
  attributed about 48 KiB of the default row to the probe's driver, much of which is inlined
  library code; that attribution has not been re-taken since. Treat every row as an upper bound.
- **`AuthorizationServer<S, C>` is monomorphized per (`Storage`, `Clock`) pair.** Measured at
  0.9.1: a second instantiation of the default surface cost **53 KiB**. That figure predates the
  0.9.2 change that made the default surface smaller, so treat it as an upper bound; it is the one
  number on this page not taken from the run above, because no row in the report reproduces it. One
  pair is the normal case and every row above is one pair. That is the price of a storage seam that
  is allocation-free and devirtualized rather than a `dyn Storage` with an indirect call on every
  storage operation, and it is the trade this crate chose deliberately.
- **Sharing helps less than the dependency list suggests.** Adding this crate to a host that
  already links and uses serde_json, http, bytes and sha2 recovers only about 5% of the default
  row. serde and serde_json are generic: their machinery instantiated for your types is different
  machine code from the same machinery instantiated for ours, and only the non-generic core is
  actually shared.
- The `.rlib` is megabytes and is **not** a cost. It is crate metadata plus generic bodies nobody
  instantiates. Do not use it to judge this or any other crate.

**CI fails the build when any of `default`, `jwt`, `jwt-p256`, `http`, `http,jwt`, `axum` or
`--all-features` grows past a recorded budget**, and the budgets carry their reasoning next to them
in `scripts/size-report.sh`. When one is blown, the design gets fixed, not the number. Each budget
is its measurement plus 1.5% rounded up to the next KiB (and each floor its measurement minus 1.5%
rounded down) — so a budget also comes DOWN when a row does, which is the only way it stays a gate
on that row. For 0.10.0 the two rows the crypto-agility work actually moved past their band,
`jwt-p256` and `--all-features`, were re-derived from this run; the other five gated rows still sit
inside their 0.9.5 bands and were left untouched rather than re-tightened for churn.

### Allocations

- **Zero allocations** when an uninstalled hook is invoked, pinned by a counting allocator.
- Allocation counts and type sizes on the hot paths are gated in CI. Those gates have caught three
  real regressions, including a 2 KB per-request allocation caused by crossing tokio's 2048 byte
  future boxing threshold.

### What it costs you to run

The other half of "no background tasks, no globals, nothing until you ask" is that some things are
now **yours to do**. None of these is optional, and the first one is the one people forget:

- **Sweep expired records on a timer.** `Storage::sweep_expired` is the only thing that reclaims
  anything, and it runs when you call it and never otherwise. The RFC 8628 device authorization
  endpoint takes no credential from a public client, so an unswept deployment is an unbounded
  allocation loop available to anyone who can open a socket. Expiry is enforced on read, so this
  is not a security hole, it is a memory exhaustion one. Spawn one task per process, sweep well
  inside the shortest artifact lifetime, log failures and keep going.
- **Rate limit.** RFC 8628 s5.1 makes device user code entropy adequate only in combination with
  it, and this library never sees a request, so it has no caller to count.
- **Show a real consent screen.** Naming the user is not the same as asking them.
- **Wire the CSRF seam** on the device verification form, and give the subject resolver a session
  your server established rather than a header a caller chose.
- **Refresh retry tolerance is opt-in.** Set `ServerConfig::refresh_retry_window`
  to a short duration (for example 30 seconds) to recover a lost response or
  overlapping refresh without revoking the grant. Both bundled stores atomically
  record one rotation in the existing credential rows. Equivalent retries and early
  refreshes of its successor return the same credentials with the remaining access
  lifetime; the deadline and absolute refresh expiry never slide. Different scope,
  resource or authorization-detail selections are refused during this window.
  Revocation and sender constraints still apply. After the window, presenting a
  spent predecessor again revokes its family. This intentionally delays theft
  detection: a holder of the same bearer credential can recover its successor
  during the window. The default is zero (strict rotation). Custom stores must
  implement `Storage::rotate_refresh_token` atomically or requests fail closed;
  separate writes are not a substitute. Enable the same policy on all nodes.
  The optional serde field is backwards readable, but older nodes enforce strict
  reuse and must be drained before enabling retries. No new table is required.

- **Implement `take_*` and `claim_replay_id` atomically.** Read-then-delete double-spends refresh
  tokens across nodes and destroys reuse detection. Check yours with the `test-util` conformance
  harness rather than by reading it.

**`crates/oauth-as/examples/production_server.rs` wires all of them in one file**, with a comment
at each site saying what breaks if you get it wrong. Copy that one. Do not copy
`conformance_server.rs`: it is a black-box test fixture and it says so at the top, in the loudest
available terms.

## Minimum supported Rust version

The protocol core keeps Rust 1.75 support. Enabling the built-in ES256 backend now
requires Rust 1.88: the security update to `p256` 0.14 removes the vulnerable
`crypto-bigint` 0.5 tree (RUSTSEC-2026-0387), and its current patched dependency
graph includes `sha2` 0.11.1, which requires 1.88. This is a security-driven
increase for `jwt-p256` and `jwt-pkcs8` in the 1.0.x patch release.

| Feature set | Supported Rust version | Built in CI at |
| ----------- | ---------------------- | -------------- |
| default, `jwt` | **1.75** | 1.75, derived from the manifest |
| `http` | **1.75** locally measured | 1.80 |
| `axum` | **1.80** | stable; its HTTP dependencies also build at 1.80 |
| `jwt-p256`, `jwt-pkcs8`, all features | **1.88** | 1.88 |

The `jwt` signing and verification traits carry no ES256 arithmetic dependency.
Hosts using their own `JwsSigner` and `JwsVerifier` keep the core floor without
enabling `jwt-p256`. The RSA and Ed25519 backends retain their existing dependency
versions; their Rust 1.75 support is based on dependency declarations rather than
a dedicated CI build.

MSRV jobs build the library with `--locked`; behavioral tests run on stable.
Dev-dependencies are outside the consumer's build and require newer toolchains.

1.74 fails on exactly one thing: return position `impl Trait` in the `Storage` trait. Going lower
would mean `Box<dyn Future>` there, a heap allocation on every storage call, paid forever by every
consumer to support toolchains older than December 2023.

## Evidence

An authorization server decides who gets access to everything else. It should not be taken on
trust, including by its authors. So:

- **An independently authored conformance harness passes 8/8.**
  `crates/oauth-as-conformance` was written by an author who could not see this crate's source.
  That matters because this crate's own tests were written by its author: the judge was arms
  length, but the choice of what to test was not. It drives the server over HTTP as a black box and
  discovers every endpoint from the metadata document, so it also proves the advertised endpoints
  are real. No file in it was modified to make it pass.
- **A pinned third party client is the judge.** `oauth2 = "=5.0.0"` completes a full device flow
  and a full authorization code with PKCE flow against this server and decides for itself whether
  the responses are spec legal. Pinned exactly: a silent upgrade must never change what
  "conformant" means.
- **RFC published vectors, byte exact**, so the oracle is the spec author.
- **Every gate proven able to fail.** `scripts/oauth-conformance.sh --selftest` shows a corrupted
  vector failing the vector suite and a deliberately nonconformant stub server failing the black
  box suite, before any green is trusted.
- **Adversarial security review**, with each fix beginning as a test that reproduced the attack and
  failed. It found, among others, a cross site device approval chain, missing refresh token reuse
  detection, and a constant time comparison that returned true for unequal inputs.
- **Mutation testing**, because a passing suite does not prove the tests constrain the code. It is
  run against a frozen tree between releases, and what it finds is recorded as still-open rather
  than only as closed.

### What is not claimed

There is **no OAuth 2.1 certification programme in existence** (it is still an Internet Draft), so
no implementation can hold one, and none is claimed here.

What IS now claimable, and was not before:

- **Two independently written third party client libraries, in two languages, accept this server**:
  `oauth2 = "=5.0.0"` (Rust) and `golang.org/x/oauth2 v0.36.0` (the Go project's own). Each pinned
  exactly, each gate proven able to go red. They cover different ground: the Go drive exercises
  client credentials and refresh rotation, which the Rust one does not.
- **A third party scanner nobody here wrote applies its own RFC 8414, RFC 7636, RFC 9207, RFC 8707
  and RFC 7591 checks to this crate's metadata document**, in CI, pinned. Its findings are recorded
  and explained in `crates/oauth-as-conformance/authgent-baseline.json` rather than silenced, and
  the gate is on anything NEW rather than on zero.

- **The OIDF FAPI 2.0 Security Profile Final `plain_oauth` + `private_key_jwt` + DPoP plan passes
  on the OpenID Foundation's hosted suite** (`www.certification.openid.net`, plan `ADGRXePBZaLpa`):
  51 modules, 0 failures. Two WARNINGs, neither a failure: the fixture's resource server validates
  access tokens statelessly and does not introspect, so it does not observe the token revocation
  the AS performs on authorization-code reuse (a SHOULD); and the DPoP `htu` comparison does not
  apply RFC 3986 default-port normalization (`https://host:443/x` vs `https://host/x`), a library
  fix scheduled for 1.0.1. The RS256 client-assertion negative test is SKIPPED by the suite because
  the profile's clients use ES256. CI runs the same plan on every push to `qa`
  (`.github/workflows/fapi2-conformance.yml`) against a self-hosted suite, which can gate but cannot
  certify: a self-hosted suite signs its logs with a key the OpenID Foundation does not hold.
  oauth-as 1.0.0 is OpenID® Certified™ to the FAPI2SP OP private key + DPoP profile: the OpenID
  Foundation published the certification on 24 September 2026 ([listing](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)). It is a
  self-certification under the OpenID Foundation's program, covering version 1.0.0 only; the
  OpenID Foundation does not independently verify conformance claims.

Still not claimable, and stated so it stays that way: any OAuth 2.1 certification (none exists),
any OpenID Connect claim (this crate is not an OP), and any MCP conformance claim. A headless OAuch
run is impossible by design and its authors say so.

At 1.0 the public API is frozen and the SemVer contract is in force. If you want an embeddable,
host-agnostic OAuth 2.1 core with its evidence and its gaps both in the open, this is that.

## Layout

- `crates/oauth-as` is the library. `examples/production_server.rs` is the worked wiring a real
  deployment starts from; `examples/conformance_server.rs` is a harness fixture and is not.
- `crates/oauth-as-conformance` is the independent harness. It contains no code from `oauth-as`,
  never links against it, and is never published.
- `scripts/oauth-conformance.sh` runs it: `--selftest` proves the gate can go red, `--check` runs
  it against a live server.
- [SECURITY.md](SECURITY.md) is the disclosure policy. [CONTRIBUTING.md](CONTRIBUTING.md) has the
  house rules, which are unusual. [CHANGELOG.md](CHANGELOG.md) carries a migration for every
  breaking change and a section for what each release knowingly left open.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the house rules and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the standards expected of participants. CI runs on the
dev → qa → main flow, so a change is validated on `dev` and `qa` before it reaches `main`.

## Security

To report a vulnerability, follow the private disclosure process in [SECURITY.md](SECURITY.md).
Please do not open a public issue for security reports.

## Changelog

Notable changes are recorded in [CHANGELOG.md](CHANGELOG.md), which follows
[Keep a Changelog](https://keepachangelog.com) and [Semantic Versioning](https://semver.org).

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
