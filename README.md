# oauth-as

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/MattJackson)

[![CI](https://github.com/MattJackson/oauth-as/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MattJackson/oauth-as/actions/workflows/publish.yml)
[![crates.io](https://img.shields.io/crates/v/oauth-as.svg)](https://crates.io/crates/oauth-as)
[![codecov](https://codecov.io/gh/MattJackson/oauth-as/graph/badge.svg)](https://codecov.io/gh/MattJackson/oauth-as)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV 1.75](https://img.shields.io/badge/MSRV-1.75-blue.svg)](#minimum-supported-rust-version)
[![Conformance](https://img.shields.io/badge/independent%20conformance-8%2F8-brightgreen.svg)](#evidence)

An embeddable **OAuth 2.1 Authorization Server** for Rust.

This is the authorization server half of OAuth: it registers clients, runs the grant state
machines, and issues, introspects and revokes tokens, producing exactly the wire shapes the RFCs
define. It is a **library**, not a server binary. The host owns the listener, TLS, persistence and
the consent experience; the library owns the protocol.

```toml
[dependencies]
oauth-as = "0.10"
```

## Status

**Beta, and pre-1.0.** The API is not yet frozen. Every release in the `0.9` line is meant to be
tested in earnest, and each one exists because auditing the release before it found something worth
fixing — an independent mutation sweep, real SSRF and revocation defects caught and closed, a
concurrent-refresh race hardened. What each version changed, and how to migrate across the one
breaking `Storage` change (0.9.1), is in [`CHANGELOG.md`](CHANGELOG.md).

**Upgrades within `0.9` are drop-in.** New capabilities land opt-in and off by default: leave the
new configuration alone and the server compiles and behaves exactly as the previous version did. A
store that passes `oauth_as::storage_conformance` keeps passing it, and persisted records decode
unchanged across the upgrade.

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

A runnable FAPI 2.0 Security Profile fixture (`examples/fapi2_conformance_server.rs`) and a manual,
`workflow_dispatch`-only CI job exist so the OIDF `plain_oauth` suite can be run against this crate
on demand; running it needs no OIDF payment or membership, but certification is a separate, manual
submission and **nothing is certified**. See "What is not claimed", below.

What is missing today is in "What is not claimed", below. It is written down rather than left to be
discovered.

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

Measured per feature, because there is not one number. The last column is what CI actually builds
with `--locked`, and it is a separate column because for one row it is NOT the same as the floor:

| Feature set | Floor | Set by | Built in CI at |
| ----------- | ----- | ------ | -------------- |
| default | **1.75** | this crate (RPITIT in `Storage`) | 1.75 |
| `jwt` | **1.75** | this crate; `jwt` adds only `serde_json`, which declares 1.71 | 1.75, and `jwt-p256` at 1.75 too |
| `http` | **1.75** | this crate; `http`, `http-body` and `bytes` are all lower | **1.80 only, never 1.75** |
| `axum` | **1.80** | `axum` 0.8 declares it | 1.80, via `--features http` and `--all-features` |

The `jwt` row's REASON changed with the ES256 seam split, and the table said the old one until
2026-08-09: it gave `p256` as what set that floor, which stopped being true the moment `jwt`
became `["dep:serde_json"]` and the backend moved to `jwt-p256 = ["jwt", "dep:p256"]`. The floor
NUMBER was correct and still is; only the cause was stale. `jwt` pulls no `p256` at all now, so
nothing it adds sets a floor above this crate's own, and `p256`'s 1.65 belongs to the `jwt-p256`
row instead.

The `http` row is the one to read carefully. `cargo +1.75 build -p oauth-as --locked --features
http` does succeed, and that was re-measured for this release, but it was measured on a
workstation: no job in `.github/workflows/qa.yml` builds `http` on 1.75. The
`MSRV build (toolchain from rust-version)` job — named that because it reads the floor out of
`crates/oauth-as/Cargo.toml` rather than hardcoding it, so the number in the manifest is the number
CI installs — builds default, `jwt`, `jwt-p256` and `jwt-pkcs8` only, and `http` is built by the
separate `MSRV (1.80) http feature` job. So 1.80 is the number for `http` that a stranger can verify from
CI logs alone, and 1.75 is a local measurement that nothing re-checks on every push.

Every MSRV job BUILDS and none of them TEST, and that is deliberate rather than an omission. An
MSRV is a promise to a consumer that their toolchain can compile this library, and a consumer
never compiles our dev-dependencies. Ours cannot run at 1.75: `cargo +1.75 test -p oauth-as
--locked --no-run` fails with `package litemap v0.7.5 cannot be built because it requires rustc
1.81 or newer`, reached through `url -> idna -> idna_adapter -> icu_normalizer ->
icu_properties -> icu_locid`, and both `url` and `oauth2` need it. Behaviour is verified by the
full test suite on stable instead. So what is checked at the floor is "it compiles"; what is not
checked at the floor, and cannot be without dragging every dev-dependency back, is "it passes its
tests".

`axum` is the only feature that raises the floor, and it raises it because a dependency it pulls
in says so, not because of anything in this crate. Of the other eighteen, five add no crate at all
(`par`, `consent`, `token-exchange`, `resource-metadata`, `test-util`) and so add no floor, and the
rest add only crates whose own declared floor is below this one: `serde_json` 1.71 for `jwt` (and
so for `client-assertion`, `dpop` and `jar`, which turn it on), for `mtls`, for `rar` and for
`cimd`, `http` 1.57 / `http-body` 1.61 / `bytes` 1.57 for `http`, `p256` 1.65 for `jwt-p256`, and
`pkcs8` 1.65 for `jwt-pkcs8`.

The three built-in backends that landed in 0.10.0 declare floors below this one too: `rsa` 1.65
(with `num-bigint-dig` 1.56 and `pkcs1` 1.60) for `jwt-rsa`, `ed25519-dalek` 1.60 (with `ed25519`,
`curve25519-dalek` and `signature`, all 1.60) for `jwt-ed25519`, and the `pkcs8`/`der`/`spki` 1.65
tree already counted above for `jwt-ed25519-pkcs8`. These floors are the crates' DECLARED
`rust-version`s, not a CI measurement: the `MSRV build` job builds `default`, `jwt`, `jwt-p256` and
`jwt-pkcs8` only, so `jwt-rsa` and `jwt-ed25519` are not compiled at 1.75 on every push the way the
first four are. If a future bump to either backend raises its own floor past this crate's, that is
where the number would move, and the job would need a row to catch it.

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

Still not claimable, and stated so it stays that way: any certification, any OpenID Foundation
conformance run, any MCP conformance claim. A runnable FAPI 2.0 Security Profile fixture
(`examples/fapi2_conformance_server.rs`) and a manual, `workflow_dispatch`-only CI job
(`.github/workflows/fapi2-conformance.yml`) now exist and can run the OIDF `plain_oauth` suite's
`fapi2-security-profile-final-test-plan` against this crate on demand, at no OIDF cost — but running
the suite is not the same as certifying against it. Certification is a separate, manual step
(publishing the run's logs, obtaining a payment code, and submitting through
`https://submissions.openid.net/`, per `EXTERNAL-TOOLING.md` section 2.4) that has not been taken,
and no result is claimed here. A headless OAuch run is impossible by design and its authors say so.

The 0.x version is deliberate. If you need a battle hardened server today, use one. If you want an
embeddable, host agnostic OAuth 2.1 core with its evidence and its gaps both in the open, this is
that.

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
