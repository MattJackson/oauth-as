# oauth-as

[![CI](https://github.com/MattJackson/oauth-as/actions/workflows/dev.yml/badge.svg?branch=dev)](https://github.com/MattJackson/oauth-as/actions/workflows/dev.yml)
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
oauth-as = "0.9"
```

## Beta

**0.9.1 is a beta.** 0.9.0 was an alpha, published so it could be built against and reported on;
this is the release meant to be tested in earnest, and it exists because auditing that alpha found
things worth fixing. It is still pre-1.0 and the API is not frozen.

**It contains a BREAKING CHANGE to `Storage`, and one to a feature name.** A host implementing
`Storage` itself has work to do; a host on `MemoryStorage` or `oauth-as-postgres` does not. See
`CHANGELOG.md` for the migration, and run `oauth_as::storage_conformance` against your store,
which now checks the new rule.

What 0.9.0 listed here as a known defect is FIXED:

- **Reuse detection can no longer be raced during token signing.** In 0.9.0, detecting a stolen
  refresh token revoked the family, but an issuance already in flight across the `await` inside
  ES256 signing could complete behind the revocation and leave a live access token, which was
  effectively closed for the built-in `jwt-p256` backend and OPEN for an `Es256Signer` fronting a
  remote KMS or HSM. The fix needed the breaking `Storage` change this release makes: a revocation
  now records a durable barrier, and the writes that would resurrect what it removed are refused.
  The same held for authorization code replay, and that half needed a second mechanism. The two
  reproductions that shipped `#[ignore]`d in 0.9.0 are green and no longer ignored.

What is still true and worth knowing before you adopt it:

- **Mutation coverage is incomplete.** Surviving mutants are tracked individually rather than as a
  percentage, and the ones that are not killed by a test are argued in writing beside the code they
  mutate. A green test run does not yet mean the tests would have caught any given change.

The known-defects section of `CHANGELOG.md` has the detail, including the test names.

## What it does

| Capability | Spec | Notes |
| ---------- | ---- | ----- |
| Authorization code grant | RFC 6749 s4.1 | PKCE required, `S256` only, exact redirect URI matching |
| PKCE | RFC 7636 | Verified against the appendix B vector |
| Device authorization grant | RFC 8628 | Full state machine: pending, `slow_down`, expiry, denial, single use |
| Refresh rotation | RFC 6749 s6 | Single use, absolute lifetime, reuse detection revokes the family, and the revocation cannot be undone by an issuance already in flight |
| Client credentials | RFC 6749 s4.4 | Confidential clients only, no refresh token |
| Server metadata | RFC 8414 | Derived from config, so an advertised endpoint is one that exists |
| Token introspection | RFC 7662 | Unknown, expired and other clients' tokens all read `{"active": false}` |
| Token revocation | RFC 7009 | Idempotent, ownership verified, no existence oracle, cascades to the grant |
| Mix-up defence | RFC 9207 | `iss` on every authorization response, success and error |
| Resource indicators | RFC 8707 | Narrowable audience, wired into the JWT `aud` claim |
| Dynamic client registration | RFC 7591 / 7592 | Off unless configured AND a host policy is installed |

Behind off-by-default features:

| Capability | Spec | Feature |
| ---------- | ---- | ------- |
| JWT access tokens and JWKS | RFC 9068 / 7517 | `jwt` |
| JWT client authentication | RFC 7523 | `client-assertion` |
| DPoP sender-constrained tokens | RFC 9449 | `dpop` |
| mTLS client auth and certificate-bound tokens | RFC 8705 | `mtls` |
| Pushed authorization requests | RFC 9126 | `par` |
| Signed request objects | RFC 9101 | `jar` |
| Token exchange | RFC 8693 | `token-exchange` |
| Rich authorization requests | RFC 9396 | `rar` |
| Protected resource metadata | RFC 9728 | `resource-metadata` |
| Consent records and step-up auth | RFC 9470 | `consent` |
| An HTTP service over all of it | | `http` |
| An axum adapter for that service | | `axum` |
| A `Storage` conformance harness for hosts | | `test-util` |

Plus the seams a real deployment needs: an audit **event sink**, a **rate limiting** hook
(RFC 8628 s5.1 makes device user code entropy adequate only in combination with one), a **client
secret verifier** so hosts store a hash rather than a secret, a **consent** seam, and **CSRF**
protection on the device verification form.

What is missing today is in "What is not claimed", below. It is written down rather than left to be
discovered.

## Features

Fifteen features. The default set is **empty**, and stays that way.

| Feature | Adds | Implies | Cost in dependencies |
| ------- | ---- | ------- | -------------------- |
| *(default)* | The protocol core | | `serde`, `getrandom`, `sha2`, `base64` |
| `http` | An HTTP service over the server: `http::Request` in, `http::Response` out, **no web framework and no async runtime** | | `http`, `http-body`, `bytes` |
| `axum` | `impl From<AuthorizationService> for axum::Router`, plus the runtime to bind a listener with. About thirty lines, and the whole of this crate's exposure to a pre-1.0 framework | `http` | `axum` 0.8, `tokio` |
| `jwt` | RFC 9068 `at+jwt` access tokens and the RFC 7517 JWKS document, over the `Es256Signer` / `Es256Verifier` seam | | `serde_json` |
| `jwt-p256` | The built-in ES256 backend for that seam, for a host with no opinion about where its signing key lives | `jwt` | `p256` |
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
| `test-util` | A runnable `Storage` conformance harness for hosts to run against their own store | | none |

Five of the fifteen add NOTHING to your dependency tree, not even transitively: `par`, `consent`,
`token-exchange`, `resource-metadata` and `test-util` are serde shapes and comparisons over what is
already there. Three more (`client-assertion`, `dpop`, `jar`) add no crate of their own; they turn
on `jwt`, which brings `serde_json`. The other seven each bring at least one crate: `serde_json`
for `jwt`, `mtls` and `rar` (it is optional as of 0.9.0, so a default build no longer carries it),
`http`/`http-body`/`bytes` for `http`, `axum` and `tokio` for `axum`, `p256` for `jwt-p256`, and
`pkcs8` for `jwt-pkcs8`. `http` is deliberately **not** axum: `http` 1.x and `http-body` 1.x are 1.0 crates
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
| *(default)* the protocol core | **229 KiB** | 216 KiB |
| `jwt` | 263 KiB | 244 KiB |
| `http` | 428 KiB | not measured |
| `http` + `jwt` | 461 KiB | 389 KiB |
| `axum` (with a tokio runtime and a bound listener) | 662 KiB | not measured |
| everything, all fifteen features | 1340 KiB | 1259 KiB |

What each optional feature adds on top of the core:

| Feature | Adds | Feature | Adds |
| ------- | ---- | ------- | ---- |
| `mtls` | 7 KiB | `jwt` | 34 KiB (the seam and the JWS surface: NO curve implementation) |
| `resource-metadata` | 7 KiB | `jwt-p256` | 69 KiB (`jwt` plus the built-in backend, so 35 KiB over `jwt`) |
| `token-exchange` | 11 KiB | `rar` | 96 KiB |
| `par` | 19 KiB | `test-util` | 242 KiB |
| `consent` | 33 KiB | `http` | 199 KiB |
|  |  | `axum` | 433 KiB (234 of it over `http`, and nearly all of that is tokio) |

and on top of `jwt-p256`: `dpop` 46 KiB, `jar` 46 KiB, `client-assertion` 53 KiB, `jwt-pkcs8`
30 KiB.

`test-util` is the largest single feature, and it is larger than the whole HTTP surface. That is
the conformance harness a host runs against its own `Storage` implementation, and it grew by 94 KiB
in 0.9.1 because it gained twenty-seven checks. It is a dev-dependency feature: nothing that ships
to production should enable it, and no other row in this table includes it.

The `jwt` row is the one that moved: it was 64 KiB when the feature implied `p256`. A host that
brings its own ES256 backend (a cloud KMS, an HSM, or the `ring` it already links through `rustls`)
now pays 34 KiB and takes no second elliptic curve implementation. A host with no opinion enables
`jwt-p256` and pays 68 KiB, which is 471 bytes more than the same host paid before the seam.

**Read the caveats, because they change what the numbers mean.**

- **Platform and profile:** `aarch64-apple-darwin`, `rustc 1.97.0`, `lto = "fat"`,
  `codegen-units = 1`, `opt-level = 3`, `panic = "unwind"`. Code size is a property of the target's
  instruction encoding, so an x86-64 figure is a different figure. **Nothing in this repository's
  `[profile.release]` reaches you**: cargo honors profiles only for the workspace being built, so
  you compile this crate with YOUR profile and get YOUR numbers. A build without LTO will be
  larger, in some rows considerably.
- **"Uses" is doing real work in that sentence.** With LTO the linker deletes whatever nothing
  calls, so a feature you switch on and never touch costs close to nothing. Every row above was
  measured with the surface actually driven: all four grants end to end, the authorization
  endpoint, introspection, revocation, dynamic registration, and for `http` a request dispatched to
  every route. `scripts/size-probe/src/` is the definition of what was exercised, per row.
- **The rows include a host's own calling code**, because something has to call the library and
  under fat LTO the two are inlined together and cannot be separated. About 48 KiB of the default
  row is attributed to the probe's driver by `cargo bloat`, much of which is inlined library code.
  Treat every row as an upper bound.
- **`AuthorizationServer<S, C>` is monomorphized per (`Storage`, `Clock`) pair.** Measured: a
  second instantiation of the default surface costs **53 KiB**, about 27% of the row again. One
  pair is the normal case and every row above is one pair. That is the price of a storage seam that
  is allocation-free and devirtualized rather than a `dyn Storage` with an indirect call on every
  storage operation, and it is the trade this crate chose deliberately.
- **Sharing helps less than the dependency list suggests.** Adding this crate to a host that
  already links and uses serde_json, http, bytes and sha2 recovers only about 7% of the default
  row. serde and serde_json are generic: their machinery instantiated for your types is different
  machine code from the same machinery instantiated for ours, and only the non-generic core is
  actually shared.
- The `.rlib` is megabytes and is **not** a cost. It is crate metadata plus generic bodies nobody
  instantiates. Do not use it to judge this or any other crate.

**CI fails the build when any of `default`, `jwt`, `http`, `http,jwt`, `axum` or `--all-features`
grows past a recorded budget**, and the budgets carry their reasoning next to them in
`scripts/size-report.sh`. When one is blown, the design gets fixed, not the number.

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
workstation: no job in `.github/workflows/qa.yml` builds `http` on 1.75. The `MSRV (1.75) build`
job builds default, `jwt` and `jwt-p256` only, and `http` is built by the separate
`MSRV (1.80) http feature` job. So 1.80 is the number for `http` that a stranger can verify from
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
in says so, not because of anything in this crate. Of the other fourteen, five add no crate at all
(`par`, `consent`, `token-exchange`, `resource-metadata`, `test-util`) and so add no floor, and the
rest add only crates whose own declared floor is below this one: `serde_json` 1.71 for `jwt` (and
so for `client-assertion`, `dpop` and `jar`, which turn it on), for `mtls` and for `rar`,
`http` 1.57 / `http-body` 1.61 / `bytes` 1.57 for `http`, `p256` 1.65 for `jwt-p256`, and
`pkcs8` 1.65 for `jwt-pkcs8`.

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
conformance run, any MCP conformance claim. A FAPI 2.0 `plain_oauth` run is achievable and the
remaining work is written down in `crates/oauth-as-conformance/EXTERNAL-TOOLING.md`, but it has not
been done. A headless OAuch run is impossible by design and its authors say so.

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

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
