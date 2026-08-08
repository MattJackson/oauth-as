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
oauth-as = "0.2"
```

## What it does

| Capability | Spec | Notes |
| ---------- | ---- | ----- |
| Authorization code grant | RFC 6749 s4.1 | PKCE required, `S256` only, exact redirect URI matching |
| PKCE | RFC 7636 | Verified against the appendix B vector |
| Device authorization grant | RFC 8628 | Full state machine: pending, `slow_down`, expiry, denial, single use |
| Refresh rotation | RFC 6749 s6 | Single use, absolute chain lifetime, **reuse detection revokes the family** |
| Client credentials | RFC 6749 s4.4 | Confidential clients only, no refresh token |
| Server metadata | RFC 8414 | Derived from config, so an advertised endpoint is one that exists |
| Token introspection | RFC 7662 | Unknown, expired and other clients' tokens all read `{"active": false}` |
| Token revocation | RFC 7009 | Idempotent, ownership verified, no existence oracle |
| Mix-up defence | RFC 9207 | `iss` on every authorization response, success and error |
| Resource indicators | RFC 8707 | Narrowable audience, wired into the JWT `aud` claim |
| JWT access tokens | RFC 9068 | `at+jwt` / ES256 with a JWKS document, optional |

Plus the seams a real deployment needs: an audit **event sink**, a **rate limiting** hook
(RFC 8628 s5.1 makes device user code entropy adequate only in combination with one), a **client
secret verifier** so hosts store a hash rather than a secret, a **consent** seam, and **CSRF**
protection on the device verification form.

See [ROADMAP.md](ROADMAP.md) for what is coming and, more usefully, what is missing today.

## Features

The default feature set is **empty**, and stays that way.

| Feature | Adds | Cost |
| ------- | ---- | ---- |
| *(default)* | The protocol core | `serde`, `serde_json`, `getrandom`, `sha2`, `base64` |
| `http` | An axum router over the server | `axum`, `tokio` |
| `jwt` | RFC 9068 signed access tokens and a JWKS | `p256` |

A consumer who wants only the library gets no HTTP stack, no async runtime, and no signing code.
That is the premise of the crate, not a configuration option.

## Cost

Measured, not asserted:

- **113 KiB** of linked binary for the whole protocol surface, with LTO and stripping, every entry
  point reachable so nothing is dead stripped.
- **Zero allocations** when an uninstalled hook is invoked, pinned by a counting allocator.
- Allocation counts and type sizes on the hot paths are gated in CI. Those gates have caught three
  real regressions, including a 2 KB per-request allocation caused by crossing tokio's 2048 byte
  future boxing threshold.

## Minimum supported Rust version

Measured per feature, because there is not one number, and each is built at exactly that toolchain
in CI with `--locked`:

| Feature set | Floor | Set by |
| ----------- | ----- | ------ |
| default | **1.75** | this crate (RPITIT in `Storage`) |
| `jwt` | **1.75** | `p256` builds there |
| `http` | **1.80** | `axum` 0.8 declares it |

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
- **Mutation testing**, because a passing suite does not prove the tests constrain the code. See
  [MUTANTS.md](MUTANTS.md), which records what is still open rather than only what is closed.

### What is not claimed

There is **no OAuth 2.1 certification programme in existence** (it is still an Internet Draft), so
no implementation can hold one. **No third party conformance tool has been run**, because none that
applies exists: the OpenID Foundation suite covers OIDC and FAPI and contains zero references to
RFC 8628; `authgent` is an MCP scanner that skips every check without RFC 9728 metadata; OAuch has
no headless mode. The independent judges here are the vendored vectors and the pinned client. That
is a real bar and it is not certification, and this README will not imply otherwise.

The 0.x version is deliberate. If you need a battle hardened server today, use one. If you want an
embeddable, host agnostic OAuth 2.1 core with its evidence and its gaps both in the open, this is
that.

## Layout

- `crates/oauth-as` is the library.
- `crates/oauth-as-conformance` is the independent harness. It contains no code from `oauth-as`,
  never links against it, and is never published.
- `scripts/oauth-conformance.sh` runs it: `--selftest` proves the gate can go red, `--check` runs
  it against a live server.
- [GOAL.md](GOAL.md) defines done as gates that can be checked. [SECURITY.md](SECURITY.md) is the
  disclosure policy. [CONTRIBUTING.md](CONTRIBUTING.md) has the house rules, which are unusual.

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
