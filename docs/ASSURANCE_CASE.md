<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Matthew Jackson
-->

# Assurance case

An assurance case is a structured argument, supported by evidence, that the
software achieves its security claim. This is a short, honest one for `oauth-as`.
It is not a proof; it makes the claims checkable, which is the most the project
offers (see `SECURITY.md`, "Our own practice").

## Claim

`oauth-as` correctly and safely performs the authorization-server role it
implements: it does not issue, accept, or leak a token or grant that a party
should not obtain, within the boundary it draws (the host owns transport
security, rate limiting, and the consent experience — see `SECURITY.md`, "Scope").

## Sub-claims and evidence

1. **It does not crash on untrusted input.**
   - *Argument:* the crate is `#![forbid(unsafe_code)]`; every credential that
     arrives from the wire is size-bounded before parsing, and parsing returns
     `Result` rather than panicking.
   - *Evidence:* the `cargo-fuzz` targets under `fuzz/` with committed corpora;
     the panic-focused tests; CI running the full test matrices with warnings as
     errors.

2. **Algorithm confusion is prevented structurally.**
   - *Argument:* the registration (never the token header) chooses the algorithm;
     `classify_alg` cannot name `none` or an HMAC where an asymmetric key is
     expected; RS256 and PS256 occupy distinct verifier slots so a signature made
     under one padding cannot verify under the other with the same key.
   - *Evidence:* `tests/algorithm_confusion.rs` (the confusion matrix across every
     wired algorithm and site), the `backends/rsa.rs` seam tests, and the FAPI
     algorithm allow-list.

3. **Proof-of-possession and single-use artifacts hold under races.**
   - *Argument:* DPoP binds codes and tokens to a key; authorization-code replay
     and refresh-token reuse revoke the family through a durable barrier plus a
     compare-and-swap, closing the signing-window race.
   - *Evidence:* `SECURITY.md` (the 0.9.1 reuse-window record), the refresh-token
     state-machine tests, the DPoP code-binding tests, and the `Storage` atomicity
     contract.

4. **What it advertises is what it accepts.**
   - *Argument:* RFC 8414 metadata is derived from the same verifier resolution the
     endpoints use, so advertised algorithms match accepted algorithms at both the
     registered and DPoP chokepoints.
   - *Evidence:* `tests/metadata_verifier_truth.rs` and the allow-list tests.

5. **The implementation is independently checkable.**
   - *Argument:* an independently-authored black-box conformance harness drives the
     server without seeing its source; the OIDF FAPI 2.0 Security Profile suite runs
     green in CI.
   - *Evidence:* `crates/oauth-as-conformance`, the `fapi2-conformance` workflow,
     and the recorded, justified expected-failures/skips.

## Residual risks (honestly stated)

- **Bus factor 1** — a single maintainer (see `GOVERNANCE.md`).
- **RUSTSEC-2023-0071** — the `rsa` crate's signing-side timing side-channel, which
  does not affect the verification this crate performs; documented and accepted in
  `SECURITY.md` and `deny.toml`.
- **Mutation coverage is not complete** — surviving mutants are tracked and argued
  in writing rather than assumed away (see `SECURITY.md`).

This assurance case is revisited when the threat model or the evidence changes.
