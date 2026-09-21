<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Matthew Jackson
-->

# Code review standards

Every change is reviewed against these standards before it is merged. They apply
to external pull requests and to the maintainer's own changes alike.

## What a reviewer checks

- **Correctness first.** The change does what it claims, and the claim is one a
  real deployment needs (see `CONTRIBUTING.md`). Edge cases — empty, single, and
  maximum inputs — are considered.
- **Red before green.** Every behavioural change is accompanied by a test that
  failed before the change and passes after. Security fixes must include a test
  that reproduces the *attack*, not merely the changed path.
- **Security boundary.** The change does not widen the attack surface or cross a
  boundary the project draws (see `SECURITY.md`, "Scope"). Untrusted input is
  size-bounded and validated; nothing panics on wire input; no secret or key
  material is logged or leaked; comparisons on secrets are constant-time.
- **The full gate is green.** `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --locked -- -D warnings` (and the `--all-features` and per-feature
  cells), and `cargo test --workspace --locked`. `--locked` is required.
- **Public surface and docs.** New public API is documented (docs.rs is the
  published surface, built with `-D warnings`); enums that must compel a review of
  every match are kept non-`#[non_exhaustive]` on purpose; comments and docs match
  the code.
- **Dependencies.** New dependencies are justified and pass the supply-chain gate
  (`cargo deny check`, `cargo audit`); the default feature set stays minimal.

## Process

- Changes come in as pull requests and are reviewed by a maintainer before merge
  (see `GOVERNANCE.md`).
- A release additionally requires the manual pre-release audit described in
  `CONTRIBUTING.md` — an independent read of the change set before an irreversible
  crates.io publish.
- **Two-person review** (a second reviewer independent of the author on a majority
  of changes) is a goal the project cannot yet meet while it is single-maintainer;
  growing a second maintainer is tracked in `ROADMAP.md`. Until then, the manual
  pre-release audit and the independent black-box conformance harness are the
  compensating controls.
