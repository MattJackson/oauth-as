<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Matthew Jackson
-->

# Roadmap

This is a direction-of-travel document, not a dated commitment. The project's
fixed priorities are correctness and security over feature velocity; anything
below is subject to that. What is deliberately **not** built (and why) is tracked
in the "What is not claimed" section of [`README.md`](README.md), and per-release
honesty (including "known, and not fixed") lives in [`CHANGELOG.md`](CHANGELOG.md).

## Near term

- **Reach 1.0.** Finalise the public API and cut a 1.0 once the FAPI 2.0 work and
  the supply-chain/certification hardening have settled. The version after the
  current 0.10.x line will be either 0.11.0 or the first 1.0.0.
- **Certification & assurance.** Complete the OpenSSF Best Practices self-
  assessment and pursue the FAPI 2.0 OpenID Foundation certification (the
  conformance suite already runs green; certification is a separate submission).
- **Supply-chain provenance.** Ship the first cosign-signed, SLSA-attested release
  through the existing publish workflow.

## Medium term

- **Broaden backends and storage seams** as real deployments need them, keeping
  the "permanent liability" rule: an algorithm or backend is added only when it
  earns its place, never as a host-pluggable registry.
- **Grow the maintainer team.** The project is currently single-maintainer
  (bus factor 1; see [`GOVERNANCE.md`](GOVERNANCE.md)). Adding a second independent
  maintainer who can review and release is an explicit goal, both for resilience
  and to unlock the multi-reviewer quality practices (two-person review) that a
  solo project cannot meet.

## How to influence the roadmap

Open an issue describing what a change buys a real deployment (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)). Concrete, deployment-driven proposals are
what move items up this list.
