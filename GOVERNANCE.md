<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Matthew Jackson
-->

# Governance

This document describes how `oauth-as` is governed: who decides what, how changes
are made, and how continuity is maintained. It is deliberately short and honest
about the project's current size.

## Model

`oauth-as` uses a **benevolent-maintainer** model. The project is currently
maintained by a single maintainer (see [Roles](#roles-and-responsibilities)).
Decisions are made in the open on the GitHub issue tracker and pull requests, and
the maintainer is responsible for the final call, guided by the project's stated
priorities: correctness and security over feature velocity (see `README.md` and
`SECURITY.md`).

There is no separate steering committee or foundation. If the project grows to
more than one active maintainer, this document will be updated to describe how
decisions are shared (expected: lazy consensus on pull requests, with any
maintainer able to merge after review, and disputes escalated to a documented
tie-break).

## Roles and responsibilities

- **Maintainer** — Matthew Jackson ([@MattJackson](https://github.com/MattJackson)).
  Reviews and merges changes, cuts releases, triages issues and security reports,
  and owns the release keys and repository/registry credentials. The authoritative,
  machine-readable owner list is [`CODEOWNERS`](CODEOWNERS).
- **Contributors** — anyone who opens an issue or a pull request. Contribution
  requirements are in [`CONTRIBUTING.md`](CONTRIBUTING.md); the code of conduct is
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## How decisions are made

1. Non-trivial changes start as an issue describing what the change buys a real
   deployment (see `CONTRIBUTING.md`).
2. Changes are proposed as pull requests and must pass the full CI gate
   (`cargo fmt --check`, `clippy -D warnings`, the test matrices) and, for a
   release, the manual pre-release audit described in `CONTRIBUTING.md`.
3. The maintainer merges once the change meets the contribution requirements. A
   security-relevant change additionally follows the process in `SECURITY.md`.

## Access and continuity

- **Who has access.** The maintainer holds admin on the GitHub repository, the
  crates.io publishing token (stored only as a GitHub Actions secret,
  `CARGO_REGISTRY_TOKEN`), and any release-signing material. No credential is
  committed to the repository.
- **Bus factor.** The project's current bus factor is **1**. This is stated plainly
  rather than hidden: it is the main structural risk of a single-maintainer
  project, and closing it (a second maintainer who can review and release) is an
  explicit goal — see [`ROADMAP.md`](ROADMAP.md).
- **Continuity plan.** The project is fully reproducible from the public
  repository: the source, the exact dependency versions (`Cargo.lock`), the CI and
  release workflows, and the release process are all in-tree, so a new maintainer
  can take over with only repository-admin and a crates.io token. Released versions
  on crates.io are immutable and independently verifiable (SLSA build-provenance
  attestations and cosign signatures; see `.github/workflows/publish.yml`), so the
  supply chain does not depend on any single person remaining reachable. In the
  event the maintainer becomes unavailable, another trusted contributor can fork
  and continue under the same MIT OR Apache-2.0 license.

## Changing this document

Changes to governance are made the same way as any other change: a pull request,
reviewed and merged by the maintainer.
