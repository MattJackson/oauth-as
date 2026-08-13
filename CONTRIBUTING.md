# Contributing to oauth-as

This repository has a specific and somewhat unusual set of house rules. They exist because this
is an OAuth 2.1 authorization server: a defect here is rarely cosmetic, and a claim of
correctness is worthless unless it is checkable. Read this before opening a pull request, because
review will hold you to it.

## Before you write any code

Read `README.md` and `SECURITY.md`. The README's "What is not claimed" section lists what is
deliberately not built yet and why; `CHANGELOG.md` carries the same honesty per release, including
a "known, and not fixed" section. Open an issue before writing code, and say what your change buys
a real deployment; "a competitor has it" is not a reason this project accepts.

## Red before green

Every behavioural change starts with a failing test. Write the test, run it, SEE it fail, then
write the fix. A gate nobody has watched go red is a gate nobody should trust, because it might
be passing for a reason that has nothing to do with your fix.

**Security fixes specifically must begin with a test that reproduces the ATTACK**, not a test
that merely exercises the changed code path. The requests, the order they are sent in, and what
an attacker ends up holding that they should not. A security fix with no test that failed
beforehand is not a fix, it is a hope.

## The full gate, before every commit

Run all three, in order, before you commit:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

All three are load bearing. `--locked` matters: it is what keeps a green `cargo test` here
honest about what will actually build for a consumer of the published lockfile.

## Where tests live

Tests are never inline with implementation. No `#[cfg(test)] mod tests { ... }` block sitting in
the same file as the code it tests. Unit tests that need access to private items go in
`src/tests/<module>.rs`, referenced from the implementation file as:

```rust
#[cfg(test)]
#[path = "tests/<module>.rs"]
mod tests;
```

Integration-level tests (crate public API, conformance, schema validation) live under `tests/` in
the normal Cargo convention. The reasoning: implementation files should read as implementation,
not as implementation interleaved with its own grading.

## Comments explain WHY, and cite the RFC

This codebase is heavily and precisely commented on purpose. A comment that restates what the
code does is noise. A comment is worth writing when it explains why a choice was made, and where
an RFC settles the question, the comment names the RFC and section, not just "per spec". If you
add behaviour that a reader could reasonably ask "why this and not the obvious alternative"
about, answer that in a comment, with a citation if one exists.

## SPDX headers and copyright

Every source file carries an SPDX license identifier header and a copyright line. Match the
existing files under `crates/` for the exact form. Do not add a file without one.

## ASCII only, no em dashes, no en dashes

No em dashes, no en dashes, no other non-ASCII characters, anywhere: not in source, not in
comments, not in commit messages, not in markdown, not in YAML. This applies to this file too. If
your editor or an AI tool inserts one, remove it before committing. Use a comma, a colon, a
semicolon, or a plain hyphen-minus instead.

## Attribution

Commits are attributed to their human author only. Do not add `Co-Authored-By:` trailers for
tooling of any kind, in a commit message, a PR description, or anywhere else in this repository.
Whoever submits the change is accountable for it, and the history should say so plainly.

## Where the harness and the library disagree, the RFC wins

`crates/oauth-as-conformance` is an independent black-box harness, written by an author who could
not see `crates/oauth-as`'s source. That arms-length property is the entire point of it: this
crate's own tests were written by this crate's author, so the judge is arms length but the choice
of what to test was not. The harness closes that gap.

When the harness and the library disagree:

- The RFC wins. Find the section that settles the question and change whichever side is wrong.
- If neither side is clearly wrong, prefer changing the harness's ASSUMPTION over the server's
  BEHAVIOUR, and say explicitly, in the commit message, which one you changed and why.
- Any defect the harness finds is a SUCCESS of the method, not an embarrassment to paper over.
  Never weaken an assertion just to get a suite green. If an assertion in the harness is itself
  wrong, name the RFC section that settles it before you touch it.

## The MSRV floor

The measured floor is Rust 1.75. It is measured, not guessed: 1.74 fails only on
return-position `impl Trait` in the `Storage` trait, and 1.75 and 1.80 compile clean. Do not raise
it casually. If a change would raise the floor, that is a decision for the owner, not something
that happens as a side effect of a convenient API choice. Optional features may carry their own
higher floors since they pull in dependencies this crate does not control; document those
per-feature rather than letting them silently raise the core floor.

## Running the conformance harness

```
scripts/oauth-conformance.sh --selftest
```

Proves the gate can go RED before its green is trusted, on both axes: a corrupted RFC 7636
Appendix B expectation must fail the hermetic vector suite, and a deliberately nonconformant stub
AS (one whose RFC 8414 metadata is an empty JSON object) must fail the black-box suite. If either
axis passes when it should fail, the gate is worthless and `--selftest` says so.

```
scripts/oauth-conformance.sh --check
```

Runs the real thing: starts `crates/oauth-as` over HTTP via `crates/oauth-as/conformance-serve.sh`,
waits for its RFC 8414 metadata document, then runs the hermetic vectors, the black-box shape
suite, and the pinned third-party `oauth2 = "=5.0.0"` client (a full device flow and a full
authorization-code-with-PKCE flow) against the live server. It fails loudly, rather than passing
vacuously, if the serve shim is missing or the AS never comes up. If you are adding or changing
protocol behaviour, run this before opening a PR; `dev`'s CI gate does not run it, `qa`'s does.

## Branches

Work happens on `dev`. `dev` runs the fast gate on every push and pull request: `cargo fmt --all
--check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked`. `qa` runs the full suite, including MSRV verification, the
conformance self-test, the live conformance check, the packaging dry run, and the size budgets.

Mutation testing is NOT a CI job. There used to be one, and it swallowed its own exit code and
reported for information, which is a job that cannot fail; it was REMOVED at 0.9.1 rather than
kept, and `.github/workflows/qa.yml` records the argument. Mutation testing is now run
deliberately against a frozen tree between releases.

`main` publishes. Reaching `main` IS the release: `publish.yml` triggers on push to `main`, reads
the version from `crates/oauth-as/Cargo.toml`, and stops green without publishing if that version
already exists on crates.io. So the deliberate act is editing the version in a reviewed commit,
not pressing a button. `workflow_dispatch` is kept as an escape hatch for re-running a publish
step that failed after the gate passed.

`main` and `qa` are promotion branches. Promotion is the owner's call, not something a
contributor's PR triggers by merging to `dev`.

## License

`oauth-as` is dual licensed under MIT OR Apache-2.0. By submitting a contribution, you agree it is
licensed under both, matching the notice in `README.md`.

## Opening a pull request

- Keep the change scoped to one coherent thing. A PR that mixes a protocol fix with an unrelated
  refactor is harder to review and harder to revert if one half turns out wrong.
- State which RFC section the change implements or corrects, if any.
- If you touched `crates/oauth-as-conformance`, say explicitly whether you changed the harness's
  assumption or the library's behaviour, and why.
- Fill in the pull request template. It exists so this list does not have to be re-derived from
  memory on every review.
