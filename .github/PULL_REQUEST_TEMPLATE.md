<!--
Before filling this in, read CONTRIBUTING.md if you have not already. This template exists so
the house rules do not have to be re-derived from memory on every review.
-->

## What this changes, and why

<!-- One or two sentences. Why this change is needed, not just what it does. -->

## RFC section

<!--
Which RFC section does this implement, correct, or clarify, if any? e.g. "RFC 6749 s4.1.2.1" or
"RFC 8628 s3.5". If this is not a protocol change (docs, CI, tooling), write "n/a".
-->

## Red before green

<!--
Describe the failing test you wrote and watched fail before writing the fix. If this is a
security fix, the test must reproduce the ATTACK (the requests, their order, and what an
attacker ends up holding), not just exercise the changed code path.
-->

- [ ] I wrote a test, watched it fail, then made it pass.
- [ ] (Security fixes only) the test reproduces the attack, not just the code path.

## Harness disagreement, if any

<!--
If this touches crates/oauth-as-conformance and the harness disagreed with the library: which
side was wrong, which side did you change, and what RFC section settled it? If this PR does not
touch the harness, write "n/a".
-->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D
      warnings`, and `cargo test --workspace --locked` all pass locally.
- [ ] New or changed tests live in their own files, not inline `#[cfg(test)] mod tests` blocks.
- [ ] Comments on any nontrivial or non-obvious choice explain WHY, with an RFC citation where one
      applies.
- [ ] No em dashes, no en dashes, no non-ASCII characters, anywhere in the diff.
- [ ] Every new source file carries the SPDX header and copyright line.
- [ ] No AI or agent attribution anywhere in the commit messages or this description.
- [ ] If protocol behaviour changed, `scripts/oauth-conformance.sh --check` was run locally.
- [ ] This targets `dev`. (`main` and `qa` are promotion branches; the owner decides promotion.)
