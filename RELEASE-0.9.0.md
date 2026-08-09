# The goal for today: oauth-as 0.9.0 on crates.io, fit for a third party to test

Written 2026-08-09. This is the day's plan and its exit criteria. `GOAL.md` defines what "100%"
means in general and does not change; this file says what has to be true TODAY, in what order, and
who owns each step.

## The end state, in one sentence

`oauth-as 0.9.0` is published to crates.io, and busbar can `cargo add oauth-as` and build a real
authorization server against it without reading our source to find out what is true.

"Fit for a third party to test" is the bar, not "feature complete". A third party finding a defect
is a success of the method. A third party finding that a CLAIM was false is not.

---

## 1. Land every agent

In flight right now:

- **The ES256 signing seam** (`Es256Signer` / `Es256Verifier`, the `jwt` / `jwt-p256` split, the
  signer conformance harness and its planted-fault selftest). This is the last breaking change we
  can make for free, because crates.io holds only an empty `0.0.1` and there is no consumer to
  break yet. After the first real publish there is one, forever.
- **The mutation sweep** and the killing tests it is writing.
- **The craft and performance pass** (`hex.rs` extraction, refusal-cost gate, stale rationales).

Exit: `git status` clean, every agent reported, nothing half-applied.

## 2. Clear the handed-back backlog (task #44)

A fix agent handed ten items back rather than rushing them, which was the right call. They are
blocked only on file ownership, not on difficulty. The one that matters most:

**RFC 7009 public-client revocation is refused, and the finding is CONFIRMED.** s2.1 scopes
credential validation with "(in case of a confidential client)"; s5 says "a valid `client_id`, in
the case of a public client". We issue tokens to public clients through code+PKCE and refresh, then
deny them the only standard way to invalidate them. The refusal arrived bundled with the
INTROSPECTION fix under one citation pair, and the RFC 7009 half of that citation does not support
it. The introspection refusal stays (RFC 7662 s4 genuinely says MUST NOT be publicly available).

## 3. /codeaudit to zero

Four rounds have run: 41 findings, then 26, then 39, then 13. Round 4 was the first with no HIGH.

Zero does NOT mean an empty findings array. It means:

- no new confirmed correctness, security or robustness defect, AND
- every lens retired, where a lens retires only when it comes up dry ON OPUS with nothing left
  unread.

While any lens sits on unread scope, the findings are a SAMPLE and the report must say so. At real
convergence what remains is coverage-of-fixes, false positives and by-design items. That, not an
empty array, is what done looks like.

**The seam must be audited as NEW CODE, not inherited as reviewed.** It is security-critical and it
landed mid-audit. It needs its own mutation sweep, its own fuzz coverage of the verifier, and its
own pass from the audit lenses.

## 4. Close the two open gates

- **Gate 4, mutation coverage.** Currently NOT MET. Either every survivor is killed or triaged with
  a stated reason, or `GOAL.md` and `MUTANTS.md` say plainly what remains. **Do not declare it met
  to tidy a document.** A named list of survivors is worth more to a third party than a percentage.
- **Gate 8, the claims are true.** In progress. Three counts have already been re-derived by
  measurement rather than by picking whichever number was already written down. The remainder:
  README, KICKOFF, GOAL, CHANGELOG, and the CI job names, all checked against what the code now
  does after a day of churn.

## 5. Green through the pipeline

`dev` green, promote to `qa` green, then `main`. The full local gate first: fmt, clippy on default
AND all-features, both test matrices, doc with `-D warnings`, feature-combination builds,
conformance selftest and check, MSRV 1.75 build, `size-report.sh --check`, and
`cargo publish --dry-run --locked`.

## 6. Publish, which is NOT mine to do

Two prerequisites only the owner can satisfy, and the release cannot happen without them:

1. **Create the `crates-io-publish` GitHub Environment with required reviewers.** Until it exists
   the manual-approval gate on the publish workflow is not actually enforced, so the workflow's
   safety is currently theatre.
2. **Add the `CARGO_REGISTRY_TOKEN` secret.**

There is deliberately no crates.io credential on this machine and the publish workflow is
dispatch-only. I will hand over the exact command and the package list when the gates are met, and
I will say plainly if a gate is NOT met rather than presenting a clean-looking release.

---

## What would make me say "do not publish yet"

Written down now, while nothing is at stake, so it is not renegotiated under pressure later:

- Gate 4 still open AND `MUTANTS.md` does not name what survives.
- The signing seam shipped without its conformance harness, so a host can install a broken signer
  and get silently invalid tokens.
- Any claim in README, KICKOFF or SECURITY that measurement contradicts.
- `cargo package --list` containing anything a consumer cannot use.
- A lens that has never run on opus over its own scope.

Publishing to crates.io is irreversible: a version number cannot be reused, and yanking is a
retraction, not an undo. That asymmetry is the reason the bar sits where it does.
