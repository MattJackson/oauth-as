# oauth-as: the goal, and what "100%" means

Written 2026-08-08. This file exists so that "done" is a thing that can be CHECKED rather than
felt. Every exit criterion below is a command someone can run, or an artifact someone can read.
If a criterion cannot be checked mechanically, it is written as a specific question with a
specific answer, not as a feeling about quality.

## THE GOAL

Build `oauth-as` into an embeddable OAuth 2.1 Authorization Server library that a stranger can
adopt on the evidence, not on trust, and publish it to crates.io AT 0.9.0.

**The publish target is 0.9.0, not 0.1.0.** Nothing goes to crates.io before then. 0.1.0 through
0.8.0 are built, tested and pushed through the dev/qa/main promotion pipeline, but they are not
published: a crates.io release is permanent, a version can be yanked but never deleted, and there
is no reason to spend permanent version numbers on a surface that is still changing shape every
release. The name is already held by the 0.0.1 placeholder, so there is nothing to defend.

At 0.9.0 the crate does what third party tooling and third party clients expect of an OAuth 2.1
authorization server (see ROADMAP.md), everything is green, and the work PAUSES so the owner can
test it himself. 1.0.0 comes after that, and only if it feels solid.

Three properties, in priority order. Where they conflict, the earlier one wins.

1. **CORRECT.** Every behaviour traces to an RFC section. Where the RFCs and our harness disagree,
   the RFC wins. Where an RFC leaves a choice, the choice is documented with its reasoning.
2. **PROVEN.** Correctness is demonstrated by tests an outsider can run, including tests written
   by an author who could not see the implementation, and including a mutation run that proves the
   tests actually constrain the code. Nothing is claimed that is not demonstrated.
3. **EFFICIENT.** Fast and small, with the claims gated in CI rather than asserted in prose. A
   consumer who does not enable a feature pays nothing for it, in dependencies, memory, or size.

Non-goals for 0.1.0, stated so nobody had to guess: no OIDC, no dynamic client registration
(RFC 7591), no DPoP, no PAR, no FAPI profile.

UPDATE at 0.9.0: all of those except OIDC and a FAPI profile have since landed, on purpose, via
the 0.2.0 to 0.8.0 releases in ROADMAP.md. **OIDC remains a non-goal** for the reason KICKOFF gives:
the badge it would earn would be true and substantively misleading. A FAPI 2.0 run is now
achievable and the remaining work is written down in
`crates/oauth-as-conformance/EXTERNAL-TOOLING.md`, including a genuine spec conflict worth knowing
about: FAPI 2.0 s5.3.2.1-9 forbids refresh token rotation, which OAuth 2.1 s6.1 and RFC 9700
s4.14.2 are precisely why this crate does it.

## WHAT 100% MEANS

100% is all ten gates below passing, on the `qa` branch, with no exceptions carried.

### Gate 1: the protocol is complete
- [x] RFC 8628 device authorization grant, full state machine
- [x] RFC 6749 s4.1 authorization code grant with mandatory PKCE (RFC 7636, S256 only)
- [x] RFC 6749 s6 refresh rotation, single use, absolute chain lifetime
- [x] RFC 6749 s4.4 client credentials
- [x] RFC 8414 authorization server metadata
- [x] RFC 7662 introspection
- [x] RFC 7009 revocation
- [x] RFC 9068 JWT access tokens plus RFC 7517 JWKS, behind an off-by-default feature

CHECK: every item above has a test file naming the RFC section it pins.

### Gate 2: an external process can talk to it
- [x] HTTP surface behind an off-by-default `http` feature, forcing no web framework on anyone
- [x] `crates/oauth-as/conformance-serve.sh` honouring the launch contract in
      `crates/oauth-as-conformance/src/lib.rs`

CHECK: `scripts/oauth-conformance.sh --check` starts the AS and reaches its metadata document.

### Gate 3: the independent harness is green
The harness was written by an author who could not see the library. That is the whole point of it:
the library's own tests were written by the library's author, so the judge is arms-length but the
CHOICE OF WHAT TO TEST is not. The harness closes that gap.

- [x] `scripts/oauth-conformance.sh --selftest` passes (the gate is proven able to go RED first)
- [x] `scripts/oauth-conformance.sh --check` passes against the live AS

CHECK: both commands exit 0. Any defect the harness found is recorded in the commit that fixed it,
with the RFC section that settled it and a note of WHICH SIDE changed, the harness's assumption or
the server's behaviour. No assertion was ever weakened to obtain green.

### Gate 4: the tests actually constrain the code
- [x] `cargo mutants -p oauth-as` run to completion
- [ ] Every surviving mutant is either killed by a new test, or recorded in writing as equivalent
      with the reason. **NOT MET.** Every survivor on the measured surface is closed, but eight
      modules (registration, resource_metadata, token_exchange, par, rar, dpop, mtls,
      client_assertion) landed AFTER that run and have never been mutation tested. That is the
      same position `http.rs` was in before this session. See MUTANTS.md.

CHECK: the mutants report is clean or annotated. A surviving mutant is a hole in the suite, not a
curiosity.

### Gate 5: efficiency is gated, not asserted
- [x] Allocation counts on the hot paths pinned by a zero-dependency counting allocator
- [x] Size bounds pinned for the core public types
- [x] Default feature set empty: no HTTP stack, no crypto beyond PKCE, in a default build

CHECK: `cargo tree -p oauth-as` on default features shows only serde, serde_json, getrandom, sha2,
base64. The allocation tests pass, and each was proven able to fail.

### Gate 6: it builds where it claims to
- [x] MSRV is the TRUE floor, verified, not guessed. Measured as 1.75: 1.74 fails only on RPITIT
      in `store.rs`, 1.75 and 1.80 compile clean.
- [x] `Cargo.lock` in a format the floor toolchain can parse, so `--locked` is honest at the floor
- [x] Per-feature floors documented separately where an optional dependency raises them

CHECK: `cargo +1.75 test -p oauth-as --locked` passes.

### Gate 7: the promotion pipeline works
- [x] push to `dev` runs the fast gate: fmt, clippy, test
- [x] push to `qa` runs the full suite: MSRV, conformance selftest, live conformance check,
      third-party client drive, mutants, package dry run
- [x] `main` publishes only by explicit owner action, never automatically

CHECK: a real push to `dev` goes green, then a real push to `qa` goes green. Observed, not assumed.

### Gate 8: the claims are true
- [x] README states exactly what is proven and exactly what is not
- [x] No third-party verification is claimed that was not actually run. UPDATED as the position
      changed during the work: the independent judges are now the vendored RFC vectors, TWO pinned
      third-party clients in two languages (`oauth2 = "=5.0.0"` for Rust and
      `golang.org/x/oauth2 v0.36.0` for Go), and the `authgent` scanner, which became applicable
      once RFC 9728 landed and IS now run in CI with its findings recorded rather than silenced.
      OAuch still has no headless mode and its authors say so. There is still no OAuth 2.1
      certification programme in existence, so no certification claim is possible for this or any
      other implementation, and none is made.
- [x] KICKOFF.md corrected where research contradicted it

CHECK: read the README against this list. Every claim maps to a command in this file.

### Gate 9: it is safe to publish
- [x] `cargo publish --dry-run --locked -p oauth-as` passes
- [x] `cargo package --list` read LINE BY LINE. The repo is public and so is the tarball: nothing
      private, nothing machine specific, no absolute paths
- [ ] Adversarial security review completed, every finding either fixed or recorded with its
      reasoning. **PARTIALLY MET.** Two reviews run, all findings fixed (one critical, three high,
      several medium and low). But mTLS, RAR and consent landed AFTER the second review and have
      had none. The first two reviews each found serious defects on smaller surface.

CHECK: the package list is in the release commit message or the PR body, so the review is
auditable after the fact.

### Gate 10: the owner says go, at 0.9.0
- [ ] Every gate above passes at version 0.9.0
- [ ] The publish command is handed to the owner. It is NOT run by an agent.
- [ ] Work PAUSES there so the owner can test the published crate himself

A crates.io publish is permanent. A version can be yanked, never deleted. There is deliberately no
crates.io credential on the build machine, and the publish workflow is dispatch-only behind a
manual-approval environment so it cannot fire by accident. An agent preparing the release and an
agent performing it are different things, and only the first one happens here.

After the pause, 1.0.0 is cut only if the owner's own testing agrees with the evidence. See the
1.0.0 criteria in ROADMAP.md: the feeling is allowed to veto the checklist, it is not allowed to
substitute for it.

## ORDER OF WORK

The ordering is forced by dependencies, not preference.

1. HTTP surface and serve shim. Nothing external can verify this crate until an external process
   can talk to it, so this gates everything downstream. (Gate 2)
2. Harness green. Fix what it finds, RFC first. (Gate 3)
3. JWT feature, then re-run the harness, which tests RFC 9068 tokens against a JWKS. (Gates 1, 3)
4. Mutants, then close the holes it exposes. Do this AFTER the feature work, or it just gets
   re-run. (Gate 4)
5. Efficiency gates and MSRV drop to 1.75. (Gates 5, 6)
6. Security review findings resolved. (Gate 9)
7. README and KICKOFF honesty pass, once the facts are final. (Gate 8)
8. Push `dev`, observe green. Push `qa`, observe green. (Gate 7)
9. Package review, dry run, hand the command to the owner. (Gates 9, 10)

## THE STANDING RULES

These are not negotiable and they outrank convenience.

- Red before green. Write the failing test, SEE it fail, then fix. A gate you have not seen go red
  is a gate you cannot trust.
- Where the harness and the library disagree, THE RFC WINS. If neither is clearly right, prefer
  changing the harness's ASSUMPTION over the server's BEHAVIOUR, and say which you did.
- Any defect the harness finds is a SUCCESS of the method. Never weaken an assertion to get green.
  If an assertion is itself wrong, name the RFC section that settles it before changing it.
- Honesty over polish. This is an authorization server. It does not get taken on trust, including
  by us.
- Tests live in their own files, never inline with implementation.
- No em dashes, no en dashes, no non-ASCII.
- Never any AI attribution, in a commit message or anywhere else.
