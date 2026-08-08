# oauth-as: kickoff

You are starting fresh on this repository. Read this first. It is written for someone who has no
context on busbar and does not need any.

## WHAT THIS IS

A standalone OAuth 2.1 Authorization Server LIBRARY in Rust. The host owns the HTTP listener, the
routes, TLS and persistence. The library owns the protocol.

It was developed inside a private workspace behind a CI gate that proved it took no dependency on
that workspace, then extracted here. It has no relationship to any other project and must never
grow one. If you find yourself reaching for something outside this repo, stop.

Two crates:
- `crates/oauth-as`, the publishable library.
- `crates/oauth-as-conformance`, a black-box harness. Never published. See "the harness" below,
  because WHO WROTE IT is the point.

## STATE, as of 2026-08-08

- `0.0.1` IS PUBLISHED to crates.io. It is a PLACEHOLDER that says so in its own docs and README,
  contains no implementation, and exists only to hold the name. Do not be confused by it.
- `0.1.0` is the first real release. NOT published. It is what you are working toward.
- Branches `main`, `dev`, `qa` all start at the same commit. Work on `dev`.
- Dual licensed `MIT OR Apache-2.0` from the first release, so there is no licence change to
  explain later. Every source file carries the SPDX header, copyright Matthew Jackson.
- `crates/oauth-as` declares `rust-version = "1.86"` and this is VERIFIED to build and test there.

## WHAT EXISTS

RFC 8628 device authorization grant state machine, PKCE S256 primitives, refresh rotation, client
authentication, introspection, and a storage trait the host implements.

## WHAT DOES NOT EXIST, and this is the work

1. **No HTTP surface.** No routes, no endpoints, no server.
2. **No RFC 8414 metadata document.** No `/.well-known/oauth-authorization-server`. The only mention
   of 8414 in the crate is a doc comment on `ServerConfig::issuer`.
3. **No authorization code endpoint.** `lib.rs` currently defers it as "a later pass".

Item 2 is the highest-value item and it is the gate for everything else. Nothing external can test
this crate until an external process can talk to it. That includes our own harness.

## THE HARNESS, and why it matters more than it looks

`crates/oauth-as-conformance` was written by an author who COULD NOT SEE THE LIBRARY. That was
deliberate. The library's own tests were written by the library's author, so the judge is
arms-length but the CHOICE OF WHAT TO TEST is not. The harness closes that gap.

It carries RFC test vectors quoted from RFC text with per-entry citations, schema validators
transcribed from RFC 6749 section 5 and RFC 8628 sections 3.2 and 3.5, and a PINNED third-party
client, `oauth2 = "=5.0.0"`, driven against the AS as a black box so that the client library, not
our assertions, decides whether responses are spec-legal. Pinned exactly on purpose: a silent client
upgrade must never change what "conformant" means.

`scripts/oauth-conformance.sh --check` cannot run yet, because it needs the AS served over HTTP.
`--selftest` does run and proves the gate can go RED on both its axes before its green is trusted.

RULES WHEN YOU MAKE IT RUN:
- Where the harness and the library disagree, THE RFC WINS.
- If neither is clearly right, prefer changing the harness's ASSUMPTION over the AS's BEHAVIOUR, and
  say which you did.
- ANY DEFECT THE HARNESS FINDS IS A SUCCESS OF THE METHOD. Never weaken an assertion to get green.
  If an assertion is itself wrong, name the RFC section that settles it before you change it.

KNOWN MISMATCH to resolve: the harness verifies RFC 9068 JWT access tokens against a `jwks_uri`, but
this crate's tokens are OPAQUE by design. Either the crate gains optional JWT tokens or the harness
narrows to what a library with opaque tokens can prove. Both are defensible. Pick one, justify it,
and make it consistent.

## CONFORMANCE: WHAT IS ACTUALLY AVAILABLE

Researched from primary sources, 2026-08-08. Do not redo this; do challenge it if you find better.

**There is no OAuth 2.1 conformance tester you can get a genuine green from.** OAuth 2.1 is still
`draft-ietf-oauth-v2-1-15` (2 March 2026), no certification programme, no official suite, no
official vectors.

**The OpenID Foundation suite has ZERO references to RFC 8628.** Nothing external tests the device
grant polling state machine at all: not `authorization_pending`, not `slow_down`, not
`expired_token`, not interval enforcement. Our in-house harness tests more of RFC 8628 than any
third-party tool in existence.

**One correction to earlier belief, worth knowing:** the OIDF suite's FAPI 2.0 Security Profile plan
has an explicit `plain_oauth` variant that runs against RFC 8414 metadata and never asks for an
`id_token`. IBM Verify SaaS is certified that way on the public register. So a non-OIDC AS CAN be
certified. But FAPI 2.0 demands PAR, sender-constrained tokens via mTLS or DPoP, `private_key_jwt`
or mTLS client auth, RFC 9207, and a browser-driven authorization code flow, and it tests zero
percent of the device grant. Pursue only if a customer demands FAPI 2.0.

**OAuch** (DistriNet/KU Leuven, MIT) is the only OAuth-first tool that cares about what this crate
does: RFC 6819 and RFC 9700 threat corpus, PKCE downgrade detection, six device-endpoint tests. It
is a web app with no CI mode; its device flow ends in a human-driven browser popup. A headless
runner is a spike, not a given.

**Do NOT bolt OIDC onto this crate to earn a Basic OP badge.** It would mean id_token issuance, a
JWKS endpoint, a UserInfo endpoint, a claims model, a user profile store and a locale layer, all of
which are host concerns this design deliberately pushed out. The badge would be true and
substantively misleading. Certify OIDC only if this actually becomes an identity provider.

**CORRECTED 2026-08-08, this claim was wrong.** The original text said: "Cheap and worth doing once
the metadata document exists: `authgent` ships a GitHub Action that lints an RFC 8414 discovery
document and flags things like `plain` PKCE. Small project, pin the version."

`authgent/authgent` does exist (Apache-2.0, PyPI `authgent-server`, tags through `v0.3.4`, a real
composite action at `authgent/authgent/.github/actions/mcp-lint@v0.3.4`). It is NOT a generic
RFC 8414 discovery linter. It is an MCP-OAuth conformance scanner: `scanner.py` fetches RFC 9728
Protected Resource Metadata FIRST, and when that is absent, which it always will be for a plain
OAuth AS that has no PRM endpoint, it returns one critical "not an MCP server" finding and SKIPS
every remaining check, including the RFC 8414 and PKCE checks this project wanted. There is no flag
to aim it at bare AS metadata.

The only way to unlock those checks would be to stand up a throwaway RFC 9728 PRM document this
project has no reason to own. That is the same "true but substantively misleading" trap this
document already warns about for OIDC bolt-ons, so it was not done. Not wired into CI.

(Their own marketplace README advertises `authgent/mcp-lint-action@v1`, a repository that 404s.
The reference that actually resolves is the one in their `docs/ci-integration.md`.)

OAuch was re-checked and KICKOFF's original assessment holds: interactive web UI only, no CLI, no
REST automation surface, no headless mode. A search for standalone RFC 8414 metadata validators,
OIDC discovery linters and conformance CLIs turned up only mock SERVERS, which test the opposite
direction. NOTHING additional could be confirmed and wired up honestly.

So the independent judges of this AS remain exactly two: the vendored RFC vectors with the
gate-goes-red self-test, and the pinned third-party `oauth2 = "=5.0.0"` client driving it as a
black box. The README must not imply otherwise.

## HOUSE RULES

- Red-before-green for every behavioural change. Write the failing test, SEE it fail, then fix.
- Full gate before every commit: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  --locked -- -D warnings`, `cargo test --workspace --locked`.
- A gate you have not seen go RED is a gate you cannot trust. Keep the selftest-first discipline.
- Keep the MSRV floor at 1.86 for the published crate. A library that forces consumers onto current
  stable is a library people cannot adopt. One use of `is_multiple_of` already became `% 2 == 0` to
  buy that floor. The harness may require newer, since nobody depends on it.
- Do NOT force a web framework on a consumer who wants only the library. Any HTTP surface is an
  optional feature or an example binary, and the no-server default stays intact.
- No em dashes, no en dashes, no non-ASCII.
- Never add Co-Authored-By or any AI attribution to a commit message.
- Push `dev`. `main` and `qa` are promotion branches and the owner decides.
- HONESTY OVER POLISH. The README states what is proven and what is not. Keep it accurate as things
  change. This is an authorization server. It does not get taken on trust, including by us.

## PUBLISHING

There is no crates.io credential on this machine. The owner rotated it immediately after the
placeholder went out, which was the right call. When `0.1.0` is ready:

1. `cargo publish --dry-run -p oauth-as` must pass.
2. Read `cargo package --list` LINE BY LINE. The repo is public and so is the tarball. Nothing
   private, nothing machine-specific, no absolute paths.
3. Hand the owner the command. Do not publish without his word. A crates.io publish is permanent:
   a version can be yanked, never deleted.

## THE ONE-LINE VERSION

Build the HTTP surface and the RFC 8414 metadata document, because until an external process can
talk to this crate, nothing can verify it and no claim about it can be checked.
