#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# WHAT DOES oauth-as COST A HOST, IN BYTES, AND WHICH FEATURE COSTS IT.
#
# Run it:
#   scripts/size-report.sh                 the whole table
#   scripts/size-report.sh --check         the same, and FAIL if a row is over budget
#   scripts/size-report.sh --selftest      prove --check can go RED, by forcing a budget to 1 byte
#   scripts/size-report.sh --rows a,b,c    just those rows (names from the table below)
#   scripts/size-report.sh --tsv           machine readable, one row per line
#
# ---------------------------------------------------------------------------------------------
# WHY IT IS BUILT THIS WAY. Three things make a naive measurement wrong, and each cost a wrong
# number before it was understood.
#
# 1. THE .rlib IS NOT A COST. `crates/oauth-as`'s rlib is megabytes, and almost none of it is
#    linked into anything: it is crate metadata plus generic bodies that no consumer instantiates.
#    Quoting it would overstate the cost by more than an order of magnitude. The only honest
#    number is the DELTA between a linked binary that uses the crate and a matched binary that
#    does not, which is what this script builds.
#
# 2. LTO DELETES WHAT NOTHING CALLS. `scripts/size-probe` therefore EXERCISES every surface it
#    measures rather than merely enabling it. A first hand measurement of `http,jwt` read
#    identical to `jwt` alone, because the probe never dispatched an HTTP request and the linker
#    threw the entire service away. So every row here means "what a host pays when it USES this",
#    and `scripts/size-probe/src/exercise*.rs` is the definition of what "uses" means for each.
#    A host that enables a feature and never calls it pays close to nothing, which is a real and
#    useful property of the design, but it is not what a feature COSTS.
#
# 3. SEGMENTS ARE PAGE GRANULAR AND SECTIONS ARE NOT. On arm64 macOS a Mach-O `__TEXT` SEGMENT is
#    rounded to 16 KB, so a segment-level or file-level measurement cannot see a difference
#    smaller than that and reports it as zero. This script sums SECTION sizes inside __TEXT,
#    __DATA_CONST and __DATA instead, which are byte exact, so a 300 byte feature reads as 300
#    bytes rather than as nothing. Zero-fill sections (`__bss`, `__thread_bss`) are excluded: they
#    occupy no bytes in the linked image.
#
# WHAT THE NUMBERS INCLUDE THAT IS NOT STRICTLY THIS CRATE, stated because it is not separable
# and pretending otherwise would be the dishonest option:
#
#   * THE PROBE'S OWN DRIVER. Something has to call the library, and under `lto = "fat"` the
#     library is inlined INTO that caller, so no tool can cleanly split them: `cargo bloat`
#     attributes about 48 KiB of the default row to `size_probe`, and much of that is oauth-as
#     code that got inlined. Read every row as an upper bound that includes a host's own calling
#     code for the same surface.
#   * MemoryStorage. The probe uses this crate's in-memory `Storage`, whose impl is about 14 KiB
#     in the default row. A real host substitutes its own store of comparable or greater size, so
#     this is not an overstatement so much as a stand-in.
#   * The std library growth oauth-as causes (formatting, BTreeMap, HashMap and so on), which is
#     about 33 KiB on the default row. It is a real cost to a binary that did not already have it,
#     and it is exactly what the `(host has deps)` rows are for.
#
# AND THE ONE THING NO ROW SHOWS: `AuthorizationServer<S, C>` is monomorphized per (Storage,
# Clock) pair. MEASURED, 2026-08-09, on the default surface: a SECOND instantiation costs 53,548
# bytes, which is 27% of the whole default row again. One pair is the normal case and every row
# here is one pair; a host that instantiates several pays roughly this per extra pair. That is
# the price of the storage seam being allocation-free and devirtualized, and the root Cargo.toml
# records the trade. It is written here because a trade with no number attached is not a trade.
#
# The profile is scripts/size-probe/Cargo.toml's `[profile.release]` and its reasoning is written
# down there. It is deliberately NOT this repository's root `[profile.release]`: cargo profiles are
# honored only for the workspace being built, so nothing in our root manifest reaches a consumer,
# and a report measured under settings a consumer never gets would be a report about us.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_DIR="$REPO_ROOT/scripts/size-probe"
# Per-configuration target directories, under one root, so that a second run is cached and so that
# two configurations can never overwrite each other's binary (which they would in one directory,
# and the second measurement would silently be of the first binary).
TARGET_ROOT="${SIZE_REPORT_TARGET_ROOT:-$REPO_ROOT/target/size-report}"

HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"

# Every oauth-as feature, mirrored in the probe as `f-<name>`. --all-features is this list.
ALL_FEATURES="f-http,f-axum,f-jwt,f-jwt-p256,f-jwt-pkcs8,f-mtls,f-par,f-jar,f-rar,f-dpop,f-client-assertion,f-consent,f-token-exchange,f-resource-metadata,f-test-util"

# ---------------------------------------------------------------------------------------------
# THE ROWS.
#
# `name|probe features|baseline probe features|what the row answers`
#
# The baseline column is what makes a row STANDALONE or MARGINAL:
#   * an empty baseline is the matched empty binary, so the number is "what oauth-as adds to a
#     program that had nothing";
#   * `hostdeps` is a binary that already links AND EXERCISES serde, serde_json, http, bytes and
#     sha2, so the number is "what oauth-as adds to a host that already has its dependencies".
# The second is the number most evaluating hosts actually want, and it is not the first minus the
# dependency sizes: serde and serde_json are GENERIC, so the machinery instantiated for a host's
# types is different machine code from the same machinery instantiated for ours. Only the
# non-generic core is shared, which is why the saving is far short of what "the deps compile once"
# suggests.
ROWS=(
  "default|lib||the protocol core: four grants, the authorization endpoint, RFC 8414 metadata, RFC 7662, RFC 7009, RFC 7591"
  "http|f-http||the core plus the HTTP service, with a request dispatched to every route"
  "axum|f-axum||the above plus the axum Router adapter and the tokio a host binds a listener with"
  "jwt (seam only)|f-jwt||the core with RFC 9068 at+jwt access tokens over a HOST-supplied ES256 signer: no curve implementation at all"
  "jwt-p256|f-jwt-p256||the above plus the built-in p256 backend, which is what every consumer of jwt had before the seam"
  "jwt-pkcs8 (called)|f-jwt-pkcs8||jwt-p256, plus a PKCS#8 key actually exported and re-imported"
  "jwt-pkcs8 (never called)|f-jwt-pkcs8-unused||jwt-p256, with the jwt-pkcs8 feature ON and its two constructors never reached"
  "mtls|f-mtls||RFC 8705 thumbprints, subject matching and certificate-bound tokens"
  "par|f-par||RFC 9126 pushed authorization requests, pushed and redeemed"
  "jar|f-jar||RFC 9101 signed request objects (implies jwt)"
  "rar|f-rar||RFC 9396 authorization_details, parsed, type-checked and narrowed"
  "dpop|f-dpop||RFC 9449 proof verification (implies jwt)"
  "client-assertion|f-client-assertion||RFC 7523 private_key_jwt and client_secret_jwt (implies jwt)"
  "consent|f-consent||consent records, withdrawal cascade and RFC 9470 step-up"
  "token-exchange|f-token-exchange||RFC 8693 token exchange"
  "resource-metadata|f-resource-metadata||the RFC 9728 document type"
  "test-util|f-test-util||the Storage conformance harness, RUN, not merely constructed"
  "http,jwt|f-http,f-jwt||the conformance server's own feature set"
  "axum,jwt|f-axum,f-jwt||a host that wants a mountable Router and signed tokens"
  "all-features|$ALL_FEATURES||every feature this crate has, every one of them exercised"
  "default (host has deps)|lib|hostdeps|the core, added to a host that already links serde_json, http, bytes and sha2"
  "jwt (host has deps)|f-jwt|hostdeps|as above, with RFC 9068 signing"
  "http,jwt (host has deps)|f-http,f-jwt|hostdeps|as above, with the HTTP service"
  "all-features (host has deps)|$ALL_FEATURES|hostdeps|everything, added to a host that already has the shared crates"
)

# ---------------------------------------------------------------------------------------------
# THE BUDGETS, and the house rule that goes with them.
#
# THESE ARE A DESIGN GATE, NOT A RECORD OF THE PRESENT. If a change blows a budget, the change is
# what gets fixed. Raising a number here is a decision with a reason written next to it, in the
# same spirit as tests/allocation.rs, which is the gate this one is modelled on.
#
# PLATFORM SPECIFIC ON PURPOSE. Code size is a property of the target's instruction encoding, and
# an arm64 measurement is not an x86-64 one. Budgets are recorded for the platform they were
# measured on, and `--check` REFUSES on any other platform rather than passing vacuously against
# numbers that do not describe it. The CI job runs on the platform these were taken on.
#
# Every number is the measured value at 0.9.0 plus a headroom allowance. The allowance is 5% or
# 4 KB, whichever is larger, rounded up to the nearest KB: enough that an innocuous refactor or a
# compiler upgrade does not go red for nothing, tight enough that a whole new subsystem cannot
# arrive unnoticed. The measured figures the budgets were set from are in the table this script
# prints, and are quoted in README.md's Cost section with the same caveats.
budget_for() {
  case "$HOST_TRIPLE:$1" in
    # ALL SIX MEASURED 2026-08-09 on aarch64-apple-darwin, rustc 1.97.0, by this script.
    #
    # the protocol core, every grant driven end to end. Measured 221,945 bytes at 0.9.1,
    # RE-MEASURED from 199,953 at 0.9.0. The +21,992 is the RESURRECTION RULE and it is
    # unconditional because revocation is: a `RevocationBarrier`, the predicate every write
    # consults, four new `Storage` methods, `AuthorizationCodeState::Replayed` with its serde arms,
    # and the undo path issuance needs when a revocation lands between its two writes.
    #
    # RAISED DELIBERATELY, which this file's own rule permits only when the growth buys something
    # and the reason is written next to the number. What it buys: in 0.9.0 a detected refresh-token
    # reuse or authorization-code replay could be raced by an issuance already in flight across the
    # ES256 signing await, so the AS revoked a family and the token it was containing stayed live.
    # That was a HIGH severity known defect shipped in the published alpha, open under any remote
    # signer, and closing it is the entire reason 0.9.1 exists. 21.5 KiB is what a revocation that
    # cannot be undone costs.
    #
    # THE CHANGE WAS FIXED FIRST, before the number moved: the barrier collection was a `HashMap`
    # keyed by a compound enum while every read of it is a linear scan over three scopes at once,
    # so the map bought nothing and cost a hashbrown instantiation. Making it a `Vec` took 2,204
    # bytes off this row and put the `http` row back under its budget without touching that one.
    #
    # RE-MEASURED 2026-08-13 at 0.9.1 FINAL: 234,489. The figures above (221,945 / 199,953) were
    # taken mid-release and are superseded; the honest before-and-after is 209,376 at the rebuilt
    # v0.9.0 tag against 234,489 now, so the resurrection rule cost this row 25,113 bytes.
    #
    # RAISED 2026-08-13, from 234,496, and NOT because the code grew.
    #
    # It was left at 234,496 earlier the same day on the argument that a passing row does not get
    # its number moved. It passed by SEVEN BYTES. It then went RED on CI, on macos-26-arm64 — the
    # same aarch64-apple-darwin triple — at 234,656, over by 161.
    #
    # THE MEASUREMENT IS NOT PATH INDEPENDENT, WHICH IS THE REAL DEFECT. The probe links panic
    # `Location` strings, and they are ABSOLUTE, because oauth-as is an out-of-workspace path
    # dependency of the probe. So the byte count includes the length of the checkout directory.
    # Measured, same tree and same toolchain, only the directory differing: 218,989 from `/tmp/oa`
    # against 219,229 from a 73-character worktree. 240 bytes of pure path length. A GitHub runner
    # checks out at `/Users/runner/work/oauth-as/oauth-as`, which is longer than a typical local
    # path, and that is the 161 bytes.
    #
    # A gate whose verdict depends on where the repository happens to sit is not a gate. Seven
    # bytes of margin could never survive it, and leaving it there was the wrong call: the row was
    # not passing on its merits, it was passing on this machine.
    #
    # THE NUMBER IS THE STOPGAP. THE FIX IS `--remap-path-prefix` in the probe profile, so the
    # embedded paths are constant and the measurement is reproducible anywhere. That is 0.9.2 work
    # because it changes every row at once and every budget has to be re-taken with it. Until then
    # this row carries ~4 KiB, which is the same order as every other row here and enough to
    # absorb the path-length variance rather than be decided by it.
    aarch64-apple-darwin:default) echo 238592 ;;
    # + the HTTP service with a request dispatched to every route. Measured 397,429. Roughly
    # doubling the core is what a wire surface costs: a router, a form and query parser, a body
    # reader, and one response serializer per endpoint.
    # RAISED 2026-08-13 at 0.9.1 FINAL, from 417,792. Measured 438,009, over by 20,217.
    #
    # WHAT BOUGHT IT, attributed rather than asserted. The v0.9.0 tag was rebuilt in a worktree on
    # this machine and toolchain and measured with its OWN probe: `http` was 404,943 there, so this
    # row grew 33,066 bytes across the release. The `default` row grew 25,113 over the same span,
    # which is the resurrection rule and is unconditional. So 25,113 of this row's growth is the
    # core arriving, and roughly 8,000 is the HTTP surface's own: per-request `tokio::spawn`, the
    # build-time route normalisation that made matching byte-exact on the raw wire path, the two
    # new `ApprovalRequest` fields, and the RAR refusal sites.
    #
    # CAVEAT ON THE COMPARISON, because it changes what the number means: each tree was measured
    # with its own `scripts/size-probe`, and 0.9.1's probe exercises more surface than 0.9.0's did.
    # Some of the growth is therefore the probe reaching code that was always there. The bytes are
    # real for a host that reaches the same code; they are not all NEW code.
    aarch64-apple-darwin:http) echo 442368 ;;
    # + the Router adapter AND a tokio multi-thread runtime with a bound listener, because that is
    # what a host turns this feature on to do. Measured 614,661; the 212 KiB over the `http` row is
    # almost entirely the runtime, which is the host's cost and not this crate's.
    # RAISED 2026-08-13 at 0.9.1 FINAL, from 646,144. Measured 677,639, over by 31,495. Against the
    # rebuilt v0.9.0 (623,963) this row grew 53,676: the 25,113 of core, the ~8,000 of HTTP surface
    # accounted for on that row, and the balance is the axum adapter compiled against both.
    aarch64-apple-darwin:axum) echo 681984 ;;
    # + RFC 9068 signing over a HOST-SUPPLIED `Es256Signer`, the RFC 7517 JWKS, and the JWK
    # parsing the verification seam rests on. NO curve implementation: this is what a host with
    # its key in a KMS pays. Measured 244,013, RE-MEASURED 2026-08-09 when the seam split `jwt`
    # from `jwt-p256`; the row was 274,254 when `jwt` implied p256, so the split took 29.5 KiB off
    # a host that brings its own backend. The budget comes DOWN with the measurement, because a
    # budget left at the old number would stop being a gate on this row at all.
    # RE-MEASURED 2026-08-10 at 0.9.1: 256,491, up 12,478 from 244,013. The rise is the default
    # row's rise minus what this row already carried, which is the same resurrection rule seen
    # through a feature that adds signing on top of it.
    aarch64-apple-darwin:"jwt (seam only)") echo 271360 ;;
    # + the built-in p256 backend, which is what every consumer of `jwt` had before the seam.
    # Measured 274,725 against the pre-seam `jwt` row's 274,254: the seam costs a host that keeps
    # the built-in backend 471 bytes, which is the `Arc<dyn Es256Signer>` vtable and the boxed
    # future's shim. It does NOT include PKCS#8 key loading, which is a separate `jwt-pkcs8`
    # feature and, measured, a separate 30,536 bytes paid only by a host that calls the two
    # constructors behind it.
    # RE-MEASURED 2026-08-10 at 0.9.1: 291,669, up 16,944 from 274,725. Same cause as the two rows
    # above; the p256 backend itself did not move.
    aarch64-apple-darwin:jwt-p256) echo 308224 ;;
    # the conformance server's own feature set. Measured 440,476, down from 461,974 before the
    # signing seam: `http,jwt` is now the HTTP surface plus the seam, with no curve.
    # RAISED 2026-08-13 at 0.9.1 FINAL, from 462,848. Measured 472,520, over by 9,672. Against the
    # rebuilt v0.9.0 (440,287) it grew 32,233, which is the core's 25,113 plus the HTTP surface's
    # own. The signing seam did not move: the `jwt` and `jwt-p256` rows both still PASS, and were
    # deliberately not raised.
    aarch64-apple-darwin:"http,jwt") echo 476160 ;;
    # every feature, every one exercised. Measured 1,170,306, RE-MEASURED 2026-08-09 for the
    # signing seam. It was 1,165,636: the +4,670 is the seam itself (two traits, the object-safe
    # bridge, the verifier indirection at three call sites) plus the `signer_conformance` harness,
    # which `test-util` now carries alongside the `Storage` one. This is the ceiling on what this
    # crate can cost anyone, and it is the row a new subsystem shows up in first.
    # RAISED 2026-08-13 at 0.9.1 FINAL, from 1,229,824. Measured 1,372,273, over by 142,449 — by far
    # the largest overrun in the table, and the one that had to be attributed before it was allowed.
    #
    # IT IS ALMOST ALL `test-util`. Against the rebuilt v0.9.0 this row grew 203,014 bytes, and the
    # `test-util` row alone grew 121,819 of that (360,936 -> 482,755). Subtract the 25,113 of core
    # every row took and `test-util` is 96,706 bytes bigger on its own account. That is the
    # `Storage` conformance harness gaining twenty-seven checks, each with a planted fault: the
    # checks a host runs against its own store to find out whether it honours the resurrection rule.
    # The remaining ~81,000 is spread across the other thirteen features plus the cross-feature
    # monomorphisation that only `all-features` links at all.
    #
    # THIS IS THE ROW A HOST NEVER SHIPS. `test-util` is a dev-dependency feature and it is now the
    # largest single feature in the crate, larger than the whole HTTP surface. No production binary
    # enables it, and no other budgeted row includes it. Paying 96 KiB in a test binary to tell a
    # stranger's store that it silently loses revocations is the trade this release exists to make.
    #
    # It is still the ceiling on what this crate can cost anyone, and still the row a new subsystem
    # shows up in first — but read it knowing the harness dominates it.
    aarch64-apple-darwin:all-features) echo 1378304 ;;
    *) echo "" ;;
  esac
}

# --selftest forces every budget to an impossible value so the gate has to go red. The wrapper is
# separate from budget_for() so that the recorded numbers above stay the only place a real budget
# is written down, which is what the house rule about raising one depends on.
budget_for_mode() {
  if [ -n "$SELFTEST_BUDGET" ]; then
    # Only for a row that HAS a real budget, so the self-test cannot invent a gated row and then
    # congratulate itself for failing on it.
    if [ -n "$(budget_for "$1")" ]; then printf '%s' "$SELFTEST_BUDGET"; fi
    return
  fi
  budget_for "$1"
}

# The rows `--check` gates. Not every row: a gate over twenty numbers is a gate that goes red for
# noise and gets ignored. These six are the feature sets a real consumer actually picks, and any
# regression big enough to matter shows up in at least one of them.
# `jwt (seam only)` AND `jwt-p256` are both gated, because after the seam they are two different
# consumers with two different costs, and a gate on only one of them would let the other drift.
GATED_ROWS=("default" "http" "axum" "jwt (seam only)" "jwt-p256" "http,jwt" "all-features")

# ---------------------------------------------------------------------------------------------
# The instrument: the sum of the byte-exact SECTION sizes in the loadable code and data segments.

section_bytes() {
  local binary="$1"
  case "$HOST_TRIPLE" in
    *-apple-darwin)
      # `size -m` lists sections under their segment. __LINKEDIT (symbol tables, dyld fixups) is
      # excluded because it is bookkeeping whose size tracks symbol NAMES, and __PAGEZERO because
      # it is an address reservation and not bytes.
      size -m "$binary" | awk '
        /^Segment __(TEXT|DATA_CONST|DATA):/ { inseg = 1; next }
        /^Segment / { inseg = 0 }
        inseg && /^\tSection / && $0 !~ /zerofill/ { total += $3 }
        END { print total + 0 }'
      ;;
    *)
      # GNU/ELF: sysv format, one section per line, allocated sections only.
      size -A "$binary" | awk '
        $1 ~ /^\.(text|rodata|data|data\.rel\.ro|got|got\.plt|plt|plt\.sec|init_array|fini_array|eh_frame|eh_frame_hdr|gcc_except_table)$/ { total += $2 }
        END { print total + 0 }'
      ;;
  esac
}

# Build one configuration and return its section byte count.
measure() {
  local features="$1"
  local key
  key="$(printf '%s' "${features:-none}" | tr ',' '_')"
  local target_dir="$TARGET_ROOT/$key"
  # --locked, and it is not optional for a gate whose budgets are BYTE-EXACT. The probe has its
  # own committed scripts/size-probe/Cargo.lock; without --locked cargo is free to resolve a newer
  # patch of any dependency at any time, so a budget measured against one resolve is being checked
  # against a different one, and the gate goes red for a reason that is not a change to this
  # repository. A budget against a moving target is not a budget.
  local args=(build --release --quiet --locked --target-dir "$target_dir")
  if [ -z "$features" ]; then
    args+=(--no-default-features)
  else
    args+=(--features "$features")
  fi
  if ! ( cd "$PROBE_DIR" && cargo "${args[@]}" >&2 ); then
    echo "size-report: the probe failed to build for features '${features:-<none>}'." >&2
    echo "size-report: a size gate that skips a configuration it cannot build is a gate that" >&2
    echo "size-report: cannot fail, so this is fatal rather than a missing row." >&2
    exit 1
  fi
  local bytes
  bytes="$(section_bytes "$target_dir/release/size-probe")"
  if [ -z "$bytes" ] || [ "$bytes" -le 0 ]; then
    echo "size-report: measured zero bytes for '${features:-<none>}', which means the instrument" >&2
    echo "size-report: did not understand this platform's object format. Refusing to report it." >&2
    exit 1
  fi
  printf '%s' "$bytes"
}

human() {
  # KiB to one decimal, which is the resolution anyone reading this can act on.
  awk -v b="$1" 'BEGIN { printf "%.1f", b / 1024 }'
}

# ---------------------------------------------------------------------------------------------

MODE="table"
ONLY=""
SELFTEST_BUDGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    --selftest) MODE="selftest" ;;
    --tsv) MODE="tsv" ;;
    --rows) ONLY="$2"; shift ;;
    # Internal, set only by --selftest re-invoking this script. Forces every budget to this many
    # bytes so a green run has to go red. Not documented in --help because it is not a knob:
    # anybody who used it by hand would be turning the gate off.
    --force-budget) SELFTEST_BUDGET="$2"; shift ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "size-report: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

# THE SELF-TEST, and this script was the ONE shell gate in this repository without one.
#
# scripts/oauth-conformance.sh, scripts/oauth-interop.sh and scripts/oauth-mcp-lint.sh all run a
# --selftest in CI before their --check is believed, on the house rule that a gate nobody has
# watched go red is worth nothing. This gate had no such proof, and it has more moving parts than
# any of them: a per-platform budget table, an awk section parser that reports zero on a format it
# does not understand, and a `--rows` filter. Any one of those quietly emptying the gated set
# would leave `--check` printing "every gated feature set is within its recorded budget" over
# nothing at all.
#
# WHAT IT PROVES, precisely: that a --check run whose budgets are impossible to meet exits 1 and
# names the row. That covers the whole chain -- the row set is non-empty, the probe built, the
# instrument returned a positive byte count, the comparison happened, and the failure reaches the
# exit status -- because a break anywhere in it produces a 0 instead.
#
# ONE ROW, not seven: this re-links the probe, and the proof is about the mechanism rather than
# about any particular feature set. `default` is the cheapest and is gated in every run.
if [ "$MODE" = "selftest" ]; then
  echo "size-report: SELF-TEST. Re-running --check with every budget forced to 1 byte."
  echo "size-report: the run below MUST fail. If it passes, this gate cannot go red and every"
  echo "size-report: green it has ever produced means nothing."
  echo
  if "${BASH_SOURCE[0]}" --check --rows default --force-budget 1; then
    echo >&2
    echo "size-report: SELF-TEST FAILED: --check exited 0 against a 1 byte budget." >&2
    echo "size-report: the gate is not comparing anything. Fix it before trusting a green." >&2
    exit 1
  fi
  echo
  echo "size-report: self-test passed: --check went RED against an impossible budget, naming the"
  echo "size-report: row. The comparison, the measurement and the exit status all work."
  exit 0
fi

if [ "$MODE" = "check" ]; then
  missing=0
  for row in "${GATED_ROWS[@]}"; do
    if [ -z "$(budget_for "$row")" ]; then missing=1; fi
  done
  if [ "$missing" = 1 ]; then
    cat >&2 <<EOF
size-report: no size budgets are recorded for $HOST_TRIPLE.

Code size is a property of the target's instruction encoding, so budgets measured on one platform
do not describe another. This gate REFUSES rather than passing against numbers that do not apply:
a gate that cannot fail is worth nothing. Either run it on a platform with recorded budgets, or
record a set for this one by running scripts/size-report.sh here and adding the measured figures
to budget_for() in this file, with the date, toolchain and reasoning beside them.
EOF
    exit 1
  fi
fi

# Baselines are shared across rows, so measure each exactly once.
#
# Memoized in a newline-delimited "key<TAB>value" string rather than an associative array, because
# `declare -A` is bash 4 and macOS ships bash 3.2 as /bin/bash. This script gates a macOS runner
# (the recorded budgets are arm64), so bash 4 is exactly the thing it cannot assume.
BASELINE_CACHE=""
baseline_for() {
  local features="${1:-none}"
  local hit
  hit="$(printf '%s\n' "$BASELINE_CACHE" | awk -F'\t' -v k="$features" '$1 == k { print $2; exit }')"
  if [ -z "$hit" ]; then
    hit="$(measure "$1")"
    BASELINE_CACHE="$(printf '%s\n%s\t%s' "$BASELINE_CACHE" "$features" "$hit")"
  fi
  printf '%s' "$hit"
}

if [ "$MODE" = "table" ]; then
  echo "oauth-as linked size report"
  echo "  platform : $HOST_TRIPLE"
  echo "  toolchain: $(rustc -vV | sed -n 's/^rustc //p')"
  echo "  profile  : scripts/size-probe [profile.release] (lto = fat, codegen-units = 1, opt-level = 3, panic = unwind)"
  echo "  measured : sum of byte-exact section sizes in the loadable code and data segments"
  echo "  meaning  : the delta over a matched baseline binary, with the surface EXERCISED (see scripts/size-probe/src/)"
  echo
  printf '%-28s %12s %12s %10s  %s\n' "feature set" "baseline" "linked" "delta" "budget"
  printf '%-28s %12s %12s %10s  %s\n' "----------------------------" "------------" "------------" "----------" "------"
fi

status=0
for spec in "${ROWS[@]}"; do
  IFS='|' read -r name features baseline_features description <<< "$spec"
  if [ -n "$ONLY" ] && [[ ",$ONLY," != *",$name,"* ]]; then continue; fi
  # In --check mode, build ONLY what is gated. The other rows are for a human reading the table;
  # building them in CI would be minutes of fat-LTO link time spent on numbers nothing fails on.
  if [ "$MODE" = "check" ] && [[ " ${GATED_ROWS[*]} " != *" $name "* ]]; then continue; fi

  base="$(baseline_for "$baseline_features")"
  total="$(measure "$features${baseline_features:+,$baseline_features}")"
  delta=$((total - base))

  budget="$(budget_for_mode "$name")"
  case "$MODE" in
    tsv)
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$features" "$base" "$total" "$delta" "$description"
      ;;
    *)
      note=""
      if [ -n "$budget" ] && [ "$budget" != "0" ]; then
        note="$(human "$budget") KiB"
        if [ "$delta" -gt "$budget" ]; then
          note="$note OVER"
          if [ "$MODE" = "check" ]; then
            echo "size-report: FAIL: '$name' is $(human "$delta") KiB against a budget of $(human "$budget") KiB (+$((delta - budget)) bytes)" >&2
            status=1
          fi
        fi
      fi
      if [ "$MODE" = "table" ]; then
        printf '%-28s %12s %12s %9s  %s\n' "$name" "$base" "$total" "$(human "$delta") KiB" "$note"
      fi
      ;;
  esac
done

if [ "$MODE" = "check" ]; then
  if [ "$status" = 0 ]; then
    echo "size-report: every gated feature set is within its recorded budget."
  else
    cat >&2 <<'EOF'

A budget is a DESIGN gate. The rule this project runs on, the same one tests/allocation.rs runs
on: when a change blows a budget, the change gets fixed, not the number. If the growth is
genuinely the cost of something worth having, raising the budget is allowed, but it is a decision
that gets written down next to the number in scripts/size-report.sh, with what bought it.
EOF
  fi
fi
exit "$status"
