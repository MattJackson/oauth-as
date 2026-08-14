#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# WHAT DOES oauth-as COST A HOST, IN BYTES, AND WHICH FEATURE COSTS IT.
#
# Run it:
#   scripts/size-report.sh                 the whole table
#   scripts/size-report.sh --check         the same, and FAIL if a row is outside its band
#   scripts/size-report.sh --selftest      prove --check can go RED, on both ends of the band
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
# Clock) pair. MEASURED, 2026-08-09, on the default surface: a SECOND instantiation cost 53,548
# bytes. One pair is the normal case and every row here is one pair; a host that instantiates
# several pays roughly this per extra pair. That is the price of the storage seam being
# allocation-free and devirtualized, and the root Cargo.toml records the trade. It is written here
# because a trade with no number attached is not a trade.
#
# THAT FIGURE IS THE ONE NUMBER IN THIS FILE NOT FROM THE 2026-08-13 RUN. It predates both
# --remap-path-prefix and the `ScopeSet` change, and there is no row here that reproduces it: it
# was taken by hand with a probe modified to instantiate a second pair. Since the change it
# predates made the default surface SMALLER, treat 53,548 as an upper bound rather than a current
# reading, and re-take it by hand before quoting it as anything tighter.
#
# The profile is scripts/size-probe/Cargo.toml's `[profile.release]` and its reasoning is written
# down there. It is deliberately NOT this repository's root `[profile.release]`: cargo profiles are
# honored only for the workspace being built, so nothing in our root manifest reaches a consumer,
# and a report measured under settings a consumer never gets would be a report about us.

set -euo pipefail

# `pwd -P`, the PHYSICAL path, and it is load bearing rather than tidy. rustc emits absolute paths
# canonicalized through symlinks, so a repository reached through one -- which on macOS is every
# checkout under /tmp, since /tmp is a symlink to /private/tmp -- yields a logical `$PWD` that does
# NOT prefix-match what rustc embedded, and the --remap-path-prefix below silently matches nothing.
# MEASURED 2026-08-13: the same tree built from `/tmp/x` linked `/private/tmp/x/crates/oauth-as/
# src/store.rs` while the remap was written for `/tmp/x`, and the row came out 12 bytes off its
# twin. A remap that quietly fails is worse than no remap, because the number still looks stable.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROBE_DIR="$REPO_ROOT/scripts/size-probe"
# Per-configuration target directories, under one root, so that a second run is cached and so that
# two configurations can never overwrite each other's binary (which they would in one directory,
# and the second measurement would silently be of the first binary).
TARGET_ROOT="${SIZE_REPORT_TARGET_ROOT:-$REPO_ROOT/target/size-report}"

HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"

# Every oauth-as feature, mirrored in the probe as `f-<name>`. --all-features is this list.
ALL_FEATURES="f-http,f-axum,f-jwt,f-jwt-p256,f-jwt-pkcs8,f-mtls,f-par,f-jar,f-rar,f-dpop,f-client-assertion,f-consent,f-token-exchange,f-resource-metadata,f-cimd,f-test-util"

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
  "cimd|f-cimd||the client identifier metadata document VALIDATOR; there is no fetch to measure"
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
# EVERY NUMBER BELOW WAS RE-DERIVED 2026-08-13 FOR 0.9.2, from one run of this script, and the
# rule that produced them is uniform: the measured value plus 1.5%, rounded UP to the next whole
# KiB. That lands every row between 1.51% and 1.92% of headroom. It replaces the old "5% or 4 KB,
# whichever is larger" allowance, which produced margins that ranged from 4 KiB down to SEVEN BYTES
# on the `default` row once that row had been raised by hand and then measured again. Seven bytes
# is not headroom, it is a coincidence, and it is what put CI red at 0.9.1.
#
# The allowance is a band and not a per-row negotiation on purpose: a row with more slack than its
# neighbours is a row that has quietly stopped gating. 1.5% of the smallest gated row is about
# 3.9 KB, which absorbs an innocuous refactor or a compiler patch bump, and is far short of any new
# subsystem -- the smallest optional feature in the table, `mtls`, is 5.6 KB all by itself.
#
# WHY THEY ALL MOVED AT ONCE, and why the previous numbers could not simply be kept:
#
#   1. `--remap-path-prefix` (see measure(), below) landed in this release. Before it, the byte
#      count included the length of the directory the repository was checked out into -- MEASURED,
#      240 bytes between two paths on this machine. Every budget recorded before it was taken in an
#      unknown, unrecorded amount of path. Comparisons in the notes below to any pre-0.9.2 figure
#      are therefore good to a couple of hundred bytes and no better, and are marked where it
#      matters.
#   2. `ScopeSet` became a sorted `Vec` instead of a `BTreeSet`, which took 13,463 bytes off the
#      `default` row and more off others.
#
# Both of those make every row SMALLER, so every budget here comes DOWN. That direction is not
# optional: a budget left at a number the code no longer approaches has stopped being a gate on
# that row at all, and would silently permit back exactly the bytes that were just removed.
#
# The measured figures these were set from are in the table this script prints, and are quoted in
# README.md's Cost section from the same run.
budget_for() {
  case "$HOST_TRIPLE:$1" in
    # ALL SEVEN MEASURED 2026-08-13 for 0.9.2, on aarch64-apple-darwin, rustc 1.97.0, by this
    # script, in ONE run, with --remap-path-prefix in force. Each budget is that measurement plus
    # 1.5% rounded up to the next KiB. The measured value is written beside every one of them, so a
    # later reader can tell headroom from history without re-running anything.
    #
    # the protocol core, every grant driven end to end. MEASURED 221,026, against the 234,489 this
    # row was set from at 0.9.1: it LOST 13,463 bytes.
    #
    # WHAT REMOVED THEM: `ScopeSet` stopped being a `BTreeSet<Scope>` and became a sorted `Vec`.
    # The set holds one to five short words, which is a size at which a B-tree's leaf node and its
    # descent code cost more than a linear scan over a slice, in both bytes and time. The invariant
    # (sorted, deduplicated) is unchanged, so nothing about the type's contract moved. That commit
    # measured 15,394 bytes off this row on its own; the net here is 13,463 because 0.9.2's own
    # additions to the core spent some of it back. -13,463 is the figure to hold the release to.
    #
    # THE BUDGET COMES DOWN WITH IT, from 238,592 to 225,280. That is this file's own rule and it
    # is the whole reason the rule exists: 238,592 against a 221,026 row would be 17 KB of licence
    # to put the B-tree back, or anything else of that size, without a single gate going red.
    #
    # WHAT IS NO LONGER TRUE, since three sets of notes accumulated on this row across 0.9.1 and
    # are superseded wholesale: the 221,945 / 199,953 / 209,376 / 234,496 figures, the "seven bytes
    # of margin" that this row once passed by, and the stopgap ~4 KiB that was carried here while
    # --remap-path-prefix was still 0.9.2 work. The remap is now in measure() and the path variance
    # it was carrying is gone, so the margin is the ordinary 1.5% band and nothing special.
    #
    # WHAT IS STILL TRUE and is the reason this row is as large as it is: the RESURRECTION RULE
    # from 0.9.1. A `RevocationBarrier`, the predicate every write consults, four `Storage` methods
    # and the undo path issuance needs when a revocation lands between its two writes. That was
    # measured at 25,113 bytes when it landed and none of it has been given back; it is what stops
    # a contained token staying live because an issuance was already in flight across a signing
    # await.
    aarch64-apple-darwin:default) echo 225280 ;;
    # + the HTTP service with a request dispatched to every route. MEASURED 423,691, against the
    # 438,009 this row was set from at 0.9.1: down 14,318. The `default` row underneath it accounts
    # for 13,463 of that; the remaining 855 is this surface's own, and is small enough that it is
    # not worth an attribution beyond "the same change, seen through more call sites". Roughly
    # doubling the core is still what a wire surface costs: a router, a form and query parser, a
    # body reader, and one response serializer per endpoint.
    # Budget down from 442,368 to 430,080.
    aarch64-apple-darwin:http) echo 430080 ;;
    # + the Router adapter AND a tokio multi-thread runtime with a bound listener, because that is
    # what a host turns this feature on to do. MEASURED 662,357, down 15,282 from the 677,639 this
    # row was set from. The 233 KiB over the `http` row is almost entirely the runtime, which is
    # the host's cost and not this crate's.
    # Budget down from 681,984 to 672,768.
    aarch64-apple-darwin:axum) echo 672768 ;;
    # + RFC 9068 signing over a HOST-SUPPLIED `Es256Signer`, the RFC 7517 JWKS, and the JWK parsing
    # the verification seam rests on. NO curve implementation: this is what a host with its key in
    # a KMS pays. MEASURED 256,106, essentially where it was at 0.9.1 (256,491, down 385) -- and
    # that near-standstill is the interesting part rather than a null result. This row took the
    # same 13 KB of `ScopeSet` saving as every other, and gave it back to 0.9.2's own additions on
    # the signing path. The row is flat; the code underneath it is not.
    # Budget down from 271,360 to 260,096. The old number was 15 KB above the measurement, which is
    # more slack than this row has ever needed.
    aarch64-apple-darwin:"jwt (seam only)") echo 260096 ;;
    # + the built-in p256 backend, which is what every consumer of `jwt` had before the seam.
    # MEASURED 292,418, UP 749 from 291,669 at 0.9.1 -- the only gated row in the table that grew
    # across this release. 749 bytes is the seam's own overhead moving slightly and not a subsystem
    # arriving; the p256 backend itself did not change. The backend costs 36,312 bytes over the
    # seam-only row, which is the number a host deciding whether to bring its own ES256 signer
    # actually wants.
    # Budget down from 308,224 to 296,960, because 308,224 was 5.4% above a row that moved by 749
    # bytes all release.
    aarch64-apple-darwin:jwt-p256) echo 296960 ;;
    # the conformance server's own feature set: the HTTP surface plus the signing seam, with no
    # curve. MEASURED 458,484, down 14,036 from the 472,520 this row was set from, for the same
    # reason as `http`.
    # Budget down from 476,160 to 465,920.
    aarch64-apple-darwin:"http,jwt") echo 465920 ;;
    # every feature, every one exercised. MEASURED 1,380,383, down 22,175 from the 1,402,558 this
    # row was set from -- the largest absolute saving in the table, because this row links every
    # feature's scope handling at once and `ScopeSet` is in all of them.
    #
    # Budget down from 1,406,976 to 1,401,856. Note what that means: the old budget was raised for
    # `cimd` days ago and the row has since fallen 22 KB BELOW the number it was raised to. Leaving
    # it would have left the whole `cimd` justification standing as unspent licence.
    #
    # THE TWO THINGS THIS ROW IS FOR, both re-measured in the same run:
    #
    #   * IT IS DOMINATED BY `test-util`. That feature alone is 235,994 bytes over the core, larger
    #     than the entire HTTP surface (202,665). It is a dev-dependency feature: it is the
    #     `Storage` conformance harness a host RUNS against its own store to find out whether that
    #     store honours the resurrection rule. No production binary enables it and no other budgeted
    #     row includes it.
    #   * IT IS WHERE A NEW SUBSYSTEM SHOWS UP FIRST. `cimd` is the most recent one. Standalone it
    #     costs 90,132 bytes over the core, almost entirely serde_json's DESERIALIZER instantiated
    #     for one more document shape -- the same shape of cost `rar` pays at 100,550. MEASURED
    #     here by building this row with and without it: 1,644,742 against 1,614,113, so its
    #     marginal cost in a binary that already parses JSON for something else is 30,629 bytes.
    #     (The 24 KiB quoted for this before was taken pre-remap and pre-`ScopeSet`; 30,629 is the
    #     figure from this run.)
    aarch64-apple-darwin:all-features) echo 1401856 ;;
    *) echo "" ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# THE FLOORS, and why a size gate needs a MINIMUM at all.
#
# THE HOLE THEY CLOSE. Until these existed the only comparison in this script was
# `[ "$delta" -gt "$budget" ]`. That makes a row that measures TOO LITTLE unconditionally green --
# and measuring too little is not a hypothetical, it is the exact failure this whole probe was
# built to prevent. Point 2 at the top of this file says it: under `lto = "fat"` the linker
# deletes what nothing calls, so a row whose exerciser stops exercising collapses toward the
# baseline and reports that the feature is nearly free. The budget then passes with room to
# spare, `--check` prints "every gated feature set is within its recorded budget", and the number
# it printed is a lie in the one direction the gate could not see.
#
# scripts/feature-mirrors.py cannot cover this. Its exerciser check is a STRING check: it looks
# for a gated `pub fn <name>()` in exercise_features.rs and a call to it from exercise.rs. Replace
# that function's BODY with `0` and the `#[cfg]`, the `pub fn` and the call site are all still
# there, so it still reports "all mirrored". A byte count is the only thing that can notice, and
# a byte count only notices if something compares it downward.
#
# THE RULE, and it is deliberately the budgets' own rule mirrored. A budget is the recorded
# measurement plus 1.5% rounded UP to the next whole KiB; a floor is that same measurement minus
# 1.5% rounded DOWN to the previous whole KiB. Same run, same date, same reasoning, one band per
# row. That lands the floors between 1.50% and 1.78% below their measurements, which is the same
# spread as the budgets' 1.51% to 1.92% above them, and for the same reason: a row with more slack
# than its neighbours is a row that has quietly stopped gating, in either direction.
#
# A DROP IS A DECISION, exactly as a rise is. This file already insists that a budget only comes
# down when someone writes down what removed the bytes -- the `ScopeSet` note on the `default` row
# is that discipline in action. A floor makes the same discipline enforced instead of remembered:
# take 13 KB off a row and the gate goes red and asks you to re-derive the band and say what did
# it. That is a feature. The alternative is what 0.9.2 nearly shipped, where the budgets were
# re-derived downward by hand only because somebody thought to.
#
# WHAT A FLOOR ON THESE ROWS DOES **NOT** CATCH, measured rather than assumed, because a gate
# oversold is worse than no gate:
#
#   MEASURED 2026-08-13. `exercise_features::rar()` was replaced with a body of `0` -- the very
#   sabotage feature-mirrors.py cannot see -- and the `all-features` row moved from 1,387,055 to
#   1,385,187. ONE THOUSAND EIGHT HUNDRED AND SIXTY-EIGHT BYTES, 0.13% of the row. No floor can
#   catch that, and one tight enough to try would go red on every innocuous refactor.
#
#   The reason is not that RAR is cheap: standalone it is 100,550 bytes over the core. It is that
#   `all-features` links `cimd`, `consent`, `token-exchange` and the rest, which already
#   instantiate serde_json's deserializer and the JSON machinery RAR shares -- the same effect the
#   `cimd` note on the budget above records from the other direction (90,132 standalone, 30,629
#   marginal). A feature's marginal cost inside the everything row is a small fraction of its
#   standalone cost, so the everything row is the WORST place to look for one feature going quiet.
#
#   The floor therefore catches a ROW COLLAPSE -- an exerciser for a gated row's own surface
#   stopping, the probe ceasing to link the crate, the instrument mis-parsing a section table --
#   and not a single optional feature falling silent inside a row that carries fifteen others.
#   Closing THAT hole means gating the feature's own row, where the collapse is 31% and not 0.13%.
#   That is a decision about CI minutes (one fat-LTO link per row added, about 40 seconds each)
#   and it is not taken here; it is written down so the next reader does not have to re-measure
#   1,868 bytes to discover the limit for themselves.
#
# EVERY FLOOR BELOW COMES FROM THE SAME 2026-08-13 0.9.2 RUN AS THE BUDGET ABOVE IT, on
# aarch64-apple-darwin, rustc 1.97.0, with --remap-path-prefix in force. The measurement is quoted
# beside each so the band can be read without re-running anything. All seven were reproduced on a
# second run of this script on the same machine; the reproduction cleared its floor by between
# 3,862 bytes (`default`) and 28,207 (`all-features`), which is the margin these numbers actually
# carry against run-to-run variation.
floor_for() {
  case "$HOST_TRIPLE:$1" in
    # MEASURED 221,026, budget 225,280. 221,026 - 1.5% = 217,710, down to 212 KiB.
    aarch64-apple-darwin:default) echo 217088 ;;
    # MEASURED 423,691, budget 430,080. Down to 407 KiB. This row is the core plus the HTTP
    # surface; if exercise_http::plane() stops dispatching, the row falls back to roughly the
    # `default` row's 221 KB and this floor is 195 KB above that.
    aarch64-apple-darwin:http) echo 416768 ;;
    # MEASURED 662,357, budget 672,768. Down to 637 KiB.
    aarch64-apple-darwin:axum) echo 652288 ;;
    # MEASURED 256,106, budget 260,096. Down to 246 KiB. The tightest band in the table in
    # absolute terms after `default`, and the row the 0.9.2 notes describe as flat: it moved 385
    # bytes across a whole release, so 4 KB of downward slack is generous for it.
    aarch64-apple-darwin:"jwt (seam only)") echo 251904 ;;
    # MEASURED 292,418, budget 296,960. Down to 281 KiB. The gap to the seam-only floor is what
    # stops the built-in p256 backend disappearing from the probe unnoticed.
    aarch64-apple-darwin:jwt-p256) echo 287744 ;;
    # MEASURED 458,484, budget 465,920. Down to 441 KiB.
    aarch64-apple-darwin:"http,jwt") echo 451584 ;;
    # MEASURED 1,380,383, budget 1,401,856. Down to 1327 KiB. 21 KB of downward slack, which is
    # the largest in the table in bytes and the same 1.56% in proportion. Read the note above
    # before trusting this one to notice a single feature: it will not.
    aarch64-apple-darwin:all-features) echo 1358848 ;;
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

# The same wrapper for the other end of the band. --force-floor sets a floor no real row can be
# above, which is how the self-test proves the UNDER comparison exists -- the forced-budget proof
# cannot say anything about it, because a row that fails a 1-byte budget passes its real floor on
# the way past.
floor_for_mode() {
  if [ -n "$SELFTEST_FLOOR" ]; then
    if [ -n "$(floor_for "$1")" ]; then printf '%s' "$SELFTEST_FLOOR"; fi
    return
  fi
  floor_for "$1"
}

# The rows `--check` gates. Not every row: a gate over twenty numbers is a gate that goes red for
# noise and gets ignored. These are the feature sets a real consumer actually picks, and any
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
  # --remap-path-prefix, AND IT IS WHAT MAKES THIS GATE MEAN THE SAME THING TWICE.
  #
  # The probe links panic `Location` strings, and they are ABSOLUTE, because oauth-as is an
  # out-of-workspace path dependency of the probe. So the byte count included the length of the
  # directory the repository happened to be checked out into. MEASURED 2026-08-13, same tree, same
  # toolchain, only the path differing: 218,989 bytes from `/tmp/oa` against 219,229 from a
  # 73-character worktree. 240 bytes of pure path length.
  #
  # That is not an academic difference. The `default` row went RED on CI at 234,656 against a
  # budget of 234,496 that passed locally at 234,489 -- on the SAME aarch64-apple-darwin triple.
  # The runner checks out at /home/runner/work/oauth-as/oauth-as, which is longer than a typical
  # local path, and the release was blocked by the name of a directory.
  #
  # Remapping both the repository root and CARGO_HOME collapses every such string to a constant, so
  # the number this script prints depends on the code and the toolchain and nothing else. A gate
  # whose verdict moves with where you cloned it is not a gate; it is a coincidence that has been
  # passing.
  #
  # VERIFIED 2026-08-13 RATHER THAN ASSUMED, because a remap that silently misses looks exactly
  # like a remap that works. The same tree (`diff -r` clean) was built from SIX directories: the
  # 75-character worktree, `/private/tmp/x`, `/private/tmp/y` (same length, different name), a
  # 74-character path of `q`s, and two under /Users. Five of the six gave a byte-identical
  # `default` row of 485,377 linked. Comparing any two of the binaries, the __cstring section is
  # now IDENTICAL: no absolute path survives anywhere in the image, which is the thing this flag
  # was added to guarantee, and it is what took the 240-byte spread to zero.
  #
  # THE ONE RESIDUAL, stated because leaving it undocumented would invite the next person to
  # rediscover it as a mystery. The sixth directory came out 8 bytes larger, and the difference is
  # entirely in __unwind_info -- no code section, and no string, differs. The cause is that cargo
  # derives a crate's `-C metadata` disambiguator from its absolute path, so the SYMBOL HASHES
  # differ between checkouts, function layout follows them, and __unwind_info's page packing is
  # quantized: it usually lands on the same size and occasionally lands 8 bytes off. It does not
  # track path LENGTH (the 74-character path agreed with the 14-character one). 8 bytes against a
  # smallest-row headroom of 3,990 is noise the budgets absorb without noticing; 240 bytes against
  # the seven bytes of margin this gate once carried was not.
  #
  # Both prefixes are the PHYSICAL paths, for the reason written beside REPO_ROOT: rustc embeds
  # symlink-resolved paths, so a logical prefix matches nothing and the remap fails without saying
  # so. CARGO_HOME gets the same treatment because it is just as often a symlink into a volume.
  local cargo_home
  cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
  local remap="--remap-path-prefix=$REPO_ROOT=/oauth-as --remap-path-prefix=$cargo_home=/cargo"
  if ! ( cd "$PROBE_DIR" && RUSTFLAGS="${RUSTFLAGS:-} $remap" cargo "${args[@]}" >&2 ); then
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
SELFTEST_FLOOR=""
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
    # The same, for the floor: a value no real row can be above, so the UNDER arm has to fire.
    --force-floor) SELFTEST_FLOOR="$2"; shift ;;
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
# WHAT IT PROVES, precisely: that a --check run whose numbers are impossible to meet exits 1 and
# names the row. That covers the whole chain -- the row set is non-empty, the probe built, the
# instrument returned a positive byte count, the comparison happened, and the failure reaches the
# exit status -- because a break anywhere in it produces a 0 instead.
#
# THREE PROOFS, not one, and each answers a question the others cannot:
#
#   1. THE CEILING, on `default`. The original proof. Forces the budget to 1 byte.
#   2. THE FLOOR, on `default`. Forces the floor above any real row. Proof 1 says NOTHING about
#      this arm: a row that fails a 1-byte budget sails past its real floor on the way, so before
#      the floors existed this self-test would have passed identically against a script with no
#      downward comparison in it at all -- which is exactly what it did.
#   3. THE CEILING ON A FEATURE ROW, `jwt (seam only)`. Proofs 1 and 2 both run `--rows default`,
#      which is the `lib` row: no optional feature, no exercise_features.rs, no `--features` flag
#      on the probe build. So they prove the shared mechanism and say nothing about whether a
#      FEATURE row can go red -- whether the feature actually reaches the probe, whether the
#      row's name survives the `--rows` filter with a space in it, whether budget_for()'s quoted
#      case arms match. A feature row is where every one of those first goes wrong.
#
# ONE ROW PER PROOF, not seven: each re-links the probe, and the proof is about the mechanism
# rather than about any particular feature set. `default` is the cheapest row, and
# `jwt (seam only)` is the cheapest gated row that is a feature. The two share the `none`
# baseline, which is measured once and cached on disk, so the third proof costs one extra link.
#
# A NON-ZERO EXIT IS NOT ENOUGH, and accepting one was the shape of the bug this whole release is
# about. `--check` exits 1 for a missing budget table, an unparseable argument, a probe that will
# not build and a row outside its band, and only the last of those proves anything about the
# comparison. A self-test that asks only "did it fail?" is satisfied by a script that failed
# before it measured a single byte -- it would report a healthy gate over an empty one, which is
# precisely what it exists to rule out. So each proof asserts the SPECIFIC failure line, naming
# the row and the end of the band it left, and treats any other red as a broken self-test.
selftest_run() {
  local what="$1" expect="$2" row="$3"; shift 3
  local output rc=0
  echo "size-report: SELF-TEST [$what]: the run below MUST fail with '$expect' on '$row'."
  echo "size-report:   \$ ${BASH_SOURCE[0]} --check $*"
  echo
  output="$("${BASH_SOURCE[0]}" --check "$@" 2>&1)" || rc=$?
  printf '%s\n' "$output"
  echo
  if [ "$rc" = 0 ]; then
    echo "size-report: SELF-TEST FAILED [$what]: --check exited 0 against numbers no row can" >&2
    echo "size-report: satisfy. That arm of the gate is not comparing anything, and every green" >&2
    echo "size-report: it has ever produced through it means nothing. Fix it before trusting one." >&2
    exit 1
  fi
  case "$output" in
    *"size-report: FAIL: '$row' is "*"$expect"*) ;;
    *)
      echo "size-report: SELF-TEST FAILED [$what]: --check exited $rc, but NOT with the" >&2
      echo "size-report: comparison failure this proof is about ('$expect' on row '$row'). A red" >&2
      echo "size-report: for some other reason -- a missing budget table, an argument it did not" >&2
      echo "size-report: understand, a probe that would not build -- proves nothing about whether" >&2
      echo "size-report: the comparison happened, and accepting one would make this self-test the" >&2
      echo "size-report: same kind of gate it exists to rule out. Output is above." >&2
      exit 1
      ;;
  esac
  echo "size-report: [$what] went RED with the expected comparison failure, naming the row. OK."
  echo
}

if [ "$MODE" = "selftest" ]; then
  echo "size-report: SELF-TEST. Three --check runs, each of which must fail."
  echo
  # The ceiling: 1 byte is a budget no linked row can be inside.
  selftest_run "ceiling, lib row" "against a budget of" "default" \
    --rows default --force-budget 1
  # The floor: 1 GiB is a floor no row in this table is above. Deliberately not a number near a
  # real row, so this cannot pass by coincidence if a budget is ever raised that far.
  selftest_run "floor, lib row" "UNDER its floor of" "default" \
    --rows default --force-floor 1073741824
  # The ceiling again, on a row that is a FEATURE rather than the bare library.
  selftest_run "ceiling, feature row" "against a budget of" "jwt (seam only)" \
    --rows "jwt (seam only)" --force-budget 1
  echo "size-report: self-test passed: --check went RED at BOTH ends of the band, and on a"
  echo "size-report: feature row as well as the lib row. The comparisons, the measurement and"
  echo "size-report: the exit status all work."
  exit 0
fi

if [ "$MODE" = "check" ]; then
  missing=0
  # BOTH ENDS, because a row with a budget and no floor is a row that is gated in one direction
  # only, which is the state this script shipped in and the state the floors exist to end. A
  # half-recorded platform REFUSES rather than silently gating half of what it claims to.
  for row in "${GATED_ROWS[@]}"; do
    if [ -z "$(budget_for "$row")" ] || [ -z "$(floor_for "$row")" ]; then missing=1; fi
  done
  if [ "$missing" = 1 ]; then
    cat >&2 <<EOF
size-report: no size band is recorded for $HOST_TRIPLE, for at least one gated row.

Code size is a property of the target's instruction encoding, so budgets measured on one platform
do not describe another. This gate REFUSES rather than passing against numbers that do not apply:
a gate that cannot fail is worth nothing. Either run it on a platform with recorded budgets, or
record a set for this one by running scripts/size-report.sh here and adding the measured figures
to budget_for() AND floor_for() in this file, with the date, toolchain and reasoning beside them.
Both are required: a row with a budget and no floor is gated against growth only, and a row that
collapses to nothing is comfortably inside any budget.
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
  floor="$(floor_for_mode "$name")"
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
      # THE OTHER END OF THE BAND. Checked independently of the budget rather than as an `else`:
      # the two are separate questions, and a --selftest that forces one must not be able to
      # suppress the other.
      if [ -n "$floor" ] && [ "$floor" != "0" ]; then
        note="${note:+$note }(floor $(human "$floor") KiB)"
        if [ "$delta" -lt "$floor" ]; then
          note="$note UNDER"
          if [ "$MODE" = "check" ]; then
            echo "size-report: FAIL: '$name' is $(human "$delta") KiB, UNDER its floor of $(human "$floor") KiB ($((floor - delta)) bytes short)" >&2
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
    echo "size-report: every gated feature set is inside its recorded band (floor and budget)."
  else
    cat >&2 <<'EOF'

A band is a DESIGN gate at BOTH ends. The rule this project runs on, the same one
tests/allocation.rs runs on: when a change leaves the band, the change gets fixed, not the number.

OVER: if the growth is genuinely the cost of something worth having, raising the budget is
allowed, but it is a decision that gets written down next to the number in scripts/size-report.sh,
with what bought it.

UNDER is not automatically good news, and it is the reason the floor exists. Ask first whether the
row still MEASURES what it claims to: under `lto = "fat"` an exerciser that stopped exercising
collapses the row toward its baseline, and the resulting "the feature is nearly free" is the one
lie a budget alone cannot catch. Check scripts/size-probe/src/exercise*.rs before believing a
saving. If the bytes really did go away, re-derive BOTH numbers for that row from a fresh run and
write down what removed them -- a floor left under a row the code no longer approaches has stopped
gating it just as surely as a budget left above one.
EOF
  fi
fi
exit "$status"
