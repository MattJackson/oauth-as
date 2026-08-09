#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# WHAT DOES oauth-as COST A HOST, IN BYTES, AND WHICH FEATURE COSTS IT.
#
# Run it:
#   scripts/size-report.sh                 the whole table
#   scripts/size-report.sh --check         the same, and FAIL if a row is over budget
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
ALL_FEATURES="f-http,f-axum,f-jwt,f-jwt-pkcs8,f-mtls,f-par,f-jar,f-rar,f-dpop,f-client_assertion,f-consent,f-token-exchange,f-resource-metadata,f-test-util"

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
  "jwt|f-jwt||the core with RFC 9068 at+jwt access tokens, ES256 signing, and the RFC 7517 JWKS"
  "jwt-pkcs8 (called)|f-jwt-pkcs8||jwt, plus a PKCS#8 key actually exported and re-imported"
  "jwt-pkcs8 (never called)|f-jwt-pkcs8-unused||jwt, with the jwt-pkcs8 feature ON and its two constructors never reached"
  "mtls|f-mtls||RFC 8705 thumbprints, subject matching and certificate-bound tokens"
  "par|f-par||RFC 9126 pushed authorization requests, pushed and redeemed"
  "jar|f-jar||RFC 9101 signed request objects (implies jwt)"
  "rar|f-rar||RFC 9396 authorization_details, parsed, type-checked and narrowed"
  "dpop|f-dpop||RFC 9449 proof verification (implies jwt)"
  "client_assertion|f-client_assertion||RFC 7523 private_key_jwt and client_secret_jwt (implies jwt)"
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
    # the protocol core, every grant driven end to end. Measured 199,953 bytes.
    aarch64-apple-darwin:default) echo 210944 ;;
    # + the HTTP service with a request dispatched to every route. Measured 397,429. Roughly
    # doubling the core is what a wire surface costs: a router, a form and query parser, a body
    # reader, and one response serializer per endpoint.
    aarch64-apple-darwin:http) echo 417792 ;;
    # + the Router adapter AND a tokio multi-thread runtime with a bound listener, because that is
    # what a host turns this feature on to do. Measured 614,661; the 212 KiB over the `http` row is
    # almost entirely the runtime, which is the host's cost and not this crate's.
    aarch64-apple-darwin:axum) echo 646144 ;;
    # + RFC 9068 ES256 signing, the RFC 7517 JWKS, and JWS verification. Measured 265,017; about a
    # third of the 64 KiB over the core is p256/primeorder and the rest is this crate's. It does
    # NOT include PKCS#8 key loading, which is a separate `jwt-pkcs8` feature and, measured, a
    # separate 30,824 bytes paid only by a host that calls the two constructors behind it.
    aarch64-apple-darwin:jwt) echo 278528 ;;
    # the conformance server's own feature set. Measured 461,974.
    aarch64-apple-darwin:"http,jwt") echo 485376 ;;
    # every feature, every one exercised. Measured 1,129,020. This is the ceiling on what this
    # crate can cost anyone, and it is the row a new subsystem shows up in first.
    aarch64-apple-darwin:all-features) echo 1185792 ;;
    *) echo "" ;;
  esac
}

# The rows `--check` gates. Not every row: a gate over twenty numbers is a gate that goes red for
# noise and gets ignored. These six are the feature sets a real consumer actually picks, and any
# regression big enough to matter shows up in at least one of them.
GATED_ROWS=("default" "http" "axum" "jwt" "http,jwt" "all-features")

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
  local args=(build --release --quiet --target-dir "$target_dir")
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
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    --tsv) MODE="tsv" ;;
    --rows) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "size-report: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

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

  budget="$(budget_for "$name")"
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
