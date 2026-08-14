#!/usr/bin/env bash
# oauth-conformance.sh - runs the INDEPENDENT OAuth 2.1 conformance harness
# (crates/oauth-as-conformance) against the live AS (crates/oauth-as) as a black box.
#
# Modes:
#   --selftest   Prove the gate can go RED before anyone trusts a green (house discipline:
#                a check is not trusted until it has been shown red first):
#                  RED-A   the hermetic RFC-vector suite MUST FAIL when the expected PKCE
#                          challenge is deliberately corrupted via
#                          OAUTH_CONFORMANCE_SELFTEST_BREAK=pkce;
#                  GREEN-A the same suite MUST PASS clean;
#                  RED-B   the black-box suite MUST FAIL against a deliberately
#                          nonconformant stub AS (a python http server whose RFC 8414
#                          metadata document is an empty JSON object).
#   --check      Run the real thing: start the AS over HTTP, wait for its RFC 8414 metadata,
#                run the black-box + third-party-client suites against it. FAILS LOUDLY
#                (exit 1 with a clear message) when the AS cannot be served; this gate must
#                never pass vacuously.
#
# AS launch contract (assumptions are documented in crates/oauth-as-conformance/src/lib.rs):
#   crates/oauth-as is a LIBRARY with no binary, so serving it requires an executable
#   crates/oauth-as/conformance-serve.sh, which must:
#   * serve HTTP on the address in OAUTH_AS_ADDR (we use 127.0.0.1:8914) and block until
#     killed;
#   * honor OAUTH_AS_CONFORMANCE_SEED=1 by seeding the deterministic conformance clients and
#     auto-approval behavior described in crates/oauth-as-conformance/src/lib.rs.
#   That shim EXISTS (crates/oauth-as/conformance-serve.sh) and is executable. The `-x` check
#   below still gates on its presence rather than assuming it, so a tree that loses it fails
#   loudly rather than passing vacuously.
#
# Backgrounded servers ALWAYS get their stdout/stderr redirected to a log file, never
# captured via command substitution (a hard-won lesson: substitution hangs until the
# backgrounded child closes its inherited stdout).

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="127.0.0.1:8914"
BASE_URL="http://${ADDR}"
TMPDIR_CONF="$(mktemp -d "${TMPDIR:-/tmp}/oauth-conf.XXXXXX")"
AS_PID=""
STUB_PID=""

cleanup() {
  [ -n "$AS_PID" ] && kill "$AS_PID" 2>/dev/null
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$TMPDIR_CONF"
}
trap cleanup EXIT INT TERM

fail() { echo "oauth-conformance: FAIL: $*" >&2; exit 1; }
note() { echo "oauth-conformance: $*"; }

wait_for_metadata() {
  # $1 = base url, $2 = timeout seconds
  local url="$1/.well-known/oauth-authorization-server" deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -sf -o /dev/null --max-time 2 "$url"; then return 0; fi
    sleep 1
  done
  return 1
}

run_vectors() {
  ( cd "$ROOT" && cargo test --locked -p oauth-as-conformance --test rfc_vectors )
}

run_blackbox() {
  # Single-threaded: the flows share seeded state and interleaving would blur failures.
  ( cd "$ROOT" && OAUTH_AS_BASE_URL="$BASE_URL" \
      cargo test --locked -p oauth-as-conformance --test blackbox_http --test client_drive \
      -- --ignored --test-threads=1 )
}

# HOW MANY CHECKS THERE ARE SUPPOSED TO BE, counted from the source rather than typed here.
#
# A hard-coded number is another hand-maintained mirror, and this repository already carries
# enough of those to have been bitten by them repeatedly. Counting `async fn` in the two test
# binaries means adding a check raises the floor automatically and DELETING one lowers it in the
# same commit that removes it -- which is visible in review, where a silently shrinking suite is
# not.
expected_blackbox_checks() {
  grep -cE '^async fn ' "$ROOT/crates/oauth-as-conformance/tests/blackbox_http.rs"
}
expected_client_drive_checks() {
  grep -cE '^async fn ' "$ROOT/crates/oauth-as-conformance/tests/client_drive.rs"
}

# THE GATE HAD NO FLOOR, AND THE BADGE RESTED ON IT.
#
# `run_blackbox` reported success on whatever it happened to run, and nothing counted. An audit
# lens deleted SEVEN of the eight black-box checks and BOTH third-party client drives, then ran
# `--selftest` and `--check`: both printed PASS. Nine of ten independent checks were gone and the
# gate said conformance PASS, while README.md serves an "independent conformance 8/8" badge on
# the strength of it.
#
# The self-test did not catch it either, because RED-B only required the suite to fail against a
# deliberately nonconformant stub AND the log to mention "RFC 8414 metadata violations" -- a
# condition ONE surviving check satisfies.
#
# Every sibling gate in this repository already has a floor: the fuzz job compares `cargo fuzz
# list` against the [[bin]] table and counts iterations, oauth-interop.sh requires each of three
# grants to be named failing individually, and oauth-mcp-lint.sh requires MCP-PKCE-001 and
# MCP-CSRF-001 by name. This was the one that enumerated nothing.
assert_blackbox_floor() {
  local log="$1" want_bb want_cd got
  want_bb="$(expected_blackbox_checks)"
  want_cd="$(expected_client_drive_checks)"
  if [ "$want_bb" -lt 1 ] || [ "$want_cd" -lt 1 ]; then
    fail "counted $want_bb black-box and $want_cd client-drive checks in the source. A floor
derived from an empty count is not a floor, so this is fatal rather than a pass."
  fi
  # `test result: ok. N passed` once per binary, in the order the two --test flags name them.
  got="$(grep -cE '^test result: ok\. [0-9]+ passed' "$log" || true)"
  if [ "$got" -ne 2 ]; then
    fail "expected a passing result line from BOTH test binaries, saw $got. A binary that ran
nothing reports nothing, which is the shape this floor exists to catch."
  fi
  local ran
  ran="$(grep -oE '^test result: ok\. [0-9]+ passed' "$log" | grep -oE '[0-9]+' | paste -sd+ - | bc)"
  if [ "$ran" -lt "$((want_bb + want_cd))" ]; then
    fail "the black-box suite ran $ran checks against $((want_bb + want_cd)) defined in the
source ($want_bb black-box, $want_cd client drive). A conformance gate that reports PASS on a
suite somebody shortened is not a gate, and README.md quotes its result as a badge."
  fi
  note "black-box floor: $ran checks ran, $((want_bb + want_cd)) defined in the source"
}

start_stub_as() {
  # A deliberately NONCONFORMANT AS: answers every path with an empty JSON object, so the
  # RFC 8414 metadata validation must reject it. Used only by --selftest RED-B.
  python3 - "$ADDR" >"$TMPDIR_CONF/stub.log" 2>&1 <<'PYEOF' &
import http.server, sys
host, port = sys.argv[1].rsplit(":", 1)
class H(http.server.BaseHTTPRequestHandler):
    def _serve(self):
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = _serve
    do_POST = _serve
    def log_message(self, *a):  # quiet
        pass
http.server.HTTPServer((host, int(port)), H).serve_forever()
PYEOF
  STUB_PID=$!
}

run_selftest() {
  local rc

  note "SELFTEST RED-A: corrupting the expected RFC 7636 App B challenge; vector suite must FAIL"
  ( cd "$ROOT" && OAUTH_CONFORMANCE_SELFTEST_BREAK=pkce \
      cargo test --locked -p oauth-as-conformance --test rfc_vectors ) \
      >"$TMPDIR_CONF/red-a.log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_CONF/red-a.log"
    fail "RED-A: vector suite PASSED with a corrupted expectation; the gate cannot go red"
  fi
  note "SELFTEST RED-A: failed as required (exit $rc)"

  note "SELFTEST GREEN-A: clean vector suite must PASS"
  run_vectors >"$TMPDIR_CONF/green-a.log" 2>&1 || {
    cat "$TMPDIR_CONF/green-a.log"
    fail "GREEN-A: clean vector suite failed"
  }
  note "SELFTEST GREEN-A: passed"

  note "SELFTEST RED-B: black-box suite must FAIL against a nonconformant stub AS"
  command -v python3 >/dev/null 2>&1 || fail "RED-B needs python3 for the stub AS"
  start_stub_as
  wait_for_metadata "$BASE_URL" 15 || fail "RED-B: stub AS did not come up on $ADDR"
  run_blackbox >"$TMPDIR_CONF/red-b.log" 2>&1
  rc=$?
  kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; STUB_PID=""
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_CONF/red-b.log"
    fail "RED-B: black-box suite PASSED against a nonconformant AS; the gate is worthless"
  fi
  if ! grep -q "RFC 8414 metadata violations" "$TMPDIR_CONF/red-b.log"; then
    cat "$TMPDIR_CONF/red-b.log"
    fail "RED-B: suite failed, but not for the planted metadata violations; investigate"
  fi
  note "SELFTEST RED-B: failed as required (exit $rc), naming the planted RFC 8414 violations"
  note "selftest OK: the gate has been shown red on both the vector and black-box axes"
}

run_check() {
  if [ ! -d "$ROOT/crates/oauth-as" ]; then
    fail "crates/oauth-as does not exist in this tree. The OAuth 2.1 AS is NOT present, so \
independent conformance CANNOT run and this gate refuses to pass vacuously."
  fi
  if [ ! -x "$ROOT/crates/oauth-as/conformance-serve.sh" ]; then
    fail "crates/oauth-as is a library with no binary, and the serve shim \
crates/oauth-as/conformance-serve.sh does not exist (or is not executable). Independent \
black-box conformance CANNOT run and this gate refuses to pass vacuously. Write the shim \
per the launch contract in crates/oauth-as-conformance/src/lib.rs, then re-run."
  fi

  note "vector suite (hermetic RFC vectors)"
  run_vectors || fail "RFC vector suite failed"

  note "starting crates/oauth-as on $ADDR via conformance-serve.sh"
  OAUTH_AS_ADDR="$ADDR" OAUTH_AS_CONFORMANCE_SEED=1 \
    "$ROOT/crates/oauth-as/conformance-serve.sh" >"$TMPDIR_CONF/as.log" 2>&1 &
  AS_PID=$!
  if ! wait_for_metadata "$BASE_URL" 120; then
    echo "---- AS log ----"; cat "$TMPDIR_CONF/as.log"; echo "----------------"
    fail "AS never served RFC 8414 metadata at $BASE_URL/.well-known/oauth-authorization-server \
within 120s. The launch contract is documented in crates/oauth-as-conformance/src/lib.rs."
  fi

  note "black-box + third-party client drive against $BASE_URL"
  if ! run_blackbox >"$TMPDIR_CONF/blackbox.log" 2>&1; then
    cat "$TMPDIR_CONF/blackbox.log"
    echo "---- AS log ----"; cat "$TMPDIR_CONF/as.log"; echo "----------------"
    fail "black-box conformance failed against the live AS"
  fi
  cat "$TMPDIR_CONF/blackbox.log"
  # A green suite that ran fewer checks than the source defines is the failure this catches.
  assert_blackbox_floor "$TMPDIR_CONF/blackbox.log"
  note "conformance PASS"
}

case "${1:-}" in
  --selftest) run_selftest ;;
  --check)    run_check ;;
  --help|-h)  sed -n '2,30p' "$0"; exit 0 ;;
  *) echo "usage: scripts/oauth-conformance.sh --selftest | --check" >&2; exit 2 ;;
esac
