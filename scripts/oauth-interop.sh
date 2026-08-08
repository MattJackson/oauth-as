#!/usr/bin/env bash
# oauth-interop.sh - drive a SECOND, independent third-party OAuth client against the live AS.
#
# WHY THIS EXISTS, and what it is worth
#
# crates/oauth-as-conformance already drives the pinned Rust client `oauth2 = "=5.0.0"`. That is
# one independent judgement. This adds a second one from a different author, a different language
# and a different codebase: golang.org/x/oauth2, maintained by the Go project, pinned exactly at
# v0.36.0 with go.sum locking the module hashes.
#
# Two independent client libraries accepting the same wire bytes is a materially stronger claim
# than one, and it is deliberately NOT a second opinion on the same questions: this drive covers
# the RFC 6749 s4.4 client credentials grant and the s6 refresh grant with rotation, neither of
# which the Rust client drive exercises.
#
# What it is NOT: it is not certification, and it is not a conformance suite. It is two clients
# agreeing. See the "What is not claimed" section of README.md, which this does not change.
#
# Modes:
#   --selftest  Prove the gate can go RED before any green from it is trusted, on both axes:
#                 RED-A  with no AS reachable at all, the drive must FAIL rather than skip;
#                 RED-B  against a stub AS that serves plausible RFC 8414 metadata but answers
#                        every protocol endpoint with an empty JSON object, the drive must FAIL
#                        and must NAME the individual checks that failed, which proves the
#                        per-grant assertions are live and not merely the metadata fetch.
#   --check     Run it against the AS served by crates/oauth-as/conformance-serve.sh.
#
# Requires the `go` toolchain (>= 1.25, the floor golang.org/x/oauth2 v0.36.0 itself declares) and
# python3 for the --selftest stub. Both are absent-is-FAIL, never absent-is-skip.
#
# Backgrounded servers ALWAYS get their stdout/stderr redirected to a log file, never captured via
# command substitution, which would hang until the backgrounded child closed its inherited stdout.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GODIR="$ROOT/crates/oauth-as-conformance/interop/go"
ADDR="127.0.0.1:8914"
BASE_URL="http://${ADDR}"
TMPDIR_INTEROP="$(mktemp -d "${TMPDIR:-/tmp}/oauth-interop.XXXXXX")"
AS_PID=""
STUB_PID=""

cleanup() {
  [ -n "$AS_PID" ] && kill "$AS_PID" 2>/dev/null
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$TMPDIR_INTEROP"
}
trap cleanup EXIT INT TERM

fail() { echo "oauth-interop: FAIL: $*" >&2; exit 1; }
note() { echo "oauth-interop: $*"; }

require_go() {
  command -v go >/dev/null 2>&1 || fail "the go toolchain is not installed. This gate refuses to \
skip: install go (>= 1.25) or remove this job, but do not let it pass without running."
  [ -f "$GODIR/go.mod" ] || fail "$GODIR/go.mod is missing; the pinned third-party client is gone"
}

# -mod=readonly (the default) plus the committed go.sum: the build fails rather than silently
# resolving a different version of the judge.
run_drive() {
  ( cd "$GODIR" && OAUTH_AS_BASE_URL="$1" go run -mod=readonly . )
}

wait_for_metadata() {
  local url="$1/.well-known/oauth-authorization-server" deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -sf -o /dev/null --max-time 2 "$url"; then return 0; fi
    sleep 1
  done
  return 1
}

start_stub_as() {
  # Plausible RFC 8414 metadata, nothing behind it. The metadata is deliberately well formed so
  # that the drive gets PAST discovery and the failure lands on the per-grant assertions; a stub
  # that failed at discovery would only prove the first line of the program runs.
  command -v python3 >/dev/null 2>&1 || fail "RED-B needs python3 for the stub AS"
  python3 - "$ADDR" >"$TMPDIR_INTEROP/stub.log" 2>&1 <<'PYEOF' &
import http.server, json, sys
host, port = sys.argv[1].rsplit(":", 1)
base = "http://%s:%s" % (host, port)
META = {
    "issuer": base,
    "authorization_endpoint": base + "/authorize",
    "token_endpoint": base + "/token",
    "device_authorization_endpoint": base + "/device_authorization",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "client_credentials",
                              "urn:ietf:params:oauth:grant-type:device_code"],
    "code_challenge_methods_supported": ["S256"],
}
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/.well-known/oauth-authorization-server"):
            self._send(json.dumps(META).encode())
        else:
            self._send(b"{}")
    def do_POST(self):
        self._send(b"{}")
    def log_message(self, *a):
        pass
http.server.HTTPServer((host, int(port)), H).serve_forever()
PYEOF
  STUB_PID=$!
}

run_selftest() {
  require_go
  local rc

  note "SELFTEST RED-A: no AS running; the drive must FAIL rather than skip"
  run_drive "http://127.0.0.1:1" >"$TMPDIR_INTEROP/red-a.log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_INTEROP/red-a.log"
    fail "RED-A: the drive PASSED with no AS to talk to; it can pass vacuously"
  fi
  note "SELFTEST RED-A: failed as required (exit $rc)"

  note "SELFTEST RED-B: stub AS with plausible metadata and empty responses; drive must FAIL"
  start_stub_as
  wait_for_metadata "$BASE_URL" 15 || fail "RED-B: stub AS did not come up on $ADDR"
  run_drive "$BASE_URL" >"$TMPDIR_INTEROP/red-b.log" 2>&1
  rc=$?
  kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; STUB_PID=""
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_INTEROP/red-b.log"
    fail "RED-B: the drive PASSED against a stub that issues no tokens; the gate is worthless"
  fi
  # Each named grant must be reported failing individually. Exit status alone would also be
  # satisfied by a crash during discovery, which would prove nothing about the assertions.
  for want in "FAIL  device flow" "FAIL  authorization code" "FAIL  client credentials"; do
    if ! grep -q "$want" "$TMPDIR_INTEROP/red-b.log"; then
      cat "$TMPDIR_INTEROP/red-b.log"
      fail "RED-B: the drive failed, but never reported '$want'; the per-grant assertions are \
not doing the work and this gate cannot be trusted"
    fi
  done
  note "SELFTEST RED-B: failed as required (exit $rc), naming each grant individually"
  note "selftest OK: the second-judge gate has been shown red on both axes"
}

run_check() {
  require_go
  if [ ! -x "$ROOT/crates/oauth-as/conformance-serve.sh" ]; then
    fail "crates/oauth-as/conformance-serve.sh does not exist (or is not executable), so the AS \
cannot be served and this gate refuses to pass vacuously."
  fi

  note "starting crates/oauth-as on $ADDR via conformance-serve.sh"
  OAUTH_AS_ADDR="$ADDR" OAUTH_AS_CONFORMANCE_SEED=1 \
    "$ROOT/crates/oauth-as/conformance-serve.sh" >"$TMPDIR_INTEROP/as.log" 2>&1 &
  AS_PID=$!
  if ! wait_for_metadata "$BASE_URL" 120; then
    echo "---- AS log ----"; cat "$TMPDIR_INTEROP/as.log"; echo "----------------"
    fail "AS never served RFC 8414 metadata at $BASE_URL within 120s"
  fi

  note "golang.org/x/oauth2 v0.36.0 (pinned) driving $BASE_URL"
  if ! run_drive "$BASE_URL"; then
    echo "---- AS log ----"; cat "$TMPDIR_INTEROP/as.log"; echo "----------------"
    fail "the second independent client rejected this AS"
  fi
  note "interop PASS: a second, independent client library accepts this AS"
}

case "${1:-}" in
  --selftest) run_selftest ;;
  --check)    run_check ;;
  --help|-h)  sed -n '2,40p' "$0"; exit 0 ;;
  *) echo "usage: scripts/oauth-interop.sh --selftest | --check" >&2; exit 2 ;;
esac
