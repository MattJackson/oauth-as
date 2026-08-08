#!/usr/bin/env bash
# oauth-mcp-lint.sh - run the third-party `authgent` MCP-OAuth scanner against this project's
# RFC 8414 authorization server metadata document.
#
# ============================================================================================
# READ THIS FIRST: what this proves, and the much larger thing it does NOT prove
# ============================================================================================
#
# `authgent` (github.com/authgent/authgent, Apache-2.0, PyPI `authgent-server`) is an MCP-OAuth
# conformance scanner. Its subject is an MCP RESOURCE SERVER. It finds the authorization server
# by fetching RFC 9728 protected resource metadata from the target and following
# `authorization_servers[0]`, and with no such document it emits one critical "not an MCP server"
# finding and skips every other check (scanner.py: `if status != 200 ... return findings, None`).
#
# THIS PROJECT IS NOT AN MCP SERVER AND WILL NEVER CLAIM TO BE ONE. Nothing this tool says about
# MCP conformance is quoted anywhere in this repository, and a clean run here is not an MCP badge.
#
# What is quoted is narrower and is the entire reason this exists: once the scanner reaches the
# authorization server, seven of its checks are checks OF AN RFC 8414 DOCUMENT, and they are made
# by a tool nobody here wrote:
#
#   MCP-AS-001         the RFC 8414 metadata document is reachable and is a JSON object
#   MCP-PKCE-001       `S256` is offered and `plain` is NOT (RFC 7636, OAuth 2.1)
#   MCP-PKCE-002       a LIVE probe of /authorize with `code_challenge_method=plain`, to catch a
#                      server that advertises S256-only and accepts plain anyway
#   MCP-ISS-001        `authorization_response_iss_parameter_supported` (RFC 9207)
#   MCP-AUD-001        `resource_indicators_supported` (RFC 8707)
#   MCP-DCR-001        `registration_endpoint` (RFC 7591)
#   MCP-CSRF-001       `token` is NOT in `response_types_supported` (no implicit grant)
#   MCP-REFRESH-001    DPoP algs advertised when the refresh grant is offered (RFC 9449)
#   MCP-PASSTHROUGH-001 an unauthenticated GET of the resource does not return 200
#
# Independent judges are the hardest thing for a plain OAuth AS to buy, and this is one.
#
# THE FIXTURE, and why standing one up is legitimate rather than a dodge.
#
# The scanner's discovery hop needs an RFC 9728 document, and RFC 9728 section 3.1 puts that
# document under the RESOURCE's identifier. `oauth-as` is an authorization server: it holds the
# TYPE and deliberately serves nothing (see src/resource_metadata.rs). So
# crates/oauth-as/examples/protected_resource_fixture.rs stands up a loopback test resource that
# publishes a correct document naming this AS.
#
# The obvious objection is that this is a resource server invented to satisfy a scanner. Three
# things answer it:
#
#   1. Nothing about the PUBLISHED crate changes. The fixture is an example, compiled only under
#      two off-by-default features, never linked into the library, and labelled in its own module
#      docs as a fixture that validates no token and serves no data.
#   2. The document is TRUE. A resource at http://127.0.0.1:8915 whose authorization server is
#      http://127.0.0.1:8914 is an accurate statement about the deployment under test. That is the
#      difference between this and the OIDC bolt-on KICKOFF.md refuses: that would add real
#      protocol surface to the published crate to earn a badge asserting a capability the design
#      deliberately rejects. This asserts nothing about the crate at all.
#   3. It earns its keep independently. `ProtectedResourceMetadata` had no worked consumer in the
#      tree, and the two things a reader is most likely to get wrong (the well-known path
#      insertion rule, and the section 5.1 `WWW-Authenticate` challenge) are now written out.
#
# The scaffolding is the same class of object as the seeded auto-approval, the RFC 7515 Appendix
# A.3 signing key, and the redirect URI at 127.0.0.1:8917 that the black-box harness already uses:
# things that exist so an external process can reach the thing under test, and that are labelled
# so nobody mistakes them for a template.
#
# THE BASELINE, and why this gates on regressions rather than on zero.
#
# The scanner's default threshold is `error`, and the run against this AS reports three findings,
# recorded in crates/oauth-as-conformance/authgent-baseline.json:
#
#   MCP-AUD-001 (error)     `resource_indicators_supported` is not advertised. This crate
#                           IMPLEMENTS RFC 8707 resource indicators, and RFC 8707 registers no
#                           metadata member for them (it has no IANA metadata registration at
#                           all). The member the scanner wants comes from the MCP specification,
#                           not from RFC 8707. Kept as an accepted finding rather than silenced,
#                           because "an external tool wants a member we do not publish" is a fact
#                           worth keeping in front of us.
#   MCP-DCR-001 (warning)   no `registration_endpoint`. The crate implements RFC 7591, but the
#                           conformance example does not turn it on, and an authorization server
#                           that opens registration by default is a worse one.
#   MCP-REFRESH-001 (warn)  no `dpop_signing_alg_values_supported`. The crate implements RFC 9449,
#                           behind an off-by-default feature the conformance example does not
#                           enable.
#
# Silencing those would be exactly the "green badge over an honest answer" trade this project
# refuses. Recording them and gating on ANYTHING NEW keeps the finding visible and still makes a
# regression fail. The baseline being ABSENT is not a way to pass: the scanner treats a missing
# baseline as empty, so every finding becomes new and the gate goes red.
#
# Modes:
#   --selftest  Prove the gate can go RED before any green from it is trusted:
#                 RED-A  with the fixture resource NOT running, the scan must fail, so the gate
#                        cannot pass by silently losing its discovery hop;
#                 RED-B  against a stub AS advertising `plain` PKCE and the implicit grant, the
#                        scan must fail and must NAME MCP-PKCE-001 and MCP-CSRF-001, which is what
#                        proves the AS-metadata checks are the ones doing the work.
#   --check     Start the AS and the fixture and run the scan in --diff mode against the baseline.
#   --baseline  Re-record the baseline. Run this ONLY when a finding has been read and accepted,
#               and say in the commit message which finding changed and why.
#
# Requires python3 (>= 3.11, which authgent-server 0.3.4 declares) and network access to PyPI.
# The scanner version is PINNED EXACTLY, for the same reason every other judge here is: a silent
# upgrade must never be able to change what "conformant" means.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER_PIN="authgent-server==0.3.4"
BASELINE="$ROOT/crates/oauth-as-conformance/authgent-baseline.json"
AS_ADDR="127.0.0.1:8914"
RS_ADDR="127.0.0.1:8915"
RESOURCE="http://${RS_ADDR}"
TMPDIR_LINT="$(mktemp -d "${TMPDIR:-/tmp}/oauth-mcp-lint.XXXXXX")"
AS_PID=""
RS_PID=""
STUB_PID=""
LINT=""

cleanup() {
  [ -n "$AS_PID" ] && kill "$AS_PID" 2>/dev/null
  [ -n "$RS_PID" ] && kill "$RS_PID" 2>/dev/null
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$TMPDIR_LINT"
}
trap cleanup EXIT INT TERM

fail() { echo "oauth-mcp-lint: FAIL: $*" >&2; exit 1; }
note() { echo "oauth-mcp-lint: $*"; }

install_scanner() {
  command -v python3 >/dev/null 2>&1 || fail "python3 is required and this gate refuses to skip"
  note "installing the pinned scanner ($SCANNER_PIN) into a throwaway venv"
  python3 -m venv "$TMPDIR_LINT/venv" >"$TMPDIR_LINT/venv.log" 2>&1 \
    || { cat "$TMPDIR_LINT/venv.log"; fail "could not create a venv"; }
  "$TMPDIR_LINT/venv/bin/pip" install --quiet "$SCANNER_PIN" >"$TMPDIR_LINT/pip.log" 2>&1 \
    || { cat "$TMPDIR_LINT/pip.log"; fail "could not install $SCANNER_PIN"; }
  LINT="$TMPDIR_LINT/venv/bin/authgent-server"
  [ -x "$LINT" ] || fail "authgent-server was installed but is not executable at $LINT"
}

build_examples() {
  note "building the AS and the RFC 9728 fixture resource"
  ( cd "$ROOT" && cargo build --locked -p oauth-as --features http,jwt,resource-metadata \
      --example conformance_server --example protected_resource_fixture ) \
      >"$TMPDIR_LINT/build.log" 2>&1 \
      || { cat "$TMPDIR_LINT/build.log"; fail "the examples did not build"; }
}

wait_for_url() {
  local url="$1" deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    # -f is deliberately absent: the fixture answers 401 on `/`, which is correct and not a
    # reason to keep waiting. Any response at all means the listener is up.
    if curl -s -o /dev/null --max-time 2 "$url"; then return 0; fi
    sleep 1
  done
  return 1
}

start_as() {
  OAUTH_AS_ADDR="$AS_ADDR" OAUTH_AS_CONFORMANCE_SEED=1 \
    "$ROOT/target/debug/examples/conformance_server" >"$TMPDIR_LINT/as.log" 2>&1 &
  AS_PID=$!
  wait_for_url "http://${AS_ADDR}/.well-known/oauth-authorization-server" 60 \
    || { cat "$TMPDIR_LINT/as.log"; fail "the AS never came up on $AS_ADDR"; }
}

start_fixture() {
  OAUTH_RS_ADDR="$RS_ADDR" OAUTH_AS_ISSUER="http://${AS_ADDR}" \
    "$ROOT/target/debug/examples/protected_resource_fixture" >"$TMPDIR_LINT/rs.log" 2>&1 &
  RS_PID=$!
  wait_for_url "$RESOURCE/.well-known/oauth-protected-resource" 60 \
    || { cat "$TMPDIR_LINT/rs.log"; fail "the fixture resource never came up on $RS_ADDR"; }
}

start_stub_as() {
  # An AS that advertises exactly the two things OAuth 2.1 forbids and the scanner checks for:
  # `plain` PKCE (RFC 7636 s4.3 / OAuth 2.1) and the implicit grant in response_types_supported.
  # Everything else is well formed, so the scan gets all the way to the AS-metadata checks and
  # the failure lands on them rather than on discovery.
  #
  # Written to a file rather than piped in on a heredoc: a backgrounded command with no stdin
  # redirection gets /dev/null for stdin (POSIX XCU 2.9.3), so `python3 -` would read nothing and
  # exit immediately, and the selftest would then fail for a reason that has nothing to do with
  # the AS.
  cat >"$TMPDIR_LINT/stub.py" <<'PYEOF'
import http.server, json, sys
host, port = sys.argv[1].rsplit(":", 1)
base = "http://%s:%s" % (host, port)
META = {
    "issuer": base,
    "authorization_endpoint": base + "/authorize",
    "token_endpoint": base + "/token",
    "response_types_supported": ["code", "token"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["plain", "S256"],
    "authorization_response_iss_parameter_supported": True,
    "resource_indicators_supported": True,
}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(META).encode() if ".well-known" in self.path else b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer((host, int(port)), H).serve_forever()
PYEOF
  python3 "$TMPDIR_LINT/stub.py" "$AS_ADDR" >"$TMPDIR_LINT/stub.log" 2>&1 &
  STUB_PID=$!
}

run_scan() {
  # Extra args are passed through verbatim. Prints to stdout; the caller decides what the exit
  # status means, because for two of the three modes here a nonzero exit is the required outcome.
  "$LINT" lint "$RESOURCE" "$@"
}

run_selftest() {
  install_scanner
  build_examples
  local rc

  note "SELFTEST RED-A: fixture resource NOT running; the scan must FAIL"
  start_as
  run_scan "--diff=$BASELINE" >"$TMPDIR_LINT/red-a.log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_LINT/red-a.log"
    fail "RED-A: the scan PASSED with no RFC 9728 document to discover through; the gate can \
pass without ever reaching this project's RFC 8414 document"
  fi
  if ! grep -q "MCP-PRM-001" "$TMPDIR_LINT/red-a.log"; then
    cat "$TMPDIR_LINT/red-a.log"
    fail "RED-A: the scan failed, but not with the expected MCP-PRM-001 discovery finding"
  fi
  note "SELFTEST RED-A: failed as required (exit $rc), naming MCP-PRM-001"
  kill "$AS_PID" 2>/dev/null; wait "$AS_PID" 2>/dev/null; AS_PID=""

  note "SELFTEST RED-B: stub AS advertising plain PKCE and the implicit grant; scan must FAIL"
  start_stub_as
  wait_for_url "http://${AS_ADDR}/.well-known/oauth-authorization-server" 30 \
    || fail "RED-B: the stub AS did not come up on $AS_ADDR"
  start_fixture
  run_scan "--diff=$BASELINE" >"$TMPDIR_LINT/red-b.log" 2>&1
  rc=$?
  kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; STUB_PID=""
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_LINT/red-b.log"
    fail "RED-B: the scan PASSED against an AS offering plain PKCE and the implicit grant"
  fi
  for want in MCP-PKCE-001 MCP-CSRF-001; do
    if ! grep -q "$want" "$TMPDIR_LINT/red-b.log"; then
      cat "$TMPDIR_LINT/red-b.log"
      fail "RED-B: the scan failed, but never reported $want; the RFC 8414 metadata checks are \
not the ones doing the work and this gate cannot be trusted"
    fi
  done
  note "SELFTEST RED-B: failed as required (exit $rc), naming MCP-PKCE-001 and MCP-CSRF-001"
  note "selftest OK: the scanner gate has been shown red on both axes"
}

run_check() {
  [ -f "$BASELINE" ] || fail "the accepted-findings baseline $BASELINE is missing. It is not \
optional: without it every finding is new and this gate is meaningless. Re-record it with \
--baseline only after reading what changed."
  install_scanner
  build_examples
  start_as
  start_fixture
  note "scanning $RESOURCE with $SCANNER_PIN, gating on anything new since the baseline"
  if ! run_scan "--diff=$BASELINE"; then
    echo "---- AS log ----"; cat "$TMPDIR_LINT/as.log"; echo "----------------"
    fail "the third-party scanner reported a finding that is NOT in the accepted baseline. That \
is a regression in this AS, or a finding worth accepting in writing; it is not a reason to \
re-record the baseline without reading it."
  fi
  note "scanner PASS: no finding beyond the ones recorded and explained in the baseline"
}

run_record_baseline() {
  install_scanner
  build_examples
  start_as
  start_fixture
  note "re-recording $BASELINE"
  "$LINT" lint "$RESOURCE" --save-baseline="$BASELINE" -f human
  note "baseline written. Read the diff before committing it, and say in the commit message \
which finding changed and why it is accepted."
}

case "${1:-}" in
  --selftest) run_selftest ;;
  --check)    run_check ;;
  --baseline) run_record_baseline ;;
  --help|-h)  sed -n '2,100p' "$0"; exit 0 ;;
  *) echo "usage: scripts/oauth-mcp-lint.sh --selftest | --check | --baseline" >&2; exit 2 ;;
esac
