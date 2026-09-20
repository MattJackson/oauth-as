#!/usr/bin/env bash
# Run the OpenID Foundation FAPI 2.0 Security Profile conformance suite against this crate's
# authorization server, in the `openid=plain_oauth` variant (no OIDC: this is an OAuth 2.1 AS).
#
# Invoked by .github/workflows/fapi2-conformance.yml on push to the qa branch (it GATES qa) and on
# workflow_dispatch, or by hand. Running the OIDF suite requires no OIDF membership, payment or
# agreement (EXTERNAL-TOOLING.md s2.4); only formal CERTIFICATION does, and that is a separate
# manual submission this script does not perform.
#
# HONESTY, in the manner of qa.yml: this job is wired to fail LOUDLY, never vacuously green.
# The fixture it drives is crates/oauth-as/examples/fapi2_conformance_server.rs (the preflight
# below still checks it is present, so a renamed or deleted fixture stops here with a pointer
# rather than "passing" an empty run). The runner's exit status is the gate: every condition
# FAILURE or WARNING the suite records is a red, EXCEPT the ones listed, one entry per condition,
# in crates/oauth-as-conformance/fapi2/expected-failures.json (FAPI2_EXPECTED_FAILURES below).
# That file is the OIDF runner's own --expected-failures-file mechanism and it cuts both ways: an
# unlisted failure is a red, AND a listed condition that STOPS failing (an XPASS) is ALSO a red
# ("expected failure did not happen"), so a fix cannot land without deleting its entry and a
# stale entry cannot hide a regression. A missing file is a hard stop, not an empty list. Each
# entry carries its justification; the evidence is crates/oauth-as-conformance/fapi2/FINDINGS.md.
#
# Usage:
#   scripts/fapi2-conformance.sh
#
# Environment (all optional; defaults chosen to run locally with no public hostname):
#   FAPI2_FIXTURE_EXAMPLE  cargo example that serves the FAPI 2.0 fixture over HTTPS.
#                          Default: fapi2_conformance_server
#   FAPI2_EXPECTED_FAILURES  the OIDF --expected-failures-file: exact per-condition entries, no
#                          wildcards (rules in crates/oauth-as-conformance/fapi2/README.md).
#                          Default: crates/oauth-as-conformance/fapi2/expected-failures.json
#   FAPI2_PLAN             the OIDF test-plan string to run.
#                          Default: the private_key_jwt + DPoP plain_oauth profile.
#   CONFORMANCE_SUITE_DIR  checkout of gitlab.com/openid/conformance-suite.
#                          Default: .fapi2/conformance-suite (cloned + built if absent).
#   CONFORMANCE_SUITE_REF  git ref of the suite to pin. Default: the commit cited in
#                          EXTERNAL-TOOLING.md s2 so a green is reproducible.
#   FAPI2_CONFIG           the suite config.json (two clients, resource.resourceUrl, browser task
#                          list). Default: crates/oauth-as-conformance/fapi2/config.json
#   FAPI2_LOG_DIR          where to write the certification log ZIP + run logs.
#                          Default: target/fapi2-conformance
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

FAPI2_FIXTURE_EXAMPLE="${FAPI2_FIXTURE_EXAMPLE:-fapi2_conformance_server}"
FAPI2_PLAN="${FAPI2_PLAN:-fapi2-security-profile-final-test-plan[openid=plain_oauth][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]}"
CONFORMANCE_SUITE_DIR="${CONFORMANCE_SUITE_DIR:-$repo_root/.fapi2/conformance-suite}"
CONFORMANCE_SUITE_REF="${CONFORMANCE_SUITE_REF:-6b8b809dd07df6ca8b4481a9e921bf48b9ffbffe}"
FAPI2_CONFIG="${FAPI2_CONFIG:-$repo_root/crates/oauth-as-conformance/fapi2/config.json}"
FAPI2_EXPECTED_FAILURES="${FAPI2_EXPECTED_FAILURES:-$repo_root/crates/oauth-as-conformance/fapi2/expected-failures.json}"
FAPI2_EXPECTED_SKIPS="${FAPI2_EXPECTED_SKIPS:-$repo_root/crates/oauth-as-conformance/fapi2/expected-skips.json}"
FAPI2_LOG_DIR="${FAPI2_LOG_DIR:-$repo_root/target/fapi2-conformance}"

die() { echo "fapi2-conformance: $*" >&2; exit 1; }

# --- Preflight: the fixture is the blocker, so check it first and fail with the pointer. --------
fixture_src="crates/oauth-as/examples/${FAPI2_FIXTURE_EXAMPLE}.rs"
if [[ ! -f "$fixture_src" ]]; then
  cat >&2 <<EOF
fapi2-conformance: STOP. The FAPI 2.0 fixture example is not in the tree yet.

  expected: $fixture_src

This is the known, written-down blocker, not a bug in this script. The FAPI 2.0 Security Profile
plain_oauth run needs a fixture that:
  1. serves this AS over HTTPS with a self-signed cert (the suite trusts all certs; no public
     hostname or CA is required -- EXTERNAL-TOOLING.md s2.2),
  2. registers two static clients with distinct private_key_jwt keys (client, client2),
  3. stands up a protected resource endpoint that returns JSON ONLY for a valid DPoP-bound token,
  4. makes PAR mandatory and emits require_pushed_authorization_requests +
     pushed_authorization_request_endpoint + authorization_response_iss_parameter_supported:true,
  5. sets an auth-code lifetime <= 60s and request_uri expiry < 600s,
  6. runs with refresh-token ROTATION DISABLED (FAPI 2.0 s5.3.2.1-9 forbids rotation; this crate
     rotates by default -- a config switch to turn it off is required and does not exist yet).

The full list with spec citations is EXTERNAL-TOOLING.md s2.3; the single next step is s2.5.
Build that example (and the rotation-off switch it depends on), then re-run this script.
EOF
  exit 1
fi

command -v docker >/dev/null 2>&1 || die "docker is required to run the OIDF suite"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

# --- The expected-failures file is part of the gate's definition, so check it HERE, before the
# ten-minute suite build, and check its SHAPE as well as its presence: the runner indexes every
# key of every entry directly and raises (KeyError / TypeError) at ANALYSIS time, i.e. after the
# whole plan has run, for an entry missing one. A wildcard is refused here even where the runner
# would accept one ('test-name', 'current-block', variant '*'): one '*' can swallow an unrelated
# regression, which is the one thing this file must never do. The rules, and how to capture the
# exact strings for a new entry, are in crates/oauth-as-conformance/fapi2/README.md. ------------
[[ -f "$FAPI2_EXPECTED_FAILURES" ]] \
  || die "expected-failures file not found: $FAPI2_EXPECTED_FAILURES (crates/oauth-as-conformance/fapi2/README.md)"
python3 - "$FAPI2_EXPECTED_FAILURES" <<'PY' || die "expected-failures file is malformed (see above)"
import json, sys
path = sys.argv[1]
required = ("test-name", "variant", "configuration-filename", "condition", "current-block", "expected-result")
ok = True
with open(path) as f:
    entries = json.load(f)
if not isinstance(entries, list):
    print(f"{path}: the top level must be a JSON array of entries")
    sys.exit(1)
for i, e in enumerate(entries):
    missing = [k for k in required if k not in e]
    if missing:
        print(f"{path}: entry {i} is missing {missing}")
        ok = False
    if e.get("expected-result") not in ("failure", "warning"):
        print(f"{path}: entry {i}: expected-result must be 'failure' or 'warning'")
        ok = False
    for k in ("test-name", "condition", "current-block"):
        if "*" in str(e.get(k, "")):
            print(f"{path}: entry {i}: a wildcard in {k!r} is forbidden in this repository")
            ok = False
    if e.get("variant") == "*" or not isinstance(e.get("variant"), dict):
        print(f"{path}: entry {i}: variant must be an object of pinned dimensions, never '*'")
        ok = False
sys.exit(0 if ok else 1)
PY

# --- The expected-SKIPS file is the same kind of gate as expected-failures and is held to the same
# honesty rules: exact test-name, a pinned variant object, no wildcards. The OIDF runner
# (--expected-skips-file) treats a listed test that STOPS being SKIPPED as a red
# (expected_skip_did_not_happen), so a skip that turns into a real pass cannot go unnoticed. A skip
# is only ever listed for a test the plan legitimately cannot run against this profile (e.g. a
# module that needs RSA/PS256 keys this ES256 fixture does not offer), never to hide a failure. ---
[[ -f "$FAPI2_EXPECTED_SKIPS" ]] \
  || die "expected-skips file not found: $FAPI2_EXPECTED_SKIPS (crates/oauth-as-conformance/fapi2/README.md)"
python3 - "$FAPI2_EXPECTED_SKIPS" <<'PY' || die "expected-skips file is malformed (see above)"
import json, sys
path = sys.argv[1]
required = ("test-name", "variant", "configuration-filename")
ok = True
with open(path) as f:
    entries = json.load(f)
if not isinstance(entries, list):
    print(f"{path}: the top level must be a JSON array of entries")
    sys.exit(1)
for i, e in enumerate(entries):
    missing = [k for k in required if k not in e]
    if missing:
        print(f"{path}: entry {i} is missing {missing}")
        ok = False
    if "*" in str(e.get("test-name", "")):
        print(f"{path}: entry {i}: a wildcard in 'test-name' is forbidden in this repository")
        ok = False
    if e.get("variant") == "*" or not isinstance(e.get("variant"), dict):
        print(f"{path}: entry {i}: variant must be an object of pinned dimensions, never '*'")
        ok = False
sys.exit(0 if ok else 1)
PY

# --- Bring up the OIDF conformance suite (local devmode: no CONFORMANCE_TOKEN needed). ----------
if [[ ! -d "$CONFORMANCE_SUITE_DIR/.git" ]]; then
  echo "fapi2-conformance: cloning conformance-suite @ $CONFORMANCE_SUITE_REF"
  mkdir -p "$(dirname "$CONFORMANCE_SUITE_DIR")"
  git clone https://gitlab.com/openid/conformance-suite.git "$CONFORMANCE_SUITE_DIR"
fi
git -C "$CONFORMANCE_SUITE_DIR" fetch --depth 1 origin "$CONFORMANCE_SUITE_REF" || true
git -C "$CONFORMANCE_SUITE_DIR" checkout -q "$CONFORMANCE_SUITE_REF"

# Build the suite first. `mvn clean` wipes target/, which is bind-mounted into the server container
# at /server, so the PKI below must be generated AFTER the build and BEFORE the container starts.
echo "fapi2-conformance: building the suite (mvn package)"
( cd "$CONFORMANCE_SUITE_DIR" && mvn -q -B clean package -DskipTests )

# --- TLS trust: the suite's HtmlUnit BROWSER (unlike its condition HTTP client) uses the JVM
# default trust store and does NOT trust arbitrary certs, so a self-signed fixture cert makes every
# browser-driven authorization leg hang in WAITING. Establish a private CA, sign an `as.local` leaf
# for the fixture with it, and import the CA into the server container's trust store. The suite
# itself is UNMODIFIED -- this is PKI configuration of the test environment, exactly as a real
# deployment presents a publicly-trusted certificate, so the run stays certification-legitimate.
PKI="$CONFORMANCE_SUITE_DIR/target/fapi2-pki"   # under target/ -> mounted at /server in the container
mkdir -p "$PKI"
echo "fapi2-conformance: generating a private CA and an as.local leaf certificate"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PKI/ca.key" -out "$PKI/ca.crt" \
  -subj "/CN=oauth-as-fapi2-test-CA" -days 2 -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$PKI/as.key" -out "$PKI/as.csr" \
  -subj "/CN=as.local" 2>/dev/null
printf 'subjectAltName=DNS:as.local,DNS:localhost,DNS:localhost.emobix.co.uk,IP:127.0.0.1\n' > "$PKI/as.ext"
openssl x509 -req -in "$PKI/as.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
  -out "$PKI/as.crt" -days 2 -extfile "$PKI/as.ext" 2>/dev/null
cat "$PKI/as.crt" "$PKI/ca.crt" > "$PKI/as.fullchain.crt"

# The suite runs in Docker; this crate's fixture runs on the host. Containers cannot reach the host
# via `localhost`, so map `as.local` to the host gateway for the `server` container (which also
# hosts the in-JVM HtmlUnit browser). The same override imports the private CA into the container's
# JDK cacerts before the JVM starts, so the browser trusts the fixture's as.local certificate. The
# original java command line is reproduced verbatim (compose `command` replaces, not merges).
cat > "$CONFORMANCE_SUITE_DIR/docker-compose.override.yml" <<'OVERRIDE'
services:
  server:
    user: root
    extra_hosts:
      - "as.local:host-gateway"
    command:
      - /bin/sh
      - -c
      - |
        set -e
        keytool -importcert -noprompt -cacerts -storepass changeit \
          -alias oauth-as-fapi2-ca -file /server/fapi2-pki/ca.crt
        exec java -jar /server/fapi-test-suite.jar \
          -Djdk.tls.maxHandshakeMessageSize=65536 \
          --fintechlabs.base_url=https://localhost.emobix.co.uk:8443 \
          --fintechlabs.devmode=true \
          --fintechlabs.startredir=true
OVERRIDE

echo "fapi2-conformance: starting the suite (docker compose up)"
( cd "$CONFORMANCE_SUITE_DIR" && docker compose up -d )

# The OIDF runner (run-test-plan.py) needs httpx + pyparsing.
python3 -m pip install -q -r "$CONFORMANCE_SUITE_DIR/scripts/requirements.txt"

mkdir -p "$FAPI2_LOG_DIR"

# On ANY exit, dump the suite server's own logs (they show per-module progress and the exact point
# a run stalls or fails) so a hang or a red is diagnosable from the uploaded artifact rather than
# being a black box, then tear everything down.
cleanup() {
  # Capture each test module's FULL log (the suite records every browser request/redirect/error
  # here, so this shows exactly where a WAITING module stalls) BEFORE tearing the suite down.
  if [[ -f "$FAPI2_LOG_DIR/run.log" ]]; then
    mkdir -p "$FAPI2_LOG_DIR/modules"
    grep "new id:" "$FAPI2_LOG_DIR/run.log" 2>/dev/null \
      | sed -E 's/.*new id: ([A-Za-z0-9]+).*/\1/' | sort -u | while read -r mid; do
        [[ -n "$mid" ]] || continue
        curl -ksSf "https://localhost.emobix.co.uk:8443/api/log/$mid" \
          -o "$FAPI2_LOG_DIR/modules/$mid.json" 2>/dev/null || true
      done
  fi
  ( cd "$CONFORMANCE_SUITE_DIR" && docker compose logs --no-color server > "$FAPI2_LOG_DIR/suite-server.log" 2>&1 ) || true
  kill "${fixture_pid:-0}" 2>/dev/null || true
  ( cd "$CONFORMANCE_SUITE_DIR" && docker compose down -v ) || true
}
trap cleanup EXIT

# Wait for the suite API to answer (devmode: no auth token required).
echo "fapi2-conformance: waiting for the suite to come up"
for _ in $(seq 1 60); do
  if curl -ksSf https://localhost.emobix.co.uk:8443/api/currentuser >/dev/null 2>&1; then break; fi
  sleep 5
done

# --- Launch this crate's FAPI 2.0 fixture over HTTPS. -------------------------------------------
echo "fapi2-conformance: launching fixture example '$FAPI2_FIXTURE_EXAMPLE'"
cargo build --release --example "$FAPI2_FIXTURE_EXAMPLE" \
  --features "axum,jwt-p256,dpop,par,client-assertion" \
  || die "the fixture example failed to build"
# The suite owns :8443 (its nginx front-end), so the fixture binds :8444 on all interfaces and is
# reached from the suite containers as `as.local` (mapped to the host gateway above). The redirect
# URI must point back to the SUITE's per-alias callback: in a conformance run the suite is the
# client, so the AS redirects the user-agent to the suite, not to itself.
export OAUTH_AS_ADDR="${OAUTH_AS_ADDR:-0.0.0.0:8444}"
export OAUTH_AS_ISSUER="${OAUTH_AS_ISSUER:-https://as.local:8444}"
export OAUTH_AS_RESOURCE="${OAUTH_AS_RESOURCE:-https://as.local:8444/resource}"
export OAUTH_AS_FAPI_REDIRECT_URIS="${OAUTH_AS_FAPI_REDIRECT_URIS:-https://localhost.emobix.co.uk:8443/test/a/oauth-as-fapi2-plain-oauth/callback}"
# Serve the CA-signed leaf (fullchain) generated above, so the suite's browser -- which imported the
# CA into its trust store -- accepts the fixture's certificate on the authorization leg.
export OAUTH_AS_TLS_CERT="${OAUTH_AS_TLS_CERT:-$PKI/as.fullchain.crt}"
export OAUTH_AS_TLS_KEY="${OAUTH_AS_TLS_KEY:-$PKI/as.key}"
"./target/release/examples/${FAPI2_FIXTURE_EXAMPLE}" > "$FAPI2_LOG_DIR/fixture.log" 2>&1 &
fixture_pid=$!

[[ -f "$FAPI2_CONFIG" ]] || die "suite config not found: $FAPI2_CONFIG (see EXTERNAL-TOOLING.md s2.3)"

# --- Prove reachability BEFORE running the plan, so a networking fault fails fast and legibly
# instead of hanging the plan for hours on a module that can never complete. -------------------
disc_path="/.well-known/oauth-authorization-server"
echo "fapi2-conformance: probing the fixture locally (127.0.0.1:8444)"
for _ in $(seq 1 30); do
  if curl -ksSf "https://127.0.0.1:8444$disc_path" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -ksSf "https://127.0.0.1:8444$disc_path" >/dev/null 2>&1 \
  || { echo "----- fixture.log -----"; cat "$FAPI2_LOG_DIR/fixture.log" || true; \
       die "the fixture is not serving discovery on 127.0.0.1:8444 (see fixture.log)"; }

echo "fapi2-conformance: probing the fixture FROM the suite server container (as.local:8444)"
( cd "$CONFORMANCE_SUITE_DIR" \
  && docker compose exec -T server curl -ksSf "https://as.local:8444$disc_path" >/dev/null 2>&1 ) \
  || die "the suite container cannot reach the fixture at as.local:8444 -- the host-gateway \
override (docker-compose.override.yml) or the host firewall is the problem, not a conformance \
failure. The fixture IS up locally (probe above passed)."

# --- Run the plan with the OIDF runner and collect the certification package. -------------------
echo "fapi2-conformance: running plan"
echo "  $FAPI2_PLAN"
# Hard cap the run: a plan that has not finished in 25 minutes is stuck, and a fast red with the
# suite-server.log dumped by cleanup() is worth far more than a 6-hour silent hang.
#
# The runner's exit status IS the verdict and `pipefail` carries it through the tee: it exits 1
# on any condition failure/warning not listed in FAPI2_EXPECTED_FAILURES, on any listed one that
# did NOT happen (an XPASS is a red here by design), on an unexpected SKIP, and on a listed entry
# that matched no module at all (e.g. a configuration-filename glob that does not match the path
# passed as the second argument). --verbose makes it print, for every unexpected result, the
# exact block/condition strings as a ready-to-paste entry template, so a new finding is recorded
# from the run rather than guessed.
timeout "${FAPI2_PLAN_TIMEOUT:-1500}" python3 "$CONFORMANCE_SUITE_DIR/scripts/run-test-plan.py" \
  "$FAPI2_PLAN" "$FAPI2_CONFIG" --export-dir "$FAPI2_LOG_DIR" \
  --expected-failures-file "$FAPI2_EXPECTED_FAILURES" \
  --expected-skips-file "$FAPI2_EXPECTED_SKIPS" --verbose \
  | tee "$FAPI2_LOG_DIR/run.log"

echo "fapi2-conformance: done. Logs + certification package under $FAPI2_LOG_DIR"
echo "For a formal certification submission, use the suite's 'Publish for certification' to"
echo "produce the log ZIP, then submit at https://submissions.openid.net/ (EXTERNAL-TOOLING.md s2.4)."
