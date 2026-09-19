#!/usr/bin/env bash
# Run the OpenID Foundation FAPI 2.0 Security Profile conformance suite against this crate's
# authorization server, in the `openid=plain_oauth` variant (no OIDC: this is an OAuth 2.1 AS).
#
# This is a MANUAL step, not a gate. It is invoked by .github/workflows/fapi2-conformance.yml on
# workflow_dispatch, or by hand. It never runs on push and never blocks main. Running the OIDF
# suite requires no OIDF membership, payment or agreement (EXTERNAL-TOOLING.md s2.4); only formal
# CERTIFICATION does, and that is a separate manual submission this script does not perform.
#
# HONESTY, in the manner of qa.yml: this job is wired to fail LOUDLY, never vacuously green.
# The FAPI 2.0 fixture it needs -- an HTTPS listener, two static private_key_jwt clients, a
# DPoP-verifying protected resource, mandatory PAR, and a refresh-rotation-OFF policy -- does not
# exist in the tree yet. The remaining pieces are enumerated in
# crates/oauth-as-conformance/EXTERNAL-TOOLING.md s2.3, and the single next step is s2.5. Until an
# example named below exists, this script STOPS at preflight with a pointer to that list. A green
# from this script is only trustworthy once that fixture is real; a red before then is correct.
#
# Usage:
#   scripts/fapi2-conformance.sh
#
# Environment (all optional; defaults chosen to run locally with no public hostname):
#   FAPI2_FIXTURE_EXAMPLE  cargo example that serves the FAPI 2.0 fixture over HTTPS.
#                          Default: fapi2_conformance_server  (DOES NOT EXIST YET -- see s2.5)
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

# --- Bring up the OIDF conformance suite (local devmode: no CONFORMANCE_TOKEN needed). ----------
if [[ ! -d "$CONFORMANCE_SUITE_DIR/.git" ]]; then
  echo "fapi2-conformance: cloning conformance-suite @ $CONFORMANCE_SUITE_REF"
  mkdir -p "$(dirname "$CONFORMANCE_SUITE_DIR")"
  git clone https://gitlab.com/openid/conformance-suite.git "$CONFORMANCE_SUITE_DIR"
fi
git -C "$CONFORMANCE_SUITE_DIR" fetch --depth 1 origin "$CONFORMANCE_SUITE_REF" || true
git -C "$CONFORMANCE_SUITE_DIR" checkout -q "$CONFORMANCE_SUITE_REF"

echo "fapi2-conformance: building + starting the suite (docker compose up)"
( cd "$CONFORMANCE_SUITE_DIR" \
    && mvn -q -B clean package -DskipTests \
    && docker compose up -d )

cleanup() { ( cd "$CONFORMANCE_SUITE_DIR" && docker compose down -v ) || true; }
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
"./target/release/examples/${FAPI2_FIXTURE_EXAMPLE}" &
fixture_pid=$!
trap 'kill "$fixture_pid" 2>/dev/null || true; cleanup' EXIT

[[ -f "$FAPI2_CONFIG" ]] || die "suite config not found: $FAPI2_CONFIG (see EXTERNAL-TOOLING.md s2.3)"

# --- Run the plan with the OIDF runner and collect the certification package. -------------------
mkdir -p "$FAPI2_LOG_DIR"
echo "fapi2-conformance: running plan"
echo "  $FAPI2_PLAN"
python3 "$CONFORMANCE_SUITE_DIR/scripts/run-test-plan.py" \
  "$FAPI2_PLAN" "$FAPI2_CONFIG" \
  | tee "$FAPI2_LOG_DIR/run.log"

echo "fapi2-conformance: done. Logs + certification package under $FAPI2_LOG_DIR"
echo "For a formal certification submission, use the suite's 'Publish for certification' to"
echo "produce the log ZIP, then submit at https://submissions.openid.net/ (EXTERNAL-TOOLING.md s2.4)."
