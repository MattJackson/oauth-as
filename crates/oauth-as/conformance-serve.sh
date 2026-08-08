#!/usr/bin/env bash
# conformance-serve.sh - serve crates/oauth-as over HTTP for the independent black-box harness.
#
# crates/oauth-as is a LIBRARY with no binary, and its HTTP surface is an OPTIONAL feature, so
# "run the AS" means "run the example that turns the feature on". This shim is the whole of the
# launch contract documented in crates/oauth-as-conformance/src/lib.rs:
#
#   * bind the address in OAUTH_AS_ADDR (the harness uses 127.0.0.1:8914) and block until killed;
#   * under OAUTH_AS_CONFORMANCE_SEED=1, seed the deterministic fixtures: the public client
#     `conformance-public` (redirect http://127.0.0.1:8917/cb), the confidential client
#     `conformance-confidential`, auto-approval of a valid authorization request as
#     `conformance-user`, and approval of a device grant by POSTing form field `user_code` to the
#     advertised verification_uri.
#
# The seeding lives in the EXAMPLE (crates/oauth-as/examples/conformance_server.rs), never in the
# library: a published authorization server must not ship a client with a known secret.
#
# `exec` matters. scripts/oauth-conformance.sh kills the PID it backgrounded, so this process must
# BECOME the server rather than wrap it; a wrapper would leave the real listener holding the port.

set -eu

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$CRATE_DIR/../.." && pwd)"

export OAUTH_AS_ADDR="${OAUTH_AS_ADDR:-127.0.0.1:8914}"

# Build first, then exec the built binary. `cargo run` would leave cargo itself as the process the
# harness kills, and cargo does not always pass the signal on to the child.
cargo build --locked --manifest-path "$CRATE_DIR/Cargo.toml" \
  --features http --example conformance_server >&2

exec "$ROOT/target/debug/examples/conformance_server"
