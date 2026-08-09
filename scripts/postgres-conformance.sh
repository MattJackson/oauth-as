#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# Run the oauth-as Storage conformance harness, and the two-connection atomicity proof, against a
# REAL PostgreSQL.
#
# WHY A SCRIPT RATHER THAN `cargo test`. The tests are behind `--features pg-integration` and
# refuse to run without a database, on purpose: a storage test that quietly skips is exactly the
# kind of green this repository does not accept. This script supplies the database so that the
# refusal is never the reason somebody stops checking.
#
#   ./scripts/postgres-conformance.sh            # start a throwaway container, run, clean up
#   OAUTH_AS_POSTGRES_TEST_URL=... ./scripts/postgres-conformance.sh   # use an existing database
#
# The container is named and removed on exit, including on failure.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="oauth-as-postgres-conformance"
IMAGE="postgres:16-alpine"
# Not 5432, and not the usual 554xx throwaway ports either: a developer machine often already has
# something on those, and a port clash here would look like a database failure rather than like a
# port clash. Override with OAUTH_AS_POSTGRES_TEST_PORT.
PORT="${OAUTH_AS_POSTGRES_TEST_PORT:-59432}"
STARTED_CONTAINER=0

cleanup() {
    if [ "$STARTED_CONTAINER" = "1" ]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [ -z "${OAUTH_AS_POSTGRES_TEST_URL:-}" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        cat >&2 <<'EOF'
================================================================================
No OAUTH_AS_POSTGRES_TEST_URL and no docker. This script cannot supply a
database, so the atomicity proof cannot run.

It is deliberately an ERROR rather than a skip: the two-connection test is the
only evidence this repository has that take_* is atomic across connections,
which is the one thing the in-process conformance harness says it cannot prove.
Point OAUTH_AS_POSTGRES_TEST_URL at a PostgreSQL and run this again.
================================================================================
EOF
        exit 1
    fi

    echo "starting a throwaway $IMAGE on port $PORT"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER" \
        -e POSTGRES_PASSWORD=postgres \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_DB=oauth_as_test \
        -p "$PORT:5432" \
        "$IMAGE" >/dev/null
    STARTED_CONTAINER=1

    echo -n "waiting for the server to accept connections"
    for _ in $(seq 1 60); do
        if docker exec "$CONTAINER" pg_isready -U postgres -d oauth_as_test >/dev/null 2>&1; then
            break
        fi
        echo -n "."
        sleep 1
    done
    echo
    if ! docker exec "$CONTAINER" pg_isready -U postgres -d oauth_as_test >/dev/null 2>&1; then
        echo "the container never became ready" >&2
        exit 1
    fi

    export OAUTH_AS_POSTGRES_TEST_URL="postgres://postgres:postgres@127.0.0.1:$PORT/oauth_as_test"
fi

echo "running against $OAUTH_AS_POSTGRES_TEST_URL"
cd "$ROOT"
# `--test-threads` is left alone deliberately: the tests take their own schema each precisely so
# they CAN run in parallel, and running them in parallel is additional load on the same server,
# which is closer to the deployment the atomicity contract is about.
cargo test -p oauth-as-postgres --features pg-integration --locked -- --nocapture "$@"
