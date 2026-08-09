// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The LOUD half of "these tests did not run".
//!
//! The database-backed tests are behind `--features pg-integration` so that
//! `cargo test --workspace` on a machine with no PostgreSQL is honest rather than red. The cost
//! of that choice is the failure mode this repository refuses to accept elsewhere: a suite that
//! looks green while proving nothing. So the default build carries a test whose NAME is the
//! notice, printed by `cargo test` on every run, and which points at the script that supplies the
//! database.
//!
//! With the feature on, this file compiles to nothing and the real tests run instead; a missing
//! `OAUTH_AS_POSTGRES_TEST_URL` is then a panic, not a skip.

#![cfg(not(feature = "pg-integration"))]

#[test]
fn postgres_atomicity_proof_did_not_run_use_scripts_postgres_conformance_sh() {
    eprintln!(
        "\n\
         oauth-as-postgres: the conformance run and the two-connection atomicity proof were NOT\n\
         executed. They need a real PostgreSQL and are behind `--features pg-integration`.\n\
         Run scripts/postgres-conformance.sh (it starts a throwaway container), or:\n\
         \n  \
         OAUTH_AS_POSTGRES_TEST_URL=postgres://... \\\n    \
         cargo test -p oauth-as-postgres --features pg-integration\n"
    );
}
