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

/// The NAME is the whole notice, and it has to be: `cargo test` captures both `stdout` and
/// `stderr` of a test that PASSES and discards them, so a `println!` or `eprintln!` here would be
/// invisible in exactly the case this file exists for (the normal one, where the suite is green
/// and nobody passed `--nocapture`). The one line that always reaches the terminal is
/// `test <name> ... ok`, so everything that has to be read goes in the name.
///
/// The body stays empty for the same reason. A body that printed the longer form would look like
/// the notice while being the half nobody sees, which is the failure this whole file is about.
/// The longer form lives in the module docs above, where a reader who follows the name will find
/// it, and in `scripts/postgres-conformance.sh`.
#[test]
fn skipped_postgres_atomicity_proof_run_scripts_postgres_conformance_sh_or_features_pg_integration()
{
}
