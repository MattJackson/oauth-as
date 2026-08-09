// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! STEADY-STATE HEAP per stored record, which is the efficiency number a deployment actually
//! feels.
//!
//! `tests/allocation.rs` pins allocator TRAFFIC: how much work one request buys. That is the right
//! question for a hot path and the wrong question for a stored record, because traffic says nothing
//! about what is still held afterwards. A device grant is created once and then sits in the store
//! for its whole `device_code_ttl`; what it costs is not the allocations that produced it but the
//! bytes it keeps. Nothing in this crate measured that before this file existed.
//!
//! # How it is measured
//!
//! [`support::alloc::Delta::resident`] is `bytes - freed`: allocations made inside the window minus
//! everything handed back, so a window that creates N records and drops every transient buffer on
//! the way reports exactly the N records' own bytes plus whatever the store's index grew by. That
//! is the honest figure, because a `HashMap` bucket table IS resident memory a deployment pays for.
//!
//! Each gate warms the store with one record BEFORE the window (so the constant cost of a map's
//! first table is not charged to the per-record average), then creates [`RECORDS`] more inside it
//! and divides. [`RECORDS`] is large enough that a single bucket-table doubling is a small
//! fraction of the total and small enough that the whole file runs in well under a second.
//!
//! # What the figures do NOT include
//!
//! `layout.size()`, which is what the allocator is asked for, not what the allocator's size class
//! rounds that up to. Real RSS is therefore somewhat higher than every number here. The figures are
//! comparable to each other and to their own history, which is what a gate needs; they are a FLOOR
//! on what a deployment pays, not an estimate of its resident set.
//!
//! # Why this is a separate test binary from `tests/allocation.rs`
//!
//! A `#[global_allocator]` is process-wide and each integration test file is its own binary, so
//! this file gets its own. It follows the same one-`#[test]`-per-binary discipline for the reason
//! that file's module docs give: `std`'s harness starts an OS thread per `#[test]`, and thread
//! creation touches the allocator outside any lock this crate can take.

mod support;

use std::time::{Duration, SystemTime};

use oauth_as::server::UserApproval;
use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, Storage, TokenRequest,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use support::alloc::{measure, CountingAllocator, TEST_LOCK};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

/// How many records each gate creates inside its measured window. See the module docs.
const RECORDS: usize = 512;

/// A plausible mid-size deployment, used only to turn a per-record figure into a sentence a
/// capacity planner can act on. Nothing is asserted about this number itself.
const PLAUSIBLE_DEPLOYMENT: usize = 10_000;

#[test]
fn steady_state_heap_per_stored_record() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let gates: &[(&str, fn())] = &[
        ("device_grant_resident_bytes", device_grant_resident_bytes),
        (
            "authorization_code_resident_bytes",
            authorization_code_resident_bytes,
        ),
        ("access_token_resident_bytes", access_token_resident_bytes),
        ("refresh_token_resident_bytes", refresh_token_resident_bytes),
        (
            "consent_record_resident_bytes",
            consent_record_resident_bytes,
        ),
        (
            "pushed_request_resident_bytes",
            pushed_request_resident_bytes,
        ),
        ("replay_id_resident_bytes", replay_id_resident_bytes),
        ("empty_store_is_free", empty_store_is_free),
    ];

    let mut failures = Vec::new();
    for (name, gate) in gates {
        if let Err(cause) = catch_unwind(AssertUnwindSafe(gate)) {
            let msg = cause
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| cause.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panicked with a non-string payload".to_string());
            failures.push(format!("{name}: {msg}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} footprint gate(s) failed:\n{}",
        failures.len(),
        gates.len(),
        failures.join("\n")
    );
}

// ------------------------------------------------------------------------------------ helpers

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}

fn config() -> ServerConfig {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    // Long enough that nothing created inside a measured window can expire and be swept mid-run,
    // which would make the resident figure depend on how fast the machine is.
    cfg.device_code_ttl = Duration::from_secs(86_400);
    cfg.authorization_code_ttl = Duration::from_secs(86_400);
    cfg.access_token_ttl = Duration::from_secs(86_400);
    cfg
}

fn test_client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "s3cret".to_string(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
        ],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn server(rt: &tokio::runtime::Runtime, cfg: ServerConfig) -> AuthorizationServer<MemoryStorage> {
    rt.block_on(async {
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(test_client()).await.unwrap();
        srv
    })
}

/// Report a per-record figure and check it against `budget`, with the 10k-record consequence in the
/// message so a failure says what it costs rather than only that it changed.
fn check(name: &str, resident: usize, budget: usize) {
    let per = resident / RECORDS;
    assert!(
        per <= budget,
        "{name}: {per} resident bytes per record (budget {budget}); \
         {PLAUSIBLE_DEPLOYMENT} live records would be {} KiB",
        per * PLAUSIBLE_DEPLOYMENT / 1024
    );
    // Printed on a passing run under `--nocapture` so the observed figures in the comments below
    // can be re-derived rather than taken on trust.
    println!(
        "{name}: {per} bytes/record, {} KiB at {PLAUSIBLE_DEPLOYMENT} records",
        per * PLAUSIBLE_DEPLOYMENT / 1024
    );
}

/// A PKCE-verified authorization request for the fixture client, ready to be approved.
fn authorization_request(challenge: &str) -> AuthorizationRequest<'_> {
    AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".into()),
        client_id: Some("app".into()),
        redirect_uri: Some("https://app.example/cb".into()),
        scope: Some("read write".into()),
        state: Some("s".into()),
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    }
}

// -------------------------------------------------------------------------------- the gates

/// One live RFC 8628 device grant: a [`oauth_as::DeviceGrant`] plus its `device_by_code` entry and
/// its `user_code_index` entry, so the device code string is resident TWICE (once as the record's
/// field, once as the map key) and the user code three times.
fn device_grant_resident_bytes() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    // Warm: the first record pays for both maps' first bucket tables.
    rt.block_on(srv.device_authorization(&ClientId::new("app"), Some("s3cret"), None))
        .unwrap();

    let ((), d) = measure(|| {
        rt.block_on(async {
            for _ in 0..RECORDS {
                srv.device_authorization(&ClientId::new("app"), Some("s3cret"), None)
                    .await
                    .unwrap();
            }
        })
    });
    check("device grant", d.resident(), DEVICE_GRANT_BUDGET);
}

/// One live RFC 6749 s4.1 authorization code record, in `Issued` state.
fn authorization_code_resident_bytes() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let issue = || async {
        let req = authorization_request(&challenge);
        let validated = srv.validate_authorization_request(&req).await.unwrap();
        srv.issue_authorization_code(UserApproval::granted(&validated, "user-1"))
            .await
            .unwrap();
    };
    rt.block_on(issue());

    let ((), d) = measure(|| {
        rt.block_on(async {
            for _ in 0..RECORDS {
                issue().await;
            }
        })
    });
    check(
        "authorization code",
        d.resident(),
        AUTHORIZATION_CODE_BUDGET,
    );
}

/// One live access token: an `Arc<IssuedToken>` plus its `tokens` map entry. Minted through
/// `client_credentials`, the one grant that produces an access token and NOTHING else, so the
/// figure is the token's own and not a token plus a refresh chain plus a consumed code.
fn access_token_resident_bytes() {
    let rt = current_thread_runtime();
    let mut cfg = config();
    cfg.issue_refresh_tokens = false;
    let srv = server(&rt, cfg);
    let mint = || async {
        srv.token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: Some("s3cret".to_string()),
            scope: None,
        })
        .await
        .unwrap()
    };
    rt.block_on(mint());

    let ((), d) = measure(|| {
        rt.block_on(async {
            for _ in 0..RECORDS {
                let _ = mint().await;
            }
        })
    });
    check("access token", d.resident(), ACCESS_TOKEN_BUDGET);
}

/// One live refresh chain link, measured by ISOLATING it: the record is handed straight to
/// `Storage::put_refresh_token` rather than minted through a grant, because every grant that mints
/// a refresh token also mints an access token and the two would be indistinguishable in one
/// window. The field values are the sizes the server itself produces (64 hex characters of token,
/// 32 of family id), so this is the real record and not a smaller stand-in.
fn refresh_token_resident_bytes() {
    let rt = current_thread_runtime();
    let store = MemoryStorage::new();
    let record = |n: usize| oauth_as::RefreshTokenRecord {
        refresh_token: format!("{n:064x}"),
        client_id: ClientId::new("app"),
        subject: Some("user-1".to_string()),
        scope: ScopeSet::parse("read write").unwrap(),
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000)),
        #[cfg(feature = "dpop")]
        jkt: None,
        #[cfg(feature = "mtls")]
        x5t_s256: None,
        family_id: format!("{n:032x}"),
        state: oauth_as::RefreshTokenState::Active,
        #[cfg(feature = "consent")]
        authentication: None,
    };
    rt.block_on(store.put_refresh_token(record(0))).unwrap();

    let ((), d) = measure(|| {
        rt.block_on(async {
            for n in 1..=RECORDS {
                store.put_refresh_token(record(n)).await.unwrap();
            }
        })
    });
    check("refresh token", d.resident(), REFRESH_TOKEN_BUDGET);
}

/// One remembered consent record. Unlike every other record here a consent has no TTL: it is
/// resident until the user withdraws it, so this is the one figure a deployment multiplies by its
/// user count rather than by its request rate.
#[cfg(feature = "consent")]
fn consent_record_resident_bytes() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let scope = ScopeSet::parse("read write").unwrap();
    let client_id = ClientId::new("app");
    // One consent per SUBJECT: `record_consent` widens an existing record for the same
    // client/subject pair rather than adding one, so a fixed subject would measure a single
    // record being rewritten and report nearly zero.
    rt.block_on(srv.record_consent(&client_id, "user-0", &scope, &[], None))
        .unwrap();

    let ((), d) = measure(|| {
        rt.block_on(async {
            for n in 1..=RECORDS {
                let subject = format!("user-{n}");
                srv.record_consent(&client_id, &subject, &scope, &[], None)
                    .await
                    .unwrap();
            }
        })
    });
    check("consent record", d.resident(), CONSENT_RECORD_BUDGET);
}

#[cfg(not(feature = "consent"))]
fn consent_record_resident_bytes() {}

/// One live RFC 9126 pushed authorization request, between the push and its single use.
#[cfg(feature = "par")]
fn pushed_request_resident_bytes() {
    let rt = current_thread_runtime();
    let mut cfg = config();
    cfg.par = Some(Box::new(oauth_as::ParConfig::new()));
    let srv = server(&rt, cfg);
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let parameters = [
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read"),
        ("state", "opaque-state"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let push = || async {
        srv.pushed_authorization_request(&ClientId::new("app"), Some("s3cret"), &parameters)
            .await
            .unwrap()
    };
    rt.block_on(push());

    let ((), d) = measure(|| {
        rt.block_on(async {
            for _ in 0..RECORDS {
                let _ = push().await;
            }
        })
    });
    check("pushed request", d.resident(), PUSHED_REQUEST_BUDGET);
}

#[cfg(not(feature = "par"))]
fn pushed_request_resident_bytes() {}

/// One claimed replay identifier (RFC 7523 s3 `jti`, RFC 9449 s11.1 `jti`).
///
/// This is the record an UNAUTHENTICATED-ish caller can grow fastest, so its per-entry cost is the
/// one that decides how much memory a flood of distinct assertions can pin until the next sweep.
/// It is deliberately the cheapest record in the store: a `String` key and a `SystemTime`, with no
/// value struct at all.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
fn replay_id_resident_bytes() {
    let rt = current_thread_runtime();
    let store = MemoryStorage::new();
    let deadline = SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    // The shape `AuthorizationServer::replay_key` produces: "{kind}:{owner}:{jti}".
    let id = |n: usize| format!("assertion:client-app:{n:032x}");
    rt.block_on(store.claim_replay_id(&id(0), deadline))
        .unwrap();

    let ((), d) = measure(|| {
        rt.block_on(async {
            for n in 1..=RECORDS {
                store.claim_replay_id(&id(n), deadline).await.unwrap();
            }
        })
    });
    check("replay id", d.resident(), REPLAY_ID_BUDGET);
}

#[cfg(not(any(feature = "client_assertion", feature = "dpop")))]
fn replay_id_resident_bytes() {}

/// The crate doc's "nothing is allocated until the host constructs an `AuthorizationServer`" claim,
/// checked at the STORE: an empty [`MemoryStorage`] must hold no heap at all. `HashMap::new` does
/// not allocate until the first insert, and this is what pins that a future field cannot quietly
/// change it.
fn empty_store_is_free() {
    let (store, d) = measure(MemoryStorage::new);
    assert_eq!(
        d.resident(),
        0,
        "an empty MemoryStorage must hold no heap: {d:?}"
    );
    drop(store);
}

// ------------------------------------------------------------------------------- the budgets
//
// OBSERVED figures are recorded beside each budget so a failing run can be compared against what
// this file was written against, rather than against a number with no provenance.
//
// Every figure below is DETERMINISTIC: each record's strings are fixed-length hex minted from the
// same entropy budget on every run, and `RECORDS` is a constant, so the same feature set produces
// the same byte count every time (verified by repeated runs). The margin is therefore roughly 12
// percent and not the 25 an averaged measurement would need. That is deliberately tight enough
// that ONE new `String` field on a stored record fails the gate.
//
// A feature's cost is stated ADDITIVELY, exactly as `tests/allocation.rs` does for the size gate
// and for the same reason: a deployment that does not enable a feature must not be charged for it,
// and a budget widened to the all-features shape would silently absorb a new default-build field.
//
// Note what a `#[cfg]` field costs depends on HOW the record is stored:
//
// - `DeviceGrant`, `AuthorizationCodeRecord` and `PushedAuthorizationRequest` are stored BY VALUE
//   in their `HashMap`, so a new field is paid TWICE: once in the record and once in the bucket
//   table's value slot. Measured: `rar` plus `consent` add 32 bytes of struct to
//   `AuthorizationCodeRecord` and 64 bytes of resident heap.
// - `IssuedToken`, `RefreshTokenRecord` and `ConsentRecord` are stored behind an `Arc`, so the map
//   holds an 8-byte pointer and a new field is paid ONCE. Measured: the same four optional fields
//   add 56 bytes of struct to `IssuedToken` and 56 bytes of resident heap.
//
// That difference is itself worth knowing, and it is the argument for `Arc` in the store beyond
// the read-path allocation saving it was introduced for.

/// Observed 1009 on EVERY feature set: `DeviceGrant` has no `#[cfg]` field.
const DEVICE_GRANT_BUDGET: usize = 1128;

/// Observed 1002 default, 1066 all-features. Stored by value, so each optional field counts twice:
/// `rar`'s `AuthorizationDetails` (a `Vec`, 24) and `consent`'s `Option<Box<Authentication>>` (8).
const AUTHORIZATION_CODE_BUDGET: usize = 1120
    + if cfg!(feature = "rar") { 48 } else { 0 }
    + if cfg!(feature = "consent") { 16 } else { 0 };

/// Observed 672 default, 728 all-features. Stored behind an `Arc`, so each optional field counts
/// once: `rar` 24, `dpop`'s `Option<Box<str>>` 16, `mtls`'s `Option<Box<CertificateThumbprint>>` 8,
/// `consent` 8.
const ACCESS_TOKEN_BUDGET: usize = 752
    + if cfg!(feature = "rar") { 24 } else { 0 }
    + if cfg!(feature = "dpop") { 16 } else { 0 }
    + if cfg!(feature = "mtls") { 8 } else { 0 }
    + if cfg!(feature = "consent") { 8 } else { 0 };

/// Observed 707 default, 763 all-features. The same four optional fields as `IssuedToken`, in the
/// same shapes, and stored behind an `Arc` the same way.
const REFRESH_TOKEN_BUDGET: usize = 792
    + if cfg!(feature = "rar") { 24 } else { 0 }
    + if cfg!(feature = "dpop") { 16 } else { 0 }
    + if cfg!(feature = "mtls") { 8 } else { 0 }
    + if cfg!(feature = "consent") { 8 } else { 0 };

/// Observed 573. `ConsentRecord` has no `#[cfg]` field of its own (the whole module is behind
/// `consent`), so this is one number and not a sum.
const CONSENT_RECORD_BUDGET: usize = 640;

/// Observed 943 with `rar` and `consent` also on, which is the record's WIDEST shape: it is stored
/// by value, and `rar` and `consent` add one `Option<String>` each (24 bytes of struct, 48 of
/// resident heap apiece). With `par` alone the record is smaller and this bound is loose, which is
/// the correct direction for an upper bound.
const PUSHED_REQUEST_BUDGET: usize = 1056;

/// Observed 134, and it is the cheapest record in the store by a factor of five: a `String` key and
/// a `SystemTime`, with no value struct at all. It is also the only one an attacker can grow
/// without holding a grant, which is why it is worth pinning even though it is small.
const REPLAY_ID_BUDGET: usize = 152;
