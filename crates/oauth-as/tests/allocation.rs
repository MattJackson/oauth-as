// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Efficiency gates for the crate doc's "Zero cost until enabled" promise
//! (`crates/oauth-as/src/lib.rs`): "a host that compiles this crate in but never turns it on must
//! pay nothing at runtime. There are NO global statics, NO lazy singletons, NO background tasks,
//! and no allocation at load time. The only allocation entry point is
//! `AuthorizationServer::new`." That is a claim about the SOURCE (no static/lazy-singleton
//! machinery to allocate behind the host's back) and a claim about COST (the operations the host
//! actually calls do not allocate more than their own output requires). This file checks both:
//!
//! - [`no_global_statics_or_lazy_singletons_in_the_library_source`] reads the library's own
//!   top-level source files and structurally rejects a `static` item or a lazy-init dependency,
//!   rather than trusting the doc comment.
//! - The remaining gates use [`support::alloc`], a hand-rolled counting allocator (no new
//!   dependency: it wraps [`std::alloc::System`]), to pin an UPPER BOUND on allocator traffic for
//!   the crate's hot paths and pure functions, and an exact zero for the `Cow`-borrowing claim on
//!   [`oauth_as::AuthorizationRequest`].
//!
//! # Why these are upper bounds, not exact counts
//!
//! `MemoryStorage`'s maps are ordinary `std::collections::HashMap`s: their bucket-table growth
//! points are not part of this crate's public contract, so pinning an exact allocation count would
//! make the gate brittle against a `HashMap` implementation detail rather than against this
//! crate's own logic. An upper bound with a stated margin still fails the moment somebody adds an
//! unnecessary clone or a needless intermediate `String`, which is the regression this file exists
//! to catch.
//!
//! # Why this file is ONE `#[test]`, not several
//!
//! A `#[global_allocator]` is process-wide. `std`'s test harness starts one OS thread per `#[test]`
//! up front (by default up to `--test-threads` of them at once), and thread creation itself can
//! touch the allocator on some platforms (stack bookkeeping, TLS), outside anything this crate's
//! own code can lock. In development this file DID use one `#[test]` per gate, each holding
//! [`support::alloc::TEST_LOCK`] for its whole body, and it was still flaky under `cargo test`'s
//! default parallelism: a gate several tests away, doing nothing but starting up, could add a
//! handful of stray allocations to a neighbor's measurement window. Collapsing to a single
//! `#[test]` removes the harness's own concurrency from the picture; each gate below is a plain
//! function, run in sequence, with failures collected and reported together at the end so one run
//! still shows every gate that regressed, not just the first.

mod support;

use oauth_as::server::UserApproval;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, AuthorizationServerMetadata, Client, ClientAuth,
    ClientId, ErrorResponse, GrantType, IssuedToken, MemoryStorage, ScopeSet, ServerConfig,
    TokenRequest,
};
use support::alloc::{measure, CountingAllocator, Delta, TEST_LOCK};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

/// Run every gate, in sequence, on this one test's thread; collect failures instead of stopping at
/// the first one, so a single `cargo test` run reports the full list of what regressed.
#[test]
fn zero_cost_efficiency_gates() {
    // Defense in depth per the module doc: harmless here since this is the only #[test] in the
    // binary, but it keeps the requirement documented at the call site too.
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let gates: &[(&str, fn())] = &[
        (
            "no_global_statics_or_lazy_singletons_in_the_library_source",
            no_global_statics_or_lazy_singletons_in_the_library_source,
        ),
        (
            "no_lazy_init_dependency_is_declared",
            no_lazy_init_dependency_is_declared,
        ),
        (
            "code_challenge_s256_allocates_only_its_return_value",
            code_challenge_s256_allocates_only_its_return_value,
        ),
        (
            "scope_set_parse_is_linear_in_token_count",
            scope_set_parse_is_linear_in_token_count,
        ),
        (
            "metadata_derivation_allocates_a_bounded_small_amount",
            metadata_derivation_allocates_a_bounded_small_amount,
        ),
        (
            "authorization_request_from_borrowed_pairs_allocates_nothing",
            authorization_request_from_borrowed_pairs_allocates_nothing,
        ),
        (
            "authorization_response_location_allocates_exactly_once_at_the_exact_size",
            authorization_response_location_allocates_exactly_once_at_the_exact_size,
        ),
        (
            "device_authorization_hot_path_allocation_bound",
            device_authorization_hot_path_allocation_bound,
        ),
        (
            "device_token_pending_poll_hot_path_allocation_bound",
            device_token_pending_poll_hot_path_allocation_bound,
        ),
        (
            "authorization_code_redemption_hot_path_allocation_bound",
            authorization_code_redemption_hot_path_allocation_bound,
        ),
        (
            "refresh_rotation_hot_path_allocation_bound",
            refresh_rotation_hot_path_allocation_bound,
        ),
        (
            "introspection_hot_path_allocation_bound",
            introspection_hot_path_allocation_bound,
        ),
        (
            "a_refusal_built_from_a_literal_allocates_nothing",
            a_refusal_built_from_a_literal_allocates_nothing,
        ),
        (
            "refused_token_request_allocation_bound",
            refused_token_request_allocation_bound,
        ),
        (
            "metadata_serialization_allocation_bound",
            metadata_serialization_allocation_bound,
        ),
        (
            "core_public_types_stay_within_their_size_budget",
            core_public_types_stay_within_their_size_budget,
        ),
        (
            "token_future_stays_under_tokios_debug_boxing_threshold",
            token_future_stays_under_tokios_debug_boxing_threshold,
        ),
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
        "{} of {} efficiency gate(s) failed:\n{}",
        failures.len(),
        gates.len(),
        failures.join("\n")
    );
}

// ------------------------------------------------------------------- structural: no statics

/// Read every top-level file in `src/` (NOT the `src/tests/` tree, which is `#[cfg(test)]`-only
/// and never ships) and assert none declares a module-level `static` item.
///
/// This is deliberately a text scan rather than a `syn`-based parse: the crate's dependency policy
/// is "deliberately tiny" and this test earns its keep precisely by adding nothing to that set. A
/// line is flagged when, after trimming leading whitespace and an optional `pub`/`pub(crate)`
/// prefix, it begins with `static `. That excludes `&'static str` (the lifetime is glued to the
/// preceding `'` with no space of its own before `static`, so it never starts a trimmed line) and
/// excludes prose like "NO global statics" (no line starts with the literal word `static `).
fn no_global_statics_or_lazy_singletons_in_the_library_source() {
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut offending = Vec::new();
    for entry in std::fs::read_dir(src_dir).expect("crate src/ must exist") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (lineno, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let trimmed = trimmed
                .strip_prefix("pub(crate)")
                .or_else(|| trimmed.strip_prefix("pub"))
                .unwrap_or(trimmed)
                .trim_start();
            if trimmed.starts_with("static ") {
                offending.push(format!("{}:{}: {line}", path.display(), lineno + 1));
            }
        }
    }
    assert!(
        offending.is_empty(),
        "the crate doc promises NO global statics and NO lazy singletons; found:\n{}",
        offending.join("\n")
    );
}

/// Lazy-init crates (`lazy_static`, `once_cell`) are the usual way a "pure" library smuggles in a
/// hidden allocation at first use. The dependency policy in `Cargo.toml` already forbids them; this
/// pins that as a check rather than a policy nobody re-reads. `std::sync::OnceLock` is std, not a
/// dependency, and is excluded from this particular check (there are none in the source today; the
/// static scan above would catch one if it appeared as a module-level item).
fn no_lazy_init_dependency_is_declared() {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let text = std::fs::read_to_string(manifest).unwrap();
    for forbidden in ["lazy_static", "once_cell"] {
        assert!(
            !text.contains(forbidden),
            "found a dependency on {forbidden}, which exists to build lazy singletons"
        );
    }
}

// ------------------------------------------------------------------------- pure functions

/// `code_challenge_s256` is SHA-256 into a fixed 32-byte array followed by one base64url encode.
/// The only thing it can legitimately allocate is the 43-byte `String` it returns; anything more
/// means an intermediate buffer got introduced.
fn code_challenge_s256_allocates_only_its_return_value() {
    let (challenge, d) = measure(|| oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER));
    assert_eq!(challenge.len(), 43);
    assert!(
        d.allocs <= 2,
        "code_challenge_s256 should allocate at most its own 43-byte String, got {d:?}"
    );
    assert!(
        d.bytes <= 128,
        "unexpectedly large allocation traffic: {d:?}"
    );
}

/// `ScopeSet::parse` on a borrowed `&str` cannot avoid allocating: `Scope` wraps an owned `String`
/// per RFC 6749 section 3.3 token, and the crate's own [`crate::client::Client`] fixtures store
/// `ScopeSet`, not a borrowed view, so this is a genuine cost, not something a `Cow` could remove.
/// What this test pins is that the cost stays LINEAR in token count with a small constant, not
/// something worse hiding in `BTreeSet` bookkeeping.
fn scope_set_parse_is_linear_in_token_count() {
    let (set, d) = measure(|| ScopeSet::parse("read write admin").unwrap());
    assert_eq!(set.len(), 3);
    // Observed: 1 String allocation per token plus a small constant for BTreeSet's own node(s).
    // Bound is 2 allocations per token plus 4, which comfortably covers today's 4-for-3-tokens
    // while still catching an accidental extra clone per token.
    assert!(
        d.allocs <= 3 * 2 + 4,
        "ScopeSet::parse(3 tokens) should stay near linear in token count, got {d:?}"
    );
}

/// `AuthorizationServerMetadata::from_config` builds roughly a dozen owned `String`s and a handful
/// of small `Vec<String>`s (RFC 8414's `*_supported` arrays); the whole document is a page of JSON,
/// not something a real host serves at request rate uncached, but it should still be a fixed,
/// small number of allocations rather than growing with anything unbounded.
fn metadata_derivation_allocates_a_bounded_small_amount() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let (_doc, d) = measure(|| AuthorizationServerMetadata::from_config(&cfg));
    // Observed 26: 5 derived endpoint Strings, the issuer String, and 6 `*_supported` Vecs whose
    // elements are themselves Strings (1 + 1 + 4 + 3 + 1 = 10 elements, each a Vec alloc plus a
    // String alloc). Bound doubles that with headroom for a future field.
    assert!(
        d.allocs <= 60,
        "metadata derivation should stay a small fixed cost, got {d:?}"
    );
}

// --------------------------------------------------------------------------- Cow borrowing

/// [`AuthorizationRequest`] holds `Cow<str>` fields specifically so a host parsing a query string
/// with no percent-escapes can borrow straight from the request buffer (see the module doc on
/// `authorization.rs`, "Why the request type is lenient" / "Allocation"). Building one from
/// borrowed `&str` pairs must therefore allocate NOTHING: this is the one gate in this file with
/// zero margin, because zero is the actual claim being made, not an approximation of it.
fn authorization_request_from_borrowed_pairs_allocates_nothing() {
    let pairs = [
        ("response_type", "code"),
        ("client_id", "public-app"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read write"),
        ("state", "opaque-state"),
        (
            "code_challenge",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ),
        ("code_challenge_method", "S256"),
    ];
    let (req, d) = measure(|| AuthorizationRequest::from_pairs(pairs));
    assert_eq!(req.client_id.as_deref(), Some("public-app"));
    assert_eq!(
        d,
        Delta {
            allocs: 0,
            deallocs: 0,
            bytes: 0
        },
        "AuthorizationRequest::from_pairs on borrowed &str must not allocate at all, got {d:?}"
    );
}

/// `AuthorizationResponse::location` sizes its output buffer from
/// `AuthorizationResponse::encoded_len`, a private worst-case estimate whose whole job is to make
/// the function allocate EXACTLY once (see its doc comment). That estimate is otherwise invisible:
/// a wrong one still produces the correct string, because `String` simply reallocates. Allocator
/// traffic is the only observation that can tell a right estimate from a wrong one, which is
/// exactly what this counting allocator exists for.
///
/// The inputs below are chosen so the estimate is EXACT rather than merely sufficient: every byte
/// of both the code and the state is outside the RFC 3986 unreserved set, so each expands to three
/// characters, which is the `len * 3` the estimate assumes. With an exact estimate:
///
/// - an UNDER-estimate (a smaller constant, a dropped term, `* 3` weakened to `+ 3` or `/ 3`)
///   makes the single `with_capacity` too small and `String` reallocates, raising `allocs`;
/// - an OVER-estimate (a term multiplied instead of added) still allocates once but asks the
///   allocator for more bytes than the string can ever need, raising `bytes`.
///
/// Pinning both to their exact values therefore constrains the estimate in both directions.
fn authorization_response_location_allocates_exactly_once_at_the_exact_size() {
    // 4 characters, none of them unreserved, so the encoded form is 12 characters.
    let code = "&=#?";
    // 3 characters, likewise, so the encoded form is 9 characters.
    let state = " /+";
    // Not a realistic issuer identifier, and deliberately so: RFC 9207 s2 puts `iss` on every
    // authorization response, and this gate needs EVERY byte of every value to expand to three
    // characters or the worst-case estimate stops being exact and the `bytes` assertion below
    // stops constraining it in the over-estimate direction. A real `https://...` issuer is mostly
    // unreserved characters; the length arithmetic is identical either way.
    let iss = "^|`";
    let redirect_uri = "https://app.example/cb";

    let response = oauth_as::AuthorizationResponse {
        code: code.to_string(),
        state: Some(state.to_string()),
        iss: iss.to_string(),
    };
    let (location, d) = measure(|| response.location(redirect_uri));

    // "?code=" is 6 characters, "&state=" is 7, "&iss=" is 5: exactly the three constants the
    // estimate carries.
    let exact_len =
        redirect_uri.len() + 6 + code.len() * 3 + 7 + state.len() * 3 + 5 + iss.len() * 3;
    assert_eq!(
        location.len(),
        exact_len,
        "test setup: every input byte must percent-encode to three characters, got {location}"
    );
    assert_eq!(
        d,
        Delta {
            allocs: 1,
            deallocs: 0,
            bytes: exact_len
        },
        "location() must allocate its buffer once, at exactly the size the output needs: {d:?}"
    );
}

// ------------------------------------------------------------------------------ hot paths
//
// Every hot-path gate builds its server and warms the store BEFORE the measured window, then
// measures exactly one call. A `tokio::runtime::Builder::new_current_thread()` runtime is built
// outside the window too: building it is a one-time host cost (like `AuthorizationServer::new`
// itself), not part of the per-request path this file is pinning. `new_current_thread` is used
// throughout (never `rt-multi-thread`) specifically so no extra OS thread is alive while a window
// is being measured.

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}

fn device_test_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// RFC 8628 section 3.1: one device-authorization request against a warm store (one client
/// already registered). Dominated by two fresh high-entropy strings (`device_code`, `user_code`,
/// each hex- or alphabet-encoded from 32 bytes / configured length of OS randomness), each cloned
/// once more into the persisted [`oauth_as::DeviceGrant`] and once more into the two `MemoryStorage`
/// indexes (`device_by_code`, `user_code_index`), plus the `verification_uri_complete` `format!`.
fn device_authorization_hot_path_allocation_bound() {
    let rt = current_thread_runtime();
    let srv = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(device_test_client()).await.unwrap();
        srv
    });

    let (auth, d) = measure(|| {
        rt.block_on(srv.device_authorization(&ClientId::new("device-client"), None, None))
    });
    let auth = auth.unwrap();
    assert!(!auth.device_code.is_empty());
    // Observed 19 allocs / 1795 bytes on a warm single-client store, on every feature set.
    // It was 26 / 2383 through 0.9.0: `Storage::get_client` returning an owned `Client` deep
    // copied the registration on every authenticated call, and returning `Arc<Client>` took
    // SEVEN allocations off this path (this fixture's client has no redirect URIs and no name;
    // a fuller registration saved more).
    //
    // Bound leaves roughly 35% margin over the observed count so ordinary HashMap growth jitter
    // cannot make this flaky, while still catching, say, an accidental second random_hex draw or
    // a reintroduced full-Client clone.
    assert!(
        d.allocs <= 26,
        "device_authorization allocation count regressed: {d:?}"
    );
    assert!(
        d.bytes <= 2560,
        "device_authorization allocation bytes regressed: {d:?}"
    );
}

/// RFC 8628 section 3.5: one poll that lands on `authorization_pending` (the grant exists, is
/// unexpired, is not yet approved). This is the CHEAPEST call on the token plane, which is what
/// makes it the honest place to see what a request pays before it does any work of its own.
///
/// What is left after the `Arc<Client>` read is `get_device_grant`/`put_device_grant`, which still
/// clone a full owned record (device code, user code, scope) out of and back into the mutexed map.
/// That one is DELIBERATELY not an `Arc` read: the poll MUTATES what it read (`last_poll_at`, and
/// `interval` on a too-fast poll) and writes it back, so an `Arc` would force the clone at the
/// mutation instead of at the read and then add one more allocation to re-wrap it. Measured, not
/// assumed: `get_device_grant` costs 5 allocations, `DeviceGrant::clone` costs the same 5, and
/// `Arc::new` of that clone costs 6. Moving a cost is not removing it.
fn device_token_pending_poll_hot_path_allocation_bound() {
    let rt = current_thread_runtime();
    let (srv, device_code) = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(device_test_client()).await.unwrap();
        let auth = srv
            .device_authorization(&ClientId::new("device-client"), None, None)
            .await
            .unwrap();
        (srv, auth.device_code)
    });

    let (result, d) = measure(|| {
        rt.block_on(srv.token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            device_code: device_code.clone(),
        }))
    });
    assert_eq!(
        result.unwrap_err().error,
        oauth_as::ErrorCode::AuthorizationPending
    );
    // Observed 11 allocs / 591 bytes on default features, 12 / 759 with every feature on. It was
    // 18 / 1179 (19 all-features) through 0.9.0, and `get_client` alone was 7 of them.
    assert!(
        d.allocs <= 17,
        "device_token(authorization_pending) allocation count regressed: {d:?}"
    );
    assert!(
        d.bytes <= 1280,
        "device_token(authorization_pending) allocation bytes regressed: {d:?}"
    );
}

fn code_test_client() -> Client {
    Client {
        client_id: ClientId::new("public-app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// RFC 6749 section 4.1.3 with RFC 7636 verification: redeeming a live authorization code.
/// Dominated by the atomic `take` returning an owned `AuthorizationCodeRecord`, `issue()` minting
/// TWO fresh 32-byte random strings (access token, refresh token) and persisting both, and the
/// code being put back in `Consumed` state (which clones the freshly minted access/refresh token
/// strings a second time to record them). `authenticate_client` no longer clones the `Client`.
fn authorization_code_redemption_hot_path_allocation_bound() {
    let rt = current_thread_runtime();
    let verifier = support::RFC7636_VERIFIER;
    let (srv, code) = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(code_test_client()).await.unwrap();
        let challenge = oauth_as::pkce::code_challenge_s256(verifier);
        let req = AuthorizationRequest {
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: Default::default(),
            response_type: Some("code".into()),
            client_id: Some("public-app".into()),
            redirect_uri: Some("https://app.example/cb".into()),
            scope: Some("read write".into()),
            state: Some("s".into()),
            code_challenge: Some(challenge.into()),
            code_challenge_method: Some("S256".into()),
            #[cfg(feature = "consent")]
            acr_values: None,
            #[cfg(feature = "consent")]
            max_age: None,
        };
        let validated = srv.validate_authorization_request(&req).await.unwrap();
        let response = srv
            .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
            .await
            .unwrap();
        (srv, response.code)
    });

    let (token, d) = measure(|| {
        rt.block_on(srv.token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: code.clone(),
            redirect_uri: Some("https://app.example/cb".to_string()),
            code_verifier: Some(verifier.to_string()),
        }))
    });
    let token = token.unwrap();
    assert!(token.refresh_token.is_some());
    // Observed 39 allocs / 3041 bytes on default features, 40 / 3417 with every feature on. It
    // was 46 / 4608 (47 all-features) through 0.9.0.
    //
    // The net is nine fewer, and it is a NET rather than a straight subtraction: the `Arc<Client>`
    // read took nine off, and `put_token` plus `put_refresh_token` each added ONE back, because
    // `MemoryStorage` now wraps the record it is handed. That is the deliberate side of the trade
    // recorded on `introspection_hot_path_allocation_bound`: one allocation on the write, seven
    // off every read of the same record afterwards, and with opaque tokens (this crate's default)
    // a token is read far more often than it is issued.
    assert!(
        d.allocs <= 52,
        "authorization_code redemption allocation count regressed: {d:?}"
    );
    assert!(
        d.bytes <= 4608,
        "authorization_code redemption allocation bytes regressed: {d:?}"
    );
}

/// RFC 6749 section 6 with OAuth 2.1 single-use rotation. Dominated the same way as code
/// redemption: the atomic `take` of the old refresh record, minting a fresh access token AND a
/// fresh rotated refresh token, and persisting both plus the SPENT record that makes reuse
/// detectable. Those three writes are why this path pays three of `MemoryStorage`'s new `Arc`
/// wraps where redemption pays two.
fn refresh_rotation_hot_path_allocation_bound() {
    let rt = current_thread_runtime();
    let verifier = support::RFC7636_VERIFIER;
    let (srv, refresh_token) = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(code_test_client()).await.unwrap();
        let challenge = oauth_as::pkce::code_challenge_s256(verifier);
        let req = AuthorizationRequest {
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: Default::default(),
            response_type: Some("code".into()),
            client_id: Some("public-app".into()),
            redirect_uri: Some("https://app.example/cb".into()),
            scope: Some("read write".into()),
            state: Some("s".into()),
            code_challenge: Some(challenge.into()),
            code_challenge_method: Some("S256".into()),
            #[cfg(feature = "consent")]
            acr_values: None,
            #[cfg(feature = "consent")]
            max_age: None,
        };
        let validated = srv.validate_authorization_request(&req).await.unwrap();
        let response = srv
            .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
            .await
            .unwrap();
        let token = srv
            .token(TokenRequest::AuthorizationCode {
                client_id: ClientId::new("public-app"),
                client_secret: None,
                code: response.code,
                redirect_uri: Some("https://app.example/cb".to_string()),
                code_verifier: Some(verifier.to_string()),
            })
            .await
            .unwrap();
        (srv, token.refresh_token.unwrap())
    });

    let (result, d) = measure(|| {
        rt.block_on(srv.token(TokenRequest::RefreshToken {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            refresh_token: refresh_token.clone(),
            scope: None,
        }))
    });
    let result = result.unwrap();
    assert!(result.refresh_token.is_some());
    // Observed 33 allocs / 2725 bytes on default features, 34 / 3157 with every feature on. It
    // was 39 / 2796 (40 all-features) through 0.9.0.
    assert!(
        d.allocs <= 44,
        "refresh rotation allocation count regressed: {d:?}"
    );
    assert!(
        d.bytes <= 3840,
        "refresh rotation allocation bytes regressed: {d:?}"
    );
}

fn confidential_test_client() -> Client {
    Client {
        client_id: ClientId::new("confidential-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "s3cret".to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// RFC 7662 introspection of a live access token by its owner.
///
/// This gate exists because introspection is the read that DECIDES whether `Storage::get_token`
/// should hand back an `Arc`. With opaque tokens, which are this crate's default, a resource
/// server introspects on every protected request it serves, so this path runs far more often than
/// issuance does; `get_token` returning an owned [`IssuedToken`] cost 7 allocations per call
/// (measured in isolation against `MemoryStorage`) purely to copy a record nobody was going to
/// modify. That is the whole of what the `Arc` removes here, and the one allocation it adds back
/// on `put_token` is charged to the redemption and rotation gates above, where it is visible.
fn introspection_hot_path_allocation_bound() {
    let rt = current_thread_runtime();
    let (srv, token) = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(confidential_test_client())
            .await
            .unwrap();
        let issued = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some("s3cret".to_string()),
                scope: None,
            })
            .await
            .unwrap();
        (srv, issued.access_token)
    });

    let (response, d) = measure(|| {
        rt.block_on(srv.introspection_response(
            &ClientId::new("confidential-app"),
            Some("s3cret"),
            &token,
        ))
    });
    assert!(response.unwrap().active, "the token must introspect active");
    // Observed 4 allocs / 58 bytes, on every feature set: the RFC 7662 response document's own
    // owned strings, and NOTHING for either record read, since `get_client` and `get_token` are
    // both pointer clones now. It was 18 before them: the same four, plus 7 for the `Client` deep
    // copy and 7 for the `IssuedToken` deep copy, both measured in isolation against
    // `MemoryStorage`.
    assert!(
        d.allocs <= 8,
        "introspection allocation count regressed: {d:?}"
    );
    assert!(
        d.bytes <= 256,
        "introspection allocation bytes regressed: {d:?}"
    );
}

/// [`ErrorResponse::with_description`] on a `&'static str` must allocate NOTHING.
///
/// This is the zero-margin gate of the two below it, and the claim is exact rather than
/// approximate: `error_description` is a `Cow<'static, str>`, so a refusal whose description is a
/// string constant borrows the constant. Roughly 50 of this crate's 57 description sites pass a
/// literal, and a refusal is a request an ATTACKER sets the rate of, so an allocation here is one
/// an unauthenticated caller can ask for as fast as it can open sockets.
fn a_refusal_built_from_a_literal_allocates_nothing() {
    let (err, d) = measure(|| {
        ErrorResponse::new(oauth_as::ErrorCode::InvalidRequest)
            .with_description("this server does not offer pushed authorization requests")
    });
    assert!(err.error_description.is_some());
    assert_eq!(
        d,
        Delta::default(),
        "a refusal described by a string constant must not copy it onto the heap: {d:?}"
    );
}

/// One REFUSED token request, end to end: a public client asking for `client_credentials`, which
/// RFC 6749 section 4.4 has no answer for because there is no way to authenticate the caller.
///
/// Refusals are gated separately from the success paths for a reason the success paths do not
/// have: an attacker chooses how many refusals this server issues, and chooses nothing about how
/// many tokens it mints. A refusal that allocates is therefore work bought by whoever is attacking,
/// which is the one place in the crate where "it is only one allocation" is the wrong sentence.
fn refused_token_request_allocation_bound() {
    let rt = current_thread_runtime();
    let srv = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        // Registered for the grant, so the refusal is the RFC 6749 s4.4 confidentiality rule and
        // not an earlier and cheaper "this client may not use this grant".
        srv.register_client(Client {
            client_id: ClientId::new("public-app"),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read write").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
        srv
    });

    // Built OUTSIDE the window: `ClientId::new` owns its string, and that allocation is the
    // caller's, not the endpoint's. Measuring it would hide the number this gate is about.
    let request = TokenRequest::ClientCredentials {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        scope: None,
    };
    let (result, d) = measure(|| rt.block_on(srv.token(request)));
    assert_eq!(
        result.unwrap_err().error,
        oauth_as::ErrorCode::InvalidClient
    );
    // ZERO on every feature set but one. It was 1 allocation of 49 bytes before
    // `error_description` became a `Cow<'static, str>`: the whole of it was copying the string
    // constant "client_credentials requires a confidential client" onto the heap so it could be
    // owned by a response about to be serialized and dropped.
    //
    // `dpop` is the exception, and the allocation is NOT the description. `token_with_context`
    // reaches the RFC 9449 proof check through a `Box::pin` (168 bytes, measured), which is what
    // keeps the token future under tokio's debug boxing threshold, and it is paid on every token
    // request under that feature whether or not a proof was presented. It is called out here
    // rather than budgeted silently: this is a REFUSAL gate, so a reader has to be able to tell
    // an allocation the crate chose from one an attacker bought.
    let dpop_boxed_proof_check = usize::from(cfg!(feature = "dpop"));
    assert_eq!(
        d.allocs, dpop_boxed_proof_check,
        "a refused token request must allocate NOTHING beyond the dpop proof check: {d:?}"
    );

    // `deallocs` is deliberately not asserted: the `ClientId` the request was built with is moved
    // in and dropped here, and freeing memory the caller allocated is not the endpoint's cost.
}

/// The RFC 8414 discovery document is fetched once by any client that has not cached it, so its
/// serialization cost is not on a hot request path the way token issuance is, but the crate still
/// makes a wire-shape promise about it and the serializer's own buffer growth is worth pinning so
/// nobody adds an accidental double-serialize.
fn metadata_serialization_allocation_bound() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let doc = AuthorizationServerMetadata::from_config(&cfg);
    let (json, d) = measure(|| serde_json::to_string(&doc).unwrap());
    assert!(json.contains("\"issuer\""));
    // Observed 4 allocs / 1920 bytes: serde_json's internal String buffer growing a handful of
    // times as it writes the document. Bound leaves room for one more growth step.
    assert!(
        d.allocs <= 8,
        "metadata serialization allocation count regressed: {d:?}"
    );
}

// ------------------------------------------------------------------------------- size gate

/// `std::mem::size_of` for the crate's core public types, so a casually added `String` field on a
/// hot enum (every `TokenRequest` variant, every `ErrorResponse`) fails CI instead of quietly
/// inflating every value the host copies or stores. Bounds are set with roughly 25-30% headroom
/// over what is measured today on this target, which is enough for pointer-width or field-ordering
/// differences across platforms but not enough to hide a new heap-owning field for free.
fn core_public_types_stay_within_their_size_budget() {
    // AuthorizationServer<MemoryStorage> is ServerConfig + MemoryStorage + SystemClock; MemoryStorage
    // is a single Mutex<MemoryInner> of 6 empty-capacity HashMaps (3 words each: ptr, len, cap-ish
    // RandomState overhead), so the server's size tracks ServerConfig's almost directly.
    //
    // The budget is stated PER FEATURE SET rather than loosened to the widest build, because the
    // promise this gate makes is "a consumer who does not enable a feature pays nothing for it".
    // A default build is unchanged by anything below; each optional feature declares exactly what
    // it costs, so a field added without a matching line here still fails.
    //
    // RFC 9126: `Option<Box<ParConfig>>` on ServerConfig (8) plus one HashMap of pushed requests
    // inside MemoryStorage's MemoryInner (48).
    #[cfg(feature = "par")]
    const PAR: usize = 8 + 48;
    #[cfg(not(feature = "par"))]
    const PAR: usize = 0;
    // RFC 9101: `Option<Box<JarConfig>>` on ServerConfig, and no storage of its own.
    #[cfg(feature = "jar")]
    const JAR: usize = 8;
    #[cfg(not(feature = "jar"))]
    const JAR: usize = 0;
    // `rar` adds ServerConfig::authorization_details_types_supported, the RFC 9396 s10
    // catalogue: an Option<Vec<String>>, three words.
    #[cfg(feature = "rar")]
    const RAR: usize = 24;
    #[cfg(not(feature = "rar"))]
    const RAR: usize = 0;
    let server_budget = 832 + PAR + JAR + RAR;
    assert!(
        size_of::<AuthorizationServer<MemoryStorage>>() <= server_budget,
        "AuthorizationServer<MemoryStorage> grew past its size budget: {}",
        size_of::<AuthorizationServer<MemoryStorage>>()
    );
    // ServerConfig carries ~9 String/Option<String> endpoint fields plus Option<Vec<String>> and
    // several Duration/bool/usize fields (RFC-shaped defaults, all host-overridable).
    assert!(
        size_of::<ServerConfig>() <= 448 + RAR,
        "ServerConfig grew past its size budget: {}",
        size_of::<ServerConfig>()
    );
    // TokenRequest is an enum over 4 grant shapes; its size is its LARGEST variant
    // (AuthorizationCode: client_id, 2 Option<String>, String, Option<String>) plus a discriminant.
    assert!(
        size_of::<TokenRequest>() <= 160,
        "TokenRequest grew past its size budget: {}",
        size_of::<TokenRequest>()
    );
    // ErrorResponse is an ErrorCode (a fieldless enum, one byte's worth of information padded to
    // its alignment) plus two Option<String>.
    assert!(
        size_of::<ErrorResponse>() <= 80,
        "ErrorResponse grew past its size budget: {}",
        size_of::<ErrorResponse>()
    );
    // IssuedToken carries the opaque token string, a ClientId, an Option<String> subject, a
    // ScopeSet (a BTreeSet, 1 pointer-ish word), and two SystemTime instants.
    //
    // Each optional sender-constraining mechanism adds ONE field, and each is budgeted
    // SEPARATELY and ADDITIVELY rather than by raising a single number: a deployment that
    // enables neither must not be made to pay for either, and one that enables one must
    // not be made to pay for the other.
    //
    // `dpop`: the RFC 9449 s6 key binding, an `Option<Box<str>>`, 16 bytes, because `str`
    // is unsized and the pointer to it is fat.
    // `mtls`: the RFC 8705 s3 certificate binding, an `Option<Box<CertificateThumbprint>>`,
    // 8 bytes, because a thumbprint is a fixed `[u8; 32]` and the pointer to it is thin.
    // The 32 bytes themselves are allocated only for a token that is certificate bound.
    // `rar`: the RFC 9396 authorization details the token carries, a `Vec`, 24 bytes.
    // `consent`: the RFC 9470 authentication report, an `Option<Box<Authentication>>`, 8
    // bytes, because the report itself lives behind the pointer and only a grant the host
    // actually described allocates it.
    let issued_token_budget = 176
        + if cfg!(feature = "dpop") { 16 } else { 0 }
        + if cfg!(feature = "mtls") { 8 } else { 0 }
        + if cfg!(feature = "rar") { 24 } else { 0 }
        + if cfg!(feature = "consent") { 8 } else { 0 };
    assert!(
        size_of::<IssuedToken>() <= issued_token_budget,
        "IssuedToken grew past its size budget: {}",
        size_of::<IssuedToken>()
    );
}

/// The token endpoint's future must stay under tokio's DEBUG BOXING THRESHOLD.
///
/// `tokio::runtime::Runtime::block_on` and `tokio::spawn` box any future larger than 2048 bytes
/// when the runtime is built without optimisation, which every host's test suite and most hosts'
/// staging builds are. Crossing the threshold therefore costs a 2 KB heap allocation on EVERY
/// token request, and it costs it invisibly: the endpoint still returns the right answer, so
/// nothing but an allocation count or this measurement can tell that it happened.
///
/// This crate has crossed the line twice. The first time, an `async fn` wrapper around the
/// endpoint gave the token path a second generator frame holding its own copy of the request; the
/// second time, threading RFC 9396 authorization details through the grant helpers pushed it to
/// 2168 bytes. Both were fixed by RESTRUCTURING (see `token_with_context`), never by widening a
/// budget, because 2048 is not this crate's number to choose: tokio owns it.
///
/// The bound below is therefore the real threshold and not a percentage of anything. What keeps it
/// from being a gate that only fires after the damage is done is the OBSERVED figures recorded
/// here, which a reviewer can compare against a failing run's reported size:
///
/// - default features: 1080 bytes
/// - `--all-features`: 1344 bytes
///
/// Both SHRANK when `Storage`'s read paths began returning `Arc`: an owned `Client`, `IssuedToken`
/// or `RefreshTokenRecord` held across an await point is that many bytes of the generator frame,
/// and a pointer is eight.
///
/// `AuthorizationCode` is the variant measured because it is the widest arm of [`TokenRequest`]
/// and the deepest call chain behind it, so it is the arm that sets the high-water mark.
fn token_future_stays_under_tokios_debug_boxing_threshold() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    // Never polled: a future's SIZE is a property of the type, and constructing one is enough to
    // read it. Nothing here touches the store.
    let future = srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        code: String::new(),
        redirect_uri: None,
        code_verifier: None,
    });
    let size = std::mem::size_of_val(&future);
    drop(future);
    assert!(
        size <= 2048,
        "the token future is {size} bytes, past tokio's 2048-byte debug boxing threshold: every \
         token request now pays a 2 KB allocation. Restructure the path (do not raise this bound, \
         which is tokio's and not this crate's)"
    );
}
