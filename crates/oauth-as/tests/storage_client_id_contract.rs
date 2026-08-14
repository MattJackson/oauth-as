// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT REACHES `Storage::get_client`, in the exact bytes the host's store will see.
//!
//! `ClientId::new` validates nothing and this crate refuses no identifier on syntax, because RFC
//! 6749 section 2.2 leaves the identifier's syntax to the server and a host names its own clients.
//! The consequence is a seam contract rather than a bug: the value handed to a host-implemented
//! `Storage::get_client` is a string an unauthenticated stranger chose, and a store that puts it
//! into a filesystem path, an object key, an LDAP filter or SQL text — rather than using it as an
//! opaque key — inherits every shape below.
//!
//! That contract is written on [`oauth_as::store::Storage::get_client`]. These tests are what
//! makes it a contract somebody has to keep: they record the ids the crate actually delivers, so
//! the documentation cannot drift from the behaviour in either direction.
//!
//! The RFC 7592 route is the interesting one because its segment is PERCENT-DECODED. The router
//! matches the registration prefix on the RAW path and refuses a raw `/`, so nothing mounted under
//! the registration endpoint can be reached by a path like `/register/a/b` — that part is settled
//! before any decoding happens, and `a_percent_encoded_slash_does_not_change_the_route` holds it
//! there. What the decode then produces is a client id containing `/`, or `..`, or a NUL, and
//! `get_client` is where it lands.
//!
//! It is deliberately NOT unique to that route, and the last test says so: the authorization
//! endpoint hands the same seam an arbitrary query parameter. Validating the RFC 7592 segment
//! alone would therefore close nothing while suggesting to a host that something had been closed.

#![cfg(feature = "http")]

use std::sync::{Arc, Mutex};

use oauth_as::client::{Client, ClientId};
use oauth_as::http::{Body, ServiceBuilder};
use oauth_as::registration::RegistrationConfig;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::{MemoryStorage, Storage, StorageError};

/// A store that records every `client_id` it is asked for, verbatim, and otherwise behaves exactly
/// as `MemoryStorage` does.
#[derive(Default)]
struct RecordingStorage {
    inner: MemoryStorage,
    seen: Mutex<Vec<String>>,
}

impl RecordingStorage {
    fn take_seen(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Storage for RecordingStorage {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(client_id.as_str().to_string());
        self.inner.get_client(client_id).await
    }

    oauth_as::delegate_storage! {
        to inner;
        put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        put_token, get_token, delete_token,
        put_refresh_token, get_refresh_token, take_refresh_token, revoke_token_family,
        put_consent, compare_and_swap_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

type Service = oauth_as::http::AuthorizationService<RecordingStorage, SystemClock>;

fn config() -> ServerConfig {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(RegistrationConfig::new()));
    cfg
}

fn service() -> (Service, Arc<AuthorizationServer<RecordingStorage>>) {
    let srv = Arc::new(AuthorizationServer::new(
        config(),
        RecordingStorage::default(),
    ));
    let service = ServiceBuilder::new(Arc::clone(&srv))
        .build()
        .expect("service");
    (service, srv)
}

async fn get(uri: &str) -> (http::StatusCode, Vec<String>) {
    let (service, srv) = service();
    let request = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::from(String::new()))
        .expect("a well-formed request");
    let response = service.handle(request).await;
    (response.status(), srv.store().take_seen())
}

/// A raw `/` is a different PATH, not a client id, and the router settles that on the wire form
/// before anything is decoded. Nothing reaches the store.
#[tokio::test]
async fn a_raw_slash_in_the_segment_is_not_a_registration_route_at_all() {
    let (status, seen) = get("/register/a/b").await;
    assert_eq!(status, http::StatusCode::NOT_FOUND);
    assert!(
        seen.is_empty(),
        "a path that is not a route must not reach the store: {seen:?}"
    );
}

/// The percent-encoded form IS the route — which is correct, because `registration_client_uri`
/// mints exactly that encoding (RFC 7592 s3) — and the id the store is handed contains a real
/// slash.
#[tokio::test]
async fn a_percent_encoded_slash_does_not_change_the_route() {
    let (status, seen) = get("/register/a%2Fb").await;
    assert_eq!(
        status,
        http::StatusCode::UNAUTHORIZED,
        "the route is the management route; the id is simply unknown"
    );
    assert_eq!(
        seen,
        vec!["a/b".to_string()],
        "the host's store is handed the DECODED id, slash and all"
    );
}

/// Dot-dot, NUL and a byte that is not UTF-8: the three shapes a path-shaped or key-shaped store
/// has to care about, all of which arrive intact (the last one lossily, as U+FFFD).
#[tokio::test]
async fn the_decoded_segment_carries_dot_dot_nul_and_invalid_utf8() {
    let (_, seen) = get("/register/%2E%2E").await;
    assert_eq!(seen, vec!["..".to_string()]);

    let (_, seen) = get("/register/..%2Fregister").await;
    assert_eq!(seen, vec!["../register".to_string()]);

    let (_, seen) = get("/register/a%00b").await;
    assert_eq!(seen, vec!["a\u{0}b".to_string()], "a NUL passes through");

    let (_, seen) = get("/register/a%FFb").await;
    assert_eq!(
        seen,
        vec!["a\u{FFFD}b".to_string()],
        "the decode is lossy, so invalid UTF-8 becomes a replacement character"
    );
}

/// THE REASON THE CONTRACT IS ON THE TRAIT AND NOT ON THE ROUTE. The authorization endpoint hands
/// the same seam an arbitrary unauthenticated string with no decoding subtlety at all, so a store
/// that is unsafe for `../x` was already unsafe before RFC 7592 was mounted.
#[tokio::test]
async fn the_authorization_endpoint_hands_the_same_seam_an_arbitrary_id() {
    let (_, seen) = get("/authorize?response_type=code&client_id=..%2F..%2Fetc%2Fpasswd").await;
    assert_eq!(
        seen,
        vec!["../../etc/passwd".to_string()],
        "one unvalidated route is not the shape of this: every client lookup is host-named"
    );
}
