// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! EVERY URL THE RFC 8414 DOCUMENT ADVERTISES ON THIS ISSUER MUST ROUTE.
//!
//! The document is a promise made to a stranger. A client reads it, picks the endpoint it needs,
//! and calls it; a member naming a path this service answers 404 on is a promise the server does
//! not keep, and the client has no way to find that out except by making the call and failing.
//!
//! WHY THIS FILE EXISTS. A tester reported that `revocation_endpoint` and
//! `device_authorization_endpoint` were advertised but not mounted. They are not: both route, and
//! this file proves it. But the report was right about the thing that mattered, which is that
//! NOTHING PROVED IT. `tests/http_advertised_reachability.rs` covers `jwks_uri` specifically -- a
//! build that cannot serve one must refuse to route a promise for it -- and `wire_reachability.rs`
//! covers what the document says under given features. Neither walks the document member by member
//! and calls what it finds, so the general property was argued rather than checked, and the two
//! members named could just as easily have been the two that broke.
//!
//! This is the mirror of a defect the fuzzer found from the other side: `/introspect` is ROUTED
//! whether or not it is ADVERTISED, deliberately, and the fuzz oracle called that a defect because
//! it derived the routed set from the document. Advertisement and routing are two sets that must
//! agree in one direction and are allowed to differ in the other:
//!
//!   ADVERTISED but not routed -> a broken promise. Never allowed. This file.
//!   ROUTED but not advertised -> an endpoint a client is not told about. Allowed, and used:
//!                                introspection answers the token's own client whether or not the
//!                                deployment publishes the member.
//!
//! The probe is deliberately dumb: take the served document, keep every string member that is a
//! URL under this issuer, and call it. A 404 to BOTH `GET` and `POST` is the failure. Anything
//! else -- 400, 401, 405, 200 -- means the route exists and the request was merely wrong, which is
//! not what this test is about.

#![cfg(feature = "http")]

use std::sync::Arc;

use oauth_as::http::{Body, ServiceBuilder};
use oauth_as::registration::RegistrationConfig;
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;

const ISSUER: &str = "https://as.example";

/// Serve the document, then call every endpoint it names on this issuer.
async fn unrouted_members(cfg: ServerConfig) -> Vec<String> {
    let srv = Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()));
    let service = ServiceBuilder::new(srv)
        .build()
        .expect("the fixture configuration routes without collision");

    let response = service
        .handle(
            http::Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::from(String::new()))
                .expect("a well-formed request"),
        )
        .await;
    let bytes = response.into_body().into_bytes();
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the metadata document is JSON");

    let mut unrouted = Vec::new();
    for (member, value) in document.as_object().expect("the document is an object") {
        let Some(url) = value.as_str() else { continue };
        // Only what this server is responsible for answering. `issuer` itself is not an endpoint,
        // and a member pointing off-issuer (a host's own documentation URL, say) is somebody
        // else's to serve.
        let Some(path) = url.strip_prefix(ISSUER) else {
            continue;
        };
        if path.is_empty() || !path.starts_with('/') || path == "/" {
            continue;
        }

        let mut answered_404 = 0;
        for method in ["GET", "POST"] {
            let response = service
                .handle(
                    http::Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::from(String::new()))
                        .expect("a well-formed request"),
                )
                .await;
            if response.status().as_u16() == 404 {
                answered_404 += 1;
            }
        }
        // 404 to BOTH verbs is "no such route". A 404 to one and a 405 to the other is a route
        // that exists and rejects the verb, which is correct behaviour and not this test's
        // business.
        if answered_404 == 2 {
            unrouted.push(format!("{member} -> {path}"));
        }
    }
    unrouted
}

async fn assert_all_routed(label: &str, cfg: ServerConfig) {
    let unrouted = unrouted_members(cfg).await;
    assert!(
        unrouted.is_empty(),
        "[{label}] the RFC 8414 document advertises {} endpoint(s) this service does not route, \
         so a client that reads the document and calls what it names gets a 404 from the server \
         that published it:\n  {}",
        unrouted.len(),
        unrouted.join("\n  ")
    );
}

#[tokio::test]
async fn a_default_configuration_routes_everything_it_advertises() {
    assert_all_routed(
        "defaults",
        ServerConfig::new(ISSUER, "https://as.example/device"),
    )
    .await;
}

/// The paths a host OVERRIDES are the interesting ones: the default spellings are exercised by
/// every other test in the suite, while an override is a value that has to reach both the document
/// and the router, from one field, without either side deriving it independently.
#[tokio::test]
async fn overridden_endpoint_paths_route_where_the_document_says_they_do() {
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    cfg.authorization_endpoint = Some(format!("{ISSUER}/oauth2/authorize"));
    cfg.token_endpoint = Some(format!("{ISSUER}/oauth2/token"));
    cfg.revocation_endpoint = Some(format!("{ISSUER}/oauth2/revoke"));
    cfg.introspection_endpoint = Some(format!("{ISSUER}/oauth2/introspect"));
    cfg.device_authorization_endpoint = Some(format!("{ISSUER}/oauth2/device_authorization"));
    assert_all_routed("overridden paths", cfg).await;
}

/// Dynamic registration is the member that is genuinely conditional: a host that never enabled it
/// advertises nothing and routes nothing, and a host that did must do both.
#[tokio::test]
async fn dynamic_registration_advertised_is_dynamic_registration_routed() {
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read").expect("a well-formed scope");
    registration.management_enabled = true;
    cfg.registration = Some(Box::new(registration));
    assert_all_routed("registration enabled", cfg).await;
}

/// An issuer with a PATH component. RFC 8414 section 3.1 puts the well-known string between the
/// host and the issuer's path, so this is the shape where a naive `strip_prefix` on either side
/// stops agreeing with the other.
#[tokio::test]
async fn an_issuer_with_a_path_component_routes_everything_it_advertises() {
    let issuer_with_path = "https://as.example/tenant-a";
    let cfg = ServerConfig::new(issuer_with_path, "https://as.example/tenant-a/device");
    let srv = Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()));
    let service = ServiceBuilder::new(srv)
        .build()
        .expect("the fixture configuration routes without collision");

    let response = service
        .handle(
            http::Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-authorization-server/tenant-a")
                .body(Body::from(String::new()))
                .expect("a well-formed request"),
        )
        .await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "RFC 8414 s3.1 locates a path-bearing issuer's document at \
         /.well-known/oauth-authorization-server{{path}}, and this server must serve it there"
    );
    let bytes = response.into_body().into_bytes();
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the metadata document is JSON");

    let mut unrouted = Vec::new();
    for (member, value) in document.as_object().expect("the document is an object") {
        let Some(url) = value.as_str() else { continue };
        let Some(path) = url.strip_prefix(issuer_with_path) else {
            continue;
        };
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        let full = format!("/tenant-a{path}");
        let mut answered_404 = 0;
        for method in ["GET", "POST"] {
            let response = service
                .handle(
                    http::Request::builder()
                        .method(method)
                        .uri(&full)
                        .body(Body::from(String::new()))
                        .expect("a well-formed request"),
                )
                .await;
            if response.status().as_u16() == 404 {
                answered_404 += 1;
            }
        }
        if answered_404 == 2 {
            unrouted.push(format!("{member} -> {full}"));
        }
    }
    assert!(
        unrouted.is_empty(),
        "[issuer with path] advertised but not routed:\n  {}",
        unrouted.join("\n  ")
    );
}
