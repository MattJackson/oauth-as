// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Everything the RFC 8414 document promises has to be REACHABLE through this router.
//!
//! `src/http.rs` states the rule in its own module docs: "an advertised endpoint that 404s is a
//! lie a client cannot recover from", so either the route moves with the configuration or
//! `ServiceBuilder::build` refuses to produce a service at all. Two configurations slipped
//! between those two outcomes and reached the third, which is the one the rule forbids: the
//! document advertises, `build` returns `Ok`, and the request 404s.
//!
//! ONE, a build WITHOUT the `jwt` feature. `jwks_uri` is a plain public field of `ServerConfig`
//! and the `http` feature does not imply `jwt`, so the member was published while every branch
//! that routes it is `#[cfg(feature = "jwt")]`.
//!
//! TWO, an issuer whose path contains a character a client must percent-encode. The routes are
//! derived from the DECODED issuer and were matched against `uri.path()`, which is what arrived on
//! the wire and is still encoded, so every route missed by exactly the escaping the client was
//! required to perform.

#![cfg(feature = "http")]

use std::sync::Arc;

use oauth_as::http::{Body, ServiceBuilder};
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;

fn server(cfg: ServerConfig) -> Arc<AuthorizationServer<MemoryStorage, SystemClock>> {
    Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()))
}

fn get(uri: &str) -> http::Request<Body> {
    http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::from(String::new()))
        .expect("a well-formed request")
}

/// A `jwks_uri` under the issuer, in a build that cannot serve one.
///
/// Without `jwt` this crate signs nothing and has no key set to publish, so there is no branch
/// that routes the member: the host either points it at a URL this service does not claim, or it
/// has configured an endpoint that can only ever 404. `build` is the only place that can say so.
#[cfg(not(feature = "jwt"))]
#[test]
fn a_jwks_uri_under_the_issuer_is_refused_by_a_build_that_cannot_serve_one() {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.jwks_uri = Some("https://as.example/jwks.json".to_string());
    let err = ServiceBuilder::new(server(cfg))
        .build()
        .expect_err("a jwks_uri this build cannot serve must not become a routed promise");
    let text = err.to_string();
    assert!(
        text.contains("jwks_uri") && text.contains("https://as.example/jwks.json"),
        "the refusal must name the member and the URL the host configured: {text}"
    );
}

/// The other half, so the refusal above is a boundary and not a ban: RFC 8414 lets an AS publish a
/// key set some other component holds, and a URL outside the issuer is exactly that statement.
/// This service never claimed that path, so nothing it serves 404s.
#[cfg(not(feature = "jwt"))]
#[test]
fn a_jwks_uri_outside_the_issuer_still_builds_without_the_jwt_feature() {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.jwks_uri = Some("https://keys.example/jwks.json".to_string());
    assert!(
        ServiceBuilder::new(server(cfg)).build().is_ok(),
        "keys held elsewhere are the host's own affair and must still build"
    );
}

/// An issuer with a non-ASCII path component. `tests/issuer_origin_boundary.rs` already pins that
/// this configuration BUILDS; what was never checked is that anything it built can be reached.
///
/// The document is at `/.well-known/oauth-authorization-server/{issuer path}` (RFC 8414 s3.1), and
/// a client fetching it sends the path percent-encoded because it has no choice: `\u{e9}` is not a
/// `pchar`. Written as an escape because this repository is ASCII-only, source included.
#[tokio::test]
async fn an_issuer_path_a_client_must_encode_is_still_routed() {
    let service = ServiceBuilder::new(server(ServerConfig::new(
        "https://as.example/\u{e9}",
        "https://as.example/\u{e9}/device",
    )))
    .build()
    .expect("service");

    let response = service
        .handle(get("/.well-known/oauth-authorization-server/%C3%A9"))
        .await;
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "the metadata document must be served at the path a client is required to send"
    );

    let response = service.handle(get("/%C3%A9/authorize")).await;
    assert_ne!(
        response.status(),
        http::StatusCode::NOT_FOUND,
        "the authorization endpoint the document advertises must resolve to a route: a 404 here \
         is the advertised-but-unreachable shape the module docs forbid"
    );
}

/// The ASCII issuer, unchanged, so the decoding above cannot be a rewrite of the ordinary case:
/// nothing that resolved before may stop resolving.
#[tokio::test]
async fn an_ordinary_issuer_path_still_resolves_verbatim() {
    let service = ServiceBuilder::new(server(ServerConfig::new(
        "https://as.example/tenant1",
        "https://as.example/tenant1/device",
    )))
    .build()
    .expect("service");

    let response = service
        .handle(get("/.well-known/oauth-authorization-server/tenant1"))
        .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        service.handle(get("/tenant1/nothing")).await.status(),
        http::StatusCode::NOT_FOUND,
        "an unrouted path is still a 404"
    );
}

/// THREE, the mirror image of TWO, which the two tests above cannot see.
///
/// An issuer whose path a client must escape has two spellings, and only one of them is a legal
/// URI: RFC 3986 section 3.3 admits `pchar` only, so `https://as.example/tenant%20a` is the
/// RFC-correct way to write a tenant whose name contains a space, and a raw non-ASCII issuer is
/// the spelling that is not. The route table is built by `endpoint_path`, which is
/// `url.strip_prefix(issuer)` and decodes nothing, so the table holds the issuer VERBATIM as the
/// host configured it. Decoding the WIRE path before matching therefore helps the illegal
/// spelling and breaks the legal one: `%20` on the wire becomes a space, the table holds `%20`,
/// and every endpoint the document advertises 404s.
#[tokio::test]
async fn a_percent_encoded_issuer_path_is_still_routed() {
    let service = ServiceBuilder::new(server(ServerConfig::new(
        "https://as.example/tenant%20a",
        "https://as.example/tenant%20a/device",
    )))
    .build()
    .expect("service");

    assert_eq!(
        service
            .handle(get("/.well-known/oauth-authorization-server/tenant%20a"))
            .await
            .status(),
        http::StatusCode::OK,
        "RFC 8414 s3.1: the document must be served at the path a client sends, and a client \
         sends the issuer path exactly as the issuer spells it"
    );
    assert_ne!(
        service.handle(get("/tenant%20a/authorize")).await.status(),
        http::StatusCode::NOT_FOUND,
        "the authorization endpoint the document advertises must resolve"
    );
}

/// FOUR, and this one is about who else is looking at the path.
///
/// This crate's deployment model is that the host owns the listener and mounts the service under
/// whatever it already runs, so the request has usually passed a reverse proxy, an ingress rule or
/// a WAF that matched on the RAW path: `location = /register`, `PathPrefix(/register)`, a `deny`.
/// Restricting RFC 7591 dynamic registration to an internal network BY PATH is an ordinary
/// supported configuration. If this service decodes the whole path before matching, then
/// `/%72egister` misses every one of those rules and hits the registration endpoint anyway, and
/// the same trick reaches the token, revocation and metadata endpoints. A route is the exact
/// string it is, and an escaped spelling is a different string.
#[tokio::test]
async fn an_escaped_spelling_of_a_route_is_not_the_route() {
    let service = ServiceBuilder::new(server(ServerConfig::new(
        "https://as.example",
        "https://as.example/device",
    )))
    .build()
    .expect("service");

    for path in [
        "/.well-known/oauth-authorization-%73erver",
        "/%74oken",
        "/%74%6F%6B%65%6E",
        "/%72evoke",
    ] {
        assert_eq!(
            service.handle(get(path)).await.status(),
            http::StatusCode::NOT_FOUND,
            "{path} is not a route this service serves, and every layer in front of it that \
             matched the raw path agreed"
        );
    }
}

/// FIVE, the case FOUR's rule has to be stated carefully enough not to swallow.
///
/// "A route is the exact string it is" is true of the CHARACTERS a path names, and RFC 3986
/// section 6.2.2.1 says the hexadecimal digits of a percent-encoding are not among them: `%c3`
/// and `%C3` are the same octet, and the section directs a normaliser to prefer the uppercase
/// form. Uppercasing is therefore a transformation a client library, a reverse proxy or an
/// ingress controller is entitled to perform, and several do.
///
/// So a host that spells its issuer's escapes in lowercase (a legal URI, and the spelling a
/// hand-written config file tends to carry) publishes a document whose endpoints a normalising
/// client cannot reach: it sends the uppercase form, the table holds the lowercase one, and the
/// byte-for-byte match that FOUR depends on fails on every endpoint at once.
///
/// The fix belongs in the TABLE, not the matcher: the escapes a host configured are normalised to
/// the RFC 3986 form once at build time, and the wire path is still compared verbatim, so
/// everything FOUR pins is unchanged.
#[tokio::test]
async fn a_lowercase_escape_in_the_issuer_still_routes_the_form_a_client_normalises_to() {
    let service = ServiceBuilder::new(server(ServerConfig::new(
        "https://as.example/caf%c3%a9",
        "https://as.example/caf%c3%a9/device",
    )))
    .build()
    .expect("service");

    assert_eq!(
        service
            .handle(get("/.well-known/oauth-authorization-server/caf%C3%A9"))
            .await
            .status(),
        http::StatusCode::OK,
        "RFC 3986 s6.2.2.1: a client that normalises the escapes it was given must still find \
         the document"
    );
    assert_ne!(
        service.handle(get("/caf%C3%A9/authorize")).await.status(),
        http::StatusCode::NOT_FOUND,
        "the authorization endpoint the document advertises must resolve for the normalised \
         spelling too"
    );
    // And the spelling the host actually configured keeps working, because uppercasing the hex
    // is the only change: a table that answered one form and not the other would have moved the
    // problem rather than fixed it.
    assert_ne!(
        service.handle(get("/caf%c3%a9/authorize")).await.status(),
        http::StatusCode::NOT_FOUND,
        "the spelling the host configured must not stop resolving"
    );
}
