// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What the BUNDLED ROUTER's document may promise, which is less than the library's document.
//!
//! `src/metadata.rs` opens with the rule: "an advertised endpoint that does not answer, or an
//! advertised capability the server rejects, is a lie the client cannot recover from." Two
//! advertisements broke it in opposite directions.
//!
//! ONE, RFC 8705. With `mtls` compiled in, `AuthorizationServerMetadata::from_config` publishes
//! `tls_client_auth`, `self_signed_tls_client_auth` and
//! `tls_client_certificate_bound_access_tokens: true`. All three are honest for a host that
//! reaches `AuthorizationServer` through its own handler with a certificate its TLS terminator
//! verified. None of them is honest for the bundled router, which is handed an already-parsed
//! request and passes `certificate: None` on every credential it builds: a client that acts on
//! the advertisement is refused `invalid_client` forever, and one that asks for a bound token
//! silently gets a bearer token. The field doc offered "a host that is not doing that should not
//! compile the `mtls` feature in", which cargo feature unification takes out of the host's hands.
//! So the SERVICE strips what the SERVICE cannot honour, and the server's own document is left
//! alone for the host that serves its own routes.
//!
//! TWO, RFC 7662. `introspection_endpoint` was advertised unconditionally while
//! `AuthorizationServer::introspection_response_with_credential` answered `{"active":false}` to
//! every authenticated caller that was not the token's own client, which was to say to every
//! RESOURCE SERVER, RFC 7662's primary consumer. 0.9.2 built that channel
//! (`ServerConfig::resource_servers`) and the advertisement REMAINS the host's opt-in
//! (`ServerConfig::introspection_endpoint`), because the channel only exists for a deployment that
//! registered resource servers and this crate cannot know whether one did. The ROUTE is
//! unconditional either way, because a client introspecting its own token always works and
//! withdrawing it would be a functional regression rather than an honesty fix.

#![cfg(feature = "http")]

use std::sync::Arc;

use oauth_as::http::{Body, ServiceBuilder};
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;
use serde_json::Value;

fn config() -> ServerConfig {
    ServerConfig::new("https://as.example", "https://as.example/device")
}

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

fn post(uri: &str, form: &str) -> http::Request<Body> {
    http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))
        .expect("a well-formed request")
}

/// The document this router SERVES, fetched the way a client fetches it.
async fn served_document(cfg: ServerConfig) -> Value {
    let service = ServiceBuilder::new(server(cfg)).build().expect("service");
    let response = service
        .handle(get("/.well-known/oauth-authorization-server"))
        .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_slice(&response.into_body().into_bytes()).expect("a JSON document")
}

/// RFC 8705 sections 2.1.1 and 2.2.1: the two certificate-bound client authentication methods.
#[cfg(feature = "mtls")]
#[tokio::test]
async fn the_router_does_not_advertise_client_auth_it_cannot_perform() {
    let doc = served_document(config()).await;
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("RFC 8414 s2 token_endpoint_auth_methods_supported");
    for method in ["tls_client_auth", "self_signed_tls_client_auth"] {
        assert!(
            !methods.contains(&Value::String(method.to_string())),
            "this router passes certificate: None on every credential, so {method} can only ever \
             answer invalid_client: {methods:?}"
        );
    }
    assert!(
        methods.contains(&Value::String("client_secret_basic".to_string())),
        "the strip must remove exactly the two mtls methods: {methods:?}"
    );
}

/// RFC 8705 section 3.3: the binding promise a client acts on when it decides to present a
/// certificate at all.
#[cfg(feature = "mtls")]
#[tokio::test]
async fn the_router_does_not_promise_certificate_bound_tokens() {
    let doc = served_document(config()).await;
    assert_eq!(
        doc["tls_client_certificate_bound_access_tokens"],
        Value::Bool(false),
        "a deployment whose only front door is this router binds nothing, so section 3.3's \
         default (false) is the only honest value here"
    );
}

/// The other half of the strip: a host serving its own routes with a real TLS terminator still
/// gets the full document, because for that host every member is true. If the strip reached
/// `AuthorizationServer::metadata` it would take RFC 8705 away from the only deployment that can
/// use it.
#[cfg(feature = "mtls")]
#[test]
fn the_servers_own_document_still_advertises_mtls() {
    let meta = server(config()).metadata();
    assert!(
        meta.token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "tls_client_auth"),
        "a host with its own handler passes the certificate in and this method works"
    );
    assert!(
        meta.tls_client_certificate_bound_access_tokens,
        "RFC 8705 s3: with the feature compiled in, a certificate the host supplies IS bound"
    );
}

/// RFC 7662: not promised by default, and still served.
#[tokio::test]
async fn introspection_is_unadvertised_by_default_and_still_routed() {
    let doc = served_document(config()).await;
    assert!(
        doc.get("introspection_endpoint").is_none(),
        "RFC 7662's primary consumer is a resource server, and this server has no resource-server \
         channel, so the member waits for a host to opt in: {doc}"
    );

    let service = ServiceBuilder::new(server(config()))
        .build()
        .expect("service");
    let response = service.handle(post("/introspect", "token=nothing")).await;
    assert_ne!(
        response.status(),
        http::StatusCode::NOT_FOUND,
        "the route is unconditional: a client introspecting its OWN token is the case that works, \
         and withdrawing it would be a regression rather than an honesty fix"
    );
}

/// The opt-in, end to end: a host that names the endpoint gets it advertised AND routed.
#[tokio::test]
async fn a_host_that_names_the_introspection_endpoint_gets_it_advertised() {
    let mut cfg = config();
    cfg.introspection_endpoint = Some("https://as.example/introspect".to_string());
    let doc = served_document(cfg).await;
    assert_eq!(
        doc["introspection_endpoint"],
        Value::String("https://as.example/introspect".to_string())
    );
}
