// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The two doors where `authorization_details` is refused even by a build that DOES support the
//! type, because this crate's grant cannot carry it there.
//!
//! `tests/authorization_details_refusal_without_rar.rs` is about the build that honours no detail
//! type at all, where RFC 9396 section 5's condition holds for every request. This file is the
//! other half, and the reason it exists separately is that the two refusals are gated differently
//! and a feature-gated refusal tested in one configuration only is how this crate has already
//! shipped a door that was open in the configuration nobody built locally.
//!
//! - the RFC 8628 device authorization request has NO authorization_details in this crate: a
//!   [`oauth_as::DeviceGrant`] has no field for one, so there is nothing for a supported type to be
//!   recorded in. `AuthorizationServer::token` already refuses to mint detail for a device grant
//!   under `rar` ("the device authorization request granted no authorization_details"); this is the
//!   same refusal moved to the door the client actually knocks on, where it can still be told which
//!   parameter was wrong.
//! - the RFC 8693 token exchange grant derives everything it issues from the SUBJECT token, so it
//!   has no request parameter for detail either, supported type or not.
//!
//! Same posture, and the same argument, as the DPoP proof this router already refuses on the
//! exchange grant rather than ignoring: a client that asked this server for something it cannot do
//! is a wiring mistake, and the only person who can fix it is the one who is told.

#![cfg(all(feature = "http", feature = "rar"))]

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{Body, ServiceBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;

const REDIRECT_URI: &str = "https://app.example/cb";
/// A minimal RFC 9396 section 2 value, percent-encoded for the form body. The type below is the
/// one the configuration SUPPORTS, so nothing here is refused for being unknown.
const DETAILS_ESCAPED: &str = "%5B%7B%22type%22%3A%22payment_initiation%22%7D%5D";

type Service = oauth_as::http::AuthorizationService<MemoryStorage, SystemClock>;

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::DeviceCode],
        redirect_uris: vec![REDIRECT_URI.to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn service() -> Service {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    // The deployment that supports the type. Without this every refusal below would be the
    // unsupported-type one and the test would prove nothing about the door.
    cfg.authorization_details_types_supported = Some(vec!["payment_initiation".to_string()]);
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    srv.register_client(client()).await.expect("registered");
    ServiceBuilder::new(Arc::new(srv)).build().expect("service")
}

fn post(uri: &str, body: &str) -> http::Request<Body> {
    http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .expect("a well-formed request")
}

fn body_text(response: http::Response<Body>) -> String {
    String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned()
}

/// The device authorization request, with a type this server publishes as supported. It is still
/// refused, because SUPPORTING a type and being able to RECORD it on this particular grant are
/// different things, and only the second one decides whether the token will say what the client
/// asked it to.
#[tokio::test]
async fn the_device_authorization_endpoint_refuses_a_supported_type_too() {
    let service = service().await;
    let response = service
        .handle(post(
            "/device_authorization",
            &format!("client_id=app&scope=read&authorization_details={DETAILS_ESCAPED}"),
        ))
        .await;
    let body = body_text(response);
    assert!(
        body.contains("invalid_authorization_details"),
        "a device grant has nowhere to carry a detail, so accepting one mints a user code for a \
         permission that will never appear on the token: {body}"
    );
}

/// The token exchange grant, same argument.
#[cfg(feature = "token-exchange")]
#[tokio::test]
async fn the_token_exchange_grant_refuses_a_supported_type_too() {
    let service = service().await;
    let response = service
        .handle(post(
            "/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
                 &client_id=app&subject_token=not-a-real-token\
                 &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
                 &authorization_details={DETAILS_ESCAPED}"
            ),
        ))
        .await;
    let body = body_text(response);
    assert!(
        body.contains("invalid_authorization_details"),
        "RFC 8693 issues from the subject token, so a requested detail has nowhere to go: {body}"
    );
}

/// The boundary: the same device authorization request WITHOUT the parameter is untouched. A
/// refusal that also refused the requests carrying nothing would be a worse defect than the drop
/// it replaced.
#[tokio::test]
async fn a_device_authorization_request_without_the_parameter_is_untouched() {
    let service = service().await;
    let response = service
        .handle(post("/device_authorization", "client_id=app&scope=read"))
        .await;
    let body = body_text(response);
    assert!(
        body.contains("user_code"),
        "an ordinary device authorization request must still get its codes: {body}"
    );
}
