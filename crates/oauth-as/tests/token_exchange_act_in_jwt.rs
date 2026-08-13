// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE DELEGATION HAS TO REACH THE RESOURCE SERVER, AND THERE ARE TWO ROUTES, NOT ONE.
//!
//! RFC 8693 section 1.1 draws the whole distinction between delegation and impersonation, and it
//! is a distinction FOR THE RESOURCE SERVER: whether it can tell "A acting for B" from "B". A
//! delegation the resource server cannot observe is impersonation with extra steps at this server.
//!
//! There are exactly two ways this crate's access tokens carry anything, and they reach a resource
//! server differently:
//!
//! - an OPAQUE token carries nothing itself, so RFC 7662 introspection is its only channel;
//! - an RFC 9068 JWT is typically validated OFFLINE, by a resource server that reads the claims
//!   and never calls introspection at all.
//!
//! 0.9.1 first put the `act` claim on the persisted record and reported it at introspection, and
//! the module doc then claimed the gap was closed. It was not: it had MOVED, from opaque
//! deployments to JWT ones, which is why this file exists and why it tests the JWT route
//! specifically. `tests/token_exchange.rs` owns the introspection route.

#![cfg(all(feature = "token-exchange", feature = "jwt-p256"))]

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ScopeSet,
    ServerConfig, TokenExchange, TokenExchangeRequest, TokenRequest, TokenTypeIdentifier,
};

const HOLDER_SECRET: &str = "holder-secret-value-for-tests";
const EXCHANGER_SECRET: &str = "exchanger-secret-value-for-tests";

fn client(id: &str, secret: &str) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth: ClientAuth::ConfidentialSecret {
            secret: secret.to_string(),
        },
        grant_types: vec![
            GrantType::ClientCredentials,
            GrantType::TokenExchange,
            GrantType::AuthorizationCode,
        ],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A server that signs RFC 9068 access tokens, so the wire token is a JWT whose claims can be read
/// the way an offline resource server reads them.
async fn signing_server() -> AuthorizationServer<MemoryStorage> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("act-test-kid"),
        "https://rs.example",
    )));
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    srv.register_client(client("holder", HOLDER_SECRET))
        .await
        .unwrap();
    srv.register_client(client("exchanger", EXCHANGER_SECRET))
        .await
        .unwrap();
    srv
}

/// The claims of a signed access token, as an offline resource server would read them: decode the
/// payload segment, and never ask this server anything.
fn claims_of(access_token: &str) -> serde_json::Value {
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "the wire token must be a JWS compact form");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("payload base64url"))
        .expect("payload JSON")
}

async fn subject_token(srv: &AuthorizationServer<MemoryStorage>) -> String {
    srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("holder"),
        client_secret: Some(HOLDER_SECRET.to_string()),
        scope: None,
    })
    .await
    .expect("the holder mints its own token")
    .access_token
}

async fn actor_token(srv: &AuthorizationServer<MemoryStorage>) -> String {
    srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("exchanger"),
        client_secret: Some(EXCHANGER_SECRET.to_string()),
        scope: None,
    })
    .await
    .expect("the exchanging client mints its own actor token")
    .access_token
}

/// A DELEGATED token names its actor in the signed claims, so a resource server that never
/// introspects still sees the delegation.
#[tokio::test]
async fn a_delegated_jwt_carries_the_act_claim() {
    let srv = signing_server().await;
    let subject = subject_token(&srv).await;
    let actor = actor_token(&srv).await;

    let client_id = ClientId::new("exchanger");
    let mut req = TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    req.client_secret = Some(EXCHANGER_SECRET);
    req.actor_token = Some(&actor);
    req.actor_token_type = Some(TokenTypeIdentifier::AccessToken);
    let exchanged = srv.exchange_token(&req).await.expect("delegation exchange");

    let claims = claims_of(&exchanged.response.access_token);
    let act = claims
        .get("act")
        .expect("a delegated JWT must name its actor: an offline resource server has no other way");
    assert_eq!(
        act.get("sub").and_then(|v| v.as_str()),
        Some("exchanger"),
        "the act claim must name the ACTING party: {claims}"
    );
    // `sub` is REQUIRED by RFC 9068 s2.2 and is present. It is not asserted to be the holder here,
    // and that is a fact about the fixture rather than a concession: the subject token above comes
    // from RFC 6749 s4.4 client credentials, which has no resource owner at all, so s2.2's answer
    // for `sub` is the client identifier. Which principal a delegated token names is pinned by
    // `tests/token_exchange.rs` against a subject token that actually carries a user; what THIS
    // file is for is that the delegation is visible without introspection.
    assert!(
        claims.get("sub").and_then(|v| v.as_str()).is_some(),
        "RFC 9068 s2.2 makes sub REQUIRED: {claims}"
    );
}

/// An IMPERSONATION exchange names no actor, so the claim must be ABSENT rather than null. A
/// member that is present and null invites a careless resource server to treat it as answered.
#[tokio::test]
async fn an_impersonated_jwt_omits_the_act_claim_entirely() {
    let srv = signing_server().await;
    let subject = subject_token(&srv).await;

    let client_id = ClientId::new("exchanger");
    let mut req = TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    req.client_secret = Some(EXCHANGER_SECRET);
    let exchanged = srv
        .exchange_token(&req)
        .await
        .expect("impersonation exchange");

    let claims = claims_of(&exchanged.response.access_token);
    assert!(
        claims.get("act").is_none(),
        "an impersonation exchange names no actor, so the member must be absent, not null: \
         {claims}"
    );
}

/// Every OTHER grant is unchanged: the claim costs a deployment that never exchanges anything
/// nothing at all, including a member in its tokens.
#[tokio::test]
async fn an_ordinary_grants_jwt_has_no_act_member() {
    let srv = signing_server().await;
    let issued = subject_token(&srv).await;
    let claims = claims_of(&issued);
    assert!(claims.get("act").is_none(), "{claims}");
}
