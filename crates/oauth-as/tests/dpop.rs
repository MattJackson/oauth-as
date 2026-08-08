// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9449 DPoP, end to end through the token endpoint.
//!
//! `src/tests/dpop.rs` tests the PROOF VALIDATOR in isolation. This file tests what a deployment
//! actually buys with it: that a token issued against a proof is BOUND to that key and says so, on
//! the wire and at introspection; that a captured proof cannot be spent twice; and that the binding
//! survives refresh, which is the difference between DPoP being real and being decorative.
#![cfg(feature = "dpop")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::dpop::htu_of;
use oauth_as::jwt::{compact_jws, EcdsaP256Key};
use oauth_as::{
    AuthorizationServer, AuthorizationServerMetadata, Client, ClientAuth, ClientId, ErrorCode,
    GrantType, MemoryStorage, ScopeSet, ServerConfig, Storage, TokenRequest, TokenRequestContext,
    TokenType,
};

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const SECRET: &str = "confidential-client-secret";
const REDIRECT: &str = "https://app.example/cb";

fn server() -> AuthorizationServer<MemoryStorage> {
    AuthorizationServer::new(
        ServerConfig::new(ISSUER, "https://as.example/device"),
        MemoryStorage::new(),
    )
}

fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One RFC 9449 section 4.2 proof for `POST {TOKEN_ENDPOINT}`, signed by `key`.
fn proof(key: &EcdsaP256Key, jti: &str) -> String {
    proof_for(key, jti, "POST", TOKEN_ENDPOINT)
}

fn proof_for(key: &EcdsaP256Key, jti: &str, htm: &str, htu: &str) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = serde_json::json!({ "jti": jti, "htm": htm, "htu": htu, "iat": now_secs() });
    compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

fn request() -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    }
}

fn with_proof(proof: &str) -> TokenRequestContext<'_> {
    TokenRequestContext {
        dpop_proof: Some(proof),
        ..Default::default()
    }
}

// -------------------------------------------------------------------------------- the binding

#[tokio::test]
async fn a_token_issued_against_a_proof_is_bound_to_that_key_and_says_so() {
    let key = EcdsaP256Key::generate("device");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();

    let response = srv
        .token_with_context(request(), with_proof(&proof(&key, "p-1")))
        .await
        .expect("a conforming proof yields a token");

    // RFC 9449 s5: the token_type changes, and it has to, because it is what tells the client (and
    // anything reading the response) that this token must be presented with a proof.
    assert_eq!(response.token_type, TokenType::Dpop);

    // RFC 9449 s6.1 with RFC 7662: a resource server that introspects must be able to CONFIRM the
    // binding. Without this the binding stops at this server and the RS is back to trusting a
    // bearer string, which is the whole thing DPoP exists to stop.
    let introspected = srv
        .introspection_response(&ClientId::new("app"), Some(SECRET), &response.access_token)
        .await
        .unwrap();
    assert!(introspected.active);
    assert_eq!(introspected.token_type, Some(TokenType::Dpop));
    assert_eq!(
        introspected.cnf.expect("a bound token reports cnf").jkt,
        key.to_public_jwk().thumbprint(),
    );
}

#[tokio::test]
async fn a_request_with_no_proof_still_gets_an_ordinary_bearer_token() {
    // DPoP is opt-in per request unless the deployment requires it. A server that started refusing
    // unbound requests the moment the feature was compiled in would break every existing client.
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();
    let response = srv.token(request()).await.unwrap();
    assert_eq!(response.token_type, TokenType::Bearer);

    let introspected = srv
        .introspection_response(&ClientId::new("app"), Some(SECRET), &response.access_token)
        .await
        .unwrap();
    assert_eq!(introspected.token_type, Some(TokenType::Bearer));
    assert!(
        introspected.cnf.is_none(),
        "an unbound token must not claim a confirmation an RS would think it had checked"
    );
}

#[tokio::test]
async fn a_deployment_may_require_a_proof_on_every_token_request() {
    // The FAPI 2.0 posture. Off by default, because turning it on breaks every client of the
    // deployment and that has to be a decision somebody wrote down.
    let mut config = ServerConfig::new(ISSUER, "https://as.example/device");
    config.require_dpop = true;
    let srv = AuthorizationServer::new(config, MemoryStorage::new());
    srv.register_client(confidential_client()).await.unwrap();

    let refused = srv.token(request()).await.unwrap_err();
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    let key = EcdsaP256Key::generate("k");
    assert!(srv
        .token_with_context(request(), with_proof(&proof(&key, "p-1")))
        .await
        .is_ok());
}

// -------------------------------------------------------------------------------- THE REPLAY

#[tokio::test]
async fn the_same_proof_cannot_be_spent_twice() {
    // THE ATTACK. A DPoP proof is NOT a secret: it rides in a header on every request, so a reverse
    // proxy, a logging sidecar, a TLS terminator or anyone reading a request dump has a complete
    // copy, and it stays acceptable for the whole `iat` window. Without single-use tracking, that
    // copy is spendable: the holder cannot forge a proof for a key they do not have, but they do
    // not need to, because they already have one that verifies. RFC 9449 s4.3 (2) is the `jti`
    // check, and this is it.
    //
    // Both requests below are byte for byte identical.
    let key = EcdsaP256Key::generate("device");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();

    let captured = proof(&key, "spend-once");
    assert!(
        srv.token_with_context(request(), with_proof(&captured))
            .await
            .is_ok(),
        "the legitimate client must get its token"
    );
    let replay = srv
        .token_with_context(request(), with_proof(&captured))
        .await;
    assert_eq!(
        replay.unwrap_err().error,
        ErrorCode::InvalidDpopProof,
        "an observed proof must not be spendable a second time"
    );
}

#[tokio::test]
async fn a_fresh_proof_from_the_same_key_still_works_after_a_replay_was_refused() {
    // The defence refuses the REPLAY, not the key. Otherwise any observer could lock a client out
    // of its own key by replaying one proof.
    let key = EcdsaP256Key::generate("device");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();

    let first = proof(&key, "p-1");
    assert!(srv
        .token_with_context(request(), with_proof(&first))
        .await
        .is_ok());
    assert!(srv
        .token_with_context(request(), with_proof(&first))
        .await
        .is_err());
    assert!(srv
        .token_with_context(request(), with_proof(&proof(&key, "p-2")))
        .await
        .is_ok());
}

#[tokio::test]
async fn two_keys_may_use_the_same_jti() {
    // The replay set is namespaced by thumbprint, so one client cannot spend another's `jti` values
    // in advance. A `jti` is often a counter, so the collision is ordinary rather than exotic.
    let a = EcdsaP256Key::generate("a");
    let b = EcdsaP256Key::generate("b");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();
    assert!(srv
        .token_with_context(request(), with_proof(&proof(&a, "1")))
        .await
        .is_ok());
    assert!(srv
        .token_with_context(request(), with_proof(&proof(&b, "1")))
        .await
        .is_ok());
}

#[tokio::test]
async fn a_spent_proof_jti_is_reclaimed_by_the_host_s_sweep() {
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();
    assert!(srv
        .token_with_context(request(), with_proof(&proof(&key, "p-1")))
        .await
        .is_ok());
    let swept = srv
        .store()
        .sweep_expired(SystemTime::now() + Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(swept > 0, "a sweep past the proof window reclaims its jti");
}

// ------------------------------------------------------------------------ proof binding attacks

#[tokio::test]
async fn a_proof_captured_at_a_resource_server_cannot_be_spent_at_the_token_endpoint() {
    // The reason `htu` exists. The client sends a proof with EVERY resource-server request, so a
    // compromised or merely nosy resource server accumulates them by the thousand. If the token
    // endpoint accepted one, that resource server could mint fresh tokens for the client's key.
    let key = EcdsaP256Key::generate("device");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();

    let captured_at_the_rs = proof_for(&key, "p-1", "GET", "https://rs.example/orders/42");
    let refused = srv
        .token_with_context(request(), with_proof(&captured_at_the_rs))
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidDpopProof);
}

#[tokio::test]
async fn a_proof_for_the_right_endpoint_but_the_wrong_method_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(confidential_client()).await.unwrap();
    let refused = srv
        .token_with_context(
            request(),
            with_proof(&proof_for(&key, "p-1", "GET", TOKEN_ENDPOINT)),
        )
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidDpopProof);
}

#[tokio::test]
async fn the_proof_is_checked_against_the_token_endpoint_the_metadata_advertises() {
    // A host that moves its token endpoint moves what `htu` must be, because a conforming client
    // takes `htu` from the RFC 8414 document. If the two ever disagreed, this server would refuse
    // every conforming client and there would be nothing in the document to explain why.
    let mut config = ServerConfig::new(ISSUER, "https://as.example/device");
    config.token_endpoint = Some("https://as.example/oauth2/v1/token".to_string());
    let doc = AuthorizationServerMetadata::from_config(&config);
    let srv = AuthorizationServer::new(config, MemoryStorage::new());
    srv.register_client(confidential_client()).await.unwrap();

    let key = EcdsaP256Key::generate("k");
    assert!(
        srv.token_with_context(
            request(),
            with_proof(&proof_for(&key, "p-1", "POST", &doc.token_endpoint))
        )
        .await
        .is_ok(),
        "a proof built from the advertised token_endpoint must be accepted"
    );
    assert!(
        srv.token_with_context(
            request(),
            with_proof(&proof_for(&key, "p-2", "POST", TOKEN_ENDPOINT))
        )
        .await
        .is_err(),
        "and one built from the DEFAULT endpoint, which this server does not answer on, must not"
    );
}

// -------------------------------------------------------------------------- the refresh binding

/// A confidential client that gets a refresh token, so the chain binding can be exercised.
fn refreshing_client() -> Client {
    Client {
        grant_types: vec![
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
            GrantType::AuthorizationCode,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        ..confidential_client()
    }
}

/// Start a refresh chain, optionally bound to `key`, and return its refresh token.
///
/// Through the AUTHORIZATION CODE grant rather than `client_credentials`, because RFC 6749 s4.4.3
/// says the latter SHOULD NOT issue a refresh token and this crate honours that: a client holding
/// its own credentials can simply ask for another access token, so a refresh token there would be a
/// second long-lived secret bought for nothing.
async fn mint_refresh_token(
    srv: &AuthorizationServer<MemoryStorage>,
    key: Option<&EcdsaP256Key>,
    jti: &str,
) -> String {
    srv.register_client(refreshing_client()).await.unwrap();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = oauth_as::pkce::code_challenge_s256(verifier);
    let request = oauth_as::AuthorizationRequest {
        resource: Vec::new(),
        response_type: Some("code".into()),
        client_id: Some("app".into()),
        redirect_uri: Some(REDIRECT.into()),
        scope: Some("read".into()),
        state: Some("s".into()),
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".into()),
    };
    let validated = srv.validate_authorization_request(&request).await.unwrap();
    let code = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .unwrap()
        .code;

    let proof = key.map(|k| proof(k, jti));
    let context = match &proof {
        Some(proof) => with_proof(proof),
        None => TokenRequestContext::default(),
    };
    srv.token_with_context(
        TokenRequest::AuthorizationCode {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            code,
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: Some(verifier.to_string()),
        },
        context,
    )
    .await
    .unwrap()
    .refresh_token
    .expect("the authorization code grant issues a refresh token")
}

#[tokio::test]
async fn a_bound_refresh_chain_cannot_be_rebound_to_another_key() {
    // WITHOUT THIS THE BINDING IS DECORATIVE. An attacker who steals a DPoP-bound refresh token
    // holds a string; the access token it was issued with is useless to them, because they cannot
    // prove possession of the key. But if a rotation accepted a proof from a DIFFERENT key, the
    // thief simply presents their own: they get a fresh access token bound to THEIR key, and it is
    // the victim who is now unable to use the chain. RFC 9449 s5.
    let victim = EcdsaP256Key::generate("victim");
    let thief = EcdsaP256Key::generate("thief");
    let srv = server();
    let stolen = mint_refresh_token(&srv, Some(&victim), "seed").await;

    let refused = srv
        .token_with_context(
            TokenRequest::RefreshToken {
                client_id: ClientId::new("app"),
                client_secret: Some(SECRET.to_string()),
                refresh_token: stolen.clone(),
                scope: None,
            },
            with_proof(&proof(&thief, "thief-1")),
        )
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidDpopProof);

    // And the victim's chain is untouched: a refused rotation must not be a denial of service the
    // thief gets for free.
    assert!(
        srv.token_with_context(
            TokenRequest::RefreshToken {
                client_id: ClientId::new("app"),
                client_secret: Some(SECRET.to_string()),
                refresh_token: stolen,
                scope: None,
            },
            with_proof(&proof(&victim, "victim-2")),
        )
        .await
        .is_ok(),
        "the key the chain is bound to must still be able to rotate it"
    );
}

#[tokio::test]
async fn a_bound_refresh_chain_cannot_be_rotated_with_no_proof_at_all() {
    // The other half of the same attack, and the easier one: presenting no proof must not read as
    // "unbound", or a thief could simply omit the header.
    let victim = EcdsaP256Key::generate("victim");
    let srv = server();
    let stolen = mint_refresh_token(&srv, Some(&victim), "seed").await;
    let refused = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            refresh_token: stolen,
            scope: None,
        })
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidDpopProof);
}

#[tokio::test]
async fn an_unbound_refresh_chain_cannot_be_bound_by_presenting_a_proof_at_rotation() {
    // The mirror image. A chain issued without a proof was never bound to anything, and letting a
    // rotation attach a key would let whoever holds the string decide who owns it.
    let srv = server();
    let unbound = mint_refresh_token(&srv, None, "unused").await;

    let key = EcdsaP256Key::generate("opportunist");
    let refused = srv
        .token_with_context(
            TokenRequest::RefreshToken {
                client_id: ClientId::new("app"),
                client_secret: Some(SECRET.to_string()),
                refresh_token: unbound,
                scope: None,
            },
            with_proof(&proof(&key, "p-1")),
        )
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidDpopProof);
}

#[tokio::test]
async fn the_binding_survives_rotation() {
    // The rotated token is bound to the same key, so the chain stays sender-constrained rather than
    // reverting to bearer after the first refresh.
    let key = EcdsaP256Key::generate("device");
    let srv = server();
    let rt = mint_refresh_token(&srv, Some(&key), "seed").await;
    let rotated = srv
        .token_with_context(
            TokenRequest::RefreshToken {
                client_id: ClientId::new("app"),
                client_secret: Some(SECRET.to_string()),
                refresh_token: rt,
                scope: None,
            },
            with_proof(&proof(&key, "rot-1")),
        )
        .await
        .unwrap();
    assert_eq!(rotated.token_type, TokenType::Dpop);
    let introspected = srv
        .introspection_response(&ClientId::new("app"), Some(SECRET), &rotated.access_token)
        .await
        .unwrap();
    assert_eq!(
        introspected.cnf.unwrap().jkt,
        key.to_public_jwk().thumbprint()
    );
}

// ---------------------------------------------------------------------------------- the metadata

#[test]
fn the_metadata_advertises_the_proof_algorithms_and_nothing_it_would_refuse() {
    // RFC 9449 s5.1. Its PRESENCE is how a client learns DPoP is available at all, so what it lists
    // has to be exactly what the verifier will accept.
    let doc = AuthorizationServerMetadata::from_config(&ServerConfig::new(
        ISSUER,
        "https://as.example/device",
    ));
    let algs = doc
        .dpop_signing_alg_values_supported
        .expect("a server that verifies proofs advertises which algorithms it verifies");
    assert_eq!(algs, vec!["ES256".to_string()]);
    assert!(
        !algs.iter().any(|a| a == "none" || a.starts_with("HS")),
        "RFC 9449 s4.2 requires an asymmetric algorithm"
    );
}

#[test]
fn htu_of_is_the_comparison_the_rfc_describes() {
    assert_eq!(htu_of("https://as.example/token?x=1#f"), TOKEN_ENDPOINT);
}
