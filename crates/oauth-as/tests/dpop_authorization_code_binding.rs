// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9449 section 10: the DPoP-bound authorization code, end to end through PAR.
//!
//! A code bound to a key at the authorization request (a DPoP proof at the PAR endpoint, or the
//! `dpop_jkt` parameter) may only be redeemed by proving THAT key at the token endpoint. Without it
//! the token binding starts only at redemption, so a code stolen in transit could be redeemed and
//! bound to the thief's key — the authorization-code injection DPoP is meant to stop. These are the
//! properties the FAPI 2.0 Security Profile modules `ensure-mismatched-dpop-jkt-fails` and
//! `ensure-token-endpoint-fails-with-mismatched-dpop-{proof-,}jkt` exercise.
#![cfg(all(feature = "par", feature = "dpop", feature = "jwt-p256"))]

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use oauth_as::jwt::{compact_jws, EcdsaP256Key};
use oauth_as::server::{ClientCredential, UserApproval};
use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType,
    MemoryStorage, ParConfig, ScopeSet, ServerConfig, TokenRequest, TokenRequestContext, TokenType,
};

const ISSUER: &str = "https://as.example";
const PAR_ENDPOINT: &str = "https://as.example/par";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const REDIRECT: &str = "https://app.example/cb";
const SECRET: &str = "confidential-client-secret";
// The RFC 7636 verifier whose S256 challenge the pushed request carries.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One RFC 9449 section 4.2 proof for `POST htu`, signed by `key`.
fn proof(key: &EcdsaP256Key, jti: &str, htu: &str) -> String {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = json!({ "jti": jti, "htm": "POST", "htu": htu, "iat": now_secs() });
    compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

fn server() -> AuthorizationServer<MemoryStorage> {
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    cfg.par = Some(Box::new(ParConfig::new()));
    // FAPI 2.0 posture: a proof is required on every token request, so the redemptions below all
    // carry one and the binding check is what distinguishes them.
    cfg.require_dpop = true;
    cfg.authorization_code_ttl = std::time::Duration::from_secs(300);
    AuthorizationServer::new(cfg, MemoryStorage::new())
}

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn push_params(challenge: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_string()),
        ("client_id", "app".to_string()),
        ("redirect_uri", REDIRECT.to_string()),
        ("scope", "read".to_string()),
        ("state", "s".to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ]
}

/// Push `params` (plus an optional extra `dpop_jkt` parameter) with a DPoP proof, resolve the
/// handle, and issue a code — returning the code and the request_uri result.
async fn push_and_issue(
    srv: &AuthorizationServer<MemoryStorage>,
    par_proof: &str,
    extra: &[(&str, String)],
) -> Result<String, ErrorCode> {
    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let mut params = push_params(&challenge);
    params.extend(extra.iter().map(|(k, v)| (*k, v.clone())));
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let pushed = srv
        .pushed_authorization_request_with_credential_and_proof(
            &ClientId::new("app"),
            &ClientCredential::secret(Some(SECRET)),
            &borrowed,
            Some(par_proof),
        )
        .await
        .map_err(|e| e.error)?;
    let validated = srv
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .expect("the pushed request validates");
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("a code is issued")
        .code;
    Ok(code)
}

fn redeem(code: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        code: code.to_string(),
        redirect_uri: Some(REDIRECT.to_string()),
        code_verifier: Some(VERIFIER.to_string()),
    }
}

#[tokio::test]
async fn a_code_bound_by_a_par_proof_is_redeemable_only_by_proving_that_key() {
    let bound_key = EcdsaP256Key::generate("bound");
    let other_key = EcdsaP256Key::generate("other");
    let srv = server();
    srv.register_client(client()).await.unwrap();

    let code = push_and_issue(&srv, &proof(&bound_key, "par-1", PAR_ENDPOINT), &[])
        .await
        .expect("the push binds the code and issues it");

    // A proof of a DIFFERENT key at the token endpoint is refused: the code is bound to `bound_key`.
    let refused = srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &other_key,
                "tok-other",
                TOKEN_ENDPOINT,
            )),
        )
        .await
        .expect_err("a mismatched DPoP key must not redeem a bound code");
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    // The refusal put the code back (a mismatch is retryable, not a burned code), so the matching
    // key still redeems it, and the issued token binds to that key.
    let ok = srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &bound_key,
                "tok-bound",
                TOKEN_ENDPOINT,
            )),
        )
        .await
        .expect("the bound key redeems the code");
    assert_eq!(ok.token_type, TokenType::Dpop);
    let introspected = srv
        .introspection_response(&ClientId::new("app"), Some(SECRET), &ok.access_token)
        .await
        .unwrap();
    assert_eq!(
        introspected.cnf.unwrap().jkt,
        Some(bound_key.to_public_jwk().thumbprint())
    );
}

#[tokio::test]
async fn a_par_push_refuses_a_dpop_jkt_parameter_that_disagrees_with_the_proof() {
    // RFC 9449 s10.1: if the pushed request carries BOTH a `dpop_jkt` parameter and a DPoP proof,
    // the parameter must equal the proof's key thumbprint.
    let proof_key = EcdsaP256Key::generate("proof");
    let declared_key = EcdsaP256Key::generate("declared");
    let srv = server();
    srv.register_client(client()).await.unwrap();

    let refused = push_and_issue(
        &srv,
        &proof(&proof_key, "par-mismatch", PAR_ENDPOINT),
        &[("dpop_jkt", declared_key.to_public_jwk().thumbprint())],
    )
    .await
    .expect_err("a dpop_jkt parameter disagreeing with the proof must be refused at PAR");
    assert_eq!(refused, ErrorCode::InvalidDpopProof);

    // The SAME key in both places is accepted, and binds the code (redeemable by that key).
    let code = push_and_issue(
        &srv,
        &proof(&proof_key, "par-agree", PAR_ENDPOINT),
        &[("dpop_jkt", proof_key.to_public_jwk().thumbprint())],
    )
    .await
    .expect("a matching dpop_jkt parameter and proof are accepted");
    assert!(srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &proof_key,
                "tok-agree",
                TOKEN_ENDPOINT
            )),
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn a_dpop_jkt_parameter_on_a_plain_authorize_request_binds_the_code() {
    // RFC 9449 s10: the `dpop_jkt` binding also reaches the code through the PLAIN (non-PAR)
    // authorization request, not only through a PAR push. This exercises
    // validate_authorization_request -> issue_authorization_code -> redemption for that route so a
    // regression that threaded `dpop_jkt` only through the PAR struct would be caught.
    let bound_key = EcdsaP256Key::generate("bound");
    let other_key = EcdsaP256Key::generate("other");
    let srv = server();
    srv.register_client(client()).await.unwrap();

    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let mut request = AuthorizationRequest::default();
    request.response_type = Some("code".into());
    request.client_id = Some("app".into());
    request.redirect_uri = Some(REDIRECT.into());
    request.scope = Some("read".into());
    request.state = Some("s".into());
    request.code_challenge = Some(challenge.into());
    request.code_challenge_method = Some("S256".into());
    request.dpop_jkt = Some(bound_key.to_public_jwk().thumbprint().into());

    let validated = srv
        .validate_authorization_request(&request)
        .await
        .expect("the plain authorization request validates");
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("a code is issued")
        .code;

    let refused = srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &other_key,
                "tok-other",
                TOKEN_ENDPOINT,
            )),
        )
        .await
        .expect_err("a mismatched DPoP key must not redeem a code the query parameter bound");
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    let ok = srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &bound_key,
                "tok-bound",
                TOKEN_ENDPOINT,
            )),
        )
        .await
        .expect("the declared key redeems the code");
    assert_eq!(ok.token_type, TokenType::Dpop);
    let introspected = srv
        .introspection_response(&ClientId::new("app"), Some(SECRET), &ok.access_token)
        .await
        .unwrap();
    assert_eq!(
        introspected.cnf.unwrap().jkt,
        Some(bound_key.to_public_jwk().thumbprint())
    );
}

#[tokio::test]
async fn a_par_dpop_jkt_parameter_without_a_proof_binds_the_code() {
    // RFC 9449 s10: a PAR push MAY carry a `dpop_jkt` parameter with NO DPoP proof at the PAR
    // endpoint (the proof is optional there; `require_dpop` is enforced at the token endpoint). The
    // parameter alone must bind the code, so `bind_par_dpop`'s no-proof early return must leave the
    // declared binding intact through to redemption. The other PAR tests always send a proof, so
    // this guards the parameter-only branch end to end.
    let bound_key = EcdsaP256Key::generate("bound");
    let other_key = EcdsaP256Key::generate("other");
    let srv = server();
    srv.register_client(client()).await.unwrap();

    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let mut params = push_params(&challenge);
    params.push(("dpop_jkt", bound_key.to_public_jwk().thumbprint()));
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // Deliberately NO proof at the PAR endpoint (the last argument is `None`).
    let pushed = srv
        .pushed_authorization_request_with_credential_and_proof(
            &ClientId::new("app"),
            &ClientCredential::secret(Some(SECRET)),
            &borrowed,
            None,
        )
        .await
        .map_err(|e| e.error)
        .expect("a parameter-only push (no proof) is accepted");
    let validated = srv
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .expect("the pushed request validates");
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("a code is issued")
        .code;

    let refused = srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &other_key,
                "tok-other",
                TOKEN_ENDPOINT,
            )),
        )
        .await
        .expect_err("a mismatched DPoP key must not redeem a parameter-bound code");
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    let ok = srv
        .token_with_context(
            redeem(&code),
            TokenRequestContext::default().with_dpop_proof(&proof(
                &bound_key,
                "tok-bound",
                TOKEN_ENDPOINT,
            )),
        )
        .await
        .expect("the declared key redeems the code");
    assert_eq!(ok.token_type, TokenType::Dpop);
    let introspected = srv
        .introspection_response(&ClientId::new("app"), Some(SECRET), &ok.access_token)
        .await
        .unwrap();
    assert_eq!(
        introspected.cnf.unwrap().jkt,
        Some(bound_key.to_public_jwk().thumbprint())
    );
}
