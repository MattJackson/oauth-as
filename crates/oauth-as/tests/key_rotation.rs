// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7517 section 4.5 / RFC 7515 section 4.1.4 signing key rotation (feature `jwt`).
//!
//! The whole point of a `kid` is that an authorization server can change which key it signs with
//! WITHOUT invalidating the tokens it already signed: the old public key stays in the JWKS, the
//! token names the key it was signed under, and a resource server picks that key rather than
//! trialling every advertised one. A server that can only ever publish one key has no rotation
//! story at all, scheduled or on compromise: at the instant of the swap every live token stops
//! verifying everywhere.
//!
//! So the property under test here is a LIFECYCLE, not a single call:
//!
//! 1. a token signed under key A verifies against the JWKS;
//! 2. after rotating to key B it STILL verifies, because A is published as retired;
//! 3. new tokens are signed under B, and only under B;
//! 4. once the host explicitly drops A, that same token STOPS verifying.
//!
//! Step 4 is asserted for the same reason steps 2 and 3 are. Dropping a key is the only
//! destructive operation in this file, and a test suite that only ever watched the safe steps
//! would not notice if dropping quietly did nothing.

#![cfg(feature = "jwt")]

use std::time::Duration;

use oauth_as::jwt::{
    verify_es256, AccessTokenClaims, AccessTokenFormat, Audience, CompactJws, EcdsaP256Key, Jwks,
    JwtConfig, PublicJwk,
};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ScopeSet,
    ServerConfig, TokenRequest,
};

// ---------------------------------------------------------------------------------------------
// A resource server, in miniature.
// ---------------------------------------------------------------------------------------------

/// Verify `token` the way RFC 7515 section 4.1.4 intends a relying party to: read the `kid` out of
/// the protected header, look up THAT key in the fetched JWKS, and verify under it. No trialling
/// of every key, because trialling every key is precisely the behaviour `kid` exists to remove and
/// a test that trialled would pass even if rotation published the wrong key set.
fn verifies_against(jwks: &Jwks, token: &str) -> bool {
    let jws = CompactJws::parse(token).expect("a token this crate signed must parse");
    let Some(kid) = jws.header_str("kid") else {
        panic!("RFC 9068 tokens from this crate always carry a kid");
    };
    let Some(jwk) = jwks.keys.iter().find(|k| k.kid == kid) else {
        return false;
    };
    // Round-tripped through JSON rather than field-by-field: this is what a resource server
    // actually has, the serialized document, and it keeps the test honest about the SERVED shape
    // of `Jwk` rather than about a struct only this crate can see.
    let public = PublicJwk::from_json(&serde_json::to_value(jwk).expect("a JWK serializes"))
        .expect("a served JWK must be acceptable as a verifying key");
    verify_es256(&public, jws.signing_input.as_bytes(), &jws.signature)
}

fn claims(jti: &str) -> AccessTokenClaims {
    AccessTokenClaims {
        iss: "https://as.example".to_string(),
        exp: 1_700_003_600,
        aud: Audience::One("https://api.example".to_string()),
        sub: "user-1".to_string(),
        client_id: "app".to_string(),
        iat: 1_700_000_000,
        jti: jti.to_string(),
        scope: None,
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        #[cfg(any(feature = "dpop", feature = "mtls"))]
        cnf: None,
    }
}

fn kids(jwks: &Jwks) -> Vec<String> {
    jwks.keys.iter().map(|k| k.kid.clone()).collect()
}

// ---------------------------------------------------------------------------------------------
// The lifecycle
// ---------------------------------------------------------------------------------------------

#[test]
fn a_token_signed_under_the_old_key_survives_rotation_and_dies_only_when_the_key_is_dropped() {
    let key_a = EcdsaP256Key::generate("key-a");
    let key_b = EcdsaP256Key::generate("key-b");

    let config = JwtConfig::new(key_a, "https://api.example");
    let signed_under_a = config.sign_access_token(&claims("jti-a")).unwrap();

    // Before any rotation the single-key case is exactly what it always was: one key, and it is
    // the one that signed.
    assert_eq!(kids(&config.jwks()), vec!["key-a".to_string()]);
    assert!(verifies_against(&config.jwks(), &signed_under_a));

    // Rotate. The host promotes B; A becomes retired, NOT deleted.
    let config = config.rotate_to(key_b);

    // RFC 7517 section 5 places no ordering requirement on `keys`, but the active key first is the
    // order that makes a naive verifier (one that takes the first `alg`-compatible key) right by
    // default for the tokens it is most likely to see.
    assert_eq!(
        kids(&config.jwks()),
        vec!["key-b".to_string(), "key-a".to_string()],
        "the JWKS must publish the active key and every retired key, active first"
    );
    assert_eq!(config.kid(), "key-b", "signing moves to the new active key");
    assert_eq!(
        config.retired_kids().collect::<Vec<_>>(),
        vec!["key-a"],
        "the previous active key is now retired"
    );

    // The point of the whole exercise: a token minted before the rotation is still good.
    assert!(
        verifies_against(&config.jwks(), &signed_under_a),
        "a token signed under the retired key must still verify after rotation"
    );

    // And new tokens are signed under B, so the two coexist.
    let signed_under_b = config.sign_access_token(&claims("jti-b")).unwrap();
    let header = CompactJws::parse(&signed_under_b).unwrap();
    assert_eq!(header.header_str("kid"), Some("key-b"));
    assert!(verifies_against(&config.jwks(), &signed_under_b));

    // Once the host is satisfied every token signed under A has expired, it drops A. That is the
    // destructive step, and it is destructive on purpose.
    let config = config.forget_retired_key_breaking_its_live_tokens("key-a");
    assert_eq!(kids(&config.jwks()), vec!["key-b".to_string()]);
    assert!(
        !verifies_against(&config.jwks(), &signed_under_a),
        "once the retired key is dropped its tokens must stop verifying"
    );
    assert!(
        verifies_against(&config.jwks(), &signed_under_b),
        "dropping a retired key must not touch the active one"
    );
}

/// Two rotations in a row: retirement accumulates in order, oldest last, and the active key is
/// never in the retired list. A host that rotates monthly and keeps an hour of overlap will hold
/// exactly one retired key; a host recovering from a compromise may briefly hold several.
#[test]
fn successive_rotations_accumulate_retired_keys_newest_first() {
    let config = JwtConfig::new(EcdsaP256Key::generate("k1"), "https://api.example")
        .rotate_to(EcdsaP256Key::generate("k2"))
        .rotate_to(EcdsaP256Key::generate("k3"));

    assert_eq!(config.kid(), "k3");
    assert_eq!(
        config.retired_kids().collect::<Vec<_>>(),
        vec!["k2", "k1"],
        "most recently retired first: it is the one with tokens still alive"
    );
    assert_eq!(
        kids(&config.jwks()),
        vec!["k3".to_string(), "k2".to_string(), "k1".to_string()]
    );
}

/// Rotating to a key whose `kid` matches one already published REPLACES that entry rather than
/// publishing the same name twice. Two JWKs sharing a `kid` make key selection ambiguous, which is
/// the exact failure `kid` exists to prevent (RFC 7517 section 4.5).
#[test]
fn a_reused_kid_never_appears_twice_in_the_key_set() {
    let config = JwtConfig::new(EcdsaP256Key::generate("k1"), "https://api.example")
        .rotate_to(EcdsaP256Key::generate("k2"))
        .rotate_to(EcdsaP256Key::generate("k1"));

    assert_eq!(config.kid(), "k1");
    assert_eq!(
        kids(&config.jwks()),
        vec!["k1".to_string(), "k2".to_string()]
    );
}

/// Dropping a `kid` that is not retired is a no-op, including the ACTIVE kid: a host that could
/// drop its own signing key by naming it would be one typo away from an AS that signs with a key
/// it does not publish, which is worse than the state it was trying to leave.
#[test]
fn dropping_an_unknown_or_active_kid_changes_nothing() {
    let config = JwtConfig::new(EcdsaP256Key::generate("k1"), "https://api.example")
        .rotate_to(EcdsaP256Key::generate("k2"))
        .forget_retired_key_breaking_its_live_tokens("k2")
        .forget_retired_key_breaking_its_live_tokens("nonexistent");

    assert_eq!(config.kid(), "k2");
    assert_eq!(
        kids(&config.jwks()),
        vec!["k2".to_string(), "k1".to_string()]
    );
}

// ---------------------------------------------------------------------------------------------
// Through the server
// ---------------------------------------------------------------------------------------------

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        // RFC 6749 section 4.4: `client_credentials` is a confidential-client grant, so this
        // fixture carries a secret even though the rotation property under test does not.
        auth: ClientAuth::ConfidentialSecret {
            secret: "s3cret".to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// `AuthorizationServer::jwks` is what the host actually serves, so the rotated key set has to
/// reach it. Asserted separately from the `JwtConfig` tests above because the server holds the
/// config behind `AccessTokenFormat::Jwt(Box<..>)` and a delegation that dropped the retired keys
/// on the way through would leave every unit test above green.
#[test]
fn the_served_key_set_carries_the_retired_keys() {
    let old = EcdsaP256Key::generate("old");
    let signed_under_old = JwtConfig::new(old.clone(), "https://api.example")
        .sign_access_token(&claims("jti-old"))
        .unwrap();

    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    config.access_token_ttl = Duration::from_secs(300);
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(
        JwtConfig::new(old, "https://api.example")
            .with_jwks_uri("https://as.example/jwks")
            .rotate_to(EcdsaP256Key::generate("new")),
    ));

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let served = rt.block_on(async {
        let srv = AuthorizationServer::new(config, MemoryStorage::new());
        srv.register_client(client()).await.unwrap();
        let issued = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("app"),
                client_secret: Some("s3cret".to_string()),
                scope: None,
            })
            .await
            .unwrap();
        (srv.jwks().unwrap(), issued.access_token)
    });
    let (jwks, fresh) = served;

    assert_eq!(kids(&jwks), vec!["new".to_string(), "old".to_string()]);
    assert!(
        verifies_against(&jwks, &signed_under_old),
        "the served key set must still verify tokens signed before the rotation"
    );
    assert_eq!(
        CompactJws::parse(&fresh).unwrap().header_str("kid"),
        Some("new")
    );
    assert!(verifies_against(&jwks, &fresh));
}
