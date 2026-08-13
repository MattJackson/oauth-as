// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7523 JWT client authentication, end to end through the token endpoint.
//!
//! `src/tests/client_assertion.rs` tests the VALIDATOR in isolation. This file tests the thing a
//! deployment actually cares about: that a client holding only a key can get a token, that a client
//! holding the wrong thing cannot, and above all that an assertion is single use. The replay test
//! here is the one that matters most, because an implementation that verifies the signature and
//! forgets the `jti` passes every other test in both files while shipping a credential anybody who
//! observed one request can send again.
#![cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
// Requires `jwt-p256`, the built-in ES256 backend, because every test below has to PRODUCE a
// signature. `jwt` alone carries the `Es256Signer`/`Es256Verifier` seam and no curve arithmetic at
// all, so in that build there is nothing here that could run.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey, CLIENT_ASSERTION_TYPE};
use oauth_as::jwt::{compact_jws, hmac_sha256, EcdsaP256Key};
use oauth_as::{
    AuthorizationServer, AuthorizationServerMetadata, Client, ClientAuth, ClientCredential,
    ClientId, ErrorCode, GrantType, MemoryStorage, ScopeSet, ServerConfig, Storage, TokenRequest,
    TokenRequestContext,
};

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const SECRET: &str = "a-high-entropy-registered-client-secret";

fn server() -> AuthorizationServer<MemoryStorage> {
    AuthorizationServer::new(
        ServerConfig::new(ISSUER, "https://as.example/device"),
        MemoryStorage::new(),
    )
}

fn client(id: &str, auth: ClientAuth) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth,
        grant_types: vec![GrantType::ClientCredentials],
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

/// A conforming RFC 7523 section 3 claim set for `client_id`, with the caller's own `jti`.
fn claims(client_id: &str, jti: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": TOKEN_ENDPOINT,
        "exp": now_secs() + 120,
        "iat": now_secs(),
        "jti": jti,
    })
}

fn sign_hs256(secret: &str, claims: &serde_json::Value) -> String {
    compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(claims).unwrap(),
        |input| hmac_sha256(secret.as_bytes(), input.as_bytes()).to_vec(),
    )
}

fn sign_es256(key: &EcdsaP256Key, claims: &serde_json::Value) -> String {
    compact_jws(
        br#"{"alg":"ES256","typ":"JWT"}"#,
        &serde_json::to_vec(claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

fn request(client_id: &str) -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new(client_id),
        client_secret: None,
        scope: None,
    }
}

fn context<'a>(assertion: &'a str) -> TokenRequestContext<'a> {
    TokenRequestContext::new(ClientCredential::assertion(
        Some(CLIENT_ASSERTION_TYPE),
        assertion,
    ))
}

/// Sign with a header the caller chooses, so a test can put a `crit` in it.
fn sign_hs256_with_header(secret: &str, header: &[u8], claims: &serde_json::Value) -> String {
    compact_jws(header, &serde_json::to_vec(claims).unwrap(), |input| {
        hmac_sha256(secret.as_bytes(), input.as_bytes()).to_vec()
    })
}

/// RFC 7515 section 4.1.11: a JWS whose header names an extension the recipient does not
/// implement is INVALID, and the signature being genuine is exactly why that matters.
///
/// The assertion below is signed correctly with the right secret and carries valid claims. What it
/// also carries is a `crit` naming `b64` (RFC 7797), which is the producer stating that the
/// payload is NOT base64url-encoded and that understanding this is REQUIRED to process the JWS.
/// A verifier that ignores `crit` therefore verifies a different message from the one the producer
/// signed, which is the class RFC 8725 section 3.10 names.
///
/// Until the 0.9.1 audit this rule was implemented once, for request objects in `par.rs`, while
/// client assertions and DPoP proofs — also attacker-supplied JWS, also parsed by `CompactJws` —
/// checked `typ` and `alg` and nothing else. One hardened reader and two unhardened ones is the
/// shape that produced this crate's earlier `claim_time` defect.
#[tokio::test]
async fn an_assertion_whose_header_names_an_unknown_crit_extension_is_refused() {
    let srv = server();
    srv.register_client(client(
        "critter",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::ClientSecret {
                secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
            },
        },
    ))
    .await
    .unwrap();

    let assertion = sign_hs256_with_header(
        SECRET,
        br#"{"alg":"HS256","typ":"JWT","crit":["b64"],"b64":false}"#,
        &claims("critter", "crit-1"),
    );
    let refused = srv
        .token_with_context(request("critter"), context(&assertion))
        .await
        .expect_err("a crit naming an unimplemented extension must be refused");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

/// The other half of RFC 7515 section 4.1.11: an EMPTY `crit` is forbidden by the RFC itself,
/// independently of which extensions a recipient implements. Without this, "no names I do not
/// understand" would read as acceptable.
#[tokio::test]
async fn an_assertion_whose_header_has_an_empty_crit_is_refused() {
    let srv = server();
    srv.register_client(client(
        "critter-empty",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::ClientSecret {
                secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
            },
        },
    ))
    .await
    .unwrap();

    let assertion = sign_hs256_with_header(
        SECRET,
        br#"{"alg":"HS256","typ":"JWT","crit":[]}"#,
        &claims("critter-empty", "crit-2"),
    );
    let refused = srv
        .token_with_context(request("critter-empty"), context(&assertion))
        .await
        .expect_err("an empty crit is forbidden by RFC 7515 s4.1.11");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

// ------------------------------------------------------------------------------- the happy path

#[tokio::test]
async fn a_private_key_jwt_client_gets_a_token_without_ever_holding_a_shared_secret() {
    // The whole point of the feature: this server holds only the PUBLIC half, so a dump of its
    // client table contains nothing that can authenticate as this client.
    let key = EcdsaP256Key::generate("client-key");
    let srv = server();
    srv.register_client(client(
        "pkjwt",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();

    let assertion = sign_es256(&key, &claims("pkjwt", "a-1"));
    let response = srv
        .token_with_context(request("pkjwt"), context(&assertion))
        .await
        .expect("a conforming assertion authenticates the client");
    assert!(!response.access_token.is_empty());
}

#[tokio::test]
async fn a_client_secret_jwt_client_gets_a_token_without_transmitting_its_secret() {
    let srv = server();
    srv.register_client(client(
        "csjwt",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::ClientSecret {
                secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
            },
        },
    ))
    .await
    .unwrap();

    let assertion = sign_hs256(SECRET, &claims("csjwt", "a-1"));
    assert!(srv
        .token_with_context(request("csjwt"), context(&assertion))
        .await
        .is_ok());
}

// -------------------------------------------------------------------------------- THE REPLAY

#[tokio::test]
async fn the_same_assertion_cannot_be_spent_twice() {
    // THE ATTACK RFC 7523 SECTION 3 EXISTS TO STOP. A client assertion is not a secret in the way a
    // client secret is: it is sent over the wire, and anything on the path (a reverse proxy, a
    // logging sidecar, a compromised TLS terminator, an operator reading a request dump) has a
    // complete copy. It is still valid for as long as its own `exp` says. Without single-use
    // tracking, whoever holds that copy can authenticate as the client, repeatedly, until it
    // expires, and nothing in the signature check would notice: the assertion IS genuine, and that
    // is precisely the problem.
    //
    // Both requests below are byte for byte identical. The first must succeed and the second must
    // not.
    let key = EcdsaP256Key::generate("client-key");
    let srv = server();
    srv.register_client(client(
        "replay-me",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();

    let assertion = sign_es256(&key, &claims("replay-me", "spend-once"));

    let first = srv
        .token_with_context(request("replay-me"), context(&assertion))
        .await;
    assert!(first.is_ok(), "the legitimate client must get its token");

    let replay = srv
        .token_with_context(request("replay-me"), context(&assertion))
        .await;
    assert_eq!(
        replay.unwrap_err().error,
        ErrorCode::InvalidClient,
        "an observed assertion must not be spendable a second time"
    );
}

#[tokio::test]
async fn a_fresh_jti_from_the_same_client_still_works_after_a_replay_was_refused() {
    // The defence must refuse the REPLAY, not the client. A server that locked the client out after
    // a replayed assertion would hand any observer a denial of service for free.
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(client(
        "still-fine",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();

    let first = sign_es256(&key, &claims("still-fine", "jti-1"));
    assert!(srv
        .token_with_context(request("still-fine"), context(&first))
        .await
        .is_ok());
    assert!(srv
        .token_with_context(request("still-fine"), context(&first))
        .await
        .is_err());

    let second = sign_es256(&key, &claims("still-fine", "jti-2"));
    assert!(
        srv.token_with_context(request("still-fine"), context(&second))
            .await
            .is_ok(),
        "a fresh jti from the same client must still authenticate"
    );
}

#[tokio::test]
async fn two_clients_may_use_the_same_jti_without_locking_each_other_out() {
    // The replay set is namespaced by client id. Without that, a client numbering its assertions
    // from a counter (which is a perfectly legal `jti`) could spend another client's future values
    // in advance: a denial of service bought for the price of one refused request.
    let key_a = EcdsaP256Key::generate("a");
    let key_b = EcdsaP256Key::generate("b");
    let srv = server();
    for (id, key) in [("client-a", &key_a), ("client-b", &key_b)] {
        srv.register_client(client(
            id,
            ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::PublicKeys {
                    keys: vec![key.to_public_jwk()],
                },
            },
        ))
        .await
        .unwrap();
    }
    let a = sign_es256(&key_a, &claims("client-a", "1"));
    let b = sign_es256(&key_b, &claims("client-b", "1"));
    assert!(srv
        .token_with_context(request("client-a"), context(&a))
        .await
        .is_ok());
    assert!(
        srv.token_with_context(request("client-b"), context(&b))
            .await
            .is_ok(),
        "another client's identical jti must not have been spent"
    );
}

/// THE SWEEP INSTANT IS CHOSEN SO THAT ONLY THE `jti` IS DEAD, and that is the whole test.
///
/// `Storage::sweep_expired` returns ONE aggregate across every collection it walks, and the token
/// request below also stored an access token with the default 3600 second TTL. A sweep at
/// `now + 3600` therefore reports at least one removal whether or not the replay set was ever
/// written to: making `claim_replay_id` a no-op left that assertion green. The assertion's `exp`
/// is `now + 120` and the replay entry is remembered until exactly that, so at `now + 300` the
/// claimed `jti` is the ONLY dead record in the store and the count is exactly one. The second
/// sweep is what pins that reading: it reclaims the access token, so the two ones are two
/// different records rather than the same one counted twice.
#[tokio::test]
async fn a_spent_jti_is_reclaimed_by_the_host_s_sweep() {
    // Nothing in this crate evicts anything on a timer (see the crate docs), so the replay set is
    // reclaimed the same way every other retained record is: when the HOST sweeps. A host that
    // never sweeps has a set that only grows, which is why `MAX_ASSERTION_LIFETIME` caps how long
    // any single entry can be made to live.
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(client(
        "sweepable",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();
    let assertion = sign_es256(&key, &claims("sweepable", "sweep-1"));
    let issued_at = SystemTime::now();
    assert!(srv
        .token_with_context(request("sweepable"), context(&assertion))
        .await
        .is_ok());

    let swept = srv
        .store()
        .sweep_expired(issued_at + Duration::from_secs(300))
        .await
        .unwrap();
    assert_eq!(
        swept, 1,
        "past the assertion's own exp and inside the access token's TTL, the claimed jti is the \
         one record a sweep may reclaim"
    );

    let later = srv
        .store()
        .sweep_expired(issued_at + Duration::from_secs(3601))
        .await
        .unwrap();
    assert_eq!(
        later, 1,
        "and the access token is still there to be reclaimed afterwards, which is what makes the \
         count above the jti and not the token"
    );
}

// ------------------------------------------------------------------------------ downgrade attacks

#[tokio::test]
async fn a_client_registered_for_an_assertion_cannot_authenticate_with_a_secret() {
    // THE DOWNGRADE. A registration that says `private_key_jwt` is a statement that this client's
    // credential is a key; if a `client_secret_post` guess could also authenticate it, the
    // registration would be advice rather than a rule.
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(client(
        "keys-only",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::ClientSecret {
                secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
            },
        },
    ))
    .await
    .unwrap();
    let _ = key;

    // Even the RIGHT secret, presented the ordinary way, is not this registration's credential.
    let refused = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("keys-only"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidClient);
}

#[tokio::test]
async fn a_client_registered_for_a_secret_cannot_promote_itself_with_an_assertion() {
    // The mirror image. An attacker who can mint assertions (for instance because they know a
    // client secret that is ALSO the HMAC key) must not be able to authenticate a registration this
    // server holds no assertion key for. The registration decides, always.
    let srv = server();
    srv.register_client(client(
        "secret-only",
        ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
    ))
    .await
    .unwrap();

    let assertion = sign_hs256(SECRET, &claims("secret-only", "a-1"));
    let refused = srv
        .token_with_context(request("secret-only"), context(&assertion))
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidClient);
}

#[tokio::test]
async fn presenting_a_secret_and_an_assertion_together_is_refused() {
    // RFC 6749 s2.3: one authentication method per request. A server that resolves the ambiguity by
    // precedence behaves differently from the next server, and that difference is what a request
    // smuggling intermediary would aim at.
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(client(
        "both",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();

    let assertion = sign_es256(&key, &claims("both", "a-1"));
    let mut credential = ClientCredential::assertion(Some(CLIENT_ASSERTION_TYPE), &assertion);
    credential.client_secret = Some(SECRET);
    let refused = srv
        .token_with_context(request("both"), TokenRequestContext::new(credential))
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidClient);
}

#[tokio::test]
async fn an_assertion_with_the_wrong_or_missing_client_assertion_type_is_refused() {
    // RFC 7521 s4.2. An assertion whose format nobody declared is a credential this server cannot
    // check, and "cannot check" must never read as "checked out".
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(client(
        "typed",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();
    let assertion = sign_es256(&key, &claims("typed", "a-1"));

    for wrong in [None, Some("urn:example:saml2-bearer"), Some("")] {
        let refused = srv
            .token_with_context(
                request("typed"),
                TokenRequestContext::new(ClientCredential::assertion(wrong, &assertion)),
            )
            .await;
        assert_eq!(
            refused.unwrap_err().error,
            ErrorCode::InvalidClient,
            "client_assertion_type {wrong:?} must be refused"
        );
    }
}

#[tokio::test]
async fn an_assertion_from_one_client_cannot_authenticate_another() {
    // Two registrations sharing a `client_secret_jwt` secret is a deployment mistake, and a common
    // one. RFC 7523 s3 (1) and (2) are what keep it from being an impersonation: the `iss` and
    // `sub` name a client, and this server checks them against the client the request claims to be.
    let srv = server();
    for id in ["twin-a", "twin-b"] {
        srv.register_client(client(
            id,
            ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::ClientSecret {
                    secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
                },
            },
        ))
        .await
        .unwrap();
    }
    // Signed correctly, and with a secret `twin-b` genuinely shares, but claiming to be `twin-a`.
    let assertion = sign_hs256(SECRET, &claims("twin-a", "a-1"));
    let refused = srv
        .token_with_context(request("twin-b"), context(&assertion))
        .await;
    assert_eq!(refused.unwrap_err().error, ErrorCode::InvalidClient);
}

#[tokio::test]
async fn an_unknown_client_and_a_bad_assertion_are_the_same_answer_on_the_wire() {
    // RFC 6749 s5.2 `invalid_client`, with no description in either case: a description naming
    // which check failed would tell an attacker that the client id they guessed is real.
    let key = EcdsaP256Key::generate("k");
    let srv = server();
    srv.register_client(client(
        "known",
        ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![key.to_public_jwk()],
            },
        },
    ))
    .await
    .unwrap();

    let foreign = EcdsaP256Key::generate("attacker");
    let bad = sign_es256(&foreign, &claims("known", "a-1"));
    let for_known = srv
        .token_with_context(request("known"), context(&bad))
        .await
        .unwrap_err();

    let unknown = sign_es256(&foreign, &claims("nobody", "a-1"));
    let for_unknown = srv
        .token_with_context(request("nobody"), context(&unknown))
        .await
        .unwrap_err();

    assert_eq!(for_known, for_unknown);
}

// ---------------------------------------------------------------------------------- the metadata

#[test]
fn the_metadata_advertises_both_methods_and_the_algorithms_that_go_with_them() {
    // RFC 8414 s2 makes `token_endpoint_auth_signing_alg_values_supported` REQUIRED once either JWT
    // method is advertised, and the requirement is practical: a client cannot construct an
    // assertion without knowing which algorithm the server will accept.
    let doc = AuthorizationServerMetadata::from_config(&ServerConfig::new(
        ISSUER,
        "https://as.example/device",
    ));
    for method in ["client_secret_jwt", "private_key_jwt"] {
        assert!(
            doc.token_endpoint_auth_methods_supported
                .iter()
                .any(|m| m == method),
            "{method} must be advertised"
        );
    }
    let algs = doc
        .token_endpoint_auth_signing_alg_values_supported
        .expect("advertised methods require advertised algorithms");
    assert!(algs.iter().any(|a| a == "HS256"));
    assert!(algs.iter().any(|a| a == "ES256"));
    assert!(
        !algs.iter().any(|a| a == "none"),
        "`none` must never be advertised as a signing algorithm"
    );
}
