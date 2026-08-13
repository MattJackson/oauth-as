// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! ONE CLIENT MUST NOT BE ABLE TO SPEND ANOTHER CLIENT'S SINGLE-USE SLOT.
//!
//! The RFC 7523 section 3 replay defence claims a storage key per `(client, jti)` pair. If two
//! different pairs can produce the SAME key, the defence turns into a weapon: whoever claims the
//! key first denies it to the other, and the victim's perfectly conforming assertion comes back
//! `invalid_client`. The victim cannot fix it, because the colliding value is the attacker's
//! registration and the attacker's `jti`, neither of which the victim can see.
//!
//! The attack the tests below run is exactly the one the encoding has to make impossible:
//!
//! - the victim is registered as `urn:client:foo` and sends `jti` `42`,
//! - the attacker registers as `urn` (a client id this server accepts: `ClientId::new` imposes
//!   no character restriction, and URN-shaped client ids are ordinary) and sends `jti`
//!   `client:foo:42`.
//!
//! Under a `kind:owner:jti` concatenation with an unescaped separator, both produce
//! `ca:urn:client:foo:42`. The attacker goes first, and the victim is refused as a replayer of an
//! assertion nobody sent.
//!
//! HS256 throughout, so this file needs no ES256 backend and runs in every `client-assertion`
//! build.

#![cfg(feature = "client-assertion")]

use std::time::{SystemTime, UNIX_EPOCH};

use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey};
use oauth_as::jwt::{compact_jws, hmac_sha256};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientCredential, ClientId, GrantType, MemoryStorage,
    ScopeSet, ServerConfig, TokenRequest, TokenRequestContext, CLIENT_ASSERTION_TYPE,
};

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";

/// The victim: a URN-style client id, which is what makes the colliding split available.
const VICTIM: &str = "urn:client:foo";
/// The attacker: a registration whose id is a PREFIX of the victim's, up to the separator.
const ATTACKER: &str = "urn";

const VICTIM_SECRET: &str = "victim-high-entropy-registered-secret";
const ATTACKER_SECRET: &str = "attacker-high-entropy-registered-secret";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn assertion(client_id: &str, secret: &str, jti: &str) -> String {
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": TOKEN_ENDPOINT,
        "exp": now_secs() + 120,
        "iat": now_secs(),
        "jti": jti,
    });
    compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).unwrap(),
        |input| hmac_sha256(secret.as_bytes(), input.as_bytes()).to_vec(),
    )
}

async fn server() -> AuthorizationServer<MemoryStorage> {
    let srv = AuthorizationServer::new(
        ServerConfig::new(ISSUER, "https://as.example/device"),
        MemoryStorage::new(),
    );
    for (id, secret) in [(VICTIM, VICTIM_SECRET), (ATTACKER, ATTACKER_SECRET)] {
        srv.register_client(Client {
            client_id: ClientId::new(id),
            auth: ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::ClientSecret {
                    secret: ClientSecretKey::new(secret).expect("fixture secrets clear the floor"),
                },
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .expect("both fixture registrations are well formed");
    }
    srv
}

fn request(client_id: &str) -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new(client_id),
        client_secret: None,
        scope: None,
    }
}

fn context(assertion: &str) -> TokenRequestContext<'_> {
    TokenRequestContext::new(ClientCredential::assertion(
        Some(CLIENT_ASSERTION_TYPE),
        assertion,
    ))
}

/// THE ATTACK. The attacker authenticates first with a `jti` chosen to land on the victim's
/// storage key; the victim's own assertion must still authenticate.
#[tokio::test]
async fn one_client_cannot_spend_another_clients_single_use_slot() {
    let srv = server().await;

    let attackers = assertion(ATTACKER, ATTACKER_SECRET, "client:foo:42");
    srv.token_with_context(request(ATTACKER), context(&attackers))
        .await
        .expect("the attacker's own assertion is valid for the attacker's own registration");

    let victims = assertion(VICTIM, VICTIM_SECRET, "42");
    srv.token_with_context(request(VICTIM), context(&victims))
        .await
        .expect(
            "the victim's jti was never used by the victim, so this must not be read as a replay",
        );
}

/// The same collision in the other direction: the victim goes first and the attacker's request is
/// what gets refused. Asserted because a single-use defence that silently depends on the ORDER
/// requests arrive in is a defence whose behaviour nobody can state.
#[tokio::test]
async fn the_collision_does_not_depend_on_who_arrives_first() {
    let srv = server().await;

    let victims = assertion(VICTIM, VICTIM_SECRET, "42");
    srv.token_with_context(request(VICTIM), context(&victims))
        .await
        .expect("the victim's assertion is valid");

    let attackers = assertion(ATTACKER, ATTACKER_SECRET, "client:foo:42");
    srv.token_with_context(request(ATTACKER), context(&attackers))
        .await
        .expect("a different client's jti is a different single-use identifier");
}

/// The property the collision test would be worthless without: within ONE registration the `jti`
/// is still single use, so the fix cannot be "stop claiming the key".
#[tokio::test]
async fn a_jti_is_still_single_use_within_one_registration() {
    let srv = server().await;
    let first = assertion(VICTIM, VICTIM_SECRET, "reused");
    srv.token_with_context(request(VICTIM), context(&first))
        .await
        .expect("the first use authenticates");
    srv.token_with_context(request(VICTIM), context(&first))
        .await
        .expect_err("RFC 7523 s3: the same jti twice is a replay");
}
