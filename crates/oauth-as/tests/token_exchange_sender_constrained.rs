// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8693 token exchange must not launder a sender-constrained token into a bearer token.
//!
//! THE ATTACK, in full, because it is the only thing this file is about. Sender constraining (RFC
//! 9449 DPoP, RFC 8705 mutual TLS) is bought for exactly one property: a token that LEAKS is worth
//! nothing to whoever finds it, because spending it needs a private key or a client certificate
//! that never left the legitimate client. Token exchange is a grant that takes a token string and
//! hands back a different token. If the exchange ignores the subject token's binding, then anyone
//! who can authenticate as ANY client registered for the grant, an insider, a compromised
//! service, a leaked client secret, can post a stolen bound token and receive a plain bearer token
//! carrying the same subject, scope and audience. The binding is gone, the theft is now spendable,
//! and nothing in the exchange ever asked for proof of possession, because the exchanging client
//! does not hold the key and could not have produced any.
//!
//! So the rule this file pins: a sender-constrained subject token is REFUSED. RFC 8693 section
//! 2.2.2 makes `invalid_request` the answer for a subject token that is "unacceptable based on
//! policy", which this is. See the module docs in `src/token_exchange.rs` for why refusal rather
//! than propagating the `cnf` claim onto a client that cannot prove possession of the key.
#![cfg(feature = "token-exchange")]

mod support;

use oauth_as::{
    Client, ClientAuth, ClientId, GrantType, ScopeSet, TokenExchange, TokenExchangeRequest,
    TokenRequest, TokenTypeIdentifier,
};
// Used only by the two sender-constraining tests below, each behind its own feature. Imported
// under the union of those features rather than unconditionally, because an unused import is a
// warning and CI builds this crate with `-D warnings` under feature sets a local `--all-features`
// run never exercises.
#[cfg(any(all(feature = "dpop", feature = "jwt-p256"), feature = "mtls"))]
use oauth_as::{ErrorCode, TokenRequestContext};
use support::{server_with, ManualClock};

const VICTIM_SECRET: &str = "victim-client-secret-for-tests";
const GATEWAY_SECRET: &str = "gateway-client-secret-for-tests";

/// The client whose token is sender constrained: it holds the DPoP key, or the certificate, that
/// makes its token worthless to a thief.
fn victim() -> Client {
    Client {
        client_id: ClientId::new("victim"),
        auth: ClientAuth::ConfidentialSecret {
            secret: VICTIM_SECRET.to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// The exchanging client: perfectly legitimate, registered for the grant, and holding NEITHER the
/// victim's DPoP key nor its certificate. In the attack it is the compromised or hostile party.
fn gateway() -> Client {
    Client {
        client_id: ClientId::new("gateway"),
        auth: ClientAuth::ConfidentialSecret {
            secret: GATEWAY_SECRET.to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials, GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn victim_request() -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new("victim"),
        client_secret: Some(VICTIM_SECRET.to_string()),
        scope: None,
    }
}

fn exchange<'a>(stolen: &'a str, gateway_id: &'a ClientId) -> TokenExchangeRequest<'a> {
    let mut request =
        TokenExchangeRequest::new(gateway_id, stolen, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(GATEWAY_SECRET);
    request
}

/// RFC 9449: a DPoP-bound access token, exchanged, must not come back out as a bearer token.
// A signing KEY, so `jwt-p256` and not `dpop`: minting a proof needs an ES256 signer, and since
// the seam `dpop` implies only `jwt`, the trait surface with no curve arithmetic behind it.
// `EcdsaP256Key` is the built-in backend's type. Gated on `dpop` alone this file did not compile
// in any `dpop`-without-backend build, which nothing ever tried until the no-backend CI job
// gained the rest of the feature set.
#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
#[tokio::test]
async fn a_dpop_bound_subject_token_cannot_be_exchanged_into_a_bearer_token() {
    use oauth_as::jwt::{compact_jws, EcdsaP256Key};
    use oauth_as::Clock;
    use std::time::UNIX_EPOCH;

    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![victim(), gateway()]).await;

    // The victim gets a token bound to a key only it holds.
    let key = EcdsaP256Key::generate("victim-device");
    let iat = clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = serde_json::json!({
        "jti": "victim-proof-1",
        "htm": "POST",
        "htu": "https://as.example/token",
        "iat": iat,
    });
    let proof = compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    );
    let bound = srv
        .token_with_context(
            victim_request(),
            TokenRequestContext::default().with_dpop_proof(&proof),
        )
        .await
        .expect("the victim's own request is conforming");
    assert_eq!(bound.token_type, oauth_as::TokenType::Dpop);

    // The theft. The gateway holds the string and nothing else.
    let gateway_id = ClientId::new("gateway");
    let outcome = srv
        .exchange_token(&exchange(&bound.access_token, &gateway_id))
        .await;

    let error = outcome.expect_err(
        "exchanging a DPoP-bound token for an unbound one destroys the binding it was bought for",
    );
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

/// RFC 8705 section 3: the same rule for a certificate-bound token. A different mechanism with the
/// same purchase, so a fix that covered only DPoP would leave the whole of mutual TLS exposed.
#[cfg(feature = "mtls")]
#[tokio::test]
async fn a_certificate_bound_subject_token_cannot_be_exchanged_into_a_bearer_token() {
    use oauth_as::{ClientCertificate, ClientCredential};

    const VICTIM_DER: &[u8] = b"\x30\x82\x02\x0a--the-victim-client-certificate";

    let srv = server_with(ManualClock::at_epoch(), vec![victim(), gateway()]).await;

    let certificate = ClientCertificate::from_der(VICTIM_DER);
    let bound = srv
        .token_with_context(
            victim_request(),
            TokenRequestContext::new(ClientCredential::certificate(&certificate)),
        )
        .await
        .expect("the victim's own request is conforming");

    let gateway_id = ClientId::new("gateway");
    let outcome = srv
        .exchange_token(&exchange(&bound.access_token, &gateway_id))
        .await;

    let error = outcome
        .expect_err("exchanging a certificate-bound token for an unbound one destroys the binding");
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

/// The control, and it is load bearing: an UNBOUND subject token must still exchange. A fix that
/// refused every exchange would pass the two attacks above and break the grant.
#[tokio::test]
async fn an_unbound_subject_token_still_exchanges() {
    let srv = server_with(ManualClock::at_epoch(), vec![victim(), gateway()]).await;
    let plain = srv
        .token(victim_request())
        .await
        .expect("an ordinary client credentials request");

    let gateway_id = ClientId::new("gateway");
    srv.exchange_token(&exchange(&plain.access_token, &gateway_id))
        .await
        .expect("a bearer subject token has no binding to lose");
}
