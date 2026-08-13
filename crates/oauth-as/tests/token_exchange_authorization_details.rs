// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8693 exchange meets RFC 9396 `authorization_details`: the cross-client escalation.
//!
//! Through 0.9.0 the exchange applied TWO ceilings to scope (the subject token's granted scope, and
//! the exchanging client's own registration) and ZERO to `authorization_details`, which it copied
//! from the subject token onto the issued token unchanged. The issued token belongs to a DIFFERENT
//! principal than the subject token, so that copy is the registration boundary crossed by a bearer
//! string, and it is crossed with the one thing a scope string cannot express: "transfer 50 euros to
//! this account".
//!
//! The fixture is the real topology this grant exists for. A resource owner approves a payment at
//! payments client `payments-v`. Downstream microservice `svc-a` is an ordinary confidential client
//! registered for `read` and for the token-exchange grant, and it legitimately RECEIVES the caller's
//! token, because forwarding the caller's token is what this grant is for. It exchanges that token
//! for one of its own, asking for nothing but `read`. Both scope ceilings pass. What comes back must
//! not be a token in `svc-a`'s name that can initiate the payment.

#![cfg(all(feature = "token-exchange", feature = "rar"))]

mod support;

use std::time::{Duration, UNIX_EPOCH};

use oauth_as::rar::AuthorizationDetails;
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType, IssuedToken,
    MemoryStorage, ScopeSet, ServerConfig, Storage, TokenExchange, TokenExchangeRequest,
    TokenTypeIdentifier,
};
use support::ManualClock;

const SERVICE_SECRET: &str = "downstream-service-secret-for-tests";
const SUBJECT_TOKEN: &str = "the-payment-token-svc-a-was-handed";

/// What the resource owner approved AT THE PAYMENTS CLIENT, and nowhere else. The amount and the
/// creditor live in `other`, which this crate carries unchanged precisely because it has no
/// vocabulary for them (RFC 9396 section 2).
const APPROVED_PAYMENT: &str = r#"[{"type":"payment_initiation","actions":["initiate"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"},"creditorAccount":{"iban":"DE02100100109307118603"}}]"#;

/// The payments client the owner actually authorized. Registered so the fixture is the real
/// topology rather than a token with an invented issuer.
fn payments_client() -> Client {
    Client {
        client_id: ClientId::new("payments-v"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "payments-client-secret-for-tests".into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// The downstream microservice. An ORDINARY client: `read` only, and the token-exchange grant,
/// which is the whole of what a deployment gives a service that has to call on behalf of its
/// caller. Nothing here says it may move money.
fn downstream_service() -> Client {
    Client {
        client_id: ClientId::new("svc-a"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SERVICE_SECRET.into(),
        },
        grant_types: vec![GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server() -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.authorization_details_types_supported = Some(vec!["payment_initiation".to_string()]);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(payments_client()).await.unwrap();
    srv.register_client(downstream_service()).await.unwrap();
    srv
}

/// The token the owner's browser obtained at `payments-v` and that `payments-v` forwarded on the
/// call into `svc-a`. Written into the store directly rather than driven through an authorization
/// code: what is on trial is the EXCHANGE, and minting it through consent would put the whole
/// authorization-code path in the way of reading this one result.
async fn forwarded_payment_token<S: Storage>(
    srv: &AuthorizationServer<S, ManualClock>,
    details: &str,
) -> String {
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut token = IssuedToken::new(
        SUBJECT_TOKEN,
        ClientId::new("payments-v"),
        Some("the-account-holder".to_string()),
        ScopeSet::parse("read").unwrap(),
        now,
        now + Duration::from_secs(3600),
    );
    token.authorization_details = AuthorizationDetails::parse(details).expect("fixture details");
    let _ = srv.store().put_token(token).await.unwrap();
    SUBJECT_TOKEN.to_string()
}

/// THE FINDING. `svc-a` asks for `read`, which is inside the subject token's scope AND inside its
/// own registration, so every ceiling the exchange had passes. What it must not walk away with is
/// the payment.
#[tokio::test]
async fn a_downstream_service_cannot_inherit_the_payment_it_was_never_authorized_for() {
    let srv = server().await;
    let subject = forwarded_payment_token(&srv, APPROVED_PAYMENT).await;
    let client_id = ClientId::new("svc-a");

    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SERVICE_SECRET);
    let narrowed = ScopeSet::parse("read").unwrap();
    request.scope = Some(&narrowed);

    let refused = match srv.exchange_token(&request).await {
        Err(refused) => refused,
        Ok(exchanged) => {
            // Not `expect_err`: the failure message has to SHOW the escalation, because that is the
            // finding. What prints here is a payment authorization on a token issued to `svc-a`,
            // with a fresh lifetime, visible to every resource server that reads RFC 7662
            // introspection or an RFC 9068 claim set.
            let issued = srv
                .introspect(&exchanged.response.access_token)
                .await
                .unwrap()
                .expect("the exchange just issued it");
            panic!(
                "cross-client escalation: svc-a holds a token for client {} scope {} carrying {:?}",
                issued.client_id.as_str(),
                issued.scope,
                issued.authorization_details
            );
        }
    };

    // RFC 8693 section 2.2.2 names `invalid_target` for a target service the server cannot issue
    // for, and `invalid_request` for a subject token that is "unacceptable based on policy". No
    // target was named in this request and the refusal is not about one: what is unacceptable is the
    // SUBJECT TOKEN, whose authority this server cannot re-issue to a different principal. Same code
    // as the sender-constrained refusal, for the same reason.
    assert_eq!(refused.error, ErrorCode::InvalidRequest);
    let description = refused.error_description.unwrap_or_default();
    assert!(
        description.contains("authorization_details"),
        "the client has to be told what it tripped over, and it is not a secret: {description}"
    );
}

/// The refusal is about the DETAILS and not about the grant. A subject token carrying none is the
/// ordinary case and still exchanges, so a deployment that does not use RFC 9396 sees no change.
#[tokio::test]
async fn a_subject_token_without_details_still_exchanges() {
    let srv = server().await;
    let subject = forwarded_payment_token(&srv, "[]").await;
    let client_id = ClientId::new("svc-a");

    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SERVICE_SECRET);

    srv.exchange_token(&request)
        .await
        .expect("an exchange with no rich authorization detail in sight is untouched by this rule");
}
