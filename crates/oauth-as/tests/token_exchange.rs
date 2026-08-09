// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8693 token exchange, driven through the crate's public API.
//!
//! Why this suite exists, and what it is mostly about. Token exchange is the one grant whose
//! entire job is to turn one principal's authority into another's, so the only interesting failure
//! mode is WIDENING: an exchange that hands back more scope, or a wider audience, than the subject
//! token carried has silently bypassed every access control that produced the subject token in the
//! first place. Most of the tests below are therefore attacks rather than examples, and each one
//! names what an attacker ends up holding that they must not.
//!
//! The RFC clauses pinned here:
//!
//! - section 2.1: the request parameters, `subject_token_type` REQUIRED, `actor_token_type`
//!   REQUIRED when `actor_token` is present;
//! - section 2.1.1: `resource` and `audience` both name the target service;
//! - section 2.2.1: `access_token`, `issued_token_type` and `token_type` all REQUIRED in the
//!   response, and a refresh token typically not issued;
//! - section 2.2.2: an invalid or policy-unacceptable token is `invalid_request`; an unwilling or
//!   unsupported target is `invalid_target`;
//! - section 1.1: delegation versus impersonation;
//! - section 4.1: the `act` claim identifies the CURRENT acting party.
#![cfg(feature = "token-exchange")]

mod support;

use std::time::Duration;

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType,
    MemoryStorage, ScopeSet, Storage, TokenRequest, TokenResponse,
};
use oauth_as::{ExchangeSemantics, TokenExchange, TokenExchangeRequest, TokenTypeIdentifier};
use support::{server_with, ManualClock, RFC7636_VERIFIER};

const RS_ONE: &str = "https://rs.example/api";
const RS_TWO: &str = "https://other-rs.example/api";

const EXCHANGER_SECRET: &str = "exchanger-secret-for-tests";
const EXCHANGER_REDIRECT: &str = "https://exchanger.example/cb";
const READ_ONLY_SECRET: &str = "read-only-exchanger-secret";
const HOLDER_SECRET: &str = "holder-secret-for-tests";
const HOLDER_REDIRECT: &str = "https://holder.example/cb";

/// The client that performs exchanges: confidential, registered for the grant, and also for the
/// code and client-credentials grants so one fixture can both HOLD a subject token and exchange
/// one.
fn exchanger() -> Client {
    Client {
        client_id: ClientId::new("exchanger"),
        auth: ClientAuth::ConfidentialSecret {
            secret: EXCHANGER_SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::TokenExchange,
        ],
        redirect_uris: vec![EXCHANGER_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write admin").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Exchanging service".into()),
        registration: None,
    }
}

/// An exchanging client whose OWN registration permits only `read`. It is the fixture for the
/// second ceiling: holding a `write` token must not let it mint a `write` token of its own.
fn read_only_exchanger() -> Client {
    Client {
        client_id: ClientId::new("read-only-exchanger"),
        auth: ClientAuth::ConfidentialSecret {
            secret: READ_ONLY_SECRET.into(),
        },
        grant_types: vec![GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A confidential client NOT registered for the exchange grant.
fn unregistered_exchanger() -> Client {
    Client {
        client_id: ClientId::new("no-exchange"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "no-exchange-secret-for-tests".into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A PUBLIC client that is nonetheless registered for the exchange grant, so the refusal under
/// test is the confidentiality rule and not the registration rule.
fn public_exchanger() -> Client {
    Client {
        client_id: ClientId::new("public-exchanger"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// The client that ORIGINALLY held the user's token, so a subject token can belong to somebody
/// other than the exchanging client (which is the ordinary shape: a gateway exchanges a token it
/// received).
fn holder() -> Client {
    Client {
        client_id: ClientId::new("holder"),
        auth: ClientAuth::ConfidentialSecret {
            secret: HOLDER_SECRET.into(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![HOLDER_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write admin").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn fixture() -> AuthorizationServer<MemoryStorage, ManualClock> {
    server_with(
        ManualClock::at_epoch(),
        vec![
            exchanger(),
            read_only_exchanger(),
            unregistered_exchanger(),
            public_exchanger(),
            holder(),
        ],
    )
    .await
}

/// Mint a real, subject-bearing access token through the authorization code grant, optionally
/// audience-restricted to `resources` (RFC 8707 s2). This is what a gateway would have received.
async fn subject_token<S: Storage>(
    srv: &AuthorizationServer<S, ManualClock>,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    scope: &str,
    subject: &str,
    resources: &[&str],
) -> TokenResponse {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", scope),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ];
    for r in resources {
        pairs.push(("resource", r));
    }
    let validated = srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs(pairs))
        .await
        .expect("fixture authorization request must validate");
    let response = srv
        .issue_authorization_code(&validated, subject)
        .await
        .expect("fixture code issuance must succeed");
    srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new(client_id),
        client_secret: Some(client_secret.to_string()),
        code: response.code,
        redirect_uri: Some(redirect_uri.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    })
    .await
    .expect("fixture code redemption must succeed")
}

fn exchange_request<'a>(
    subject_token: &'a str,
    client_id: &'a ClientId,
) -> TokenExchangeRequest<'a> {
    let mut req = TokenExchangeRequest::new(client_id, subject_token);
    req.client_secret = Some(EXCHANGER_SECRET);
    req
}

// ------------------------------------------------------------------ the response of section 2.2.1

/// RFC 8693 s2.2.1 makes THREE members required, and `issued_token_type` is the one a server that
/// reused its RFC 6749 s5.1 response type would silently omit. s2.2.1 also says a refresh token
/// will typically not be issued for an exchange of one temporary credential for another, which
/// this server takes as never.
#[tokio::test]
async fn the_response_carries_every_required_member_and_no_refresh_token() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read write",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let exchanged = srv
        .exchange_token(&exchange_request(&subject.access_token, &client_id))
        .await
        .expect("a narrowing exchange by a registered confidential client must succeed");

    assert!(!exchanged.response.access_token.is_empty());
    assert_eq!(
        exchanged.response.issued_token_type,
        TokenTypeIdentifier::AccessToken
    );
    assert_eq!(exchanged.response.token_type, oauth_as::TokenType::Bearer);
    assert!(exchanged.response.expires_in.is_some());
    assert_eq!(
        exchanged.response.refresh_token, None,
        "RFC 8693 s2.2.1: no refresh token for an exchange of one temporary credential"
    );

    let body = serde_json::to_value(&exchanged.response).unwrap();
    assert_eq!(
        body["issued_token_type"],
        serde_json::json!("urn:ietf:params:oauth:token-type:access_token"),
        "RFC 8693 s3 registers the URN; a shortened spelling is a different type"
    );
    assert_eq!(body["token_type"], serde_json::json!("Bearer"));
    assert!(
        body.get("refresh_token").is_none(),
        "an absent optional member is omitted, never null"
    );
}

/// RFC 8693 s1.1: with no actor token the issued token is indistinguishable from the subject's own
/// within its rights context, and this server says so rather than leaving it to be inferred.
#[tokio::test]
async fn an_exchange_without_an_actor_token_is_impersonation() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let exchanged = srv
        .exchange_token(&exchange_request(&subject.access_token, &client_id))
        .await
        .unwrap();
    assert_eq!(exchanged.semantics, ExchangeSemantics::Impersonation);
    assert_eq!(exchanged.act, None);
}

/// RFC 8693 s1.1 and s4.1: an actor token makes the exchange DELEGATION, and the `act` claim names
/// the current acting party. A client-credentials actor token names no user, so the acting party
/// is the client itself.
#[tokio::test]
async fn an_actor_token_makes_the_exchange_delegation_and_names_the_actor() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let actor = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("exchanger"),
            client_secret: Some(EXCHANGER_SECRET.to_string()),
            scope: None,
        })
        .await
        .expect("the exchanging client must be able to mint its own actor token");

    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    req.actor_token = Some(&actor.access_token);
    req.actor_token_type = Some(TokenTypeIdentifier::AccessToken);

    let exchanged = srv.exchange_token(&req).await.unwrap();
    assert_eq!(exchanged.semantics, ExchangeSemantics::Delegation);
    let act = exchanged.act.expect("delegation must carry an act claim");
    assert_eq!(act.sub, "exchanger");
    assert_eq!(act.client_id.as_deref(), Some("exchanger"));
    assert_eq!(act.act, None, "there is no prior actor to nest");
}

// ------------------------------------------------------------------------------- the ATTACKS

/// ATTACK. The client holds a read-only token and asks the exchange for `write`. If the server
/// obliges, it has minted authority nobody granted, and the read-only boundary that produced the
/// subject token has been defeated by one HTTP request.
#[tokio::test]
async fn an_exchange_cannot_widen_the_subject_tokens_scope() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let wider = ScopeSet::parse("read write").unwrap();
    let mut req = exchange_request(&subject.access_token, &client_id);
    req.scope = Some(&wider);

    let error = srv
        .exchange_token(&req)
        .await
        .expect_err("RFC 6749 s6's narrowing rule applies to the subject token");
    assert_eq!(error.error, ErrorCode::InvalidScope);

    // The refusal must not have consumed the subject token: asking for the wrong scope is a client
    // bug, and burning a live credential over it is a denial of service an attacker gets for free.
    // Same rule the refresh grant follows.
    assert!(
        srv.introspect(&subject.access_token)
            .await
            .unwrap()
            .is_some(),
        "a refused exchange must leave the subject token live"
    );
}

/// ATTACK. A client whose OWN registration permits only `read` gets hold of somebody else's
/// `write` token (which is exactly what a bearer token exposed to a middlebox is) and exchanges it
/// for a `write` token issued to itself. RFC 8693 does not forbid this; RFC 6749 s3.3's
/// registration boundary does, and a token issued TO this client has to respect it.
#[tokio::test]
async fn an_exchange_cannot_exceed_the_exchanging_clients_own_registration() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read write",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("read-only-exchanger");
    let mut req = TokenExchangeRequest::new(&client_id, &subject.access_token);
    req.client_secret = Some(READ_ONLY_SECRET);

    let error = srv
        .exchange_token(&req)
        .await
        .expect_err("the issued token belongs to a client registered for read only");
    assert_eq!(error.error, ErrorCode::InvalidScope);
}

/// ATTACK. The subject token is audience-restricted to one resource server; the client asks for a
/// token good at a DIFFERENT one. RFC 8707 s2 and RFC 8693 s2.2.2: `invalid_target`. Getting this
/// wrong turns an audience restriction into a suggestion.
#[tokio::test]
async fn an_exchange_cannot_widen_the_audience_to_another_resource() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[RS_ONE],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    let targets = [RS_TWO.to_string()];
    req.resource = &targets;

    let error = srv
        .exchange_token(&req)
        .await
        .expect_err("RFC 8707 s2: a token request may narrow the audience, never widen it");
    assert_eq!(error.error, ErrorCode::InvalidTarget);
}

/// ATTACK. The subject token names NO resource, so it has no audience to narrow. Naming one is
/// widening from nothing, and answering it any other way would let the exchange invent an audience
/// that no authorization request ever obtained.
#[tokio::test]
async fn an_exchange_cannot_invent_an_audience_the_subject_token_never_had() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    let targets = [RS_ONE.to_string()];
    req.resource = &targets;

    let error = srv.exchange_token(&req).await.expect_err(
        "a grant that named no resource has nothing to narrow, so any target widens it",
    );
    assert_eq!(error.error, ErrorCode::InvalidTarget);
}

/// ATTACK, through the OTHER parameter. RFC 8693 s2.1.1 makes `audience` the non-URI spelling of
/// the same idea as `resource`, so a server that checked only `resource` would leave the whole
/// ceiling bypassable by renaming the parameter.
#[tokio::test]
async fn the_audience_parameter_cannot_widen_either() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[RS_ONE],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    let audiences = [RS_TWO.to_string()];
    req.audience = &audiences;

    let error = srv
        .exchange_token(&req)
        .await
        .expect_err("audience is checked against the same ceiling as resource");
    assert_eq!(error.error, ErrorCode::InvalidTarget);
}

/// ATTACK, token type confusion. A refresh token is a bearer credential too, and it is the one a
/// client is most likely to have lying around. Labelling it an access token must not make this
/// server check it as one: the two live in different stores with different single-use rules, and
/// an exchange that accepted a refresh token would have converted a rotating credential into a
/// non-rotating one.
#[tokio::test]
async fn a_refresh_token_presented_as_a_subject_access_token_is_refused() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let refresh = subject
        .refresh_token
        .expect("the holder registration issues a refresh chain");
    let client_id = ClientId::new("exchanger");
    let error = srv
        .exchange_token(&exchange_request(&refresh, &client_id))
        .await
        .expect_err("RFC 8693 s2.2.2: a subject token that is invalid is invalid_request");
    assert_eq!(error.error, ErrorCode::InvalidRequest);

    // And the refresh token is untouched by the attempt: a failed exchange must not be a way to
    // burn somebody else's live rotating credential.
    assert!(srv
        .store()
        .get_refresh_token(&refresh)
        .await
        .unwrap()
        .is_some());
}

/// ATTACK, token type confusion the other way. The string IS a live access token, but the caller
/// labels it a JWT. RFC 8693 s3's `jwt` type means "any JWT", which is a statement about encoding
/// and not about who signed it; a server that ignored the label and checked the string its own way
/// would have made `subject_token_type` decorative, and a client could then present a token of a
/// type this server never validated.
#[tokio::test]
async fn a_subject_token_labelled_with_a_type_this_server_does_not_accept_is_refused() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    for wrong in [
        TokenTypeIdentifier::Jwt,
        TokenTypeIdentifier::RefreshToken,
        TokenTypeIdentifier::IdToken,
        TokenTypeIdentifier::Saml2,
    ] {
        let mut req = exchange_request(&subject.access_token, &client_id);
        req.subject_token_type = wrong;
        match srv.exchange_token(&req).await {
            Ok(_) => panic!("{wrong} must be refused, but a token was issued"),
            Err(error) => assert_eq!(error.error, ErrorCode::InvalidRequest, "for {wrong}"),
        }
    }
}

/// ATTACK. The acting party in an `act` claim is a party the server is ASSERTING acted. Accepting
/// any live access token as the actor would let a client that merely obtained a copy of another
/// client's token have this server certify that OTHER client as the actor.
#[tokio::test]
async fn an_actor_token_issued_to_another_client_is_refused() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let someone_elses = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-2",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    req.actor_token = Some(&someone_elses.access_token);
    req.actor_token_type = Some(TokenTypeIdentifier::AccessToken);

    let error = srv
        .exchange_token(&req)
        .await
        .expect_err("the acting party must be the party that authenticated");
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

// ------------------------------------------------------------------------ who may exchange at all

/// A public client identifier is a string anyone may claim, so "authenticated as a public client"
/// is true of every caller on the internet. Same refusal, and same reason, as client credentials,
/// introspection and revocation.
#[tokio::test]
async fn a_public_client_cannot_exchange() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("public-exchanger");
    let req = TokenExchangeRequest::new(&client_id, &subject.access_token);
    let error = srv.exchange_token(&req).await.expect_err(
        "a grant that converts one principal's authority into another's cannot rest on a name",
    );
    assert_eq!(error.error, ErrorCode::InvalidClient);
}

/// Who may exchange is a deployment decision, recorded where this crate records every other such
/// decision about grants: the client registration.
#[tokio::test]
async fn a_client_not_registered_for_the_grant_is_refused() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("no-exchange");
    let mut req = TokenExchangeRequest::new(&client_id, &subject.access_token);
    req.client_secret = Some("no-exchange-secret-for-tests");
    let error = srv.exchange_token(&req).await.unwrap_err();
    assert_eq!(error.error, ErrorCode::UnauthorizedClient);
}

/// RFC 8693 s2.1 makes `actor_token_type` REQUIRED when `actor_token` is present. A server that
/// defaulted it would be guessing how to check a credential.
#[tokio::test]
async fn an_actor_token_without_its_type_is_refused() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    req.actor_token = Some("some-actor-token");
    let error = srv.exchange_token(&req).await.unwrap_err();
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

/// An expired subject token is not a token. RFC 8693 s2.2.2 folds "invalid for any reason" into
/// one answer, so this reads the same as an unknown string.
#[tokio::test]
async fn an_expired_subject_token_is_refused() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![exchanger(), holder()]).await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    clock.advance(Duration::from_secs(3601));
    let client_id = ClientId::new("exchanger");
    let error = srv
        .exchange_token(&exchange_request(&subject.access_token, &client_id))
        .await
        .unwrap_err();
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

/// This server issues exactly one kind of token, so a request for a SAML assertion is a mistake no
/// amount of correct authentication fixes. RFC 8693 s2.2.2.
#[tokio::test]
async fn a_requested_token_type_this_server_does_not_issue_is_refused() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let mut req = exchange_request(&subject.access_token, &client_id);
    req.requested_token_type = Some(TokenTypeIdentifier::Saml2);
    let error = srv.exchange_token(&req).await.unwrap_err();
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

// -------------------------------------------------------------- what a successful exchange yields

/// The narrowing direction, which is the one an exchange is FOR: a gateway holding a broad token
/// mints a narrow one for the single downstream call it is about to make.
#[tokio::test]
async fn a_narrowing_exchange_yields_exactly_the_narrowed_scope_and_audience() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read write",
        "user-1",
        &[RS_ONE, RS_TWO],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let narrower = ScopeSet::parse("read").unwrap();
    let targets = [RS_ONE.to_string()];
    let mut req = exchange_request(&subject.access_token, &client_id);
    req.scope = Some(&narrower);
    req.resource = &targets;

    let exchanged = srv.exchange_token(&req).await.unwrap();
    assert_eq!(exchanged.response.scope.as_deref(), Some("read"));

    // The audience is observable where a resource server or an operator would look for it.
    let introspected = srv
        .introspection_response(
            &ClientId::new("exchanger"),
            Some(EXCHANGER_SECRET),
            &exchanged.response.access_token,
        )
        .await
        .unwrap();
    assert!(introspected.active);
    assert_eq!(introspected.aud, Some(vec![RS_ONE.to_string()]));
    assert_eq!(
        introspected.sub.as_deref(),
        Some("user-1"),
        "the exchanged token still acts for the original subject"
    );
    assert_eq!(
        introspected.client_id.as_deref(),
        Some("exchanger"),
        "but it is issued TO the exchanging client"
    );
}

/// An exchange with no `scope` inherits the subject token's, which is the narrowing rule's
/// identity case, and must not quietly fall back to the client's registered default (which here is
/// narrower, so a bug in that direction would look harmless, and in a deployment where the default
/// is WIDER would be an escalation).
#[tokio::test]
async fn an_exchange_with_no_scope_inherits_the_subject_tokens_scope() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read write",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let exchanged = srv
        .exchange_token(&exchange_request(&subject.access_token, &client_id))
        .await
        .unwrap();
    assert_eq!(exchanged.response.scope.as_deref(), Some("read write"));
}

/// The exchanged token goes through the same issuance as every other grant, so it is a real token
/// at this AS: revocable, introspectable, and dead when revoked.
#[tokio::test]
async fn the_exchanged_token_is_a_first_class_token_at_this_server() {
    let srv = fixture().await;
    let subject = subject_token(
        &srv,
        "holder",
        HOLDER_SECRET,
        HOLDER_REDIRECT,
        "read",
        "user-1",
        &[],
    )
    .await;
    let client_id = ClientId::new("exchanger");
    let exchanged = srv
        .exchange_token(&exchange_request(&subject.access_token, &client_id))
        .await
        .unwrap();
    srv.revoke(
        &ClientId::new("exchanger"),
        Some(EXCHANGER_SECRET),
        &exchanged.response.access_token,
        None,
    )
    .await
    .unwrap();
    assert!(srv
        .introspect(&exchanged.response.access_token)
        .await
        .unwrap()
        .is_none());
}
