// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8693 bounds and the one opt-in the exchange has.
//!
//! Two unrelated things share a file because they share a fixture: the section 2.1.1 `audience`
//! array (repeatable, deduplicated with an O(n) scan per element, and uncapped) and
//! `ServerConfig::allow_sender_constrained_exchange`, the migration switch behind the refusal of a
//! bound subject token.

#![cfg(feature = "token-exchange")]

mod support;

use std::time::{Duration, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode, GrantType, IssuedToken,
    MemoryStorage, ScopeSet, ServerConfig, Storage, TokenExchange, TokenExchangeRequest,
    TokenRequest, TokenTypeIdentifier,
};
use support::ManualClock;

const SECRET: &str = "exchanger-secret-for-tests";

fn exchanger() -> Client {
    Client {
        client_id: ClientId::new("exchanger"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![GrantType::TokenExchange, GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server(allow_bound: bool) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.allow_sender_constrained_exchange = allow_bound;
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(exchanger()).await.unwrap();
    srv
}

/// A subject token held by the exchanging client itself, which is all this file needs: what is on
/// trial is the `audience` array and the binding check, neither of which cares who the subject is.
async fn subject_token<S: Storage>(srv: &AuthorizationServer<S, ManualClock>) -> String {
    srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("exchanger"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    })
    .await
    .expect("fixture subject token")
    .access_token
}

fn audiences(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("urn:svc:{i}")).collect()
}

/// THE FINDING. Section 2.1.1 makes `audience` repeatable, this crate dedups it against `targets`
/// with an O(n) scan per element, and nothing bounded how many a request could carry.
#[tokio::test]
async fn the_exchange_refuses_more_audience_values_than_the_cap() {
    let srv = server(false).await;
    let subject = subject_token(&srv).await;
    let client_id = ClientId::new("exchanger");

    let over = audiences(oauth_as::token_exchange::MAX_AUDIENCE_VALUES + 1);
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    request.audience = &over;

    let refused = srv
        .exchange_token(&request)
        .await
        .expect_err("one past the cap is refused");
    assert_eq!(
        refused.error,
        ErrorCode::InvalidTarget,
        "RFC 8693 s2.1.1 audiences go to the same ceiling as RFC 8707 resources"
    );
    // The CODE alone does not discriminate: an over-cap request would also be refused
    // `invalid_target` a few lines later by the audience ceiling, for a different reason. The
    // description is what says the SIZE check is the thing that fired, which is the point: the
    // work must be refused before it is done, not after.
    assert!(
        refused
            .error_description
            .unwrap_or_default()
            .contains("too many audience values"),
        "the size check has to be what refused, and it has to refuse BEFORE the dedup scan runs"
    );
}

/// The cap is not so tight that a legal request trips it. At the cap the request still reaches the
/// audience CEILING, which refuses for a different reason (a subject token carrying no resource has
/// nothing to narrow to), and that is the answer this suite expects: the size check passed.
#[tokio::test]
async fn exactly_the_cap_is_not_a_size_refusal() {
    let srv = server(false).await;
    let subject = subject_token(&srv).await;
    let client_id = ClientId::new("exchanger");

    let at = audiences(oauth_as::token_exchange::MAX_AUDIENCE_VALUES);
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    request.audience = &at;

    let outcome = srv.exchange_token(&request).await;
    let refused = outcome.expect_err("the subject token names no resource, so the ceiling refuses");
    // The ERROR CODE is pinned as well as the description, exactly as the one-past-the-cap test
    // above does. Asserting only that a description lacks "too many" is satisfied by ANY earlier
    // refusal — a mistyped secret, a client not registered for the grant, a subject token the
    // fixture failed to mint — so the property "the cap is not too tight" would keep passing after
    // the request stopped reaching the size check at all, leaving the boundary untested in both
    // directions.
    assert_eq!(
        refused.error,
        ErrorCode::InvalidTarget,
        "at the cap the request must reach the audience CEILING, not some earlier refusal"
    );
    let description = refused.error_description.unwrap_or_default();
    assert!(
        !description.contains("too many"),
        "at the cap the size check must not be what refused: {description}"
    );
}

/// GROUP E, the half `ServerConfig` owns. A sender-constrained subject token is refused by DEFAULT,
/// because the token this server would hand back belongs to the exchanging client, which cannot
/// prove possession of the binding key, so it can only be a plain bearer token. The switch exists
/// only as a migration path off the silent downgrade 0.9.0 and earlier performed.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_bound_subject_token_is_refused_by_default_and_allowed_only_by_opt_in() {
    // Written into the store directly rather than minted through a DPoP proof: what is on trial is
    // the CONFIG guard, and a real proof exchange would be testing RFC 9449's verifier instead.
    async fn bound_token<S: Storage>(srv: &AuthorizationServer<S, ManualClock>) -> String {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut token = IssuedToken::new(
            "bound-subject-token",
            ClientId::new("exchanger"),
            Some("user-1".to_string()),
            ScopeSet::parse("read").unwrap(),
            now,
            now + Duration::from_secs(3600),
        );
        // The binding this test is about: without it the exchange has nothing to refuse.
        token.jkt = Some("a-thumbprint-standing-in-for-a-real-one".into());
        let _ = srv.store().put_token(token).await.unwrap();
        "bound-subject-token".to_string()
    }

    let client_id = ClientId::new("exchanger");

    let refusing = server(false).await;
    let subject = bound_token(&refusing).await;
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    let refused = refusing
        .exchange_token(&request)
        .await
        .expect_err("the default must refuse to strip a binding");
    assert_eq!(refused.error, ErrorCode::InvalidRequest);
    assert!(
        refused
            .error_description
            .unwrap_or_default()
            .contains("sender constrained"),
        "the client needs to be told WHY: it just presented the token carrying the binding"
    );

    let permissive = server(true).await;
    let subject = bound_token(&permissive).await;
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    permissive
        .exchange_token(&request)
        .await
        .expect("the opt-in is what a deployment mid-migration off the silent downgrade needs");
}

/// RFC 8693 s2.2.1 withholds the refresh token from an exchange so that an exchanged token cannot
/// outlive by rotation the grant it was derived from. That rule is worth nothing on its own,
/// because the token this server issues for an exchange is an ORDINARY ACCESS TOKEN and therefore
/// an acceptable SUBJECT token in its turn, and exchanging one's own token is explicitly permitted.
///
/// So the attack needs no stolen credential and no second client: hold the token, and a moment
/// before each expiry exchange it for another. Before the clamp landed each hop restarted the full
/// `access_token_ttl`, so a grant made once at 09:00 stayed spendable for as long as the holder
/// kept walking it forward — days, weeks — and nothing counted the hops. What settles it is not
/// that the exchange is refused (it is not, and should not be: narrowing your own token is the
/// ordinary use of this grant) but that the token it hands back DIES WHEN THE ORIGINAL DID.
#[tokio::test]
async fn repeated_self_exchange_cannot_carry_a_grant_past_the_subject_token_it_descends_from() {
    let clock = ManualClock::at_epoch();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_ttl = Duration::from_secs(3600);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock.clone());
    srv.register_client(exchanger()).await.unwrap();
    let client_id = ClientId::new("exchanger");

    let original = subject_token(&srv).await;
    let original_expiry = srv
        .introspect(&original)
        .await
        .unwrap()
        .expect("the fixture token must be live")
        .expires_at;

    // Four hops, each 10 minutes after the last, which is the shape of the attack: always exchange
    // while the token you hold is still live, and never let the chain lapse.
    //
    // THE STRIDE HAS TO KEEP ALL FOUR HOPS INSIDE THE ORIGINAL HOUR. At 50 minutes a hop the
    // second exchange presented a subject token that was already dead, the exchange errored, and
    // the loop returned — so three of the four hops, and the terminal assertion below, never ran
    // at all, and the test's name was describing a walk it never took. 4 x 10 minutes leaves the
    // whole chain inside the grant, which is what makes each hop a real exchange whose issued
    // expiry can be compared against the grant it descends from.
    let mut held = original;
    for hop in 0..4 {
        clock.advance(Duration::from_secs(10 * 60));
        let mut request =
            TokenExchangeRequest::new(&client_id, &held, TokenTypeIdentifier::AccessToken);
        request.client_secret = Some(SECRET);
        // NOT a silent `return`. Every hop here is inside the original grant's lifetime, so a
        // refusal is a defect in the exchange and not the ceiling being reached; swallowing it
        // left the test asserting nothing whatever while still reporting green.
        let exchanged = srv.exchange_token(&request).await.unwrap_or_else(|e| {
            panic!("hop {hop} is inside the original grant and must exchange: {e:?}")
        });
        let issued = srv
            .introspect(&exchanged.response.access_token)
            .await
            .unwrap()
            .expect("an exchange that succeeded must have persisted a token");
        assert!(
            issued.expires_at <= original_expiry,
            "hop {hop}: the exchanged token expires at {:?}, past the {original_expiry:?} of the \
             grant it descends from — the exchange has renewed the grant's lifetime",
            issued.expires_at
        );
        // RFC 6749 s5.1: what the client is TOLD has to be the same instant, or it keeps using a
        // token this server has already stopped honouring.
        assert!(
            exchanged
                .response
                .expires_in
                .expect("s2.2.1 optional but always sent here")
                <= original_expiry
                    .duration_since(clock.now())
                    .unwrap_or_default()
                    .as_secs(),
            "hop {hop}: expires_in outlives the stored expiry"
        );
        held = exchanged.response.access_token;
    }

    // The user-visible outcome: ONE SECOND past the ORIGINAL grant's expiry, nothing the chain
    // produced is spendable. One second rather than an hour, because the whole question is whether
    // the chain outlived the grant: without the clamp the last hop's token was minted with a fresh
    // full `access_token_ttl` and would still be live here, with another walk available.
    clock.advance(
        original_expiry
            .duration_since(clock.now())
            .expect("the whole chain is inside the original grant")
            + Duration::from_secs(1),
    );
    assert!(
        srv.introspect(&held).await.unwrap().is_none(),
        "a token reached by four exchanges is still dead at the original grant's expiry"
    );
}

/// RFC 8707 section 2 requires `invalid_target` when the server "is unwilling or unable to issue an
/// access token" for a named target. `ServerConfig::allowed_resources` is where a deployment says
/// that, and it is how an operator DECOMMISSIONS a resource server: remove it from the list, and
/// this server stops issuing for it.
///
/// RFC 8693 section 2.1.1 gives the same target a second spelling, `audience`, which need not be a
/// URI and therefore has to skip the syntax half of the check. Through 0.9.1 it skipped the
/// allowlist half with it, and `narrow_resources` does not cover the gap: it asks only whether the
/// SUBJECT token carries the value, never whether the server still stands behind it. So any client
/// holding a live token whose grant recorded the decommissioned resource could name it as an
/// `audience` and be handed a freshly signed token whose `aud` is the server the operator believed
/// they had switched off.
///
/// The two spellings are asserted TOGETHER, because the `resource` spelling was already refused:
/// what makes this a defect rather than a missing feature is that the two disagreed.
#[tokio::test]
async fn a_decommissioned_target_is_refused_under_the_audience_spelling_too() {
    const STILL_SERVED: &str = "https://kept.example/api";
    const DECOMMISSIONED: &str = "https://retired.example/api";

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    // What this deployment is still willing to issue for. `DECOMMISSIONED` was on this list
    // yesterday, which is why a live grant below still records it.
    cfg.allowed_resources = Some(Box::new([STILL_SERVED.into()]));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(exchanger()).await.unwrap();

    // A token minted while the retired resource was still served, written directly because the
    // config it was issued under no longer exists.
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut subject = IssuedToken::new(
        "subject-from-before-the-decommissioning",
        ClientId::new("exchanger"),
        Some("user-1".to_string()),
        ScopeSet::parse("read").unwrap(),
        now,
        now + Duration::from_secs(3600),
    );
    subject.resource = vec![STILL_SERVED.to_string(), DECOMMISSIONED.to_string()];
    let _ = srv.store().put_token(subject).await.unwrap();

    let client_id = ClientId::new("exchanger");
    let subject_token = "subject-from-before-the-decommissioning";
    let retired = [DECOMMISSIONED.to_string()];

    // The `resource` spelling: already refused before this fix, and pinned so the two spellings
    // cannot drift apart again.
    let mut by_resource =
        TokenExchangeRequest::new(&client_id, subject_token, TokenTypeIdentifier::AccessToken);
    by_resource.client_secret = Some(SECRET);
    by_resource.resource = &retired;
    let refused = srv
        .exchange_token(&by_resource)
        .await
        .expect_err("a resource this server no longer serves must not be issuable");
    assert_eq!(refused.error, ErrorCode::InvalidTarget);

    // The `audience` spelling, naming exactly the same target.
    let mut by_audience =
        TokenExchangeRequest::new(&client_id, subject_token, TokenTypeIdentifier::AccessToken);
    by_audience.client_secret = Some(SECRET);
    by_audience.audience = &retired;
    let refused = srv.exchange_token(&by_audience).await.expect_err(
        "audience names the same target as resource (RFC 8693 s2.1.1); the spelling must not \
             decide whether the allowlist applies",
    );
    assert_eq!(refused.error, ErrorCode::InvalidTarget);

    // And the target that IS still served goes through under the same spelling, so the refusal
    // above is the allowlist doing its job rather than `audience` having become unusable.
    let kept = [STILL_SERVED.to_string()];
    let mut allowed =
        TokenExchangeRequest::new(&client_id, subject_token, TokenTypeIdentifier::AccessToken);
    allowed.client_secret = Some(SECRET);
    allowed.audience = &kept;
    let issued = srv
        .exchange_token(&allowed)
        .await
        .expect("a target this server still serves, and the subject token carries, is issuable");
    let record = srv
        .introspect(&issued.response.access_token)
        .await
        .unwrap()
        .expect("the issued token must be live");
    assert_eq!(
        record.resource,
        vec![STILL_SERVED.to_string()],
        "the issued token names only the target that was asked for and permitted"
    );
}
