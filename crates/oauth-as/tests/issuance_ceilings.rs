// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THREE CEILINGS THAT WERE CHECKED IN ONE DIRECTION AND NOT THE OTHER.
//!
//! Each is a rule this crate already states and already enforces somewhere, applied to what the
//! REQUEST asked for and not to what the server actually ISSUED. The difference only shows on the
//! path where the request asks for nothing, which is the ordinary path: a refresh that names no
//! resource, an exchange that names neither `resource` nor `audience`, an authorization request
//! whose entry point is the plain one.
//!
//! - `ServerConfig::allowed_resources` is how an operator DECOMMISSIONS a resource server (RFC 8707
//!   section 2 `invalid_target`). It was consulted only about values the request named, so a grant
//!   that recorded the retired target went on minting tokens naming it, forever, because
//!   `refresh_token_ttl` defaults to `None`.
//! - RFC 9470 `acr_values`/`max_age` are parsed onto the validated request and evaluated by
//!   `issue_authorization_code_with_authentication`. The PLAIN entry point discarded them, and the
//!   plain entry point is the one the direct API invites (see `tests/direct_consent_seam.rs`).
//! - `Client::allowed_scopes` is re-applied to a refresh chain at every rotation, which is right,
//!   but `resolve_scope` had granted `default_scopes` without ever checking it against that same
//!   ceiling. A deployment whose two fields disagree issued grants its own rotation then destroyed.

mod support;

// Both of these are used only inside feature-gated tests below: `Duration` by the
// `token-exchange` case and `ErrorCode` by the `consent` one. Imported ungated, a default-feature
// build fails `-D warnings` on an unused import, which is what `cargo clippy --workspace
// --all-targets` does and what an `--all-features` run cannot see.
#[cfg(feature = "token-exchange")]
use std::time::Duration;

use oauth_as::server::UserApproval;
use oauth_as::Clock;
#[cfg(feature = "consent")]
use oauth_as::ErrorCode;
use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};
use support::{ManualClock, RFC7636_VERIFIER};

const SECRET: &str = "issuance-ceilings-secret-for-tests";
const REDIRECT: &str = "https://app.example/cb";

fn client_with(allowed: &str, default: &str) -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            #[cfg(feature = "token-exchange")]
            GrantType::TokenExchange,
        ],
        redirect_uris: vec![REDIRECT.into()],
        allowed_scopes: ScopeSet::parse(allowed).unwrap(),
        default_scopes: ScopeSet::parse(default).unwrap(),
        name: None,
        registration: None,
    }
}

fn authorization_request(extra: Vec<(&'static str, String)>) -> AuthorizationRequest<'static> {
    let mut pairs = vec![
        ("response_type", "code".to_string()),
        ("client_id", "app".to_string()),
        ("redirect_uri", REDIRECT.to_string()),
        (
            "code_challenge",
            oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER),
        ),
        ("code_challenge_method", "S256".to_string()),
    ];
    pairs.extend(extra);
    AuthorizationRequest::from_pairs(pairs)
}

/// THE FINDING for `allowed_resources`, on the REFRESH path and in its most ordinary form: a
/// rotation that names no `resource` at all.
///
/// `narrow_resources` returns the grant's recorded list verbatim when the request names nothing,
/// and under `jwt` that list REPLACES the configured audience in the RFC 9068 `aud` claim. So the
/// allowlist, which `target_is_permitted`'s own doc calls the way an operator decommissions a
/// resource server, was never consulted on the set actually issued. With `refresh_token_ttl`
/// defaulting to `None` the chain never expires either: the decommissioned server keeps receiving
/// freshly signed tokens naming it, from a grant recorded before it was retired, indefinitely.
///
/// The fix makes the allowlist a property of the ISSUED set rather than the requested one, so this
/// asserts on what the new token CARRIES and not merely on which error came back.
#[tokio::test]
async fn a_refresh_that_names_no_resource_still_drops_a_decommissioned_one() {
    const KEPT: &str = "https://kept.example/api";
    const RETIRED: &str = "https://retired.example/api";

    use oauth_as::{RefreshTokenRecord, Storage};

    // TODAY's deployment: RETIRED has been decommissioned by removing it from the allowlist.
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.allowed_resources = Some(Box::new([KEPT.into()]));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(client_with("read", "read"))
        .await
        .unwrap();

    // A chain recorded YESTERDAY, when both were served. Written directly, exactly as
    // `tests/token_exchange_bounds.rs` writes its subject token, because the configuration that
    // issued it no longer exists and `refresh_token_ttl` defaults to `None` so it never expires.
    let mut record = RefreshTokenRecord::new(
        "chain-from-before-the-decommissioning",
        ClientId::new("app"),
        Some("alice".to_string()),
        ScopeSet::parse("read").unwrap(),
        "family-1",
    );
    record.resource = vec![KEPT.to_string(), RETIRED.to_string()];
    record.grant_established_at = ManualClock::at_epoch().now();
    let _ = srv.store().put_refresh_token(record).await.unwrap();
    let refresh_token = "chain-from-before-the-decommissioning".to_string();

    let rotated = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            refresh_token,
            scope: None,
        })
        .await
        .expect("the grant is still honoured for the resource server that is still served");

    let record = srv
        .introspect(&rotated.access_token)
        .await
        .expect("storage")
        .expect("the rotated token is live");
    assert!(
        !record.resource.iter().any(|r| r == RETIRED),
        "a rotation that named no resource must not mint one this server no longer serves: {:?}",
        record.resource
    );
    assert!(
        record.resource.iter().any(|r| r == KEPT),
        "and the target that IS still served survives the narrowing: {:?}",
        record.resource
    );
}

/// The same gap under RFC 8693, in the spelling round 7's fix did not reach: an exchange naming
/// NEITHER `resource` NOR `audience`. `token_exchange.rs` already says `narrow_resources` "only
/// asks whether the SUBJECT TOKEN carries the value and never whether the server still stands
/// behind it", and that sentence stayed true of this path.
#[cfg(feature = "token-exchange")]
#[tokio::test]
async fn an_exchange_that_names_no_target_still_drops_a_decommissioned_one() {
    use oauth_as::{
        IssuedToken, Storage, TokenExchange, TokenExchangeRequest, TokenTypeIdentifier,
    };
    use std::time::UNIX_EPOCH;

    const KEPT: &str = "https://kept.example/api";
    const RETIRED: &str = "https://retired.example/api";

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.allowed_resources = Some(Box::new([KEPT.into()]));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(client_with("read", "read"))
        .await
        .unwrap();

    // Minted while RETIRED was still served, written directly because that configuration is gone.
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut subject = IssuedToken::new(
        "subject-from-before-the-decommissioning",
        ClientId::new("app"),
        Some("alice".to_string()),
        ScopeSet::parse("read").unwrap(),
        now,
        now + Duration::from_secs(3600),
    );
    subject.resource = vec![KEPT.to_string(), RETIRED.to_string()];
    let _ = srv.store().put_token(subject).await.unwrap();

    let client_id = ClientId::new("app");
    let mut request = TokenExchangeRequest::new(
        &client_id,
        "subject-from-before-the-decommissioning",
        TokenTypeIdentifier::AccessToken,
    );
    request.client_secret = Some(SECRET);
    let issued = srv
        .exchange_token(&request)
        .await
        .expect("the exchange still succeeds for the target that is still served");
    let record = srv
        .introspect(&issued.response.access_token)
        .await
        .expect("storage")
        .expect("the exchanged token is live");
    assert!(
        !record.resource.iter().any(|r| r == RETIRED),
        "an exchange naming no target must not inherit one this server no longer serves: {:?}",
        record.resource
    );
}

/// THE FINDING for RFC 9470. `validate_authorization_request` parses `acr_values` and `max_age`
/// onto the validated request; the PLAIN issuance entry point threw the requirement away and
/// minted a code as though the client had asked for nothing.
///
/// The sibling's own doc says why that is a library job: "a `max_age` the host is trusted to check
/// for itself is a `max_age` that gets checked in whichever code path somebody remembered". The
/// `http` layer uses the enforcing variant, so what shipped was the enforcement missing from
/// exactly the path `UserApproval` calls "the path this crate's DEFAULT BUILD invites".
///
/// The refusal is RFC 9470 section 3 `insufficient_user_authentication`, which is the answer a
/// requirement no report satisfies already gets on the enforcing path: unchanged behaviour for
/// every request that carries neither parameter, because `AuthenticationRequirement::satisfied_by`
/// answers `Ok(())` for an empty requirement.
#[cfg(feature = "consent")]
#[tokio::test]
async fn the_plain_issuance_entry_point_enforces_the_step_up_requirement() {
    use oauth_as::AuthorizationError;

    let srv =
        support::server_with(ManualClock::at_epoch(), vec![client_with("read", "read")]).await;

    // A request that asks for nothing extra is untouched: this is most requests, and the fix must
    // not turn them into refusals.
    let plain = authorization_request(vec![("scope", "read".to_string())]);
    let validated = srv
        .validate_authorization_request(&plain)
        .await
        .expect("a well formed request");
    srv.issue_authorization_code(UserApproval::granted(&validated, "alice"))
        .await
        .expect("a request with no RFC 9470 requirement is unaffected");

    // A request that DOES ask. Nobody has reported an authentication to this entry point, and it
    // has no argument through which they could, so the honest answer is a refusal.
    let stepped = authorization_request(vec![
        ("scope", "read".to_string()),
        ("acr_values", "phr".to_string()),
    ]);
    let validated = srv
        .validate_authorization_request(&stepped)
        .await
        .expect("acr_values is a well formed parameter");
    let refused = srv
        .issue_authorization_code(UserApproval::granted(&validated, "alice"))
        .await
        .expect_err("an unevaluated RFC 9470 requirement must not mint a code");
    match refused {
        AuthorizationError::Redirect(redirect) => assert_eq!(
            redirect.error.error,
            ErrorCode::InsufficientUserAuthentication,
            "RFC 9470 s3 names the code, and s4.1.2.1 makes it a redirect"
        ),
        other => panic!("the client asked the question, so the client is told: {other:?}"),
    }
}

/// THE REGRESSION. The rotation ceiling refuses a chain whose scope is not a subset of
/// `allowed_scopes` and deliberately does not put the record back, on the premise that "the client
/// asked to continue a grant this server is no longer willing to honour".
///
/// That premise fails when `default_scopes` is not a subset of `allowed_scopes`, because
/// `resolve_scope` granted `default_scopes` on the `None` arm with no subset check of its own. Such
/// a deployment IS willing to honour the grant: an identical fresh authorization request with no
/// `scope` mints the same scope again. So the server issued a grant and then destroyed its refresh
/// chain on the first rotation, permanently, with `invalid_scope` and no recovery.
///
/// The fix is at the point of ISSUANCE rather than at registration. Refusing the registration was
/// tried and rejected: `tests/registration_narrowing.rs` narrows `allowed_scopes` ALONE, which is
/// the control this crate tells an operator to reach for when a client should never have held a
/// scope, and a `register_client` that refused it would turn that control into an error message.
/// So `granted_default_scope` trims the default to the allowance instead, and it is shared by both
/// endpoints that apply the RFC 6749 section 3.3 default so the two cannot answer differently.
#[tokio::test]
async fn a_grant_taking_the_default_scope_survives_its_first_rotation() {
    let srv = support::server_with(
        ManualClock::at_epoch(),
        vec![client_with("read", "read write")],
    )
    .await;

    let request = authorization_request(vec![]);
    let validated = srv
        .validate_authorization_request(&request)
        .await
        .expect("a request naming no scope takes the registration's default");
    let approved = srv
        .issue_authorization_code(UserApproval::granted(&validated, "alice"))
        .await
        .expect("the user approved");
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            code: approved.code,
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("redemption");
    let refresh_token = issued.refresh_token.expect("the grant carries a chain");

    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        refresh_token,
        scope: None,
    })
    .await
    .expect(
        "a chain carrying only what this server itself granted must rotate: destroying it \
         permanently is a grant the server issues and then refuses to continue",
    );
}
