// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WORK AN UNAUTHENTICATED CALLER CAN BUY BY MAKING A REQUEST BIGGER.
//!
//! `src/rar.rs` already settled the shape of this argument for RFC 9396: attacker-supplied,
//! repeatable structure arriving at an endpoint that takes no credential gets an explicit constant
//! cap, checked before any per-element work, and the constant carries the reason for its own value.
//! Three arrays in this crate were repeatable and uncapped while sitting behind the same
//! endpoints, and one of them accumulated into a PERSISTED record, so the cost outlived the
//! request that bought it.
//!
//! The algorithm question is settled separately and deliberately: at a cap of 16 a linear scan is
//! faster than hashing (a `HashSet<String>` pays a SipHash of the whole string per lookup, against
//! sixteen comparisons that mostly fail on the length byte), so these stay linear scans and the
//! cap is the whole of the fix. What was wrong was never the scan, it was that nothing bounded `n`.

mod support;

use oauth_as::{AuthorizationRequest, ClientId, ErrorCode, TokenRequest};

use support::{server_with, ManualClock, PUBLIC_REDIRECT, RFC7636_VERIFIER};

fn resources(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("https://rs{i}.example/api"))
        .collect()
}

fn authorization_request<'a>(
    resource: &'a [String],
    challenge: &'a str,
) -> AuthorizationRequest<'a>
where
{
    AuthorizationRequest {
        resource: resource.iter().map(|r| r.as_str().into()).collect(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".into()),
        client_id: Some("public-app".into()),
        redirect_uri: Some(PUBLIC_REDIRECT.into()),
        scope: Some("read".into()),
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    }
}

/// THE FINDING. RFC 8707 section 2 makes `resource` repeatable, the authorization endpoint takes no
/// client credential, and nothing bounded how many a request could carry. The dedup is an O(n) scan
/// per element and the allowlist check is another, so the cost is quadratic in a number the caller
/// picks.
#[tokio::test]
async fn the_authorization_endpoint_refuses_more_resource_indicators_than_the_cap() {
    let srv = server_with(ManualClock::at_epoch(), vec![support::public_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);

    let at_cap = resources(oauth_as::server::MAX_RESOURCE_INDICATORS);
    srv.validate_authorization_request(&authorization_request(&at_cap, &challenge))
        .await
        .expect("exactly the cap is still a legal request");

    let over_cap = resources(oauth_as::server::MAX_RESOURCE_INDICATORS + 1);
    let refused = srv
        .validate_authorization_request(&authorization_request(&over_cap, &challenge))
        .await
        .expect_err("one past the cap is refused");
    let response = match refused {
        oauth_as::AuthorizationError::Direct(e) => e,
        oauth_as::AuthorizationError::Redirect(r) => r.error,
    };
    assert_eq!(
        response.error,
        ErrorCode::InvalidTarget,
        "RFC 8707 s2 names invalid_target for a resource this server will not issue for"
    );
}

/// The same parameter at the TOKEN endpoint. It is authenticated there, but a client that has
/// merely leaked a secret should not get an amplifier with it, and the check has to be in the one
/// function both endpoints share or the two will drift.
#[tokio::test]
async fn the_token_endpoint_refuses_more_resource_indicators_than_the_cap() {
    let srv = server_with(ManualClock::at_epoch(), vec![support::public_client()]).await;
    let over_cap = resources(oauth_as::server::MAX_RESOURCE_INDICATORS + 1);
    let refused = srv
        .token_with_resources(
            TokenRequest::AuthorizationCode {
                client_id: ClientId::new("public-app"),
                client_secret: None,
                code: "no-such-code".to_string(),
                redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
                code_verifier: Some(RFC7636_VERIFIER.to_string()),
            },
            &over_cap,
        )
        .await
        .expect_err("one past the cap is refused");
    assert_eq!(refused.error, ErrorCode::InvalidTarget);
}

/// The cap is REFUSAL, not truncation. Silently dropping indicators past the cap would issue a
/// token whose audience is not the one the client asked for, and neither the client nor anything
/// downstream would be told: exactly the failure mode `src/rar.rs` refuses for unknown members.
#[tokio::test]
async fn the_resource_cap_refuses_rather_than_truncating() {
    let srv = server_with(ManualClock::at_epoch(), vec![support::public_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let over_cap = resources(oauth_as::server::MAX_RESOURCE_INDICATORS + 4);
    assert!(srv
        .validate_authorization_request(&authorization_request(&over_cap, &challenge))
        .await
        .is_err());
}

/// A refusal an UNAUTHENTICATED caller can trigger at will must not allocate to describe itself.
/// `tests/allocation.rs` states the rule on `refused_token_request_allocation_bound`: a refusal is
/// work the attacker buys, so the crate's roughly fifty refusal sites all hand back a `&'static
/// str`. `resolve_scope` was building its description with `format!`, and echoing the caller's own
/// scope string back into it.
///
/// The RFC 8628 section 3.1 device authorization endpoint is the reachable one: it takes NO
/// credential from a public client, so anyone who can open a socket can drive this refusal at
/// whatever rate they like.
#[tokio::test]
async fn a_scope_refusal_borrows_its_description_rather_than_building_one() {
    let client = oauth_as::Client {
        client_id: oauth_as::ClientId::new("public-device"),
        auth: oauth_as::ClientAuth::Public,
        grant_types: vec![oauth_as::GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: oauth_as::ScopeSet::parse("read").unwrap(),
        default_scopes: oauth_as::ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    };
    let srv = server_with(ManualClock::at_epoch(), vec![client]).await;

    // Inside the RFC 6749 section 3.3 charset, outside the registration's allowed set.
    let asked = oauth_as::ScopeSet::parse("read superuser").unwrap();
    let refused = srv
        .device_authorization(&ClientId::new("public-device"), None, Some(&asked))
        .await
        .expect_err("superuser is not in the registration");
    assert_eq!(refused.error, ErrorCode::InvalidScope);
    let description = refused
        .error_description
        .expect("the developer still gets told what was wrong");
    assert!(
        matches!(description, std::borrow::Cow::Borrowed(_)),
        "a refusal an attacker sets the rate of must borrow, not allocate: got {description:?}"
    );
    assert!(
        !description.contains("superuser"),
        "and it must not echo the caller's own string back at them"
    );
}

/// RFC 7591 section 2 puts no bound on `redirect_uris`, and every authorization request for the
/// registered client then scans the whole list with exact string comparison. A registration is a
/// durable object, so an unbounded one is a durable cost paid per request forever.
#[tokio::test]
async fn dynamic_registration_refuses_more_redirect_uris_than_the_cap() {
    use oauth_as::{
        ClientMetadata, MemoryStorage, RegistrationAttempt, RegistrationConfig,
        RegistrationDecision, RegistrationErrorCode, RegistrationFailure, RegistrationPolicy,
        ServerConfig,
    };

    struct OpenPolicy;
    impl RegistrationPolicy for OpenPolicy {
        fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
            RegistrationDecision::Allow
        }
    }

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(RegistrationConfig::new()));
    let srv = oauth_as::AuthorizationServer::with_clock(
        cfg,
        MemoryStorage::new(),
        ManualClock::at_epoch(),
    )
    .with_registration_policy(Box::new(OpenPolicy));

    let uris = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("https://app{i}.example/cb"))
            .collect()
    };

    let at_cap = ClientMetadata {
        redirect_uris: uris(oauth_as::registration::MAX_REGISTERED_REDIRECT_URIS),
        ..ClientMetadata::default()
    };
    srv.register_dynamic_client(&at_cap, None)
        .await
        .expect("exactly the cap registers");

    let over_cap = ClientMetadata {
        redirect_uris: uris(oauth_as::registration::MAX_REGISTERED_REDIRECT_URIS + 1),
        ..ClientMetadata::default()
    };
    let refused = srv
        .register_dynamic_client(&over_cap, None)
        .await
        .expect_err("one past the cap is refused");
    match refused {
        RegistrationFailure::Invalid(response) => assert_eq!(
            response.error,
            RegistrationErrorCode::InvalidRedirectUri,
            "RFC 7591 s3.2.2: too many is a redirect_uri problem, not a generic metadata one"
        ),
        other => panic!("expected an invalid_redirect_uri refusal, got {other:?}"),
    }
}
