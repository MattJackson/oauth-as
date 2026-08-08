// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8707: resource indicators.
//!
//! Why this exists. Without it every access token this AS issues is implicitly good at every
//! resource server that trusts this issuer, so one leaked token is a leak against the whole
//! deployment. RFC 8707 lets the client name the resource server it actually intends to call, and
//! the AS narrows the token's audience to it. That is the same blast-radius argument RFC 9700
//! makes for audience restriction, and it lands directly on the RFC 9068 `aud` claim this crate
//! emits under the `jwt` feature.
//!
//! The rules pinned here come from RFC 8707 section 2:
//!
//! - the parameter is `resource`, it appears at both the authorization endpoint and the token
//!   endpoint, and it MAY be repeated;
//! - its value MUST be an absolute URI (RFC 3986 section 4.3), MAY carry a query, and MUST NOT
//!   carry a fragment;
//! - a request the AS will not honour is refused with the error code `invalid_target`.
//!
//! The narrowing rule (a token request must not ask for a resource the authorization request did
//! not obtain) is the same shape as RFC 6749 section 6's scope rule for refresh, and is tested the
//! same way.

mod support;

use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId,
    ErrorCode, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};
use support::{
    client_credentials_client, confidential_client, mint_code_token, public_client, server_with,
    ManualClock, CC_SECRET, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, PUBLIC_REDIRECT,
    RFC7636_VERIFIER,
};

const RS_ONE: &str = "https://rs.example/api";
const RS_TWO: &str = "https://other-rs.example/";

fn challenge() -> String {
    oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER)
}

/// A valid authorization request built from wire pairs, so `resource` can be repeated the way a
/// query string repeats it (RFC 8707 s2). `AuthorizationRequest::from_pairs` is exactly what a host
/// feeds its parsed query into.
fn request_with_resources<'a>(
    challenge: &'a str,
    client_id: &'a str,
    redirect_uri: &'a str,
    resources: &[&'a str],
) -> AuthorizationRequest<'a> {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", "read"),
        ("state", "opaque-state"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    for r in resources {
        pairs.push(("resource", r));
    }
    AuthorizationRequest::from_pairs(pairs)
}

/// RFC 8707 s2: the requested resource is what the token is FOR, so it has to survive the
/// authorization request, the code, and issuance. The audience is observable through RFC 7662
/// introspection's `aud` member, which is where a resource server or an operator would look.
#[tokio::test]
async fn a_requested_resource_becomes_the_token_audience() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let req = request_with_resources(&c, "confidential-app", CONFIDENTIAL_REDIRECT, &[RS_ONE]);

    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("a well formed resource must be accepted");
    let response = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .unwrap();
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("the code must redeem");

    let introspected = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    let json = serde_json::to_value(&introspected).unwrap();
    assert_eq!(
        json.get("aud"),
        Some(&serde_json::json!([RS_ONE])),
        "RFC 8707 s2 with RFC 7662 s2.2: the audience the token was narrowed to must be reportable"
    );
}

/// RFC 8707 s2: "Multiple `resource` parameters MAY be used". Keeping only the first would silently
/// drop half of what the client asked for, and the client would then get a token that fails at the
/// resource server it never heard about.
#[tokio::test]
async fn several_resource_parameters_are_all_carried() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let req = request_with_resources(
        &c,
        "confidential-app",
        CONFIDENTIAL_REDIRECT,
        &[RS_ONE, RS_TWO],
    );

    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let response = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .unwrap();
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .unwrap();

    let introspected = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    let json = serde_json::to_value(&introspected).unwrap();
    assert_eq!(
        json.get("aud"),
        Some(&serde_json::json!([RS_ONE, RS_TWO])),
        "RFC 8707 s2 permits repetition; every requested resource must be carried"
    );
}

/// RFC 7662 s2.2 lists `aud` as OPTIONAL, and a token with no resource indicator has no audience
/// this AS can honestly name. Emitting an empty array, or the issuer, or a guess, would be
/// inventing a restriction nobody asked for.
#[tokio::test]
async fn a_token_with_no_requested_resource_reports_no_audience() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    let introspected = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    let json = serde_json::to_value(&introspected).unwrap();
    assert_eq!(
        json.get("aud"),
        None,
        "no resource was requested, so there is no audience to report (RFC 7662 s2.2 makes aud \
         OPTIONAL)"
    );
}

/// RFC 8707 s2: the value MUST be an absolute URI as defined by RFC 3986 s4.3. A relative
/// reference names nothing an AS can restrict a token to, and s2 gives `invalid_target` as the
/// error code for a resource the AS will not honour.
#[tokio::test]
async fn a_relative_resource_reference_is_invalid_target() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();
    let req = request_with_resources(&c, "public-app", PUBLIC_REDIRECT, &["/api"]);

    let err = srv
        .validate_authorization_request(&req)
        .await
        .expect_err("a relative resource reference must be refused");
    match err {
        AuthorizationError::Redirect(r) => assert_eq!(
            serde_json::to_value(&r.error).unwrap().get("error"),
            Some(&serde_json::json!("invalid_target")),
            "RFC 8707 s2 names invalid_target as the error code"
        ),
        AuthorizationError::Direct(e) => panic!("expected a redirected error, got {e}"),
    }
}

/// RFC 8707 s2 again, and this half is the security-relevant one: the URI "MUST NOT include a
/// fragment component". A fragment never reaches a server, so two requests differing only in their
/// fragment name the same resource while looking different to any policy check written against the
/// raw string.
#[tokio::test]
async fn a_resource_with_a_fragment_is_invalid_target() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();
    let req = request_with_resources(
        &c,
        "public-app",
        PUBLIC_REDIRECT,
        &["https://rs.example/#a"],
    );

    let err = srv
        .validate_authorization_request(&req)
        .await
        .expect_err("a resource URI with a fragment must be refused");
    match err {
        AuthorizationError::Redirect(r) => assert_eq!(
            serde_json::to_value(&r.error).unwrap().get("error"),
            Some(&serde_json::json!("invalid_target"))
        ),
        AuthorizationError::Direct(e) => panic!("expected a redirected error, got {e}"),
    }
}

/// RFC 8707 s2 explicitly allows a query component, so a resource that carries one must NOT be
/// swept up by the fragment rule. Pinned because the obvious implementation of "no fragment" is a
/// substring search that also trips over `?`.
#[tokio::test]
async fn a_resource_with_a_query_component_is_accepted() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();
    let req = request_with_resources(
        &c,
        "public-app",
        PUBLIC_REDIRECT,
        &["https://rs.example/api?tenant=1"],
    );

    srv.validate_authorization_request(&req)
        .await
        .expect("RFC 8707 s2 permits a query component in a resource indicator");
}

/// The refusal is reported to the client, not rendered to the user: by the time `resource` is
/// examined the client and its redirect URI have been validated, so RFC 6749 s4.1.2.1 makes this a
/// redirect error, and RFC 9207 s2.2 puts `iss` on it. Checking the two together pins the ORDER of
/// validation, which is the part that is a security boundary rather than a preference.
#[tokio::test]
async fn the_invalid_target_refusal_goes_back_to_the_client_with_iss() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();
    let req = request_with_resources(&c, "public-app", PUBLIC_REDIRECT, &["not a uri"]);

    let err = srv.validate_authorization_request(&req).await.unwrap_err();
    let redirect = match err {
        AuthorizationError::Redirect(r) => r,
        AuthorizationError::Direct(e) => panic!("expected a redirected error, got {e}"),
    };
    let location = redirect.location();
    assert!(location.starts_with(PUBLIC_REDIRECT), "{location}");
    assert!(location.contains("error=invalid_target"), "{location}");
    assert!(
        location.contains("iss=https%3A%2F%2Fas.example"),
        "RFC 9207 s2.2: an error authorization response carries iss too, got {location}"
    );
}

// ------------------------------------------------------------------- the token endpoint

/// A public client registered for the device grant only, so the device-poll case below has a real
/// grant to poll. Defined here rather than in `support` because no other suite needs it.
fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// Mint a code for `resources` and hand back the code string, so the token-endpoint tests below
/// start from a grant that really did obtain those resource indicators.
async fn code_for<S: oauth_as::Storage>(
    srv: &oauth_as::AuthorizationServer<S, ManualClock>,
    challenge: &str,
    resources: &[&str],
) -> String {
    let req = request_with_resources(
        challenge,
        "confidential-app",
        CONFIDENTIAL_REDIRECT,
        resources,
    );
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    srv.issue_authorization_code(&validated, "user-1")
        .await
        .unwrap()
        .code
}

fn redeem(code: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        code: code.to_string(),
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    }
}

async fn audience_of<S: oauth_as::Storage>(
    srv: &oauth_as::AuthorizationServer<S, ManualClock>,
    access_token: &str,
) -> Option<Vec<String>> {
    srv.introspection_response(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        access_token,
    )
    .await
    .unwrap()
    .aud
}

/// RFC 8707 s2: a token request may ask for a SUBSET of the resources the authorization request
/// obtained. This is the whole point of the parameter appearing at both endpoints: a client that
/// obtained consent for two resource servers can still take a token that only works at one of them.
#[tokio::test]
async fn the_token_request_may_narrow_the_resource_set() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let code = code_for(&srv, &c, &[RS_ONE, RS_TWO]).await;

    let issued = srv
        .token_with_resources(redeem(&code), &[RS_TWO.to_string()])
        .await
        .expect("narrowing to a granted resource must be honoured");

    assert_eq!(
        audience_of(&srv, &issued.access_token).await,
        Some(vec![RS_TWO.to_string()]),
        "RFC 8707 s2: the issued token is for exactly what the token request narrowed to"
    );
}

/// RFC 8707 s2, the half that is a security rule rather than a convenience: the token request must
/// not obtain a resource the authorization request never did. Same shape as the RFC 6749 s6 scope
/// rule for refresh, and the same reason: what the user approved is the ceiling.
///
/// The code is put BACK, so a client that simply asked wrongly can retry. Burning a live code over
/// a recoverable client bug would hand an attacker a denial of service for the cost of one guess.
#[tokio::test]
async fn the_token_request_may_not_widen_the_resource_set() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let code = code_for(&srv, &c, &[RS_ONE]).await;

    let err = srv
        .token_with_resources(redeem(&code), &[RS_TWO.to_string()])
        .await
        .expect_err("a resource the authorization request never obtained must be refused");
    assert_eq!(err.error, ErrorCode::InvalidTarget);

    let issued = srv
        .token_with_resources(redeem(&code), &[RS_ONE.to_string()])
        .await
        .expect("the code must survive a refusal it was not to blame for");
    assert_eq!(
        audience_of(&srv, &issued.access_token).await,
        Some(vec![RS_ONE.to_string()])
    );
}

/// A grant that obtained NO resource has nothing to narrow, so a token request naming one is
/// widening from nothing (RFC 8707 s2). Refusing is the only answer that does not let the token
/// endpoint mint an audience no authorization request ever obtained.
#[tokio::test]
async fn a_token_request_cannot_introduce_a_resource_the_grant_never_had() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let code = code_for(&srv, &c, &[]).await;

    let err = srv
        .token_with_resources(redeem(&code), &[RS_ONE.to_string()])
        .await
        .expect_err("a grant with no resource indicator cannot acquire one at the token endpoint");
    assert_eq!(err.error, ErrorCode::InvalidTarget);
}

/// RFC 8707 s2's URI rules apply wherever the parameter appears, not only at the authorization
/// endpoint. A malformed indicator at the token endpoint is `invalid_target` too.
#[tokio::test]
async fn a_malformed_resource_at_the_token_endpoint_is_invalid_target() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let code = code_for(&srv, &c, &[RS_ONE]).await;

    let err = srv
        .token_with_resources(redeem(&code), &["https://rs.example/#frag".to_string()])
        .await
        .expect_err("a fragment is forbidden by RFC 8707 s2 at either endpoint");
    assert_eq!(err.error, ErrorCode::InvalidTarget);
}

/// RFC 6749 s6 refresh under RFC 8707 s2: the rotated token inherits the chain's resources by
/// default, may narrow them, and may not widen them. The chain remembers what it started with, so
/// narrowing once does not silently become the new ceiling for the NEXT rotation.
#[tokio::test]
async fn refresh_inherits_narrows_and_refuses_to_widen_the_resource_set() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let c = challenge();
    let code = code_for(&srv, &c, &[RS_ONE, RS_TWO]).await;
    let issued = srv.token(redeem(&code)).await.unwrap();
    let refresh = issued
        .refresh_token
        .expect("this grant issues a refresh token");

    let refresh_request =
        |token: &str, scope: Option<oauth_as::ScopeSet>| TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: token.to_string(),
            scope,
        };

    // Inherit: no resource named, so the rotated token keeps the chain's audience.
    let rotated = srv
        .token(refresh_request(&refresh, None))
        .await
        .expect("a refresh naming no resource inherits the chain's");
    assert_eq!(
        audience_of(&srv, &rotated.access_token).await,
        Some(vec![RS_ONE.to_string(), RS_TWO.to_string()])
    );

    // Widen: refused, and the (unspent) record goes back so the client can retry.
    let refresh2 = rotated.refresh_token.unwrap();
    let err = srv
        .token_with_resources(
            refresh_request(&refresh2, None),
            &["https://third-rs.example/".to_string()],
        )
        .await
        .expect_err("a refresh may not widen the resource set (RFC 8707 s2)");
    assert_eq!(err.error, ErrorCode::InvalidTarget);

    // Narrow: honoured, on the same still-live refresh token.
    let narrowed = srv
        .token_with_resources(refresh_request(&refresh2, None), &[RS_ONE.to_string()])
        .await
        .expect("the refresh token must have survived the refused widening");
    assert_eq!(
        audience_of(&srv, &narrowed.access_token).await,
        Some(vec![RS_ONE.to_string()])
    );
}

/// RFC 6749 s4.4 client credentials has no authorization request behind it, so there is nothing to
/// narrow against: the authenticated client naming a resource server IS the request. The indicator
/// is still validated (RFC 8707 s2), and it still becomes the token's audience.
#[tokio::test]
async fn client_credentials_takes_its_resource_directly() {
    let srv = server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    let request = || TokenRequest::ClientCredentials {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        scope: None,
    };

    let issued = srv
        .token_with_resources(request(), &[RS_ONE.to_string()])
        .await
        .expect("a well formed resource must be accepted");
    assert_eq!(
        audience_of(&srv, &issued.access_token).await,
        Some(vec![RS_ONE.to_string()])
    );

    let err = srv
        .token_with_resources(request(), &["urn-with-no-scheme".to_string()])
        .await
        .expect_err("RFC 8707 s2 requires an absolute URI here too");
    assert_eq!(err.error, ErrorCode::InvalidTarget);
}

/// RFC 8628 s3.1 does not carry a `resource` parameter in this crate, so a device poll naming one
/// is asking the token endpoint to invent an audience the user never approved at the verification
/// screen. `invalid_target` (RFC 8707 s2) says so rather than silently ignoring the parameter,
/// because a client that believes it holds an audience-restricted token and does not is worse off
/// than one told plainly that it cannot have one.
#[tokio::test]
async fn a_device_poll_naming_a_resource_is_refused() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    let err = srv
        .token_with_resources(
            TokenRequest::DeviceCode {
                client_id: ClientId::new("device-client"),
                client_secret: None,
                device_code: auth.device_code,
            },
            &[RS_ONE.to_string()],
        )
        .await
        .expect_err("the device grant has no granted resource to narrow to");
    assert_eq!(err.error, ErrorCode::InvalidTarget);
}

// ------------------------------------------------------- the RFC 9068 `aud` claim (feature jwt)

/// RFC 8707 s2 exists to restrict the audience, and under the `jwt` feature the audience is not an
/// introspection detail: it is the RFC 9068 s2.2 `aud` claim a resource server verifies offline.
/// So the requested resource must REPLACE the configured default audience, not sit beside it. A
/// token that still carried the deployment-wide audience would be accepted at resource servers the
/// client did not ask for, which is the blast radius the parameter exists to shrink.
///
/// One resource stays the plain-string form RFC 7519 s4.1.3 allows; several become the array form.
#[cfg(feature = "jwt")]
#[tokio::test]
async fn the_requested_resource_replaces_the_configured_aud_claim() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};
    use oauth_as::{AuthorizationServer, MemoryStorage, ServerConfig};

    /// The `aud` claim of a signed access token, straight out of the payload segment.
    fn aud_claim(token: &str) -> serde_json::Value {
        let payload = token
            .split('.')
            .nth(1)
            .expect("compact JWS has three parts");
        let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        claims
            .get("aud")
            .cloned()
            .expect("RFC 9068 s2.2 REQUIREs aud")
    }

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("kid-1"),
        "https://default-rs.example",
    )));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(confidential_client()).await.unwrap();
    let c = challenge();

    // No resource: the deployment's configured audience, unchanged from before RFC 8707 existed.
    let plain = srv
        .token(redeem(&code_for(&srv, &c, &[]).await))
        .await
        .unwrap();
    assert_eq!(
        aud_claim(&plain.access_token),
        serde_json::json!("https://default-rs.example")
    );

    // One resource: it replaces the configured audience outright.
    let one = srv
        .token(redeem(&code_for(&srv, &c, &[RS_ONE]).await))
        .await
        .unwrap();
    assert_eq!(aud_claim(&one.access_token), serde_json::json!(RS_ONE));

    // Two: the RFC 7519 s4.1.3 array form, and still no trace of the configured default.
    let two = srv
        .token(redeem(&code_for(&srv, &c, &[RS_ONE, RS_TWO]).await))
        .await
        .unwrap();
    assert_eq!(
        aud_claim(&two.access_token),
        serde_json::json!([RS_ONE, RS_TWO])
    );
}

/// RFC 8707 section 2: the server MUST answer `invalid_target` when it "is unwilling or unable to
/// issue an access token" for a requested resource. Syntax is not authorisation, and until this
/// check existed the server had no notion of unwilling, so any well-formed absolute URI was
/// accepted from any client.
///
/// The escalation that makes this more than tidiness: with the `jwt` feature on, the requested
/// resource REPLACES the configured audience in the RFC 9068 `aud` claim. So a client registered
/// against one resource server could name a second one and be handed a token THIS SERVER SIGNED
/// carrying that second server's identifier in `aud`. The second server fetches our JWKS, the
/// signature verifies, `aud` names it, and it authorises on whatever scope string the two happen
/// to share. Resource servers sharing a scope name like `read` is the ordinary case.
#[tokio::test]
async fn a_resource_outside_the_allowlist_is_invalid_target() {
    let clock = ManualClock::at_epoch();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.allowed_resources = vec!["https://a.example/api".to_string()];
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    srv.register_client(client_credentials_client())
        .await
        .unwrap();

    // The resource this deployment actually serves is fine.
    srv.token_with_resources(
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("cc-app"),
            client_secret: Some(CC_SECRET.to_string()),
            scope: None,
        },
        &["https://a.example/api".to_string()],
    )
    .await
    .expect("a resource this server serves must still be issuable");

    // A resource server it was never authorised for is refused, not signed for.
    let err = srv
        .token_with_resources(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("cc-app"),
                client_secret: Some(CC_SECRET.to_string()),
                scope: None,
            },
            &["https://b.example/api".to_string()],
        )
        .await
        .expect_err("naming a resource this server does not serve must be invalid_target");
    assert_eq!(err.error, ErrorCode::InvalidTarget);
}

/// An empty allowlist keeps the previous behaviour rather than refusing everything, because
/// turning refusal on by default would break every deployment already using resource indicators.
/// That is a deliberate choice with a real cost, so it is pinned here: if someone later "fixes"
/// the default, this test tells them they have made a breaking change rather than a safety
/// improvement, and they can decide knowingly.
#[tokio::test]
async fn an_empty_allowlist_means_no_restriction() {
    let clock = ManualClock::at_epoch();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    assert!(
        cfg.allowed_resources.is_empty(),
        "the default is unrestricted, and that is the documented risk"
    );
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    srv.register_client(client_credentials_client())
        .await
        .unwrap();

    srv.token_with_resources(
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("cc-app"),
            client_secret: Some(CC_SECRET.to_string()),
            scope: None,
        },
        &["https://anything.example/api".to_string()],
    )
    .await
    .expect("with no allowlist configured, any well-formed resource is still accepted");
}
