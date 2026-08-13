// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Five carriers of grant state that a mutation sweep found nothing constraining: what an
//! exchanged token inherits, what a device grant may not be handed, what a `cnf` names, which
//! audiences an exchange accumulates, and what a compare-and-swap does to the user-code index.
//!
//! They have nothing in common except their shape. Each one is a small piece of plumbing between
//! two features, which is exactly the kind of code a suite organised BY feature never looks at:
//! the RAR suite does not perform exchanges, the exchange suite does not carry details, and the
//! device suite does not swap user codes.

mod support;

// ------------------------------------------------------- what an exchanged token inherits

/// KILLS: `server.rs replace GrantedDetails::of_token -> Self with Default::default()`.
///
/// RFC 8693 section 2.1 exchanges one token for another, and RFC 9396 section 7 says the details
/// travel with the authority: the exchanged token inherits the subject token's
/// `authorization_details`, because it is acting for the same grant. `of_token` is the whole of
/// that inheritance.
///
/// Defaulted, the exchanged token carries NO details. That fails OPEN in the direction that
/// matters least and closed in the direction that matters most: a gateway exchanges a token that
/// authorizes a specific payment, receives one that authorizes nothing, and the downstream call
/// it was exchanging FOR is refused. Worse, a resource server that reads `authorization_details`
/// to decide what a token may do, and treats an absent list as "unconstrained", is handed exactly
/// the wrong answer.
#[cfg(all(feature = "token-exchange", feature = "rar"))]
#[tokio::test]
async fn an_exchanged_token_inherits_the_subject_tokens_authorization_details() {
    use oauth_as::server::UserApproval;
    use oauth_as::{
        AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
        MemoryStorage, ScopeSet, ServerConfig, TokenExchange, TokenExchangeRequest, TokenRequest,
        TokenRequestContext, TokenTypeIdentifier,
    };
    use support::ManualClock;

    const SECRET: &str = "carrier-suite-client-secret";
    const REDIRECT: &str = "https://app.example/cb";
    const DETAILS: &str = r#"[{"type":"payment_initiation","actions":["initiate"]}]"#;

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.authorization_details_types_supported = Some(vec!["payment_initiation".to_string()]);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::TokenExchange,
            GrantType::ClientCredentials,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs([
            ("response_type", "code"),
            ("client_id", "app"),
            ("redirect_uri", REDIRECT),
            ("scope", "read"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("authorization_details", DETAILS),
        ]))
        .await
        .expect("a well-formed request carrying details");
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("issuing the code")
        .code;
    let subject = srv
        .token_with_context(
            TokenRequest::AuthorizationCode {
                client_id: ClientId::new("app"),
                client_secret: Some(SECRET.to_string()),
                code,
                redirect_uri: Some(REDIRECT.to_string()),
                code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
            },
            TokenRequestContext::default(),
        )
        .await
        .expect("redeeming the code");

    let client_id = ClientId::new("app");
    let mut request = TokenExchangeRequest::new(
        &client_id,
        &subject.access_token,
        TokenTypeIdentifier::AccessToken,
    );
    request.client_secret = Some(SECRET);
    let exchanged = TokenExchange::exchange_token(&srv, &request)
        .await
        .expect("the exchange itself is well formed");

    let introspected = srv
        .introspection_response(
            &ClientId::new("app"),
            Some(SECRET),
            &exchanged.response.access_token,
        )
        .await
        .expect("introspection of the server's own token");
    assert!(introspected.active);
    assert_eq!(
        introspected.authorization_details.len(),
        1,
        "the exchanged token must still authorize the payment the subject token authorized"
    );
    assert_eq!(
        serde_json::to_string(&introspected.authorization_details).unwrap(),
        DETAILS,
        "and it must be the SAME detail, element for element"
    );
}

// ---------------------------------------------- what a device grant may not be handed at the token
// endpoint

/// KILLS: `server.rs replace GrantedDetails::is_empty -> bool with true`.
///
/// The device authorization request (RFC 8628 section 3.1) has no `authorization_details`
/// parameter in this crate, so a device grant never granted any, so there is nothing for a poll to
/// narrow to. RFC 9396 section 6 makes the token endpoint's `authorization_details` a NARROWING of
/// what was granted, and narrowing nothing to something is minting authority the user never saw:
/// the device flow's whole premise is that the user approved what was displayed to them on another
/// screen, and no detail was.
///
/// Constant `true` deletes that refusal, and the poll succeeds. It looks harmless because the
/// details are then dropped rather than granted, but the observable half is the half that matters:
/// a client asks for a payment detail, is answered `200 OK` with a token, and believes it holds
/// authority the server never granted. `invalid_authorization_details` is the honest answer and
/// RFC 9396 section 5 registers it for exactly this.
#[cfg(feature = "rar")]
#[tokio::test]
async fn a_device_poll_asking_for_authorization_details_is_refused_rather_than_ignored() {
    use oauth_as::{
        AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType, MemoryStorage,
        ScopeSet, ServerConfig, TokenRequest, TokenRequestContext,
    };
    use support::ManualClock;

    const DEVICE_SECRET: &str = "s3cret-value-for-tests";

    // The type IS advertised as supported, so that RFC 9396 s5's "unknown type" refusal cannot
    // stand in for the s6 refusal this test is about. Without that, the request is rejected two
    // checks earlier and the device branch is never reached.
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.authorization_details_types_supported = Some(vec!["payment_initiation".to_string()]);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(Client {
        client_id: ClientId::new("device-only"),
        auth: ClientAuth::ConfidentialSecret {
            secret: DEVICE_SECRET.to_string(),
        },
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    let authorized = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .expect("a device authorization request");
    // The user approves on the other screen. Nothing there mentions authorization_details,
    // which is the whole point.
    srv.approve_device(&authorized.user_code, "user-1")
        .await
        .expect("the host reports the approval");

    let refusal = srv
        .token_with_context(
            TokenRequest::DeviceCode {
                client_id: ClientId::new("device-only"),
                client_secret: Some(DEVICE_SECRET.to_string()),
                device_code: authorized.device_code.clone(),
            },
            TokenRequestContext::default().with_authorization_details(
                r#"[{"type":"payment_initiation","actions":["initiate"]}]"#,
            ),
        )
        .await
        .expect_err("a device grant granted no details, so there is nothing to narrow to");
    assert_eq!(
        refusal.error,
        ErrorCode::InvalidAuthorizationDetails,
        "RFC 9396 s6: asking to narrow a grant that carries nothing is not a request this \
         server may answer with a token"
    );
}

// ----------------------------------------------------------------- what a `cnf` names

/// KILLS: `token.rs replace Confirmation::jkt -> Self with Default::default()`.
///
/// [`Confirmation`] has no public field discipline problem and no private constructor: it is a
/// plain RFC 7800 `cnf` object, and `jkt` is the named constructor a host uses to build the RFC
/// 9449 section 6.1 binding it is about to publish. Defaulted, that constructor hands back a
/// confirmation naming NOTHING.
///
/// The consequence is exact and it is silent. `Confirmation::is_empty` is what decides whether
/// `cnf` is serialized at all, and it answers "empty" for the default, so the member VANISHES:
/// a host that built a sender-constrained token's confirmation publishes a token that reads as an
/// ordinary bearer token. Every resource server checking `cnf.jkt` before accepting a DPoP proof
/// concludes there is no binding to check, which is precisely the downgrade RFC 9449 section 6.1
/// exists to prevent.
#[cfg(feature = "dpop")]
#[test]
fn a_confirmation_built_from_a_thumbprint_names_that_thumbprint() {
    use oauth_as::token::Confirmation;

    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let cnf = Confirmation::jkt(JKT);

    assert_eq!(
        cnf.jkt.as_deref(),
        Some(JKT),
        "the thumbprint a host bound the token to must be the one the confirmation carries"
    );
    assert!(
        !cnf.is_empty(),
        "a confirmation that names a key is not the empty confirmation, and is_empty is what \
         decides whether cnf appears on the wire at all"
    );
    assert_eq!(
        serde_json::to_string(&cnf).expect("a cnf serializes"),
        format!(r#"{{"jkt":"{JKT}"}}"#),
        "RFC 9449 s6.1: the wire form a resource server checks is a jkt member naming the key"
    );
}

// -------------------------------------------------- which audiences an exchange accumulates

/// KILLS: `token_exchange.rs replace == with != in exchange` (the `audience` deduplication).
///
/// `if !targets.iter().any(|t| t == audience) { targets.push(...) }` is a de-duplication: an
/// audience already named by a `resource` indicator is not added twice. Inverted, the test becomes
/// "is there any target that DIFFERS from this audience", which is true as soon as one unrelated
/// resource is present, so the audience is silently DROPPED.
///
/// RFC 8693 section 2.1.1 makes `audience` and `resource` two spellings of the same request, and a
/// client is entitled to use both in one exchange. Dropping one of them issues a token whose
/// audience is narrower than the client asked for, with a `200 OK` and no indication that anything
/// was refused: the client discovers it at the resource server, as a rejection it cannot explain.
#[cfg(feature = "token-exchange")]
#[tokio::test]
async fn an_exchange_naming_both_a_resource_and_an_audience_keeps_both() {
    use oauth_as::server::UserApproval;
    use oauth_as::{
        AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
        MemoryStorage, ScopeSet, ServerConfig, TokenExchange, TokenExchangeRequest, TokenRequest,
        TokenTypeIdentifier,
    };
    use support::ManualClock;

    const SECRET: &str = "carrier-suite-client-secret";
    const REDIRECT: &str = "https://app.example/cb";
    const RS_ONE: &str = "https://rs.example/api";
    const RS_TWO: &str = "https://other-rs.example/api";

    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        ManualClock::at_epoch(),
    );
    srv.register_client(Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::TokenExchange],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    // A subject token audience-restricted to BOTH resource servers, so asking for both is
    // narrowing to the whole of what was granted rather than widening.
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs([
            ("response_type", "code"),
            ("client_id", "app"),
            ("redirect_uri", REDIRECT),
            ("scope", "read"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", RS_ONE),
            ("resource", RS_TWO),
        ]))
        .await
        .expect("a well-formed request naming two resources");
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("issuing the code")
        .code;
    let subject = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            code,
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("redeeming the code");

    let client_id = ClientId::new("app");
    let resources = [RS_ONE.to_string()];
    let audiences = [RS_TWO.to_string()];
    let mut request = TokenExchangeRequest::new(
        &client_id,
        &subject.access_token,
        TokenTypeIdentifier::AccessToken,
    );
    request.client_secret = Some(SECRET);
    request.resource = &resources;
    request.audience = &audiences;

    let exchanged = TokenExchange::exchange_token(&srv, &request)
        .await
        .expect("naming two granted targets, one per parameter, is narrowing to both");

    let introspected = srv
        .introspection_response(
            &ClientId::new("app"),
            Some(SECRET),
            &exchanged.response.access_token,
        )
        .await
        .expect("introspection of the server's own token");
    let mut aud = introspected
        .aud
        .expect("the exchanged token names its audience");
    aud.sort();
    assert_eq!(
        aud,
        vec![RS_TWO.to_string(), RS_ONE.to_string()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
        "RFC 8693 s2.1.1: resource and audience are two spellings of the same request, and a \
         client that used both asked for both"
    );
}

// ---------------------------------------------- the user-code index across a compare-and-swap

/// KILLS: `store.rs replace != with == in <impl Storage for MemoryStorage>::compare_and_swap_device_grant`.
///
/// The swap maintains the RFC 8628 section 6.1 user-code index, and the branch under test is the
/// one that removes the OLD entry when the swap changes the user code. Inverted, the removal fires
/// when the code did NOT change (which is harmless, because the insert immediately below puts the
/// same entry straight back) and does NOT fire when it did: the previous user code stays in the
/// index, pointing at this grant, for as long as the grant lives.
///
/// A user code is the credential a human types on the verification page. A stale one left live
/// means the code shown on the first screen still resolves after the grant has been reissued a new
/// one, so a person who saw or guessed the earlier code can still reach the grant. The reference
/// store is the one hosts read to learn what the contract means, and
/// `Storage::compare_and_swap_device_grant`'s own documentation says the index is maintained here
/// precisely because a `&mut` guard is already held and the duplication is a drift hazard.
#[tokio::test]
async fn a_swap_that_changes_the_user_code_retires_the_old_one() {
    use std::time::Duration;

    use oauth_as::device::normalize_user_code;
    use oauth_as::{ClientId, DeviceGrant, DeviceGrantState, MemoryStorage, ScopeSet, Storage};

    let store = MemoryStorage::new();
    // Real time, because the reference store treats an expired grant as gone.
    let now = std::time::SystemTime::now();
    let grant = DeviceGrant {
        device_code: "device-code-value".to_string(),
        user_code: "WDJB-MJHT".to_string(),
        client_id: ClientId::new("device-only"),
        scope: ScopeSet::parse("read").unwrap(),
        state: DeviceGrantState::Pending,
        created_at: now,
        expires_at: now + Duration::from_secs(600),
        interval: Duration::from_secs(5),
        last_poll_at: None,
    };
    store.put_device_grant(grant.clone()).await.unwrap();
    assert!(
        store
            .find_device_grant_by_user_code(&normalize_user_code("WDJB-MJHT"))
            .await
            .unwrap()
            .is_some(),
        "the fixture must be reachable by the code it was issued with"
    );

    // The host reissues a fresh user code for the same grant, atomically.
    let reissued = DeviceGrant {
        user_code: "BDWJ-THJM".to_string(),
        ..grant
    };
    assert!(
        store
            .compare_and_swap_device_grant(&DeviceGrantState::Pending, reissued)
            .await
            .unwrap(),
        "the state matched, so the swap applies"
    );

    assert!(
        store
            .find_device_grant_by_user_code(&normalize_user_code("ZZZZ-ZZZZ"))
            .await
            .unwrap()
            .is_none(),
        "a code nobody ever issued must not resolve"
    );
    assert!(
        store
            .find_device_grant_by_user_code(&normalize_user_code("BDWJ-THJM"))
            .await
            .unwrap()
            .is_some(),
        "the NEW code must reach the grant"
    );
    assert!(
        store
            .find_device_grant_by_user_code(&normalize_user_code("WDJB-MJHT"))
            .await
            .unwrap()
            .is_none(),
        "the OLD code is a credential the host has retired: leaving it live means the code from \
         the first screen still opens the grant shown on the second"
    );
}
