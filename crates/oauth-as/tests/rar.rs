// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9396 rich authorization requests, driven through the crate's public API.
//!
//! Why this suite exists, and what it is mostly about. `authorization_details` is the parameter
//! that lets a client ask for "transfer 50 euros to account X" instead of the scope token
//! "payments", which means it is also the parameter an attacker would edit to ask for a different
//! account or a larger amount. So most of what follows is attacks, and each one names what the
//! attacker ends up holding that they must not:
//!
//! - the token endpoint asking for an element the authorization request never obtained;
//! - the token endpoint adding one `action` to an element it DID obtain;
//! - the token endpoint broadening `locations`, which is the same move against the resource server
//!   list;
//! - the token endpoint changing, or simply omitting, the `identifier`, which turns a detail about
//!   one account into a detail about all of them;
//! - a refresh doing any of the above later, when nobody is watching the browser;
//! - a grant that carried NO details acquiring some at the token endpoint;
//! - an element whose type this server was never told it supports being processed anyway
//!   (RFC 9396 section 5 makes that a MUST NOT);
//! - and the quiet one: an AS that keeps the members it recognises and drops the rest, so that the
//!   token describes a DIFFERENT authorization from the one the resource owner approved.
//!
//! The clauses pinned here:
//!
//! - section 2: the parameter is a JSON array of objects, each with a REQUIRED `type`;
//! - section 2.2: the common data fields `locations`, `actions`, `datatypes`, `identifier`,
//!   `privileges`;
//! - section 5: an unknown type, or a detail that does not conform, is
//!   `invalid_authorization_details`;
//! - section 6: the token request may not exceed what the underlying grant allows;
//! - section 7: the AS returns the details as granted, attached to the access token;
//! - section 9.1 / 9.2: the details reach the resource server through the JWT claim and through
//!   introspection;
//! - section 10: `authorization_details_types_supported` in the RFC 8414 document.
#![cfg(feature = "rar")]

mod support;

use oauth_as::rar::{
    AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_BYTES, MAX_AUTHORIZATION_DETAILS_ELEMENTS,
};
use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServer, AuthorizationServerMetadata,
    Client, ClientAuth, ClientId, ErrorCode, GrantType, MemoryStorage, ScopeSet, ServerConfig,
    TokenRequest, TokenRequestContext,
};
use support::{ManualClock, RFC7636_VERIFIER};

const PAYMENT: &str = "payment_initiation";
const ACCOUNT: &str = "account_information";
const REDIRECT: &str = "https://rar.example/cb";
const SECRET: &str = "rar-client-secret-for-tests";

/// The detail the resource owner approves throughout this suite: one payment, on one account, at
/// one resource server, for a stated amount that this crate has no vocabulary for and therefore
/// must carry unchanged.
const GRANTED: &str = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}}]"#;

fn challenge() -> String {
    oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER)
}

/// A confidential client, because introspection (RFC 7662 section 2.1) is how this suite reads the
/// details back off an issued token and that endpoint refuses public clients.
fn rar_client() -> Client {
    Client {
        client_id: ClientId::new("rar-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A server that has been told which RFC 9396 types it speaks. Every suite below needs one,
/// because a server told nothing refuses every type (section 5, and see
/// `AuthorizationDetails::require_supported_types`).
async fn rar_server(clock: ManualClock) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.authorization_details_types_supported =
        Some(vec![PAYMENT.to_string(), ACCOUNT.to_string()]);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    srv.register_client(rar_client()).await.unwrap();
    srv
}

/// An authorization request carrying `authorization_details`, built from wire pairs exactly as a
/// host feeds its parsed query string in.
fn request_with_details<'a>(
    challenge: &'a str,
    details: Option<&'a str>,
) -> AuthorizationRequest<'a> {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", "rar-app"),
        ("redirect_uri", REDIRECT),
        ("scope", "read"),
        ("state", "opaque-state"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    if let Some(d) = details {
        pairs.push(("authorization_details", d));
    }
    AuthorizationRequest::from_pairs(pairs)
}

/// Drive the authorization leg and return the code, having approved `details`.
async fn code_for(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    challenge: &str,
    details: Option<&str>,
) -> String {
    let req = request_with_details(challenge, details);
    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("a well formed authorization_details must be accepted");
    srv.issue_authorization_code(&validated, "user-1")
        .await
        .expect("issuing the code")
        .code
}

fn redeem(code: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("rar-app"),
        client_secret: Some(SECRET.to_string()),
        code: code.to_string(),
        redirect_uri: Some(REDIRECT.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    }
}

/// A token request carrying `authorization_details`. RFC 9396 section 6 makes it a parameter of
/// the token request itself, so this crate carries it on [`TokenRequestContext`] alongside the RFC
/// 8707 `resource` indicators rather than on any one grant.
async fn token_asking_for(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    request: TokenRequest,
    requested: &str,
) -> Result<oauth_as::TokenResponse, oauth_as::ErrorResponse> {
    srv.token_with_context(
        request,
        TokenRequestContext {
            authorization_details: Some(requested),
            ..Default::default()
        },
    )
    .await
}

/// Redeem `code` while asking the token endpoint for `requested` details.
async fn redeem_asking_for(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    code: &str,
    requested: &str,
) -> Result<oauth_as::TokenResponse, oauth_as::ErrorResponse> {
    token_asking_for(srv, redeem(code), requested).await
}

/// The details recorded against an issued access token, read back the way a resource server would
/// (RFC 7662 / RFC 9396 section 9.2).
async fn introspected_details(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    access_token: &str,
) -> AuthorizationDetails {
    let response = srv
        .introspection_response(&ClientId::new("rar-app"), Some(SECRET), access_token)
        .await
        .expect("introspection of the server's own token");
    assert!(
        response.active,
        "the token this suite just minted must be active"
    );
    response.authorization_details
}

// --------------------------------------------------------------------- the happy path first

/// RFC 9396 s2 and s7: what the client asks for at the authorization endpoint is what the code
/// records, and what the token carries. Without this the rest of the suite is testing nothing.
#[tokio::test]
async fn a_requested_detail_is_recorded_on_the_code_and_reaches_the_token() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let token = srv.token(redeem(&code)).await.expect("redemption");
    let details = introspected_details(&srv, &token.access_token).await;

    assert_eq!(details.len(), 1, "exactly the one element that was granted");
    let element = &details.as_slice()[0];
    assert_eq!(&*element.detail_type, PAYMENT);
    assert_eq!(element.identifier.as_deref(), Some("acct-1"));
    assert_eq!(&*element.actions, ["initiate".into(), "status".into()]);
}

/// THE QUIET ATTACK. RFC 9396 s2 makes `type` the definition of every other member, so an AS that
/// keeps `actions` and `locations` and discards the members it has no vocabulary for has granted
/// something OTHER than what was asked for and approved: here, a payment with no amount attached,
/// which the resource server is then free to interpret however it likes.
///
/// The amount is checked by VALUE, not merely for presence, because a re-serialization that
/// rounded, re-typed or reordered it would be the same defect wearing a hat.
#[tokio::test]
async fn members_this_server_has_no_vocabulary_for_are_preserved_exactly() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;
    let token = srv.token(redeem(&code)).await.expect("redemption");

    let details = introspected_details(&srv, &token.access_token).await;
    let element = &details.as_slice()[0];
    let amount = element
        .other
        .get("instructedAmount")
        .expect("the amount the client asked for must survive issuance");
    assert_eq!(
        amount,
        &serde_json::json!({"currency": "EUR", "amount": "50.00"}),
        "the type-defined members must arrive byte for byte as they were requested"
    );

    // And it must survive the wire shape too: a resource server reads this out of JSON, not out of
    // a Rust struct.
    let json = serde_json::to_string(&details).unwrap();
    assert!(json.contains("\"instructedAmount\""), "{json}");
    assert!(json.contains("\"50.00\""), "{json}");
}

// ------------------------------------------------------------- section 5: unknown types

/// RFC 9396 s5: "The AS MUST refuse to process any unknown authorization details type". Ignoring
/// the element instead would hand back a token that says nothing about a permission the client
/// believes it holds, and the client cannot tell the difference.
#[tokio::test]
async fn an_unknown_type_is_refused_at_the_authorization_endpoint() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let req = request_with_details(&c, Some(r#"[{"type":"nuclear_launch"}]"#));

    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Redirect(r)) => {
            assert_eq!(r.error.error, ErrorCode::InvalidAuthorizationDetails);
        }
        other => panic!("an unknown type must be refused, got {other:?}"),
    }
}

/// The same MUST at the token endpoint, where `client_credentials` has no prior authorization
/// request to have been checked at.
#[tokio::test]
async fn an_unknown_type_is_refused_at_the_token_endpoint() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let error = token_asking_for(
        &srv,
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("rar-app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        },
        r#"[{"type":"nuclear_launch"}]"#,
    )
    .await
    .expect_err("an unknown type must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// A server that has declared no types supports none, so every type is unknown. This is the
/// default configuration, and it is why compiling the feature in is not the same as turning it on.
#[tokio::test]
async fn a_server_that_declares_no_types_refuses_every_type() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    assert!(
        cfg.authorization_details_types_supported.is_none(),
        "the default must be to declare nothing"
    );
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(rar_client()).await.unwrap();

    let c = challenge();
    let req = request_with_details(&c, Some(GRANTED));
    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Redirect(r)) => {
            assert_eq!(r.error.error, ErrorCode::InvalidAuthorizationDetails);
        }
        other => panic!("an undeclared type must be refused, got {other:?}"),
    }
}

// ------------------------------------------------ section 6: the narrowing rule, as attacks

/// ATTACK: the client obtained a payment detail, and at the token endpoint asks for that one PLUS
/// an account-information detail nobody approved. What the attacker would hold is a token carrying
/// authority over a second API that never appeared on the consent screen.
#[tokio::test]
async fn the_token_endpoint_cannot_add_an_element() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let widened = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}},{"type":"account_information","actions":["read"]}]"#;
    let error = redeem_asking_for(&srv, &code, widened)
        .await
        .expect_err("adding an element is widening and must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);

    // And the code is still live, exactly as it is after a resource or redirect_uri mismatch: a
    // client bug must not be a free denial of service against the client's own flow.
    srv.token(redeem(&code))
        .await
        .expect("the refused request must not have burned the code");
}

/// ATTACK, and the subtle one. Every element is present, the type and identifier match, and only
/// ONE string has been added to `actions`: `cancel`. A comparison that checked element COUNT, or
/// that compared types and identifiers only, would pass this.
#[tokio::test]
async fn the_token_endpoint_cannot_add_an_action_to_a_granted_element() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let widened = r#"[{"type":"payment_initiation","actions":["initiate","status","cancel"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}}]"#;
    let error = redeem_asking_for(&srv, &code, widened)
        .await
        .expect_err("adding an action is widening and must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// ATTACK: `locations` names the resource servers a detail is good at, so broadening it is the RFC
/// 8707 audience attack wearing RFC 9396 clothes. The attacker would hold a payment authority
/// usable at an admin endpoint the resource owner never saw.
#[tokio::test]
async fn the_token_endpoint_cannot_broaden_locations() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let widened = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments","https://rs.example/admin"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}}]"#;
    let error = redeem_asking_for(&srv, &code, widened)
        .await
        .expect_err("broadening locations is widening and must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// ATTACK: same shape, different account. `identifier` is the whole point of a rich authorization
/// request, so a token endpoint that lets it be swapped has authorized a payment from an account
/// the resource owner never approved.
#[tokio::test]
async fn the_token_endpoint_cannot_change_the_identifier() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let swapped = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"identifier":"acct-2","instructedAmount":{"currency":"EUR","amount":"50.00"}}]"#;
    let error = redeem_asking_for(&srv, &code, swapped)
        .await
        .expect_err("changing the identifier must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// ATTACK, and the one that looks like a narrowing. OMITTING `identifier` asks for the detail
/// without the restriction to one account, which is the widest request in the file dressed as the
/// smallest diff. An implementation that treated "fewer members" as "less authority" would grant it.
#[tokio::test]
async fn the_token_endpoint_cannot_drop_the_identifier() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let unrestricted = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"instructedAmount":{"currency":"EUR","amount":"50.00"}}]"#;
    let error = redeem_asking_for(&srv, &code, unrestricted)
        .await
        .expect_err("dropping the identifier asks for the whole class and must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// ATTACK: the amount. This crate has no vocabulary for `instructedAmount` and therefore cannot
/// know whether 5000 is more than 50; RFC 9396 s6.1 says so outright ("there is no standardized
/// mechanism to compare two arbitrary authorization detail requests"). The only sound answer for a
/// member whose meaning is unknown is to require it to be identical.
#[tokio::test]
async fn the_token_endpoint_cannot_change_a_type_defined_member() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let richer = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"5000.00"}}]"#;
    let error = redeem_asking_for(&srv, &code, richer)
        .await
        .expect_err("a changed type-defined member must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// ATTACK: a grant that carried no authorization details at all acquiring some at the token
/// endpoint. There is nothing to narrow from, so this is widening from nothing, and it is the same
/// answer this crate already gives for RFC 8707 resources.
#[tokio::test]
async fn a_grant_with_no_details_cannot_acquire_them_at_the_token_endpoint() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, None).await;

    let error = redeem_asking_for(&srv, &code, GRANTED)
        .await
        .expect_err("an ungranted detail must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// ATTACK, later and quieter: the refresh leg. RFC 6749 s6 already forbids widening scope here and
/// RFC 8707 s2 forbids widening the audience; the same has to hold for the detail, or an attacker
/// who holds a refresh token simply waits until nobody is looking at a browser.
#[tokio::test]
async fn a_refresh_cannot_widen_the_authorization_details() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;
    let first = srv.token(redeem(&code)).await.expect("redemption");
    let refresh_token = first.refresh_token.expect("a refresh token");

    let widened = r#"[{"type":"payment_initiation","actions":["initiate","status","cancel"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}}]"#;
    let error = token_asking_for(
        &srv,
        TokenRequest::RefreshToken {
            client_id: ClientId::new("rar-app"),
            client_secret: Some(SECRET.to_string()),
            refresh_token: refresh_token.clone(),
            scope: None,
        },
        widened,
    )
    .await
    .expect_err("a refresh may narrow the detail, never widen it");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);

    // The chain is intact: a widening attempt is a client bug, and burning the refresh token for
    // it would lock out the legitimate client. Same treatment as a widened scope.
    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("rar-app"),
        client_secret: Some(SECRET.to_string()),
        refresh_token,
        scope: None,
    })
    .await
    .expect("the refused refresh must not have spent the token");
}

/// The rule is NARROWING, not freezing: dropping an element, and dropping an action from the
/// element that remains, is exactly what a client with two jobs and one task should be able to do.
/// Without this test the suite would pass just as well if the AS refused everything.
#[tokio::test]
async fn the_token_endpoint_may_narrow_to_less_than_was_granted() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let two = r#"[{"type":"payment_initiation","actions":["initiate","status"],"identifier":"acct-1"},{"type":"account_information","actions":["read"]}]"#;
    let code = code_for(&srv, &c, Some(two)).await;

    let narrowed = r#"[{"type":"payment_initiation","actions":["status"],"identifier":"acct-1"}]"#;
    let token = redeem_asking_for(&srv, &code, narrowed)
        .await
        .expect("narrowing must be allowed");

    let details = introspected_details(&srv, &token.access_token).await;
    assert_eq!(
        details.len(),
        1,
        "the token carries only what was asked for"
    );
    let element = &details.as_slice()[0];
    assert_eq!(&*element.detail_type, PAYMENT);
    assert_eq!(&*element.actions, ["status".into()]);
}

/// The refresh leg, narrowing correctly, and the chain remembering the NARROWED set afterwards:
/// otherwise a client could narrow once and widen back on the next rotation.
#[tokio::test]
async fn a_narrowed_refresh_narrows_the_chain_too() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let two = r#"[{"type":"payment_initiation","actions":["initiate","status"],"identifier":"acct-1"},{"type":"account_information","actions":["read"]}]"#;
    let code = code_for(&srv, &c, Some(two)).await;
    let first = srv.token(redeem(&code)).await.expect("redemption");

    let narrowed = r#"[{"type":"account_information","actions":["read"]}]"#;
    let second = token_asking_for(
        &srv,
        TokenRequest::RefreshToken {
            client_id: ClientId::new("rar-app"),
            client_secret: Some(SECRET.to_string()),
            refresh_token: first.refresh_token.expect("a refresh token"),
            scope: None,
        },
        narrowed,
    )
    .await
    .expect("narrowing on refresh must be allowed");

    // Now try to climb back to the payment detail on the next rotation.
    let error = token_asking_for(
        &srv,
        TokenRequest::RefreshToken {
            client_id: ClientId::new("rar-app"),
            client_secret: Some(SECRET.to_string()),
            refresh_token: second.refresh_token.expect("a rotated refresh token"),
            scope: None,
        },
        two,
    )
    .await
    .expect_err("the chain must remember the narrowed set");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

// ------------------------------------------------------------------- bounds on wire input

/// `authorization_details` is unauthenticated attacker-supplied JSON at the authorization
/// endpoint. A server that will parse however much of it arrives is a denial of service, so the
/// size is refused BEFORE the parser is handed anything.
#[tokio::test]
async fn an_oversized_authorization_details_is_refused() {
    let filler = "a".repeat(MAX_AUTHORIZATION_DETAILS_BYTES);
    let raw = format!(r#"[{{"type":"payment_initiation","note":"{filler}"}}]"#);
    assert!(raw.len() > MAX_AUTHORIZATION_DETAILS_BYTES);
    let error = AuthorizationDetails::parse(&raw).expect_err("oversize must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// The element count is bounded because narrowing compares every requested element against every
/// granted one. Unbounded, one request buys quadratic work at this server's expense.
#[tokio::test]
async fn too_many_elements_are_refused() {
    let one = r#"{"type":"payment_initiation"}"#;
    let raw = format!(
        "[{}]",
        vec![one; MAX_AUTHORIZATION_DETAILS_ELEMENTS + 1].join(",")
    );
    let error = AuthorizationDetails::parse(&raw).expect_err("too many elements must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// Nesting is bounded so that no walk in this crate, and no `Drop` of what it built, can be driven
/// until the stack runs out.
#[tokio::test]
async fn excessive_nesting_is_refused() {
    let deep = format!(
        r#"[{{"type":"payment_initiation","nest":{}{}}}]"#,
        "[".repeat(32),
        "]".repeat(32)
    );
    let error = AuthorizationDetails::parse(&deep).expect_err("deep nesting must be refused");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
}

/// RFC 9396 s2: the parameter is an ARRAY of OBJECTS and `type` is REQUIRED. Each of these is a
/// shape the RFC does not admit, and each must be refused rather than coerced into something.
#[tokio::test]
async fn malformed_authorization_details_is_refused() {
    for raw in [
        "not json at all",
        r#"{"type":"payment_initiation"}"#,
        r#"[{"actions":["read"]}]"#,
        r#"[{"type":""}]"#,
        r#"[{"type":42}]"#,
        r#"[{"type":"payment_initiation","actions":"read"}]"#,
        r#"[{"type":"payment_initiation","identifier":["acct-1"]}]"#,
        r#"["payment_initiation"]"#,
    ] {
        let error = match AuthorizationDetails::parse(raw) {
            Err(e) => e,
            Ok(parsed) => panic!("{raw} must be refused, parsed as {parsed:?}"),
        };
        assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails, "{raw}");
    }
}

/// No refusal may quote the request back. RFC 6749 s5.2 fixes a charset for `error_description`
/// that excludes the double quote and the backslash, and `authorization_details` is
/// attacker-controlled text that need not respect it: a description built by interpolating the
/// offending value would put an unescapable byte into a JSON error body, which is how an error
/// message becomes an injection vector.
///
/// The type below carries both excluded characters, and is refused twice over: once as an unknown
/// type (s5) and once for exceeding the byte bound.
#[tokio::test]
async fn a_refusal_never_echoes_the_request_back() {
    // Built through serde_json so the two characters are correctly ESCAPED on the wire and
    // therefore genuinely reach the parser as part of the type, rather than making the JSON
    // malformed and being refused for the wrong reason.
    let poison = "quote\" backslash\\ injection";
    let raw = serde_json::to_string(&serde_json::json!([{"type": poison}])).unwrap();
    let parsed = AuthorizationDetails::parse(&raw).expect("this one is well formed, just unknown");

    let oversized = serde_json::to_string(&serde_json::json!([{
        "type": poison,
        "n": "x".repeat(MAX_AUTHORIZATION_DETAILS_BYTES),
    }]))
    .unwrap();
    let errors = [
        parsed
            .require_supported_types(Some(&[PAYMENT.to_string()]))
            .expect_err("an unknown type must be refused"),
        AuthorizationDetails::parse(&oversized).expect_err("oversize must be refused"),
    ];

    for error in errors {
        assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);
        let description = error.error_description.unwrap_or_default();
        assert!(
            !description.contains('"') && !description.contains('\\'),
            "error_description must stay inside the RFC 6749 s5.2 charset: {description}"
        );
        assert!(
            !description.contains("injection"),
            "the offending input must not be echoed back: {description}"
        );
    }
}

// --------------------------------------------------------------------- section 10: metadata

/// RFC 9396 s10: a client learns which types it may ask for from the RFC 8414 document, not by
/// probing. Omitted rather than empty when the host declared none, for the reason
/// `scopes_supported` is: an empty array claims the server supports no types, which is a different
/// statement from silence and would be read as one.
#[test]
fn the_metadata_document_advertises_the_supported_types() {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let bare = AuthorizationServerMetadata::from_config(&cfg);
    assert!(bare.authorization_details_types_supported.is_none());
    let json = serde_json::to_string(&bare).unwrap();
    assert!(
        !json.contains("authorization_details_types_supported"),
        "an undeclared catalogue must be omitted, not empty: {json}"
    );

    cfg.authorization_details_types_supported = Some(vec![PAYMENT.to_string()]);
    let doc = AuthorizationServerMetadata::from_config(&cfg);
    assert_eq!(
        doc.authorization_details_types_supported,
        Some(vec![PAYMENT.to_string()])
    );
    let json = serde_json::to_string(&doc).unwrap();
    assert!(
        json.contains(r#""authorization_details_types_supported":["payment_initiation"]"#),
        "{json}"
    );
}

// ------------------------------------------------------- section 9.1: the RFC 9068 JWT claim

/// RFC 9396 s9.1: the AS is RECOMMENDED to put the details in the access token as a top-level
/// claim, so a resource server holding a JWT does not have to call introspection to learn what it
/// is allowed to do.
#[cfg(feature = "jwt")]
#[tokio::test]
async fn the_jwt_access_token_carries_the_authorization_details_claim() {
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.authorization_details_types_supported = Some(vec![PAYMENT.to_string()]);
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("k1"),
        "https://rs.example/",
    )));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(rar_client()).await.unwrap();

    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;
    let token = srv.token(redeem(&code)).await.expect("redemption");

    let payload = token
        .access_token
        .split('.')
        .nth(1)
        .expect("a JWS compact serialization has three parts");
    let claims: serde_json::Value =
        serde_json::from_slice(&base64_url_decode(payload).expect("the payload must be base64url"))
            .expect("the payload must be JSON");
    let details = claims
        .get("authorization_details")
        .expect("RFC 9396 s9.1: the claim must be present when the grant carries details");
    assert_eq!(details.as_array().map(|a| a.len()), Some(1));
    assert_eq!(details[0]["identifier"], serde_json::json!("acct-1"));
    assert_eq!(
        details[0]["instructedAmount"],
        serde_json::json!({"currency": "EUR", "amount": "50.00"}),
        "the type-defined members reach the resource server unchanged"
    );
}

/// A token from a grant with no details must not carry an empty claim: an empty array reads as
/// "authorized for nothing in particular", which is a statement, and the truth is silence.
#[cfg(feature = "jwt")]
#[tokio::test]
async fn a_grant_with_no_details_signs_no_claim() {
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("k1"),
        "https://rs.example/",
    )));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(rar_client()).await.unwrap();

    let c = challenge();
    let code = code_for(&srv, &c, None).await;
    let token = srv.token(redeem(&code)).await.expect("redemption");
    let payload = token.access_token.split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&base64_url_decode(payload).unwrap()).unwrap();
    assert!(
        claims.get("authorization_details").is_none(),
        "no details means no claim: {claims}"
    );
}

/// base64url without padding (RFC 7515 s2), hand-rolled here rather than pulling `base64` into the
/// dev-dependency set for one call.
#[cfg(feature = "jwt")]
fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in s.bytes() {
        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// ATTACK. Every element is, individually, a perfect narrowing of the one granted element: they
/// are all EXACT COPIES of it. Nothing is added, nothing is changed, nothing is broadened. What
/// changes is how MANY there are.
///
/// A check that asks "is each requested element a narrowing of something granted?" answers yes
/// sixteen times, and the resource server is handed sixteen payment authorizations for a consent
/// screen that showed one. Whether that means sixteen payments is type-defined, which is exactly
/// the point: RFC 9396 s6.1 says the authorization server cannot know what a type's members mean,
/// and every OTHER ambiguity in this comparison is resolved by refusing (a changed identifier, a
/// dropped identifier, a changed type-defined member). Duplication was the one move that got the
/// permissive answer.
///
/// So a requested element must consume a DISTINCT granted element. Genuine narrowing still works,
/// because narrowing a granted element still matches it once.
#[tokio::test]
async fn the_token_endpoint_cannot_duplicate_a_granted_element() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    // The granted element, repeated to the element ceiling. Byte-identical each time.
    let one = r#"{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}}"#;
    let sixteen = format!(
        "[{}]",
        std::iter::repeat(one)
            .take(MAX_AUTHORIZATION_DETAILS_ELEMENTS)
            .collect::<Vec<_>>()
            .join(",")
    );

    let error = redeem_asking_for(&srv, &code, &sixteen)
        .await
        .expect_err("one granted authorization must not become sixteen");
    assert_eq!(error.error, ErrorCode::InvalidAuthorizationDetails);

    srv.token(redeem(&code))
        .await
        .expect("the refused request must not have burned the code");
}

/// The other half, so the fix cannot be "refuse anything repeated". Two DIFFERENT granted
/// elements must still both be obtainable, and a genuine narrowing of each must still match: the
/// rule is one granted element consumed per requested element, not a ban on similar-looking ones.
#[tokio::test]
async fn two_distinct_granted_elements_can_both_be_narrowed() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let two = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}},{"type":"account_information","actions":["read","list"],"identifier":"acct-1"}]"#;
    let code = code_for(&srv, &c, Some(two)).await;

    // Each narrowed: one action dropped from each element.
    let narrowed = r#"[{"type":"payment_initiation","actions":["initiate"],"locations":["https://rs.example/payments"],"identifier":"acct-1","instructedAmount":{"currency":"EUR","amount":"50.00"}},{"type":"account_information","actions":["read"],"identifier":"acct-1"}]"#;
    redeem_asking_for(&srv, &code, narrowed)
        .await
        .expect("narrowing each of two distinct granted elements must still be allowed");
}

/// RFC 9396 s7: "the AS MUST also return the `authorization_details` as granted by the resource
/// owner and assigned to the respective access token". The crate honoured s9.1 (the JWT claim) and
/// s9.2 (introspection) but not the token response body itself.
///
/// It matters for the same reason RFC 6749 s3.3 has `scope` echoed when it differs from the
/// request: s7.1 explicitly permits granted to differ from requested, so without this a client
/// that asked for two details and was granted one has no way to find out, and goes on to call a
/// resource server believing it can do something it cannot.
#[tokio::test]
async fn the_token_response_carries_the_granted_authorization_details() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, Some(GRANTED)).await;

    let issued = srv.token(redeem(&code)).await.expect("redeemed");

    let body = serde_json::to_value(&issued).unwrap();
    let details = body
        .get("authorization_details")
        .expect("RFC 9396 s7 makes this a MUST on a response to a request that carried details");
    assert_eq!(
        details,
        &serde_json::from_str::<serde_json::Value>(GRANTED).unwrap(),
        "the response must carry what was GRANTED, byte for byte"
    );
}

/// The other half: a grant that carried no authorization details must emit exactly the body it
/// emitted before this member existed. A `null`, or an empty array, would be a wire change for
/// every deployment that does not use the feature.
#[tokio::test]
async fn a_grant_with_no_details_omits_the_member_entirely() {
    let srv = rar_server(ManualClock::at_epoch()).await;
    let c = challenge();
    let code = code_for(&srv, &c, None).await;

    let issued = srv.token(redeem(&code)).await.expect("redeemed");
    let body = serde_json::to_value(&issued).unwrap();
    assert!(
        body.get("authorization_details").is_none(),
        "an unused member must be omitted, not null and not [], got {body}"
    );
}
