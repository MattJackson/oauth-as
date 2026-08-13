// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Machine-checkable schema conformance: every body this AS emits is validated against
//! validators transcribed clause-by-clause from RFC 6749 sections 5.1/5.2 and RFC 8628 sections
//! 3.2/3.5. Each check names the clause it comes from, and the negative tests at the bottom prove
//! the validators can actually FAIL (a gate nobody has watched go red is a gate nobody should
//! trust).
//!
//! WHY PLAIN RUST AND NOT A JSON SCHEMA VALIDATOR. These clauses used to be expressed as JSON
//! Schema documents checked by the `jsonschema` crate. That crate is taken with its default
//! features (`resolve-http`, `resolve-file`, `tls-aws-lc-rs`) merely to validate in-memory
//! `serde_json::Value`s, so it dragged a second `reqwest`, `hyper`, `h2`, `rustls` and the
//! `aws-lc-sys` C/asm build into a dev-dependency tree that never resolves a remote `$ref` and
//! never opens a socket: 88 of the packages in `Cargo.lock` existed for this one file. It also
//! declares `rust-version = 1.85`, which was the loudest of the reasons the MSRV job could only
//! BUILD, rather than TEST, at the measured 1.75 floor. None of that bought an assertion that is
//! not expressible in twenty lines of Rust, so the assertions were kept and the dependency was
//! dropped. What is checked here is exactly what the schemas checked, minus one clause named
//! below that provably checked nothing.
//!
//! NOT CARRIED OVER, deliberately: `format: "uri"` on `verification_uri` and
//! `verification_uri_complete`. In JSON Schema Draft 2020-12 `format` is an ANNOTATION, not an
//! assertion (Draft 2020-12 Validation section 7.2.1), so those two clauses validated nothing at
//! all and removing them loses nothing. The real parse-based URI check lives in the arms-length
//! harness (`validate_device_authorization_response` in `crates/oauth-as-conformance`), which
//! runs `url::Url::parse` over the body as it comes off the wire and is strictly stronger than
//! the annotation ever was.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode, ErrorResponse, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};

#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);
impl ManualClock {
    fn new() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}
impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

/// A validator is a function from a body to the list of clauses it violates. Returning every
/// violation, rather than the first, is what lets one failing body name all of its defects at
/// once; it is also the shape the independent harness uses, so the two read the same way.
type Violations = Vec<String>;

/// RFC 6749 Appendix A: parameter values on the wire are `*VSCHAR`, i.e. `%x20-7E`. `minLength`
/// is folded in here because both token members that use this are also `minLength: 1`: an empty
/// access_token is not a token.
fn is_nonempty_vschar(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c, '\x20'..='\x7e'))
}

/// RFC 6749 Appendix A `scope`: `scope-token *( SP scope-token )`, where a scope-token is
/// 1*NQCHAR and NQCHAR is `%x21 / %x23-5B / %x5D-7E` (no space, no double quote, no backslash).
fn is_scope_wire_form(s: &str) -> bool {
    !s.is_empty()
        && s.split(' ').all(|token| {
            !token.is_empty()
                && token
                    .chars()
                    .all(|c| matches!(c, '\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e'))
        })
}

/// RFC 6749 s5.2 `error_description`: `%x20-21 / %x23-5B / %x5D-7E`. Note this ADMITS the space
/// at `%x20` (descriptions are prose) while excluding `"` and `\`, which would have to be escaped
/// by any consumer re-emitting the value into a WWW-Authenticate header.
fn is_error_description_charset(s: &str) -> bool {
    s.chars()
        .all(|c| matches!(c, '\x20'..='\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e'))
}

/// The RFC 6749 s5.2 token-endpoint error codes, plus the four RFC 8628 s3.5 device-grant codes,
/// plus the registered extension codes this server's token endpoint really emits. A code outside
/// this set is not registered and no client is obliged to understand it.
///
/// The extension codes are gated exactly as the `ErrorCode` variants behind them are, so a build
/// without a feature admits exactly the set it admitted before that feature existed. Leaving them
/// out entirely was not "strict": it made this validator reject bodies the server produces, which
/// would have turned the first test to drive one through here into a false failure.
const TOKEN_ERROR_CODES: &[&str] = &[
    // RFC 6749 s5.2
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    // RFC 8628 s3.5
    "authorization_pending",
    "slow_down",
    "access_denied",
    "expired_token",
    // RFC 8693 s2.2.2 registers the code; RFC 8707 s2 is what directs an AS to use it for a
    // `resource` indicator it will not issue a token for. Not feature gated, because
    // `ErrorCode::InvalidTarget` is not either.
    "invalid_target",
    // RFC 9449 s5, registered by s12.3: the DPoP proof is missing, malformed, unbound or replayed.
    #[cfg(feature = "dpop")]
    "invalid_dpop_proof",
    // RFC 9396 s5: the `authorization_details` parameter is unparseable, names an unsupported
    // `type`, or asks for more than the underlying grant allows.
    #[cfg(feature = "rar")]
    "invalid_authorization_details",
];

/// The whole point of `additionalProperties: false`, which this replaces: an accidentally added
/// struct member, or a `#[serde(rename)]` typo, leaks into a wire body and no other assertion in
/// this file would notice. Asserting the EXACT admissible key set is what catches it, so this is
/// applied to all three shapes. It also carries the `required` check, because both questions are
/// about the same key set.
fn check_member_set(
    obj: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    cite: &str,
    out: &mut Violations,
) {
    for key in required {
        if !obj.contains_key(*key) {
            out.push(format!("missing REQUIRED member \"{key}\" ({cite})"));
        }
    }
    for key in obj.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            out.push(format!(
                "member \"{key}\" is not defined by {cite}; an undeclared member has leaked \
                 into a wire body"
            ));
        }
    }
}

/// Read a member that must be a JSON string when present, reporting a type violation otherwise.
fn string_member<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
    cite: &str,
    out: &mut Violations,
) -> Option<&'a str> {
    match obj.get(key) {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(other) => {
            out.push(format!(
                "member \"{key}\" must be a JSON string, got {other} ({cite})"
            ));
            None
        }
    }
}

/// Read a member that must be a non-negative JSON integer when present. `lifetime` members are
/// seconds, so a fractional or negative value is a defect regardless of the minimum applied next.
fn integer_member(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    minimum: u64,
    cite: &str,
    out: &mut Violations,
) {
    match obj.get(key) {
        None => {}
        Some(Value::Number(n)) => match n.as_u64() {
            Some(v) if v >= minimum => {}
            Some(v) => out.push(format!(
                "member \"{key}\" is {v}, below the minimum of {minimum} ({cite})"
            )),
            None => out.push(format!(
                "member \"{key}\" must be a non-negative integer, got {n} ({cite})"
            )),
        },
        Some(other) => out.push(format!(
            "member \"{key}\" must be a JSON number, got {other} ({cite})"
        )),
    }
}

fn as_object<'a>(
    body: &'a Value,
    cite: &str,
    out: &mut Violations,
) -> Option<&'a serde_json::Map<String, Value>> {
    match body.as_object() {
        Some(o) => Some(o),
        None => {
            out.push(format!("body must be a JSON object ({cite}), got {body}"));
            None
        }
    }
}

/// The exact spellings `token_type` may take, which is the whole registered set this server can
/// issue and not one value more.
///
/// The comparison against these is CASE EXACT on purpose. RFC 6749 s5.1 calls `token_type` case
/// insensitive for a RECIPIENT, but this assertion is about what this server EMITS, and emitting
/// `bearer` or `dpop` would be a silent change to the wire form that some strict third-party
/// clients reject. Pinning the spellings here is what makes such a change fail a test rather than
/// fail a user.
///
/// `DPoP` is gated exactly as `TokenType::Dpop` is. RFC 9449 s5 requires it on a token issued
/// against a proof, and s7.1 makes the spelling the HTTP authentication scheme name the client
/// will present the token under, so the capitalisation is load bearing rather than cosmetic.
const TOKEN_TYPES: &[&str] = &[
    // RFC 6750 s4.
    "Bearer",
    // RFC 9449 s5 / s7.1.
    #[cfg(feature = "dpop")]
    "DPoP",
];

/// RFC 6749 s5.1: `access_token` and `token_type` REQUIRED; `expires_in` a number; `scope` and
/// `refresh_token` strings. Parameter values are limited to VSCHAR on the wire; `token_type` is
/// pinned to the exact registered spellings in [`TOKEN_TYPES`]. Under the `rar` feature the body
/// also carries the RFC 9396 s7 `authorization_details` member, which section 7 makes a MUST on a
/// response to a request that carried them; it is gated here exactly as the struct member is, so a
/// build without `rar` still refuses it as undeclared.
fn validate_token_success(body: &Value) -> Violations {
    let cite = "RFC 6749 s5.1";
    let mut v = Violations::new();
    let Some(obj) = as_object(body, cite, &mut v) else {
        return v;
    };
    check_member_set(
        obj,
        &["access_token", "token_type"],
        &[
            "expires_in",
            "refresh_token",
            "scope",
            // RFC 9396 s7.
            #[cfg(feature = "rar")]
            "authorization_details",
        ],
        cite,
        &mut v,
    );
    if let Some(t) = string_member(obj, "access_token", cite, &mut v) {
        if !is_nonempty_vschar(t) {
            v.push(format!(
                "access_token {t:?} is not 1*VSCHAR (%x20-7E), which RFC 6749 Appendix A requires \
                 of a parameter value"
            ));
        }
    }
    if let Some(t) = string_member(obj, "token_type", cite, &mut v) {
        if !TOKEN_TYPES.contains(&t) {
            v.push(format!(
                "token_type is {t:?}; this server issues only {TOKEN_TYPES:?} and emits the \
                 spelling exactly as registered"
            ));
        }
    }
    // A zero-second lifetime is a token that is expired on arrival, so the floor is 1, not 0.
    integer_member(obj, "expires_in", 1, cite, &mut v);
    if let Some(t) = string_member(obj, "refresh_token", cite, &mut v) {
        if !is_nonempty_vschar(t) {
            v.push(format!(
                "refresh_token {t:?} is not 1*VSCHAR (%x20-7E), which RFC 6749 Appendix A requires \
                 of a parameter value"
            ));
        }
    }
    if let Some(s) = string_member(obj, "scope", cite, &mut v) {
        if !is_scope_wire_form(s) {
            v.push(format!(
                "scope {s:?} is not scope-token *( SP scope-token ) with scope-token = 1*NQCHAR \
                 (RFC 6749 Appendix A)"
            ));
        }
    }
    v
}

/// RFC 6749 s5.2 error object, with the `error` enum extended by the four RFC 8628 s3.5
/// device-grant codes. `error_description` is limited to the s5.2 charset.
fn validate_error_body(body: &Value) -> Violations {
    let cite = "RFC 6749 s5.2 / RFC 8628 s3.5";
    let mut v = Violations::new();
    let Some(obj) = as_object(body, cite, &mut v) else {
        return v;
    };
    check_member_set(
        obj,
        &["error"],
        &["error_description", "error_uri"],
        cite,
        &mut v,
    );
    if let Some(code) = string_member(obj, "error", cite, &mut v) {
        if !TOKEN_ERROR_CODES.contains(&code) {
            v.push(format!(
                "error code {code:?} is not one of the registered codes ({cite})"
            ));
        }
    }
    if let Some(d) = string_member(obj, "error_description", cite, &mut v) {
        if !is_error_description_charset(d) {
            v.push(format!(
                "error_description {d:?} contains characters outside %x20-21 / %x23-5B / %x5D-7E \
                 (RFC 6749 s5.2)"
            ));
        }
    }
    string_member(obj, "error_uri", cite, &mut v);
    v
}

/// RFC 8628 s3.2: `device_code`, `user_code`, `verification_uri`, `expires_in` REQUIRED;
/// `verification_uri_complete` and `interval` OPTIONAL. See the module docs for why the URI
/// members carry no format assertion here.
fn validate_device_authorization(body: &Value) -> Violations {
    let cite = "RFC 8628 s3.2";
    let mut v = Violations::new();
    let Some(obj) = as_object(body, cite, &mut v) else {
        return v;
    };
    check_member_set(
        obj,
        &["device_code", "user_code", "verification_uri", "expires_in"],
        &["verification_uri_complete", "interval"],
        cite,
        &mut v,
    );
    for key in [
        "device_code",
        "user_code",
        "verification_uri",
        "verification_uri_complete",
    ] {
        if let Some(s) = string_member(obj, key, cite, &mut v) {
            if s.is_empty() {
                v.push(format!("member \"{key}\" must not be empty ({cite})"));
            }
        }
    }
    // Same reasoning as the token body: a device code that has already expired is not a grant.
    integer_member(obj, "expires_in", 1, cite, &mut v);
    // RFC 8628 s3.2 gives `interval` as the minimum polling wait in seconds; 0 is legal (it means
    // the client may poll at the default 5s rate), a negative or fractional value is not.
    integer_member(obj, "interval", 0, cite, &mut v);
    v
}

fn assert_valid(validate: fn(&Value) -> Violations, body: &Value, what: &str) {
    let violations = validate(body);
    assert!(
        violations.is_empty(),
        "{what} violates the RFC schema: {violations:?}\nbody: {body}"
    );
}

/// The negative half of every assertion in this file. `base` must be conformant (asserted, so a
/// broken base can never make a rejection look meaningful) and `mutant` must be rejected for the
/// single named clause it violates.
fn assert_rejects(validate: fn(&Value) -> Violations, base: &Value, mutant: &Value, clause: &str) {
    assert!(
        validate(base).is_empty(),
        "the control body for {clause:?} is itself nonconformant, so its rejection would prove \
         nothing: {:?}",
        validate(base)
    );
    assert!(
        !validate(mutant).is_empty(),
        "the validator ACCEPTED a body that violates {clause}: {mutant}"
    );
}

fn client() -> Client {
    Client {
        client_id: ClientId::new("c"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn poll(device_code: &str) -> TokenRequest {
    TokenRequest::DeviceCode {
        client_id: ClientId::new("c"),
        client_secret: None,
        device_code: device_code.into(),
    }
}

/// Drive a whole device flow and validate EVERY emitted body against the transcribed clauses.
#[tokio::test]
async fn every_emitted_body_matches_the_rfc_schemas() {
    let clock = ManualClock::new();
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        clock.clone(),
    );
    srv.register_client(client()).await.unwrap();

    // Device authorization response (RFC 8628 s3.2).
    let auth = srv
        .device_authorization(&ClientId::new("c"), None, None)
        .await
        .unwrap();
    assert_valid(
        validate_device_authorization,
        &serde_json::to_value(&auth).unwrap(),
        "device authorization response",
    );

    // authorization_pending, then an immediate re-poll for slow_down.
    let pending = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(pending.error, ErrorCode::AuthorizationPending);
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&pending).unwrap(),
        "authorization_pending body",
    );
    let slow = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(slow.error, ErrorCode::SlowDown);
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&slow).unwrap(),
        "slow_down body",
    );

    // Approval, then the success body (RFC 6749 s5.1).
    srv.approve_device(&auth.user_code, "subject")
        .await
        .unwrap();
    clock.advance(Duration::from_secs(30));
    let token = srv.token(poll(&auth.device_code)).await.unwrap();
    assert_valid(
        validate_token_success,
        &serde_json::to_value(&token).unwrap(),
        "token success body",
    );

    // Spent code: invalid_grant.
    clock.advance(Duration::from_secs(30));
    let spent = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&spent).unwrap(),
        "invalid_grant body",
    );

    // Refresh success body.
    let refreshed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("c"),
            client_secret: None,
            refresh_token: token.refresh_token.clone().unwrap(),
            scope: None,
        })
        .await
        .unwrap();
    assert_valid(
        validate_token_success,
        &serde_json::to_value(&refreshed).unwrap(),
        "refresh success body",
    );

    // access_denied and expired_token bodies from fresh grants.
    let auth2 = srv
        .device_authorization(&ClientId::new("c"), None, None)
        .await
        .unwrap();
    srv.deny_device(&auth2.user_code).await.unwrap();
    clock.advance(Duration::from_secs(30));
    let denied = srv.token(poll(&auth2.device_code)).await.unwrap_err();
    assert_eq!(denied.error, ErrorCode::AccessDenied);
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&denied).unwrap(),
        "access_denied body",
    );

    let auth3 = srv
        .device_authorization(&ClientId::new("c"), None, None)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(600));
    let expired = srv.token(poll(&auth3.device_code)).await.unwrap_err();
    assert_eq!(expired.error, ErrorCode::ExpiredToken);
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&expired).unwrap(),
        "expired_token body",
    );

    // invalid_client and invalid_scope bodies (these carry descriptions; the description charset
    // constraint is part of the checked clause set).
    let bad_client = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("ghost"),
            client_secret: None,
            device_code: "x".into(),
        })
        .await
        .unwrap_err();
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&bad_client).unwrap(),
        "invalid_client body",
    );
    let bad_scope = srv
        .device_authorization(
            &ClientId::new("c"),
            None,
            Some(&ScopeSet::parse("root").unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(bad_scope.error, ErrorCode::InvalidScope);
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&bad_scope).unwrap(),
        "invalid_scope body",
    );
}

/// A conformant RFC 6749 s5.1 body, used as the control every success mutant is derived from.
fn valid_success() -> Value {
    json!({
        "access_token": "at-1",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "rt-1",
        "scope": "read write"
    })
}

/// A conformant RFC 6749 s5.2 body, used as the control every error mutant is derived from.
fn valid_error() -> Value {
    json!({ "error": "invalid_grant", "error_description": "the code was already used" })
}

/// A conformant RFC 8628 s3.2 body, used as the control every device mutant is derived from.
fn valid_device() -> Value {
    json!({
        "device_code": "dc-1",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://as.example/device",
        "verification_uri_complete": "https://as.example/device?user_code=ABCD-EFGH",
        "expires_in": 600,
        "interval": 5
    })
}

/// RED-PROOF for the RFC 6749 s5.1 success body. Every clause carried over from the schemas gets
/// one deliberately illegal fixture here, because a validator nobody has watched reject anything
/// is indistinguishable from `fn validate(_) -> Vec<String> { vec![] }`.
#[test]
fn the_token_success_clauses_reject_spec_illegal_bodies() {
    let base = valid_success();
    let reject = |mutant: Value, clause: &str| {
        assert_rejects(validate_token_success, &base, &mutant, clause);
    };

    // RFC 6749 s5.1: the body is a JSON object, not a bare value.
    reject(
        json!("at-1"),
        "a token response is a JSON object (RFC 6749 s5.1)",
    );

    // RFC 6749 s5.1: access_token and token_type are REQUIRED.
    reject(
        json!({ "token_type": "Bearer", "expires_in": 60 }),
        "access_token is REQUIRED (RFC 6749 s5.1)",
    );
    reject(
        json!({ "access_token": "at-1", "expires_in": 60 }),
        "token_type is REQUIRED (RFC 6749 s5.1)",
    );

    // additionalProperties: false. THE assertion this file exists for: a member nobody declared,
    // e.g. an id_token accidentally added to the token response by an OIDC-shaped change.
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "id_token": "eyJ..." }),
        "no undeclared member may appear in a token response (RFC 6749 s5.1)",
    );

    // RFC 6750: this server issues only Bearer, and emits it in exactly that case.
    reject(
        json!({ "access_token": "at-1", "token_type": "bearer" }),
        "token_type must be the exact string Bearer, not bearer",
    );
    reject(
        json!({ "access_token": "at-1", "token_type": "BEARER" }),
        "token_type must be the exact string Bearer, not BEARER",
    );
    reject(
        json!({ "access_token": "at-1", "token_type": "MAC" }),
        "token_type must be a registered type, not a foreign one",
    );
    // RFC 9449 s7.1 makes the spelling the authentication scheme name, so the capitalisation is
    // part of the wire contract in exactly the way "Bearer" is.
    #[cfg(feature = "dpop")]
    reject(
        json!({ "access_token": "at-1", "token_type": "dpop" }),
        "token_type must be the exact string DPoP, not dpop (RFC 9449 s7.1)",
    );

    // expires_in: a number, not the string some broken servers emit, and at least 1.
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "expires_in": "3600" }),
        "expires_in must be a JSON number (RFC 6749 s5.1)",
    );
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "expires_in": 0 }),
        "expires_in must be at least 1; a zero-second token is expired on arrival",
    );

    // VSCHAR (%x20-7E) on access_token and refresh_token, per RFC 6749 Appendix A.
    reject(
        json!({ "access_token": "", "token_type": "Bearer" }),
        "access_token must be 1*VSCHAR, so never empty",
    );
    reject(
        json!({ "access_token": "at\u{7f}1", "token_type": "Bearer" }),
        "access_token must be VSCHAR: DEL (%x7F) is outside %x20-7E",
    );
    reject(
        json!({ "access_token": "at\n1", "token_type": "Bearer" }),
        "access_token must be VSCHAR: LF is outside %x20-7E",
    );
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "refresh_token": "" }),
        "refresh_token must be 1*VSCHAR, so never empty",
    );
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "refresh_token": "rt\u{e9}1" }),
        "refresh_token must be VSCHAR: a non-ASCII character is outside %x20-7E",
    );

    // scope: scope-token *( SP scope-token ), scope-token = 1*NQCHAR.
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "scope": "read  write" }),
        "scope tokens are separated by exactly one SP (RFC 6749 Appendix A)",
    );
    reject(
        json!({ "access_token": "at-1", "token_type": "Bearer", "scope": "read \"write\"" }),
        "a double quote is not NQCHAR (RFC 6749 Appendix A)",
    );
}

/// RED-PROOF for the RFC 6749 s5.2 / RFC 8628 s3.5 error body.
#[test]
fn the_error_clauses_reject_spec_illegal_bodies() {
    let base = valid_error();
    let reject = |mutant: Value, clause: &str| {
        assert_rejects(validate_error_body, &base, &mutant, clause);
    };

    // RFC 6749 s5.2: the body is a JSON object, not a bare value.
    reject(
        json!("invalid_grant"),
        "an error response is a JSON object (RFC 6749 s5.2)",
    );

    // `error` is REQUIRED and must be a REGISTERED code.
    reject(
        json!({ "error_description": "no code at all" }),
        "error is REQUIRED (RFC 6749 s5.2)",
    );
    reject(
        json!({ "error": "pending" }),
        "\"pending\" is not a registered code; RFC 8628 s3.5 defines authorization_pending",
    );
    reject(
        json!({ "error": "slowdown" }),
        "the registered code is slow_down, with the underscore (RFC 8628 s3.5)",
    );
    reject(
        json!({ "error": 42 }),
        "error must be a JSON string (RFC 6749 s5.2)",
    );

    // additionalProperties: false.
    reject(
        json!({ "error": "invalid_grant", "status": 400 }),
        "no undeclared member may appear in an error response (RFC 6749 s5.2)",
    );

    // error_description charset: %x20-21 / %x23-5B / %x5D-7E.
    reject(
        json!({ "error": "invalid_request", "error_description": "d\u{e9}sol\u{e9}" }),
        "non-ASCII in error_description violates the RFC 6749 s5.2 charset",
    );
    reject(
        json!({ "error": "invalid_request", "error_description": "he said \"no\"" }),
        "a double quote (%x22) is excluded from the RFC 6749 s5.2 charset",
    );
    reject(
        json!({ "error": "invalid_request", "error_description": "a\\b" }),
        "a backslash (%x5C) is excluded from the RFC 6749 s5.2 charset",
    );
    reject(
        json!({ "error": "invalid_request", "error_description": "line\r\nbreak" }),
        "CR/LF are excluded from the RFC 6749 s5.2 charset",
    );
}

/// RED-PROOF for the RFC 8628 s3.2 device authorization response.
#[test]
fn the_device_authorization_clauses_reject_spec_illegal_bodies() {
    let base = valid_device();
    let reject = |mutant: Value, clause: &str| {
        assert_rejects(validate_device_authorization, &base, &mutant, clause);
    };

    // RFC 8628 s3.2: the body is a JSON object, not a bare value.
    reject(
        json!(["dc-1"]),
        "a device authorization response is a JSON object (RFC 8628 s3.2)",
    );

    // All four REQUIRED members, one fixture each.
    reject(
        json!({ "user_code": "U", "verification_uri": "https://x", "expires_in": 600 }),
        "device_code is REQUIRED (RFC 8628 s3.2)",
    );
    reject(
        json!({ "device_code": "d", "verification_uri": "https://x", "expires_in": 600 }),
        "user_code is REQUIRED (RFC 8628 s3.2)",
    );
    reject(
        json!({ "device_code": "d", "user_code": "U", "expires_in": 600 }),
        "verification_uri is REQUIRED (RFC 8628 s3.2)",
    );
    reject(
        json!({ "device_code": "d", "user_code": "U", "verification_uri": "https://x" }),
        "expires_in is REQUIRED (RFC 8628 s3.2)",
    );

    // additionalProperties: false.
    reject(
        json!({
            "device_code": "d", "user_code": "U", "verification_uri": "https://x",
            "expires_in": 600, "verification_url": "https://x"
        }),
        "no undeclared member may appear; verification_url is the Google-era misspelling",
    );

    // Empty strings, and the numeric bounds.
    reject(
        json!({ "device_code": "", "user_code": "U", "verification_uri": "https://x",
                "expires_in": 600 }),
        "device_code must not be empty (RFC 8628 s3.2)",
    );
    reject(
        json!({ "device_code": "d", "user_code": "", "verification_uri": "https://x",
                "expires_in": 600 }),
        "user_code must not be empty (RFC 8628 s3.2)",
    );
    reject(
        json!({ "device_code": "d", "user_code": "U", "verification_uri": "https://x",
                "expires_in": 0 }),
        "expires_in must be at least 1; a grant that has already expired is not a grant",
    );
    reject(
        json!({ "device_code": "d", "user_code": "U", "verification_uri": "https://x",
                "expires_in": "600" }),
        "expires_in must be a JSON number (RFC 8628 s3.2)",
    );
    reject(
        json!({ "device_code": "d", "user_code": "U", "verification_uri": "https://x",
                "expires_in": 600, "interval": -1 }),
        "interval is a wait in seconds and cannot be negative (RFC 8628 s3.2)",
    );
}

/// THE SHAPES THE DEVICE FLOW CANNOT REACH, part one: RFC 9449 s5's `token_type: "DPoP"`.
///
/// `every_emitted_body_matches_the_rfc_schemas` above drives the device-code grant, which carries
/// no proof, so until this existed no test had ever put a DPoP success body in front of these
/// validators and the file's claim to check "every body this AS emits" was a claim about bodies it
/// had never seen. A validator that rejects a body the server really emits is not a strict gate,
/// it is a gate pointed the wrong way: the first deployment to turn `dpop` on would have found the
/// conformance suite calling its conforming responses nonconformant.
#[tokio::test]
#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
async fn a_dpop_bound_token_response_matches_the_rfc_schemas() {
    // The system clock, not the manual one: an RFC 9449 s4.2 proof carries an `iat` the server
    // checks against ITS clock, and a proof issued at 2023-11-14 for a server that thinks it is
    // now would be refused for freshness rather than validated for shape.
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
    );
    srv.register_client(Client {
        client_id: ClientId::new("c"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "conformance-secret-for-tests".to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    let key = oauth_as::jwt::EcdsaP256Key::generate("conformance");
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = json!({
        "jti": "conformance-proof-1",
        "htm": "POST",
        "htu": "https://as.example/token",
        "iat": iat,
    });
    let proof = oauth_as::jwt::compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    );
    let token = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("c"),
                client_secret: Some("conformance-secret-for-tests".to_string()),
                scope: None,
            },
            oauth_as::TokenRequestContext::default().with_dpop_proof(&proof),
        )
        .await
        .expect("a conforming proof yields a token");

    let body = serde_json::to_value(&token).unwrap();
    assert_eq!(
        body.get("token_type").and_then(Value::as_str),
        Some("DPoP"),
        "the fixture must actually have produced the shape under test, or this proves nothing"
    );
    assert_valid(
        validate_token_success,
        &body,
        "DPoP-bound token success body",
    );
}

/// THE SHAPES THE DEVICE FLOW CANNOT REACH, part two: RFC 9396 s7's `authorization_details`.
///
/// Section 7 makes returning the details AS GRANTED a MUST on a response to a request that carried
/// them, so this sixth success member is not an extension a deployment opts into at the wire level:
/// it is what a conforming AS emits the moment a client uses the parameter. The validator declared
/// five members, so it would have reported the required one as an undeclared leak.
#[tokio::test]
#[cfg(feature = "rar")]
async fn a_rich_authorization_token_response_matches_the_rfc_schemas() {
    const DETAILS: &str = r#"[{"type":"payment_initiation","actions":["initiate"],"locations":["https://rs.example/payments"],"identifier":"acct-1"}]"#;
    const REDIRECT: &str = "https://rar.example/cb";
    const SECRET: &str = "conformance-rar-secret-for-tests";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.authorization_details_types_supported = Some(vec!["payment_initiation".to_string()]);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::new());
    srv.register_client(Client {
        client_id: ClientId::new("c"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let req = oauth_as::AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "c"),
        ("redirect_uri", REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("authorization_details", DETAILS),
    ]);
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let issued = srv
        .issue_authorization_code(oauth_as::server::UserApproval::granted(&validated, "u"))
        .await
        .unwrap();
    let token = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("c"),
            client_secret: Some(SECRET.to_string()),
            code: issued.code,
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: Some(VERIFIER.to_string()),
        })
        .await
        .expect("the redemption must succeed");

    let body = serde_json::to_value(&token).unwrap();
    assert!(
        body.get("authorization_details").is_some(),
        "the fixture must actually have produced the shape under test, or this proves nothing: \
         {body}"
    );
    assert_valid(validate_token_success, &body, "RFC 9396 token success body");
}

/// The token endpoint's registered EXTENSION error codes, driven end to end rather than asserted
/// as literals, because the point of this file is what comes off the wire. Each of these was
/// outside `TOKEN_ERROR_CODES` while the endpoint really emitted it, which the device-code-only
/// walk above could never have discovered.
#[tokio::test]
async fn the_extension_error_bodies_match_the_rfc_schemas() {
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        ManualClock::new(),
    );
    srv.register_client(Client {
        client_id: ClientId::new("c"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "extension-secret-for-tests".to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    let request = || TokenRequest::ClientCredentials {
        client_id: ClientId::new("c"),
        client_secret: Some("extension-secret-for-tests".to_string()),
        scope: None,
    };

    // RFC 8707 s2: a `resource` that is not an absolute URI without a fragment.
    let resources = vec!["not-a-uri".to_string()];
    let bad_target = srv
        .token_with_context(
            request(),
            oauth_as::TokenRequestContext::default().with_resources(&resources),
        )
        .await
        .expect_err("RFC 8707 s2 refuses a malformed resource indicator");
    assert_eq!(bad_target.error, ErrorCode::InvalidTarget);
    assert_valid(
        validate_error_body,
        &serde_json::to_value(&bad_target).unwrap(),
        "invalid_target body",
    );

    // RFC 9449 s5: a proof that is not even a JWS.
    #[cfg(feature = "dpop")]
    {
        let bad_proof = srv
            .token_with_context(
                request(),
                oauth_as::TokenRequestContext::default().with_dpop_proof("not-a-proof"),
            )
            .await
            .expect_err("RFC 9449 s5 refuses a malformed proof");
        assert_eq!(bad_proof.error, ErrorCode::InvalidDpopProof);
        assert_valid(
            validate_error_body,
            &serde_json::to_value(&bad_proof).unwrap(),
            "invalid_dpop_proof body",
        );
    }

    // RFC 9396 s5: `authorization_details` that is not even JSON.
    #[cfg(feature = "rar")]
    {
        let bad_details = srv
            .token_with_context(
                request(),
                oauth_as::TokenRequestContext::default().with_authorization_details("{"),
            )
            .await
            .expect_err("RFC 9396 s5 refuses unparseable authorization_details");
        assert_eq!(bad_details.error, ErrorCode::InvalidAuthorizationDetails);
        assert_valid(
            validate_error_body,
            &serde_json::to_value(&bad_details).unwrap(),
            "invalid_authorization_details body",
        );
    }
}

/// The ErrorResponse type itself cannot serialize an unregistered code (the enum is closed), so
/// pin the serialized form of each device-grant code against the validator one by one.
///
/// UNFALSIFIABLE-BY-TYPE, and named rather than tested: several schema clauses cannot be violated
/// by anything this crate serializes, because the Rust type already forbids it. `expires_in` is a
/// `u64`, so it can never be a string, negative, or fractional; `token_type` is the closed
/// `TokenType` enum and `error` the closed `ErrorCode` enum, so neither can carry an unregistered
/// string; and no response type uses `#[serde(flatten)]`, so no member can appear that its struct
/// did not declare. The checks above are therefore aimed at the SERIALIZATION, not at the values:
/// a changed `#[serde(rename)]`, a new struct member, or a `skip_serializing_if` that drops a
/// REQUIRED member are all real, reachable defects, and the red-proofs above show each check
/// firing on exactly that shape of body. Writing a test that fed an out-of-range `u64` through
/// these types would be impossible, not merely redundant.
#[test]
fn each_device_grant_error_code_serializes_to_a_registered_wire_form() {
    for code in [
        ErrorCode::AuthorizationPending,
        ErrorCode::SlowDown,
        ErrorCode::AccessDenied,
        ErrorCode::ExpiredToken,
    ] {
        let body = serde_json::to_value(ErrorResponse::new(code)).unwrap();
        assert_valid(validate_error_body, &body, "device-grant error body");
    }
}
