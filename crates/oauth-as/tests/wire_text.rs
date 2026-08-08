// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The human- and wire-facing TEXT of this crate's types, plus the small set-semantics accessors
//! on [`ScopeSet`].
//!
//! Why this file exists: mutation testing showed that every `Display` implementation in the crate
//! could be replaced with one that writes NOTHING and no test noticed. That matters more here than
//! in an ordinary library. `ErrorCode`'s `Display` is the registered RFC 6749 section 5.2 wire
//! token, `GrantType`'s is the registered `grant_type` value (RFC 8628's is a full URN), and
//! `ScopeSet`'s is the RFC 6749 section 3.3 space-delimited wire form that the `Serialize` impl is
//! built directly on top of. A silently empty `Display` on any of those is a protocol defect, not a
//! cosmetic one. The error types' `Display` is what a host puts in its own operational logs, and an
//! empty one there turns a diagnosable failure into a blank line.

use oauth_as::authorization::{AuthorizationErrorRedirect, AuthorizationResponse};
use oauth_as::grant::UnknownGrantType;
use oauth_as::scope::InvalidScopeToken;
use oauth_as::server::DeviceApprovalError;
use oauth_as::{
    AuthorizationError, ClientId, ErrorCode, ErrorResponse, GrantType, IntrospectionResponse,
    Scope, ScopeSet, StorageError, TokenTypeHint,
};

// --------------------------------------------------------------------- registered wire tokens

/// RFC 6749 section 5.2 and RFC 8628 section 3.5: each `error` code has ONE registered spelling,
/// and `Display` must produce exactly it. A host that logs or renders `{err}` is looking at the
/// same token the wire carries, so this pins `Display` to `as_str` rather than letting the two
/// drift (or letting `Display` write nothing at all).
#[test]
fn error_code_display_is_the_registered_wire_token() {
    for (code, wire) in [
        (ErrorCode::InvalidRequest, "invalid_request"),
        (ErrorCode::InvalidClient, "invalid_client"),
        (ErrorCode::InvalidGrant, "invalid_grant"),
        (ErrorCode::UnauthorizedClient, "unauthorized_client"),
        (ErrorCode::UnsupportedGrantType, "unsupported_grant_type"),
        (ErrorCode::InvalidScope, "invalid_scope"),
        (ErrorCode::AccessDenied, "access_denied"),
        (
            ErrorCode::UnsupportedResponseType,
            "unsupported_response_type",
        ),
        (ErrorCode::ServerError, "server_error"),
        (ErrorCode::TemporarilyUnavailable, "temporarily_unavailable"),
        (ErrorCode::AuthorizationPending, "authorization_pending"),
        (ErrorCode::SlowDown, "slow_down"),
        (ErrorCode::ExpiredToken, "expired_token"),
    ] {
        assert_eq!(format!("{code}"), wire);
    }
}

/// RFC 6749 section 4 and RFC 8628 section 3.4: the `grant_type` request parameter carries these
/// exact strings, and the device grant's is the full registered URN rather than a short name.
/// `Display` is what a host building a request or a log line reaches for, so it must be the
/// registered spelling and must round-trip back through `FromStr`.
#[test]
fn grant_type_display_is_the_registered_value_and_round_trips() {
    for (grant, wire) in [
        (GrantType::AuthorizationCode, "authorization_code"),
        (GrantType::RefreshToken, "refresh_token"),
        (GrantType::ClientCredentials, "client_credentials"),
        (
            GrantType::DeviceCode,
            "urn:ietf:params:oauth:grant-type:device_code",
        ),
    ] {
        assert_eq!(format!("{grant}"), wire);
        assert_eq!(wire.parse::<GrantType>().unwrap(), grant);
    }
}

/// RFC 6749 section 2.2: a `client_id` is not a secret and is the identifier every other party
/// names the client by, so `Display` must reproduce it verbatim, unaltered and non-empty.
#[test]
fn client_id_display_is_the_identifier_verbatim() {
    assert_eq!(format!("{}", ClientId::new("public-app")), "public-app");
    assert_eq!(ClientId::new("public-app").as_str(), "public-app");
}

/// RFC 6749 section 3.3: a scope token is the literal string the client asked for, so `Display`
/// must reproduce it exactly. `ScopeSet`'s space-delimited wire form is built out of these, so an
/// empty or substituted `Display` here would silently corrupt the `scope` parameter itself.
#[test]
fn scope_display_is_the_token_verbatim() {
    let scope = Scope::new("read").unwrap();
    assert_eq!(format!("{scope}"), "read");
    assert_eq!(scope.as_str(), "read");
}

/// RFC 6749 section 3.3: the wire form of a scope set is its tokens, space delimited, and this
/// crate emits them in lexicographic order so the serialization is deterministic. `Display` IS the
/// wire form (`Serialize` calls it), so an empty one would put `scope=""` on the wire.
#[test]
fn scope_set_display_is_the_space_delimited_wire_form() {
    assert_eq!(
        ScopeSet::parse("write read admin").unwrap().to_string(),
        "admin read write"
    );
    assert_eq!(ScopeSet::parse("read").unwrap().to_string(), "read");
    // The empty set is the one case that legitimately prints nothing; hosts omit the parameter.
    assert_eq!(ScopeSet::empty().to_string(), "");
}

// ------------------------------------------------------------------- diagnostic error text

/// RFC 6749 section 5.2 makes `error_description` the developer-facing detail, and this crate's
/// `Display` is what a host writes to its own log. It must show the code, and must show the
/// description too when there is one, or a host log loses the only detail the server produced.
#[test]
fn error_response_display_shows_the_code_and_any_description() {
    let bare = ErrorResponse::new(ErrorCode::InvalidGrant);
    assert_eq!(format!("{bare}"), "invalid_grant");

    let detailed =
        ErrorResponse::new(ErrorCode::InvalidGrant).with_description("authorization code expired");
    assert_eq!(
        format!("{detailed}"),
        "invalid_grant: authorization code expired"
    );
    // `with_description` attaches the text without disturbing the code that is going on the wire.
    assert_eq!(detailed.error, ErrorCode::InvalidGrant);
    assert_eq!(
        detailed.error_description.as_deref(),
        Some("authorization code expired")
    );
    assert_eq!(detailed.error_uri, None);
}

/// An unknown `grant_type` is refused (RFC 6749 section 5.2 `unsupported_grant_type`), and the
/// rejection has to name the value that was refused: "unknown grant_type" with the value missing
/// tells an operator nothing about which client is misconfigured.
#[test]
fn unknown_grant_type_display_names_the_rejected_value() {
    let err = "password".parse::<GrantType>().unwrap_err();
    assert_eq!(err, UnknownGrantType("password".to_string()));
    let printed = format!("{err}");
    assert!(printed.contains("password"), "{printed}");
    assert!(printed.contains("unknown grant_type"), "{printed}");
}

/// Same requirement for a malformed scope token (RFC 6749 section 3.3): the rejection must carry
/// the offending token, or an operator cannot tell which of several scopes was refused.
#[test]
fn invalid_scope_token_display_names_the_rejected_token() {
    let err = Scope::new("has space").unwrap_err();
    assert_eq!(err, InvalidScopeToken("has space".to_string()));
    let printed = format!("{err}");
    assert!(printed.contains("has space"), "{printed}");
    assert!(printed.contains("invalid scope token"), "{printed}");
}

/// [`StorageError`]'s text is explicitly host-log-only (it never reaches the wire, where a storage
/// failure becomes an opaque `server_error` per RFC 6749 section 5.2). That makes the `Display`
/// text the ONLY place the real cause survives, so an empty one loses it entirely.
#[test]
fn storage_error_display_carries_the_host_facing_cause() {
    let err = StorageError::new("connection pool exhausted");
    let printed = format!("{err}");
    assert!(printed.contains("connection pool exhausted"), "{printed}");
    assert!(printed.contains("storage error"), "{printed}");
}

/// The device verification-UI rejections are not wire errors: RFC 8628 leaves the verification
/// interaction to the implementation, so this text is what the HOST renders or logs. Each variant
/// must say something different, or the host cannot tell an unknown code from an expired one from
/// an already-used one.
#[test]
fn device_approval_error_display_distinguishes_every_outcome() {
    let cases = [
        (DeviceApprovalError::UnknownUserCode, "unknown user code"),
        (DeviceApprovalError::Expired, "the code has expired"),
        (DeviceApprovalError::NotPending, "the code was already used"),
        (
            DeviceApprovalError::Storage(StorageError::new("io failure")),
            "storage error: io failure",
        ),
    ];
    for (err, text) in &cases {
        assert_eq!(&format!("{err}"), text);
    }
}

/// RFC 6749 section 4.1.2.1 splits authorization errors into the form that MUST NOT redirect and
/// the form delivered to the validated redirect URI. Both carry an `ErrorResponse`, and `Display`
/// must surface it either way: a host logging a refused authorization request should not have to
/// know which arm it landed in to find out what went wrong.
#[test]
fn authorization_error_display_surfaces_the_inner_error_from_either_arm() {
    let direct = AuthorizationError::Direct(
        ErrorResponse::new(ErrorCode::InvalidRequest).with_description("unknown client_id"),
    );
    assert_eq!(format!("{direct}"), "invalid_request: unknown client_id");

    let redirect = AuthorizationError::Redirect(AuthorizationErrorRedirect {
        redirect_uri: "https://app.example/cb".to_string(),
        error: ErrorResponse::new(ErrorCode::AccessDenied),
        state: None,
        iss: "https://as.example".to_string(),
    });
    assert_eq!(format!("{redirect}"), "access_denied");
}

/// RFC 6749 section 4.1.2.1 again, as a status code. `invalid_client`'s 401 belongs to the token
/// endpoint's `WWW-Authenticate` exchange; the authorization endpoint has no client authentication
/// to challenge, so a refused request is a plain 400, a redirected one is a 302, and only an
/// internal failure is a 500.
#[test]
fn authorization_error_http_status_separates_direct_redirect_and_server_error() {
    assert_eq!(
        AuthorizationError::Direct(ErrorResponse::new(ErrorCode::InvalidRequest)).http_status(),
        400
    );
    assert_eq!(
        AuthorizationError::Direct(ErrorResponse::new(ErrorCode::InvalidClient)).http_status(),
        400,
        "invalid_client's 401 is a token-endpoint rule; there is nothing to challenge here"
    );
    assert_eq!(
        AuthorizationError::Direct(ErrorResponse::new(ErrorCode::ServerError)).http_status(),
        500
    );
    assert_eq!(
        AuthorizationError::Redirect(AuthorizationErrorRedirect {
            redirect_uri: "https://app.example/cb".to_string(),
            error: ErrorResponse::new(ErrorCode::AccessDenied),
            state: None,
            iss: "https://as.example".to_string(),
        })
        .http_status(),
        302
    );
}

// -------------------------------------------------------------------- set semantics on scope

/// RFC 6749 section 3.3 treats scope as a SET of case-sensitive tokens. `contains` is a membership
/// test over that set and must answer honestly in both directions, and must not match a token by
/// prefix or by case: `read` is not `readwrite` and is not `READ`.
#[test]
fn scope_set_membership_is_exact_and_case_sensitive() {
    let set = ScopeSet::parse("read write").unwrap();
    assert!(set.contains("read"));
    assert!(set.contains("write"));
    assert!(
        !set.contains("admin"),
        "a token not in the set is not in it"
    );
    assert!(!set.contains("rea"), "membership is not a prefix test");
    assert!(
        !set.contains("readwrite"),
        "membership is not a substring test"
    );
    assert!(
        !set.contains("READ"),
        "RFC 6749 s3.3 scope tokens are case sensitive"
    );
    assert!(!ScopeSet::empty().contains("read"));
}

/// `iter` is the only way a host can enumerate a granted scope set, so it must yield every token
/// and yield them in the crate's stated lexicographic order.
#[test]
fn scope_set_iteration_yields_every_token_in_order() {
    let set = ScopeSet::parse("write read admin").unwrap();
    let tokens: Vec<&str> = set.iter().map(|s| s.as_str()).collect();
    assert_eq!(tokens, vec!["admin", "read", "write"]);
    assert_eq!(tokens.len(), set.len());
    assert_eq!(ScopeSet::empty().iter().count(), 0);
}

/// `is_empty` decides whether the RFC 6749 section 5.1 `scope` member is included in a token
/// response at all, so it has to be false for a populated set as well as true for an empty one.
#[test]
fn scope_set_emptiness_answers_both_ways() {
    assert!(ScopeSet::empty().is_empty());
    assert_eq!(ScopeSet::empty().len(), 0);
    let set = ScopeSet::parse("read").unwrap();
    assert!(!set.is_empty());
    assert_eq!(set.len(), 1);
}

/// `from_tokens` is the programmatic constructor a host uses to build a registration's allowed and
/// default scopes. It must validate each token against the RFC 6749 section 3.3 grammar (so an
/// illegal scope cannot enter a registration by the side door) and must actually keep the tokens.
#[test]
fn scope_set_from_tokens_validates_and_retains_every_token() {
    let set = ScopeSet::from_tokens(["write", "read", "read"]).unwrap();
    assert_eq!(set.len(), 2, "duplicates collapse, as in a set");
    assert_eq!(set.to_string(), "read write");
    assert!(
        ScopeSet::from_tokens(["read", "has space"]).is_err(),
        "the section 3.3 charset applies to the programmatic constructor too"
    );
    assert!(
        ScopeSet::from_tokens(["read", ""]).is_err(),
        "a scope token is 1*(charset), never empty"
    );
    assert!(ScopeSet::from_tokens(Vec::<String>::new())
        .unwrap()
        .is_empty());
}

// ----------------------------------------------------------------------- small wire helpers

/// RFC 7662 section 2.2: for an inactive token `active` is the ONLY member, because section 4
/// warns the endpoint must not describe a token the caller has not proven it holds. Every other
/// member must therefore be absent, not merely falsy.
#[test]
fn inactive_introspection_response_carries_nothing_but_active_false() {
    let inactive = IntrospectionResponse::inactive();
    assert!(!inactive.active);
    assert_eq!(inactive.scope, None);
    assert_eq!(inactive.client_id, None);
    assert_eq!(inactive.sub, None);
    assert_eq!(inactive.token_type, None);
    assert_eq!(inactive.exp, None);
    assert_eq!(inactive.iat, None);
    assert_eq!(inactive.iss, None);
    assert_eq!(
        serde_json::to_value(&inactive).unwrap(),
        serde_json::json!({ "active": false }),
        "absent members must be omitted, never null"
    );
}

/// RFC 7009 section 2.1: `token_type_hint` has exactly two registered values, and anything else is
/// simply not a hint. Parsing must accept both and reject the rest, including the near misses a
/// client might invent.
#[test]
fn token_type_hint_parses_exactly_the_two_registered_values() {
    assert_eq!(
        "access_token".parse::<TokenTypeHint>(),
        Ok(TokenTypeHint::AccessToken)
    );
    assert_eq!(
        "refresh_token".parse::<TokenTypeHint>(),
        Ok(TokenTypeHint::RefreshToken)
    );
    for unknown in ["", "AccessToken", "access-token", "id_token", "bearer"] {
        assert!(
            unknown.parse::<TokenTypeHint>().is_err(),
            "{unknown} is not a registered token_type_hint"
        );
    }
}

/// RFC 6749 section 4.1.2: the success redirect carries `code`, and `state` only when the request
/// carried one. Both are appended as query parameters, so the separator has to be `?` for a URI
/// with no query and `&` for one that already has a query, and every value has to be
/// percent-encoded or a crafted value could forge or truncate the query.
#[test]
fn authorization_response_location_encodes_and_separates_correctly() {
    let no_state = AuthorizationResponse {
        code: "abc".to_string(),
        state: None,
        // RFC 9207 s2: every authorization response names its issuer, so every expected string
        // below carries it. The value is percent-encoded like any other parameter.
        iss: "https://as.example".to_string(),
    };
    assert_eq!(
        no_state.location("https://app.example/cb"),
        "https://app.example/cb?code=abc&iss=https%3A%2F%2Fas.example"
    );
    assert_eq!(
        no_state.location("https://app.example/cb?tenant=acme"),
        "https://app.example/cb?tenant=acme&code=abc&iss=https%3A%2F%2Fas.example"
    );

    let with_state = AuthorizationResponse {
        code: "a&b".to_string(),
        state: Some("x=y#z".to_string()),
        iss: "https://as.example".to_string(),
    };
    assert_eq!(
        with_state.location("https://app.example/cb"),
        "https://app.example/cb?code=a%26b&state=x%3Dy%23z&iss=https%3A%2F%2Fas.example"
    );
}

/// RFC 6749 section 4.1.2.1: the error redirect carries `error`, the optional `error_description`
/// and `error_uri`, and the echoed `state`. Same encoding and separator rules as the success
/// redirect, and the same reason: an unencoded `&` or `#` in a description would forge or truncate
/// the query the client is about to parse.
#[test]
fn authorization_error_redirect_location_carries_every_present_member() {
    let full = AuthorizationErrorRedirect {
        redirect_uri: "https://app.example/cb?tenant=acme".to_string(),
        error: ErrorResponse {
            error: ErrorCode::InvalidScope,
            error_description: Some("scope [a&b] exceeds".to_string()),
            error_uri: Some("https://as.example/docs#scope".to_string()),
        },
        state: Some("s t".to_string()),
        iss: "https://as.example".to_string(),
    };
    assert_eq!(
        full.location(),
        "https://app.example/cb?tenant=acme\
         &error=invalid_scope\
         &error_description=scope%20%5Ba%26b%5D%20exceeds\
         &error_uri=https%3A%2F%2Fas.example%2Fdocs%23scope\
         &state=s%20t\
         &iss=https%3A%2F%2Fas.example"
    );

    let minimal = AuthorizationErrorRedirect {
        redirect_uri: "https://app.example/cb".to_string(),
        error: ErrorResponse::new(ErrorCode::AccessDenied),
        state: None,
        iss: "https://as.example".to_string(),
    };
    assert_eq!(
        minimal.location(),
        // RFC 9207 s2 puts iss on the error response too; absent OPTIONAL members still
        // contribute nothing.
        "https://app.example/cb?error=access_denied&iss=https%3A%2F%2Fas.example",
        "absent optional members must contribute no parameter at all"
    );
}
