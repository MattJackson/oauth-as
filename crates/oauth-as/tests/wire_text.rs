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
            error_description: Some("scope [a&b] exceeds".into()),
            error_uri: Some("https://as.example/docs#scope".into()),
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

// ------------------------------------------------------------- the optional features' own text
//
// Everything below is behind a cargo feature, and every one of these `Display` and `Debug`
// implementations was a surviving mutant in the first all-features mutation run: each could be
// replaced with one that writes NOTHING and the suite still passed. They are grouped here rather
// than scattered across the feature test files because what they have in common is the reason they
// matter: an error whose text is empty is a host operator staring at a blank audit line while an
// authentication is being refused for a reason nobody can now name.

/// RFC 7523 section 3: every one of these refusals collapses to `invalid_client` on the wire, so
/// the ONLY place the distinction survives is the host's audit channel, and that channel is this
/// `Display`. An empty one turns a diagnosable `private_key_jwt` failure into a blank line.
#[cfg(feature = "client_assertion")]
#[test]
fn client_assertion_failure_display_names_the_check_that_refused() {
    use oauth_as::AssertionFailure;

    for (failure, text) in [
        (
            AssertionFailure::Malformed,
            "the client assertion is not a well formed JWT",
        ),
        (
            AssertionFailure::AlgorithmMismatch,
            "the client assertion alg is not the one this registration signs with",
        ),
        (
            AssertionFailure::BadSignature,
            "the client assertion signature did not verify",
        ),
        (
            AssertionFailure::WrongPrincipal,
            "the client assertion iss/sub is not this client",
        ),
        (
            AssertionFailure::WrongAudience,
            "the client assertion aud is not this server",
        ),
        (
            AssertionFailure::Expired,
            "the client assertion is expired or too long lived",
        ),
        (
            AssertionFailure::NotYetValid,
            "the client assertion is not yet valid",
        ),
        (
            AssertionFailure::MissingJti,
            "the client assertion carries no jti",
        ),
        (
            AssertionFailure::Replayed,
            "the client assertion jti has already been used",
        ),
    ] {
        assert_eq!(format!("{failure}"), text);
    }
}

/// RFC 7591 section 2 and RFC 8414 `token_endpoint_auth_methods_supported`: these two names are
/// registered spellings that a metadata document advertises and a client matches on, so the
/// accessor has to produce exactly them and has to tell the two variants apart.
#[cfg(feature = "client_assertion")]
#[test]
fn assertion_keys_report_the_registered_auth_method_and_never_print_the_secret() {
    use oauth_as::AssertionKeys;

    let symmetric = AssertionKeys::ClientSecret {
        secret: "s3cr3t-not-for-logs".to_string(),
    };
    let asymmetric = AssertionKeys::PublicKeys { keys: Vec::new() };

    assert_eq!(
        symmetric.token_endpoint_auth_method(),
        "client_secret_jwt",
        "RFC 7523 section 2.2 with a MAC is `client_secret_jwt` on the wire"
    );
    assert_eq!(
        asymmetric.token_endpoint_auth_method(),
        "private_key_jwt",
        "RFC 7523 section 2.2 with a signature is `private_key_jwt` on the wire"
    );

    // The hand-written `Debug` exists to keep the shared secret out of a log; an empty one would
    // hide the whole registration instead, which is the other way of being useless.
    let printed = format!("{symmetric:?}");
    assert_eq!(printed, "ClientSecret { secret: \"[redacted]\" }");
    assert!(!printed.contains("s3cr3t-not-for-logs"));
    assert_eq!(format!("{asymmetric:?}"), "PublicKeys { keys: [] }");
}

/// RFC 9449 section 4.3 lists the checks a proof must pass. Each refusal below is one of them, and
/// the text is the only record of WHICH, since the wire answer is the same `invalid_dpop_proof`
/// either way.
#[cfg(feature = "dpop")]
#[test]
fn dpop_failure_display_names_the_check_that_refused() {
    use oauth_as::DpopFailure;

    for (failure, text) in [
        (
            DpopFailure::Malformed,
            "the DPoP proof is not a well formed JWT",
        ),
        (DpopFailure::NotAProof, "the DPoP proof typ is not dpop+jwt"),
        (
            DpopFailure::UnsupportedAlgorithm,
            "the DPoP proof alg is not supported",
        ),
        (
            DpopFailure::BadProofKey,
            "the DPoP proof jwk is missing or is not a public key",
        ),
        (
            DpopFailure::BadSignature,
            "the DPoP proof signature did not verify",
        ),
        (
            DpopFailure::WrongMethod,
            "the DPoP proof htm is not this request's method",
        ),
        (
            DpopFailure::WrongUri,
            "the DPoP proof htu is not this request's URI",
        ),
        (
            DpopFailure::StaleProof,
            "the DPoP proof iat is missing or outside the window",
        ),
        (DpopFailure::MissingJti, "the DPoP proof carries no jti"),
        (
            DpopFailure::Replayed,
            "the DPoP proof jti has already been used",
        ),
    ] {
        assert_eq!(format!("{failure}"), text);
    }
}

/// RFC 9470 section 3: `description` is the `error_description` this failure puts ON THE WIRE, back
/// to the client through the authorization response redirect, so an empty or wrong one is a
/// protocol-visible defect rather than a log-only one. `Display` is the host-facing short form.
#[cfg(feature = "consent")]
#[test]
fn step_up_failure_text_is_the_wire_description_and_the_short_form() {
    use oauth_as::StepUpFailure;

    for (failure, description, short) in [
        (
            StepUpFailure::NotReported,
            "no user authentication was reported for this request",
            "no authentication reported",
        ),
        (
            StepUpFailure::Stale,
            "the user authentication is older than the requested max_age",
            "authentication older than max_age",
        ),
        (
            StepUpFailure::AcrNotMet,
            "the user authentication does not satisfy the requested acr_values",
            "acr_values not satisfied",
        ),
    ] {
        assert_eq!(failure.description(), description);
        assert_eq!(format!("{failure}"), short);
    }
}

/// RFC 8705 section 3.1: the `x5t#S256` wire form is base64url of the SHA-256 of the DER
/// certificate, unpadded, 43 characters. `Display` IS that wire form, which is what an operator
/// compares against a certificate fingerprint, so it has to round-trip the parser exactly.
#[cfg(feature = "mtls")]
#[test]
fn certificate_thumbprint_display_is_the_rfc_8705_wire_form() {
    use oauth_as::CertificateThumbprint;

    // 32 zero bytes: a value with an unambiguous base64url spelling, so the assertion is about the
    // encoding rather than about a fixture.
    let wire = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let thumbprint = CertificateThumbprint::from_base64url(wire).expect("43 chars is 32 bytes");
    assert_eq!(thumbprint.to_string(), wire);
    assert_eq!(thumbprint.to_string(), thumbprint.to_base64url());
    assert_eq!(thumbprint.as_bytes(), &[0u8; 32]);

    // A second, DIFFERENT value, so `as_bytes` cannot be a constant: a fixed return there would
    // make every certificate compare equal to every other, which is the whole binding gone.
    let ones = CertificateThumbprint::from_base64url("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
        .expect("43 chars is 32 bytes");
    assert_eq!(ones.as_bytes(), &[1u8; 32]);
    assert_ne!(thumbprint.as_bytes(), ones.as_bytes());
}

/// RFC 8705 sections 2.1.1, 2.1.2 and 3.1: every one of these is a REGISTRATION-time refusal, which
/// is the one place this crate can tell an operator they have configured mutual-TLS wrongly before
/// a client ever presents a certificate. An empty message there is a silent misconfiguration.
#[cfg(feature = "mtls")]
#[test]
fn mtls_registration_error_display_says_what_the_operator_got_wrong() {
    use oauth_as::MtlsRegistrationError;

    for (error, text) in [
        (
            MtlsRegistrationError::NoSubjectValue,
            "tls_client_auth requires one of the RFC 8705 s2.1.1 subject parameters",
        ),
        (
            MtlsRegistrationError::MoreThanOneSubjectValue,
            "RFC 8705 s2.1.2 permits exactly one tls_client_auth subject parameter",
        ),
        (
            MtlsRegistrationError::EmptySubjectValue,
            "a tls_client_auth subject parameter was empty, which no certificate can match",
        ),
        (
            MtlsRegistrationError::MalformedJwks,
            "the JWK Set could not be parsed",
        ),
        (
            MtlsRegistrationError::NoCertificateInJwks,
            "the JWK Set carries no x5c certificate to match against",
        ),
        (
            MtlsRegistrationError::MalformedCertificate,
            "the certificate is not DER or PEM-wrapped DER",
        ),
        (
            MtlsRegistrationError::MalformedThumbprint,
            "an x5t#S256 value is base64url of exactly 32 bytes",
        ),
    ] {
        assert_eq!(format!("{error}"), text);
    }
}

/// RFC 9101 section 6.2: a request object is verified against a key the CLIENT registered, so the
/// only person who can fix a bad key is the operator reading this message at registration time.
#[cfg(feature = "jar")]
#[test]
fn request_object_key_error_display_names_the_key_that_will_not_load() {
    use oauth_as::RegisteredRequestObjectKey;

    let thirty_two = "A".repeat(43);
    let err = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, "!not base64!", "AA")
        .expect_err("a non-base64url x is not a key");
    assert_eq!(
        err.to_string(),
        "request object key error: x is not base64url"
    );

    let err = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, &thirty_two, "!!")
        .expect_err("a non-base64url y is not a key");
    assert_eq!(
        err.to_string(),
        "request object key error: y is not base64url"
    );

    let err = RegisteredRequestObjectKey::es256_from_sec1(None, &[4u8; 10])
        .expect_err("ten bytes is not a P-256 point");
    assert_eq!(
        err.to_string(),
        "request object key error: an uncompressed P-256 point is exactly 65 bytes"
    );
}

/// RFC 7518 section 6.2.1.2 fixes BOTH P-256 coordinates at 32 bytes. The check is one condition
/// per coordinate joined by `or`, and joining them by `and` instead would accept a key with exactly
/// one wrong coordinate: this pins each coordinate's length independently of the other's.
#[cfg(feature = "jar")]
#[test]
fn each_p256_coordinate_is_length_checked_on_its_own() {
    use oauth_as::RegisteredRequestObjectKey;

    let full = "A".repeat(43); // 32 bytes
    let short = "A".repeat(42); // 31 bytes

    for (x, y) in [
        (short.as_str(), full.as_str()),
        (full.as_str(), short.as_str()),
        (short.as_str(), short.as_str()),
    ] {
        let err = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, x, y)
            .expect_err("a coordinate that is not 32 bytes is not a key");
        assert_eq!(
            err.to_string(),
            "request object key error: a P-256 coordinate is exactly 32 bytes"
        );
    }
}

/// RFC 7591 section 3.2.2: these three codes are a registry of their own, separate from RFC 6749
/// section 5.2, and `Display` is what a host logs and what the error body carries.
#[test]
fn registration_error_text_is_the_registered_code_and_the_description() {
    use oauth_as::{RegistrationErrorCode, RegistrationErrorResponse, RegistrationFailure};

    for (code, wire) in [
        (
            RegistrationErrorCode::InvalidRedirectUri,
            "invalid_redirect_uri",
        ),
        (
            RegistrationErrorCode::InvalidClientMetadata,
            "invalid_client_metadata",
        ),
        (
            RegistrationErrorCode::InvalidSoftwareStatement,
            "invalid_software_statement",
        ),
    ] {
        assert_eq!(format!("{code}"), wire);
        assert_eq!(code.as_str(), wire);
    }

    let described = RegistrationErrorResponse::new(
        RegistrationErrorCode::InvalidRedirectUri,
        "a redirect URI must not carry a fragment",
    );
    assert_eq!(
        described.to_string(),
        "invalid_redirect_uri: a redirect URI must not carry a fragment"
    );

    let bare = RegistrationErrorResponse {
        error: RegistrationErrorCode::InvalidClientMetadata,
        error_description: None,
    };
    assert_eq!(bare.to_string(), "invalid_client_metadata");

    // And the failure enum that wraps it, including the two that carry no body at all.
    assert_eq!(
        RegistrationFailure::Disabled.to_string(),
        "dynamic client registration is disabled"
    );
    assert_eq!(
        RegistrationFailure::Unauthorized.to_string(),
        "not authorized to register"
    );
    assert_eq!(
        RegistrationFailure::Invalid(described).to_string(),
        "invalid_redirect_uri: a redirect URI must not carry a fragment"
    );
    assert_eq!(
        RegistrationFailure::Storage(StorageError::new("the database is gone")).to_string(),
        "storage error: the database is gone"
    );
}

/// RFC 7591 section 3.2.1 hands back a `client_secret` and RFC 7592 section 3 a
/// `registration_access_token`. Both are bearer credentials, and this struct is what a host holds
/// at exactly the moment it is most likely to debug-print one. The hand-written `Debug` keeps the
/// SHAPE (a secret was issued) and drops the VALUE; an empty one would drop both.
#[test]
fn client_information_debug_redacts_both_credentials_and_keeps_the_shape() {
    use oauth_as::{ClientInformation, ClientMetadata};

    let issued = ClientInformation {
        client_id: "c-1".to_string(),
        client_secret: Some("secret-value-do-not-log".to_string()),
        client_id_issued_at: Some(1_700_000_000),
        client_secret_expires_at: Some(0),
        registration_access_token: Some("rat-value-do-not-log".to_string()),
        registration_client_uri: Some("https://as.example/register/c-1".to_string()),
        metadata: ClientMetadata::default(),
    };
    let printed = format!("{issued:?}");
    assert!(!printed.contains("secret-value-do-not-log"), "{printed}");
    assert!(!printed.contains("rat-value-do-not-log"), "{printed}");
    assert!(
        printed.contains("client_secret: Some(\"[redacted]\")"),
        "the Some/None distinction is registration shape, not a secret: {printed}"
    );
    assert!(
        printed.contains("registration_access_token: Some(\"[redacted]\")"),
        "{printed}"
    );
    assert!(printed.contains("client_id: \"c-1\""), "{printed}");
    assert!(
        printed.contains("client_id_issued_at: Some(1700000000)"),
        "{printed}"
    );
    assert!(
        printed.contains("registration_client_uri: Some(\"https://as.example/register/c-1\")"),
        "the management URI is not a credential and stays readable: {printed}"
    );

    // A PUBLIC registration holds neither credential, and the redaction must say so rather than
    // claiming a secret that does not exist.
    let public = ClientInformation {
        client_secret: None,
        registration_access_token: None,
        ..issued
    };
    let printed = format!("{public:?}");
    assert!(printed.contains("client_secret: None"), "{printed}");
    assert!(
        printed.contains("registration_access_token: None"),
        "{printed}"
    );
    assert!(!printed.contains("[redacted]"), "{printed}");
}

/// RFC 8693 section 3 registers the `*_token_type` identifiers. A value outside the registry is
/// rejected, and the message has to name the value the deployment actually sent or the operator is
/// debugging a typo they cannot see.
#[cfg(feature = "token-exchange")]
#[test]
fn unknown_token_type_identifier_display_quotes_the_rejected_value() {
    use oauth_as::TokenTypeIdentifier;

    let err = "urn:example:not-registered"
        .parse::<TokenTypeIdentifier>()
        .expect_err("an unregistered identifier is not accepted");
    assert_eq!(
        err.to_string(),
        "unknown token type identifier \"urn:example:not-registered\""
    );
}

/// The JWS verification errors never name which check failed in a way a client could use to probe a
/// key, but they do have to say SOMETHING: this is the host's only account of why a key it
/// configured was refused.
#[cfg(feature = "jwt")]
#[test]
fn jwk_verify_error_display_is_prefixed_and_carries_the_reason() {
    use oauth_as::jwt::PublicJwk;

    let err =
        PublicJwk::from_json(&serde_json::Value::from(1u8)).expect_err("a number is not a JWK");
    assert_eq!(
        err.to_string(),
        "JWS verification error: a JWK must be a JSON object"
    );
}
