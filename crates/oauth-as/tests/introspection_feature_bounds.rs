//! What an introspection response MEANS must not depend on the flag set of the build that reads
//! it.
//!
//! [`oauth_as::token::IntrospectionResponse`] carries five members that exist only under a cargo
//! feature: `cnf` (`dpop` or `mtls`), `act` (`token-exchange`), `auth_time` and `acr` (`consent`),
//! and `authorization_details` (`rar`). Every one of them is a statement a resource server acts
//! on, and four of the five say the token is NARROWER than a plain bearer token: bound to a key or
//! a certificate, delegated, authenticated at a particular time and class, or authorized for a
//! particular transaction.
//!
//! Deserializing such a response in a build without the feature used to drop the member in
//! silence, so the reader was told a certificate-bound token was an ordinary bearer token and had
//! no way at all to notice. THE SAME OBJECT'S `token_type` FAILED LOUDLY under the same conditions
//! (`"DPoP"` is not a variant without `dpop`), which is the shape the rest of the object now
//! matches: a claim this build cannot represent is an error, not an omission.
//!
//! NOT `deny_unknown_fields`, and the distinction is the whole design. RFC 7662 section 2.2 says
//! "specific implementations MAY extend this structure with their own service-specific response
//! names as top-level members of this JSON object", so a response carrying `username` or `nbf` is
//! CONFORMANT and refusing it would turn a silent drop into an inability to introspect at all.
//! Only the members this crate itself knows the meaning of, and would therefore be discarding
//! knowingly, are refused. `unknown_member_is_still_accepted` is the half of that pair which keeps
//! the tolerance honest.

use oauth_as::token::IntrospectionResponse;

/// Parse an introspection body, returning the serde error text on failure.
fn parse(body: &str) -> Result<IntrospectionResponse, String> {
    serde_json::from_str::<IntrospectionResponse>(body).map_err(|e| e.to_string())
}

/// The comparison case, and the reason the rest of this file exists: `token_type` has ALWAYS been
/// loud, because a missing enum variant is a serde error rather than a dropped member.
#[test]
#[cfg(not(feature = "dpop"))]
fn dpop_token_type_is_loud_without_the_feature() {
    let err = parse(r#"{"active":true,"token_type":"DPoP"}"#).unwrap_err();
    assert!(
        err.contains("unknown variant"),
        "expected an unknown-variant error, got {err}"
    );
}

/// RFC 8705 section 3.2: `cnf.x5t#S256` says the token is bound to a client certificate, and a
/// resource server that never sees the member treats it as a bearer token it may accept from
/// anyone holding the string.
#[test]
#[cfg(not(any(feature = "dpop", feature = "mtls")))]
fn certificate_binding_is_refused_not_dropped() {
    let err =
        parse(r#"{"active":true,"token_type":"Bearer","cnf":{"x5t#S256":"thumb"}}"#).unwrap_err();
    assert!(err.contains("cnf"), "expected `cnf` to be named, got {err}");
}

/// RFC 9470 section 6.2: `auth_time` and `acr` are what make a step-up challenge answerable, so a
/// reader that drops them concludes the token satisfies a `max_age` it was never measured against.
#[test]
#[cfg(not(feature = "consent"))]
fn authentication_report_is_refused_not_dropped() {
    let err = parse(r#"{"active":true,"auth_time":1700000000}"#).unwrap_err();
    assert!(
        err.contains("auth_time"),
        "expected `auth_time` to be named, got {err}"
    );
    let err = parse(r#"{"active":true,"acr":"phrh"}"#).unwrap_err();
    assert!(err.contains("acr"), "expected `acr` to be named, got {err}");
}

/// RFC 8693 section 4.1: without `act` a reader cannot tell "A acting for B" from "B", which is
/// the entire distinction section 1.1 draws between delegation and impersonation.
#[test]
#[cfg(not(feature = "token-exchange"))]
fn delegation_chain_is_refused_not_dropped() {
    let err = parse(r#"{"active":true,"act":{"sub":"actor"}}"#).unwrap_err();
    assert!(err.contains("act"), "expected `act` to be named, got {err}");
}

/// RFC 9396 section 9.2: for an opaque token this member is the ONLY statement of what the token
/// authorizes, so dropping it reads as "authorized for nothing in particular" when the truth may
/// be a payment initiation.
#[test]
#[cfg(not(feature = "rar"))]
fn authorization_details_is_refused_not_dropped() {
    let err = parse(r#"{"active":true,"authorization_details":[{"type":"payment"}]}"#).unwrap_err();
    assert!(
        err.contains("authorization_details"),
        "expected `authorization_details` to be named, got {err}"
    );
}

/// THE INTERIOR OF `cnf`, which is the case the top-level guard above cannot reach.
///
/// `cnf` is not one member but an OBJECT of confirmation methods (RFC 7800 section 3.1), and each
/// sender-constraining mechanism registers its own: `jkt` under `dpop` (RFC 9449 section 6.1),
/// `x5t#S256` under `mtls` (RFC 8705 section 3.1). A build with one feature and not the other has
/// the top-level member and not the interior one, so the outer guard passes and the inner method
/// is dropped. The result is the exact downgrade the outer guard exists to stop: a
/// certificate-bound token read as an ordinary bearer token, because `Confirmation::is_empty`
/// answers `true` for a confirmation whose only method this build cannot spell.
#[test]
#[cfg(all(feature = "dpop", not(feature = "mtls")))]
fn a_certificate_confirmation_method_is_refused_not_dropped() {
    let err = parse(r#"{"active":true,"cnf":{"x5t#S256":"abc"}}"#).unwrap_err();
    assert!(
        err.contains("x5t#S256"),
        "expected the certificate confirmation method to be named, got {err}"
    );
}

/// The mirror image of the case above, so neither feature is the privileged one: a `dpop` key
/// binding read by a build that has `mtls` and not `dpop`.
#[test]
#[cfg(all(feature = "mtls", not(feature = "dpop")))]
fn a_key_confirmation_method_is_refused_not_dropped() {
    let err = parse(r#"{"active":true,"cnf":{"jkt":"abc"}}"#).unwrap_err();
    assert!(
        err.contains("jkt"),
        "expected the key confirmation method to be named, got {err}"
    );
}

/// A `cnf` carrying a method NEITHER feature registers is still accepted, for the reason
/// `unknown_member_is_still_accepted` below states: RFC 7800 section 3.1 leaves the member set of
/// `cnf` open, so refusing an unregistered method would refuse a conformant response. Only the
/// methods this crate knows the meaning of, and would therefore be discarding knowingly, are
/// refused.
#[test]
#[cfg(any(feature = "dpop", feature = "mtls"))]
fn an_unknown_confirmation_method_is_still_accepted() {
    let parsed = parse(r#"{"active":true,"cnf":{"kid":"key-1"}}"#).expect(
        "an unregistered RFC 7800 s3.1 confirmation method must not make a response unreadable",
    );
    assert!(parsed.active);
}

/// The other half of the contract: RFC 7662 section 2.2 PERMITS extension members, so a response
/// from a server that reports `username` must still parse. This is what makes the refusals above a
/// statement about members this crate knows the meaning of rather than a blanket
/// `deny_unknown_fields`.
#[test]
fn unknown_member_is_still_accepted() {
    let parsed = parse(r#"{"active":true,"sub":"u-1","username":"alice","nbf":1700000000}"#)
        .expect("an RFC 7662 s2.2 extension member must not make a response unreadable");
    assert!(parsed.active);
    assert_eq!(parsed.sub.as_deref(), Some("u-1"));
}

/// The drift guard. The refusals above are implemented against a mirror of this struct's field
/// list, so a member added to one and not the other would silently stop round-tripping. Populating
/// every field the current flag set has and asserting the value survives serialization is what
/// notices.
#[test]
fn every_member_of_the_current_build_round_trips() {
    let mut response = IntrospectionResponse::inactive();
    response.active = true;
    response.scope = Some("a b".to_string());
    response.client_id = Some("client".to_string());
    response.sub = Some("subject".to_string());
    response.token_type = Some(oauth_as::token::TokenType::Bearer);
    response.exp = Some(1_700_000_100);
    response.iat = Some(1_700_000_000);
    response.iss = Some("https://as.example".to_string());
    response.aud = Some(vec!["https://rs.example".to_string()]);
    #[cfg(feature = "consent")]
    {
        response.auth_time = Some(1_699_999_000);
        response.acr = Some("phrh".to_string());
    }
    // `Confirmation` is `#[non_exhaustive]`, so a host builds one the way its doc says: from
    // `default()` plus the members its mechanism registers.
    #[cfg(feature = "dpop")]
    {
        response.cnf = Some(oauth_as::token::Confirmation::jkt("thumb"));
    }
    #[cfg(all(feature = "mtls", not(feature = "dpop")))]
    {
        response.cnf = Some(oauth_as::token::Confirmation::default());
    }
    let text = serde_json::to_string(&response).expect("serialize");
    let back = parse(&text).expect("the response this build produced must be readable by it");
    assert_eq!(back, response);
}
