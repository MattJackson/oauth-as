// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the consent and RFC 9470 step-up primitives.
//!
//! These are the decisions the module makes on its own, away from a server: what "already
//! consented" means, what satisfies an `acr_values` / `max_age` requirement, and what the RFC 9470
//! section 3 challenge looks like on the wire. The behavioural half, where the answers reach a
//! token, lives in `tests/consent.rs` and `tests/step_up.rs`.

use std::time::{Duration, UNIX_EPOCH};

use super::*;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn scopes(s: &str) -> ScopeSet {
    ScopeSet::parse(s).unwrap()
}

fn record(scope: &str, resource: &[&str]) -> ConsentRecord {
    ConsentRecord {
        consent_id: "consent-1".into(),
        client_id: ClientId::new("app"),
        subject: "user-1".into(),
        scope: scopes(scope),
        resource: resource.iter().map(|r| r.to_string()).collect(),
        granted_at: at(1_000),
        authentication: None,
    }
}

// -------------------------------------------------------------------------- remembered consent

/// A remembered consent covers a request for LESS than was approved. This is the ordinary case and
/// the only one where skipping a prompt could ever be defensible.
#[test]
fn a_narrower_request_is_covered() {
    let r = record("read write", &[]);
    assert!(r.covers(&scopes("read"), &[]));
    assert!(r.covers(&scopes("read write"), &[]));
    assert!(r.covers(&ScopeSet::empty(), &[]));
}

/// One scope token more than was approved is NOT covered. This is the whole security content of
/// `covers`: a remembered consent that grew by one token would be a permission the user never saw.
#[test]
fn one_extra_scope_token_is_not_covered() {
    let r = record("read", &[]);
    assert!(!r.covers(&scopes("read write"), &[]));
    assert!(!r.covers(&scopes("admin"), &[]));
}

/// RFC 8707 s2 makes the resource the audience the token will be good at, so a consent that named
/// no resource does not cover a request that names one. "Approved for no particular resource" is
/// not "approved for that resource", and reading it the other way would let a remembered consent
/// acquire an audience silently.
#[test]
fn a_resource_the_consent_never_named_is_not_covered() {
    let none = record("read", &[]);
    assert!(!none.covers(&scopes("read"), &["https://rs.example/".to_string()]));

    let one = record("read", &["https://rs.example/"]);
    assert!(one.covers(&scopes("read"), &["https://rs.example/".to_string()]));
    assert!(!one.covers(&scopes("read"), &["https://other.example/".to_string()]));
    // Naming one of two approved resources is a narrowing, which is covered.
    let two = record("read", &["https://rs.example/", "https://other.example/"]);
    assert!(two.covers(&scopes("read"), &["https://other.example/".to_string()]));
}

/// Widening accumulates rather than replacing: a user who approves `write` today has not withdrawn
/// the `read` they approved last month, and the identifier and the original grant instant survive
/// so that one relationship stays one row in a user's consent list.
#[test]
fn extend_accumulates_and_keeps_the_identity_of_the_consent() {
    let mut r = record("read", &["https://rs.example/"]);
    r.extend(&scopes("write"), &["https://other.example/".to_string()]);
    assert_eq!(r.scope, scopes("read write"));
    assert_eq!(
        r.resource,
        vec![
            "https://rs.example/".to_string(),
            "https://other.example/".to_string()
        ]
    );
    assert_eq!(&*r.consent_id, "consent-1");
    assert_eq!(r.granted_at, at(1_000));
}

/// Widening by something already covered changes nothing at all, and in particular does not
/// duplicate a resource indicator: a record that grew a copy of an entry on every approval would
/// grow without bound for a client a user visits every day.
#[test]
fn extend_by_what_is_already_covered_is_a_no_op() {
    let mut r = record("read write", &["https://rs.example/"]);
    let before = r.clone();
    r.extend(&scopes("read"), &["https://rs.example/".to_string()]);
    assert_eq!(r, before);
}

// -------------------------------------------------------------------------- parsing (RFC 9470 s4)

/// An ordinary authorization request carries neither parameter, and must not acquire a requirement
/// by being parsed.
#[test]
fn a_request_with_neither_parameter_requires_nothing() {
    let req = AuthenticationRequirement::from_pairs([("client_id", "app"), ("scope", "read")])
        .expect("no step-up parameters is not an error");
    assert!(req.is_empty());
    assert_eq!(req, AuthenticationRequirement::none());
}

#[test]
fn acr_values_is_a_space_delimited_ordered_list() {
    let req =
        AuthenticationRequirement::from_pairs([("acr_values", "  urn:mace:silver  phr ")]).unwrap();
    assert_eq!(
        req.acr_values,
        vec![Box::<str>::from("urn:mace:silver"), Box::<str>::from("phr")]
    );
    assert!(!req.is_empty());
}

/// `max_age=0` means re-authenticate NOW. It must not collapse into "absent", which is the reading
/// that would turn the strongest possible request into no request at all.
#[test]
fn max_age_zero_is_a_requirement_and_not_an_absence() {
    let req = AuthenticationRequirement::from_pairs([("max_age", "0")]).unwrap();
    assert_eq!(req.max_age, Some(Duration::ZERO));
    assert!(!req.is_empty());
}

/// A `max_age` that is not a number of seconds is REFUSED, not ignored. Ignoring it would answer a
/// step-up challenge with a token that never had the freshness the resource server asked for.
#[test]
fn a_malformed_max_age_is_invalid_request() {
    for bad in ["", "-1", "soon", "60s", "1.5", "9999999999999999999999"] {
        let err = AuthenticationRequirement::from_pairs([("max_age", bad)])
            .expect_err("a max_age that is not a number of seconds must be refused");
        assert_eq!(err.error, ErrorCode::InvalidRequest, "max_age={bad:?}");
    }
}

/// RFC 6749 s3.1 says a parameter MUST NOT appear more than once; where one does, the FIRST wins,
/// matching `AuthorizationRequest::from_pairs`. Last-wins is the smuggling-friendly choice when two
/// intermediaries disagree about which copy counts.
#[test]
fn a_repeated_parameter_keeps_the_first_occurrence() {
    let req = AuthenticationRequirement::from_pairs([
        ("acr_values", "strong"),
        ("acr_values", "weak"),
        ("max_age", "60"),
        ("max_age", "86400"),
    ])
    .unwrap();
    assert_eq!(req.acr_values, vec![Box::<str>::from("strong")]);
    assert_eq!(req.max_age, Some(Duration::from_secs(60)));
}

// -------------------------------------------------------------------------- enforcement

/// No requirement means no check, whether or not the host reported anything.
#[test]
fn an_empty_requirement_is_satisfied_by_anything() {
    let req = AuthenticationRequirement::none();
    assert_eq!(req.satisfied_by(None, at(5_000)), Ok(()));
    assert_eq!(
        req.satisfied_by(Some(&Authentication::at(at(1))), at(5_000)),
        Ok(())
    );
}

/// THE FAILURE THAT MATTERS: a host that reports nothing must not satisfy a requirement. "We were
/// not told" reading as "there is nothing to check" is what would make an unwired host silently
/// satisfy every step-up challenge it is ever sent.
#[test]
fn an_unreported_authentication_satisfies_nothing() {
    let fresh = AuthenticationRequirement {
        acr_values: Vec::new(),
        max_age: Some(Duration::from_secs(60)),
    };
    assert_eq!(
        fresh.satisfied_by(None, at(5_000)),
        Err(StepUpFailure::NotReported)
    );
    let strong = AuthenticationRequirement {
        acr_values: vec!["phr".into()],
        max_age: None,
    };
    assert_eq!(
        strong.satisfied_by(None, at(5_000)),
        Err(StepUpFailure::NotReported)
    );
}

/// `max_age` is measured from `auth_time`, and the boundary is inclusive: an authentication exactly
/// `max_age` old still satisfies it, one second older does not.
#[test]
fn max_age_is_enforced_against_auth_time_at_the_boundary() {
    let req = AuthenticationRequirement {
        acr_values: Vec::new(),
        max_age: Some(Duration::from_secs(300)),
    };
    let auth = Authentication::at(at(1_000));
    assert_eq!(req.satisfied_by(Some(&auth), at(1_300)), Ok(()));
    assert_eq!(
        req.satisfied_by(Some(&auth), at(1_301)),
        Err(StepUpFailure::Stale)
    );
    // max_age=0 means now: any elapsed time at all fails.
    let now_only = AuthenticationRequirement {
        acr_values: Vec::new(),
        max_age: Some(Duration::ZERO),
    };
    assert_eq!(now_only.satisfied_by(Some(&auth), at(1_000)), Ok(()));
    assert_eq!(
        now_only.satisfied_by(Some(&auth), at(1_001)),
        Err(StepUpFailure::Stale)
    );
}

/// An `auth_time` in the future is a clock skew between two machines, not an attack, and reads as
/// zero elapsed time. Failing it would lock a user out of a deployment whose AS and login service
/// disagree by a second.
#[test]
fn an_auth_time_in_the_future_reads_as_no_elapsed_time() {
    let req = AuthenticationRequirement {
        acr_values: Vec::new(),
        max_age: Some(Duration::ZERO),
    };
    let auth = Authentication::at(at(2_000));
    assert_eq!(req.satisfied_by(Some(&auth), at(1_000)), Ok(()));
}

/// `acr_values` is an ordered preference, so ANY of the requested classes satisfies it. A host that
/// answered with the second-choice class has still answered.
#[test]
fn any_requested_acr_satisfies_the_request() {
    let req = AuthenticationRequirement {
        acr_values: vec!["phr".into(), "mfa".into()],
        max_age: None,
    };
    let mfa = Authentication::at(at(1_000)).with_acr("mfa");
    assert_eq!(req.satisfied_by(Some(&mfa), at(1_000)), Ok(()));
    let pwd = Authentication::at(at(1_000)).with_acr("pwd");
    assert_eq!(
        req.satisfied_by(Some(&pwd), at(1_000)),
        Err(StepUpFailure::AcrNotMet)
    );
    // Reported nothing at all: a request for a specific class is not satisfied by silence.
    let bare = Authentication::at(at(1_000));
    assert_eq!(
        req.satisfied_by(Some(&bare), at(1_000)),
        Err(StepUpFailure::AcrNotMet)
    );
}

/// `acr` values are compared as OPAQUE strings, byte for byte. This crate has no registry to check
/// them against and no business case-folding somebody else's vocabulary.
#[test]
fn acr_comparison_is_exact() {
    let req = AuthenticationRequirement {
        acr_values: vec!["PHR".into()],
        max_age: None,
    };
    let lower = Authentication::at(at(1_000)).with_acr("phr");
    assert_eq!(
        req.satisfied_by(Some(&lower), at(1_000)),
        Err(StepUpFailure::AcrNotMet)
    );
}

/// Freshness is checked BEFORE class, so a login that is both stale and of the wrong class is
/// reported as stale: logging in again is the action that fixes either, and it does not tell the
/// client which `acr` a stale session happened to hold.
#[test]
fn staleness_is_reported_before_the_class_mismatch() {
    let req = AuthenticationRequirement {
        acr_values: vec!["phr".into()],
        max_age: Some(Duration::from_secs(60)),
    };
    let old_and_wrong = Authentication::at(at(1_000)).with_acr("pwd");
    assert_eq!(
        req.satisfied_by(Some(&old_and_wrong), at(9_000)),
        Err(StepUpFailure::Stale)
    );
}

/// Every failure is reported as RFC 9470 s3's `insufficient_user_authentication`, and the
/// description is a `&'static str`, so a refusal on a path an unauthenticated caller can drive
/// allocates nothing for it.
#[test]
fn every_failure_is_insufficient_user_authentication() {
    for failure in [
        StepUpFailure::NotReported,
        StepUpFailure::Stale,
        StepUpFailure::AcrNotMet,
    ] {
        let err = failure.error_response();
        assert_eq!(err.error, ErrorCode::InsufficientUserAuthentication);
        assert_eq!(
            err.error_description.as_deref(),
            Some(failure.description()),
            "{failure}"
        );
        // The description must not name the user's actual acr or auth_time: it goes to the CLIENT.
        let text = failure.description();
        assert!(!text.contains("1970"), "{text}");
    }
    assert_eq!(
        ErrorCode::InsufficientUserAuthentication.as_str(),
        "insufficient_user_authentication"
    );
}

// -------------------------------------------------------------------------- the s3 challenge

/// RFC 9470 s3's challenge, in the shape a resource server sends it.
#[test]
fn the_challenge_carries_the_error_and_both_parameters() {
    let challenge = step_up_challenge(
        "Bearer",
        &["phr".into(), "mfa".into()],
        Some(Duration::from_secs(300)),
    );
    assert_eq!(
        challenge,
        "Bearer error=\"insufficient_user_authentication\", \
         error_description=\"the user authentication does not meet the requirements of this \
         resource\", acr_values=\"phr mfa\", max_age=\"300\""
    );
}

/// An empty `acr_values` is OMITTED rather than sent blank: an empty list reads as "no class is
/// acceptable", which is the opposite of "any class will do". Same for an absent `max_age`.
#[test]
fn the_challenge_omits_what_was_not_asked_for() {
    let challenge = step_up_challenge("DPoP", &[], None);
    assert_eq!(
        challenge,
        "DPoP error=\"insufficient_user_authentication\", \
         error_description=\"the user authentication does not meet the requirements of this \
         resource\""
    );
    assert!(!challenge.contains("acr_values"));
    assert!(!challenge.contains("max_age"));
}

/// A quote or a backslash inside an `acr` value would otherwise close the quoted string early and
/// forge the parameter after it (RFC 9110 s5.6.4). Escaped, not rejected: this crate does not own
/// the host's `acr` vocabulary.
#[test]
fn the_challenge_escapes_quotes_in_an_acr_value() {
    let challenge = step_up_challenge("Bearer", &["a\"b\\c".into()], None);
    assert!(
        challenge.contains("acr_values=\"a\\\"b\\\\c\""),
        "{challenge}"
    );
    // Nothing after the escaped value could be read as a new parameter.
    assert_eq!(challenge.matches("error=").count(), 1);
}
