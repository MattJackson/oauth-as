// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Behaviours a full `cargo mutants --all-features` run found nothing pinning.
//!
//! Each test here corresponds to a surviving mutant: a change that could be made to the source
//! with the whole suite still green. A survivor in a serialization helper or a registration parser
//! is not a curiosity, it is a behaviour the tests do not actually constrain, and this crate's
//! standard is that such a thing is either killed by a test or argued, in writing beside the code,
//! to be indistinguishable from the original. These are the killings.

#![cfg(any(feature = "rar", feature = "mtls", feature = "client-assertion"))]

/// SURVIVOR: `rar::is_empty_list` could return a constant and nothing failed.
///
/// It is the `skip_serializing_if` predicate for the list members of an authorization detail, so a
/// constant `true` silently DROPS every `actions`, `locations`, `datatypes` and `privileges` list
/// from the wire, and a constant `false` emits `[]` for members RFC 9396 section 2 says are
/// optional. The first is the dangerous direction: a resource server would be handed a detail whose
/// action list vanished, and RFC 9396 section 6.1 says only the API that defined the type knows
/// what an absent `actions` means there.
#[cfg(feature = "rar")]
#[test]
fn authorization_detail_list_members_serialize_when_present_and_vanish_when_absent() {
    use oauth_as::rar::AuthorizationDetails;

    let with_lists = r#"[{"type":"payment_initiation","actions":["initiate"],"locations":["https://rs.example/p"]}]"#;
    let parsed = AuthorizationDetails::parse(with_lists).expect("valid details");
    let json = serde_json::to_value(&parsed).unwrap();
    assert_eq!(
        json[0]["actions"],
        serde_json::json!(["initiate"]),
        "a present actions list must reach the wire; dropping it changes what the token authorizes"
    );
    assert_eq!(
        json[0]["locations"],
        serde_json::json!(["https://rs.example/p"])
    );

    let without = r#"[{"type":"payment_initiation"}]"#;
    let parsed = AuthorizationDetails::parse(without).expect("valid details");
    let json = serde_json::to_value(&parsed).unwrap();
    assert!(
        json[0].get("actions").is_none(),
        "an absent optional member is OMITTED, not emitted as [], got {json}"
    );
    assert!(json[0].get("locations").is_none());
}

/// SURVIVOR: the `tls_client_auth_san_ip` arm of the RFC 8705 section 2.1.1 registration parser
/// could be deleted and nothing failed.
///
/// Deleting it does not fail closed. The arm falls through to the `_ => continue` that exists for
/// the unrelated members a registration document carries, so a registration naming ONLY an IP SAN
/// parses as naming no subject at all, and section 2.1.2's "exactly one" check then reports the
/// wrong reason. A host would read "no subject parameter" for a document that plainly has one.
#[cfg(feature = "mtls")]
#[test]
fn every_rfc8705_subject_parameter_is_recognised_including_the_ip_san() {
    use oauth_as::mtls::{ExpectedSubject, MtlsRegistrationError};

    for (name, value, expected) in [
        (
            "tls_client_auth_subject_dn",
            "CN=payments,O=Example,C=GB",
            ExpectedSubject::SubjectDn("CN=payments,O=Example,C=GB".into()),
        ),
        (
            "tls_client_auth_san_dns",
            "client.example",
            ExpectedSubject::SanDns("client.example".into()),
        ),
        (
            "tls_client_auth_san_uri",
            "https://client.example/id",
            ExpectedSubject::SanUri("https://client.example/id".into()),
        ),
        (
            "tls_client_auth_san_ip",
            "203.0.113.7",
            ExpectedSubject::SanIp("203.0.113.7".into()),
        ),
        (
            "tls_client_auth_san_email",
            "ops@client.example",
            ExpectedSubject::SanEmail("ops@client.example".into()),
        ),
    ] {
        let got = ExpectedSubject::from_registration_parameters([(name, value)])
            .unwrap_or_else(|e| panic!("{name} must be recognised, got {e:?}"));
        assert_eq!(got, expected, "{name} parsed to the wrong variant");
    }

    // And the section 2.1.2 rule still holds for the one that was unpinned: naming the IP SAN
    // alongside another parameter is two subjects, which is refused rather than resolved.
    let two = ExpectedSubject::from_registration_parameters([
        ("tls_client_auth_san_ip", "203.0.113.7"),
        ("tls_client_auth_san_dns", "client.example"),
    ])
    .expect_err("two subject parameters must be refused (RFC 8705 s2.1.2)");
    assert!(matches!(
        two,
        MtlsRegistrationError::MoreThanOneSubjectValue
    ));
}
