// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! draft-ietf-oauth-client-id-metadata-document, from the outside: exactly the surface a HOST
//! codes against, because a host is the only caller this feature has. Nothing in this crate
//! reaches `cimd` itself.
//!
//! Every refusal here asserts the REASON and not merely that it errored. That is a house rule with
//! a history behind it: this suite's recurring failure has been a test that could not say why it
//! refused, and would therefore have gone on passing if the refusal had moved to a different rule.

#![cfg(feature = "cimd")]

use oauth_as::cimd::{CimdError, CimdPolicy, ClientIdUrl, ValidatedClientIdDocument};

/// The identifier every test below uses unless it is testing the identifier itself.
const URL: &str = "https://client.example/oauth/client";

fn strict() -> CimdPolicy {
    CimdPolicy::new()
}

fn url(raw: &str) -> ClientIdUrl {
    ClientIdUrl::parse(raw, &strict()).expect("a client identifier the syntax rules accept")
}

/// The document a well-behaved client publishes, as bytes, so every test starts from something
/// that is known to VALIDATE and changes exactly one thing.
fn document(body: &str) -> Vec<u8> {
    body.as_bytes().to_vec()
}

fn valid_document() -> Vec<u8> {
    document(
        r#"{
            "client_id": "https://client.example/oauth/client",
            "client_name": "Example",
            "redirect_uris": ["https://client.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }"#,
    )
}

// ---------------------------------------------------------------------------------------------
// Section 4.1: the document's client_id, against the URL it was fetched from.
//
// This is the check the whole mechanism rests on, so it gets the most cases.
// ---------------------------------------------------------------------------------------------

/// The happy path, stated first so that every refusal below is a refusal of ONE difference from a
/// document that is known to be accepted.
#[test]
fn a_document_whose_client_id_is_the_fetch_url_becomes_a_public_client() {
    let validated = ValidatedClientIdDocument::validate(&url(URL), &valid_document(), &strict())
        .expect("a conformant document");
    let client = validated.to_client();
    assert_eq!(client.client_id.as_str(), URL);
    assert_eq!(client.auth, oauth_as::ClientAuth::Public);
    assert_eq!(
        client.redirect_uris,
        vec!["https://client.example/callback"]
    );
    assert_eq!(client.name.as_deref(), Some("Example"));
    // Not a dynamic registration: there is no RFC 7592 management credential and no management
    // surface, because the client edits its own document.
    assert!(client.registration.is_none());
}

/// THE CHECK. Without it, any document authorizes any client: an attacker publishes a document at
/// a URL they control that claims somebody else's identifier, and an authorization server that
/// skipped this comparison hands them that client's redirect URIs.
#[test]
fn a_document_claiming_another_clients_identifier_is_refused() {
    let attacker = "https://attacker.example/evil";
    let body = document(
        r#"{
            "client_id": "https://client.example/oauth/client",
            "redirect_uris": ["https://attacker.example/callback"],
            "token_endpoint_auth_method": "none"
        }"#,
    );
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(attacker), &body, &strict()),
        Err(CimdError::ClientIdMismatch),
        "a document fetched from {attacker} may not claim the identifier of another client"
    );
}

/// Section 4.1 makes the comparison an RFC 3986 section 6.2.1 SIMPLE STRING COMPARISON, so each of
/// these three must be REFUSED rather than normalised. Normalising any one of them means two
/// distinct strings name one client, which is exactly the property the check exists to deny.
#[test]
fn the_comparison_is_byte_equality_and_normalises_nothing() {
    for (case, claimed) in [
        ("a trailing slash", "https://client.example/oauth/client/"),
        (
            "the case of the host",
            "https://CLIENT.example/oauth/client",
        ),
        (
            "percent-encoding in the path",
            "https://client.example/oauth/%63lient",
        ),
    ] {
        let body = document(&format!(
            r#"{{"client_id": "{claimed}", "redirect_uris": ["https://client.example/callback"],
                 "token_endpoint_auth_method": "none"}}"#
        ));
        assert_eq!(
            ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
            Err(CimdError::ClientIdMismatch),
            "a client_id differing from the fetch URL by {case} must be refused, not normalised"
        );
    }
}

/// REQUIRED (section 4.1), and its absence is a different fact from a mismatch: nothing was
/// claimed at all. A host that logs the refusal should be able to tell the two apart.
#[test]
fn a_document_with_no_client_id_is_refused_as_missing_rather_than_mismatched() {
    let body = document(r#"{"redirect_uris": ["https://client.example/callback"]}"#);
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
        Err(CimdError::MissingClientId),
    );
}

// ---------------------------------------------------------------------------------------------
// Section 4.1: the two prohibitions.
// ---------------------------------------------------------------------------------------------

/// A document anyone can GET cannot hold a shared secret, so a secret in one is a secret published
/// to the internet. Refused rather than dropped: dropping a member the client believes is being
/// honoured registers a client on terms nobody agreed to.
#[test]
fn a_document_carrying_a_client_secret_is_refused_rather_than_stripped() {
    for member in ["client_secret", "client_secret_expires_at"] {
        let value = match member {
            "client_secret" => "\"s3cret\"",
            _ => "0",
        };
        let body = document(&format!(
            r#"{{"client_id": "{URL}", "redirect_uris": ["https://client.example/callback"],
                 "token_endpoint_auth_method": "none", "{member}": {value}}}"#
        ));
        assert_eq!(
            ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
            Err(CimdError::ClientSecretPresent),
            "{member} must be a refusal, not a silently discarded member"
        );
    }
}

/// The same argument one member over: a method that rests on a shared symmetric secret cannot be
/// established by a public document, so naming one is a refusal.
#[test]
fn a_shared_symmetric_token_endpoint_auth_method_is_refused() {
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
    ] {
        let body = document(&format!(
            r#"{{"client_id": "{URL}", "redirect_uris": ["https://client.example/callback"],
                 "token_endpoint_auth_method": "{method}"}}"#
        ));
        assert_eq!(
            ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
            Err(CimdError::SharedSecretAuthMethod),
            "{method} rests on a secret a world-readable document cannot hold"
        );
    }
}

/// RFC 7591 section 2 says an ABSENT `token_endpoint_auth_method` means `client_secret_basic`,
/// which section 4.1 forbids. Taking that default literally would refuse every document that omits
/// the member, so an absent one is read as `none` and the client is public. This pins the
/// deviation, because it IS a deviation and a silent one would be a bug.
#[test]
fn an_absent_token_endpoint_auth_method_means_none_and_not_rfc_7591s_default() {
    let body = document(&format!(
        r#"{{"client_id": "{URL}", "redirect_uris": ["https://client.example/callback"]}}"#
    ));
    let validated = ValidatedClientIdDocument::validate(&url(URL), &body, &strict())
        .expect("an omitted auth method is not a refusal");
    assert_eq!(validated.to_client().auth, oauth_as::ClientAuth::Public);
}

// ---------------------------------------------------------------------------------------------
// Section 3: client identifier URL syntax. One case per prohibition.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_section_3_syntax_table_refuses_each_prohibition_for_its_own_reason() {
    let cases: &[(&str, CimdError, &str)] = &[
        (
            "http://client.example/app",
            CimdError::NotHttps,
            "plain HTTP",
        ),
        (
            "HTTPS://client.example/app",
            CimdError::NotHttps,
            "an upper-case scheme, which is refused rather than folded because section 4.1 \
             compares byte for byte",
        ),
        (
            "https://client.example",
            CimdError::NoPath,
            "a bare origin has no path component",
        ),
        (
            "https://client.example/a/../b",
            CimdError::DotSegment,
            "a double-dot segment inside an otherwise valid path",
        ),
        (
            "https://client.example/a/./b",
            CimdError::DotSegment,
            "a single-dot segment",
        ),
        (
            "https://client.example/app#frag",
            CimdError::Fragment,
            "a fragment",
        ),
        (
            "https://client.example/app?x=1#frag",
            CimdError::Fragment,
            "a fragment after a query",
        ),
        (
            "https://client.example@attacker.example/app",
            CimdError::Userinfo,
            "userinfo whose text before the @ is a plausible host, which is the whole trick",
        ),
        (
            "https://client.example/app?tenant=1",
            CimdError::QueryString,
            "a query string, which section 3 says SHOULD NOT and this policy refuses",
        ),
        (
            "https:///app",
            CimdError::NoHost,
            "an empty authority names nothing a fetch could be made against",
        ),
        (
            "https://:8443/app",
            CimdError::NoHost,
            "a port with no host in front of it is still no host",
        ),
        (
            "https://client.example/a b",
            CimdError::NotAscii,
            "RFC 3986 s2 requires anything outside the URI grammar to be percent-encoded",
        ),
        (
            "https://client.example/a\nSet-Cookie: x",
            CimdError::NotAscii,
            "a newline in an identifier that reaches an audit record is log injection",
        ),
        (
            "https://client.exämple/app",
            CimdError::NotAscii,
            "a non-ASCII host must arrive already punycoded, not folded here",
        ),
    ];
    for (raw, expected, why) in cases {
        assert_eq!(
            ClientIdUrl::parse(raw, &strict()).err().as_ref(),
            Some(expected),
            "{raw} must be refused because {why}"
        );
    }
}

/// The other half of the table: what section 3 explicitly ALLOWS, so that the rules above are not
/// quietly implemented as "refuse anything unusual".
#[test]
fn the_section_3_syntax_table_accepts_what_it_permits() {
    for raw in [
        // MUST have a path; `/` is one (RFC 3986 s3.3 `path-abempty` is non-empty here).
        "https://client.example/",
        // MAY contain a port.
        "https://client.example:8443/app",
        // A dot INSIDE a segment is not a dot segment.
        "https://client.example/v1.2/client",
        // A public IP literal is not a special-use address.
        "https://93.184.216.34/app",
    ] {
        assert!(
            ClientIdUrl::parse(raw, &strict()).is_ok(),
            "{raw} is permitted by section 3 and must not be refused"
        );
    }
    // A query string is a SHOULD NOT, so a deployment may take it.
    let mut permissive = strict();
    permissive.allow_query_string = true;
    assert!(ClientIdUrl::parse("https://client.example/app?tenant=1", &permissive).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Section 6.5: special-use address literals, and the loopback carve-out.
// ---------------------------------------------------------------------------------------------

/// The RFC 6890 ranges, v4 and v6, as literals. This is the half of section 6.5 a library with no
/// resolver can decide; see [`the_host_duties_this_crate_does_not_discharge`] for the other half.
#[test]
fn special_use_address_literals_are_refused_in_both_address_families() {
    for host in [
        // v4, RFC 6890.
        "0.0.0.0",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.169.254",
        "192.0.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "192.88.99.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        // v6, bracketed as RFC 3986 section 3.2.2 requires.
        "[::]",
        "[64:ff9b::1.2.3.4]",
        "[100::1]",
        "[2001::1]",
        "[2001:2::1]",
        "[2001:db8::1]",
        "[2002::1]",
        "[fc00::1]",
        "[fd12:3456::1]",
        "[fe80::1]",
        "[ff02::1]",
        // A v4 special-use address written as a v6-mapped literal is the SAME address, and reading
        // it as "some address in ::ffff:0:0/96" would let every v4 rule be bypassed by rewriting.
        "[::ffff:169.254.169.254]",
    ] {
        let raw = format!("https://{host}/app");
        assert_eq!(
            ClientIdUrl::parse(&raw, &strict()).err(),
            Some(CimdError::SpecialUseAddress),
            "{host} is a special-use literal (RFC 6890) and dereferencing it is a request to this \
             deployment's own network"
        );
    }
}

/// Section 6.5's carve-out, BOTH ways: off by default, because a loopback client identifier in a
/// deployment reachable from elsewhere is the AS making a request to itself on somebody else's
/// behalf; on when a host says its AS runs on that same loopback interface.
#[test]
fn the_loopback_carve_out_is_off_by_default_and_relaxes_only_loopback() {
    let mut permissive = strict();
    permissive.allow_loopback = true;
    for host in ["127.0.0.1", "127.9.9.9", "[::1]"] {
        let raw = format!("https://{host}/app");
        assert_eq!(
            ClientIdUrl::parse(&raw, &strict()).err(),
            Some(CimdError::SpecialUseAddress),
            "{host} must be refused unless the host opts in"
        );
        assert!(
            ClientIdUrl::parse(&raw, &permissive).is_ok(),
            "{host} is what the section 6.5 carve-out is for"
        );
    }
    // And it relaxes NOTHING else: every other special-use range stays refused.
    assert_eq!(
        ClientIdUrl::parse("https://169.254.169.254/app", &permissive).err(),
        Some(CimdError::SpecialUseAddress),
        "the carve-out is for loopback, not for link-local metadata services"
    );
    assert_eq!(
        ClientIdUrl::parse("https://10.0.0.1/app", &permissive).err(),
        Some(CimdError::SpecialUseAddress),
    );
}

// ---------------------------------------------------------------------------------------------
// Section 6.6: the size cap.
// ---------------------------------------------------------------------------------------------

/// At the cap, one over, one under. The cap is on the BYTES HANDED IN, which is the only place a
/// library that never reads a socket can apply one.
#[test]
fn the_document_size_cap_holds_at_the_boundary() {
    assert_eq!(oauth_as::MAX_CLIENT_ID_DOCUMENT_BYTES, 5120);

    // Padded to an exact length with a member the validator ignores, so the only thing changing
    // across the three cases is the byte count.
    let build = |total: usize| -> Vec<u8> {
        let prefix = format!(
            r#"{{"client_id":"{URL}","redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"none","logo_uri":""#
        );
        let suffix = r#""}"#;
        let pad = total - prefix.len() - suffix.len();
        format!("{prefix}{}{suffix}", "x".repeat(pad)).into_bytes()
    };

    let policy = strict();
    let at = build(policy.max_document_bytes);
    assert_eq!(at.len(), policy.max_document_bytes);
    assert!(
        ValidatedClientIdDocument::validate(&url(URL), &at, &policy).is_ok(),
        "a document exactly at the cap is within it"
    );

    let under = build(policy.max_document_bytes - 1);
    assert!(ValidatedClientIdDocument::validate(&url(URL), &under, &policy).is_ok());

    let over = build(policy.max_document_bytes + 1);
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(URL), &over, &policy),
        Err(CimdError::DocumentTooLarge),
        "one byte over the cap is over the cap"
    );
}

/// The identifier itself is bounded too: it arrives as an unauthenticated `client_id` request
/// parameter of an attacker's chosen length, and every syntax check is a scan over it.
#[test]
fn the_client_id_url_is_bounded() {
    assert_eq!(oauth_as::MAX_CLIENT_ID_URL_BYTES, 2048);
    let prefix = "https://client.example/";
    let raw = format!(
        "{prefix}{}",
        "a".repeat(oauth_as::MAX_CLIENT_ID_URL_BYTES - prefix.len() + 1)
    );
    assert_eq!(
        ClientIdUrl::parse(&raw, &strict()).err(),
        Some(CimdError::UrlTooLong)
    );
}

// ---------------------------------------------------------------------------------------------
// Sections 4.5 and 6.1: redirect URIs.
// ---------------------------------------------------------------------------------------------

/// Section 6.1 PERMITS an AS to require a relationship between `redirect_uris` and the client
/// identifier. It is on by default here, because without it anyone who can host a document can
/// name any redirect URI in it.
#[test]
fn a_cross_origin_redirect_uri_is_refused_by_default_and_allowed_when_a_host_says_so() {
    let body = document(&format!(
        r#"{{"client_id": "{URL}", "redirect_uris": ["https://elsewhere.example/callback"],
             "token_endpoint_auth_method": "none"}}"#
    ));
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
        Err(CimdError::RedirectUriNotSameOrigin),
    );

    let mut permissive = strict();
    permissive.redirect_uris_same_origin = false;
    assert!(
        ValidatedClientIdDocument::validate(&url(URL), &body, &permissive).is_ok(),
        "a deployment serving native clients turns this off knowing what it costs"
    );
}

/// The prefix trap the same-origin check has to avoid: `https://client.example.evil.example` has
/// the client identifier's origin as a string PREFIX and is a different origin.
#[test]
fn same_origin_is_an_origin_comparison_and_not_a_string_prefix() {
    let body = document(&format!(
        r#"{{"client_id": "{URL}",
             "redirect_uris": ["https://client.example.evil.example/callback"],
             "token_endpoint_auth_method": "none"}}"#
    ));
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
        Err(CimdError::RedirectUriNotSameOrigin),
    );
}

/// The RFC 7591 rules are not re-implemented here, they are RUN here: this is
/// `registration::validate`, the same function the dynamic registration endpoint calls, so a
/// refusal arrives with an RFC 7591 section 3.2.2 code rather than a CIMD-specific one.
#[test]
fn the_rfc_7591_metadata_rules_are_the_same_rules_and_not_a_second_copy() {
    let refusals: &[(&str, oauth_as::RegistrationErrorCode)] = &[
        // A redirect URI with a fragment (RFC 6749 s3.1.2).
        (
            r#""redirect_uris": ["https://client.example/cb#x"]"#,
            oauth_as::RegistrationErrorCode::InvalidRedirectUri,
        ),
        // A relative redirect URI is not absolute.
        (
            r#""redirect_uris": ["/cb"]"#,
            oauth_as::RegistrationErrorCode::InvalidRedirectUri,
        ),
        // A grant OAuth 2.1 removed.
        (
            r#""redirect_uris": ["https://client.example/cb"], "grant_types": ["password"]"#,
            oauth_as::RegistrationErrorCode::InvalidClientMetadata,
        ),
        // A response type this server does not issue.
        (
            r#""redirect_uris": ["https://client.example/cb"], "response_types": ["token"]"#,
            oauth_as::RegistrationErrorCode::InvalidClientMetadata,
        ),
        // A software statement this server does not evaluate (RFC 7591 s2.3).
        (
            r#""redirect_uris": ["https://client.example/cb"], "software_statement": "eyJ...""#,
            oauth_as::RegistrationErrorCode::InvalidSoftwareStatement,
        ),
    ];
    for (members, expected) in refusals {
        let body = document(&format!(
            r#"{{"client_id": "{URL}", "token_endpoint_auth_method": "none", {members}}}"#
        ));
        match ValidatedClientIdDocument::validate(&url(URL), &body, &strict()) {
            Err(CimdError::Metadata(response)) => assert_eq!(
                response.error, *expected,
                "{members} must be refused by the RFC 7591 validator with its own code"
            ),
            other => panic!("{members} should have reached the RFC 7591 validator, got {other:?}"),
        }
    }
}

/// The cap on `redirect_uris` is the registration one, because it is the same list read the same
/// way: exact string comparison, linearly, on every authorization request for the client.
#[test]
fn the_redirect_uri_cap_is_the_registration_cap() {
    let uris: Vec<String> = (0..=oauth_as::MAX_REGISTERED_REDIRECT_URIS)
        .map(|i| format!("\"https://client.example/cb{i}\""))
        .collect();
    let body = document(&format!(
        r#"{{"client_id": "{URL}", "token_endpoint_auth_method": "none",
             "redirect_uris": [{}]}}"#,
        uris.join(",")
    ));
    match ValidatedClientIdDocument::validate(&url(URL), &body, &strict()) {
        Err(CimdError::Metadata(response)) => assert_eq!(
            response.error,
            oauth_as::RegistrationErrorCode::InvalidRedirectUri
        ),
        other => panic!("one over the cap must be refused, got {other:?}"),
    }
}

/// The scope ceiling is the deployment's, not the document's: a document that asks for more than
/// the policy offers is refused rather than trimmed.
#[test]
fn the_scope_ceiling_belongs_to_the_deployment() {
    let body = document(&format!(
        r#"{{"client_id": "{URL}", "token_endpoint_auth_method": "none",
             "redirect_uris": ["https://client.example/cb"], "scope": "read write admin"}}"#
    ));
    match ValidatedClientIdDocument::validate(&url(URL), &body, &strict()) {
        Err(CimdError::Metadata(response)) => assert_eq!(
            response.error,
            oauth_as::RegistrationErrorCode::InvalidClientMetadata
        ),
        other => panic!("an undeclared scope catalogue offers nothing, got {other:?}"),
    }

    let mut permissive = strict();
    permissive.registration_bounds.allowed_scopes =
        oauth_as::ScopeSet::parse("read write admin").expect("a valid scope list");
    let validated = ValidatedClientIdDocument::validate(&url(URL), &body, &permissive)
        .expect("within the declared ceiling");
    let client = validated.to_client();
    // `ScopeSet` is a SET, so the order it prints in is its own; what is asserted is
    // membership, which is what the ceiling means.
    for scope in ["read", "write", "admin"] {
        assert!(
            client
                .allowed_scopes
                .to_string()
                .split(' ')
                .any(|s| s == scope),
            "the document's scope must survive into the client's ceiling: {scope}"
        );
    }
    // The DEFAULT is empty: what a request naming no scope receives is a deployment decision, and
    // a document the client wrote is not one.
    assert!(client.default_scopes.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Malformed input.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_body_that_is_not_a_json_object_is_refused_as_such() {
    for body in [
        &b""[..],
        b"not json",
        b"[]",
        b"\"https://client.example/oauth/client\"",
        b"{\"client_id\":",
        // Valid UTF-8 is not assumed: the seam takes bytes.
        &[0xff, 0xfe, 0x00][..],
    ] {
        assert_eq!(
            ValidatedClientIdDocument::validate(&url(URL), body, &strict()),
            Err(CimdError::NotJson),
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Section 5: the metadata member.
// ---------------------------------------------------------------------------------------------

/// Section 5 requires the AS to publish `client_id_metadata_document_supported`, and it has to be
/// TRUE OF THIS DEPLOYMENT rather than true of the build. This crate performs no fetch, so
/// compiling the feature in proves the validator exists and nothing else; only the host knows
/// whether it wired the fetch, and the member is derived from the host saying so.
#[test]
fn the_metadata_member_follows_the_host_configuration_and_not_the_cargo_feature() {
    let mut config = oauth_as::ServerConfig::new("https://as.example", "https://as.example/device");
    let off = oauth_as::AuthorizationServerMetadata::from_config(&config);
    assert!(
        !off.client_id_metadata_document_supported,
        "the feature is compiled in for this test binary, and the answer is still false, because \
         the host has not wired a fetch"
    );

    config.cimd = Some(Box::new(CimdPolicy::new()));
    let on = oauth_as::AuthorizationServerMetadata::from_config(&config);
    assert!(on.client_id_metadata_document_supported);

    // It is published either way rather than omitted when false: the member is what a client reads
    // BEFORE trying, so silence and `false` must not be the same wire bytes here.
    let json = serde_json::to_value(&off).expect("the document serializes");
    assert_eq!(
        json.get("client_id_metadata_document_supported"),
        Some(&serde_json::Value::Bool(false))
    );
}

// ---------------------------------------------------------------------------------------------
// The overclaim guard.
// ---------------------------------------------------------------------------------------------

/// A GREEN RUN OF THIS FILE PROVES LESS THAN IT LOOKS LIKE, and that is worth a test rather than a
/// comment, because the comment is what gets skipped. Every duty below is the host's, none of it
/// is checked anywhere in this crate, and a reader who takes the suite above as "CIMD is done" is
/// wrong in exactly these places.
///
/// The lesson is a specific one from this repository: the signer harness asserted five
/// MUST-NOT-PANIC inputs and presented three, and nothing said so.
#[test]
fn the_host_duties_this_crate_does_not_discharge() {
    const HOST_DUTIES: &[&str] = &[
        "the fetch itself",
        "s4.2: MUST NOT follow HTTP redirects, which every HTTP client does by default",
        "s4.2: only a 200 is a document; every other status is an error",
        "s4.3: on fetch failure, abort the authorization request",
        "s4.4: never cache an error response, an invalid document or a malformed one",
        "s6.5: DNS resolution, which is the half of the special-use check that needs a resolver",
        "s6.5: the rebinding window between checking an address and connecting to a name",
        "TLS certificate verification",
    ];
    // The one thing the crate CAN do about the first two is structural rather than enforced, and
    // saying which is the point of this test.
    assert_eq!(HOST_DUTIES.len(), 8);

    // `validate` takes the URL the bytes CAME FROM, so a host that followed a redirect to another
    // URL and passed THAT fails the section 4.1 comparison instead of passing it. This converts
    // the most common section 4.2 violation into a refusal; it does not enforce section 4.2.
    let redirected_to = "https://cdn.example/hosted/client";
    let body = valid_document();
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(redirected_to), &body, &strict()),
        Err(CimdError::ClientIdMismatch),
        "a document retrieved from somewhere else is not this client's document"
    );

    // And the case it does NOT catch, stated so nobody reads the assertion above as more than it
    // is: a host that follows a redirect and then hands back the REQUESTED url validates fine.
    assert!(
        ValidatedClientIdDocument::validate(&url(URL), &body, &strict()).is_ok(),
        "the crate cannot tell where these bytes actually came from; not following redirects \
         remains the host's duty"
    );

    // A special-use check on a NAME is not performed at all, because it cannot be: there is no
    // resolver here. `internal.corp.example` may well resolve to 10.0.0.1.
    assert!(
        ClientIdUrl::parse("https://internal.corp.example/app", &strict()).is_ok(),
        "a name is not a literal, and Ok() here is not a statement that fetching it is safe"
    );
}

/// The refusal type is an error a host can put behind `?`, like every other refusal this crate
/// publishes.
#[test]
fn cimd_error_is_a_std_error() {
    fn as_boxed<E: std::error::Error + Send + Sync + 'static>(e: E) -> Box<dyn std::error::Error> {
        Box::new(e)
    }
    let text = CimdError::ClientIdMismatch.to_string();
    assert_eq!(as_boxed(CimdError::ClientIdMismatch).to_string(), text);
    assert!(
        text.contains("client_id"),
        "a host that logs the refusal must be told which rule it was: {text}"
    );
}

/// SECTION 6.5's LITERAL CHECK MUST READ THE SAME ADDRESS THE FETCHER WILL CONNECT TO.
///
/// The crate decided "is this an IP literal" with `Ipv4Addr::from_str`, which accepts only
/// canonical dotted-quad. The host that performs the fetch does not: every mainstream HTTP client
/// goes through a WHATWG URL parser, which accepts decimal, hex, octal and short forms and
/// normalises them all to the same address. So the only spelling being refused was the one an
/// attacker would never use, and `https://0x7f000001/app` passed validation and then fetched
/// 127.0.0.1 -- inside the deployment's network, which is the request this check exists to stop.
///
/// This matters more here than an ordinary bounds check because of what the module PROMISES: its
/// docs tell the host that the literal half of section 6.5 is discharged and only name resolution
/// is left to them. A host that believed it added no defence of its own.
///
/// Each spelling below is 127.0.0.1 or 10.0.0.1 to a WHATWG parser.
#[test]
fn an_ip_literal_spelled_any_way_but_canonically_is_refused() {
    let policy = CimdPolicy::new();
    for spelling in [
        "https://2130706433/app", // decimal
        "https://0x7f000001/app", // hex
        "https://0xa000001/app",  // hex, 10.0.0.1
        "https://0177.0.0.1/app", // octal first octet
        "https://127.1/app",      // short form
        "https://127.0.0.1./app", // trailing dot, dropped by the parser
        "https://2852039166/app", // decimal 169.254.169.254, the cloud metadata service
    ] {
        assert_eq!(
            ClientIdUrl::parse(spelling, &policy).unwrap_err(),
            CimdError::SpecialUseAddress,
            "{spelling} is a special-use address to the client that will fetch it, so this crate \
             must not certify it as a name -- and it must be refused BY THAT RULE, not swept up by \
             a syntax check that happens to fire first"
        );
    }
}

/// A BACKSLASH MAKES THIS CRATE AND THE FETCHER DISAGREE ABOUT WHICH HOST THEY ARE LOOKING AT.
///
/// `https://good.example\.evil.com/app`: this crate reads the authority as
/// `good.example\.evil.com`, so the origin, the same-origin redirect rule and the byte-equality
/// check are all computed against that, while a WHATWG parser treats the backslash as a path
/// separator and connects to `good.example`. One string, two hosts.
///
/// The refusal is [`CimdError::NotAscii`], a variant reused rather than earned -- a backslash IS
/// printable ASCII -- and pinning it is the point rather than an endorsement of it. This case used
/// to assert only `is_err()`, which is what let the misattribution below sit here unnoticed.
#[test]
fn a_backslash_in_the_authority_is_refused() {
    let policy = CimdPolicy::new();
    for spelling in [
        "https://good.example\\.evil.com/app",
        "https://client.example\\evil.example/app",
    ] {
        assert_eq!(
            ClientIdUrl::parse(spelling, &policy).unwrap_err(),
            CimdError::NotAscii,
            "{spelling} names one host to this crate and another to the fetcher, and must be \
             refused BY THE BACKSLASH RULE: asserting only that it errored would go on passing if \
             that rule were deleted and some other check caught the string by accident"
        );
    }
}

/// NOT a backslash test, despite containing a backslash, and it is separate so that nobody folds
/// it back into one.
///
/// `https://client.example\@evil.example/app` was pinned above as a backslash refusal. It is not:
/// the userinfo check runs over the authority BEFORE the backslash check does, so this string is
/// refused for its `@` and would still be refused with the backslash rule deleted. The ordering is
/// the whole of what this case establishes.
#[test]
fn a_backslash_beside_a_userinfo_marker_is_refused_for_the_userinfo() {
    let policy = CimdPolicy::new();
    assert_eq!(
        ClientIdUrl::parse("https://client.example\\@evil.example/app", &policy).unwrap_err(),
        CimdError::Userinfo,
        "`@` is checked before `\\`, so this is section 3's userinfo refusal"
    );
}

/// The refusals above must not cost a legitimate identifier. "Ends in a number" is a property of
/// the LAST label only, so a name merely containing digits is a name.
#[test]
fn the_address_refusals_do_not_reject_ordinary_names() {
    let policy = CimdPolicy::new();
    for ok in [
        "https://client.example/app",
        "https://client.example:8443/app",
        "https://sub.client.example/app",
        "https://xn--e1afmkfd.example/app", // punycode
        "https://client4.example/app",      // a digit, but not in the last label
        "https://8.8.8.8/app",              // a canonical literal that is NOT special-use
    ] {
        assert!(
            ClientIdUrl::parse(ok, &policy).is_ok(),
            "{ok} is a legitimate client identifier and must still parse"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Section 4.1: the members that carry a CREDENTIAL.
//
// `client_secret` is the draft's prohibition and has its own test above. These are the member the
// draft PERMITS and this build cannot honour, which is the harder case: the temptation is to let
// `serde` drop it, and dropping it registers a public client out of a document that asked to be a
// confidential one.
// ---------------------------------------------------------------------------------------------

/// Both spellings, and the refusal names the rule rather than "some metadata was wrong": a
/// `CimdError::Metadata` here would mean the key had reached the RFC 7591 validator, which does not
/// model it and would therefore have dropped it.
#[test]
fn a_document_offering_a_key_is_refused_rather_than_registered_as_public() {
    for member in [
        r#""jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "aa", "y": "bb"}]}"#,
        r#""jwks_uri": "https://client.example/jwks.json""#,
    ] {
        let body = document(&format!(
            r#"{{
                "client_id": "https://client.example/oauth/client",
                "redirect_uris": ["https://client.example/callback"],
                "token_endpoint_auth_method": "none",
                {member}
            }}"#
        ));
        assert_eq!(
            ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
            Err(CimdError::KeyMaterialPresent),
            "a document carrying {member} must be refused, not accepted with the key dropped"
        );
    }
}

/// The draft's MUST NOT on PRIVATE key material, which is only ever reachable through `jwks`: a
/// private JWK is a JWK. Asserted separately from the test above because the two say different
/// things — that one is "this build cannot honour a key", this one is "the draft forbids this one
/// outright" — and a future release that makes `jwks` registrable must keep this refusal.
#[test]
fn a_document_publishing_a_private_key_is_refused() {
    let body = document(
        r#"{
            "client_id": "https://client.example/oauth/client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "none",
            "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "aa", "y": "bb", "d": "SECRET"}]}
        }"#,
    );
    assert_eq!(
        ValidatedClientIdDocument::validate(&url(URL), &body, &strict()),
        Err(CimdError::KeyMaterialPresent),
    );
}

/// The refusal is of the MEMBER, not of any word in the document: a client whose metadata merely
/// mentions a key-shaped string elsewhere still registers. Without this, the check above could be
/// satisfied by something as crude as a substring scan of the body.
#[test]
fn a_document_that_names_no_key_member_still_registers() {
    let body = document(
        r#"{
            "client_id": "https://client.example/oauth/client",
            "client_name": "jwks_uri is not a key here, it is a name",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "none"
        }"#,
    );
    let validated = ValidatedClientIdDocument::validate(&url(URL), &body, &strict())
        .expect("a document with no key member is unaffected");
    assert_eq!(validated.to_client().auth, oauth_as::ClientAuth::Public);
}

/// A PERCENT-ESCAPE IN THE AUTHORITY IS THE SPECIAL-USE REFUSAL DEFEATED ONE ENCODING LAYER DOWN.
///
/// `ends_in_a_number` reads the raw authority text. A WHATWG host parser percent-DECODES the host
/// before applying that rule, so the crate and the fetcher read different strings — which is the
/// entire class of defect the special-use check exists to prevent, and the first version of that
/// check missed it. Measured before the fix: every URL below parsed `Ok`, and `curl` on the second
/// connects to 169.254.169.254, the cloud metadata service.
///
/// Refused rather than decoded-and-rechecked, deliberately: decoding would mean two parties
/// deriving a host from the same bytes by their own rules, which is what went wrong in the first
/// place. Nothing legitimate is lost — an internationalised name arrives as punycode, and section
/// 4.1's byte-for-byte `client_id` comparison means an escaped authority could never match its own
/// document anyway.
#[test]
fn a_percent_escaped_authority_is_refused() {
    let policy = CimdPolicy::new();
    for encoded in [
        "https://%31%32%37%2e%30%2e%30%2e%31/app", // 127.0.0.1
        "https://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/app", // 169.254.169.254
        "https://%31%30%2e%30%2e%30%2e%31/app",    // 10.0.0.1
        "https://127.0.0.1%2e/app",                // only the trailing dot encoded
        "https://client%2eexample/app",            // an ordinary name, still refused
    ] {
        assert_eq!(
            ClientIdUrl::parse(encoded, &policy).unwrap_err(),
            CimdError::NotAscii,
            "{encoded} would be decoded by the fetcher into a host this crate never inspected"
        );
    }
    // ORDER MATTERS, and this case pins it rather than leaving it to chance. Encoding only the
    // FIRST label leaves the last one (`1`) a bare number, so `ends_in_a_number` fires before the
    // percent rule is reached and the refusal is SpecialUseAddress. Still refused, by a different
    // rule; asserting NotAscii here would pin the wrong one.
    assert_eq!(
        ClientIdUrl::parse("https://%31%32%37.0.0.1/app", &policy).unwrap_err(),
        CimdError::SpecialUseAddress
    );

    // The path may still carry escapes: only the AUTHORITY is refused, because only the authority
    // decides where the request goes.
    assert!(ClientIdUrl::parse("https://client.example/a%20b", &policy).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Section 6.5, the other direction: what the SSRF refusal must NOT refuse.
// ---------------------------------------------------------------------------------------------

/// The whole of section 6.5's coverage above asserts REFUSALS, and a refusal-only suite cannot
/// tell a working defence from one that refuses everything. This is the half that was missing:
/// the mutation sweep at 0.9.2 left seventeen survivors inside `is_special_use_literal`, all of
/// them mutations that change WHICH address the function computes while leaving the verdict
/// "special-use, refuse" intact -- so every assertion above still passed.
///
/// The v4-mapped case is the sharpest of them. `::ffff:93.184.216.34` extracts its embedded
/// address with `s[6] >> 8`; mutate that to `<<` and the extraction truncates to `0.x.x.x`,
/// which `[0, ..] => true` refuses as "this host on this network". Every refusal test still
/// passes, because the mutant refuses MORE. Only an acceptance can see the difference.
///
/// The boundaries matter for the same reason and for a second one: a range guard that is one
/// address too wide silently refuses a legitimate client, and the failure mode of an SSRF
/// defence that is too broad is an authorization server that will not talk to real clients.
#[test]
fn addresses_outside_every_special_use_range_are_accepted() {
    for host in [
        // An ordinary public v4 literal, and the same address written v4-mapped. The second is
        // the one that pins the embedded-address arithmetic.
        "93.184.216.34",
        "[::ffff:93.184.216.34]",
        // One address on each side of every bounded v4 range, chosen to sit exactly one step
        // outside it, so a guard widened by one is caught rather than merely a guard deleted.
        "172.15.255.255",  // just below 172.16.0.0/12
        "172.32.0.1",      // just above 172.31.255.255
        "100.63.255.255",  // just below 100.64.0.0/10
        "100.128.0.1",     // just above 100.127.255.255
        "198.17.255.255",  // just below 198.18.0.0/15
        "198.20.0.1",      // just above 198.19.255.255
        "223.255.255.255", // just below the 224/4 multicast floor
        // And the v6 boundaries, which the suite reached not at all.
        "[2001:200::1]", // outside 2001::/23, which ends at 2001:01ff
        "[2003::1]",     // outside 2002::/16
        "[fb00::1]",     // just below fc00::/7
        "[fec0::1]",     // outside fe80::/10, above its ceiling
        "[2606:2800:220:1:248:1893:25c8:1946]", // a real public v6 address
    ] {
        let raw = format!("https://{host}/app");
        assert!(
            ClientIdUrl::parse(&raw, &strict()).is_ok(),
            "{host} is outside every RFC 6890 special-use range, so refusing it would make this \
             server decline a legitimate client identifier"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Mutation-kill coverage: boundaries and bit-ops the tests above did not pin.
// ---------------------------------------------------------------------------------------------

/// The URL length cap is `>`, not `>=`: a URL EXACTLY at the cap is within it. Without a case at
/// the boundary, the length check could be off by one (refusing the last legal byte) and every
/// test still pass, because the only length assertions above are one-over.
#[test]
fn a_client_id_url_exactly_at_the_cap_is_accepted() {
    let prefix = "https://client.example/";
    let at_cap = format!(
        "{prefix}{}",
        "a".repeat(oauth_as::MAX_CLIENT_ID_URL_BYTES - prefix.len())
    );
    assert_eq!(at_cap.len(), oauth_as::MAX_CLIENT_ID_URL_BYTES);
    assert!(
        ClientIdUrl::parse(&at_cap, &strict()).is_ok(),
        "a URL exactly at the cap is not over it; the check is strictly greater-than"
    );
}

/// `Display` writes the identifier VERBATIM. A host that logs or renders the client identifier
/// gets the string it parsed, so an impl that wrote nothing (or a default) would silently blank
/// every audit line that formats a `ClientIdUrl`.
#[test]
fn a_client_id_url_displays_as_the_string_it_parsed() {
    let parsed = url(URL);
    assert_eq!(format!("{parsed}"), URL);
    assert_eq!(parsed.to_string(), URL);
    // A non-empty rendering is the point: an `Ok(Default::default())` impl would print "".
    assert!(!parsed.to_string().is_empty());
}

/// The three IPv4 ranges whose membership turns on the SECOND octet, pinned on BOTH sides of each
/// boundary. A test that only supplies in-range addresses cannot tell a real range guard from one
/// that always fires; each accepted address below is the octet just outside the range, and would be
/// wrongly refused if the guard were widened to `true` or its bound moved.
#[test]
fn the_second_octet_ranges_are_pinned_on_both_sides() {
    let policy = strict();
    // RFC 1918 private: 172.16.0.0/12, i.e. second octet 16..=31.
    // RFC 6598 shared: 100.64.0.0/10, i.e. second octet 64..=127.
    // RFC 2544 benchmarking: 198.18.0.0/15, i.e. second octet 18 or 19.
    let refused = [
        "172.16.0.1",
        "172.31.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "198.18.0.1",
        "198.19.0.1",
    ];
    for host in refused {
        let raw = format!("https://{host}/app");
        assert_eq!(
            ClientIdUrl::parse(&raw, &policy).err(),
            Some(CimdError::SpecialUseAddress),
            "{host} is inside its special-use range and must be refused"
        );
    }
    let accepted = [
        "172.15.0.1",  // one below the 172.16 range
        "172.32.0.1",  // one above the 172.31 range
        "100.63.0.1",  // one below the 100.64 range
        "100.128.0.1", // one above the 100.127 range
        "198.17.0.1",  // one below the benchmarking pair
        "198.20.0.1",  // one above the benchmarking pair
    ];
    for host in accepted {
        let raw = format!("https://{host}/app");
        assert!(
            ClientIdUrl::parse(&raw, &policy).is_ok(),
            "{host} is OUTSIDE every special-use range and must be accepted; refusing it would be a \
             range guard that fires too widely"
        );
    }
}

/// A v4-mapped (`::ffff:a.b.c.d`) or v4-compatible (`::a.b.c.d`) IPv6 literal is classified by its
/// EMBEDDED v4 address, and it reaches this crate spelled in hex/colon form (the dotted form is
/// refused one step earlier by the "ends in a number" rule). This pins the octet extraction and the
/// guard that selects the mapped/compatible block: each accepted address embeds a PUBLIC v4 address,
/// and each refused address embeds a SPECIAL-USE one whose classification turns on an octet the
/// extraction must read correctly.
#[test]
fn a_v4_mapped_or_compatible_literal_is_classified_by_its_embedded_address() {
    let policy = strict();

    // Embedded 8.8.8.8, public. `::ffff:808:808` has s[5]==0xffff; `::808:808` has s[5]==0. Both
    // must be ACCEPTED, which pins the mapped/compatible guard (any mutation that skips the block
    // falls through to `match s[0]`, where s[0]==0 => true => wrongly refused) and the first-octet
    // extraction (a `<<` in place of `>>` zeroes the first octet, making it 0.8.8.8, special).
    for host in ["[::ffff:808:808]", "[::808:808]"] {
        let raw = format!("https://{host}/app");
        assert!(
            ClientIdUrl::parse(&raw, &policy).is_ok(),
            "{host} embeds the public address 8.8.8.8 and must be accepted"
        );
    }

    // Embedded special-use addresses whose membership turns on the SECOND octet (`s[6] & 0xff`) and
    // the THIRD octet (`s[7] >> 8`), so a bit-op that mangles those octets would wrongly ACCEPT them.
    // `::ffff:ac10:505` = ::ffff:172.16.5.5 (RFC 1918, second octet); the second octet OR-ed or
    // XOR-ed with 0xff leaves the 16..=31 range and would be accepted.
    // `::ffff:cb00:7105` = ::ffff:203.0.113.5 (RFC 5737 doc, third octet); zeroing the third octet
    // gives 203.0.0.5, which is not special and would be accepted.
    // `2002::808:808` is 6to4 (special by s[0]) with a public embedded tail: a mapped/compatible
    // guard that fired on s[5]==0 alone would classify it by 8.8.8.8 and wrongly accept it.
    let refused = ["[::ffff:ac10:505]", "[::ffff:cb00:7105]", "[2002::808:808]"];
    for host in refused {
        let raw = format!("https://{host}/app");
        assert_eq!(
            ClientIdUrl::parse(&raw, &policy).err(),
            Some(CimdError::SpecialUseAddress),
            "{host} is special-use and must be refused; accepting it is the SSRF the check exists \
             to stop"
        );
    }
}

/// The IPv6 range guards that turn on segments after the first, pinned at their boundaries.
///
/// `100::/64` (RFC 6666 discard) is special only when segments 1..=3 are all zero; an address that
/// zeroes only SOME of them (`100:1::`, `100:0:1::`) is a different, non-special address and must be
/// accepted, which pins both `&&`s in that guard. `2001::/23` (RFC 2928) is `s[1] < 0x0200`;
/// `2001:200::1` is the first address just OUTSIDE it and must be accepted, which pins the `<`
/// against a `<=`.
#[test]
fn the_v6_range_guards_are_pinned_at_their_boundaries() {
    let policy = strict();

    // Inside 100::/64: refused.
    for host in ["[100::1]", "[2001::1]"] {
        let raw = format!("https://{host}/app");
        assert_eq!(
            ClientIdUrl::parse(&raw, &policy).err(),
            Some(CimdError::SpecialUseAddress),
            "{host} is inside its special-use range and must be refused"
        );
    }

    // Just outside each guard: accepted.
    for host in [
        "[100:1::]",     // segment 1 non-zero => not the /64 discard prefix
        "[100:0:1::]",   // segment 2 non-zero => not the /64 discard prefix
        "[2001:200::1]", // s[1] == 0x0200 is the first value outside 2001::/23
    ] {
        let raw = format!("https://{host}/app");
        assert!(
            ClientIdUrl::parse(&raw, &policy).is_ok(),
            "{host} is OUTSIDE its special-use range and must be accepted"
        );
    }
}
