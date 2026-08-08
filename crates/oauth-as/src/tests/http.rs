// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the parts of the `http` feature that are not reachable from outside the crate:
//! the form/query decoder, the RFC 6749 s2.3.1 Basic decoder, and the route derivation that turns
//! an RFC 8414 document into paths. The wire behaviour they support is tested end to end over a
//! socket in `tests/http_surface.rs`.

use super::*;
use crate::server::ServerConfig;

fn headers_with(auth: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::AUTHORIZATION, HeaderValue::from_str(auth).unwrap());
    h
}

#[test]
fn decoding_borrows_when_there_is_nothing_to_decode() {
    // The efficiency claim in the module docs, held to: an opaque token is hex or base64url and
    // never needs decoding, so the common case must not allocate.
    assert!(matches!(
        decode_component("abc123-_~"),
        Cow::Borrowed("abc123-_~")
    ));
    assert!(matches!(decode_component("a+b"), Cow::Owned(_)));
    assert!(matches!(decode_component("a%20b"), Cow::Owned(_)));
}

#[test]
fn decodes_plus_and_percent_escapes() {
    assert_eq!(decode_component("a+b"), "a b");
    assert_eq!(decode_component("a%20b"), "a b");
    assert_eq!(decode_component("%2D"), "-");
    assert_eq!(decode_component("urn%3Aietf%3Aparams"), "urn:ietf:params");
}

#[test]
fn a_stray_percent_is_passed_through_not_fatal() {
    // A truncated escape cannot be an escape; keeping the byte lets the value be refused on its
    // merits rather than turning a wrong client id into a parse failure.
    assert_eq!(decode_component("100%"), "100%");
    assert_eq!(decode_component("%zz"), "%zz");
}

#[test]
fn parse_pairs_keeps_present_but_empty_parameters() {
    let pairs = parse_pairs("a=1&b=&c");
    assert_eq!(param(&pairs, "a"), Some("1"));
    // RFC 6749 distinguishes an empty value from an absent parameter (an empty `client_id` is a
    // present-and-invalid client id, not a missing one), so both must survive parsing.
    assert_eq!(param(&pairs, "b"), Some(""));
    assert_eq!(param(&pairs, "c"), Some(""));
    assert_eq!(param(&pairs, "d"), None);
}

#[test]
fn a_repeated_parameter_keeps_the_first() {
    // RFC 6749 s3.1: a parameter MUST NOT be sent more than once. First-wins denies a smuggled
    // duplicate the ability to override what earlier layers parsed.
    let pairs = parse_pairs("grant_type=authorization_code&grant_type=client_credentials");
    assert_eq!(param(&pairs, "grant_type"), Some("authorization_code"));
}

#[test]
fn basic_credentials_are_form_urldecoded_before_use() {
    // RFC 6749 s2.3.1: each half is form-urlencoded, THEN joined and base64ed.
    let raw = BASE64_STANDARD.encode("s6%42he:7Fjfp0%24ZM");
    let headers = headers_with(&format!("Basic {raw}"));
    assert!(basic_attempted(&headers));
    let (id, secret) = decode_basic(&headers).expect("well-formed");
    assert_eq!(id, "s6Bhe");
    assert_eq!(secret, "7Fjfp0$ZM");
}

#[test]
fn a_password_containing_a_colon_survives() {
    // RFC 7617: the userid cannot contain a colon, so the split is on the FIRST one only.
    let raw = BASE64_STANDARD.encode("client:a:b:c");
    let (id, secret) = decode_basic(&headers_with(&format!("Basic {raw}"))).expect("well-formed");
    assert_eq!(id, "client");
    assert_eq!(secret, "a:b:c");
}

#[test]
fn malformed_basic_is_invalid_client() {
    for value in ["Basic !!!not-base64!!!", "Basic Y2xpZW50"] {
        let err = decode_basic(&headers_with(value)).expect_err("must be refused");
        assert_eq!(err.error, ErrorCode::InvalidClient);
    }
}

#[test]
fn a_non_basic_authorization_header_is_not_an_attempt() {
    // A Bearer header at the token endpoint is not client authentication, so it must not turn a
    // body-credential failure into a 401 challenge for a scheme the client never offered.
    assert!(!basic_attempted(&headers_with("Bearer abc")));
    assert!(basic_attempted(&headers_with("basic abc")));
}

#[test]
fn two_authentication_methods_are_refused() {
    // RFC 6749 s2.3: "The client MUST NOT use more than one authentication method in each
    // request."
    let raw = BASE64_STANDARD.encode("client:secret");
    let form = parse_pairs("client_id=client&client_secret=secret");
    let err = credentials(&headers_with(&format!("Basic {raw}")), &form).expect_err("refused");
    assert_eq!(err.error, ErrorCode::InvalidRequest);

    // Even a bare client_id alongside Basic is two methods' worth of identity claims.
    let form = parse_pairs("client_id=client");
    let err = credentials(&headers_with(&format!("Basic {raw}")), &form).expect_err("refused");
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn a_public_client_may_present_a_bare_client_id() {
    // RFC 6749 s3.2.1: a client that is not authenticating still identifies itself.
    let creds = credentials(&HeaderMap::new(), &parse_pairs("client_id=public")).expect("ok");
    assert_eq!(creds.client_id, "public");
    assert_eq!(creds.client_secret, None);
}

#[test]
fn no_credentials_at_all_is_invalid_client() {
    // RFC 6749 s5.2 lists "no client authentication included" under invalid_client by name.
    let err = credentials(&HeaderMap::new(), &parse_pairs("grant_type=x")).expect_err("refused");
    assert_eq!(err.error, ErrorCode::InvalidClient);
}

#[test]
fn routes_are_derived_from_the_advertised_urls() {
    assert_eq!(
        endpoint_path(
            "https://as.example",
            "token_endpoint",
            "https://as.example/token"
        )
        .unwrap(),
        "/token"
    );
    // RFC 8414 s3.1 / C12: an issuer with a path serves its endpoints under that path, so a
    // per-tenant router can be merged into one origin without collisions.
    assert_eq!(
        endpoint_path(
            "https://as.example/tenant1",
            "token_endpoint",
            "https://as.example/tenant1/token"
        )
        .unwrap(),
        "/tenant1/token"
    );
    // An endpoint on another origin cannot be served here, and pretending otherwise would publish
    // a promise nothing keeps.
    let err = endpoint_path(
        "https://as.example",
        "token_endpoint",
        "https://other.example/token",
    )
    .unwrap_err();
    assert!(matches!(err, RouterError::EndpointOutsideIssuer { .. }));
    // A prefix match that is not a PATH boundary is not a match either.
    assert!(endpoint_path(
        "https://as.example",
        "token_endpoint",
        "https://as.example.evil/token"
    )
    .is_err());
}

#[test]
fn the_issuer_origin_drops_the_path() {
    // What an Origin header carries (RFC 6454 s6.1): scheme, host, port, and nothing else.
    assert_eq!(issuer_origin("https://as.example"), "https://as.example");
    assert_eq!(
        issuer_origin("https://as.example:8443/tenant1"),
        "https://as.example:8443"
    );
    assert_eq!(
        issuer_origin("https://as.example/a/b"),
        "https://as.example"
    );
}

#[test]
fn the_verification_page_escapes_what_it_echoes() {
    let html = verification_page("\"><script>alert(1)</script>", None, None, None);
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");
    assert!(html.contains("&quot;"), "{html}");
}

/// RFC 8628 s3.3 / s5.4: the consent stage of the page names the client and the scope, and a
/// client name is attacker-influenced data (RFC 7591 registration), so it is escaped too.
#[test]
fn the_consent_stage_names_the_client_and_the_scope_and_escapes_both() {
    let grant = DeviceGrant {
        device_code: "dc".to_string(),
        user_code: "WDJB-MJHT".to_string(),
        client_id: ClientId::new("evil<client>"),
        scope: ScopeSet::from_tokens(["read", "write"]).unwrap(),
        state: DeviceGrantState::Pending,
        created_at: std::time::SystemTime::UNIX_EPOCH,
        expires_at: std::time::SystemTime::UNIX_EPOCH,
        interval: std::time::Duration::from_secs(5),
        last_poll_at: None,
    };
    let named = Some((grant, Some("<script>Totally Legit</script>".to_string())));
    let html = verification_page("WDJB-MJHT", None, named.as_ref(), Some("tok&en"));
    assert!(html.contains("Totally Legit"), "{html}");
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&lt;client&gt;"), "{html}");
    assert!(html.contains("read write"), "{html}");
    assert!(html.contains("WDJB-MJHT"), "{html}");
    // The CSRF token is rendered into the form, escaped.
    assert!(html.contains("name=\"csrf_token\""), "{html}");
    assert!(html.contains("tok&amp;en"), "{html}");
    // Approve is an affirmative, named action; there is no bare submit that approves.
    assert!(html.contains("name=\"action\" value=\"approve\""), "{html}");
    assert!(html.contains("name=\"action\" value=\"deny\""), "{html}");
}

/// Without a grant to describe, the page cannot offer approval: RFC 8628 s3.3's confirmation
/// step is meaningless if the user is confirming something the page never named.
#[test]
fn the_code_entry_stage_offers_no_approve_button() {
    let html = verification_page("", None, None, Some("t"));
    assert!(!html.contains("value=\"approve\""), "{html}");
    assert!(html.contains("Continue"), "{html}");
}

/// A CSRF token is a secret the submitter claims to know, so the comparison must not leak how
/// much of it matched (RFC 6749 s10.12 protection is worthless if it can be searched).
#[test]
fn csrf_tokens_are_compared_in_constant_time_and_correctly() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", ""));
    assert!(!constant_time_eq("", "abc"));
    assert!(constant_time_eq("", ""));
    // Length must not be a shortcut to equality either way.
    assert!(!constant_time_eq("abc", "abc "));
    assert!(!constant_time_eq("abc", &"abc".repeat(1000)));
}

/// RFC 6749 s10.12 defence in depth: a cross-origin form POST is a CORS "simple request", so the
/// browser sends it without a preflight. `Origin` and `Sec-Fetch-Site` are what distinguish it
/// from a real submission of our own form, and absence is not a pass.
#[test]
fn only_a_same_origin_submission_passes_the_origin_check() {
    let origin = "https://as.example";
    let with = |name: &'static str, value: &str| {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    };
    assert!(same_origin(&with("origin", origin), origin));
    assert!(same_origin(&with("sec-fetch-site", "same-origin"), origin));
    assert!(!same_origin(&with("sec-fetch-site", "cross-site"), origin));
    assert!(!same_origin(&with("sec-fetch-site", "same-site"), origin));
    // A user-typed navigation is not a submission of the form we rendered.
    assert!(!same_origin(&with("sec-fetch-site", "none"), origin));
    assert!(!same_origin(
        &with("origin", "https://attacker.example"),
        origin
    ));
    // A prefix of the issuer's origin is a different origin.
    assert!(!same_origin(
        &with("origin", "https://as.example.evil"),
        origin
    ));
    assert!(!same_origin(&HeaderMap::new(), origin));
    // Sec-Fetch-Site is decisive when present, even alongside a forged-looking Origin.
    let mut both = with("sec-fetch-site", "cross-site");
    both.insert("origin", HeaderValue::from_static("https://as.example"));
    assert!(!same_origin(&both, origin));
}

/// Defence in depth for RFC 6749 s10.12: only a real form encoding is accepted.
#[test]
fn only_a_form_urlencoded_body_is_accepted() {
    let ct = |value: &str| {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
        h
    };
    assert!(is_form_urlencoded(&ct("application/x-www-form-urlencoded")));
    assert!(is_form_urlencoded(&ct(
        "application/x-www-form-urlencoded; charset=UTF-8"
    )));
    assert!(is_form_urlencoded(&ct("APPLICATION/X-WWW-FORM-URLENCODED")));
    assert!(!is_form_urlencoded(&ct("text/plain")));
    assert!(!is_form_urlencoded(&ct("application/json")));
    assert!(!is_form_urlencoded(&ct("multipart/form-data")));
    assert!(!is_form_urlencoded(&HeaderMap::new()));
}

#[test]
fn a_router_refuses_to_publish_a_path_it_would_shadow() {
    // Two endpoints on one path means one of them silently never answers, which is the exact
    // metadata lie this module exists to prevent.
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    config.token_endpoint = Some("https://as.example/same".to_string());
    config.introspection_endpoint = Some("https://as.example/same".to_string());
    let server = Arc::new(AuthorizationServer::new(
        config,
        crate::store::MemoryStorage::new(),
    ));
    let err = RouterBuilder::new(server).build().unwrap_err();
    assert!(matches!(err, RouterError::DuplicatePath { .. }), "{err}");
}

/// RFC 8414 s2 with RFC 9068 s4: a server that signs must publish keys somewhere a resource
/// server can reach, and an advertised `jwks_uri` this router cannot serve is the same lie as any
/// other unroutable endpoint. Off-issuer is refused rather than silently unrouted because these
/// bytes are produced by this server and nothing else can produce them.
#[cfg(feature = "jwt")]
#[test]
fn a_jwks_uri_off_the_issuer_refuses_to_build() {
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    config.access_token_format = crate::jwt::AccessTokenFormat::Jwt(Box::new(
        crate::jwt::JwtConfig::new(
            crate::jwt::EcdsaP256Key::generate("k1"),
            "https://rs.example",
        )
        .with_jwks_uri("https://keys.example/jwks"),
    ));
    let server = Arc::new(AuthorizationServer::new(
        config,
        crate::store::MemoryStorage::new(),
    ));
    let err = RouterBuilder::new(server).build().unwrap_err();
    assert!(
        matches!(err, RouterError::EndpointOutsideIssuer { endpoint, .. } if endpoint == "jwks_uri"),
        "{err}"
    );
}

/// The key set shares the collision check every other route gets: a `jwks_uri` that lands on the
/// token endpoint would shadow one of the two, and which one is an implementation detail no host
/// should have to know.
#[cfg(feature = "jwt")]
#[test]
fn a_jwks_uri_colliding_with_another_endpoint_refuses_to_build() {
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    config.access_token_format = crate::jwt::AccessTokenFormat::Jwt(Box::new(
        crate::jwt::JwtConfig::new(
            crate::jwt::EcdsaP256Key::generate("k1"),
            "https://rs.example",
        )
        .with_jwks_uri("https://as.example/token"),
    ));
    let server = Arc::new(AuthorizationServer::new(
        config,
        crate::store::MemoryStorage::new(),
    ));
    let err = RouterBuilder::new(server).build().unwrap_err();
    assert!(matches!(err, RouterError::DuplicatePath { .. }), "{err}");
}

#[test]
fn a_verification_uri_off_the_issuer_is_not_an_error() {
    // RFC 8628 announces verification_uri per response, not in the RFC 8414 document, and a host
    // may serve its device page anywhere. It simply does not get routed here.
    let config = ServerConfig::new("https://as.example", "https://accounts.example/device");
    let server = Arc::new(AuthorizationServer::new(
        config,
        crate::store::MemoryStorage::new(),
    ));
    assert!(RouterBuilder::new(server).build().is_ok());
}
