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

/// [`parse_pairs`] for the tests that are not about [`MAX_FORM_PARAMETERS`]: every input below is
/// a handful of parameters, so the cap can only be an obstacle to reading them.
fn pairs_of(input: &str) -> Vec<Pair<'_>> {
    parse_pairs(input).unwrap_or_else(|_| panic!("this fixture is within the parameter cap"))
}

/// The refusal, or a panic naming what came back instead.
///
/// `Result::expect_err` cannot be used here: it formats the `Ok` value with `Debug`, and
/// `Credentials` deliberately has none, because deriving one would put a live client secret into
/// whatever formatted it. That is the point of the omission, so the tests work around it rather
/// than reintroducing the derive to make an assertion tidier.
fn refusal(result: Result<Credentials, ErrorResponse>) -> ErrorResponse {
    match result {
        Err(e) => e,
        Ok(creds) => panic!(
            "expected a refusal, got credentials for client_id {:?}",
            creds.client_id
        ),
    }
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
    let pairs = pairs_of("a=1&b=&c");
    assert_eq!(param(&pairs, "a"), Some("1"));
    // RFC 6749 distinguishes an empty value from an absent parameter (an empty `client_id` is a
    // present-and-invalid client id, not a missing one), so both must survive parsing.
    assert_eq!(param(&pairs, "b"), Some(""));
    assert_eq!(param(&pairs, "c"), Some(""));
    assert_eq!(param(&pairs, "d"), None);
}

/// The exact boundary of [`MAX_FORM_PARAMETERS`], because an off-by-one here is either a hole in
/// the cap or a refusal of a request a client is entitled to send.
#[test]
fn the_parameter_cap_is_exact_at_its_boundary() {
    let at_the_cap = vec!["a=1"; MAX_FORM_PARAMETERS].join("&");
    assert_eq!(
        parse_pairs(&at_the_cap).map(|p| p.len()).ok(),
        Some(MAX_FORM_PARAMETERS),
        "a request with exactly MAX_FORM_PARAMETERS parameters is within the cap"
    );
    let one_over = vec!["a=1"; MAX_FORM_PARAMETERS + 1].join("&");
    assert!(
        parse_pairs(&one_over).is_err(),
        "one parameter past the cap is refused"
    );
}

#[test]
fn a_repeated_parameter_keeps_the_first() {
    // RFC 6749 s3.1: a parameter MUST NOT be sent more than once. First-wins denies a smuggled
    // duplicate the ability to override what earlier layers parsed.
    let pairs = pairs_of("grant_type=authorization_code&grant_type=client_credentials");
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
    let form = pairs_of("client_id=client&client_secret=secret");
    let err = refusal(credentials(&headers_with(&format!("Basic {raw}")), &form));
    assert_eq!(err.error, ErrorCode::InvalidRequest);

    // Even a bare client_id alongside Basic is two methods' worth of identity claims.
    let form = pairs_of("client_id=client");
    let err = refusal(credentials(&headers_with(&format!("Basic {raw}")), &form));
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

/// RFC 9126 s2.1 makes this the ONE endpoint where a form `client_id` alongside Basic is not two
/// authentication methods: the pushed body carries the RFC 6749 s4.1.1 authorization request, in
/// which `client_id` is REQUIRED, and the client also authenticates as it does at the token
/// endpoint. Applying the token endpoint's rule here would make PAR unusable for every
/// confidential client that authenticates with a header.
#[cfg(feature = "par")]
#[test]
fn a_pushed_request_may_carry_client_id_alongside_basic() {
    let raw = BASE64_STANDARD.encode("client:secret");
    let headers = headers_with(&format!("Basic {raw}"));
    let form = pairs_of("client_id=client&response_type=code");

    // The token endpoint's rule is unchanged.
    assert_eq!(
        refusal(credentials(&headers, &form)).error,
        ErrorCode::InvalidRequest
    );

    // The PAR endpoint's is not, and the identity comes from the HEADER, which is the
    // authenticated one. A mismatched body `client_id` is then caught by RFC 9126 s2.1's own
    // check inside the server, not by pretending the parameter was a credential.
    let creds = pushed_request_credentials(&headers, &form).expect("RFC 9126 s2.1 allows this");
    assert_eq!(creds.client_id, "client");
    assert_eq!(creds.client_secret.as_deref(), Some("secret"));

    // A real second CREDENTIAL is still two methods.
    let both = pairs_of("client_id=client&client_secret=secret");
    assert_eq!(
        refusal(pushed_request_credentials(&headers, &both)).error,
        ErrorCode::InvalidRequest
    );
}

#[test]
fn a_public_client_may_present_a_bare_client_id() {
    // RFC 6749 s3.2.1: a client that is not authenticating still identifies itself.
    let creds = credentials(&HeaderMap::new(), &pairs_of("client_id=public")).expect("ok");
    assert_eq!(creds.client_id, "public");
    assert_eq!(creds.client_secret, None);
}

#[test]
fn no_credentials_at_all_is_invalid_client() {
    // RFC 6749 s5.2 lists "no client authentication included" under invalid_client by name.
    let err = refusal(credentials(&HeaderMap::new(), &pairs_of("grant_type=x")));
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
    assert!(matches!(err, ServiceError::EndpointOutsideIssuer { .. }));
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
    // The `+ 3` that steps past `://` is exactly three. A `* 3` would land ten bytes further into
    // the issuer and, with more than one path segment, cut the origin at a LATER slash: this input
    // has its authority end at index 13 but `5 * 3 == 15` sits past it, inside `/tenant`.
    assert_eq!(issuer_origin("https://as.ex/tenant/x"), "https://as.ex");
}

/// The origin is derived by SEARCHING for the path separator rather than by subtracting a trimmed
/// length from an untrimmed string, and this is the input that tells the two apart: each trailing
/// slash the trim removes shifts a subtracted index one byte further into the issuer, and with a
/// two-byte character in the path the index lands inside it, where slicing a `str` panics.
///
/// NOT reachable through [`ServiceBuilder::build`] today, because `from_config` trims the issuer
/// before this ever sees it, and a trimmed issuer has no trailing slash to shift anything. It is
/// asserted anyway because "safe as long as one caller keeps trimming first" is a property no
/// reader of this function can see, and the panic-free form costs nothing.
#[test]
fn the_issuer_origin_does_not_slice_inside_a_character() {
    assert_eq!(
        issuer_origin("https://as.example/\u{e9}//"),
        "https://as.example"
    );
    assert_eq!(
        issuer_origin("https://as.example:8443/\u{1f600}/x///"),
        "https://as.example:8443"
    );
    // A trailing slash with no path at all, which is the case that already worked.
    assert_eq!(issuer_origin("https://as.example//"), "https://as.example");
}

/// RFC 9110 s5.6.4: a quoted-string escapes exactly two characters, `"` and `\`, each by prefixing
/// one backslash, and leaves everything else alone. A value with neither is BORROWED, so the
/// ordinary 401 whose `WWW-Authenticate` names a well-formed issuer URL costs no allocation.
#[test]
fn escape_quoted_string_escapes_only_quote_and_backslash_and_borrows_otherwise() {
    // Nothing to escape: borrowed, byte for byte, not rebuilt or replaced by a constant.
    assert!(matches!(
        escape_quoted_string("https://as.example"),
        Cow::Borrowed("https://as.example")
    ));
    assert_eq!(escape_quoted_string("plain"), "plain");
    // A quote and a backslash each gain exactly one backslash, and ONLY those two do.
    assert_eq!(escape_quoted_string("a\"b"), "a\\\"b");
    assert_eq!(escape_quoted_string("a\\b"), "a\\\\b");
    assert_eq!(escape_quoted_string("x\"y\\z"), "x\\\"y\\\\z");
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
    let err = ServiceBuilder::new(server).build().unwrap_err();
    assert!(matches!(err, ServiceError::DuplicatePath { .. }), "{err}");
}

/// RFC 8414 s2 with RFC 9068 s4: a server that signs must publish keys somewhere a resource
/// server can reach, and an advertised `jwks_uri` this router cannot serve is the same lie as any
/// other unroutable endpoint. Off-issuer is refused rather than silently unrouted because these
/// bytes are produced by this server and nothing else can produce them.
///
/// Gated on `jwt-p256` and NOT on `jwt`, because the fixture needs a signing KEY and since the
/// ES256 seam `jwt` is the trait surface with no backend behind it: `EcdsaP256Key` only exists
/// with the built-in backend compiled in. Under plain `jwt` this file did not compile at all,
/// which is why `--features http,client-assertion` (client-assertion implies jwt, not jwt-p256)
/// was a build nobody could run.
#[cfg(feature = "jwt-p256")]
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
    let err = ServiceBuilder::new(server).build().unwrap_err();
    assert!(
        matches!(err, ServiceError::EndpointOutsideIssuer { endpoint, .. } if endpoint == "jwks_uri"),
        "{err}"
    );
}

/// The key set shares the collision check every other route gets: a `jwks_uri` that lands on the
/// token endpoint would shadow one of the two, and which one is an implementation detail no host
/// should have to know.
///
/// `jwt-p256` for the same reason as the test above: the fixture needs a real signing key.
#[cfg(feature = "jwt-p256")]
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
    let err = ServiceBuilder::new(server).build().unwrap_err();
    assert!(matches!(err, ServiceError::DuplicatePath { .. }), "{err}");
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
    assert!(ServiceBuilder::new(server).build().is_ok());
}

// ---------------------------------------------------------------------------------------------
// Closing holes a `--features http,jwt` mutation run found. Each test below exists because the
// code it covers could be changed and nothing failed.
// ---------------------------------------------------------------------------------------------

/// Exhaustive over all 256 byte values, because a hex nibble decoder is exactly the kind of small
/// arithmetic where a wrong constant is invisible in the cases anyone thinks to write. The
/// existing decoder tests used `%2D`, `%20` and `%3A`: digits and uppercase only, so the entire
/// lowercase arm and every arithmetic constant in it went unpinned.
///
/// RFC 3986 s2.1 makes the two hex digits case-insensitive, so lowercase is not an edge case, it
/// is what most clients emit.
#[test]
fn hex_value_is_exhaustively_correct_over_every_byte() {
    const DIGITS: &[u8] = b"0123456789abcdef";
    for b in 0u8..=255 {
        // The reference answer, written independently of the implementation: the position of this
        // byte in the hex alphabet, case-folded, or nothing at all.
        let expected = DIGITS
            .iter()
            .position(|d| *d == b.to_ascii_lowercase())
            .map(|i| i as u8);
        assert_eq!(hex_value(b), expected, "byte {b:#04x}");
    }
}

/// The same decoder from the outside: a lowercase escape has to produce the byte it names.
#[test]
fn lowercase_percent_escapes_decode_to_the_byte_they_name() {
    assert_eq!(decode_component("%2f"), "/");
    assert_eq!(decode_component("%6a"), "j");
    assert_eq!(decode_component("%7e"), "~");
    // Mixed case in one escape, which RFC 3986 s2.1 also permits.
    assert_eq!(decode_component("%2F"), "/");
    assert_eq!(decode_component("%6A"), "j");
    assert_eq!(
        decode_component("urn%3aietf%3aparams%3aoauth%3agrant-type%3adevice_code"),
        "urn:ietf:params:oauth:grant-type:device_code"
    );
}

/// A `%` with exactly ONE byte after it. The escape guard has to demand both nibbles are real
/// INDICES, not merely that one more byte exists, or the decoder reads past the end of an
/// attacker-supplied string. The existing tests covered `%` at the very end and `%zz`, both of
/// which miss this position by one.
#[test]
fn a_truncated_escape_at_the_end_is_passed_through_rather_than_read_past() {
    assert_eq!(decode_component("%2"), "%2");
    assert_eq!(decode_component("%"), "%");
    assert_eq!(decode_component("ab%f"), "ab%f");
    assert_eq!(decode_component("a%2b%c"), "a+%c");
}

/// RFC 8707 s2 permits `resource` to be repeated, and every occurrence counts: dropping one would
/// issue a token for less than the client asked for, silently. This is the one parameter the
/// first-wins rule in [`param`] must not be applied to.
#[test]
fn every_resource_indicator_survives_including_repeats() {
    let pairs =
        pairs_of("resource=https%3A%2F%2Fa.example&client_id=c&resource=https%3A%2F%2Fb.example");
    assert_eq!(
        resource_indicators(&pairs),
        vec![
            "https://a.example".to_string(),
            "https://b.example".to_string()
        ]
    );
    assert!(resource_indicators(&pairs_of("client_id=c")).is_empty());
}

/// A missing-parameter refusal must BORROW its description, not build one.
///
/// The rule is the one `tests/allocation.rs` states on
/// `refused_token_request_allocation_bound`: a refusal is work an ATTACKER sets the rate of, so a
/// refusal that allocates is an allocation an unauthenticated caller can ask for as fast as it can
/// open sockets. Roughly fifty of this crate's description sites pass a literal;
/// [`required`] was the one that formatted, although `name` is always a `&'static str` from a
/// finite set. `error_description` is a `Cow<'static, str>`, so `Cow::Borrowed` IS the assertion
/// that nothing was copied onto the heap: this needs no allocator instrumentation to be exact.
///
/// The set of names is read out of this module's own SOURCE rather than listed here, so a new
/// `required(..)` call site whose name was never added to the borrowing match fails this test
/// instead of silently reintroducing the allocation.
#[test]
fn a_missing_required_parameter_borrows_its_description() {
    let source = include_str!("../http.rs");
    let mut names: Vec<&str> = Vec::new();
    for (at, _) in source.match_indices("required(") {
        let from = at + "required(".len();
        let rest = &source[from..(from + 128).min(source.len())];
        // `required(&form, "code")` and `required(form, "subject_token")`: the name is the
        // literal between the first pair of quotes after the call.
        let Some(open) = rest.find('"') else { continue };
        let Some(close) = rest[open + 1..].find('"') else {
            continue;
        };
        let name = &rest[open + 1..open + 1 + close];
        // Only names in the same statement, never a quote from some later line.
        if rest[..open].contains(';') || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            continue;
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    assert!(
        names.len() >= 6,
        "the source scan found only {names:?}; it is meant to find every required() call site"
    );

    for name in names {
        let err = required(&[], name).expect_err("no parameters means every one of them is absent");
        match err.error_description {
            Some(Cow::Borrowed(_)) => {}
            other => panic!(
                "required({name:?}) built its description on the heap ({other:?}): add the \
                 parameter to the borrowing match in http.rs"
            ),
        }
    }
}

/// A supplied `scope` has to be READ, and a malformed one has to be `invalid_scope` rather than
/// silently absent. Treating an unparseable scope as "none requested" would hand the client the
/// registered DEFAULT scopes instead of refusing, which is a quiet upgrade of what it asked for.
#[test]
fn a_supplied_scope_is_parsed_and_a_malformed_one_is_invalid_scope() {
    assert!(optional_scope(&pairs_of("grant_type=x"))
        .expect("absent is not an error")
        .is_none());

    let parsed = optional_scope(&pairs_of("scope=read+write"))
        .expect("a well-formed scope")
        .expect("present");
    assert_eq!(parsed.to_string(), "read write");

    // RFC 6749 s3.3 scope tokens exclude the double quote and the backslash.
    let err = optional_scope(&pairs_of("scope=%22read%22")).expect_err("not a scope list");
    assert_eq!(err.error, ErrorCode::InvalidScope);
}

/// Every [`ServiceError`] is a host configuration mistake, and the message is the only thing that
/// tells the host WHICH one. An empty message turns a five-second fix into a hunt.
#[test]
fn router_errors_name_the_endpoint_or_the_path_at_fault() {
    let text = ServiceError::EndpointOutsideIssuer {
        endpoint: "token_endpoint",
        url: "https://other.example/token".to_string(),
    }
    .to_string();
    assert!(text.contains("token_endpoint"), "{text}");
    assert!(text.contains("https://other.example/token"), "{text}");

    let text = ServiceError::DuplicatePath {
        path: "/same".to_string(),
    }
    .to_string();
    assert!(text.contains("/same"), "{text}");

    let text = ServiceError::MetadataNotSerializable {
        detail: "serializer said no".to_string(),
    }
    .to_string();
    assert!(text.contains("serializer said no"), "{text}");

    #[cfg(feature = "jwt")]
    {
        let text = ServiceError::JwksNotSerializable {
            detail: "serializer said no".to_string(),
        }
        .to_string();
        assert!(text.contains("serializer said no"), "{text}");
    }
}

/// The message-only page is what every outcome and every refusal on the device verification
/// endpoint is rendered through, so a page that does not contain its message is a user staring at
/// a blank screen after approving access to their account.
#[test]
fn a_message_page_carries_its_message_and_escapes_it() {
    let html = verification_message("Approved. You can return to your device.");
    assert!(html.starts_with("<!DOCTYPE html"), "{html}");
    assert!(
        html.contains("Approved. You can return to your device."),
        "{html}"
    );
    assert!(html.ends_with("</body></html>"), "{html}");

    let html = verification_message("<script>alert(1)</script>");
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");
}

// ---------------------------------------------------------------------------------------------
// The route matcher and the body reader, which replaced the framework's. Both are new surface,
// so both are pinned here rather than only at the socket in tests/http_surface.rs.
// ---------------------------------------------------------------------------------------------

/// A route table with the one dynamic route and a static route that lives UNDER it, which is the
/// case a prefix matcher gets wrong.
fn routes_with_management() -> Routes {
    Routes {
        well_known: "/.well-known/oauth-authorization-server".to_string(),
        authorize: "/authorize".to_string(),
        token: "/token".to_string(),
        device: "/device_authorization".to_string(),
        introspect: Some("/introspect".to_string()),
        revoke: None,
        verification: Some("/device".to_string()),
        register: Some("/register".to_string()),
        manage: Some("/register/".to_string()),
        #[cfg(feature = "par")]
        par: None,
        #[cfg(feature = "jwt")]
        jwks: None,
    }
}

#[test]
fn every_configured_path_resolves_and_nothing_else_does() {
    let routes = routes_with_management();
    assert!(matches!(
        routes.resolve("/.well-known/oauth-authorization-server"),
        Some(Route::Metadata)
    ));
    assert!(matches!(routes.resolve("/token"), Some(Route::Token)));
    assert!(matches!(
        routes.resolve("/introspect"),
        Some(Route::Introspect)
    ));
    // Not configured on this table, so it is a 404 rather than a route that happens to exist.
    assert!(routes.resolve("/revoke").is_none());
    // A prefix of a route is not the route, and neither is a suffix.
    assert!(routes.resolve("/tok").is_none());
    assert!(routes.resolve("/token/").is_none());
    assert!(routes.resolve("/xtoken").is_none());
}

/// RFC 7592 s3: the management URL this server mints is `{registration_endpoint}/{client_id}`,
/// ONE segment. A deeper path is a different resource, and an empty one is the registration
/// endpoint with a stray slash, not a client with an empty id.
#[test]
fn the_management_route_captures_exactly_one_segment() {
    let routes = routes_with_management();
    assert!(matches!(routes.resolve("/register/abc"), Some(Route::Manage(id)) if id == "abc"));
    assert!(routes.resolve("/register/abc/extra").is_none());
    assert!(routes.resolve("/register/").is_none());
    // The registration endpoint itself is still the registration endpoint.
    assert!(matches!(routes.resolve("/register"), Some(Route::Register)));
}

/// A STATIC route underneath the dynamic one must win, exactly as a trie-based router would have
/// it. Without the ordering, a host whose configuration nests an endpoint under the registration
/// endpoint would find it shadowed by a client id that can never exist, and the build-time
/// duplicate check cannot see it because the two strings differ.
#[test]
fn a_static_route_beats_the_dynamic_one() {
    let mut routes = routes_with_management();
    routes.token = "/register/token".to_string();
    assert!(matches!(
        routes.resolve("/register/token"),
        Some(Route::Token)
    ));
    assert!(matches!(routes.resolve("/register/other"), Some(Route::Manage(id)) if id == "other"));
}

/// RFC 3986 s3.3 puts `+` in `sub-delims`, so it is a literal in a path; only
/// `application/x-www-form-urlencoded` gives it the "space" meaning. Decoding it as a space would
/// rewrite the `registration_client_uri` this server itself minted for a client whose id has one.
#[test]
fn a_path_segment_decodes_percent_escapes_but_not_plus() {
    assert_eq!(decode_path_segment("a+b"), "a+b");
    assert_eq!(decode_component("a+b"), "a b");
    assert_eq!(decode_path_segment("a%2Bb"), "a+b");
    assert_eq!(decode_path_segment("client%20one"), "client one");
    // Still borrows when there is nothing to unescape.
    assert!(matches!(
        decode_path_segment("plain-id"),
        Cow::Borrowed("plain-id")
    ));
    assert!(matches!(decode_path_segment("a+b"), Cow::Borrowed("a+b")));
}

/// The ROUTE TABLE is normalised into wire form, which is what lets an issuer whose path a client
/// must escape be reached at all WITHOUT the matcher ever touching the wire path.
///
/// Both legal spellings of such an issuer have to land on the same route, because a client sends
/// the same bytes for both: the raw one (not a legal URI, but this crate accepts it) and the RFC
/// 3986 section 3.3 percent-encoded one. The escaped spelling of an ORDINARY route must NOT land
/// on it, which is the property that keeps this service's idea of the path the same as that of
/// every proxy in front of it.
#[test]
fn the_route_table_is_normalised_to_what_a_client_sends() {
    for issuer in ["https://as.example/\u{e9}", "https://as.example/%C3%A9"] {
        let mut config = ServerConfig::new(issuer, "https://as.example/device");
        config.registration = None;
        let meta = crate::metadata::AuthorizationServerMetadata::from_config(&config);
        let iss = meta.issuer.clone();
        let token = endpoint_path(&iss, "token_endpoint", &meta.token_endpoint).expect("under");
        assert_eq!(
            token, "/%C3%A9/token",
            "{issuer}: the table must hold the bytes a client puts on the wire"
        );
    }
    // And nothing else is rewritten: an escaped spelling of an ASCII route is a different string.
    assert_eq!(encode_route_path("/token"), "/token");
    assert_ne!(encode_route_path("/token"), "/%74oken");
    // An issuer that already carries escapes passes through once, not twice.
    assert_eq!(encode_route_path("/tenant%20a/token"), "/tenant%20a/token");
    // BOTH nibbles must be hex for a `%` to be an escape. `%2g` is a literal `%` followed by two
    // pchars, so it is copied verbatim, letters and all -- treating it as an escape (either nibble
    // hex) would uppercase the `g` and rewrite the configured path.
    assert_eq!(encode_route_path("/%2g"), "/%2g");
    assert_eq!(encode_route_path("/%g2"), "/%g2");
}

/// The WIRE half of the same normalisation, [`uppercase_escapes`], which nothing else pins. It
/// BORROWS unless the path carries a lowercase escape, uppercases the hex digits of a real escape,
/// and copies everything else -- including a `%` that is not an escape -- byte for byte.
#[test]
fn uppercase_escapes_borrows_unless_a_lowercase_escape_is_present() {
    // No `%` at all: borrowed, even when two hex-looking letters follow another byte (the `needs`
    // scan must key on `%`, and only on the pattern that starts with one).
    assert!(matches!(uppercase_escapes("/ab"), Cow::Borrowed("/ab")));
    assert!(matches!(
        uppercase_escapes("/token"),
        Cow::Borrowed("/token")
    ));
    // An UPPERCASE escape is already canonical: there is nothing to change, so it stays borrowed
    // rather than being copied because a `%` was seen.
    assert!(matches!(uppercase_escapes("/%20"), Cow::Borrowed("/%20")));
    // A lowercase escape is the one case that allocates.
    assert!(matches!(uppercase_escapes("/%2f"), Cow::Owned(_)));
}

#[test]
fn uppercase_escapes_uppercases_real_escapes_and_copies_everything_else_verbatim() {
    // A real lowercase escape becomes uppercase.
    assert_eq!(uppercase_escapes("/%2fpath"), "/%2Fpath");
    // A `%` where the second nibble is not hex is NOT an escape: copied as-is, letters unchanged.
    assert_eq!(uppercase_escapes("/%2f%zz"), "/%2F%zz");
    // Nor is one where only the FIRST nibble is hex.
    assert_eq!(uppercase_escapes("/%2f%az"), "/%2F%az");
    // A stray `%` at the very end is passed through, and the run loop must still TERMINATE and copy
    // the whole preceding run: a decrement-that-never-advances hangs here.
    assert_eq!(uppercase_escapes("/%2f%"), "/%2F%");
    // Runs between escapes are copied whole and byte for byte.
    assert_eq!(uppercase_escapes("/a%2fb%2fc"), "/a%2Fb%2Fc");
}

/// RFC 9110 s15.5.6 makes `Allow` mandatory on a 405, and HEAD is listed wherever GET is because
/// it is actually served (s9.3.2 defines it as GET with the body dropped).
#[test]
fn the_allow_header_lists_head_wherever_get_is_served() {
    assert_eq!(allowed(&Route::Metadata), "GET, HEAD");
    assert_eq!(allowed(&Route::Token), "POST");
    assert_eq!(allowed(&Route::Verification), "GET, HEAD, POST");
    assert_eq!(allowed(&Route::Manage("c")), "GET, HEAD, PUT, DELETE");
}

/// A body that declares nothing and just keeps sending: the size hint cannot see it, so only the
/// running total can. This is the shape `Content-Length` does not cover and the one an attacker
/// picks.
struct Dribble {
    remaining: usize,
    chunk: usize,
}

impl http_body::Body for Dribble {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let n = self.chunk.min(self.remaining);
        self.remaining -= n;
        std::task::Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(vec![b'x'; n])))))
    }

    // Deliberately the default: unknown length, which is what a chunked body reports.
}

#[tokio::test]
async fn a_body_within_the_cap_is_read_whole() {
    let body = Dribble {
        remaining: 100,
        chunk: 7,
    };
    let bytes = match collect_body(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => panic!("a 100 byte body is inside a 64 KiB cap"),
    };
    assert_eq!(bytes.len(), 100);
    assert!(bytes.iter().all(|b| *b == b'x'));
}

/// The security property [`MAX_BODY_BYTES`] exists for: these endpoints buffer the whole body
/// before parsing and are reachable before the client is authenticated, so an unbounded body is a
/// memory exhaustion primitive available to anyone who can open a socket.
#[tokio::test]
async fn a_body_over_the_cap_is_refused_rather_than_buffered() {
    let body = Dribble {
        remaining: 5_000,
        chunk: 64,
    };
    assert!(matches!(
        collect_body(body, 1_000).await,
        Err(BodyError::TooLarge)
    ));
    // Exactly at the cap is inside it; one byte more is not.
    assert!(collect_body(
        Dribble {
            remaining: 1_000,
            chunk: 64
        },
        1_000
    )
    .await
    .is_ok());
    assert!(collect_body(
        Dribble {
            remaining: 1_001,
            chunk: 64
        },
        1_000
    )
    .await
    .is_err());
}

/// The other half of the cap: a DECLARED length over the limit is refused before a single byte is
/// buffered, so a hostile `Content-Length: 4000000000` costs nothing at all.
#[tokio::test]
async fn a_declared_length_over_the_cap_is_refused_before_reading() {
    // `Body` reports an exact size hint, which is the same thing a `Content-Length` gives.
    let huge = Body::from(Bytes::from(vec![b'x'; 2_000]));
    assert!(matches!(
        collect_body(huge, 1_000).await,
        Err(BodyError::TooLarge)
    ));
}

/// The response body has to report an EXACT length, or a server emits chunked transfer encoding
/// for a response it knows the size of, and `is_end_stream` has to be true for an empty body so
/// nothing polls for a frame that will never come.
#[test]
fn the_response_body_reports_an_exact_length() {
    use http_body::Body as _;
    let empty = Body::empty();
    assert!(empty.is_end_stream());
    assert_eq!(empty.size_hint().exact(), Some(0));

    let full = Body::from("hello".to_string());
    assert!(!full.is_end_stream());
    assert_eq!(full.size_hint().exact(), Some(5));
    assert_eq!(full.into_bytes(), Bytes::from_static(b"hello"));

    // An empty `Bytes` and no body at all are the same response on the wire.
    assert!(Body::from(Bytes::new()).is_end_stream());
}
