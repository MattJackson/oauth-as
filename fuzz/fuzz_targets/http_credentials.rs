// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Client authentication over the wire: `decode_basic` and `credentials`, RFC 6749 section 2.3.1.
//!
//! Section 2.3.1 is a small clause with an unusual rule in it. The client id and secret are
//! `application/x-www-form-urlencoded` encoded FIRST and base64 encoded SECOND, so a conforming
//! server percent-decodes INSIDE the base64. That is a decode of attacker-controlled bytes into
//! attacker-controlled bytes, feeding the comparison that decides who a request is from, and it
//! is the single highest-value thing in `src/http.rs` to fuzz.
//!
//! A separate target from `http_request` on purpose: a crash reachable only through a
//! `Authorization: Basic` header is much easier to read when the only thing varying is that
//! header and the form body next to it.
//!
//! # The invariants
//!
//! Beyond the four in [`oauth_as_fuzz::assert_response_invariants`]:
//!
//! 1. NO GENERATED CREDENTIAL AUTHENTICATES. The fixture's secret is a 52-character random
//!    string, so a fuzzer that produces a 200 from the token endpoint has found a way to
//!    authenticate WITHOUT the secret. This is the assertion that makes this target worth
//!    running: it catches a decoder that, say, compares a prefix, or that reads an empty
//!    presented secret as a match, and it catches them as a wrong ANSWER rather than as a crash.
//! 2. A 401 CARRIES `WWW-Authenticate`. RFC 9110 s11.6.1 makes the header mandatory on a 401, and
//!    RFC 6749 s5.2 requires it specifically when the request used an authentication scheme. A
//!    401 without it is a response no conforming client can act on.
//! 3. NO CREDENTIAL IS REFLECTED. Nothing the request presented as a secret appears anywhere in
//!    the response body. An error path that echoes what it was sent turns a mistyped credential
//!    in a proxy log into a disclosed one.

#![no_main]

use arbitrary::Arbitrary;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use base64::Engine as _;
use http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use libfuzzer_sys::fuzz_target;
use oauth_as::http::Body;
use oauth_as_fuzz::{
    assert_response_invariants, fixture, runtime, CONFIDENTIAL_ID, CONFIDENTIAL_SECRET,
};

/// How the `Authorization` header is spelled.
#[derive(Arbitrary, Debug)]
enum Header {
    /// No header at all: the credential, if any, is in the form body.
    Absent,
    /// `Basic <base64(userid ":" password)>`, with the RFC 6749 s2.3.1 form encoding applied to
    /// each half as the section requires.
    Basic { user: String, password: String },
    /// The same, with the halves NOT form-encoded. A client that gets section 2.3.1 wrong sends
    /// this, and what the server does with it is exactly the question.
    BasicUnencoded { user: String, password: String },
    /// `Basic <arbitrary bytes>`: not necessarily base64, not necessarily containing a colon.
    BasicRaw(Vec<u8>),
    /// Base64 in a different alphabet or padding: `STANDARD_NO_PAD` and `URL_SAFE` both decode
    /// strings that the RFC 4648 s4 alphabet does not, and a decoder that accepts either is
    /// accepting a second spelling of the same credential.
    BasicAlternateAlphabet { which: u8, user: String },
    /// Another scheme entirely.
    OtherScheme { scheme: String, token: String },
    /// A completely arbitrary header value.
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    header: Header,
    /// The form body: `client_id` and `client_secret` may be presented here instead
    /// (`client_secret_post`), and section 2.3.1 forbids presenting both ways at once.
    body_client_id: Option<String>,
    body_client_secret: Option<String>,
    grant_type: Option<String>,
    /// Extra body text, appended raw, so a `&` or a `%` can appear anywhere.
    body_tail: String,
}

/// RFC 6749 appendix B: the `application/x-www-form-urlencoded` encoding section 2.3.1 requires
/// before the base64. Written out rather than pulled from a URL crate so that what the fixture
/// encodes is exactly what the RFC says and not what some crate's default happens to be.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn header_value(header: &Header) -> Option<Vec<u8>> {
    Some(match header {
        Header::Absent => return None,
        Header::Basic { user, password } => {
            let joined = format!("{}:{}", form_encode(user), form_encode(password));
            format!("Basic {}", STANDARD.encode(joined)).into_bytes()
        }
        Header::BasicUnencoded { user, password } => {
            let joined = format!("{user}:{password}");
            format!("Basic {}", STANDARD.encode(joined)).into_bytes()
        }
        Header::BasicRaw(bytes) => {
            let mut value = b"Basic ".to_vec();
            value.extend_from_slice(bytes);
            value
        }
        Header::BasicAlternateAlphabet { which, user } => {
            let joined = format!("{}:{}", form_encode(user), form_encode(CONFIDENTIAL_SECRET));
            let encoded = match which % 2 {
                0 => STANDARD_NO_PAD.encode(joined),
                _ => URL_SAFE.encode(joined),
            };
            format!("Basic {encoded}").into_bytes()
        }
        Header::OtherScheme { scheme, token } => format!("{scheme} {token}").into_bytes(),
        Header::Raw(bytes) => bytes.clone(),
    })
}

/// Every string the input presented as a secret, so invariant 3 can look for each of them.
fn presented_secrets(input: &Input) -> Vec<String> {
    let mut secrets = Vec::new();
    match &input.header {
        Header::Basic { password, .. } | Header::BasicUnencoded { password, .. } => {
            secrets.push(password.clone())
        }
        Header::BasicAlternateAlphabet { .. } => secrets.push(CONFIDENTIAL_SECRET.to_string()),
        _ => {}
    }
    if let Some(secret) = &input.body_client_secret {
        secrets.push(secret.clone());
    }
    // Only secrets long enough to be distinctive. A one-character "secret" would collide with
    // ordinary response text and the invariant would be about nothing.
    secrets.retain(|s| s.len() >= 8);
    secrets
}

fuzz_target!(|input: Input| {
    let fixture = fixture();

    let mut body = String::new();
    if let Some(grant_type) = &input.grant_type {
        body.push_str(&format!("grant_type={}", form_encode(grant_type)));
    } else {
        body.push_str("grant_type=client_credentials");
    }
    if let Some(id) = &input.body_client_id {
        body.push_str(&format!("&client_id={}", form_encode(id)));
    }
    if let Some(secret) = &input.body_client_secret {
        body.push_str(&format!("&client_secret={}", form_encode(secret)));
    }
    // Appended RAW: this is what puts a bare `%`, a truncated escape and a stray `&` into the
    // form parser, which is the byte-level half of what this target is for.
    body.push('&');
    body.push_str(&input.body_tail);

    let mut builder = http::Request::builder()
        .method("POST")
        .uri("/token")
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    if let Some(value) = header_value(&input.header) {
        match HeaderValue::from_bytes(&value) {
            Ok(value) => builder = builder.header(AUTHORIZATION, value),
            // Not a field value any HTTP server would deliver. See `http_request` for why
            // skipping these is matching the attack surface rather than narrowing it.
            Err(_) => return,
        }
    }
    let Ok(request) = builder.body(Body::from(body.clone())) else {
        return;
    };

    let response = runtime().block_on(fixture.service.handle(request));

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let challenge = response.headers().get(WWW_AUTHENTICATE).is_some();
    let bytes = response.into_body().into_bytes();

    assert_response_invariants(status, content_type.as_deref(), &bytes);

    // 2.
    if status == 401 {
        assert!(
            challenge,
            "a 401 was returned without WWW-Authenticate (RFC 9110 s11.6.1, RFC 6749 s5.2)"
        );
    }

    // 1. A success is only legitimate if the registered secret was actually PRESENT in the
    // request, in one form or another. The fixture secret is 52 characters of fixed text that a
    // fuzzer cannot reach by search, and the generator only ever plants it deliberately (the
    // `BasicAlternateAlphabet` arm), so this reduces to: no input that does not contain the
    // secret may authenticate. That is the bypass check, and it is a wrong ANSWER rather than a
    // crash, which is what a panic-only target would have missed.
    if status < 400 {
        let header_text = header_value(&input.header)
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default();
        let secret_present = body.contains(CONFIDENTIAL_SECRET)
            || header_text.contains(CONFIDENTIAL_SECRET)
            || matches!(input.header, Header::BasicAlternateAlphabet { .. });
        assert!(
            secret_present,
            "the token endpoint answered {status} for client {CONFIDENTIAL_ID} without the \
             registered secret being presented at all: header={:?} body={body:?}",
            input.header
        );
    }

    // 3.
    let text = String::from_utf8_lossy(&bytes);
    for secret in presented_secrets(&input) {
        assert!(
            !text.contains(&secret),
            "a presented credential was reflected in the response body: {text:?}"
        );
    }
});
