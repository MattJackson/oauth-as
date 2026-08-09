// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The whole `src/http.rs` wire surface: `AuthorizationService::handle`.
//!
//! # Why this target goes through `handle` rather than at the decoders directly
//!
//! `decode_component`, `percent_decode`, `parse_pairs`, `param`, `bearer_token` and the body
//! reader are all PRIVATE to `src/http.rs`. That is the right visibility for them and this
//! workstream does not get to change it, so the honest way to fuzz them is the way an attacker
//! reaches them: over the wire, through the one public entry point. The cost is attribution (a
//! crash lands in `handle` and has to be read back to a helper) and the benefit is that the input
//! distribution is exactly the real one, including the interactions between a percent-escaped
//! query, a duplicated parameter and a body that disagrees with its `Content-Length`.
//!
//! What this reaches, per request: route resolution, the RFC 9110 s9.3.2 HEAD handling, the
//! method check, the bounded body read, `parse_pairs` and `decode_component` over both the query
//! and the form body, `param`'s first-wins rule, `credentials` (RFC 6749 s2.3.1, including the
//! form-urldecode INSIDE the base64 that section mandates), and `bearer_token`.
//!
//! # The invariants
//!
//! Every one of them is checked by [`oauth_as_fuzz::assert_response_invariants`], so a new target
//! cannot forget one:
//!
//! 1. NO 5xx. `MemoryStorage` is infallible, so the only route to a 500 here is the server failing
//!    to handle bytes it was handed. That is a denial of service at an unauthenticated endpoint.
//! 2. A BODY DECLARED JSON IS JSON.
//! 3. RFC 6749 s5.2 CHARSET on `error` and `error_description`. These are the two members that
//!    can carry request-derived text, and section 5.2 fixes their charset precisely so a value
//!    cannot escape the string it sits in. This is the injection check.
//! 4. AN ERROR BODY CARRIES NO CREDENTIAL: no `access_token`, `refresh_token` or `device_code`
//!    alongside an `error`.
//!
//! And, specific to this target:
//!
//! 5. HEAD RETURNS NO BODY (RFC 9110 s9.3.2), whatever the request said.
//! 6. NO UNROUTED PATH IS SERVED. A path that is not one of the service's own answers 404, so a
//!    percent-escaped or dot-segmented path cannot reach a handler by a spelling the router did
//!    not intend.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use http::header::{HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use oauth_as::http::Body;
use oauth_as_fuzz::{assert_response_invariants, fixture, runtime};

/// Header names worth aiming at, because each one steers a different decoder.
const INTERESTING_HEADERS: &[&str] = &[
    "authorization",
    "content-type",
    "content-length",
    "dpop",
    "accept",
    "x-forwarded-for",
    "cookie",
];

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Request {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let paths = &fixture().paths;
        // Mostly a real routed path, because a request that 404s exercises the router and nothing
        // else. The remaining draws are for invariant 6: near misses, escapes and dot segments.
        let path = match u.int_in_range(0..=5)? {
            0 => String::arbitrary(u)?,
            1 => format!("{}{}", u.choose(paths.as_slice())?, String::arbitrary(u)?),
            _ => u.choose(paths.as_slice())?.clone(),
        };
        let method = u
            .choose(&["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"])?
            .to_string();

        let header_count = u.int_in_range(0..=4)?;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let name = if u.int_in_range(0..=3)? == 0 {
                String::arbitrary(u)?
            } else {
                (*u.choose(INTERESTING_HEADERS)?).to_string()
            };
            headers.push((name, <Vec<u8>>::arbitrary(u)?));
        }
        // The form content type is what makes the body reach `parse_pairs` at all, so it is added
        // most of the time rather than left to chance.
        if u.int_in_range(0..=3)? != 0 {
            headers.push((
                "content-type".to_string(),
                b"application/x-www-form-urlencoded".to_vec(),
            ));
        }

        Ok(Request {
            method,
            path,
            query: String::arbitrary(u)?,
            headers,
            body: <Vec<u8>>::arbitrary(u)?,
        })
    }
}

fuzz_target!(|request: Request| {
    let fixture = fixture();

    let uri = match request.query.is_empty() {
        true => request.path.clone(),
        false => format!("{}?{}", request.path, request.query),
    };
    let mut builder = http::Request::builder()
        .method(request.method.as_str())
        .uri(&uri);
    for (name, value) in &request.headers {
        // A name or value an `http::HeaderMap` will not hold is one no HTTP server would deliver
        // either: `HeaderValue` rejects the control bytes that RFC 9110 s5.5 excludes from a field
        // value. Skipping them is not narrowing the attack surface, it is matching it.
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_bytes(value),
        ) {
            builder = builder.header(name, value);
        }
    }
    let Ok(built) = builder.body(Body::from(request.body.clone())) else {
        // An invalid method token or an unparseable URI. Nothing reaches `handle` in that case on
        // a real server either.
        return;
    };

    let is_head = request.method == "HEAD";
    // THE PATH THE SERVER SEES, taken from the parsed URI rather than from the string the
    // generator built. Those are not the same thing and the difference was a false positive the
    // fuzzer found in under thirty thousand executions: the generator appends arbitrary text to a
    // real path, that text can start with `?`, and `/register?x=1` is the routed path `/register`
    // with a query. An oracle that reads the raw string calls that unrouted and then reports the
    // perfectly correct 405 as a defect. `http::Uri` splits it the way the server does.
    let path = built.uri().path().to_string();
    let routed = fixture.paths.contains(&path)
        // The RFC 7592 s3 client-management route is `{register}/{client_id}`, a prefix match, so
        // "is this path routed" cannot be a set membership test alone.
        || fixture
            .paths
            .iter()
            .any(|p| path.starts_with(&format!("{p}/")));

    let response = runtime().block_on(fixture.service.handle(built));

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response.into_body().into_bytes();

    // 1 through 4.
    assert_response_invariants(status, content_type.as_deref(), &body);

    // 5.
    if is_head {
        assert!(
            body.is_empty(),
            "a HEAD response carried {} body bytes (RFC 9110 s9.3.2)",
            body.len()
        );
    }

    // 6.
    if !routed {
        assert_eq!(
            status, 404,
            "an unrouted path was served: {uri:?} answered {status}"
        );
    }
});
