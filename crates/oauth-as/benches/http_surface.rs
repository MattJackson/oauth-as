// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The HTTP surface, end to end through [`oauth_as::AuthorizationService::handle`].
//!
//! Every other target in this suite calls [`oauth_as::AuthorizationServer`] directly, which
//! measures the protocol and measures AROUND the wire. This one measures THROUGH it: route
//! matching, body reading, form decoding, the RFC-mandated response headers and JSON
//! serialization are all inside the clock. The difference between a row here and its counterpart
//! in `benches/token.rs` is exactly what the `http` feature costs on top of the library call it
//! wraps, which is the number a host deciding whether to write its own wire layer actually needs.
//!
//! There is still NO SOCKET, no TLS, no HTTP framing and no runtime scheduling here: `handle` takes
//! a `http::Request` and returns a `http::Response`, and this file hands it one directly. So these
//! rows are a lower bound on what a real deployment serves, and the gap between them and a real
//! request is the host's server, not this crate.

#[path = "harness/mod.rs"]
mod harness;

#[cfg(feature = "http")]
use std::sync::Arc;

#[cfg(feature = "http")]
use oauth_as::http::Body;
#[cfg(feature = "http")]
use oauth_as::{
    ApprovalDecision, AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage,
    ScopeSet, ServerConfig, ServiceBuilder,
};

/// Without the `http` feature there is no wire surface to measure, and a bench target still has to
/// link. Saying so is better than an empty table a reader would take for a zero.
#[cfg(not(feature = "http"))]
fn main() {
    println!("benches/http_surface.rs measures the `http` feature, which is off in this build.");
    println!("Run: cargo bench -p oauth-as --features http --bench http_surface");
}

#[cfg(feature = "http")]
const SECRET: &str = "a-high-entropy-registered-client-secret";
#[cfg(feature = "http")]
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

#[cfg(feature = "http")]
fn form(uri: &str, body: String) -> http::Request<Body> {
    http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("a well-formed request")
}

#[cfg(feature = "http")]
fn get(uri: &str) -> http::Request<Body> {
    http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("a well-formed request")
}

#[cfg(feature = "http")]
fn main() {
    harness::print_environment();
    let mut b = harness::Bench::from_args("HTTP surface (AuthorizationService::handle)");
    let rt = harness::runtime();

    let server = rt.block_on(async {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(Client {
            client_id: ClientId::new("confidential-app"),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![
                GrantType::ClientCredentials,
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
            ],
            redirect_uris: vec!["https://app.example/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read write").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
        Arc::new(srv)
    });

    let service = ServiceBuilder::new(Arc::clone(&server))
        // AUTO-APPROVING, which a real deployment must never be (RFC 6749 s10.12). It is right for
        // a benchmark: a real consent resolver reads the host's session store, and the cost of that
        // belongs to the host, not to this crate. Measuring it here would be measuring the fixture.
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        .with_approval_resolver(|_request| ApprovalDecision::Approve)
        .build()
        .expect("service");

    // A live token to introspect, minted through the library rather than through the wire so the
    // setup does not depend on the rows being measured.
    let token = rt.block_on(async {
        server
            .token(oauth_as::TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(SECRET.to_string()),
                scope: None,
            })
            .await
            .unwrap()
            .access_token
    });

    // --- RFC 8414 discovery. Served uncached by this crate, so this row is what a host pays per
    // discovery request if it does not put a cache in front. Compare against `metadata_from_config`
    // plus `metadata_serialize_json` in benches/parsing.rs to see how much of it is the document.
    b.bench_fast("GET /.well-known/oauth-authorization-server", || {
        rt.block_on(service.handle(get("/.well-known/oauth-authorization-server")))
    });

    // --- RFC 7662 introspection, the highest-QPS endpoint in an opaque-token deployment. The
    // number to compare against is `introspection_active` in benches/token.rs: the difference is
    // the whole cost of the wire layer on the endpoint where it is paid most often.
    {
        let body = format!(
            "token={token}&client_id=confidential-app&client_secret={SECRET}&token_type_hint=access_token"
        );
        b.bench_fast("POST /introspect (active)", || {
            rt.block_on(service.handle(form("/introspect", body.clone())))
        });
    }

    // --- RFC 6749 s4.4 client credentials over the wire.
    {
        let body = format!(
            "grant_type=client_credentials&client_id=confidential-app&client_secret={SECRET}"
        );
        b.bench_fast("POST /token (client_credentials)", || {
            rt.block_on(service.handle(form("/token", body.clone())))
        });
    }

    // --- The two refusals an unauthenticated caller can drive at will. A 404 on an unrouted path
    // is the cheapest thing this service can be asked to do, so it is the floor for "how much does
    // a request cost before any protocol work happens"; the malformed token request is the floor
    // for a request that reaches an endpoint and is rejected.
    b.bench_fast("POST /token (unknown grant_type)", || {
        rt.block_on(service.handle(form("/token", "grant_type=nonsense".to_string())))
    });
    b.bench_fast("GET /not-a-route (404)", || {
        rt.block_on(service.handle(get("/not-a-route")))
    });

    // --- The form decoder, exercised through the only public door it has. `parse_pairs` is
    // private, so the honest way to measure it is to send a body with many parameters and diff
    // against the same request with few: everything else about the two requests is identical.
    //
    // THIS IS AN UNAUTHENTICATED AMPLIFICATION MEASUREMENT, not a curiosity. `/token` rejects an
    // unknown client before it does anything expensive, but it decodes the FORM first, and the
    // form is whatever the caller sent up to `MAX_BODY_BYTES` (64 KiB in src/http.rs). So the
    // question this sweep answers is: how much server CPU does one 64 KiB packet of junk
    // parameters buy an attacker, and does the answer grow faster than the packet does?
    //
    // `request_construction_only` is the control: it builds the same `http::Request` and does not
    // call `handle`, so the `String` clone that every row above pays inside its own closure can be
    // subtracted rather than guessed at.
    //
    // WHAT THIS SWEEP MEASURES NOW. It found the answer to be about 1000x, so `src/http.rs` grew
    // `MAX_FORM_PARAMETERS` (64) and every row here past the cap is a REFUSAL rather than a
    // decode. Measured on one aarch64 laptop, before the cap and after it:
    //
    //     n        before      after
    //     0       2.65 us    2.67 us
    //    64       7.55 us    2.15 us   (refused, so cheaper than the grant it skips)
    //   256      22.15 us    4.46 us
    //  1024      83.33 us   14.50 us
    //
    // The sweep is kept, and kept at these sizes, because what it now proves is that the cap
    // HOLDS: the remaining growth is buffering and UTF-8 validating the body, which
    // `MAX_BODY_BYTES` bounds and which nothing can avoid, and the ns/element column must keep
    // falling rather than flattening at the per-parameter cost.
    const PARAM_COUNTS: &[usize] = &[0, 64, 256, 1024];
    {
        let base = format!(
            "grant_type=client_credentials&client_id=confidential-app&client_secret={SECRET}"
        );
        let mut bodies = Vec::new();
        for &n in PARAM_COUNTS {
            let mut body = base.clone();
            for i in 0..n {
                body.push_str(&format!("&unknown_parameter_{i}=some%20encoded%20value"));
            }
            bodies.push(body);
        }
        for (idx, &n) in PARAM_COUNTS.iter().enumerate() {
            let body = bodies[idx].clone();
            b.bench_fast(
                &format!("POST /token[+{n} ignored form parameters]"),
                || rt.block_on(service.handle(form("/token", body.clone()))),
            );
        }
        let largest = bodies.last().unwrap().clone();
        b.bench_fast("request_construction_only[largest body]", || {
            form("/token", largest.clone())
        });
    }

    // --- The authorization endpoint: a GET that ends in a 302 to the client's redirect URI. This
    // is the one endpoint where the crate builds a URL rather than a JSON document, and
    // `AuthorizationResponse::location` is the single-allocation exact-capacity function
    // `tests/allocation.rs` pins; this row is what it costs in time.
    {
        let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
        let uri = format!(
            "/authorize?response_type=code&client_id=confidential-app\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=opaque-state\
             &code_challenge={challenge}&code_challenge_method=S256"
        );
        b.bench_fast("GET /authorize (302 to redirect_uri)", || {
            rt.block_on(service.handle(get(&uri)))
        });
    }

    b.finish();
    harness::print_growth(
        &b,
        "ignored form parameters on POST /token",
        PARAM_COUNTS,
        |n| format!("POST /token[+{n} ignored form parameters]"),
    );
}
