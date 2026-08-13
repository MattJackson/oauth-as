// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The `http` plane: build the service and DISPATCH a request to every route it answers.
//!
//! Dispatching is the whole point. An early hand measurement enabled `http` without ever calling
//! `handle`, and LTO deleted the entire service, so `http,jwt` read identical to `jwt`. That
//! number was not wrong about the build, it was wrong about the question: a host that turns the
//! feature on and calls it pays for the router, the form and query parsers, the body reader, and
//! one response serializer per endpoint.

use oauth_as::http::{ApprovalDecision, Body, ServiceBuilder};

use crate::blockon::block_on;
use crate::exercise::ISSUER;

fn post(path: &str, body: &str) -> http::Request<Body> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("{ISSUER}{path}"))
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::from(body.to_string()))
        .expect("static request parts are valid")
}

fn get(path_and_query: &str) -> http::Request<Body> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{ISSUER}{path_and_query}"))
        .body(Body::empty())
        .expect("static request parts are valid")
}

pub fn plane() -> u64 {
    let server = crate::exercise::server();
    let service = ServiceBuilder::new(server)
        // A constant subject and a blanket approval: a probe, never a template. See the banner in
        // examples/conformance_server.rs for what each of these deletes in production.
        .with_subject_resolver(|_headers| Some("probe-subject".to_string()))
        .with_approval_resolver(|_request| ApprovalDecision::Approve)
        .dangerously_disable_verification_protections()
        .build()
        .expect("the probe config routes to distinct paths");

    let mut acc: u64 = 0;
    block_on(async {
        // Every route in the table, plus a 404 and a 405, because the refusal paths are code too
        // and a host pays for them the moment it mounts the service.
        // `mut` is unused when neither jwt nor par is on; the push sites below are gated.
        #[allow(unused_mut)]
        let mut requests: Vec<http::Request<Body>> = vec![
            get("/.well-known/oauth-authorization-server"),
            get("/authorize?response_type=code&client_id=probe-public&redirect_uri=https%3A%2F%2Fclient.probe.example%2Fcb&scope=read&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"),
            post("/device_authorization", "client_id=probe-public"),
            post(
                "/token",
                "grant_type=client_credentials&client_id=probe-confidential&client_secret=probe-secret-0123456789abcdefghij",
            ),
            post(
                "/introspect",
                "token=nope&client_id=probe-confidential&client_secret=probe-secret-0123456789abcdefghij",
            ),
            post(
                "/revoke",
                "token=nope&client_id=probe-confidential&client_secret=probe-secret-0123456789abcdefghij",
            ),
            get("/device"),
            post("/device", "user_code=ABCD-EFGH"),
            post("/register", r#"{"redirect_uris":["https://client.probe.example/cb"]}"#),
            get("/register/probe-public"),
            get("/nothing-here"),
            post("/.well-known/oauth-authorization-server", ""),
        ];
        #[cfg(feature = "f-jwt")]
        requests.push(get("/jwks"));
        #[cfg(feature = "f-par")]
        requests.push(post(
            "/par",
            "response_type=code&client_id=probe-public&redirect_uri=https%3A%2F%2Fclient.probe.example%2Fcb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        ));

        for request in requests {
            let response = service.handle(request).await;
            acc = acc.wrapping_add(u64::from(response.status().as_u16()));
            acc = acc.wrapping_add(response.headers().len() as u64);
            acc = acc.wrapping_add(response.into_body().into_bytes().len() as u64);
        }
    });

    #[cfg(feature = "f-axum")]
    {
        // The adapter AND what a host does with it. Building only the `Router` would have
        // measured this row at the adapter's thirty lines and reported tokio at under a
        // kilobyte, because LTO deletes a runtime nothing ever enters. A host that turns this
        // feature on turns it on in order to SERVE, so the probe starts a multi-thread runtime,
        // binds a listener on an ephemeral port and constructs the `axum::serve` future. The
        // future is dropped rather than awaited: the probe must terminate, and everything the
        // row is measuring (the runtime, the reactor, the accept path, the router) is linked by
        // the time it exists.
        let router: axum::Router = axum::Router::from(service);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a runtime can be built");
        acc = acc.wrapping_add(runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("an ephemeral port is available");
            let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
            let serving = axum::serve(listener, router);
            drop(std::hint::black_box(serving));
            u64::from(port)
        }));
    }

    std::hint::black_box(acc)
}
