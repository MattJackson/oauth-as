// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A worked example of the RFC 9728 host seam: a PROTECTED RESOURCE that publishes its own
//! metadata document and points at the authorization server in `conformance_server.rs`.
//!
//! # Why an authorization server crate ships a resource server example
//!
//! Read `src/resource_metadata.rs` first. This crate is an AUTHORIZATION SERVER. RFC 9728
//! section 3.1 places the protected resource metadata document under the RESOURCE's own
//! identifier, not under the AS's issuer, so `oauth-as` deliberately gives a host the TYPE and
//! serves nothing. That boundary is correct and this example does not move it: everything below
//! is the HOST's half, written out in full precisely because the library will not do it for you.
//!
//! Two things it is for:
//!
//! 1. **Documentation.** `ProtectedResourceMetadata` had no worked consumer anywhere in the tree.
//!    A seam with no example is a seam a reader has to guess at, and the two details most likely
//!    to be guessed wrong are both here: the document goes at
//!    [`oauth_as::resource_metadata::well_known_path`] (the suffix is INSERTED between host and
//!    path, not appended), and an unauthenticated request answers 401 with the RFC 9728 section
//!    5.1 `WWW-Authenticate: Bearer resource_metadata="..."` challenge that tells a client where
//!    to find it.
//! 2. **An external judge.** The `authgent` MCP-OAuth scanner discovers an authorization server by
//!    reading a resource's RFC 9728 document, and without one it returns a single "not an MCP
//!    server" finding and skips every check it has. Standing this fixture up is what lets that
//!    scanner reach, and form its own opinion about, THIS PROJECT'S RFC 8414 document.
//!
//! # What this is NOT, stated plainly because the distinction is the whole point
//!
//! This is a FIXTURE. It is a test resource with no resources in it: it validates no access
//! token, enforces no scope, and serves no protected data, because none of that is an
//! authorization server's job and none of it is what the document is for. It is compiled only as
//! an example, is never part of the library, and its `resource` identifier is a loopback address.
//!
//! Running it does NOT make `oauth-as` an MCP server, and a green from a scanner that reached us
//! through it says nothing about MCP conformance. What such a run CAN say is narrower and is the
//! only thing this project will claim from it: an independently authored third-party tool read
//! this crate's RFC 8414 metadata document and applied its own checks to it.
//!
//! # Environment
//!
//! * `OAUTH_RS_ADDR` (default `127.0.0.1:8915`): the address to bind. Deliberately a DIFFERENT
//!   port from the AS: RFC 9728 section 3.1 puts this document under the resource's identifier,
//!   and serving it from the issuer's origin would demonstrate the exact mistake the module docs
//!   warn about.
//! * `OAUTH_RS_RESOURCE` (default `http://{OAUTH_RS_ADDR}`): the section 2 `resource` identifier.
//!   Section 3.3 makes a client compare this against the identifier it built the request URL
//!   from, so the default is derived from the bind address rather than configured separately.
//! * `OAUTH_AS_ISSUER` (default `http://127.0.0.1:8914`): the section 2 `authorization_servers`
//!   entry. The same variable name `conformance_server.rs` reads, so one export configures both.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use oauth_as::resource_metadata::{ProtectedResourceConfig, ProtectedResourceMetadata};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("OAUTH_RS_ADDR").unwrap_or_else(|_| "127.0.0.1:8915".to_string());
    let resource = std::env::var("OAUTH_RS_RESOURCE").unwrap_or_else(|_| format!("http://{addr}"));
    let issuer =
        std::env::var("OAUTH_AS_ISSUER").unwrap_or_else(|_| "http://127.0.0.1:8914".to_string());

    // Every member below is one the host actually knows about its own resource. Section 2 makes
    // `resource` and nothing else REQUIRED, so anything added here is a claim being made on
    // purpose rather than a field being filled in.
    let mut config = ProtectedResourceConfig::new(resource.clone(), issuer);
    // RECOMMENDED (section 2). Publishing the catalogue is what lets a client ask for the least it
    // needs rather than the most it can (section 7.2). These are the two scopes the AS example
    // registers its fixture clients for, so the two documents agree.
    config.scopes_supported = Some(vec!["read".to_string(), "write".to_string()]);
    config.resource_name = Some("oauth-as conformance fixture resource".to_string());

    let document = ProtectedResourceMetadata::from_config(&config);
    // The location is DERIVED from the document, never written out by hand. RFC 9728 section 3.3
    // has the client compare the served `resource` member against the identifier it inserted the
    // well-known suffix into, so a document whose location and whose `resource` member were
    // maintained separately is a document that eventually teaches clients to skip that check.
    let path = document.well_known_path();
    let body = serde_json::to_string(&document)?;
    let shared = Arc::new(body);

    // Section 5.1: an unauthenticated request to the resource itself gets a 401 whose
    // `WWW-Authenticate` names the metadata URL. That is the OTHER half of discovery, the one a
    // client uses when it was given a resource URL and no configuration at all, and it is the
    // reason this fixture answers 401 rather than 200 on `/`: a protected resource that serves
    // its contents to an unauthenticated caller is not protected.
    let challenge = format!(
        "Bearer resource_metadata=\"{}{}\"",
        resource.trim_end_matches('/'),
        path
    );

    let doc_for_route = Arc::clone(&shared);
    let app = Router::new()
        .route(
            &path,
            get(move || {
                let doc = Arc::clone(&doc_for_route);
                async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        // A document a client caches for a year is a document a rotation cannot
                        // reach, so it is explicitly not cached here.
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(Body::from((*doc).clone()))
                        .expect("static response")
                }
            }),
        )
        .fallback(move || {
            let value = HeaderValue::from_str(&challenge).expect("ASCII challenge");
            async move {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(header::WWW_AUTHENTICATE, value)
                    .body(Body::empty())
                    .expect("static response")
            }
        });

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("RFC 9728 fixture resource on {addr}: resource {resource}, document at {path}");
    axum::serve(listener, app).await?;
    Ok(())
}
