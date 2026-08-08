// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A runnable authorization server over the optional `http` feature, and the target of the
//! independent black-box conformance harness.
//!
//! # Why the fixtures live here and not in the library
//!
//! The harness needs a deterministic AS: two known clients, a known user, and an approval path it
//! can drive without a browser. None of that belongs in a published library. A crate that ships a
//! client called `conformance-public` with a hard-coded secret has shipped a backdoor and an
//! excuse; so the fixtures live in this example, which is never published as a binary and is
//! compiled only when the `http` feature is on.
//!
//! # Environment
//!
//! * `OAUTH_AS_ADDR` (default `127.0.0.1:8914`): the address to bind.
//! * `OAUTH_AS_ISSUER` (default `http://{OAUTH_AS_ADDR}`): the RFC 8414 `issuer`. RFC 8414 s3.3
//!   requires it to equal the URL the metadata document is fetched from, so the default is
//!   derived from the bind address and an override exists only for a host behind a proxy.
//! * `OAUTH_AS_CONFORMANCE_SEED=1`: register the deterministic fixtures below, treat every
//!   request as coming from the signed-in user `conformance-user`, auto-approve consent, and
//!   disable the device verification form's CSRF protection. WITHOUT it this example is an empty
//!   AS with no clients, no logged-in user, no consent step and no device approvals, which is
//!   what any other reader should see.
//!
//! # The seeded mode is NOT a template
//!
//! Under the seed flag this example turns off two protections a real authorization server must
//! have: the RFC 6749 s10.12 consent step, and the CSRF protection on the RFC 8628 verification
//! form. They are off because the harness is not a browser, and they are spelled out by name at
//! the wiring site below so that copying them is a deliberate act rather than an accident. Do not
//! copy them. See `RouterBuilder::with_consent_resolver` and `RouterBuilder::with_csrf_tokens`
//! for what a production host wires instead.

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{ConsentDecision, RouterBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;

/// The launch contract in `crates/oauth-as-conformance/src/lib.rs`, verbatim. These strings are
/// the harness's, not ours: changing one here silently breaks a gate that is supposed to be
/// arms-length, so they are quoted rather than derived.
const PUBLIC_CLIENT_ID: &str = "conformance-public";
const PUBLIC_REDIRECT_URI: &str = "http://127.0.0.1:8917/cb";
const CONFIDENTIAL_CLIENT_ID: &str = "conformance-confidential";
const CONFIDENTIAL_CLIENT_SECRET: &str = "conformance-secret-0123456789abcdef";
/// The test user every seeded approval acts as.
const SEEDED_SUBJECT: &str = "conformance-user";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("OAUTH_AS_ADDR").unwrap_or_else(|_| "127.0.0.1:8914".to_string());
    let issuer = std::env::var("OAUTH_AS_ISSUER").unwrap_or_else(|_| format!("http://{addr}"));
    let seed = std::env::var("OAUTH_AS_CONFORMANCE_SEED").as_deref() == Ok("1");

    // RFC 8628 s3.2: the device page the user is sent to. Under the issuer, so the router serves
    // it; a real host would put its own branded page here instead.
    let verification_uri = format!("{}/device", issuer.trim_end_matches('/'));
    let mut config = ServerConfig::new(issuer.clone(), verification_uri);
    // RFC 8414 s2 `scopes_supported`: stating the catalogue costs nothing and lets a client see
    // what it may ask for without probing.
    config.scopes_supported = Some(vec!["read".to_string(), "write".to_string()]);

    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));

    if seed {
        seed_fixtures(&server).await?;
    }

    let mut builder = RouterBuilder::new(Arc::clone(&server));
    if seed {
        // ############################################################################
        // # CONFORMANCE FIXTURE ONLY. NEVER COPY ANY OF THIS INTO A PRODUCTION HOST.  #
        // ############################################################################
        //
        // The black-box harness drives this AS with an HTTP client and no browser, so it has no
        // session, cannot hold a CSRF token, and cannot click anything. Its launch contract
        // therefore requires the seeded AS to auto-approve a valid authorization request and to
        // approve a device grant on a bare `user_code` POST. Both of those are behaviours a real
        // AS must NOT have, so they are opted into BY NAME here rather than being what a host
        // gets by leaving something unwired.
        //
        // What each line would cost in production:
        //
        // * `with_subject_resolver` returning a constant: every request is the same user. Real
        //   hosts read their own session.
        // * `with_consent_resolver` returning `Approve`: RFC 6749 s10.12 consent, deleted. Any
        //   cross-site navigation would silently issue a code for a logged-in user. A real host
        //   returns `ConsentDecision::Respond` with a consent screen and approves only after the
        //   user has answered it.
        // * `dangerously_disable_verification_protections`: RFC 6749 s10.12 CSRF protection on
        //   the device verification form, deleted. On a browser-reachable endpoint that is the
        //   complete cross-site forced-approval chain, which is account takeover.
        builder = builder
            .with_subject_resolver(|_headers| Some(SEEDED_SUBJECT.to_string()))
            .with_consent_resolver(|_request| ConsentDecision::Approve)
            .dangerously_disable_verification_protections();
    }
    let router = builder.build()?;

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // The harness waits for the RFC 8414 document to answer before it starts, so announcing the
    // bind on stdout is for a human reading the log, not for the gate.
    println!("oauth-as example listening on {addr} (issuer {issuer}, seeded: {seed})");
    axum::serve(listener, router).await?;
    Ok(())
}

/// Register the two clients the launch contract names.
async fn seed_fixtures<S>(server: &AuthorizationServer<S>) -> Result<(), Box<dyn std::error::Error>>
where
    S: oauth_as::store::Storage,
{
    let scopes = ScopeSet::from_tokens(["read", "write"])?;

    // The contract asks for `authorization_code` and the device grant. `refresh_token` is added
    // because a token response for a client that cannot refresh omits `refresh_token`, and the
    // harness's RFC 6749 s5.1 validation is strictly happier with the fuller shape. It is a
    // superset of what the contract requires, so no harness assumption is weakened by it.
    server
        .register_client(Client {
            client_id: ClientId::new(PUBLIC_CLIENT_ID),
            auth: ClientAuth::Public,
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::DeviceCode,
                GrantType::RefreshToken,
            ],
            redirect_uris: vec![PUBLIC_REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes.clone(),
            name: Some("Conformance public client".to_string()),
        })
        .await?;

    server
        .register_client(Client {
            client_id: ClientId::new(CONFIDENTIAL_CLIENT_ID),
            auth: ClientAuth::ConfidentialSecret {
                secret: CONFIDENTIAL_CLIENT_SECRET.to_string(),
            },
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::DeviceCode,
                GrantType::RefreshToken,
            ],
            redirect_uris: vec![PUBLIC_REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: Some("Conformance confidential client".to_string()),
        })
        .await?;

    Ok(())
}
