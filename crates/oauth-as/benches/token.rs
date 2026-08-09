// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The token plane: what a real deployment spends its time on.
//!
//! Every figure here is measured against [`oauth_as::MemoryStorage`], in process, with no network,
//! no TLS and no database. That is deliberate (it isolates THIS CRATE's cost) and it is the single
//! largest caveat on every number; see `benches/README.md` before quoting any of them.
//!
//! # Why introspection is weighted first
//!
//! This crate's default access token is OPAQUE. A resource server holding an opaque token cannot
//! validate it locally, so it calls RFC 7662 introspection on EVERY protected request it serves.
//! For a deployment that issues one token per user session and then serves thousands of API calls
//! against it, introspection is not one endpoint among several, it is the highest-QPS endpoint in
//! the system by a wide margin. It is measured first and in the most detail for that reason.
//!
//! # The `block_on` baseline row
//!
//! Every async row pays one `tokio::runtime::Runtime::block_on` per iteration, which a real host
//! serving from an already-running reactor does not pay. `runtime_block_on_baseline` measures an
//! empty `block_on` so a reader can subtract it rather than guess at it.

#[path = "harness/mod.rs"]
mod harness;

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest, TokenTypeHint, UserApproval,
};

/// The RFC 7636 appendix B code verifier. Reused rather than invented so the PKCE rows are
/// measuring the same input the correctness tests pin.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn config() -> ServerConfig {
    ServerConfig::new("https://as.example", "https://as.example/device")
}

fn public_code_client() -> Client {
    Client {
        client_id: ClientId::new("public-app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("confidential-app"),
        auth: ClientAuth::ConfidentialSecret {
            // A high-entropy secret, because `ClientAuth::verify` hashes both sides with SHA-256
            // before comparing (see src/client.rs) and a short fixture would understate that cost
            // no more than a long one would overstate it, but a realistic one is the honest input.
            secret: "a-high-entropy-registered-client-secret".to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

const SECRET: &str = "a-high-entropy-registered-client-secret";

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn authorization_pairs(challenge: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_string()),
        ("client_id", "public-app".to_string()),
        ("redirect_uri", "https://app.example/cb".to_string()),
        ("scope", "read write".to_string()),
        ("state", "opaque-state".to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ]
}

fn main() {
    harness::print_environment();
    let mut b = harness::Bench::from_args("token plane (MemoryStorage, in process)");
    let rt = harness::runtime();

    // ------------------------------------------------------------------ the subtraction baseline
    b.bench_fast("runtime_block_on_baseline", || rt.block_on(async {}));

    // ------------------------------------------------------------------------------ introspection
    //
    // The highest-QPS endpoint in an opaque-token deployment. Three rows, because a resource
    // server sees all three shapes and they are not the same cost:
    //   * active   : the token exists and is live. The common case.
    //   * inactive : the token is not in the store at all. RFC 7662 s2.2 says answer
    //                {"active": false} rather than an error, so this is the shape a resource
    //                server sees for every expired session and every attacker probe, and an
    //                attacker sets the rate of the second kind.
    //   * raw read : `introspect()` without the RFC 7662 response document, which isolates the
    //                store read plus client authentication from the serde shape built on top.
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(confidential_client()).await.unwrap();
            srv
        });
        let token = rt.block_on(async {
            srv.token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(SECRET.to_string()),
                scope: None,
            })
            .await
            .unwrap()
            .access_token
        });
        let cid = ClientId::new("confidential-app");

        b.bench_fast("introspection_active", || {
            rt.block_on(srv.introspection_response(&cid, Some(SECRET), &token))
        });
        b.bench_fast("introspection_inactive_unknown_token", || {
            rt.block_on(srv.introspection_response(
                &cid,
                Some(SECRET),
                "not-a-token-we-ever-issued",
            ))
        });
        b.bench_fast("introspection_store_read_only", || {
            rt.block_on(srv.introspect(&token))
        });
        // Revocation of an already-revoked token: RFC 7009 s2.2 makes this a 200, so it is the
        // shape a retrying client produces, and it exercises the family revocation scan in
        // MemoryStorage without the issuance cost in front of it.
        b.bench_fast("revocation_unknown_token", || {
            rt.block_on(srv.revoke(
                &cid,
                Some(SECRET),
                "not-a-token-we-ever-issued",
                Some(TokenTypeHint::AccessToken),
            ))
        });
    }

    // ------------------------------------------------------------------------- client credentials
    //
    // RFC 6749 s4.4. The one grant with no prior artifact to redeem, so it is the cleanest view of
    // "authenticate a confidential client, then mint and persist a token".
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(confidential_client()).await.unwrap();
            srv
        });
        b.bench_fast("client_credentials_issue", || {
            rt.block_on(srv.token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(SECRET.to_string()),
                scope: None,
            }))
        });
        // The refusal path, which an unauthenticated caller can drive at whatever rate it can open
        // sockets. It must not be dramatically more expensive than the success path, or the
        // cheapest request to make is the most expensive one to serve.
        b.bench_fast("client_credentials_wrong_secret", || {
            rt.block_on(srv.token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some("wrong-secret-of-the-same-rough-length".to_string()),
                scope: None,
            }))
        });
    }

    // ------------------------------------------------------------- authorization code redemption
    //
    // A code is SINGLE USE by design, so each iteration needs a fresh one. `bench_with` mints it
    // outside the clock; the cost of that shows up as extra spread on this row, not in its median.
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(public_code_client()).await.unwrap();
            srv
        });
        let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
        let pairs = authorization_pairs(&challenge);

        b.bench_with(
            "authorization_code_redemption",
            || {
                rt.block_on(async {
                    let req = AuthorizationRequest::from_pairs(
                        pairs.iter().map(|(k, v)| (*k, v.as_str())),
                    );
                    let validated = srv.validate_authorization_request(&req).await.unwrap();
                    srv.issue_authorization_code(UserApproval::granted(&validated, "user-1"))
                        .await
                        .unwrap()
                        .code
                })
            },
            |code| {
                rt.block_on(srv.token(TokenRequest::AuthorizationCode {
                    client_id: ClientId::new("public-app"),
                    client_secret: None,
                    code,
                    redirect_uri: Some("https://app.example/cb".to_string()),
                    code_verifier: Some(VERIFIER.to_string()),
                }))
            },
        );

        // The two halves of the authorization endpoint, measured apart from redemption because a
        // host calls them on a different request (and, with a real consent screen, on a different
        // round trip) from the token endpoint.
        // `.is_ok()` on both of these rather than returning the `Result`: `AuthorizationError` is
        // a large enum and clippy's `result_large_err` fires on a closure that returns one.
        // Nothing is measured away by it, because the whole call runs and the whole value is
        // dropped inside the clock either way; only the discriminant leaves the closure.
        b.bench_fast("validate_authorization_request", || {
            let req = AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (*k, v.as_str())));
            rt.block_on(srv.validate_authorization_request(&req))
                .is_ok()
        });
        b.bench_with(
            "issue_authorization_code",
            || {
                let req =
                    AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (*k, v.as_str())));
                rt.block_on(srv.validate_authorization_request(&req))
                    .unwrap()
            },
            |validated| {
                rt.block_on(
                    srv.issue_authorization_code(UserApproval::granted(&validated, "user-1")),
                )
                .is_ok()
            },
        );
    }

    // ------------------------------------------------------------------------- refresh rotation
    //
    // OAuth 2.1 s6.1 single-use rotation, so the same fresh-artifact-per-iteration problem as code
    // redemption: the token returned by the previous iteration is the only one that still works.
    //
    // The refresh token has to come from the AUTHORIZATION CODE grant, not from client
    // credentials: RFC 6749 s4.4.3 says a client-credentials response SHOULD NOT include one, and
    // this crate obeys that, so seeding from client credentials would leave nothing to rotate and
    // this row would silently measure `Option::map` over `None`. It did, in the first draft of
    // this file, and reported 15 ns.
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(public_code_client()).await.unwrap();
            srv
        });
        let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
        let pairs = authorization_pairs(&challenge);

        b.bench_with(
            "refresh_rotation",
            || {
                rt.block_on(async {
                    let req = AuthorizationRequest::from_pairs(
                        pairs.iter().map(|(k, v)| (*k, v.as_str())),
                    );
                    let validated = srv.validate_authorization_request(&req).await.unwrap();
                    let code = srv
                        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
                        .await
                        .unwrap()
                        .code;
                    srv.token(TokenRequest::AuthorizationCode {
                        client_id: ClientId::new("public-app"),
                        client_secret: None,
                        code,
                        redirect_uri: Some("https://app.example/cb".to_string()),
                        code_verifier: Some(VERIFIER.to_string()),
                    })
                    .await
                    .unwrap()
                    .refresh_token
                    .expect("the authorization code grant issues a refresh token")
                })
            },
            |refresh_token| {
                rt.block_on(srv.token(TokenRequest::RefreshToken {
                    client_id: ClientId::new("public-app"),
                    client_secret: None,
                    refresh_token,
                    scope: None,
                }))
            },
        );
    }

    // --------------------------------------------------------------------------- the device flow
    //
    // RFC 8628. The POLL is the one that matters: every pending device calls it every `interval`
    // seconds for as long as the user takes to approve, so a deployment with N devices waiting is
    // serving N/interval polls per second whether or not anybody ever approves anything. It is
    // high frequency by construction, not by traffic pattern.
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(device_client()).await.unwrap();
            srv
        });
        let cid = ClientId::new("device-client");

        b.bench_fast("device_authorization", || {
            rt.block_on(srv.device_authorization(&cid, None, None))
        });

        // A grant that exists, is unexpired and is not yet approved: the `authorization_pending`
        // answer, which is what essentially every poll in a real deployment gets.
        let pending = rt
            .block_on(srv.device_authorization(&cid, None, None))
            .unwrap();
        b.bench_fast("device_poll_authorization_pending", || {
            rt.block_on(srv.token(TokenRequest::DeviceCode {
                client_id: ClientId::new("device-client"),
                client_secret: None,
                device_code: pending.device_code.clone(),
            }))
        });

        b.bench_with(
            "device_approval",
            || {
                rt.block_on(srv.device_authorization(&cid, None, None))
                    .unwrap()
                    .user_code
            },
            |user_code| rt.block_on(srv.approve_device(&user_code, "user-1")),
        );

        b.bench_with(
            "device_redemption_after_approval",
            || {
                rt.block_on(async {
                    let auth = srv.device_authorization(&cid, None, None).await.unwrap();
                    srv.approve_device(&auth.user_code, "user-1").await.unwrap();
                    auth.device_code
                })
            },
            |device_code| {
                rt.block_on(srv.token(TokenRequest::DeviceCode {
                    client_id: ClientId::new("device-client"),
                    client_secret: None,
                    device_code,
                }))
            },
        );
    }

    b.finish();
}
