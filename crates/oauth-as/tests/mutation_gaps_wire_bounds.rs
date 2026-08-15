// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! FOUR BOUNDARIES NOTHING STOOD ON, AND ONE PATH DECODER THAT COULD REWRITE A CLIENT ID.
//!
//! Survivors of the `--all-features` mutation sweep at commit `42fa851`:
//!
//! ```text
//! http.rs   replace > with == in collect_body
//! http.rs   replace > with >= in collect_body
//! http.rs   replace match guard plus_is_space with true in percent_decode
//! dpop.rs    replace > with >= in verify_proof
//! consent.rs replace + with - in step_up_challenge
//! ```
//!
//! Each comparison mutant differs from the original at EXACTLY ONE input, and the suite had tests
//! on both sides of every one of these boundaries and none on it. That is the recurring shape of a
//! surviving relational mutant, and it is worth stating plainly: "over the cap is refused" and
//! "well under the cap is accepted" together do not pin where the cap IS.
//!
//! The `percent_decode` guard is a different animal. It decides whether `+` means a space, and it
//! is `false` for a URL PATH segment (RFC 3986 section 3.3 puts `+` in `sub-delims`; only
//! `application/x-www-form-urlencoded` gives it the "space" meaning). Forced true, the RFC 7592
//! section 3 `registration_client_uri` this server itself minted stops resolving to the client it
//! names.

mod support;

// ------------------------------------------------------------- the request body cap and the path

#[cfg(feature = "http")]
mod over_http {
    use oauth_as::http::{Body, ServiceBuilder, MAX_BODY_BYTES};
    use oauth_as::{AuthorizationServer, MemoryStorage, ServerConfig, SystemClock};

    type Service = oauth_as::http::AuthorizationService<MemoryStorage, SystemClock>;

    const ISSUER: &str = "https://as.example";

    fn server() -> AuthorizationServer<MemoryStorage> {
        AuthorizationServer::new(config(None), MemoryStorage::new())
    }

    /// `registration` is what makes the RFC 7592 management route exist at all: without a
    /// registration endpoint there is nothing under it for a client id to be a segment of.
    fn config(registration: Option<oauth_as::registration::RegistrationConfig>) -> ServerConfig {
        let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
        cfg.registration = registration.map(Box::new);
        cfg
    }

    fn service_over(server: AuthorizationServer<MemoryStorage>) -> Service {
        let builder = ServiceBuilder::new(std::sync::Arc::new(server))
            .with_approval_resolver(|_req| oauth_as::http::ApprovalDecision::Approve);
        builder.build().expect("a default service builds")
    }

    struct Wire {
        status: u16,
        body: String,
    }

    async fn send(service: &Service, request: http::Request<Body>) -> Wire {
        let response = service.handle(request).await;
        let status = response.status().as_u16();
        let body = String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned();
        Wire { status, body }
    }

    /// A body of EXACTLY [`MAX_BODY_BYTES`] is accepted; one byte more is refused.
    ///
    /// Kills both `collect_body` mutants at `1138`. `>=` refuses the body that exactly fills the
    /// cap, and `==` refuses it too, since that is the one length at which `lower() == limit`
    /// holds, so the same pair of requests separates the original from both.
    ///
    /// Stated as an INCLUSIVE cap because that is what the constant's name and the refusal's own
    /// text say: a request "exceeds this server's limit" only when it is LARGER than the limit. A
    /// client that sizes its request against the documented number and gets a 413 has no way to
    /// discover that the real limit was one byte lower.
    #[tokio::test]
    async fn a_body_of_exactly_the_cap_is_accepted_and_one_byte_more_is_not() {
        let service = service_over(server());

        // A form body padded to an exact length with one long value. Not a valid token request, so
        // the answer is an RFC 6749 s5.2 error rather than a token, and that is the point: any
        // status but 413 means the body was READ, and 413 means it was refused before anything
        // looked at it.
        let pad = |total: usize| {
            let prefix = "grant_type=client_credentials&x=";
            let mut body = String::with_capacity(total);
            body.push_str(prefix);
            body.extend(std::iter::repeat('a').take(total - prefix.len()));
            body
        };

        let post = |bytes: String| {
            http::Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(bytes))
                .expect("a well-formed request")
        };

        let at_the_cap = send(&service, post(pad(MAX_BODY_BYTES))).await;
        assert_ne!(
            at_the_cap.status, 413,
            "a body of exactly MAX_BODY_BYTES does not EXCEED the cap: {}",
            at_the_cap.body
        );

        let past_the_cap = send(&service, post(pad(MAX_BODY_BYTES + 1))).await;
        assert_eq!(
            past_the_cap.status, 413,
            "one byte past the cap is refused: {}",
            past_the_cap.body
        );
    }

    /// A `+` in a URL PATH segment is a literal plus, even when the same segment carries a percent
    /// escape.
    ///
    /// Kills `replace match guard plus_is_space with true in percent_decode`. The guard is only
    /// REACHABLE when the segment also contains a `%`: without one, `percent_decode` returns the
    /// borrowed input before the loop runs at all, which is why a client id containing only a plus
    /// would not have caught this.
    ///
    /// The harm is the one the function's own comment names: the RFC 7592 section 3
    /// `registration_client_uri` this server minted for client `a+b c` would resolve to the
    /// different client `a b c`, so a client could not read, update or delete its own
    /// registration.
    #[tokio::test]
    async fn a_plus_in_a_path_segment_is_a_literal_plus_and_not_a_space() {
        use oauth_as::client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash};
        use oauth_as::{GrantType, ScopeSet};

        // A client id containing BOTH a plus and a character that has to be percent-encoded in a
        // path. The two together are what make the guard reachable.
        const CLIENT_ID: &str = "a+b c";
        const REGISTRATION_TOKEN: &str = "registration-access-token-0123456789";

        let server = AuthorizationServer::new(
            config(Some(oauth_as::registration::RegistrationConfig::new())),
            MemoryStorage::new(),
        );
        server
            .register_client(Client {
                client_id: ClientId::new(CLIENT_ID),
                auth: ClientAuth::Public,
                grant_types: vec![GrantType::ClientCredentials],
                redirect_uris: vec![],
                allowed_scopes: ScopeSet::empty(),
                default_scopes: ScopeSet::empty(),
                name: None,
                registration: Some(Box::new(DynamicRegistration {
                    registration_access_token_hash: SecretHash::sha256(REGISTRATION_TOKEN),
                    client_id_issued_at: None,
                    client_secret_expires_at: None,
                    token_endpoint_auth_method: "none".to_string(),
                })),
            })
            .await
            .expect("a client whose id contains a plus is a client like any other");

        let service = service_over(server);

        // `%20` for the space, and the plus LEFT AS ITSELF, which is what RFC 3986 s3.3 says it is.
        let request = http::Request::builder()
            .method("GET")
            .uri("/register/a+b%20c")
            .header("authorization", format!("Bearer {REGISTRATION_TOKEN}"))
            .body(Body::empty())
            .expect("a well-formed request");
        let read = send(&service, request).await;

        assert_eq!(
            read.status, 200,
            "the management URL for `a+b c` must resolve to `a+b c`, not to `a b c`: {}",
            read.body
        );
        assert!(
            read.body.contains(CLIENT_ID),
            "and it must hand back that client's registration: {}",
            read.body
        );
    }
}

// ------------------------------------------------------------- the DPoP future bound

#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
mod dpop_horizon {
    use crate::support::ManualClock;
    use oauth_as::dpop::CLOCK_SKEW_LEEWAY;
    use oauth_as::jwt::{compact_jws, EcdsaP256Key};
    use oauth_as::server::Clock;
    use oauth_as::{
        AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ScopeSet,
        ServerConfig, TokenRequest, TokenRequestContext,
    };
    use std::time::UNIX_EPOCH;

    const SECRET: &str = "confidential-client-secret";

    /// A proof issued EXACTLY at the far edge of the accepted clock skew is accepted.
    ///
    /// Kills `dpop.rs:295: replace > with >=`. The predicate is `issued_at > horizon`, so
    /// `issued_at == now + CLOCK_SKEW_LEEWAY` is the last acceptable instant and `>=` refuses it.
    /// The failure that produces is among the worst to diagnose: a client whose clock is fast by
    /// exactly the leeway is refused with `invalid_dpop_proof` and nothing else to go on, and the
    /// refusal moves as both clocks drift.
    ///
    /// Driven with a MANUAL clock. `SystemTime::now()` read here and read again inside the server
    /// are two reads of a moving clock, so a proof minted at the edge lands one second inside it
    /// whenever the second ticks between them, and a test that only sometimes stands on the
    /// boundary is a test that only sometimes kills the mutant.
    #[tokio::test]
    async fn a_proof_at_exactly_the_skew_horizon_is_accepted() {
        let clock = ManualClock::at_epoch();
        let now = clock
            .now()
            .duration_since(UNIX_EPOCH)
            .expect("the manual clock is after the epoch")
            .as_secs();

        let srv = AuthorizationServer::with_clock(
            ServerConfig::new("https://as.example", "https://as.example/device"),
            MemoryStorage::new(),
            clock.clone(),
        );
        srv.register_client(Client {
            client_id: ClientId::new("app"),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();

        let key = EcdsaP256Key::generate("skewed");
        // EXACTLY the horizon: the last instant `issued_at > horizon` does not refuse.
        let iat = now + CLOCK_SKEW_LEEWAY.as_secs();
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
        });
        let claims = serde_json::json!({
            "jti": "horizon-1",
            "htm": "POST",
            "htu": "https://as.example/token",
            "iat": iat,
        });
        let proof = compact_jws(
            &serde_json::to_vec(&header).unwrap(),
            &serde_json::to_vec(&claims).unwrap(),
            |input| key.sign_signing_input(input).unwrap(),
        );

        let issued = srv
            .token_with_context(
                TokenRequest::ClientCredentials {
                    client_id: ClientId::new("app"),
                    client_secret: Some(SECRET.to_string()),
                    scope: None,
                },
                TokenRequestContext::default().with_dpop_proof(&proof),
            )
            .await;
        assert!(
            issued.is_ok(),
            "a proof at the documented clock-skew horizon must be accepted: {issued:?}"
        );

        // The control: one second PAST the horizon is refused, so the assertion above is about
        // where the bound is rather than about there being no bound.
        let claims = serde_json::json!({
            "jti": "horizon-2",
            "htm": "POST",
            "htu": "https://as.example/token",
            "iat": iat + 1,
        });
        let too_far = compact_jws(
            &serde_json::to_vec(&header).unwrap(),
            &serde_json::to_vec(&claims).unwrap(),
            |input| key.sign_signing_input(input).unwrap(),
        );
        let refused = srv
            .token_with_context(
                TokenRequest::ClientCredentials {
                    client_id: ClientId::new("app"),
                    client_secret: Some(SECRET.to_string()),
                    scope: None,
                },
                TokenRequestContext::default().with_dpop_proof(&too_far),
            )
            .await;
        assert!(
            refused.is_err(),
            "one second past the horizon is outside the window"
        );
    }
}

// ------------------------------------------------------------- the RFC 9470 challenge

#[cfg(feature = "consent")]
mod challenge {
    use oauth_as::consent::step_up_challenge;

    /// A one-character `acr` value does not panic the challenge builder.
    ///
    /// Kills `consent.rs:531: replace + with -`. The expression is the `String::with_capacity`
    /// hint `acr_values.iter().map(|a| a.len() + 3).sum()`, and a capacity hint is normally
    /// invisible; this one is not, because `usize` subtraction UNDERFLOWS for any `acr` value
    /// shorter than three characters. This crate does not own the host's `acr` vocabulary (the
    /// function's own comment says so, which is why it escapes such values rather than refusing
    /// them), so a host with a short class name is a panic out of a library, on the path that
    /// builds a resource server's challenge.
    ///
    /// The sibling mutant `+` to `*` is killed separately, in
    /// `mutation_gaps_step_up_capacity.rs`. An earlier version of this comment argued it was
    /// equivalent -- an allocation-size change with nothing observable -- and that was WRONG: `+ 3`
    /// reserves enough that a challenge naming several short `acr` classes lands in ONE allocation,
    /// while `* 3` under-reserves for short names and forces a buffer grow, a second allocation the
    /// counting allocator sees even though the emitted string is byte-identical. The 0.9.2 sweep
    /// left it surviving because nothing counted allocations on this path; the 0.9.3 sweep's kill
    /// does.
    #[test]
    fn a_short_acr_value_does_not_underflow_the_challenge_buffer() {
        let acr: Vec<Box<str>> = vec!["a".into(), "bb".into()];
        let challenge = step_up_challenge("Bearer", &acr, None);
        assert!(
            challenge.contains("acr_values=\"a bb\""),
            "both classes have to reach the challenge: {challenge:?}"
        );
        assert!(
            challenge.contains("insufficient_user_authentication"),
            "RFC 9470 s3: {challenge:?}"
        );
    }
}
