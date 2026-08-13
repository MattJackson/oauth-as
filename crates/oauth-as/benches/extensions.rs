// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The optional features, each measured only when its own cargo feature is on.
//!
//! Everything here is OFF in a default build, so these rows are what a host BUYS by turning a
//! feature on, in time, on top of the core numbers in `benches/token.rs`. That is the shape a
//! feature decision actually has: not "is DPoP fast" but "what does DPoP add to a token request I
//! am already paying for".
//!
//! The most consequential row in this file is the opaque-versus-JWT pair. A host choosing between
//! them is choosing between paying an ES256 signature ONCE PER TOKEN ISSUED and paying an
//! introspection round trip ONCE PER PROTECTED REQUEST SERVED. Those are different units, and the
//! ratio between how often each happens is the deployment's own; what this file can supply is the
//! two per-operation costs, so the arithmetic can be done on numbers instead of on instinct.
//!
//! Run with `cargo bench -p oauth-as --all-features --bench extensions` to get every row. With no
//! optional feature enabled every block below compiles out, so the target SAYS that in one line
//! rather than exiting silently on an empty table: a bench that prints nothing is
//! indistinguishable from a bench that failed to run.

#[path = "harness/mod.rs"]
mod harness;

#[cfg(all(
    feature = "jwt-p256",
    any(feature = "dpop", feature = "client-assertion")
))]
use std::time::{SystemTime, UNIX_EPOCH};

/// The crate's built-in ES256 backend. Verification goes through the `Es256Verifier` seam, so a
/// verifier is a per-call argument; this is the one a consumer who enables `jwt-p256` gets by
/// default, which is what keeps these benchmarks measuring what they always measured.
#[cfg(all(
    feature = "jwt-p256",
    any(feature = "dpop", feature = "client-assertion")
))]
const VERIFIER: &oauth_as::jwt::P256Verifier = &oauth_as::jwt::P256Verifier;

#[cfg(all(
    feature = "jwt-p256",
    any(feature = "dpop", feature = "client-assertion")
))]
fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

fn main() {
    harness::print_environment();
    #[allow(unused_mut)]
    let mut b = harness::Bench::from_args("optional features");

    // ==================================================================== RFC 9068 JWT access tokens
    #[cfg(feature = "jwt-p256")]
    {
        use oauth_as::jwt::{compact_jws, AccessTokenFormat, EcdsaP256Key, JwtConfig};
        use oauth_as::{
            AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ScopeSet,
            ServerConfig, TokenRequest,
        };

        const SECRET: &str = "a-high-entropy-registered-client-secret";
        fn client() -> Client {
            Client {
                client_id: ClientId::new("confidential-app"),
                auth: ClientAuth::ConfidentialSecret {
                    secret: SECRET.to_string(),
                },
                grant_types: vec![GrantType::ClientCredentials],
                redirect_uris: vec![],
                allowed_scopes: ScopeSet::parse("read write").unwrap(),
                default_scopes: ScopeSet::parse("read").unwrap(),
                name: None,
                registration: None,
            }
        }

        let rt = harness::runtime();

        // The primitive: one ES256 signature over a realistic signing input, with the base64url
        // encoding and the compact serialization included, because that is what an issuer actually
        // executes. Nothing here touches storage.
        let key = EcdsaP256Key::generate("bench-kid");
        let header = br#"{"alg":"ES256","typ":"at+jwt","kid":"bench-kid"}"#;
        let payload = br#"{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","exp":1900000000,"iat":1899996400,"jti":"0123456789abcdef0123456789abcdef","client_id":"confidential-app","scope":"read"}"#;
        b.bench_fast("es256_sign_compact_jws", || {
            compact_jws(header, payload, |input| {
                key.sign_signing_input(input).expect("sign")
            })
        });

        // THE COMPARISON. Same grant, same client, same store: the only difference is the format
        // of the access token this server hands back.
        let opaque_srv = rt.block_on(async {
            let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
            let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
            srv.register_client(client()).await.unwrap();
            srv
        });
        let jwt_srv = rt.block_on(async {
            let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
            cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(
                JwtConfig::new(EcdsaP256Key::generate("bench-kid"), "https://rs.example")
                    .with_jwks_uri("https://as.example/jwks"),
            ));
            let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
            srv.register_client(client()).await.unwrap();
            srv
        });
        let request = || TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        };
        b.bench_fast("issue_token_opaque", || {
            rt.block_on(opaque_srv.token(request()))
        });
        b.bench_fast("issue_token_rfc9068_jwt", || {
            rt.block_on(jwt_srv.token(request()))
        });

        // The other half of the trade: what a resource server does INSTEAD of introspecting. The
        // JWKS document is what it fetches (once, then caches) to be able to verify locally.
        b.bench_fast("jwks_document", || jwt_srv.jwks());
    }

    // ================================================================================ RFC 9449 DPoP
    #[cfg(all(feature = "dpop", feature = "jwt-p256"))]
    {
        use oauth_as::dpop::{verify_proof, DpopFailure};
        use oauth_as::jwt::{compact_jws, EcdsaP256Key};

        const HTM: &str = "POST";
        const HTU: &str = "https://as.example/token";

        // `now` is captured ONCE and passed to every verification, so the proof never ages out
        // mid-run. A bench whose input expires partway through stops measuring the success path
        // and starts measuring the refusal path, which is a different number wearing the same name.
        let now = SystemTime::now();
        let key = EcdsaP256Key::generate("device-key");
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
        });
        let claims = serde_json::json!({
            "jti": "proof-0001",
            "htm": HTM,
            "htu": HTU,
            "iat": secs(now),
        });
        let proof = compact_jws(
            &serde_json::to_vec(&header).unwrap(),
            &serde_json::to_vec(&claims).unwrap(),
            |input| key.sign_signing_input(input).unwrap(),
        );
        assert!(
            verify_proof(VERIFIER, &proof, HTM, HTU, now).is_ok(),
            "the fixture proof must verify, or this row measures a refusal"
        );

        // The verification is an ES256 SIGNATURE VERIFY, which is the expensive half of the curve
        // (verify is roughly twice sign on P-256), and a resource server that requires DPoP pays it
        // on every request. That makes this row the single most consequential number in the file
        // for a DPoP deployment.
        b.bench_fast("dpop_verify_proof", || {
            verify_proof(VERIFIER, &proof, HTM, HTU, now)
        });

        // The refusal, driven by an attacker who has no key. TWO of them, because they are not
        // the same cost and conflating them would misreport what a garbage proof buys an attacker:
        //
        //   * MALFORMED: the proof is not even three base64url segments, so it is rejected by the
        //     parser before any curve arithmetic happens.
        //   * WELL FORMED, WRONG SIGNATURE: everything parses, the embedded JWK is a real key, and
        //     the ES256 verification runs to completion and fails. This one costs a full verify.
        //
        // The tampering is done INSIDE the signature segment rather than at the end of the string,
        // and it is done to a character that stays inside the base64url alphabet. Flipping the
        // final character (which the first draft of this file did) sometimes produced non-canonical
        // trailing bits and so sometimes failed in the decoder instead, which made this row report
        // 774 ns on one run and 135 us on the next. A benchmark whose answer depends on a random
        // key is not measuring the code.
        let malformed = "not.a.proof";
        let wrong_signature = {
            let (head, sig) = proof
                .rsplit_once('.')
                .expect("compact JWS has three segments");
            let mut sig: Vec<char> = sig.chars().collect();
            sig[10] = if sig[10] == 'a' { 'b' } else { 'a' };
            format!("{head}.{}", sig.into_iter().collect::<String>())
        };
        //
        // Both refusals are PINNED TO THEIR REASON, for the same reason the happy path above is
        // pinned to its success. A refusal fixture that starts failing EARLIER than intended
        // (a `typ` this crate stops recognising, a size cap that now catches the fixture) still
        // refuses, so the row still runs, and it silently reports the cost of a path nobody meant
        // to measure. These two rows exist precisely to be compared against each other, so the
        // one that must cost a full ES256 verify has to be the one that actually ran one.
        assert_eq!(
            verify_proof(VERIFIER, malformed, HTM, HTU, now),
            Err(DpopFailure::Malformed),
            "this row must measure the PARSER refusing, before any curve arithmetic"
        );
        assert_eq!(
            verify_proof(VERIFIER, &wrong_signature, HTM, HTU, now),
            Err(DpopFailure::BadSignature),
            "this row must measure a COMPLETED ES256 verification that failed, not an earlier              refusal that skipped it"
        );
        b.bench_fast("dpop_verify_proof_malformed", || {
            verify_proof(VERIFIER, malformed, HTM, HTU, now)
        });
        b.bench_fast("dpop_verify_proof_bad_signature", || {
            verify_proof(VERIFIER, &wrong_signature, HTM, HTU, now)
        });
    }

    // ====================================================================== RFC 7523 client assertion
    #[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
    {
        use oauth_as::client_assertion::{verify_assertion, AssertionKeys, ClientSecretKey};
        use oauth_as::jwt::{compact_jws, hmac_sha256, EcdsaP256Key};

        const CLIENT: &str = "assertion-client";
        const TOKEN_ENDPOINT: &str = "https://as.example/token";
        const ISSUER: &str = "https://as.example";
        const SECRET: &str = "a-high-entropy-registered-client-secret";

        let now = SystemTime::now();
        let audiences = [TOKEN_ENDPOINT, ISSUER];
        let claims = serde_json::json!({
            "iss": CLIENT,
            "sub": CLIENT,
            "aud": TOKEN_ENDPOINT,
            "exp": secs(now) + 120,
            "iat": secs(now),
            "jti": "assertion-0001",
        });
        let claims_bytes = serde_json::to_vec(&claims).unwrap();

        // client_secret_jwt: HMAC-SHA-256, symmetric, cheap.
        let hs_keys = AssertionKeys::ClientSecret {
            secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the entropy floor"),
        };
        let hs = compact_jws(br#"{"alg":"HS256","typ":"JWT"}"#, &claims_bytes, |input| {
            hmac_sha256(SECRET.as_bytes(), input.as_bytes()).to_vec()
        });
        assert!(
            verify_assertion(Some(VERIFIER), &hs_keys, &hs, CLIENT, &audiences, now).is_ok(),
            "the HS256 fixture must verify"
        );
        b.bench_fast("client_secret_jwt_hs256_verify", || {
            verify_assertion(Some(VERIFIER), &hs_keys, &hs, CLIENT, &audiences, now)
        });

        // private_key_jwt: ES256, asymmetric, and the reason a deployment whose policy forbids
        // transmitting a shared secret can use this crate at all. Measured next to HS256 so the
        // price of that policy is a number rather than a feeling.
        let key = EcdsaP256Key::generate("client-key-1");
        let es_keys = AssertionKeys::PublicKeys {
            keys: vec![key.to_public_jwk()],
        };
        let es = compact_jws(br#"{"alg":"ES256","typ":"JWT"}"#, &claims_bytes, |input| {
            key.sign_signing_input(input).unwrap()
        });
        assert!(
            verify_assertion(Some(VERIFIER), &es_keys, &es, CLIENT, &audiences, now).is_ok(),
            "the ES256 fixture must verify"
        );
        b.bench_fast("private_key_jwt_es256_verify", || {
            verify_assertion(Some(VERIFIER), &es_keys, &es, CLIENT, &audiences, now)
        });
    }

    // ================================================================================= RFC 9126 PAR
    #[cfg(feature = "par")]
    {
        use oauth_as::{
            AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ParConfig,
            ScopeSet, ServerConfig,
        };

        const SECRET: &str = "a-high-entropy-registered-client-secret";
        let rt = harness::runtime();
        let srv = rt.block_on(async {
            let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
            cfg.par = Some(Box::new(ParConfig::new()));
            let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
            srv.register_client(Client {
                client_id: ClientId::new("par-app"),
                auth: ClientAuth::ConfidentialSecret {
                    secret: SECRET.to_string(),
                },
                grant_types: vec![GrantType::AuthorizationCode],
                redirect_uris: vec!["https://app.example/cb".to_string()],
                allowed_scopes: ScopeSet::parse("read write").unwrap(),
                default_scopes: ScopeSet::parse("read").unwrap(),
                name: None,
                registration: None,
            })
            .await
            .unwrap();
            srv
        });
        let challenge =
            oauth_as::pkce::code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        fn params(challenge: &str) -> Vec<(&str, &str)> {
            vec![
                ("response_type", "code"),
                ("client_id", "par-app"),
                ("redirect_uri", "https://app.example/cb"),
                ("scope", "read"),
                ("state", "opaque-state"),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
            ]
        }

        // The PUSH: a back-channel POST that validates the whole authorization request and stores
        // it behind a handle.
        b.bench_fast("par_push", || {
            rt.block_on(srv.pushed_authorization_request(
                &ClientId::new("par-app"),
                Some(SECRET),
                &params(&challenge),
            ))
        });

        // The REDEMPTION of the handle at the authorization endpoint. Single use by RFC 9126 s2.2,
        // so it needs a fresh push per iteration, minted outside the clock.
        b.bench_with(
            "par_redeem_request_uri",
            || {
                rt.block_on(srv.pushed_authorization_request(
                    &ClientId::new("par-app"),
                    Some(SECRET),
                    &params(&challenge),
                ))
                .expect("push")
                .request_uri
            },
            // `.is_ok()` rather than returning the `Result`: `AuthorizationError` is a large
            // enum and clippy's `result_large_err` fires on a closure that returns one. Nothing
            // is measured away by this. The whole call runs and the whole value is dropped, both
            // inside the clock; only the discriminant leaves the closure.
            |request_uri| {
                rt.block_on(srv.validate_pushed_authorization_request("par-app", &request_uri))
                    .is_ok()
            },
        );
    }

    // ================================================================== RFC 9396 authorization details
    //
    // The SCALING of these two is in benches/scaling.rs, where it belongs (they are the pair whose
    // cost is bounded by a cap rather than by an algorithm). What is here is the single-element
    // cost, so it can be compared against the endpoints that call it.
    #[cfg(feature = "rar")]
    {
        use oauth_as::AuthorizationDetails;
        let raw = r#"[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://rs.example"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]"#;
        b.bench_fast("rar_parse_one_element", || AuthorizationDetails::parse(raw));
        let granted = AuthorizationDetails::parse(raw).expect("fixture parses");
        b.bench_fast("rar_narrow_one_element", || granted.narrow(&granted));
    }

    // ================================================================ RFC 8705 certificate thumbprint
    #[cfg(feature = "mtls")]
    {
        use oauth_as::CertificateThumbprint;
        // A DER blob of roughly the size of a real client certificate. RFC 8705 s3.1 defines
        // exactly one piece of arithmetic on it, the SHA-256 thumbprint, and that is what a host
        // pays per mTLS-authenticated request.
        let der = vec![0x42u8; 1200];
        b.bench_fast("mtls_certificate_thumbprint", || {
            CertificateThumbprint::from_der(&der)
        });
    }

    b.finish();
    if b.measured_nothing() {
        println!();
        println!("== optional features ==");
        println!(
            "   nothing measured: every row in this target is behind an optional cargo feature \
             and none is enabled."
        );
        println!("   cargo bench -p oauth-as --all-features --bench extensions");
    }
}
