// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The FAPI 2.0 Security Profile conformance FIXTURE: an HTTPS authorization server plus a
//! DPoP-verifying protected resource, built so the OpenID Foundation FAPI 2.0 Security Profile
//! suite (`openid=plain_oauth`, `client_auth_type=private_key_jwt`, `sender_constrain=dpop`,
//! `fapi_profile=plain_fapi`) can drive it HEADLESS to green.
//!
//! Read `crates/oauth-as-conformance/EXTERNAL-TOOLING.md` §2.2 and §2.3 first: items 1-8 there are
//! the requirement list this file answers, each with its spec citation. What this fixture is, and
//! is NOT, is the same distinction `conformance_server.rs` and `protected_resource_fixture.rs`
//! draw, and for the same reason: it turns off protections a real authorization server must have,
//! because the suite is not a browser, and it does so BY NAME at each wiring site so copying one is
//! a deliberate act rather than an accident. Do not copy them into production.
//!
//! # What this fixture does, mapped to the §2.3 list
//!
//! 1. **A DPoP-verifying protected resource** (§2.3 item 1, FAPI2-SP-FINAL-5.3.4-2). `/resource`
//!    returns JSON ONLY for an access token that is (a) a validly signed RFC 9068 `at+jwt`, and
//!    (b) sender-constrained: the request must carry a DPoP proof whose key thumbprint equals the
//!    token's `cnf.jkt` and whose `ath` equals the SHA-256 of the presented token, and (c) fresh:
//!    the proof's `jti` must not have been used before (RFC 9449 s11.1), so a replayed proof is
//!    rejected. That is strictly more than the RFC 9728 fixture, which validates no token at all.
//! 2. **HTTPS with a self-signed certificate** (§2.2, §2.3 item 2). The suite trusts all server
//!    certificates and skips hostname verification, so a certificate generated at boot is enough;
//!    FAPI 2.0 s5.3.2.2-8 forbids the `http` scheme off-loopback, which is why this fixture, unlike
//!    the others, owns a TLS listener.
//! 3. **Two static clients with DISTINCT `private_key_jwt` keys** (§2.3 item 3). `client` and
//!    `client2`, each registering its own public JWKS; the suite holds the matching private key and
//!    signs its client assertions with it.
//! 4. **PAR mandatory + the metadata flags** (§2.3 items 4, 5, 8). `require_pushed_authorization_requests`
//!    is `true`, the `pushed_authorization_request_endpoint` is advertised and routed, and
//!    `authorization_response_iss_parameter_supported` is `true` (the library always emits it).
//! 5. **Two hard numbers** (§2.3 item 6): the authorization code lifetime is 60s (s5.3.2.1-11's
//!    ceiling) and the PAR `request_uri` lifetime is 90s, well under the 600s ceiling (s5.3.2.2-12).
//! 6. **Refresh rotation OFF** (§2.3 item 7): `RefreshRotation::Reuse`, which FAPI 2.0 s5.3.2.1-9
//!    requires and which is a deliberate downgrade of this crate's default reuse detection, safe
//!    here ONLY because every token is DPoP sender-constrained.
//! 7. **A sign-in page IN FRONT of `/authorize`, with Approve and Deny** (§2.3; FINDINGS.md D2).
//!    Every request is the same user, but no authorization request is decided until someone presses
//!    a button: the first `GET /authorize` of a request is answered with this fixture's own page and
//!    never reaches the library, so a PAR `request_uri` is not consumed by merely loading the page
//!    (FAPI 2.0 SP Final s5.3.2.2 NOTE 3: one-time use is enforced "at the point of authorization").
//!    The button's answer rides a one-shot cookie back to `/authorize`, where the approval resolver
//!    turns it into `Approve` or `Deny` (RFC 6749 s4.1.2.1 `access_denied`). The suite's headless
//!    browser presses the buttons from `crates/oauth-as-conformance/fapi2/config.json`, including a
//!    per-module `override` that presses Deny for the user-rejects module.
//! 8. **Client-assertion `aud` = the issuer, as a string** (FAPI 2.0 s5.3.2.1-8, s5.3.3.1-5;
//!    FINDINGS.md D4). `AssertionAudience::IssuerOnly` refuses the token endpoint URL and any array
//!    `aud` on `private_key_jwt` client authentication assertions, at PAR and the token endpoint
//!    alike.
//!
//! # Environment
//!
//! * `OAUTH_AS_ADDR` (default `127.0.0.1:8443`): the address to bind. `localhost.emobix.co.uk`, the
//!   suite's default base host, resolves to `127.0.0.1`, so loopback is reachable under that name.
//! * `OAUTH_AS_ISSUER` (default `https://localhost.emobix.co.uk:8443`): the RFC 8414 `issuer`. It
//!   MUST equal the URL the metadata document is fetched from (RFC 8414 s3.3), so for the default
//!   suite deployment leave it at the default; override it only if you moved the suite's base URL.
//! * `OAUTH_AS_FAPI_REDIRECT_URIS` (default `https://localhost.emobix.co.uk:8443/test/a/oauth-as/callback`):
//!   comma-separated redirect URIs for `client`. FAPI 2.0 requires exact redirect URI matching, so
//!   this must equal `client.redirect_uri` in the suite configuration. `client2` is registered with
//!   these same URIs plus a `?dummy1=lorem&dummy2=ipsum` query component, because the happy-flow's
//!   second-client leg exercises exact matching on a query-carrying redirect URI and requires the
//!   AS to accept it; the config side and this side are matched together, exactly as the keys are.
//! * `OAUTH_AS_RESOURCE` (default `{issuer}/resource`): the `resource.resourceUrl` the suite calls
//!   with a DPoP-bound token. It is a route on THIS listener, so its DPoP `htu` is this URL.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::client_assertion::AssertionKeys;
use oauth_as::dpop::{self, verify_proof};
use oauth_as::grant::GrantType;
use oauth_as::http::{ApprovalDecision, ServiceBuilder};
use oauth_as::jwt::{
    AccessTokenFormat, CompactJws, EcdsaP256Key, Jwk, JwsAlg, JwsVerifiers, JwtConfig, P256Verifier,
};
use oauth_as::par::ParConfig;
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AssertionAudience, AuthorizationServer, RefreshRotation, ServerConfig};
use oauth_as::store::MemoryStorage;
use sha2::{Digest, Sha256};

// #############################################################################
// # CONFORMANCE FIXTURE ONLY. NEVER COPY ANY OF THIS INTO A PRODUCTION HOST.   #
// #############################################################################

/// The two client identifiers the suite's `@ConfigurationFields` name (`client.client_id`,
/// `client2.client_id`); EXTERNAL-TOOLING.md §2.3 item 3.
const CLIENT_ID: &str = "client";
const CLIENT2_ID: &str = "client2";

/// The subject every approval acts as. There is one user and the sign-in page asks for no
/// password: the suite tests the authorization server, not a login system.
const SEEDED_SUBJECT: &str = "fapi-conformance-user";

/// The one-shot cookie that carries the sign-in page's answer (`approve` or `deny`) back to
/// `/authorize`. See `login_gate`.
const DECISION_COOKIE: &str = "fixture_decision";

/// The kid of the AS access-token signing key, published in the JWKS and in every token header.
const AS_SIGNING_KID: &str = "fapi-as-es256-1";

/// ############################################################################
/// # CONFORMANCE FIXTURE ONLY. NEVER COPY THIS INTO A PRODUCTION HOST.        #
/// ############################################################################
///
/// The AS access-token ES256 signing key, as a raw P-256 private scalar. HARD-CODED for the same
/// reason `conformance_server.rs` hard-codes RFC 7515 A.3: a conformance fixture must be
/// REPRODUCIBLE, so a failure can be diagnosed against the same key that produced it. A hard-coded
/// signing key in production is catastrophic — it is the one secret that decides which access
/// tokens the whole deployment believes — and this fixture is never published as a binary. A real
/// host loads its key from a KMS or a sealed secret.
const AS_SIGNING_SCALAR: [u8; 32] = [
    0x7f, 0x3e, 0x11, 0x9a, 0x22, 0xc4, 0x58, 0x0d, 0x91, 0x6b, 0x2f, 0xa7, 0x5c, 0x38, 0xe0, 0x4b,
    0xd1, 0x0c, 0x66, 0x9e, 0x81, 0x24, 0x37, 0xb5, 0x40, 0xaa, 0x1d, 0x72, 0x93, 0x58, 0xcf, 0x6a,
];

/// ############################################################################
/// # CONFORMANCE FIXTURE ONLY. NEVER COPY THESE INTO A PRODUCTION HOST.       #
/// ############################################################################
///
/// The two `private_key_jwt` CLIENT keys, as raw P-256 private scalars. These are the private
/// halves the SUITE signs its client assertions with; this fixture registers only the PUBLIC half
/// of each (see `assertion_keys_for`). They are hard-coded, and DISTINCT per client, so the two
/// public JWKS this fixture prints at boot are reproducible and the suite configuration can be
/// matched to them once and left. In a real registration the client generates its own key and the
/// AS only ever sees the public JWK.
const CLIENT_KEY_SCALAR: [u8; 32] = [
    0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x02,
    0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x03,
];
const CLIENT2_KEY_SCALAR: [u8; 32] = [
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f, 0x1e, 0x2d, 0x3c,
    0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x0a, 0x1b, 0x2c, 0x3d,
];
const CLIENT_KEY_KID: &str = "client-pkjwt-1";
const CLIENT2_KEY_KID: &str = "client2-pkjwt-1";

/// The FAPI `request_uri` handle lifetime: 90 seconds, comfortably under the 600 second ceiling of
/// FAPI 2.0 s5.3.2.2-12. EXTERNAL-TOOLING.md §2.3 item 6.
const REQUEST_URI_TTL_SECS: u64 = 90;

/// State the protected resource needs to verify a DPoP-bound token.
struct ResourceState {
    /// The PUBLIC half of the AS signing key: what verifies the `at+jwt` signature.
    as_public_jwk: Jwk,
    /// The RFC 8414 `issuer`, checked against the token's `iss`.
    issuer: String,
    /// The resource identifier, which is both this endpoint's URL (the DPoP `htu`) and the value
    /// the token's `aud` must carry.
    resource_url: String,
    /// The DPoP proof `jti`s this resource has already accepted, so a REPLAYED proof (RFC 9449
    /// s11.1) is refused rather than honoured a second time.
    ///
    /// ############################################################################
    /// # CONFORMANCE FIXTURE ONLY. NEVER COPY THIS INTO A PRODUCTION HOST.        #
    /// ############################################################################
    ///
    /// A plain in-memory `HashSet` behind a `Mutex`, which is enough BECAUSE this is a fixture: one
    /// process, one resource, a short conformance run. It grows without bound and is not shared
    /// across replicas, neither of which matters for a headless suite that sends a bounded number of
    /// requests. A real resource server bounds the set by the proof's own `iat` window (the same
    /// bound RFC 9449 s11.1 names) and shares it across every node that could see a replay — exactly
    /// what `oauth_as`'s own `claim_replay_id` seam does for RFC 7523 assertion `jti`s. The library
    /// deliberately owns no replay store for a resource server it does not run, so the fixture holds
    /// its own here rather than pretending the AS could do it.
    seen_proof_jtis: Mutex<HashSet<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The `ring` crypto provider for rustls, installed explicitly so no `aws-lc-rs` C toolchain is
    // pulled in: `ring` is already in this workspace and `p256` (the crate's own backend) is pure
    // Rust, so the fixture keeps that property. `ok()` because a second install is a no-op.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = std::env::var("OAUTH_AS_ADDR").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
    let issuer = std::env::var("OAUTH_AS_ISSUER")
        .unwrap_or_else(|_| "https://localhost.emobix.co.uk:8443".to_string());
    let issuer = issuer.trim_end_matches('/').to_string();
    let redirect_uris: Vec<String> = std::env::var("OAUTH_AS_FAPI_REDIRECT_URIS")
        .unwrap_or_else(|_| format!("{issuer}/test/a/oauth-as/callback"))
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let resource_url =
        std::env::var("OAUTH_AS_RESOURCE").unwrap_or_else(|_| format!("{issuer}/resource"));

    // A device verification URI is required by the constructor even though the device grant is not
    // part of a FAPI 2.0 run; it is under the issuer so the router serves it.
    let verification_uri = format!("{issuer}/device");
    let mut config = ServerConfig::new(issuer.clone(), verification_uri);

    // RFC 8414 `scopes_supported`. A superset the suite can pick `client.scope` from; the clients
    // below are registered for the same set so the two documents agree.
    let scope_names = [
        "openid",
        "profile",
        "email",
        "read",
        "write",
        "offline_access",
    ];
    config.scopes_supported = Some(scope_names.iter().map(|s| s.to_string()).collect());

    // (§2.3 item 6) FAPI 2.0 s5.3.2.1-11: the authorization code lives at most 60 seconds. This is
    // the crate default, set explicitly so the number is visible next to its citation.
    config.authorization_code_ttl = std::time::Duration::from_secs(60);

    // (§2.3 items 4, 8) RFC 9126 PAR, made MANDATORY: FAPI 2.0 s5.3.2.2-3 requires the AS to reject
    // any authorization request not sent via PAR. With `require_pushed_authorization_requests` true
    // the metadata document advertises the flag as a boolean and the endpoint, and
    // `validate_authorization_request` answers `invalid_request` for a query-parameter request.
    let mut par = ParConfig::new();
    par.require_pushed_authorization_requests = true;
    // (FINDINGS.md D6 / FAPI2-SP-FINAL-5.3.2.2 clause 6) the AS shall require `redirect_uri` in
    // pushed authorization requests. `require_redirect_uri` overrides the RFC 6749 s3.1.2.3
    // single-registered-URI fallback for the PAR push path, so a push omitting `redirect_uri` is
    // rejected `invalid_request` rather than silently defaulted. This is what flips
    // `ensure-request-object-without-redirect-uri-fails` to PASS.
    par.require_redirect_uri = true;
    // (§2.3 item 6) the `request_uri` handle expiry, 90s < 600s (s5.3.2.2-12).
    par.request_uri_ttl = std::time::Duration::from_secs(REQUEST_URI_TTL_SECS);
    config.par = Some(Box::new(par));

    // (§2.3 item 1 / FAPI2-SP-FINAL-5.3.4-2) RFC 9449: EVERY token request must carry a DPoP proof,
    // so every access token this server issues is sender-constrained and carries `cnf.jkt`.
    config.require_dpop = true;

    // (§2.3 item 7) FAPI 2.0 s5.3.2.1-9 forbids refresh token rotation. `RefreshRotation::Reuse` is
    // a DELIBERATE downgrade of this crate's default reuse detection (OAuth 2.1 s6.1 / RFC 9700
    // s4.14.2), and is only sound here because tokens are DPoP sender-constrained above.
    config = config.with_refresh_rotation(RefreshRotation::Reuse);

    // (§2.3 item 8 / FAPI2-SP-FINAL-5.3.2.1-8) FAPI 2.0 s5.3.2.1-8 and s5.3.3.1-5: a client
    // authentication assertion's `aud` must be the issuer identifier AS A STRING — the token
    // endpoint URL is refused and an array is refused even when it carries the issuer.
    // `AssertionAudience::IssuerOnly` is that tightening of RFC 7523 s3 (3); it is what flips the
    // FINDINGS.md D4 modules (par-test-token-endpoint-url-as-audience-fails,
    // par-test-array-as-audience-fails) to PASS.
    config = config.with_assertion_audience(AssertionAudience::IssuerOnly);

    // (§2.3 item 1) RFC 9068 `at+jwt` access tokens, signed with the fixture key, so the protected
    // resource can verify them offline against the advertised JWKS. `with_jwks_uri` is what makes
    // the metadata advertise `jwks_uri`, served by this router at `/jwks`. The token `aud` is the
    // resource URL, which the resource checks.
    let as_key = EcdsaP256Key::from_scalar_bytes(AS_SIGNING_KID, &AS_SIGNING_SCALAR)?;
    let as_public_jwk = as_key.public_jwk();
    let jwks_uri = format!("{issuer}/jwks");
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(
        JwtConfig::new(as_key, resource_url.clone()).with_jwks_uri(jwks_uri),
    ));

    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));

    // (§2.3 item 3) the two static `private_key_jwt` clients, each with its own public key.
    // FAPI 2.0 mandates EXACT redirect-URI matching, and the suite tests that on a URI that carries
    // a query component: the happy-flow's second-client leg registers/uses client2 with client's
    // redirect URI plus `?dummy1=lorem&dummy2=ipsum` and requires the AS to accept it (PAR -> 201).
    // So client2 must be registered with exactly that query-carrying variant, or its PAR is
    // (correctly) rejected with `invalid_request: redirect_uri does not exactly match`.
    let client2_redirect_uris: Vec<String> = redirect_uris
        .iter()
        .map(|u| format!("{u}?dummy1=lorem&dummy2=ipsum"))
        .collect();
    register_client(
        &server,
        CLIENT_ID,
        &redirect_uris,
        &scope_names,
        client_keys(),
    )
    .await?;
    register_client(
        &server,
        CLIENT2_ID,
        &client2_redirect_uris,
        &scope_names,
        client2_keys(),
    )
    .await?;

    // ############################################################################
    // # CONFORMANCE FIXTURE ONLY. NEVER COPY ANY OF THIS INTO A PRODUCTION HOST.  #
    // ############################################################################
    //
    // The suite drives this AS with an HTTP client and a headless HtmlUnit browser that follows a
    // scripted task list. This fixture opts IN BY NAME to shortcuts a real AS must NEVER take:
    //
    // * `with_subject_resolver` returning a constant: every request is the same user, and the
    //   sign-in page has no password. A real host reads its own authenticated session.
    // * The approval answer rides a bare cookie set by `/fixture/login`, with no CSRF token and no
    //   binding to the request it answers beyond being one-shot. A real host binds the answer to
    //   the user's session and to this exact request, and protects the form against CSRF.
    //
    // The approval itself is NOT automatic any more: `login_gate` answers the first visit with a
    // sign-in page, and only a request carrying that page's answer reaches the library. The
    // resolver reads the answer; anything but an explicit `approve` is a refusal.
    let builder = ServiceBuilder::new(Arc::clone(&server))
        .with_subject_resolver(|_headers| Some(SEEDED_SUBJECT.to_string()))
        .with_approval_resolver(|request| match decision_cookie(request.headers) {
            Some("approve") => ApprovalDecision::Approve,
            _ => ApprovalDecision::Deny,
        });

    // The library hands back a framework-free service; the adapter puts it on axum. The protected
    // resource is one more route on the SAME origin, so its DPoP `htu` is under the issuer.
    let rs_state = Arc::new(ResourceState {
        as_public_jwk,
        issuer: issuer.clone(),
        resource_url: resource_url.clone(),
        seen_proof_jtis: Mutex::new(HashSet::new()),
    });
    let resource_path = path_of(&resource_url, &issuer);
    // The resource is its own `Router<()>` (its state baked in with `with_state`) so it MERGES onto
    // the library's `Router<()>`: both share the empty outer state, and the resource's DPoP checks
    // read the `ResourceState` closed over here rather than an axum state parameter the library
    // routes would also have to carry.
    let resource_router = Router::new()
        .route(&resource_path, get(protected_resource))
        .with_state(rs_state);
    let router = axum::Router::from(builder.build()?)
        .merge(resource_router)
        .route("/fixture/login", post(fixture_login))
        // CONFORMANCE FIXTURE ONLY: render a rejected authorization request as an HTML error page
        // so the suite's headless browser can screenshot it. See `authorization_errors_as_html`.
        .layer(axum::middleware::from_fn(authorization_errors_as_html))
        // Outermost, so an undecided `GET /authorize` never reaches the library. See `login_gate`.
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(LoginGate::default()),
            login_gate,
        ));

    print_boot_banner(&issuer, &resource_url, &redirect_uris);

    // (§2.2 / §2.3 item 2) HTTPS. The suite's *condition* HTTP client trusts all certificates, but
    // its HtmlUnit BROWSER does NOT (it uses the JVM default trust store), so the browser-driven
    // authorization leg needs a certificate the suite's JVM trusts. When OAUTH_AS_TLS_CERT and
    // OAUTH_AS_TLS_KEY are set (the conformance harness generates a private CA, signs this leaf with
    // it, and imports the CA into the suite container's trust store), serve that CA-signed pair;
    // otherwise fall back to a boot self-signed certificate for ad-hoc / condition-only use.
    let tls = match (
        std::env::var("OAUTH_AS_TLS_CERT").ok(),
        std::env::var("OAUTH_AS_TLS_KEY").ok(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            println!("FAPI 2.0 fixture: serving CA-signed TLS from {cert_path} / {key_path}");
            RustlsConfig::from_pem_file(cert_path, key_path).await?
        }
        _ => self_signed_tls(&issuer).await?,
    };
    let socket = addr.parse()?;
    println!("FAPI 2.0 fixture listening on https://{addr} (issuer {issuer})");
    axum_server::bind_rustls(socket, tls)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}

/// The two clients' `private_key_jwt` registrations. Separated so the boot banner and the
/// registration use the exact same key material.
fn client_keys() -> AssertionKeys {
    assertion_keys_for(CLIENT_KEY_KID, &CLIENT_KEY_SCALAR)
}
fn client2_keys() -> AssertionKeys {
    assertion_keys_for(CLIENT2_KEY_KID, &CLIENT2_KEY_SCALAR)
}

/// Build a `private_key_jwt` registration from a private scalar: derive the PUBLIC JWK and register
/// only that. The scalar itself never leaves this process; the suite holds its own copy.
fn assertion_keys_for(kid: &str, scalar: &[u8; 32]) -> AssertionKeys {
    let key = EcdsaP256Key::from_scalar_bytes(kid, scalar).expect("fixed 32-byte scalar is valid");
    AssertionKeys::PublicKeys {
        alg: JwsAlg::Es256,
        keys: vec![key.public_jwk()],
    }
}

/// Register one static `private_key_jwt` client for the authorization-code + refresh-token grants.
async fn register_client<S>(
    server: &AuthorizationServer<S>,
    client_id: &str,
    redirect_uris: &[String],
    scope_names: &[&str],
    keys: AssertionKeys,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: oauth_as::store::Storage,
{
    let scopes = ScopeSet::from_tokens(scope_names.iter().copied())?;
    server
        .register_client(Client {
            client_id: ClientId::new(client_id),
            auth: ClientAuth::ConfidentialAssertion { keys },
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: redirect_uris.to_vec(),
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: Some(format!("FAPI 2.0 conformance {client_id}")),
            registration: None,
        })
        .await?;
    Ok(())
}

/// The protected resource (§2.3 item 1, FAPI2-SP-FINAL-5.3.4-2): JSON ONLY for a valid DPoP-bound
/// access token.
///
/// This is the check `protected_resource_fixture.rs` deliberately does NOT make. The steps are the
/// resource-server half of RFC 9449 plus RFC 9068 token validation:
///
/// 1. The `Authorization` header is `DPoP <token>` (RFC 9449 s7.1), not `Bearer`.
/// 2. Exactly one `DPoP` proof header is present (RFC 9449 s4.3(1)).
/// 3. The token is a valid `at+jwt`: ES256 signature over the AS public key, unexpired, `iss` and
///    `aud` as expected (RFC 9068 s4).
/// 4. The proof verifies for THIS request line (`GET` + this URL) and is within its `iat` window
///    (`verify_proof`).
/// 5. The proof key thumbprint equals the token's `cnf.jkt` (RFC 9449 s6.1) — the binding itself.
/// 6. The proof's `ath` equals the base64url SHA-256 of the presented token (RFC 9449 s4.3(11)),
///    which `verify_proof` cannot check because it never sees the token.
/// 7. The proof's `jti` has not been seen before (RFC 9449 s11.1): a replayed proof is refused,
///    which `verify_proof` cannot enforce because it is stateless.
async fn protected_resource(
    State(state): State<Arc<ResourceState>>,
    headers: HeaderMap,
) -> Response {
    match verify_dpop_bound(&state, &headers) {
        Ok(subject) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            format!(
                "{{\"sub\":\"{}\",\"resource\":\"{}\",\"message\":\"FAPI 2.0 DPoP-bound access granted\"}}",
                subject, state.resource_url
            ),
        )
            .into_response(),
        Err(detail) => {
            // RFC 6750 s3 / RFC 9449 s7.1: a resource that refuses names the scheme it wants.
            (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    format!("DPoP error=\"invalid_token\", error_description=\"{detail}\""),
                )],
            )
                .into_response()
        }
    }
}

/// The verification body of [`protected_resource`], returning the token subject on success.
fn verify_dpop_bound(state: &ResourceState, headers: &HeaderMap) -> Result<String, &'static str> {
    // (1) `Authorization: DPoP <token>`.
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Authorization header")?;
    // The scheme is case-INSENSITIVE (RFC 9110 s11.1), so `DPoP`, `dpop` and `DPOP` are the same
    // credential; matching only the exact casing is what `access-token-type-header-case-sensitivity`
    // catches. Split off the scheme token and compare it without regard to case.
    let token = authz
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("DPoP"))
        .map(|(_, rest)| rest)
        .ok_or("Authorization is not a DPoP-bound credential (RFC 9449 s7.1)")?
        .trim();

    // (2) exactly one DPoP proof header.
    let mut proofs = headers.get_all(dpop::DPOP_HEADER).iter();
    let proof = proofs.next().ok_or("missing DPoP proof header")?;
    if proofs.next().is_some() {
        return Err("more than one DPoP header (RFC 9449 s4.3)");
    }
    let proof = proof.to_str().map_err(|_| "DPoP header is not ASCII")?;

    // (3) the token is a valid RFC 9068 at+jwt.
    let jws = CompactJws::parse(token).map_err(|_| "access token is not a compact JWS")?;
    if !oauth_as::jwt::verify_es256(
        &state.as_public_jwk,
        jws.signing_input.as_bytes(),
        &jws.signature,
    ) {
        return Err("access token signature does not verify");
    }
    let now = std::time::SystemTime::now();
    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock before epoch")?
        .as_secs();
    match jws.claim_time("exp") {
        Some(exp) if exp > now_secs => {}
        _ => return Err("access token is expired or has no exp"),
    }
    if jws.claim_str("iss") != Some(state.issuer.as_str()) {
        return Err("access token iss does not match this deployment");
    }
    if !audience_contains(&jws, &state.resource_url) {
        return Err("access token aud does not name this resource");
    }
    // (5, first half) the binding lives in cnf.jkt.
    let token_jkt = jws
        .payload
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(|j| j.as_str())
        .ok_or("access token is not sender-constrained (no cnf.jkt)")?;

    // (4) the proof verifies for GET on this resource, within its iat window. Phase A's DPoP seam
    // takes the installed verifier SET (the header carries the proof key, so the algorithm is read
    // off the header against the installed verifiers); this fixture installs the built-in ES256 one.
    let mut verifiers = JwsVerifiers::new();
    verifiers.install(Arc::new(P256Verifier));
    let verified = verify_proof(&verifiers, proof, "GET", &state.resource_url, now)
        .map_err(|_| "DPoP proof did not verify for this request")?;

    // (5, second half) the proof key IS the key the token is bound to.
    if verified.jkt != token_jkt {
        return Err("DPoP proof key does not match the token's cnf.jkt");
    }

    // (6) ath binds the proof to THIS token. verify_proof cannot check it (no token in a proof), so
    // the resource does.
    let proof_jws = CompactJws::parse(proof).map_err(|_| "DPoP proof is not a compact JWS")?;
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    match proof_jws.claim_str("ath") {
        Some(ath) if ath == expected_ath => {}
        _ => return Err("DPoP proof ath does not match the presented token (RFC 9449 s4.3(11))"),
    }

    // (7) SINGLE USE (RFC 9449 s11.1). A proof that verifies for this request line and binds this
    // token is still a bearer artifact until its `jti` is spent: anyone who captured it (a proxy
    // log, a mirrored request) could send it again. `verify_proof` cannot enforce this — it is
    // stateless and sees one proof — so the resource records each accepted `jti` and refuses a
    // repeat. `HashSet::insert` returns false when the value was already present, which is the
    // replay.
    let jti = proof_jws
        .claim_str("jti")
        .ok_or("DPoP proof has no jti, so single use cannot be enforced (RFC 9449 s4.2)")?;
    {
        let mut seen = state
            .seen_proof_jtis
            .lock()
            .map_err(|_| "resource replay set is poisoned")?;
        if !seen.insert(jti.to_string()) {
            return Err("DPoP proof jti has already been used (RFC 9449 s11.1 replay)");
        }
    }

    Ok(jws.claim_str("sub").unwrap_or(SEEDED_SUBJECT).to_string())
}

/// RFC 7519 s4.1.3 `aud` is either a string or an array of strings; accept either shape.
fn audience_contains(jws: &CompactJws<'_>, resource: &str) -> bool {
    match jws.payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == resource,
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(resource)),
        _ => false,
    }
}

/// The path portion of a URL under `issuer` (e.g. `https://host:8443/resource` -> `/resource`),
/// which is what axum routes on.
fn path_of(url: &str, issuer: &str) -> String {
    url.strip_prefix(issuer)
        .filter(|p| p.starts_with('/'))
        .unwrap_or("/resource")
        .to_string()
}

/// CONFORMANCE FIXTURE ONLY. Re-render a rejected authorization request as an HTML error page.
///
/// The library answers a rejected authorization request (a reused / expired / wrong-client
/// `request_uri`, or a request not sent via PAR) with a DIRECT `application/json` error body. That
/// is the correct machine-readable answer and RFC 6749 s4.1.2.1 forbids redirecting it to a
/// `redirect_uri` the server has not validated, so the library keeps it a direct response and this
/// fixture does NOT change that decision. But the suite drives `/authorize` with a headless HtmlUnit
/// browser, and HtmlUnit renders a JSON response as a non-HTML `TextPage` on which the suite's
/// `["wait","xpath","//*", …]` browser command finds no DOM, so the module's `ExpectXxxErrorPage`
/// placeholder never clears and the test hangs in WAITING until the plan timeout (FINDINGS.md D1). A
/// real browser-facing authorization endpoint shows an HTML error page; this fixture does the same,
/// but ONLY for a 4xx at `/authorize`, so the token, PAR, resource, and metadata endpoints keep the
/// exact JSON bytes the suite's HTTP client parses. The page carries the fixed literal "Authorization
/// error" that `crates/oauth-as-conformance/fapi2/config.json` waits for to fill the placeholder.
async fn authorization_errors_as_html(req: Request, next: Next) -> Response {
    let is_authorize = req.method() == Method::GET && req.uri().path() == "/authorize";
    let resp = next.run(req).await;
    if !is_authorize || !resp.status().is_client_error() {
        return resp;
    }
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        return resp;
    }

    let (mut parts, body) = resp.into_parts();
    let status = parts.status;
    // Buffer the library's JSON error body and report it FAITHFULLY: never invent an error code the
    // AS did not return, so a certification screenshot/log cannot misrepresent which check failed.
    // If the body cannot be read (oversized past the cap, or a stream error) or is not the expected
    // JSON, show what actually happened (the status, or the raw body) rather than a fabricated code.
    let (error, description) = match to_bytes(body, 64 * 1024).await {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => match value.get("error").and_then(|v| v.as_str()) {
                Some(error) => (
                    error.to_string(),
                    value
                        .get("error_description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
                // Valid JSON but not the `{"error":..}` shape: show it verbatim rather than a blank
                // code, so the page never misreports which check failed.
                None => (
                    format!("HTTP {}", status.as_u16()),
                    String::from_utf8_lossy(&bytes).into_owned(),
                ),
            },
            Err(_) => (
                format!("HTTP {}", status.as_u16()),
                String::from_utf8_lossy(&bytes).into_owned(),
            ),
        },
        Err(_) => (
            format!("HTTP {}", status.as_u16()),
            "the authorization endpoint error body could not be read".to_string(),
        ),
    };
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let (error, description) = (esc(&error), esc(&description));
    // "Authorization error" is the literal fapi2/config.json's browser task waits for; the error
    // code and description follow it so a certification reviewer's screenshot shows both.
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Authorization error</title></head><body>\
         <h1>Authorization error</h1>\
         <p>The authorization request was rejected.</p>\
         <p>error: {error}</p><p>{description}</p></body></html>"
    );
    parts
        .headers
        .insert(header::CONTENT_TYPE, html_content_type());
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(html))
}

/// CONFORMANCE FIXTURE ONLY. The `/authorize` URLs (path and query) the sign-in page has already
/// been shown for, so a second showing of the SAME request can say so.
///
/// This exists for one suite module and is test-automation scaffolding, not AS behaviour:
/// `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` visits the authorization
/// endpoint twice with one `request_uri` and requires that nobody signs in on the first visit
/// ("On the first visit no login should be attempted"). A person running it simply does nothing the
/// first time. The headless browser cannot tell the visits apart (the suite drives each visit from
/// its own browser thread), so a repeat showing adds a second approve button, `id="approve-revisit"`,
/// which that module's browser override clicks with the runner's `"optional"` flag: absent on the
/// first visit, so nothing is pressed; present on the second, so the user approves.
/// The AS treats both visits identically; what the module actually verifies -- that loading the page
/// did not consume the `request_uri` -- is decided by the library and by this gate keeping the
/// first visit away from it.
#[derive(Default)]
struct LoginGate {
    shown: Mutex<HashSet<String>>,
}

/// The answer the sign-in page recorded, if the request carries one.
fn decision_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().strip_prefix(DECISION_COOKIE)?.strip_prefix('='))
        .find(|v| matches!(*v, "approve" | "deny"))
}

/// CONFORMANCE FIXTURE ONLY. Answer an undecided `GET /authorize` with a sign-in page, and let a
/// decided one through to the library exactly once.
///
/// A real host does the same thing with its own login and consent UI: the library's docs on
/// `ApprovalDecision::Respond` say a host that sends a visitor to its login page "does it in front
/// of this service, where its session already lives". Keeping the first visit away from the library
/// is what keeps a PAR `request_uri` alive until the user has actually answered.
async fn login_gate(State(gate): State<Arc<LoginGate>>, req: Request, next: Next) -> Response {
    if req.method() != Method::GET || req.uri().path() != "/authorize" {
        return next.run(req).await;
    }
    if decision_cookie(req.headers()).is_some() {
        let mut resp = next.run(req).await;
        // One shot: the answer applies to this authorization request and no other.
        resp.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "fixture_decision=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            ),
        );
        return resp;
    }
    let target = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/authorize".to_string(), |pq| pq.as_str().to_string());
    let revisit = gate
        .shown
        .lock()
        .map(|mut shown| !shown.insert(target.clone()))
        .unwrap_or(false);
    sign_in_page(&target, revisit)
}

/// The sign-in page: one user, two buttons. `id="approve"` / `id="deny"` are what
/// `fapi2/config.json` presses.
fn sign_in_page(target: &str, revisit: bool) -> Response {
    let attr = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    };
    // A repeat showing carries a SECOND approve button with its own id. It submits exactly what
    // `id="approve"` does; it exists only so one suite module's browser override can press Approve
    // on the second visit and do nothing on the first (see `LoginGate`).
    let revisit_button = if revisit {
        " <button type=\"submit\" id=\"approve-revisit\" name=\"decision\" value=\"approve\">\
         Approve (this request was shown before)</button>"
    } else {
        ""
    };
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Sign in</title></head><body>\
         <h1>oauth-as FAPI 2.0 fixture: sign in</h1>\
         <p>Signed in as {SEEDED_SUBJECT}. Approve or deny this authorization request.</p>\
         <form method=\"post\" action=\"/fixture/login\">\
         <input type=\"hidden\" name=\"return_to\" value=\"{target}\">\
         <button type=\"submit\" id=\"approve\" name=\"decision\" value=\"approve\">Approve</button> \
         <button type=\"submit\" id=\"deny\" name=\"decision\" value=\"deny\">Deny</button>{revisit_button}\
         </form></body></html>",
        target = attr(target),
    );
    let mut resp = Response::new(Body::from(html));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, html_content_type());
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// CONFORMANCE FIXTURE ONLY. The sign-in page's form target: record the answer in the one-shot
/// cookie and send the browser back to the same authorization request.
async fn fixture_login(body: axum::body::Bytes) -> Response {
    let (mut decision, mut return_to) = (None, None);
    for (k, v) in url::form_urlencoded::parse(&body) {
        match k.as_ref() {
            "decision" => decision = Some(v.into_owned()),
            "return_to" => return_to = Some(v.into_owned()),
            _ => {}
        }
    }
    let decision = match decision.as_deref() {
        Some("approve") => "approve",
        Some("deny") => "deny",
        _ => return (StatusCode::BAD_REQUEST, "decision must be approve or deny").into_response(),
    };
    // Only ever back to this server's own authorization endpoint: never an open redirect.
    let location = match return_to
        .filter(|r| r.starts_with("/authorize?"))
        .and_then(|r| HeaderValue::from_str(&r).ok())
    {
        Some(location) => location,
        None => {
            return (StatusCode::BAD_REQUEST, "return_to must be /authorize?...").into_response()
        }
    };
    let cookie = HeaderValue::from_str(&format!(
        "{DECISION_COOKIE}={decision}; Path=/; Secure; HttpOnly; SameSite=Lax"
    ))
    .expect("a fixed ASCII cookie is a valid header value");
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(header::LOCATION, location);
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    resp
}

/// The `Content-Type` for the fixture's HTML error page (mirrors the library's own value).
fn html_content_type() -> HeaderValue {
    HeaderValue::from_static("text/html;charset=UTF-8")
}

/// Generate a self-signed certificate at boot and build the rustls server config from its PEM.
/// §2.2: the suite trusts all certificates, so this needs no CA. `RustlsConfig::from_pem` builds
/// over the process default crypto provider, which `main` installed as `ring`.
async fn self_signed_tls(issuer: &str) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    // SAN entries covering the suite's default host and loopback. Hostname verification is off in
    // the suite, so these are courtesy rather than a requirement.
    let host = issuer
        .strip_prefix("https://")
        .and_then(|h| h.split([':', '/']).next())
        .unwrap_or("localhost")
        .to_string();
    let sans = vec![
        host,
        "localhost".to_string(),
        "localhost.emobix.co.uk".to_string(),
        "127.0.0.1".to_string(),
    ];
    let cert = rcgen::generate_simple_self_signed(sans)?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    Ok(RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?)
}

/// Print the two clients' PUBLIC JWKS and the protected-resource URL, so an operator wiring the
/// suite configuration can copy the `client.jwks` / `client2.jwks` public halves and confirm the
/// resource URL. The matching PRIVATE keys are the suite's to hold.
fn print_boot_banner(issuer: &str, resource_url: &str, redirect_uris: &[String]) {
    println!("=========================================================================");
    println!("FAPI 2.0 conformance fixture (openid=plain_oauth, private_key_jwt, dpop)");
    println!("  issuer:        {issuer}");
    println!("  resource URL:  {resource_url}");
    println!("  redirect URIs: {}", redirect_uris.join(", "));
    println!("  PAR mandatory, DPoP required, refresh rotation OFF (FAPI 2.0)");
    for (id, kid, keys) in [
        (CLIENT_ID, CLIENT_KEY_KID, client_keys()),
        (CLIENT2_ID, CLIENT2_KEY_KID, client2_keys()),
    ] {
        if let AssertionKeys::PublicKeys { keys, .. } = keys {
            let jwks =
                serde_json::json!({ "keys": keys.iter().map(jwk_to_json).collect::<Vec<_>>() });
            println!("  {id} ({kid}) public JWKS: {jwks}");
        }
    }
    println!("=========================================================================");
}

/// A `Jwk` as the JSON the suite's `client.jwks` field expects (public half).
fn jwk_to_json(jwk: &Jwk) -> serde_json::Value {
    // `Jwk` serializes its public members (`kty`, `crv`, `x`, `y`, `kid`); the suite's `client.jwks`
    // additionally wants the `use`/`alg` hints, added here. These fixture keys are ES256.
    let mut obj = serde_json::to_value(jwk).expect("a JWK serializes");
    if let Some(map) = obj.as_object_mut() {
        map.insert(
            "use".to_string(),
            serde_json::Value::String("sig".to_string()),
        );
        map.insert(
            "alg".to_string(),
            serde_json::Value::String("ES256".to_string()),
        );
    }
    obj
}
