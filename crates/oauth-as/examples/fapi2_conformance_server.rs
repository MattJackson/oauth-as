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
//! 7. **Auto-login / auto-consent** (§2.3, headless): every request is the same signed-in user and
//!    every valid authorization request is approved without a consent screen, because the suite's
//!    HtmlUnit browser completes the redirect from a scripted task list and cannot click anything.
//!
//! # Environment
//!
//! * `OAUTH_AS_ADDR` (default `127.0.0.1:8443`): the address to bind. `localhost.emobix.co.uk`, the
//!   suite's default base host, resolves to `127.0.0.1`, so loopback is reachable under that name.
//! * `OAUTH_AS_ISSUER` (default `https://localhost.emobix.co.uk:8443`): the RFC 8414 `issuer`. It
//!   MUST equal the URL the metadata document is fetched from (RFC 8414 s3.3), so for the default
//!   suite deployment leave it at the default; override it only if you moved the suite's base URL.
//! * `OAUTH_AS_FAPI_REDIRECT_URIS` (default `https://localhost.emobix.co.uk:8443/test/a/oauth-as/callback`):
//!   comma-separated redirect URIs registered for BOTH clients. FAPI 2.0 requires exact redirect
//!   URI matching, so this must equal `client.redirect_uri` in the suite configuration; the
//!   config side and this side are matched together, exactly as the client keys are.
//! * `OAUTH_AS_RESOURCE` (default `{issuer}/resource`): the `resource.resourceUrl` the suite calls
//!   with a DPoP-bound token. It is a route on THIS listener, so its DPoP `htu` is this URL.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
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
use oauth_as::server::{AuthorizationServer, RefreshRotation, ServerConfig};
use oauth_as::store::MemoryStorage;
use sha2::{Digest, Sha256};

// #############################################################################
// # CONFORMANCE FIXTURE ONLY. NEVER COPY ANY OF THIS INTO A PRODUCTION HOST.   #
// #############################################################################

/// The two client identifiers the suite's `@ConfigurationFields` name (`client.client_id`,
/// `client2.client_id`); EXTERNAL-TOOLING.md §2.3 item 3.
const CLIENT_ID: &str = "client";
const CLIENT2_ID: &str = "client2";

/// The subject every seeded approval acts as. There is one user, because the suite is not a browser
/// and there is no login form for it to fill in.
const SEEDED_SUBJECT: &str = "fapi-conformance-user";

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
        &redirect_uris,
        &scope_names,
        client2_keys(),
    )
    .await?;

    // ############################################################################
    // # CONFORMANCE FIXTURE ONLY. NEVER COPY ANY OF THIS INTO A PRODUCTION HOST.  #
    // ############################################################################
    //
    // The suite drives this AS with an HTTP client and a headless HtmlUnit browser that follows a
    // scripted task list; it has no session and cannot click a consent button. So, exactly as
    // `conformance_server.rs` does under its seed flag, this fixture opts IN BY NAME to two
    // behaviours a real AS must NEVER have:
    //
    // * `with_subject_resolver` returning a constant: every request is the same user. A real host
    //   reads its own authenticated session.
    // * `with_approval_resolver` returning `Approve`: RFC 6749 s10.12 consent, DELETED. Any
    //   cross-site navigation would silently issue a code for the logged-in user. A real host
    //   returns `ApprovalDecision::Respond` with a consent screen and approves only after the user
    //   has answered it.
    let builder = ServiceBuilder::new(Arc::clone(&server))
        .with_subject_resolver(|_headers| Some(SEEDED_SUBJECT.to_string()))
        .with_approval_resolver(|_request| ApprovalDecision::Approve);

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
    let router = axum::Router::from(builder.build()?).merge(resource_router);

    print_boot_banner(&issuer, &resource_url, &redirect_uris);

    // (§2.2 / §2.3 item 2) HTTPS under a self-signed certificate generated at boot. The suite
    // trusts all certificates and skips hostname verification, so this needs no CA and no public
    // hostname.
    let tls = self_signed_tls(&issuer).await?;
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
    let token = authz
        .strip_prefix("DPoP ")
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
