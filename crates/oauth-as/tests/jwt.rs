// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9068 JWT access tokens and the RFC 7517 JWKS document (feature `jwt`).
//!
//! Two independent oracles are used here on purpose:
//!
//! 1. The RFC 7515 appendix A.3 ES256 vector, VENDORED in
//!    `crates/oauth-as-conformance/vectors/rfc_vectors.json` with its citation. ECDSA signing is
//!    randomized (RFC 6979 deterministic signing is not what `p256` does by default), so a produced
//!    signature can NEVER be compared byte-for-byte with the appendix's. What the appendix does fix
//!    is a public key and a signature over a fixed signing input, and THAT is verified here, along
//!    with the base64url encoding of the key's affine coordinates, which is exactly the encoding
//!    our JWKS emits.
//! 2. The structural validator the independent harness applies
//!    (`oauth_as_conformance::validate_rfc9068_access_token`), transcribed below rather than
//!    imported: `oauth-as` must not depend on the harness (the harness requires a far newer
//!    toolchain and is never published), and a transcription that drifts is caught the moment the
//!    black-box run happens.

#![cfg(feature = "jwt")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, GrantType, MemoryStorage,
    RefreshTokenRecord, RefreshTokenState, ScopeSet, ServerConfig, Storage, TokenRequest,
};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A hand-cranked clock so `iat`/`exp` are exact rather than approximately now.
#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

const NOW_SECS: u64 = 1_700_000_000;

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Test device".into()),
    }
}

fn signing_key() -> EcdsaP256Key {
    EcdsaP256Key::generate("test-kid-1")
}

fn jwt_config(key: EcdsaP256Key) -> JwtConfig {
    JwtConfig::new(key, "https://rs.example").with_jwks_uri("https://as.example/jwks")
}

async fn jwt_server(
    clock: ManualClock,
    key: EcdsaP256Key,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(jwt_config(key));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    srv.register_client(device_client()).await.unwrap();
    srv
}

/// Run a device grant end to end and return the wire access token.
async fn issue_via_device_flow(srv: &AuthorizationServer<MemoryStorage, ManualClock>) -> String {
    let client_id = ClientId::new("device-client");
    let auth = srv
        .device_authorization(&client_id, None, None)
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "user-42")
        .await
        .unwrap();
    srv.token(TokenRequest::DeviceCode {
        client_id,
        client_secret: None,
        device_code: auth.device_code.clone(),
    })
    .await
    .unwrap()
    .access_token
}

// ---------------------------------------------------------------------------------------------
// Helpers: JWS decoding and ES256 verification, written here so the tests do not trust the code
// under test to tell them whether it is right.
// ---------------------------------------------------------------------------------------------

fn parts(token: &str) -> (Value, Value, Vec<u8>) {
    let p: Vec<&str> = token.split('.').collect();
    assert_eq!(p.len(), 3, "compact JWS is three parts (RFC 7515 s3.1)");
    let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p[0]).unwrap()).unwrap();
    let payload = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p[1]).unwrap()).unwrap();
    (header, payload, URL_SAFE_NO_PAD.decode(p[2]).unwrap())
}

/// Verify an ES256 signature from raw affine coordinates, which is precisely what a resource
/// server does with a JWK: rebuild the point, verify over `header.payload` (RFC 7515 s5.2).
fn es256_verify(signing_input: &[u8], signature: &[u8], x: &[u8], y: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04); // uncompressed point (SEC 1 s2.3.3)
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    vk.verify(signing_input, &sig).is_ok()
}

/// Verify a compact JWS against a JWKS document, selecting the key by `kid`.
fn verify_against_jwks(token: &str, jwks: &Value) -> bool {
    let (header, _, sig) = parts(token);
    let kid = header.get("kid").and_then(Value::as_str);
    let signing_input = &token[..token.rfind('.').unwrap()];
    jwks["keys"]
        .as_array()
        .expect("keys array (RFC 7517 s5)")
        .iter()
        .filter(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid)
        .any(|k| {
            let x = URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap();
            let y = URL_SAFE_NO_PAD.decode(k["y"].as_str().unwrap()).unwrap();
            es256_verify(signing_input.as_bytes(), &sig, &x, &y)
        })
}

/// TRANSCRIBED from `oauth_as_conformance::validate_rfc9068_access_token`. Any divergence is a
/// bug in this transcription, not a licence to weaken it.
fn rfc9068_violations(token: &str) -> Vec<String> {
    let mut v = Vec::new();
    let (header, claims, _) = parts(token);
    match header.get("typ") {
        None => v.push("header missing typ (RFC 9068 s2.1)".to_string()),
        Some(Value::String(t)) => {
            if !t.eq_ignore_ascii_case("at+jwt") && !t.eq_ignore_ascii_case("application/at+jwt") {
                v.push(format!("header typ {t} must be at+jwt (RFC 9068 s2.1)"));
            }
        }
        Some(other) => v.push(format!("header typ must be a string, got {other}")),
    }
    match header.get("alg") {
        None => v.push("header missing alg (RFC 7515 s4.1.1)".to_string()),
        Some(Value::String(a)) if a.eq_ignore_ascii_case("none") => {
            v.push("alg none is forbidden for access tokens (RFC 9068 s2.1)".to_string());
        }
        Some(Value::String(_)) => {}
        Some(other) => v.push(format!("header alg must be a string, got {other}")),
    }
    for (claim, kinds) in [
        ("iss", "string"),
        ("exp", "number"),
        ("aud", "string-or-array"),
        ("sub", "string"),
        ("client_id", "string"),
        ("iat", "number"),
        ("jti", "string"),
    ] {
        let ok = match (claims.get(claim), kinds) {
            (Some(Value::String(_)), "string" | "string-or-array") => true,
            (Some(Value::Array(a)), "string-or-array") => a.iter().all(Value::is_string),
            (Some(Value::Number(_)), "number") => true,
            _ => false,
        };
        if !ok {
            v.push(format!(
                "claim {claim} missing or wrong type (must be {kinds}); RFC 9068 s2.2"
            ));
        }
    }
    v
}

/// The vendored RFC vectors. They live in the harness crate, which is repo-only: a consumer who
/// runs `cargo test` on the published tarball does not have the file, and the test says so rather
/// than pretending to have checked something.
fn rfc_vectors() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oauth-as-conformance/vectors/rfc_vectors.json");
    let bytes = std::fs::read(&path).ok()?;
    Some(serde_json::from_slice(&bytes).expect("vendored rfc_vectors.json must be valid JSON"))
}

// ---------------------------------------------------------------------------------------------
// RFC 7515 appendix A.3 (ES256), against the vendored vector
// ---------------------------------------------------------------------------------------------

#[test]
fn rfc7515_appendix_a3_signature_verifies_against_its_own_key() {
    let Some(vectors) = rfc_vectors() else {
        eprintln!("SKIPPED: vendored rfc_vectors.json not present (packaged tarball)");
        return;
    };
    let v = &vectors["jws_a3_es256"];
    let signing_input = format!(
        "{}.{}",
        v["header_b64"].as_str().unwrap(),
        v["payload_b64"].as_str().unwrap()
    );
    let sig = URL_SAFE_NO_PAD
        .decode(v["signature_b64"].as_str().unwrap())
        .unwrap();
    let x = URL_SAFE_NO_PAD
        .decode(v["jwk_x"].as_str().unwrap())
        .unwrap();
    let y = URL_SAFE_NO_PAD
        .decode(v["jwk_y"].as_str().unwrap())
        .unwrap();
    assert_eq!((x.len(), y.len(), sig.len()), (32, 32, 64), "P-256 widths");
    assert!(
        es256_verify(signing_input.as_bytes(), &sig, &x, &y),
        "the RFC's own ES256 signature must verify under the RFC's own key"
    );
    // Same key, same signature, one flipped payload byte: must NOT verify. Without this the
    // assertion above would pass for a verifier that returns true unconditionally.
    let tampered = signing_input.replace(
        v["payload_b64"].as_str().unwrap(),
        &v["payload_b64"].as_str().unwrap().replace('e', "f"),
    );
    assert_ne!(tampered, signing_input);
    assert!(!es256_verify(tampered.as_bytes(), &sig, &x, &y));
}

#[test]
fn our_jwks_coordinate_encoding_matches_the_rfc7515_appendix_a3_form() {
    let Some(vectors) = rfc_vectors() else {
        eprintln!("SKIPPED: vendored rfc_vectors.json not present (packaged tarball)");
        return;
    };
    // The appendix fixes what a P-256 JWK looks like: 32-byte fixed-width coordinates, unpadded
    // base64url, 43 characters each. Our own generated key must present the same shape.
    let a3 = &vectors["jws_a3_es256"];
    let jwks = jwt_config(signing_key()).jwks();
    let doc = serde_json::to_value(&jwks).unwrap();
    let k = &doc["keys"][0];
    for field in ["x", "y"] {
        let ours = k[field].as_str().unwrap();
        let theirs = a3[format!("jwk_{field}")].as_str().unwrap();
        assert_eq!(
            ours.len(),
            theirs.len(),
            "{field} must be 43 chars: unpadded base64url of a fixed-width 32 byte coordinate"
        );
        assert!(!ours.contains('='), "no base64 padding in a JWK coordinate");
        assert_eq!(URL_SAFE_NO_PAD.decode(ours).unwrap().len(), 32);
    }
}

// ---------------------------------------------------------------------------------------------
// RFC 7517 JWKS
// ---------------------------------------------------------------------------------------------

#[test]
fn jwks_is_rfc7517_shaped() {
    let jwks = jwt_config(EcdsaP256Key::generate("rotate-me")).jwks();
    let doc = serde_json::to_value(&jwks).unwrap();
    let keys = doc["keys"].as_array().expect("keys array (RFC 7517 s5)");
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!(k["kty"], "EC");
    assert_eq!(k["crv"], "P-256");
    assert_eq!(k["kid"], "rotate-me");
    assert_eq!(k["use"], "sig");
    assert_eq!(k["alg"], "ES256");
    assert!(k["x"].is_string() && k["y"].is_string());
}

/// The single most catastrophic bug available in a JWKS implementation: publishing the private
/// scalar. RFC 7517 s4 makes `d` the private key parameter for an EC JWK; it must never appear,
/// and neither must the scalar's bytes under any encoding we could plausibly emit.
#[test]
fn jwks_never_exposes_private_key_material() {
    let scalar = [7u8; 32];
    let key = EcdsaP256Key::from_scalar_bytes("k", &scalar).unwrap();
    let serialized = serde_json::to_string(&jwt_config(key).jwks()).unwrap();

    let doc: Value = serde_json::from_str(&serialized).unwrap();
    assert!(
        doc["keys"][0].get("d").is_none(),
        "RFC 7517 s6.2.2.1 `d` is the EC PRIVATE key; a JWKS must never carry it"
    );
    for forbidden in [
        URL_SAFE_NO_PAD.encode(scalar),
        base64::engine::general_purpose::URL_SAFE.encode(scalar),
        base64::engine::general_purpose::STANDARD.encode(scalar),
        scalar
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    ] {
        assert!(
            !serialized.contains(&forbidden),
            "serialized JWKS contains the private scalar: {serialized}"
        );
    }
    // Whitelist the key parameters outright: a future field cannot sneak in unnoticed.
    let members: Vec<&String> = doc["keys"][0].as_object().unwrap().keys().collect();
    let mut members: Vec<&str> = members.iter().map(|s| s.as_str()).collect();
    members.sort_unstable();
    assert_eq!(members, ["alg", "crv", "kid", "kty", "use", "x", "y"]);
}

// ---------------------------------------------------------------------------------------------
// RFC 9068 access tokens from the live server
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issued_access_token_satisfies_the_independent_harness_checks() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    let token = issue_via_device_flow(&srv).await;
    let violations = rfc9068_violations(&token);
    assert!(
        violations.is_empty(),
        "RFC 9068 violations: {violations:#?}"
    );
}

#[tokio::test]
async fn header_is_rfc9068_s2_1() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    let token = issue_via_device_flow(&srv).await;
    let (header, _, sig) = parts(&token);
    assert_eq!(header["typ"], "at+jwt", "RFC 9068 s2.1 fixes typ exactly");
    assert_eq!(header["alg"], "ES256");
    assert_ne!(header["alg"], "none", "RFC 9068 s2.1 forbids alg none");
    assert_eq!(header["kid"], "test-kid-1", "kid selects the verifying key");
    assert_eq!(sig.len(), 64, "ES256 is fixed-width r||s (RFC 7518 s3.4)");
}

#[tokio::test]
async fn claims_are_rfc9068_s2_2() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    let token = issue_via_device_flow(&srv).await;
    let (_, claims, _) = parts(&token);
    assert_eq!(claims["iss"], "https://as.example");
    assert_eq!(claims["aud"], "https://rs.example");
    assert_eq!(claims["sub"], "user-42");
    assert_eq!(claims["client_id"], "device-client");
    assert_eq!(claims["iat"], NOW_SECS);
    assert_eq!(claims["exp"], NOW_SECS + 3600);
    assert_eq!(claims["scope"], "read");
    let jti = claims["jti"].as_str().expect("jti is a string");
    assert!(jti.len() >= 32, "jti must be unguessable, got {jti:?}");
}

/// RFC 9068 s2.2: `sub` is REQUIRED even when there is no resource owner, and the RFC's own
/// guidance is to use the `client_id` as the subject in that case. The path that can reach it here
/// is a refresh chain whose record carries no subject.
#[tokio::test]
async fn subject_falls_back_to_client_id_when_there_is_no_resource_owner() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    srv.store()
        .put_refresh_token(RefreshTokenRecord {
            refresh_token: "seeded-refresh".into(),
            client_id: ClientId::new("device-client"),
            subject: None,
            scope: ScopeSet::parse("read").unwrap(),
            expires_at: None,
            // A seeded chain still needs a family, since reuse detection revokes by family
            // (OAuth 2.1 s6.1, RFC 9700 s4.14.2). Active, because this one has not been rotated.
            family_id: "seeded-family".into(),
            state: RefreshTokenState::Active,
        })
        .await
        .unwrap();
    let token = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: "seeded-refresh".into(),
            scope: None,
        })
        .await
        .unwrap()
        .access_token;
    let (_, claims, _) = parts(&token);
    assert_eq!(claims["sub"], "device-client");
    assert!(rfc9068_violations(&token).is_empty());
}

#[tokio::test]
async fn issued_token_verifies_against_the_advertised_jwks_and_tampering_fails() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    let jwks =
        serde_json::to_value(srv.jwks().expect("jwks when JWT signing is configured")).unwrap();
    let token = issue_via_device_flow(&srv).await;
    assert!(
        verify_against_jwks(&token, &jwks),
        "an RS must be able to verify with only the published JWKS"
    );

    // Tamper with the payload: re-encode the claims with an escalated scope, keep the signature.
    let (header_b64, rest) = token.split_once('.').unwrap();
    let (_, sig_b64) = rest.split_once('.').unwrap();
    let (_, mut claims, _) = parts(&token);
    claims["scope"] = Value::String("read write admin".into());
    let forged = format!(
        "{header_b64}.{}.{sig_b64}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    assert_ne!(forged, token);
    assert!(
        !verify_against_jwks(&forged, &jwks),
        "a tampered payload MUST NOT verify"
    );

    // A token signed under a DIFFERENT key, advertising the SAME kid, must not verify: the kid is
    // a hint for key selection and never a substitute for checking the signature.
    let other = jwt_server(
        ManualClock::at_epoch(),
        EcdsaP256Key::generate("test-kid-1"),
    )
    .await;
    let foreign = issue_via_device_flow(&other).await;
    assert!(!verify_against_jwks(&foreign, &jwks));
}

/// The JWT is what goes on the wire, but the record is still PERSISTED, so RFC 7662
/// introspection and RFC 7009 revocation keep operating on the exact string the client presents.
#[tokio::test]
async fn jwt_tokens_are_still_persisted_for_introspection() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    let token = issue_via_device_flow(&srv).await;
    let record = srv
        .introspect(&token)
        .await
        .unwrap()
        .expect("a JWT access token must still be introspectable");
    assert_eq!(record.access_token, token, "keyed by the presented string");
    assert_eq!(record.subject.as_deref(), Some("user-42"));
    assert_eq!(record.client_id, ClientId::new("device-client"));
}

/// Opaque stays the default even with the feature compiled in: a host that does not configure a
/// signing key gets exactly the tokens it got before.
#[tokio::test]
async fn opaque_remains_the_default_when_no_signing_key_is_configured() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    assert_eq!(cfg.access_token_format, AccessTokenFormat::Opaque);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(device_client()).await.unwrap();
    let token = issue_via_device_flow(&srv).await;
    assert!(!token.contains('.'), "opaque token, got {token}");
    assert_eq!(token.len(), 64);
    assert!(srv.jwks().is_none(), "no JWKS without a signing key");
    assert!(
        srv.jwks_uri().is_none(),
        "RFC 8414 metadata must advertise jwks_uri only when signing is configured"
    );
}

#[tokio::test]
async fn jwks_uri_is_advertised_when_signing_is_configured() {
    let srv = jwt_server(ManualClock::at_epoch(), signing_key()).await;
    assert_eq!(srv.jwks_uri(), Some("https://as.example/jwks"));
}

// ---------------------------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------------------------

#[test]
fn keys_load_from_raw_scalar_and_from_pkcs8_and_agree() {
    // A fixed scalar, so this is a statement about the two loaders and not about randomness.
    let scalar = [0x2au8; 32];
    let from_raw = EcdsaP256Key::from_scalar_bytes("kid-a", &scalar).unwrap();
    let der = from_raw.to_pkcs8_der().unwrap();
    let from_pkcs8 = EcdsaP256Key::from_pkcs8_der("kid-a", &der).unwrap();

    let a = serde_json::to_value(jwt_config(from_raw).jwks()).unwrap();
    let b = serde_json::to_value(jwt_config(from_pkcs8).jwks()).unwrap();
    assert_eq!(a, b, "the same key by either route publishes the same JWK");
}

#[test]
fn invalid_key_material_is_rejected_rather_than_guessed_at() {
    // All zeroes is not a valid P-256 scalar (SEC 1: 1 <= d <= n-1).
    assert!(EcdsaP256Key::from_scalar_bytes("k", &[0u8; 32]).is_err());
    assert!(EcdsaP256Key::from_scalar_bytes("k", &[1u8; 31]).is_err());
    assert!(EcdsaP256Key::from_pkcs8_der("k", b"not der").is_err());
}
