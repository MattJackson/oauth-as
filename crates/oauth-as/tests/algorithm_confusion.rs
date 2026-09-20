// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE ALGORITHM-CONFUSION MATRIX for the algorithm-tagged JWS seam.
//!
//! Every published JWS confusion attack is a token whose HEADER names one algorithm while the
//! verifier was set up for another: `alg: none` where a signature was expected, `HS256` where a
//! public key is verified as if it were an HMAC secret, one asymmetric algorithm substituted for
//! another. The seam answers all of them structurally — `classify_alg` cannot spell `none` or an
//! HMAC, and the REGISTRATION (never the token header) chooses the algorithm — and this file is the
//! harness that proves it at all three sites a client-signed JWS reaches this crate: RFC 7523 client
//! assertions, RFC 9449 DPoP proofs, and RFC 9101 request objects.
//!
//! THE SHAPE IS A MATRIX so each wired algorithm is a ROW. It iterates every wired
//! [`oauth_as::jwt::JwsAlg`] a backend is compiled for as the algorithm a credential is genuinely
//! SIGNED under, crossed with every algorithm name a header could CLAIM — the wired ones plus a
//! fixed set of foreign spellings — and asserts the credential is accepted only when the claimed
//! algorithm matches the one it was signed under. Under `--all-features` the wired set is the full
//! ES256 / RS256 / EdDSA / PS256, so the matrix is 4×N: an ES256-signed credential claiming RS256, an
//! RSA-signed credential claiming ES256 (a cross-KIND swap), a PS256-signed credential claiming RS256
//! (a same-KEY, different-PADDING swap, since PS256 and RS256 share `KeyKind::Rsa`) and vice-versa,
//! and every `none`/`HS256`/foreign spelling are each REFUSED at all three sites, while the
//! truthfully-labelled one is accepted.

#![cfg(all(
    feature = "jwt-p256",
    feature = "dpop",
    feature = "client-assertion",
    feature = "jar"
))]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;

use oauth_as::client_assertion::{verify_assertion, AssertionKeys, AudienceRule};
use oauth_as::dpop::verify_proof;
use oauth_as::jwt::{
    EcdsaP256Key, Jwk, JwsAlg, JwsSignature, JwsSigner, JwsVerifier, JwsVerifiers,
};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, GrantType, JarConfig, MemoryStorage,
    RegisteredRequestObjectKey, RequestObjectKeys, ScopeSet, ServerConfig,
};

const CLIENT: &str = "app";
const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const REDIRECT: &str = "https://app.example/cb";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ---------------------------------------------------------------------------- the signer per row

/// One signer for each wired algorithm, so the matrix can produce a genuinely-signed credential
/// under any of them. The RS256, PS256 and EdDSA variants exist only when their backend is compiled.
enum MatrixKey {
    Es256(EcdsaP256Key),
    #[cfg(feature = "jwt-rsa")]
    Rs256(Box<oauth_as::RsaSigner>),
    // PS256 uses the SAME A.2 RSA public key as the RS256 row, so the cross-verify rows are a genuine
    // same-key/different-padding confusion test rather than merely different keys.
    #[cfg(feature = "jwt-rsa")]
    Ps256(Box<oauth_as::Ps256Signer>),
    #[cfg(feature = "jwt-ed25519")]
    EdDsa(oauth_as::Ed25519Signer),
}

impl MatrixKey {
    fn alg(&self) -> JwsAlg {
        match self {
            MatrixKey::Es256(k) => JwsSigner::alg(k),
            #[cfg(feature = "jwt-rsa")]
            MatrixKey::Rs256(k) => JwsSigner::alg(k.as_ref()),
            #[cfg(feature = "jwt-rsa")]
            MatrixKey::Ps256(k) => JwsSigner::alg(k.as_ref()),
            #[cfg(feature = "jwt-ed25519")]
            MatrixKey::EdDsa(k) => JwsSigner::alg(k),
        }
    }

    fn public_jwk(&self) -> Jwk {
        match self {
            MatrixKey::Es256(k) => JwsSigner::public_jwk(k),
            #[cfg(feature = "jwt-rsa")]
            MatrixKey::Rs256(k) => JwsSigner::public_jwk(k.as_ref()),
            #[cfg(feature = "jwt-rsa")]
            MatrixKey::Ps256(k) => JwsSigner::public_jwk(k.as_ref()),
            #[cfg(feature = "jwt-ed25519")]
            MatrixKey::EdDsa(k) => JwsSigner::public_jwk(k),
        }
    }

    fn kid(&self) -> String {
        self.public_jwk().kid().unwrap_or_default().to_string()
    }

    /// The raw signature octets over `input`, whatever algorithm this key signs with. The seam's
    /// `sign` is async but ready on its first poll for every in-process backend.
    async fn sign_input(&self, input: &[u8]) -> Vec<u8> {
        let sig: JwsSignature = match self {
            MatrixKey::Es256(k) => JwsSigner::sign(k, input).await,
            #[cfg(feature = "jwt-rsa")]
            MatrixKey::Rs256(k) => JwsSigner::sign(k.as_ref(), input).await,
            #[cfg(feature = "jwt-rsa")]
            MatrixKey::Ps256(k) => JwsSigner::sign(k.as_ref(), input).await,
            #[cfg(feature = "jwt-ed25519")]
            MatrixKey::EdDsa(k) => JwsSigner::sign(k, input).await,
        }
        .expect("an in-process backend signs");
        sig.as_bytes().to_vec()
    }

    /// A compact JWS over `header`/`payload`, signed with this key's real algorithm whatever the
    /// header CLAIMS.
    async fn sign(&self, header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let signature = self.sign_input(signing_input.as_bytes()).await;
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

/// The backend for a wired algorithm, or `None` when its backend is not compiled into this build.
fn signer_for(alg: JwsAlg) -> Option<MatrixKey> {
    match alg {
        JwsAlg::Es256 => Some(MatrixKey::Es256(
            EcdsaP256Key::from_scalar_bytes("matrix-es256", &[7u8; 32])
                .expect("a valid P-256 scalar"),
        )),
        JwsAlg::Rs256 => {
            #[cfg(feature = "jwt-rsa")]
            {
                Some(MatrixKey::Rs256(Box::new(rsa_matrix_signer())))
            }
            #[cfg(not(feature = "jwt-rsa"))]
            {
                None
            }
        }
        JwsAlg::Ps256 => {
            #[cfg(feature = "jwt-rsa")]
            {
                Some(MatrixKey::Ps256(Box::new(ps256_matrix_signer())))
            }
            #[cfg(not(feature = "jwt-rsa"))]
            {
                None
            }
        }
        JwsAlg::EdDsa => {
            #[cfg(feature = "jwt-ed25519")]
            {
                Some(MatrixKey::EdDsa(
                    oauth_as::Ed25519Signer::from_seed_bytes("matrix-eddsa", &[9u8; 32])
                        .expect("any 32-byte Ed25519 seed is valid"),
                ))
            }
            #[cfg(not(feature = "jwt-ed25519"))]
            {
                None
            }
        }
    }
}

/// The RFC 7515 Appendix A.2 RSA-2048 private key, rebuilt deterministically from its components so
/// the matrix needs no RNG and no `getrandom` feature on `rsa`, and sits right at the 2048-bit floor.
#[cfg(feature = "jwt-rsa")]
fn a2_rsa_private_key() -> rsa::RsaPrivateKey {
    use rsa::{BigUint, RsaPrivateKey};
    const N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    const E: &str = "AQAB";
    const D: &str = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
    const P: &str = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
    const Q: &str = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";
    let b = |s: &str| BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(s).unwrap());
    RsaPrivateKey::from_components(b(N), b(E), b(D), vec![b(P), b(Q)])
        .expect("A.2 components are consistent")
}

#[cfg(feature = "jwt-rsa")]
fn rsa_matrix_signer() -> oauth_as::RsaSigner {
    oauth_as::RsaSigner::from_private_key("matrix-rsa", a2_rsa_private_key())
        .expect("A.2 is a 2048-bit key")
}

/// PS256 over the SAME A.2 key as `rsa_matrix_signer`: same public modulus, PSS padding.
#[cfg(feature = "jwt-rsa")]
fn ps256_matrix_signer() -> oauth_as::Ps256Signer {
    oauth_as::Ps256Signer::from_private_key("matrix-ps256", a2_rsa_private_key())
        .expect("A.2 is a 2048-bit key")
}

/// The verifier for a wired algorithm. Only ever called for an algorithm whose signer exists, which
/// is exactly the algorithms a backend is compiled for.
fn verifier_for(alg: JwsAlg) -> &'static dyn JwsVerifier {
    match alg {
        JwsAlg::Es256 => &oauth_as::jwt::P256Verifier,
        #[cfg(feature = "jwt-rsa")]
        JwsAlg::Rs256 => &oauth_as::RsaVerifier,
        #[cfg(feature = "jwt-rsa")]
        JwsAlg::Ps256 => &oauth_as::Ps256Verifier,
        #[cfg(feature = "jwt-ed25519")]
        JwsAlg::EdDsa => &oauth_as::Ed25519Verifier,
        #[allow(unreachable_patterns)]
        _ => unreachable!("verifier_for is only called for an algorithm whose backend is compiled"),
    }
}

/// Every verifier this build has, for the DPoP site (whose policy reads the algorithm off the proof
/// header against the installed set — the RFC 9449 self-carried-key exception).
fn all_verifiers() -> JwsVerifiers {
    let mut verifiers = JwsVerifiers::new();
    verifiers.install(Arc::new(oauth_as::jwt::P256Verifier));
    #[cfg(feature = "jwt-rsa")]
    verifiers.install(Arc::new(oauth_as::RsaVerifier));
    #[cfg(feature = "jwt-rsa")]
    verifiers.install(Arc::new(oauth_as::Ps256Verifier));
    #[cfg(feature = "jwt-ed25519")]
    verifiers.install(Arc::new(oauth_as::Ed25519Verifier));
    verifiers
}

/// The wired algorithms this build can actually SIGN under, in `JwsAlg::ALL` order.
fn wired_algs() -> Vec<JwsAlg> {
    JwsAlg::ALL
        .iter()
        .copied()
        .filter(|&a| signer_for(a).is_some())
        .collect()
}

/// The header algorithm spellings a token might CLAIM: every wired algorithm's JOSE name plus a
/// fixed set of foreign ones (`none` and `HS256` are the confusion classics; the rest are asymmetric
/// algorithms this crate does not wire).
fn claimed_alg_spellings() -> Vec<String> {
    let mut names: Vec<String> = JwsAlg::ALL
        .iter()
        .map(|a| a.jose_name().to_string())
        .collect();
    // "PS256" is no longer here: it is a WIRED algorithm now, added by the `JwsAlg::ALL` loop above.
    // The foreign set stays the confusion classics (`none`, `HS256`) plus asymmetric algs this crate
    // does not wire.
    for foreign in ["none", "HS256", "ES384", "ES512"] {
        names.push(foreign.to_string());
    }
    names
}

// ---------------------------------------------------------------- site 1: RFC 7523 client assertion

async fn client_assertion_accepts(key: &MatrixKey, claimed_alg: &str) -> bool {
    let header = json!({ "alg": claimed_alg, "typ": "JWT" });
    let payload = json!({
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": TOKEN_ENDPOINT,
        "exp": secs(now()) + 60,
        "iat": secs(now()),
        "jti": "assertion-jti",
    });
    let assertion = key.sign(&header, &payload).await;
    // The registration decides the algorithm and the key; the verifier is the one for that alg.
    let keys = AssertionKeys::PublicKeys {
        alg: key.alg(),
        keys: vec![key.public_jwk()],
    };
    verify_assertion(
        Some(verifier_for(key.alg())),
        &keys,
        &assertion,
        CLIENT,
        AudienceRule::AnyOf(&[TOKEN_ENDPOINT, ISSUER]),
        now(),
    )
    .is_ok()
}

// ------------------------------------------------------------------------ site 2: RFC 9449 DPoP proof

async fn dpop_accepts(key: &MatrixKey, claimed_alg: &str) -> bool {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": claimed_alg,
        "jwk": serde_json::to_value(key.public_jwk()).unwrap(),
    });
    let payload = json!({
        "jti": "proof-jti",
        "htm": "POST",
        "htu": TOKEN_ENDPOINT,
        "iat": secs(now()),
    });
    let proof = key.sign(&header, &payload).await;
    verify_proof(&all_verifiers(), &proof, "POST", TOKEN_ENDPOINT, now()).is_ok()
}

// -------------------------------------------------------------------- site 3: RFC 9101 request object

struct Keys(RegisteredRequestObjectKey);

impl RequestObjectKeys for Keys {
    fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
        (client_id.as_str() == CLIENT).then(|| self.0.clone())
    }
}

fn client() -> Client {
    Client {
        client_id: ClientId::new(CLIENT),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn registered_key(key: &MatrixKey) -> RegisteredRequestObjectKey {
    RegisteredRequestObjectKey::from_jwk(key.alg(), key.public_jwk())
        .expect("a JWK this crate emitted, matching its own algorithm, registers")
}

async fn par_server(key: &MatrixKey) -> AuthorizationServer<MemoryStorage> {
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    cfg.jar = Some(Box::new(JarConfig::new()));
    let server = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_request_object_keys(Box::new(Keys(registered_key(key))));
    server.register_client(client()).await.unwrap();
    server
}

async fn request_object_accepts(key: &MatrixKey, claimed_alg: &str) -> bool {
    let server = par_server(key).await;
    let header = json!({ "alg": claimed_alg, "kid": key.kid() });
    // `exp` is required and is measured against the server's OWN clock (real time), so it is
    // computed from `SystemTime::now()` rather than the fixed `now()` the pure verify functions
    // above are handed. Kept short, inside the default request-object lifetime ceiling.
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let payload = json!({
        "client_id": CLIENT,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "read",
        "code_challenge": oauth_as::pkce::code_challenge_s256(PKCE_VERIFIER),
        "code_challenge_method": "S256",
        "exp": exp,
    });
    let object = key.sign(&header, &payload).await;
    server
        .validate_signed_authorization_request(CLIENT, &object)
        .await
        .is_ok()
}

// --------------------------------------------------------------------------------------- the matrix

/// The positive anchors: a credential signed under a wired algorithm and honestly claiming it is
/// accepted at each site. Without these, the negative rows below could pass for the wrong reason (a
/// fixture so broken nothing ever verifies).
#[tokio::test]
async fn a_truthfully_labelled_credential_is_accepted_at_every_site() {
    for sign_alg in wired_algs() {
        let key = signer_for(sign_alg).expect("wired_algs only yields algs with a signer");
        let honest = sign_alg.jose_name();
        assert!(
            client_assertion_accepts(&key, honest).await,
            "client assertion signed under {honest} and claiming {honest} must be accepted"
        );
        assert!(
            dpop_accepts(&key, honest).await,
            "DPoP proof signed under {honest} and claiming {honest} must be accepted"
        );
        assert!(
            request_object_accepts(&key, honest).await,
            "request object signed under {honest} and claiming {honest} must be accepted"
        );
    }
}

/// THE CONFUSION MATRIX. For every (sign_alg, claimed_alg) pair, the credential is genuinely signed
/// under `sign_alg` but its header claims `claimed_alg`; it must be accepted only when the two agree.
/// A mismatch is a header LYING about its algorithm — `none`, `HS256`, a foreign asymmetric name, or
/// ANOTHER wired algorithm (which is also a cross-KIND swap: ES256⇔EC, RS256⇔RSA, EdDSA⇔OKP) — and
/// every one must be refused at all three sites.
#[tokio::test]
async fn a_header_that_lies_about_its_algorithm_is_refused_at_every_site() {
    for sign_alg in wired_algs() {
        let key = signer_for(sign_alg).expect("wired_algs only yields algs with a signer");
        for claimed in claimed_alg_spellings() {
            let should_accept = claimed == sign_alg.jose_name();

            assert_eq!(
                client_assertion_accepts(&key, &claimed).await,
                should_accept,
                "client assertion: signed {}, header claims {claimed}",
                sign_alg.jose_name()
            );
            assert_eq!(
                dpop_accepts(&key, &claimed).await,
                should_accept,
                "DPoP proof: signed {}, header claims {claimed}",
                sign_alg.jose_name()
            );
            assert_eq!(
                request_object_accepts(&key, &claimed).await,
                should_accept,
                "request object: signed {}, header claims {claimed}",
                sign_alg.jose_name()
            );
        }
    }
}

/// THE CROSS-KIND SWAP, made explicit. A DPoP proof genuinely signed ES256 but whose header claims
/// RS256 (or EdDSA) while carrying the EC key it was actually signed with: the header names a wired
/// algorithm of a DIFFERENT key kind than the presented key. `consistent(alg, &jwk)` is the guard
/// that refuses it — the EC key is not the kind RS256/EdDSA signs with — and it must be refused even
/// though the algorithm IS installed. Only runs when a second key kind is compiled in.
#[cfg(any(feature = "jwt-rsa", feature = "jwt-ed25519"))]
#[tokio::test]
async fn an_ec_proof_claiming_an_rsa_or_okp_algorithm_is_refused() {
    let key = signer_for(JwsAlg::Es256).unwrap();
    for foreign in [
        #[cfg(feature = "jwt-rsa")]
        "RS256",
        #[cfg(feature = "jwt-ed25519")]
        "EdDSA",
    ] {
        assert!(
            !dpop_accepts(&key, foreign).await,
            "a proof signed ES256 but claiming {foreign}, carrying an EC key, must be refused: the \
             key is not the kind {foreign} signs with"
        );
    }
}

/// The other direction of the cross-kind guard, when RSA is compiled: an RSA-signed DPoP proof whose
/// header claims ES256 while carrying the RSA key must be refused — an EC algorithm can never route
/// a verification at an RSA key.
#[cfg(feature = "jwt-rsa")]
#[tokio::test]
async fn an_rsa_proof_claiming_es256_is_refused() {
    let key = signer_for(JwsAlg::Rs256).unwrap();
    assert!(
        !dpop_accepts(&key, "ES256").await,
        "a proof signed RS256 but claiming ES256, carrying an RSA key, must be refused"
    );
}

/// The Phase A wrong-KIND anchor that needs no second backend: a proof whose self-carried `jwk` is a
/// symmetric (`oct`) key must be refused at the key-parse stage, and the built-in verifier never
/// confuses a non-EC key into a pass.
#[tokio::test]
async fn a_proof_key_of_the_wrong_kind_is_refused() {
    let key = signer_for(JwsAlg::Es256).unwrap();
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": { "kty": "oct", "k": "AAAA" },
    });
    let payload = json!({ "jti": "j", "htm": "POST", "htu": TOKEN_ENDPOINT, "iat": secs(now()) });
    let proof = key.sign(&header, &payload).await;
    assert!(
        verify_proof(&all_verifiers(), &proof, "POST", TOKEN_ENDPOINT, now()).is_err(),
        "a proof whose self-carried key is not the kind ES256 signs with must be refused"
    );
    let _ = Jwk::from_json(&json!({ "kty": "oct", "k": "AAAA" }))
        .expect_err("a symmetric JWK must not parse as a verifiable key");
}
