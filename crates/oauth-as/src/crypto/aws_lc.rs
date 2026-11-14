// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
use super::{CryptoError, CryptoProvider};

/// AWS-LC primitives and asymmetric operations.
#[cfg(feature = "aws-lc")]
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLc;
/// AWS-LC FIPS 3 primitives, restricted to this backend's approved algorithm policy.
#[cfg(feature = "fips")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Fips;

macro_rules! primitives {
    () => {
        fn sha256(&self, input: &[u8]) -> [u8; 32] {
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input);
            let mut out = [0; 32];
            out.copy_from_slice(digest.as_ref());
            out
        }
        fn hmac_sha256(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
            let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
            let tag = aws_lc_rs::hmac::sign(&key, message);
            let mut out = [0; 32];
            out.copy_from_slice(tag.as_ref());
            out
        }
        fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
            aws_lc_rs::rand::fill(output).map_err(|_| CryptoError::EntropyUnavailable)
        }
        fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
            aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
        }
    };
}
#[cfg(feature = "aws-lc")]
impl CryptoProvider for AwsLc {
    primitives!();
    #[cfg(feature = "jwt")]
    fn verifier(&self, alg: crate::jwt::JwsAlg) -> Option<&dyn crate::jwt::JwsVerifier> {
        Some(verifier(alg, false))
    }
    #[cfg(feature = "jwt")]
    fn signing_key(
        &self,
        alg: crate::jwt::JwsAlg,
        kid: &str,
        der: &[u8],
    ) -> Result<super::ProviderSigner, CryptoError> {
        load_key(alg, kid, der, false)
    }
}
#[cfg(feature = "fips")]
impl CryptoProvider for Fips {
    primitives!();
    fn validate(&self) -> Result<(), CryptoError> {
        aws_lc_rs::try_fips_mode().map_err(|_| CryptoError::FipsUnavailable)
    }
    #[cfg(feature = "jwt")]
    fn verifier(&self, alg: crate::jwt::JwsAlg) -> Option<&dyn crate::jwt::JwsVerifier> {
        // Conservative FIPS 3 policy: no Ed25519; FAPI further restricts RS256 itself.
        if alg == crate::jwt::JwsAlg::EdDsa {
            None
        } else {
            Some(verifier(alg, true))
        }
    }
    #[cfg(feature = "jwt")]
    fn signing_key(
        &self,
        alg: crate::jwt::JwsAlg,
        kid: &str,
        der: &[u8],
    ) -> Result<super::ProviderSigner, CryptoError> {
        self.validate()?;
        if self.verifier(alg).is_none() {
            return Err(CryptoError::UnsupportedAlgorithm(alg.jose_name()));
        }
        load_key(alg, kid, der, true)
    }
}

#[cfg(feature = "jwt")]
use crate::jwt::{Jwk, JwsAlg, JwsSignature, JwsSigner, JwsVerifier, SignerError};
#[cfg(feature = "jwt")]
use aws_lc_rs::signature::{self, KeyPair};
#[cfg(feature = "jwt")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};

#[cfg(feature = "jwt")]
struct Verifier(JwsAlg, bool);
#[cfg(feature = "jwt")]
fn verifier(alg: JwsAlg, fips: bool) -> &'static Verifier {
    match (alg, fips) {
        (JwsAlg::Es256, false) => &Verifier(JwsAlg::Es256, false),
        (JwsAlg::EdDsa, false) => &Verifier(JwsAlg::EdDsa, false),
        (JwsAlg::Rs256, false) => &Verifier(JwsAlg::Rs256, false),
        (JwsAlg::Ps256, false) => &Verifier(JwsAlg::Ps256, false),
        (JwsAlg::Es256, true) => &Verifier(JwsAlg::Es256, true),
        (JwsAlg::EdDsa, true) => &Verifier(JwsAlg::EdDsa, true),
        (JwsAlg::Rs256, true) => &Verifier(JwsAlg::Rs256, true),
        (JwsAlg::Ps256, true) => &Verifier(JwsAlg::Ps256, true),
    }
}
// Certificate 5314, approved RSA signature sizes. Require the high bit as well as byte
// length: a 3071-bit modulus occupies the same number of bytes as a 3072-bit modulus.
#[cfg(feature = "jwt")]
fn approved_rsa_modulus(n: &[u8]) -> bool {
    [256, 384, 512].contains(&n.len()) && n[0] & 0x80 != 0
}
#[cfg(feature = "jwt")]
impl JwsVerifier for Verifier {
    fn alg(&self) -> JwsAlg {
        self.0
    }
    fn verify(&self, key: &Jwk, message: &[u8], sig: &[u8]) -> bool {
        if !crate::jwt::consistent(self.0, key) || (self.1 && self.0 == JwsAlg::EdDsa) {
            return false;
        }
        match key {
            Jwk::Ec { x, y, .. } => {
                let (Ok(x), Ok(y)) = (B64.decode(x), B64.decode(y)) else {
                    return false;
                };
                if x.len() != 32 || y.len() != 32 || sig.len() != 64 {
                    return false;
                }
                let mut point = [0; 65];
                point[0] = 4;
                point[1..33].copy_from_slice(&x);
                point[33..].copy_from_slice(&y);
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, sig)
                    .is_ok()
            }
            Jwk::Okp { x, .. } => {
                let Ok(key) = B64.decode(x) else {
                    return false;
                };
                if key.len() != 32 || sig.len() != 64 {
                    return false;
                }
                signature::UnparsedPublicKey::new(&signature::ED25519, key)
                    .verify(message, sig)
                    .is_ok()
            }
            Jwk::Rsa { n, e, .. } => {
                let (Ok(n), Ok(e)) = (B64.decode(n), B64.decode(e)) else {
                    return false;
                };
                if self.1 && !approved_rsa_modulus(&n) {
                    return false;
                }
                let alg = match self.0 {
                    JwsAlg::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    JwsAlg::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
                    _ => return false,
                };
                signature::RsaPublicKeyComponents { n, e }
                    .verify(alg, message, sig)
                    .is_ok()
            }
        }
    }
}
#[cfg(feature = "jwt")]
enum Key {
    Ec(signature::EcdsaKeyPair),
    Ed(signature::Ed25519KeyPair),
    Rsa(signature::RsaKeyPair),
}
#[cfg(feature = "jwt")]
struct Signer {
    key: Key,
    alg: JwsAlg,
    public: Jwk,
}
#[cfg(feature = "jwt")]
fn load_key(
    alg: JwsAlg,
    kid: &str,
    der: &[u8],
    fips: bool,
) -> Result<super::ProviderSigner, CryptoError> {
    let (key, public) = match alg {
        JwsAlg::Es256 => {
            let k = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                der,
            )
            .map_err(|_| CryptoError::InvalidKey)?;
            let p = k.public_key().as_ref();
            if p.len() != 65 || p[0] != 4 {
                return Err(CryptoError::InvalidKey);
            }
            let j = Jwk::from_coordinates(&B64.encode(&p[1..33]), &B64.encode(&p[33..]))
                .map_err(|_| CryptoError::InvalidKey)?
                .with_kid(kid);
            (Key::Ec(k), j)
        }
        JwsAlg::EdDsa => {
            if fips {
                return Err(CryptoError::UnsupportedAlgorithm(alg.jose_name()));
            }
            let k =
                signature::Ed25519KeyPair::from_pkcs8(der).map_err(|_| CryptoError::InvalidKey)?;
            let j = Jwk::from_json(&serde_json::json!({
                "kty": "OKP", "crv": "Ed25519", "x": B64.encode(k.public_key().as_ref()), "kid": kid
            }))
            .map_err(|_| CryptoError::InvalidKey)?;
            (Key::Ed(k), j)
        }
        JwsAlg::Rs256 | JwsAlg::Ps256 => {
            let k = signature::RsaKeyPair::from_pkcs8(der).map_err(|_| CryptoError::InvalidKey)?;
            let p = k.public_key();
            let n = p.modulus().big_endian_without_leading_zero();
            let e = p.exponent().big_endian_without_leading_zero();
            if n.len() < 256 || (fips && !approved_rsa_modulus(n)) {
                return Err(CryptoError::InvalidKey);
            }
            #[cfg(feature = "fips")]
            if fips && !k.is_valid_fips_key() {
                return Err(CryptoError::InvalidKey);
            }
            let j = Jwk::from_json(
                &serde_json::json!({"kty":"RSA","n":B64.encode(n),"e":B64.encode(e),"kid":kid}),
            )
            .map_err(|_| CryptoError::InvalidKey)?;
            (Key::Rsa(k), j)
        }
    };
    Ok(super::ProviderSigner::from_signer(Signer {
        key,
        alg,
        public,
    }))
}
#[cfg(feature = "jwt")]
impl JwsSigner for Signer {
    fn alg(&self) -> JwsAlg {
        self.alg
    }
    fn public_jwk(&self) -> Jwk {
        self.public.clone()
    }
    async fn sign(&self, message: &[u8]) -> Result<JwsSignature, SignerError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let err = || SignerError::new("AWS-LC signing failed");
        match &self.key {
            Key::Ec(k) => {
                let s = k.sign(&rng, message).map_err(|_| err())?;
                JwsSignature::from_wire(self.alg, s.as_ref()).ok_or_else(err)
            }
            Key::Ed(k) => {
                JwsSignature::from_wire(self.alg, k.sign(message).as_ref()).ok_or_else(err)
            }
            Key::Rsa(k) => {
                let mut out = vec![0; k.public_modulus_len()];
                let padding: &dyn signature::RsaEncoding = if self.alg == JwsAlg::Ps256 {
                    &signature::RSA_PSS_SHA256
                } else {
                    &signature::RSA_PKCS1_SHA256
                };
                k.sign(padding, &rng, message, &mut out)
                    .map_err(|_| err())?;
                JwsSignature::from_wire(self.alg, &out).ok_or_else(err)
            }
        }
    }
}
