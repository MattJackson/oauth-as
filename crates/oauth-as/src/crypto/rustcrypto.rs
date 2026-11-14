// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
use super::{CryptoError, CryptoProvider};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// RustCrypto primitives, with asymmetric backends enabled by their existing features.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCrypto;
impl CryptoProvider for RustCrypto {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }
    fn hmac_sha256(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        // HMAC accepts every key length. The fallible trait signature is generic over MACs.
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key length");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(output).map_err(|_| CryptoError::EntropyUnavailable)
    }
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        bool::from(a.ct_eq(b))
    }
    #[cfg(feature = "jwt")]
    fn verifier(&self, alg: crate::jwt::JwsAlg) -> Option<&dyn crate::jwt::JwsVerifier> {
        match alg {
            #[cfg(feature = "jwt-p256")]
            crate::jwt::JwsAlg::Es256 => Some(&crate::jwt::P256Verifier),
            #[cfg(feature = "jwt-rsa")]
            crate::jwt::JwsAlg::Rs256 => Some(&crate::backends::rsa::RsaVerifier),
            #[cfg(feature = "jwt-rsa")]
            crate::jwt::JwsAlg::Ps256 => Some(&crate::backends::rsa::Ps256Verifier),
            #[cfg(feature = "jwt-ed25519")]
            crate::jwt::JwsAlg::EdDsa => Some(&crate::backends::ed25519::Ed25519Verifier),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
    #[cfg(feature = "jwt")]
    fn signing_key(
        &self,
        alg: crate::jwt::JwsAlg,
        kid: &str,
        der: &[u8],
    ) -> Result<super::ProviderSigner, CryptoError> {
        let _ = (kid, der);
        match alg {
            #[cfg(feature = "jwt-pkcs8")]
            crate::jwt::JwsAlg::Es256 => crate::jwt::EcdsaP256Key::from_pkcs8_der(kid, der)
                .map(super::ProviderSigner::from_signer)
                .map_err(|_| CryptoError::InvalidKey),
            #[cfg(feature = "jwt-rsa")]
            crate::jwt::JwsAlg::Rs256 => crate::backends::rsa::RsaSigner::from_pkcs8_der(kid, der)
                .map(super::ProviderSigner::from_signer)
                .map_err(|_| CryptoError::InvalidKey),
            #[cfg(feature = "jwt-rsa")]
            crate::jwt::JwsAlg::Ps256 => {
                crate::backends::rsa::Ps256Signer::from_pkcs8_der(kid, der)
                    .map(super::ProviderSigner::from_signer)
                    .map_err(|_| CryptoError::InvalidKey)
            }
            #[cfg(feature = "jwt-ed25519-pkcs8")]
            crate::jwt::JwsAlg::EdDsa => {
                crate::backends::ed25519::Ed25519Signer::from_pkcs8_der(kid, der)
                    .map(super::ProviderSigner::from_signer)
                    .map_err(|_| CryptoError::InvalidKey)
            }
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::UnsupportedAlgorithm(alg.jose_name())),
        }
    }
}
