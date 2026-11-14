// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
//! Explicit, per-server cryptographic implementations. No global provider or implicit fallback.
use std::{fmt, sync::Arc};

/// A provider or its configuration could not perform the requested operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// No implementation was selected and none is compiled in.
    MissingProvider,
    /// Secure random bytes could not be obtained.
    EntropyUnavailable,
    /// The selected provider does not implement or permit this algorithm.
    UnsupportedAlgorithm(&'static str),
    /// A key is malformed, too small, or unsuitable for the requested algorithm.
    InvalidKey,
    /// Signing failed without producing a signature.
    SigningFailed,
    /// The requested validated module is not operating in FIPS mode.
    FipsUnavailable,
}
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProvider => {
                f.write_str("supply a CryptoProvider or enable a backend feature")
            }
            Self::EntropyUnavailable => f.write_str("secure entropy unavailable"),
            Self::UnsupportedAlgorithm(a) => write!(f, "crypto provider refuses algorithm {a}"),
            Self::InvalidKey => f.write_str("invalid cryptographic key"),
            Self::SigningFailed => f.write_str("cryptographic signing failed"),
            Self::FipsUnavailable => f.write_str("AWS-LC FIPS mode unavailable"),
        }
    }
}
impl std::error::Error for CryptoError {}

/// The host's sole primitive implementation. Implementations must not panic on errors.
///
/// `ct_eq` must compare equal-length contents in constant time. Length is public; callers
/// must not use it to compare variable-length human passwords. Randomness must be a CSPRNG.
/// Unsupported asymmetric algorithms return no verifier and a typed key-construction error.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Validate provider initialization before constructing a server.
    fn validate(&self) -> Result<(), CryptoError> {
        Ok(())
    }
    /// SHA-256 of exactly these bytes (RFC 6234).
    fn sha256(&self, input: &[u8]) -> [u8; 32];
    /// HMAC-SHA-256, including standard long-key normalization (RFC 2104).
    fn hmac_sha256(&self, key: &[u8], message: &[u8]) -> [u8; 32];
    /// Fill all bytes securely or return an error; callers discard the buffer on error.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError>;
    /// Constant-time equality for equal-length byte strings.
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool;
    /// The verifier for this algorithm, with no fallback to another implementation.
    #[cfg(feature = "jwt")]
    fn verifier(&self, _alg: crate::jwt::JwsAlg) -> Option<&dyn crate::jwt::JwsVerifier> {
        None
    }
    /// Load an algorithm-pinned PKCS#8 signing key. KMS hosts may return their own signer.
    #[cfg(feature = "jwt")]
    fn signing_key(
        &self,
        alg: crate::jwt::JwsAlg,
        _kid: &str,
        _pkcs8: &[u8],
    ) -> Result<ProviderSigner, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(alg.jose_name()))
    }
}

/// An object-safe signing key, reusable through the existing `JwsSigner` contract.
#[cfg(feature = "jwt")]
#[derive(Clone)]
pub struct ProviderSigner(Arc<dyn SigningKey>);
/// Object-safe async key operations for host KMS/HSM implementations.
#[cfg(feature = "jwt")]
pub trait SigningKey: Send + Sync + 'static {
    /// Fixed algorithm; never inferred from untrusted input.
    fn alg(&self) -> crate::jwt::JwsAlg;
    /// Cached public key only.
    fn public_jwk(&self) -> crate::jwt::Jwk;
    /// Sign the complete JWS input, propagating provider failures.
    fn sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<crate::jwt::JwsSignature, crate::jwt::SignerError>,
                > + Send
                + 'a,
        >,
    >;
}
#[cfg(feature = "jwt")]
impl ProviderSigner {
    /// Adapt a host's object-safe key.
    pub fn new(key: Arc<dyn SigningKey>) -> Self {
        Self(key)
    }
    /// Adapt an existing async signer without changing its public API.
    pub fn from_signer<T: crate::jwt::JwsSigner + 'static>(signer: T) -> Self {
        struct Adapter<T>(T);
        impl<T: crate::jwt::JwsSigner + 'static> SigningKey for Adapter<T> {
            fn alg(&self) -> crate::jwt::JwsAlg {
                self.0.alg()
            }
            fn public_jwk(&self) -> crate::jwt::Jwk {
                self.0.public_jwk()
            }
            fn sign<'a>(
                &'a self,
                msg: &'a [u8],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<crate::jwt::JwsSignature, crate::jwt::SignerError>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(self.0.sign(msg))
            }
        }
        Self(Arc::new(Adapter(signer)))
    }
}
#[cfg(feature = "jwt")]
impl crate::jwt::JwsSigner for ProviderSigner {
    fn alg(&self) -> crate::jwt::JwsAlg {
        self.0.alg()
    }
    fn public_jwk(&self) -> crate::jwt::Jwk {
        self.0.public_jwk()
    }
    async fn sign(
        &self,
        message: &[u8],
    ) -> Result<crate::jwt::JwsSignature, crate::jwt::SignerError> {
        self.0.sign(message).await
    }
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto::RustCrypto;
#[cfg(any(feature = "aws-lc", feature = "fips"))]
mod aws_lc;
#[cfg(feature = "aws-lc")]
pub use aws_lc::AwsLc;
#[cfg(feature = "fips")]
pub use aws_lc::Fips;

/// Select the compiled default. Explicit server injection always wins over this helper.
/// RustCrypto preserves legacy defaults when compiled; otherwise FIPS precedes AWS-LC.
/// Explicit FIPS deployments disable defaults or pass `Fips` directly. Errors never fall back.
pub fn default_provider() -> Result<Arc<dyn CryptoProvider>, CryptoError> {
    #[cfg(any(feature = "rustcrypto", feature = "aws-lc", feature = "fips"))]
    {
        let p = builtin();
        p.validate()?;
        Ok(Arc::new(p))
    }
    #[cfg(not(any(feature = "rustcrypto", feature = "aws-lc", feature = "fips")))]
    {
        Err(CryptoError::MissingProvider)
    }
}

// Value construction, never global mutable state or a cached provider.
#[cfg(all(feature = "fips", not(feature = "rustcrypto")))]
pub(crate) fn builtin() -> Fips {
    Fips
}
#[cfg(all(feature = "aws-lc", not(feature = "fips"), not(feature = "rustcrypto")))]
pub(crate) fn builtin() -> AwsLc {
    AwsLc
}
#[cfg(feature = "rustcrypto")]
pub(crate) fn builtin() -> RustCrypto {
    RustCrypto
}

#[cfg(feature = "jwt")]
pub(crate) struct ProviderVerifier {
    pub(crate) provider: Arc<dyn CryptoProvider>,
    pub(crate) alg: crate::jwt::JwsAlg,
}
#[cfg(feature = "jwt")]
impl crate::jwt::JwsVerifier for ProviderVerifier {
    fn alg(&self) -> crate::jwt::JwsAlg {
        self.alg
    }
    fn verify(&self, key: &crate::jwt::Jwk, message: &[u8], signature: &[u8]) -> bool {
        self.provider
            .verifier(self.alg)
            .is_some_and(|v| v.verify(key, message, signature))
    }
}

/// Build verifier slots from exactly one provider, with no fallback implementations.
#[cfg(feature = "jwt")]
pub fn verifiers(provider: Arc<dyn CryptoProvider>) -> crate::jwt::JwsVerifiers {
    let mut out = crate::jwt::JwsVerifiers::new();
    for &alg in crate::jwt::JwsAlg::ALL {
        if provider.verifier(alg).is_some() {
            out.install(Arc::new(ProviderVerifier {
                provider: provider.clone(),
                alg,
            }));
        }
    }
    out
}
