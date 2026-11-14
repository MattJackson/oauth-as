// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
//! Backend selection for conformance fixtures; never a production key source.
use oauth_as::crypto::{CryptoError, CryptoProvider, ProviderSigner};
use oauth_as::jwt::JwsAlg;
use std::sync::Arc;

pub fn provider() -> Result<Arc<dyn CryptoProvider>, CryptoError> {
    let p: Arc<dyn CryptoProvider> = match std::env::var("OAUTH_AS_CRYPTO").as_deref() {
        #[cfg(feature = "rustcrypto")]
        Ok("rustcrypto") => Arc::new(oauth_as::crypto::RustCrypto),
        #[cfg(feature = "aws-lc")]
        Ok("aws-lc") => Arc::new(oauth_as::crypto::AwsLc),
        #[cfg(feature = "fips")]
        Ok("fips") => Arc::new(oauth_as::crypto::Fips),
        Err(_) => oauth_as::crypto::default_provider()?,
        _ => return Err(CryptoError::MissingProvider),
    };
    p.validate()?;
    Ok(p)
}

pub fn scalar_key(
    p: &dyn CryptoProvider,
    kid: &str,
    scalar: &[u8; 32],
) -> Result<ProviderSigner, CryptoError> {
    // RFC 5208 PrivateKeyInfo containing an RFC 5915 ECPrivateKey, P-256 OIDs.
    // The public key is derived by the selected backend; no other crypto stack is involved.
    let mut der = vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25,
        0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(scalar);
    p.signing_key(JwsAlg::Es256, kid, &der)
}
