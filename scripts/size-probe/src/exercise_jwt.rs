// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The `jwt` plane: key handling, RFC 9068 signing, the RFC 7517 JWKS, and verification.
//!
//! The core plane already signs, because `exercise::config` sets `AccessTokenFormat::Jwt` when
//! this feature is on, so every token issued there goes through ES256. What this adds is the rest
//! of the surface a host touches: key import and export, the published key set, and the
//! VERIFICATION half that `jar`, `dpop` and `client-assertion` all rest on.

use oauth_as::jwt::Jwk;

pub fn plane() -> u64 {
    let mut acc: u64 = 0;

    // The SEAM half, which is all a host with its own backend links: a published JWK, serialized,
    // read back through the attacker-input parser, and thumbprinted. One copy of this code serves
    // `jar`, `dpop` and `client-assertion` (see the VERIFICATION banner in src/jwt.rs), so it is
    // charged to `jwt` here rather than three times over.
    #[cfg(not(feature = "f-jwt-p256"))]
    let jwk = {
        // 43 base64url characters decode to exactly the 32 bytes RFC 7518 s6.2.1.2 fixes a P-256
        // coordinate at. All-zero rather than a real point, and spelled out rather than encoded,
        // so the probe takes no `base64` dependency of its own: nothing here verifies anything,
        // and a coordinate that is well FORMED is all the JWKS serialization path reads.
        Jwk::Ec {
            crv: oauth_as::jwt::EcCurve::P256,
            x: "A".repeat(43),
            y: "A".repeat(43),
            kid: Some("probe-host-2".to_string()),
        }
    };

    #[cfg(feature = "f-jwt-p256")]
    let jwk = {
        use oauth_as::jwt::EcdsaP256Key;

        let key = EcdsaP256Key::generate("probe-es256-2");
        acc = acc.wrapping_add(key.kid().len() as u64);

        // PKCS#8 export and re-import. This is the ONLY thing p256's `pkcs8` sub-feature buys, and
        // it is behind this crate's own `jwt-pkcs8` feature, so the report can show BOTH what it
        // costs a host that uses it and what it costs a host that merely has it compiled in.
        #[cfg(feature = "f-jwt-pkcs8")]
        if let Ok(der) = key.to_pkcs8_der() {
            acc = acc.wrapping_add(der.len() as u64);
            if let Ok(reloaded) = EcdsaP256Key::from_pkcs8_der("probe-es256-3", &der) {
                acc = acc.wrapping_add(reloaded.kid().len() as u64);
            }
        }
        // The raw-scalar constructor, which is what a host provisioning its own key file uses.
        let scalar = [7u8; 32];
        if let Ok(from_scalar) = EcdsaP256Key::from_scalar_bytes("probe-es256-4", &scalar) {
            acc = acc.wrapping_add(from_scalar.kid().len() as u64);
        }
        // The ES256 VERIFICATION arithmetic is deliberately NOT exercised here, and that is
        // unchanged from before the seam: it is charged to the `jar`, `dpop` and
        // `client-assertion` rows, which are the features a host turns on to use it. Charging it
        // here as well would make this row incomparable with the `jwt` row it replaces.
        key.public_jwk()
    };

    // RFC 7517: the JWK and the key set a resource server fetches.
    acc = acc.wrapping_add(
        serde_json::to_string(&jwk)
            .map(|s| s.len() as u64)
            .unwrap_or(0),
    );

    if let Ok(value) = serde_json::to_value(&jwk) {
        if let Ok(parsed) = Jwk::from_json(&value) {
            acc = acc.wrapping_add(parsed.thumbprint().len() as u64);
            acc = acc.wrapping_add(parsed.kty().len() as u64);
        }
    }

    // THE BUILT-IN RS256 BACKEND (`jwt-rsa`), signing AND verification arithmetic both linked, so
    // the row measures what a host issuing or validating RS256 tokens actually pays for the `rsa`
    // crate. The signer is loaded through `from_pkcs8_der` behind a `black_box`, so fat LTO cannot
    // const-fold the input to `Err` and delete the signing path: the probe is BUILT and measured,
    // never RUN, so the bytes need not decode to a real key. The verifier half runs on a
    // well-FORMED RSA JWK so the attacker-input parser and the modexp are reached, not short-cut.
    #[cfg(feature = "f-jwt-rsa")]
    {
        use oauth_as::{JwsSigner, JwsVerifier, RsaSigner, RsaVerifier};
        let der = std::hint::black_box([0u8; 16]);
        if let Ok(signer) = RsaSigner::from_pkcs8_der("probe-rs256", &der) {
            acc = acc.wrapping_add(signer.kid().len() as u64);
            if let Ok(sig) = crate::blockon::block_on(JwsSigner::sign(&signer, b"probe.rs256")) {
                acc = acc.wrapping_add(sig.as_bytes().len() as u64);
            }
            acc = acc.wrapping_add(
                serde_json::to_string(&signer.public_jwk())
                    .map(|s| s.len() as u64)
                    .unwrap_or(0),
            );
        }
        let rsa_jwk = Jwk::Rsa {
            n: std::hint::black_box("A".repeat(342)),
            e: "AQAB".to_string(),
            kid: Some("probe-rs256".to_string()),
        };
        let rsa_sig = std::hint::black_box(vec![0u8; 256]);
        acc = acc.wrapping_add(u64::from(RsaVerifier.verify(
            &rsa_jwk,
            b"probe.rs256",
            &rsa_sig,
        )));
    }

    // THE BUILT-IN EdDSA (Ed25519) BACKEND (`jwt-ed25519`). `from_seed_bytes` takes a raw 32-byte
    // seed and always succeeds, so this genuinely produces a signer, signs, and verifies -- the
    // whole `ed25519-dalek` signing and `verify_strict` path is linked.
    #[cfg(feature = "f-jwt-ed25519")]
    {
        use oauth_as::{Ed25519Signer, Ed25519Verifier, JwsSigner, JwsVerifier};
        let seed = std::hint::black_box([7u8; 32]);
        if let Ok(signer) = Ed25519Signer::from_seed_bytes("probe-eddsa", &seed) {
            acc = acc.wrapping_add(signer.kid().len() as u64);
            let public = signer.public_jwk();
            if let Ok(sig) = crate::blockon::block_on(JwsSigner::sign(&signer, b"probe.eddsa")) {
                acc = acc.wrapping_add(u64::from(Ed25519Verifier.verify(
                    &public,
                    b"probe.eddsa",
                    sig.as_bytes(),
                )));
            }
            acc = acc.wrapping_add(
                serde_json::to_string(&public)
                    .map(|s| s.len() as u64)
                    .unwrap_or(0),
            );
        }
        // The PKCS#8 DER loader (`jwt-ed25519-pkcs8`), the EdDSA sibling of `jwt-pkcs8`: the ONLY
        // thing `ed25519-dalek`'s `pkcs8` sub-feature buys. Loaded behind a `black_box` for the
        // same reason as the RSA path above.
        #[cfg(feature = "f-jwt-ed25519-pkcs8")]
        {
            let der = std::hint::black_box([0u8; 16]);
            if let Ok(reloaded) = Ed25519Signer::from_pkcs8_der("probe-eddsa-2", &der) {
                acc = acc.wrapping_add(reloaded.kid().len() as u64);
            }
        }
    }

    std::hint::black_box(acc)
}
