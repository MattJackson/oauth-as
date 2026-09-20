// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `JwsSignature::from_wire`, RFC 7518 sections 3.3 and 3.4 (the signature width contract).
//!
//! The third segment of a compact JWS is attacker-controlled octets of ANY length. `from_wire` is
//! the seam that turns those decoded octets into a typed `JwsSignature` for a chosen algorithm, or
//! refuses them. It is the width check the fixed-size arrays (`[u8; 64]` for ES256 and EdDSA) make
//! impossible to skip, and RS256's deliberate absence of one (its width is the signer's modulus,
//! not known here, so the guard is the verifier's per key). A length the fuzzer supplies — 0, 63,
//! 64, 65, 255, 256, 512, or enormous — must produce a `Some`/`None`, never a panic and never an
//! out-of-bounds slice.
//!
//! # The invariants
//!
//! 1. NEVER PANICS. Any `(alg, bytes)` pair returns an `Option`, for every length including the
//!    empty slice.
//! 2. THE FIXED-WIDTH CURVES ARE EXACTLY 64 BYTES. `from_wire` returns `Some` for ES256/EdDSA if
//!    and only if the input is exactly 64 bytes long. This is the whole point of the width check.
//! 3. RS256 IS LENGTH-LENIENT BY DESIGN. `from_wire` returns `Some` for RS256 whatever the length
//!    (the modulus-equality check belongs to `RsaVerifier`, not the wire), so the octets survive
//!    verbatim to the verifier that CAN size them.
//! 4. THE ROUND TRIP IS FAITHFUL. When `from_wire` accepts, the result reports the algorithm it
//!    was asked for and hands back exactly the octets it was given.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use oauth_as::jwt::{JwsAlg, JwsSignature};

/// `JwsAlg` is a closed enum in the crate and does not derive `Arbitrary`, so the choice is made
/// here over its three variants.
fn arbitrary_alg(u: &mut Unstructured<'_>) -> arbitrary::Result<JwsAlg> {
    Ok(*u.choose(&[JwsAlg::Es256, JwsAlg::Rs256, JwsAlg::EdDsa, JwsAlg::Ps256])?)
}

/// The wire octets. A raw byte buffer some of the time; a buffer of a length chosen from the set
/// that straddles the 64-byte boundary and the common modulus sizes the rest of the time, so the
/// interesting lengths are hit far more often than a purely random length would hit them.
fn arbitrary_wire(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    if u.arbitrary()? {
        // A fuzzer-chosen length drawn from the boundary set, filled with fuzzer bytes.
        let len = *u.choose(&[
            0usize, 1, 32, 63, 64, 65, 127, 128, 255, 256, 384, 512, 4096,
        ])?;
        u.bytes(len).map(<[u8]>::to_vec)
    } else {
        // The front door: a wholly arbitrary buffer, whatever length the generator lands on.
        <Vec<u8>>::arbitrary(u)
    }
}

#[derive(Debug)]
struct Input {
    alg: JwsAlg,
    raw: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Input {
            alg: arbitrary_alg(u)?,
            raw: arbitrary_wire(u)?,
        })
    }
}

fuzz_target!(|input: Input| {
    let Input { alg, raw } = input;

    // 1. The call itself is the invariant: it must return, never panic.
    let signature = JwsSignature::from_wire(alg, &raw);

    match alg {
        // 2.
        JwsAlg::Es256 | JwsAlg::EdDsa => assert_eq!(
            signature.is_some(),
            raw.len() == 64,
            "{alg:?} from_wire accepted iff the input is 64 bytes was violated at len {}",
            raw.len()
        ),
        // 3. RS256 and PS256 (both RSA, modulus-width signatures) are length-lenient by design:
        // `from_wire` accepts any width and the `length == modulus` check is the verifier's.
        JwsAlg::Rs256 | JwsAlg::Ps256 => assert!(
            signature.is_some(),
            "{alg:?} from_wire refused a {}-byte input; RSA signatures are length-lenient by design",
            raw.len()
        ),
    }

    // 4.
    if let Some(sig) = signature {
        assert_eq!(sig.alg(), alg, "from_wire retagged the algorithm");
        assert_eq!(
            sig.as_bytes(),
            raw.as_slice(),
            "from_wire did not preserve the wire octets verbatim"
        );
    }
});
