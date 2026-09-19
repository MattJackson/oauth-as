// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Pluggable JWS backends: the concrete `JwsSigner`/`JwsVerifier` implementations this crate ships
//! for the seam defined in [`crate::jwt`]. Each backend is behind its own `jwt-<alg>` feature and
//! adds exactly one arithmetic dependency; the seam itself (`jwt`) carries none.
//!
//! - `jwt-p256` — ES256 over `p256`. (Ships inline in [`crate::jwt`] as `EcdsaP256Key`, kept there
//!   because it predates this module.)
//! - `jwt-rsa` — RS256 over `rsa`. See [`rsa`](crate::backends::rsa).
//! - `jwt-ed25519` — EdDSA/Ed25519 over `ed25519-dalek`. See [`ed25519`](crate::backends::ed25519).
//!
//! Each backend is ADDITIVE: a tree that enables several compiles, each installs its verifier as a
//! default for its own algorithm, and a host that installs its own always wins because installation
//! beats a feature flag.

#[cfg(feature = "jwt-rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-rsa")))]
pub mod rsa;

#[cfg(feature = "jwt-ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-ed25519")))]
pub mod ed25519;
