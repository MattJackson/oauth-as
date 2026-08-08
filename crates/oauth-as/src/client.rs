// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Registered OAuth clients, mirrored from RFC 6749 section 2 with the OAuth 2.1 public /
//! confidential split.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::grant::GrantType;
use crate::scope::ScopeSet;

/// A client identifier (RFC 6749 section 2.2): opaque to this crate, unique per registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId(String);

impl ClientId {
    /// Wrap an identifier.
    pub fn new(id: impl Into<String>) -> Self {
        ClientId(id.into())
    }

    /// The identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the client authenticates to the token endpoint (RFC 6749 section 2.3).
///
/// `Debug` is hand-written rather than derived (see below) so that `ConfidentialSecret`'s secret
/// never appears in a debug format. `Client` derives `Debug` and holds a `ClientAuth`, so this
/// also keeps `{:?}` on a whole `Client` safe, without needing a hand-written `Debug` there too.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientAuth {
    /// A public client (native app, browser app, device): no secret exists, so possession of the
    /// `client_id` proves nothing and the flows compensate (PKCE, device-code user interaction).
    Public,
    /// A confidential client holding a secret. The host decides how the secret at rest is
    /// protected; this crate only compares, in constant time.
    ConfidentialSecret {
        /// The shared secret the client presents.
        secret: String,
    },
}

/// Hand-written so `ConfidentialSecret { secret }` never prints the secret. An AS library that
/// logs nothing itself should still not make `tracing::debug!(?client)` on a host's part into a
/// plaintext credential leak; deriving `Debug` here would do exactly that. Every non-secret
/// variant and field stays visible so the type is still useful to debug-print.
impl fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientAuth::Public => f.write_str("Public"),
            ClientAuth::ConfidentialSecret { secret: _ } => f
                .debug_struct("ConfidentialSecret")
                .field("secret", &"[redacted]")
                .finish(),
        }
    }
}

impl ClientAuth {
    /// Verify a presented secret. Public clients accept `None` and reject any presented secret
    /// (presenting a secret for a secretless registration is a client mixup worth failing loud
    /// on). Confidential clients require the exact secret; the comparison is constant time
    /// regardless of the length of either the registered or the presented secret (see
    /// [`constant_time_eq`]).
    ///
    /// What this does NOT cover: if the caller (see `server.rs`) returns early for an unknown
    /// `client_id` before ever calling `verify`, an unknown client and a known client with a
    /// wrong secret are distinguishable by timing even though `verify` itself leaks nothing.
    /// Making those two paths cost the same wall time is the caller's responsibility, not this
    /// function's; a caller that cares should call `verify` against some registered client (or an
    /// equivalent-cost dummy) on the unknown-client path too.
    pub fn verify(&self, presented: Option<&str>) -> bool {
        match self {
            ClientAuth::Public => presented.is_none(),
            ClientAuth::ConfidentialSecret { secret } => match presented {
                Some(p) => constant_time_eq(secret.as_bytes(), p.as_bytes()),
                None => false,
            },
        }
    }
}

/// Constant-time equality, by comparing SHA-256 digests over a fixed 32 bytes rather than the raw
/// inputs.
///
/// Hashing first is what makes this constant time, on two axes that a raw byte-by-byte compare
/// cannot deliver at once:
///
/// 1. Value: the accumulator below visits all 32 digest bytes regardless of where (or whether) the
///    inputs first differ, so no early difference shows up as an early exit.
/// 2. Length: SHA-256 always produces exactly 32 bytes no matter how long `a` or `b` are, so the
///    loop always runs exactly 32 iterations. Comparing the raw inputs directly, even with a
///    "run for max(a.len(), b.len())" loop, makes wall time grow with the presented secret's
///    length once it exceeds the registered one, which lets a network attacker binary-search the
///    registered secret's length by timing the token endpoint. Hashing first removes the input
///    length from the loop bound entirely.
///
/// This also happens to make the function actually correct: two digests are equal only when the
/// two inputs were equal (SHA-256 collision resistance), so there is no longer a length-encoding
/// edge case where sufficiently padded unequal inputs compare equal.
///
/// This is NOT password hashing, and SHA-256 is not being used as a KDF here. `secret` is a
/// high-entropy, host-generated and host-managed credential, not a human-chosen password, so
/// there is no offline-guessing threat this needs to be slow against. SHA-256's only job in this
/// function is to be a fixed-width length equaliser ahead of a constant-time compare; nobody
/// should read this as a template for verifying user passwords.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    let mut acc: u8 = 0;
    for i in 0..32 {
        acc |= da[i] ^ db[i];
    }
    acc == 0
}

/// A registered client: identity, authentication, and what it is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// The unique client identifier.
    pub client_id: ClientId,
    /// How the client authenticates.
    pub auth: ClientAuth,
    /// The grant types this registration may use; anything else is `unauthorized_client`.
    pub grant_types: Vec<GrantType>,
    /// Registered redirect URIs (authorization-code grant; exact-match per OAuth 2.1).
    pub redirect_uris: Vec<String>,
    /// The scopes this client may ever be granted; a request outside this set is `invalid_scope`.
    pub allowed_scopes: ScopeSet,
    /// The scopes granted when a request names none (RFC 6749 section 3.3 server default).
    pub default_scopes: ScopeSet,
    /// Human-readable name for consent and admin surfaces.
    pub name: Option<String>,
}

impl Client {
    /// Whether the registration permits `grant_type`.
    pub fn allows_grant(&self, grant_type: GrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }
}

#[cfg(test)]
#[path = "tests/client.rs"]
mod tests;
