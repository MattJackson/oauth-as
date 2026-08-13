// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Registered OAuth clients, mirrored from RFC 6749 section 2 with the OAuth 2.1 public /
//! confidential split.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::grant::GrantType;
// Aliased to the name this module used when it carried its own copy of the encoder, so the call
// sites below (and `src/tests/client.rs`, which reaches the private helper) read unchanged. There
// is one FUNCTION; `crate::hex` owns it, and `tests/hex_single_definition.rs` keeps it at one.
use crate::hex::encode as hex_lower;
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

/// A STORED VERIFIER for a client secret: enough to check a presented secret, never enough to
/// present one.
///
/// This is what [`ClientAuth::ConfidentialSecretHash`] holds, and it is the shape a host should
/// persist. RFC 6749 section 2.3.1 says the client secret is a password; a password at rest
/// belongs in a one-way form, so that a dump of the client table is not a set of working
/// credentials.
///
/// Two kinds of scheme:
///
/// - [`SecretHash::SHA256_HEX`], built by [`SecretHash::sha256`] and verified by this crate with
///   no host code and no new dependency (`sha2` is already here for RFC 7636 PKCE). Plain SHA-256
///   is the RIGHT primitive for this particular job and the wrong one for a user password: a
///   client secret is high-entropy and host-generated, so there is no dictionary to run against
///   it, and the offline-guessing threat that makes a slow KDF necessary for human-chosen
///   passwords does not exist here. The comparison is constant time regardless, for the reason
///   given on [`ClientAuth::verify_with`].
/// - Anything else, built by [`SecretHash::custom`] and verified by a host-supplied
///   [`SecretVerifier`]. A host whose policy names argon2id, scrypt or bcrypt, or whose
///   verification happens in an HSM, keeps that dependency in its own tree where it belongs. A
///   custom scheme with NO verifier installed never authenticates: failing closed is the only
///   safe reading of "the server cannot check this credential".
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHash {
    scheme: String,
    encoded: String,
}

/// Hand-written for the same reason as [`ClientAuth`]'s: a stored verifier is not a credential a
/// client can present, but it IS the input to an offline attack, so it must not turn up in a
/// host's logs through `{:?}`. The SCHEME stays visible, because that is the field an operator
/// needs when auditing which registrations still use a weak or retired one.
impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretHash")
            .field("scheme", &self.scheme)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

impl SecretHash {
    /// The scheme identifier for the built-in hash: lower-case hex of the SHA-256 digest of the
    /// secret's UTF-8 bytes. Named on the wire-visible model of a `$scheme$` prefix so a host can
    /// migrate registrations one at a time and tell which is which.
    pub const SHA256_HEX: &'static str = "sha256-hex";

    /// Hash `secret` with the built-in scheme. The result is what the host stores; the secret
    /// itself is handed to the client once and never persisted here.
    pub fn sha256(secret: &str) -> Self {
        SecretHash {
            scheme: SecretHash::SHA256_HEX.to_string(),
            encoded: hex_lower(&Sha256::digest(secret.as_bytes())),
        }
    }

    /// A stored verifier in a scheme this crate does not implement, to be checked by the host's
    /// [`SecretVerifier`]. `encoded` is opaque here: a PHC string, a KMS key handle, whatever the
    /// host's verifier understands.
    pub fn custom(scheme: impl Into<String>, encoded: impl Into<String>) -> Self {
        SecretHash {
            scheme: scheme.into(),
            encoded: encoded.into(),
        }
    }

    /// The scheme identifier.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The stored verifier text, in whatever encoding the scheme defines.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Verify against the BUILT-IN scheme only; any other scheme is `false` here and is the host
    /// verifier's business. Constant time via [`constant_time_eq`].
    fn verify_builtin(&self, presented: &str) -> bool {
        if self.scheme != SecretHash::SHA256_HEX {
            return false;
        }
        let computed = hex_lower(&Sha256::digest(presented.as_bytes()));
        constant_time_eq(computed.as_bytes(), self.encoded.as_bytes())
    }

    /// Whether `presented` is the secret behind this stored verifier, consulting `verifier` for a
    /// scheme this crate does not implement.
    ///
    /// The same ORDER OF PREFERENCE, and the same fail-closed rule, as
    /// [`ClientAuth::verify_with`], which delegates here: the crate's own scheme is decided by the
    /// crate, an unrecognised one is decided by the host, and an unrecognised one with no host
    /// verifier installed never verifies.
    ///
    /// Public because a [`SecretHash`] is no longer only a client secret. RFC 7592 section 2 makes
    /// the registration access token a bearer credential the server has to check on every
    /// management request, and it is stored the same one-way way for the same reason (see
    /// [`crate::registration`]), so it needs the same comparison rather than a second copy of it.
    pub fn verify(&self, presented: &str, verifier: Option<&dyn SecretVerifier>) -> bool {
        if self.scheme == SecretHash::SHA256_HEX {
            self.verify_builtin(presented)
        } else {
            // Fails closed with no verifier: the server cannot check this credential, and "cannot
            // check" must never read as "checked out".
            match verifier {
                Some(v) => v.verify(self, presented),
                None => false,
            }
        }
    }
}

/// The host's client-secret verifier, for [`SecretHash`] schemes this crate does not implement.
///
/// Installed on the server (`AuthorizationServer::with_secret_verifier`) and consulted by
/// [`ClientAuth::verify_with`]. It is an ADDITION, never an override: a registration in the
/// built-in scheme is always verified by this crate, so a permissive or buggy host verifier cannot
/// weaken one.
///
/// Implementations MUST compare in constant time with respect to the presented secret: a
/// comparison that returns early on the first differing byte leaks, through its own timing, how
/// much of a guess was right, which turns an offline search into an online one an attacker can
/// run a byte at a time. Every serious password-hashing crate already does this.
///
/// # MUST NOT PANIC
///
/// [`SecretVerifier::verify`] MUST answer `false` for every input it cannot make sense of: a
/// stored encoding it does not recognise, a truncated hash, a parameter block with a length it did
/// not expect, a presented secret that is empty or enormous. `false` is the fail-closed answer and
/// it is always available; this trait has no error channel precisely because there is nothing a
/// verifier could report that is not "this does not verify".
///
/// This crate catches no unwind anywhere on a request path, so a panic here is not turned into
/// `invalid_client`. It unwinds out of `AuthorizationServer::authenticate_client` and out of the
/// token request the host is driving. NAMING THE CONSEQUENCE: this seam is reachable by a caller
/// with NO valid credential at all. [`SecretVerifier::dummy_hash`] is consulted on the
/// UNKNOWN-CLIENT path, deliberately, so an unauthenticated request with an invented `client_id`
/// runs this verifier over host-controlled bytes. A verifier that panics on a malformed encoding
/// is therefore a remotely reachable panic on the token endpoint, and on a host that treats a
/// panicking task as fatal it is a remotely reachable process abort.
///
/// # `verify` runs on the CALLER'S EXECUTOR THREAD, and it is not async
///
/// This method is synchronous and is called inline inside an `async fn`, so the KDF runs on
/// whichever executor thread is polling the token request. Nothing here yields, and a host cannot
/// interpose `spawn_blocking` from outside: there is no async variant of this seam in 0.9.
///
/// The cost is not hypothetical, and this trait's own docs price it: argon2id at ordinary
/// parameters is roughly 200 ms (see [`SecretVerifier::dummy_hash`]). On a CURRENT-THREAD runtime
/// that is 200 ms during which the reactor polls nothing else, per token request, and the
/// unknown-client path pays it too. What a host should do about it:
///
/// - budget for it as request LATENCY, not as background work,
/// - run the server on a multi-threaded runtime, so one stalled worker is not the whole reactor,
/// - keep the [`crate::events::RateLimiter`] installed. It runs BEFORE this seam, so a host can
///   bound how many of these an unauthenticated caller can start,
/// - or hand off internally: a verifier may keep its own blocking pool and block on the result,
///   which moves the KDF off the executor thread at the cost of a hop.
///
/// An ASYNC variant of this method would remove the need for all four, and it is not in 0.9: it
/// would be a breaking change to a trait hosts already implement, so it belongs to 1.0.
pub trait SecretVerifier: Send + Sync {
    /// Whether `presented` is the secret behind `stored`.
    fn verify(&self, stored: &SecretHash, presented: &str) -> bool;

    /// A stored verifier in THIS verifier's scheme, over a secret nobody knows, used to make an
    /// unknown `client_id` cost the same wall time as a known one.
    ///
    /// # What it is for
    ///
    /// RFC 6749 section 5.2 has an unknown client and a wrong secret collapse into one
    /// `invalid_client`, and this crate keeps that collapse on the wire. TIMING breaks it anyway
    /// when verification is expensive: the token endpoint cannot verify a secret for a
    /// registration it did not find, so it answers immediately, while a real id pays the whole
    /// KDF. With argon2id at ordinary parameters that is roughly 200 ms against 2 ms — a
    /// single-request oracle over the entire client registry, which per-id throttling does not
    /// touch because the attacker sends exactly one request per id.
    ///
    /// So the server performs a DUMMY verification on the unknown-id path, through this seam,
    /// against whatever this method returns. It is this method rather than a constant in this
    /// crate because only the host knows its own scheme: a hash in a scheme the verifier does not
    /// recognise would be rejected on inspection, in microseconds, which is the leak again.
    ///
    /// # What to return
    ///
    /// A [`SecretHash`] in the same scheme and with the same cost parameters as the registrations
    /// this verifier actually checks, over a secret that was drawn at random and thrown away (or,
    /// equivalently, over a value no client will ever present). It may be a constant compiled into
    /// the host: it authenticates nothing, because no registration names it, and it is only ever
    /// compared against.
    ///
    /// # The default, and why it is `None` rather than something
    ///
    /// A verifier that supplies nothing here leaves the crate's own fallback in place, which
    /// equalises the built-in `sha256-hex` scheme and cannot equalise a scheme it does not
    /// implement. That is a real residual and it is stated on
    /// `AuthorizationServer::authenticate_client` rather than papered over: this crate cannot
    /// invent a well-formed argon2id encoding, and a required method here would break every
    /// existing implementation of this trait to fix a leak most of them do not have.
    fn dummy_hash(&self) -> Option<SecretHash> {
        None
    }
}

/// How the client authenticates to the token endpoint (RFC 6749 section 2.3).
///
/// `Debug` is hand-written rather than derived (see below) so that `ConfidentialSecret`'s secret
/// never appears in a debug format. `Client` derives `Debug` and holds a `ClientAuth`, so this
/// also keeps `{:?}` on a whole `Client` safe, without needing a hand-written `Debug` there too.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
/// `#[non_exhaustive]`: `client-assertion` and `mtls` each add a variant, independently, so this
/// enum has four possible variant sets. A host matches this to render "how does this client
/// authenticate" in an admin UI, or to decide what its own registration endpoint will accept, and
/// neither of those should stop compiling because an unrelated crate in the graph wanted mutual
/// TLS. Registering a client is unaffected: naming a variant is still just naming it.
#[non_exhaustive]
pub enum ClientAuth {
    /// A public client (native app, browser app, device): no secret exists, so possession of the
    /// `client_id` proves nothing and the flows compensate (PKCE, device-code user interaction).
    Public,
    /// A confidential client whose SECRET ITSELF is stored here.
    ///
    /// PREFER [`ClientAuth::ConfidentialSecretHash`]. This variant means the plaintext credential
    /// lives wherever the host persists a [`Client`], so a leak of that store is a leak of every
    /// client's working credential, and the host cannot honestly tell a customer that their secret
    /// is not recoverable. It stays supported because it is legitimately right for two cases: a
    /// host that resolves secrets from a vault or KMS at request time and never writes them down,
    /// and a host migrating registrations gradually. This crate only ever compares it, in constant
    /// time, and never logs it.
    ConfidentialSecret {
        /// The shared secret the client presents.
        secret: String,
    },
    /// A confidential client stored as a one-way VERIFIER rather than as its secret. This is the
    /// variant to reach for: see [`SecretHash`].
    ConfidentialSecretHash {
        /// The stored verifier.
        hash: SecretHash,
    },
    /// A confidential client that authenticates with an RFC 7523 signed assertion rather than by
    /// presenting a secret: `private_key_jwt` or `client_secret_jwt`.
    ///
    /// The keys are held INLINE rather than behind a `Box`, unlike `Client::registration`. The
    /// question is what this costs a deployment that does not use it, and the answer is nothing:
    /// the widest existing variant is `ConfidentialSecretHash` (two `String`s), and
    /// [`crate::client_assertion::AssertionKeys`] is narrower than that, so `ClientAuth` does not
    /// grow by a byte. Boxing would have ADDED an allocation at registration time to save a struct
    /// size that was already paid for.
    #[cfg(feature = "client-assertion")]
    ConfidentialAssertion {
        /// What the registration expects the assertion to be signed with. This, and never the
        /// token's own header, is what decides the algorithm: see
        /// [`crate::client_assertion::verify_assertion`].
        keys: crate::client_assertion::AssertionKeys,
    },
    /// RFC 8705: a confidential client that authenticates with a mutual-TLS CERTIFICATE and
    /// holds no shared secret at all. This is the variant a deployment whose policy forbids
    /// shared secrets registers, and the only one where the credential never travels: the
    /// client proves possession of a private key to the host's TLS layer, and this crate is
    /// handed the resulting certificate as an established fact.
    ///
    /// Carried INLINE rather than boxed, on the same measurement as the assertion variant
    /// above: the widest shape [`crate::mtls::MtlsClientRegistration`] can take is one
    /// `String` plus a discriminant, against `ConfidentialSecretHash`'s two `String`s, so
    /// this variant does not make `ClientAuth`, or the [`Client`] every host store holds one
    /// of per registration, any bigger than it already was.
    #[cfg(feature = "mtls")]
    Mtls {
        /// Which RFC 8705 method, and what it expects to see.
        registration: crate::mtls::MtlsClientRegistration,
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
            // `SecretHash`'s own Debug is already redacted; going through it keeps the scheme
            // visible, which is the part an operator can act on.
            ClientAuth::ConfidentialSecretHash { hash } => f
                .debug_struct("ConfidentialSecretHash")
                .field("hash", hash)
                .finish(),
            // `AssertionKeys`'s own Debug redacts a `client_secret_jwt` secret and prints the
            // PUBLIC keys of a `private_key_jwt` registration, which are public.
            #[cfg(feature = "client-assertion")]
            ClientAuth::ConfidentialAssertion { keys } => f
                .debug_struct("ConfidentialAssertion")
                .field("keys", keys)
                .finish(),
            // NOT redacted: a registration that names an expected subject DN or a certificate
            // thumbprint holds no secret. Both are public facts about a public document, and
            // an operator debugging a refused mutual-TLS client needs to see exactly which
            // value the server expected.
            #[cfg(feature = "mtls")]
            ClientAuth::Mtls { registration } => f
                .debug_struct("Mtls")
                .field("registration", registration)
                .finish(),
        }
    }
}

impl ClientAuth {
    /// Whether this registration is CONFIDENTIAL, meaning the client can prove possession of
    /// something. RFC 6749 section 4.4 (client credentials), RFC 7662 section 2.1 (introspection)
    /// and RFC 7009 section 2.1 (revocation) all require that, and the answer must not be "is this
    /// variant `ConfidentialSecret`", because a new storage form for the same credential would
    /// then silently read as public.
    pub fn is_confidential(&self) -> bool {
        !matches!(self, ClientAuth::Public)
    }

    /// Verify a presented secret with no host verifier installed. See [`ClientAuth::verify_with`],
    /// which this delegates to; a [`ClientAuth::ConfidentialSecretHash`] in a scheme this crate
    /// does not implement therefore never authenticates through this entry point.
    pub fn verify(&self, presented: Option<&str>) -> bool {
        self.verify_with(presented, None)
    }

    /// Verify a presented secret, consulting the host's [`SecretVerifier`] for hash schemes this
    /// crate does not implement.
    ///
    /// Public clients accept `None` and reject any presented secret (presenting a secret for a
    /// secretless registration is a client mixup worth failing loud on). Confidential clients
    /// require the exact secret; the comparison is constant time regardless of the length of
    /// either the registered or the presented secret: an early-exit comparison would report,
    /// through its own timing, how many leading bytes of a guess were right.
    ///
    /// ORDER OF PREFERENCE for a hashed registration: the crate's own scheme is checked by the
    /// crate, and only an unrecognised scheme is passed to `verifier`. That way installing a
    /// verifier can only ADD registrations that authenticate, never change the answer for one the
    /// crate could already decide.
    ///
    /// What this does NOT cover, and who does: if the caller returned early for an unknown
    /// `client_id` without calling this at all, an unknown client and a known client with a wrong
    /// secret would be distinguishable by timing even though this function leaks nothing. That is
    /// the caller's responsibility rather than this function's, and
    /// `AuthorizationServer::authenticate_client` discharges it by running a DUMMY verification
    /// through this same function on the unknown-id path. See [`SecretVerifier::dummy_hash`] for
    /// the part of it only the host can supply.
    pub fn verify_with(
        &self,
        presented: Option<&str>,
        verifier: Option<&dyn SecretVerifier>,
    ) -> bool {
        match self {
            ClientAuth::Public => presented.is_none(),
            ClientAuth::ConfidentialSecret { secret } => match presented {
                Some(p) => constant_time_eq(secret.as_bytes(), p.as_bytes()),
                None => false,
            },
            ClientAuth::ConfidentialSecretHash { hash } => match presented {
                Some(p) => hash.verify(p, verifier),
                None => false,
            },
            // NEVER, and not because it is unimplemented. This registration's credential is a
            // SIGNATURE over a claim set (RFC 7523 section 3), and there is no presented string
            // that is the right answer here. Returning `true` for any input would let a client
            // registered for `private_key_jwt` be authenticated by the `client_secret_post` path
            // instead, which is the downgrade the registration exists to forbid; the assertion path
            // is `AuthorizationServer::authenticate_client` and it does not come through here.
            #[cfg(feature = "client-assertion")]
            ClientAuth::ConfidentialAssertion { .. } => false,
            // NEVER, and for the same reason as the assertion arm above. A mutual-TLS
            // registration has no secret to compare against, so there is no presented string
            // that could be the right one, and `None` is not the right answer either: unlike
            // `Public`, this client is confidential and something must be proven. The
            // certificate is checked by `crate::mtls::verify_certificate`, which is reached
            // only from `AuthorizationServer::authenticate_client`; every OTHER caller of
            // this function, now or later, therefore fails closed on a mutual-TLS client
            // rather than accidentally authenticating one with no evidence at all.
            #[cfg(feature = "mtls")]
            ClientAuth::Mtls { .. } => false,
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
    /// Present exactly when this registration was created by RFC 7591 dynamic client
    /// registration, and absent for one the host provisioned itself.
    ///
    /// BOXED, and this is not a style choice, though the reason is no longer the one it was
    /// written for. The original argument was that a `Client` is deep cloned out of the store on
    /// every token-plane request, so every byte here is paid per request;
    /// [`crate::store::Storage::get_client`] hands back an `Arc<Client>` now, so a read is a
    /// pointer clone and the struct's SIZE is not on that path at all.
    ///
    /// Re-examined on that basis, the box is MORE clearly right than when it was chosen, because
    /// the optimisation removed its only cost. What it buys is now a memory argument rather than a
    /// per-request one. MEASURED: `Option<Box<DynamicRegistration>>` is 8 bytes against 104 for
    /// the record inline, which is the difference between a `Client` of 200 bytes and one of 296,
    /// paid by every registration in every store whether or not RFC 7591 is enabled. What it USED
    /// to cost was an extra allocation on every clone of a client that does have one; with `Arc`
    /// there are no such clones, so that allocation is now paid exactly once, when the
    /// registration is created.
    ///
    /// It lives on the client rather than in a table of its own because it IS the client: RFC
    /// 7592 section 2 manages a registration through the same identifier the token endpoint
    /// authenticates, and splitting the two across two stores would make deletion a
    /// two-phase problem the host has to get right.
    pub registration: Option<Box<DynamicRegistration>>,
}

/// What a dynamically registered client carries beyond an ordinary registration: the RFC 7592
/// section 2 management credential, and the RFC 7591 section 3.2.1 members that are not
/// recoverable from the rest of the [`Client`].
///
/// The registration access token is held as a one-way [`SecretHash`], never as itself. It is a
/// bearer credential that reads, rewrites and DELETES a registration, so it is at least as
/// sensitive as the client secret next to it, and it is stored the same way for the same reason:
/// a dump of the client table must not be a set of working credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicRegistration {
    /// The stored verifier for the RFC 7592 section 2 registration access token.
    pub registration_access_token_hash: SecretHash,
    /// RFC 7591 section 3.2.1 `client_id_issued_at`: seconds since the Unix epoch.
    pub client_id_issued_at: Option<u64>,
    /// RFC 7591 section 3.2.1 `client_secret_expires_at`: seconds since the Unix epoch, or `0`
    /// for a secret that never expires. `None` when no secret was issued.
    pub client_secret_expires_at: Option<u64>,
    /// RFC 7591 section 2 `token_endpoint_auth_method`, as registered. Kept verbatim because
    /// [`ClientAuth`] deliberately does not distinguish `client_secret_basic` from
    /// `client_secret_post` (RFC 6749 section 2.3.1 lets a confidential client use either), so the
    /// value the client registered cannot be recovered from it.
    pub token_endpoint_auth_method: String,
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
