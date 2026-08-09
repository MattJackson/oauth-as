// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7523 JWT client authentication: `private_key_jwt` and `client_secret_jwt`.
//!
//! # What this buys
//!
//! A deployment whose security policy forbids transmitting a shared secret cannot use
//! `client_secret_basic` or `client_secret_post` at all, because both put the secret on the wire on
//! every single request. RFC 7523 lets a client prove possession of a key instead, and with
//! `private_key_jwt` this server never holds anything that could authenticate AS the client, only
//! the public half. It is also required by FAPI 2.0 and expected by most enterprise deployments.
//!
//! # What the host owns
//!
//! The registration, and with it the algorithm. A client authenticates this way exactly when its
//! [`crate::client::ClientAuth`] is [`crate::client::ClientAuth::ConfidentialAssertion`], and the
//! [`AssertionKeys`] inside decide BOTH which `alg` is accepted and which key verifies. Nothing
//! about either comes off the wire. See [`verify_assertion`] for why that is the whole defence
//! against JWS algorithm confusion rather than one check among many.
//!
//! # Single use is the point
//!
//! RFC 7523 section 3 requires the `jti` to be single use within the assertion's own validity
//! window, and an implementation that verifies the signature and skips that has built a credential
//! that anyone who observed one request can send again. Verification here is PURE: it returns the
//! `jti` and the deadline, and CLAIMING it is [`crate::store::Storage::claim_replay_id`], which
//! `AuthorizationServer::authenticate_client` calls on the same request. Neither half is worth
//! anything without the other, which is why [`VerifiedAssertion`] carries the deadline rather than
//! leaving a caller to invent one.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::jwt::{verify_es256, verify_hs256, CompactJws, PublicJwk};

/// RFC 7521 section 4.2: the `client_assertion_type` a JWT bearer assertion must carry.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The RFC 8414 `token_endpoint_auth_methods_supported` value for a MAC-signed assertion.
pub const CLIENT_SECRET_JWT: &str = "client_secret_jwt";

/// The RFC 8414 `token_endpoint_auth_methods_supported` value for a public-key-signed assertion.
pub const PRIVATE_KEY_JWT: &str = "private_key_jwt";

/// The shortest `client_secret_jwt` key this crate will register: 22 characters.
///
/// NOT tuning, and the same reasoning as [`crate::server::MIN_USER_CODE_LENGTH`]: a parameter this
/// weak is not a slower version of the feature, it is the feature not working. RFC 6749 section
/// 10.10 requires a credential of this kind to carry at least 128 bits of entropy, and base64url,
/// which is what a generated secret is nearly always spelled in, carries 6 bits per character, so
/// 128 bits is `ceil(128 / 6)` = 22 characters.
///
/// The reason it matters MORE here than for `client_secret_basic` is that a `client_secret_jwt`
/// assertion is an HMAC over public inputs: an attacker who observes ONE assertion (from a log, a
/// proxy, a captured request) can grind candidate keys against it offline, at whatever rate their
/// hardware allows, without ever touching this server again. There is no rate limit that reaches
/// that, so the key length is the entire defence.
///
/// This is a LENGTH check and length only bounds entropy from above: 22 copies of the letter `a`
/// clears it and carries none. A library cannot measure the entropy of a string it did not
/// generate, and refusing the obviously-too-short case is the part that can be checked. Clamping,
/// the answer [`crate::server::ServerConfig::user_code_length`] gives, is not available here: this
/// crate cannot lengthen a secret the client already holds.
pub const MIN_CLIENT_SECRET_JWT_KEY_LENGTH: usize = 22;

/// A registered `client_secret_jwt` HMAC key that has cleared
/// [`MIN_CLIENT_SECRET_JWT_KEY_LENGTH`].
///
/// A newtype with a private field rather than a bare `String` on the variant, because a private
/// field is the only spelling Rust has for "this cannot be reached by a struct literal", and a
/// floor a caller can skip by writing `AssertionKeys::ClientSecret { secret: "abc".into() }` is not
/// a floor. Deserialization is routed through the same check for the same reason
/// [`crate::jwt::PublicJwk`]'s is: a registration read back out of the host's store must be held to
/// what the constructor holds a fresh one to, or the store becomes the way around it.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ClientSecretKey(String);

impl ClientSecretKey {
    /// Register a secret, refusing one below the floor.
    pub fn new(secret: impl Into<String>) -> Result<Self, WeakClientSecret> {
        let secret = secret.into();
        // Characters, not bytes: the floor is an argument about how many symbols of a generated
        // alphabet the secret carries, and a multi-byte character contributes one of those.
        if secret.chars().count() < MIN_CLIENT_SECRET_JWT_KEY_LENGTH {
            return Err(WeakClientSecret);
        }
        Ok(ClientSecretKey(secret))
    }

    /// The key material, for the HMAC.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Hand-written, for the reason [`AssertionKeys`]'s own is: this type exists to sit inside a
/// registration that gets logged, and a derived one would print the key.
impl fmt::Debug for ClientSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"[redacted]\"")
    }
}

impl<'de> Deserialize<'de> for ClientSecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        ClientSecretKey::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// A `client_secret_jwt` key that does not clear [`MIN_CLIENT_SECRET_JWT_KEY_LENGTH`].
///
/// Carries NO payload: the whole of it is "too short", and a rejection that echoed the offending
/// secret would write the credential into whatever log caught the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WeakClientSecret;

impl fmt::Display for WeakClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a client_secret_jwt key must be at least {MIN_CLIENT_SECRET_JWT_KEY_LENGTH} \
             characters (RFC 6749 s10.10, 128 bits at 6 bits per base64url character)"
        )
    }
}

impl std::error::Error for WeakClientSecret {}

/// The `token_endpoint_auth_signing_alg_values_supported` this server advertises (RFC 8414
/// section 2), which is exactly what [`AssertionKeys::signing_alg`] can return.
pub const ASSERTION_SIGNING_ALGS: &[&str] = &["HS256", "ES256"];

/// The longest `exp - now` this server will accept on an assertion.
///
/// Ten minutes. This is not a guess at what clients do, it is a bound on what an attacker can make
/// this server REMEMBER: the replay defence has to hold a `jti` until the assertion's own `exp`, so
/// an unbounded `exp` is an unbounded storage commitment chosen by the party presenting the
/// credential. Ten minutes is comfortably longer than any legitimate client's assertion lifetime
/// and short enough that the retained set is bounded by request rate rather than by a number an
/// attacker wrote in a claim.
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::from_secs(600);

/// How far a client's clock may be AHEAD of this server's before `iat` and `nbf` are refused.
///
/// Granted in that direction only. Leeway that lets an assertion be accepted slightly early can
/// only ever refuse a request that was going to be fine anyway; leeway on `exp` would keep a dead
/// credential alive, so [`verify_assertion`] does not grant any there.
pub const CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(60);

/// What a registration expects a client assertion to be signed with.
///
/// The variants are the two RFC 7523 methods, and the choice between them is the choice of
/// algorithm: there is deliberately no way to spell "this client uses `private_key_jwt` and also
/// HS256". See [`verify_assertion`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssertionKeys {
    /// `client_secret_jwt` (RFC 7523 section 2.2 with a MAC): HMAC-SHA-256 under the registered
    /// client secret.
    ///
    /// Weaker than [`AssertionKeys::PublicKeys`] and supported because deployments have it: the
    /// server still holds a secret that could authenticate as the client, so a dump of the client
    /// table is still a set of working credentials. What it does buy over `client_secret_basic` is
    /// that the secret never crosses the network, so it cannot be captured in transit or logged by
    /// an intermediary.
    ClientSecret {
        /// The shared secret. Held in the clear because HMAC verification needs the key itself; a
        /// one-way [`crate::client::SecretHash`] cannot be used here, and pretending otherwise
        /// would be the kind of storage that looks safe and is not.
        ///
        /// A [`ClientSecretKey`] rather than a `String` so that the entropy floor cannot be walked
        /// past by writing the variant out by hand.
        secret: ClientSecretKey,
    },
    /// `private_key_jwt` (RFC 7523 section 2.2 with a digital signature): ECDSA P-256 under a key
    /// only the client holds. This is the variant to reach for.
    PublicKeys {
        /// The registered public keys. Several are allowed so a client can rotate: it publishes the
        /// new key alongside the old, signs with either during the overlap, and retires the old one
        /// when it is done. A server that accepted only one key would make rotation an outage.
        keys: Vec<PublicJwk>,
    },
}

/// Hand-written for the same reason as [`crate::client::ClientAuth`]'s: `ClientAuth` derives
/// nothing that would print a secret, and this type sits inside it. The PUBLIC keys stay visible,
/// because they are public and because "which keys does this registration actually hold" is the
/// first question anyone debugging a `private_key_jwt` failure asks.
impl fmt::Debug for AssertionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssertionKeys::ClientSecret { .. } => f
                .debug_struct("ClientSecret")
                .field("secret", &"[redacted]")
                .finish(),
            AssertionKeys::PublicKeys { keys } => {
                f.debug_struct("PublicKeys").field("keys", keys).finish()
            }
        }
    }
}

impl AssertionKeys {
    /// The RFC 8414 method name this registration authenticates with.
    pub fn token_endpoint_auth_method(&self) -> &'static str {
        match self {
            AssertionKeys::ClientSecret { .. } => CLIENT_SECRET_JWT,
            AssertionKeys::PublicKeys { .. } => PRIVATE_KEY_JWT,
        }
    }

    /// The ONE `alg` this registration's assertions may carry.
    ///
    /// Singular on purpose. A registration that accepted a SET of algorithms would be one where an
    /// attacker gets to pick from that set, and the interesting attacks are all about picking the
    /// element the deployment did not think about.
    pub fn signing_alg(&self) -> &'static str {
        match self {
            AssertionKeys::ClientSecret { .. } => "HS256",
            AssertionKeys::PublicKeys { .. } => "ES256",
        }
    }
}

/// Why an assertion was refused.
///
/// Every one of these becomes the same `invalid_client` on the wire (RFC 6749 section 5.2), for the
/// same reason `authenticate_client` collapses "unknown client" and "wrong secret": telling a
/// caller WHICH check it failed is telling an attacker how to get closer. The distinction exists
/// for the host's audit channel, where the reader is not the attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssertionFailure {
    /// Not a compact JWS, or its `typ` says it is some other kind of JWT.
    Malformed,
    /// The header's `alg` is not the one this registration signs with.
    AlgorithmMismatch,
    /// The signature did not verify under any registered key.
    BadSignature,
    /// `iss` or `sub` is absent, or is not the client this request claims to be.
    WrongPrincipal,
    /// `aud` names neither this server's token endpoint nor its issuer.
    WrongAudience,
    /// `exp` is absent, has passed, or is further out than this server will track a `jti` for.
    Expired,
    /// `nbf` or `iat` is in the future by more than [`CLOCK_SKEW_LEEWAY`].
    NotYetValid,
    /// `jti` is absent or empty, so single use cannot be enforced.
    MissingJti,
    /// This `jti` has been seen before within the assertion's own validity window.
    Replayed,
}

impl fmt::Display for AssertionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AssertionFailure::Malformed => "the client assertion is not a well formed JWT",
            AssertionFailure::AlgorithmMismatch => {
                "the client assertion alg is not the one this registration signs with"
            }
            AssertionFailure::BadSignature => "the client assertion signature did not verify",
            AssertionFailure::WrongPrincipal => "the client assertion iss/sub is not this client",
            AssertionFailure::WrongAudience => "the client assertion aud is not this server",
            AssertionFailure::Expired => "the client assertion is expired or too long lived",
            AssertionFailure::NotYetValid => "the client assertion is not yet valid",
            AssertionFailure::MissingJti => "the client assertion carries no jti",
            AssertionFailure::Replayed => "the client assertion jti has already been used",
        })
    }
}

impl std::error::Error for AssertionFailure {}

/// What a verified assertion leaves the caller holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The `jti` the caller MUST claim as single use before treating the client as authenticated.
    pub jti: String,
    /// The assertion's own `exp`: how long the `jti` has to be remembered, and no longer.
    pub expires_at: SystemTime,
}

/// The `typ` header values this server will read as a client assertion.
///
/// RFC 7523 does not fix `typ`, so an absent one is legal and common. What this list is really for
/// is REFUSING the values that mean something else: RFC 9449 section 4.2 fixes a DPoP proof at
/// `dpop+jwt` and RFC 9068 section 2.1 fixes an access token at `at+jwt`, and both are JWTs the
/// same party signs with the same key and sends to this same endpoint. With no `typ` check they are
/// interchangeable with an authentication credential, so a proof captured from one request could be
/// presented as the client's password on the next. `client-authentication+jwt` is the value
/// draft-ietf-oauth-rfc7523bis introduces for exactly this reason, and is accepted so that a client
/// which already sets it is not punished for being early.
const ACCEPTED_TYP: &[&str] = &["JWT", "jwt", "client-authentication+jwt"];

/// Verify one RFC 7523 section 3 client assertion.
///
/// `audiences` is what section 3 (3) will accept as naming this server: the caller passes the token
/// endpoint URL and the issuer identifier. `now` is the server's clock.
///
/// The ORDER of the checks below is the security property of this function:
///
/// 1. `alg` comes from `keys`, which is the REGISTRATION, and never from the token header. This is
///    the whole of the defence against JWS algorithm confusion, and it is structural rather than a
///    check that could be forgotten: [`AssertionKeys`] holds either a secret or public keys, so
///    there is no value an attacker can put in the header that routes an HMAC verification at a
///    public key it already knows.
/// 2. The SIGNATURE is verified before any claim is read for anything but its own sake. Acting on
///    an unauthenticated claim, even only to produce a better error message, is how a verifier ends
///    up telling an attacker which client ids exist.
/// 3. Everything after that is the section 3 claim set, in the section's own order.
///
/// PUBLIC because [`VerifiedAssertion`] and [`AssertionFailure`] are, and a type no consumer can
/// obtain is a type that should not have been exported. It is also the other half of
/// [`unverified_subject`], which has always been public: exposing the "believe nothing" lookup
/// while hiding the verification it exists to feed left the safe path out of reach.
pub fn verify_assertion(
    keys: &AssertionKeys,
    assertion: &str,
    client_id: &str,
    audiences: &[&str],
    now: SystemTime,
) -> Result<VerifiedAssertion, AssertionFailure> {
    let jws = CompactJws::parse(assertion).map_err(|_| AssertionFailure::Malformed)?;

    if let Some(typ) = jws.header_str("typ") {
        if !ACCEPTED_TYP.contains(&typ) {
            return Err(AssertionFailure::Malformed);
        }
    }

    // (1) The registration decides the algorithm. An ABSENT `alg` fails here too rather than
    // defaulting to anything: RFC 7515 section 4.1.1 makes it REQUIRED, and a missing one is not
    // something this server has to guess about.
    if jws.header_str("alg") != Some(keys.signing_alg()) {
        return Err(AssertionFailure::AlgorithmMismatch);
    }

    // (2) The signature, over the bytes that arrived.
    let signed = match keys {
        // The entropy floor is enforced at registration and again on the way out of the host's
        // store, so nothing here has to re-check it; see `ClientSecretKey`.
        AssertionKeys::ClientSecret { secret } => verify_hs256(
            secret.as_bytes(),
            jws.signing_input.as_bytes(),
            &jws.signature,
        ),
        // Any ONE registered key is enough: see `AssertionKeys::PublicKeys` on rotation.
        AssertionKeys::PublicKeys { keys } => keys
            .iter()
            .any(|key| verify_es256(key, jws.signing_input.as_bytes(), &jws.signature)),
    };
    if !signed {
        return Err(AssertionFailure::BadSignature);
    }

    // RFC 7523 section 3 (1) and (2): for CLIENT AUTHENTICATION the issuer and the subject are both
    // the client itself. Checked against the `client_id` this request presented, so an assertion
    // minted for one registration cannot authenticate another even where two registrations have
    // been given the same secret, which is a deployment mistake but a common one.
    if jws.claim_str("iss") != Some(client_id) || jws.claim_str("sub") != Some(client_id) {
        return Err(AssertionFailure::WrongPrincipal);
    }

    // RFC 7523 section 3 (3): the assertion must name THIS server. Without it, every other
    // authorization server the client also authenticates to can take the assertion it was handed
    // and present it here as that client. This is the only check standing between a multi-AS client
    // and a credential its other servers can spend.
    if !audience_matches(&jws, audiences) {
        return Err(AssertionFailure::WrongAudience);
    }

    // RFC 7523 section 3 (4): `exp` is REQUIRED and must not have passed. NO skew leeway here: see
    // `CLOCK_SKEW_LEEWAY`.
    //
    // The addition is CHECKED. `exp` is a `u64` out of JSON that nobody has authenticated yet (this
    // assertion IS the authentication), and `UNIX_EPOCH + Duration::from_secs(u64::MAX)` PANICS
    // rather than wrapping. In a library that panic unwinds into the host's request handler, and it
    // happened BEFORE either bound below was compared. `Expired` is the honest answer for a value
    // that cannot be represented: it is far past the `MAX_ASSERTION_LIFETIME` ceiling the next check
    // imposes, so the refusal is the same one an `exp` of merely a year hence already gets.
    let exp = jws.claim_time("exp").ok_or(AssertionFailure::Expired)?;
    let expires_at = UNIX_EPOCH
        .checked_add(Duration::from_secs(exp))
        .ok_or(AssertionFailure::Expired)?;
    if now >= expires_at {
        return Err(AssertionFailure::Expired);
    }
    let ceiling = now
        .checked_add(MAX_ASSERTION_LIFETIME)
        .ok_or(AssertionFailure::Expired)?;
    if expires_at > ceiling {
        return Err(AssertionFailure::Expired);
    }

    // RFC 7523 section 3 (5) and (6): `nbf` and `iat` are OPTIONAL and are checked when present.
    // Both get the skew leeway, because both can only ever refuse an assertion that is otherwise
    // fine.
    //
    // Checked for the same reason `exp` above is, and mapped to `NotYetValid` for the same kind of
    // reason: a `nbf` or `iat` too large to represent is a time in the future, which is exactly what
    // this loop refuses. A value that overflows must never be the one value that skips the check.
    let horizon = now
        .checked_add(CLOCK_SKEW_LEEWAY)
        .ok_or(AssertionFailure::NotYetValid)?;
    for claim in ["nbf", "iat"] {
        if let Some(value) = jws.claim_time(claim) {
            match UNIX_EPOCH.checked_add(Duration::from_secs(value)) {
                Some(instant) if instant <= horizon => {}
                _ => return Err(AssertionFailure::NotYetValid),
            }
        }
    }

    // RFC 7523 section 3 (7): the `jti` is what single use is enforced ON. An assertion without one
    // cannot be tracked, and an untrackable bearer credential is one that anybody who saw the
    // request can send again, so it is refused outright rather than accepted with the replay check
    // quietly skipped. "We could not check this" must never read as "checked out".
    let jti = jws.claim_str("jti").unwrap_or_default();
    if jti.is_empty() {
        return Err(AssertionFailure::MissingJti);
    }

    Ok(VerifiedAssertion {
        jti: jti.to_string(),
        expires_at,
    })
}

/// The `sub` an assertion claims, WITHOUT verifying anything about it.
///
/// RFC 7521 section 4.2 makes `client_id` optional on a request that carries an assertion, because
/// the assertion already names the client. Something still has to LOCATE the registration before
/// the registration can decide the key, and this is that something.
///
/// It is safe only because of what the caller does next, and the caller is the only reason this is
/// public: the value returned here is used to look up a client, and then
/// [`verify_assertion`] re-checks `iss` and `sub` against that client's own id under the
/// registration's key. Nothing is believed on the strength of this read. A caller that used the
/// result for anything else, an audit record naming the client, a rate limit bucket, an
/// authorization decision, would be trusting an unsigned string an attacker wrote.
pub fn unverified_subject(assertion: &str) -> Option<String> {
    let jws = CompactJws::parse(assertion).ok()?;
    jws.claim_str("sub").map(str::to_string)
}

/// Whether the assertion names one of `audiences`, in either of the two shapes RFC 7519 section
/// 4.1.3 allows for the claim.
fn audience_matches(jws: &CompactJws<'_>, audiences: &[&str]) -> bool {
    match jws.payload.get("aud") {
        Some(serde_json::Value::String(one)) => audiences.iter().any(|a| a == one),
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .filter_map(|v| v.as_str())
            .any(|one| audiences.contains(&one)),
        _ => false,
    }
}

#[cfg(test)]
#[path = "tests/client_assertion.rs"]
mod tests;
