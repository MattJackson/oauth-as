// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9449 DPoP: sender-constrained access tokens.
//!
//! # What this buys, and it is the largest security change in this crate
//!
//! Without it every token this server issues is a BEARER token (RFC 6750 section 1: possession of
//! the string is the whole of the authorization). A token that leaks, into a log, a proxy, a crash
//! dump, a compromised resource server, is a token the finder can spend. DPoP binds the token to a
//! key the client holds: the client signs a fresh proof for every request, the token carries the
//! RFC 7638 thumbprint of that key in `cnf.jkt` (section 6), and a resource server that checks the
//! binding refuses a token presented by anyone who cannot sign for the key. A leaked DPoP-bound
//! token is worth nothing without the private key, which never leaves the client.
//!
//! # What this module does and does not do
//!
//! It validates a PROOF (section 4.3) and produces a thumbprint. It does not speak HTTP: the host
//! (or the optional `http` feature) reads the `DPoP` request header and hands the string in.
//!
//! Two things RFC 9449 defines that are NOT implemented here, called out rather than left to be
//! discovered:
//!
//! - SERVER-PROVIDED NONCES (section 8), the `DPoP-Nonce` response header and the `use_dpop_nonce`
//!   error. They need the AS to mint, remember and return a nonce on a REJECTED request, which is a
//!   response-header seam this crate's error type does not have and a second piece of server state.
//!   Their purpose is to stop a client pre-generating proofs long in advance; the `iat` window here
//!   bounds that to [`MAX_PROOF_AGE`] instead, which is the weaker but non-optional half of the
//!   same defence.
//! - The `dpop_jkt` AUTHORIZATION REQUEST parameter (section 10), which binds an authorization code
//!   to a key at the authorization endpoint so a stolen code cannot be redeemed by another client.
//!   It belongs with the authorization request rather than here.
//!
//! # Single use is the point, again
//!
//! A proof is not a secret: it travels in a header on every request, so anything on the path sees
//! them constantly. Its whole value is in what a captured one cannot be used for, which is `htm`,
//! `htu`, `iat` and `jti` (section 4.3). [`verify_proof`] is PURE and returns the `jti` with the
//! deadline it must be remembered to; claiming it is [`crate::store::Storage::claim_replay_id`],
//! which `AuthorizationServer` calls on the same request. A verifier that checks the signature and
//! skips the `jti` has left the replay window wide open for exactly [`MAX_PROOF_AGE`].

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::jwt::{verify_es256, CompactJws, PublicJwk};

/// RFC 9449 section 4.2: the `typ` a DPoP proof MUST carry.
pub const DPOP_PROOF_TYP: &str = "dpop+jwt";

/// RFC 9449 section 5: the `token_type` a DPoP-bound token is issued with, and the HTTP
/// authentication scheme a client presents it under.
pub const DPOP_TOKEN_TYPE: &str = "DPoP";

/// RFC 9449 section 4: the request header a proof travels in.
pub const DPOP_HEADER: &str = "DPoP";

/// The JWS algorithms this server accepts on a proof, and exactly what it advertises as
/// `dpop_signing_alg_values_supported` (RFC 9449 section 5.1).
///
/// One entry, and the list must stay honest: RFC 9449 section 4.2 requires an ASYMMETRIC algorithm,
/// and this crate implements ES256 and nothing else (see `Cargo.toml` on why `p256` and not a JOSE
/// framework). Advertising an algorithm the verifier will refuse is worse than advertising fewer,
/// because a client that picks it has no way to find out except by failing.
pub const DPOP_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &["ES256"];

/// How old a proof's `iat` may be (RFC 9449 section 4.3 (10): "within an acceptable window").
///
/// Five minutes. Two things are bought with the same number, which is why it is one constant: it
/// bounds how long a captured proof is worth replaying, and it bounds the replay cache, because a
/// proof older than this is refused on time alone and its `jti` no longer has to be remembered. RFC
/// 9449 section 11.1 notes that a server wanting a tighter bound should use the section 8 nonce
/// mechanism rather than shrinking this to the point where ordinary clock skew breaks clients.
pub const MAX_PROOF_AGE: Duration = Duration::from_secs(300);

/// How far a client's clock may be AHEAD of this server's before `iat` is refused. Granted in that
/// direction only, for the same reason as in [`crate::client_assertion`].
pub const CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(60);

/// Why a DPoP proof was refused.
///
/// RFC 9449 section 5 makes `invalid_dpop_proof` the token-endpoint answer for all of these; the
/// distinction here is for the host's audit channel, not for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DpopFailure {
    /// Not a compact JWS at all.
    Malformed,
    /// The `typ` header is not `dpop+jwt`, so this JWT is something else.
    NotAProof,
    /// The `alg` is not one this server accepts for a proof.
    UnsupportedAlgorithm,
    /// The `jwk` header is missing, malformed, or carries a private key parameter.
    BadProofKey,
    /// The signature did not verify under the proof's own advertised key.
    BadSignature,
    /// `htm` is absent or is not this request's method.
    WrongMethod,
    /// `htu` is absent or is not this request's URI.
    WrongUri,
    /// `iat` is absent, too old, or in the future.
    StaleProof,
    /// `jti` is absent or empty, so single use cannot be enforced.
    MissingJti,
    /// This `jti` has been seen before within the proof's acceptance window.
    Replayed,
}

impl fmt::Display for DpopFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DpopFailure::Malformed => "the DPoP proof is not a well formed JWT",
            DpopFailure::NotAProof => "the DPoP proof typ is not dpop+jwt",
            DpopFailure::UnsupportedAlgorithm => "the DPoP proof alg is not supported",
            DpopFailure::BadProofKey => "the DPoP proof jwk is missing or is not a public key",
            DpopFailure::BadSignature => "the DPoP proof signature did not verify",
            DpopFailure::WrongMethod => "the DPoP proof htm is not this request's method",
            DpopFailure::WrongUri => "the DPoP proof htu is not this request's URI",
            DpopFailure::StaleProof => "the DPoP proof iat is missing or outside the window",
            DpopFailure::MissingJti => "the DPoP proof carries no jti",
            DpopFailure::Replayed => "the DPoP proof jti has already been used",
        })
    }
}

impl std::error::Error for DpopFailure {}

/// What a verified proof leaves the caller holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// The RFC 7638 thumbprint of the proof key: the `cnf.jkt` (RFC 9449 section 6.1) the issued
    /// token is bound to, and the value a resource server compares against.
    pub jkt: String,
    /// The `jti` the caller MUST claim as single use before issuing anything.
    pub jti: String,
    /// When the caller may stop remembering this `jti`: the last instant at which this exact proof
    /// would still pass the `iat` check. Remembering for less would leave a window in which a
    /// captured proof is forgotten by the cache but still accepted by the clock, which is precisely
    /// where a replay would be aimed.
    pub replay_until: SystemTime,
}

/// The `htu` of a request URI: everything before the query and the fragment.
///
/// RFC 9449 section 4.3 (7) compares `htu` against the request URI "ignoring any query and fragment
/// parts", so both sides go through this. Doing it to BOTH matters: a client that included its
/// query string in `htu` is conformant, and so is one that did not.
pub fn htu_of(url: &str) -> &str {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    &url[..end]
}

/// Verify one RFC 9449 section 4.3 DPoP proof.
///
/// `htm` is the request's method and `htu` its URI (the query and fragment are stripped here, so a
/// caller may pass either form). `now` is the server's clock.
///
/// The key comes from the proof itself, which looks like a violation of the rule stated in
/// `src/jwt.rs` that the verifier chooses the key, and is not. A proof only ever proves possession
/// of the key it advertises; it establishes no identity on its own. What makes it mean something is
/// the BINDING: the token issued alongside it carries that key's thumbprint in `cnf.jkt`, so a
/// later request has to prove possession of the same key. Section 4.3 (6) is what closes the gap,
/// by requiring the signature to verify under the proof's OWN key: an attacker who captures a proof
/// cannot substitute their key without invalidating the signature, and cannot re-sign without the
/// private half.
///
/// PUBLIC because [`VerifiedProof`] and [`DpopFailure`] are, and a type with no reachable producer
/// is a type a consumer can read about and never obtain. It is also the function a host needs
/// directly: RFC 9449 section 7 has the RESOURCE server check a proof on every request, and a host
/// whose resource server is in the same tree as its AS should not have to reimplement section 4.3
/// to do it. Nothing is retained here, so claiming the returned `jti` (see
/// [`crate::store::Storage::claim_replay_id`]) remains the caller's obligation either way.
pub fn verify_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    now: SystemTime,
) -> Result<VerifiedProof, DpopFailure> {
    let jws = CompactJws::parse(proof).map_err(|_| DpopFailure::Malformed)?;

    // (3) `typ` is `dpop+jwt`, and compared exactly. Case folding it would accept `DPOP+JWT`, which
    // no conforming client sends and which only widens what a captured JWT can be presented as; the
    // media type here is a fixed string, not a header field name.
    if jws.header_str("typ") != Some(DPOP_PROOF_TYP) {
        return Err(DpopFailure::NotAProof);
    }

    // (4) and (5): an asymmetric `alg` this server implements. Checked BEFORE the key is read, so
    // no attacker-chosen algorithm ever reaches a verification routine. A symmetric `alg` is
    // refused here rather than failing later on key type, because the reason it is wrong is
    // structural: a MAC is verified with a key both parties hold, which proves possession of
    // nothing this server does not already have, and would turn proof-of-possession back into a
    // bearer scheme.
    match jws.header_str("alg") {
        Some(alg) if DPOP_SIGNING_ALG_VALUES_SUPPORTED.contains(&alg) => {}
        _ => return Err(DpopFailure::UnsupportedAlgorithm),
    }

    // (4) The proof key, which MUST be a public key and MUST NOT carry a private one. `from_json`
    // is where that is enforced, for every JWK this crate parses; see `PRIVATE_JWK_MEMBERS`.
    let jwk = jws.header.get("jwk").ok_or(DpopFailure::BadProofKey)?;
    let jwk = PublicJwk::from_json(jwk).map_err(|_| DpopFailure::BadProofKey)?;

    // (6) The signature, under the proof's own key, over the bytes that arrived.
    if !verify_es256(&jwk, jws.signing_input.as_bytes(), &jws.signature) {
        return Err(DpopFailure::BadSignature);
    }

    // (7) The proof is bound to THIS request. Without these two a proof captured anywhere the
    // client sends one, above all at a resource server, could be spent at the token endpoint.
    // RFC 9110 s9.1 makes the method case sensitive, so this comparison is too.
    if jws.claim_str("htm") != Some(htm) {
        return Err(DpopFailure::WrongMethod);
    }
    match jws.claim_str("htu") {
        Some(claimed) if htu_of(claimed) == htu_of(htu) => {}
        _ => return Err(DpopFailure::WrongUri),
    }

    // (10) `iat` within an acceptable window, in both directions. A proof from the future would
    // otherwise extend its own life past the window by however far ahead the client dares to
    // claim, which is the one bound this check exists to impose.
    //
    // The age bound is EXCLUSIVE, and the one character is load bearing. `replay_until` below is
    // `iat + MAX_PROOF_AGE`, and `Storage::sweep_expired` drops a claimed `jti` when `now < exp`
    // fails, so at `now == iat + MAX_PROOF_AGE` the `jti` is already forgotten. An inclusive check
    // here would still ACCEPT the proof at that instant, against an empty replay cache: exactly
    // one free replay of a captured proof, which is the whole thing the `jti` exists to refuse.
    // The two predicates have to agree at the boundary, and the sweep's is the exclusive one.
    // `client_assertion` has never had this gap because its acceptance was exclusive already.
    let iat = jws.claim_time("iat").ok_or(DpopFailure::StaleProof)?;
    let issued_at = UNIX_EPOCH + Duration::from_secs(iat);
    if issued_at > now + CLOCK_SKEW_LEEWAY || issued_at + MAX_PROOF_AGE <= now {
        return Err(DpopFailure::StaleProof);
    }

    // (2) The `jti`, which single use is enforced on. Same argument as RFC 7523's: a proof that
    // cannot be remembered is one that can be sent again, so it is refused rather than accepted
    // with the check quietly skipped.
    let jti = jws.claim_str("jti").unwrap_or_default();
    if jti.is_empty() {
        return Err(DpopFailure::MissingJti);
    }

    Ok(VerifiedProof {
        jkt: jwk.thumbprint(),
        jti: jti.to_string(),
        replay_until: issued_at + MAX_PROOF_AGE,
    })
}

#[cfg(test)]
#[path = "tests/dpop.rs"]
mod tests;
