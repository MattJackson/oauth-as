// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The host seams this library cannot fill for itself: an AUDIT EVENT channel and a RATE LIMITING
//! decision point, plus the one slot ([`Hooks`]) the server carries for both of them and for the
//! client secret verifier ([`crate::client::SecretVerifier`]).
//!
//! # Why these live here and not in the host's own code
//!
//! Both answer questions only the library can ask and only the host can answer.
//!
//! - OBSERVATION. This crate revokes a whole token family when it detects authorization code
//!   replay (RFC 9700 section 4.1.1) or refresh token reuse (OAuth 2.1 draft section 6.1, RFC 9700
//!   section 4.14.2). Those are the crate's most serious security behaviours and their entire
//!   value is that somebody NOTICES: a revocation that appears in no log is an incident nobody
//!   investigates. Nothing outside the library can see either event, because the evidence (a
//!   consumed code presented twice, a spent refresh record presented again) exists only inside the
//!   grant machinery.
//! - THROTTLING. RFC 8628 section 5.1 makes the device user code's entropy adequate only IN
//!   COMBINATION WITH rate limiting of code entry. The library knows an attempt happened and
//!   whether it failed; it does NOT know the caller, the IP, the session or the user, because it
//!   never sees a request. So the library asks and reports, and the host counts and decides.
//!
//! # Zero cost until enabled
//!
//! The crate doc promises a host that never turns something on pays nothing for it, and this
//! module is built to keep that promise structurally rather than by intention:
//!
//! - [`Hooks`] is ONE pointer wide: three seams behind three trait objects would be 48 bytes on
//!   every [`crate::server::AuthorizationServer`] value, paid by every host, so the three live
//!   inside a boxed struct that is not allocated at all until something is installed.
//! - [`Hooks::emit`] takes a CLOSURE, not an [`Event`]. With no sink installed the closure is
//!   never called, so the event is never built: no allocation, no formatting, no vtable dispatch,
//!   just one null check on a pointer that is already in cache. `tests/events.rs` measures exactly
//!   that with a counting allocator and with a closure that panics if it is ever run.
//! - Events are delivered SYNCHRONOUSLY, on the calling task. This crate has no background task by
//!   design (see the crate docs) and does not gain one here; a host that wants buffering owns a
//!   channel and writes three lines of [`EventSink`].
//!
//! # What events may carry, and what they may never carry
//!
//! Security finding C13 hand-wrote `Debug` on every type in this crate that holds a credential, so
//! that a host's `tracing::debug!(?request)` could not become a plaintext credential leak. An event
//! channel is a second way out of the process for the same values, and it goes to the same logs,
//! so it is held to the same rule: NO access token, NO refresh token, NO authorization code, NO
//! device code, NO user code, NO client secret, NO PKCE verifier. `tests/events.rs` scans the
//! [`Event`] declaration and fails if a field named after one of those appears.
//!
//! What events DO carry is what an incident response needs to act:
//!
//! - `client_id`, which RFC 6749 section 2.2 states is not a secret.
//! - the `subject`, where there is one. This is the host's own user identifier, which the host
//!   already put into this crate; it is not a credential (holding it authenticates nobody), though
//!   a host in a privacy-regulated setting may want to treat it as personal data in its logs.
//! - the `family_id` of a refresh chain. This one is worth justifying, because it is the only
//!   opaque server-minted string in the whole set. It is SAFE to log because it is not a
//!   credential in any sense the protocol recognises: it is accepted at no endpoint, it appears in
//!   no request and no response, it is never given to a client, and possessing it lets nobody
//!   obtain, refresh or introspect a token. Its only power is to NAME a set of records in the
//!   host's own store, which is precisely the correlation an operator needs to answer "what else
//!   did this compromised grant issue" and to call [`crate::store::Storage::revoke_token_family`]
//!   by hand. The alternative, logging the tokens themselves, is the leak this rule exists to
//!   prevent; the alternative of logging nothing makes the revocation untraceable.

use crate::client::SecretVerifier;
use crate::error::ErrorCode;
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::token::TokenTypeHint;

/// Why a client failed to authenticate (RFC 6749 section 5.2 `invalid_client`).
///
/// The WIRE collapses all of these into one `invalid_client`, deliberately, so an attacker cannot
/// probe which client ids exist. The AUDIT channel separates them just as deliberately: the host
/// is not the attacker, and "a thousand unknown client ids" and "a thousand wrong secrets for one
/// real client" are different incidents with different responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientAuthFailure {
    /// No registration exists for the presented `client_id`.
    UnknownClient,
    /// The registration exists and the presented credential did not verify (or none was presented
    /// for a confidential client, or one was presented for a public one).
    SecretMismatch,
    /// The host's own [`RateLimiter`] refused the attempt before it was evaluated.
    RateLimited,
}

/// Something the authorization server did, or refused to do, worth recording.
///
/// Every field borrows: an event costs no allocation to build, which is what lets a host with a
/// sink installed pay only for what its sink chooses to keep. See the module docs for the rule on
/// what may and may not appear here.
///
/// `#[non_exhaustive]`: later releases will add events (RFC 7591 registration, DPoP proof failures)
/// and adding one must not be a breaking change for a host that matched on this.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event<'a> {
    /// A client failed to authenticate at a token-plane endpoint.
    ClientAuthenticationFailed {
        /// The `client_id` presented, which may not name any registration.
        client_id: &'a str,
        /// Which of the two indistinguishable-on-the-wire failures this actually was.
        failure: ClientAuthFailure,
    },
    /// An access token was issued (and possibly a refresh token with it).
    TokenIssued {
        /// The client the grant was issued to.
        client_id: &'a str,
        /// Which grant produced it.
        grant_type: GrantType,
        /// The resource owner, absent for `client_credentials` (RFC 6749 section 4.4 has none).
        subject: Option<&'a str>,
        /// The granted scope, borrowed rather than rendered: a sink that does not want it pays
        /// nothing, and one that does can format it itself.
        scope: &'a ScopeSet,
        /// The refresh chain this issuance belongs to, when it has one. See the module docs for
        /// why this identifier is safe to log.
        family_id: Option<&'a str>,
        /// Whether a refresh token was issued alongside the access token.
        refresh_issued: bool,
    },
    /// A grant request was refused, with the RFC 6749 section 5.2 code the client was told.
    GrantRefused {
        /// The client that asked.
        client_id: &'a str,
        /// The grant it asked for.
        grant_type: GrantType,
        /// The error code that went back on the wire.
        error: ErrorCode,
    },
    /// A user approved a device grant at the host's verification UI (RFC 8628 section 3.3).
    DeviceGrantApproved {
        /// The device's client.
        client_id: &'a str,
        /// The user who approved it.
        subject: &'a str,
    },
    /// A user refused a device grant, which the device will next see as `access_denied`.
    DeviceGrantDenied {
        /// The device's client.
        client_id: &'a str,
    },
    /// EVIDENCE OF COMPROMISE. An authorization code was presented after it had already been
    /// redeemed (RFC 6749 section 4.1.2, RFC 9700 section 4.1.1). The server has refused the
    /// replay and revoked what the code minted; a code is a value that leaks into logs, `Referer`
    /// headers and browser history, so a replay means either a leak or an attack in progress.
    AuthorizationCodeReplayDetected {
        /// The client the code was issued to.
        client_id: &'a str,
        /// The refresh family that was revoked, when the code's chain was still reachable.
        family_id: Option<&'a str>,
        /// Whether anything was actually revoked (a chain already swept leaves nothing to kill).
        tokens_revoked: bool,
    },
    /// EVIDENCE OF COMPROMISE, and the most serious event here. A superseded refresh token was
    /// presented, which means two parties hold it (OAuth 2.1 draft section 6.1, RFC 9700 section
    /// 4.14.2). The whole family has been revoked, which also logs out the legitimate client, so
    /// this is an event a host will be asked about.
    RefreshTokenReuseDetected {
        /// The client that presented the spent token.
        client_id: &'a str,
        /// The revoked family. See the module docs for why this is safe to log.
        family_id: &'a str,
        /// How many records the family revocation removed.
        records_revoked: u64,
    },
    /// A token was revoked through the RFC 7009 endpoint.
    TokenRevoked {
        /// The client that revoked it (section 2.1 requires it to be the owner).
        client_id: &'a str,
        /// Which kind was removed.
        token_type: TokenTypeHint,
    },
}

/// Where events go. The host implements this; the library never logs anything itself.
///
/// `on_event` is called SYNCHRONOUSLY, inside the request the host is already driving, and it takes
/// `&self` so the sink is shared. Two consequences a host should design for: a slow sink slows the
/// token endpoint, and a panicking sink panics the request. A host doing anything expensive should
/// push onto a channel here and do the work elsewhere; this crate will not own that thread.
pub trait EventSink: Send + Sync {
    /// Record one event. Must not panic and should not block.
    fn on_event(&self, event: Event<'_>);
}

/// Something a caller is attempting that a host may want to throttle.
///
/// Deliberately carries no credential: not the user code being tried (RFC 8628 section 6.1 makes
/// it the credential a human types) and not the secret. It also cannot carry an IP or a session,
/// because this library never sees a request; a host correlates using its own request context,
/// which it still holds at the moment it calls into the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Attempt<'a> {
    /// A client is authenticating at a token-plane endpoint. The `client_id` is included because
    /// RFC 6749 section 2.2 makes it explicitly not a secret, so a limiter may key on it.
    ClientAuthentication {
        /// The presented identifier, which may name no registration.
        client_id: &'a str,
    },
    /// A user code was entered at the host's verification UI
    /// ([`crate::server::AuthorizationServer::approve_device`] /
    /// [`crate::server::AuthorizationServer::deny_device`]). This is the attempt RFC 8628 section
    /// 5.1 requires a deployment to rate limit.
    DeviceUserCodeEntry,
}

/// What a [`RateLimiter`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitDecision {
    /// Proceed.
    Allow,
    /// Refuse without evaluating the credential.
    Deny,
}

/// How an attempt turned out, reported back so a limiter can count FAILURES rather than traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptOutcome {
    /// The credential verified / the code matched a live grant.
    Succeeded,
    /// It did not. This is the signal a guessing attack produces.
    Failed,
}

/// The host's throttle. THIS LIBRARY DOES NOT RATE LIMIT ANYTHING, and cannot: it never sees a
/// request, so it has no caller, no IP, no session and no user to count against.
///
/// RFC 8628 section 5.1 is explicit that the device user code's entropy is sufficient only in
/// combination with rate limiting of user code entry, so for any deployment offering the device
/// grant this is not optional in practice, only optional in the type system.
pub trait RateLimiter: Send + Sync {
    /// Decide whether `attempt` may proceed. Called BEFORE any credential is evaluated, so a
    /// `Deny` costs the attacker a lookup and tells them nothing.
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision;

    /// Report how an allowed attempt turned out. Defaults to doing nothing, so a host that only
    /// wants a hard ceiling implements one method.
    fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
        let _ = (attempt, outcome);
    }
}

/// The three installed seams. Boxed as a unit (see [`Hooks`]) so that installing none of them
/// allocates nothing at all.
#[derive(Default)]
struct Installed {
    events: Option<Box<dyn EventSink>>,
    rate_limiter: Option<Box<dyn RateLimiter>>,
    secret_verifier: Option<Box<dyn SecretVerifier>>,
}

/// The server's slot for the host seams: exactly one pointer wide, and null until the host
/// installs something.
///
/// This shape is the design decision the module docs argue for. Holding three `Option<Box<dyn _>>`
/// fields directly on [`crate::server::AuthorizationServer`] would add 48 bytes to every server
/// value in every deployment, including every deployment that installs nothing, and
/// `tests/allocation.rs` holds that type to a size budget precisely so a convenience like that
/// cannot be paid for silently.
#[derive(Default)]
pub struct Hooks(Option<Box<Installed>>);

impl Hooks {
    /// An empty slot: nothing installed, nothing allocated.
    pub fn new() -> Self {
        Hooks(None)
    }

    fn installed(&mut self) -> &mut Installed {
        // The one allocation this module can make, and only on a host's explicit install call.
        self.0.get_or_insert_with(Default::default)
    }

    /// Install the audit sink, replacing any previous one.
    pub fn install_event_sink(&mut self, sink: Box<dyn EventSink>) {
        self.installed().events = Some(sink);
    }

    /// Install the rate limiter, replacing any previous one.
    pub fn install_rate_limiter(&mut self, limiter: Box<dyn RateLimiter>) {
        self.installed().rate_limiter = Some(limiter);
    }

    /// Install the client secret verifier, replacing any previous one.
    pub fn install_secret_verifier(&mut self, verifier: Box<dyn SecretVerifier>) {
        self.installed().secret_verifier = Some(verifier);
    }

    /// Whether an event sink is installed.
    ///
    /// Call sites use this to decide whether to CLONE a value that is about to be consumed and
    /// would otherwise be unavailable by the time the event can honestly be emitted (a client id
    /// moved into a grant record, say). An unobserved host takes the `false` branch and pays
    /// nothing; an observed one pays one small clone for the record it asked for.
    pub fn is_observed(&self) -> bool {
        match &self.0 {
            Some(installed) => installed.events.is_some(),
            None => false,
        }
    }

    /// Emit an event, building it ONLY if a sink is installed.
    ///
    /// The closure is the whole point: see the module docs. With no sink this compiles down to a
    /// null check and a return.
    pub fn emit<'a, F>(&self, event: F)
    where
        F: FnOnce() -> Event<'a>,
    {
        if let Some(installed) = &self.0 {
            if let Some(sink) = &installed.events {
                sink.on_event(event());
            }
        }
    }

    /// Ask the host's limiter whether `attempt` may proceed. With none installed the answer is
    /// [`RateLimitDecision::Allow`]: a library with no notion of a caller has no business
    /// inventing a throttling policy, and failing closed here would break every host that has not
    /// yet written one.
    pub fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        match &self.0 {
            Some(installed) => match &installed.rate_limiter {
                Some(limiter) => limiter.check(attempt),
                None => RateLimitDecision::Allow,
            },
            None => RateLimitDecision::Allow,
        }
    }

    /// Report an outcome to the host's limiter, if any.
    pub fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
        if let Some(installed) = &self.0 {
            if let Some(limiter) = &installed.rate_limiter {
                limiter.record(attempt, outcome);
            }
        }
    }

    /// The installed client secret verifier, for [`crate::client::ClientAuth::verify_with`].
    pub fn secret_verifier(&self) -> Option<&dyn SecretVerifier> {
        match &self.0 {
            Some(installed) => installed.secret_verifier.as_deref(),
            None => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/events.rs"]
mod tests;
