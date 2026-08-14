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
//!   That reasoning explains why this is a SEAM. It never justified shipping the seam EMPTY, and
//!   as of 0.9.0 the crate does not: [`crate::rate_limit::FixedWindowRateLimiter`] is a counter a
//!   host installs in one line, with defaults derived from the section 5.1 arithmetic. It is a
//!   floor rather than a ceiling (it is per process, so on a multi-node deployment the effective
//!   limit is multiplied by the node count); its module docs say plainly what it cannot do.
//!
//! # Zero cost until enabled
//!
//! The crate doc promises a host that never turns something on pays nothing for it, and this
//! module is built to keep that promise structurally rather than by intention:
//!
//! - [`Hooks`] is ONE pointer wide. The seams behind it are four in a default build (an
//!   [`EventSink`], a [`RateLimiter`], a [`crate::client::SecretVerifier`] and a
//!   [`crate::registration::RegistrationPolicy`]) and six with `jar` and `jwt` (a
//!   `RequestObjectKeys` and an `Es256Verifier`). Held as separate `Option<Box<dyn _>>` fields they
//!   would be 16 bytes each on every [`crate::server::AuthorizationServer`] value, so 64 bytes paid
//!   by every host and 96 by one enabling both features; instead they live inside a boxed struct
//!   that is not allocated at all until something is installed.
//!
//!   The registration policy is worth naming rather than counting, because it is the seam whose
//!   ABSENCE is the security behaviour: with none installed, every RFC 7591 registration is REFUSED
//!   (see [`Hooks::registration_policy`]), which is the opposite default to the rate limiter's.
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
#[cfg(feature = "client-assertion")]
use crate::client_assertion::AssertionFailure;
#[cfg(feature = "dpop")]
use crate::dpop::DpopFailure;
use crate::error::ErrorCode;
use crate::grant::GrantType;
use crate::registration::RegistrationPolicy;
use crate::scope::ScopeSet;
use crate::token::TokenTypeHint;

/// Why a client failed to authenticate (RFC 6749 section 5.2 `invalid_client`).
///
/// The WIRE collapses all of these into one `invalid_client`, deliberately, so an attacker cannot
/// probe which client ids exist. The AUDIT channel separates them just as deliberately: the host
/// is not the attacker, and "a thousand unknown client ids" and "a thousand wrong secrets for one
/// real client" are different incidents with different responses.
///
/// Shared by BOTH planes: it is the reason carried by
/// [`Event::ClientAuthenticationFailed`] (the token plane) and by
/// [`Event::ClientRegistrationAuthenticationFailed`] (the RFC 7592 management plane). One
/// vocabulary rather than two, because a host counting credential guesses wants to count the same
/// shapes wherever they happen; WHICH plane an attempt arrived on is the event variant, not this
/// enum, so a sink can separate them without having to learn a second set of names.
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
    /// The registration is dynamic (RFC 7591) and its `client_secret_expires_at` has passed, so the
    /// secret is no longer a credential however correct it is.
    ///
    /// Separated from [`ClientAuthFailure::SecretMismatch`] because the response differs and the
    /// urgency differs. This is not an attack: it is a client that missed a rotation window this
    /// server announced when it registered them, and the fix is to re-register rather than to
    /// investigate. A run of these after a rotation deadline is expected; a run of them before one
    /// means the deployment's clock or its issued lifetimes are wrong.
    SecretExpired,
    /// The registration is PUBLIC and the endpoint the caller reached admits confidential clients
    /// only: RFC 7662 section 2.1 introspection, and the RFC 6749 section 4.4 client credentials
    /// grant.
    ///
    /// Not a wrong credential — no credential was ever in play. A public registration has no
    /// secret, so "authenticated as a public client" is a sentence true of every caller on the
    /// internet, and naming a client id is not authentication.
    ///
    /// IT EXISTS SO THAT THE WIRE DOES NOT HAVE TO SAY IT. Through 0.9.1 both endpoints answered
    /// this case with an `invalid_client` CARRYING A DESCRIPTION ("introspection requires a
    /// confidential client"), while an unknown client id and a confidential client with the wrong
    /// secret both got a BARE `invalid_client` — so the description sorted "this id is registered,
    /// and it is public" from everything else, which is the enumeration
    /// [`ClientAuthFailure::UnknownClient`] and [`ClientAuthFailure::SecretMismatch`] are collapsed
    /// on the wire to prevent. The description is gone; the fact is here instead, in the channel
    /// where the reader is not the attacker. It is also the sentence an operator actually needs,
    /// because the usual cause is a resource server registered with the wrong
    /// `token_endpoint_auth_method` rather than an attack.
    NotConfidential,
    /// MANAGEMENT PLANE ONLY. The `client_id` names a client the HOST provisioned itself, which
    /// carries no RFC 7591 registration record and therefore no registration access token that
    /// could ever verify.
    ///
    /// Separated from [`ClientAuthFailure::UnknownClient`] because it says something that one does
    /// not: the client id was REAL. A run of these is somebody walking a deployment's static client
    /// ids looking for one that happens to be dynamically registered and therefore rewritable
    /// through RFC 7592 section 2.2; a run of `UnknownClient` is somebody who has not found a live
    /// id yet. The wire tells the caller neither (both are the same `401`).
    NoDynamicRegistration,
    /// The registration authenticates with RFC 8705 mutual TLS and NO certificate reached
    /// this crate. Worth separating from a mismatch: in practice it usually means the TLS
    /// terminator is not configured to request, verify or forward a client certificate, which
    /// is an operational fault affecting every mutual-TLS client at once rather than an
    /// attack on one of them.
    #[cfg(feature = "mtls")]
    NoCertificatePresented,
    /// A certificate was presented and did not match the registration (RFC 8705 section 2.1
    /// subject values, or section 2.2 thumbprints). This one IS the attack shape: a caller
    /// holding some valid certificate trying to be a client it is not.
    #[cfg(feature = "mtls")]
    CertificateMismatch,
    /// The registration exists and an RFC 7523 client assertion was presented that did not verify:
    /// a bad signature, an `alg` the registration does not use, an audience naming another server,
    /// an expired assertion, or a `jti` that had already been spent.
    ///
    /// Separated from [`ClientAuthFailure::SecretMismatch`] because the responses differ. A run of
    /// wrong secrets is credential stuffing; a run of REPLAYED assertions is somebody who has
    /// captured a client's traffic, which is a different incident and a much worse one.
    ///
    /// CARRIES THE REASON, because collapsing the nine into one told the operator nothing they
    /// could act on. `AssertionFailure` documents itself as existing "for the host's audit channel,
    /// where the reader is not the attacker", and until 0.9.1 the server discarded it here, so a
    /// burst of these was indistinguishable between clock skew on the client
    /// (`Expired`/`NotYetValid`, fix NTP), a key rotation the registration did not follow
    /// (`BadSignature`, fix the registration), and assertions captured at another authorization
    /// server and replayed here (`WrongAudience`, an incident). The mutual-TLS arm beside it
    /// already forwarded its failure verbatim, which is how the omission was found.
    #[cfg(feature = "client-assertion")]
    AssertionInvalid {
        /// Which of the RFC 7523 section 3 checks the assertion failed. Never reaches the wire:
        /// every one of them is the same `invalid_client` there.
        reason: AssertionFailure,
    },
}

/// The OPERATOR's sentence, never the client's. Everything here is what the wire deliberately
/// refuses to distinguish (see the type's docs), so these strings must not reach a response body.
impl std::fmt::Display for ClientAuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ClientAuthFailure::UnknownClient => "no registration for that client_id",
            ClientAuthFailure::SecretMismatch => "the presented client credential did not verify",
            ClientAuthFailure::RateLimited => "the host's rate limiter refused the attempt",
            ClientAuthFailure::SecretExpired => {
                "the registration's client_secret_expires_at has passed"
            }
            ClientAuthFailure::NotConfidential => {
                "that client id is registered as a public client, and this endpoint admits \
                 confidential clients only"
            }
            ClientAuthFailure::NoDynamicRegistration => {
                "that client id exists but was provisioned by the host, so it has no registration \
                 access token"
            }
            #[cfg(feature = "mtls")]
            ClientAuthFailure::NoCertificatePresented => {
                "the registration authenticates with mutual TLS and no certificate was presented"
            }
            #[cfg(feature = "mtls")]
            ClientAuthFailure::CertificateMismatch => {
                "the presented certificate is not one this registration authenticates with"
            }
            #[cfg(feature = "client-assertion")]
            // The REASON is appended rather than dropped: `AssertionFailure` already writes one
            // sentence per check, and this is the channel those sentences were written for.
            ClientAuthFailure::AssertionInvalid { reason } => {
                return write!(f, "the client assertion did not verify: {reason}")
            }
        })
    }
}

/// It is the `Err` payload of `crate::mtls::authenticate_via_mtls`, so a host handling that with
/// `?` or collecting it into a `Box<dyn Error>` needs this, exactly as `DpopFailure` and
/// `AssertionFailure` do for theirs. (Plain text rather than intra-doc links: those two types are
/// behind features this one is not, so a link would dangle in a default build.)
impl std::error::Error for ClientAuthFailure {}

/// Something the authorization server did, or refused to do, worth recording.
///
/// Every field borrows: an event costs no allocation to build, which is what lets a host with a
/// sink installed pay only for what its sink chooses to keep. See the module docs for the rule on
/// what may and may not appear here.
///
/// `#[non_exhaustive]`: later releases will add events, and adding one must not be a breaking change
/// for a host that matched on this. The RFC 7591 and 7592 registration events below arrived exactly
/// that way and are here now, as did [`Event::DpopProofRefused`], which this paragraph named as
/// the next candidate until 0.9.1 added it.
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
    /// An RFC 9449 DPoP proof was refused, and WHY.
    ///
    /// No `client_id`, and its absence is the honest shape rather than an omission: the proof is
    /// checked BEFORE anything authenticates (see `AuthorizationServer::verify_dpop`), because it
    /// binds to the REQUEST rather than to the grant, so at the moment this fires there is no
    /// established identity to name. A host that wants to correlate has its own request context,
    /// exactly as [`Attempt::DeviceUserCodeEntry`] requires.
    ///
    /// Every one of these is the same `invalid_dpop_proof` on the wire. The distinction is the
    /// operator's, and `DpopFailure` documents itself as existing for exactly that; through 0.9.0
    /// the server discarded it and emitted NO event at all, so a deployment could not tell a
    /// client with a skewed clock from one whose proofs were being captured and replayed.
    #[cfg(feature = "dpop")]
    DpopProofRefused {
        /// Which of the RFC 9449 section 4.3 checks the proof failed.
        failure: DpopFailure,
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
        /// Whether the refresh family was actually revoked (a chain already swept leaves nothing to
        /// kill, and a store that refuses the revocation kills nothing either).
        tokens_revoked: bool,
        /// Whether ANY step of the compromise response failed to persist: the family revocation,
        /// the fallback deletion of the access token the code minted, or the write that puts the
        /// consumed code record back so the NEXT replay is still detectable.
        ///
        /// This exists because the wire cannot carry the news. A replayed code is answered
        /// `invalid_grant` however badly the store is behaving, since the party being answered is
        /// whoever holds the leaked code, so this event is the ONLY signal a deployment gets that a
        /// code was replayed and the only place the truth about what was done can be told. An event
        /// that overstates the containment is worse than no event: it is what an operator reads
        /// while deciding not to investigate.
        ///
        /// `true` means credentials the server intended to destroy may still be live. Treat it as
        /// an incident that needs a human, not as a storage warning.
        containment_failed: bool,
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
        /// How many records the family revocation removed. `0` when the revocation itself failed,
        /// which `containment_failed` is what tells apart from a family that was already swept.
        records_revoked: u64,
        /// Whether the family revocation failed to persist, exactly as on
        /// [`Event::AuthorizationCodeReplayDetected`].
        ///
        /// The reuse is real and is reported either way: the token was consumed before this was
        /// judged, so the server cannot un-know that two parties hold it, and the presenter is
        /// answered `invalid_grant` whatever the store did. This event is therefore the ONLY place
        /// the truth about what was actually done can be told, and an event that overstates the
        /// containment is worse than no event — it is what an operator reads while deciding not to
        /// investigate.
        ///
        /// `true` means the compromised grant's tokens ARE STILL LIVE, up to their own expiry: the
        /// access tokens the family issued still authorize, and the refresh chain the thief rotated
        /// away can still be rotated again. The presented token's `Spent` record is put back so a
        /// further presentation is still detected as reuse, but nothing was revoked. Treat it as an
        /// incident that needs a human, not as a storage warning.
        containment_failed: bool,
    },
    /// A token was revoked through the RFC 7009 endpoint.
    TokenRevoked {
        /// The client that revoked it (section 2.1 requires it to be the owner).
        client_id: &'a str,
        /// Which kind was removed.
        token_type: TokenTypeHint,
        /// The presented token IS revoked; this says whether the RFC 7009 section 2.1 SHOULD that
        /// follows it succeeded. Revoking a refresh token also invalidates the access tokens of the
        /// same grant, and that cascade is deliberately non-fatal: turning a completed revocation
        /// into an error would tell an honest client nothing happened when the token it named is
        /// already gone. Non-fatal is not the same as unreported, and `true` here means the
        /// client's access tokens from that grant are still live for up to one access token TTL.
        ///
        /// Always `false` for an access token: there is no grant-wide cascade to attempt.
        cascade_failed: bool,
    },
    /// A resource owner WITHDREW a consent, and everything issued under it was revoked.
    ///
    /// The one event in this set a USER causes rather than a client, and it is worth recording for
    /// the same reason the two compromise events are: the cascade logs a client out of an account
    /// it was in the middle of working with, so a host will be asked what happened.
    /// `records_revoked` is how many tokens, codes and approved device grants the withdrawal
    /// actually removed, which is what distinguishes "the user ended a live session" from "the
    /// user revoked something that had already expired".
    #[cfg(feature = "consent")]
    ConsentWithdrawn {
        /// The client that may no longer act for this user.
        client_id: &'a str,
        /// The user who withdrew it.
        subject: &'a str,
        /// How many records the cascade removed.
        records_revoked: u64,
    },
    /// A client registered itself through RFC 7591 dynamic client registration.
    ///
    /// Worth watching even in a deployment that meant to enable this: RFC 7591 section 5 is
    /// explicit that an open registration endpoint lets anyone create clients, so the RATE of this
    /// event is the signal that an abuse policy is not holding. Carries no credential, so neither
    /// the issued client secret nor the registration access token reaches the host's logs.
    ClientRegistered {
        /// The identifier the server minted.
        client_id: &'a str,
    },
    /// A caller failed to authenticate at the RFC 7592 registration MANAGEMENT endpoint.
    ///
    /// The sibling of [`Event::ClientAuthenticationFailed`], and separate from it on purpose: the
    /// two planes are guessed at for different reasons, and a sink that could not tell them apart
    /// would report a management-plane brute force as token-endpoint noise. What is being guessed
    /// here is the registration access token, and RFC 7592 section 2.2 lets its holder replace the
    /// whole metadata document INCLUDING `redirect_uris`, which is where this client's
    /// authorization codes are delivered. A landed guess is therefore not "an attacker can act as
    /// this client"; it is "an attacker can have this client's codes sent to a URI they chose".
    ///
    /// Emitted for all four refusals of a management request, which the wire deliberately cannot
    /// tell apart (they are one `401`, because distinguishing them is an enumeration oracle over
    /// the client table): an attempt this host's [`RateLimiter`] denied before the store was
    /// touched ([`ClientAuthFailure::RateLimited`]), an unknown `client_id`
    /// ([`ClientAuthFailure::UnknownClient`]), a host-provisioned client that has no registration
    /// at all ([`ClientAuthFailure::NoDynamicRegistration`]), and a registration access token that
    /// did not verify ([`ClientAuthFailure::SecretMismatch`]).
    ///
    /// The limited one is emitted but NOT recorded as an attempt: the attempt never happened, so
    /// there is no outcome to report and charging it would bill the caller twice for one try.
    ///
    /// Carries no credential: not the presented token, not a prefix of it, not its length. See the
    /// module docs for the rule.
    ClientRegistrationAuthenticationFailed {
        /// The `client_id` the request named, which may name no registration. Not a secret
        /// (RFC 6749 section 2.2).
        client_id: &'a str,
        /// Which of the four indistinguishable-on-the-wire refusals this actually was.
        failure: ClientAuthFailure,
    },
    /// A registration was rewritten through RFC 7592 section 2.2.
    ///
    /// An update can change the redirect URIs, which is the whole of where this client's
    /// authorization codes may be delivered, so it deserves the same attention as the original
    /// registration.
    ClientRegistrationUpdated {
        /// The registration that changed.
        client_id: &'a str,
    },
    /// A registration was deleted through RFC 7592 section 2.3, taking with it every token,
    /// refresh chain and outstanding authorization code it held.
    ClientRegistrationDeleted {
        /// The registration that is now gone.
        client_id: &'a str,
    },
    /// The host's own [`crate::registration::RegistrationPolicy`] refused a registration or an
    /// update.
    ///
    /// Distinct from [`Event::ClientRegistrationAuthenticationFailed`], and the distinction is the
    /// point: that one is somebody who could not prove who they are, this one is somebody who
    /// DID and was then told no. On the management plane the caller has already presented a valid
    /// registration access token, so a stream of these is a client with a working credential
    /// repeatedly attempting something the deployment's policy forbids, which is a different
    /// investigation from a brute force and was previously invisible in both directions.
    ///
    /// It is also the only signal a host gets that its own policy is doing anything at all. The
    /// wire answer is a bare `401` chosen so that a policy refusing on CONTENT does not confirm
    /// what content it dislikes (see `register_dynamic_client`), which means the operator learns
    /// nothing from it either.
    ///
    /// Carries no credential: not the initial access token, not the registration access token, and
    /// not the rejected metadata document, which is attacker-supplied text of the host's own
    /// choosing to log or not.
    ClientRegistrationRefusedByPolicy {
        /// The registration being updated, for an RFC 7592 section 2.2 management request. `None`
        /// for an initial RFC 7591 registration, which has no `client_id` yet: the refusal happens
        /// before one is minted, deliberately, so that a refused attempt allocates nothing.
        client_id: Option<&'a str>,
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
    /// A client is authenticating at a token-plane endpoint, or at the RFC 7592 registration
    /// management plane. The `client_id` is included because RFC 6749 section 2.2 makes it
    /// explicitly not a secret, so a limiter may key on it.
    ///
    /// ONE BUDGET FOR A CLIENT'S TWO BEARER CREDENTIALS, deliberately. The client secret and the
    /// registration access token answer the same question — may this caller keep presenting
    /// credentials as this `client_id` — and separate budgets would let an attacker stuffing the
    /// management plane stay under a limiter watching the token endpoint, while the credential
    /// they are guessing at is the more powerful of the two (RFC 7592 section 2.3 deletes the
    /// registration and everything it was issued).
    ///
    /// IT ALSO CARRIES A RESOURCE SERVER'S INTROSPECTION TRAFFIC, and a limiter keying on this
    /// needs to know that, because it is the one caller whose volume is not a function of anything
    /// this server issued. A registration named in
    /// [`crate::server::ServerConfig::resource_servers`] authenticates here once per RFC 7662
    /// introspection, which is once per call at the protected resource it guards. There is
    /// deliberately no introspection-specific variant: adding one to this `#[non_exhaustive]` enum
    /// would land in the wildcard arm of every limiter already written, and a wildcard that
    /// answers [`RateLimitDecision::Allow`] would silently stop throttling the endpoint on
    /// upgrade. See "Resource servers introspect once per API call" in [`crate::rate_limit`] for
    /// how to give one `client_id` a capacity of its own instead.
    ClientAuthentication {
        /// The presented identifier, which may name no registration.
        client_id: &'a str,
    },
    /// A user code was entered at the host's verification UI
    /// ([`crate::server::AuthorizationServer::approve_device`] /
    /// [`crate::server::AuthorizationServer::deny_device`]). This is the attempt RFC 8628 section
    /// 5.1 requires a deployment to rate limit.
    DeviceUserCodeEntry,
    /// A request at the AUTHORIZATION endpoint
    /// ([`crate::server::AuthorizationServer::validate_authorization_request`], and again where an
    /// approved request is turned into a code).
    ///
    /// The endpoint that takes NO CREDENTIAL at all, which is why it wants a variant of its own
    /// rather than sharing [`Attempt::ClientAuthentication`]'s: there is nothing here for a limiter
    /// counting credential guesses to count, and the `client_id` is the presented one (RFC 6749
    /// section 2.2 makes it public), so a caller may name any registration they like. What a
    /// deployment is bounding is work and STORAGE: every request costs a `get_client`, and an
    /// approved one WRITES an authorization code record that nothing but
    /// [`crate::store::Storage::sweep_expired`] reclaims.
    ///
    /// Checked twice on a completed flow, deliberately, because the two points cost different
    /// things: the validation is a read, and the issuance is the write. A limiter that charged the
    /// second to the first would let a caller who validates once issue without further charge.
    AuthorizationRequest {
        /// The `client_id` the request named, which may name no registration.
        client_id: &'a str,
    },
    /// An RFC 7591 dynamic client registration
    /// ([`crate::server::AuthorizationServer::register_dynamic_client`]).
    ///
    /// THE ONE UNBOUNDED WRITE IN THE CRATE, and the reason is that a [`crate::client::Client`] has
    /// no expiry: no deadline, no sweep, nothing that ever reclaims one. Every other attacker-driven
    /// record this server writes (a code, a token, a device grant, a replay `jti`) carries a
    /// deadline and is reclaimed by [`crate::store::Storage::sweep_expired`], so an unthrottled
    /// endpoint there is a burst. Here it is permanent growth, one row per request, forever.
    ///
    /// NO `client_id`, and its absence is deliberate rather than an oversight: at the moment this
    /// is checked no identifier has been minted, and none is minted for a refusal, so a refused
    /// registration allocates nothing at all. A limiter that wants to key on the caller has to use
    /// its own request context, exactly as [`Attempt::DeviceUserCodeEntry`] requires.
    ClientRegistration,
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
///
/// A HOST DOES NOT HAVE TO WRITE ONE. [`crate::rate_limit::FixedWindowRateLimiter`] is an
/// implementation this crate ships, in memory, with no new dependency and with defaults derived
/// from the section 5.1 arithmetic. Implement this trait yourself when you have something the
/// library does not: a request IP, a session, a user, or a store shared across nodes.
///
/// # MUST NOT PANIC, and should not block
///
/// Both methods MUST answer for every input. There is no error channel and none is needed:
/// [`RateLimitDecision::Allow`] and [`RateLimitDecision::Deny`] are both always available, and a
/// limiter that cannot reach its shared counter should decide which of the two its deployment
/// prefers rather than unwinding. This crate catches no unwind anywhere on a request path.
///
/// NAMING THE CONSEQUENCE, once per method, because the two sit at different points of a request:
///
/// - [`RateLimiter::check`] runs BEFORE any credential is evaluated, which is the whole point of
///   it, and that puts it on the paths an UNAUTHENTICATED caller reaches: the authorization
///   request, RFC 8628 section 5.1 user-code entry, and client authentication at the token
///   endpoint. A panic here is remotely reachable by anyone who can open a socket, and it takes
///   the request down before the throttle that would have limited how often they could try it.
/// - [`RateLimiter::record`] runs AFTER the request has done its work, including after the store
///   writes it drove. A panic here unwinds a request whose records are already written and whose
///   response never reaches the client: the credential was spent, the client was told nothing, and
///   the only place the two could have been reconciled was the response that was lost.
///
/// Blocking is the same argument one notch quieter. `check` is called inline on the caller's
/// executor thread, so a limiter that waits on a network round trip to a shared counter adds that
/// wait to every request, and on a current-thread runtime it adds it to every OTHER request too.
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

/// The installed seams. Boxed as a unit (see [`Hooks`]) so that installing none of them allocates
/// anything at all.
#[derive(Default)]
struct Installed {
    events: Option<Box<dyn EventSink>>,
    rate_limiter: Option<Box<dyn RateLimiter>>,
    secret_verifier: Option<Box<dyn SecretVerifier>>,
    registration_policy: Option<Box<dyn RegistrationPolicy>>,
    #[cfg(feature = "jar")]
    request_object_keys: Option<Box<dyn crate::par::RequestObjectKeys>>,
    /// The host's ES256 backend for VERIFICATION (RFC 9449 DPoP proofs, RFC 9101 request objects,
    /// RFC 7523 client assertions). `Arc` rather than `Box` because it is also what a host hands
    /// to [`crate::signer_conformance`] and may share with its own resource-server half.
    #[cfg(feature = "jwt")]
    es256_verifier: Option<std::sync::Arc<dyn crate::jwt::Es256Verifier>>,
}

/// The server's slot for the host seams: exactly one pointer wide, and null until the host
/// installs something.
///
/// This shape is the design decision the module docs argue for. Holding the seams as separate
/// `Option<Box<dyn _>>` fields directly on [`crate::server::AuthorizationServer`] would add 16
/// bytes each, 64 in a default build and 96 with `jar` and `jwt`, to every server value in every
/// deployment, including every deployment that installs nothing, and
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

    // THE INSTALLERS ARE `pub(crate)`, and the READERS below are `pub`. That asymmetry is the
    // whole shape of this type: `Hooks` is a LAYOUT decision (one nullable pointer, size-gated in
    // `tests/allocation.rs`), not a second installation API. A host installs through the six
    // `AuthorizationServer::with_*` builders, which are the one verb for the one job; it reads
    // through `AuthorizationServer::hooks()` when it wants to emit onto the same channel or
    // consult its own limiter. Through 0.9.0 both spellings were public and only one of them was
    // reachable, because `AuthorizationServer::new` builds its own `Hooks` and hands out only a
    // shared reference: every in-tree caller of the `install_*` form was a test.

    /// Install the audit sink, replacing any previous one.
    pub(crate) fn install_event_sink(&mut self, sink: Box<dyn EventSink>) {
        self.installed().events = Some(sink);
    }

    /// Install the rate limiter, replacing any previous one.
    pub(crate) fn install_rate_limiter(&mut self, limiter: Box<dyn RateLimiter>) {
        self.installed().rate_limiter = Some(limiter);
    }

    /// Install the client secret verifier, replacing any previous one.
    pub(crate) fn install_secret_verifier(&mut self, verifier: Box<dyn SecretVerifier>) {
        self.installed().secret_verifier = Some(verifier);
    }

    /// Install the RFC 7591 registration policy, replacing any previous one.
    pub(crate) fn install_registration_policy(&mut self, policy: Box<dyn RegistrationPolicy>) {
        self.installed().registration_policy = Some(policy);
    }

    /// Install the RFC 9101 request object verification keys, replacing any previous source.
    #[cfg(feature = "jar")]
    pub(crate) fn install_request_object_keys(
        &mut self,
        keys: Box<dyn crate::par::RequestObjectKeys>,
    ) {
        self.installed().request_object_keys = Some(keys);
    }

    /// Install the ES256 backend used to VERIFY signatures, replacing any previous one.
    #[cfg(feature = "jwt")]
    pub(crate) fn install_es256_verifier(
        &mut self,
        verifier: std::sync::Arc<dyn crate::jwt::Es256Verifier>,
    ) {
        self.installed().es256_verifier = Some(verifier);
    }

    /// The installed ES256 verifier, or `None`.
    ///
    /// `None` is NOT read as "accept anything": every caller refuses instead. Callers inside this
    /// crate reach the verifier through a private resolver on `AuthorizationServer`, which is what
    /// applies the `jwt-p256` fallback; this method reports only what the HOST installed, so that
    /// fallback lives in exactly one place.
    #[cfg(feature = "jwt")]
    pub fn es256_verifier(&self) -> Option<&std::sync::Arc<dyn crate::jwt::Es256Verifier>> {
        match &self.0 {
            Some(installed) => installed.es256_verifier.as_ref(),
            None => None,
        }
    }

    /// The installed RFC 9101 request object key source.
    ///
    /// `None` is NOT read as "accept anything", for the same reason as
    /// [`Hooks::registration_policy`] and the opposite of the [`RateLimiter`] default: a server
    /// that cannot check a signature must refuse the request, because "cannot check" must never
    /// read as "checked out".
    #[cfg(feature = "jar")]
    pub fn request_object_keys(&self) -> Option<&dyn crate::par::RequestObjectKeys> {
        match &self.0 {
            Some(installed) => installed.request_object_keys.as_deref(),
            None => None,
        }
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
    ///
    /// "Allow" is therefore the answer for a host that installed nothing, and RFC 8628 section 5.1
    /// says that host is running an under-protected verification endpoint. Install
    /// [`crate::rate_limit::FixedWindowRateLimiter`] if you have nothing better.
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

    /// The installed RFC 7591 registration policy.
    ///
    /// `None` means the host installed none, and that is NOT read as "allow": see
    /// [`RegistrationPolicy`]. It is the opposite of the [`RateLimiter`] default above, and
    /// deliberately so. An absent limiter means the host has not written a throttling policy yet,
    /// and refusing every request would break a host that never asked for throttling. An absent
    /// registration policy means the host turned on an endpoint that mints clients and said
    /// nothing about who may use it, and RFC 7591 section 5 is explicit about what an open one
    /// costs.
    pub fn registration_policy(&self) -> Option<&dyn RegistrationPolicy> {
        match &self.0 {
            Some(installed) => installed.registration_policy.as_deref(),
            None => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/events.rs"]
mod tests;
