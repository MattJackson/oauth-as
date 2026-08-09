// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Consent records, consent withdrawal, and RFC 9470 step-up authentication.
//!
//! Two things a real deployment needs that nothing else in this crate provided.
//!
//! # 1. A consent is a UNIT, and a unit can be withdrawn
//!
//! Before this module the only durable grouping this server had was the refresh chain's
//! `family_id` (see [`crate::token::RefreshTokenRecord::family_id`]), which exists so that RFC 9700
//! section 4.14.2 reuse detection can revoke "the tokens issued for that authorization grant".
//! That grouping is too NARROW to answer the question a user asks. A user does not ask "end the
//! chain that started on Tuesday"; they ask "this application should no longer act for me", and one
//! application acting for one user accumulates many families over time, because every fresh trip
//! through the authorization endpoint mints another one.
//!
//! So a [`ConsentRecord`] is the broader unit, keyed by (client, subject), and
//! [`crate::store::Storage::revoke_consent`] is [`crate::store::Storage::revoke_token_family`] at
//! that broader granularity: the same "remove every record reachable from this unit" primitive,
//! asked of a bigger unit, in ONE storage operation so a host's database can do the whole cascade
//! in one transaction. A withdrawal that left tokens alive would be the whole feature failing
//! silently, and silently is the worst way for it to fail, because the user has been told they
//! stopped something they did not. `tests/consent.rs` attacks exactly that case.
//!
//! # 2. This library cannot authenticate anybody, and says so
//!
//! RFC 9470 is about the AUTHENTICATION behind an authorization: a resource server decides the
//! request it just received needs a stronger or a fresher login than the token reflects, and says
//! so with an `insufficient_user_authentication` challenge (section 3). The client then repeats its
//! authorization request carrying `acr_values` and `max_age` (section 4, the parameters OpenID
//! Connect Core section 3.1.2.1 defines), and the authorization server is expected to act on them
//! and to report what it did as `acr` and `auth_time` (section 5).
//!
//! This crate has no login page, no session store, no password, no second factor, and no way to
//! challenge a user, and it will not grow any of them: that is the same boundary the crate docs
//! draw around the HTTP listener and persistence. So the division of labour is blunt, and worth
//! stating in full rather than leaving to be discovered:
//!
//! - the HOST authenticates the user, by whatever means, and REPORTS the result as an
//!   [`Authentication`]: when it happened, and which authentication context class it satisfied. The
//!   library takes that report at face value, because it has nothing to check it against. A host
//!   that stamps `auth_time` with the current instant on every request has disabled `max_age` for
//!   itself and no code here can tell.
//! - the LIBRARY records that report on the consent, on the authorization code, and on the tokens
//!   the code mints, and it ENFORCES `max_age` and `acr_values` against it
//!   ([`AuthenticationRequirement::satisfied_by`]). Enforcement is the half that must not be left
//!   to the host: a `max_age` a host is trusted to check for itself is a `max_age` that gets
//!   checked in whichever code path somebody remembered.
//! - the library CANNOT re-authenticate anyone in response to a failure. It answers
//!   [`crate::error::ErrorCode::InsufficientUserAuthentication`] and the host decides whether that
//!   becomes a fresh login prompt or a refusal.
//!
//! # Allocation
//!
//! [`Authentication`] hangs off its three records as an `Option<Box<Authentication>>`: one null
//! pointer for the common case of a host that reports nothing, and one small allocation for a host
//! that does. Its `acr`, and the consent record's identifier and subject, are `Box<str>` rather
//! than `String` for the reason [`crate::token::IssuedToken::jkt`] gives: they are written once and
//! never appended to, so a `String`'s growable capacity would be 8 dead bytes on every record a
//! store holds. Everything here is feature gated, so a build without `consent` carries neither the
//! pointers nor the code that reads them.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::error::{ErrorCode, ErrorResponse};
use crate::scope::ScopeSet;

/// The largest number of RFC 8707 resource indicators one [`ConsentRecord`] will accumulate.
///
/// # Why this one matters more than the per-request caps
///
/// [`crate::server::MAX_RESOURCE_INDICATORS`] bounds what a single request may ask for, and that
/// cost dies with the request. This bounds what a (client, subject) relationship accumulates over
/// its whole life. The list is only ever widened by [`ConsentRecord::extend`], it is never pruned,
/// and [`ConsentRecord::covers`] walks it linearly on every authorization request that consults the
/// record. Without a bound, a client naming one fresh indicator per request buys a record that
/// grows forever and a check that gets slower forever, and the deployment never gets that back.
///
/// # Why 32
///
/// It is twice the per-request cap, which is the smallest number that is not simply the per-request
/// cap in disguise: a relationship legitimately widens over time, so a user who approves one set of
/// resources today and a different set next month should not hit the ceiling on the second visit.
/// Beyond that, a single (client, subject) pair spanning more than thirty-two distinct resource
/// servers is a client acting for the user across an estate large enough that per-resource consent
/// has stopped meaning anything to the person granting it, which is a product problem this number
/// makes visible rather than a limit it creates.
pub const MAX_CONSENT_RESOURCES: usize = 32;

/// What the HOST says about how, and when, it authenticated the resource owner.
///
/// This is a REPORT, not a proof. See the module docs: this crate cannot authenticate anyone and
/// has no way to check this against anything, so it records it and holds requests to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authentication {
    /// When the user actually authenticated. OpenID Connect Core section 2 defines `auth_time` as
    /// the "time when the End-User authentication occurred", and RFC 9470 section 5 is what makes
    /// it worth carrying: `max_age` is meaningless without an instant to measure from.
    ///
    /// NOT "when this request arrived". A host that conflates the two makes every request look
    /// freshly authenticated, which is the one mistake that turns this whole mechanism into
    /// decoration.
    pub auth_time: SystemTime,
    /// The authentication context class the host says was satisfied: OpenID Connect Core section 2
    /// `acr`. `None` means the host reported none, which can satisfy no `acr_values` request.
    ///
    /// The VALUES are the host's own vocabulary. This crate compares them as opaque strings and
    /// deliberately knows nothing about what any of them means: there is no registry it could check
    /// against, and a library that pretended to understand "phr" would be asserting something about
    /// a login flow it has never seen.
    ///
    /// `Box<str>`, not `String`: written once at the moment the host reports it and never appended
    /// to. Same reasoning as [`crate::token::IssuedToken::jkt`].
    pub acr: Option<Box<str>>,
}

impl Authentication {
    /// A report with no `acr`, for an authentication that happened at `auth_time`.
    ///
    /// `auth_time` is WHEN THE USER ACTUALLY LOGGED IN, not when this request arrived, and this
    /// constructor is the place that distinction is lost or kept. Passing `SystemTime::now()` here
    /// on every request makes every login look seconds old, which satisfies every `max_age` a
    /// client can ask for and turns RFC 9470 step-up into decoration for that deployment. Nothing
    /// downstream can detect it: see the module docs on which half of this boundary is the host's.
    pub fn at(auth_time: SystemTime) -> Self {
        Authentication {
            auth_time,
            acr: None,
        }
    }

    /// Name the authentication context class this login satisfied.
    ///
    /// `&str` rather than `impl Into<String>`: a generic here monomorphizes once per argument type
    /// at every call site, and the value is going into a `Box<str>` either way.
    pub fn with_acr(mut self, acr: &str) -> Self {
        self.acr = Some(acr.into());
        self
    }

    /// How old this authentication is at `now`, or `None` if it is stamped in the future.
    ///
    /// A future `auth_time` is not an error here: clocks on separate machines disagree, and the one
    /// decision this feeds ([`AuthenticationRequirement::satisfied_by`]) reads `None` as "no
    /// elapsed time", which is the reading that cannot lock a user out over a clock skew.
    pub fn age(&self, now: SystemTime) -> Option<Duration> {
        now.duration_since(self.auth_time).ok()
    }
}

/// A persisted record that one resource owner granted one client a set of permissions.
///
/// Keyed by (`client_id`, `subject`): one live consent per pair, widened in place when the user
/// approves something further or re-authenticates. That key is what makes withdrawal answerable,
/// and it is deliberately COARSER than the refresh chain's `family_id`, because a user withdrawing
/// consent means "not this application, not for me, not any more" rather than "not this chain".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// The server-minted identifier for this consent.
    ///
    /// Opaque, and NOT a credential: it is accepted at no endpoint, it authenticates nobody, and
    /// its only power is to NAME this record in the host's own store, exactly as `family_id` names
    /// a chain (the [`crate::events`] module docs make that argument in full). It is still minted
    /// from OS randomness rather than derived from the client and the subject, because naming a
    /// record that can end a user's sessions should not be something a third party can do by
    /// guessing two strings it already knows.
    ///
    /// `Box<str>`: written once at creation and never appended to.
    pub consent_id: Box<str>,
    /// The client the user granted.
    pub client_id: ClientId,
    /// The resource owner who granted it, in the host's own vocabulary for users. `Box<str>` for
    /// the same reason as `consent_id`.
    pub subject: Box<str>,
    /// The scope the user approved, accumulated across grants: this is what "remembered consent"
    /// remembers.
    pub scope: ScopeSet,
    /// The RFC 8707 resource indicators the user approved this client to obtain tokens for. Empty
    /// means the user approved no audience restriction, which is NOT the same as approving every
    /// resource: see [`ConsentRecord::covers`].
    ///
    /// A `Vec` and not a `Box<[_]>`, unlike everything else here, because this is the one field
    /// that genuinely grows: [`ConsentRecord::extend`] widens it in place as a user approves more,
    /// and a boxed slice would mean reallocating the list on every widening to save 8 bytes on a
    /// record there is one of per (client, user) pair.
    pub resource: Vec<String>,
    /// When this consent was first recorded. Widening does not move it: a user asking "since when
    /// has this application been able to act for me" means the beginning, not the last change.
    pub granted_at: SystemTime,
    /// The authentication the host reported at the most recent approval, if any. See
    /// [`Authentication`], and the module docs on whose job this is.
    pub authentication: Option<Box<Authentication>>,
}

impl ConsentRecord {
    /// Whether this record already covers a request for `scope` and `resource`.
    ///
    /// This is the whole of what "remembered consent" means in this crate, and it ANSWERS a
    /// question rather than making a decision: the `http` feature's
    /// `ServiceBuilder::with_consent_resolver` is where the answer is turned into one. Nothing in
    /// this crate approves an authorization request on the strength of a `true` here.
    ///
    /// Both halves are SUBSET tests against what was approved, never equality and never a widening:
    /// a request for less than was granted is covered, and a request for one token more is not.
    /// Requesting a resource that was never approved is not covered either, because RFC 8707
    /// section 2 makes the resource the audience the token will be good at, so treating "approved
    /// for no particular resource" as "approved for that one" would let a remembered consent grow
    /// an audience the user never saw.
    pub fn covers(&self, scope: &ScopeSet, resource: &[String]) -> bool {
        scope.is_subset(&self.scope) && resource.iter().all(|r| self.resource.contains(r))
    }

    /// Widen this record to also cover `scope` and `resource`.
    ///
    /// Accumulating rather than replacing, because a user who approves `write` today has not
    /// withdrawn the `read` they approved last month, and a record that replaced would re-prompt
    /// for something they can see in their own consent list. Narrowing is not done here at all: the
    /// way to take something back is [`crate::server::AuthorizationServer::withdraw_consent`],
    /// which also revokes what the grant issued, and a silent narrowing that left live tokens
    /// holding the removed scope would be the same lie this module exists to avoid.
    pub fn extend(&mut self, scope: &ScopeSet, resource: &[String]) {
        if !scope.is_subset(&self.scope) {
            let merged = self
                .scope
                .iter()
                .chain(scope.iter())
                .map(|s| s.as_str())
                .collect::<Vec<&str>>();
            // Both sets were parsed by `ScopeSet` already, so the union of their tokens cannot fail
            // to parse. On the impossible error the OLD set stands: failing to widen re-prompts a
            // user, and that is the harmless direction to fail in.
            if let Ok(widened) = ScopeSet::from_tokens(merged) {
                self.scope = widened;
            }
        }
        // CAPPED at [`MAX_CONSENT_RESOURCES`], and this is the one bound in the crate whose cost is
        // DURABLE rather than per request. `self.resource` is the union of every resource ever
        // approved for one (client, subject) pair; it is only ever widened here and pruned nowhere,
        // and `covers` scans it linearly on every authorization request that consults the record.
        // A client that names one fresh resource indicator per authorization request therefore
        // bought a permanently larger record and a permanently slower check, and nothing anywhere
        // said no.
        //
        // The cap refuses to GROW; it never removes. Dropping something already approved would
        // narrow a consent silently while tokens carrying it are still live, which is the same lie
        // this method's docs refuse to tell about narrowing generally.
        //
        // Failing here is the HARMLESS direction, and it is the same direction the scope union
        // above already fails in: a resource that did not fit is not covered, `covers` answers
        // false, and the host re-prompts the user. The dangerous direction would be reporting
        // coverage that was never recorded.
        let room = MAX_CONSENT_RESOURCES.saturating_sub(self.resource.len());
        self.resource.reserve(resource.len().min(room));
        for r in resource {
            if self.resource.len() >= MAX_CONSENT_RESOURCES {
                break;
            }
            if !self.resource.contains(r) {
                self.resource.push(r.clone());
            }
        }
    }
}

/// What the client asked for about the USER's authentication, from an authorization request.
///
/// RFC 9470 section 4 carries exactly two parameters, both defined by OpenID Connect Core section
/// 3.1.2.1, and this crate implements only those two. Reading two of OpenID Connect's parameters
/// does not make this OpenID Connect: there is no `id_token`, no UserInfo endpoint and no claims
/// model here, and ROADMAP.md keeps all three off the list on purpose.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticationRequirement {
    /// Requested authentication context classes, in order of preference, from the space-delimited
    /// `acr_values` parameter. Empty means the client asked for none.
    ///
    /// Satisfied when the host's reported `acr` is ANY of these. OpenID Connect Core section 3.1.2.1
    /// makes `acr_values` a voluntary, ordered preference rather than a demand, so honouring a later
    /// entry is legal; RFC 9470 section 4 is what turns it into a requirement here, because the
    /// whole point of the exchange is that a resource server has already refused the token the
    /// previous `acr` produced.
    pub acr_values: Vec<Box<str>>,
    /// The RFC 9470 section 4 / OpenID Connect Core section 3.1.2.1 `max_age`: how old the user's
    /// authentication may be. `None` means the client did not constrain it.
    ///
    /// `max_age=0` is a real and meaningful value, not an absent one: it means re-authenticate now.
    /// It is kept as `Some(Duration::ZERO)` for that reason, and any elapsed time at all fails it.
    pub max_age: Option<Duration>,
}

impl AuthenticationRequirement {
    /// No requirement at all: what an ordinary authorization request carries.
    pub fn none() -> Self {
        AuthenticationRequirement::default()
    }

    /// Collect the two RFC 9470 section 4 parameters from already-decoded `(name, value)` query
    /// pairs, the same shape [`crate::authorization::AuthorizationRequest::from_pairs`] takes.
    ///
    /// This is a CONVENIENCE over [`AuthenticationRequirement::from_request`], for a host that
    /// holds query pairs and nothing else. It is not what this crate's own endpoints use: they
    /// build the requirement from the RESOLVED request, because for an RFC 9126 pushed request or
    /// an RFC 9101 signed one the query is not where these parameters live, and reading it anyway
    /// both drops the ones that were sent and honours ones that were not.
    ///
    /// A repeated parameter keeps the FIRST occurrence, matching `from_pairs` and for the same
    /// reason: RFC 6749 section 3.1 says a parameter MUST NOT appear more than once, and last-wins
    /// is the smuggling-friendly choice when two intermediaries disagree about which copy counts.
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ErrorResponse>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut acr_values = None;
        let mut max_age = None;
        for (k, v) in pairs {
            match k.as_ref() {
                "acr_values" if acr_values.is_none() => acr_values = Some(v),
                "max_age" if max_age.is_none() => max_age = Some(v),
                _ => {}
            }
        }
        AuthenticationRequirement::from_raw(
            acr_values.as_ref().map(AsRef::as_ref),
            max_age.as_ref().map(AsRef::as_ref),
        )
    }

    /// The requirement an already-resolved authorization request carries.
    ///
    /// THE one source of these two parameters for every path into the authorization endpoint. A
    /// plain RFC 6749 request populated the fields from its query, an RFC 9126 pushed request from
    /// the record it stored at push time, and an RFC 9101 signed request from the claims inside
    /// the signature; each of the three is the only text that path is allowed to trust, and this
    /// reads whichever one it was handed.
    pub fn from_request(
        request: &crate::authorization::AuthorizationRequest<'_>,
    ) -> Result<Self, ErrorResponse> {
        AuthenticationRequirement::from_raw(
            request.acr_values.as_deref(),
            request.max_age.as_deref(),
        )
    }

    /// The parse itself, over the two raw parameter values.
    fn from_raw(acr_values: Option<&str>, max_age: Option<&str>) -> Result<Self, ErrorResponse> {
        let mut out = AuthenticationRequirement::none();
        if let Some(raw) = acr_values {
            // One pass to size the list and one to fill it: `acr_values` is a short
            // space-delimited list, and counting separators is cheaper than the reallocation
            // a growing `Vec` would do on the way to the same answer.
            out.acr_values = Vec::with_capacity(raw.bytes().filter(|b| *b == b' ').count() + 1);
            out.acr_values.extend(
                raw.split(' ')
                    .filter(|s| !s.is_empty())
                    .map(Box::<str>::from),
            );
        }
        if let Some(raw) = max_age {
            // Refused rather than ignored. OpenID Connect Core section 3.1.2.1 makes this
            // the "Maximum Authentication Age... Specified as the number of seconds", so a
            // value that is not that is not a weaker request, it is an unintelligible one,
            // and treating it as absent would answer a step-up challenge with a token that
            // never had the freshness the resource server asked for.
            let secs: u64 = raw.parse().map_err(|_| {
                ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("max_age must be a non-negative number of seconds")
            })?;
            out.max_age = Some(Duration::from_secs(secs));
        }
        Ok(out)
    }

    /// Whether this asks for nothing, in which case no check has to run at all.
    pub fn is_empty(&self) -> bool {
        self.acr_values.is_empty() && self.max_age.is_none()
    }

    /// Hold a host's reported authentication to this requirement.
    ///
    /// The ORDER of the two checks is deliberate: freshness first, then class. A user whose login is
    /// both too old and of the wrong class is told to log in again, which is the action that fixes
    /// either problem, and it avoids telling a client which `acr` a stale session had.
    ///
    /// An absent report fails any non-empty requirement. "The host told us nothing" must never read
    /// as "there is nothing to check": that reading is what makes an unwired host silently satisfy
    /// every step-up challenge it is ever sent.
    pub fn satisfied_by(
        &self,
        authentication: Option<&Authentication>,
        now: SystemTime,
    ) -> Result<(), StepUpFailure> {
        if self.is_empty() {
            return Ok(());
        }
        let authentication = match authentication {
            Some(a) => a,
            None => return Err(StepUpFailure::NotReported),
        };
        if let Some(max_age) = self.max_age {
            // `age` is `None` only for an `auth_time` in the future, which reads as zero elapsed
            // time (see `Authentication::age`) and therefore passes.
            if authentication.age(now).unwrap_or_default() > max_age {
                return Err(StepUpFailure::Stale);
            }
        }
        if !self.acr_values.is_empty() {
            match &authentication.acr {
                Some(acr) => {
                    if !self
                        .acr_values
                        .iter()
                        .any(|want| want.as_ref() == acr.as_ref())
                    {
                        return Err(StepUpFailure::AcrNotMet);
                    }
                }
                // A host that reported no `acr` has not satisfied a request for a specific one.
                // Same rule as the absent report above, one level down.
                None => return Err(StepUpFailure::AcrNotMet),
            }
        }
        Ok(())
    }
}

/// Why a host's reported authentication did not satisfy an [`AuthenticationRequirement`].
///
/// Fieldless on purpose, and not only for the size of it. The `error_description` these produce goes
/// back to the CLIENT through the authorization response redirect (RFC 6749 section 4.1.2.1), and
/// the client is not entitled to learn when the user last logged in or which `acr` they hold; "not
/// fresh enough" is the whole of what it needs in order to decide to ask again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StepUpFailure {
    /// The host reported no authentication at all, and the request asked about one.
    NotReported,
    /// The authentication is older than the request's `max_age`.
    Stale,
    /// The reported `acr` is not one of the requested `acr_values` (or none was reported).
    AcrNotMet,
}

impl StepUpFailure {
    /// The developer-facing description this failure carries onto the wire.
    ///
    /// `&'static str`, so a refusal allocates nothing for it. The authorization endpoint is a path
    /// whose rate an unauthenticated caller sets, and an allocation per refusal there is a cost an
    /// attacker chooses.
    pub fn description(self) -> &'static str {
        match self {
            StepUpFailure::NotReported => "no user authentication was reported for this request",
            StepUpFailure::Stale => "the user authentication is older than the requested max_age",
            StepUpFailure::AcrNotMet => {
                "the user authentication does not satisfy the requested acr_values"
            }
        }
    }

    /// The RFC 9470 section 3 error this failure is reported as.
    ///
    /// `insufficient_user_authentication` is registered by RFC 9470 for the RESOURCE server's
    /// challenge, and section 4 names no code for the authorization server's own refusal. This crate
    /// uses the same one, deliberately, because it is the code the client has just been handed by
    /// the resource server and re-sending it says exactly the true thing: the authentication is
    /// still not sufficient. The alternative, a bare `invalid_request`, tells a client its
    /// parameters were malformed and invites it to retry the identical request.
    pub fn error_response(self) -> ErrorResponse {
        ErrorResponse::new(ErrorCode::InsufficientUserAuthentication)
            .with_description(self.description())
    }
}

impl std::fmt::Display for StepUpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StepUpFailure::NotReported => "no authentication reported",
            StepUpFailure::Stale => "authentication older than max_age",
            StepUpFailure::AcrNotMet => "acr_values not satisfied",
        })
    }
}

/// The other error-shaped types in this crate ([`crate::dpop::DpopFailure`],
/// [`crate::client_assertion::AssertionFailure`], [`crate::mtls::MtlsRegistrationError`]) are all
/// `std::error::Error`, and a host that puts one of them behind `?` or in a `Box<dyn Error>` has to
/// be able to do the same with this one. `Display` above is the whole implementation.
impl std::error::Error for StepUpFailure {}

impl From<StepUpFailure> for ErrorResponse {
    fn from(failure: StepUpFailure) -> ErrorResponse {
        failure.error_response()
    }
}

/// Build the RFC 9470 section 3 `WWW-Authenticate` challenge a RESOURCE SERVER sends when the token
/// it received is valid but the authentication behind it is not enough.
///
/// This crate is an authorization server, not a resource server, so this is a HELPER for the host's
/// own resource servers rather than something this server ever sends: the same posture as
/// [`crate::resource_metadata`], where the type is defined here and publishing it is the resource's
/// job. It is here because the challenge and the authorization request that answers it have to agree
/// on the spelling of two parameters, and one module owning both is how they stay in agreement.
///
/// `scheme` is the RFC 6750 section 3 (or RFC 9449 section 7.1) authentication scheme the resource
/// server challenges with, normally `Bearer` or `DPoP`. Section 3 puts `error`, `error_description`,
/// `acr_values` and `max_age` in the challenge; `acr_values` is omitted when empty rather than sent
/// blank, because an empty list reads as "no class is acceptable".
///
/// The values are emitted inside quoted strings, so a `"` or a `\` in an `acr` value would forge the
/// parameter that follows it. Both are ESCAPED, per the `quoted-string` rule of RFC 9110 section
/// 5.6.4, rather than the value being rejected: this crate does not own the host's `acr` vocabulary
/// and has no business refusing a value it merely has to transmit.
///
/// One allocation: the buffer is sized up front from the parts that go into it.
pub fn step_up_challenge(
    scheme: &str,
    acr_values: &[Box<str>],
    max_age: Option<Duration>,
) -> String {
    use std::fmt::Write as _;

    const ERROR: &str = " error=\"insufficient_user_authentication\"";
    const DESCRIPTION: &str =
        ", error_description=\"the user authentication does not meet the requirements of this \
         resource\"";
    let acr_len: usize = acr_values.iter().map(|a| a.len() + 3).sum();
    let mut out = String::with_capacity(
        scheme.len() + ERROR.len() + DESCRIPTION.len() + acr_len + max_age.map_or(0, |_| 32),
    );
    out.push_str(scheme);
    out.push_str(ERROR);
    out.push_str(DESCRIPTION);
    if !acr_values.is_empty() {
        out.push_str(", acr_values=\"");
        for (i, acr) in acr_values.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            push_quoted(&mut out, acr);
        }
        out.push('"');
    }
    if let Some(max_age) = max_age {
        // Written through the same buffer rather than through an intermediate `to_string`, so the
        // whole challenge is still the one allocation the capacity above sized.
        let _ = write!(out, ", max_age=\"{}\"", max_age.as_secs());
    }
    out
}

/// Append `value`, backslash-escaping the two characters RFC 9110 section 5.6.4 requires escaping
/// inside a `quoted-string`.
fn push_quoted(out: &mut String, value: &str) {
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
}

#[cfg(test)]
#[path = "tests/consent.rs"]
mod tests;
