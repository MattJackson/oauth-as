// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The authorization server itself: configuration, the clock seam, and the grant state machines.
//!
//! Construction is the crate's ONLY allocation entry point (see the crate docs on zero cost until
//! enabled): a host that never constructs [`AuthorizationServer`] pays nothing. There is no
//! background task; every state transition happens inside a host-driven call.

use std::fmt;
use std::time::{Duration, SystemTime};

use crate::authorization::{
    AuthorizationCodeRecord, AuthorizationCodeState, AuthorizationError,
    AuthorizationErrorRedirect, AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod,
    ValidatedAuthorizationRequest,
};
use crate::client::{Client, ClientId};
#[cfg(feature = "client-assertion")]
use crate::client_assertion::{verify_assertion, CLIENT_ASSERTION_TYPE};
use crate::device::{
    normalize_user_code, DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState,
};
#[cfg(feature = "dpop")]
use crate::dpop::verify_proof;
use crate::error::{ErrorCode, ErrorResponse};
use crate::events::{
    Attempt, AttemptOutcome, ClientAuthFailure, Event, EventSink, Hooks, RateLimitDecision,
    RateLimiter,
};
use crate::grant::GrantType;
// The crate's ONE lower-case hex encoder (`client::SecretHash` is the other caller). Aliased to
// the name this module used when it carried its own copy, which is also the name the measurement
// in `crate::hex` is written against.
use crate::hex::encode as hex_encode;
#[cfg(feature = "jwt")]
use crate::jwt::{AccessTokenClaims, AccessTokenFormat, Jwks};
use crate::scope::ScopeSet;
use crate::store::{Storage, StorageError};
use crate::token::{
    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,
    TokenType, TokenTypeHint,
};

/// Seconds since the Unix epoch, for the RFC 7519 `exp` / `iat` style claims RFC 7662 reuses.
/// A pre-epoch instant is not representable in that encoding, so it is reported as absent rather
/// than wrapped into a misleading number.
/// `base + span`, saturating instead of panicking.
///
/// `SystemTime + Duration` PANICS on overflow, and every caller adds a HOST-CONFIGURED `Duration`
/// to `now`. `ServerConfig`'s TTL fields are public and nothing validates them, so a deployment
/// that sets one from a config file holding an out-of-range value would panic on an ordinary
/// request rather than fail at startup. Saturating yields a deadline no clock will reach, which
/// for an expiry means "does not expire by time" — which is what the absurd configuration asked
/// for.
///
/// The ATTACKER-supplied durations in this crate (`dpop`, `client_assertion`) already use
/// `checked_add`, with the reasoning written beside them. This is the host-supplied half of the
/// same rule, and it was missing.
pub(crate) fn saturating_deadline(base: SystemTime, span: std::time::Duration) -> SystemTime {
    if let Some(exact) = base.checked_add(span) {
        return exact;
    }
    // Halve until it fits, accumulating what does: this lands within a second of the platform's
    // ceiling without needing to know what that ceiling is.
    let mut out = base;
    let mut span = span;
    while span > std::time::Duration::from_secs(1) {
        span /= 2;
        if let Some(next) = out.checked_add(span) {
            out = next;
        }
    }
    out
}

pub(crate) fn unix_seconds(t: SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// The time source. Injectable so grant expiry and poll pacing are testable without sleeping;
/// production hosts use [`SystemClock`].
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> SystemTime;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Server configuration. [`ServerConfig::new`] fills RFC-shaped defaults; every field is public so
/// hosts override what they need.
#[derive(Debug, Clone, PartialEq, Eq)]
/// `#[non_exhaustive]`: this struct's field set VARIES WITH CARGO FEATURES, so a host that writes a
/// full struct literal has a build that breaks the day anything in their dependency graph enables a
/// feature they did not ask for. Construct with `new()` and assign the fields you want. This is the
/// one attribute on this type that cannot be added after publication, because by then somebody's
/// struct literal is in production.
#[non_exhaustive]
pub struct ServerConfig {
    /// The issuer identifier (RFC 8414 `issuer`): the canonical `https` URL of this AS.
    ///
    /// RFC 8414 section 2 requires the `https` scheme in production. This crate does NOT enforce
    /// it, because the same code has to be runnable over plain HTTP on loopback for conformance
    /// runs and local development; enforcing transport security is the host's job, and the host
    /// is the only party that knows whether it is behind a TLS terminator.
    pub issuer: String,
    /// Where a user goes to enter a device user code (RFC 8628 `verification_uri`).
    pub verification_uri: String,
    /// RFC 8414 `authorization_endpoint`. `None` derives `{issuer}/authorize`.
    pub authorization_endpoint: Option<String>,
    /// RFC 8414 `token_endpoint`. `None` derives `{issuer}/token`.
    pub token_endpoint: Option<String>,
    /// RFC 8628 `device_authorization_endpoint`. `None` derives `{issuer}/device_authorization`.
    pub device_authorization_endpoint: Option<String>,
    /// RFC 7662 `introspection_endpoint`. `None` derives `{issuer}/introspect`.
    pub introspection_endpoint: Option<String>,
    /// RFC 7009 `revocation_endpoint`. `None` derives `{issuer}/revoke`.
    pub revocation_endpoint: Option<String>,
    /// RFC 8414 `jwks_uri`. `None` (the default) means this server publishes no keys, which is
    /// the truth for opaque access tokens.
    pub jwks_uri: Option<String>,
    /// RFC 7591 dynamic client registration. `None` is the DEFAULT and means registration is OFF:
    /// no `registration_endpoint` is advertised, no route is served, and
    /// [`AuthorizationServer::register_dynamic_client`] answers
    /// [`crate::registration::RegistrationFailure::Disabled`].
    ///
    /// Turning it on is meant to be a sentence somebody wrote and a reviewer can find:
    /// `config.registration = Some(Box::new(RegistrationConfig::new()))`. RFC 7591 section 5 is
    /// why (an open registration endpoint lets anyone mint a client), and enabling it is still not
    /// sufficient: a [`crate::registration::RegistrationPolicy`] must also be installed or every
    /// registration is refused. See the [`crate::registration`] module docs.
    ///
    /// BOXED so that the overwhelmingly common `None` costs one null pointer on every
    /// [`ServerConfig`] rather than the whole struct, and allocates nothing.
    pub registration: Option<Box<crate::registration::RegistrationConfig>>,
    /// RFC 9126 pushed authorization requests. `None` is the DEFAULT and means PAR is OFF: no
    /// `pushed_authorization_request_endpoint` is advertised and
    /// [`AuthorizationServer::pushed_authorization_request`] refuses.
    ///
    /// BOXED for the same reason as [`ServerConfig::registration`]: the overwhelmingly common
    /// `None` costs one null pointer on every [`ServerConfig`] rather than the whole struct, and
    /// allocates nothing.
    #[cfg(feature = "par")]
    pub par: Option<Box<crate::par::ParConfig>>,
    /// RFC 9101 signed request objects. `None` is the DEFAULT and means JAR is OFF: a `request`
    /// parameter is answered with `request_not_supported` rather than parsed.
    #[cfg(feature = "jar")]
    pub jar: Option<Box<crate::par::JarConfig>>,
    /// draft-ietf-oauth-client-id-metadata-document-01 client identifier metadata documents. `None`
    /// is the DEFAULT and means the mechanism is OFF: the RFC 8414 document says
    /// `client_id_metadata_document_supported: false`.
    ///
    /// SETTING IT IS A CLAIM ABOUT THE HOST, not about this crate, and that is why it is a config
    /// field rather than a constant derived from the cargo feature. This crate performs no fetch
    /// (see [`crate::cimd`]), so compiling the feature in proves only that the VALIDATOR is
    /// available; whether this deployment actually dereferences a client identifier URL is
    /// something only the host knows. Deriving the advertised member from the feature would
    /// publish a capability the build might always refuse, which is a defect shape this crate has
    /// already shipped twice.
    ///
    /// BOXED for the same reason as [`ServerConfig::registration`].
    #[cfg(feature = "cimd")]
    pub cimd: Option<Box<crate::cimd::CimdPolicy>>,
    /// RFC 8414 `scopes_supported`. `None` omits the member rather than claiming an empty
    /// catalogue.
    pub scopes_supported: Option<Vec<String>>,
    /// The RFC 8707 resource indicators this server is WILLING to issue tokens for.
    ///
    /// `None` (the default) means no restriction, which is the pre-existing behaviour and is why
    /// it is the default: turning refusal on by default would break every deployment already
    /// using resource indicators. It is also why `None` is a real risk rather than a
    /// neutral one, and the risk is worth stating here rather than in a changelog.
    ///
    /// `Option<Box<[Box<str>]>>` rather than `Vec<String>` so a host that never sets it pays ONE
    /// pointer on every `ServerConfig`, not a 24 byte vector header. The list is written once at
    /// construction and only ever iterated.
    ///
    /// RFC 8707 section 2 requires `invalid_target` when the server "is unwilling or unable to
    /// issue an access token" for a requested resource. With this empty, the server has no notion
    /// of unwilling: any syntactically valid absolute URI is accepted. Under the `jwt` feature the
    /// requested resource then REPLACES the configured audience in the RFC 9068 `aud` claim, so
    /// any client can obtain a token this server signed, carrying another resource server's
    /// identifier in `aud`. That server verifies the signature against our JWKS, sees its own
    /// identifier, and authorises.
    ///
    /// A deployment serving more than one resource server should set this.
    pub allowed_resources: Option<Box<[Box<str>]>>,
    /// Which registered clients are RESOURCE SERVERS, and which RFC 8707 resource identifiers each
    /// one answers for. This is what opens the channel RFC 7662 section 1 describes, in which the
    /// specification "allows authorized protected resources to query the authorization server";
    /// empty (the default) means this server introspects for
    /// the token's own client and nobody else, which is what it did through 0.9.1.
    ///
    /// A resource server is NOT a new kind of principal. It registers as an ordinary confidential
    /// [`crate::Client`] and authenticates to the introspection endpoint with whatever this build
    /// accepts from any client -- `client_secret_basic`, `client_secret_post`, RFC 7523
    /// `private_key_jwt` or `client_secret_jwt`, RFC 8705 mutual TLS -- through the same
    /// `authenticate_client` every other endpoint uses. Section 2.1 requires the endpoint be
    /// protected; reusing the client credential machinery is how it is protected, and inventing a
    /// second credential type would have meant a second thing to get constant-time comparison,
    /// rotation and revocation right on.
    ///
    /// What this adds on top of authentication is AUTHORIZATION, and that is the part that is not
    /// optional. Authenticating as a resource server must not mean reading every token in the
    /// store: an introspection endpoint that answers any authenticated resource server about any
    /// token is a token-scanning oracle, which is section 4's warning with a credential stapled to
    /// it. So a resource server is answered about a token ONLY when the token's own
    /// [`crate::IssuedToken::resource`] set names one of the identifiers registered here.
    ///
    /// AN EMPTY `resource` ON THE TOKEN NAMES NOBODY, AND IS REFUSED TO EVERY RESOURCE SERVER.
    /// That is the same fail-open reading [`crate::jwt::Audience::names_a_resource_server`] exists
    /// to refuse, arriving through the other door: a grant that requested no resource indicator is
    /// restricted to nothing in particular, and reading "restricted to nothing in particular" as
    /// "so anyone may ask about it" would hand every resource server in the deployment every token
    /// that did not happen to use RFC 8707. The token's own client can still introspect it, which
    /// is the pre-0.9.2 behaviour and is unchanged.
    ///
    /// # WHAT THIS COSTS YOUR RATE LIMITER, and what to set
    ///
    /// SETTING THIS CHANGES THE TRAFFIC SHAPE AT THE CLIENT-AUTHENTICATION BUDGET, and it is the
    /// one consequence of registering a resource server that is not visible from anything else on
    /// this page. An introspection is a client authentication like any other -- that is the whole
    /// point of the paragraph above -- so it is charged
    /// [`crate::rate_limit::ATTEMPT_COST`] against
    /// [`crate::events::Attempt::ClientAuthentication`] keyed on the RESOURCE SERVER's
    /// `client_id`. Through 0.9.1 that budget only ever carried a client asking about tokens it
    /// had itself been issued, so its volume tracked issuance. A resource server introspects ONCE
    /// PER CALL AT THE PROTECTED RESOURCE, at a rate set by that API's own clients.
    ///
    /// [`crate::rate_limit::DEFAULT_CLIENT_AUTHENTICATION_CAPACITY`] is 6000 a minute, which is
    /// 100 a second, and it was derived from a client's token traffic. Left alone it becomes the
    /// protected resource's request ceiling, per node.
    ///
    /// AND IT DOES NOT READ AS A THROTTLE WHEN IT BITES. RFC 7662 introspection over the ceiling
    /// is refused with a bare `invalid_client`, the same answer a wrong secret gets, because a
    /// distinct code would tell an attacker they had found a live client id. A resource server
    /// that fails closed then refuses EVERY request it is handling, and its operator is looking at
    /// what appears to be a credential problem. The [`crate::events::EventSink`] channel is where
    /// the two are distinguishable:
    /// [`crate::events::Event::ClientAuthenticationFailed`] carries
    /// [`crate::events::ClientAuthFailure::RateLimited`] for a throttle and
    /// [`crate::events::ClientAuthFailure::SecretMismatch`] for a credential that did not verify.
    /// A deployment that registers resource servers should install one.
    ///
    /// So, two things:
    ///
    /// - Size the budget for the API, not for a client:
    ///   [`crate::rate_limit::RateLimitConfig::with_client_authentication_capacity_for`] raises
    ///   ONE registration and leaves every other `client_id` where it was. Raising
    ///   `client_authentication_capacity` globally would also raise how many wrong secrets every
    ///   other registration admits per window, each of which can cost the host an argon2id.
    /// - CACHE THE INTROSPECTION RESPONSE at the resource server, which RFC 7662 section 4
    ///   recommends and which is the only measure that changes the traffic shape rather than the
    ///   ceiling. It costs a bounded delay before a revocation is observed.
    ///
    /// A host that implements [`crate::events::RateLimiter`] itself makes the same decision in its
    /// own terms; there is no introspection-specific [`crate::events::Attempt`] variant to key on,
    /// deliberately, and the module docs on [`crate::rate_limit`] say why.
    ///
    /// `Option<Box<[_]>>` rather than `Vec<_>` for the reason [`ServerConfig::allowed_resources`]
    /// gives next door and with the same measurement behind it: the list is written once at
    /// construction and only ever iterated, so the growable shape buys nothing, and a boxed slice
    /// is 16 bytes against a vector header's 24 on every `ServerConfig` in every deployment.
    /// MEASURED: `ServerConfig` 464 before this field, 488 as a `Vec`, 480 as this.
    pub resource_servers: Option<Box<[ResourceServerRegistration]>>,
    /// RFC 8414 `service_documentation`.
    pub service_documentation: Option<String>,
    /// RFC 9396 section 10 `authorization_details_types_supported`: the authorization
    /// details types this deployment actually implements.
    ///
    /// `None` is the DEFAULT and means NO type is supported, so every `authorization_details`
    /// request is refused with `invalid_authorization_details`. That is not conservatism for
    /// its own sake, it is section 5: "The AS MUST refuse to process any unknown
    /// authorization details type", and a server that has been told nothing about a type
    /// cannot be said to know it. Compiling the `rar` feature in is therefore not the same
    /// as turning it on; a host turns it on by naming its types here.
    #[cfg(feature = "rar")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// RFC 9728 section 4 `protected_resources`: the resource identifiers of the protected
    /// resources this AS issues tokens for. `None` (the default) omits the member; see
    /// [`crate::metadata::AuthorizationServerMetadata::protected_resources`], and note that
    /// this is the AS half only. The DOCUMENT each of those resources publishes is
    /// [`crate::resource_metadata::ProtectedResourceMetadata`], and publishing it is the
    /// resource's own job, not this server's.
    #[cfg(feature = "resource-metadata")]
    pub protected_resources: Option<Vec<String>>,
    /// What the client receives as its `access_token`. Defaults to [`AccessTokenFormat::Opaque`],
    /// which is the behaviour of this crate without the `jwt` feature; setting
    /// [`AccessTokenFormat::Jwt`] makes the wire token an RFC 9068 `at+jwt` while the AS-side
    /// record is still persisted, so introspection and revocation are unchanged.
    #[cfg(feature = "jwt")]
    pub access_token_format: AccessTokenFormat,
    /// Authorization code lifetime. RFC 6749 section 4.1.2 recommends a maximum of 10 minutes;
    /// the default is 60 seconds, which is ample for a redirect round trip.
    pub authorization_code_ttl: Duration,
    /// Whether device authorization responses include `verification_uri_complete`
    /// (`{verification_uri}?user_code={code}`). `false` by default.
    ///
    /// RFC 8628 section 5.4 (Remote Phishing) is why this is a decision and not a convenience
    /// setting. The attack is that an attacker starts a device grant for their OWN client and mails
    /// the victim the link ("click here to finish setting up your TV"); the victim, already signed
    /// in, lands on a page that needs one click, and the attacker collects the tokens. Section 5.4
    /// names TYPING THE CODE as the friction that makes this hard, and this member is precisely the
    /// removal of that friction: the code arrives pre-filled from a URL the user did not compose.
    ///
    /// OFF by default as of 0.9.1, having been on. Section 3.3.1 makes the member OPTIONAL, so
    /// omitting it is conformant and costs a deployment only the QR-code convenience, while
    /// including it by default made every host that never read this paragraph pay for a capability
    /// it did not ask for. That is the same posture the rest of this config takes:
    /// [`ServerConfig::registration`] and the PAR and JAR blocks are all off until a host says
    /// otherwise. A host that turns this ON should pair it with a verification page that names the
    /// client and the scope and requires an affirmative action, which is what section 3.3 asks for
    /// and what the `http` feature's page does.
    pub include_verification_uri_complete: bool,
    /// Device code and user code lifetime. Default 600 seconds.
    pub device_code_ttl: Duration,
    /// Initial minimum poll spacing (RFC 8628 `interval`). Default 5 seconds.
    pub poll_interval: Duration,
    /// How much a `slow_down` raises the required spacing. RFC 8628 section 3.5 mandates the
    /// client add 5 seconds, which is the default.
    pub slow_down_increment: Duration,
    /// Access token lifetime. Default 3600 seconds.
    pub access_token_ttl: Duration,
    /// Whether user-approved grants also issue a refresh token. Default true.
    pub issue_refresh_tokens: bool,
    /// RFC 8693: whether a SENDER-CONSTRAINED subject token may be exchanged.
    ///
    /// `false` by default, which means the exchange is REFUSED with `invalid_request` when the
    /// subject token carries an RFC 9449 DPoP or RFC 8705 mutual-TLS binding. See the "A
    /// SENDER-CONSTRAINED subject token is REFUSED" section of the [`crate::token_exchange`] module
    /// docs for the full argument; the short form is that the token this server would hand back
    /// belongs to the EXCHANGING client, which does not hold the original client's key, so it can
    /// only be a plain bearer token. Anyone able to authenticate as any client registered for this
    /// grant could then post a stolen bound token and receive a spendable one, and the property the
    /// deployment turned DPoP on to buy would be gone.
    ///
    /// # What turning it on gives up
    ///
    /// Exactly that property, and it is worth being blunt about it: with `true`, a sender-
    /// constrained token becomes exchangeable for an UNBOUND bearer token, so a leaked bound token
    /// is once again worth something to whoever finds it, via one request to this endpoint. The
    /// binding is not propagated (a `cnf` naming a key the new holder cannot prove would be a
    /// broken grant dressed as a secure one), it is DROPPED, and nothing downstream is told.
    ///
    /// It exists because 0.9.0 and earlier did exactly this silently, so a deployment that has
    /// already built on the downgrade needs a way to keep running while it migrates. It is not a
    /// tuning knob: a host that sets it has decided that its delegation topology is trusted enough
    /// to hold the binding for it, and that decision belongs in a sentence somebody wrote and a
    /// reviewer can find.
    pub allow_sender_constrained_exchange: bool,
    /// Allow an RFC 8693 exchange of a subject token that carries RFC 9396 `authorization_details`,
    /// propagating those details onto a token issued to a DIFFERENT client. `false` by default, and
    /// the default is the safe one.
    ///
    /// # Why this is off
    ///
    /// The exchange applies TWO ceilings to scope: the subject token's granted scope (RFC 6749
    /// section 6 narrowing) and then the exchanging client's own
    /// [`crate::client::Client::allowed_scopes`], because the issued token belongs to a different
    /// principal. It applied NONE to `authorization_details`, which are strictly more specific:
    /// RFC 9396 exists precisely because a scope token cannot say "transfer 50 euros to IBAN X".
    ///
    /// So the weaker rule was applied to the more dangerous grant. A downstream service registered
    /// for `read`, which receives a payments client's token because forwarding the caller's token
    /// is exactly what this grant is for, could exchange it asking for `read`, pass both scope
    /// ceilings, and walk away with a token issued to ITSELF carrying the full payment
    /// authorization, signed into the RFC 9068 claim, visible over RFC 7662 introspection, and with
    /// a fresh lifetime that outlives the token it came from.
    ///
    /// # Why an opt-in rather than a per-client ceiling
    ///
    /// The correct ceiling is a per-client registration of the detail types a client may hold, the
    /// analogue of `allowed_scopes`. [`crate::client::Client`] has no such field, and adding one is
    /// a breaking change to a type hosts construct. Until it exists there is nothing to narrow
    /// against, so the honest choice is to refuse and let a host that has reasoned about its own
    /// delegation topology say so. Setting this to `true` accepts that any client permitted this
    /// grant may inherit any detail any subject token carries.
    pub allow_authorization_details_exchange: bool,
    /// Absolute refresh chain lifetime. Rotation preserves the chain's original expiry rather than
    /// sliding it, so this is a ceiling on the whole chain and not on one token.
    ///
    /// `None` (the default) means NO TIME EXPIRY AT ALL: a refresh chain established once lives
    /// until something revokes it. `None` is the default because it is the pre-existing behaviour
    /// and turning expiry on by default would sign every deployment's users out on an interval
    /// nobody chose, so, exactly as with [`ServerConfig::allowed_resources`], `None` is a real risk
    /// rather than a neutral one and the risk belongs here rather than in a changelog.
    ///
    /// What it costs: a refresh token exfiltrated once is a credential for the user's account
    /// FOREVER, and rotation does not fix that. RFC 9700 section 4.14.2 reuse detection catches the
    /// thief only if the legitimate client comes back and presents the token the thief already
    /// spent; a thief who steals a chain the user has abandoned, or who simply rotates it faster
    /// than the real client does, is never detected by anything and holds access indefinitely.
    /// Setting this bounds that to a window, and OAuth 2.1 draft section 6.1 asks for either a
    /// finite lifetime or rotation on the same grounds.
    ///
    /// A deployment whose users are humans, and whose refresh tokens sit on devices those humans
    /// lose, should set this.
    pub refresh_token_ttl: Option<Duration>,
    /// How long a ROTATED (spent) refresh token is retained purely so that its reuse can be
    /// detected, when its chain has no absolute expiry of its own. Default 30 days.
    ///
    /// Reuse detection (OAuth 2.1 draft section 6.1, RFC 9700 section 4.14.2) only works while the
    /// superseded token is still recognisable, so this is the window in which a stolen-and-rotated
    /// token still triggers revocation of its family. Past it the record is sweepable and a
    /// presentation reads as an unknown token. When the chain HAS an absolute expiry, that expiry
    /// is used instead: there is nothing left to protect once the chain itself is dead.
    pub refresh_reuse_window: Duration,
    /// RFC 9449: whether EVERY token request must carry a DPoP proof.
    ///
    /// `false` by default, which means "DPoP is available, and a client that wants a
    /// sender-constrained token asks for one by presenting a proof". `true` is the FAPI 2.0
    /// posture: it refuses every token request without a proof, which is a breaking change for
    /// every existing client of the deployment and therefore a sentence somebody has to write on
    /// purpose rather than a default anybody inherits.
    #[cfg(feature = "dpop")]
    pub require_dpop: bool,
    /// User code length in symbols, excluding the display hyphen. Default
    /// [`MIN_USER_CODE_LENGTH`] (about 34 bits over the 20-symbol alphabet, the RFC 8628 section
    /// 6.1 example shape).
    ///
    /// Values below [`MIN_USER_CODE_LENGTH`] are CLAMPED UP at generation, not honoured. This is
    /// not tuning: 4 symbols is about 160,000 possibilities, which is seconds of guessing against
    /// an endpoint this library cannot rate limit, and 0 produces an empty code that every grant
    /// collides on. Clamping rather than rejecting keeps a misconfiguration from becoming a
    /// runtime failure at the one moment a user is standing in front of a device.
    pub user_code_length: usize,
}

/// The floor [`ServerConfig::user_code_length`] is clamped up to: the RFC 8628 section 6.1 example
/// shape, about 34 bits over the 20-symbol alphabet.
///
/// Section 6.1 is explicit that this entropy is adequate only IN COMBINATION WITH rate limiting of
/// user-code entry. This library performs none and cannot: it never sees a request, only the host
/// does. See [`AuthorizationServer::approve_device`].
pub const MIN_USER_CODE_LENGTH: usize = 8;

/// The largest number of RFC 8707 `resource` indicators one request may carry.
///
/// # Why there is a cap at all
///
/// Section 2 makes `resource` a REPEATABLE parameter, and it is accepted at the authorization
/// endpoint, which takes no client credential: an unauthenticated caller chooses `n`. Validation is
/// O(n) per element against [`ServerConfig::allowed_resources`] plus an O(n) dedup scan, so the
/// cost is quadratic in a number the caller picks, and it is paid before anything has authenticated
/// anybody. This is the same argument, and the same remedy, as
/// [`crate::rar::MAX_AUTHORIZATION_DETAILS_ELEMENTS`]: the other repeatable array a request can
/// carry. Leaving one capped and the other not was the defect.
///
/// # Why 16
///
/// It is the number of DISTINCT resource servers one access token may be good at. RFC 8707's own
/// security considerations push the other way, toward narrow audiences, and a deployment that
/// genuinely needs one token accepted at more than sixteen separate resource servers has an
/// audience so wide that the indicator has stopped restricting anything. Sixteen is also what
/// RFC 9396 already allows for `authorization_details`, so the two arrays a request can repeat are
/// bounded alike and a reader does not have to hold two numbers.
///
/// # Why the scan stayed linear
///
/// At sixteen, a `HashSet<String>` is slower, not faster: it pays a SipHash of the whole string per
/// lookup against at most sixteen comparisons that mostly fail on the length. The defect was never
/// the scan, it was that nothing bounded `n`. A cap is the entire fix.
///
/// # It refuses, it does not truncate
///
/// Silently dropping the indicators past the cap would issue a token whose audience is not the one
/// the client asked for, with nothing told to anybody: the exact failure `crate::rar` refuses for
/// unknown members. `invalid_target` (section 2) is the honest answer.
pub const MAX_RESOURCE_INDICATORS: usize = 16;

/// Which of RFC 7662's two legitimate callers an introspection request is being answered as.
///
/// Not public: it is the shape of one decision inside
/// [`AuthorizationServer::introspection_response_with_credential`], and a host that could name it
/// would be able to depend on a split that exists to serve the response document rather than to
/// describe the deployment.
enum IntrospectionView {
    /// The client the token was issued to. Sees the whole record, including every resource
    /// identifier the grant was restricted to.
    OwningClient,
    /// A registered resource server, carrying the identifiers of ITS OWN that this token names.
    /// Never empty: an empty intersection is not a resource-server view, it is `active: false`.
    ResourceServer(Vec<String>),
}

/// The RFC 9396 details a RESOURCE SERVER may be told about, given the identifiers `mine` it is
/// registered for and answers for.
///
/// Section 9.2: the details are "filtered and extended for the RS making the introspection
/// request". This is the filtering half; this crate does no extending, because an extension would
/// be an assertion about an API vocabulary it does not know (see [`crate::rar`] on `other`).
///
/// The rule, and why each arm is the safe one:
///
/// - an element with NO `locations` is KEPT. Section 2.2 makes the member optional, so its absence
///   says nothing about where the element belongs; dropping it would withhold a detail the resource
///   owner did approve from the only party in a position to enforce it, which is a fail-open move
///   dressed as a privacy one.
/// - an element whose `locations` names one of `mine` is kept, with its `locations` REDUCED to the
///   intersection. Keeping the element whole would let a detail addressed to two resource servers
///   hand each of them the other's URI, which is the disclosure this function exists to stop
///   arriving one level down.
/// - anything else is DROPPED: its `locations` names other services only, and a resource server
///   that is not named in an element has no business acting on it or knowing it exists.
///
/// The reduction cannot produce an element with an EMPTY `locations`, because an empty intersection
/// is the dropped arm. That matters beyond tidiness: empty is how this crate spells "the member was
/// absent", so an element narrowed to nothing would read on the wire as one that was never located
/// at all -- a widening performed by a filter.
///
/// Filtering everything away yields an EMPTY set, and
/// [`crate::token::IntrospectionResponse::authorization_details`] omits the member rather than
/// serializing `[]`, so the resource server sees exactly what it sees for a grant that carried no
/// details at all. That is the "not granted" / "not for you" indistinguishability at its widest,
/// and it is the intended shape: see this method's caller for why that direction is the harmless
/// one.
#[cfg(feature = "rar")]
fn details_for_resource_server(
    details: &crate::rar::AuthorizationDetails,
    mine: &[String],
) -> crate::rar::AuthorizationDetails {
    crate::rar::AuthorizationDetails::from_elements(
        details
            .iter()
            .filter_map(|detail| {
                if detail.locations.is_empty() {
                    return Some(detail.clone());
                }
                let locations: Vec<Box<str>> = detail
                    .locations
                    .iter()
                    .filter(|at| mine.iter().any(|id| id.as_str() == &***at))
                    .cloned()
                    .collect();
                (!locations.is_empty()).then(|| crate::rar::AuthorizationDetail {
                    locations: locations.into_boxed_slice(),
                    ..detail.clone()
                })
            })
            .collect(),
    )
}

/// One resource server, as [`ServerConfig::resource_servers`] declares it: the registered client
/// identity it authenticates as, and the RFC 8707 resource identifiers it is the protected
/// resource FOR.
///
/// The two halves answer two different questions and neither substitutes for the other.
/// `client_id` answers "who is calling", and it is checked by the ordinary client authentication
/// every endpoint uses, so a resource server needs a real credential and gets constant-time
/// verification, rotation and revocation for free. `resources` answers "what may it ask about",
/// and it is checked against the token's own [`crate::IssuedToken::resource`] set, so a resource
/// server is told about tokens addressed to it and is told `{"active": false}` about every other
/// token in the store.
///
/// Registering the same `client_id` twice is not an error and not special: the identifier sets are
/// considered in order and a match in any of them is a match. It is simply a longer way of writing
/// one entry with both lists concatenated.
#[derive(Debug, Clone, PartialEq, Eq)]
/// `#[non_exhaustive]`: this is a DEPLOYMENT POLICY object for a channel that will grow. A per-RS
/// claim filter, a per-RS introspection policy and a `token_endpoint_auth_method` constraint are
/// all plausible next fields, and each one would be a major-version event if a host could write a
/// struct literal here. Its sibling [`crate::cimd::CimdPolicy`] is sealed for the same reason and
/// states it plainly: "A host writes a full struct literal today and has a build that breaks on a
/// patch release; `new()` plus assignment does not. The attribute cannot be added after
/// publication, because by then the literal is in somebody's production tree."
///
/// It is sealed HERE rather than later because 0.9.2 is the release that introduces it. The
/// `tests/host_api_shape.rs` gate does not catch this one and is not wrong to miss it -- that scan
/// flags types whose field set VARIES WITH A CARGO FEATURE, and this one's does not. The rule the
/// crate actually follows is broader than the gate that enforces part of it.
#[non_exhaustive]
pub struct ResourceServerRegistration {
    /// The registered client this resource server authenticates as. It must be a CONFIDENTIAL
    /// client: introspection refuses public clients (see
    /// [`AuthorizationServer::introspection_response_with_credential`]), and naming a public client
    /// here therefore registers a resource server that can never successfully call.
    pub client_id: ClientId,
    /// The RFC 8707 resource identifiers this server is the protected resource for. An entry with
    /// an EMPTY list can never match any token, because matching requires naming an identifier the
    /// token carries; it registers a resource server with no authority rather than one with
    /// universal authority, which is the fail-closed direction.
    pub resources: Vec<String>,
}

impl ResourceServerRegistration {
    /// Declare `client_id` to be the resource server for `resources`.
    pub fn new(
        client_id: ClientId,
        resources: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            client_id,
            resources: resources.into_iter().map(Into::into).collect(),
        }
    }
}

/// The RFC 8693 section 4.1 actor an issuance carries, in a wrapper that is ZERO SIZED without the
/// `token-exchange` feature.
///
/// Exactly the same device as [`GrantedAuthentication`] below and for exactly the same reason: one
/// `issue` signature in every feature configuration, because a `cfg` on an argument cannot be
/// matched by a `cfg` at the call site. Only the delegation branch of a token exchange ever fills
/// it; every other grant passes the default, which is what `None` on the record means.
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct GrantedActor {
    #[cfg(feature = "token-exchange")]
    pub(crate) act: Option<Box<crate::token_exchange::ActClaim>>,
}

/// The host-reported authentication an issuance carries, in a wrapper that is ZERO SIZED without
/// the `consent` feature.
///
/// It exists so [`AuthorizationServer::issue`] and its five call sites have ONE signature in every
/// feature configuration. The alternative, a `cfg` on the argument, cannot be matched by a `cfg` at
/// the call site, and duplicating five call sites under a `cfg` is five places to get it wrong in
/// the configuration nobody builds locally. Same reason `Bound` exists for the RFC 9449 binding.
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct GrantedAuthentication {
    #[cfg(feature = "consent")]
    pub(crate) authentication: Option<Box<crate::consent::Authentication>>,
}

impl GrantedAuthentication {
    /// What an authorization code carries into the token it mints.
    #[cfg(feature = "consent")]
    pub(crate) fn from_code(record: &AuthorizationCodeRecord) -> Self {
        GrantedAuthentication {
            authentication: record.authentication.clone(),
        }
    }

    /// Without the feature there is no field to fill, and no field on the record to fill it from.
    #[cfg(not(feature = "consent"))]
    pub(crate) fn from_code(_record: &AuthorizationCodeRecord) -> Self {
        GrantedAuthentication {}
    }

    /// What a refresh chain carries across a rotation: the ORIGINAL authentication, unchanged. See
    /// [`crate::token::RefreshTokenRecord::authentication`] on why a rotation is not a new one.
    #[cfg(feature = "consent")]
    pub(crate) fn from_refresh(record: &RefreshTokenRecord) -> Self {
        GrantedAuthentication {
            authentication: record.authentication.clone(),
        }
    }

    /// Without the feature, as above.
    #[cfg(not(feature = "consent"))]
    pub(crate) fn from_refresh(_record: &RefreshTokenRecord) -> Self {
        GrantedAuthentication {}
    }
}

/// A statement, by the HOST, that a resource owner saw one validated authorization request and
/// agreed to it. The only thing [`AuthorizationServer::issue_authorization_code`] will mint from.
///
/// # Why this type exists
///
/// The `http` feature's `ServiceBuilder` REFUSES TO BUILD without a consent resolver, so a host on
/// that path cannot reach code issuance without having written the word "approve". The direct API
/// had no such step, and the direct API is the path this crate's DEFAULT BUILD invites: no HTTP
/// surface, no listener, the host owning its own routes. `issue_authorization_code(&validated,
/// "alice")` read like a lookup, compiled, passed the host's own tests, and shipped an
/// authorization server that approved everything. The refusal existed on one of two supported
/// adoption paths, which is the same as not existing.
///
/// # What it is, and what it is not
///
/// It is NOT a proof, and no type this crate could define would be one: this library has no user,
/// no session and no screen, so "the user agreed" is a fact only the host holds. Nor is it weaker
/// than the seam it mirrors. A host can wire `|_| ApprovalDecision::Approve` into the `http` path
/// just as it can call [`UserApproval::granted`] here, so what BOTH seams buy is the same and is
/// the whole of what a library at this boundary can buy: the approval becomes a sentence the host
/// WROTE rather than a default it inherited, and the host that never considered RFC 6749 section
/// 10.12 gets a compile error naming it instead of a working forgery endpoint.
///
/// It also closes a bug class the two-argument form left open. The approval BORROWS the request it
/// approves, so there is no second request parameter left to disagree with it: a host cannot prompt
/// for one request and issue for another, approving a `read` and minting a `read write`.
///
/// # Allocation
///
/// A borrow plus the `subject` String, which is the same one allocation the old
/// `subject: impl Into<String>` argument made on its way into the record. Nothing on the token path
/// changes, and nothing here is on it.
pub struct UserApproval<'a> {
    request: &'a ValidatedAuthorizationRequest,
    subject: String,
    /// When the decision this approval reports was MADE, if the host knows.
    ///
    /// `None` means "now", which is right for a host that prompted the user during this request
    /// and wrong for one that is acting on a standing approval it read a moment ago. See
    /// [`UserApproval::decided_at`] for why the difference is load bearing.
    decided_at: Option<std::time::SystemTime>,
}

impl<'a> UserApproval<'a> {
    /// The resource owner named by `subject` approved `request`.
    ///
    /// CALLING THIS IS AN ASSERTION. It says a real user was really asked about really this
    /// request, in whatever the deployment's consent step is, and said yes. This crate cannot check
    /// that and will not try; what it can do is refuse to mint anything until someone writes it.
    ///
    /// `subject` is the authenticated resource owner, in the host's own vocabulary for users, and
    /// is what the issued code and every token it mints will carry.
    pub fn granted(request: &'a ValidatedAuthorizationRequest, subject: impl Into<String>) -> Self {
        UserApproval {
            request,
            subject: subject.into(),
            decided_at: None,
        }
    }

    /// The same approval, dated.
    ///
    /// WHAT THIS IS FOR, and it is not bookkeeping. A revocation barrier refuses a write whose
    /// GRANT predates the revocation, and the grant instant a code carries is the instant of the
    /// decision it rests on. For a host that prompted the user during this request those are the
    /// same moment and [`UserApproval::granted`] is right. For a host acting on a STANDING
    /// approval — a remembered consent it read at the top of the request — they are not, and
    /// dating a months-old approval at this instant makes it outrank a withdrawal recorded in
    /// between.
    ///
    /// The failure that costs is precise. The user opens the authorization page; the host reads
    /// their standing consent; the user, elsewhere, clicks "remove this application", and the
    /// withdrawal cascades away every token and records its barrier; the first request then
    /// resumes and mints a code on the strength of the pre-withdrawal snapshot. Nothing refuses
    /// the code — `put_authorization_code` is deliberately barrier-exempt — and at redemption a
    /// code dated NOW postdates the barrier, so the token is issued and its refresh chain
    /// inherits the same instant, rotating happily long after the barrier is swept.
    ///
    /// Pass the instant the decision was made: the standing record's own `granted_at`, or the
    /// instant the request was received, whichever the host can honestly claim. Both are earlier
    /// than any withdrawal that has not yet been read, which is the whole of what is needed.
    pub fn granted_at(
        request: &'a ValidatedAuthorizationRequest,
        subject: impl Into<String>,
        decided_at: std::time::SystemTime,
    ) -> Self {
        UserApproval {
            request,
            subject: subject.into(),
            decided_at: Some(decided_at),
        }
    }

    /// When the decision was made, if the host said. See [`UserApproval::granted_at`].
    pub fn decided_at(&self) -> Option<std::time::SystemTime> {
        self.decided_at
    }

    /// The request this approves.
    pub fn request(&self) -> &'a ValidatedAuthorizationRequest {
        self.request
    }

    /// The resource owner who approved it.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// Hand-written: `subject` is a user identifier, and this crate does not print those into whatever
/// caught a `{:?}`. Which REQUEST is being approved stays visible, because that is the whole of
/// what anybody debugging an issuance needs.
impl fmt::Debug for UserApproval<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserApproval")
            .field("client_id", &self.request.client_id)
            .field("scope", &self.request.scope)
            .field("subject", &"[redacted]")
            .finish()
    }
}

/// How many times user-code generation may redraw on a collision before giving up.
///
/// A collision at the floor length is a roughly one-in-a-hundred-billion event per live grant, so
/// a run of this many is not chance: it is a store that is full, broken, or under an allocation
/// flood. Bounded rather than unbounded because an endpoint that spins forever under load is a
/// worse failure than one that answers `server_error`.
const USER_CODE_GENERATION_ATTEMPTS: usize = 8;

impl ServerConfig {
    /// A config with RFC-shaped defaults; `issuer` and `verification_uri` have no sane default and
    /// are required.
    pub fn new(issuer: impl Into<String>, verification_uri: impl Into<String>) -> Self {
        ServerConfig {
            issuer: issuer.into(),
            verification_uri: verification_uri.into(),
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
            jwks_uri: None,
            // OFF. See the field's own docs, and RFC 7591 section 5.
            registration: None,
            // OFF. PAR is a capability a host opts into, not a default: see the field's docs.
            #[cfg(feature = "par")]
            par: None,
            #[cfg(feature = "jar")]
            jar: None,
            // OFF, and off means the RFC 8414 document says so: a host that has not wired the
            // fetch must not advertise that it did. See the field's own docs.
            #[cfg(feature = "cimd")]
            cimd: None,
            scopes_supported: None,
            allowed_resources: None,
            resource_servers: None,
            service_documentation: None,
            // OFF. An undeclared catalogue supports no types: see the field's own docs and
            // RFC 9396 section 5.
            #[cfg(feature = "rar")]
            authorization_details_types_supported: None,
            #[cfg(feature = "resource-metadata")]
            protected_resources: None,
            #[cfg(feature = "jwt")]
            access_token_format: AccessTokenFormat::Opaque,
            authorization_code_ttl: Duration::from_secs(60),
            // OFF. RFC 8628 s5.4 remote phishing: see the field's own docs.
            include_verification_uri_complete: false,
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(5),
            slow_down_increment: Duration::from_secs(5),
            access_token_ttl: Duration::from_secs(3600),
            issue_refresh_tokens: true,
            // OFF: an exchange that drops a sender constraint is a decision, not a default. See the
            // field's own docs for what turning it on gives up.
            allow_sender_constrained_exchange: false,
            allow_authorization_details_exchange: false,
            refresh_token_ttl: None,
            // 30 days: long enough that a chain abandoned by a client that later comes back with
            // a stale token is still recognised as reuse rather than as noise.
            refresh_reuse_window: Duration::from_secs(30 * 24 * 60 * 60),
            #[cfg(feature = "dpop")]
            require_dpop: false,
            user_code_length: MIN_USER_CODE_LENGTH,
        }
    }
}

/// A parsed token-endpoint request (RFC 6749 section 3.2). The host parses the form body and the
/// `Authorization` header into this; `client_secret` is `None` for public clients.
///
/// `Debug` is hand-written (see below) rather than derived. Every variant of this type is built
/// directly out of an inbound request and every variant carries at least one credential: RFC 6749
/// section 2.3.1 makes `client_secret` a password, and section 4.1.2, section 6 and RFC 8628
/// section 3.4 each make the grant artifact (`code`, `refresh_token`, `device_code`) a bearer
/// credential in its own right. This is the type a host is most likely to debug-print, since it is
/// the request it just parsed, so a derived `Debug` here would be the single easiest way to end up
/// with plaintext credentials in a host's logs.
#[derive(Clone, PartialEq, Eq)]
pub enum TokenRequest {
    /// RFC 6749 section 4.1.3: `grant_type=authorization_code`, with the RFC 7636 `code_verifier`
    /// that OAuth 2.1 makes mandatory.
    AuthorizationCode {
        /// The redeeming client.
        client_id: ClientId,
        /// The client secret, when the client is confidential.
        client_secret: Option<String>,
        /// The code from the authorization response (single use).
        code: String,
        /// The redirect URI the authorization request used; must match exactly.
        redirect_uri: Option<String>,
        /// The PKCE verifier for the challenge recorded against the code.
        code_verifier: Option<String>,
    },
    /// RFC 6749 section 4.4: `grant_type=client_credentials`. Confidential clients only, and no
    /// refresh token is issued (section 4.4.3: the client can simply request another token).
    ClientCredentials {
        /// The client acting on its own behalf.
        client_id: ClientId,
        /// The client secret. A public client has none, and cannot use this grant.
        client_secret: Option<String>,
        /// Optional narrowing scope.
        scope: Option<ScopeSet>,
    },
    /// RFC 8628 section 3.4: `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
    DeviceCode {
        /// The polling client.
        client_id: ClientId,
        /// The client secret, when the client is confidential.
        client_secret: Option<String>,
        /// The `device_code` from the device authorization response.
        device_code: String,
    },
    /// RFC 6749 section 6: `grant_type=refresh_token`, with OAuth 2.1 rotation.
    RefreshToken {
        /// The refreshing client.
        client_id: ClientId,
        /// The client secret, when the client is confidential.
        client_secret: Option<String>,
        /// The refresh token being redeemed (single use).
        refresh_token: String,
        /// Optional narrowing scope; widening is `invalid_scope`.
        scope: Option<ScopeSet>,
    },
}

/// Hand-written so no credential reaches a debug format, while everything that identifies WHICH
/// request this is stays visible: the variant name (so the grant type is readable), `client_id`
/// (RFC 6749 section 2.2 makes it explicitly not a secret), `redirect_uri` and `scope`.
///
/// `client_secret` and `code_verifier` are `Option`s, and the Some/None distinction is kept: it is
/// not a credential, it is the difference between "a secret was presented" and "none was", which
/// is exactly what someone debugging an `invalid_client` (RFC 6749 section 5.2) or a missing-PKCE
/// rejection needs, and it can be read off the request's shape without the value.
impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Option<&str>` rather than a bare string, so `Some("[redacted]")` / `None` prints and
        // the presence of the credential stays legible while its value does not.
        fn redact_opt<T>(value: &Option<T>) -> Option<&'static str> {
            value.as_ref().map(|_| "[redacted]")
        }
        match self {
            TokenRequest::AuthorizationCode {
                client_id,
                client_secret,
                code: _,
                redirect_uri,
                code_verifier,
            } => f
                .debug_struct("AuthorizationCode")
                .field("client_id", client_id)
                .field("client_secret", &redact_opt(client_secret))
                .field("code", &"[redacted]")
                .field("redirect_uri", redirect_uri)
                .field("code_verifier", &redact_opt(code_verifier))
                .finish(),
            TokenRequest::ClientCredentials {
                client_id,
                client_secret,
                scope,
            } => f
                .debug_struct("ClientCredentials")
                .field("client_id", client_id)
                .field("client_secret", &redact_opt(client_secret))
                .field("scope", scope)
                .finish(),
            TokenRequest::DeviceCode {
                client_id,
                client_secret,
                device_code: _,
            } => f
                .debug_struct("DeviceCode")
                .field("client_id", client_id)
                .field("client_secret", &redact_opt(client_secret))
                // RFC 8628 section 3.4 redeems the device code with no further proof from a public
                // client, so it is as much a bearer credential as an authorization code is.
                .field("device_code", &"[redacted]")
                .finish(),
            TokenRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token: _,
                scope,
            } => f
                .debug_struct("RefreshToken")
                .field("client_id", client_id)
                .field("client_secret", &redact_opt(client_secret))
                .field("refresh_token", &"[redacted]")
                .field("scope", scope)
                .finish(),
        }
    }
}

/// How a client is authenticating on one request.
///
/// A value of its own rather than more fields on every [`TokenRequest`] variant, for the same
/// reason RFC 8707's `resource` is a separate argument: client authentication is a property of the
/// REQUEST and is identical across every grant, so putting it on each variant would state the same
/// thing four times, grow an enum every host copies around, and make each future grant repeat it
/// again.
///
/// [`Default`] is a PUBLIC client: no secret, no assertion.
///
/// `Debug` is HAND-WRITTEN (below) and does not print the secret or the assertion. It derived one
/// until 0.9.2, which made the guarantee on `crate::http`'s private `Credentials` -- "DELIBERATELY NOT
/// `Debug` ... a derived `Debug` would put all of it verbatim into a host's logs the first time
/// somebody wrote `tracing::debug!(?creds)`" -- last exactly as long as the one function call that
/// converts the one into the other. And this is the worse of the two to leave open: it is PUBLIC
/// API, so it is the value a host builds by hand for [`AuthorizationServer::token`], and a host
/// that never touches `http::Credentials` reaches it anyway.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
/// `#[non_exhaustive]`: `client-assertion` adds two fields and `mtls` adds a third, so this is four
/// different structs depending on the flag set. Three named constructors already cover the three
/// ways a client can authenticate ([`ClientCredential::secret`], [`ClientCredential::assertion`],
/// [`ClientCredential::certificate`]), and the RFC 8705 section 4 case of binding a token for a
/// client that authenticated some other way is a field assignment on top of one of them, which is
/// exactly what that field's own documentation already tells a host to do.
#[non_exhaustive]
pub struct ClientCredential<'a> {
    /// The RFC 6749 section 2.3.1 shared secret, from `Authorization: Basic` or from the form body.
    /// `None` for a public client, and `None` when an assertion is presented instead.
    pub client_secret: Option<&'a str>,
    /// RFC 7521 section 4.2 `client_assertion_type`. It MUST be
    /// [`crate::client_assertion::CLIENT_ASSERTION_TYPE`]; any other value is refused rather than
    /// ignored, because an assertion format this server does not implement is a credential it
    /// cannot check, and "cannot check" must never read as "checked out".
    #[cfg(feature = "client-assertion")]
    pub client_assertion_type: Option<&'a str>,
    /// RFC 7523 section 2.2 `client-assertion`: the signed JWT itself.
    #[cfg(feature = "client-assertion")]
    pub client_assertion: Option<&'a str>,
    /// The RFC 8705 client certificate the HOST has ALREADY VERIFIED for this connection.
    ///
    /// READ [`crate::mtls`]'s trust boundary section before setting this. This library
    /// never sees a socket, so it cannot validate a chain it did not negotiate: a host that
    /// fills this in from an unverified source (an unstripped `X-Client-Cert` header, a
    /// terminator that requests but does not require a certificate) has authenticated
    /// nobody, and every comparison this crate then makes is against a value the caller
    /// chose.
    ///
    /// It does two separate jobs, either of which can apply on its own:
    ///
    /// - section 2, AUTHENTICATION: a client registered with
    ///   [`crate::client::ClientAuth::Mtls`] is authenticated by this certificate and by
    ///   nothing else. Such a client cannot authenticate through a call that leaves this
    ///   `None`, which is the point: a host that forgets to pass the certificate gets
    ///   `invalid_client`, never a token.
    /// - section 3, BINDING: the issued access token is bound to this certificate whatever
    ///   the client's authentication method was, including a public client (section 4).
    ///   Binding is not conditional on a per-client flag, because a bound token is never
    ///   less safe than the unbound one it replaces, and a client that does not want
    ///   binding does not present a certificate.
    #[cfg(feature = "mtls")]
    pub certificate: Option<&'a crate::mtls::ClientCertificate<'a>>,
}

/// Hand-written so neither the shared secret nor the assertion ever prints, in the same shape
/// [`crate::token::TokenResponse`] uses: the `Some`/`None` distinction is KEPT, because WHICH
/// credential a request presented is the diagnostic an operator actually needs and is not itself
/// secret, while the value is. `client_assertion_type` prints in full: RFC 7521 section 4.2 makes
/// it a fixed registered URN, so it identifies the mechanism rather than the holder. The
/// certificate prints through its own `Debug`, which is a public document by construction.
impl fmt::Debug for ClientCredential<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redact_opt<T>(value: &Option<T>) -> Option<&'static str> {
            value.as_ref().map(|_| "[redacted]")
        }
        let mut out = f.debug_struct("ClientCredential");
        out.field("client_secret", &redact_opt(&self.client_secret));
        #[cfg(feature = "client-assertion")]
        out.field("client_assertion_type", &self.client_assertion_type);
        #[cfg(feature = "client-assertion")]
        out.field("client_assertion", &redact_opt(&self.client_assertion));
        #[cfg(feature = "mtls")]
        out.field("certificate", &self.certificate);
        out.finish()
    }
}

impl<'a> ClientCredential<'a> {
    /// The credential of a client presenting a shared secret, or of a public client presenting
    /// none.
    pub fn secret(client_secret: Option<&'a str>) -> Self {
        ClientCredential {
            client_secret,
            #[cfg(feature = "client-assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client-assertion")]
            client_assertion: None,
            #[cfg(feature = "mtls")]
            certificate: None,
        }
    }

    /// The RFC 7523 credential: the assertion, and the type that names its format.
    #[cfg(feature = "client-assertion")]
    pub fn assertion(client_assertion_type: Option<&'a str>, client_assertion: &'a str) -> Self {
        ClientCredential {
            client_secret: None,
            client_assertion_type,
            client_assertion: Some(client_assertion),
            #[cfg(feature = "mtls")]
            certificate: None,
        }
    }

    /// The RFC 8705 credential: the client certificate the host verified during the TLS
    /// handshake, and no secret at all.
    ///
    /// For a client that authenticates some OTHER way and still wants its token bound
    /// (RFC 8705 section 4, including a public client), set
    /// [`ClientCredential::certificate`] on the credential it is already using rather than
    /// replacing it with this one.
    #[cfg(feature = "mtls")]
    pub fn certificate(certificate: &'a crate::mtls::ClientCertificate<'a>) -> Self {
        ClientCredential {
            certificate: Some(certificate),
            ..ClientCredential::secret(None)
        }
    }

    /// Fall back to the secret carried on the [`TokenRequest`] variant when the context named none,
    /// so a host may present it either way and neither is silently ignored.
    fn or_secret(mut self, secret: Option<&'a str>) -> Self {
        if self.client_secret.is_none() {
            self.client_secret = secret;
        }
        self
    }
}

/// Everything about a token request that is not part of the grant itself.
///
/// Passed by reference to [`AuthorizationServer::token_with_context`]. Growing this struct is
/// cheap; growing [`TokenRequest`] is not, because a host copies that around and
/// `tests/allocation.rs` holds it to a size budget.
#[derive(Debug, Clone, Copy, Default)]
/// `#[non_exhaustive]`: `rar` and `dpop` each add a field, and this is the type a host assembles on
/// EVERY token request, so it is the single most likely struct literal in a host's codebase and the
/// most expensive one to break. "Growing this struct is cheap" above is only true while growing it
/// is not a semver-major change, which is what the attribute buys.
///
/// Build it with [`TokenRequestContext::new`] and assign what the request carried; `Default` is
/// still there for a request with no credential at all, though the credential is the one thing
/// every request has an answer for, which is why it is the constructor's only argument.
#[non_exhaustive]
pub struct TokenRequestContext<'a> {
    /// How the client is authenticating.
    pub credential: ClientCredential<'a>,
    /// The RFC 8707 `resource` parameters, in wire order.
    pub resources: &'a [String],
    /// The RFC 9396 `authorization_details` parameter, raw and unparsed.
    ///
    /// Here rather than on each [`TokenRequest`] variant for the reason `resources` is
    /// here: section 6 defines it as a parameter of the token REQUEST, independent of
    /// `grant_type`. What it MEANS does depend on the grant, and section 6 is what decides:
    /// `authorization_code` and `refresh_token` may narrow what the authorization request
    /// obtained and never widen it; `client_credentials` has no prior authorization request,
    /// so its details are checked against the supported types and used; and the device grant
    /// refuses any at all, because the RFC 8628 section 3.1 request cannot carry them in
    /// this crate and so granted nothing for a poll to narrow to.
    ///
    /// NOT FEATURE GATED, for the reason
    /// [`crate::authorization::AuthorizationRequest::authorization_details`] is not: a build
    /// without `rar` still has to be TOLD the parameter arrived, because refusing it is what
    /// RFC 9396 section 5 requires of exactly that build. Setting it in such a build makes the
    /// request an error rather than making the field meaningless.
    pub authorization_details: Option<&'a str>,
    /// The RFC 9449 `DPoP` request header, verbatim and unparsed.
    ///
    /// `None` means the client sent none, which is refused only when
    /// [`ServerConfig::require_dpop`] is set. When it is present and valid, the issued token is
    /// BOUND to the proof's key: `token_type` becomes `DPoP` and RFC 7662 introspection reports
    /// `cnf.jkt`.
    #[cfg(feature = "dpop")]
    pub dpop_proof: Option<&'a str>,
}

impl<'a> TokenRequestContext<'a> {
    /// The context of a request that carried nothing but its client authentication, which is every
    /// request in a deployment that has enabled none of the parameters the other fields exist for.
    ///
    /// The RFC 8707 `resource` list, the RFC 9396 `authorization_details` and the RFC 9449 `DPoP`
    /// header are public fields on the returned value, so a host's token endpoint reads as the
    /// sequence of parameters it actually found on the wire.
    pub fn new(credential: ClientCredential<'a>) -> Self {
        TokenRequestContext {
            credential,
            resources: &[],
            authorization_details: None,
            #[cfg(feature = "dpop")]
            dpop_proof: None,
        }
    }

    /// The RFC 8707 `resource` parameters the request carried, in wire order.
    pub fn with_resources(mut self, resources: &'a [String]) -> Self {
        self.resources = resources;
        self
    }

    /// The RFC 9396 `authorization_details` parameter, raw and unparsed. Available in every
    /// build: without `rar` what it buys is a REFUSAL rather than a grant, which is what RFC 9396
    /// section 5 asks of a server that supports no detail type.
    pub fn with_authorization_details(mut self, authorization_details: &'a str) -> Self {
        self.authorization_details = Some(authorization_details);
        self
    }

    /// The RFC 9449 `DPoP` request header, verbatim.
    #[cfg(feature = "dpop")]
    pub fn with_dpop_proof(mut self, dpop_proof: &'a str) -> Self {
        self.dpop_proof = Some(dpop_proof);
        self
    }
}

/// What each grant helper needs about the REQUEST rather than about the grant.
///
/// One reference wide at every call site, which is actually SMALLER than the `Option<&str>` client
/// secret it replaces there. That is not incidental: these helpers are the token future, and
/// `tests/allocation.rs` fails if that future crosses tokio's 2048-byte debug boxing threshold.
pub(crate) struct Bound<'a> {
    /// The credential to authenticate with.
    pub(crate) cred: ClientCredential<'a>,
    /// The RFC 9449 section 6.1 thumbprint the issued token must be bound to, when the request
    /// carried a valid proof.
    #[cfg(feature = "dpop")]
    pub(crate) jkt: Option<&'a str>,
}

impl<'a> Bound<'a> {
    /// A request authenticating with a shared secret and asking for no RFC 9449 binding.
    ///
    /// For the grant surfaces that reach `issue` from outside this module (RFC 8693 token
    /// exchange). They get an unbound token, which is honest: they have not been given a proof to
    /// bind one to. Wiring DPoP into them is a matter of threading a `Bound` in, not of changing
    /// anything here.
    ///
    /// `dead_code` because its only caller is behind another slice's cargo feature, and gating it
    /// on that feature by name would tie this module to a flag it has no other business knowing.
    #[allow(dead_code)]
    pub(crate) fn secret(client_secret: Option<&'a str>) -> Self {
        Bound {
            cred: ClientCredential::secret(client_secret),
            #[cfg(feature = "dpop")]
            jkt: None,
        }
    }
}

/// Rejections for the host-driven verification-UI actions ([`AuthorizationServer::approve_device`]
/// / [`AuthorizationServer::deny_device`]). These are NOT wire errors: the RFC leaves the
/// verification interaction to the implementation, and the host renders these however its UI
/// wants.
///
/// `#[non_exhaustive]`, for the reason `lib.rs` gives for re-exporting it at all: a host's
/// verification UI is expected to MATCH on this, so a later release that has a new way to refuse an
/// entered code must be able to say so without that being a semver-major change for every host.
/// Every other host-facing failure enum in this crate carries the same attribute
/// ([`crate::registration::RegistrationFailure`], [`crate::events::ClientAuthFailure`],
/// [`crate::consent::AuthenticationRequirement`]); this one was the exception, and there was no argument
/// for the exception.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceApprovalError {
    /// No live grant matches the entered code.
    UnknownUserCode,
    /// The grant existed but its lifetime has passed.
    Expired,
    /// The grant was already approved or denied.
    NotPending,
    /// The host's own [`crate::events::RateLimiter`] refused the attempt before the code was
    /// looked up at all. RFC 8628 section 5.1 makes throttling user-code entry a REQUIREMENT of
    /// the deployment, not an optimisation, so this is a first-class answer and not an error.
    RateLimited,
    /// The storage seam failed.
    Storage(StorageError),
}

impl std::fmt::Display for DeviceApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceApprovalError::UnknownUserCode => f.write_str("unknown user code"),
            DeviceApprovalError::Expired => f.write_str("the code has expired"),
            DeviceApprovalError::NotPending => f.write_str("the code was already used"),
            DeviceApprovalError::RateLimited => f.write_str("too many attempts"),
            DeviceApprovalError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DeviceApprovalError {}

/// The RFC 8628 section 6.1 example alphabet: 20 consonants, chosen upstream to avoid vowels
/// (accidental words) and easily confused symbols.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Fresh OS randomness, hex encoded: `n` bytes of entropy, `2n` characters. Used for device codes
/// and tokens; 32 bytes = 256 bits, far past any brute-force horizon for a 10-minute artifact.
///
/// `None` means the OS would not give this process randomness. That is a real runtime condition —
/// an exhausted file descriptor table on the platforms where `getrandom` opens `/dev/urandom`, a
/// seccomp policy, a container without the syscall — and it is a condition every OTHER fallible
/// operation on these paths reports as [`ErrorCode::ServerError`] and returns from. Panicking
/// instead means a library aborting the HOST's request handler, and in a host built with
/// `panic = "abort"` it means taking the whole process down: an authorization server that stops
/// serving the requests it COULD still serve because one of them could not be given 32 bytes.
///
/// THERE IS NO PANICKING FORM ANY MORE, and its removal is the point. A `random_hex` that
/// `expect`ed survived here through 0.9.0 with a doc claiming its remaining call sites were
/// "outside the request path" — `crate::registration`'s minting and `crate::par`'s `request_uri`.
/// Both halves were false by the time the doc was read: PAR had already moved to this function,
/// and RFC 7591 dynamic registration is an ordinary unauthenticated `POST /register` route. A
/// function that cannot be called is the only reliable way to keep that from happening again.
///
/// The DRAW and the ENCODING are separate calls so that one `getrandom` call can feed several
/// artifacts. `getrandom::fill` is a SYSCALL, and the measurement that matters is that its cost is
/// almost entirely per CALL rather than per byte: 875 ns for one byte against 1025 ns for
/// thirty-two on the machine benches/README.md names. So the number of calls is the thing to
/// reduce, and a caller that needs two 32-byte artifacts should draw 64 bytes once rather than 32
/// bytes twice. See `issue`.
pub(crate) fn try_random_hex(n_bytes: usize) -> Option<String> {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).ok()?;
    Some(hex_encode(&buf))
}

/// The refusal a request-reachable randomness failure becomes, in the one spelling all three sites
/// use.
///
/// Modelled on [`storage_error`], and for the same reason: the host learns what happened through
/// its own logs, the wire gets the opaque RFC 6749 section 5.2 `server_error` and nothing about
/// this server's internals. It IS a server error in the section's sense — "the authorization
/// server encountered an unexpected condition that prevented it from fulfilling the request" — and
/// the client's correct response, retrying later, is the same one it would make to a store that
/// was briefly unavailable.
/// The fixed input [`AuthorizationServer::dummy_assertion_verify`] verifies over.
///
/// It is not a JWS signing input and does not need to be: an ES256 verification costs the same
/// whatever it is handed, and the string exists only so the operation is well defined.
#[cfg(feature = "client-assertion")]
const DUMMY_ASSERTION_SIGNING_INPUT: &str = "oauth-as dummy verification input";

/// A real ES256 signature over [`DUMMY_ASSERTION_SIGNING_INPUT`], made once by a throwaway key.
///
/// IT IS A COST, NOT A CREDENTIAL, exactly as the dummy secret hash beside it is: the private half
/// was never kept, no registration names the public half below, and the value it signs is a
/// constant rather than a token request. What it buys is a verification that runs to completion —
/// a malformed signature or a point off the curve would be refused in the parse and cost a
/// fraction of the real work, which is the leak again.
#[cfg(feature = "client-assertion")]
const DUMMY_ASSERTION_SIGNATURE: [u8; 64] = [
    91, 15, 217, 171, 65, 158, 255, 105, 97, 207, 103, 199, 34, 188, 42, 123, 113, 63, 9, 92, 242,
    81, 20, 20, 147, 223, 209, 148, 122, 59, 212, 156, 132, 79, 44, 44, 108, 53, 228, 247, 251,
    153, 155, 251, 71, 102, 34, 231, 227, 160, 80, 16, 215, 84, 84, 74, 117, 3, 91, 5, 148, 20, 28,
    47,
];

/// The public half of that throwaway key.
///
/// BUILT PER CALL, not cached in a `OnceLock`: this crate promises no global statics and no lazy
/// singletons (the crate docs say so, and `tests/allocation.rs` enforces it), and the four small
/// allocations a [`crate::jwt::PublicJwk`] costs are invisible beside the ES256 verification they
/// are there to feed — which is the whole point, since the KNOWN-id path this is matching pays
/// that verification too. The `Jwk` literal is the crate's own publishing shape, whose coordinates
/// are by construction the 32-byte base64url a verifier expects.
#[cfg(feature = "client-assertion")]
fn dummy_assertion_key() -> crate::jwt::PublicJwk {
    crate::jwt::Jwk {
        kty: "EC",
        crv: "P-256",
        x: "LIZkYOSRaSLc5uMxzlzV9pgt1ARaDl_3tZfRkt9mzFY".to_string(),
        y: "fBSzqWfCploda0TpKf3N56v6fk-fORAiVsXUmkWYWkw".to_string(),
        kid: "oauth-as-dummy-verification-key".to_string(),
        use_: "sig",
        alg: "ES256",
    }
    .to_public_jwk()
}

fn randomness_error() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::ServerError)
}

/// WHAT THIS REQUEST'S PRESENTED CREDENTIAL HAS ALREADY BEEN CHARGED FOR, carried from wherever the
/// work happened to the ONE exit that refuses a client authentication.
///
/// This exists because the previous shape had no such carrier: every branch of
/// [`AuthorizationServer::authenticate_client`] was also an EXIT, so every branch had to remember to
/// charge the dummy verification the unknown-id path charges, and four consecutive audit rounds
/// found a branch that had forgotten. A flag that records what WAS spent, plus a single exit that
/// spends the remainder, cannot forget: adding a refusal adds a `return Ok(Refused(..))` that
/// carries this ledger unchanged, and the charge happens whether or not the author thought about it.
///
/// Both fields mean "a REAL verification of this kind has already been performed on this request",
/// so the exit owes the dummy for whichever kind the request PRESENTED and did not get. Nothing here
/// is a fact about the registration, which is the point: what a refusal costs must be a function of
/// what arrived on the wire, never of what the store holds.
#[derive(Default)]
struct CredentialCost {
    /// A secret verification ran through [`crate::client::ClientAuth::verify_with`].
    secret: bool,
    /// An RFC 7523 assertion verification was ATTEMPTED against a registration's keys.
    ///
    /// "Attempted" rather than "performed", and that is the residual documented as FOURTH on
    /// [`AuthorizationServer::authenticate_client`]: `verify_assertion` refuses a malformed
    /// assertion, and one whose `alg` is not the registration's, before it reaches any signature
    /// work. Setting the flag at the call preserves EXACTLY what this crate charged before this
    /// restructure, which is what makes the restructure reviewable as a mechanical change; closing
    /// that last gap needs `verify_assertion` to report whether it reached the signature, which is
    /// a change to a public function and is not this one.
    #[cfg(feature = "client-assertion")]
    assertion: bool,
}

/// The outcome of examining a presented credential, BEFORE anything is charged, recorded or
/// emitted for it.
///
/// A value rather than a return: this is what lets the five refusal decisions in
/// [`AuthorizationServer::classify_client_credential`] be decisions instead of exits. Every one of
/// them hands back `Refused(failure)` and the single exit does the identical three things to all of
/// them — settle the credential's cost, record the failed attempt, tell the audit channel which
/// failure it was — before returning the one bare `invalid_client` RFC 6749 section 5.2 collapses
/// them into.
enum ClientAuthVerdict {
    /// The credential verified. The `Arc` is the registration the caller asked for.
    Authenticated(std::sync::Arc<Client>),
    /// The credential did not verify, for the reason the HOST's audit channel is told. The wire is
    /// told nothing beyond `invalid_client`.
    Refused(ClientAuthFailure),
}

/// The rejection-sampling bound: the largest multiple of [`USER_CODE_ALPHABET`]'s length that fits
/// in a byte. Values at or above it are redrawn rather than folded, because folding them would
/// hand the low-index symbols extra probability.
const USER_CODE_REJECT_AT: u8 = 240;

/// Map one random byte to a user-code symbol, or reject it for a redraw.
///
/// This is split out of [`random_user_code`] ON PURPOSE, and the reason is testability rather than
/// structure. The property that matters here is UNIFORMITY, and uniformity is not a property of any
/// single generated code: a test that can only look at sampled output has to argue statistically,
/// which means either a test that is flaky or a test that draws hundreds of thousands of samples to
/// notice a bias of a few percent. As a total function of one byte it can instead be checked
/// EXHAUSTIVELY over all 256 inputs, which settles the question outright (see
/// `src/tests/server.rs`).
///
/// The numbers are load bearing. 240 is the largest multiple of 20 below 256, so the accepted
/// values 0..=239 cover each of the 20 symbols exactly 12 times. Accepting one more value would
/// give symbol 0 a thirteenth preimage, an 8% excess over its peers, and RFC 8628 section 5.1 is
/// explicit that the user code's entropy is already only just sufficient (in combination with host
/// rate limiting) because the code is short enough for a human to type.
fn user_code_symbol(byte: u8) -> Option<u8> {
    if byte < USER_CODE_REJECT_AT {
        Some(USER_CODE_ALPHABET[(byte % 20) as usize])
    } else {
        None
    }
}

/// A user code of `len` symbols over [`USER_CODE_ALPHABET`], unbiased via rejection sampling.
///
/// # The entropy is drawn in ONE call, not one per symbol
///
/// `getrandom::fill` is a SYSCALL and its cost is almost entirely per CALL rather than per byte:
/// MEASURED on the machine `benches/README.md` names, 875 ns for one byte and 1025 ns for
/// thirty-two. Drawing a byte at a time therefore made the call COUNT the entire cost, and sweeping
/// `user_code_length` showed a slope of roughly 960 to 1160 ns per SYMBOL. At the default eight
/// symbols that was about 8.2 us of `device_authorization`'s 9.27 us: 85% of an endpoint that takes
/// no credential from a public client, spent on syscall entry.
///
/// Being honest about the magnitude: on Linux with a vDSO `getrandom` (kernel 6.11 and glibc 2.42
/// or newer) the per-call cost is far lower, so the figures above are partly a macOS and BSD
/// `getentropy` number. THE CALL COUNT IS THE PORTABLE DEFECT, which is why this is worth doing
/// regardless of where it runs.
///
/// The uniformity argument is untouched. Every byte still goes through [`user_code_symbol`], values
/// at or above [`USER_CODE_REJECT_AT`] are still redrawn rather than folded, and the buffer is
/// simply refilled when it runs out, so a run of rejections costs another draw exactly as it did.
/// The buffer is a fixed stack array, so this adds no allocation: 64 bytes is enough that the
/// probability of needing a second draw for the default eight-symbol code is negligible (each byte
/// is accepted with probability 240/256), while staying small enough to sit in a frame.
///
/// `None` for the reason [`try_random_hex`] gives: this runs on RFC 8628 section 3.1's device
/// authorization endpoint, which is an ordinary request, and a library must not abort its host's
/// process because the OS momentarily would not hand over 64 bytes.
fn random_user_code(len: usize) -> Option<String> {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        getrandom::fill(&mut buf).ok()?;
        for &byte in buf.iter() {
            if out.len() == len {
                break;
            }
            if let Some(symbol) = user_code_symbol(byte) {
                out.push(symbol as char);
            }
        }
    }
    Some(out)
}

/// `WDJBMJHT` to `WDJB-MJHT`: hyphenate the middle for display when the length is even and at
/// least 4; otherwise the raw run is the display form.
fn display_user_code(raw: &str) -> String {
    // `% 2 == 0` rather than `is_multiple_of`, which did not stabilise until well after this
    // crate's supported floor. A library should compile on the oldest toolchain it reasonably can,
    // and this reads no worse.
    if raw.len() >= 4 && raw.len() % 2 == 0 {
        let mid = raw.len() / 2;
        format!("{}-{}", &raw[..mid], &raw[mid..])
    } else {
        raw.to_string()
    }
}

/// Whether a `code_challenge` has the RFC 7636 section 4.2 S256 shape: the base64url (no padding)
/// encoding of a 32 byte digest, which is exactly 43 characters of the base64url alphabet.
///
/// Section 4.1's ABNF admits 43 to 128 characters generally, but that range covers the `plain`
/// method, where the challenge is the verifier itself. For S256 the length is fixed by the digest
/// size, so anything else was never produced by SHA-256 and cannot match any verifier.
fn challenge_is_well_formed(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The number of decimal digits `n` is written in, which is what `replay_key` has to reserve for
/// its length prefix. `0` is one digit, and there is no case with none.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
fn decimal_width(n: usize) -> usize {
    let mut width = 1;
    let mut rest = n / 10;
    while rest > 0 {
        rest /= 10;
        width += 1;
    }
    width
}

/// The storage key one single-use identifier is claimed under.
///
/// NAMESPACED, and both halves matter. `kind` keeps an RFC 7523 assertion's `jti` from colliding
/// with an RFC 9449 proof's, which are different credentials with different lifetimes that a client
/// may well number from the same counter. `owner` (the client id for an assertion, the key
/// thumbprint for a proof) keeps one client from locking another out by choosing its `jti` values:
/// without it, an attacker could spend a victim's future `jti` values in advance, which is a denial
/// of service bought for the price of a refused request.
///
/// # Why the length prefix, and why a separator alone was not enough
///
/// The encoding is `kind ":" LEN(owner) ":" owner jti`, and it is INJECTIVE, which is a stronger
/// statement than "the parts are separated" and is the statement that matters:
///
/// - `kind` is one of this file's own two constants (`ca`, `dpop`), neither of which contains a
///   colon, so the first colon ends it;
/// - what follows is the decimal byte length of `owner`, digits only, so the next colon ends it;
/// - that length says exactly where `owner` stops and `jti` starts, whatever either of them
///   contains.
///
/// Every part is therefore recoverable from the key, so no two distinct `(kind, owner, jti)`
/// triples can produce the same one.
///
/// The previous encoding, `kind:owner:jti`, was NOT injective, and the counterexample is ordinary
/// rather than exotic. `ClientId::new` imposes no character restriction and URN-style client ids
/// are common, so a client registered as `urn` presenting the `jti` `client:foo:42` produced
/// `ca:urn:client:foo:42`, which is exactly what the client registered as `urn:client:foo` gets
/// for its `jti` `42`. Whoever claimed it first denied it to the other, so one client could spend
/// another's single-use slot and the victim's conforming assertion came back `invalid_client` as a
/// replay of something nobody sent. `tests/replay_key_collision.rs` runs that attack.
///
/// One allocation per assertion or proof, on a path that only exists when the feature is on: the
/// capacity below is exact, and `write!` into a `String` with room does not grow it.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
fn replay_key(kind: &str, owner: &str, jti: &str) -> String {
    use std::fmt::Write as _;
    let mut key = String::with_capacity(
        kind.len() + 1 + decimal_width(owner.len()) + 1 + owner.len() + jti.len(),
    );
    key.push_str(kind);
    key.push(':');
    // Infallible: `fmt::Write` for `String` cannot fail, and there is no error to handle.
    let _ = write!(key, "{}", owner.len());
    key.push(':');
    key.push_str(owner);
    key.push_str(jti);
    key
}

fn storage_error(e: StorageError) -> ErrorResponse {
    // The host sees the real error through its own Storage impl; the wire gets the opaque code.
    let _ = e;
    ErrorResponse::new(ErrorCode::ServerError)
}

/// The RFC 9396 authorization details flowing through one issuance: what a grant carries,
/// what a token request asked to narrow it to, and what the issued token ends up with.
///
/// A WRAPPER rather than the details themselves, and the reason is structural. `issue` and
/// the grant helpers have to have exactly ONE signature in every feature configuration: an
/// argument can carry a `cfg`, but the ARGUMENT AT THE CALL SITE cannot, so a gated
/// parameter would mean duplicating five call sites under `cfg` and giving the eight
/// existing arguments five more places to drift. This is the same reasoning `Bound` above
/// records for the RFC 9449 key binding.
///
/// Without `rar` this struct has no fields, so it is zero sized, every construction of it
/// compiles to nothing, and the default build's token future keeps the size
/// `tests/allocation.rs` pins. That gate exists because crossing tokio's 2048-byte debug
/// boxing threshold costs an allocation on every request that reaches the endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GrantedDetails {
    /// BOXED, and an `Option` so that the common case is a null pointer. The token future
    /// is 1824 bytes against tokio's 2048-byte debug boxing threshold, and this value is
    /// live in it at six points; carrying the details inline (three words) crossed the
    /// threshold and cost a 2 KB allocation on EVERY token request, which is exactly the
    /// regression `tests/allocation.rs` was written to catch, and it caught this one. One
    /// word costs 48 bytes of the future instead of 144, and the allocation behind the
    /// `Some` is paid only by a request that actually carries authorization details.
    #[cfg(feature = "rar")]
    inner: Option<Box<crate::rar::AuthorizationDetails>>,
}

impl GrantedDetails {
    /// Wrap details read off a grant record, keeping the empty case a null pointer.
    #[cfg(feature = "rar")]
    fn of(details: &crate::rar::AuthorizationDetails) -> Self {
        GrantedDetails {
            inner: (!details.is_empty()).then(|| Box::new(details.clone())),
        }
    }

    /// What an authorization code granted (RFC 9396 section 7: the details as approved by
    /// the resource owner and assigned to the token this code mints).
    fn of_code(record: &AuthorizationCodeRecord) -> Self {
        #[cfg(feature = "rar")]
        {
            GrantedDetails::of(&record.authorization_details)
        }
        #[cfg(not(feature = "rar"))]
        {
            let _ = record;
            GrantedDetails {}
        }
    }

    /// What a refresh chain carries, which is what the previous leg narrowed it to.
    fn of_refresh(record: &RefreshTokenRecord) -> Self {
        #[cfg(feature = "rar")]
        {
            GrantedDetails::of(&record.authorization_details)
        }
        #[cfg(not(feature = "rar"))]
        {
            let _ = record;
            GrantedDetails {}
        }
    }

    /// What an already-issued token carries, for a grant that continues it: the RFC 8693
    /// exchange, where the exchanged token inherits the subject token's details.
    ///
    /// `dead_code` for the same reason [`Bound::secret`] carries it: its only caller is
    /// behind another slice's cargo feature, and gating this on that feature by name would
    /// tie this module to a flag it has no other business knowing.
    #[allow(dead_code)]
    pub(crate) fn of_token(token: &IssuedToken) -> Self {
        #[cfg(feature = "rar")]
        {
            GrantedDetails::of(&token.authorization_details)
        }
        #[cfg(not(feature = "rar"))]
        {
            let _ = token;
            GrantedDetails {}
        }
    }

    /// The owned details to write onto a record.
    #[cfg(feature = "rar")]
    fn into_details(self) -> crate::rar::AuthorizationDetails {
        self.inner.map(|d| *d).unwrap_or_default()
    }

    /// Whether anything was asked for at all.
    ///
    /// `dead_code` for the same reason [`GrantedDetails::of_token`] carries it, and NOT because
    /// nothing calls it: `token_with_resources` uses it on the device-code branch to refuse
    /// `authorization_details` on a grant that never carried any. That call site is behind
    /// `#[cfg(feature = "rar")]`, so in a build without that feature this genuinely has no caller,
    /// and gating the allow on the feature by name would tie this wrapper to a flag whose whole
    /// purpose is to be invisible from here.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        #[cfg(feature = "rar")]
        {
            self.inner.is_none()
        }
        #[cfg(not(feature = "rar"))]
        {
            true
        }
    }

    /// The details an issuance gets: `requested` may NARROW what `self` carries and may
    /// never widen it (RFC 9396 section 6). Delegated to [`crate::rar`], which is where the
    /// comparison rule and the argument for it live; this is the seam, not the rule.
    fn narrow(&self, requested: &GrantedDetails) -> Result<GrantedDetails, ErrorResponse> {
        #[cfg(feature = "rar")]
        {
            let requested = match &requested.inner {
                // Nothing asked for, so nothing to narrow: the grant passes through.
                None => return Ok(self.clone()),
                Some(requested) => requested.as_ref(),
            };
            // A grant carrying none narrows to nothing, and `narrow` refuses accordingly:
            // widening from nothing is still widening. The empty set allocates nothing.
            let empty = crate::rar::AuthorizationDetails::none();
            let granted = self.inner.as_deref().unwrap_or(&empty);
            Ok(GrantedDetails::of(&granted.narrow(requested)?))
        }
        #[cfg(not(feature = "rar"))]
        {
            let _ = requested;
            Ok(GrantedDetails {})
        }
    }
}

/// The refresh chain an issuance CONTINUES: carried from the redeemed record to its replacement,
/// so that rotation preserves both the family (RFC 9700 section 4.14.2 revokes by grant) and the
/// absolute lifetime (a chain must not slide its own expiry forward every time it rotates).
pub(crate) struct RefreshChain {
    family_id: String,
    expires_at: Option<SystemTime>,
}

/// The authorization server. Generic over the host's [`Storage`] and (for tests) the [`Clock`].
pub struct AuthorizationServer<S: Storage, C: Clock = SystemClock> {
    config: ServerConfig,
    store: S,
    clock: C,
    /// The RFC 8414 `token_endpoint` this server answers on, derived once from `config`.
    ///
    /// It exists as a field because it is compared against on every RFC 9449 proof and every RFC
    /// 7523 assertion (see [`AuthorizationServer::token_endpoint`]), and it is fixed for the life
    /// of the server: `config` is moved in here and there is no way to mutate it afterwards.
    /// `Box<str>` rather than `String` because it is never appended to, which keeps the field at
    /// 16 bytes instead of 24 on a struct `tests/allocation.rs` holds to a size budget.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    token_endpoint: Box<str>,
    /// The host's optional seams (audit sink, rate limiter, secret verifier). ONE pointer wide and
    /// null until the host installs something: see [`Hooks`] for why the three do not sit here as
    /// three separate fields.
    hooks: Hooks,
}

impl<S: Storage> AuthorizationServer<S, SystemClock> {
    /// Construct with the real clock. This is the crate's allocation entry point: call it when
    /// (and only when) host config enables the AS.
    pub fn new(config: ServerConfig, store: S) -> Self {
        Self::with_clock(config, store, SystemClock)
    }
}

impl<S: Storage, C: Clock> AuthorizationServer<S, C> {
    /// Construct with an injected clock (tests).
    pub fn with_clock(config: ServerConfig, store: S, clock: C) -> Self {
        // Derived HERE and not at each use, and derived exactly as
        // `AuthorizationServerMetadata::from_config` derives it, because a server whose own idea
        // of its token endpoint differs from the one it publishes refuses every conforming client.
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        let token_endpoint: Box<str> = match &config.token_endpoint {
            Some(endpoint) => endpoint.as_str().into(),
            None => format!("{}/token", config.issuer.trim_end_matches('/')).into_boxed_str(),
        };
        AuthorizationServer {
            config,
            store,
            clock,
            #[cfg(any(feature = "client-assertion", feature = "dpop"))]
            token_endpoint,
            hooks: Hooks::new(),
        }
    }

    /// Install the audit sink (RFC-agnostic; see [`crate::events`]). Builder-style so a host wires
    /// it at construction: `AuthorizationServer::new(cfg, store).with_event_sink(Box::new(sink))`.
    ///
    /// This crate logs nothing by itself. Without a sink, the two events that are evidence of
    /// compromise (authorization code replay, refresh token reuse) revoke silently, which means an
    /// operator learns about a stolen grant from a support ticket rather than from a log line.
    pub fn with_event_sink(mut self, sink: Box<dyn EventSink>) -> Self {
        self.hooks.install_event_sink(sink);
        self
    }

    /// Install the rate limiter. THIS LIBRARY DOES NOT RATE LIMIT: RFC 8628 section 5.1 makes user
    /// code entropy adequate only IN COMBINATION WITH rate limiting of code entry, and only the
    /// host has a caller, an IP or a session to count against. See
    /// [`AuthorizationServer::approve_device`].
    pub fn with_rate_limiter(mut self, limiter: Box<dyn RateLimiter>) -> Self {
        self.hooks.install_rate_limiter(limiter);
        self
    }

    /// Install the client secret verifier, for [`crate::client::SecretHash`] schemes this crate
    /// does not implement (argon2id, scrypt, an HSM). The built-in scheme needs no verifier and is
    /// never delegated to one.
    pub fn with_secret_verifier(
        mut self,
        verifier: Box<dyn crate::client::SecretVerifier>,
    ) -> Self {
        self.hooks.install_secret_verifier(verifier);
        self
    }

    /// Install the RFC 7591 registration policy: who may create a client here.
    ///
    /// Required, not optional, for any host that sets [`ServerConfig::registration`]: with no
    /// policy installed every registration is refused, because an endpoint that mints clients and
    /// has been told nothing about who may use it is the abuse vector RFC 7591 section 5
    /// describes. See [`crate::registration::RegistrationPolicy`].
    pub fn with_registration_policy(
        mut self,
        policy: Box<dyn crate::registration::RegistrationPolicy>,
    ) -> Self {
        self.hooks.install_registration_policy(policy);
        self
    }

    /// Install the RFC 9101 request object verification keys: which public key, under which
    /// algorithm, each client registered for signing request objects.
    ///
    /// Required, not optional, for a host that sets [`ServerConfig::jar`]: with no key source
    /// installed every `request` parameter is refused, because a server that cannot check a
    /// signature must not act on the claims under it. See [`crate::par::RequestObjectKeys`].
    #[cfg(feature = "jar")]
    pub fn with_request_object_keys(
        mut self,
        keys: Box<dyn crate::par::RequestObjectKeys>,
    ) -> Self {
        self.hooks.install_request_object_keys(keys);
        self
    }

    /// Install the ES256 backend this server VERIFIES signatures with: RFC 9449 DPoP proofs, RFC
    /// 9101 request objects, RFC 7523 client assertions.
    ///
    /// Required unless `jwt-p256` is compiled in, which installs [`crate::jwt::P256Verifier`] as
    /// the default. With neither, every signed credential is REFUSED, exactly as an absent
    /// [`crate::par::RequestObjectKeys`] or an absent registration policy refuses: a server that
    /// cannot check a signature must never behave as though it had checked one.
    ///
    /// A verifier installed here WINS over the built-in one, because it was installed. That is the
    /// whole of the precedence rule, and it is why nothing in this crate's feature set is mutually
    /// exclusive: a dependency graph that unifies `jwt-p256` on cannot take a host's choice away.
    ///
    /// Run [`crate::signer_conformance`] against whatever you install here before you deploy it.
    // NO `#[must_use]`, for the crate-wide reason `tests/host_api_shape.rs` states and gates: this
    // is one of twenty-nine consuming builders, all of which move their receiver, so dropping the
    // result is a compile error at the next use of it rather than a setting silently lost. One
    // marked builder out of twenty-nine is the state that gate exists to refuse.
    #[cfg(feature = "jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
    pub fn with_es256_verifier(
        mut self,
        verifier: std::sync::Arc<dyn crate::jwt::Es256Verifier>,
    ) -> Self {
        self.hooks.install_es256_verifier(verifier);
        self
    }

    /// The ES256 verifier this server will use, or `None` when it has none and must refuse.
    ///
    /// THE ONE PLACE the precedence rule lives: the host's installed verifier, else the built-in
    /// `jwt-p256` backend when that feature is compiled in, else nothing. Every caller
    /// (`verify_dpop`, the RFC 7523 assertion check, the RFC 9101 request object check) asks here
    /// and refuses on `None`, so there is exactly one definition of "no backend installed" and no
    /// path that can accidentally read it as "checked out".
    // Gated on the features that actually VERIFY rather than on `jwt`: a build that signs and
    // never checks anybody else's signature has no caller for this, and an uncalled resolver is
    // one more thing a reader has to work out is not reachable.
    #[cfg(any(feature = "dpop", feature = "jar", feature = "client-assertion"))]
    pub(crate) fn es256_verifier(&self) -> Option<&dyn crate::jwt::Es256Verifier> {
        match self.hooks.es256_verifier() {
            Some(installed) => Some(&**installed),
            #[cfg(feature = "jwt-p256")]
            None => Some(&crate::jwt::P256Verifier),
            #[cfg(not(feature = "jwt-p256"))]
            None => None,
        }
    }

    /// The installed host seams, for a host that wants to emit its own events onto the same
    /// channel (a consent decision, say) or to consult its own limiter.
    pub fn hooks(&self) -> &Hooks {
        &self.hooks
    }

    /// This server's clock, for the parts of the crate that live in other modules
    /// ([`crate::registration`]) and cannot reach the private field.
    pub(crate) fn now(&self) -> SystemTime {
        self.clock.now()
    }

    /// How long a [`crate::store::RevocationBarrier`] this server records has to stand.
    ///
    /// A barrier exists to refuse a write from a request that was ALREADY HOLDING a record when
    /// the revocation ran. What bounds that is not the request's wall time, which nothing here can
    /// know, but the lifetime of what such a request could still write: no in-flight issuance can
    /// produce a credential that outlives the longest this server is configured to mint. So the
    /// deadline is now plus that longest lifetime, and a barrier that has stood for it has
    /// outlived everything it was recorded to refuse.
    ///
    /// All four durations are considered rather than just the access token TTL, and the
    /// `refresh_reuse_window` is in the list on purpose: a chain with NO absolute lifetime
    /// (`refresh_token_ttl: None`) has its spent records retained for exactly that window, so it
    /// is the longest-lived thing such a family produces.
    ///
    /// Erring long costs storage that [`crate::store::Storage::sweep_expired`] reclaims. Erring
    /// short costs the revocation itself, silently, which is the failure this whole mechanism
    /// exists to prevent, so the asymmetry is taken deliberately.
    /// Put a taken refresh record back, after a judgement that is NOT evidence of compromise.
    ///
    /// [`crate::store::Storage::take_refresh_token`] removes the record before anything about it
    /// has been judged, so every refusal that is not reuse has to restore it, or a client that
    /// merely asked for the wrong scope would lose its chain. Five refusal paths do that, and they
    /// all handle a refused write the same way, so they call this rather than each writing the
    /// handling out: the last time this crate had one operation at several seams, the copy that
    /// diverged was the one that failed open.
    ///
    /// A [`crate::store::WriteOutcome::RefusedRevoked`] here is neither an error nor a surprise.
    /// It means a revocation reached this family, client or consent while the record was out of
    /// the store, and the record STAYING gone is exactly what that revocation asked for. The
    /// caller's own refusal is the answer to the client either way. A genuine storage failure is
    /// still fatal, because then it is not known whether the chain survived.
    async fn restore_refresh_token(
        &self,
        record: crate::token::RefreshTokenRecord,
    ) -> Result<(), ErrorResponse> {
        let _outcome = self
            .store
            .put_refresh_token(record)
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    /// Take back an access token this server wrote and then decided not to hand out.
    ///
    /// Issuance is two writes and [`crate::store::Storage`] has no transaction spanning them (see
    /// the trait's own docs on why requiring cross-key atomicity would exclude most stores). A
    /// revocation landing between them leaves the first write standing, so issuance has to be able
    /// to reverse itself, and this is that reversal.
    ///
    /// FAILURE IS SWALLOWED, deliberately, and this is the one judgement in it. The caller is
    /// already returning an error and the client will never see the token; the alternative is to
    /// report a storage failure INSTEAD of the revocation, which tells the caller the wrong thing
    /// about why it was refused. What is left behind on a failed undo is one orphaned access token
    /// that [`crate::store::Storage::sweep_expired`] reclaims at its own expiry, and which no
    /// client holds the string for.
    async fn undo_issuance(&self, access_token: &str) {
        let _ = self.store.delete_token(access_token).await;
    }

    /// The window a revocation happening NOW should record: the instant it happened, and the
    /// instant past which nothing it was entitled to kill can still be in flight.
    ///
    /// Both come from ONE reading of the clock. Taking `now` twice would let the two instants
    /// straddle a tick, and `recorded_at` is compared against by every subsequent write, so a
    /// `recorded_at` even fractionally later than the revocation's own effect is a grant
    /// wrongly refused.
    pub(crate) fn revocation_window(&self) -> crate::store::RevocationWindow {
        let longest = self
            .config
            .access_token_ttl
            .max(self.config.refresh_token_ttl.unwrap_or_default())
            .max(self.config.refresh_reuse_window)
            .max(self.config.authorization_code_ttl)
            .max(self.config.device_code_ttl);
        let recorded_at = self.clock.now();
        crate::store::RevocationWindow {
            recorded_at,
            until: saturating_deadline(recorded_at, longest),
        }
    }

    /// Turn the freshly minted random token into what actually goes on the wire: itself when the
    /// format is opaque (the byte-for-byte pre-feature behaviour), or an RFC 9068 access token
    /// carrying it as `jti` when the host configured signing.
    ///
    /// SYNC, and it stops one step short of the signature, which is what the awkward return type
    /// buys. The host's [`crate::jwt::Es256Signer`] may be a network round trip, so signing is
    /// async; if this function were async instead, the whole [`AccessTokenClaims`] value below
    /// would live across that suspension point and join the token endpoint's coroutine frame,
    /// which `tests/allocation.rs` holds under tokio's 2048-byte debug boxing threshold. Splitting
    /// here means the claims are built and consumed on the sync side and only a `String` crosses
    /// the await. MEASURED: 1344 bytes before the seam, 1360 after; an async `wire_access_token`
    /// measured 1656.
    // Eight arguments, since the RFC 8705 binding is a property of the REQUEST rather than of the
    // grant. Same allow and same reason as `issue` below: a private function with one call site,
    // whose arguments would have to live across every await in the token future if they were
    // bundled into a struct to satisfy a lint.
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "jwt")]
    fn access_token_signing_input(
        &self,
        client: &Client,
        subject: Option<&str>,
        scope: &ScopeSet,
        resource: &[String],
        details: &GrantedDetails,
        now: SystemTime,
        // The instant the caller has decided this token dies at, which is NOT always
        // `now + access_token_ttl`: see the `lifetime_ceiling` argument of
        // [`AuthorizationServer::issue`]. Handed in rather than recomputed here, because a signed
        // `exp` that disagrees with the stored expiry is a token two halves of one deployment
        // enforce differently.
        expires_at: SystemTime,
        jti: String,
        bound: &Bound<'_>,
        actor: &GrantedActor,
        // What the HOST reported about the resource owner's login, for RFC 9470 s6.1. Handed in
        // rather than read off the record being written next door, for the reason `expires_at` is:
        // the signed claim and the persisted record must be the one value stated twice, and the
        // record is written after this returns.
        authentication: &GrantedAuthentication,
    ) -> Result<Result<(&crate::jwt::JwtConfig, String), String>, ErrorResponse> {
        // Only the RFC 8705 binding is read out of it here; without that feature the
        // signed claim set does not depend on how the client authenticated.
        #[cfg(not(feature = "mtls"))]
        let _ = bound;
        // Likewise the RFC 9396 details, which reach the claim set only under `rar`. This is not
        // decoration: `http,jwt` without `rar` is exactly what the conformance server builds, and
        // neither a default build (where this function does not exist) nor `--all-features` (where
        // `details` IS read) compiles that combination. CI caught it; local testing had not.
        #[cfg(not(feature = "rar"))]
        let _ = details;
        let jwt = match &self.config.access_token_format {
            // `Err` is not a failure here: it is the OPAQUE arm, carrying the random string
            // through unchanged. Two arms of one `Result` rather than an `Option` plus a moved-out
            // `jti`, because the opaque path must not copy the string it already has.
            AccessTokenFormat::Opaque => return Ok(Err(jti)),
            AccessTokenFormat::Jwt(jwt) => jwt,
        };
        // Without the feature the wrapper is empty and genuinely unused here, exactly as `bound`
        // is without `dpop`; see the note at the top of `issue`.
        #[cfg(not(feature = "token-exchange"))]
        let _ = actor;
        // Same for the RFC 9470 report: without `consent` there is no field on the claim set to
        // fill and no field on the wrapper to fill it from.
        #[cfg(not(feature = "consent"))]
        let _ = authentication;
        let claims = AccessTokenClaims {
            // The SAME spelling the RFC 8414 document publishes, the RFC 9207 `iss` parameter
            // carries and introspection reports. `issuer_identifier` trims a trailing slash, and
            // the raw config value does not, so a host configuring "https://as.example/" used to
            // publish "https://as.example" everywhere except here. A resource server doing the
            // byte comparison RFC 9068 s4 and RFC 8414 s3.3 call for would then reject every
            // token this server signs, or be patched to compare loosely, which disables the
            // mix-up defence RFC 9207 exists to provide. One server, one identity, everywhere it
            // states it.
            iss: self.issuer_identifier().to_string(),
            exp: crate::jwt::unix_seconds(expires_at)
                .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))?,
            // RFC 8707 s2 with RFC 9068 s2.2: when the client named the resource server(s) it
            // means to call, THAT is the audience, and the configured default is not. The default
            // is a deployment-wide statement made before any request arrived; the resource
            // indicator is this grant's own, and honouring the wider one would hand back a token
            // valid somewhere the client did not ask for and the user did not approve. Single
            // resource stays the plain-string form RFC 7519 s4.1.3 allows, because that is what
            // most resource servers actually parse.
            aud: match resource {
                [] => jwt.audience().clone(),
                [one] => crate::jwt::Audience::One(one.clone()),
                many => crate::jwt::Audience::Many(many.to_vec()),
            },
            // RFC 9068 section 2.2: `sub` is REQUIRED. Where there is no resource owner (a
            // client-only grant) the RFC's own answer is the client identifier, so the claim is
            // never absent and never invented.
            sub: subject
                .unwrap_or_else(|| client.client_id.as_str())
                .to_string(),
            client_id: client.client_id.as_str().to_string(),
            iat: crate::jwt::unix_seconds(now)
                .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))?,
            jti,
            scope: (!scope.is_empty()).then(|| scope.to_string()),
            // RFC 9396 s9.1: the AS is RECOMMENDED to add the authorization details as a
            // top-level claim, so a resource server holding a JWT does not have to call
            // introspection to learn what the token actually authorizes. NOT filtered per
            // audience, which s9.1 also suggests: filtering means deciding which detail
            // belongs to which resource server, and only the API that defined the `type`
            // knows that (s6.1). A detail that names its own `locations` has already said
            // so, in a form the resource server can check for itself.
            #[cfg(feature = "rar")]
            authorization_details: details.clone().into_details(),
            // RFC 9470 s6.1, in the token itself. s6.2 (introspection) was the only channel this
            // crate answered on through 0.9.1, and it is the channel a JWT deployment does not
            // use: a resource server that verifies the signature locally never asks this server
            // anything, so a step-up it could not see in the claims was one it had to take the
            // client's word for. That is the failure the s3 challenge exists to prevent.
            //
            // The SAME conversion the introspection response uses, deliberately: `unix_seconds`
            // answers `None` for an instant before the epoch, so a host-reported `auth_time` this
            // server cannot state is stated by NEITHER channel rather than by one of them. Two
            // channels disagreeing about one token is worse than both being silent, and silence
            // here re-challenges (s3) rather than admitting anything.
            #[cfg(feature = "consent")]
            auth_time: authentication
                .authentication
                .as_ref()
                .and_then(|a| unix_seconds(a.auth_time)),
            #[cfg(feature = "consent")]
            acr: authentication
                .authentication
                .as_ref()
                .and_then(|a| a.acr.as_deref().map(str::to_string)),
            // EVERY binding the AS-side record carries, in the form a resource server can check
            // for itself without calling introspection at all. RFC 9449 s6.1 for `jkt`, RFC 8705
            // s3.1 for `x5t#S256`, built the same way introspection builds it so the two can never
            // disagree about what a token is bound to.
            #[cfg(any(feature = "dpop", feature = "mtls"))]
            cnf: {
                let cnf = crate::token::Confirmation {
                    #[cfg(feature = "dpop")]
                    jkt: bound.jkt.map(str::to_string),
                    #[cfg(feature = "mtls")]
                    x5t_s256: bound.cred.certificate.map(|c| *c.thumbprint()),
                };
                (!cnf.is_empty()).then_some(cnf)
            },
            // RFC 8693 s4.1, in the token itself. A JWT is typically validated offline by a
            // resource server that never introspects, so the record alone would not reach it.
            #[cfg(feature = "token-exchange")]
            act: actor.act.as_deref().cloned(),
        };
        // `claims` dies HERE, before the caller awaits the signature. See this function's doc.
        jwt.signing_input(&claims)
            .map(|input| Ok((&**jwt, input)))
            .map_err(|e| {
                // The host sees the real error through its own logging of the config it supplied; the
                // wire gets the opaque code, as with storage failures.
                let _ = e;
                ErrorResponse::new(ErrorCode::ServerError)
            })
    }

    /// The RFC 7517 key set to serve at `jwks_uri`, or `None` when tokens are opaque. PUBLIC key
    /// parameters only.
    #[cfg(feature = "jwt")]
    pub fn jwks(&self) -> Option<Jwks> {
        match &self.config.access_token_format {
            AccessTokenFormat::Opaque => None,
            AccessTokenFormat::Jwt(jwt) => Some(jwt.jwks()),
        }
    }

    /// The configured `jwks_uri`, or `None`. An RFC 8414 metadata document must advertise
    /// `jwks_uri` exactly when this is `Some`: advertising a key set for an AS that signs nothing
    /// is a lie, and signing without advertising leaves resource servers unable to verify.
    #[cfg(feature = "jwt")]
    pub fn jwks_uri(&self) -> Option<&str> {
        match &self.config.access_token_format {
            AccessTokenFormat::Opaque => None,
            AccessTokenFormat::Jwt(jwt) => jwt.jwks_uri(),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The RFC 8414 document THIS server would publish, which is the one a host should serve.
    ///
    /// Different from [`crate::metadata::AuthorizationServerMetadata::from_config`], and the
    /// difference is the point: `from_config` sees the configuration and nothing else, while some
    /// of what the document promises depends on a seam the host INSTALLED on the server. RFC 7523
    /// `private_key_jwt` is the case that forced this. It is ES256, so it is honest exactly when
    /// this server can check an ES256 signature, and that is a property of
    /// [`AuthorizationServer::with_es256_verifier`] plus the `jwt-p256` feature, neither of which
    /// a `&ServerConfig` can see. A method the document names and the token endpoint refuses
    /// every time is not a defect a client can work around: it did what it was told.
    ///
    /// `from_config` therefore advertises only what the CONFIGURATION alone establishes, and this
    /// adds back exactly what the installed seams establish. It is the direction that fails safe:
    /// a host that ignores this method under-advertises rather than inviting clients to use a
    /// method that cannot work. [`crate::http::ServiceBuilder::build`] uses this one.
    pub fn metadata(&self) -> crate::metadata::AuthorizationServerMetadata {
        #[allow(unused_mut)]
        let mut meta = crate::metadata::AuthorizationServerMetadata::from_config(&self.config);
        // Only the ES256-dependent members need adjusting, and only in a build that could verify
        // at all: the `cfg` is exactly the set `es256_verifier` is gated on, because those three
        // features are the three that advertise something an ES256 signature check has to back.
        #[cfg(any(feature = "client-assertion", feature = "jar", feature = "dpop"))]
        if self.es256_verifier().is_some() {
            meta.es256_verification_is_available();
        }
        meta
    }

    /// This server's issuer identifier, in the ONE spelling it publishes.
    ///
    /// RFC 9207 section 2.4 has the client compare the `iss` authorization response parameter
    /// against the issuer it started the flow with, for EQUALITY, and the value it started from is
    /// the RFC 8414 `issuer` metadata member. `AuthorizationServerMetadata::from_config` trims a
    /// trailing slash off the configured issuer, so this trims it too: a host that wrote
    /// `https://as.example/` must not end up with two spellings of its own identity, because the
    /// mismatch would read to a conforming client as a mix-up attack in progress.
    // `pub(crate)` so `par.rs` can check an RFC 9101 request object's `aud` claim against the
    // ONE spelling this server publishes, rather than re-deriving it and risking a second one.
    pub(crate) fn issuer_identifier(&self) -> &str {
        self.config.issuer.trim_end_matches('/')
    }

    /// Validate one RFC 8707 `resource` list from the wire into the owned form the grant records.
    ///
    /// Section 2 gives `invalid_target` as the answer for a value this server will not issue a
    /// token for, which covers both a malformed indicator and (at the token endpoint, see
    /// [`AuthorizationServer::narrow_resources`]) one that was never granted.
    pub(crate) fn validate_resources<'a>(
        &self,
        requested: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<String>, ErrorResponse> {
        // The cap is checked as the list is walked rather than up front, because `requested` is an
        // iterator (both call sites hand in a borrowed `map`, so there is nothing to count without
        // collecting first, and collecting is the allocation the cap exists to bound). Refusing at
        // the moment the cap is exceeded means at most `MAX_RESOURCE_INDICATORS` elements are ever
        // examined however many were sent.
        let mut out = Vec::new();
        // Counted on the INPUT, not on `out`. Counting deduplicated survivors would leave a caller
        // free to send ten thousand copies of one URI: each still costs a full scan of `out`, so
        // the work is unbounded even though the result is small.
        let mut seen = 0usize;
        for value in requested {
            seen += 1;
            if seen > MAX_RESOURCE_INDICATORS {
                return Err(ErrorResponse::new(ErrorCode::InvalidTarget)
                    .with_description("too many resource indicators (RFC 8707 s2)"));
            }
            if !crate::authorization::is_valid_resource_indicator(value) {
                // The offending value is NOT echoed: RFC 6749 section 5.2 restricts
                // error_description to a charset an attacker-supplied URI need not respect, and
                // naming the parameter is enough for the developer who sent it.
                return Err(
                    ErrorResponse::new(ErrorCode::InvalidTarget).with_description(
                        "resource must be an absolute URI with no fragment (RFC 8707 s2)",
                    ),
                );
            }
            // SYNTAX IS NOT AUTHORISATION. RFC 8707 section 2 requires `invalid_target` when the
            // server "is unwilling or unable to issue an access token" for a named resource, and
            // until this check existed the server had no notion of unwilling: any well-formed URI
            // was accepted. That matters most with the `jwt` feature on, where the requested
            // resource REPLACES the configured audience in the RFC 9068 `aud` claim, so a client
            // registered for one resource server could name another and receive a token this
            // server had signed, with that other server's identifier in `aud`. The second server
            // fetches our JWKS, the signature verifies, `aud` names it, and it authorises on a
            // scope string the two happen to share. Scope-name collision between resource servers
            // is the ordinary case, not an exotic one.
            //
            // FACTORED OUT rather than written here, because RFC 8693 s2.1.1 `audience` names the
            // same thing as `resource` in a spelling that need not be a URI: it must skip the
            // syntax check above and must NOT skip this one. See `target_is_permitted`.
            self.target_is_permitted(value)?;
            // A repeated identical indicator is the same request twice, not two audiences.
            if !out.iter().any(|kept: &String| kept == value) {
                out.push(value.to_string());
            }
        }
        Ok(out)
    }

    /// Whether this server is willing to issue a token naming `value` at all: the
    /// [`ServerConfig::allowed_resources`] check, on its own.
    ///
    /// SYNTAX IS NOT AUTHORISATION, and the two questions had been welded together. RFC 8707
    /// section 2 requires `invalid_target` when the server "is unwilling or unable to issue an
    /// access token" for a named target, and that is a statement about the DEPLOYMENT: it is how an
    /// operator decommissions a resource server, and until it existed any well-formed URI was
    /// accepted. It matters most with the `jwt` feature on, where the requested target REPLACES the
    /// configured audience in the RFC 9068 `aud` claim, so a client registered for one resource
    /// server could name another and receive a token this server had signed, with that other
    /// server's identifier in `aud`. The second server fetches our JWKS, the signature verifies,
    /// `aud` names it, and it authorises on a scope string the two happen to share. Scope-name
    /// collision between resource servers is the ordinary case, not an exotic one.
    ///
    /// SPLIT OUT OF [`AuthorizationServer::validate_resources`] because RFC 8693 section 2.1.1
    /// `audience` names the same target in a spelling that need not be a URI. It therefore has to
    /// skip the absolute-URI check and must not thereby skip this one, which is what it did through
    /// 0.9.1: an operator who decommissioned a resource server by removing it from the allowlist
    /// went on handing out signed tokens naming it, to any client holding a token whose grant
    /// recorded it, via `audience` on an exchange.
    ///
    /// An EMPTY allowlist keeps the previous behaviour rather than refusing everything, because
    /// refusing would break every deployment that already relies on resource indicators. That means
    /// this check protects only hosts that configure it, which is stated plainly on the config field
    /// rather than left for someone to discover.
    pub(crate) fn target_is_permitted(&self, value: &str) -> Result<(), ErrorResponse> {
        if let Some(allowed) = &self.config.allowed_resources {
            if !allowed.iter().any(|a| &**a == value) {
                // The offending value is NOT echoed, for the reason `validate_resources` gives:
                // RFC 6749 section 5.2 restricts `error_description` to a charset an
                // attacker-supplied value need not respect.
                return Err(ErrorResponse::new(ErrorCode::InvalidTarget)
                    .with_description("this server does not issue tokens for that resource"));
            }
        }
        Ok(())
    }

    /// The resource set an issuance actually gets: the request may NARROW what the grant carries,
    /// never widen it (RFC 8707 section 2).
    ///
    /// This is deliberately the same shape as the RFC 6749 section 6 scope rule that
    /// [`AuthorizationServer::refresh_token`] applies, because it is the same argument: the user
    /// approved a specific thing, and a later leg of the same grant asking for MORE than that is
    /// either a client bug or an escalation attempt, and the AS cannot tell which.
    ///
    /// A grant that named no resource has nothing to narrow, so a token request that names one is
    /// widening from nothing and is refused. Answering it any other way would let the token
    /// endpoint mint an audience the authorization request never obtained.
    ///
    /// # On the O(requested * granted) scan
    ///
    /// It needs no cap of its own, and deliberately does not have one, but the reason is now a
    /// count rather than the claim it used to make. That claim was that BOTH sides came through
    /// [`AuthorizationServer::validate_resources`], and it stopped being true when RFC 8693 token
    /// exchange started calling this: `granted` is still a validated grant record, but `requested`
    /// there is `resource` values (validated) PLUS section 2.1.1 `audience` values, which skip the
    /// URI-syntax check by design. What still bounds both sides is a CAP EACH:
    /// [`MAX_RESOURCE_INDICATORS`] on the resource list, and
    /// [`crate::token_exchange::MAX_AUDIENCE_VALUES`], deliberately the same number, on the
    /// audience list. So the worst case is 16 * 32 string comparisons, most of which fail on the
    /// length, and a third constant here would be a third number to keep in step with the other two
    /// for no gain.
    pub(crate) fn narrow_resources(
        granted: &[String],
        requested: &[String],
    ) -> Result<Vec<String>, ErrorResponse> {
        if requested.is_empty() {
            return Ok(granted.to_vec());
        }
        for want in requested {
            if !granted.iter().any(|g| g == want) {
                return Err(ErrorResponse::new(ErrorCode::InvalidTarget)
                    .with_description("resource was not granted by the authorization request"));
            }
        }
        Ok(requested.to_vec())
    }

    /// [`AuthorizationServer::narrow_resources`], then the allowlist ON WHAT SURVIVES.
    ///
    /// THE ALLOWLIST IS A PROPERTY OF THE ISSUED SET, NOT OF THE REQUESTED ONE, and that is the
    /// whole of this function. [`AuthorizationServer::target_is_permitted`] was consulted only
    /// about values a REQUEST named, and `narrow_resources` returns the grant's recorded list
    /// verbatim when the request names none, which is the ordinary case: a refresh sending no
    /// `resource`, an RFC 8693 exchange sending neither `resource` nor `audience`. So the values
    /// that reached the issued token on that path were never checked at all.
    ///
    /// What that cost is exactly what `target_is_permitted`'s own doc describes for the `audience`
    /// spelling, reached by a shorter road: an operator decommissions a resource server by removing
    /// it from [`ServerConfig::allowed_resources`], and every grant that had already recorded it
    /// goes on minting tokens naming it. Under `jwt` the issued set REPLACES the configured
    /// audience in the RFC 9068 `aud` claim, so those are freshly SIGNED tokens naming a server the
    /// operator believes they switched off, and with `refresh_token_ttl` defaulting to `None` the
    /// chain that mints them never expires.
    ///
    /// # Refused when NAMED, dropped when INHERITED, and the difference is what the client asked
    ///
    /// A request that NAMES a decommissioned target is asking for something this server will not
    /// issue, and RFC 8707 section 2's answer to that is `invalid_target`. That is what
    /// `narrow_resources` above already delivers, through the same
    /// [`AuthorizationServer::target_is_permitted`] every named value goes through.
    ///
    /// A request that names NOTHING has asked for whatever the grant still supports, so a target
    /// the server has since retired is DROPPED rather than made fatal. Refusing there would mean an
    /// operator retiring one resource server instantly breaks every live chain that ever recorded
    /// it, including clients that only ever call the ones still standing, over a value none of them
    /// mentioned. That is a bigger outage than the decommissioning itself, and it is avoidable.
    ///
    /// UNLESS NOTHING SURVIVES, which is the one case that must refuse. An empty resource list does
    /// not mean "no audience restriction" further down: [`AuthorizationServer::issue`] falls back
    /// to the configured [`crate::jwt::JwtConfig`] audience when the list is empty, so silently
    /// emptying a grant that DID name resources would WIDEN the token to this deployment's default
    /// audience, which is the opposite of what dropping was meant to do.
    pub(crate) fn narrow_and_permit(
        &self,
        granted: &[String],
        requested: &[String],
    ) -> Result<Vec<String>, ErrorResponse> {
        let issued = Self::narrow_resources(granted, requested)?;
        if !requested.is_empty() {
            // Every value here is one the request named, so each has already been through
            // `target_is_permitted` at its own endpoint, and naming a retired one is fatal there.
            return Ok(issued);
        }
        let permitted: Vec<String> = issued
            .into_iter()
            .filter(|value| self.target_is_permitted(value).is_ok())
            .collect();
        if permitted.is_empty() && !granted.is_empty() {
            return Err(
                ErrorResponse::new(ErrorCode::InvalidTarget).with_description(
                    "this server no longer issues tokens for any resource this grant names",
                ),
            );
        }
        Ok(permitted)
    }

    /// The storage seam, so the host can administer its own store.
    ///
    /// The one administrative operation this crate REQUIRES of the host is eviction:
    /// [`Storage::sweep_expired`] must be called on some host-chosen schedule, because nothing in
    /// this crate ever evicts anything on its own. There is no background task here and there will
    /// not be one (see the crate docs on zero cost until enabled), so a host that never sweeps has
    /// a store that only grows: consumed authorization codes and spent refresh records are
    /// retained ON PURPOSE until their expiry (that retention is what makes replay and reuse
    /// detectable), and expired access tokens and abandoned device grants are simply never looked
    /// at again. Anything else the host wants to do here, such as listing, is its own store's
    /// business and not this trait's.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Register (or replace) a client the HOST provisioned: no policy is consulted, no credential
    /// is minted, and whatever is handed in is what the store holds.
    ///
    /// This is the out-of-band half of registration. RFC 7591 dynamic client registration is the
    /// other half and it is built:
    /// [`AuthorizationServer::register_dynamic_client`] layers on this one, adding the
    /// [`crate::registration::RegistrationPolicy`] check, the minted `client_id` and secret, and
    /// the RFC 7592 management credential. A host calling THIS method is asserting that the
    /// registration was authorised somewhere it can point to.
    ///
    /// # What IS checked, despite "no policy is consulted"
    ///
    /// Every `redirect_uris` entry, against the same rule RFC 7591 registration applies (RFC 6749
    /// section 3.1.2: an absolute URI with no fragment, and nothing outside printable ASCII, which
    /// RFC 3986 requires of a URI anyway). This is not policy: it is whether the value can work at
    /// all, and the two ways of creating a client used to disagree about it, with the DIRECT one —
    /// the one a default build has, since `http` and dynamic registration are optional — being the
    /// permissive half.
    ///
    /// The reason it is worth a refusal here rather than being left to fail later is WHERE it fails
    /// later, which is three layers away from its cause. A redirect URI containing a space passes
    /// the authorization endpoint's exact-string match, the host's resolver approves, an
    /// authorization code is MINTED AND PERSISTED, and only then does building the `Location`
    /// header fail: the user sees a 500, the client is never reached, and the code sits in storage
    /// until it expires while every retry does it again. Refusing at registration turns that into
    /// one error, at startup, in front of the person who wrote the value.
    ///
    /// A [`StorageError`] rather than a new error type, and it is the honest reading rather than a
    /// convenience: the answer is that this registration cannot be stored as given. The message
    /// names the offending URI, because the caller is the operator who just supplied it.
    pub async fn register_client(&self, client: Client) -> Result<(), StorageError> {
        for uri in &client.redirect_uris {
            // The SAME function `crate::registration`'s `redirect_uri_is_registerable` delegates
            // to, called directly rather than copied: two implementations of one rule is how the
            // two registration paths came to disagree in the first place.
            if !crate::authorization::is_valid_resource_indicator(uri) {
                return Err(StorageError::new(format!(
                    "redirect_uri {uri:?} is not registerable: RFC 6749 s3.1.2 requires an \
                     absolute URI with no fragment, and the authorization endpoint matches it by \
                     exact string, so a registration this server cannot reproduce is a client that \
                     can never complete a flow"
                )));
            }
        }
        // A registration whose `default_scopes` exceed its `allowed_scopes` is NOT refused here,
        // and that is a decision rather than an omission. It is a real state an operator reaches by
        // the control this crate tells them to reach for: `tests/registration_narrowing.rs` narrows
        // `allowed_scopes` alone, exactly as an operator correcting an over-broad registration
        // does, and refusing that would turn a security control into an error message. What made
        // the disagreement dangerous was the GRANT it produced, not the registration itself, and
        // that is closed at the point of issuance instead: see
        // `AuthorizationServer::granted_default_scope`, which trims the default to the allowance so
        // no grant is ever minted that the rotation ceiling would later destroy.
        self.store.put_client(client).await
    }

    /// Verify `presented` against a stored verifier NOBODY holds the secret for, and throw the
    /// answer away.
    ///
    /// The point is the elapsed time, not the result: see the timing section on
    /// [`AuthorizationServer::authenticate_client`], which is the only caller. The scheme comes
    /// from the installed [`crate::client::SecretVerifier`] when it offers one, so the dummy costs
    /// what that host's real registrations cost; otherwise it is the crate's own `sha256-hex`,
    /// which prices the built-in scheme exactly and any other scheme not at all.
    ///
    /// `None` presented does no work, and that is not an omission FOR A SECRET: `verify_with`
    /// answers `false` for a confidential registration with no secret presented without verifying
    /// anything either, so doing nothing here is what MATCHES the known-id path rather than what
    /// diverges from it. It is NOT a general claim, and reading it as one is what left the RFC
    /// 7523 path uncovered through 0.9.0: a `private_key_jwt` request carries an assertion and no
    /// secret at all, so on that path the known id paid an ES256 verification and the unknown id
    /// paid nothing. [`AuthorizationServer::dummy_assertion_verify`] is that half.
    ///
    /// [`std::hint::black_box`] because the whole call is dead code by every rule the optimiser
    /// has: a pure function whose result is discarded. Without it the hashing this exists to spend
    /// is exactly what a release build is entitled to delete.
    fn dummy_verify(&self, presented: Option<&str>) {
        let presented = match presented {
            Some(p) => p,
            None => return,
        };
        let verifier = self.hooks.secret_verifier();
        let hash = match verifier.and_then(|v| v.dummy_hash()) {
            Some(hash) => hash,
            // The crate's own, over a constant that is not a secret and does not need to be: no
            // registration names this hash, so nothing authenticates by presenting the string it
            // was built from. It is a cost, not a credential.
            None => crate::client::SecretHash::sha256(
                "oauth-as dummy verification input; no registration is stored under this",
            ),
        };
        let dummy = crate::client::ClientAuth::ConfidentialSecretHash { hash };
        let _ = std::hint::black_box(dummy.verify_with(Some(presented), verifier));
    }

    /// [`AuthorizationServer::dummy_verify`]'s twin for RFC 7523 client assertions: one ES256
    /// verification through the installed seam, over a key nobody registered, answer discarded.
    ///
    /// WHY IT IS NEEDED SEPARATELY. A `private_key_jwt` request carries a `client_assertion` and
    /// NO `client_secret` — `authenticate_by_assertion` refuses a request carrying both — so
    /// `dummy_verify` was handed `None` and returned immediately, while a KNOWN id on the same
    /// request went on to a real ES256 verification, which `crate::jwt` prices at about 133
    /// microseconds. The probed id is attacker-chosen and free: `crate::http` reads it from the
    /// UNSIGNED `sub` of the assertion when the form carries no `client_id`, and a garbage
    /// signature never reaches `claim_replay_id`, so the probe is repeatable and averageable while
    /// per-id throttling sees exactly one request per candidate — the same shape the secret case
    /// above describes.
    ///
    /// WHICH VERIFICATION, and why it is not always the ES256 one. RFC 7523 has TWO client
    /// authentication methods and this crate implements both: `private_key_jwt` is ES256 through
    /// the installed seam, and `client_secret_jwt` is an HS256 HMAC over the registered secret,
    /// which `verify_assertion` performs itself and which therefore needs no seam at all. So the
    /// real cost of a known id depends on the deployment, and the dummy tracks it: an ES256
    /// verification where a verifier is installed, and an HS256 tag verification where none is,
    /// which is exactly the shape of a `client_secret_jwt`-only deployment. This used to return
    /// early on a missing verifier on the grounds that "the real path refuses without verifying
    /// anything either", and that was true only of `private_key_jwt`: a `client_secret_jwt`
    /// deployment with no ES256 backend had its known ids paying an HMAC while unknown ids paid
    /// nothing.
    ///
    /// WHAT REMAINS, stated rather than left to be discovered: a deployment running BOTH methods
    /// can still be timed to tell which method a KNOWN, EXISTING client is registered for, because
    /// an HMAC and an ES256 verification are three orders of magnitude apart and no single dummy
    /// can be both. That is a much weaker fact than the one this closes: it says nothing about
    /// whether an id exists, so it is not an enumeration primitive, and it is only readable for an
    /// id the attacker already knows is registered.
    ///
    /// WHAT IT COSTS, stated rather than left to be found: a probe that could have reached a
    /// verification now buys one of this server's time whether or not its id exists. That is a
    /// denial-of-service consideration, it was already true for every KNOWN id, and the
    /// [`RateLimiter`] is charged for the attempt either way. The aim of the whole mechanism is
    /// that the two ids cost the same; see the residuals section on
    /// [`AuthorizationServer::authenticate_client`] for where they still do not, because that
    /// claim has now been false in three different ways across three audit rounds and stating it
    /// without the exceptions is what let each one survive.
    #[cfg(feature = "client-assertion")]
    fn dummy_assertion_verify(&self) {
        match self.es256_verifier() {
            Some(verifier) => {
                let _ = std::hint::black_box(verifier.verify(
                    &dummy_assertion_key(),
                    DUMMY_ASSERTION_SIGNING_INPUT.as_bytes(),
                    &DUMMY_ASSERTION_SIGNATURE,
                ));
            }
            // The `client_secret_jwt` cost. The secret is the signing input itself, which is a
            // constant: as with the ES256 signature above this is a COST and not a credential, and
            // an HMAC costs the same whatever key it is handed.
            None => {
                let _ = std::hint::black_box(crate::jwt::verify_hs256(
                    DUMMY_ASSERTION_SIGNING_INPUT.as_bytes(),
                    DUMMY_ASSERTION_SIGNING_INPUT.as_bytes(),
                    &DUMMY_ASSERTION_SIGNATURE[..32],
                ));
            }
        }
    }

    /// Whether this request COULD have reached an assertion verification had its client id
    /// existed, which is the only condition under which charging
    /// [`AuthorizationServer::dummy_assertion_verify`] makes the two ids cost the same.
    ///
    /// It mirrors, exactly, the three refusals `authenticate_by_assertion` makes before it decodes
    /// a byte: an assertion has to be present, the RFC 7521 section 4.2 `client_assertion_type` has
    /// to be the one this server implements, and RFC 6749 section 2.3 forbids a `client_secret`
    /// alongside. Charging on the presence of the assertion ALONE, which is what this used to do,
    /// reopened the leak pointing the other way: a known id sending a garbage
    /// `client_assertion_type` was refused in nanoseconds while an unknown id sending the same
    /// bytes paid a full ES256 verification, so one request per candidate separated "registered"
    /// from "not registered" again. The two conditions have to be kept in step; if a refusal is
    /// ever added there before the verification, it belongs here too.
    #[cfg(feature = "client-assertion")]
    fn assertion_could_be_verified(cred: &ClientCredential<'_>) -> bool {
        cred.client_assertion.is_some()
            && cred.client_assertion_type == Some(CLIENT_ASSERTION_TYPE)
            && cred.client_secret.is_none()
    }

    /// Authenticate a client for a token-plane call: unknown id and failed secret verification
    /// collapse into the same `invalid_client` so an attacker cannot probe which ids exist.
    ///
    /// The WIRE keeps that collapse. The host's audit channel does NOT: an installed
    /// [`crate::events::EventSink`] is told which of the two it actually was, because the host is
    /// not the attacker and "a thousand unknown client ids" and "a thousand wrong secrets for one
    /// real client" are different incidents.
    ///
    /// The host's [`RateLimiter`] is asked FIRST, before the store is touched, so a refused
    /// attempt costs nothing and reveals nothing (RFC 9700 section 4.13 on credential stuffing at
    /// the token endpoint).
    ///
    /// # The collapse is a TIMING property too, and how far this goes
    ///
    /// Answering both cases with the same code is worth nothing if the two take visibly different
    /// wall times, and the unknown-id path is naturally the cheaper one: there is no secret to
    /// verify. So this function performs a DUMMY verification when the id is unknown, through the
    /// same [`crate::client::ClientAuth::verify_with`] every real authentication goes through.
    ///
    /// What that covers exactly:
    ///
    /// - [`crate::client::ClientAuth::ConfidentialSecretHash`] in the built-in `sha256-hex`
    ///   scheme, and [`crate::client::ClientAuth::ConfidentialSecret`], which this crate can price
    ///   for itself because it performs the comparison itself.
    /// - A HOST scheme, whenever the installed [`crate::client::SecretVerifier`] implements
    ///   [`crate::client::SecretVerifier::dummy_hash`]. This is the case that matters, because a
    ///   host scheme is the expensive one.
    /// - RFC 7523 CLIENT ASSERTIONS, through
    ///   [`AuthorizationServer::dummy_assertion_verify`]: a request presenting a
    ///   `client_assertion` for an unknown id pays one verification, which is what the known id
    ///   pays. This was uncovered through 0.9.0 because such a request carries no
    ///   `client_secret`, so the secret dummy above had nothing to do and the doc for that
    ///   `None` case read as though nothing needed doing.
    /// - THE ASSERTION CASE IN BOTH DIRECTIONS, which the first fix for it did not. The dummy is
    ///   charged only when the request could have reached a verification at all
    ///   (`assertion_could_be_verified`), and a KNOWN id whose registration does not use
    ///   assertions pays it too before `authenticate_by_assertion` returns `WrongPrincipal`.
    ///   Without the second half the mechanism ran backwards: an id registered for
    ///   `client_secret_basic` refused in nanoseconds while an unknown id sending identical bytes
    ///   paid 133 microseconds, which separates "registered, but not this way" from "not
    ///   registered" in one un-throttleable request per candidate.
    ///
    /// - THE KNOWN-ID PATHS THAT DID NO VERIFICATION AT ALL, which is the same rule pointing the
    ///   other way and had three separate instances. An expired `client_secret_expires_at` returns
    ///   before every credential branch; `verify_with` answers `false` in nanoseconds for a
    ///   `Public` or `ConfidentialAssertion` registration handed a posted secret; a mutual-TLS
    ///   registration refuses on a thumbprint comparison. Each of those was FASTER than the
    ///   unknown-id path, which pays `dummy_verify` through the host's scheme, so "fast" positively
    ///   identified a registered id. Each is charged the dummy by the one exit below.
    ///
    /// - THE REFUSALS THAT PRECEDE THE ASSERTION VERIFICATION, which the fix for the case above
    ///   introduced. `authenticate_by_assertion` refuses three requests before it decodes a byte,
    ///   and all three are charged `dummy_verify` by the same exit, rather than through a comment
    ///   asking two functions to be kept in step. They were not kept in step: a request carrying an
    ///   assertion AND a `client_secret` was refused by a known id for free while an unknown id
    ///   paid the host's secret scheme, so the fix for the previous bullet reopened the bullet
    ///   before it. See the comment at the top of that function.
    ///
    /// # ONE EXIT, and why the list above is a history rather than a checklist
    ///
    /// Every bullet above was fixed at its own SITE, and each fix was found incomplete by the next
    /// audit round: round 7 added a dummy, round 8 found the dummy made an unknown id cost MORE
    /// than a known one, round 9 found three known-id paths costing nothing, and round 10 found
    /// that round 9's own guard had two refusal sites it did not reach. The diagnosis recorded here
    /// after round 10 was that the costly half is not the branching — it is that THE BRANCHES WERE
    /// ALSO THE EXITS. Every refusal returned from where it was decided, so every refusal had to
    /// remember to charge, and that is the obligation that was forgotten four times.
    ///
    /// So this function no longer refuses anywhere. It asks
    /// [`AuthorizationServer::classify_client_credential`] for a [`ClientAuthVerdict`], a VALUE, and
    /// there is exactly one place that turns a `Refused` into a wire answer. That place charges
    /// [`AuthorizationServer::settle_credential_cost`] unconditionally, records the failed attempt
    /// and emits the failure, in that order, for every refusal there is or ever will be. What a
    /// refusal costs is therefore a function of what the request PRESENTED (through
    /// [`CredentialCost`], which records only what was really spent) and of nothing the store holds,
    /// which is the property the four rounds above were each trying to reach one site at a time.
    ///
    /// A reviewer checks this by COUNTING: one `ClientAuthVerdict::Refused` arm, one
    /// `settle_credential_cost` call on it, and no `ErrorCode::InvalidClient` built anywhere in the
    /// credential path except there. Adding a refusal means adding a `return Ok(Refused(..))`, which
    /// cannot skip the charge because it does not do the charging.
    ///
    /// THE RATE-LIMIT GATE IS NOT ONE OF THOSE REFUSALS and is deliberately kept out of the count.
    /// It is answered before the store is touched, from a public `client_id` and nothing else, so it
    /// cannot vary with any fact about a registration — and charging a dummy verification there is
    /// exactly the amplification [`crate::rate_limit::CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR`]
    /// exists to bound: past the failure ceiling a denial is what an attacker can buy at
    /// [`crate::rate_limit::ATTEMPT_COST`] apiece, thousands per window per client id, and each one
    /// would then buy the host's argon2id as well. The gate refuses free, on purpose, and it is
    /// separated into [`AuthorizationServer::admit_client_authentication`] so that the credential
    /// decision below has one exit rather than nearly one.
    ///
    /// # What it does NOT cover, stated rather than left to be discovered
    ///
    /// FIRST, a host scheme whose verifier returns `None` from `dummy_hash`. This crate cannot
    /// invent a well-formed argon2id or bcrypt encoding to hand such a verifier, and one in the
    /// wrong scheme would be rejected on inspection in microseconds, which is the leak again. A
    /// deployment using a slow custom scheme SHOULD implement that method; until it does, the wire
    /// answer is still collapsed but the wall time is not. That residual is unfixable HERE, unlike
    /// the assertion one above, which is why the assertion one was closed rather than written down
    /// beside it.
    ///
    /// SECOND, WHICH RFC 7523 METHOD an id that is known to exist is registered for, in a
    /// deployment running both. `private_key_jwt` costs an ES256 verification and
    /// `client_secret_jwt` costs an HMAC, three orders of magnitude apart, and one dummy cannot be
    /// both; [`AuthorizationServer::dummy_assertion_verify`] picks whichever matches the
    /// deployment. This is not an enumeration primitive: it says nothing about whether an id
    /// exists, and it is readable only for one the attacker already knows does.
    ///
    /// THIRD, and in the same class: a `ConfidentialSecret` registration compares its secret with
    /// [`crate::client::constant_time_eq`], two SHA-256 digests, while the dummy an unknown id pays
    /// goes through the INSTALLED verifier's scheme. In a deployment that installs argon2id and
    /// still holds plaintext-secret registrations those differ by milliseconds, so such a
    /// registration is distinguishable from an unknown id. A deployment that stores hashes
    /// throughout, which is what [`crate::client::SecretHash`] exists for and what RFC 9700 section
    /// 4.13 expects, has nothing here to read. The structural fix above is what closes it properly;
    /// charging a second dummy on top of the real comparison would only make the same registration
    /// distinguishable in the other direction.
    ///
    /// FOURTH, and FOUND BY THIS RESTRUCTURE rather than closed by it, because closing it is not a
    /// mechanical change. A registration that DOES authenticate by assertion, handed an assertion
    /// that `verify_assertion` refuses before any signature work — one over
    /// [`crate::client_assertion::MAX_ASSERTION_BYTES`], one that is not a compact JWS, or one whose
    /// `alg` is not the registration's — pays nothing, while an unknown id sending the same bytes
    /// pays [`AuthorizationServer::dummy_assertion_verify`]. That separates "registered for RFC 7523
    /// with these keys" from "not registered", which is a narrower fact than the ones above (it is
    /// only readable for the assertion-registered subset) but it is the same shape. Closing it needs
    /// `verify_assertion` to say whether it reached the signature; deciding it from the returned
    /// [`crate::client_assertion::AssertionFailure`] variant would be exactly the "kept in step by a
    /// comment" coupling this restructure exists to remove. `CredentialCost::assertion` records
    /// where that boundary currently is.
    ///
    /// RFC 8705 mutual TLS is not on this list because there is nothing to price: the HOST
    /// verified the certificate before this crate saw it, and what happens here is a thumbprint
    /// comparison.
    pub(crate) async fn authenticate_client(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
    ) -> Result<std::sync::Arc<Client>, ErrorResponse> {
        let attempt = Attempt::ClientAuthentication {
            client_id: client_id.as_str(),
        };
        self.admit_client_authentication(attempt, client_id)?;

        // WHAT WAS SPENT, carried to the exit. Nothing reads it except `settle_credential_cost`,
        // and nothing writes it except the two places that perform a real verification.
        let mut paid = CredentialCost::default();
        // THE DECISION, as a value. Its `?` is a STORAGE failure and not a refusal: it is
        // `server_error`, it says nothing about whether the id exists (the store answered nothing at
        // all), and it is the same propagation every other endpoint in this crate makes.
        let verdict = self
            .classify_client_credential(client_id, cred, &mut paid)
            .await?;
        match verdict {
            ClientAuthVerdict::Authenticated(client) => {
                self.hooks.record(attempt, AttemptOutcome::Succeeded);
                Ok(client)
            }
            // THE ONE EXIT. Every refusal in the credential path arrives here, and this is the only
            // place any of them costs, records or reports anything.
            ClientAuthVerdict::Refused(failure) => {
                // UNCONDITIONAL, and the order is the one every site used before: charge, record,
                // emit. What is charged depends on what the request PRESENTED and on what has
                // already been spent for it — never on which branch decided the refusal.
                self.settle_credential_cost(cred, &paid);
                self.hooks.record(attempt, AttemptOutcome::Failed);
                self.hooks.emit(|| Event::ClientAuthenticationFailed {
                    client_id: client_id.as_str(),
                    failure,
                });
                // The one bare `invalid_client` (RFC 6749 section 5.2). The host's audit channel was
                // told which refusal it was one line up; the wire is told nothing, because the
                // difference between "no such client", "expired", "wrong secret" and "wrong kind of
                // credential" is exactly what tells a caller that an id is real.
                Err(ErrorResponse::new(ErrorCode::InvalidClient))
            }
        }
    }

    /// The host's [`RateLimiter`] gate, asked FIRST, before the store is touched.
    ///
    /// SEPARATE FROM THE CREDENTIAL DECISION on purpose; see "ONE EXIT" on
    /// [`AuthorizationServer::authenticate_client`]. It refuses on a public `client_id` and nothing
    /// else, so it cannot vary with a fact about a registration, and it must stay FREE: a denial is
    /// what an attacker can buy in bulk once the failure ceiling is reached, so charging a dummy
    /// verification here would sell them the host's password hashing at
    /// [`crate::rate_limit::ATTEMPT_COST`] apiece.
    fn admit_client_authentication(
        &self,
        attempt: Attempt<'_>,
        client_id: &ClientId,
    ) -> Result<(), ErrorResponse> {
        if self.hooks.check(attempt) == RateLimitDecision::Deny {
            self.hooks.emit(|| Event::ClientAuthenticationFailed {
                client_id: client_id.as_str(),
                failure: ClientAuthFailure::RateLimited,
            });
            // The same `invalid_client` a wrong secret gets. A distinct code would tell an
            // attacker that they had found a live client id and merely hit the throttle.
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }
        Ok(())
    }

    /// PAY FOR WHAT THIS REQUEST PRESENTED AND DID NOT GET, at the one exit that refuses.
    ///
    /// The unknown-id path is naturally the cheapest one — there is no secret to verify and no key
    /// to verify against — so the collapse of "no such client" and "wrong credential" into one
    /// `invalid_client` is worth nothing unless the two take the same wall time. Every refusal
    /// therefore ends here, and here spends whatever a request of this shape would have spent had it
    /// got as far as a verification:
    ///
    /// - [`AuthorizationServer::dummy_verify`] unless a real secret verification already ran. It
    ///   does nothing when no secret was presented, which is what MATCHES the known-id path:
    ///   `verify_with` refuses a confidential registration with no secret without verifying anything
    ///   either.
    /// - [`AuthorizationServer::dummy_assertion_verify`] unless a real assertion verification
    ///   already ran, and only when this request COULD have reached one
    ///   ([`AuthorizationServer::assertion_could_be_verified`]) — a request every registration would
    ///   have refused before decoding a byte must not pay for a verification on either path.
    ///
    /// Both conditions are facts about `cred` and about work already done. NEITHER is a fact about
    /// the registration, and that is the whole property: no caller of this can make a refusal cheap
    /// by knowing something about the client.
    fn settle_credential_cost(&self, cred: &ClientCredential<'_>, paid: &CredentialCost) {
        if !paid.secret {
            self.dummy_verify(cred.client_secret);
        }
        #[cfg(feature = "client-assertion")]
        if !paid.assertion && Self::assertion_could_be_verified(cred) {
            self.dummy_assertion_verify();
        }
    }

    /// EXAMINE the presented credential and say what it amounts to. Charge nothing, record nothing,
    /// emit nothing: those belong to the single exit in
    /// [`AuthorizationServer::authenticate_client`], which is what keeps them from being forgotten.
    ///
    /// Every branch here is the one it was before this became a function of its own — the RFC 7591
    /// section 3.2.1 expiry gate, the RFC 7523 assertion path, the RFC 8705 mutual-TLS path and the
    /// shared-secret comparison, in that order — and each answers with a value instead of a wire
    /// refusal. `paid` is written by the two places that perform real verification work, so the exit
    /// can charge the remainder.
    async fn classify_client_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        paid: &mut CredentialCost,
    ) -> Result<ClientAuthVerdict, ErrorResponse> {
        let found = self
            .store
            .get_client(client_id)
            .await
            .map_err(storage_error)?;
        let client = match found {
            Some(client) => client,
            // THE COLLAPSE IS ALSO A TIMING PROPERTY. Answering here in the time of one store read,
            // while a real id additionally pays a full secret verification, enumerates the whole
            // registry at one request per candidate: under the shape `with_secret_verifier` exists
            // to serve — a `ConfidentialSecretHash` in a host scheme such as argon2id — that is
            // roughly two milliseconds against two hundred, and per-id throttling cannot see it
            // because the attacker never repeats an id. Nothing is charged HERE any more; the exit
            // charges it, for this refusal and for every other one, through the same `verify_with`
            // seam a real authentication uses. See `SecretVerifier::dummy_hash` for the half only
            // the host can supply.
            None => return Ok(ClientAuthVerdict::Refused(ClientAuthFailure::UnknownClient)),
        };
        // RFC 7591 section 3.2.1 `client_secret_expires_at`. THIS SERVER MINTS THAT VALUE AND
        // PUBLISHES IT TO THE REGISTRANT, and until this check existed it never looked at it again:
        // a secret this deployment had itself declared dead on the wire went on authenticating
        // forever. A rotation window a server announces and does not enforce is worse than none,
        // because the operator believes the old secret stopped working on the day the response
        // said it would.
        //
        // Checked HERE, before every credential branch below, rather than beside the secret
        // comparison: `client_secret_jwt` (RFC 7523) also authenticates with the shared secret, so
        // a check attached only to the direct comparison would let the same expired secret keep
        // working through the assertion path. A registration with no secret carries `None` and is
        // unaffected, and `private_key_jwt` and mutual TLS do not authenticate with a secret at
        // all, so refusing them here costs nothing they could have used.
        //
        // Section 3.2.1: `0` means the secret NEVER expires. It is not "expired at the epoch", and
        // reading it that way would break every registration that took the default.
        if let Some(registration) = &client.registration {
            if let Some(expires_at) = registration.client_secret_expires_at {
                let expired = expires_at != 0
                    && self
                        .clock
                        .now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|since| since.as_secs() >= expires_at)
                        // A clock before the epoch cannot say anything has expired yet, and is the
                        // host's problem rather than a reason to refuse a live credential.
                        .unwrap_or(false);
                if expired {
                    // NOTHING IS VERIFIED ON THIS PATH, and that is why it was once the fastest
                    // refusal in the function: an expired registration answered in the time of one
                    // store read while an unknown id paid a full `dummy_verify` through the host's
                    // scheme, so "fast" meant "this id is registered", the one fact the bare
                    // `invalid_client` exists to withhold. `paid` is untouched, so the exit charges
                    // exactly what the unknown-id refusal above charges for the same request.
                    return Ok(ClientAuthVerdict::Refused(ClientAuthFailure::SecretExpired));
                }
            }
        }

        // RFC 7523 client authentication, when the request presented an assertion. Handled apart
        // from the secret comparison below because it is a different KIND of credential: there is
        // nothing to compare, there is a signature to verify against the REGISTRATION's key and a
        // `jti` to spend so the request cannot be repeated.
        #[cfg(feature = "client-assertion")]
        if cred.client_assertion.is_some() {
            // NOT boxed, and that is a measurement rather than a style, in both directions.
            //
            // It WAS `Box::pin(..)` through 0.9.0: `authenticate_client` inlines into all four
            // grant helpers and so into the token future, which `tests/allocation.rs` holds under
            // tokio's 2048-byte debug boxing threshold, and inlining the assertion state (a claim
            // set, two owned Strings, a storage future) once pushed it over. It no longer does.
            // Measured both ways: 1144 under `client-assertion` alone, 1256 with `rar`, 1344 with
            // `dpop,mtls,consent,rar,par` and with `--all-features`, IDENTICAL boxed and unboxed,
            // because the token future's high-water mark moved elsewhere when the endpoint was
            // restructured (see `token_with_context`).
            //
            // What the box was still costing is one allocation on every token request that
            // presents an assertion, which for a `private_key_jwt` deployment is every token
            // request it makes: precisely the deployments RFC 7523 exists for, and the ones FAPI
            // 2.0 requires it of. `client_assertion_verification_bound` in
            // `tests/allocation_paths.rs` pins the result.
            let outcome = self.authenticate_by_assertion(&client, cred, paid).await;
            return Ok(match outcome {
                Ok(()) => ClientAuthVerdict::Authenticated(client),
                // The reason is carried to the audit channel by the single exit. The wire answer is
                // one bare `invalid_client` for every one of them, which is why there is nothing
                // here to choose between.
                Err(reason) => {
                    ClientAuthVerdict::Refused(ClientAuthFailure::AssertionInvalid { reason })
                }
            });
        }

        // RFC 8705 s2 mutual-TLS client authentication, handled apart from the secret
        // comparison below for the same reason the assertion above is: it is a different
        // KIND of credential. There is nothing to compare; there is a certificate the HOST
        // verified, matched against what the registration says it expects to see.
        //
        // Dispatched on the REGISTRATION, never on what the request happened to present.
        // That direction is load bearing in both senses: a certificate presented by a
        // secret-authenticating client never reaches this path (it is for section 3 binding
        // only), and a mutual-TLS client can never fall through to the secret comparison
        // below.
        #[cfg(feature = "mtls")]
        if matches!(client.auth, crate::client::ClientAuth::Mtls { .. }) {
            return Ok(match crate::mtls::verify_certificate(&client, cred) {
                Ok(()) => ClientAuthVerdict::Authenticated(client),
                // A thumbprint comparison is microseconds, so an mTLS registration handed a
                // posted `client_secret` refuses far faster than an unknown id pays
                // `dummy_verify`. `paid` is untouched — no secret was verified — so the exit
                // charges the dummy, and it does nothing at all for the `None` a real mutual-TLS
                // request carries, which leaves the legitimate path unchanged.
                Err(failure) => ClientAuthVerdict::Refused(failure),
            });
        }

        // WHICH REGISTRATIONS ACTUALLY VERIFY A SECRET, recorded BEFORE the call so the exit knows
        // what it still owes. `verify_with` answers `false` in nanoseconds for `Public` and for
        // `ConfidentialAssertion` (see the arms in `crate::client`: there is no presented string
        // that could be right for either), so a request posting junk as `client_secret` separated
        // those registrations from an unknown id by wall time alone — and the unknown id was the
        // SLOW one, argon2id milliseconds against nanoseconds under a host scheme. The two kinds
        // that DO verify are marked paid, so they are never charged twice.
        paid.secret = matches!(
            client.auth,
            crate::client::ClientAuth::ConfidentialSecret { .. }
                | crate::client::ClientAuth::ConfidentialSecretHash { .. }
        );
        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this
        // crate does not implement is decided by the host's verifier (see
        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.
        if !client
            .auth
            .verify_with(cred.client_secret, self.hooks.secret_verifier())
        {
            return Ok(ClientAuthVerdict::Refused(
                ClientAuthFailure::SecretMismatch,
            ));
        }
        Ok(ClientAuthVerdict::Authenticated(client))
    }

    /// RFC 7523 section 3, plus the single-use claim that makes it worth anything.
    ///
    /// Returns `Ok(())` for an authenticated client. Every refusal is the SAME bare
    /// `invalid_client` the wrong-secret path returns, with no description: this function is only
    /// reached once the client id is known to exist, so a description naming which check failed
    /// would be the difference between "this client id is real" and "it is not", which is exactly
    /// the distinction `authenticate_client` collapses on purpose. The host's audit channel is
    /// told (`ClientAuthFailure::AssertionInvalid { reason }`); the wire is not.
    ///
    /// RETURNS THE REASON rather than a built `ErrorResponse`, which is what makes that sentence
    /// true. Every refusal here is byte for byte the same bare `invalid_client`, so there was
    /// nothing for the caller to choose between and the `ErrorResponse` was constructed here only
    /// to be discarded by a `map_err(|_| ..)` that also discarded the `AssertionFailure` with it.
    /// The caller builds the one response and emits the reason, so the audit channel gets what
    /// `AssertionFailure` documents itself as existing for.
    #[cfg(feature = "client-assertion")]
    async fn authenticate_by_assertion(
        &self,
        client: &Client,
        cred: &ClientCredential<'_>,
        paid: &mut CredentialCost,
    ) -> Result<(), crate::client_assertion::AssertionFailure> {
        use crate::client_assertion::AssertionFailure;
        // THE THREE REFUSALS THAT PRECEDE ANY DECODING ARE ONE EXPRESSION, and it is the SAME
        // expression `authenticate_client` uses to decide whether to charge the assertion dummy on
        // the unknown-id path. They were three separate `if`s here and a predicate there, kept in
        // step by a comment, and a comment cannot hold an invariant across two functions.
        //
        // WHAT THAT COSTS WHEN IT DRIFTS — and the history matters, because 0.9.2 changed WHERE
        // this is paid and an auditor should not read the danger below as a hole 0.9.1 shipped.
        // `authenticate_client` enters this function on `cred.client_assertion.is_some()` ALONE,
        // so a request carrying an assertion AND a `client_secret` arrives here and is refused by
        // the RFC 6749 section 2.3 check below in nanoseconds. The UNKNOWN id sending identical
        // bytes takes the not-found arm, which charges `dummy_verify(cred.client_secret)`
        // unconditionally, and with a secret present that runs the host's `SecretVerifier` scheme:
        // argon2id milliseconds against nanoseconds. The assertion dummy balances nothing there,
        // because `assertion_could_be_verified` is false when a secret is present. One request per
        // candidate id, never repeated, sorts registered ids from unregistered ones, which is the
        // enumeration the whole mechanism exists to close.
        //
        // THAT STATE EXISTED DURING 0.9.1'S AUDIT ROUNDS AND WAS NOT RELEASED IN ONE. Released
        // 0.9.1 closed it HERE, with a `self.dummy_verify(cred.client_secret)` immediately before
        // the `Malformed` return below, so the known and unknown ids paid the same call for the
        // same request. (0.9.0 is a different shape again: it had no dummy verification anywhere,
        // so there was no asymmetry of this kind to have — the whole balancing mechanism arrived
        // in 0.9.1.) What 0.9.2 changed is that the charge is no longer made at this site, or at
        // the second site further down: see below.
        //
        // The three conditions, and why each refuses before anything is read:
        //
        // - An assertion has to be present at all.
        // - RFC 7521 section 4.2: the type is what says which assertion format this is, and this
        //   server implements exactly one. An absent or unrecognised type is refused rather than
        //   assumed, because assuming would mean verifying a credential in a format nobody
        //   declared.
        // - RFC 6749 section 2.3: "The client MUST NOT use more than one authentication method in
        //   each request." A request carrying both a secret and an assertion has not said which
        //   credential it means, and a server that picks one behaves differently from the next
        //   server, which is exactly the ambiguity an intermediary would exploit.
        //
        // All three answered `AssertionFailure::Malformed` before and all three answer it now:
        // there is no more specific variant for "this server will not read the string it was
        // handed", and the wire answer was one bare `invalid_client` for every one of them anyway.
        // So collapsing them changes what is SPENT and nothing else, on the wire or in the audit
        // channel.
        //
        // NOTHING IS CHARGED HERE ANY MORE, by either half of this function: `paid` is untouched on
        // every refusal below that did no verification, and the single exit in
        // `authenticate_client` spends what such a request would have spent. That is the 0.9.2
        // change, and it is a change of PLACE rather than of amount: 0.9.1 made two charges from
        // inside this function — a `dummy_verify` at the `Malformed` return just below, and a
        // `dummy_assertion_verify` in the `WrongPrincipal` arm after it — and each got its own
        // case right while neither could see what the other, or `authenticate_client`, had already
        // spent. `CredentialCost` is what a single exit needs in order to know.
        if !Self::assertion_could_be_verified(cred) {
            return Err(AssertionFailure::Malformed);
        }
        let assertion = cred.client_assertion.ok_or(AssertionFailure::Malformed)?;

        // THE REGISTRATION DECIDES, and this is where that starts. A client registered for
        // `client_secret_basic` cannot promote itself to `private_key_jwt` by sending an assertion,
        // because there is no key here that anybody vouched for on its behalf.
        let keys = match &client.auth {
            crate::client::ClientAuth::ConfidentialAssertion { keys } => keys,
            // The registration does not authenticate this way at all, so there is no key any
            // assertion could have been signed with. `WrongPrincipal` is the closest true
            // statement: the party this credential claims to be is not the party it names.
            // NOTHING WAS VERIFIED, so `paid.assertion` stays false and the exit charges
            // `dummy_assertion_verify` for it. A registered id that does not use assertions
            // answering in nanoseconds, while an unknown id sending identical bytes paid a full
            // verification, is the registration KIND readable off the clock — and the kind is
            // exactly what such a probe is after, so the known path has to pay too.
            _ => return Err(AssertionFailure::WrongPrincipal),
        };

        // RFC 7523 section 3 (3) admits either the token endpoint URL or, by long-established
        // practice (OpenID Connect Core section 9), the issuer identifier.
        //
        // The verifier is resolved and PASSED ALONG rather than required here, because only one of
        // the two methods needs one. `private_key_jwt` is ES256 and `verify_assertion` refuses it
        // on a `None` (an unchecked credential has authenticated nobody). `client_secret_jwt` is
        // an HS256 HMAC over the registered secret and touches no curve at all, so requiring a
        // backend on that path refused a valid credential for a reason no RFC gives. Which one
        // this registration is, is `client.auth`'s to say, and `AssertionKeys` is what says it.
        // CHARGED AS PAID AT THE CALL, not at its result. Every outcome from here on is one the
        // unknown-id path prices with a single `dummy_assertion_verify`, so charging a second one on
        // top would make a KNOWN id the slower of the two — which is how round 8 broke round 7. The
        // one gap this leaves is the refusals `verify_assertion` makes before it reaches a
        // signature; see the FOURTH residual on `authenticate_client`, and `CredentialCost`.
        paid.assertion = true;
        let verified = verify_assertion(
            self.es256_verifier(),
            keys,
            assertion,
            client.client_id.as_str(),
            &[self.token_endpoint(), self.issuer_identifier()],
            self.clock.now(),
        )?;

        // RFC 7523 section 3: the `jti` is single use within the assertion's validity. THIS is the
        // check that makes an observed request unrepeatable, and it is the whole difference between
        // an authentication mechanism and a bearer credential that happens to be signed. It is
        // namespaced by client id so that two clients choosing the same `jti` (a counter, a
        // timestamp) cannot lock each other out.
        let claimed = self
            .store
            .claim_replay_id(
                &replay_key("ca", client.client_id.as_str(), &verified.jti),
                verified.expires_at,
            )
            .await
            // FAILING CLOSED. A claim that could not be recorded is a claim that did not happen,
            // and treating a storage outage as "probably fine" would turn every assertion into a
            // replayable one for the duration of the outage.
            //
            // REPORTED AS ITS OWN REASON, and not as `Replayed`, which is what it was through
            // 0.9.0. The wire answer is identical either way (`invalid_client`), so this is
            // entirely a question about the audit channel, and there the two are opposites:
            // `Replayed` is documented as a captured-and-replayed assertion, which
            // `crate::events` calls "a different incident and a much worse one", while this is the
            // store being unreachable. An outage fails EVERY `private_key_jwt` client at once, so
            // the mislabel fired a burst of this crate's worst-incident signal at the exact moment
            // an operator was reading the channel to find out what had broken. The DPoP twin below
            // propagates the same failure with `map_err(storage_error)`.
            .map_err(|_| AssertionFailure::ReplayCheckUnavailable)?;
        if !claimed {
            return Err(AssertionFailure::Replayed);
        }
        Ok(())
    }

    /// The token endpoint URL this server answers on, which is what RFC 7523 section 3 (3) and RFC
    /// 9449 section 4.3 (7) compare against.
    ///
    /// Derived the same way `AuthorizationServerMetadata::from_config` derives it, and it MUST stay
    /// that way: the document tells a client where to send its request and what to put in `aud` and
    /// `htu`, so a server whose own idea of its token endpoint differs from the one it published
    /// refuses every conforming client.
    ///
    /// PRECOMPUTED at construction (see [`AuthorizationServer::with_clock`]) and borrowed here.
    /// The value is fixed for the life of the server, and this is called once per RFC 9449 proof
    /// verification and once per RFC 7523 assertion verification, so a `private_key_jwt` client
    /// sending DPoP paid two `format!`s of a constant on every token request. The crate already
    /// precomputes the metadata document, the JWKS and the JOSE header for exactly this reason.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    /// RFC 9449 section 4.3, and the single-use claim on the proof's `jti`.
    ///
    /// The proof is checked BEFORE the grant is looked at, because it binds to the REQUEST rather
    /// than to the grant: a proof that does not verify means this request is refused whatever it
    /// asked for, and spending its `jti` here means a replayed proof costs the attacker a lookup
    /// and gains them nothing.
    ///
    /// `htm` is `POST` because RFC 6749 section 3.2 makes the token endpoint POST-only, and `htu`
    /// is this server's own token endpoint rather than something the host passes in. That is
    /// deliberate: the value a conforming client puts in `htu` is the one it read from the RFC 8414
    /// document, which is exactly what `token_endpoint` returns, so taking it from the host would
    /// add a seam whose only possible use is to get it wrong.
    #[cfg(feature = "dpop")]
    async fn verify_dpop(&self, proof: Option<&str>) -> Result<Option<Box<str>>, ErrorResponse> {
        let proof = match proof {
            Some(proof) => proof,
            None if self.config.require_dpop => {
                return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)
                    .with_description("this server requires a DPoP proof on every token request"))
            }
            None => return Ok(None),
        };
        // Resolved BEFORE the proof is parsed: with no backend there is nothing that could make
        // this proof acceptable, so an unauthenticated caller does not get to spend a base64 decode
        // and a JSON parse finding that out.
        let verifier = self.es256_verifier().ok_or_else(|| {
            // EMITTED, and this is the refusal it matters most to emit. `jwt` carries the verifier
            // seam and `jwt-p256` carries the arithmetic, so a build with `dpop` and neither an
            // installed verifier nor that backend refuses EVERY proof: the deployment is
            // misconfigured, not the client, and through 0.9.0 this was the one refusal the audit
            // channel never heard about at all. `UnsupportedAlgorithm` is the honest reading of
            // `DpopFailure`'s existing vocabulary — with no backend, ES256 is not an algorithm
            // this build accepts, whatever `dpop_signing_alg_values_supported` advertises.
            self.hooks.emit(|| Event::DpopProofRefused {
                failure: crate::dpop::DpopFailure::UnsupportedAlgorithm,
            });
            // BARE, like the nine section 4.3 checks below. The event above carries the reason,
            // which is where `dpop.rs` says the distinction belongs; the description would have
            // put it on the wire, and `verify_dpop` runs BEFORE any client authentication, so an
            // anonymous caller could read a deployment misconfiguration off a refusal.
            ErrorResponse::new(ErrorCode::InvalidDpopProof)
        })?;
        let verified = verify_proof(
            verifier,
            proof,
            "POST",
            self.token_endpoint(),
            self.clock.now(),
        )
        // THE REASON GOES TO THE AUDIT CHANNEL, and until 0.9.1 it went nowhere: this arm was
        // `map_err(|_| ..)` and no event was emitted at all, against `dpop.rs`'s statement that
        // "the distinction here is for the host's audit channel, not for the wire". A deployment
        // could therefore not tell a client with a skewed clock (`StaleProof`) from one whose
        // proofs are being captured and replayed (`Replayed`), which are a configuration problem
        // and an incident.
        .map_err(|failure| {
            self.hooks.emit(|| Event::DpopProofRefused { failure });
            ErrorResponse::new(ErrorCode::InvalidDpopProof)
        })?;
        // Namespaced by THUMBPRINT rather than by client id: a proof is bound to a key, not to a
        // registration (a public client's proof arrives before anything has authenticated), so the
        // key is the only identity available at this point that an attacker cannot choose freely.
        let claimed = self
            .store
            .claim_replay_id(
                &replay_key("dpop", &verified.jkt, &verified.jti),
                verified.replay_until,
            )
            .await
            .map_err(storage_error)?;
        if !claimed {
            // The single-use check is one of RFC 9449 section 4.3's, so its failure is reported
            // through the same channel as the nine `verify_proof` performs. It was the one
            // `DpopFailure::Replayed` nothing ever produced.
            self.hooks.emit(|| Event::DpopProofRefused {
                failure: crate::dpop::DpopFailure::Replayed,
            });
            // BARE, for the reason the no-verifier arm above gives and one more of its own. This
            // path is reached without authentication, and "already used" told an anonymous caller
            // that the proof they presented is in the replay cache, which confirms that its
            // signature, `htu`, `htm` and `iat` all PASSED: a captured proof could be tested for
            // freshness against the server that would otherwise have accepted it. The event
            // carries `DpopFailure::Replayed` to the host, which is the whole distinction.
            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof));
        }
        Ok(Some(verified.jkt.into_boxed_str()))
    }

    /// The registered default, TRIMMED to what the registration also says may ever be granted.
    ///
    /// The trim is a fix for a defect the 0.9.1 rotation ceiling created rather than a
    /// belt-and-braces check. Nothing had ever compared `default_scopes` with `allowed_scopes`:
    /// both are plain public fields on [`crate::client::Client`], and a registration can reach a
    /// host's store without passing through [`AuthorizationServer::register_client`] at all. So a
    /// registration whose default exceeded its own allowance granted the default, and then
    /// [`AuthorizationServer::refresh_token`]'s ceiling refused the first rotation with
    /// `invalid_scope` and did NOT put the record back, destroying the chain permanently. That
    /// ceiling's premise is that "the client asked to continue a grant this server is no longer
    /// willing to honour", and the premise is false here: an identical fresh authorization request
    /// naming no scope mints the same grant again. Trimming is the reading that makes the two
    /// halves agree, and it is the fail-closed one: what is granted is exactly what the
    /// registration says may ever be granted.
    ///
    /// Written as a guarded clone so the OVERWHELMINGLY common case is byte for byte what this
    /// always did. THE SECOND ARM IS REACHABLE AND IS NOT DEAD CODE: `register_client` does NOT
    /// refuse a registration whose `default_scopes` exceed its `allowed_scopes`, deliberately, and
    /// says why in its own body -- narrowing `allowed_scopes` alone is exactly how an operator
    /// corrects an over-broad registration, and refusing that would turn a security control into
    /// an error message. This trim is what makes that safe, so deleting it as unreachable
    /// reintroduces the defect the paragraph above describes.
    ///
    /// Called from BOTH places the RFC 6749 section 3.3 default is applied, which is the other
    /// half of the fix: the authorization endpoint had its own copy of "absent means the registered
    /// default", and a rule with two implementations is a rule that drifts.
    fn granted_default_scope(client: &Client) -> ScopeSet {
        if client.default_scopes.is_subset(&client.allowed_scopes) {
            return client.default_scopes.clone();
        }
        ScopeSet::from_tokens(
            client
                .default_scopes
                .iter()
                .filter(|s| client.allowed_scopes.contains(s.as_str()))
                .map(|s| s.as_str()),
        )
        // Unreachable: every token here came out of a `ScopeSet` and so parsed once already.
        .unwrap_or_else(|_| ScopeSet::empty())
    }

    /// Resolve the scope a request will be granted: the client default when the request names
    /// none, otherwise the request, which must sit inside the registration's allowed set.
    fn resolve_scope(
        client: &Client,
        requested: Option<&ScopeSet>,
    ) -> Result<ScopeSet, ErrorResponse> {
        match requested {
            // INTERSECTED, not taken whole, and that is a fix for a defect the 0.9.1 rotation
            // ceiling created rather than a belt-and-braces check. Nothing had ever compared
            // `default_scopes` with `allowed_scopes`: both are plain public fields on
            // `crate::client::Client`, and a registration can reach a host's store without passing
            // through `register_client` at all. So a registration whose default exceeded its own
            // allowance granted the default, and then `refresh_token`'s ceiling refused the first
            // rotation with `invalid_scope` and did NOT put the record back, destroying a chain
            // permanently. That ceiling's premise is that "the client asked to continue a grant
            // this server is no longer willing to honour", and that premise is false here: an
            // identical fresh authorization request naming no scope mints the same grant again.
            // Intersecting is the only reading that makes the two halves agree, and it is the
            // fail-closed one: what is granted is exactly what the registration says may ever be
            // granted. `register_client` does NOT refuse the disagreement -- see its body for why
            // not, and `granted_default_scope` for why this trim is therefore load bearing rather
            // than defensive.
            None => Ok(Self::granted_default_scope(client)),
            Some(s) if s.is_subset(&client.allowed_scopes) => Ok(s.clone()),
            // NB: descriptions must stay inside the RFC 6749 section 5.2 charset (no double
            // quote, no backslash), which scope tokens themselves already satisfy.
            // BORROWED, not built. This refusal is reachable by an UNAUTHENTICATED caller at the
            // authorization endpoint, at whatever rate they choose, and the `format!` this replaced
            // allocated a String and echoed the caller's own scope string into it. `tests/
            // allocation.rs` states the rule on `refused_token_request_allocation_bound`: a refusal
            // is work the attacker buys, so it does not get to buy a heap allocation. Roughly fifty
            // other refusal sites in this crate already hand back a `&'static str`; this one was
            // the exception. The developer who sent it still learns which parameter was wrong,
            // which is all RFC 6749 section 5.2 asks of `error_description`, and not echoing the
            // value back keeps it out of the host's logs as well.
            Some(_) => Err(ErrorResponse::new(ErrorCode::InvalidScope)
                .with_description("requested scope exceeds the client registration")),
        }
    }

    /// RFC 8628 section 3.1/3.2: start a device authorization.
    pub async fn device_authorization(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        self.device_authorization_with_credential(
            client_id,
            &ClientCredential::secret(client_secret),
            requested_scope,
        )
        .await
    }

    /// RFC 8628 section 3.1/3.2 for a client authenticating with any credential this server
    /// accepts, including an RFC 7523 assertion.
    ///
    /// Added ALONGSIDE [`AuthorizationServer::device_authorization`] rather than replacing it: the
    /// three-argument form is what every existing host already calls and a shared secret remains
    /// the commonest credential. Both go through the same `authenticate_client`, so there is one
    /// authentication path and not two.
    pub async fn device_authorization_with_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        // STAMPED BEFORE THE REGISTRATION IS READ, for the reason `client_credentials_token`
        // states at length: `created_at` is the instant a revocation barrier compares this grant
        // against at redemption, so it must predate the read the write is derived from. Taking it
        // after `authenticate_client` would date the grant later than a `delete_client` landing in
        // that window, and the comparison would then admit a token for a registration deleted
        // before the grant was even written.
        //
        // The device flow makes that worse than elsewhere, which is why it is worth the extra
        // line: `put_device_grant` consults no barrier at all, the approval that follows is a
        // compare-and-swap against a record that is present, and a device client is typically
        // PUBLIC — so a host re-provisioning the same `client_id` needs no secret for the polling
        // device to redeem it.
        let created_at = self.clock.now();

        let client = self.authenticate_client(client_id, cred).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
                .with_description("client registration does not include the device_code grant"));
        }
        let scope = Self::resolve_scope(&client, requested_scope)?;

        let now = self.clock.now();
        // `?` rather than a panic: this is an unauthenticated-shaped request path like any
        // other, and an OS that will not hand over 32 bytes is a `server_error`, not a reason to
        // abort the host's process. See `try_random_hex`.
        let device_code = try_random_hex(32).ok_or_else(randomness_error)?;
        let user_code = self.unique_user_code().await?;
        let grant = DeviceGrant {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: client.client_id.clone(),
            scope,
            state: DeviceGrantState::Pending,
            // Read at request ENTRY, above, not here. `expires_at` below stays measured from the
            // write, because the TTL is a promise about how long the user has to type the code.
            created_at,
            expires_at: saturating_deadline(now, self.config.device_code_ttl),
            interval: self.config.poll_interval,
            last_poll_at: None,
        };
        self.store
            .put_device_grant(grant)
            .await
            .map_err(storage_error)?;

        let verification_uri_complete = self.config.include_verification_uri_complete.then(|| {
            // RFC 8628 s3.3.1: this is a DEEP LINK whose only job is to prefill the code, so
            // a `?` appended to a `verification_uri` that already carries a query does not
            // merely look wrong — it folds the code into the previous parameter's value and
            // the page prefills nothing. The same helper every authorization-response URL in
            // this crate uses, rather than a second answer to the same question.
            format!(
                "{}{}user_code={}",
                self.config.verification_uri,
                crate::authorization::query_separator(&self.config.verification_uri),
                user_code
            )
        });
        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri: self.config.verification_uri.clone(),
            verification_uri_complete,
            expires_in: self.config.device_code_ttl.as_secs(),
            interval: self.config.poll_interval.as_secs(),
        })
    }

    /// Draw a user code that no live grant already answers to.
    ///
    /// RFC 8628 section 6.1 sizes the user code for a human to type, which is exactly why it is
    /// short enough to collide: the birthday bound at the floor length is in the low hundreds of
    /// thousands of concurrent live grants. An accepted collision is not a cosmetic problem, it is
    /// two devices sharing one credential, and it corrupts the store's index for both.
    ///
    /// The draw is checked, not assumed. The check is advisory (another grant can be written
    /// between the lookup and the put), which is why [`Storage::put_device_grant`] is REQUIRED to
    /// refuse a collision outright: this loop keeps the common case cheap, the store keeps it
    /// correct.
    async fn unique_user_code(&self) -> Result<String, ErrorResponse> {
        // Clamped, not honoured: see `ServerConfig::user_code_length`.
        let len = self.config.user_code_length.max(MIN_USER_CODE_LENGTH);
        for _ in 0..USER_CODE_GENERATION_ATTEMPTS {
            // `None` is the OS refusing randomness, which is the same `server_error` the
            // storage failures in this loop become rather than a panic on a request path.
            let raw = random_user_code(len).ok_or_else(randomness_error)?;
            // The store indexes NORMALIZED codes, and `raw` is already the normalized form (the
            // alphabet is upper case and carries no hyphen), so this needs no second pass.
            if self
                .store
                .find_device_grant_by_user_code(&raw)
                .await
                .map_err(storage_error)?
                .is_none()
            {
                return Ok(display_user_code(&raw));
            }
        }
        Err(ErrorResponse::new(ErrorCode::ServerError)
            .with_description("could not allocate an unused user code"))
    }

    /// Fetch a still-live pending grant by entered user code, for the verification UI actions,
    /// with the RFC 8628 section 5.1 throttle around it.
    ///
    /// `check` runs BEFORE the lookup, so a refused attempt learns nothing, and the outcome is
    /// reported back afterwards because a guessing attack is visible in FAILURES, not in traffic.
    /// Every rejection this can produce (unknown code, expired, already used) is counted the same
    /// way: an attacker enumerating codes does not care which one they get.
    async fn pending_grant_by_user_code(
        &self,
        entered_user_code: &str,
    ) -> Result<DeviceGrant, DeviceApprovalError> {
        let attempt = Attempt::DeviceUserCodeEntry;
        if self.hooks.check(attempt) == RateLimitDecision::Deny {
            return Err(DeviceApprovalError::RateLimited);
        }
        let outcome = self
            .lookup_pending_grant_by_user_code(entered_user_code)
            .await;
        self.hooks.record(
            attempt,
            if outcome.is_ok() {
                AttemptOutcome::Succeeded
            } else {
                AttemptOutcome::Failed
            },
        );
        outcome
    }

    /// The lookup itself, split out so the throttle above wraps every exit from it.
    async fn lookup_pending_grant_by_user_code(
        &self,
        entered_user_code: &str,
    ) -> Result<DeviceGrant, DeviceApprovalError> {
        let normalized = normalize_user_code(entered_user_code);
        let grant = self
            .store
            .find_device_grant_by_user_code(&normalized)
            .await
            .map_err(DeviceApprovalError::Storage)?
            .ok_or(DeviceApprovalError::UnknownUserCode)?;
        if self.clock.now() >= grant.expires_at {
            // Expired: remove it so the user-facing answer and the poll path agree the code is
            // gone; the device's next poll will already find nothing (invalid_grant), which is
            // indistinguishable from a spent code and fine either way.
            let _ = self.store.take_device_grant(&grant.device_code).await;
            return Err(DeviceApprovalError::Expired);
        }
        if grant.state != DeviceGrantState::Pending {
            return Err(DeviceApprovalError::NotPending);
        }
        Ok(grant)
    }

    /// The host's verification UI approves a grant for `subject` (the authenticated user).
    ///
    /// # The host MUST rate limit calls to this
    ///
    /// RFC 8628 section 5.1 is explicit that the user code's entropy is sufficient only IN
    /// COMBINATION WITH rate limiting: the code is short because a human types it, and an
    /// unthrottled verification endpoint turns "short enough to type" into "short enough to
    /// enumerate".
    ///
    /// This crate CAN throttle this call, and does: the first thing this method does is
    /// `pending_grant_by_user_code`, which asks the installed [`RateLimiter`] about an
    /// [`crate::events::Attempt::DeviceUserCodeEntry`] BEFORE the code is looked up, and reports
    /// the outcome back afterwards. [`DeviceApprovalError::RateLimited`] is what a refusal looks
    /// like from here. A limiter is shipped ([`crate::rate_limit::FixedWindowRateLimiter`]), and
    /// the crate's own `http` service installs nothing by default, so a host that installs none
    /// gets none. This paragraph said the opposite through 0.9.1 — "performs NO rate limiting and
    /// cannot" — which was a promise of absence beside code that consults the throttle on its
    /// first statement, and is the kind of doc that gets a host to build a second throttle or,
    /// worse, to conclude the risk is unavoidable.
    ///
    /// What remains the HOST's, and it is the important half: this crate has no notion of a
    /// caller, an IP, a session or a user, so it can only key the throttle on what it is given.
    /// An attacker who spreads guesses across the whole code space from many sources is visible
    /// to the host and not to this crate. Without a limiter installed, [`MIN_USER_CODE_LENGTH`]
    /// symbols is a guessing exercise, not a credential.
    pub async fn approve_device(
        &self,
        entered_user_code: &str,
        subject: impl Into<String>,
    ) -> Result<(), DeviceApprovalError> {
        let mut grant = self.pending_grant_by_user_code(entered_user_code).await?;
        let subject = subject.into();
        // Cloned ONLY when a sink is installed: `grant` is consumed by the put below, so the
        // event's fields have to be captured first, and an unobserved host must not pay for that.
        let audit = self
            .hooks
            .is_observed()
            .then(|| (grant.client_id.clone(), subject.clone()));
        grant.state = DeviceGrantState::Approved { subject };
        // COMPARE-AND-SWAP against `Pending`, never a blind put. The read above and this write are
        // separated by however long the host's store takes, and this is not the only writer: a
        // DENIAL from a second verification-UI action, or a poll, can land in between. A blind put
        // resolves that by whoever writes last, which for two decisions on one user code is
        // arbitrary, and the arbitrary direction that matters is an approval overwriting a refusal
        // the user already gave. FIRST DECISION WINS instead.
        //
        // `NotPending` rather than a new variant: it is the answer this call would have given had
        // it arrived a moment later and read the decided grant, so the host's verification UI needs
        // no new case to handle a race it could already reach by being slow.
        if !self
            .store
            .compare_and_swap_device_grant(&DeviceGrantState::Pending, grant)
            .await
            .map_err(DeviceApprovalError::Storage)?
        {
            return Err(DeviceApprovalError::NotPending);
        }
        // Emitted AFTER the write: an approval that failed to persist did not happen, and an audit
        // log that says otherwise is worse than none.
        if let Some((client_id, subject)) = &audit {
            self.hooks.emit(|| Event::DeviceGrantApproved {
                client_id: client_id.as_str(),
                subject,
            });
        }
        Ok(())
    }

    /// The host's verification UI records the user's refusal.
    ///
    /// The same RFC 8628 section 5.1 obligation as [`AuthorizationServer::approve_device`] applies:
    /// this path also tells a caller whether a code exists, so the HOST must rate limit it too. An
    /// attacker enumerating codes does not care which of the two endpoints answers.
    pub async fn deny_device(&self, entered_user_code: &str) -> Result<(), DeviceApprovalError> {
        let mut grant = self.pending_grant_by_user_code(entered_user_code).await?;
        let audit = self.hooks.is_observed().then(|| grant.client_id.clone());
        grant.state = DeviceGrantState::Denied;
        // Same compare-and-swap, same reason: see `approve_device`. First decision wins in both
        // directions, so a refusal cannot overwrite an approval either.
        if !self
            .store
            .compare_and_swap_device_grant(&DeviceGrantState::Pending, grant)
            .await
            .map_err(DeviceApprovalError::Storage)?
        {
            return Err(DeviceApprovalError::NotPending);
        }
        if let Some(client_id) = &audit {
            self.hooks.emit(|| Event::DeviceGrantDenied {
                client_id: client_id.as_str(),
            });
        }
        Ok(())
    }

    /// The token endpoint (RFC 6749 section 3.2; device grant per RFC 8628 section 3.4/3.5), for a
    /// request that names no RFC 8707 resource indicator.
    ///
    /// Equivalent to [`AuthorizationServer::token_with_resources`] with an empty list, which is
    /// what a token request carrying no `resource` parameter means: no NARROWING is asked for, so
    /// the issued token inherits whatever the grant already carries.
    ///
    /// # THIS FUTURE IS NOT CANCELLATION SAFE, and what a drop costs
    ///
    /// Applies equally to [`AuthorizationServer::token_with_resources`] and
    /// [`AuthorizationServer::token_with_context`], which are the same future.
    ///
    /// A Rust future stops at whatever `await` it is suspended in when it is dropped, and it never
    /// resumes. Two grants reached through here are TAKE-THEN-WRITE sequences, meaning they remove
    /// a single-use credential from the store and then persist what that credential became. A drop
    /// between the two leaves the first half done and nothing to finish it, and the crate cannot
    /// make a dropped future complete: there is no destructor that can run an `async` store call.
    /// So the CONTRACT is stated here rather than silently relied on, because until 0.9.1 a host
    /// had no way to learn it.
    ///
    /// Named exactly, because the cost differs:
    ///
    /// - `authorization_code`. The code is TAKEN (RFC 6749 s4.1.2's one-time use), then a CONSUMED
    ///   record is written, then the tokens are issued, then that record is updated with what they
    ///   were. A drop between the take and the consumed write is the most expensive one in the
    ///   crate: the code is gone, so it cannot be redeemed twice, but RFC 9700 s4.1.1 replay
    ///   DETECTION works by recognising a code that was already redeemed, and this leaves no record
    ///   to recognise. A later replay of a code that leaked into a log, a `Referer` header or
    ///   browser history reads as an unknown string, permanently and silently, for that grant. The
    ///   write order was chosen to make a store FAILURE fall this way round rather than the other,
    ///   and a drop lands in the same window that ordering shrank; it cannot close it.
    /// - `refresh_token`. The presented token is TAKEN, then a SPENT record is written, then the
    ///   rotated chain is issued. A drop between the take and the spent write destroys the client's
    ///   chain (the string it holds is gone and no replacement was persisted, so the user
    ///   authenticates again) and loses the RFC 9700 s4.14.2 reuse marker for it, which is the same
    ///   loss as above: a later presentation of that token is an unknown string rather than
    ///   evidence of compromise, so it revokes no family.
    /// - The device grant's successful poll takes its grant record before issuing, with the same
    ///   shape and the same cost as the code path.
    ///
    /// WHAT A HOST MUST DO. Drive this from a task the connection cannot cancel, and await THAT:
    /// spawn the call and await the join handle, so a disconnecting client aborts the response and
    /// not the work. This crate's own axum adapter does exactly that; see [`crate::http`]. A host
    /// that instead selects this future against a timeout, a shutdown signal, or a connection
    /// watcher is choosing every cost listed above, and choosing it at whatever rate its clients
    /// disconnect.
    pub fn token(
        &self,
        request: TokenRequest,
    ) -> impl std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + '_ {
        self.token_with_resources(request, &[])
    }

    /// The token endpoint with the RFC 8707 `resource` parameter.
    ///
    /// `resources` is the (possibly repeated) `resource` parameter from the token request, in wire
    /// order. It is a separate argument rather than a field on every [`TokenRequest`] variant on
    /// purpose: RFC 8707 section 2 defines `resource` as a parameter of the token REQUEST,
    /// independent of `grant_type`, so putting it on each variant would state the same thing four
    /// times, grow the enum every host copies around, and make every future grant type repeat it
    /// again.
    ///
    /// What it does depends on the grant, and section 2 is what decides:
    ///
    /// - `authorization_code` and `refresh_token` may NARROW to a subset of what the authorization
    ///   request obtained, and never widen it;
    /// - `client_credentials` has no prior authorization request, so its resources are simply
    ///   validated and used;
    /// - `urn:ietf:params:oauth:grant-type:device_code` refuses any resource with `invalid_target`.
    ///   The device authorization request (RFC 8628 section 3.1) does not accept `resource` in this
    ///   crate yet, so there is nothing granted for a poll to narrow to, and inventing an audience
    ///   at the token endpoint that the user never approved is exactly what the narrowing rule
    ///   exists to prevent.
    pub fn token_with_resources<'a>(
        &'a self,
        request: TokenRequest,
        resources: &'a [String],
    ) -> impl std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + 'a {
        self.token_with_context(
            request,
            TokenRequestContext {
                resources,
                ..Default::default()
            },
        )
    }

    /// The token endpoint with everything about the request that does not belong inside
    /// [`TokenRequest`]: the RFC 8707 resource indicators, the RFC 7523 client assertion, and the
    /// RFC 9449 DPoP proof.
    ///
    /// [`AuthorizationServer::token`] and [`AuthorizationServer::token_with_resources`] are this
    /// with an emptier context, so there is one implementation of the token endpoint and not three.
    /// Both of them are plain functions returning THIS future rather than `async fn`s that await
    /// it, and that is a measurement rather than a style: an `async fn` wrapper is a second
    /// generator frame holding its own copy of the 120-byte [`TokenRequest`] while the inner future
    /// holds another, and adding one pushed the token future over tokio's 2048-byte debug boxing
    /// threshold. `tests/allocation.rs` caught it.
    ///
    /// # Why THIS one is a plain function too, and not an `async fn`
    ///
    /// The same measurement, one level down, and it is the largest single saving on this path.
    /// An `async fn` stores its parameters TWICE: once as the coroutine's upvars, which is where
    /// they live before the first poll, and again as the locals they are moved into on that first
    /// poll. rustc does not overlay the two, so `request` (120 bytes) and `context` (104 bytes)
    /// were each counted twice for the whole life of the future. A plain function returning an
    /// `async move` block captures each ONCE, as an upvar the body reads directly.
    ///
    /// Measured on the RFC 6749 s4.1.3 arm, which is the widest: 2056 bytes as an `async fn`
    /// against 1824 as a block, both `--all-features`. The first of those is past tokio's
    /// threshold and costs a 2 KB heap allocation on every single token request.
    ///
    /// The client secret may be presented EITHER on the [`TokenRequest`] variant (where it has
    /// always lived) or on [`TokenRequestContext::credential`]; the context wins when both are set,
    /// and neither is silently dropped.
    // `manual_async_fn` is exactly the simplification this function must NOT take: see the
    // measurement in the doc comment above. An `async fn` here stores `request` and `context`
    // twice over and puts the token future past tokio's debug boxing threshold.
    #[allow(clippy::manual_async_fn)]
    pub fn token_with_context<'a>(
        &'a self,
        request: TokenRequest,
        context: TokenRequestContext<'a>,
    ) -> impl std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + 'a {
        async move {
            let requested_resources =
                self.validate_resources(context.resources.iter().map(|r| r.as_str()))?;
            // RFC 9396 s5 and s6, parsed and type-checked ONCE here for the same reason the
            // resource indicators are validated once here: it is a parameter of the token
            // request itself, not of any one grant. The s5 type check has to run at THIS
            // endpoint too and not only at the authorization endpoint, because
            // `client_credentials` reaches issuance without ever passing the other one.
            #[cfg(feature = "rar")]
            let requested_details = match context.authorization_details {
                None => GrantedDetails::default(),
                Some(raw) => {
                    let parsed = crate::rar::AuthorizationDetails::parse(raw)?;
                    parsed.require_supported_types(
                        self.config.authorization_details_types_supported.as_deref(),
                    )?;
                    GrantedDetails::of(&parsed)
                }
            };
            // And the build that supports NO type refuses the parameter outright, which is the
            // same s5 rule with the type list empty. Checked before the grant is looked up, so
            // the client hears about the parameter it sent rather than about the code it sent:
            // an `invalid_grant` for a request whose real defect is `authorization_details`
            // sends the client's author to the wrong half of the request.
            #[cfg(not(feature = "rar"))]
            if context.authorization_details.is_some() {
                return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                    .with_description("this server does not support authorization_details"));
            }
            #[cfg(not(feature = "rar"))]
            let requested_details = GrantedDetails::default();
            // RFC 9449 s4.3, before anything else touches the store: see `verify_dpop`.
            //
            // NOT boxed, and that is a measurement. It was `Box::pin(..)` through 0.9.0, to keep
            // the proof-check state out of the token future, and by then the restructuring
            // recorded above (an `async move` block rather than an `async fn`, and matching
            // `request` by reference) had already bought back more than the box was saving.
            // Measured both ways on four feature sets, the future is byte for byte identical:
            // 1136 under `dpop` alone, 1248 with `rar`, 1280 with `mtls,consent,rar,par`, 1344
            // `--all-features`. So the box bought nothing and cost one 168-byte allocation on
            // EVERY token request under this feature, including every refusal, which is traffic an
            // attacker sets the rate of. `refused_token_request_allocation_bound` had been
            // carrying that as a named exception; it now asserts zero on every feature set.
            //
            // THIS ENDPOINT IS EXPENSIVE UNDER `dpop`, AND A HOST HAS TO SIZE ITS RATE LIMITER FOR
            // IT. A DPoP proof carrying a WRONG signature costs a full P-256 verification, MEASURED
            // at 133.18 us on the machine `benches/README.md` names, and it is indistinguishable
            // from a valid one until that verification finishes; a merely MALFORMED proof costs
            // 34 ns. So roughly 7,500 requests per second of well-formed garbage saturates a core,
            // and the caller need hold no credential to send them.
            //
            // The ORDERING was examined and deliberately left alone. Moving the proof check after
            // `authenticate_client` would put a cheap credential test first, but it cannot be done
            // in this function (each grant helper authenticates its own client, with its own
            // credential shape), and doing it inside each helper would CHANGE THE WIRE ANSWER: a
            // request with both a bad secret and a bad proof would answer `invalid_client` where it
            // now answers `invalid_dpop_proof`. That is error semantics, visible to every
            // conforming client, traded for a mitigation that is partial anyway, since a caller who
            // has any valid client credential (a public client id is one) pays nothing to get past
            // the reorder. RFC 9449 offers nothing cheaper to filter on either: the proof is signed
            // by a key the AS learns FROM the proof, so there is nothing to check before checking
            // the signature.
            //
            // The honest answer is therefore the rate limiter, not the ordering. See
            // `crate::rate_limit`.
            #[cfg(feature = "dpop")]
            let jkt = self.verify_dpop(context.dpop_proof).await?;
            // Matched by REFERENCE, and that is the second half of the same measurement the doc
            // comment above records. Moving the fields out of the enum does not free the enum's
            // own slot in the coroutine: `request` is an upvar, so its 120 bytes are reserved for
            // the whole life of the future either way, and the moved-out owned fields were then a
            // second 120 bytes of the same data live across the grant helper's await. Borrowing
            // costs the helpers nothing, because every one of them already takes `&str` /
            // `&ClientId` / `Option<&ScopeSet>`. Measured at 128 bytes of the all-features token
            // future, 1952 down to 1824.
            match &request {
                TokenRequest::AuthorizationCode {
                    client_id,
                    client_secret,
                    code,
                    redirect_uri,
                    code_verifier,
                } => {
                    let bound = Bound {
                        cred: context.credential.or_secret(client_secret.as_deref()),
                        #[cfg(feature = "dpop")]
                        jkt: jkt.as_deref(),
                    };
                    let outcome = self
                        .authorization_code_token(
                            client_id,
                            &bound,
                            code,
                            redirect_uri.as_deref(),
                            code_verifier.as_deref(),
                            &requested_resources,
                            requested_details,
                        )
                        .await;
                    self.emit_refusal(client_id, GrantType::AuthorizationCode, &outcome);
                    outcome
                }
                TokenRequest::ClientCredentials {
                    client_id,
                    client_secret,
                    scope,
                } => {
                    let bound = Bound {
                        cred: context.credential.or_secret(client_secret.as_deref()),
                        #[cfg(feature = "dpop")]
                        jkt: jkt.as_deref(),
                    };
                    let outcome = self
                        .client_credentials_token(
                            client_id,
                            &bound,
                            scope.as_ref(),
                            requested_resources,
                            requested_details,
                        )
                        .await;
                    self.emit_refusal(client_id, GrantType::ClientCredentials, &outcome);
                    outcome
                }
                TokenRequest::DeviceCode {
                    client_id,
                    client_secret,
                    device_code,
                } => {
                    // RFC 8707 s2: nothing was granted to narrow to, so a resource here would be an
                    // audience the user never approved. See `token_with_resources`.
                    if !requested_resources.is_empty() {
                        return Err(
                            ErrorResponse::new(ErrorCode::InvalidTarget).with_description(
                                "the device authorization request granted no resource to narrow to",
                            ),
                        );
                    }
                    // RFC 9396 s6, and the same argument: the device authorization request
                    // cannot carry authorization_details in this crate, so there is nothing
                    // granted for this poll to narrow to, and minting detail here would be
                    // authorizing something the user never saw.
                    #[cfg(feature = "rar")]
                    if !requested_details.is_empty() {
                        return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                            .with_description(
                                "the device authorization request granted no authorization_details",
                            ));
                    }
                    let bound = Bound {
                        cred: context.credential.or_secret(client_secret.as_deref()),
                        #[cfg(feature = "dpop")]
                        jkt: jkt.as_deref(),
                    };
                    let outcome = self.device_token(client_id, &bound, device_code).await;
                    self.emit_refusal(client_id, GrantType::DeviceCode, &outcome);
                    outcome
                }
                TokenRequest::RefreshToken {
                    client_id,
                    client_secret,
                    refresh_token,
                    scope,
                } => {
                    let bound = Bound {
                        cred: context.credential.or_secret(client_secret.as_deref()),
                        #[cfg(feature = "dpop")]
                        jkt: jkt.as_deref(),
                    };
                    let outcome = self
                        .refresh_token(
                            client_id,
                            &bound,
                            refresh_token,
                            scope.as_ref(),
                            &requested_resources,
                            requested_details,
                        )
                        .await;
                    self.emit_refusal(client_id, GrantType::RefreshToken, &outcome);
                    outcome
                }
            }
        }
    }

    /// Emit [`Event::GrantRefused`] when a token-endpoint answer was an error.
    ///
    /// A non-async helper called from the arms of [`AuthorizationServer::token_with_resources`],
    /// where the client id is already an owned local. Deliberately NOT a wrapper around the whole
    /// endpoint: see the note in the 0.2.0 hook patch, and `tests/allocation.rs`.
    fn emit_refusal(
        &self,
        client_id: &ClientId,
        grant_type: GrantType,
        outcome: &Result<TokenResponse, ErrorResponse>,
    ) {
        if let Err(error) = outcome {
            self.hooks.emit(|| Event::GrantRefused {
                client_id: client_id.as_str(),
                grant_type,
                error: error.error,
            });
        }
    }

    /// Validate an authorization request (RFC 6749 section 4.1.1) before any user interaction.
    ///
    /// The order of checks is dictated by RFC 6749 section 4.1.2.1 and is a security boundary,
    /// not a style choice: the client and the redirect URI are validated FIRST, because until
    /// they are, there is no address the server may safely send an error to. Everything checked
    /// afterwards is reported by redirecting to the (now validated) URI.
    ///
    /// On success the host shows its consent UI and then calls
    /// [`AuthorizationServer::issue_authorization_code`], or reports
    /// [`ValidatedAuthorizationRequest::denied`] if the user refuses.
    pub async fn validate_authorization_request(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        // The POLICY gate, ahead of the validation itself: a deployment may declare that
        // parameters in the query are not an acceptable way to ask for authorization at all.
        //
        // RFC 9126 section 4 lets a server require PAR globally, and RFC 9101 section 10.5
        // requires the equivalent for signed request objects, both for the same reason: an
        // attacker who can rewrite the browser's URL will simply strip the protection and send a
        // plain RFC 6749 request unless the server refuses one. This is the only entry point that
        // takes query parameters, so refusing here is what makes the policy hold; `par.rs` reaches
        // the validation below directly, having already established that the request was pushed or
        // signed.
        #[cfg(feature = "par")]
        if matches!(&self.config.par, Some(par) if par.require_pushed_authorization_requests) {
            return Err(AuthorizationError::Direct(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                    "this server accepts authorization request data only via PAR (RFC 9126 s4)",
                ),
            ));
        }
        #[cfg(feature = "jar")]
        if matches!(&self.config.jar, Some(jar) if jar.require_signed_request_object) {
            return Err(AuthorizationError::Direct(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                    "this server requires a signed request object (RFC 9101 s10.5)",
                ),
            ));
        }
        self.validate_direct_authorization_request(request).await
    }

    /// The validation itself, with no policy gate in front of it.
    ///
    /// Split out for RFC 9126 / RFC 9101: a pushed or signed request has ALREADY satisfied the
    /// policy the wrapper above enforces, and it arrives as parameters rather than as a query, so
    /// it needs this and not the wrapper. Everything else about it is unchanged, which is the
    /// point: the PAR endpoint validates a pushed request by calling exactly the function the
    /// authorization endpoint calls, so the two cannot drift.
    pub(crate) async fn validate_direct_authorization_request(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        // THE THROTTLE, and this endpoint had none. RFC 9700 section 4.13 is about credential
        // stuffing at the token endpoint; this one takes NO CREDENTIAL, which is precisely why it
        // needs a bound of its own rather than sharing `Attempt::ClientAuthentication`'s. What a
        // deployment is bounding here is work and storage: every request costs a `get_client`, and
        // an approved one goes on to WRITE an authorization code record that nothing but
        // `Storage::sweep_expired` ever reclaims.
        //
        // Asked FIRST, before the store is touched, for the same reason `authenticate_client` asks
        // first: a refused attempt must cost nothing and reveal nothing.
        //
        // `temporarily_unavailable` (RFC 6749 section 4.1.2.1) rather than `invalid_request`,
        // because nothing about the request was wrong and a client that retries later will
        // succeed. It is DIRECT rather than a redirect: at this point neither the client nor the
        // redirect URI has been validated, so there is no address this server may safely send
        // anything to.
        let attempt = Attempt::AuthorizationRequest {
            client_id: request.client_id.as_deref().unwrap_or(""),
        };
        if self.hooks.check(attempt) == RateLimitDecision::Deny {
            return Err(AuthorizationError::Direct(
                ErrorResponse::new(ErrorCode::TemporarilyUnavailable)
                    .with_description("too many authorization requests; retry later"),
            ));
        }
        let outcome = self
            .validate_direct_authorization_request_inner(request)
            .await;
        // Reported back so a limiter can count FAILURES rather than traffic, exactly as the token
        // plane does. A refused authorization request is the signal worth counting here: a caller
        // walking client ids, or replaying a malformed request, produces nothing else.
        self.hooks.record(
            attempt,
            match &outcome {
                Ok(_) => AttemptOutcome::Succeeded,
                Err(_) => AttemptOutcome::Failed,
            },
        );
        outcome
    }

    /// The validation itself, with the throttle above already satisfied.
    ///
    /// Split out so that every `?` below reports its refusal to the limiter through ONE place. The
    /// alternative, threading `hooks.record` through a dozen early returns, is the shape that ends
    /// with one path that forgot to.
    async fn validate_direct_authorization_request_inner(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        // `&'static str`: every description below is a constant naming a condition, never a
        // value out of the request, so the refusal borrows it rather than copying it. The
        // authorization endpoint is unauthenticated, so its refusal rate is the attacker's to
        // choose.
        let direct = |code: ErrorCode, why: &'static str| {
            AuthorizationError::Direct(ErrorResponse::new(code).with_description(why))
        };

        // 1. The client. An unknown client_id and a malformed one collapse into one answer: the
        //    user agent is untrusted here, and telling it which client ids exist helps nobody.
        let client_id = request
            .client_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| direct(ErrorCode::InvalidRequest, "missing client_id"))?;
        let client = self
            .store
            .get_client(&ClientId::new(client_id))
            .await
            .map_err(|_| direct(ErrorCode::ServerError, "storage unavailable"))?
            .ok_or_else(|| direct(ErrorCode::InvalidRequest, "unknown client_id"))?;

        // 2. The redirect URI. OAuth 2.1 section 4.1.3 requires exact string comparison: no
        //    prefix matching, no ignoring a trailing slash, no normalising case. Every relaxation
        //    of this rule has a published attack behind it.
        //
        //    WHETHER IT WAS SENT is recorded as well as what it resolved to, because RFC 6749
        //    section 4.1.3 makes the token endpoint's copy of this parameter conditional on the
        //    authorization request having carried one. The resolved value below cannot answer that
        //    question: the section 3.1.2.3 omission path fills it in from the registration, so both
        //    cases arrive at the token endpoint looking identical.
        let redirect_uri_was_explicit = request.redirect_uri.is_some();
        let redirect_uri = match request.redirect_uri.as_deref() {
            Some(requested) => client
                .redirect_uris
                .iter()
                .find(|registered| registered.as_str() == requested)
                .cloned()
                .ok_or_else(|| {
                    direct(
                        ErrorCode::InvalidRequest,
                        "redirect_uri does not exactly match a registered URI",
                    )
                })?,
            // RFC 6749 section 3.1.2.3: the request may omit it only when there is exactly one
            // registration to mean. With several, the server would be guessing where to send a
            // credential, and a wrong guess is the whole attack.
            //
            // ZERO AND SEVERAL ARE ONE ANSWER, and that is the same rule step 1 above states.
            // Separate descriptions ("client has no registered redirect_uri" against "redirect_uri
            // is required when several are registered") sorted every client id into three buckets
            // by how many URIs it has registered, from one UNAUTHENTICATED request carrying
            // nothing but a `client_id`. Combined with the unknown-id refusal that is four
            // distinguishable answers about a registration the caller has proved no relationship
            // to, which defeats the collapse the comment on step 1 promises. Neither case can be
            // repaired by the client anyway: both are answered by SENDING a `redirect_uri`, and
            // the string below says so.
            None => match client.redirect_uris.as_slice() {
                [only] => only.clone(),
                _ => {
                    return Err(direct(
                        ErrorCode::InvalidRequest,
                        "redirect_uri is required for this client",
                    ))
                }
            },
        };

        // From here the redirect URI is trusted, so errors go back to the client (section
        // 4.1.2.1) carrying the state that lets it correlate them.
        let state = request.state.as_deref().map(str::to_string);
        let redirect = |code: ErrorCode, why: &'static str| {
            AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: redirect_uri.clone(),
                error: ErrorResponse::new(code).with_description(why),
                state: state.clone(),
                // RFC 9207 section 2: every authorization response, including this one, names the
                // server that produced it.
                iss: self.issuer_identifier().to_string(),
            })
        };

        // 3. response_type. OAuth 2.1 removes the implicit grant, so `token` is not merely
        //    unsupported by this server, it is gone from the protocol.
        match request.response_type.as_deref() {
            Some("code") => {}
            None => return Err(redirect(ErrorCode::InvalidRequest, "missing response_type")),
            Some(_) => {
                return Err(redirect(
                    ErrorCode::UnsupportedResponseType,
                    "this server issues authorization codes only",
                ))
            }
        }

        if !client.allows_grant(GrantType::AuthorizationCode) {
            return Err(redirect(
                ErrorCode::UnauthorizedClient,
                "client registration does not include the authorization_code grant",
            ));
        }

        // 4. PKCE. OAuth 2.1 requires it for every authorization code request. RFC 7636 section
        //    4.3 defaults an absent code_challenge_method to `plain`, which this server does not
        //    implement and does not advertise, so an absent method is refused rather than
        //    silently downgraded.
        match request.code_challenge_method.as_deref() {
            Some("S256") => {}
            None => {
                return Err(redirect(
                    ErrorCode::InvalidRequest,
                    "code_challenge_method=S256 is required",
                ))
            }
            Some(_) => {
                return Err(redirect(
                    ErrorCode::InvalidRequest,
                    "only code_challenge_method=S256 is supported",
                ))
            }
        }
        let code_challenge = request.code_challenge.as_deref().unwrap_or_default();
        if !challenge_is_well_formed(code_challenge) {
            // A malformed challenge can never match any verifier, so accepting it would issue a
            // code that is guaranteed to fail redemption later, with a misleading error.
            return Err(redirect(
                ErrorCode::InvalidRequest,
                "code_challenge must be the base64url SHA-256 form of RFC 7636 section 4.2",
            ));
        }

        // 5. Scope. RFC 6749 section 3.3: absent means the registered default, trimmed to what the
        // registration allows. See `granted_default_scope`, which is shared with `resolve_scope`
        // precisely so this endpoint and the token endpoint cannot answer differently.
        let scope = match request.scope.as_deref() {
            None => Self::granted_default_scope(&client),
            Some(s) => {
                let requested = ScopeSet::parse(s)
                    .map_err(|_| redirect(ErrorCode::InvalidScope, "malformed scope"))?;
                if !requested.is_subset(&client.allowed_scopes) {
                    return Err(redirect(
                        ErrorCode::InvalidScope,
                        "requested scope exceeds the client registration",
                    ));
                }
                requested
            }
        };

        // 6. RFC 8707 resource indicators. Checked LAST of the redirectable checks because it is
        //    the newest and least load-bearing of them: a request that is also missing PKCE should
        //    hear about PKCE. A malformed indicator is `invalid_target` (section 2), reported to
        //    the client rather than to the user, since by here the redirect URI is trusted.
        let resource = self
            .validate_resources(request.resource.iter().map(|r| r.as_ref()))
            .map_err(|e| {
                AuthorizationError::Redirect(AuthorizationErrorRedirect {
                    redirect_uri: redirect_uri.clone(),
                    error: e,
                    state: state.clone(),
                    iss: self.issuer_identifier().to_string(),
                })
            })?;

        // RFC 9396 authorization_details, checked last among the redirectable checks for
        // the same reason `resource` is checked late: it is the newest of them, and a
        // request that is also missing PKCE should hear about PKCE. Reported to the client
        // rather than to the user, since by here the redirect URI is trusted, and REFUSED
        // rather than ignored (section 5), because a client whose authorization detail was
        // silently dropped would obtain a token it believes says something it does not.
        //
        // THE BUILD WITHOUT `rar` REFUSES EVERY ONE OF THEM, which is the stronger case and not
        // an absent one: it supports no authorization detail type whatsoever, so section 5's
        // condition holds for any value at all and there is nothing to parse before answering.
        // Same posture as the RFC 9101 request object path in `crate::par`, which already said
        // this; this is the plain query request, and the RFC 9126 push, which reaches here too.
        #[cfg(not(feature = "rar"))]
        if request.authorization_details.is_some() {
            return Err(AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: redirect_uri.clone(),
                error: ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                    .with_description("this server does not support authorization_details"),
                state: state.clone(),
                iss: self.issuer_identifier().to_string(),
            }));
        }

        #[cfg(feature = "rar")]
        let details = {
            let to_redirect = |error: ErrorResponse| {
                AuthorizationError::Redirect(AuthorizationErrorRedirect {
                    redirect_uri: redirect_uri.clone(),
                    error,
                    state: state.clone(),
                    iss: self.issuer_identifier().to_string(),
                })
            };
            match request.authorization_details.as_deref() {
                None => crate::rar::AuthorizationDetails::none(),
                Some(raw) => {
                    let parsed =
                        crate::rar::AuthorizationDetails::parse(raw).map_err(to_redirect)?;
                    parsed
                        .require_supported_types(
                            self.config.authorization_details_types_supported.as_deref(),
                        )
                        .map_err(to_redirect)?;
                    parsed
                }
            }
        };

        // RFC 9470 s4's `acr_values` and `max_age`, parsed from THIS request rather than from the
        // query the user agent arrived with. That distinction is the whole point: for an RFC 9126
        // pushed request `request` is the stored record, and for an RFC 9101 signed one it is the
        // verified claim set, so the two parameters now survive both (they were dropped entirely
        // before, which disabled step-up for every PAR and JAR deployment) and the query cannot
        // supply them for either (RFC 9126 s4, RFC 9101 s6.3, which says the server MUST use only
        // the object's parameters even when the query repeats them).
        //
        // Checked last among the redirectable checks, so a request that is ALSO missing PKCE still
        // hears about PKCE first; that is the order the endpoint reported before this moved here.
        #[cfg(feature = "consent")]
        let requirement = crate::consent::AuthenticationRequirement::from_request(request)
            .map_err(|error| {
                AuthorizationError::Redirect(AuthorizationErrorRedirect {
                    redirect_uri: redirect_uri.clone(),
                    error,
                    state: state.clone(),
                    iss: self.issuer_identifier().to_string(),
                })
            })?;

        // `mut` plus a setter rather than a ninth constructor argument: see
        // `ValidatedAuthorizationRequest::set_authorization_details`.
        #[allow(unused_mut)]
        let mut validated = ValidatedAuthorizationRequest::new(
            // Cloned rather than moved: `client` is an `Arc<Client>` shared with the store since
            // `Storage::get_client` stopped deep-copying the registration, so the id has to be
            // copied out. One allocation on the AUTHORIZATION endpoint, against the eight the
            // shared read saved on it.
            client.client_id.clone(),
            redirect_uri,
            redirect_uri_was_explicit,
            scope,
            state,
            code_challenge.to_string(),
            CodeChallengeMethod::S256,
            self.issuer_identifier().to_string(),
            resource,
        );
        #[cfg(feature = "rar")]
        validated.set_authorization_details(details);
        #[cfg(feature = "consent")]
        validated.set_authentication_requirement(requirement);
        Ok(validated)
    }

    /// Mint an authorization code for a request the user has approved (RFC 6749 section 4.1.2).
    ///
    /// RFC 6749 SECTION 10.12 IS THE REASON THIS TAKES A [`UserApproval`] AND NOT A SUBJECT.
    /// Knowing WHO the user is does not establish that they agreed to anything. An authorization
    /// endpoint that mints a code as soon as it can name the logged-in user issues one on any
    /// cross-site top-level navigation that user's browser can be made to follow, which is exactly
    /// the cross-site request forgery section 10.12 describes: the attacker's client, the victim's
    /// session, a code delivered to the attacker's registered redirect URI. Nothing in this crate
    /// can see a user, so nothing here can detect that; the only defence a library has is to
    /// require the host to SAY that a resource owner approved this request, and to be unbuildable
    /// without it.
    ///
    /// Taking a [`ValidatedAuthorizationRequest`] (through the approval) rather than a raw request
    /// is deliberate for the same reason one level down: an unvalidated request cannot reach code
    /// issuance, because it cannot be spelled.
    pub async fn issue_authorization_code(
        &self,
        approval: UserApproval<'_>,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        // RFC 9470 IS ENFORCED HERE TOO, and it was not until the 0.9.1 audit.
        // `validate_authorization_request` parses `acr_values` and `max_age` onto the validated
        // request, and this entry point threw the result away: it minted a code for a request that
        // demanded a step-up without evaluating the demand, and `GrantedAuthentication::default()`
        // then recorded no authentication, so introspection reported no `auth_time` and no `acr`
        // for every token the code produced. The sibling below calls that enforcement "a library
        // job rather than a host job on purpose: a `max_age` the host is trusted to check for
        // itself is a `max_age` that gets checked in whichever code path somebody remembered", and
        // this was the path nobody remembered. `crate::http` uses the sibling, so what shipped
        // unenforced was the DIRECT API, which is the path `UserApproval` documents as the one
        // this crate's default build invites.
        //
        // Routed through the sibling with NO report, rather than duplicating the check: this entry
        // point has no argument through which a host could report an authentication, so `None` is
        // the only honest value and `satisfied_by` answers `Ok(())` for an empty requirement. A
        // request carrying neither parameter is therefore completely unaffected, and one carrying
        // either is refused with RFC 9470 section 3 `insufficient_user_authentication` rather than
        // granted, which is the fail-closed direction and the same answer the sibling gives an
        // unreported requirement.
        #[cfg(feature = "consent")]
        {
            let requirement = approval.request().authentication_requirement.clone();
            return self
                .issue_authorization_code_with_authentication(approval, &requirement, None)
                .await;
        }
        #[cfg(not(feature = "consent"))]
        self.issue_authorization_code_inner(approval, GrantedAuthentication::default())
            .await
    }

    /// Mint an authorization code for a request the user has approved, holding the request's RFC
    /// 9470 step-up requirement to the authentication the HOST reports it performed.
    ///
    /// This is the enforcement half of RFC 9470, and it is a library job rather than a host job on
    /// purpose: a `max_age` the host is trusted to check for itself is a `max_age` that gets checked
    /// in whichever code path somebody remembered. The host still owns the authentication itself,
    /// and `authentication` is its REPORT of one; this crate cannot verify that report and does not
    /// pretend to. See the [`crate::consent`] module docs for the whole boundary.
    ///
    /// A requirement the report does not satisfy is refused with RFC 9470 section 3's
    /// `insufficient_user_authentication`, delivered as a REDIRECT (RFC 6749 section 4.1.2.1):
    /// by this point the redirect URI has been validated, and the client is both the party that
    /// asked the question and the party that has to decide whether to send the user back to log in.
    /// Nothing is minted and no consent is touched.
    /// The approval means the same thing here as it does on
    /// [`AuthorizationServer::issue_authorization_code`], and is required for the same RFC 6749
    /// section 10.12 reason: a satisfied `acr_values` says the user authenticated STRONGLY, never
    /// that they agreed.
    #[cfg(feature = "consent")]
    pub async fn issue_authorization_code_with_authentication(
        &self,
        approval: UserApproval<'_>,
        requirement: &crate::consent::AuthenticationRequirement,
        authentication: Option<&crate::consent::Authentication>,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        if let Err(failure) = requirement.satisfied_by(authentication, self.clock.now()) {
            let request = approval.request();
            return Err(AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: request.redirect_uri.clone(),
                error: failure.error_response(),
                state: request.state.clone(),
                iss: request.issuer.clone(),
            }));
        }
        self.issue_authorization_code_inner(
            approval,
            GrantedAuthentication {
                authentication: authentication.cloned().map(Box::new),
            },
        )
        .await
    }

    /// The issuance itself, shared by both entry points above so that they cannot drift.
    async fn issue_authorization_code_inner(
        &self,
        approval: UserApproval<'_>,
        authentication: GrantedAuthentication,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        #[cfg(not(feature = "consent"))]
        let _ = authentication;
        // Destructured rather than borrowed through the approval: `subject` is MOVED into the
        // record below, which is the same one allocation the previous `impl Into<String>` argument
        // produced. The approval adds no allocation of its own; it is a borrow plus that String.
        let UserApproval {
            request,
            subject,
            decided_at,
        } = approval;
        // THE SECOND CHARGE, and it is a separate one on purpose. `validate_authorization_request`
        // is charged for a READ; this is where the authorization code record is WRITTEN, and
        // nothing but `Storage::sweep_expired` reclaims one. Charging the write to the validation
        // would let a caller who validated once go on issuing for free, which is the half that
        // actually grows the store.
        //
        // A REDIRECT rather than a direct refusal, unlike the validation's: by this point the
        // redirect URI has been validated, so RFC 6749 section 4.1.2.1 sends the error back to the
        // client, carrying the state that lets it correlate. `temporarily_unavailable` because
        // nothing about the request was wrong and a retry later will succeed. Nothing is minted
        // and no consent is touched, which is the same posture the step-up refusal above takes.
        //
        // NOTHING IS RECORDED on the deny, and that is the same rule every other classification
        // site in this crate follows (`authenticate_client`, the validation above,
        // `pending_grant_by_user_code`, `register_dynamic_client`). `RateLimiter::record` is
        // documented as reporting how an ALLOWED attempt turned out, and a denial never became an
        // attempt: reporting it as `Failed` would drive the failure count with the very traffic
        // the limiter refused, and a host alerting on failure rate — which this crate tells hosts
        // to do — would read a client that merely exceeded its ceiling as a caller walking the
        // redirect-URI space. This site reported it through the 0.9.1 audit's second charge and
        // was the one exception.
        let attempt = Attempt::AuthorizationRequest {
            client_id: request.client_id.as_str(),
        };
        if self.hooks.check(attempt) == RateLimitDecision::Deny {
            return Err(AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: request.redirect_uri.clone(),
                error: ErrorResponse::new(ErrorCode::TemporarilyUnavailable)
                    .with_description("too many authorization requests; retry later"),
                state: request.state.clone(),
                iss: request.issuer.clone(),
            }));
        }
        let now = self.clock.now();
        // `?` rather than a panic, for the reason `try_random_hex` gives. The refusal is a
        // REDIRECT because by this point the redirect URI has been validated (RFC 6749 s4.1.2.1),
        // so it goes back to the client the same way the storage failure below does.
        let code = try_random_hex(32).ok_or_else(|| {
            self.hooks.record(attempt, AttemptOutcome::Failed);
            AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: request.redirect_uri.clone(),
                error: ErrorResponse::new(ErrorCode::ServerError),
                state: request.state.clone(),
                iss: request.issuer.clone(),
            })
        })?;
        let record = AuthorizationCodeRecord {
            // WHEN THE USER'S DECISION HAPPENED, which is not always now. Redemption carries this
            // into the issued token so a revocation can tell this code from one minted after it,
            // and a barrier refuses a grant that PREDATES it — so dating the decision later than
            // it happened is what lets a code outrank a withdrawal recorded in between.
            //
            // `None` means the host prompted during this request and the two instants are the
            // same. A host acting on a standing approval must say so with
            // [`UserApproval::granted_at`]; this crate's own `http` service does, passing the
            // instant the authorization request was received. See that method for the ordering
            // this closes.
            issued_at: decided_at.unwrap_or(now),
            code: code.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            // RFC 6749 s4.1.3: carried so the token endpoint can require the parameter exactly
            // when the authorization request sent one. See the field.
            redirect_uri_was_explicit: request.redirect_uri_was_explicit,
            scope: request.scope.clone(),
            subject,
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method,
            // RFC 8707 s2: what the token this code redeems into may be audience-restricted to.
            resource: request.resource.clone(),
            // RFC 9396 s7: the details as granted, which is what the redeeming token request
            // may narrow and what the issued token will carry.
            #[cfg(feature = "rar")]
            authorization_details: request.authorization_details.clone(),
            expires_at: saturating_deadline(now, self.config.authorization_code_ttl),
            state: AuthorizationCodeState::Issued,
            // RFC 9470 s6.2: recorded here because the token endpoint has no user in front of it and
            // could not ask. See `AuthorizationCodeRecord::authentication`.
            #[cfg(feature = "consent")]
            authentication: authentication.authentication,
        };
        self.store
            .put_authorization_code(record)
            .await
            .map_err(|_| {
                self.hooks.record(attempt, AttemptOutcome::Failed);
                AuthorizationError::Redirect(AuthorizationErrorRedirect {
                    redirect_uri: request.redirect_uri.clone(),
                    error: ErrorResponse::new(ErrorCode::ServerError),
                    state: request.state.clone(),
                    iss: request.issuer.clone(),
                })
            })?;
        // The record is written, so the charge is settled as a success. Reported at all because a
        // limiter that counts failures needs to be told about the ones that were not.
        self.hooks.record(attempt, AttemptOutcome::Succeeded);
        Ok(AuthorizationResponse {
            code,
            state: request.state.clone(),
            // RFC 9207 s2. Taken from the validated request rather than re-read from config so the
            // success and error halves of one authorization request cannot disagree about who
            // answered it.
            iss: request.issuer.clone(),
        })
    }

    /// RFC 6749 section 4.1.3 with the OAuth 2.1 PKCE requirement: redeem an authorization code.
    // Eight arguments rather than seven, for the reason `issue` carries the same allow: the
    // alternative is a parameter struct nobody else would ever construct, wrapping values
    // that are already named at this function's one call site.
    #[allow(clippy::too_many_arguments)]
    async fn authorization_code_token(
        &self,
        client_id: &ClientId,
        bound: &Bound<'_>,
        code: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        requested_resources: &[String],
        requested_details: GrantedDetails,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;
        if !client.allows_grant(GrantType::AuthorizationCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }

        // Single use is enforced by the atomic take: concurrent redemptions of the same code
        // cannot both succeed, because only one of them receives the record.
        let record = self
            .store
            .take_authorization_code(code)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;

        // A code belongs to the client it was issued to, and this is checked FIRST, before the
        // replay branch below, because that branch is DESTRUCTIVE. Ordering it the other way makes
        // "revoke the tokens this code minted" reachable by whoever presents the code, and a code
        // is a value that leaks: into logs, into `Referer` headers, into browser history. The
        // record goes BACK rather than being burned, for the same reason: the legitimate client
        // must still be able to complete its flow, and letting a third party destroy a live code
        // is a denial of service for free.
        //
        // Being honest about what this check is and is not. For a CONFIDENTIAL client it is an
        // authentication gate, because `authenticate_client` above proved the caller holds the
        // secret. For a PUBLIC client it is not: RFC 6749 section 4.1.2 notes that a public client
        // id is not a secret and anyone may claim one, so a leaked code still lets an attacker
        // reach this branch as the client the code WAS issued to, and still ends that client's
        // tokens. That residual is inherent to public clients and PKCE does not close it, since
        // the revocation happens before any verifier is checked. What the ordering above does buy
        // is that the residual stops at the client whose code actually leaked, instead of being
        // handed to every registered client in the deployment.
        if record.client_id != client.client_id {
            // NOT fire-and-forget. If this write fails, a LIVE code belonging to an honest client
            // has just been destroyed by a stranger's request, and answering `invalid_grant` would
            // report that as the ordinary refusal it is not: the honest client would come back a
            // moment later, be told `invalid_grant` as well, and nobody would ever connect the two.
            // `server_error` is the truthful answer and it is the only place this failure can
            // surface, because the party in front of us is not the one who was harmed.
            //
            // It reveals nothing: reaching this branch at all requires a real code, and the
            // difference between the two answers is a store failure the caller cannot provoke.
            self.store
                .put_authorization_code(record)
                .await
                .map_err(storage_error)?;
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }

        // A code presented twice is evidence it leaked, so RFC 6749 section 4.1.2 and RFC 9700
        // section 4.1.1 want the tokens it already minted revoked, not just the replay refused.
        // Refusing the replay alone would leave the attacker's stolen access token live.
        // `Replayed` counts too: a THIRD presentation is still a replay, and the record still
        // names what to revoke. Reading only `Consumed` here would make every presentation after
        // the second one look like an unknown code, which is the answer a typo gets.
        if let Some((access_token, refresh_token)) = record.state.minted() {
            let (access_token, refresh_token) = (
                access_token.map(str::to_string),
                refresh_token.map(str::to_string),
            );
            let (access_token, refresh_token) = (&access_token, &refresh_token);
            // Revoking by FAMILY rather than by the two recorded strings, so that a chain the
            // client has legitimately rotated since redemption dies too: the compromise is of the
            // grant, not of one token from it (RFC 9700 section 4.14.2).
            let mut revoked_family = false;
            // EVERY STEP BELOW CAN FAIL, AND THE WIRE CANNOT CARRY THE NEWS. The answer to a
            // replayed code is `invalid_grant` whatever happens here, because the party being
            // answered is whoever holds a leaked code and there is nothing to tell them. So the
            // AUDIT EVENT is the only signal a deployment gets, which makes an event that claims
            // containment it did not achieve strictly worse than no event: it is what an operator
            // reads while deciding not to investigate. This flag is what stops it lying.
            let mut containment_failed = false;
            // MOVED out of the record rather than cloned: `rec` is a value this scope already owns
            // and drops, so carrying its family id to the audit event below costs nothing.
            let mut revoked_family_id: Option<String> = None;
            if let Some(rt) = refresh_token {
                // The `Err` arm is NOT the same thing as `Ok(None)` and must not be folded into it.
                // `Ok(None)` means there is no chain to revoke, which is a clean outcome. `Err`
                // means the store could not say, so the family revocation was never even ATTEMPTED
                // and the attacker's chain may be live. Reading both as "no chain" is exactly the
                // overstated containment `containment_failed` exists to prevent.
                match self.store.get_refresh_token(rt).await {
                    Ok(Some(rec)) => {
                        // Cloned out of the shared snapshot `get_refresh_token` handed back. One
                        // allocation, on the detected-compromise path only, against the seven that
                        // read now costs nothing on the paths that run per request.
                        revoked_family_id = Some(rec.family_id.clone());
                        // `revoked_family` now means what its name says. It was set unconditionally
                        // here, with the `Result` discarded, so a store that failed at the one
                        // moment this server was responding to a detected compromise reported a
                        // clean containment: the attacker's chain still live, the audit log saying
                        // it was killed.
                        match self
                            .store
                            .revoke_token_family(&rec.family_id, self.revocation_window())
                            .await
                        {
                            Ok(_) => revoked_family = true,
                            Err(_) => containment_failed = true,
                        }
                    }
                    Ok(None) => {}
                    Err(_) => containment_failed = true,
                }
            }
            if !revoked_family {
                // No refresh chain to reach the family through (or it is already swept, or the
                // revocation above failed): the access token this code minted is still nameable
                // directly, so this is a genuine fallback and not merely a tidy-up. Dropping its
                // failure left the compromised access token live for its whole TTL, silently.
                //
                // `None` means the redemption that consumed this code never got as far as issuing
                // anything (see `AuthorizationCodeState::Consumed::access_token`), so there is
                // genuinely nothing to revoke and nothing failed. The replay is still real and is
                // still reported.
                if let Some(at) = access_token {
                    if self.store.delete_token(at).await.is_err() {
                        containment_failed = true;
                    }
                }
            }
            // The record goes BACK, and it goes back as `Replayed` rather than as what was read.
            // `src/authorization.rs` and `src/store.rs` both promise it is retained until its own
            // expiry, and that promise is what makes replay detection work more than once: taking
            // it here would make the NEXT replay read as an unknown code. Losing this write
            // therefore loses the EVIDENCE, not just a record, which is why it counts as a
            // containment failure too.
            //
            // `Replayed` is the DURABLE TRACE, and it is the half of this that a concurrent
            // redemption can see. Putting `Consumed` back would be byte for byte what a redemption
            // suspended on the host's signer wrote before it suspended, so that redemption would
            // wake, record what it minted, and hand out an access token and a refresh chain this
            // very replay was supposed to have contained. See `AuthorizationCodeState::Replayed`.
            let replayed = AuthorizationCodeRecord {
                state: AuthorizationCodeState::Replayed {
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                },
                ..record
            };
            if self.store.put_authorization_code(replayed).await.is_err() {
                containment_failed = true;
            }
            // EVIDENCE OF COMPROMISE (RFC 6749 section 4.1.2, RFC 9700 section 4.1.1). The
            // revocation above is silent without this: a host cannot investigate a stolen code it
            // was never told about.
            self.hooks.emit(|| Event::AuthorizationCodeReplayDetected {
                client_id: client.client_id.as_str(),
                family_id: revoked_family_id.as_deref(),
                tokens_revoked: revoked_family,
                containment_failed,
            });
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }

        if self.clock.now() >= record.expires_at {
            // Expired codes are not put back: they can never become valid again.
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("authorization code expired"));
        }

        // RFC 6749 section 4.1.3: the redirect URI presented here must be the one the code was
        // issued against, which is what stops a code obtained for one registered URI being
        // redeemed as if it had been issued for another.
        //
        // THE PARAMETER IS CONDITIONAL, and conditional in both directions. Section 4.1.3 makes it
        // REQUIRED "if the `redirect_uri` parameter was included in the authorization request", and
        // section 3.1.2.3 entitles a client with exactly one registered URI to omit it there. This
        // endpoint required it unconditionally through 0.9.1, so that ordinary and conforming
        // client was refused here — and refused with a message blaming a mismatch that had not
        // happened, which is the answer that sends its developer looking at its registration.
        //
        // The check is not weakened for the request that DID send one: `Some` still has to equal
        // the recorded URI, and `None` is accepted only against a record that says the
        // authorization request named nothing. Sending one where none was sent is still refused,
        // because a code minted for a registration-derived URI must not be redeemable as if the
        // client had chosen the address itself.
        let redirect_uri_matches = match redirect_uri {
            Some(u) => u == record.redirect_uri,
            None => !record.redirect_uri_was_explicit,
        };
        if !redirect_uri_matches {
            let _ = self.store.put_authorization_code(record).await;
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("redirect_uri does not match the authorization request"));
        }

        // RFC 7636 section 4.6. A missing verifier is the exact downgrade PKCE exists to stop, so
        // it is a failure, never a skipped check.
        //
        // The LENGTH AND ALPHABET of the verifier are checked here too (section 4.1: 43 to 128
        // characters from the unreserved set), and until the 0.9.1 audit they were checked
        // nowhere — `pkce::verifier_is_valid` existed and had no caller outside the tests. The
        // asymmetry mattered: this crate pins the challenge it MINTS at 43 base64url characters
        // and refuses `plain`, so it validated everything the server produced and nothing the
        // client presented. A client deriving its challenge from a six-character verifier gets a
        // grant an attacker can finish, because section 7.1 puts the `code_challenge` in the
        // authorization request — browser history, `Referer`, proxy logs — and six characters is
        // not a search. Refusing costs a conforming client nothing.
        let verified = match (code_verifier, record.code_challenge_method) {
            (Some(v), CodeChallengeMethod::S256) => {
                crate::pkce::verifier_is_valid(v)
                    && crate::pkce::verify_s256(v, &record.code_challenge)
            }
            (None, _) => false,
        };
        if !verified {
            let _ = self.store.put_authorization_code(record).await;
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("code_verifier does not match the recorded code_challenge"));
        }

        // RFC 8707 s2: the token request may narrow the audience the authorization request
        // obtained, never widen it. The code is put BACK on refusal, exactly as the scope and
        // redirect_uri mismatches above do: asking for the wrong resource is a client bug, and
        // burning a live code for a bug the client can fix on retry is a denial of service the
        // attacker gets for free.
        // RFC 8707 s2 and RFC 9396 s6 are the SAME rule applied to two parameters: the token
        // request may narrow what the authorization request obtained, and never widen it.
        // Both are computed as one fallible expression with ONE error path, rather than two
        // `match` blocks each holding an `ErrorResponse` across a `put_authorization_code`
        // await of its own: this function IS the token future, and `tests/allocation.rs`
        // holds that future under tokio's 2048-byte debug boxing threshold, past which every
        // single token request pays a 2 KB allocation.
        //
        // The code goes BACK on refusal, exactly as the redirect_uri and PKCE mismatches
        // above do: asking for the wrong thing is a client bug, and burning a live code for
        // a bug the client can fix on retry is a denial of service the attacker gets free.
        let narrowed = self
            .narrow_and_permit(&record.resource, requested_resources)
            .and_then(|r| {
                GrantedDetails::of_code(&record)
                    .narrow(&requested_details)
                    .map(|d| (r, d))
            });
        let (resource, details) = match narrowed {
            Ok(narrowed) => narrowed,
            Err(e) => {
                let _ = self.store.put_authorization_code(record).await;
                return Err(e);
            }
        };

        // Retain the spent code until its own expiry, recording what it minted, so a later replay
        // is recognisable as a replay rather than as an unknown code.
        //
        // THE CONSUMED RECORD IS WRITTEN BEFORE ISSUANCE, and word for word the same argument as
        // the refresh rotation in `refresh_token` below: `take_authorization_code` above has
        // already removed this code, `Storage` has no transaction so the take and this write cannot
        // be one operation, and all that can be chosen is which way the pair fails.
        //
        // Issuing first fails OPEN: a store that dies mid-issuance leaves the code gone with no
        // consumed record, so a replay of a code that leaked into a log, a `Referer` header or
        // browser history reads as a typo, and RFC 6749 section 4.1.2 / RFC 9700 section 4.1.1
        // replay detection is off for that grant permanently and silently. Writing it first fails
        // CLOSED: the client is refused and starts a new authorization request, which it can do
        // without help, and the alarm stays armed.
        //
        // The price is the SECOND write below, because what the code minted is not knowable until
        // it has been minted. That is a much smaller loss if it fails than this one is: the alarm
        // is already armed by then.
        let subject = record.subject.clone();
        let scope = record.scope.clone();
        let authentication = GrantedAuthentication::from_code(&record);
        let mut consumed = AuthorizationCodeRecord {
            state: AuthorizationCodeState::Consumed {
                access_token: None,
                refresh_token: None,
            },
            ..record
        };
        self.store
            .put_authorization_code(consumed.clone())
            .await
            .map_err(storage_error)?;

        let issued = self
            .issue_boxed(
                &client,
                bound,
                GrantType::AuthorizationCode,
                // The user's decision, taken from the code being redeemed. NOT `now`: a code
                // minted before a revocation must still be refused when it is redeemed after one.
                record.issued_at,
                Some(subject),
                scope,
                resource,
                details,
                None,
                true,
                authentication,
                // No actor: this grant delegates nothing (RFC 8693 s4.1).
                GrantedActor::default(),
                // No ceiling: an authorization code's redemption is the START of a grant's
                // lifetime, so the ordinary `access_token_ttl` is the whole rule.
                None,
            )
            .await?;

        // Now the record can name what it minted, which is what lets a replay REVOKE rather than
        // merely be refused.
        //
        // A COMPARE-AND-SWAP against the record this function wrote itself, not a blind put, and
        // the expectation is exactly the `Consumed { None, None }` written before issuance. Two
        // things can have happened during the issuance above, which may have suspended on the
        // host's `Es256Signer` for a network round trip:
        //
        // - A REPLAY was detected and marked the record `Replayed`. The swap fails, and it must:
        //   the replay path already decided this grant is compromised and found nothing to revoke
        //   because nothing had been issued yet. Writing here would hand out the very tokens it
        //   was trying to contain.
        // - The code was cascaded away by `delete_client` or `revoke_consent`. Absent refuses too,
        //   so a withdrawn consent is not undone by a redemption that started before it.
        //
        // Either way the issuance is undone below rather than reported as a storage failure.
        let expected_before_issuance = AuthorizationCodeState::Consumed {
            access_token: None,
            refresh_token: None,
        };
        consumed.state = AuthorizationCodeState::Consumed {
            access_token: Some(issued.access_token.clone()),
            refresh_token: issued.refresh_token.clone(),
        };
        let recorded = self
            .store
            .compare_and_swap_authorization_code(&expected_before_issuance, consumed)
            .await;
        if !matches!(recorded, Ok(true)) {
            // The client is answered with an error, so it never receives the tokens that were just
            // minted and they become orphans: live records nobody was ever handed. Best effort
            // cleanup, and the `Result` is deliberately discarded rather than reported, because
            // there is nothing useful left to say. These are 32 bytes of OS randomness that were
            // never transmitted to anyone, so a failed cleanup costs storage the host's
            // `Storage::sweep_expired` reclaims at the token's own expiry, and nothing else. The
            // Both artifacts are nameable directly here, which is cheaper and more precise than
            // asking the store for the family they belong to.
            self.undo_issuance(&issued.access_token).await;
            if let Some(rt) = &issued.refresh_token {
                let _ = self.store.take_refresh_token(rt).await;
            }
            // The two outcomes are answered DIFFERENTLY, because they are different facts about
            // the deployment and the wire code is what a host's dashboards count.
            //
            // `Ok(false)` is not a failure of this server: the swap did exactly its job. The grant
            // was replayed or revoked while this redemption was in flight, so `invalid_grant` is
            // the true answer and a `server_error` would send an operator looking for a storage
            // fault that never happened.
            return Err(match recorded {
                Ok(_) => ErrorResponse::new(ErrorCode::InvalidGrant).with_description(
                    "this authorization code was replayed or revoked during redemption",
                ),
                Err(_) => ErrorResponse::new(ErrorCode::ServerError)
                    .with_description("could not record the redemption"),
            });
        }

        Ok(issued)
    }

    /// RFC 6749 section 4.4: the client acts on its own behalf, with no resource owner.
    async fn client_credentials_token(
        &self,
        client_id: &ClientId,
        bound: &Bound<'_>,
        requested_scope: Option<&ScopeSet>,
        resource: Vec<String>,
        details: GrantedDetails,
    ) -> Result<TokenResponse, ErrorResponse> {
        // STAMPED BEFORE THE REGISTRATION IS READ, and that ordering is the whole point.
        //
        // This grant has no resource owner, so the client's own authentication IS the decision and
        // this is the instant it dates from. Taking it AFTER `authenticate_client` would date the
        // grant later than the read it derives from, and a `delete_client` landing in between —
        // one `get_client` round trip, plus a secret verification, plus on the assertion path a
        // JWT verify and a replay claim — would then record a barrier EARLIER than the grant it is
        // supposed to refuse. The write would be applied and a live token minted for a
        // registration that no longer exists.
        //
        // That is the exact resurrection the barrier exists to stop, and it was introduced by the
        // 0.9.1 audit fix that made barriers compare instants at all: refusing on identity alone
        // had closed it for free. Found by auditing that fix rather than by any test.
        let grant_established_at = self.clock.now();
        let client = self.authenticate_client(client_id, &bound.cred).await?;
        // RFC 6749 section 4.4: this grant is for confidential clients. A public client has no
        // secret, so "the client itself" is not an identity anyone has proven.
        //
        // BARE, for the reason spelled out at the introspection twin of this check: a description
        // here would be the only response on the endpoint that distinguishes a registered public
        // client from an unknown id, and the credential path just above collapses exactly that
        // distinction. Both sites were changed together because the introspection comment cites
        // this one as "the same refusal, for the same reason", and a fix applied to one of a pair
        // that call each other authority is how a rule ends up living in two places with two
        // answers. The operator's sentence is `ClientAuthFailure::NotConfidential`.
        if matches!(client.auth, crate::client::ClientAuth::Public) {
            self.hooks.emit(|| Event::ClientAuthenticationFailed {
                client_id: client_id.as_str(),
                failure: ClientAuthFailure::NotConfidential,
            });
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }
        if !client.allows_grant(GrantType::ClientCredentials) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }
        let scope = Self::resolve_scope(&client, requested_scope)?;
        // Section 4.4.3: a refresh token SHOULD NOT be included. The client holds its own
        // credentials and can mint another token whenever it likes, so a refresh token would be a
        // second long-lived secret bought for nothing.
        // RFC 8707 s2: there is no prior authorization request here, so there is nothing to
        // narrow AGAINST. The client authenticated as itself and is naming the resource server it
        // means to call, which is the whole of what the parameter says in this grant.
        self.issue_boxed(
            &client,
            bound,
            GrantType::ClientCredentials,
            // Read at request ENTRY, above, not here. See the comment there.
            grant_established_at,
            None,
            scope,
            resource,
            // RFC 9396 s6: there is no prior authorization request here, so there is nothing
            // to narrow AGAINST. The client authenticated as itself and is naming what it
            // means to do, which is the whole of what the parameter says in this grant; the
            // s5 type check has already run at the endpoint.
            details,
            None,
            false,
            // RFC 6749 s4.4 has no resource owner, so there is no user authentication to report.
            GrantedAuthentication::default(),
            // No actor: this grant delegates nothing (RFC 8693 s4.1).
            GrantedActor::default(),
            // No ceiling: this grant derives from the client's own live credentials and from no
            // earlier token, so there is nothing for its lifetime to be capped against.
            None,
        )
        .await
    }

    /// RFC 8628 sections 3.4/3.5: one device-token poll.
    async fn device_token(
        &self,
        client_id: &ClientId,
        bound: &Bound<'_>,
        device_code: &str,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }

        let mut grant = self
            .store
            .get_device_grant(device_code)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;

        // A device_code was issued to exactly one client; anyone else presenting it holds a grant
        // that was not made to them (RFC 6749 section 5.2 `invalid_grant`). The grant is NOT
        // consumed: a stray or malicious cross-client poll must not break the real device.
        if grant.client_id != client.client_id {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }

        let now = self.clock.now();

        // Expiry first (RFC 8628 section 3.5 `expired_token`), and the grant is removed: the code
        // can never become valid again, and later polls report plain `invalid_grant`.
        if now >= grant.expires_at {
            let _ = self.store.take_device_grant(device_code).await;
            return Err(ErrorResponse::new(ErrorCode::ExpiredToken));
        }

        // Poll pacing. Too-fast polls get `slow_down`, and the REQUIRED spacing grows by the
        // configured increment (the RFC directs the client to add 5 seconds; the server tracks the
        // same number so it can hold the client to it). The window also restarts at this poll:
        // hammering does not drain the wait.
        //
        // BOTH WRITES BELOW ARE COMPARE-AND-SWAPS, and this is the argued part. A poll and the
        // user's decision at the verification UI are two different actors on one record, and the
        // poll's write is derived from a read that happened one or more storage round trips ago.
        // Blind-putting that snapshot back reverts an approval the user really gave, or, worse, a
        // DENIAL: the verification UI has already told the user their refusal was recorded, the
        // grant is `Pending` again, and nothing anywhere reports an error.
        //
        // The trade is deliberate and it is not symmetric. A poll writes exactly two fields,
        // `interval` and `last_poll_at`, and losing them costs at most one extra `slow_down` on the
        // next poll. Losing a DECISION is losing something a human did. So a missed swap here is
        // NOT retried and NOT an error: the poll simply declines to write, the decision stands, and
        // the device reads it on its next poll a few seconds later. That is the whole design rule,
        // and it is why this is a compare-and-swap rather than a re-read-and-merge: re-reading
        // narrows the window, it does not close it, and the decision must not be losable at all.
        if let Some(last) = grant.last_poll_at {
            // `checked_add`, not `+`: `SystemTime + Duration` PANICS on overflow, and
            // `grant.interval` is grown by the poll rate below against a host-set increment that
            // nothing validates. `None` means the deadline is past any representable instant, so
            // the client is unconditionally too early.
            // `map_or(true, ..)` rather than `is_none_or`, which is stable only since 1.82 while
            // this crate's MSRV is 1.75. The clippy lint that prefers `is_none_or` does not know
            // that, so it is silenced here rather than obeyed.
            #[allow(clippy::unnecessary_map_or)]
            if last
                .checked_add(grant.interval)
                .map_or(true, |next| now < next)
            {
                let expected = grant.state.clone();
                // `saturating_add`: `Duration: AddAssign` panics on overflow, and this
                // accumulator is paced by the client's own polling against a host-set increment.
                // A saturated interval is a client that must wait longer than the grant lives,
                // which is the same refusal by a different route.
                grant.interval = grant
                    .interval
                    .saturating_add(self.config.slow_down_increment);
                grant.last_poll_at = Some(now);
                // A genuine storage FAILURE is still fatal, exactly as it was before: only losing
                // the race is tolerated. The `slow_down` answer stands either way, because the
                // pacing verdict was computed from a real read of a real record.
                self.store
                    .compare_and_swap_device_grant(&expected, grant)
                    .await
                    .map_err(storage_error)?;
                return Err(ErrorResponse::new(ErrorCode::SlowDown));
            }
        }

        // Cloned before `grant` is moved, and no more often than the `match grant.state.clone()`
        // this replaced: the branch arms need the state and the swap needs it as the expectation.
        let state = grant.state.clone();
        grant.last_poll_at = Some(now);

        match state {
            DeviceGrantState::Pending => {
                self.store
                    .compare_and_swap_device_grant(&DeviceGrantState::Pending, grant)
                    .await
                    .map_err(storage_error)?;
                Err(ErrorResponse::new(ErrorCode::AuthorizationPending))
            }
            DeviceGrantState::Denied => {
                // Terminal answer, delivered once; the grant is consumed with it.
                let _ = self.store.take_device_grant(device_code).await;
                Err(ErrorResponse::new(ErrorCode::AccessDenied))
            }
            DeviceGrantState::Approved { subject } => {
                // Single use: redemption goes through the atomic take, so a concurrent double
                // poll can only mint one token; the loser sees `invalid_grant`.
                let taken = self
                    .store
                    .take_device_grant(device_code)
                    .await
                    .map_err(storage_error)?
                    .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;
                // No resource: the device authorization request does not carry one (see
                // `token_with_resources`), and the poll above refuses any the client sends.
                self.issue_boxed(
                    &client,
                    bound,
                    GrantType::DeviceCode,
                    // The instant the DEVICE ASKED, which is NOT the instant the user approved.
                    // RFC 8628 s3.3 approval happens at the host's own verification UI and
                    // `DeviceGrantState::Approved` records only the subject, so the approval
                    // instant is never persisted and `created_at` is the closest thing that
                    // exists. It is EARLIER than the decision, never later, so a barrier recorded
                    // in between refuses this grant rather than admitting it: fail-closed, at the
                    // cost of a user who re-approves after withdrawing consent having to restart
                    // the device flow. See `IssuedToken::grant_established_at`, which states the
                    // window in full.
                    taken.created_at,
                    Some(subject),
                    taken.scope,
                    Vec::new(),
                    // No details: the device authorization request does not carry them and
                    // the poll above refuses any the client sends.
                    GrantedDetails::default(),
                    None,
                    true,
                    // The device grant carries no authentication report: RFC 8628 s3.3 approval
                    // happens at the host's own verification UI, which is where the report would
                    // have to be taken, and inventing one here would be this server asserting
                    // something it never witnessed.
                    GrantedAuthentication::default(),
                    // No actor: this grant delegates nothing (RFC 8693 s4.1).
                    GrantedActor::default(),
                    // No ceiling: RFC 8628 approval starts a grant, exactly as a code redemption
                    // does, so the ordinary `access_token_ttl` is the whole rule.
                    None,
                )
                .await
            }
        }
    }

    /// RFC 6749 section 6 with OAuth 2.1 rotation: redeem a refresh token, single use.
    async fn refresh_token(
        &self,
        client_id: &ClientId,
        bound: &Bound<'_>,
        refresh_token: &str,
        requested_scope: Option<&ScopeSet>,
        requested_resources: &[String],
        requested_details: GrantedDetails,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;
        if !client.allows_grant(GrantType::RefreshToken) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient));
        }

        // Consume first (atomic): that is what makes redemption single use under concurrency.
        // Judging comes after, and every judgement below either puts the record back or has a
        // stated reason not to.
        let record = self
            .store
            .take_refresh_token(refresh_token)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidGrant))?;

        // Presented by a client it was not issued to. The record goes BACK: the presenter proved
        // only that they hold a string, and destroying a live credential on that basis locks out
        // the client that legitimately holds it while costing the attacker nothing. Same reasoning
        // as the authorization code path, which has always put the record back on a mismatch.
        if record.client_id != client.client_id {
            self.restore_refresh_token(record).await?;
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }

        // REUSE. This token was already rotated away, so two parties hold it, and the AS has just
        // been handed unambiguous evidence of that. OAuth 2.1 draft section 6.1 and RFC 9700
        // section 4.14.2: invalidate the presented token AND revoke the tokens issued for that
        // authorization grant. Refusing the presentation alone would be the defence inverted,
        // because the party who presents the superseded token is by definition the one who did NOT
        // redeem it first, which in a theft is the victim.
        //
        // When the revocation SUCCEEDS it removes every record carrying this id, including this
        // one, so there is nothing to put back. When it fails there is, and that is the whole of
        // the paragraph below.
        if record.state == RefreshTokenState::Spent {
            // THE STORE FAILING HERE MUST NOT PROPAGATE, and the reason is the same one the
            // authorization-code replay path states above: the wire cannot carry this news. The
            // answer to a reused refresh token is `invalid_grant` however badly the store is
            // behaving, so the AUDIT EVENT is the only signal a deployment gets. Returning the
            // storage error instead lost all three halves of the response at once — the family
            // was not revoked, so the thief's rotated chain stayed live; the `Spent` record had
            // ALREADY been removed by `take_refresh_token` above and was never put back, so RFC
            // 9700 section 4.14.2 reuse detection for that family was off from then on and a later
            // presentation of the same string read as an unknown token; and no event fired at all,
            // so the host's only audit channel was never told any of it.
            let mut containment_failed = false;
            // MOVED out of the record before the `Err` arm below can move the record itself back
            // into the store. One allocation, on the detected-compromise path only.
            let family_id = record.family_id.clone();
            let mut records_revoked = 0;
            match self
                .store
                .revoke_token_family(&family_id, self.revocation_window())
                .await
            {
                Ok(revoked) => records_revoked = revoked,
                Err(_) => {
                    containment_failed = true;
                    // THE ALARM STAYS ARMED. The record goes back exactly as it was read, still
                    // `Spent`, because it is the evidence: it is what makes the NEXT presentation
                    // of this string detectable as reuse rather than as an unknown token. Its own
                    // outcome is not inspected because `containment_failed` is already true —
                    // the revocation failing is the compromise this event has to report, and a
                    // refused or failed restore only adds to a story that is already the bad one.
                    let _ = self.store.put_refresh_token(record).await;
                }
            }
            // EVIDENCE OF COMPROMISE, and the event most likely to be asked about after the fact:
            // the family revocation also logs out the legitimate client. It is emitted on BOTH
            // outcomes. A reuse that could not be contained is the more urgent of the two, not the
            // one worth staying quiet about, and `containment_failed` is what stops the event
            // claiming a containment that did not happen.
            self.hooks.emit(|| Event::RefreshTokenReuseDetected {
                client_id: client.client_id.as_str(),
                family_id: &family_id,
                records_revoked,
                containment_failed,
            });
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("refresh token reuse detected; the grant has been revoked"));
        }

        // RFC 9449 s5: a refresh chain issued to a DPoP-bound grant stays bound to the SAME key,
        // and a rotation has to prove possession of it. Without this the binding would be
        // decorative past the first access token: a stolen refresh token could simply be re-bound
        // to the thief's key on the next rotation, leaving the attacker holding a token they can
        // prove possession for while the victim's key is the one refused. The record goes BACK, as
        // for every other judgement here that is not evidence of compromise.
        #[cfg(feature = "dpop")]
        if record.jkt.as_deref() != bound.jkt {
            self.restore_refresh_token(record).await?;
            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)
                .with_description("this refresh token is bound to a different DPoP key"));
        }

        // RFC 8705 s3, and word for word the same argument as the DPoP check above: a chain
        // issued over a client certificate stays bound to THAT certificate, and a rotation
        // has to present it again. Without this the binding is decorative past the first
        // access token, because a stolen refresh token could be re-bound to the thief's own
        // certificate on the next rotation. Section 3 makes it a MUST for public clients
        // specifically; applying it to every bound chain costs a confidential mutual-TLS
        // client nothing, since it presents that certificate on every request anyway.
        #[cfg(feature = "mtls")]
        if record.x5t_s256.as_deref() != bound.cred.certificate.map(|c| c.thumbprint()) {
            self.restore_refresh_token(record).await?;
            return Err(
                ErrorResponse::new(ErrorCode::InvalidGrant).with_description(
                    "this refresh token is bound to a different client certificate",
                ),
            );
        }

        if let Some(expires_at) = record.expires_at {
            if self.clock.now() >= expires_at {
                // Not put back: an expired chain can never become valid again, and keeping it
                // would only be storage the host has to sweep.
                return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("refresh token chain expired"));
            }
        }

        // THE REGISTRATION'S CEILING, RE-APPLIED AT EVERY ROTATION.
        //
        // `Client::allowed_scopes` is documented as "the scopes this client may ever be granted",
        // and until the 0.9.1 audit a refresh chain was the one place that promise was not kept:
        // the only ceiling here was `record.scope`, so an operator who discovered a client should
        // never have held `payments:write` and narrowed the registration kept minting it on every
        // rotation. With `refresh_token_ttl` defaulting to `None` — no expiry at all — "may ever
        // be granted" was, by default, "may be granted forever regardless of what the registration
        // now says". Only `delete_client` or a per-family revocation the operator has no list of
        // actually stopped it.
        //
        // A code or a device grant has the same gap for its own lifetime, but those are 60 and 600
        // seconds and self-closing; a chain is not, which is why the check lands here.
        //
        // Refusing rather than silently intersecting is the fail-closed direction and the honest
        // one: the client asked to continue a grant this server is no longer willing to honour, and
        // quietly handing back a narrower token would look to the client like the grant it had. The
        // record is NOT put back — unlike the widening attempt below, this is not a retryable client
        // mistake, and leaving the chain alive would mean answering `invalid_scope` forever while
        // the credential stays valid.
        if !record.scope.is_subset(&client.allowed_scopes) {
            return Err(
                ErrorResponse::new(ErrorCode::InvalidScope).with_description(
                    "this grant carries scopes the client's registration no longer allows",
                ),
            );
        }

        // Narrowing only (RFC 6749 section 6: scope must not include any scope not originally
        // granted). A widening attempt is a client bug, not a compromise: put the record back so
        // the mistake is retryable.
        let scope = match requested_scope {
            None => record.scope.clone(),
            Some(s) if s.is_subset(&record.scope) => s.clone(),
            Some(_) => {
                self.restore_refresh_token(record).await?;
                return Err(ErrorResponse::new(ErrorCode::InvalidScope)
                    .with_description("refresh may narrow scope, never widen it"));
            }
        };

        // RFC 8707 s2, the same narrowing rule as the scope rule immediately above and refused the
        // same way: the record goes back so a client that asked for the wrong resource can retry.
        // RFC 8707 s2 and RFC 9396 s6, one fallible expression and one error path, for the
        // reason the authorization code grant gives above. The chain carries what the
        // PREVIOUS leg narrowed to, so a client that narrowed once cannot climb back on the
        // next rotation; the record goes back either way, because a widening attempt here is
        // a client bug and not evidence of compromise.
        let narrowed = self
            .narrow_and_permit(&record.resource, requested_resources)
            .and_then(|r| {
                GrantedDetails::of_refresh(&record)
                    .narrow(&requested_details)
                    .map(|d| (r, d))
            });
        let (resource, details) = match narrowed {
            Ok(narrowed) => narrowed,
            Err(e) => {
                self.restore_refresh_token(record).await?;
                return Err(e);
            }
        };

        // Retain the rotated token, marked spent, exactly as the authorization code path retains a
        // consumed code and for the same reason: a deleted token makes a later presentation
        // indistinguishable from an unknown string, and reuse detection is then impossible. A
        // chain with no absolute expiry gets a retention deadline here, so the record is
        // reclaimable by `Storage::sweep_expired` rather than immortal.
        //
        // THIS WRITE HAPPENS BEFORE ISSUANCE, AND THE ORDER IS A SECURITY PROPERTY RATHER THAN A
        // STYLE CHOICE. `Storage` deliberately has no transaction (see the trait's own docs: a host
        // may be backing this with anything from a HashMap to a sharded KV store, and requiring
        // cross-key atomicity would exclude most of them), so the atomic take above and this write
        // CANNOT be made one operation. All that can be chosen is which way the pair fails.
        //
        // Issuing first and marking spent afterwards fails OPEN. The take has already removed this
        // token; if anything in issuance or in this write then fails, the token is gone with NO
        // spent record, so a later presentation of it reads as an unknown string rather than as
        // reuse. RFC 9700 section 4.14.2 detection is then off for this family, permanently and
        // silently, at exactly the moment the deployment's storage is misbehaving, which is when a
        // compromise is most likely to go unnoticed. The freshly minted tokens meanwhile stay live
        // and orphaned, because the caller is answered with an error and never sees them.
        //
        // Marking spent first fails CLOSED, and that is the right trade. If this write fails,
        // nothing has been minted and the client re-authenticates. If it succeeds and issuance then
        // fails, the client is locked out of this chain and re-authenticates, and the alarm is
        // ARMED: the next presentation of this token is recognised as reuse and revokes the family.
        // Locking a client out is an inconvenience it can recover from without help; a
        // compromise-detection capability going offline is not.
        let chain_expires_at = record.expires_at;
        // Read off the record BEFORE it is moved into the spent value below. These are the same
        // three clones the issuance took when it ran first, so the ordering change costs nothing.
        let subject = record.subject.clone();
        let family_id = record.family_id.clone();
        let authentication = GrantedAuthentication::from_refresh(&record);
        // Read BEFORE `record` is consumed into `spent` below.
        let grant_established_at = record.grant_established_at;
        let spent = RefreshTokenRecord {
            state: RefreshTokenState::Spent,
            // `saturating_deadline` rather than `+`: `refresh_reuse_window` is a plain public
            // field with no validating constructor, and this branch is the DEFAULT
            // configuration's (`refresh_token_ttl: None` means the chain has no absolute expiry),
            // so every rotation in such a deployment performs this addition on a request path.
            expires_at: chain_expires_at.or_else(|| {
                Some(saturating_deadline(
                    self.clock.now(),
                    self.config.refresh_reuse_window,
                ))
            }),
            ..record
        };
        // NOT `restore_refresh_token`: this write is not a restoration and a refusal here is not
        // benign. The spent marker is what arms reuse detection for the token about to be minted,
        // so if a revocation has reached this family the rotation must STOP rather than continue
        // to issuance. Continuing would mint a chain from a grant that was revoked a moment ago,
        // and would do it with the alarm disarmed.
        if self
            .store
            .put_refresh_token(spent)
            .await
            .map_err(storage_error)?
            .is_refused()
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("the grant was revoked while this token was being refreshed"));
        }

        self.issue_boxed(
            &client,
            bound,
            GrantType::RefreshToken,
            // CARRIED from the chain, never restamped. Restamping here would let a chain walk
            // forward past the revocation that killed the decision it descends from.
            grant_established_at,
            subject,
            scope,
            resource,
            details,
            Some(RefreshChain {
                family_id,
                expires_at: chain_expires_at,
            }),
            true,
            authentication,
            // A rotation carries no actor of its own: nothing was delegated by refreshing.
            GrantedActor::default(),
            // No ceiling from the access token being replaced: the CHAIN's own absolute expiry is
            // what bounds a refresh grant's total lifetime, and it is applied to the rotated
            // refresh token above rather than to the access token here.
            None,
        )
        .await
    }

    /// Mint and persist an access token (and, when configured, a rotated refresh token).
    ///
    /// `chain`: `None` starts a NEW family (a fresh grant); `Some(_)` continues an existing one,
    /// keeping both its family id and its absolute lifetime, which is what makes rotation a chain
    /// rather than a sequence of unrelated tokens.
    // Eight arguments rather than seven, because the audit event has to name the grant that
    // produced the token and `issue` is the only place that sees the whole issuance. Bundling them
    // into a struct would be churn for its own sake on a private function with four call sites.
    #[allow(clippy::too_many_arguments)]
    /// [`AuthorizationServer::issue`] behind one heap allocation.
    ///
    /// Every caller of `issue` goes through here, and the reason is a measurement rather than a
    /// preference. `issue` is the widest frame on the token path: it holds a whole `IssuedToken`
    /// and a whole `RefreshTokenRecord` across its storage awaits, and because a generator's size
    /// is the MAXIMUM over all of its states, that width is paid by every token request including
    /// the polls and refusals that never issue anything. Inlined, it puts the token future over
    /// tokio's 2048-byte debug boxing threshold as soon as `dpop` adds a binding to both records,
    /// and tokio's answer to that is to box the WHOLE token future on every single request.
    ///
    /// So: one allocation, paid only when a token is actually issued, instead of one allocation the
    /// size of the entire token future paid on every request that reaches this endpoint. The
    /// allocation gates in `tests/allocation.rs` are what settled this, and they measure both.
    ///
    /// # RE-MEASURED after 0.9.0, and KEPT
    ///
    /// The two other `Box::pin`s on this path (the RFC 9449 proof check and the RFC 7523 assertion
    /// check) were both removed at that point, because measuring them showed the future was byte
    /// for byte identical with and without them: they had stopped buying anything. This one had
    /// not. Inlined, the `--all-features` token future goes from 1344 bytes to 1608, leaving 440
    /// bytes of headroom against tokio's 2048 rather than 704.
    ///
    /// That trade is REFUSED, and the number is why. What removing it would save is one allocation
    /// per token ISSUED, out of the 39 a code redemption already costs. What it would spend is 264
    /// bytes of the margin against a threshold this crate has crossed twice already, once for 120
    /// bytes and once for 344; a future feature the size of `rar` would put it over, and the
    /// failure mode on the other side of that line is a 2 KB heap allocation on every single token
    /// request, refusals included. Two and a half percent off the issuance path is not worth
    /// spending a third of the headroom that keeps the whole endpoint off tokio's slow path.
    #[allow(clippy::too_many_arguments)]
    fn issue_boxed<'a>(
        &'a self,
        client: &'a Client,
        bound: &'a Bound<'_>,
        grant_type: GrantType,
        // The instant the GRANT behind this issuance was authorized: the code's mint, the device
        // approval, or the instant carried forward from the chain. NOT `now`. See
        // `crate::token::IssuedToken::grant_established_at`.
        grant_established_at: SystemTime,
        subject: Option<String>,
        scope: ScopeSet,
        resource: Vec<String>,
        details: GrantedDetails,
        chain: Option<RefreshChain>,
        allow_refresh: bool,
        authentication: GrantedAuthentication,
        actor: GrantedActor,
        lifetime_ceiling: Option<SystemTime>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + Send + 'a>,
    > {
        Box::pin(self.issue(
            client,
            bound,
            grant_type,
            grant_established_at,
            subject,
            scope,
            resource,
            details,
            chain,
            allow_refresh,
            authentication,
            actor,
            lifetime_ceiling,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn issue(
        &self,
        client: &Client,
        bound: &Bound<'_>,
        grant_type: GrantType,
        // The instant the GRANT behind this issuance was authorized: the code's mint, the device
        // approval, or the instant carried forward from the chain. NOT `now`. See
        // `crate::token::IssuedToken::grant_established_at`.
        grant_established_at: SystemTime,
        subject: Option<String>,
        scope: ScopeSet,
        resource: Vec<String>,
        details: GrantedDetails,
        chain: Option<RefreshChain>,
        allow_refresh: bool,
        authentication: GrantedAuthentication,
        actor: GrantedActor,
        // An ABSOLUTE CEILING on the issued access token's expiry, or `None` for the ordinary
        // `access_token_ttl` from now. `Some` exists for RFC 8693 token exchange, where the issued
        // token derives its authority from a subject token that is itself expiring: without a
        // ceiling the exchanged token is an ordinary access token, therefore an acceptable SUBJECT
        // token, therefore re-exchangeable just before each expiry for a fresh full TTL, forever.
        // That is a grant renewing its own lifetime without limit, which is exactly what this
        // grant refuses to issue a refresh token for.
        lifetime_ceiling: Option<SystemTime>,
    ) -> Result<TokenResponse, ErrorResponse> {
        // `bound` carries only the RFC 9449 key binding, so with that feature off it is genuinely
        // unused HERE. It stays in the signature regardless, so the four call sites do not have to
        // differ by feature: a call site that differs by feature is a call site that gets it wrong
        // under the configuration nobody builds locally.
        #[cfg(not(feature = "dpop"))]
        let _ = bound;
        // Same for the RFC 9470 authentication report: without `consent` the wrapper is empty and
        // genuinely unused here, and an unused parameter is a warning rather than a signature that
        // differs by feature.
        #[cfg(not(feature = "consent"))]
        let _ = authentication;
        // And the RFC 8693 actor, which only a delegation exchange ever fills.
        #[cfg(not(feature = "token-exchange"))]
        let _ = actor;
        // Likewise: without `rar` the details are a zero sized value nothing reads.
        #[cfg(not(feature = "rar"))]
        let _ = details;
        let now = self.clock.now();
        // ONE expiry instant, computed ONCE and used by all three places that state it: the
        // persisted record, the RFC 9068 `exp` claim, and the RFC 6749 s5.1 `expires_in` member. A
        // token whose signed `exp` disagrees with the expiry this server enforces on introspection
        // is worse than either bound on its own, because the two halves of the deployment then
        // disagree about when the token died.
        //
        // The ceiling can only ever SHORTEN the lifetime: `min` of the ordinary deadline and
        // whatever the caller capped it at.
        let expires_at = {
            let ordinary = saturating_deadline(now, self.config.access_token_ttl);
            match lifetime_ceiling {
                Some(ceiling) => ordinary.min(ceiling),
                None => ordinary,
            }
        };

        let issues_refresh = allow_refresh
            && self.config.issue_refresh_tokens
            && client.allows_grant(GrantType::RefreshToken);

        // ONE DRAW FOR ALL THREE ARTIFACTS. `getrandom::fill` is a syscall whose cost is almost
        // entirely per CALL rather than per byte (see `hex_encode`), and an issuance needed up to
        // three of them: a family id, an access token, and a refresh token. MEASURED at roughly
        // 1 us saved per issuance, which is about half of `client_credentials_issue` and a fifth of
        // an authorization code redemption.
        //
        // Scoped to a block with NO await inside it, deliberately. The buffer must not survive
        // across a suspension point or its 80 bytes join the coroutine's state, and this future is
        // held under tokio's 2048-byte debug boxing threshold by `tests/allocation.rs`. The refresh
        // token is therefore encoded HERE, before the buffer dies, and carried as an `Option<String>`
        // to its use below rather than being drawn there.
        //
        // Drawing 80 bytes when only 32 will be used is free: the syscall is the cost, and the
        // alternative (branching on `issues_refresh` before the draw) would buy nothing and add a
        // path where the unused half is not overwritten.
        let (family_id, access_token, pending_refresh) = {
            let mut entropy = [0u8; 80];
            // `ok_or_else` rather than `expect`: this is the token endpoint, every other
            // fallible step of which answers `server_error`, and a panic here aborts the host
            // in a host built with `panic = "abort"`. See `try_random_hex`.
            getrandom::fill(&mut entropy).map_err(|_| randomness_error())?;
            // The family id is minted (or inherited) BEFORE the access token, because the access
            // token has to carry it: RFC 9700 section 4.14.2 revokes the tokens of the whole grant
            // on detected reuse, and an access token with no family is unreachable from that event.
            // A grant that issues no refresh chain has no family, and allocates nothing for one:
            // there is no chain to reuse, so there is nothing a reuse detection could revoke.
            let family_id = match (&chain, issues_refresh) {
                (Some(c), _) => Some(c.family_id.clone()),
                (None, true) => Some(hex_encode(&entropy[..16])),
                (None, false) => None,
            };
            (
                family_id,
                hex_encode(&entropy[16..48]),
                issues_refresh.then(|| hex_encode(&entropy[48..])),
            )
        };

        // Cloned ONLY when a sink is installed: both values are consumed by the records written
        // below, and an unobserved host must not pay two clones per issued token. BOXED because
        // this local lives across every await in the issuance, and the token future is 1936 bytes
        // against tokio's 2048-byte debug boxing threshold; 8 bytes here rather than 48 is 40
        // bytes of headroom for every caller, bought with one small allocation paid only by a
        // host that asked to be told about issuance.
        let audit = self
            .hooks
            .is_observed()
            .then(|| Box::new((subject.clone(), family_id.clone())));

        // RFC 9068, when the host configured it: the WIRE token becomes a signed JWT and the
        // random string above becomes its `jti`. The record below is persisted either way, keyed
        // by whatever the client will actually present, so RFC 7662 introspection and RFC 7009
        // revocation keep working and a revoked JWT is genuinely dead at this AS rather than
        // merely deprecated.
        // Bound before it is matched rather than matched directly, because the signing input is
        // then visibly the LAST thing computed before the suspension. MEASURED: this makes no
        // difference to the frame either way (1704 bytes on `--all-features` both ways); it is
        // written for the reader, and the measurement is recorded so nobody has to repeat it.
        //
        // WHAT IS LIVE ACROSS THE AWAIT IS THE WHOLE ISSUANCE, and an earlier version of this
        // comment claimed otherwise. `now`, `issues_refresh`, `family_id`, `pending_refresh`,
        // `audit`, `subject`, `scope`, `resource`, `details`, `authentication`, `client` and
        // `bound` are all built above and read below, so they are all in the frame. The SIZE
        // claim is unaffected and is gated by `tests/allocation.rs`; the description was simply
        // wrong, and it matters because that await is the host's `Es256Signer` and is unbounded.
        #[cfg(feature = "jwt")]
        let prepared = self.access_token_signing_input(
            client,
            subject.as_deref(),
            &scope,
            &resource,
            &details,
            now,
            expires_at,
            access_token,
            bound,
            &actor,
            &authentication,
        )?;
        #[cfg(feature = "jwt")]
        let access_token = match prepared {
            Err(opaque) => opaque,
            // The ONE await the RFC 9068 path adds, and the only thing live across it is this
            // `String` and a borrow of the configuration. A signer that cannot sign mints NOTHING:
            // there is no fallback to an opaque token and no unsigned token, because an access
            // token this server could not sign is one it must not issue.
            Ok((jwt, input)) => jwt.finish_signing(input).await.map_err(|e| {
                let _ = e;
                ErrorResponse::new(ErrorCode::ServerError)
            })?,
        };
        let refused = self
            .store
            .put_token(IssuedToken {
                // RFC 9449 s6: the binding is recorded on the AS side too, not only in the token,
                // so that RFC 7662 introspection can report it and a resource server can check it
                // without having to parse a token this server may have issued as opaque.
                #[cfg(feature = "dpop")]
                jkt: bound.jkt.map(Box::from),
                // The record was written this way before there was anybody to read it, because the
                // record is the half that cannot be added later; a registered resource server
                // reads it now (`ServerConfig::resource_servers`).
                //
                // RFC 8705 s3, and the same argument as `jkt` immediately above: an opaque
                // token carries its binding nowhere else, so s3.2 introspection could not
                // report it if it were not written down here.
                #[cfg(feature = "mtls")]
                x5t_s256: bound.cred.certificate.map(|c| Box::new(*c.thumbprint())),
                access_token: access_token.clone(),
                client_id: client.client_id.clone(),
                subject: subject.clone(),
                scope: scope.clone(),
                resource: resource.clone(),
                // RFC 9396 s7: the details as granted, assigned to this access token. This
                // is what introspection (s9.2) reports and what the s9.1 JWT claim carries.
                #[cfg(feature = "rar")]
                authorization_details: details.clone().into_details(),
                issued_at: now,
                // The GRANT's instant, not this issuance's: a barrier is compared against it, and
                // a rotation writing at `now` must not thereby outlive the revocation that killed
                // the decision it descends from.
                grant_established_at,
                // Computed at the top of this function, so the record, the signed `exp` and the
                // `expires_in` below are one instant stated three times rather than three.
                expires_at,
                family_id: family_id.clone(),
                // RFC 8693 s4.1: the token records who authority was delegated TO, so that RFC
                // 7662 introspection can report it. An opaque token carries it nowhere else.
                #[cfg(feature = "token-exchange")]
                act: actor.act.clone(),
                // RFC 9470 s6.2: the token reports the authentication behind it, so introspection can
                // answer the question the resource server's challenge asked.
                #[cfg(feature = "consent")]
                authentication: authentication.authentication.clone(),
            })
            .await
            .map_err(storage_error)?;
        // The grant was revoked while this issuance was in flight, most likely across the signing
        // await immediately above, which is a network round trip when the host's `Es256Signer`
        // fronts a KMS. Nothing was written, so there is nothing to undo; the client is told its
        // grant is invalid, which by now it is.
        if refused.is_refused() {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("the grant was revoked while this token was being issued"));
        }

        let refresh_token = if issues_refresh {
            let expires_at = match &chain {
                Some(c) => c.expires_at,
                None => self
                    .config
                    .refresh_token_ttl
                    .map(|ttl| saturating_deadline(now, ttl)),
            };
            // Drawn in the single `getrandom` call at the top of this function; `issues_refresh`
            // is what decided both that draw and this branch, so the value is always present.
            let rt = pending_refresh.expect("issues_refresh decided both");
            let refused = self
                .store
                .put_refresh_token(RefreshTokenRecord {
                    // RFC 9449 s5: the chain remembers the key it was issued to, and rotation
                    // checks it. See the check in `refresh_token`.
                    #[cfg(feature = "dpop")]
                    jkt: bound.jkt.map(Box::from),
                    // RFC 8705 s3: the chain remembers the certificate it was issued to, and
                    // rotation checks it. See the check in `refresh_token`.
                    #[cfg(feature = "mtls")]
                    x5t_s256: bound.cred.certificate.map(|c| Box::new(*c.thumbprint())),
                    refresh_token: rt.clone(),
                    client_id: client.client_id.clone(),
                    subject,
                    scope: scope.clone(),
                    // The chain remembers what it may narrow from on the next rotation.
                    resource,
                    #[cfg(feature = "rar")]
                    authorization_details: details.clone().into_details(),
                    expires_at,
                    // CARRIED, never restamped: see `RefreshTokenRecord::grant_established_at`.
                    grant_established_at,
                    // Present whenever a refresh token is: `issues_refresh` is what decided both.
                    family_id: family_id.unwrap_or_default(),
                    state: RefreshTokenState::Active,
                    // Carried, never restamped: see `RefreshTokenRecord::authentication`.
                    #[cfg(feature = "consent")]
                    authentication: authentication.authentication,
                })
                .await
                .map_err(storage_error)?;
            // Revoked BETWEEN the two writes. This is the case that needs undoing rather than
            // merely refusing: the access token a few lines above is already in the store, and
            // leaving it there would hand the caller a live credential minted from a grant that no
            // longer exists, which is the resurrection defect wearing a different hat.
            if refused.is_refused() {
                self.undo_issuance(&access_token).await;
                return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("the grant was revoked while this token was being issued"));
            }
            Some(rt)
        } else {
            None
        };

        // Emitted after BOTH records are persisted, so the event describes a token that exists.
        if let Some(audit) = &audit {
            self.hooks.emit(|| Event::TokenIssued {
                client_id: client.client_id.as_str(),
                grant_type,
                subject: audit.0.as_deref(),
                scope: &scope,
                family_id: audit.1.as_deref(),
                refresh_issued: refresh_token.is_some(),
            });
        }

        Ok(TokenResponse {
            access_token,
            // RFC 9449 s5: a token bound to a proof key is a `DPoP` token and not a `Bearer` one,
            // and the difference is exactly what tells the client, and any resource server reading
            // the response, that the token must be presented with a proof.
            #[cfg(feature = "dpop")]
            token_type: match bound.jkt {
                Some(_) => TokenType::Dpop,
                None => TokenType::Bearer,
            },
            #[cfg(not(feature = "dpop"))]
            token_type: TokenType::Bearer,
            // RFC 6749 s5.1: the lifetime IN SECONDS FROM NOW of the token just issued, derived
            // from the same `expires_at` the record and the signed `exp` carry. Not
            // `access_token_ttl`, which is only the same number when nothing capped the lifetime;
            // reporting the uncapped TTL for a capped token would have the client keep using a
            // token this server has already stopped honouring.
            //
            // `unwrap_or_default` is the fail-closed direction: a ceiling already in the past
            // yields zero rather than an underflow, and zero tells the client the token is spent.
            expires_in: expires_at.duration_since(now).unwrap_or_default().as_secs(),
            refresh_token,
            scope: (!scope.is_empty()).then(|| scope.to_string()),
            // RFC 9396 s7: what was GRANTED, from the same value that reaches the stored record
            // and the signed token, so the three cannot disagree about what this token authorizes.
            #[cfg(feature = "rar")]
            authorization_details: details.into_details(),
        })
    }

    /// Opaque-token introspection: `Ok(Some(_))` only for a known, unexpired token.
    ///
    /// This is the host-facing form, which hands back the whole record. The RFC 7662 WIRE form is
    /// [`AuthorizationServer::introspection_response`], which answers the reduced, caller-scoped
    /// document the RFC defines.
    pub async fn introspect(
        &self,
        access_token: &str,
    ) -> Result<Option<std::sync::Arc<IssuedToken>>, StorageError> {
        Ok(self
            .store
            .get_token(access_token)
            .await?
            .filter(|t| self.clock.now() < t.expires_at))
    }

    /// RFC 7662 token introspection, as the protected endpoint the RFC describes.
    ///
    /// The caller must authenticate (section 2.1), and a token the caller has no relationship to
    /// reads as inactive rather than as a description of somebody else's grant: section 2.2 says
    /// the response for an invalid token is simply `active: false`, and section 4 warns that this
    /// endpoint otherwise becomes an oracle for probing tokens a caller does not hold.
    ///
    /// # The two callers
    ///
    /// Section 1 names a protected resource as the primary consumer, and section 2.1 permits a
    /// client to introspect its own token. Both are served:
    ///
    /// - the token's OWN CLIENT, which sees the whole record; and
    /// - a RESOURCE SERVER declared in [`ServerConfig::resource_servers`], which sees a token only
    ///   when the token's RFC 8707 [`IssuedToken::resource`] set names one of the identifiers that
    ///   resource server is registered for.
    ///
    /// Everything else is `{"active": false}`, including a live token belonging to another client
    /// and addressed to another resource server. A deployment that registers no resource servers
    /// answers the token's own client and nobody else, which is what this server did through
    /// 0.9.1.
    ///
    /// The resource server is not a new kind of principal and gets no new credential: it registers
    /// as an ordinary confidential client and authenticates here exactly as any client does. See
    /// [`ServerConfig::resource_servers`] for why the authorization half is not optional -- and
    /// for what a resource server's traffic costs the client-authentication rate limit, which is
    /// the one thing about this endpoint that a host has to size rather than accept. A resource
    /// server calls it once per request at the protected resource, and the default budget was
    /// derived from a client's token traffic.
    ///
    /// # What a resource server is not told
    ///
    /// RFC 7662 section 5: "omitting privacy-sensitive information from an introspection response
    /// is the simplest way of minimizing privacy issues". The sensitive thing here is not only the
    /// user's identity, which the resource server needs and gets. It is the SHAPE OF THE GRANT:
    /// which OTHER services this user's token is good at. Two members carry that fact and both are
    /// narrowed to the asking resource server:
    ///
    /// - `aud`, to the RFC 8707 identifiers that resource server is registered for; and
    /// - `authorization_details`, to the RFC 9396 section 2.2 elements whose `locations` name one
    ///   of those identifiers, or that carry no `locations` at all. A kept element has its own
    ///   `locations` narrowed too, so an element addressed to two resource servers does not smuggle
    ///   the second one's URI past the filter. Section 9.2 asks for precisely this ("filtered and
    ///   extended for the RS making the introspection request"), and section 9.1 says the same of
    ///   the JWT form.
    ///
    /// An earlier 0.9.2 draft narrowed `aud` and shipped `authorization_details` whole, which meant
    /// the disclosure
    /// the first refused was re-made verbatim by the second, with the actions and privileges
    /// granted elsewhere attached. That is fixed rather than accepted, and the alternative
    /// resolution -- STOP NARROWING `aud`, and treat a registered resource server as a semi-trusted
    /// party that sees the grant as granted -- was rejected. A resource server is registered for
    /// the identifiers it answers for and nothing wider; a deployment adding a second protected
    /// resource would otherwise be silently telling the first one about it, and the party who pays
    /// for that is the user, who is not present and cannot be asked. Consistency in the other
    /// direction is cheaper to buy and costs somebody else.
    ///
    /// Two members are NOT narrowed, and the omission is a decision rather than an oversight:
    ///
    /// - `scope` is the whole grant's scope set. Nothing in this crate maps a scope to a resource
    ///   server -- there is no per-resource catalogue to filter against -- so any narrowing would
    ///   be a guess at which strings "belong" to the asker, and a resource server that silently
    ///   loses a scope refuses access the resource owner granted. A scope is also a token in the
    ///   deployment's own vocabulary; unlike a `locations` URI it does not NAME another service.
    /// - `act` (RFC 8693 section 4.1) describes who is acting in the call this resource server is
    ///   handling, not where else the grant reaches.
    ///
    /// The cost of the narrowing, stated plainly: a resource server given a filtered
    /// `authorization_details` cannot distinguish "not granted" from "not for you". That is the
    /// same indistinguishability the `aud` narrowing already imposes, and it is the harmless
    /// direction -- both readings oblige the resource server to refuse, because an element it is
    /// not named in is one it must not act on either way. The disclosure direction has no such
    /// symmetry. A caller that needs the unfiltered record is the token's OWN CLIENT, and it still
    /// gets it; so does a host, through [`AuthorizationServer::introspect`].
    pub async fn introspection_response(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
    ) -> Result<IntrospectionResponse, ErrorResponse> {
        self.introspection_response_with_credential(
            client_id,
            &ClientCredential::secret(client_secret),
            token,
        )
        .await
    }

    /// RFC 7662 introspection for a caller authenticating with any credential this server accepts,
    /// including an RFC 7523 assertion. See
    /// [`AuthorizationServer::device_authorization_with_credential`] on why this is an addition
    /// rather than a replacement.
    pub async fn introspection_response_with_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        token: &str,
    ) -> Result<IntrospectionResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, cred).await?;
        // RFC 7662 section 2.1 requires the endpoint to be protected, and section 4 says it MUST
        // NOT be publicly available, because it otherwise describes any token an attacker has
        // merely obtained a copy of. A PUBLIC client has no secret to verify, so "authenticated as
        // a public client" is a sentence true of every caller on the internet: naming a client id
        // is not authentication, and an ownership check made against an identity anyone may claim
        // is not an access control. Same refusal as `client_credentials_token`, for the same
        // reason.
        //
        // BARE, AND THE REASON GOES TO THE AUDIT CHANNEL. It used to carry the description
        // "introspection requires a confidential client", which was a client-existence oracle:
        // an unknown client id and a confidential client with the wrong secret both leave
        // `authenticate_client` as a BARE `invalid_client` (see "THE ONE EXIT"), so a description
        // here was the one answer that meant "this id is registered, and it is public". That is
        // precisely the distinction the whole credential path collapses, rebuilt one endpoint
        // downstream of it. 0.9.2 also turns this endpoint into an advertised resource-server-
        // facing surface, so it is now a probe an attacker is invited to make.
        //
        // The operator still gets the sentence — `ClientAuthFailure::NotConfidential` — because
        // the usual cause is a misregistered resource server rather than an attack, and a bare
        // refusal with nothing in the log would be unactionable. The rate limiter is NOT charged
        // again: `authenticate_client` already recorded this attempt's outcome, and recording a
        // second one for a single request would make this endpoint count double.
        if matches!(client.auth, crate::client::ClientAuth::Public) {
            self.hooks.emit(|| Event::ClientAuthenticationFailed {
                client_id: client_id.as_str(),
                failure: ClientAuthFailure::NotConfidential,
            });
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }
        let record = self.introspect(token).await.map_err(storage_error)?;
        // WHOSE QUESTION IS THIS. RFC 7662 has two legitimate callers and they are answered from
        // the same arm but not with the same document, so the viewpoint is decided once, here,
        // before anything is copied out of the record.
        //
        // `None` covers unknown, expired, somebody else's, and addressed-to-some-other-resource-
        // server. All four are `{"active": false}` on purpose: section 2.2 gives exactly one answer
        // for a token the caller has not proven a relationship to, and distinguishing "no such
        // token" from "a live token that is not yours" would rebuild the oracle section 4 warns
        // about out of the error channel instead of the response body.
        let view = record
            .as_ref()
            .and_then(|t| self.introspection_view(&client, t));
        Ok(match (record, view) {
            (Some(t), Some(view)) => IntrospectionResponse {
                active: true,
                // RFC 7662 s2.2, THE WHOLE GRANT'S SCOPE SET, to both viewpoints, and deliberately
                // so: see "What a resource server is not told" on this method for why this member
                // is not narrowed the way `aud` and `authorization_details` are.
                scope: (!t.scope.is_empty()).then(|| t.scope.to_string()),
                client_id: Some(t.client_id.as_str().to_string()),
                sub: t.subject.clone(),
                #[cfg(feature = "dpop")]
                token_type: Some(match t.jkt {
                    Some(_) => TokenType::Dpop,
                    None => TokenType::Bearer,
                }),
                #[cfg(not(feature = "dpop"))]
                token_type: Some(TokenType::Bearer),
                exp: unix_seconds(t.expires_at),
                iat: unix_seconds(t.issued_at),
                iss: Some(self.issuer_identifier().to_string()),
                // RFC 7662 s2.2: `aud` is OPTIONAL, and this server has one to report exactly when
                // the grant carried RFC 8707 resource indicators. Omitted rather than empty when it
                // does not: see `IntrospectionResponse::aud`.
                //
                // THIS IS THE ONE MEMBER THE TWO VIEWPOINTS DO NOT SHARE. The token's own client
                // sees the whole set, because it asked for it and already holds it. A RESOURCE
                // SERVER sees only the identifiers it is itself registered for, because the rest of
                // the set is a list of the OTHER resource servers this user's token is good at, and
                // section 5's privacy considerations do not stop at the user's identity: telling
                // api.example that this token also works at payroll.example discloses the shape of
                // somebody's account to a third party that has no part in it. Narrowing here rather
                // than at the record keeps `aud` a true statement in both documents; it is the same
                // claim, answered to the extent the asker is entitled to it.
                aud: match &view {
                    IntrospectionView::OwningClient => {
                        (!t.resource.is_empty()).then(|| t.resource.clone())
                    }
                    IntrospectionView::ResourceServer(mine) => Some(mine.clone()),
                },
                // RFC 9470 s6.2. A resource server that sent a step-up challenge has to be able to
                // see whether the token it now holds satisfies it; without these two it would have
                // to take the client's word for that, which is the whole thing the challenge exists
                // to avoid.
                #[cfg(feature = "consent")]
                auth_time: t
                    .authentication
                    .as_ref()
                    .and_then(|a| unix_seconds(a.auth_time)),
                #[cfg(feature = "consent")]
                acr: t
                    .authentication
                    .as_ref()
                    .and_then(|a| a.acr.as_deref().map(str::to_string)),
                // RFC 9396 s9.2: the details as a top-level member of the introspection
                // response. For an OPAQUE token this is the ONLY way a resource server can
                // learn what the token actually authorizes, which is the whole point of the
                // parameter, and a resource server registered under
                // `ServerConfig::resource_servers` is now the caller that receives it.
                //
                // FILTERED FOR THE ASKER, for the reason `aud` above is. An earlier 0.9.2 draft
                // left it unfiltered until the audit noticed the two members carry the same fact. A
                // section 2.2 element has `locations`, which NAMES RESOURCE SERVERS BY URI, so
                // handing api.example the whole array says "this token also works at
                // payroll.example" in the very breath `aud` refuses to say it, and adds the
                // actions and privileges granted there. Section 9.2 asks for exactly this:
                // "filtered and extended for the RS making the introspection request".
                #[cfg(feature = "rar")]
                authorization_details: match &view {
                    IntrospectionView::OwningClient => t.authorization_details.clone(),
                    IntrospectionView::ResourceServer(mine) => {
                        details_for_resource_server(&t.authorization_details, mine)
                    }
                },
                // RFC 9449 s6.1 and RFC 8705 s3.2, in ONE RFC 7800 s3.1 object. Both mechanisms
                // register a member of `cnf` and a token can carry both, so this is built from
                // every binding the record has rather than from whichever one happens to be
                // checked first. Omitted entirely when there is none.
                //
                // A caller that introspects must be able to confirm the binding, or the binding
                // stops at this server and the caller is back to trusting a bearer string.
                // That caller is the token's own client or, since 0.9.2, the resource server the
                // token is addressed to; both need to confirm the binding for the same reason.
                #[cfg(any(feature = "dpop", feature = "mtls"))]
                cnf: {
                    let cnf = crate::token::Confirmation {
                        #[cfg(feature = "dpop")]
                        jkt: t.jkt.as_deref().map(str::to_string),
                        #[cfg(feature = "mtls")]
                        x5t_s256: t.x5t_s256.as_deref().copied(),
                    };
                    (!cnf.is_empty()).then_some(cnf)
                },
                // RFC 8693 s4.1, and the reason it is on the record at all: for an OPAQUE token
                // this is the only channel a resource server has for learning that what it holds
                // is a DELEGATION rather than the subject acting directly.
                //
                // Not narrowed, and unlike `scope` there is nothing here that could be: `act`
                // describes WHO IS ACTING in the call this resource server is being made, not
                // where else the grant reaches. It names no other resource server, so it does not
                // carry the fact `aud` withholds, and withholding it would leave the RS unable to
                // tell a delegated call from a direct one -- which is the one thing section 4.1
                // exists to tell it.
                #[cfg(feature = "token-exchange")]
                act: t.act.as_deref().cloned(),
            },
            // Unknown, expired, somebody else's, or addressed to a different resource server.
            // All four are one answer on purpose; see `view` above.
            _ => IntrospectionResponse::inactive(),
        })
    }

    /// Which RFC 7662 viewpoint `client` holds on `token`, or `None` for the callers section 2.2
    /// answers `{"active": false}`.
    ///
    /// Ownership is checked FIRST and wins outright. A client that is both the token's own client
    /// and a registered resource server is answered as the owner, which is the wider of the two
    /// documents; being told about your own token is not a privilege that a second, narrower role
    /// should be able to take away.
    fn introspection_view(
        &self,
        client: &Client,
        token: &IssuedToken,
    ) -> Option<IntrospectionView> {
        if token.client_id == client.client_id {
            return Some(IntrospectionView::OwningClient);
        }
        // The resource-server channel. A registration matches only by NAMING an identifier the
        // token actually carries, so a token whose grant requested no resource indicator at all
        // (`token.resource` empty) matches nothing here and is refused to every resource server.
        // That is deliberate and it is the whole defence: see `ServerConfig::resource_servers`.
        let mine: Vec<String> = self
            .config
            .resource_servers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|rs| rs.client_id == client.client_id)
            .flat_map(|rs| rs.resources.iter())
            .filter(|id| token.resource.iter().any(|r| r == *id))
            .map(|id| id.to_string())
            .fold(Vec::new(), |mut acc, id| {
                // Deduped because the same identifier may legitimately appear in two registrations
                // for one client (see `ResourceServerRegistration`), and `aud` repeating it would
                // be a malformed-looking document produced by a configuration that is not wrong.
                if !acc.contains(&id) {
                    acc.push(id);
                }
                acc
            });
        (!mine.is_empty()).then_some(IntrospectionView::ResourceServer(mine))
    }

    /// Record that a resource owner has consented to a client acting for them.
    ///
    /// One live consent per (client, subject) pair: an existing record is WIDENED in place, keeping
    /// its identifier and its original `granted_at`, so a user who approves one more scope next
    /// month still sees one entry rather than two and withdrawing it withdraws the whole
    /// relationship. See [`crate::consent::ConsentRecord::extend`].
    ///
    /// The library NEVER calls this for itself. Recording consent is a statement that a user agreed
    /// to something, and this crate has no way to know that: it never sees a user. The host calls
    /// it once its own consent step has actually been answered.
    ///
    /// # Concurrency, and what this used to concede
    ///
    /// This is a read-modify-write: it looks for an existing record, widens it, and writes it
    /// back. It is now a COMPARE-AND-SWAP against what it read
    /// ([`Storage::compare_and_swap_consent`]), retried once, and both halves of that matter.
    ///
    /// The half this doc used to argue away was two overlapping FIRST approvals each finding
    /// nothing and each creating a record, leaving the pair with two. The argument was that the
    /// records are additive so the damage is a possible re-prompt. That much was true, and it is
    /// no longer relevant: the create is conditional on the pair still being empty, so the loser
    /// sees the winner's record and widens it instead.
    ///
    /// The half this doc never considered is the one that was not benign, and it is the reason
    /// this changed. The second writer it reasoned about was another `record_consent`. The writer
    /// that actually mattered was [`AuthorizationServer::withdraw_consent`]: a widen that read a
    /// record, and wrote it back after the user clicked withdraw, RESURRECTED a consent the user
    /// had destroyed, and every later authorization request was answered from it. "Benign in the
    /// direction that matters" was a statement about the wrong direction. See the resurrection
    /// rule in the [`crate::store`] module docs.
    ///
    /// A host no longer owes this path a lock of its own.
    #[cfg(feature = "consent")]
    pub async fn record_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
        scope: &ScopeSet,
        resource: &[String],
        authentication: Option<crate::consent::Authentication>,
    ) -> Result<crate::consent::ConsentRecord, StorageError> {
        // REFUSED AT CREATION, because refusing at withdrawal is refusing at the one operation
        // that undoes damage.
        //
        // `Storage::revoke_consent` rejects an empty `client_id` or `subject`, and it reads them
        // out of the STORED record rather than off its argument — so a record created with an
        // empty subject can never be withdrawn by any input at all. The record stands, the cascade
        // never runs, and every token and refresh chain beneath it stays live for its full
        // lifetime, while `withdraw_consent` answers an error that contradicts its own
        // documented contract ("withdrawing a consent that is already gone is `Ok(0)`, not an
        // error"). A host whose subject resolver can yield the empty string — which this crate
        // never checks, because a subject is the host's own vocabulary for users — reaches that
        // state through the ordinary API.
        //
        // A `StorageError` rather than a new error type: this is the same class of refusal
        // `revoke_consent` already answers with, and a consent that names nobody is not a consent.
        if subject.is_empty() {
            return Err(StorageError::new(
                "a consent must name a subject; an empty subject cannot be withdrawn",
            ));
        }
        let now = self.clock.now();
        // TWO attempts, and no more. One retry is what a compare-and-swap needs to absorb an
        // ordinary lost race (the other writer created or widened the record, and this call can
        // simply widen theirs instead); a loop would be a spin against a withdrawal that is going
        // to keep refusing, on a path a human drives by clicking. The second failure is reported
        // as a storage error, which is the honest answer: the consent was NOT recorded.
        // WHAT THE FIRST ATTEMPT SAW, and the retry may not contradict it. A call that started as
        // a WIDEN must not become a CREATE on its second attempt: the only way the record can have
        // vanished between them is that it was withdrawn, and turning that into a fresh consent
        // hands the user back a live grant moments after they ended it. The other direction is
        // fine and is the ordinary lost race: a call that started as a create and now finds a
        // record simply widens that record instead.
        //
        // This is NOT enforced by refusing on the barrier, deliberately. A consent barrier stands
        // for the longest token lifetime the server mints, and refusing every create for that long
        // would mean a user who withdraws an application and approves it again five minutes later
        // is told no, for an hour, with nothing to tell them why. The rule that is actually needed
        // is narrower: within ONE call, the shape may not change.
        let mut started_as_widen = None;
        for attempt in 0..2 {
            // CLONED out of the shared snapshot, because this is the one consent path that MUTATES
            // what it read (`extend` below widens the grant in place). An `Arc` cannot be widened
            // while the store still holds it, so the clone the read used to make happens here
            // instead: the cost moved, it did not go away. It is paid once per host consent
            // decision, against the read being free on the authorization endpoint, which runs per
            // request. See `remembered_consent`.
            let existing = self.store.find_consent(client_id, subject).await?;
            let expected = existing.as_deref().cloned();
            match started_as_widen {
                None => started_as_widen = Some(expected.is_some()),
                // Started as a widen, and the record is gone. It was withdrawn while this call was
                // in flight, which is the direction that is not benign.
                Some(true) if expected.is_none() => {
                    return Err(StorageError::new(
                        "the consent was withdrawn while it was being recorded",
                    ))
                }
                Some(_) => {}
            }
            let _ = attempt;
            let mut record = match &expected {
                Some(existing) => existing.clone(),
                None => crate::consent::ConsentRecord {
                    // 16 bytes of OS randomness, hex encoded, the same shape as every other opaque
                    // identifier this server mints. It is not a credential (see the field's own
                    // docs), but it names a record that can end a user's sessions, so it must not
                    // be something a third party can produce by guessing two strings it already
                    // knows.
                    // `?` rather than a panic, for the reason `try_random_hex` gives. This
                    // function answers `StorageError`, so that is the shape the refusal takes
                    // here; the host learns what happened from its own logs either way.
                    consent_id: try_random_hex(16)
                        .ok_or_else(|| {
                            StorageError::new(
                                "the OS would not provide randomness for a consent id",
                            )
                        })?
                        .into_boxed_str(),
                    client_id: client_id.clone(),
                    subject: subject.into(),
                    scope: ScopeSet::empty(),
                    resource: Vec::new(),
                    granted_at: now,
                    authentication: None,
                },
            };
            record.extend(scope, resource);
            // The LATEST authentication replaces the previous one: it is what the user just did,
            // and it is what an RFC 9470 `max_age` on the next request has to be measured against.
            // A host that reports nothing this time leaves the previous report standing rather
            // than erasing it, because "did not say" is not "no longer authenticated".
            if let Some(a) = &authentication {
                record.authentication = Some(Box::new(a.clone()));
            }
            // The write happens only if the pair still holds exactly what was read a moment ago:
            // still nothing when creating, still that record when widening. A withdrawal in
            // between refuses BOTH shapes, which is the point.
            if self
                .store
                .compare_and_swap_consent(expected.as_ref(), record.clone())
                .await?
            {
                return Ok(record);
            }
        }
        Err(StorageError::new(
            "consent record changed concurrently twice; not recorded",
        ))
    }

    /// The consent this user has already given this client, if any.
    ///
    /// This ANSWERS a question; it does not make a decision, and nothing in this crate approves an
    /// authorization request on the strength of it. See the `http` feature's
    /// `ServiceBuilder::with_approval_resolver`: the library reports what it remembers
    /// and the host decides what that is worth, because "the user agreed to this once" and "the
    /// user agrees to this now" are different sentences and only the host can tell them apart.
    #[cfg(feature = "consent")]
    pub async fn remembered_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<std::sync::Arc<crate::consent::ConsentRecord>>, StorageError> {
        self.store.find_consent(client_id, subject).await
    }

    /// Everything one resource owner has consented to, so a host can show a user what they have
    /// granted. Without this a user cannot SEE what they gave away, which is half of why this
    /// feature exists at all.
    #[cfg(feature = "consent")]
    pub async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<std::sync::Arc<crate::consent::ConsentRecord>>, StorageError> {
        self.store.consents_for_subject(subject).await
    }

    /// WITHDRAW a consent, revoking everything issued under it. Returns how many records the
    /// cascade removed.
    ///
    /// This is the point of the whole feature. A withdrawal that left tokens alive would be worse
    /// than no withdrawal at all, because the user would believe they had stopped something they
    /// had not, so the cascade is one storage operation
    /// ([`crate::store::Storage::revoke_consent`]) and it reaches every family the consent ever
    /// produced, plus the authorization codes and approved-but-unpolled device grants that would
    /// otherwise mint tokens seconds later.
    ///
    /// Withdrawing a consent that is already gone is `Ok(0)`, not an error.
    #[cfg(feature = "consent")]
    pub async fn withdraw_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        // Read first, purely so the audit event can name the client and the user. Two round trips
        // on a path a person drives by hand is not a cost worth optimising away, and an event that
        // said only "some consent was withdrawn" is an event nobody can act on.
        let record = self.store.get_consent(consent_id).await?;
        let records_revoked = self
            .store
            .revoke_consent(consent_id, self.revocation_window())
            .await?;
        if let Some(record) = &record {
            self.hooks.emit(|| Event::ConsentWithdrawn {
                client_id: record.client_id.as_str(),
                subject: record.subject.as_ref(),
                records_revoked,
            });
        }
        Ok(records_revoked)
    }

    /// RFC 7009 token revocation.
    ///
    /// Returns `Ok(())` when the token is gone, INCLUDING when it never existed: section 2.2
    /// requires a 200 for an unknown token, because distinguishing "revoked" from "never heard of
    /// it" would let an unauthenticated caller test whether a token string is real.
    ///
    /// `token_type_hint` (section 2.1) is an optimisation, not a constraint: the RFC requires the
    /// server to keep looking if the hint is wrong, so a wrong hint costs a second lookup and
    /// nothing else.
    ///
    /// PUBLIC CLIENTS MAY REVOKE THEIR OWN TOKENS here, presenting a `client_id` and no secret,
    /// which is section 2.1's own rule ("in case of a confidential client" scopes the credential
    /// check) and section 5's ("a valid `client_id`, in the case of a public client"). What stops
    /// a caller who merely knows a public client's id is the OWNERSHIP check, made against the
    /// stored record: another client's token is untouched, and answered `Ok(())` all the same.
    /// This is deliberately NOT what
    /// [`introspection_response`](AuthorizationServer::introspection_response) does; see the
    /// comment inside [`revoke_with_credential`](AuthorizationServer::revoke_with_credential) for
    /// why the two RFCs differ.
    ///
    /// # THIS FUTURE IS NOT CANCELLATION SAFE, and what a drop costs
    ///
    /// Applies equally to
    /// [`revoke_with_credential`](AuthorizationServer::revoke_with_credential), which is the same
    /// future. A dropped future stops at whatever `await` it was suspended in and never resumes,
    /// and this crate cannot make it finish: there is no destructor that can run an `async` store
    /// call. So the contract is stated rather than left to be discovered.
    ///
    /// Revoking a REFRESH token is a two-write sequence: the RFC 7009 s2.1 cascade over the
    /// grant's family, and the removal of the presented string. A drop between them leaves the
    /// family revoked, with a barrier recorded, and one live-LOOKING refresh string that names a
    /// family nothing will honour. That is fail-closed on purpose, and it is why the cascade runs
    /// first; the opposite order was worse than an incomplete revocation, because the client's
    /// RETRY found the presented string already gone and answered 200 without cascading at all,
    /// leaving every access token of a grant the user had logged out of live for its whole TTL.
    /// A retry after a drop now still reaches the cascade, and the cascade is idempotent
    /// ([`crate::store::Storage::revoke_token_family`]). `tests/revocation_cancellation.rs` pins
    /// it.
    ///
    /// WHAT IS STILL LOST to a drop, stated rather than implied: the [`crate::events::Event`] the
    /// completed call would have emitted, so an audit trail can miss a revocation that partly
    /// happened. A host that needs the sequence to complete must drive it from a task the
    /// connection cannot cancel, spawning the call and awaiting the join handle, which is what this
    /// crate's own axum adapter does; see [`crate::http`].
    pub async fn revoke(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
        token_type_hint: Option<TokenTypeHint>,
    ) -> Result<(), ErrorResponse> {
        self.revoke_with_credential(
            client_id,
            &ClientCredential::secret(client_secret),
            token,
            token_type_hint,
        )
        .await
    }

    /// RFC 7009 revocation for a caller authenticating with any credential this server accepts,
    /// including an RFC 7523 assertion. See
    /// [`AuthorizationServer::device_authorization_with_credential`] on why this is an addition
    /// rather than a replacement.
    pub async fn revoke_with_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        token: &str,
        token_type_hint: Option<TokenTypeHint>,
    ) -> Result<(), ErrorResponse> {
        let client = self.authenticate_client(client_id, cred).await?;
        // PUBLIC CLIENTS ARE ADMITTED HERE, and deliberately, which is the opposite of
        // `introspection_response_with_credential` a few hundred lines above. The two arrived
        // together under one citation pair and only the introspection half of it held.
        //
        // RFC 7009 section 2.1 scopes credential validation in as many words: the server "first
        // validates the client credentials (in case of a confidential client) and then verifies
        // whether the token was issued to the client making the revocation request". Section 5
        // says the same thing from the other side, naming "a valid client_id, in the case of a
        // public client". So the OWNERSHIP check below, not client authentication, is what this
        // endpoint's access control rests on for a public client, and the checks below already
        // perform it: a record whose `client_id` is not this one is untouched and answered 200.
        //
        // Why this matters rather than being a conformance detail: this server issues tokens to
        // public clients through code+PKCE and through the device grant, so refusing them
        // revocation left a native or browser app with no standard way to make a logout mean
        // anything. The token stayed live for its whole TTL and the refresh chain outlived the
        // user's decision entirely.
        //
        // What an attacker gains is bounded by what they must already have: the token STRING. A
        // caller who holds it can already use it, so being able to destroy it is a strictly
        // smaller capability than the one they have; and holding somebody else's token buys
        // nothing here, because the comparison is against the record, not against the asserted
        // identity. Introspection is refused for exactly the reason this is allowed: it is a
        // request to DESCRIBE a token rather than to destroy one, and RFC 7662 section 4 says it
        // MUST NOT be publicly available.

        let try_refresh = || async {
            // READ, then take. Section 2.1's ownership check is a question ABOUT someone else's
            // credential, so it must not be answered by removing it: a take-then-put-back is a
            // non-atomic read-modify-write on a live token, it opens a window in which the real
            // owner's concurrent refresh sees nothing, and if the restoring write fails the
            // victim's chain is destroyed permanently while this endpoint still answers 200.
            // Reading first means a non-owner's request touches nothing at all.
            match self.store.get_refresh_token(token).await {
                Ok(Some(record)) if record.client_id == client.client_id => {
                    // THE CASCADE RUNS FIRST, AND THE ORDER IS THE FIX. It used to take the
                    // presented refresh token and revoke the family afterwards, which is the
                    // fail-OPEN order for a two-write sequence that can stop between the writes:
                    // this future is dropped whenever the host's connection is cancelled, and a
                    // drop after the take left the presented string gone and the family whole.
                    // The client's retry then found nothing at `get_refresh_token`, fell to the
                    // `Ok(_)` arm below, and answered 200 with no cascade at all, so every access
                    // token of a grant the user had just logged out of stayed live for its whole
                    // TTL and nothing anywhere recorded it. Note that the store-ERROR path was
                    // already handled honestly (`cascade_failed` below, emitted either way); the
                    // DROP path emitted nothing, which is why it was invisible.
                    //
                    // Revoking first inverts that. A drop between the two writes leaves the family
                    // revoked, with a barrier recorded, and one live-looking refresh string that
                    // names a family nothing will honour: fail-closed, and the retry re-runs a
                    // cascade that is idempotent by contract (see `Storage::revoke_token_family`,
                    // "removing records that are already gone is success").
                    //
                    // The `family_id` comes from the record READ above rather than from a taken
                    // one. A refresh token string cannot change families, so the two always agreed;
                    // and after this call there is usually no record left to take, because
                    // `revoke_token_family` removes the family's refresh records as well.
                    //
                    // The in-flight-rotation case the previous ordering worried about is handled
                    // by the barrier, not by the ordering: a rotation that has already taken its
                    // record is invisible to the cascade's scan, and it is the barrier that
                    // REFUSES its later writes rather than letting them restore the chain the user
                    // just revoked. Recording that barrier sooner can only help.
                    //
                    // RFC 7009 section 2.1: "If the particular token is a refresh token and the
                    // authorization server supports the revocation of access tokens, then the
                    // authorization server SHOULD also invalidate all access tokens based on the
                    // same authorization grant." This server does support it, so the SHOULD
                    // applies, and the grant is exactly what `family_id` names (see
                    // `RefreshTokenRecord::family_id`): every token, access or refresh, minted from
                    // the same authorization. Killing only the presented string would leave the
                    // access token that came out of the same redemption live for its whole TTL,
                    // which is the opposite of what a client asking for revocation has just said.
                    //
                    // Deliberately NOT fatal on a storage failure. Section 2.2 makes the presented
                    // token's own revocation the answer, and the take below still runs and still
                    // reports its own failure; a cascade that could turn a completed revocation
                    // into a 503 would leave the client believing nothing was revoked when the
                    // token it named is already gone.
                    //
                    // NOT fatal, but no longer INVISIBLE. The event fired unconditionally, so an
                    // operator could not tell a complete revocation from one that killed the
                    // presented string and left every access token of the same grant alive. That
                    // is the difference between "the client's session is over" and "the client's
                    // session continues for up to one access token TTL", and only the host can
                    // decide what to do about it.
                    let cascade_failed = self
                        .store
                        .revoke_token_family(record.family_id.as_str(), self.revocation_window())
                        .await
                        .is_err();
                    // The presented string, in case the cascade did not reach it: it will already
                    // be gone in a store whose `revoke_token_family` removed the family's refresh
                    // records, and removing a record that is not there is not an error. This is
                    // what makes the sequence safe to stop after the cascade rather than before
                    // it, and what makes a retry a no-op.
                    self.store
                        .take_refresh_token(token)
                        .await
                        .map_err(storage_error)?;
                    self.hooks.emit(|| Event::TokenRevoked {
                        client_id: client.client_id.as_str(),
                        token_type: TokenTypeHint::RefreshToken,
                        cascade_failed,
                    });
                    Ok(true)
                }
                // Unknown, or somebody else's: nothing to do, and section 2.2 makes both a 200.
                Ok(_) => Ok(false),
                Err(e) => Err(storage_error(e)),
            }
        };
        let try_access = || async {
            match self.store.get_token(token).await {
                Ok(Some(t)) if t.client_id == client.client_id => {
                    self.store
                        .delete_token(token)
                        .await
                        .map_err(storage_error)?;
                    self.hooks.emit(|| Event::TokenRevoked {
                        client_id: client.client_id.as_str(),
                        token_type: TokenTypeHint::AccessToken,
                        // An access token names no grant to cascade to: it is one record and it is
                        // gone, or the `?` above already turned the failure into an error.
                        cascade_failed: false,
                    });
                    Ok(true)
                }
                Ok(_) => Ok(false),
                Err(e) => Err(storage_error(e)),
            }
        };

        // The hint only decides which lookup happens first.
        match token_type_hint {
            Some(TokenTypeHint::AccessToken) => {
                if !try_access().await? {
                    try_refresh().await?;
                }
            }
            _ => {
                if !try_refresh().await? {
                    try_access().await?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;
