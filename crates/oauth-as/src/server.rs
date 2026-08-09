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
#[cfg(feature = "client_assertion")]
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
    /// OFF by default from 0.10.0, having been on. Section 3.3.1 makes the member OPTIONAL, so
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
/// than the seam it mirrors. A host can wire `|_| ConsentDecision::Approve` into the `http` path
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
        }
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
            scopes_supported: None,
            allowed_resources: None,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientCredential<'a> {
    /// The RFC 6749 section 2.3.1 shared secret, from `Authorization: Basic` or from the form body.
    /// `None` for a public client, and `None` when an assertion is presented instead.
    pub client_secret: Option<&'a str>,
    /// RFC 7521 section 4.2 `client_assertion_type`. It MUST be
    /// [`crate::client_assertion::CLIENT_ASSERTION_TYPE`]; any other value is refused rather than
    /// ignored, because an assertion format this server does not implement is a credential it
    /// cannot check, and "cannot check" must never read as "checked out".
    #[cfg(feature = "client_assertion")]
    pub client_assertion_type: Option<&'a str>,
    /// RFC 7523 section 2.2 `client_assertion`: the signed JWT itself.
    #[cfg(feature = "client_assertion")]
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

impl<'a> ClientCredential<'a> {
    /// The credential of a client presenting a shared secret, or of a public client presenting
    /// none.
    pub fn secret(client_secret: Option<&'a str>) -> Self {
        ClientCredential {
            client_secret,
            #[cfg(feature = "client_assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client_assertion")]
            client_assertion: None,
            #[cfg(feature = "mtls")]
            certificate: None,
        }
    }

    /// The RFC 7523 credential: the assertion, and the type that names its format.
    #[cfg(feature = "client_assertion")]
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
    #[cfg(feature = "rar")]
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
pub(crate) fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).expect("OS randomness for OAuth artifacts");
    hex_encode(&buf)
}

/// The lower-case hex alphabet, as a table rather than a format string.
///
/// `write!(out, "{b:02x}")` per byte goes through `core::fmt`, which for 32 bytes is 32 trips
/// through a formatter with width and fill handling that a fixed two-nibble encoding never needs.
/// MEASURED at 1335 ns against 1092 ns for a 32-byte draw-and-encode. The output is identical, so
/// nothing about the artifact changes; this is the same string arrived at without the machinery.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Hex-encode `bytes`, lower case, two characters per byte.
///
/// SPLIT from the draw so that one `getrandom` call can feed several artifacts. `getrandom::fill`
/// is a SYSCALL, and the measurement that matters is that its cost is almost entirely per CALL
/// rather than per byte: 875 ns for one byte against 1025 ns for thirty-two on the machine
/// benches/README.md names. So the number of calls is the thing to reduce, and a caller that needs
/// two 32-byte artifacts should draw 64 bytes once rather than 32 bytes twice. See `issue`.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
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
fn random_user_code(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        getrandom::fill(&mut buf).expect("OS randomness for OAuth artifacts");
        for &byte in buf.iter() {
            if out.len() == len {
                break;
            }
            if let Some(symbol) = user_code_symbol(byte) {
                out.push(symbol as char);
            }
        }
    }
    out
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

/// The storage key one single-use identifier is claimed under.
///
/// NAMESPACED, and both halves matter. `kind` keeps an RFC 7523 assertion's `jti` from colliding
/// with an RFC 9449 proof's, which are different credentials with different lifetimes that a client
/// may well number from the same counter. `owner` (the client id for an assertion, the key
/// thumbprint for a proof) keeps one client from locking another out by choosing its `jti` values:
/// without it, an attacker could spend a victim's future `jti` values in advance, which is a denial
/// of service bought for the price of a refused request.
///
/// One allocation per assertion or proof, on a path that only exists when the feature is on.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
fn replay_key(kind: &str, owner: &str, jti: &str) -> String {
    let mut key = String::with_capacity(kind.len() + owner.len() + jti.len() + 2);
    key.push_str(kind);
    key.push(':');
    key.push_str(owner);
    key.push(':');
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
        AuthorizationServer {
            config,
            store,
            clock,
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

    /// Turn the freshly minted random token into what actually goes on the wire: itself when the
    /// format is opaque (the byte-for-byte pre-feature behaviour), or an RFC 9068 access token
    /// carrying it as `jti` when the host configured signing.
    // Eight arguments, since the RFC 8705 binding is a property of the REQUEST rather than of the
    // grant. Same allow and same reason as `issue` below: a private function with one call site,
    // whose arguments would have to live across every await in the token future if they were
    // bundled into a struct to satisfy a lint.
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "jwt")]
    fn wire_access_token(
        &self,
        client: &Client,
        subject: Option<&str>,
        scope: &ScopeSet,
        resource: &[String],
        details: &GrantedDetails,
        now: SystemTime,
        jti: String,
        bound: &Bound<'_>,
    ) -> Result<String, ErrorResponse> {
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
            AccessTokenFormat::Opaque => return Ok(jti),
            AccessTokenFormat::Jwt(jwt) => jwt,
        };
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
            exp: crate::jwt::unix_seconds(now + self.config.access_token_ttl)
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
        };
        jwt.sign_access_token(&claims).map_err(|e| {
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
            // An EMPTY allowlist keeps the previous behaviour rather than refusing everything,
            // because refusing would break every deployment that already relies on resource
            // indicators. That means this check protects only hosts that configure it, which is
            // stated plainly on the config field rather than left for someone to discover.
            if let Some(allowed) = &self.config.allowed_resources {
                if !allowed.iter().any(|a| &**a == value) {
                    return Err(ErrorResponse::new(ErrorCode::InvalidTarget)
                        .with_description("this server does not issue tokens for that resource"));
                }
            }
            // A repeated identical indicator is the same request twice, not two audiences.
            if !out.iter().any(|kept: &String| kept == value) {
                out.push(value.to_string());
            }
        }
        Ok(out)
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
    /// It needs no cap of its own, and deliberately does not have one. BOTH sides came through
    /// [`AuthorizationServer::validate_resources`], which refuses past
    /// [`MAX_RESOURCE_INDICATORS`]: `granted` was validated when the grant was created and
    /// `requested` was validated by the caller a few lines earlier. So the worst case is 16 * 16
    /// string comparisons, most of which fail on the length, and a second constant here would be a
    /// second number to keep in step with the first for no gain.
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

    /// Register (or replace) a client. Dynamic client registration (RFC 7591) will layer on this.
    pub async fn register_client(&self, client: Client) -> Result<(), StorageError> {
        self.store.put_client(client).await
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
    pub(crate) async fn authenticate_client(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
    ) -> Result<std::sync::Arc<Client>, ErrorResponse> {
        let attempt = Attempt::ClientAuthentication {
            client_id: client_id.as_str(),
        };
        if self.hooks.check(attempt) == RateLimitDecision::Deny {
            self.hooks.emit(|| Event::ClientAuthenticationFailed {
                client_id: client_id.as_str(),
                failure: ClientAuthFailure::RateLimited,
            });
            // The same `invalid_client` a wrong secret gets. A distinct code would tell an
            // attacker that they had found a live client id and merely hit the throttle.
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }

        let found = self
            .store
            .get_client(client_id)
            .await
            .map_err(storage_error)?;
        let client = match found {
            Some(client) => client,
            None => {
                self.hooks.record(attempt, AttemptOutcome::Failed);
                self.hooks.emit(|| Event::ClientAuthenticationFailed {
                    client_id: client_id.as_str(),
                    failure: ClientAuthFailure::UnknownClient,
                });
                return Err(ErrorResponse::new(ErrorCode::InvalidClient));
            }
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
                    self.hooks.record(attempt, AttemptOutcome::Failed);
                    self.hooks.emit(|| Event::ClientAuthenticationFailed {
                        client_id: client_id.as_str(),
                        failure: ClientAuthFailure::SecretExpired,
                    });
                    // The same bare `invalid_client` as every other refusal here. The host's audit
                    // channel is told which it was; the wire is not, because the difference between
                    // "expired" and "wrong" tells a caller that the id is real.
                    return Err(ErrorResponse::new(ErrorCode::InvalidClient));
                }
            }
        }

        // RFC 7523 client authentication, when the request presented an assertion. Handled apart
        // from the secret comparison below because it is a different KIND of credential: there is
        // nothing to compare, there is a signature to verify against the REGISTRATION's key and a
        // `jti` to spend so the request cannot be repeated.
        #[cfg(feature = "client_assertion")]
        if cred.client_assertion.is_some() {
            // NOT boxed, and that is a measurement rather than a style, in both directions.
            //
            // It WAS `Box::pin(..)` through 0.9.0: `authenticate_client` inlines into all four
            // grant helpers and so into the token future, which `tests/allocation.rs` holds under
            // tokio's 2048-byte debug boxing threshold, and inlining the assertion state (a claim
            // set, two owned Strings, a storage future) once pushed it over. It no longer does.
            // Measured both ways: 1144 under `client_assertion` alone, 1256 with `rar`, 1344 with
            // `dpop,mtls,consent,rar,par` and with `--all-features`, IDENTICAL boxed and unboxed,
            // because the token future's high-water mark moved elsewhere when the endpoint was
            // restructured (see `token_with_context`).
            //
            // What the box was still costing is one allocation on every token request that
            // presents an assertion, which for a `private_key_jwt` deployment is every token
            // request it makes: precisely the deployments RFC 7523 exists for, and the ones FAPI
            // 2.0 requires it of. `client_assertion_verification_bound` in
            // `tests/allocation_paths.rs` pins the result.
            return match self.authenticate_by_assertion(&client, cred).await {
                Ok(()) => {
                    self.hooks.record(attempt, AttemptOutcome::Succeeded);
                    Ok(client)
                }
                Err(error) => {
                    self.hooks.record(attempt, AttemptOutcome::Failed);
                    self.hooks.emit(|| Event::ClientAuthenticationFailed {
                        client_id: client_id.as_str(),
                        failure: ClientAuthFailure::AssertionInvalid,
                    });
                    Err(error)
                }
            };
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
            return match crate::mtls::verify_certificate(&client, cred) {
                Ok(()) => {
                    self.hooks.record(attempt, AttemptOutcome::Succeeded);
                    Ok(client)
                }
                Err(failure) => {
                    self.hooks.record(attempt, AttemptOutcome::Failed);
                    self.hooks.emit(|| Event::ClientAuthenticationFailed {
                        client_id: client_id.as_str(),
                        failure,
                    });
                    // The same bare `invalid_client` every other refusal here returns: RFC
                    // 6749 s5.2 collapses them on purpose, so a caller cannot probe a
                    // registration. The host's audit channel was told which it was.
                    Err(ErrorResponse::new(ErrorCode::InvalidClient))
                }
            };
        }

        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this
        // crate does not implement is decided by the host's verifier (see
        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.
        if !client
            .auth
            .verify_with(cred.client_secret, self.hooks.secret_verifier())
        {
            self.hooks.record(attempt, AttemptOutcome::Failed);
            self.hooks.emit(|| Event::ClientAuthenticationFailed {
                client_id: client_id.as_str(),
                failure: ClientAuthFailure::SecretMismatch,
            });
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }
        self.hooks.record(attempt, AttemptOutcome::Succeeded);
        Ok(client)
    }

    /// RFC 7523 section 3, plus the single-use claim that makes it worth anything.
    ///
    /// Returns `Ok(())` for an authenticated client. Every refusal is the SAME bare
    /// `invalid_client` the wrong-secret path returns, with no description: this function is only
    /// reached once the client id is known to exist, so a description naming which check failed
    /// would be the difference between "this client id is real" and "it is not", which is exactly
    /// the distinction `authenticate_client` collapses on purpose. The host's audit channel is
    /// told (`ClientAuthFailure::AssertionInvalid`); the wire is not.
    #[cfg(feature = "client_assertion")]
    async fn authenticate_by_assertion(
        &self,
        client: &Client,
        cred: &ClientCredential<'_>,
    ) -> Result<(), ErrorResponse> {
        let refused = || ErrorResponse::new(ErrorCode::InvalidClient);
        let assertion = cred.client_assertion.ok_or_else(refused)?;

        // RFC 7521 section 4.2: the type is what says which assertion format this is, and this
        // server implements exactly one. An absent or unrecognised type is refused rather than
        // assumed, because assuming would mean verifying a credential in a format nobody declared.
        if cred.client_assertion_type != Some(CLIENT_ASSERTION_TYPE) {
            return Err(refused());
        }
        // RFC 6749 section 2.3: "The client MUST NOT use more than one authentication method in
        // each request." A request carrying both a secret and an assertion has not said which
        // credential it means, and a server that picks one behaves differently from the next
        // server, which is exactly the ambiguity an intermediary would exploit.
        if cred.client_secret.is_some() {
            return Err(refused());
        }

        // THE REGISTRATION DECIDES, and this is where that starts. A client registered for
        // `client_secret_basic` cannot promote itself to `private_key_jwt` by sending an assertion,
        // because there is no key here that anybody vouched for on its behalf.
        let keys = match &client.auth {
            crate::client::ClientAuth::ConfidentialAssertion { keys } => keys,
            _ => return Err(refused()),
        };

        // RFC 7523 section 3 (3) admits either the token endpoint URL or, by long-established
        // practice (OpenID Connect Core section 9), the issuer identifier.
        let token_endpoint = self.token_endpoint();
        let verified = verify_assertion(
            keys,
            assertion,
            client.client_id.as_str(),
            &[token_endpoint.as_str(), self.issuer_identifier()],
            self.clock.now(),
        )
        .map_err(|_| refused())?;

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
            .map_err(|_| refused())?;
        if !claimed {
            return Err(refused());
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
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    fn token_endpoint(&self) -> String {
        match &self.config.token_endpoint {
            Some(endpoint) => endpoint.clone(),
            None => format!("{}/token", self.issuer_identifier()),
        }
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
        let verified = verify_proof(proof, "POST", &self.token_endpoint(), self.clock.now())
            .map_err(|_| ErrorResponse::new(ErrorCode::InvalidDpopProof))?;
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
            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)
                .with_description("this DPoP proof has already been used"));
        }
        Ok(Some(verified.jkt.into_boxed_str()))
    }

    /// Resolve the scope a request will be granted: the client default when the request names
    /// none, otherwise the request, which must sit inside the registration's allowed set.
    fn resolve_scope(
        client: &Client,
        requested: Option<&ScopeSet>,
    ) -> Result<ScopeSet, ErrorResponse> {
        match requested {
            None => Ok(client.default_scopes.clone()),
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
        let client = self.authenticate_client(client_id, cred).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
                .with_description("client registration does not include the device_code grant"));
        }
        let scope = Self::resolve_scope(&client, requested_scope)?;

        let now = self.clock.now();
        let device_code = random_hex(32);
        let user_code = self.unique_user_code().await?;
        let grant = DeviceGrant {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: client.client_id.clone(),
            scope,
            state: DeviceGrantState::Pending,
            created_at: now,
            expires_at: now + self.config.device_code_ttl,
            interval: self.config.poll_interval,
            last_poll_at: None,
        };
        self.store
            .put_device_grant(grant)
            .await
            .map_err(storage_error)?;

        let verification_uri_complete = self
            .config
            .include_verification_uri_complete
            .then(|| format!("{}?user_code={}", self.config.verification_uri, user_code));
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
            let raw = random_user_code(len);
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
    /// enumerate". This library performs NO rate limiting and cannot, because it never sees a
    /// request: it has no notion of a caller, an IP, a session, or a user. Every unknown-code
    /// answer this returns must be counted and throttled by the HOST, per whatever identity the
    /// host actually has. Without that, [`MIN_USER_CODE_LENGTH`] symbols is a guessing exercise,
    /// not a credential.
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
            None => match client.redirect_uris.as_slice() {
                [only] => only.clone(),
                [] => {
                    return Err(direct(
                        ErrorCode::InvalidRequest,
                        "client has no registered redirect_uri",
                    ))
                }
                _ => {
                    return Err(direct(
                        ErrorCode::InvalidRequest,
                        "redirect_uri is required when several are registered",
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

        // 5. Scope. RFC 6749 section 3.3: absent means the registered default.
        let scope = match request.scope.as_deref() {
            None => client.default_scopes.clone(),
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
        let UserApproval { request, subject } = approval;
        let now = self.clock.now();
        let code = random_hex(32);
        let record = AuthorizationCodeRecord {
            code: code.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
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
            expires_at: now + self.config.authorization_code_ttl,
            state: AuthorizationCodeState::Issued,
            // RFC 9470 s5: recorded here because the token endpoint has no user in front of it and
            // could not ask. See `AuthorizationCodeRecord::authentication`.
            #[cfg(feature = "consent")]
            authentication: authentication.authentication,
        };
        self.store
            .put_authorization_code(record)
            .await
            .map_err(|_| {
                AuthorizationError::Redirect(AuthorizationErrorRedirect {
                    redirect_uri: request.redirect_uri.clone(),
                    error: ErrorResponse::new(ErrorCode::ServerError),
                    state: request.state.clone(),
                    iss: request.issuer.clone(),
                })
            })?;
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
        if let AuthorizationCodeState::Consumed {
            access_token,
            refresh_token,
        } = &record.state
        {
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
                        match self.store.revoke_token_family(&rec.family_id).await {
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
            // The consumed record goes BACK. `src/authorization.rs` and `src/store.rs` both
            // promise it is retained until its own expiry, and that promise is what makes replay
            // detection work more than once: taking it here would make the NEXT replay read as an
            // unknown code, which is the answer a typo gets. Losing this write therefore loses the
            // EVIDENCE, not just a record, which is why it counts as a containment failure too.
            if self.store.put_authorization_code(record).await.is_err() {
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
        match redirect_uri {
            Some(u) if u == record.redirect_uri => {}
            _ => {
                let _ = self.store.put_authorization_code(record).await;
                return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("redirect_uri does not match the authorization request"));
            }
        }

        // RFC 7636 section 4.6. A missing verifier is the exact downgrade PKCE exists to stop, so
        // it is a failure, never a skipped check.
        let verified = match (code_verifier, record.code_challenge_method) {
            (Some(v), CodeChallengeMethod::S256) => {
                crate::pkce::verify_s256(v, &record.code_challenge)
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
        let narrowed =
            Self::narrow_resources(&record.resource, requested_resources).and_then(|r| {
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
                Some(subject),
                scope,
                resource,
                details,
                None,
                true,
                authentication,
            )
            .await?;

        // Now the record can name what it minted, which is what lets a replay REVOKE rather than
        // merely be refused.
        consumed.state = AuthorizationCodeState::Consumed {
            access_token: Some(issued.access_token.clone()),
            refresh_token: issued.refresh_token.clone(),
        };
        if self.store.put_authorization_code(consumed).await.is_err() {
            // The client is answered with an error, so it never receives the tokens that were just
            // minted and they become orphans: live records nobody was ever handed. Best effort
            // cleanup, and the `Result` is deliberately discarded rather than reported, because
            // there is nothing useful left to say. These are 32 bytes of OS randomness that were
            // never transmitted to anyone, so a failed cleanup costs storage the host's
            // `Storage::sweep_expired` reclaims at the token's own expiry, and nothing else. The
            // Both artifacts are nameable directly here, which is cheaper and more precise than
            // asking the store for the family they belong to.
            let _ = self.store.delete_token(&issued.access_token).await;
            if let Some(rt) = &issued.refresh_token {
                let _ = self.store.take_refresh_token(rt).await;
            }
            return Err(ErrorResponse::new(ErrorCode::ServerError)
                .with_description("could not record the redemption"));
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
        let client = self.authenticate_client(client_id, &bound.cred).await?;
        // RFC 6749 section 4.4: this grant is for confidential clients. A public client has no
        // secret, so "the client itself" is not an identity anyone has proven.
        if matches!(client.auth, crate::client::ClientAuth::Public) {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client_credentials requires a confidential client"));
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
            if now < last + grant.interval {
                let expected = grant.state.clone();
                grant.interval += self.config.slow_down_increment;
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
            self.store
                .put_refresh_token(record)
                .await
                .map_err(storage_error)?;
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant));
        }

        // REUSE. This token was already rotated away, so two parties hold it, and the AS has just
        // been handed unambiguous evidence of that. OAuth 2.1 draft section 6.1 and RFC 9700
        // section 4.14.2: invalidate the presented token AND revoke the tokens issued for that
        // authorization grant. Refusing the presentation alone would be the defence inverted,
        // because the party who presents the superseded token is by definition the one who did NOT
        // redeem it first, which in a theft is the victim.
        //
        // The family revocation removes every record carrying this id, including this one, so
        // there is nothing to put back.
        if record.state == RefreshTokenState::Spent {
            let records_revoked = self
                .store
                .revoke_token_family(&record.family_id)
                .await
                .map_err(storage_error)?;
            // EVIDENCE OF COMPROMISE, and the event most likely to be asked about after the fact:
            // the family revocation also logs out the legitimate client.
            self.hooks.emit(|| Event::RefreshTokenReuseDetected {
                client_id: client.client_id.as_str(),
                family_id: &record.family_id,
                records_revoked,
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
            self.store
                .put_refresh_token(record)
                .await
                .map_err(storage_error)?;
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
            self.store
                .put_refresh_token(record)
                .await
                .map_err(storage_error)?;
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

        // Narrowing only (RFC 6749 section 6: scope must not include any scope not originally
        // granted). A widening attempt is a client bug, not a compromise: put the record back so
        // the mistake is retryable.
        let scope = match requested_scope {
            None => record.scope.clone(),
            Some(s) if s.is_subset(&record.scope) => s.clone(),
            Some(_) => {
                self.store
                    .put_refresh_token(record)
                    .await
                    .map_err(storage_error)?;
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
        let narrowed =
            Self::narrow_resources(&record.resource, requested_resources).and_then(|r| {
                GrantedDetails::of_refresh(&record)
                    .narrow(&requested_details)
                    .map(|d| (r, d))
            });
        let (resource, details) = match narrowed {
            Ok(narrowed) => narrowed,
            Err(e) => {
                self.store
                    .put_refresh_token(record)
                    .await
                    .map_err(storage_error)?;
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
        let spent = RefreshTokenRecord {
            state: RefreshTokenState::Spent,
            expires_at: chain_expires_at
                .or_else(|| Some(self.clock.now() + self.config.refresh_reuse_window)),
            ..record
        };
        self.store
            .put_refresh_token(spent)
            .await
            .map_err(storage_error)?;

        self.issue_boxed(
            &client,
            bound,
            GrantType::RefreshToken,
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
        subject: Option<String>,
        scope: ScopeSet,
        resource: Vec<String>,
        details: GrantedDetails,
        chain: Option<RefreshChain>,
        allow_refresh: bool,
        authentication: GrantedAuthentication,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + Send + 'a>,
    > {
        Box::pin(self.issue(
            client,
            bound,
            grant_type,
            subject,
            scope,
            resource,
            details,
            chain,
            allow_refresh,
            authentication,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn issue(
        &self,
        client: &Client,
        bound: &Bound<'_>,
        grant_type: GrantType,
        subject: Option<String>,
        scope: ScopeSet,
        resource: Vec<String>,
        details: GrantedDetails,
        chain: Option<RefreshChain>,
        allow_refresh: bool,
        authentication: GrantedAuthentication,
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
        // Likewise: without `rar` the details are a zero sized value nothing reads.
        #[cfg(not(feature = "rar"))]
        let _ = details;
        let now = self.clock.now();

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
            getrandom::fill(&mut entropy).expect("OS randomness for OAuth artifacts");
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
        #[cfg(feature = "jwt")]
        let access_token = self.wire_access_token(
            client,
            subject.as_deref(),
            &scope,
            &resource,
            &details,
            now,
            access_token,
            bound,
        )?;
        self.store
            .put_token(IssuedToken {
                // RFC 9449 s6: the binding is recorded on the AS side too, not only in the token,
                // so that RFC 7662 introspection can report it and a resource server can check it
                // without having to parse a token this server may have issued as opaque.
                #[cfg(feature = "dpop")]
                jkt: bound.jkt.map(Box::from),
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
                expires_at: now + self.config.access_token_ttl,
                family_id: family_id.clone(),
                // RFC 9470 s5: the token reports the authentication behind it, so introspection can
                // answer the question the resource server's challenge asked.
                #[cfg(feature = "consent")]
                authentication: authentication.authentication.clone(),
            })
            .await
            .map_err(storage_error)?;

        let refresh_token = if issues_refresh {
            let expires_at = match &chain {
                Some(c) => c.expires_at,
                None => self.config.refresh_token_ttl.map(|ttl| now + ttl),
            };
            // Drawn in the single `getrandom` call at the top of this function; `issues_refresh`
            // is what decided both that draw and this branch, so the value is always present.
            let rt = pending_refresh.expect("issues_refresh decided both");
            self.store
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
                    // Present whenever a refresh token is: `issues_refresh` is what decided both.
                    family_id: family_id.unwrap_or_default(),
                    state: RefreshTokenState::Active,
                    // Carried, never restamped: see `RefreshTokenRecord::authentication`.
                    #[cfg(feature = "consent")]
                    authentication: authentication.authentication,
                })
                .await
                .map_err(storage_error)?;
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
            expires_in: self.config.access_token_ttl.as_secs(),
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
    /// The caller must authenticate (section 2.1), and a token belonging to a DIFFERENT client
    /// reads as inactive rather than as a description of somebody else's grant: section 2.2 says
    /// the response for an invalid token is simply `active: false`, and section 4 warns that this
    /// endpoint otherwise becomes an oracle for probing tokens a caller does not hold.
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
        if matches!(client.auth, crate::client::ClientAuth::Public) {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("introspection requires a confidential client"));
        }
        let record = self.introspect(token).await.map_err(storage_error)?;
        Ok(match record {
            Some(t) if t.client_id == client.client_id => IntrospectionResponse {
                active: true,
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
                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),
                // RFC 9470 s5. A resource server that sent a step-up challenge has to be able to
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
                // parameter.
                #[cfg(feature = "rar")]
                authorization_details: t.authorization_details.clone(),
                // RFC 9449 s6.1 with RFC 7800 s3.1. A resource server that introspects must be
                // able to confirm the binding, or the binding stops at this server and the RS is
                // back to trusting a bearer string.
                // RFC 9449 s6.1 and RFC 8705 s3.2, in ONE RFC 7800 s3.1 object. Both
                // mechanisms register a member of `cnf` and a token can carry both, so this
                // is built from every binding the record has rather than from whichever one
                // happens to be checked first. Omitted entirely when there is none.
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
            },
            // Unknown, expired, or somebody else's. All three are one answer on purpose.
            _ => IntrospectionResponse::inactive(),
        })
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
    /// # THE HOST MUST NOT CALL THIS CONCURRENTLY FOR ONE (client, subject) PAIR
    ///
    /// This is a read-modify-write: it looks for an existing record, widens it, and writes it back.
    /// [`Storage`] has no uniqueness constraint on `(client_id, subject)` and no primitive that
    /// could express one, so two calls that overlap can each find nothing and each create a record,
    /// leaving the pair with two.
    ///
    /// That is NOT fixed here, and the reason is worth stating rather than leaving as an omission.
    /// The consequences are benign in the direction that matters: the records are ADDITIVE, so
    /// nothing is lost, [`AuthorizationServer::remembered_consent`] may report the narrower of the
    /// two and cause a re-prompt (the harmless direction, and the same one
    /// [`crate::consent::ConsentRecord::extend`] already fails in), and
    /// [`AuthorizationServer::consents_for_subject`] lists both so a user can still see and
    /// withdraw the whole relationship. Against that, closing it would mean a second
    /// compare-and-swap primitive on the [`Storage`] trait for a path that runs ONCE PER HUMAN
    /// CONSENT DECISION rather than per request, and whose two writers are two tabs of the same
    /// user's own browser.
    ///
    /// What the host owes instead: serialise its own consent writes per (client, subject), which
    /// any host that already has a session lock around its consent screen gets for nothing.
    #[cfg(feature = "consent")]
    pub async fn record_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
        scope: &ScopeSet,
        resource: &[String],
        authentication: Option<crate::consent::Authentication>,
    ) -> Result<crate::consent::ConsentRecord, StorageError> {
        let now = self.clock.now();
        // CLONED out of the shared snapshot, because this is the one consent path that MUTATES
        // what it read (`extend` below widens the grant in place). An `Arc` cannot be widened
        // while the store still holds it, so the clone the read used to make happens here
        // instead: the cost moved, it did not go away. It is paid once per host consent
        // decision, against the read being free on the authorization endpoint, which runs per
        // request. See `remembered_consent`.
        let mut record = match self.store.find_consent(client_id, subject).await? {
            Some(existing) => (*existing).clone(),
            None => crate::consent::ConsentRecord {
                // 16 bytes of OS randomness, hex encoded, the same shape as every other opaque
                // identifier this server mints. It is not a credential (see the field's own docs),
                // but it names a record that can end a user's sessions, so it must not be something
                // a third party can produce by guessing two strings it already knows.
                consent_id: random_hex(16).into_boxed_str(),
                client_id: client_id.clone(),
                subject: subject.into(),
                scope: ScopeSet::empty(),
                resource: Vec::new(),
                granted_at: now,
                authentication: None,
            },
        };
        record.extend(scope, resource);
        // The LATEST authentication replaces the previous one: it is what the user just did, and it
        // is what an RFC 9470 `max_age` on the next request has to be measured against. A host that
        // reports nothing this time leaves the previous report standing rather than erasing it,
        // because "did not say" is not "no longer authenticated".
        if let Some(a) = authentication {
            record.authentication = Some(Box::new(a));
        }
        self.store.put_consent(record.clone()).await?;
        Ok(record)
    }

    /// The consent this user has already given this client, if any.
    ///
    /// This ANSWERS a question; it does not make a decision, and nothing in this crate approves an
    /// authorization request on the strength of it. See the `http` feature's
    /// `ServiceBuilder::with_consent_resolver`: the library reports what it remembers
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
        let records_revoked = self.store.revoke_consent(consent_id).await?;
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
                    self.store
                        .take_refresh_token(token)
                        .await
                        .map_err(storage_error)?;
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
                    // token's own revocation the answer and that has already succeeded; a cascade
                    // that could turn a completed revocation into a 503 would leave the client
                    // believing nothing was revoked when the token it named is already gone.
                    //
                    // NOT fatal, but no longer INVISIBLE. The event fired unconditionally, so an
                    // operator could not tell a complete revocation from one that killed the
                    // presented string and left every access token of the same grant alive. That
                    // is the difference between "the client's session is over" and "the client's
                    // session continues for up to one access token TTL", and only the host can
                    // decide what to do about it.
                    let cascade_failed = self
                        .store
                        .revoke_token_family(&record.family_id)
                        .await
                        .is_err();
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
