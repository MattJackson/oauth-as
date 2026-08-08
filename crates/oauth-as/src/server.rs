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
use crate::device::{
    normalize_user_code, DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState,
};
use crate::error::{ErrorCode, ErrorResponse};
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::store::{Storage, StorageError};
use crate::token::{
    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,
    TokenType, TokenTypeHint,
};

/// Seconds since the Unix epoch, for the RFC 7519 `exp` / `iat` style claims RFC 7662 reuses.
/// A pre-epoch instant is not representable in that encoding, so it is reported as absent rather
/// than wrapped into a misleading number.
fn unix_seconds(t: SystemTime) -> Option<u64> {
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
    /// RFC 8414 `scopes_supported`. `None` omits the member rather than claiming an empty
    /// catalogue.
    pub scopes_supported: Option<Vec<String>>,
    /// RFC 8414 `service_documentation`.
    pub service_documentation: Option<String>,
    /// Authorization code lifetime. RFC 6749 section 4.1.2 recommends a maximum of 10 minutes;
    /// the default is 60 seconds, which is ample for a redirect round trip.
    pub authorization_code_ttl: Duration,
    /// Whether device authorization responses include `verification_uri_complete`
    /// (`{verification_uri}?user_code={code}`).
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
    /// Absolute refresh chain lifetime; `None` (the default) means no time expiry. Rotation
    /// preserves the chain's original expiry rather than sliding it.
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
            scopes_supported: None,
            service_documentation: None,
            authorization_code_ttl: Duration::from_secs(60),
            include_verification_uri_complete: true,
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(5),
            slow_down_increment: Duration::from_secs(5),
            access_token_ttl: Duration::from_secs(3600),
            issue_refresh_tokens: true,
            refresh_token_ttl: None,
            // 30 days: long enough that a chain abandoned by a client that later comes back with
            // a stale token is still recognised as reuse rather than as noise.
            refresh_reuse_window: Duration::from_secs(30 * 24 * 60 * 60),
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

/// Rejections for the host-driven verification-UI actions ([`AuthorizationServer::approve_device`]
/// / [`AuthorizationServer::deny_device`]). These are NOT wire errors: the RFC leaves the
/// verification interaction to the implementation, and the host renders these however its UI
/// wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceApprovalError {
    /// No live grant matches the entered code.
    UnknownUserCode,
    /// The grant existed but its lifetime has passed.
    Expired,
    /// The grant was already approved or denied.
    NotPending,
    /// The storage seam failed.
    Storage(StorageError),
}

impl std::fmt::Display for DeviceApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceApprovalError::UnknownUserCode => f.write_str("unknown user code"),
            DeviceApprovalError::Expired => f.write_str("the code has expired"),
            DeviceApprovalError::NotPending => f.write_str("the code was already used"),
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
fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).expect("OS randomness for OAuth artifacts");
    let mut out = String::with_capacity(n_bytes * 2);
    for b in buf {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A user code of `len` symbols over [`USER_CODE_ALPHABET`], unbiased via rejection sampling.
fn random_user_code(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut byte = [0u8; 1];
    while out.len() < len {
        getrandom::fill(&mut byte).expect("OS randomness for OAuth artifacts");
        // 240 is the largest multiple of 20 below 256: values at or above it would bias the
        // low-index symbols if taken modulo, so they are redrawn.
        if byte[0] < 240 {
            out.push(USER_CODE_ALPHABET[(byte[0] % 20) as usize] as char);
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

fn storage_error(e: StorageError) -> ErrorResponse {
    // The host sees the real error through its own Storage impl; the wire gets the opaque code.
    let _ = e;
    ErrorResponse::new(ErrorCode::ServerError)
}

/// The refresh chain an issuance CONTINUES: carried from the redeemed record to its replacement,
/// so that rotation preserves both the family (RFC 9700 section 4.14.2 revokes by grant) and the
/// absolute lifetime (a chain must not slide its own expiry forward every time it rotates).
struct RefreshChain {
    family_id: String,
    expires_at: Option<SystemTime>,
}

/// The authorization server. Generic over the host's [`Storage`] and (for tests) the [`Clock`].
pub struct AuthorizationServer<S: Storage, C: Clock = SystemClock> {
    config: ServerConfig,
    store: S,
    clock: C,
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
        }
    }

    /// The configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
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
    async fn authenticate_client(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
    ) -> Result<Client, ErrorResponse> {
        let client = self
            .store
            .get_client(client_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidClient))?;
        if !client.auth.verify(client_secret) {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient));
        }
        Ok(client)
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
            Some(s) => Err(ErrorResponse::new(ErrorCode::InvalidScope)
                .with_description(format!("scope [{s}] exceeds the client registration"))),
        }
    }

    /// RFC 8628 section 3.1/3.2: start a device authorization.
    pub async fn device_authorization(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
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

    /// Fetch a still-live pending grant by entered user code, for the verification UI actions.
    async fn pending_grant_by_user_code(
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
        grant.state = DeviceGrantState::Approved {
            subject: subject.into(),
        };
        self.store
            .put_device_grant(grant)
            .await
            .map_err(DeviceApprovalError::Storage)
    }

    /// The host's verification UI records the user's refusal.
    ///
    /// The same RFC 8628 section 5.1 obligation as [`AuthorizationServer::approve_device`] applies:
    /// this path also tells a caller whether a code exists, so the HOST must rate limit it too. An
    /// attacker enumerating codes does not care which of the two endpoints answers.
    pub async fn deny_device(&self, entered_user_code: &str) -> Result<(), DeviceApprovalError> {
        let mut grant = self.pending_grant_by_user_code(entered_user_code).await?;
        grant.state = DeviceGrantState::Denied;
        self.store
            .put_device_grant(grant)
            .await
            .map_err(DeviceApprovalError::Storage)
    }

    /// The token endpoint (RFC 6749 section 3.2; device grant per RFC 8628 section 3.4/3.5).
    pub async fn token(&self, request: TokenRequest) -> Result<TokenResponse, ErrorResponse> {
        match request {
            TokenRequest::AuthorizationCode {
                client_id,
                client_secret,
                code,
                redirect_uri,
                code_verifier,
            } => {
                self.authorization_code_token(
                    &client_id,
                    client_secret.as_deref(),
                    &code,
                    redirect_uri.as_deref(),
                    code_verifier.as_deref(),
                )
                .await
            }
            TokenRequest::ClientCredentials {
                client_id,
                client_secret,
                scope,
            } => {
                self.client_credentials_token(&client_id, client_secret.as_deref(), scope.as_ref())
                    .await
            }
            TokenRequest::DeviceCode {
                client_id,
                client_secret,
                device_code,
            } => {
                self.device_token(&client_id, client_secret.as_deref(), &device_code)
                    .await
            }
            TokenRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token,
                scope,
            } => {
                self.refresh_token(
                    &client_id,
                    client_secret.as_deref(),
                    &refresh_token,
                    scope.as_ref(),
                )
                .await
            }
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
        let direct = |code: ErrorCode, why: &str| {
            AuthorizationError::Direct(ErrorResponse::new(code).with_description(why.to_string()))
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
        let redirect = |code: ErrorCode, why: &str| {
            AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: redirect_uri.clone(),
                error: ErrorResponse::new(code).with_description(why.to_string()),
                state: state.clone(),
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

        Ok(ValidatedAuthorizationRequest::new(
            client.client_id,
            redirect_uri,
            scope,
            state,
            code_challenge.to_string(),
            CodeChallengeMethod::S256,
        ))
    }

    /// Mint an authorization code for a request the user has approved (RFC 6749 section 4.1.2).
    ///
    /// `subject` is the authenticated resource owner. Taking a
    /// [`ValidatedAuthorizationRequest`] rather than a raw request is deliberate: an unvalidated
    /// request cannot reach code issuance, because it cannot be spelled.
    pub async fn issue_authorization_code(
        &self,
        request: &ValidatedAuthorizationRequest,
        subject: impl Into<String>,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        let now = self.clock.now();
        let code = random_hex(32);
        let record = AuthorizationCodeRecord {
            code: code.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            subject: subject.into(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method,
            expires_at: now + self.config.authorization_code_ttl,
            state: AuthorizationCodeState::Issued,
        };
        self.store
            .put_authorization_code(record)
            .await
            .map_err(|_| {
                AuthorizationError::Redirect(AuthorizationErrorRedirect {
                    redirect_uri: request.redirect_uri.clone(),
                    error: ErrorResponse::new(ErrorCode::ServerError),
                    state: request.state.clone(),
                })
            })?;
        Ok(AuthorizationResponse {
            code,
            state: request.state.clone(),
        })
    }

    /// RFC 6749 section 4.1.3 with the OAuth 2.1 PKCE requirement: redeem an authorization code.
    async fn authorization_code_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
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
            let _ = self.store.put_authorization_code(record).await;
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
            if let Some(rt) = refresh_token {
                if let Ok(Some(rec)) = self.store.get_refresh_token(rt).await {
                    let _ = self.store.revoke_token_family(&rec.family_id).await;
                    revoked_family = true;
                }
            }
            if !revoked_family {
                // No refresh chain to reach the family through (or it is already swept): the
                // access token this code minted is still nameable directly.
                let _ = self.store.delete_token(access_token).await;
            }
            // The consumed record goes BACK. `src/authorization.rs` and `src/store.rs` both
            // promise it is retained until its own expiry, and that promise is what makes replay
            // detection work more than once: taking it here would make the NEXT replay read as an
            // unknown code, which is the answer a typo gets.
            let _ = self.store.put_authorization_code(record).await;
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

        let issued = self
            .issue(
                &client,
                Some(record.subject.clone()),
                record.scope.clone(),
                None,
                true,
            )
            .await?;

        // Retain the spent code until its own expiry, recording what it minted, so a later replay
        // is recognisable as a replay rather than as an unknown code.
        let spent = AuthorizationCodeRecord {
            state: AuthorizationCodeState::Consumed {
                access_token: issued.access_token.clone(),
                refresh_token: issued.refresh_token.clone(),
            },
            ..record
        };
        self.store
            .put_authorization_code(spent)
            .await
            .map_err(storage_error)?;

        Ok(issued)
    }

    /// RFC 6749 section 4.4: the client acts on its own behalf, with no resource owner.
    async fn client_credentials_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
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
        self.issue(&client, None, scope, None, false).await
    }

    /// RFC 8628 sections 3.4/3.5: one device-token poll.
    async fn device_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        device_code: &str,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
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
        if let Some(last) = grant.last_poll_at {
            if now < last + grant.interval {
                grant.interval += self.config.slow_down_increment;
                grant.last_poll_at = Some(now);
                self.store
                    .put_device_grant(grant)
                    .await
                    .map_err(storage_error)?;
                return Err(ErrorResponse::new(ErrorCode::SlowDown));
            }
        }
        grant.last_poll_at = Some(now);

        match grant.state.clone() {
            DeviceGrantState::Pending => {
                self.store
                    .put_device_grant(grant)
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
                self.issue(&client, Some(subject), taken.scope, None, true)
                    .await
            }
        }
    }

    /// RFC 6749 section 6 with OAuth 2.1 rotation: redeem a refresh token, single use.
    async fn refresh_token(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        refresh_token: &str,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
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
            self.store
                .revoke_token_family(&record.family_id)
                .await
                .map_err(storage_error)?;
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("refresh token reuse detected; the grant has been revoked"));
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

        let issued = self
            .issue(
                &client,
                record.subject.clone(),
                scope,
                Some(RefreshChain {
                    family_id: record.family_id.clone(),
                    expires_at: record.expires_at,
                }),
                true,
            )
            .await?;

        // Retain the rotated token, marked spent, exactly as the authorization code path retains a
        // consumed code and for the same reason: a deleted token makes a later presentation
        // indistinguishable from an unknown string, and reuse detection is then impossible. A
        // chain with no absolute expiry gets a retention deadline here, so the record is
        // reclaimable by `Storage::sweep_expired` rather than immortal.
        let spent = RefreshTokenRecord {
            state: RefreshTokenState::Spent,
            expires_at: record
                .expires_at
                .or_else(|| Some(self.clock.now() + self.config.refresh_reuse_window)),
            ..record
        };
        self.store
            .put_refresh_token(spent)
            .await
            .map_err(storage_error)?;

        Ok(issued)
    }

    /// Mint and persist an access token (and, when configured, a rotated refresh token).
    ///
    /// `chain`: `None` starts a NEW family (a fresh grant); `Some(_)` continues an existing one,
    /// keeping both its family id and its absolute lifetime, which is what makes rotation a chain
    /// rather than a sequence of unrelated tokens.
    async fn issue(
        &self,
        client: &Client,
        subject: Option<String>,
        scope: ScopeSet,
        chain: Option<RefreshChain>,
        allow_refresh: bool,
    ) -> Result<TokenResponse, ErrorResponse> {
        let now = self.clock.now();

        let issues_refresh = allow_refresh
            && self.config.issue_refresh_tokens
            && client.allows_grant(GrantType::RefreshToken);

        // The family id is minted (or inherited) BEFORE the access token, because the access token
        // has to carry it: RFC 9700 section 4.14.2 revokes the tokens of the whole grant on
        // detected reuse, and an access token with no family is unreachable from that event. A
        // grant that issues no refresh chain has no family, and allocates nothing for one: there
        // is no chain to reuse, so there is nothing to revoke by family.
        let family_id = match (&chain, issues_refresh) {
            (Some(c), _) => Some(c.family_id.clone()),
            (None, true) => Some(random_hex(16)),
            (None, false) => None,
        };

        let access_token = random_hex(32);
        self.store
            .put_token(IssuedToken {
                access_token: access_token.clone(),
                client_id: client.client_id.clone(),
                subject: subject.clone(),
                scope: scope.clone(),
                issued_at: now,
                expires_at: now + self.config.access_token_ttl,
                family_id: family_id.clone(),
            })
            .await
            .map_err(storage_error)?;

        let refresh_token = if issues_refresh {
            let expires_at = match &chain {
                Some(c) => c.expires_at,
                None => self.config.refresh_token_ttl.map(|ttl| now + ttl),
            };
            let rt = random_hex(32);
            self.store
                .put_refresh_token(RefreshTokenRecord {
                    refresh_token: rt.clone(),
                    client_id: client.client_id.clone(),
                    subject,
                    scope: scope.clone(),
                    expires_at,
                    // Present whenever a refresh token is: `issues_refresh` is what decided both.
                    family_id: family_id.unwrap_or_default(),
                    state: RefreshTokenState::Active,
                })
                .await
                .map_err(storage_error)?;
            Some(rt)
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer,
            expires_in: self.config.access_token_ttl.as_secs(),
            refresh_token,
            scope: (!scope.is_empty()).then(|| scope.to_string()),
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
    ) -> Result<Option<IssuedToken>, StorageError> {
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
        let client = self.authenticate_client(client_id, client_secret).await?;
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
                token_type: Some(TokenType::Bearer),
                exp: unix_seconds(t.expires_at),
                iat: unix_seconds(t.issued_at),
                iss: Some(self.config.issuer.clone()),
            },
            // Unknown, expired, or somebody else's. All three are one answer on purpose.
            _ => IntrospectionResponse::inactive(),
        })
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
    pub async fn revoke(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
        token_type_hint: Option<TokenTypeHint>,
    ) -> Result<(), ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        // RFC 7009 section 2.1 requires client authentication here and requires the server to
        // verify the token was issued to the requesting client. A public client cannot satisfy the
        // first, so it cannot be held to the second: anyone may name a public client id, which
        // would make this an unauthenticated kill switch for every token that client holds.
        if matches!(client.auth, crate::client::ClientAuth::Public) {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("revocation requires a confidential client"));
        }

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
