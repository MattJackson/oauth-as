// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9126 pushed authorization requests (PAR) and RFC 9101 JWT-secured authorization requests
//! (JAR). Compiled ONLY under the off-by-default `par` and `jar` cargo features; with both off
//! this module does not exist and nothing else in the crate changes.
//!
//! # What these buy
//!
//! In a plain OAuth 2.1 authorization request every parameter travels through the user agent as
//! query text: the browser, its extensions, its history, its `Referer` headers and any proxy in
//! front of it can all read the request, and anything that can rewrite the URL can change it
//! before this server ever sees it. The two mechanisms here close that in different ways, and a
//! deployment may use either or both:
//!
//! - PAR (RFC 9126) moves the parameters off the browser entirely. The client POSTs them to a
//!   back-channel endpoint, authenticating exactly as it would at the token endpoint, and receives
//!   an opaque `request_uri` handle. Only the handle traverses the browser, and it is single use
//!   and short lived, so an intermediary sees nothing and can substitute nothing.
//! - JAR (RFC 9101) leaves the parameters in the browser but SIGNS them. An intermediary can still
//!   read the request; it can no longer alter it without the signature failing.
//!
//! # The two rules that decide whether either is worth anything
//!
//! 1. SINGLE USE, enforced by storage. A `request_uri` is consumed with
//!    [`crate::store::Storage::take_pushed_authorization_request`], the same atomic
//!    remove-and-return primitive that makes authorization codes and refresh tokens single use.
//!    RFC 9126 section 4 says a client MUST use a `request_uri` once and section 7.3 asks the
//!    server to enforce it; a read-then-delete implementation of the trait method reintroduces the
//!    replay under concurrency, which is why the trait says what it says.
//! 2. THE ALGORITHM COMES FROM THE REGISTRATION, never from the token. A JOSE header is written by
//!    whoever wrote the token, so trusting its `alg` is the classic JWS algorithm confusion attack
//!    (RFC 8725 sections 3.1 and 3.2, which RFC 9101 section 6.2 requires be applied here). This
//!    module compares the presented `alg` against the one registered for the client and refuses
//!    anything else; `none` can never match, because [`RequestObjectAlg`] has no variant that
//!    spells it and no constructor that could produce one.
//!
//! # What is deliberately NOT implemented
//!
//! - RFC 9101 section 5.2's fetched `request_uri` (the AS retrieving a request object over HTTPS
//!   from a client-supplied URL). This library never makes outbound network calls, and RFC 9101
//!   section 10.4.1 describes exactly why an AS that does is a DDoS amplifier. The only
//!   `request_uri` values this server accepts are the ones it minted itself at its own PAR
//!   endpoint (RFC 9126 section 2.2's URN form).
//! - RFC 9101 section 6.1 encrypted (JWE) request objects. A five-part JWT is refused with
//!   `invalid_request_object` rather than silently treated as unsigned.

#[cfg(feature = "jar")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "jar")]
use base64::Engine as _;
#[cfg(feature = "par")]
use serde::{Deserialize, Serialize};

use crate::authorization::{
    AuthorizationError, AuthorizationRequest, ValidatedAuthorizationRequest,
};
use crate::client::ClientId;
use crate::error::{ErrorCode, ErrorResponse};
use crate::server::{AuthorizationServer, Clock};
use crate::store::Storage;

// --------------------------------------------------------------------------- RFC 9126 PAR

/// The URN prefix RFC 9126 section 2.2 offers for a minted `request_uri`, registered in its
/// section 9.3. The RFC leaves the format to the server, so this is a choice rather than a
/// requirement; it is the choice every interoperability profile in practice expects, and it names
/// the value as a reference to server-side data rather than as something fetchable.
#[cfg(feature = "par")]
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// How many random bytes go into a `request_uri`. RFC 9126 section 7.1 defers to RFC 9101 section
/// 10.2 clause (d) on entropy: the handle is a capability URL, so guessing one is impersonating
/// the client that pushed it. 32 bytes is 256 bits, the same draw as every other artifact this
/// crate mints.
#[cfg(feature = "par")]
const REQUEST_URI_ENTROPY_BYTES: usize = 32;

/// RFC 9126 configuration. `None` on [`crate::server::ServerConfig::par`] means PAR is OFF: no
/// endpoint is advertised and [`AuthorizationServer::pushed_authorization_request`] refuses.
#[cfg(feature = "par")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParConfig {
    /// RFC 9126 section 5 `pushed_authorization_request_endpoint`. `None` derives
    /// `{issuer}/par`.
    pub pushed_authorization_request_endpoint: Option<String>,
    /// How long a minted `request_uri` stays usable.
    ///
    /// RFC 9126 section 2.2 leaves this to the server and gives 5 to 600 seconds as the typical
    /// range. The default here is 60 seconds, which is a redirect round trip with room to spare:
    /// the handle exists only to get the user agent from the client to this server's authorization
    /// endpoint, and everything the handle protects (the `code_challenge` above all) is worth less
    /// the shorter it is guessable for.
    pub request_uri_ttl: std::time::Duration,
    /// RFC 9126 section 5 `require_pushed_authorization_requests`. When true, this server refuses
    /// any authorization request whose parameters arrived in the query
    /// ([`AuthorizationServer::validate_authorization_request`] answers `invalid_request`), which
    /// is the section 4 policy statement that PAR is the only way in.
    pub require_pushed_authorization_requests: bool,
}

#[cfg(feature = "par")]
impl Default for ParConfig {
    fn default() -> Self {
        ParConfig::new()
    }
}

#[cfg(feature = "par")]
impl ParConfig {
    /// PAR offered, not required, with the 60 second handle lifetime described on
    /// [`ParConfig::request_uri_ttl`].
    pub fn new() -> Self {
        ParConfig {
            pushed_authorization_request_endpoint: None,
            request_uri_ttl: std::time::Duration::from_secs(60),
            require_pushed_authorization_requests: false,
        }
    }

    /// The advertised endpoint for `issuer`.
    pub fn endpoint(&self, issuer: &str) -> String {
        match &self.pushed_authorization_request_endpoint {
            Some(url) => url.clone(),
            None => format!("{}/par", issuer.trim_end_matches('/')),
        }
    }
}

/// The RFC 9126 section 2.2 success response body. The endpoint answers `201 Created`, which the
/// RFC states rather than suggests; see [`PushedAuthorizationResponse::http_status`].
#[cfg(feature = "par")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationResponse {
    /// The single-use handle the client puts in its authorization request.
    pub request_uri: String,
    /// The handle's lifetime in seconds (a positive integer, per section 2.2).
    pub expires_in: u64,
}

#[cfg(feature = "par")]
impl PushedAuthorizationResponse {
    /// `201`. RFC 9126 section 2.2 says the server MUST generate the request URI and provide it
    /// "with a 201 HTTP status code", so this is not the 200 the rest of this crate's endpoints
    /// use and a host must not substitute one.
    pub fn http_status(&self) -> u16 {
        201
    }
}

/// A pushed authorization request as the host persists it, keyed by `request_uri`.
///
/// The fields are the authorization request parameters this server understands, rather than an
/// opaque bag of whatever was posted. That is deliberate: the endpoint validates the pushed
/// request at push time (RFC 9126 section 2.1 step 3), so a parameter this server cannot act on
/// cannot have been validated, and storing it would only let it reappear at the authorization
/// endpoint unexamined. When a future release adds a parameter (RFC 9396 `authorization_details`
/// is the obvious next one), it is added here as well, and the compiler says so.
///
/// `Debug` is hand-written for the same reason as [`crate::authorization::AuthorizationCodeRecord`]'s:
/// the `request_uri` is a capability handle for as long as it is live (RFC 9126 section 7.1), so it
/// must not reach a host's logs through `{:?}`.
#[cfg(feature = "par")]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationRequest {
    /// The handle, and the storage key.
    pub request_uri: String,
    /// The client that pushed it. RFC 9126 section 2.2: the value MUST be bound to this client,
    /// and section 7.5 is the attack that binding prevents.
    pub client_id: ClientId,
    /// `response_type`, as pushed.
    pub response_type: Option<String>,
    /// `redirect_uri`, as pushed.
    pub redirect_uri: Option<String>,
    /// `scope`, as pushed.
    pub scope: Option<String>,
    /// `state`, as pushed.
    pub state: Option<String>,
    /// `code_challenge`, as pushed (RFC 7636 section 4.3).
    pub code_challenge: Option<String>,
    /// `code_challenge_method`, as pushed.
    pub code_challenge_method: Option<String>,
    /// RFC 8707 `resource` indicators, as pushed, in wire order.
    pub resource: Vec<String>,
    /// When the handle dies. RFC 9126 section 4: an expired `request_uri` MUST be rejected.
    pub expires_at: std::time::SystemTime,
}

#[cfg(feature = "par")]
impl std::fmt::Debug for PushedAuthorizationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedAuthorizationRequest")
            .field("request_uri", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("response_type", &self.response_type)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &self.state)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("resource", &self.resource)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[cfg(feature = "par")]
impl PushedAuthorizationRequest {
    /// The stored parameters as an authorization request, borrowing rather than copying: this is
    /// what the authorization endpoint validates, and it should cost no more than reading the
    /// record already did.
    pub fn as_request(&self) -> AuthorizationRequest<'_> {
        AuthorizationRequest {
            response_type: self.response_type.as_deref().map(Into::into),
            client_id: Some(self.client_id.as_str().into()),
            redirect_uri: self.redirect_uri.as_deref().map(Into::into),
            scope: self.scope.as_deref().map(Into::into),
            state: self.state.as_deref().map(Into::into),
            code_challenge: self.code_challenge.as_deref().map(Into::into),
            code_challenge_method: self.code_challenge_method.as_deref().map(Into::into),
            resource: self.resource.iter().map(|r| r.as_str().into()).collect(),
        }
    }
}

// --------------------------------------------------------------------------- RFC 9101 JAR

/// The signing algorithms this server will verify a request object with, in the spelling RFC 8414
/// / RFC 9101 section 4 `request_object_signing_alg_values_supported` uses.
///
/// ES256 and nothing else, for the reason `Cargo.toml` gives for the RFC 9068 signer: this crate
/// carries one curve and no JOSE framework, and an algorithm list is a menu of things an attacker
/// may ask for. `none` is absent and unreachable: see [`RequestObjectAlg`].
#[cfg(feature = "jar")]
pub const REQUEST_OBJECT_SIGNING_ALGS: &[&str] = &["ES256"];

/// The RFC 9101 section 9.4.1 media type for a request object, used as the JOSE `typ` header
/// parameter that RFC 9101 section 10.8 recommends for a new deployment.
#[cfg(feature = "jar")]
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// RFC 9101 configuration. `None` on [`crate::server::ServerConfig::jar`] means signed request
/// objects are OFF: nothing is advertised and a `request` parameter is refused.
#[cfg(feature = "jar")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JarConfig {
    /// RFC 9101 section 10.5 `require_signed_request_object`. When true, this server refuses any
    /// authorization request that is not a signed request object, which is what stops an attacker
    /// stripping the signature and falling back to a plain RFC 6749 request (the downgrade that
    /// section names).
    pub require_signed_request_object: bool,
}

#[cfg(feature = "jar")]
impl JarConfig {
    /// Signed request objects accepted, not required.
    pub fn new() -> Self {
        JarConfig::default()
    }
}

/// A signature algorithm a client may register for its request objects.
///
/// A one-variant enum on purpose. The value that matters is the one that is NOT here: RFC 9101
/// section 10.5 requires `alg: none` to be rejected, and the cheapest way to guarantee that is a
/// type in which "none" cannot be spelled, so no configuration mistake and no future edit to a
/// string comparison can reintroduce it.
#[cfg(feature = "jar")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestObjectAlg {
    /// ECDSA using P-256 and SHA-256 (RFC 7518 section 3.4).
    Es256,
}

#[cfg(feature = "jar")]
impl RequestObjectAlg {
    /// The registered JOSE `alg` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RequestObjectAlg::Es256 => "ES256",
        }
    }
}

/// A public key was not usable as a request object verification key. Carries no key material.
#[cfg(feature = "jar")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestObjectKeyError(String);

#[cfg(feature = "jar")]
impl std::fmt::Display for RequestObjectKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request object key error: {}", self.0)
    }
}

#[cfg(feature = "jar")]
impl std::error::Error for RequestObjectKeyError {}

/// What a client registered to sign its request objects with: one algorithm and one public key.
///
/// Both halves are the REGISTRATION's, never the token's. RFC 9101 section 6.2 requires the
/// signature to be validated "using a key associated with the client and the algorithm specified
/// in the `alg` Header Parameter", with RFC 8725 sections 3.1 and 3.2 applied, and the only
/// reading of those together that is not an algorithm confusion attack is: take the algorithm the
/// client registered, and refuse the token if its header names anything else.
#[cfg(feature = "jar")]
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredRequestObjectKey {
    alg: RequestObjectAlg,
    kid: Option<String>,
    /// The uncompressed SEC 1 point, `0x04 || x || y`, validated as an actual curve point at
    /// construction so a malformed registration fails when it is made rather than when a request
    /// arrives.
    sec1: [u8; 65],
}

#[cfg(feature = "jar")]
impl std::fmt::Debug for RegisteredRequestObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredRequestObjectKey")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .finish()
    }
}

#[cfg(feature = "jar")]
impl RegisteredRequestObjectKey {
    /// Register an ES256 key from the `x` and `y` members of a client's RFC 7517 JWK, exactly as
    /// they appear there (base64url, unpadded, 32 bytes each).
    pub fn es256_from_jwk_coordinates(
        kid: Option<String>,
        x: &str,
        y: &str,
    ) -> Result<Self, RequestObjectKeyError> {
        let x = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| RequestObjectKeyError("x is not base64url".into()))?;
        let y = URL_SAFE_NO_PAD
            .decode(y)
            .map_err(|_| RequestObjectKeyError("y is not base64url".into()))?;
        // RFC 7518 section 6.2.1.2 fixes both coordinates at the curve's full byte length, so a
        // trimmed leading zero is a different (and unusable) key rather than the same one.
        if x.len() != 32 || y.len() != 32 {
            return Err(RequestObjectKeyError(
                "a P-256 coordinate is exactly 32 bytes".into(),
            ));
        }
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..].copy_from_slice(&y);
        Self::es256_from_sec1(kid, &sec1)
    }

    /// Register an ES256 key from an uncompressed SEC 1 point (65 bytes, `0x04 || x || y`).
    pub fn es256_from_sec1(
        kid: Option<String>,
        sec1: &[u8],
    ) -> Result<Self, RequestObjectKeyError> {
        if sec1.len() != 65 {
            return Err(RequestObjectKeyError(
                "an uncompressed P-256 point is exactly 65 bytes".into(),
            ));
        }
        // Parsed once, here, so that "the host registered something that is not on the curve" is a
        // configuration error rather than a per-request verification failure nobody can explain.
        p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
            .map_err(|_| RequestObjectKeyError("not a point on P-256".into()))?;
        let mut owned = [0u8; 65];
        owned.copy_from_slice(sec1);
        Ok(RegisteredRequestObjectKey {
            alg: RequestObjectAlg::Es256,
            kid,
            sec1: owned,
        })
    }

    /// The registered algorithm. This, not the token header, decides.
    pub fn alg(&self) -> RequestObjectAlg {
        self.alg
    }

    /// The registered `kid`, when the client named one.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Where the request object verification keys come from: the host answers "what did this client
/// register".
///
/// This is a SEAM rather than a field on [`crate::client::Client`], and the reason is stated
/// plainly because it is a temporary one. RFC 7523 `private_key_jwt` client authentication needs
/// the same thing (a public key per client), so client-registered key material belongs on the
/// registration once that lands, and this trait should then be re-pointed at it rather than
/// duplicated. Until then, a host installs one of these with
/// [`AuthorizationServer::with_request_object_keys`] and answers from wherever it already keeps
/// client keys.
///
/// With none installed, a `request` parameter is refused: a server that cannot check a signature
/// must never treat the request as if it had checked one.
#[cfg(feature = "jar")]
pub trait RequestObjectKeys: Send + Sync {
    /// The key `client_id` registered for signing request objects, or `None` if it registered
    /// none (in which case it may not use JAR at all).
    fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey>;
}

/// The authorization request parameters carried as claims of a verified request object.
///
/// Only the parameters this server acts on are extracted. RFC 9101 section 4 lets a request object
/// carry any extension parameter, and RFC 6749 section 3.1 requires unknown ones to be ignored,
/// which is what not extracting them means here.
#[cfg(feature = "jar")]
#[derive(Debug)]
struct RequestObjectClaims {
    client_id: String,
    response_type: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Vec<String>,
}

#[cfg(feature = "jar")]
impl RequestObjectClaims {
    fn as_request(&self) -> AuthorizationRequest<'_> {
        AuthorizationRequest {
            response_type: self.response_type.as_deref().map(Into::into),
            client_id: Some(self.client_id.as_str().into()),
            redirect_uri: self.redirect_uri.as_deref().map(Into::into),
            scope: self.scope.as_deref().map(Into::into),
            state: self.state.as_deref().map(Into::into),
            code_challenge: self.code_challenge.as_deref().map(Into::into),
            code_challenge_method: self.code_challenge_method.as_deref().map(Into::into),
            resource: self.resource.iter().map(|r| r.as_str().into()).collect(),
        }
    }
}

/// `invalid_request_object` (RFC 9101 section 7) with a developer-facing reason.
///
/// The reason never quotes the offending token: RFC 6749 section 5.2 restricts `error_description`
/// to a charset a base64url blob does not respect, and echoing attacker-supplied bytes into an
/// error body is how an error message becomes an injection vector.
#[cfg(feature = "jar")]
fn invalid_request_object(why: &str) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::InvalidRequestObject).with_description(why.to_string())
}

/// One base64url (unpadded) segment of a JWS compact serialization.
#[cfg(feature = "jar")]
fn decode_segment(segment: &str, what: &str) -> Result<Vec<u8>, ErrorResponse> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| invalid_request_object(&format!("the {what} is not base64url")))
}

/// Verify an ES256 signature over `signing_input`.
///
/// SEAM, and marked as one deliberately. Another slice of this release is adding JWS VERIFICATION
/// primitives to `src/jwt.rs` for RFC 7523 client assertions and RFC 9449 DPoP proofs; when they
/// land, this function's body becomes a call to them and everything above it stays as it is. What
/// it needs from those primitives is exactly this signature: "does this 64 byte `r || s` verify
/// over these bytes under this SEC 1 public key", with no algorithm negotiation inside it, because
/// the algorithm was already decided by the registration before this is reached.
#[cfg(feature = "jar")]
fn verify_es256(sec1_public_key: &[u8; 65], signing_input: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    // RFC 7518 section 3.4: an ES256 signature is the fixed-width 64 byte `r || s`, NOT the DER
    // form. A DER-encoded signature is refused here rather than re-encoded, because accepting two
    // encodings of one signature is how signature malleability gets in.
    if signature.len() != 64 {
        return false;
    }
    let key = match p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = match p256::ecdsa::Signature::from_slice(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    key.verify(signing_input, &signature).is_ok()
}

/// Read one claim that RFC 9101 section 4 requires to be a JSON string.
#[cfg(feature = "jar")]
fn string_claim(
    claims: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<Option<String>, ErrorResponse> {
    match claims.get(name) {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        // Section 4: "Parameter names and string values MUST be included as JSON strings". A
        // number or an object here is not a request parameter that could ever have been sent in a
        // query string, so coercing it would be inventing a request the client did not make.
        Some(_) => Err(invalid_request_object(&format!(
            "the {name} claim must be a JSON string"
        ))),
    }
}

// ------------------------------------------------------------------- the server-side endpoints

impl<S: Storage, C: Clock> AuthorizationServer<S, C> {
    /// RFC 9126 section 2: the pushed authorization request endpoint.
    ///
    /// `parameters` is the form body exactly as it arrived, so that this can apply section 2.1
    /// step 2 (a pushed request carrying `request_uri` is refused) and section 3 (a `request`
    /// parameter is a signed request object) rather than making the host decide either. Parameters
    /// this server does not know are ignored, per RFC 6749 section 3.1.
    ///
    /// The client authenticates exactly as at the token endpoint (section 2.1 step 1), and the
    /// pushed request is fully validated here (step 3): client, exact-match redirect URI, PKCE
    /// S256, scope inside the registration, RFC 8707 resource indicators. That is the whole point
    /// of the back channel. A client learns its request is malformed from a JSON error it can read
    /// rather than from a browser redirect it cannot.
    ///
    /// Errors follow RFC 9126 section 2.3: the token endpoint's RFC 6749 section 5.2 shape, with
    /// `invalid_request` standing in for the authorization errors section 4.1.2.1 refuses to
    /// redirect (a missing or mismatching redirect URI above all).
    #[cfg(feature = "par")]
    pub async fn pushed_authorization_request(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        parameters: &[(&str, &str)],
    ) -> Result<PushedAuthorizationResponse, ErrorResponse> {
        self.pushed_authorization_request_with_credential(
            client_id,
            &crate::server::ClientCredential::secret(client_secret),
            parameters,
        )
        .await
    }

    /// [`AuthorizationServer::pushed_authorization_request`] for a client presenting any credential
    /// this server accepts at the token endpoint, not just a shared secret.
    ///
    /// RFC 9126 section 2.1 step 1 says the client authenticates here "in the same way as at the
    /// token endpoint", so an RFC 7523 `private_key_jwt` client that the token endpoint accepts
    /// must be accepted here too; a PAR endpoint that only understood `client_secret_basic` would
    /// lock exactly the deployments that most want PAR (FAPI 2.0 requires both) out of it. This
    /// mirrors `device_authorization_with_credential` and
    /// `introspection_response_with_credential`, for the same reason and with the same shape.
    #[cfg(feature = "par")]
    pub async fn pushed_authorization_request_with_credential(
        &self,
        client_id: &ClientId,
        credential: &crate::server::ClientCredential<'_>,
        parameters: &[(&str, &str)],
    ) -> Result<PushedAuthorizationResponse, ErrorResponse> {
        // Read before authenticating: a server that is not offering PAR should say so whatever the
        // credential was, and should not become a client-credential oracle for a feature it does
        // not run.
        if self.config().par.is_none() {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("this server does not offer pushed authorization requests"));
        }

        // 1. Client authentication, "in the same way as at the token endpoint" (section 2.1).
        let client = self.authenticate_client(client_id, credential).await?;

        // 2. Section 2.1: `request_uri` MUST NOT be provided here. Chaining one handle to another
        //    would let a client (or an attacker who captured a handle) re-push somebody else's
        //    request under its own identity.
        if parameters.iter().any(|(name, _)| *name == "request_uri") {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("request_uri must not be pushed (RFC 9126 s2.1)"));
        }

        // Section 3: the parameters may instead arrive inside a signed request object, in which
        // case they are the ONLY source; anything alongside it in the form body is client
        // authentication and nothing else.
        #[cfg(feature = "jar")]
        if let Some((_, object)) = parameters.iter().find(|(name, _)| *name == "request") {
            let claims = self.verified_request_object(&client.client_id, object)?;
            return self
                .store_pushed_request(&client.client_id, &claims.as_request())
                .await;
        }

        let request = AuthorizationRequest::from_pairs(parameters.iter().copied());
        self.store_pushed_request(&client.client_id, &request).await
    }

    /// Validate a pushed request and mint its handle. Split out so that the form-body path and the
    /// signed-request-object path cannot drift apart.
    #[cfg(feature = "par")]
    async fn store_pushed_request(
        &self,
        authenticated: &ClientId,
        request: &AuthorizationRequest<'_>,
    ) -> Result<PushedAuthorizationResponse, ErrorResponse> {
        // A client may push only its OWN request. RFC 9126 section 2.1 makes `client_id` a
        // required parameter here with its ordinary meaning, and section 3 step 3 states the rule
        // explicitly for the request-object form: the authenticated client and the request's
        // client must be the same. Without this, an authenticated client could lodge a request
        // that names a victim client and hand the handle to the browser.
        match request.client_id.as_deref() {
            Some(pushed) if pushed == authenticated.as_str() => {}
            Some(_) => {
                return Err(
                    ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                        "client_id does not match the authenticated client (RFC 9126 s2.1)",
                    ),
                )
            }
            None => {
                return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("client_id is required (RFC 9126 s2.1)"))
            }
        }

        // Section 2.1 step 3: the same validation the authorization endpoint performs, reused
        // rather than reimplemented. Two copies of this drift, and the copy that drifts is the one
        // an attacker uses.
        //
        // The two-shape authorization error (RFC 6749 section 4.1.2.1) collapses to one JSON body
        // here, because there is no user agent to redirect: section 2.3 says so and gives
        // `invalid_request` as the default for the non-redirectable half.
        self.validate_direct_authorization_request(request)
            .await
            .map_err(|e| match e {
                AuthorizationError::Direct(error) => error,
                AuthorizationError::Redirect(redirect) => redirect.error,
            })?;

        let ttl = match &self.config().par {
            Some(par) => par.request_uri_ttl,
            // Unreachable through the public endpoint, which checks this first; answered rather
            // than panicked because a library must not take a host's process down over its own
            // configuration.
            None => {
                return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("this server does not offer pushed authorization requests"))
            }
        };
        let now = self.now();
        let request_uri = format!(
            "{REQUEST_URI_PREFIX}{}",
            crate::server::random_hex(REQUEST_URI_ENTROPY_BYTES)
        );
        let record = PushedAuthorizationRequest {
            request_uri: request_uri.clone(),
            client_id: authenticated.clone(),
            response_type: request.response_type.as_deref().map(str::to_string),
            redirect_uri: request.redirect_uri.as_deref().map(str::to_string),
            scope: request.scope.as_deref().map(str::to_string),
            state: request.state.as_deref().map(str::to_string),
            code_challenge: request.code_challenge.as_deref().map(str::to_string),
            code_challenge_method: request.code_challenge_method.as_deref().map(str::to_string),
            resource: request.resource.iter().map(|r| r.to_string()).collect(),
            expires_at: now + ttl,
        };
        self.store()
            .put_pushed_authorization_request(record)
            .await
            .map_err(|e| {
                let _ = e;
                ErrorResponse::new(ErrorCode::ServerError)
            })?;
        Ok(PushedAuthorizationResponse {
            request_uri,
            expires_in: ttl.as_secs(),
        })
    }

    /// The authorization endpoint for a request that arrived as `client_id` plus `request_uri`
    /// (RFC 9126 section 4).
    ///
    /// Every OTHER query parameter is ignored, and this signature is how that is enforced: they
    /// are not accepted, so there is no code path in which one of them could win. RFC 9101
    /// section 6.3, which RFC 9126 section 4 builds on, is explicit that the server MUST only use
    /// the parameters from the reference "even if the same parameter is provided in the query
    /// parameter". A client that duplicates `scope` in the query gets the pushed `scope`; an
    /// attacker who appends one gets the same.
    ///
    /// The handle is consumed atomically, so a second use of it fails however many requests are in
    /// flight (RFC 9126 section 4 and section 7.3).
    #[cfg(feature = "par")]
    pub async fn validate_pushed_authorization_request(
        &self,
        client_id: &str,
        request_uri: &str,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        // Errors here are DIRECT, never a redirect: the redirect URI lives inside the record that
        // has not been read yet (or does not exist), and RFC 6749 section 4.1.2.1 forbids
        // redirecting to a URI the server has not validated. That is the whole reason the two
        // error shapes exist.
        let direct = |code: ErrorCode, why: &str| {
            AuthorizationError::Direct(ErrorResponse::new(code).with_description(why.to_string()))
        };

        let record = self
            .store()
            .take_pushed_authorization_request(request_uri)
            .await
            .map_err(|e| {
                let _ = e;
                AuthorizationError::Direct(ErrorResponse::new(ErrorCode::ServerError))
            })?
            .ok_or_else(|| {
                // Unknown, already used, or swept. One answer for all three: an attacker probing
                // handles learns nothing from the difference, and a client that reloaded its
                // browser learns the same thing either way.
                direct(
                    ErrorCode::InvalidRequestUri,
                    "unknown, expired or already used request_uri",
                )
            })?;

        // RFC 9126 section 2.2: the handle is bound to the client that pushed it, and section 7.5
        // (request URI swapping) is the attack. The record goes BACK, exactly as a cross-client
        // authorization code does in `server.rs`: burning a live handle for a request that was
        // never entitled to it is a denial of service handed to whoever asks.
        if record.client_id.as_str() != client_id {
            let _ = self.store().put_pushed_authorization_request(record).await;
            return Err(direct(
                ErrorCode::InvalidRequestUri,
                "request_uri was not issued to this client",
            ));
        }

        // Section 4: an expired request_uri MUST be rejected. Not put back: it can never become
        // valid again, so retaining it would only leave a guessable string in the store.
        if self.now() >= record.expires_at {
            return Err(direct(
                ErrorCode::InvalidRequestUri,
                "request_uri has expired",
            ));
        }

        // Section 4 again: validated as any other authorization request would be. The pushed
        // request was validated at push time too, and doing it twice is the answer section 7.4
        // asks for, since the client's policy may have changed in between (a redirect URI removed,
        // a scope withdrawn, the client deleted outright).
        self.validate_direct_authorization_request(&record.as_request())
            .await
    }

    /// The authorization endpoint for a request that arrived as `client_id` plus a signed
    /// `request` object (RFC 9101 sections 5.1 and 6).
    ///
    /// As with [`AuthorizationServer::validate_pushed_authorization_request`], the query
    /// parameters that a client may have duplicated alongside the object are not accepted here at
    /// all: RFC 9101 section 6.3 requires the server to use only the object's own parameters, and
    /// the surest way to honour that is to have no other parameters in hand.
    #[cfg(feature = "jar")]
    pub async fn validate_signed_authorization_request(
        &self,
        client_id: &str,
        request_object: &str,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        let claims = self
            .verified_request_object(&ClientId::new(client_id), request_object)
            .map_err(AuthorizationError::Direct)?;
        self.validate_direct_authorization_request(&claims.as_request())
            .await
    }

    /// Verify a JWS-signed request object and extract its authorization request parameters
    /// (RFC 9101 section 6.2 and section 6.3).
    ///
    /// `client_id` is the client the request CLAIMS to be, taken from the authenticated client at
    /// the PAR endpoint or from the `client_id` query parameter at the authorization endpoint
    /// (RFC 9101 section 5 makes it REQUIRED there). It selects the verification key, and section
    /// 6.3 then requires the object's own `client_id` claim to be the same value: selecting the
    /// key by the claimed identity is safe precisely because the signature check that follows is
    /// what proves the identity.
    #[cfg(feature = "jar")]
    fn verified_request_object(
        &self,
        client_id: &ClientId,
        request_object: &str,
    ) -> Result<RequestObjectClaims, ErrorResponse> {
        if self.config().jar.is_none() {
            // RFC 9101 section 7 registers `request_not_supported` for exactly this.
            return Err(ErrorResponse::new(ErrorCode::RequestNotSupported)
                .with_description("this server does not accept signed request objects"));
        }
        let keys = self.hooks().request_object_keys().ok_or_else(|| {
            // A server with no key source cannot check a signature, and "cannot check" must never
            // read as "checked out".
            invalid_request_object("no request object verification keys are installed")
        })?;
        let registered = keys
            .registered_key(client_id)
            .ok_or_else(|| invalid_request_object("the client registered no request object key"))?;

        // RFC 7515 section 3.1 compact serialization: exactly three parts. A five-part token is a
        // JWE, which RFC 9101 section 6.1 defines and this server does not implement; refusing it
        // by shape is what stops it being read as an unsigned JWS.
        let mut parts = request_object.split('.');
        let (header_b64, payload_b64, signature_b64) =
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(h), Some(p), Some(s), None) => (h, p, s),
                _ => {
                    return Err(invalid_request_object(
                        "not a three part JWS compact serialization",
                    ))
                }
            };

        let header: serde_json::Value =
            serde_json::from_slice(&decode_segment(header_b64, "header")?)
                .map_err(|_| invalid_request_object("the header is not JSON"))?;
        let alg = header
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid_request_object("the header has no alg"))?;

        // THE algorithm check. The registration decides; the header only gets to agree with it.
        // This is what makes `alg: none` and every other substitution (RFC 8725 sections 3.1 and
        // 3.2) a refusal rather than a verification path, and it is the reason `alg` is compared
        // BEFORE any signature work is attempted.
        if alg != registered.alg.as_str() {
            return Err(invalid_request_object(
                "alg does not match the algorithm registered for this client",
            ));
        }

        // RFC 9101 section 6.2: "If a kid Header Parameter is present, the key identified MUST be
        // the key used and MUST be a key associated with the client."
        if let Some(presented) = header.get("kid").and_then(serde_json::Value::as_str) {
            match registered.kid() {
                Some(kid) if kid == presented => {}
                _ => {
                    return Err(invalid_request_object(
                        "kid does not identify a key registered for this client",
                    ))
                }
            }
        }

        // RFC 9101 section 10.8 (cross-JWT confusion), applying RFC 8725 section 3.11. A request
        // object is not the only JWT this issuer's clients hold, and a JWT minted for another
        // purpose must not be usable as an authorization request. `typ` is optional (requiring it
        // would break clients that predate the media type), but a `typ` that names something else
        // is a token that was made for something else.
        if let Some(typ) = header.get("typ").and_then(serde_json::Value::as_str) {
            if typ != REQUEST_OBJECT_TYP && typ != "JWT" && typ != "jwt" {
                return Err(invalid_request_object(
                    "typ names a JWT that is not a request object",
                ));
            }
        }

        let signature = decode_segment(signature_b64, "signature")?;
        // The JWS Signing Input is the ASCII of "header.payload" (RFC 7515 section 5.2 step 8),
        // taken from the ORIGINAL text rather than re-encoded: re-encoding would verify a
        // normalisation of the token instead of the token, which is how a signature check gets
        // decoupled from what it is supposed to be checking.
        let signing_input = &request_object.as_bytes()[..header_b64.len() + 1 + payload_b64.len()];
        if !verify_es256(&registered.sec1, signing_input, &signature) {
            return Err(invalid_request_object("the signature did not verify"));
        }

        // Only now is anything in the payload worth reading.
        let payload: serde_json::Value =
            serde_json::from_slice(&decode_segment(payload_b64, "payload")?)
                .map_err(|_| invalid_request_object("the payload is not JSON"))?;
        let claims = payload
            .as_object()
            .ok_or_else(|| invalid_request_object("the payload is not a JSON object"))?;

        // RFC 9101 section 4: "request and request_uri parameters MUST NOT be included in Request
        // Objects". A nested reference would be a request that never terminates, and at the PAR
        // endpoint it would smuggle past the section 2.1 refusal of `request_uri`.
        for forbidden in ["request", "request_uri"] {
            if claims.contains_key(forbidden) {
                return Err(invalid_request_object(
                    "a request object must not carry request or request_uri (RFC 9101 s4)",
                ));
            }
        }

        // Section 6.3: the two client ids MUST be identical.
        match string_claim(claims, "client_id")? {
            Some(claimed) if claimed == client_id.as_str() => {}
            _ => {
                return Err(invalid_request_object(
                    "the client_id claim does not match the request's client_id (RFC 9101 s6.3)",
                ))
            }
        }

        // RFC 9101 section 4 says a signed request object SHOULD carry `aud` naming this server's
        // issuer identifier. When it does, it is checked: an object addressed to a different
        // authorization server, replayed here by whoever intercepted it, is the mix-up that `aud`
        // exists to stop. When it does not, the object is still accepted, because SHOULD is not
        // MUST and refusing would break conforming clients.
        if let Some(aud) = payload.get("aud") {
            let issuer = self.issuer_identifier();
            let addressed_here = match aud {
                serde_json::Value::String(one) => one == issuer,
                serde_json::Value::Array(many) => many
                    .iter()
                    .any(|v| v.as_str().map(|s| s == issuer).unwrap_or(false)),
                _ => false,
            };
            if !addressed_here {
                return Err(invalid_request_object(
                    "aud does not name this authorization server",
                ));
            }
        }

        // RFC 7519 section 4.1.4 / 4.1.5: a request object that carries a lifetime is honoured. An
        // expired object is a captured object being replayed.
        let now_secs = crate::server::unix_seconds(self.now());
        if let (Some(now), Some(exp)) = (now_secs, payload.get("exp").and_then(|v| v.as_u64())) {
            if now >= exp {
                return Err(invalid_request_object("the request object has expired"));
            }
        }
        if let (Some(now), Some(nbf)) = (now_secs, payload.get("nbf").and_then(|v| v.as_u64())) {
            if now < nbf {
                return Err(invalid_request_object(
                    "the request object is not yet valid",
                ));
            }
        }

        // RFC 8707 section 2 allows `resource` more than once, which in a JSON claim set is an
        // array; a single indicator stays a plain string.
        let resource = match claims.get("resource") {
            None => Vec::new(),
            Some(serde_json::Value::String(one)) => vec![one.clone()],
            Some(serde_json::Value::Array(many)) => {
                let mut out = Vec::with_capacity(many.len());
                for value in many {
                    match value.as_str() {
                        Some(s) => out.push(s.to_string()),
                        None => {
                            return Err(invalid_request_object(
                                "every resource claim entry must be a JSON string",
                            ))
                        }
                    }
                }
                out
            }
            Some(_) => {
                return Err(invalid_request_object(
                    "the resource claim must be a string or an array of strings",
                ))
            }
        };

        Ok(RequestObjectClaims {
            client_id: client_id.as_str().to_string(),
            response_type: string_claim(claims, "response_type")?,
            redirect_uri: string_claim(claims, "redirect_uri")?,
            scope: string_claim(claims, "scope")?,
            state: string_claim(claims, "state")?,
            code_challenge: string_claim(claims, "code_challenge")?,
            code_challenge_method: string_claim(claims, "code_challenge_method")?,
            resource,
        })
    }
}

#[cfg(test)]
#[path = "tests/par.rs"]
mod tests;
