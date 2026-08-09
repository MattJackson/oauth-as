// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! An OPTIONAL HTTP service over [`AuthorizationServer`], behind the `http` cargo feature.
//!
//! # Why this is optional, and stays optional
//!
//! The premise of this crate is that the host owns the listener. A library that drags a web
//! framework and an async runtime into every consumer has taken that decision away, so the
//! default feature set is empty and nothing in the library below this module knows this module
//! exists. Turning the feature on is the host saying "serve the RFC-shaped wire surface for me
//! rather than making me write it"; leaving it off costs nothing, not even a compiled dependency.
//!
//! # Why there is no web framework in this module's PUBLIC API
//!
//! This module speaks `http` 1.x and `http-body` 1.x and nothing else: [`AuthorizationService`]
//! is an `async fn` from an [`http::Request`] to an [`http::Response`]. Those two crates are 1.0
//! and their major has never moved, so a host may mount this service under whatever server it
//! already runs.
//!
//! That is a deliberate correction. Until 0.9 this module handed back an `axum::Router`, which
//! put a 0.x major in the signature of the only way to use the feature: a host on any other axum
//! major could not enable `http` AT ALL, and an axum major bump would have been a breaking change
//! to THIS crate for reasons that have nothing to do with OAuth. axum is now a thin ADAPTER
//! behind the separate `axum` feature (`impl From<AuthorizationService<..>> for axum::Router`),
//! so the hazard is confined to hosts that opt into it.
//!
//! Nothing was hand-rolled to get there. This module already wrote its own percent-decoder, form
//! parser, first-wins parameter logic, Basic-auth decoder and response builders, precisely so that
//! the RFC-mandated headers land on the same response as the body they describe; it used a
//! framework for exactly three things (route matching, one dynamic path segment, and body
//! collection with a cap), and those three are what [`Routes`] and [`collect_body`] now do.
//!
//! # What it serves
//!
//! Exactly the endpoints [`AuthorizationServerMetadata`] advertises, at exactly the paths it
//! advertises them, plus the RFC 8628 `verification_uri`. The paths are DERIVED from the metadata
//! document rather than hard-coded, because an advertised endpoint that 404s is a lie a client
//! cannot recover from: if a host overrides `token_endpoint`, the route moves with it or
//! [`ServiceBuilder::build`] refuses to produce a service at all.
//!
//! Under the `jwt` feature that includes `jwks_uri`: the document advertises it exactly when the
//! server signs its access tokens, and this router serves the RFC 7517 key set there. A resource
//! server that cannot fetch the keys cannot verify a single RFC 9068 token, so an advertised
//! `jwks_uri` this router cannot reach is the same lie as any other unroutable endpoint.
//!
//! # Cost
//!
//! The metadata document is serialized ONCE, when the router is built, and served from the
//! resulting [`Bytes`] (a clone is a refcount bump, not a copy). The key set is serialized once
//! for the same reason: its contents change only when the host rebuilds the router. The
//! `WWW-Authenticate` challenge
//! is likewise built once. There are no lazy statics, no background tasks, and no per-request
//! rebuilding of anything derived from configuration. Request parsing borrows out of the request
//! body and query string and only allocates for values that actually needed percent-decoding.
//!
//! # What the host still owns, and MUST wire
//!
//! Three things this module cannot invent, each with a seam, and each of which REFUSES when the
//! seam is not wired:
//!
//! 1. Authenticating the RESOURCE OWNER ([`ServiceBuilder::with_subject_resolver`]). This module
//!    cannot know how a host logs a user in.
//! 2. CONSENT at the authorization endpoint ([`ServiceBuilder::with_consent_resolver`]). RFC 6749
//!    s10.12 requires the AS to ensure the resource owner is aware of, and explicitly consents
//!    to, the authorization. A subject resolver answers "who is this"; it does not answer "did
//!    they agree", and treating the first as the second is an AS that silently authorizes any
//!    registered client on any cross-site navigation.
//! 3. A CSRF token bound to the host's session, for the device verification form
//!    ([`ServiceBuilder::with_csrf_tokens`]). This crate has no session store, so it cannot mint
//!    one; RFC 6749 s10.12 still requires the protection, so an unwired host gets a refusal and
//!    is never served a submittable, forgeable form.
//!
//! Every non-interactive endpoint works regardless of all three.

use std::borrow::Cow;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bytes::{Buf as _, Bytes};
use http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::authorization::{AuthorizationError, AuthorizationRequest};
use crate::client::ClientId;
use crate::device::{normalize_user_code, DeviceGrant, DeviceGrantState};
use crate::error::{ErrorCode, ErrorResponse};
use crate::events::{Attempt, AttemptOutcome, RateLimitDecision};
use crate::grant::GrantType;
use crate::metadata::{well_known_path, AuthorizationServerMetadata};
use crate::scope::ScopeSet;
use crate::server::{AuthorizationServer, Clock, DeviceApprovalError, TokenRequest};
use crate::store::Storage;
use crate::token::TokenTypeHint;

/// The response body this module produces: a single in-memory buffer, already complete.
///
/// Every response an authorization server emits is a short JSON document, a small HTML page, or
/// nothing at all, and all of them are finished before the first byte is written. So the body type
/// is a `Bytes` rather than a stream: there is nothing to stream, and a boxed
/// `dyn http_body::Body` would add an allocation and a virtual call per response to express a
/// capability this module never uses.
///
/// It implements [`http_body::Body`] with an INFALLIBLE error type and an EXACT size hint. The
/// second matters on the wire: a server that knows the length emits `Content-Length` rather than
/// falling back to chunked transfer encoding.
#[derive(Debug, Default, Clone)]
pub struct Body(Option<Bytes>);

impl Body {
    /// A body with no bytes at all. RFC 7009 s2.2's revocation success and RFC 7592 s2.3's
    /// deletion both answer with one.
    pub fn empty() -> Self {
        Body(None)
    }

    /// The bytes, consuming the body.
    pub fn into_bytes(self) -> Bytes {
        self.0.unwrap_or_default()
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        // An empty `Bytes` and "no frame at all" are the same response on the wire, and
        // collapsing them here means `is_end_stream` is true from the start for an empty body,
        // so a server need not poll for a frame it will never get.
        match bytes.is_empty() {
            true => Body(None),
            false => Body(Some(bytes)),
        }
    }
}

// Spelled out one type at a time rather than as `impl<T: Into<Bytes>>`, which cannot be written:
// it would overlap with the standard library's reflexive `From<T> for T` and coherence has no way
// to rule that out.
impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Body::from(Bytes::from(value))
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Body::from(Bytes::from(value))
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Body::from(Bytes::from_static(value.as_bytes()))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    // This body is already in memory, so there is no read that could fail. Naming that in the
    // type means a host mounting the service never has to write an error arm that cannot happen.
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(self.0.take().map(|b| Ok(http_body::Frame::data(b))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.0.as_ref().map_or(0, |b| b.len() as u64))
    }
}

/// The response type this module produces, and the one
/// [`ConsentDecision::Respond`] carries.
///
/// A plain [`http::Response`], deliberately: the host that renders a consent screen builds it with
/// whatever it already has, and `http` 1.x is the one HTTP vocabulary every Rust web framework
/// agrees on.
pub type Response = http::Response<Body>;

/// Build a response with a status and a complete body, and no headers yet.
///
/// Every caller sets its own `Content-Type` (and, on the token plane, the RFC 6749 s5.1 caching
/// directives), so nothing is guessed here. That is the same reason this module never used a JSON
/// extractor: the RFC-mandated headers and the body they describe are set in one place.
fn respond(status: StatusCode, body: impl Into<Body>) -> Response {
    let mut resp = Response::new(body.into());
    *resp.status_mut() = status;
    resp
}

/// How the host names the authenticated resource owner for the interactive endpoints.
///
/// The `HeaderMap` is the request's, so a host can read its own session cookie or a
/// reverse-proxy assertion header. `None` means "nobody is logged in", which is a refusal, not
/// an error: see [`ServiceBuilder::with_subject_resolver`].
pub type SubjectResolver = Arc<dyn Fn(&HeaderMap) -> Option<String> + Send + Sync>;

/// A CSRF token hook: issue one for, or take one back from, the session this request carries.
///
/// `None` means "this request has no session", which is a refusal. See
/// [`ServiceBuilder::with_csrf_tokens`] for the contract the two hooks satisfy together.
pub type CsrfTokenHook = Arc<dyn Fn(&HeaderMap) -> Option<String> + Send + Sync>;

/// What the host's consent step decided about one authorization request.
///
/// Naming the third variant `Respond` is the point of the type: a real host shows a consent
/// SCREEN, which means the first request renders HTML and a later one carries the answer. The
/// resolver returns that page here and the router serves it unchanged, so interposing a consent
/// UI never requires abandoning this router.
pub enum ConsentDecision {
    /// The resource owner has agreed to this exact request. RFC 6749 s4.1.2: mint the code.
    Approve,
    /// The resource owner refused. RFC 6749 s4.1.2.1: `access_denied` at the redirect URI, which
    /// is an answer the client is entitled to receive.
    Deny,
    /// The resource owner agreed AND asked not to be asked again: mint the code, and record (or
    /// widen) the consent so a later request can be recognised as already granted.
    ///
    /// A separate variant rather than something the library infers, because remembering is a
    /// statement about a user's intent and this crate never sees a user. It will not remember a
    /// consent nobody asked it to remember, and it will not approve one it does remember.
    #[cfg(feature = "consent")]
    ApproveAndRemember,
    /// Serve this response instead, unchanged: a consent screen, a login redirect, a step-up
    /// challenge. Nothing is issued.
    Respond(Box<Response>),
}

/// What the host's consent resolver is told about the request it is being asked to approve.
///
/// Everything borrows: the resolver is called inside the request path and nothing here outlives
/// it. The request has already passed RFC 6749 s4.1.1 validation, so `client_id`, `redirect_uri`
/// and `scope` are the VALIDATED values (the redirect URI is a registered one, the scope is
/// inside the client's registration), not raw query text.
pub struct ConsentRequest<'a> {
    /// The request's headers, so the host can find its own session.
    pub headers: &'a HeaderMap,
    /// The authenticated resource owner, as named by the subject resolver.
    pub subject: &'a str,
    /// The client asking.
    pub client_id: &'a ClientId,
    /// The scope that will be granted if this is approved.
    pub scope: &'a ScopeSet,
    /// The registered redirect URI this request resolved to.
    pub redirect_uri: &'a str,
    /// The client's `state`, if it sent one.
    pub state: Option<&'a str>,
    /// The full request URI, so a host that renders a consent screen can round-trip the user
    /// back to exactly this request after they answer.
    pub uri: &'a Uri,
    /// What this user has already granted this client, if anything.
    ///
    /// This is the library REPORTING and the host DECIDING, and that split is the whole design.
    /// [`crate::consent::ConsentRecord::covers`] answers whether the remembered grant already
    /// covers what is being asked for now; whether that is a good enough reason to skip the prompt
    /// depends on how long ago it was, what the scope means in this deployment, and whether the
    /// user is on a device the host trusts, none of which this crate knows. So it is handed over,
    /// and nothing here ever approves on the strength of it.
    #[cfg(feature = "consent")]
    pub remembered: Option<&'a crate::consent::ConsentRecord>,
}

/// How the host makes the RFC 6749 s10.12 consent decision. See
/// [`ServiceBuilder::with_consent_resolver`].
pub type ConsentResolver = Arc<dyn Fn(&ConsentRequest<'_>) -> ConsentDecision + Send + Sync>;

/// How the host answers "when, and how, did you authenticate this user".
///
/// The third identity seam, and the one RFC 9470 needs: a subject resolver answers WHO, a consent
/// resolver answers WHETHER THEY AGREED, and this answers HOW STRONGLY AND HOW RECENTLY. `None`
/// means the host is not reporting one, which satisfies no `acr_values` and no `max_age`; see
/// [`ServiceBuilder::with_authentication_reporter`].
#[cfg(feature = "consent")]
pub type AuthenticationReporter =
    Arc<dyn Fn(&HeaderMap) -> Option<crate::consent::Authentication> + Send + Sync>;

/// How the device verification form is protected against RFC 6749 s10.12 cross-site forced
/// approval.
enum VerificationProtection {
    /// No seam wired. Every interactive path refuses; see [`ServiceBuilder::with_csrf_tokens`].
    Unwired,
    /// The host mints and takes back a session-bound token.
    Tokens {
        /// Mint a token for the form this GET is about to render.
        issue: CsrfTokenHook,
        /// Take back (and invalidate) the token this session was last issued.
        consume: CsrfTokenHook,
    },
    /// Explicitly disabled by the host. See
    /// [`ServiceBuilder::dangerously_disable_verification_protections`].
    Disabled,
}

/// Why a router could not be built. Every variant is a host configuration mistake that would
/// otherwise become a runtime 404 on an endpoint the metadata document promises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// An advertised endpoint is not under the issuer, so this router cannot serve it. The host
    /// is either fronting a separate service or has a typo; either way, silently not routing it
    /// would publish a promise nothing keeps.
    EndpointOutsideIssuer {
        /// The RFC 8414 member name.
        endpoint: &'static str,
        /// The URL as advertised.
        url: String,
    },
    /// Two endpoints resolved to the same path, so one would shadow the other.
    DuplicatePath {
        /// The path claimed twice.
        path: String,
    },
    /// The metadata document could not be serialized. Structurally impossible for the derived
    /// document, but reported rather than panicked: a library does not abort a host's process.
    MetadataNotSerializable {
        /// The serializer's message.
        detail: String,
    },
    /// The RFC 7517 key set could not be serialized. As structurally impossible as the metadata
    /// case, and reported for the same reason.
    #[cfg(feature = "jwt")]
    JwksNotSerializable {
        /// The serializer's message.
        detail: String,
    },
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::EndpointOutsideIssuer { endpoint, url } => write!(
                f,
                "advertised {endpoint} ({url}) is not under the issuer, so this router cannot \
                 serve it"
            ),
            ServiceError::DuplicatePath { path } => {
                write!(f, "two endpoints resolve to the same path {path}")
            }
            ServiceError::MetadataNotSerializable { detail } => {
                write!(f, "RFC 8414 metadata could not be serialized: {detail}")
            }
            #[cfg(feature = "jwt")]
            ServiceError::JwksNotSerializable { detail } => {
                write!(f, "RFC 7517 key set could not be serialized: {detail}")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

/// Everything a handler needs, built once and shared by refcount.
struct Inner<S: Storage, C: Clock> {
    server: Arc<AuthorizationServer<S, C>>,
    /// The RFC 8414 document, serialized at build time. Serving it is a refcount bump.
    metadata: Bytes,
    /// The RFC 7517 key set, serialized at build time, present exactly when the document
    /// advertises a `jwks_uri` this router serves. PUBLIC parameters only: the bytes come from
    /// [`AuthorizationServer::jwks`], which has no way to emit a private key parameter.
    #[cfg(feature = "jwt")]
    jwks: Option<Bytes>,
    /// The RFC 6749 s5.2 / RFC 7617 challenge, built at build time because the realm never
    /// changes and formatting it per request would be pure waste.
    challenge: HeaderValue,
    /// The issuer's `scheme://authority`, for the RFC 6749 s10.12 `Origin` check. Derived once,
    /// because comparing against a freshly parsed issuer on every POST is pure waste.
    origin: String,
    subject: Option<SubjectResolver>,
    consent: Option<ConsentResolver>,
    #[cfg(feature = "consent")]
    authentication: Option<AuthenticationReporter>,
    verification: VerificationProtection,
    /// The paths, derived from the metadata document when the service was built.
    routes: Routes,
}

impl<S: Storage, C: Clock> Inner<S, C> {
    /// The authenticated resource owner, if the host can name one.
    fn subject(&self, headers: &HeaderMap) -> Option<String> {
        self.subject.as_ref().and_then(|f| f(headers))
    }
}

/// Builds the router. Construct, attach the seams the interactive endpoints need, then
/// [`build`](ServiceBuilder::build).
///
/// # The interactive endpoints refuse until they are wired
///
/// [`with_subject_resolver`](ServiceBuilder::with_subject_resolver) alone is NOT enough to run an
/// authorization server safely, and this is the one thing to read in this file. It answers "who
/// is this user"; RFC 6749 s10.12 also demands "did the user knowingly agree". Wire
/// [`with_consent_resolver`](ServiceBuilder::with_consent_resolver) and
/// [`with_csrf_tokens`](ServiceBuilder::with_csrf_tokens) too, or the authorization endpoint and
/// the device verification form refuse rather than guessing that silence means yes.
pub struct ServiceBuilder<S: Storage, C: Clock> {
    server: Arc<AuthorizationServer<S, C>>,
    subject: Option<SubjectResolver>,
    consent: Option<ConsentResolver>,
    #[cfg(feature = "consent")]
    authentication: Option<AuthenticationReporter>,
    verification: VerificationProtection,
}

impl<S: Storage + 'static, C: Clock + 'static> ServiceBuilder<S, C> {
    /// Start from a running server. `Arc` rather than ownership so the host keeps its handle for
    /// administration (client registration, sweeping) while the router serves the same instance.
    pub fn new(server: Arc<AuthorizationServer<S, C>>) -> Self {
        ServiceBuilder {
            server,
            subject: None,
            consent: None,
            #[cfg(feature = "consent")]
            authentication: None,
            verification: VerificationProtection::Unwired,
        }
    }

    /// Supply the host's answer to "who is the logged-in user for this request".
    ///
    /// The authorization endpoint cannot mint a code without a resource owner, and the device
    /// verification page cannot approve a grant without one. This crate has no login UI and no
    /// session model by design, so without a resolver both endpoints refuse with 403 rather than
    /// inventing a user.
    ///
    /// This resolver is IDENTITY ONLY. It does not express consent; see
    /// [`with_consent_resolver`](ServiceBuilder::with_consent_resolver).
    pub fn with_subject_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&HeaderMap) -> Option<String> + Send + Sync + 'static,
    {
        self.subject = Some(Arc::new(resolver));
        self
    }

    /// Supply the host's answer to "has this user knowingly agreed to this exact request".
    ///
    /// RFC 6749 s10.12 requires the AS to "ensure that the malicious client cannot obtain
    /// authorization without the awareness and explicit consent of the resource owner". An
    /// authorization endpoint that mints a code as soon as it knows who the user is satisfies
    /// neither half: any cross-site top-level navigation makes a logged-in user's browser hand a
    /// registered client a code they never asked to issue. PKCE and exact redirect-URI matching
    /// bound WHO may redeem that code; they say nothing about whether it should have existed.
    ///
    /// With NO resolver the authorization endpoint refuses with 403 and issues nothing. That is
    /// deliberate and it is a behaviour change: a host that previously wired only
    /// [`with_subject_resolver`](ServiceBuilder::with_subject_resolver) was running an
    /// AUTO-APPROVING authorization server, and the fix is to say what the consent step is rather
    /// than to leave it implied.
    ///
    /// Return [`ConsentDecision::Respond`] to render a consent screen and finish the flow on a
    /// later request; return [`ConsentDecision::Approve`] only once the user has actually agreed.
    pub fn with_consent_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&ConsentRequest<'_>) -> ConsentDecision + Send + Sync + 'static,
    {
        self.consent = Some(Arc::new(resolver));
        self
    }

    /// Supply the host's answer to "when, and how, did you authenticate this user".
    ///
    /// REQUIRED for RFC 9470 step-up authentication and useless without it. A client answering a
    /// resource server's `insufficient_user_authentication` challenge repeats its authorization
    /// request with `acr_values` and/or `max_age`; this server enforces those against whatever the
    /// reporter returns, and a host with no reporter wired fails every such request. That is the
    /// correct answer rather than a bug: an authorization server that cannot say when the user
    /// logged in cannot honestly claim they logged in recently.
    ///
    /// Ordinary requests, which carry neither parameter, are unaffected whether this is wired or
    /// not.
    ///
    /// The report is taken at FACE VALUE. This crate cannot authenticate anyone and has nothing to
    /// check it against; see the [`crate::consent`] module docs.
    #[cfg(feature = "consent")]
    pub fn with_authentication_reporter<F>(mut self, reporter: F) -> Self
    where
        F: Fn(&HeaderMap) -> Option<crate::consent::Authentication> + Send + Sync + 'static,
    {
        self.authentication = Some(Arc::new(reporter));
        self
    }

    /// Supply the host's session-bound CSRF token for the device verification form.
    ///
    /// `issue` is called when the form is RENDERED: it mints a token, binds it to whatever
    /// session the request carries, and returns it to be embedded in the form. `consume` is
    /// called when the form is SUBMITTED: it returns the token that session was last issued AND
    /// invalidates it, which is what makes the token single use. The router compares the
    /// submitted token with the consumed one in constant time; a mismatch, or either hook
    /// answering `None`, is a refusal.
    ///
    /// Why this is a seam and not something the library does: approving a device grant binds a
    /// third party's grant to the logged-in user, so RFC 6749 s10.12's CSRF requirement applies
    /// with full force, and the countermeasure has to be bound to the SESSION. This crate has no
    /// session store and will not grow one. With no hooks the verification endpoint renders no
    /// form and approves nothing, because a form that works and is forgeable is worse than no
    /// form at all.
    pub fn with_csrf_tokens<I, V>(mut self, issue: I, consume: V) -> Self
    where
        I: Fn(&HeaderMap) -> Option<String> + Send + Sync + 'static,
        V: Fn(&HeaderMap) -> Option<String> + Send + Sync + 'static,
    {
        self.verification = VerificationProtection::Tokens {
            issue: Arc::new(issue),
            consume: Arc::new(consume),
        };
        self
    }

    /// Turn OFF the device verification form's CSRF token requirement, its `Origin` check, and
    /// its affirmative-action requirement.
    ///
    /// FOR NON-BROWSER TEST HARNESSES ONLY. On an endpoint a browser can reach this re-enables
    /// the complete RFC 6749 s10.12 cross-site forced-approval chain: an attacker starts a device
    /// grant for a client they control, gets any authenticated victim's browser to POST the
    /// `user_code`, and polls out an access token and a refresh token for the victim's account.
    /// That is account takeover, and it needs no interaction beyond loading a page.
    ///
    /// It exists because this crate's black-box conformance harness drives the verification
    /// endpoint with an HTTP client and no browser session, so it cannot hold a CSRF token. It is
    /// spelled this loudly so that it is greppable, and so that no production host reaches for it
    /// without having read what it does.
    pub fn dangerously_disable_verification_protections(mut self) -> Self {
        self.verification = VerificationProtection::Disabled;
        self
    }

    /// Derive the routes from the metadata document and build the service.
    ///
    /// # Errors
    ///
    /// [`ServiceError`] when the configuration advertises something this service cannot serve.
    pub fn build(self) -> Result<AuthorizationService<S, C>, ServiceError> {
        let config = self.server.config();
        let meta = AuthorizationServerMetadata::from_config(config);
        // `from_config` trims the issuer, and derives every default endpoint from that trimmed
        // form, so the prefix relation below holds for an unconfigured host by construction.
        let issuer = meta.issuer.clone();

        let authorize = endpoint_path(
            &issuer,
            "authorization_endpoint",
            &meta.authorization_endpoint,
        )?;
        let token = endpoint_path(&issuer, "token_endpoint", &meta.token_endpoint)?;
        let device = endpoint_path(
            &issuer,
            "device_authorization_endpoint",
            &meta.device_authorization_endpoint,
        )?;
        let introspect = match &meta.introspection_endpoint {
            Some(u) => Some(endpoint_path(&issuer, "introspection_endpoint", u)?),
            None => None,
        };
        let revoke = match &meta.revocation_endpoint {
            Some(u) => Some(endpoint_path(&issuer, "revocation_endpoint", u)?),
            None => None,
        };
        // RFC 7591 s3 / RFC 8414 s2. `from_config` advertises this exactly when the host enabled
        // dynamic registration, so an off-issuer value is an error for the same reason
        // introspection's is: these bytes are produced by this server and nothing else can produce
        // them. A host that never enabled registration routes nothing here at all, which is the
        // only way an endpoint that mints clients should ever come to exist.
        let register = match &meta.registration_endpoint {
            Some(u) => Some(endpoint_path(&issuer, "registration_endpoint", u)?),
            None => None,
        };
        // RFC 7592 s3 `registration_client_uri`: `{registration_endpoint}/{client_id}`, which is
        // exactly what `registration::register_dynamic_client` hands the client, so the URL it is
        // told to use is the URL this service answers on.
        //
        // Stored as the PREFIX (with the trailing slash) because that is what the matcher needs;
        // the pattern form below exists only so the collision check and its error message name
        // something a host can recognise in its own configuration.
        let manage_prefix = register
            .as_ref()
            .filter(|_| {
                config
                    .registration
                    .as_ref()
                    .is_some_and(|r| r.management_enabled)
            })
            .map(|p| format!("{p}/"));
        let manage = manage_prefix.as_ref().map(|p| format!("{p}{{client_id}}"));
        // The verification URI is NOT part of the RFC 8414 document (it is announced in each RFC
        // 8628 s3.2 response), and a host may legitimately host its device page on a different
        // origin entirely. So an off-issuer verification URI is not an error, it just means the
        // host serves that page itself.
        let verification =
            endpoint_path(&issuer, "verification_uri", &config.verification_uri).ok();

        // RFC 9126 s5 `pushed_authorization_request_endpoint`. `from_config` advertises it exactly
        // when the host set `ServerConfig::par`, and section 5 says its presence is sufficient for
        // a client to decide it may use PAR. So an advertised endpoint that is not routed is not a
        // convenience gap, it is the one lie a client had no way to check first: it would push its
        // whole request, including the PKCE challenge, at a 404 and have nowhere to fall back to.
        // Off-issuer is an error for the same reason introspection's is: these bytes are minted by
        // this server and nothing else can mint them.
        #[cfg(feature = "par")]
        let par = match &meta.pushed_authorization_request_endpoint {
            Some(u) => Some(endpoint_path(
                &issuer,
                "pushed_authorization_request_endpoint",
                u,
            )?),
            None => None,
        };

        // RFC 8414 s2 `jwks_uri`. `from_config` advertises it exactly when this server signs its
        // access tokens, so when it is present the key set is ours to serve and an off-issuer URL
        // is an error, exactly as it is for introspection and revocation. That is stricter than
        // `verification_uri` above on purpose: the device page is a host's own branded HTML, while
        // these bytes are produced by this server and nothing else can produce them.
        #[cfg(feature = "jwt")]
        let jwks_path = match &meta.jwks_uri {
            Some(url) => Some(endpoint_path(&issuer, "jwks_uri", url)?),
            None => None,
        };
        // Serialized ONCE here rather than per request: a key set changes only when the host
        // rebuilds the router, and a verifier may fetch this on every cold cache.
        #[cfg(feature = "jwt")]
        let jwks = match (&jwks_path, self.server.jwks()) {
            (Some(_), Some(keys)) => Some(Bytes::from(serde_json::to_vec(&keys).map_err(|e| {
                ServiceError::JwksNotSerializable {
                    detail: e.to_string(),
                }
            })?)),
            // Both sides read the same `access_token_format`, so a path without keys cannot
            // arise; if it somehow did, not routing is better than routing an empty key set that
            // a verifier would read as "this issuer has no keys".
            _ => None,
        };

        // RFC 8414 s3.1: the well-known string is inserted BETWEEN the host and the issuer's
        // path, so this route is NOT `{issuer path}/.well-known/...` and is not the bare
        // well-known path either once the issuer has a path. See `metadata::well_known_path`.
        let well_known = well_known_path(&issuer);

        let metadata = serde_json::to_vec(&meta)
            .map_err(|e| ServiceError::MetadataNotSerializable {
                detail: e.to_string(),
            })?
            .into();

        let mut paths: Vec<&str> = vec![&well_known, &authorize, &token, &device];
        paths.extend(introspect.as_deref());
        paths.extend(revoke.as_deref());
        paths.extend(verification.as_deref());
        paths.extend(register.as_deref());
        paths.extend(manage.as_deref());
        #[cfg(feature = "par")]
        paths.extend(par.as_deref());
        #[cfg(feature = "jwt")]
        paths.extend(jwks_path.as_deref());
        for i in 0..paths.len() {
            if paths[i + 1..].contains(&paths[i]) {
                return Err(ServiceError::DuplicatePath {
                    path: paths[i].to_string(),
                });
            }
        }

        let routes = Routes {
            well_known,
            authorize,
            token,
            device,
            introspect,
            revoke,
            verification,
            register,
            manage: manage_prefix,
            #[cfg(feature = "par")]
            par,
            #[cfg(feature = "jwt")]
            jwks: jwks_path,
        };

        Ok(AuthorizationService {
            inner: Arc::new(Inner {
                server: self.server,
                metadata,
                #[cfg(feature = "jwt")]
                jwks,
                // RFC 7617 s2: the realm is a quoted string. The issuer is a URL and so contains
                // no double quote or backslash, which is what would need escaping here.
                challenge: HeaderValue::from_str(&format!("Basic realm=\"{issuer}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("Basic realm=\"oauth\"")),
                origin: issuer_origin(&issuer).to_string(),
                subject: self.subject,
                consent: self.consent,
                #[cfg(feature = "consent")]
                authentication: self.authentication,
                verification: self.verification,
                routes,
            }),
        })
    }
}

/// The largest request body any endpoint this service serves will read.
///
/// 64 KiB, chosen against the largest legitimate body rather than picked round. The biggest is an
/// RFC 7591 s2 client metadata document (a registration with many redirect URIs and a `jwks`), and
/// after that an RFC 9126 push carrying an RFC 9101 signed request object; both are kilobytes, not
/// tens of them. Every other body is a form of a dozen short parameters.
///
/// Stated rather than inherited from the framework's default, because a cap this file did not
/// choose is a cap that can change under it, and this one is a security property: these endpoints
/// buffer the whole body before parsing, and they are reachable before the client is
/// authenticated, so the ceiling on "how much memory can an anonymous request make this server
/// hold" is set here.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The absolute request path an advertised URL occupies, measured from the ORIGIN's root.
///
/// Origin-rooted rather than issuer-relative because that is what a router matches against. For
/// an issuer with no path the two are the same string; for `https://as.example/tenant1` the
/// token endpoint is served at `/tenant1/token`, so a host can build one router per tenant and
/// merge them without any of them colliding.
fn endpoint_path(issuer: &str, endpoint: &'static str, url: &str) -> Result<String, ServiceError> {
    match url.strip_prefix(issuer) {
        Some(rest) if rest.starts_with('/') => {
            let prefix = crate::metadata::issuer_path(issuer);
            let mut path = String::with_capacity(prefix.len() + rest.len());
            path.push_str(prefix);
            path.push_str(rest);
            Ok(path)
        }
        _ => Err(ServiceError::EndpointOutsideIssuer {
            endpoint,
            url: url.to_string(),
        }),
    }
}

/// The issuer's `scheme://authority`, which is what an `Origin` header carries (RFC 6454 s6.1:
/// scheme, host, and port, with no path).
fn issuer_origin(issuer: &str) -> &str {
    let path = crate::metadata::issuer_path(issuer);
    match path.is_empty() {
        true => issuer.trim_end_matches('/'),
        false => issuer[..issuer.len() - path.len()].trim_end_matches('/'),
    }
}

// ---------------------------------------------------------------------------------------------
// The service, its route table, and its body reader
// ---------------------------------------------------------------------------------------------

/// The paths this service answers on, derived once by [`ServiceBuilder::build`].
///
/// Every field is an ORIGIN-ROOTED absolute path, and every optional one is `Some` exactly when
/// the RFC 8414 document advertises the corresponding endpoint. That equivalence is the point:
/// [`ServiceBuilder::build`] derives both from the same document, so "advertised" and "routed"
/// cannot drift apart, and it refuses to build when two of them land on one path.
#[derive(Debug)]
struct Routes {
    well_known: String,
    authorize: String,
    token: String,
    device: String,
    introspect: Option<String>,
    revoke: Option<String>,
    verification: Option<String>,
    register: Option<String>,
    /// RFC 7592 `{registration_endpoint}/{client_id}`, held as the prefix INCLUDING its trailing
    /// slash. The one dynamic segment this service has.
    manage: Option<String>,
    #[cfg(feature = "par")]
    par: Option<String>,
    #[cfg(feature = "jwt")]
    jwks: Option<String>,
}

/// Which endpoint a request path resolved to, plus anything captured out of the path.
enum Route<'a> {
    Metadata,
    Authorize,
    Token,
    Device,
    Introspect,
    Revoke,
    Verification,
    Register,
    /// RFC 7592: the `client_id` segment, still percent-encoded.
    Manage(&'a str),
    #[cfg(feature = "par")]
    Par,
    #[cfg(feature = "jwt")]
    Jwks,
}

impl Routes {
    /// Resolve a request path, or `None` for a 404.
    ///
    /// STATIC PATHS ARE TRIED FIRST, and that ordering is load bearing rather than incidental.
    /// The one dynamic route (RFC 7592 management, `{register}/{client_id}`) is a prefix match, so
    /// a host whose configuration puts some other endpoint underneath the registration endpoint
    /// would otherwise see that endpoint shadowed by a client id that can never exist. The
    /// duplicate-path check in [`ServiceBuilder::build`] compares literal strings and cannot see
    /// that case, so the matcher settles it the same way a trie-based router would: a literal
    /// segment beats a parameter.
    fn resolve<'a>(&self, path: &'a str) -> Option<Route<'a>> {
        // A linear walk over at most eleven short strings. A trie would be the right shape for a
        // table of hundreds; here it would be more code, more allocation at build time, and
        // slower, because the first comparison usually fails on its first byte.
        if path == self.well_known {
            return Some(Route::Metadata);
        }
        if path == self.authorize {
            return Some(Route::Authorize);
        }
        if path == self.token {
            return Some(Route::Token);
        }
        if path == self.device {
            return Some(Route::Device);
        }
        if self.introspect.as_deref() == Some(path) {
            return Some(Route::Introspect);
        }
        if self.revoke.as_deref() == Some(path) {
            return Some(Route::Revoke);
        }
        if self.verification.as_deref() == Some(path) {
            return Some(Route::Verification);
        }
        if self.register.as_deref() == Some(path) {
            return Some(Route::Register);
        }
        #[cfg(feature = "par")]
        if self.par.as_deref() == Some(path) {
            return Some(Route::Par);
        }
        #[cfg(feature = "jwt")]
        if self.jwks.as_deref() == Some(path) {
            return Some(Route::Jwks);
        }
        // ONE segment, and a non-empty one. A `client_id` containing a slash would have been
        // percent-encoded into the URL this server itself minted (RFC 7592 s3
        // `registration_client_uri`), so a raw slash here is a different path, not a client id.
        if let Some(prefix) = &self.manage {
            if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                if !rest.is_empty() && !rest.contains('/') {
                    return Some(Route::Manage(rest));
                }
            }
        }
        None
    }
}

/// The methods a route answers, for the RFC 9110 s15.5.6 `Allow` header a 405 must carry.
fn allowed(route: &Route<'_>) -> &'static str {
    match route {
        // HEAD is listed wherever GET is, because it is served: RFC 9110 s9.3.2 defines it as GET
        // with the body dropped, and a client (or a health check) that probes with HEAD must not
        // be told the endpoint does not accept it.
        Route::Metadata | Route::Authorize => "GET, HEAD",
        #[cfg(feature = "jwt")]
        Route::Jwks => "GET, HEAD",
        Route::Token | Route::Device | Route::Introspect | Route::Revoke | Route::Register => {
            "POST"
        }
        #[cfg(feature = "par")]
        Route::Par => "POST",
        Route::Verification => "GET, HEAD, POST",
        Route::Manage(_) => "GET, HEAD, PUT, DELETE",
    }
}

/// An RFC-shaped authorization server as an HTTP service.
///
/// Built by [`ServiceBuilder`]. Cheap to clone (one refcount bump) and safe to share, so a host
/// clones one per connection or per task without duplicating any of the state or re-serializing
/// anything.
///
/// # Mounting it
///
/// With the `axum` feature, `axum::Router::from(service)` is the whole wiring. Without it, call
/// [`handle`](AuthorizationService::handle) from whatever the host's own server hands it: it takes
/// an [`http::Request`] over any [`http_body::Body`] and answers with an
/// [`http::Response<Body>`](Response).
pub struct AuthorizationService<S: Storage, C: Clock> {
    inner: Arc<Inner<S, C>>,
}

// The route table and nothing else. Every field of `Inner` beyond it is either a host-supplied
// closure (which has no useful representation) or bytes already published on the wire, so the
// paths are the only part a host debugging a 404 wants to see. Hand written rather than derived
// for the same reason `Clone` is, and because a derive would print the whole metadata document.
impl<S: Storage, C: Clock> std::fmt::Debug for AuthorizationService<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationService")
            .field("routes", &self.inner.routes)
            .finish_non_exhaustive()
    }
}

// Hand written rather than derived: `#[derive(Clone)]` would demand `S: Clone` and `C: Clone`,
// which is a bound on the HOST's storage that nothing here needs, since the only field is an
// `Arc`.
impl<S: Storage, C: Clock> Clone for AuthorizationService<S, C> {
    fn clone(&self) -> Self {
        AuthorizationService {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: Storage, C: Clock> AuthorizationService<S, C> {
    /// Answer one request.
    ///
    /// Generic over the request body so that a host on any HTTP server can call it: `hyper`,
    /// `axum`, a test harness holding a `String`. The body is read whole, up to
    /// [`MAX_BODY_BYTES`], before it is parsed, which is what these endpoints require (client
    /// authentication for `client_secret_post` is IN the body, so nothing can be checked before
    /// it has all arrived).
    pub async fn handle<B>(&self, request: Request<B>) -> Response
    where
        B: http_body::Body,
    {
        let state = &*self.inner;
        let (parts, body) = request.into_parts();
        let method = parts.method;
        let headers = parts.headers;
        let uri = parts.uri;

        let route = match state.routes.resolve(uri.path()) {
            Some(route) => route,
            None => return respond(StatusCode::NOT_FOUND, Body::empty()),
        };

        // RFC 9110 s9.3.2: HEAD is GET with the body suppressed. Handled here, once, rather than
        // in eleven handlers: the response is produced exactly as it would have been for GET
        // (headers included, `Content-Length` above all) and only the bytes are dropped.
        let head = method == Method::HEAD;
        let method = match head {
            true => Method::GET,
            false => method,
        };

        let response = self.dispatch(route, &method, headers, &uri, body).await;
        match head {
            true => response.map(|_| Body::empty()),
            false => response,
        }
    }

    /// The method check and the body read, then the handler.
    async fn dispatch<B>(
        &self,
        route: Route<'_>,
        method: &Method,
        headers: HeaderMap,
        uri: &Uri,
        body: B,
    ) -> Response
    where
        B: http_body::Body,
    {
        let state = &*self.inner;
        // Read the body only where a body is read. A GET whose sender attached one is not this
        // service's problem, and buffering it would be a memory cost with no reader.
        macro_rules! form_body {
            () => {
                match collect_body(body, MAX_BODY_BYTES).await {
                    Ok(bytes) => bytes,
                    Err(e) => return body_error(e),
                }
            };
        }
        match (route, method.as_str()) {
            (Route::Metadata, "GET") => metadata_handler(state),
            #[cfg(feature = "jwt")]
            (Route::Jwks, "GET") => jwks_handler(state),
            (Route::Authorize, "GET") => authorize_handler(state, &headers, uri).await,
            (Route::Token, "POST") => token_handler(state, &headers, &form_body!()).await,
            (Route::Device, "POST") => {
                device_authorization_handler(state, &headers, &form_body!()).await
            }
            (Route::Introspect, "POST") => introspect_handler(state, &headers, &form_body!()).await,
            (Route::Revoke, "POST") => revoke_handler(state, &headers, &form_body!()).await,
            #[cfg(feature = "par")]
            (Route::Par, "POST") => {
                pushed_authorization_handler(state, &headers, &form_body!()).await
            }
            (Route::Verification, "GET") => verification_page_handler(state, &headers, uri).await,
            (Route::Verification, "POST") => {
                verification_submit_handler(state, &headers, &form_body!()).await
            }
            (Route::Register, "POST") => register_handler(state, &headers, &form_body!()).await,
            // The captured segment is still percent-encoded, because that is what travelled in
            // the `registration_client_uri` this server minted (RFC 7592 s3) and a client id may
            // contain characters a path segment reserves.
            (Route::Manage(client_id), "GET") => {
                read_registration_handler(state, &headers, &decode_path_segment(client_id)).await
            }
            (Route::Manage(client_id), "PUT") => {
                let id = decode_path_segment(client_id).into_owned();
                update_registration_handler(state, &headers, &id, &form_body!()).await
            }
            (Route::Manage(client_id), "DELETE") => {
                delete_registration_handler(state, &headers, &decode_path_segment(client_id)).await
            }
            // RFC 9110 s15.5.6: a 405 MUST carry `Allow`. Without it a client cannot tell a
            // wrong method from a route that does not exist.
            (route, _) => {
                let mut resp = respond(StatusCode::METHOD_NOT_ALLOWED, Body::empty());
                resp.headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static(allowed(&route)));
                resp
            }
        }
    }
}

/// Why a request body could not be read.
enum BodyError {
    /// It exceeded [`MAX_BODY_BYTES`].
    TooLarge,
    /// The transport gave up: a truncated body, a broken connection, a bad chunk encoding.
    Incomplete,
}

/// The answer to a body that could not be read.
///
/// Not an RFC 6749 s5.2 error body, and deliberately not: section 5.2 describes what the server
/// says about a REQUEST it managed to parse, and neither of these got that far. A 413 and a 400
/// are what an HTTP client (and every proxy between it and here) already understands.
fn body_error(e: BodyError) -> Response {
    match e {
        BodyError::TooLarge => respond(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds this server's limit",
        ),
        BodyError::Incomplete => respond(StatusCode::BAD_REQUEST, "request body was not received"),
    }
}

/// Read a request body whole, refusing at `limit` bytes.
///
/// The cap is checked TWICE and both checks are needed. The size hint catches a declared
/// `Content-Length` before a single byte is buffered, which is what makes a hostile
/// `Content-Length: 4000000000` cost nothing; the running total catches a chunked body that
/// declares nothing and just keeps sending, which is the case the first check cannot see.
async fn collect_body<B>(body: B, limit: usize) -> Result<Bytes, BodyError>
where
    B: http_body::Body,
{
    let hint = body.size_hint();
    if hint.lower() > limit as u64 {
        return Err(BodyError::TooLarge);
    }
    // Sized from the hint when there is one, so the common case (a form body with a
    // `Content-Length`) allocates exactly once. Clamped to the limit so the hint cannot itself be
    // the allocation primitive.
    let expected = hint.upper().unwrap_or(hint.lower()).min(limit as u64) as usize;
    let mut collected: Vec<u8> = Vec::with_capacity(expected);

    // Pinned on the stack: `poll_frame` needs `Pin<&mut B>` and `B` is not required to be
    // `Unpin`, so boxing would be the only alternative and it would allocate on every request.
    let mut body = std::pin::pin!(body);
    loop {
        match std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            None => break,
            Some(Err(_)) => return Err(BodyError::Incomplete),
            Some(Ok(frame)) => {
                // Trailers carry no request content. `into_data` hands them back rather than
                // panicking, and they are dropped.
                if let Ok(mut data) = frame.into_data() {
                    if collected.len().saturating_add(data.remaining()) > limit {
                        return Err(BodyError::TooLarge);
                    }
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        collected.extend_from_slice(chunk);
                        let n = chunk.len();
                        data.advance(n);
                    }
                }
            }
        }
    }
    Ok(Bytes::from(collected))
}

// ---------------------------------------------------------------------------------------------
// The axum adapter, behind the `axum` cargo feature
// ---------------------------------------------------------------------------------------------

/// Mount the service on axum.
///
/// This is the ENTIRE axum surface of this crate, and it is one function on purpose. axum is a
/// 0.x crate: its major has moved before and will move again, and every earlier version of this
/// module put `axum::Router` in the return type of the only way to use the `http` feature, which
/// meant a host on a different axum major could not enable the feature at all. Confining axum to
/// an adapter behind its own feature makes that a per-host decision instead of this crate's.
///
/// A `fallback` rather than a route per endpoint: the route table is DERIVED from the metadata
/// document at build time (see [`Routes`]), so re-declaring it here in axum's syntax would create
/// a second table that could disagree with the first. A 404 from
/// [`AuthorizationService::handle`] is a path this server does not serve, which is exactly what a
/// fallback means.
#[cfg(feature = "axum")]
impl<S, C> From<AuthorizationService<S, C>> for axum::Router
where
    S: Storage + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    fn from(service: AuthorizationService<S, C>) -> axum::Router {
        axum::Router::new().fallback(move |request: axum::extract::Request| {
            let service = service.clone();
            async move {
                // `Body` is already a complete `Bytes`, so this is a move, not a copy or a
                // stream adapter.
                service
                    .handle(request)
                    .await
                    .map(|body| axum::body::Body::from(body.into_bytes()))
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------------------------

fn json_content_type() -> HeaderValue {
    // RFC 6749 s5.1: "application/json;charset=UTF-8".
    HeaderValue::from_static("application/json;charset=UTF-8")
}

/// RFC 7517 s8.5.1 registers `application/jwk-set+json` for a JWK Set, which is what this is; a
/// verifier that only checks for a JSON suffix still accepts it.
#[cfg(feature = "jwt")]
fn jwks_content_type() -> HeaderValue {
    HeaderValue::from_static("application/jwk-set+json")
}

fn html_content_type() -> HeaderValue {
    HeaderValue::from_static("text/html;charset=UTF-8")
}

/// Serialize a wire type. A serialization failure cannot happen for these shapes (they are plain
/// structs of strings and numbers), but a library must not panic inside a host's request path, so
/// the fallback is a valid RFC 6749 s5.2 body rather than an `unwrap`.
fn json_body<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_else(|_| br#"{"error":"server_error"}"#.to_vec())
}

/// Stamp the RFC 6749 s5.1 caching directives onto a token-plane response.
///
/// The bodies carry bearer credentials. A shared cache that stores one hands it to whoever asks
/// next, which is why the RFC makes this a MUST rather than advice. `Pragma: no-cache` is the
/// HTTP/1.0 belt to `no-store`'s braces, and the RFC names both.
fn no_store(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// A successful JSON response on the token plane.
fn ok_json<T: Serialize>(value: &T) -> Response {
    let mut resp = respond(StatusCode::OK, json_body(value));
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, json_content_type());
    no_store(headers);
    resp
}

/// An RFC 6749 s5.2 error response.
///
/// `via_header` records whether the client presented credentials in the `Authorization` header,
/// and it is the ONLY thing that decides between 400 and 401. Section 5.2 mandates 401 exactly
/// when header authentication was attempted and failed, and says the server MAY use 401
/// otherwise. It does not, because RFC 9110 s15.5.2 requires every 401 to carry a challenge, and
/// challenging a client that never offered header credentials tells it to retry a scheme it did
/// not choose. So header failures get 401 plus `WWW-Authenticate`, and everything else gets 400.
fn error_response(err: &ErrorResponse, via_header: bool, challenge: &HeaderValue) -> Response {
    let mut status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status == StatusCode::UNAUTHORIZED && !via_header {
        status = StatusCode::BAD_REQUEST;
    }
    let mut resp = respond(status, json_body(err));
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, json_content_type());
    no_store(headers);
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(header::WWW_AUTHENTICATE, challenge.clone());
    }
    resp
}

fn html_response(status: StatusCode, body: String) -> Response {
    let mut resp = respond(status, body);
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, html_content_type());
    resp
}

// ---------------------------------------------------------------------------------------------
// application/x-www-form-urlencoded, in both the body and the query string
// ---------------------------------------------------------------------------------------------

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode one `application/x-www-form-urlencoded` component.
///
/// Borrows when there is nothing to decode, which is the common case for `grant_type`, `code`,
/// and every opaque token this server issues (hex and base64url need no escaping). Only a value
/// that actually contains `%` or `+` costs an allocation.
fn decode_component(raw: &str) -> Cow<'_, str> {
    percent_decode(raw, true)
}

/// Decode ONE path segment: percent escapes only.
///
/// A `+` in a path segment is a literal plus (RFC 3986 s3.3 puts it in `sub-delims`); only
/// `application/x-www-form-urlencoded` gives it the "space" meaning. Decoding it as a space here
/// would rewrite the RFC 7592 s3 `registration_client_uri` this server itself minted, and a client
/// whose id contains a plus would find its own management URL pointing at a different client.
fn decode_path_segment(raw: &str) -> Cow<'_, str> {
    percent_decode(raw, false)
}

/// The shared decoder. Borrows when there is nothing to unescape, which is what keeps the common
/// case free.
fn percent_decode(raw: &str, plus_is_space: bool) -> Cow<'_, str> {
    if !raw
        .bytes()
        .any(|b| b == b'%' || (plus_is_space && b == b'+'))
    {
        return Cow::Borrowed(raw);
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match hex_pair(hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                    Some((h, l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    None => {
                        // A stray `%` is not an escape. Passing it through unchanged keeps the
                        // value intact for the comparison that will reject it anyway, rather
                        // than failing the whole request on a byte we do not need to understand.
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // Lossy on purpose: a form field that is not UTF-8 cannot match any registered client id,
    // token, or scope, so it will be refused a moment later on its merits. Rejecting the whole
    // request here would just replace a precise OAuth error with a vague one.
    Cow::Owned(match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

/// `Some((high, low))` only when both nibbles are hex.
fn hex_pair(a: Option<u8>, b: Option<u8>) -> Option<(u8, u8)> {
    match (a, b) {
        (Some(h), Some(l)) => Some((h, l)),
        _ => None,
    }
}

type Pair<'a> = (Cow<'a, str>, Cow<'a, str>);

/// Split a form body or query string into decoded pairs. A parameter with no `=` is kept with an
/// empty value, which is how a client spells "present but empty" and must not be mistaken for
/// absent.
/// Sized up front rather than grown. `Split` has no `size_hint`, so `collect` starts from nothing
/// and doubles: a six-parameter token body reallocates three times and memcpys 64 bytes per pair
/// each time. Counting the separators is one linear pass over bytes that are about to be walked
/// anyway, and it is an exact upper bound (empty segments are filtered out, so it can only
/// overshoot). This runs on EVERY routed request, which is what makes a free win worth taking.
fn parse_pairs(input: &str) -> Vec<Pair<'_>> {
    let bound = input.bytes().filter(|b| *b == b'&').count() + 1;
    let mut pairs = Vec::with_capacity(bound);
    pairs.extend(
        input
            .split('&')
            .filter(|part| !part.is_empty())
            .map(|part| match part.split_once('=') {
                Some((k, v)) => (decode_component(k), decode_component(v)),
                None => (decode_component(part), Cow::Borrowed("")),
            }),
    );
    pairs
}

/// The FIRST occurrence of a parameter.
///
/// RFC 6749 s3.1 says a parameter MUST NOT be sent more than once. First-wins rather than
/// last-wins is the deliberate choice: when two intermediaries disagree about which copy counts,
/// last-wins is the one that lets a smuggled duplicate override what the earlier layers saw.
fn param<'a>(pairs: &'a [Pair<'a>], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_ref())
}

/// A required parameter, or the RFC 6749 s5.2 `invalid_request` naming it.
fn required<'a>(pairs: &'a [Pair<'a>], name: &'static str) -> Result<&'a str, ErrorResponse> {
    param(pairs, name).ok_or_else(|| {
        ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description(format!("missing required parameter {name}"))
    })
}

/// Every `resource` parameter, in wire order (RFC 8707 s2 permits repetition, so this is the one
/// parameter [`param`]'s first-wins rule must not be applied to: dropping the second occurrence
/// would silently issue a token for half of what the client asked for).
fn resource_indicators(pairs: &[Pair<'_>]) -> Vec<String> {
    pairs
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.as_ref().to_string())
        .collect()
}

/// Parse an optional `scope` parameter. A malformed scope is `invalid_scope` (RFC 6749 s5.2)
/// rather than `invalid_request`: the parameter was supplied, it is its VALUE that is not a
/// scope.
fn optional_scope(pairs: &[Pair<'_>]) -> Result<Option<ScopeSet>, ErrorResponse> {
    match param(pairs, "scope") {
        None => Ok(None),
        Some(s) => ScopeSet::parse(s).map(Some).map_err(|_| {
            ErrorResponse::new(ErrorCode::InvalidScope)
                .with_description("scope is not a space-delimited RFC 6749 s3.3 token list")
        }),
    }
}

// ---------------------------------------------------------------------------------------------
// Client authentication (RFC 6749 s2.3)
// ---------------------------------------------------------------------------------------------

/// Authenticated (or merely identified) client credentials from one request.
///
/// DELIBERATELY NOT `Debug`, and not by omission. Every field but `client_id` is a live credential
/// decoded straight off the wire (a shared secret, or an RFC 7523 assertion that is a bearer
/// credential for as long as it is unexpired), and this value is in scope in five handlers. A
/// derived `Debug` would put all of it verbatim into a host's logs the first time somebody wrote
/// `tracing::debug!(?creds)`. A redacting `Debug` would make that line compile and print something
/// safe; no `Debug` at all makes it fail to compile, which is the stronger guarantee and costs
/// nothing, because nothing in this crate prints this type.
struct Credentials {
    client_id: String,
    /// `None` for a public client, which has no secret to present.
    client_secret: Option<String>,
    /// RFC 7521 s4.2 `client_assertion_type`, verbatim.
    #[cfg(feature = "client_assertion")]
    client_assertion_type: Option<String>,
    /// RFC 7523 `client_assertion`, verbatim.
    #[cfg(feature = "client_assertion")]
    client_assertion: Option<String>,
}

impl Credentials {
    /// The borrowed form the server takes. Borrowed rather than owned so that reading a credential
    /// off the wire costs the same as it did before these two parameters existed.
    fn credential(&self) -> crate::server::ClientCredential<'_> {
        crate::server::ClientCredential {
            client_secret: self.client_secret.as_deref(),
            #[cfg(feature = "client_assertion")]
            client_assertion_type: self.client_assertion_type.as_deref(),
            #[cfg(feature = "client_assertion")]
            client_assertion: self.client_assertion.as_deref(),
            // ALWAYS `None`, and it has to be. This router is handed a parsed request; it
            // does not terminate TLS and never sees the connection, so there is no
            // certificate here that anybody verified. RFC 8705 clients reach the server
            // through `ClientCredential::certificate` from a host that DID terminate the
            // connection. Reading one out of a proxy header here would be the exact
            // mistake `crate::mtls`'s trust boundary section warns about, and it would be
            // made on every deployment's behalf rather than on the one host that knows
            // whether its terminator can be trusted.
            #[cfg(feature = "mtls")]
            certificate: None,
        }
    }
}

/// Whether the request offered HTTP Basic credentials at all. Decided before any parsing, because
/// it is what selects 401-with-challenge over 400 even when the parsing then fails.
fn basic_attempted(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.len() >= 6 && v[..6].eq_ignore_ascii_case("basic "))
}

/// Decode `Authorization: Basic ...` into `(client_id, client_secret)`.
///
/// RFC 6749 s2.3.1 is specific and frequently got wrong: the client identifier and password are
/// each form-urlencoded FIRST, then joined with a colon and base64ed. A server that skips the
/// decode silently rejects every client whose secret contains a character the encoding escapes.
fn decode_basic(headers: &HeaderMap) -> Result<(String, String), ErrorResponse> {
    let malformed = || {
        ErrorResponse::new(ErrorCode::InvalidClient)
            .with_description("malformed HTTP Basic credentials (RFC 6749 s2.3.1)")
    };
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(malformed)?;
    let encoded = raw.get(6..).ok_or_else(malformed)?.trim();
    let decoded = BASE64_STANDARD.decode(encoded).map_err(|_| malformed())?;
    let text = String::from_utf8(decoded).map_err(|_| malformed())?;
    // Split on the FIRST colon: RFC 7617 says the userid cannot contain one, so any later colon
    // belongs to the password.
    let (id, secret) = text.split_once(':').ok_or_else(malformed)?;
    Ok((
        decode_component(id).into_owned(),
        decode_component(secret).into_owned(),
    ))
}

/// Resolve the client from the request, across all three methods this server advertises in
/// `token_endpoint_auth_methods_supported`.
///
/// RFC 6749 s2.3: "The client MUST NOT use more than one authentication method in each request."
/// Presenting Basic credentials AND body credentials is therefore refused outright rather than
/// silently resolved by precedence: a server that picks one is a server whose behaviour differs
/// from the next server's, and the ambiguity is exactly what a request-smuggling intermediary
/// would exploit.
fn credentials(headers: &HeaderMap, form: &[Pair<'_>]) -> Result<Credentials, ErrorResponse> {
    credentials_where(headers, form, false)
}

/// [`credentials`] for the RFC 9126 PAR endpoint, where a form `client_id` alongside header
/// credentials is NOT a second authentication method.
///
/// This is the one endpoint where the distinction bites. RFC 9126 s2.1 says the pushed body
/// carries the authorization request parameters of RFC 6749 s4.1.1, in which `client_id` is
/// REQUIRED, AND that the client authenticates as it does at the token endpoint. A client using
/// `client_secret_basic` therefore MUST send both, and this crate's token-endpoint rule (any
/// `client_id` in the body alongside Basic is two methods) would make PAR unusable for every
/// confidential client that authenticates with a header. The RFC settles it: there the parameter
/// is a REQUEST parameter that happens to name the same client, and it carries no credential, so
/// it cannot be a second authentication method.
///
/// Nothing is loosened about actual credentials: a `client_secret` or an assertion alongside Basic
/// is still two methods and still refused. And the pushed `client_id` is not trusted either, it is
/// checked against the AUTHENTICATED client inside
/// [`AuthorizationServer::pushed_authorization_request`], which is RFC 9126 s2.1's own rule and
/// what stops a client lodging a request under a victim's identity.
#[cfg(feature = "par")]
fn pushed_request_credentials(
    headers: &HeaderMap,
    form: &[Pair<'_>],
) -> Result<Credentials, ErrorResponse> {
    credentials_where(headers, form, true)
}

/// The shared body of the two above. `client_id_is_a_request_parameter` is the only difference.
fn credentials_where(
    headers: &HeaderMap,
    form: &[Pair<'_>],
    client_id_is_a_request_parameter: bool,
) -> Result<Credentials, ErrorResponse> {
    let basic = basic_attempted(headers);
    let body_id = param(form, "client_id");
    let body_secret = param(form, "client_secret");

    // RFC 7523 s2.2 / RFC 7521 s4.2. Handled BEFORE the three older methods, because an assertion
    // is a complete client authentication on its own and s2.2 makes `client_id` OPTIONAL alongside
    // it: the assertion already names the client, so requiring the parameter would refuse a
    // conforming client over a redundancy.
    #[cfg(feature = "client_assertion")]
    if let Some(assertion) = param(form, "client_assertion") {
        // RFC 6749 s2.3: one authentication method per request. Basic credentials or a
        // `client_secret` alongside an assertion is two, and a server that resolves the ambiguity
        // by precedence is a server whose behaviour differs from the next one's.
        if basic || body_secret.is_some() {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("more than one client authentication method (RFC 6749 s2.3)"));
        }
        // UNVERIFIED, and only used to LOCATE the registration. The registration then decides the
        // algorithm and the key, and `verify_assertion` re-checks `iss`/`sub` against the client id
        // resolved here, so nothing is trusted on the strength of this read. A form `client_id`
        // wins when present, because that is the value the client explicitly asserted.
        let client_id = match body_id {
            Some(id) => id.to_string(),
            None => crate::client_assertion::unverified_subject(assertion)
                .ok_or_else(|| {
                    ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("the client assertion names no client")
                })?
                .to_string(),
        };
        return Ok(Credentials {
            client_id,
            client_secret: None,
            client_assertion_type: param(form, "client_assertion_type").map(str::to_string),
            client_assertion: Some(assertion.to_string()),
        });
    }

    match (basic, body_id, body_secret) {
        // Header credentials, and no credential in the body. The `client_id` that may sit
        // alongside them is IGNORED for authentication: whether it may be there at all was decided
        // by the caller, and where it may, the endpoint checks it against the authenticated client
        // itself rather than letting it select one.
        (true, None, None) | (true, Some(_), None) if client_id_is_a_request_parameter => {
            let (client_id, client_secret) = decode_basic(headers)?;
            Ok(Credentials {
                client_id,
                client_secret: Some(client_secret),
                #[cfg(feature = "client_assertion")]
                client_assertion_type: None,
                #[cfg(feature = "client_assertion")]
                client_assertion: None,
            })
        }
        (true, None, None) => {
            let (client_id, client_secret) = decode_basic(headers)?;
            Ok(Credentials {
                client_id,
                client_secret: Some(client_secret),
                #[cfg(feature = "client_assertion")]
                client_assertion_type: None,
                #[cfg(feature = "client_assertion")]
                client_assertion: None,
            })
        }
        (true, _, _) => Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("more than one client authentication method (RFC 6749 s2.3)")),
        // `client_secret_post`, and the bare `client_id` a public client sends (RFC 6749 s3.2.1:
        // a client that is not authenticating still identifies itself).
        (false, Some(id), secret) => Ok(Credentials {
            client_id: id.to_string(),
            client_secret: secret.map(str::to_string),
            #[cfg(feature = "client_assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client_assertion")]
            client_assertion: None,
        }),
        // RFC 6749 s5.2 names this case explicitly under `invalid_client`: "no client
        // authentication included".
        (false, None, _) => Err(ErrorResponse::new(ErrorCode::InvalidClient)
            .with_description("no client authentication or client_id")),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// RFC 8414 s3.1. Served from the bytes produced when the router was built.
fn metadata_handler<S: Storage, C: Clock>(state: &Inner<S, C>) -> Response {
    let mut resp = respond(StatusCode::OK, state.metadata.clone());
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, json_content_type());
    resp
}

/// RFC 7517 s5: the JWK Set a resource server fetches to verify the RFC 9068 access tokens this
/// server signs. Served from the bytes produced when the router was built.
///
/// PUBLIC key parameters only, and no `Cache-Control: no-store`: unlike the token plane this body
/// carries no credential, and a key set that may not be cached would be re-fetched by every
/// verifier on every token, which is how rotation-capable deployments fall over.
#[cfg(feature = "jwt")]
fn jwks_handler<S: Storage, C: Clock>(state: &Inner<S, C>) -> Response {
    match &state.jwks {
        Some(bytes) => {
            let mut resp = respond(StatusCode::OK, bytes.clone());
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, jwks_content_type());
            resp
        }
        // Unreachable: `build` routes this path only when it has the bytes.
        None => respond(StatusCode::NOT_FOUND, Body::empty()),
    }
}

/// RFC 6749 s3.2, plus RFC 8628 s3.4 for the device grant.
async fn token_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let via_header = basic_attempted(headers);
    let text = String::from_utf8_lossy(body);
    let form = parse_pairs(&text);

    // grant_type is resolved BEFORE client authentication so that a request naming a grant this
    // server does not implement gets `unsupported_grant_type` rather than a client-auth error
    // about a parameter it never reached.
    let grant = match param(&form, "grant_type") {
        None => {
            return error_response(
                &ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("missing required parameter grant_type"),
                via_header,
                &state.challenge,
            )
        }
        Some(value) => match value.parse::<GrantType>() {
            Ok(g) => g,
            // The value is NOT echoed. RFC 6749 s5.2 restricts error_description to a charset
            // that excludes the double quote and backslash, and an attacker controls this string;
            // saying which grant was asked for is not worth having to sanitize it.
            Err(_) => {
                return error_response(
                    &ErrorResponse::new(ErrorCode::UnsupportedGrantType)
                        .with_description("this server does not implement the requested grant"),
                    via_header,
                    &state.challenge,
                )
            }
        },
    };

    let mut creds = match credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // TAKEN, not cloned. `creds` has to outlive this because `creds.credential()` borrows the
    // secret fields below, but nothing reads `client_id` off it again, so moving the String out
    // and leaving an empty one behind saves an allocation on every request to this endpoint.
    let client_id = ClientId::new(std::mem::take(&mut creds.client_id));
    // NOT moved onto the TokenRequest variant any more: every credential this endpoint accepts now
    // travels together on the request CONTEXT, so there is one place a reader has to look to see
    // what the client presented, rather than one for secrets and another for everything else.
    let client_secret: Option<String> = None;

    let request = match grant {
        GrantType::AuthorizationCode => {
            let code = match required(&form, "code") {
                Ok(v) => v.to_string(),
                Err(e) => return error_response(&e, via_header, &state.challenge),
            };
            TokenRequest::AuthorizationCode {
                client_id,
                client_secret,
                code,
                redirect_uri: param(&form, "redirect_uri").map(str::to_string),
                code_verifier: param(&form, "code_verifier").map(str::to_string),
            }
        }
        GrantType::ClientCredentials => {
            let scope = match optional_scope(&form) {
                Ok(s) => s,
                Err(e) => return error_response(&e, via_header, &state.challenge),
            };
            TokenRequest::ClientCredentials {
                client_id,
                client_secret,
                scope,
            }
        }
        GrantType::DeviceCode => {
            let device_code = match required(&form, "device_code") {
                Ok(v) => v.to_string(),
                Err(e) => return error_response(&e, via_header, &state.challenge),
            };
            TokenRequest::DeviceCode {
                client_id,
                client_secret,
                device_code,
            }
        }
        GrantType::RefreshToken => {
            let refresh_token = match required(&form, "refresh_token") {
                Ok(v) => v.to_string(),
                Err(e) => return error_response(&e, via_header, &state.challenge),
            };
            let scope = match optional_scope(&form) {
                Ok(s) => s,
                Err(e) => return error_response(&e, via_header, &state.challenge),
            };
            TokenRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token,
                scope,
            }
        }
        // RFC 8693 s2 shares the token endpoint with the RFC 6749 grants but NOT their
        // response body (s2.2.1 adds a REQUIRED member), so it answers from here rather
        // than producing a `TokenRequest`. Serving it matters beyond convenience: the RFC
        // 8414 document advertises the grant when this feature is on, and an advertised
        // grant this router refused would be exactly the lie that document exists to
        // avoid.
        #[cfg(feature = "token-exchange")]
        GrantType::TokenExchange => {
            return token_exchange_response(&state, &form, client_id, client_secret, via_header)
                .await
        }
    };

    // RFC 8707 s2: `resource` is a parameter of the token request itself, independent of
    // `grant_type`, so it is collected once here rather than inside each arm above.
    let resources = resource_indicators(&form);

    // RFC 9449 s4.3 (1): there must be exactly ONE `DPoP` header. Several is not a request this
    // server may pick a favourite from: an intermediary that appended one, or a client that sent
    // two, leaves it ambiguous which proof the client meant to bind the token to.
    #[cfg(feature = "dpop")]
    let dpop_proof = {
        let mut values = headers.get_all(crate::dpop::DPOP_HEADER).iter();
        let first = values.next();
        if values.next().is_some() {
            return error_response(
                &ErrorResponse::new(ErrorCode::InvalidDpopProof)
                    .with_description("more than one DPoP header (RFC 9449 s4.3)"),
                via_header,
                &state.challenge,
            );
        }
        match first.map(|v| v.to_str()) {
            None => None,
            Some(Ok(value)) => Some(value),
            // A header that is not visible ASCII cannot be a compact JWS, so this is a malformed
            // proof rather than an absent one, and answering "absent" would silently downgrade a
            // client that asked for a bound token to a bearer one.
            Some(Err(_)) => {
                return error_response(
                    &ErrorResponse::new(ErrorCode::InvalidDpopProof)
                        .with_description("the DPoP header is not a compact JWS"),
                    via_header,
                    &state.challenge,
                )
            }
        }
    };

    let context = crate::server::TokenRequestContext {
        credential: creds.credential(),
        resources: &resources,
        // RFC 9396 s2 makes this ONE JSON array, so `param`'s first-wins rule is the right
        // one here and a duplicate is a smuggled parameter rather than a second value.
        // That is the opposite of `resource`, which s2 of RFC 8707 explicitly allows to
        // repeat, and the difference is why the two are read differently.
        #[cfg(feature = "rar")]
        authorization_details: param(&form, "authorization_details"),
        #[cfg(feature = "dpop")]
        dpop_proof,
    };
    match state.server.token_with_context(request, context).await {
        Ok(response) => ok_json(&response),
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}

/// RFC 8693 s2: the token exchange grant.
///
/// The router serves the WIRE response only. A host that needs to know whether the exchange
/// was delegation or impersonation (s1.1), or that needs the s4.1 `act` claim to put into a
/// token of its own, calls [`crate::token_exchange::TokenExchange::exchange_token`] directly:
/// neither is a response parameter RFC 8693 defines, so neither belongs in this body.
#[cfg(feature = "token-exchange")]
async fn token_exchange_response<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    form: &[Pair<'_>],
    client_id: ClientId,
    client_secret: Option<String>,
    via_header: bool,
) -> Response {
    fn token_type(
        name: &'static str,
        value: &str,
    ) -> Result<crate::token_exchange::TokenTypeIdentifier, ErrorResponse> {
        // The VALUE is not echoed, for the reason `grant_type` is not echoed above: RFC
        // 6749 s5.2 restricts error_description to a charset an attacker-supplied URN need
        // not respect, and naming the parameter is enough for the developer who sent it.
        value.parse().map_err(|_| {
            ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description(format!("{name} is not a token type RFC 8693 s3 registers"))
        })
    }

    let subject_token = match required(form, "subject_token") {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let subject_token_type = match required(form, "subject_token_type")
        .and_then(|v| token_type("subject_token_type", v))
    {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let actor_token = param(form, "actor_token");
    let actor_token_type = match param(form, "actor_token_type")
        .map(|v| token_type("actor_token_type", v))
        .transpose()
    {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let requested_token_type = match param(form, "requested_token_type")
        .map(|v| token_type("requested_token_type", v))
        .transpose()
    {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let scope = match optional_scope(form) {
        Ok(s) => s,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // Both target parameters may repeat (RFC 8693 s2.1, RFC 8707 s2), so neither may go
    // through `param`'s first-wins rule: dropping the second occurrence would silently
    // narrow the request to half of what the client asked for.
    let resource = resource_indicators(form);
    let audience: Vec<String> = form
        .iter()
        .filter(|(k, _)| k == "audience")
        .map(|(_, v)| v.as_ref().to_string())
        .collect();

    let request = crate::token_exchange::TokenExchangeRequest {
        client_id: &client_id,
        client_secret: client_secret.as_deref(),
        subject_token,
        subject_token_type,
        actor_token,
        actor_token_type,
        resource: &resource,
        audience: &audience,
        scope: scope.as_ref(),
        requested_token_type,
    };
    match crate::token_exchange::TokenExchange::exchange_token(&*state.server, &request).await {
        Ok(exchanged) => ok_json(&exchanged.response),
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}

/// RFC 8628 s3.1: the device authorization request.
async fn device_authorization_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let via_header = basic_attempted(headers);
    let text = String::from_utf8_lossy(body);
    let form = parse_pairs(&text);

    let mut creds = match credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // TAKEN rather than cloned, for the reason the token endpoint gives: `creds` must
    // outlive this call because `creds.credential()` borrows out of it, but its
    // `client_id` is never read again.
    let client_id = ClientId::new(std::mem::take(&mut creds.client_id));
    let scope = match optional_scope(&form) {
        Ok(s) => s,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    match state
        .server
        .device_authorization_with_credential(&client_id, &creds.credential(), scope.as_ref())
        .await
    {
        Ok(response) => ok_json(&response),
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}

/// RFC 9126 s2: the pushed authorization request endpoint.
///
/// It is on the TOKEN plane, not the authorization plane, and everything about this handler
/// follows from that: the client authenticates here exactly as it does at the token endpoint
/// (s2.1 step 1), so client authentication is resolved by the same [`credentials`] function and a
/// failure gets the same RFC 6749 s5.2 shape with the same 401-versus-400 rule; and the response
/// carries a capability handle, so it gets the same s5.1 caching directives. The one thing that
/// differs is the success status, which s2.2 states rather than suggests: 201, not 200.
#[cfg(feature = "par")]
async fn pushed_authorization_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let via_header = basic_attempted(headers);
    let text = String::from_utf8_lossy(body);
    let form = parse_pairs(&text);

    let mut creds = match pushed_request_credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // TAKEN rather than cloned, for the reason the token endpoint gives: `creds` must
    // outlive this call because `creds.credential()` borrows out of it, but its
    // `client_id` is never read again.
    let client_id = ClientId::new(std::mem::take(&mut creds.client_id));
    // The form EXACTLY as it arrived, with nothing filtered out. RFC 9126 s2.1 step 2 REFUSES a
    // pushed `request_uri` and s3 treats a `request` as a signed request object, and both of those
    // are decisions for the server: a router that quietly dropped either parameter would turn a
    // refusal the RFC requires into a silent acceptance of a different request. Borrowed out of
    // the parsed form, so passing it costs no allocation per parameter.
    let parameters: Vec<(&str, &str)> =
        form.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect();
    match state
        .server
        .pushed_authorization_request_with_credential(&client_id, &creds.credential(), &parameters)
        .await
    {
        Ok(response) => {
            // s2.2: "with a 201 HTTP status code". Taken from the response type rather than
            // written here twice, so the wire status and the type's own answer cannot drift.
            let status =
                StatusCode::from_u16(response.http_status()).unwrap_or(StatusCode::CREATED);
            let mut resp = respond(status, json_body(&response));
            let h = resp.headers_mut();
            h.insert(header::CONTENT_TYPE, json_content_type());
            no_store(h);
            resp
        }
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}

/// RFC 7662 s2.1: token introspection, for a caller that authenticates as a client.
async fn introspect_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let via_header = basic_attempted(headers);
    let text = String::from_utf8_lossy(body);
    let form = parse_pairs(&text);

    let mut creds = match credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // TAKEN rather than cloned, for the reason the token endpoint gives: `creds` must
    // outlive this call because `creds.credential()` borrows out of it, but its
    // `client_id` is never read again.
    let client_id = ClientId::new(std::mem::take(&mut creds.client_id));
    let token = match required(&form, "token") {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    match state
        .server
        .introspection_response_with_credential(&client_id, &creds.credential(), token)
        .await
    {
        Ok(response) => ok_json(&response),
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}

/// RFC 7009 s2.1: token revocation. Success is a 200 with an empty body (s2.2).
async fn revoke_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let via_header = basic_attempted(headers);
    let text = String::from_utf8_lossy(body);
    let form = parse_pairs(&text);

    let mut creds = match credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // TAKEN rather than cloned, for the reason the token endpoint gives: `creds` must
    // outlive this call because `creds.credential()` borrows out of it, but its
    // `client_id` is never read again.
    let client_id = ClientId::new(std::mem::take(&mut creds.client_id));
    let token = match required(&form, "token") {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    // An unrecognised hint is IGNORED rather than refused. RFC 7009 s2.1 requires the server to
    // keep looking when the hint is wrong, and s2.2.1's `unsupported_token_type` is for a token
    // type the server cannot revoke at all; this server revokes both types it issues, so there is
    // nothing here it is unable to do.
    let hint = param(&form, "token_type_hint").and_then(|h| h.parse::<TokenTypeHint>().ok());

    match state
        .server
        .revoke(&client_id, creds.client_secret.as_deref(), token, hint)
        .await
    {
        Ok(()) => {
            let mut resp = respond(StatusCode::OK, Body::empty());
            no_store(resp.headers_mut());
            resp
        }
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}

// ---------------------------------------------------------------------------------------------
// RFC 7591 registration and RFC 7592 management
// ---------------------------------------------------------------------------------------------

/// The RFC 6750 s2.1 bearer token from the `Authorization` header, if the request carried one.
///
/// Used for BOTH credentials this pair of RFCs defines: the RFC 7591 s1.2 initial access token and
/// the RFC 7592 s2 registration access token. Both are access tokens presented the same way, so
/// there is one parser rather than two that could disagree.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    // Case-insensitive scheme (RFC 9110 s11.1), then the token68 with its surrounding space
    // trimmed. An empty remainder is `None`: a header that names the scheme and supplies nothing
    // presented no credential.
    if raw.len() < 7 || !raw[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = raw[7..].trim();
    (!token.is_empty()).then_some(token)
}

/// Turn an RFC 7591 s3.2.2 / RFC 7592 s2 refusal into a response.
///
/// A 401 carries an RFC 6750 s3 `Bearer` challenge rather than the `Basic` one the token plane
/// uses: this endpoint authenticates with a bearer token, and telling a client to retry with a
/// scheme it cannot use here would be worse than saying nothing. Only the `Invalid` case has a
/// body, because it is the only one with something a client can act on; a 401 that described what
/// was wrong with the token would be describing somebody else's credential.
fn registration_error(failure: &crate::registration::RegistrationFailure) -> Response {
    let status =
        StatusCode::from_u16(failure.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = match failure {
        crate::registration::RegistrationFailure::Invalid(body) => respond(status, json_body(body)),
        _ => respond(status, Body::empty()),
    };
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, json_content_type());
    no_store(headers);
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    resp
}

/// Parse an RFC 7591 s2 metadata document out of a request body.
///
/// A body that is not JSON at all is `invalid_client_metadata`: s3.2.2 has no code for "your body
/// was not JSON", and the client's problem is genuinely that the metadata it submitted is not
/// metadata this server can read.
///
/// The error half is BOXED. An `axum::Response` is a large value (a status, a header map and a
/// body), and the `Ok` half here is the common one, so an unboxed `Result` would make every
/// successful parse carry the error variant's footprint on the stack. That is what
/// `clippy::result_large_err` is pointing at, and boxing is the fix it asks for rather than a
/// lint to silence: the allocation happens only on the refusal path, which is the path that is
/// about to write a response to a socket anyway.
fn client_metadata(body: &Bytes) -> Result<crate::registration::ClientMetadata, Box<Response>> {
    serde_json::from_slice(body).map_err(|_| {
        Box::new(registration_error(
            &crate::registration::RegistrationFailure::Invalid(
                crate::registration::RegistrationErrorResponse::new(
                    crate::registration::RegistrationErrorCode::InvalidClientMetadata,
                    "the request body is not an RFC 7591 s2 client metadata JSON object",
                ),
            ),
        ))
    })
}

/// RFC 7591 s3.1: the client registration request. Success is a 201 (s3.2.1).
async fn register_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let metadata = match client_metadata(body) {
        Ok(m) => m,
        Err(response) => return *response,
    };
    match state
        .server
        .register_dynamic_client(&metadata, bearer_token(headers))
        .await
    {
        Ok(info) => {
            // s3.2.1: "201 Created", and the body carries a client secret and a registration
            // access token, so the s5.1 caching rules of RFC 6749 apply exactly as they do to a
            // token response.
            let mut resp = respond(StatusCode::CREATED, json_body(&info));
            let h = resp.headers_mut();
            h.insert(header::CONTENT_TYPE, json_content_type());
            no_store(h);
            resp
        }
        Err(e) => registration_error(&e),
    }
}

/// RFC 7592 s2.1: read a registration.
async fn read_registration_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    client_id: &str,
) -> Response {
    let token = bearer_token(headers).unwrap_or_default();
    match state
        .server
        .read_registration(&ClientId::new(client_id), token)
        .await
    {
        Ok(info) => ok_json(&info),
        Err(e) => registration_error(&e),
    }
}

/// RFC 7592 s2.2: replace a registration's metadata.
async fn update_registration_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    client_id: &str,
    body: &Bytes,
) -> Response {
    let metadata = match client_metadata(body) {
        Ok(m) => m,
        Err(response) => return *response,
    };
    let token = bearer_token(headers).unwrap_or_default();
    match state
        .server
        .update_registration(&ClientId::new(client_id), token, &metadata)
        .await
    {
        Ok(info) => ok_json(&info),
        Err(e) => registration_error(&e),
    }
}

/// RFC 7592 s2.3: delete a registration. Success is a 204 with no body.
async fn delete_registration_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    client_id: &str,
) -> Response {
    let token = bearer_token(headers).unwrap_or_default();
    match state
        .server
        .delete_registration(&ClientId::new(client_id), token)
        .await
    {
        Ok(()) => {
            let mut resp = respond(StatusCode::NO_CONTENT, Body::empty());
            no_store(resp.headers_mut());
            resp
        }
        Err(e) => registration_error(&e),
    }
}

/// Which of the ways an authorization request may arrive this one used, validated.
///
/// Three, and the two that are not query text exist because query text is the problem: it travels
/// through the browser, its history, its `Referer` headers and every proxy in front of it, and
/// anything able to rewrite the URL can change it before this server sees it.
///
/// - RFC 6749 s4.1.1, the parameters in the query.
/// - RFC 9126 s4, `client_id` plus a `request_uri` this server minted at its own PAR endpoint.
/// - RFC 9101 s5.1, `client_id` plus a signed `request` object.
///
/// For the latter two, EVERY other query parameter is ignored. That is not this function's choice
/// to make and it is not made here: RFC 9101 s6.3 (which RFC 9126 s4 builds on) requires the
/// server to use only the parameters carried by the reference or the object "even if the same
/// parameter is provided in the query parameter", and the two server methods enforce it by not
/// accepting any others, so there is no code path in which an appended `scope` could win.
///
/// With neither feature compiled in this is the plain query path and nothing else, which is what
/// the crate did before either feature existed.
async fn resolve_authorization_request<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    pairs: &[Pair<'_>],
) -> Result<crate::authorization::ValidatedAuthorizationRequest, AuthorizationError> {
    #[cfg(any(feature = "par", feature = "jar"))]
    {
        // A `request_uri` this server cannot resolve (the `par` feature is off) is an UNKNOWN
        // parameter, and RFC 6749 s3.1 says an unknown parameter is ignored. That is safe here
        // only because a server without PAR compiled in never minted one, so there is no handle
        // for the ignoring to downgrade.
        #[cfg(feature = "par")]
        let by_reference = param(pairs, "request_uri");
        #[cfg(not(feature = "par"))]
        let by_reference: Option<&str> = None;
        #[cfg(feature = "jar")]
        let by_value = param(pairs, "request");
        #[cfg(not(feature = "jar"))]
        let by_value: Option<&str> = None;

        // RFC 9101 s5: "The client MUST NOT send both". Refused rather than resolved by
        // precedence, for the reason RFC 6749 s2.3 gives about two client authentication methods:
        // a server that picks one behaves differently from the next server, and that difference is
        // what a smuggling intermediary exploits.
        if by_reference.is_some() && by_value.is_some() {
            return Err(AuthorizationError::Direct(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                    "request and request_uri must not both be sent (RFC 9101 s5)",
                ),
            ));
        }

        if by_reference.is_some() || by_value.is_some() {
            // RFC 9126 s4 and RFC 9101 s5 both make `client_id` REQUIRED alongside the handle or
            // the object, and it is load bearing rather than decorative: it selects the pushed
            // record whose binding is then checked (s2.2, and s7.5 is the swapping attack), or the
            // registered key the signature is verified with. Resolved once here rather than in a
            // closure per branch, because a closure whose `Ok` is a `&str` and whose `Err` is a
            // 128 byte `AuthorizationError` is exactly what `clippy::result_large_err` objects to.
            let client_id = match param(pairs, "client_id") {
                Some(id) => id,
                None => {
                    return Err(AuthorizationError::Direct(
                        ErrorResponse::new(ErrorCode::InvalidRequest)
                            .with_description("client_id is required (RFC 9126 s4, RFC 9101 s5)"),
                    ))
                }
            };

            #[cfg(feature = "par")]
            if let Some(request_uri) = by_reference {
                return state
                    .server
                    .validate_pushed_authorization_request(client_id, request_uri)
                    .await;
            }
            #[cfg(feature = "jar")]
            if let Some(request_object) = by_value {
                return state
                    .server
                    .validate_signed_authorization_request(client_id, request_object)
                    .await;
            }
        }
    }

    let request =
        AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (k.as_ref(), v.clone())));
    state.server.validate_authorization_request(&request).await
}

/// RFC 6749 s4.1.1: the authorization endpoint.
async fn authorize_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    uri: &Uri,
) -> Response {
    let pairs = parse_pairs(uri.query().unwrap_or_default());

    let validated = match resolve_authorization_request(&state, &pairs).await {
        Ok(v) => v,
        // RFC 6749 s4.1.2.1. `Direct` means the client or the redirect URI could not be
        // validated, so there is no address the server may safely send this to; it is rendered
        // to the user agent instead. `via_header` is false because the authorization endpoint has
        // no client authentication to challenge.
        Err(AuthorizationError::Direct(e)) => {
            return error_response(&e, false, &state.challenge);
        }
        Err(AuthorizationError::Redirect(r)) => return redirect(r.location()),
    };

    // The resource owner. Without one there is nobody whose consent a code could represent.
    let subject = match state.subject(&headers) {
        Some(s) => s,
        // Deliberately NOT an error redirect. `access_denied` at the client's redirect URI would
        // tell the client a user refused, when in truth no user was ever asked: this host has not
        // wired up authentication. A direct 403 says that without lying to the client.
        None => {
            return unwired(
                "no authenticated resource owner; the host must supply a subject resolver",
            )
        }
    };

    // RFC 6749 s10.12: knowing WHO the user is does not establish that they agreed. Without a
    // consent seam this endpoint would mint a code on any cross-site top-level navigation a
    // logged-in user's browser is made to follow, so an unwired host refuses. This is a direct
    // 403 for the same reason as the missing subject above: no user refused, none was asked.

    // What this user has already granted this client, handed to the resolver below. A storage
    // failure reads as "nothing remembered", which makes the host ask again: the failure mode of
    // this lookup has to be an extra prompt, never a skipped one.
    #[cfg(feature = "consent")]
    let remembered = state
        .server
        .remembered_consent(&validated.client_id, &subject)
        .await
        .unwrap_or(None);

    let consent = match &state.consent {
        Some(resolver) => resolver(&ConsentRequest {
            headers: &headers,
            subject: &subject,
            client_id: &validated.client_id,
            scope: &validated.scope,
            redirect_uri: &validated.redirect_uri,
            state: validated.state.as_deref(),
            uri: &uri,
            #[cfg(feature = "consent")]
            // Deref through the shared `Arc<ConsentRecord>` the storage seam now returns: the
            // resolver borrows for the length of the call and never needs the handle.
            remembered: remembered.as_deref(),
        }),
        None => {
            return unwired(
                "no consent step is configured; the host must supply a consent resolver \
                 (RFC 6749 s10.12)",
            )
        }
    };
    // Only ever set by the host's own `ApproveAndRemember`; see that variant's docs.
    #[cfg(feature = "consent")]
    let mut remember = false;
    match consent {
        ConsentDecision::Approve => {}
        #[cfg(feature = "consent")]
        ConsentDecision::ApproveAndRemember => remember = true,
        // A refusal is an answer the client is entitled to receive at its (validated) redirect
        // URI, which is exactly what RFC 6749 s4.1.2.1 `access_denied` is for.
        ConsentDecision::Deny => return redirect(validated.denied().location()),
        ConsentDecision::Respond(response) => return *response,
    }

    // The host's report of how and when it authenticated this user, for RFC 9470 s4's parameters to
    // be enforced against. An unwired host reports `None`, which satisfies no requirement.
    #[cfg(feature = "consent")]
    let authentication = state.authentication.as_ref().and_then(|f| f(&headers));
    // The requirement comes off the RESOLVED request, not off `pairs`. For a PAR or JAR request the
    // query holds only `client_id` plus the handle or the object, so reading `pairs` here dropped
    // `acr_values` and `max_age` entirely and silently disabled step-up for both (RFC 9126 s4, RFC
    // 9101 s6.3). A malformed `max_age` is now refused during validation, on the same redirect the
    // rest of the redirectable checks use.
    #[cfg(feature = "consent")]
    let issued = state
        .server
        .issue_authorization_code_with_authentication(
            &validated,
            subject.clone(),
            &validated.authentication_requirement,
            authentication.as_ref(),
        )
        .await;
    #[cfg(not(feature = "consent"))]
    let issued = state
        .server
        .issue_authorization_code(&validated, subject)
        .await;

    // AFTER issuance, and only on success: a consent records that the user granted something, and
    // nothing was granted if the code was refused.
    #[cfg(feature = "consent")]
    if remember && issued.is_ok() {
        // A failure to remember is not a failure to authorize. The user consented and the code is
        // already minted; turning that into an error would throw away an approval the user actually
        // gave, and the only consequence of the lost record is being asked again next time.
        let _ = state
            .server
            .record_consent(
                &validated.client_id,
                &subject,
                &validated.scope,
                &validated.resource,
                authentication,
            )
            .await;
    }

    match issued {
        Ok(response) => redirect(response.location(&validated.redirect_uri)),
        Err(AuthorizationError::Direct(e)) => error_response(&e, false, &state.challenge),
        Err(AuthorizationError::Redirect(r)) => redirect(r.location()),
    }
}

/// The authorization endpoint's answer when a seam the host had to wire is missing.
///
/// 403 with `access_denied` and a description naming the gap: the client learns the request was
/// not authorized, and the host's developer learns why without the server having invented a user
/// or a decision. Never a redirect, for the reason above.
fn unwired(why: &'static str) -> Response {
    let err = ErrorResponse::new(ErrorCode::AccessDenied).with_description(why);
    let mut resp = respond(StatusCode::FORBIDDEN, json_body(&err));
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, json_content_type());
    no_store(headers);
    resp
}

/// A 302 to `location`.
///
/// RFC 6749 s4.1.2 leaves the exact 3xx to the server; 302 is what the RFC's own examples show
/// and what every client understands. A non-ASCII location cannot be a header value, and the
/// only strings reaching here are percent-encoded by [`crate::authorization`], so the fallback is
/// unreachable rather than load-bearing.
fn redirect(location: String) -> Response {
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut resp = respond(StatusCode::FOUND, Body::empty());
            resp.headers_mut().insert(header::LOCATION, value);
            resp
        }
        Err(_) => error_response(
            &ErrorResponse::new(ErrorCode::ServerError),
            false,
            &HeaderValue::from_static("Basic realm=\"oauth\""),
        ),
    }
}

/// Constant-time equality, over SHA-256 digests so the loop bound does not depend on either
/// input's length.
///
/// A CSRF token is a secret the submitter is claiming to know, so comparing it with `==` leaks
/// the length of the match through timing exactly as a secret comparison would. This mirrors
/// `client::constant_time_eq`, which is private to that module; duplicating six lines is cheaper
/// than widening that function's visibility, and this one is exercised by its own test.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    let mut acc: u8 = 0;
    for i in 0..32 {
        acc |= da[i] ^ db[i];
    }
    acc == 0
}

/// Whether the request body is `application/x-www-form-urlencoded`.
///
/// Required on the verification POST as defence in depth for RFC 6749 s10.12: it is one of the
/// three content types a cross-origin form or a no-preflight `fetch` may send, but demanding it
/// still removes every JSON or text body that could otherwise be smuggled here, and it costs a
/// conforming browser form nothing because that is exactly what a form sends.
fn is_form_urlencoded(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        // Parameters are allowed (`; charset=utf-8`), so only the media type is compared.
        .map(|v| v.split(';').next().unwrap_or_default().trim())
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// Whether this POST demonstrably came from a document on the issuer's own origin.
///
/// RFC 6749 s10.12, RFC 9700 s4.7. A browser sends `Origin` on every POST and `Sec-Fetch-Site` on
/// every request it makes from a document, so a genuine submission of the form this server
/// rendered carries at least one of them and both say "us". A cross-site forced submission
/// carries the ATTACKER's origin, which is the whole signal. Absence is refused rather than
/// waved through: on a browser-facing endpoint absence means a client that is not a browser, and
/// a request that is not from a browser has no session cookie worth forging.
fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    // `Sec-Fetch-Site` is the more precise of the two where it exists, so it is decisive when
    // present: `same-origin` is a submission from our own page, and anything else (including
    // `none`, a user-typed navigation) is not.
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site.eq_ignore_ascii_case("same-origin");
    }
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(origin))
}

/// The pending grant behind an entered user code, plus the client's display name, for the
/// consent screen. `None` when nothing pending matches.
///
/// Read through the public storage seam rather than through a server method, and deliberately
/// NOT treated as authoritative: expiry and state are re-checked inside
/// `AuthorizationServer::approve_device` against the server's own clock when the user actually
/// approves. This lookup exists to DISPLAY, so being one moment stale costs nothing.
async fn pending_grant<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    entered_user_code: &str,
) -> Option<(DeviceGrant, Option<String>)> {
    // THIS LOOKUP IS A GUESSING ORACLE, so it goes through the host's throttle exactly as
    // AuthorizationServer::pending_grant_by_user_code does. The response distinguishes a live
    // pending code from an unknown one perfectly (one renders the client and the scope, the other
    // says the code was not recognised), so without this a host that implemented the RateLimiter
    // seam correctly would still see nothing while an attacker walked the code space with GETs and
    // spent a single throttled POST on the one that hit.
    //
    // RFC 8628 s5.1 makes the user code's entropy adequate only IN COMBINATION WITH rate limiting
    // of code entry, and s5.4 names this exact URL, the verification_uri_complete deep link, as
    // the higher-risk entry point.
    let hooks = state.server.hooks();
    if hooks.check(Attempt::DeviceUserCodeEntry) == RateLimitDecision::Deny {
        return None;
    }
    let normalized = normalize_user_code(entered_user_code);
    let grant = state
        .server
        .store()
        .find_device_grant_by_user_code(&normalized)
        .await
        .ok()
        .flatten()
        .filter(|g| g.state == DeviceGrantState::Pending);
    // Report the outcome, because a guessing attack shows up in FAILURES, not in traffic volume.
    hooks.record(
        Attempt::DeviceUserCodeEntry,
        if grant.is_some() {
            AttemptOutcome::Succeeded
        } else {
            AttemptOutcome::Failed
        },
    );
    let grant = grant?;
    let name = state
        .server
        .store()
        .get_client(&grant.client_id)
        .await
        .ok()
        .flatten()
        // Cloned out of the shared `Arc<Client>` (see `Storage::get_client`): this renders a human
        // facing verification page, so one string copy per page view is not a cost worth shaping
        // the storage seam around.
        .and_then(|c| c.name.clone());
    Some((grant, name))
}

/// Render the verification page for whatever `entered` resolves to, with a fresh CSRF token.
async fn render_verification<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    entered: &str,
    status: StatusCode,
    message: Option<&str>,
) -> Response {
    let csrf = match &state.verification {
        // RFC 6749 s10.12 is the AS's obligation, so an unwired host is served an explanation
        // and NO form. A form that works and is forgeable is worse than no form at all.
        VerificationProtection::Unwired => {
            return html_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                verification_message(
                    "This server is not configured to accept device approvals. The host must \
                     supply CSRF tokens (RFC 6749 s10.12).",
                ),
            )
        }
        VerificationProtection::Tokens { issue, .. } => match issue(headers) {
            Some(token) => Some(token),
            // No session means no token can be bound to one, so there is nothing to render.
            None => {
                return html_response(
                    StatusCode::FORBIDDEN,
                    verification_message("You are not signed in."),
                )
            }
        },
        VerificationProtection::Disabled => None,
    };

    let grant = match entered.is_empty() {
        true => None,
        false => pending_grant(state, entered).await,
    };
    // A code that was typed but matches nothing pending is worth saying so, rather than
    // rendering a consent screen with nothing on it.
    let message = match (message, entered.is_empty(), grant.is_some()) {
        (Some(m), _, _) => Some(m),
        (None, false, false) => Some("That code was not recognised."),
        _ => None,
    };
    html_response(
        status,
        verification_page(entered, message, grant.as_ref(), csrf.as_deref()),
    )
}

/// RFC 8628 s3.3: the page a user visits to enter the code shown on the device.
async fn verification_page_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    uri: &Uri,
) -> Response {
    // `verification_uri_complete` (RFC 8628 s3.3.1) carries the code in the query so the user
    // does not retype it; prefilling is the entire point of that member. Prefilling is ALL it
    // does: RFC 8628 s5.4 (Remote Phishing) is explicit that this deep link removes the one
    // friction point that made the attack harder, so what it lands on has to be a page naming
    // the client and the scope, with the approval still one deliberate click away.
    let pairs = parse_pairs(uri.query().unwrap_or_default());
    let prefill = param(&pairs, "user_code").unwrap_or_default();
    render_verification(&state, &headers, prefill, StatusCode::OK, None).await
}

/// The verification form's submission: the user has entered the code shown on their device.
async fn verification_submit_handler<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    // Checked before the body is even parsed, and before the unprotected escape hatch is
    // consulted, because it is the one guard that costs a conforming browser nothing.
    if !is_form_urlencoded(headers) {
        return html_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            verification_message("Expected an application/x-www-form-urlencoded submission."),
        );
    }

    let text = String::from_utf8_lossy(&body);
    let form = parse_pairs(&text);
    let user_code = param(&form, "user_code").unwrap_or_default();

    // RFC 6749 s10.12, defence in depth, in the order that refuses soonest. A host that has
    // explicitly disabled these is not browser-facing and is answering for that itself.
    let protected = !matches!(state.verification, VerificationProtection::Disabled);
    if protected {
        if !same_origin(&headers, &state.origin) {
            return html_response(
                StatusCode::FORBIDDEN,
                verification_message("That request did not come from this site."),
            );
        }
        let expected =
            match &state.verification {
                VerificationProtection::Tokens { consume, .. } => consume(&headers),
                // No CSRF seam: nothing to compare against, so nothing is approved. The GET above
                // already refused to render a form, so this is the direct-POST path.
                VerificationProtection::Unwired => return html_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    verification_message(
                        "This server is not configured to accept device approvals. The host must \
                         supply CSRF tokens (RFC 6749 s10.12).",
                    ),
                ),
                VerificationProtection::Disabled => None,
            };
        let presented = param(&form, "csrf_token").unwrap_or_default();
        // Constant time, and `expected` was consumed above, so a token works exactly once.
        let ok = expected.is_some_and(|e| constant_time_eq(&e, presented));
        if !ok {
            return html_response(
                StatusCode::FORBIDDEN,
                verification_message("That form has expired. Start again."),
            );
        }
    }

    if user_code.is_empty() {
        return render_verification(
            &state,
            &headers,
            "",
            StatusCode::BAD_REQUEST,
            Some("Enter the code shown on your device."),
        )
        .await;
    }

    // RFC 8628 s3.3 requires an explicit confirmation step, so approval needs an affirmative
    // action and nothing else does it. A submission with no action re-renders the consent screen
    // for the code just entered, which is the second stage of the two-stage form: type a code,
    // see what it is for, THEN decide. The escape hatch keeps the old approve-by-default shape,
    // because the non-browser harness that needs it posts a bare user_code.
    let action = param(&form, "action").unwrap_or_default();
    let denied = action == "deny";
    let approved = action == "approve" || !protected;
    if !denied && !approved {
        return render_verification(&state, &headers, user_code, StatusCode::OK, None).await;
    }

    // Approval binds the grant to a USER, so the same rule as the authorization endpoint applies:
    // without an authenticated resource owner there is nobody to bind it to.
    let subject = match state.subject(&headers) {
        Some(s) => s,
        None => {
            return html_response(
                StatusCode::FORBIDDEN,
                verification_message("You are not signed in."),
            )
        }
    };

    // RFC 8628 s3.3 leaves the deny path to the implementation; offering it matters, because a
    // user who did not start the flow needs a way to say so.
    let outcome = if denied {
        state.server.deny_device(user_code).await
    } else {
        state.server.approve_device(user_code, subject).await
    };

    match outcome {
        Ok(()) if denied => html_response(StatusCode::OK, verification_message("Request denied.")),
        Ok(()) => html_response(
            StatusCode::OK,
            verification_message("Approved. You can return to your device."),
        ),
        // These are NOT OAuth wire errors: RFC 8628 leaves the verification interaction to the
        // implementation, and the audience here is a human, not a client library.
        Err(e) => {
            let message = match e {
                DeviceApprovalError::UnknownUserCode => "That code was not recognised.",
                DeviceApprovalError::Expired => "That code has expired. Start again on the device.",
                DeviceApprovalError::NotPending => "That code has already been used.",
                DeviceApprovalError::Storage(_) => "Something went wrong. Try again.",
                // The host's own limiter refused this before the code was even looked up
                // (RFC 8628 section 5.1). Deliberately says nothing about whether the code was
                // real: that is the question the throttle exists to stop being asked.
                DeviceApprovalError::RateLimited => "Too many attempts. Wait and try again.",
            };
            let status = match e {
                DeviceApprovalError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
                // 429 is the honest status and the one a host's own reverse proxy metrics will
                // already be counting.
                DeviceApprovalError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::BAD_REQUEST,
            };
            // The CSRF token was consumed above, so this re-render mints a fresh one; without
            // that a mistyped code would leave the user with a form that can never be submitted.
            render_verification(&state, &headers, user_code, status, Some(message)).await
        }
    }
}

/// Escape the five characters that can break out of HTML text or an attribute value. The user
/// code is echoed back into the form, and it arrived from the network.
fn escape_html(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
}

const PAGE_HEAD: &str = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
     <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
     <title>Device authorization</title></head><body><h1>Device authorization</h1>";

/// The minimal verification form. Deliberately unstyled and dependency-free: a host that wants a
/// branded page serves its own route and calls [`AuthorizationServer::approve_device`] directly.
///
/// Two stages, and the second is not optional. With no pending grant behind the entered code the
/// page can only ask for the code, so its single button says CONTINUE and approves nothing. With
/// a grant it names the client and the exact scope being handed over, and only then offers
/// Approve and Deny. RFC 8628 s3.3: "the authorization server SHOULD display information about
/// the device"; s5.4 is why the deep link may not skip it.
///
/// Everything variable here is escaped. The user code came off the network, and a client name is
/// registration data, which under RFC 7591 dynamic client registration is chosen by whoever
/// registered the client.
fn verification_page(
    prefill: &str,
    message: Option<&str>,
    grant: Option<&(DeviceGrant, Option<String>)>,
    csrf: Option<&str>,
) -> String {
    let mut html = String::with_capacity(768);
    html.push_str(PAGE_HEAD);
    if let Some(message) = message {
        html.push_str("<p>");
        escape_html(message, &mut html);
        html.push_str("</p>");
    }
    html.push_str("<form method=\"post\">");
    if let Some(token) = csrf {
        html.push_str("<input type=\"hidden\" name=\"csrf_token\" value=\"");
        escape_html(token, &mut html);
        html.push_str("\">");
    }
    match grant {
        None => {
            html.push_str(
                "<label for=\"user_code\">Code shown on your device</label>\
                 <input id=\"user_code\" name=\"user_code\" autocomplete=\"off\" \
                 spellcheck=\"false\" value=\"",
            );
            escape_html(prefill, &mut html);
            html.push_str("\"><button type=\"submit\">Continue</button>");
        }
        Some((grant, name)) => {
            // The name is a display convenience; the client_id is the identity, so it is shown
            // either way. A pretty name is exactly what a phishing registration would choose.
            html.push_str("<p>The application <strong>");
            escape_html(
                name.as_deref().unwrap_or_else(|| grant.client_id.as_str()),
                &mut html,
            );
            html.push_str("</strong> (<code>");
            escape_html(grant.client_id.as_str(), &mut html);
            html.push_str("</code>) is asking to access your account.</p><p>It will be allowed: ");
            let scope = grant.scope.to_string();
            if scope.is_empty() {
                html.push_str("no scopes");
            } else {
                escape_html(&scope, &mut html);
            }
            html.push_str("</p><p>Code on your device: <code>");
            escape_html(&grant.user_code, &mut html);
            html.push_str("</code></p><input type=\"hidden\" name=\"user_code\" value=\"");
            escape_html(&grant.user_code, &mut html);
            html.push_str(
                "\"><button type=\"submit\" name=\"action\" value=\"approve\">Approve</button>\
                 <button type=\"submit\" name=\"action\" value=\"deny\">Deny</button>",
            );
        }
    }
    html.push_str("</form></body></html>");
    html
}

/// A page that is only a message: an outcome, or a refusal with no form to offer.
fn verification_message(message: &str) -> String {
    let mut html = String::with_capacity(256);
    html.push_str(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Device authorization</title></head><body><p>",
    );
    escape_html(message, &mut html);
    html.push_str("</p></body></html>");
    html
}

#[cfg(test)]
#[path = "tests/http.rs"]
mod tests;
