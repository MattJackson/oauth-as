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
//! collection with a cap), and those three are what `Routes::resolve` and `collect_body` now do
//! in this file.
//!
//! # What it serves
//!
//! Exactly the endpoints [`crate::metadata::AuthorizationServerMetadata`] advertises, at exactly the paths it
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
//! 2. CONSENT at the authorization endpoint ([`ServiceBuilder::with_approval_resolver`]). RFC 6749
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
//!
//! # What this service CANNOT do, and a host must not advertise through it
//!
//! RFC 8705 mutual-TLS client authentication. A build with the `mtls` feature advertises
//! `tls_client_auth` and `self_signed_tls_client_auth` in the RFC 8414 document's
//! `token_endpoint_auth_methods_supported`, and a client that reads them and authenticates that
//! way THROUGH THIS SERVICE is refused with `invalid_client`, every time. That is not an oversight: this module is handed an already-parsed request, it never
//! terminates TLS and never sees the connection, so there is no certificate here that anybody
//! verified. Reading one out of a proxy header would trust that header on every deployment's
//! behalf rather than on the one host that knows whether its terminator can be trusted; the
//! `oauth_as::mtls` module's trust boundary section is the argument in full.
//!
//! So a host that terminates mTLS must call `AuthorizationServer::token_with_context` (or the
//! other `*_with_credential` entry points) itself, passing the `ClientCredential::certificate` it
//! verified. A host that mounts only this service should not register mTLS clients at all,
//! because the metadata document will invite them and this endpoint will refuse them.

use std::borrow::Cow;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bytes::Buf as _;
use http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use http_body::Body as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::authorization::{AuthorizationError, AuthorizationRequest};
use crate::client::ClientId;
use crate::device::{normalize_user_code, DeviceGrant, DeviceGrantState};
use crate::error::{ErrorCode, ErrorResponse};
use crate::events::{Attempt, AttemptOutcome, RateLimitDecision};
use crate::grant::GrantType;
use crate::metadata::well_known_path;
use crate::scope::ScopeSet;
use crate::server::{AuthorizationServer, Clock, DeviceApprovalError, TokenRequest, UserApproval};
use crate::store::Storage;
use crate::token::TokenTypeHint;

/// Re-exported so a host building a [`ApprovalDecision::Respond`] body does not have to name
/// `bytes` in its own manifest just to agree with this crate about which version it means.
pub use bytes::Bytes;

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
/// [`ApprovalDecision::Respond`] carries.
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

/// What the host's approval step decided about one authorization request.
///
/// APPROVAL, not CONSENT, and the distinction is what the rename in 0.9.1 bought. This type is a
/// UI PROMPT: a question asked about one request, answered once, and never stored. The `consent`
/// module's [`crate::consent::ConsentRecord`] is a PERSISTED GRANT: a durable statement that
/// survives the request and can be withdrawn. Both were called "consent" at the crate root, which
/// is two meanings of one word in the one place a reader looks first. The direct API already
/// called the prompt's answer [`crate::server::UserApproval`], so this is the crate agreeing with
/// itself rather than inventing a third vocabulary.
///
/// Naming the third variant `Respond` is the point of the type: a real host shows a consent
/// SCREEN, which means the first request renders HTML and a later one carries the answer. The
/// resolver returns that page here and the router serves it unchanged, so interposing a consent
/// UI never requires abandoning this router.
/// `#[non_exhaustive]`: this type's shape already varies with the cargo features a host
/// enables, so an exhaustive match on it was never portable between builds of this crate.
#[non_exhaustive]
pub enum ApprovalDecision {
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
    /// Serve this response instead, unchanged: a consent screen, a step-up challenge, a redirect
    /// back into the host's own flow. Nothing is issued.
    ///
    /// READ WHEN THIS IS REACHED, because one case a reader expects is not among them. The
    /// authorization endpoint refuses BEFORE this resolver runs when
    /// [`ServiceBuilder::with_subject_resolver`] answers `None`, so a resolver cannot answer a
    /// signed-out visitor with a login redirect through this router: there is no subject to build
    /// an [`ApprovalRequest`] around, and inventing one would be this crate deciding who the user
    /// is. A host that wants to send an anonymous visitor to its login page does it in front of
    /// this service, where its session already lives; what this variant serves is every decision
    /// taken about a user the host has already named, step-up included.
    Respond(Box<Response>),
}

/// What the host's approval resolver is told about the request it is being asked to approve.
///
/// Everything borrows: the resolver is called inside the request path and nothing here outlives
/// it. The request has already passed RFC 6749 s4.1.1 validation, so `client_id`, `redirect_uri`
/// and `scope` are the VALIDATED values (the redirect URI is a registered one, the scope is
/// inside the client's registration), not raw query text.
/// `#[non_exhaustive]`: this type's shape already varies with the cargo features a host
/// enables, so an exhaustive match on it was never portable between builds of this crate.
#[non_exhaustive]
pub struct ApprovalRequest<'a> {
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
    /// The RFC 8707 resource indicators this request asked for, already validated against the
    /// server's `allowed_resources`. Empty when the client named none.
    ///
    /// It is here because the audience a token will carry is part of what the user is being asked
    /// to approve: "read your calendar" means something different at one resource server than at
    /// another, and the host cannot recover this from the query. For a PAR request the query holds
    /// only `client_id` and the request URI, and the pushed record has already been consumed by
    /// the time this resolver runs; for a JAR request the values are inside the signed object.
    pub resource: &'a [String],
    /// The RFC 9396 `authorization_details` this request asked for, already parsed and already
    /// checked against the server's supported types (section 5).
    ///
    /// THE TYPE CHECK IS NOT AN APPROVAL. `AuthorizationDetails::require_supported_types` inspects
    /// the `type` string alone, so the amount, the `identifier`, the creditor account and every
    /// other type-specific member of an element reach the issued token unexamined unless this
    /// resolver looks at them. RFC 9396 section 2 makes the elements the thing being authorized,
    /// and this crate never renders a screen, so the decision belongs here: a host that shows only
    /// [`ApprovalRequest::scope`] is asking the user to approve a payment they were never shown.
    /// Like [`ApprovalRequest::resource`], it cannot be recovered from the query on the PAR or JAR
    /// paths.
    #[cfg(feature = "rar")]
    pub authorization_details: &'a crate::rar::AuthorizationDetails,
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
    ///
    /// `covers` takes all three of what is being asked for, and the third is
    /// [`ApprovalRequest::authorization_details`], wrapped by
    /// [`crate::consent::RequestedDetails::of`]. It answers `false` for any request that carries
    /// one, so a resolver that skips its prompt on a `true` still asks about every RFC 9396
    /// element: a remembered consent records a scope and a resource list, and an element it never
    /// recorded is not something it can be said to cover. That method's docs give the argument in
    /// full, including why the answer would barely change if it did record them.
    #[cfg(feature = "consent")]
    pub remembered: Option<&'a crate::consent::ConsentRecord>,
}

/// How the host makes the RFC 6749 s10.12 approval decision. See
/// [`ServiceBuilder::with_approval_resolver`].
pub type ApprovalResolver = Arc<dyn Fn(&ApprovalRequest<'_>) -> ApprovalDecision + Send + Sync>;

/// How the host answers "when, and how, did you authenticate this user".
///
/// The third identity seam, and the one RFC 9470 needs: a subject resolver answers WHO, an approval
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
/// `#[non_exhaustive]`: this type's shape already varies with the cargo features a host
/// enables, so an exhaustive match on it was never portable between builds of this crate.
#[non_exhaustive]
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
    /// The document advertises a `jwks_uri` under the issuer, in a build with no `jwt` feature.
    /// Nothing here can serve a key set, so the member is a promise of a path that can only 404.
    /// A key set some other component holds is still fine: point the member outside the issuer,
    /// which is what "some other component holds the keys" looks like in a URL.
    #[cfg(not(feature = "jwt"))]
    JwksNotServable {
        /// The URL as advertised.
        url: String,
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
            #[cfg(not(feature = "jwt"))]
            ServiceError::JwksNotServable { url } => write!(
                f,
                "advertised jwks_uri ({url}) is under the issuer, but this build has no jwt \
                 feature and so has no key set to serve there"
            ),
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
    approval: Option<ApprovalResolver>,
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
/// [`with_approval_resolver`](ServiceBuilder::with_approval_resolver) and
/// [`with_csrf_tokens`](ServiceBuilder::with_csrf_tokens) too, or the authorization endpoint and
/// the device verification form refuse rather than guessing that silence means yes.
pub struct ServiceBuilder<S: Storage, C: Clock> {
    server: Arc<AuthorizationServer<S, C>>,
    subject: Option<SubjectResolver>,
    approval: Option<ApprovalResolver>,
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
            approval: None,
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
    /// This resolver is IDENTITY ONLY. It does not express approval; see
    /// [`with_approval_resolver`](ServiceBuilder::with_approval_resolver).
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
    /// AUTO-APPROVING authorization server, and the fix is to say what the approval step is rather
    /// than to leave it implied.
    ///
    /// Return [`ApprovalDecision::Respond`] to render a consent screen and finish the flow on a
    /// later request; return [`ApprovalDecision::Approve`] only once the user has actually agreed.
    pub fn with_approval_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&ApprovalRequest<'_>) -> ApprovalDecision + Send + Sync + 'static,
    {
        self.approval = Some(Arc::new(resolver));
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
        // The SERVER's document, not the configuration's: what this service can honour depends on
        // the seams the host installed on the server as well as on the configuration, and RFC 7523
        // `private_key_jwt` is the case that separates the two. See
        // [`crate::AuthorizationServer::metadata`].
        // `mut` for the RFC 8705 strip below, which is the one place the document this service
        // SERVES has to say less than the document the server describes itself with.
        #[allow(unused_mut)]
        let mut meta = self.server.metadata();
        // `from_config` trims the issuer, and derives every default endpoint from that trimmed
        // form, so the prefix relation below holds for an unconfigured host by construction.
        let issuer = meta.issuer.clone();

        // RFC 8705 sections 2.1.1, 2.2.1 and 3.3, REMOVED from the served document.
        //
        // Every one of them is true of `AuthorizationServer` reached through a host's own handler
        // with a certificate its TLS terminator verified, and none of them is true of THIS router,
        // which is handed an already-parsed request and passes `certificate: None` on every
        // credential it builds (see `Credentials::credential`). A client that reads
        // `tls_client_auth` here and presents a certificate is answered `invalid_client` forever;
        // one that reads the section 3.3 flag believes its token is certificate bound when it is a
        // bearer token. The field doc used to offer "a host that is not doing that should not
        // compile the `mtls` feature in", which cargo feature unification takes out of the host's
        // hands: one other crate in the graph enabling `mtls` makes this router lie.
        //
        // Only the SERVED copy is touched. `AuthorizationServer::metadata()` is unchanged, so a
        // host serving its own routes still publishes the full document, which for that host is
        // the honest one.
        #[cfg(feature = "mtls")]
        {
            meta.token_endpoint_auth_methods_supported.retain(|m| {
                m != crate::mtls::TLS_CLIENT_AUTH && m != crate::mtls::SELF_SIGNED_TLS_CLIENT_AUTH
            });
            meta.tls_client_certificate_bound_access_tokens = false;
        }

        let default_introspection_endpoint = format!("{issuer}/introspect");

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
        // RFC 7662. The one route derived from the CONFIGURATION rather than from the document,
        // and deliberately: `from_config` publishes `introspection_endpoint` only where the host
        // named it, because whether this server answers a RESOURCE SERVER depends on whether the
        // deployment registered any (`ServerConfig::resource_servers`), and only the host knows
        // that. See the field's doc in `crate::metadata` for why 0.9.2 building the channel did
        // NOT make the member unconditional. Withdrawing the ROUTE with the promise would take
        // away the half that always works -- a client asking about its own token -- which is a
        // functional regression rather than an honesty fix. Serving a path the document does not
        // name misleads nobody; the rule this module opens with is about the other direction.
        let introspect = Some(endpoint_path(
            &issuer,
            "introspection_endpoint",
            match &config.introspection_endpoint {
                Some(u) => u,
                None => &default_introspection_endpoint,
            },
        )?);
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
        // RFC 8414 s2 `jwks_uri` in a build WITHOUT the `jwt` feature, which is a build that signs
        // nothing and has no key set to serve. `http` does not imply `jwt` and
        // `ServerConfig::jwks_uri` is a plain public field, so the document could advertise the
        // member while every branch that routes it above is compiled out: `build` returned `Ok`,
        // the document promised the endpoint, and `resolve` answered `None`. An advertised endpoint
        // that 404s is the exact defect this module's docs open by naming, and RFC 9068 s4 makes it
        // expensive: a resource server that cannot fetch the keys cannot verify anything.
        //
        // Refused rather than silently dropped, and only when the URL is UNDER the issuer. Off
        // issuer is the documented case for this build (`metadata::advertised_jwks_uri`: some other
        // component holds the keys), this service never claimed that path, and nothing it serves
        // 404s. Under the issuer there is no reading on which the promise is kept.
        #[cfg(not(feature = "jwt"))]
        if let Some(url) = &meta.jwks_uri {
            if endpoint_path(&issuer, "jwks_uri", url).is_ok() {
                return Err(ServiceError::JwksNotServable {
                    url: url.to_string(),
                });
            }
        }

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
        // Normalised like every route `endpoint_path` produces, and for the same reason: this one
        // also carries the issuer's path, so a tenant whose name a client must escape is escaped
        // here too and the document is served at the path the client actually asks for.
        let well_known = encode_route_path(&well_known_path(&issuer));

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
                // RFC 7617 s2: the realm is a quoted-string, so `"` and `\` must be escaped.
                //
                // The issuer OUGHT to be a URL and so ought to contain neither, and until the
                // 0.9.1 audit this code said so and stopped there. But `ServerConfig::issuer` is a
                // bare `String` that this crate deliberately does not validate — it does not even
                // require `https` — so "the issuer is a URL" is an assumption about the host's
                // configuration, not a property of the type. A stray quote picked up from a config
                // template would otherwise put a second `realm` auth-param on every 401 this
                // server sends, which a conforming client parses as a different challenge.
                //
                // `HeaderValue::from_str` already refuses CR and LF, so there was never a response
                // splitting hole here; the escape is about producing a challenge that parses as
                // the one thing it means.
                challenge: HeaderValue::from_str(&format!(
                    "Basic realm=\"{}\"",
                    escape_quoted_string(&issuer)
                ))
                .unwrap_or_else(|_| HeaderValue::from_static("Basic realm=\"oauth\"")),
                origin: issuer_origin(&issuer).to_string(),
                subject: self.subject,
                approval: self.approval,
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
/// Public because it is a ceiling a host needs when sizing its own proxy or gateway limits, and
/// because [`MAX_FORM_PARAMETERS`] documents itself in terms of it.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// The largest number of form or query parameters any endpoint this service serves will decode.
///
/// [`MAX_BODY_BYTES`] does NOT bound this, and that is why the constant exists. Decoding is per
/// PARAMETER, not per byte: every pair is split, percent-decoded and pushed onto a vector, and
/// every later `param` lookup is a linear scan across all of them. MEASURED with
/// `benches/http_surface.rs`, on an aarch64 macOS laptop, before this cap existed: `POST /token`
/// costs 2.65 us with no extra parameters, 7.55 us with 64 ignored ones, 22.15 us with 256 and
/// 83.33 us with 1024, against 163 ns for a 404 on an unrouted path. The growth is LINEAR (81 to
/// 118 ns per parameter across that sweep), which is the problem rather than the reassurance: 64
/// KiB of `&a=b` pairs is roughly 2300 parameters, so a byte cap alone left one unauthenticated
/// packet buying about three orders of magnitude more work than the service's cheapest answer.
/// The GET endpoints are worse still: their parameters arrive in a URL, which [`MAX_BODY_BYTES`]
/// never applied to at all.
///
/// With the cap, the same 1024-parameter request costs 14.50 us, and what is left is not decoding:
/// it is buffering and UTF-8 validating the body, which [`MAX_BODY_BYTES`] already bounds and which
/// no parameter cap can avoid, since the count cannot be known before the bytes have arrived.
///
/// SIXTY-FOUR, counted from the largest legitimate request rather than rounded. The biggest form
/// this crate defines is an RFC 9126 push of an authorization request, which can carry
/// `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`,
/// `code_challenge_method`, `nonce`, `prompt`, `login_hint`, `max_age`, `acr_values`, `request`,
/// `authorization_details` and up to four of client authentication's parameters: about twenty.
/// After it comes an RFC 8693 exchange at about thirteen. RFC 8707 s2 allows `resource` to repeat,
/// which is the one parameter a conforming client can send many of, and RFC 6749 s3.1 lets a
/// deployment define extension parameters this server ignores. Sixty-four is therefore roughly
/// three times the largest request this crate can construct, with the whole of that headroom left
/// for repetition and extensions, and it is still 36 times below what the byte cap alone allowed.
///
/// The check is a count of `&` separators with an early exit, so REFUSING is cheaper than parsing
/// even the first pair: it stops reading the input at the sixty-fourth separator. That matters
/// because a refusal is work an attacker chooses the rate of.
pub const MAX_FORM_PARAMETERS: usize = 64;

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
            // NORMALISED TO WIRE FORM here, at build time, and nowhere else. The issuer arrives
            // exactly as the host configured it and the two legal spellings of a path a client
            // must escape produce the same bytes on the wire; `encode_route_path` is what makes
            // the table hold those bytes, so `handle` can compare the raw path and nothing that
            // sits in front of this service disagrees with it about which route was asked for.
            Ok(encode_route_path(&path))
        }
        _ => Err(ServiceError::EndpointOutsideIssuer {
            endpoint,
            url: url.to_string(),
        }),
    }
}

/// The issuer's `scheme://authority`, which is what an `Origin` header carries (RFC 6454 s6.1:
/// scheme, host, and port, with no path).
///
/// SEARCHED for, rather than computed by subtraction. Subtracting the length of [`crate::metadata::issuer_path`] from the
/// issuer would put the split point wherever a trailing slash the path trimmed used to be, so an
/// issuer with both a non-ASCII path and a trailing slash split inside a character and PANICKED:
/// `https://as.example/\u{e9}//` landed on the second byte of the two-byte character. Searching
/// for the separator can only ever land on a boundary, whatever the issuer contains. The one
/// caller passes an issuer already trimmed by `from_config`, so nothing reachable produced that
/// panic, but "safe because one caller trims first" is not a property this function can state.
fn issuer_origin(issuer: &str) -> &str {
    // Past `://` when there is one, so a colon in the scheme cannot be read as a port and the
    // first `/` found is the one that starts the path. `issuer_path` reads the same shape.
    let authority_at = match issuer.find("://") {
        Some(i) => i + 3,
        None => 0,
    };
    match issuer[authority_at..].find('/') {
        Some(i) => &issuer[..authority_at + i],
        None => issuer,
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
    /// RFC 7592: the `client_id` segment, RAW as it arrived. Decoded at the match arms by
    /// `decode_path_segment`, and only after the route has been decided, for the reason the
    /// resolver's own comment gives: the path is matched in wire form.
    ///
    /// THE DECODED VALUE IS NOT VALIDATED, and it goes to the host's
    /// [`crate::store::Storage::get_client`]. `%2F` decodes to a real `/` here, `%2E%2E` to `..`,
    /// `%00` to a NUL, and invalid UTF-8 to U+FFFD. Routing is unaffected — the raw path is what
    /// was matched, so nothing mounted under the registration endpoint can be reached this way —
    /// and this crate does not refuse the value, because an identifier's syntax is the host's
    /// (RFC 6749 s2.2) and a host whose ids are HTTPS URLs has a `/` in every one. It is also not
    /// a shape unique to this route: the authorization and token endpoints hand `get_client` an
    /// arbitrary unauthenticated string too, so validating here would close nothing. The
    /// obligation is stated where the value lands, on [`crate::store::Storage::get_client`], and
    /// `tests/storage_client_id_contract.rs` pins it.
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
        // ONE segment, and a non-empty one. `crate::registration`'s `registration_client_uri`
        // percent-encodes the id into the URL this server itself minted (RFC 7592 s3), and
        // `decode_path_segment` undoes exactly that below, so a RAW slash arriving here is a
        // different path rather than a client id whose name contains one. Until the 0.9.1 audit
        // this comment asserted the encoding while the minting side did not perform it; the
        // asymmetry was invisible only because a minted id is 32 hex characters.
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
    /// `axum`, a test harness holding a `String`. The body is read whole, up to 64 KiB, before it
    /// is parsed, which is what these endpoints require (client
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

        // THE RAW WIRE PATH, matched byte for byte. The normalisation happens on the other side:
        // `ServiceBuilder::build` runs every route through `encode_route_path`, so the table is
        // already in the form a client sends. Decoding here instead would make `/%74oken` the
        // token endpoint and `/%72egister` the registration endpoint, which is a different string
        // to every reverse proxy, ingress rule and WAF in front of this service and the same one
        // to this service: a host restricting RFC 7591 registration to an internal network BY PATH
        // would be serving it to everyone. Only the captured RFC 7592 id is decoded, and only
        // after the route has been decided.
        //
        // "BYTE FOR BYTE" IS QUALIFIED BY ONE RULE, and only one: RFC 3986 s6.2.2.1 says the
        // hexadecimal digits of a percent-encoding are case INSENSITIVE and directs a normaliser
        // to prefer the uppercase form, so `%c3` and `%C3` are the same octet and any client
        // library, proxy or ingress in the path is entitled to convert between them. Both sides
        // are therefore brought to the uppercase form -- the table by `encode_route_path` at build
        // time, the wire path by `uppercase_escapes` here -- and compared verbatim after that.
        // This is NOT decoding and gives none of decoding's ground away: `%74oken` uppercases to
        // `%74oken`, which is still not `/token`, and every rule in front of this service that
        // matched the raw path is looking at a string this transformation cannot alter the
        // meaning of. It costs a scan for `%` per request and allocates only for a path that
        // carries a lowercase escape.
        let path = uppercase_escapes(uri.path());
        let route = match state.routes.resolve(&path) {
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

        let mut response = self.dispatch(route, &method, headers, &uri, body).await;
        if head {
            // The LENGTH is kept and only the bytes are dropped. RFC 9110 s9.3.2 says a HEAD
            // response's header fields SHOULD be identical to the GET's, and `Content-Length` is
            // the one a cache and a health check actually read; answering zero would tell them
            // the representation is empty. Setting it here rather than leaving the full body for
            // the transport to suppress means a host that does not special-case HEAD still emits
            // a correct response instead of content the RFC forbids.
            let length = response.body().size_hint().exact().unwrap_or(0);
            *response.body_mut() = Body::empty();
            if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
                response.headers_mut().insert(header::CONTENT_LENGTH, value);
            }
        }
        response
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
            // The captured segment arrives RAW, because the route was decided on the wire path
            // (see `handle`), and it is decoded here: a client id may contain characters a path
            // segment reserves, and `registration_client_uri` percent-encodes them into the URL
            // this server minted (RFC 7592 s3), so this is the other half of that round trip. It
            // is the ONE decode this module performs on a path, and it happens after the route is
            // settled, so it can never turn one route into another.
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
        BodyError::TooLarge => text_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds this server's limit",
        ),
        BodyError::Incomplete => {
            text_response(StatusCode::BAD_REQUEST, "request body was not received")
        }
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
/// document at build time, so re-declaring it here in axum's syntax would create
/// a second table that could disagree with the first. A 404 from
/// [`AuthorizationService::handle`] is a path this server does not serve, which is exactly what a
/// fallback means.
///
/// # Why the request is answered on a spawned task
///
/// BECAUSE A CLIENT THAT HANGS UP MUST NOT BE ABLE TO STOP THE SERVER MID-SEQUENCE. hyper drops
/// the service future when the connection closes, and a dropped future does not fail: the code
/// after the `.await` it was suspended on simply never runs. `crate::server` has no transactions
/// (`Storage` deliberately offers none), so several of its sequences are an atomic TAKE followed
/// by a write, and every one of those arguments about which way the pair fails assumes that a
/// failure HAPPENS. The refresh rotation is the sharp case: `Storage::take_refresh_token` removes
/// the chain and the spent marker that arms RFC 9700 s4.14.2 reuse detection is written after it,
/// so a drop in between leaves the chain gone with no marker, which is the exact state that
/// ordering exists to prevent. The authorization code path has the same shape with its consumed
/// record. Neither is a race an attacker has to win by timing: whoever presents the credential is
/// whoever decides when to close the socket.
///
/// Awaiting a `JoinHandle` moves the cancellation to the RIGHT place. The client's disconnect
/// cancels this adapter's await on the handle; the spawned task keeps its own place in the runtime
/// and runs the store sequence to the end. Nothing else in this crate can do this, because the
/// `http` feature deliberately pulls in no runtime; the `axum` feature is the one place a runtime
/// is already present (`axum = ["http", "dep:axum", "dep:tokio"]`), so it is the one place this can
/// be contained. A HOST MOUNTING [`AuthorizationService::handle`] ITSELF OWNS THIS, and should
/// spawn for the same reason.
///
/// # What a host may notice
///
/// IN-FLIGHT WORK IS NO LONGER BOUNDED BY CONNECTIONS. That is the point of the spawn and it is
/// also its cost: a client that hangs up stops waiting but no longer stops the work, so axum's and
/// hyper's connection limits, and any accept-side bound the host set, no longer bound the tasks
/// this service is running. The bound becomes request RATE times handler latency, and NEITHER
/// FACTOR IS THIS CRATE'S TO SET.
///
/// The rate half is the stronger one: the limiter runs INSIDE [`AuthorizationService::handle`] and
/// refuses before the store is touched, so a refused request costs a spawn and nothing more. It is
/// still not a global ceiling — the budgets [`crate::rate_limit`] ships for the endpoints that
/// name a client are keyed per `client_id`, which RFC 6749 section 2.2 makes public, so a caller
/// spraying identifiers gets a budget apiece up to
/// [`crate::rate_limit::DEFAULT_MAX_TRACKED_CLIENTS`] counters before the rest share an overflow
/// counter.
///
/// The latency half is the host's outright. A handler makes a bounded NUMBER of store calls, but
/// each one is the host's [`crate::store::Storage`] and this crate sets no timeout anywhere, on
/// anything; the token path additionally awaits [`crate::jwt::Es256Signer`], which that trait's
/// own docs say may be a network round trip to a KMS. Nor is the latency all waiting:
/// a host-installed [`crate::client::SecretVerifier`] runs its KDF INLINE on the executor thread
/// polling the request — that trait prices argon2id at ordinary parameters at roughly 200 ms, paid
/// per token request and on the unknown-client path too — so it occupies a worker rather than
/// yielding it. A host that wants a hard
/// ceiling should take a semaphore permit before the spawn, or spawn into a `JoinSet` it owns, and
/// answer 503 when it cannot get one.
///
/// A PANIC in a handler no longer unwinds into hyper. It arrives here as a `JoinError` and is
/// answered with an empty 500, which is what the panicking connection produced anyway, minus the
/// connection dying with it. RUNTIME SHUTDOWN is the other `JoinError`: a task cancelled because
/// its runtime is going away answers the same 500. The two are not distinguished on the wire on
/// purpose, because they are the same news to the client (this request did not complete and it
/// does not know whether anything happened), and both are already visible to the host: a panic
/// through its own hook, a shutdown because it asked for one.
///
/// # Cost
///
/// One `tokio::spawn` per request, which is ONE allocation: measured with `tests/support/alloc.rs`
/// on aarch64-apple-darwin at 1 alloc and 128 bytes for a trivial task, the block sized by the task
/// header plus the handler future. `tests/allocation.rs` budgets the REQUEST path, which this does
/// not touch: nothing inside [`AuthorizationService::handle`] changes, and the token endpoint's own
/// budget there is two orders of magnitude larger than one task. It buys the store sequence the
/// right to finish.
///
/// The other half of the cost is not an allocation. Detaching the handler from the connection
/// means in-flight work is bounded by request RATE rather than by concurrent connections: a client
/// that disconnects immediately after sending no longer sheds any load, because the handler it
/// started runs to completion regardless. That is the same property that buys the store sequence
/// its right to finish, seen from the load side. A host that relied on disconnects for
/// backpressure needs a concurrency limit in front of this service — `tower::limit` or the
/// equivalent — and the rate limiter this crate already has does not substitute for one, because
/// it refuses attempts rather than bounding work already accepted.
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
                match tokio::spawn(async move { service.handle(request).await }).await {
                    // `Body` is already a complete `Bytes`, so this is a move, not a copy or a
                    // stream adapter.
                    Ok(response) => response.map(|body| axum::body::Body::from(body.into_bytes())),
                    // A panic, or a runtime being torn down. No body: there is nothing this
                    // service knows about the failure that a client could act on, and every
                    // endpoint here answers a different content type, so an invented JSON error
                    // would be a guess about which one this request wanted.
                    Err(_) => {
                        let mut response = axum::http::Response::new(axum::body::Body::empty());
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        response
                    }
                }
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

/// The RFC 8628 verification page, and the only HTML this server emits.
///
/// It carries more headers than any other response here because it is the only one a BROWSER
/// renders, and the only one whose defences a browser can be tricked into satisfying on the user's
/// behalf.
///
/// FRAMING. The page's CSRF defence is `Sec-Fetch-Site: same-origin` (see
/// `same_origin_submission`), and a document inside a cross-site iframe posting to its own origin
/// sends exactly that. So without a framing refusal the whole defence is decorative against a
/// clickjack: an attacker frames the page invisibly, starts a device flow of their own, and lands
/// the user's click on Approve. `frame-ancestors 'none'` is the standard's answer and
/// `X-Frame-Options: DENY` is the one older browsers obey; both are sent because they are
/// enforced by different code paths and neither supersedes the other everywhere.
///
/// CACHING. The body carries a live single-use CSRF token and the details of a third party's
/// pending grant. This was the one response in this file that did not call `no_store`, which
/// meant a shared cache, or a browser's back button, could re-serve another user's approval form.
///
/// The rest is the ordinary hardening for a page with no scripts, no styles, no images and one
/// same-origin form: `default-src 'none'` (nothing may be loaded), `form-action 'self'` (the
/// submission cannot be redirected off-origin by injected markup), `base-uri 'none'` (a `<base>`
/// cannot relocate the relative form action), `nosniff`, and `no-referrer` so the user code in
/// the deep-link URL is not handed to a third party.
fn html_response(status: StatusCode, body: String) -> Response {
    let mut resp = respond(status, body);
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, html_content_type());
    no_store(headers);
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
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
///
/// ONE SEGMENT, never the whole path. For a few days of the 0.9.1 audit this crate decoded the
/// entire request path before matching it, to make a raw non-ASCII issuer routable, and the price
/// was two defects at once: `/%74oken` became the token endpoint and `/%72egister` became the RFC
/// 7591 registration endpoint, under every reverse proxy, ingress rule and WAF that had matched
/// the RAW path and seen no such string; and an issuer spelled the way RFC 3986 section 3.3
/// requires (`https://as.example/tenant%20a`) stopped routing at all, because
/// [`endpoint_path`] holds the issuer verbatim. Both directions are fixed in the ROUTE TABLE
/// instead, by [`encode_route_path`]: the table is normalised into wire form once at build time
/// and the wire path is compared byte for byte, which is what every layer in front of this service
/// is also doing.
fn decode_path_segment(raw: &str) -> Cow<'_, str> {
    percent_decode(raw, false)
}

/// Normalise a route-table path into the form a client puts on the wire.
///
/// The table is derived from the issuer AS THE HOST CONFIGURED IT (see [`endpoint_path`]), and a
/// host may legitimately configure either of two spellings for a path a client must escape: the
/// RFC 3986 section 3.3 one, `https://as.example/tenant%20a`, which is a legal URI, or a raw
/// non-ASCII one, `https://as.example/\u{e9}`, which is not but which this crate accepts and
/// `tests/issuer_origin_boundary.rs` pins as buildable. A client fetching from either sends the
/// same bytes: percent-encoded ones. So the table is brought to that form ONCE, here, and the
/// matcher never touches the wire path.
///
/// `%` IS LEFT ALONE, which is what makes the first spelling survive: an issuer that already
/// carries escapes passes through unchanged rather than being encoded a second time into `%2520`.
/// The cost is that a literal `%` in an issuer that is not an escape cannot be expressed, which is
/// a URI that is malformed under section 2.1 anyway.
///
/// Left alone EXCEPT FOR THE CASE OF ITS TWO HEX DIGITS, which are uppercased. RFC 3986 s6.2.2.1
/// makes those digits case insensitive and directs a normaliser to prefer the uppercase form, so
/// `https://as.example/caf%c3%a9` and `https://as.example/caf%C3%A9` are the same issuer and a
/// client, proxy or ingress that normalises sends the uppercase one whichever the document
/// carried. Uppercasing here is what makes the table CANONICAL rather than a copy of one host's
/// spelling; `uppercase_escapes` does the same to the wire path, and the comparison between the
/// two is still byte for byte. A `%` NOT followed by two hex digits is not an escape at all and
/// keeps the pass-through behaviour above.
///
/// Run once per route at build time, so its cost is not on any request path.
fn encode_route_path(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut skip = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if b == b'%' {
            if let (Some(&h), Some(&l)) = (bytes.get(i + 1), bytes.get(i + 2)) {
                if hex_value(h).is_some() && hex_value(l).is_some() {
                    out.push('%');
                    out.push(h.to_ascii_uppercase() as char);
                    out.push(l.to_ascii_uppercase() as char);
                    skip = 2;
                    continue;
                }
            }
        }
        // RFC 3986 s3.3 `pchar` (unreserved / sub-delims / ":" / "@"), plus the separator itself
        // and the escape introducer.
        let verbatim = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
                    | b'%'
            );
        if verbatim {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// The wire half of [`encode_route_path`]'s normalisation: uppercase the hex digits of every
/// percent-encoding in a path and change nothing else.
///
/// RFC 3986 s6.2.2.1 defines this as case normalisation and it is the only transformation this
/// service applies to a path before matching it. It is NOT decoding: the number of characters is
/// unchanged, `%74oken` stays `%74oken`, and every rule in front of this service that matched on
/// the raw path is matching a string this cannot alter. Doing it on both sides is what lets a host
/// spell its issuer's escapes either way and a client normalise or not: all four combinations meet
/// in the same canonical form, and a table normalised alone would have swapped one broken pairing
/// for another.
///
/// Borrows unless the path actually carries a lowercase escape, so an ASCII route (every route, in
/// every deployment that does not put an escape in its issuer) allocates nothing and pays one scan
/// for `%`.
fn uppercase_escapes(path: &str) -> Cow<'_, str> {
    let bytes = path.as_bytes();
    let needs = bytes.iter().enumerate().any(|(i, &b)| {
        b == b'%'
            && matches!(
                (bytes.get(i + 1), bytes.get(i + 2)),
                (Some(&h), Some(&l))
                    if hex_value(h).is_some()
                        && hex_value(l).is_some()
                        && (h.is_ascii_lowercase() || l.is_ascii_lowercase())
            )
    });
    if !needs {
        return Cow::Borrowed(path);
    }
    // Written as its own loop rather than as a call to `encode_route_path`: that function also
    // ESCAPES what is not a `pchar`, which is right for a path a host configured and wrong for one
    // that arrived on the wire, where anything outside the grammar is the client's problem and not
    // something this service should quietly rewrite into a route.
    //
    // Copied in RUNS between escapes rather than byte by byte, which keeps it correct for a
    // multi-byte character (`%` is ASCII, so every index this slices at is a character boundary)
    // as well as cheaper.
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(&h), Some(&l)) if hex_value(h).is_some() && hex_value(l).is_some() => {
                out.push('%');
                out.push(h.to_ascii_uppercase() as char);
                out.push(l.to_ascii_uppercase() as char);
                i += 3;
            }
            _ => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'%' {
                    i += 1;
                }
                out.push_str(&path[start..i]);
            }
        }
    }
    Cow::Owned(out)
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

/// A request carrying more parameters than [`MAX_FORM_PARAMETERS`], refused before it is decoded.
struct TooManyParameters;

/// The answer to one of those.
///
/// A bare 413 rather than an RFC 6749 s5.2 error body, for exactly the reason [`body_error`] is
/// one: nothing has been parsed, so there is no `grant_type`, no authenticated client and no
/// validated redirect URI to shape a protocol error around, and 413 is what every proxy between
/// here and the caller already understands. It says PAYLOAD even when the parameters came from a
/// query string, because the payload being refused is the parameter list; 414 would assert the
/// URI was too long in BYTES, which it need not be.
fn too_many_parameters() -> Response {
    text_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "request carries too many parameters",
    )
}

/// A refusal that happens BEFORE the request is parsed far enough to have an OAuth error code.
///
/// These are the only responses in this file that carry bytes without an RFC 6749 s5.2 JSON body:
/// the body cap and the parameter cap both fire on the raw request, where there is no `grant_type`
/// and no `client_id` to name, and inventing an OAuth error for them would be a claim about a
/// request this server never read. They still need a `Content-Type` (RFC 9110 s8.3) or the client
/// cannot decode the sentence explaining what happened — which is what they are for. The payloads
/// are fixed ASCII literals with no attacker-controlled substring, so `text/plain` is safe here in
/// a way it would not be for anything echoing input.
fn text_response(status: StatusCode, body: &'static str) -> Response {
    let mut resp = respond(status, body);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain;charset=UTF-8"),
    );
    resp
}

/// Split a form body or query string into decoded pairs. A parameter with no `=` is kept with an
/// empty value, which is how a client spells "present but empty" and must not be mistaken for
/// absent.
/// Sized up front rather than grown. `Split` has no `size_hint`, so `collect` starts from nothing
/// and doubles: a six-parameter token body reallocates three times and memcpys 64 bytes per pair
/// each time. Counting the separators is one linear pass over bytes that are about to be walked
/// anyway, and it is an exact upper bound (empty segments are filtered out, so it can only
/// overshoot). This runs on EVERY routed request, which is what makes a free win worth taking.
///
/// THE SAME PASS ENFORCES [`MAX_FORM_PARAMETERS`], and it is the reason the count is taken here
/// rather than at the eight call sites: decoding is per parameter, so a cap any one caller could
/// forget to apply is not a cap. The loop returns at the separator that crosses the ceiling, so a
/// 64 KiB body of junk is refused after reading the first few hundred bytes of it and allocating
/// nothing at all. Separators rather than parameters is a conservative over-count (`a&&&&b` is two
/// parameters and five segments), which is the right direction for a bound whose only job is to
/// stop absurd requests: nothing legitimate sends empty segments.
fn parse_pairs(input: &str) -> Result<Vec<Pair<'_>>, TooManyParameters> {
    let mut separators = 0usize;
    for b in input.bytes() {
        if b == b'&' {
            separators += 1;
            if separators >= MAX_FORM_PARAMETERS {
                return Err(TooManyParameters);
            }
        }
    }
    let bound = separators + 1;
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
    Ok(pairs)
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
///
/// The description is BORROWED from the table below rather than formatted, and the reason is the
/// rule `tests/allocation.rs` states on `refused_token_request_allocation_bound`: a refusal is
/// work an attacker sets the rate of, so a refusal that allocates is an allocation anyone who can
/// open a socket may ask for at whatever rate they like. Every other refusal in this file already
/// passes a literal into `error_description`, which is a `Cow<'static, str>`; this one formatted,
/// although `name` is a `&'static str` drawn from the finite set of parameters the endpoints
/// below actually demand. `src/tests/http.rs` reads that set out of this file's source and fails
/// if a call site's name is missing from the table, so the fallback cannot quietly become the
/// common case.
fn required<'a>(pairs: &'a [Pair<'a>], name: &'static str) -> Result<&'a str, ErrorResponse> {
    param(pairs, name).ok_or_else(|| {
        let description: Cow<'static, str> = match name {
            "code" => Cow::Borrowed("missing required parameter code"),
            "device_code" => Cow::Borrowed("missing required parameter device_code"),
            "refresh_token" => Cow::Borrowed("missing required parameter refresh_token"),
            "token" => Cow::Borrowed("missing required parameter token"),
            "subject_token" => Cow::Borrowed("missing required parameter subject_token"),
            "subject_token_type" => Cow::Borrowed("missing required parameter subject_token_type"),
            // Unreachable from this file today, and kept total rather than made a panic: a
            // refusal is the wrong place to introduce a way for the process to die.
            other => Cow::Owned(format!("missing required parameter {other}")),
        };
        ErrorResponse::new(ErrorCode::InvalidRequest).with_description(description)
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

/// RFC 9396 s5 for the two doors whose grant has NOWHERE to carry an authorization detail, in any
/// build: the RFC 8628 device authorization request and the RFC 8693 token exchange grant.
///
/// Every other door refuses in the core, gated on `not(feature = "rar")`, because the core has an
/// argument the parameter arrives in and can therefore see it. These two do not:
/// `device_authorization_with_credential` takes a scope and nothing else, and
/// [`crate::token_exchange::TokenExchangeRequest`] derives what it issues from the SUBJECT token,
/// so the parameter dies in this router unless this router answers it. That made the same POST to
/// the same `/token` URL refuse for `authorization_code` and silently drop for
/// `grant_type=...:token-exchange`.
///
/// UNGATED, unlike the core's refusals, and the difference is what is being refused. There the
/// answer turns on whether the build supports any detail TYPE; here it turns on the GRANT, which
/// has no field for a detail whether the type is supported or not. `AuthorizationServer::token`
/// already refuses to mint detail for a device grant under `rar` for exactly this reason; this is
/// that refusal moved to the door the client knocks on, where it can still be told which parameter
/// was wrong instead of receiving codes and discovering the omission at the resource server.
///
/// Checked BEFORE the credential and before the grant, like the DPoP proof this router refuses on
/// the same grant: a client asking for something this server cannot do is a wiring mistake, and
/// the refusal is only useful if it names the parameter rather than whatever was checked first.
fn refuse_authorization_details(pairs: &[Pair<'_>]) -> Option<ErrorResponse> {
    param(pairs, "authorization_details").map(|_| {
        // The VALUE is never echoed (RFC 6749 s5.2 restricts the charset, and this one is
        // attacker-supplied JSON); naming the parameter is what the developer who sent it needs.
        ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
            .with_description("this server does not accept authorization_details on this grant")
    })
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
    #[cfg(feature = "client-assertion")]
    client_assertion_type: Option<String>,
    /// RFC 7523 `client-assertion`, verbatim.
    #[cfg(feature = "client-assertion")]
    client_assertion: Option<String>,
}

impl Credentials {
    /// The borrowed form the server takes. Borrowed rather than owned so that reading a credential
    /// off the wire costs the same as it did before these two parameters existed.
    fn credential(&self) -> crate::server::ClientCredential<'_> {
        crate::server::ClientCredential {
            client_secret: self.client_secret.as_deref(),
            #[cfg(feature = "client-assertion")]
            client_assertion_type: self.client_assertion_type.as_deref(),
            #[cfg(feature = "client-assertion")]
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
    #[cfg(feature = "client-assertion")]
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
                #[cfg(feature = "client-assertion")]
                client_assertion_type: None,
                #[cfg(feature = "client-assertion")]
                client_assertion: None,
            })
        }
        (true, None, None) => {
            let (client_id, client_secret) = decode_basic(headers)?;
            Ok(Credentials {
                client_id,
                client_secret: Some(client_secret),
                #[cfg(feature = "client-assertion")]
                client_assertion_type: None,
                #[cfg(feature = "client-assertion")]
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
            #[cfg(feature = "client-assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client-assertion")]
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
    let form = match parse_pairs(&text) {
        Ok(form) => form,
        Err(TooManyParameters) => return too_many_parameters(),
    };

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
        // `GrantType::parse` and NOT `value.parse::<GrantType>()`: `FromStr`'s error carries an
        // owned copy of the caller's value, and the arm below discards it unread. That copy was
        // sized by an unauthenticated caller (one form parameter can be nearly the whole 64 KiB
        // body), which made a refusal cost the server a 60 KiB malloc and memcpy at whatever rate
        // the caller could open sockets. See `tests/refusal_cost.rs`.
        Some(value) => match GrantType::parse(value) {
            Some(g) => g,
            // The value is NOT echoed. RFC 6749 s5.2 restricts error_description to a charset
            // that excludes the double quote and backslash, and an attacker controls this string;
            // saying which grant was asked for is not worth having to sanitize it.
            None => {
                return error_response(
                    &ErrorResponse::new(ErrorCode::UnsupportedGrantType)
                        .with_description("this server does not implement the requested grant"),
                    via_header,
                    &state.challenge,
                )
            }
        },
    };

    let mut creds = match credentials(headers, &form) {
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

    // RFC 9449 s4.3 (1): there must be exactly ONE `DPoP` header. Several is not a request this
    // server may pick a favourite from: an intermediary that appended one, or a client that sent
    // two, leaves it ambiguous which proof the client meant to bind the token to.
    //
    // RESOLVED HERE, before the grant is dispatched, and that placement is the fix for a silent
    // downgrade rather than tidiness. The RFC 8693 arm below RETURNS, so while this block sat
    // after the dispatch a `DPoP` header sent with `grant_type=token-exchange` was never read at
    // all: no duplicate check, no proof verification, and an issued token with no `jkt`. A client
    // that asked for a sender-constrained token got a bearer token and no way to find out.
    #[cfg(feature = "dpop")]
    let dpop_proof = {
        let mut values = headers.get_all(crate::dpop::DPOP_HEADER).iter();
        let first = values.next();
        if values.next().is_some() {
            // EMITTED like every other proof refusal. These two are refused HERE rather than in
            // `verify_proof`, which is the only reason they were silent through 0.9.0: a
            // deployment reading `DpopProofRefused` to tell its failure modes apart would have
            // seen nothing whatever for a client sending two headers, which is a client bug the
            // operator is the only one who can report back.
            state
                .server
                .hooks()
                .emit(|| crate::events::Event::DpopProofRefused {
                    failure: crate::dpop::DpopFailure::Malformed,
                });
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
                state
                    .server
                    .hooks()
                    .emit(|| crate::events::Event::DpopProofRefused {
                        failure: crate::dpop::DpopFailure::Malformed,
                    });
                return error_response(
                    &ErrorResponse::new(ErrorCode::InvalidDpopProof)
                        .with_description("the DPoP header is not a compact JWS"),
                    via_header,
                    &state.challenge,
                );
            }
        }
    };

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
            // RFC 9449: this grant CANNOT bind the token it issues, so a presented proof is
            // REFUSED rather than ignored. `TokenExchangeRequest` carries no proof and
            // `crate::token_exchange` has nowhere to record a `jkt`, so honouring the header would
            // mean issuing an unbound token to a client that asked for a bound one and telling it
            // nothing: the silent downgrade that module argues against at length for the SUBJECT
            // token, applied to the ISSUED token by the same module. Loud beats quiet, and the
            // refusal is what an operator who turned DPoP on can actually see.
            #[cfg(feature = "dpop")]
            if dpop_proof.is_some() {
                // And it is REPORTED, for the same reason it is refused loudly: a client asking
                // this server for something it cannot do is a wiring mistake, and the operator who
                // turned DPoP on is the only party who can tell the client's author.
                //
                // `NotAcceptedHere`, NOT `Malformed`, which is what this said until the 0.9.1
                // audit: the proof has not been parsed at this point and is probably a perfectly
                // good JWS. Reporting it as malformed described the client's string instead of
                // this server's capability, and pointed the one person who could fix it at the one
                // person who could not.
                state
                    .server
                    .hooks()
                    .emit(|| crate::events::Event::DpopProofRefused {
                        failure: crate::dpop::DpopFailure::NotAcceptedHere,
                    });
                return error_response(
                    &ErrorResponse::new(ErrorCode::InvalidDpopProof).with_description(
                        "this server does not issue sender-constrained tokens through RFC 8693 \
                         token exchange",
                    ),
                    via_header,
                    &state.challenge,
                );
            }
            // The WHOLE credential, not the secret alone. RFC 8693 s2.1 authenticates the client
            // exactly as the other grants do, and `TokenExchange::exchange_token` REFUSES a client
            // that is not confidential: forwarding only `client_secret` first made every exchange
            // `invalid_client` (the `None` the other arms carry), and then, once the secret was
            // restored, still refused every client registered for `private_key_jwt` or
            // `client_secret_jwt`, whose credential arrives in `client-assertion`. Half a repair
            // is what left the second half invisible.
            return token_exchange_response(state, &form, client_id, &creds, via_header).await;
        }
    };

    // RFC 8707 s2: `resource` is a parameter of the token request itself, independent of
    // `grant_type`, so it is collected once here rather than inside each arm above.
    let resources = resource_indicators(&form);

    let context = crate::server::TokenRequestContext {
        credential: creds.credential(),
        resources: &resources,
        // RFC 9396 s2 makes this ONE JSON array, so `param`'s first-wins rule is the right
        // one here and a duplicate is a smuggled parameter rather than a second value.
        // That is the opposite of `resource`, which s2 of RFC 8707 explicitly allows to
        // repeat, and the difference is why the two are read differently.
        //
        // READ IN EVERY BUILD, not only under `rar`: a build that supports no authorization
        // detail type has to refuse the parameter (RFC 9396 s5), and a router that never read it
        // off the form left the endpoint nothing to refuse. See `TokenRequestContext`.
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
    creds: &Credentials,
    via_header: bool,
) -> Response {
    // The three refusals below, written out rather than built from the parameter's name. There
    // are exactly three call sites and the name is a constant at each of them, so `format!` was
    // copying one of three fixed sentences onto the heap per refused request; this refusal happens
    // BEFORE the exchange is attempted, so before the presented client credential has been
    // checked, which makes its rate the caller's to choose.
    const SUBJECT_NOT_A_TOKEN_TYPE: &str =
        "subject_token_type is not a token type RFC 8693 s3 registers";
    const ACTOR_NOT_A_TOKEN_TYPE: &str =
        "actor_token_type is not a token type RFC 8693 s3 registers";
    const REQUESTED_NOT_A_TOKEN_TYPE: &str =
        "requested_token_type is not a token type RFC 8693 s3 registers";

    fn token_type(
        refusal: &'static str,
        value: &str,
    ) -> Result<crate::token_exchange::TokenTypeIdentifier, ErrorResponse> {
        // The VALUE is not echoed, for the reason `grant_type` is not echoed above: RFC
        // 6749 s5.2 restricts error_description to a charset an attacker-supplied URN need
        // not respect, and naming the parameter is enough for the developer who sent it.
        //
        // And because it is not echoed, the parse must not COPY it either: `FromStr` builds an
        // `UnknownTokenTypeIdentifier` holding an owned, caller-sized `String` that this line then
        // throws away. `TokenTypeIdentifier::parse` is the same match with no payload.
        crate::token_exchange::TokenTypeIdentifier::parse(value)
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidRequest).with_description(refusal))
    }

    // RFC 9396 s5, before anything else is parsed. This grant issues from the SUBJECT token, so
    // `TokenExchangeRequest` has no member an authorization detail could travel in and the
    // parameter would die here silently; the token endpoint's shared handling, which refuses it,
    // is downstream of the arm that called this function and never runs for this grant. See
    // `refuse_authorization_details`.
    if let Some(refusal) = refuse_authorization_details(form) {
        return error_response(&refusal, via_header, &state.challenge);
    }

    let subject_token = match required(form, "subject_token") {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let subject_token_type = match required(form, "subject_token_type")
        .and_then(|v| token_type(SUBJECT_NOT_A_TOKEN_TYPE, v))
    {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let actor_token = param(form, "actor_token");
    let actor_token_type = match param(form, "actor_token_type")
        .map(|v| token_type(ACTOR_NOT_A_TOKEN_TYPE, v))
        .transpose()
    {
        Ok(v) => v,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let requested_token_type = match param(form, "requested_token_type")
        .map(|v| token_type(REQUESTED_NOT_A_TOKEN_TYPE, v))
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
        client_secret: creds.client_secret.as_deref(),
        // RFC 7521 s4.2 / RFC 7523 s2.2, forwarded rather than dropped: without these two an
        // assertion-authenticated confidential client cannot use this grant at all, and this is
        // the endpoint that advertises it.
        #[cfg(feature = "client-assertion")]
        client_assertion_type: creds.client_assertion_type.as_deref(),
        #[cfg(feature = "client-assertion")]
        client_assertion: creds.client_assertion.as_deref(),
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
    let form = match parse_pairs(&text) {
        Ok(form) => form,
        Err(TooManyParameters) => return too_many_parameters(),
    };

    // RFC 9396 s3 names the device authorization request as a place this parameter may be used,
    // and s5 requires refusing one this server will not honour. See
    // `refuse_authorization_details`: a `DeviceGrant` has no field for a detail, so accepting one
    // here mints a user code for a permission that can never reach the token.
    if let Some(refusal) = refuse_authorization_details(&form) {
        return error_response(&refusal, via_header, &state.challenge);
    }

    let mut creds = match credentials(headers, &form) {
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
    let form = match parse_pairs(&text) {
        Ok(form) => form,
        Err(TooManyParameters) => return too_many_parameters(),
    };

    let mut creds = match pushed_request_credentials(headers, &form) {
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
    let form = match parse_pairs(&text) {
        Ok(form) => form,
        Err(TooManyParameters) => return too_many_parameters(),
    };

    let mut creds = match credentials(headers, &form) {
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
    let form = match parse_pairs(&text) {
        Ok(form) => form,
        Err(TooManyParameters) => return too_many_parameters(),
    };

    let mut creds = match credentials(headers, &form) {
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

    // The WHOLE credential, exactly as the other three protected endpoints in this module do.
    // Forwarding only `client_secret` dropped every other way a client can authenticate: an RFC
    // 7523 assertion arrives in `client-assertion`, not in `client_secret`, so an
    // assertion-authenticated confidential client was refused `invalid_client` at this endpoint
    // and could never revoke anything through this service. Same defect, same cause and same
    // invisibility as the RFC 8693 one `tests/wire_reachability.rs` was written after: an arm not
    // updated when credentials moved onto the request context, with a revocation suite that only
    // ever drove the library API.
    match state
        .server
        .revoke_with_credential(&client_id, &creds.credential(), token, hint)
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
    // The `Content-Type` goes on the arm that HAS a body. An empty octet stream is not a valid
    // `application/json` document (RFC 8259 s2), and announcing it as one turns every RFC 7592
    // 401, 404 and 500 into a decode exception in the client rather than into the status it meant
    // to report: `response.json()` raises before anything can read `response.status`.
    let mut resp = match failure {
        crate::registration::RegistrationFailure::Invalid(body) => {
            let mut resp = respond(status, json_body(body));
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, json_content_type());
            resp
        }
        _ => respond(status, Body::empty()),
    };
    let headers = resp.headers_mut();
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
    // THROTTLE FIRST, on the one endpoint of this service where there may be no credential to
    // look at instead. RFC 7591 s3.1 registration may be ANONYMOUS, so the trick
    // `update_registration_handler` uses below — authenticate, then parse — has nothing to work
    // with here; what it does have is `Attempt::ClientRegistration`, which is keyed on nothing and
    // therefore answerable before a single byte of the body means anything. Parsing up to
    // `MAX_BODY_BYTES` of a stranger's JSON before asking the only gate this endpoint has is the
    // shape `MAX_FORM_PARAMETERS`'s own comment argues against: a refusal is work an attacker sets
    // the rate of.
    //
    // Unlike the management plane's arrangement, the check is NOT repeated inside the server
    // method: `admit_registration` and `register_admitted_client` are the two halves of
    // `register_dynamic_client` precisely so that one HTTP request is one charge. The registration
    // budget is global and small (60 per window by default), so a second charge would halve a
    // host's configured ceiling rather than cost it a rounding error.
    if let Err(e) = state.server.admit_registration() {
        return registration_error(&e);
    }
    let metadata = match client_metadata(body) {
        Ok(m) => m,
        Err(response) => return *response,
    };
    match state
        .server
        .register_admitted_client(&metadata, bearer_token(headers))
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
    // AUTHENTICATE FIRST, and unlike `register_handler` this handler can afford to. RFC 7591 s3.1
    // registration may be anonymous, so there is nothing to check before the body there; RFC 7592
    // management is credentialed on every request, and parsing up to `MAX_BODY_BYTES` of a
    // stranger's JSON before looking at the credential is the shape `MAX_FORM_PARAMETERS`'s own
    // comment argues against: a refusal is work an attacker sets the rate of. The read and delete
    // handlers already touched nothing before the token; this one parsed first, and that asymmetry
    // was the whole of the defect.
    //
    // The check is repeated inside `update_registration`, which is deliberate: this one is a
    // cheaper refusal, not the authority. The cost of the repeat is one storage read and one hash
    // on the SUCCESS path of an endpoint a deployment uses rarely, against a full JSON parse an
    // anonymous caller could buy at whatever rate it liked.
    let token = bearer_token(headers).unwrap_or_default();
    if let Err(e) = state
        .server
        .authenticate_registration(&ClientId::new(client_id), token)
        .await
    {
        return registration_error(&e);
    }
    let metadata = match client_metadata(body) {
        Ok(m) => m,
        Err(response) => return *response,
    };
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
    // WHEN THIS REQUEST ARRIVED, read before anything is looked up, and the instant the code
    // minted below is dated from.
    //
    // The decision this handler acts on is not always made during this handler. With a remembered
    // consent it was made when the user first approved, and the read that surfaces it happens
    // several awaits from here. Dating the code at ISSUANCE would let a standing approval outrank
    // a withdrawal recorded in between: the user clicks "remove this application" elsewhere, the
    // withdrawal cascades and records its barrier, this request resumes on its pre-withdrawal
    // snapshot, and a code dated NOW postdates the barrier — so the token is issued and its
    // refresh chain inherits the same instant and rotates long after the barrier is swept.
    //
    // Request entry is the latest instant this service can honestly claim: any withdrawal
    // recorded before it is one the consent read below would have seen, and any recorded after it
    // is later than this instant and refuses the write. See `UserApproval::granted_at`.
    let received_at = state.server.now();

    let pairs = match parse_pairs(uri.query().unwrap_or_default()) {
        Ok(pairs) => pairs,
        Err(TooManyParameters) => return too_many_parameters(),
    };

    let validated = match resolve_authorization_request(state, &pairs).await {
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
    let subject = match state.subject(headers) {
        Some(s) => s,
        // Deliberately NOT an error redirect. `access_denied` at the client's redirect URI would
        // tell the client a user refused, when in truth no user was ever asked. A direct 403 says
        // that without lying to the client.
        //
        // TWO STATES, and they are not the same mistake, which is why they are no longer the same
        // sentence. Until the 0.9.1 audit both said "the host must supply a subject resolver", and
        // for the common one that is false: `SubjectResolver` documents `None` as "nobody is
        // logged in", so an ordinary signed-out browser navigation told a fully wired host to
        // install what it had already installed, and sent whoever read it to the wrong file.
        None => {
            return match state.subject.is_some() {
                true => {
                    unwired("no authenticated resource owner: nobody is signed in for this request")
                }
                false => unwired(
                    "no authenticated resource owner; the host must supply a subject resolver",
                ),
            }
        }
    };

    // RFC 6749 s10.12: knowing WHO the user is does not establish that they agreed. Without a
    // approval seam this endpoint would mint a code on any cross-site top-level navigation a
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

    let approval = match &state.approval {
        Some(resolver) => resolver(&ApprovalRequest {
            headers,
            subject: &subject,
            client_id: &validated.client_id,
            scope: &validated.scope,
            redirect_uri: &validated.redirect_uri,
            state: validated.state.as_deref(),
            resource: &validated.resource,
            #[cfg(feature = "rar")]
            authorization_details: &validated.authorization_details,
            uri,
            #[cfg(feature = "consent")]
            // Deref through the shared `Arc<ConsentRecord>` the storage seam now returns: the
            // resolver borrows for the length of the call and never needs the handle.
            remembered: remembered.as_deref(),
        }),
        None => {
            return unwired(
                "no approval step is configured; the host must supply an approval resolver \
                 (RFC 6749 s10.12)",
            )
        }
    };
    // Only ever set by the host's own `ApproveAndRemember`; see that variant's docs.
    #[cfg(feature = "consent")]
    let mut remember = false;
    match approval {
        ApprovalDecision::Approve => {}
        #[cfg(feature = "consent")]
        ApprovalDecision::ApproveAndRemember => remember = true,
        // A refusal is an answer the client is entitled to receive at its (validated) redirect
        // URI, which is exactly what RFC 6749 s4.1.2.1 `access_denied` is for.
        ApprovalDecision::Deny => return redirect(validated.denied().location()),
        ApprovalDecision::Respond(response) => return *response,
    }

    // The host's report of how and when it authenticated this user, for RFC 9470 s4's parameters to
    // be enforced against. An unwired host reports `None`, which satisfies no requirement.
    #[cfg(feature = "consent")]
    let authentication = state.authentication.as_ref().and_then(|f| f(headers));
    // The requirement comes off the RESOLVED request, not off `pairs`. For a PAR or JAR request the
    // query holds only `client_id` plus the handle or the object, so reading `pairs` here dropped
    // `acr_values` and `max_age` entirely and silently disabled step-up for both (RFC 9126 s4, RFC
    // 9101 s6.3). A malformed `max_age` is now refused during validation, on the same redirect the
    // rest of the redirectable checks use.
    #[cfg(feature = "consent")]
    let issued = state
        .server
        .issue_authorization_code_with_authentication(
            // The assertion `UserApproval::granted_at` makes is exactly what this service has
            // just finished doing: the approval resolver returned `Approve` for THIS request, on
            // behalf of the subject the host's own resolver named. Nowhere else in this file may
            // mint one. It is dated from request entry rather than from now because the decision
            // may be a standing one; see `received_at` above.
            UserApproval::granted_at(&validated, subject.clone(), received_at),
            &validated.authentication_requirement,
            authentication.as_ref(),
        )
        .await;
    #[cfg(not(feature = "consent"))]
    let issued = state
        .server
        .issue_authorization_code(UserApproval::granted_at(&validated, subject, received_at))
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
/// and what every client understands.
///
/// `no_store`, because this is a credential-bearing response like any other on the token plane:
/// the `Location` of a successful authorization carries the authorization CODE and the `state`.
/// RFC 9111 s4.2.2 does not list 302 as heuristically cacheable, so a conforming shared cache will
/// not keep it — but `no-store` is what turns that from a hope about the intermediary into an
/// instruction, and every other credential-bearing constructor in this file already sends it.
///
/// THE FALLBACK IS REACHABLE, contrary to what this comment said until the 0.9.1 audit. The
/// appended parameters are percent-encoded by [`crate::authorization`], but the REGISTERED redirect
/// URI is pushed verbatim, so a URI with a space in it reaches `HeaderValue::from_str` and fails
/// it, AFTER the code has been minted and persisted.
///
/// WHICH DOOR IS OPEN was named wrongly here until 0.9.2, and the correction matters because it
/// tells the reader where to look. This said "only the RFC 7591 dynamic path validates it — a host
/// calling `register_client` directly supplies a bare `Vec<String>`".
/// [`crate::server::AuthorizationServer::register_client`] DOES validate, through the same
/// predicate the dynamic path uses (`crate::authorization::is_valid_resource_indicator`), and
/// `tests/authorization_code.rs` has held it to that since 0.9.1. Both of this crate's
/// registration entry points are therefore closed.
///
/// What is open is BELOW them: [`crate::store::Storage::put_client`] and
/// [`crate::store::Storage::compare_and_swap_client`] take a [`crate::client::Client`] as given,
/// they are public on a public trait, and `AuthorizationServer::store` hands the host the store to
/// call them on. A host that provisions clients by writing rows — directly, or by migrating a
/// legacy table, or by implementing `Storage` over a database it also writes from elsewhere — puts
/// a `redirect_uris` entry into circulation that no validator in this crate ever saw. That is the
/// path that ends here.
///
/// The 500 is the honest answer at that point; the fix belongs at provisioning, and the failure is
/// named here so that whoever meets it once knows where to look.
fn redirect(location: String) -> Response {
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut resp = respond(StatusCode::FOUND, Body::empty());
            let headers = resp.headers_mut();
            headers.insert(header::LOCATION, value);
            no_store(headers);
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

/// What the RFC 8628 section 5.1 throttle has already been told about the user code a page is
/// about to display.
///
/// ONE CODE ENTRY IS CHARGED ONCE, however many times a single request resolves it. A wrong code
/// posted with `action=approve` is resolved TWICE — once by
/// [`crate::server::AuthorizationServer::approve_device`], and again by the re-render that reports
/// the failure — and charging both halved every budget a host configured: a 200-unit-per-minute
/// limiter documented as allowing twenty wrong entries a minute allowed ten. The error was
/// fail-closed, which is why nothing noticed it. This enum is how the second resolution says "that
/// entry is already counted" without any handler having to remember the rule.
#[derive(Clone, Copy)]
enum CodeEntry {
    /// Nothing on this request has counted this entry yet, so the lookup counts it. Every
    /// separately-attackable entry point is this: the RFC 8628 s3.3.1 deep link, and the
    /// stage-one POST that types a code to see what it is for. Making those free would let an
    /// attacker walk the code space for nothing, which is a worse defect than the double charge.
    Uncharged,
    /// A handler earlier in THIS request already counted this exact entry, so the lookup must not
    /// count it a second time.
    AlreadyCharged,
    /// The throttle already REFUSED this entry earlier in this request. There is nothing to look
    /// up: a lookup would answer, for free, the one question the refusal exists to leave
    /// unanswered.
    Refused,
}

/// The throttle refused to answer for this user code (RFC 8628 section 5.1).
///
/// A distinct outcome from "nothing pending matches", and the distinction is the point: they are
/// the same value to the ATTACKER (see [`THROTTLED_MESSAGE`]) but they are not the same value to
/// this code, which must not tell a user with a perfectly good code that it was not recognised.
struct Throttled;

/// The pending grant behind an entered user code, plus the client's display name, for the
/// consent screen. `Ok(None)` when nothing pending matches.
///
/// Read through the public storage seam rather than through a server method, and deliberately
/// NOT treated as authoritative: expiry and state are re-checked inside
/// `AuthorizationServer::approve_device` against the server's own clock when the user actually
/// approves. This lookup exists to DISPLAY, so being one moment stale costs nothing.
async fn pending_grant<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    entered_user_code: &str,
    entry: CodeEntry,
) -> Result<Option<(DeviceGrant, Option<String>)>, Throttled> {
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
    //
    // `entry` decides whether THIS resolution is the one that pays; see [`CodeEntry`].
    let hooks = state.server.hooks();
    match entry {
        CodeEntry::Refused => return Err(Throttled),
        CodeEntry::Uncharged => {
            if hooks.check(Attempt::DeviceUserCodeEntry) == RateLimitDecision::Deny {
                return Err(Throttled);
            }
        }
        // The check is skipped along with the charge, and deliberately: the handler that charged
        // this entry was ALLOWED through, so asking the limiter again could only refuse a request
        // it has already accepted, halfway through answering it.
        CodeEntry::AlreadyCharged => {}
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
    // Only when this resolution is the one paying for the entry: a second report of one entry is
    // a second charge, which is the whole defect [`CodeEntry`] exists to describe.
    if matches!(entry, CodeEntry::Uncharged) {
        hooks.record(
            Attempt::DeviceUserCodeEntry,
            if grant.is_some() {
                AttemptOutcome::Succeeded
            } else {
                AttemptOutcome::Failed
            },
        );
    }
    let Some(grant) = grant else {
        return Ok(None);
    };
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
        //
        // A storage FAILURE here is deliberately not fatal to the page, and the reason is what the
        // page actually shows: `verification_page` renders the `client_id` and the scope whatever
        // happens, and falls back to the `client_id` when there is no name, because a registration
        // is entitled to have none and because a pretty name is the part a phishing registration
        // chooses. So a failed lookup degrades to exactly the page a nameless registration gets,
        // which still identifies the client (RFC 8628 s3.3) and still requires an affirmative
        // click. Refusing to render at all would mean an unrelated store hiccup ended a login the
        // user is in the middle of, and would do it on the ONE screen where the user is watching.
        .and_then(|c| c.name.clone());
    Ok(Some((grant, name)))
}

/// What a user is told when the RFC 8628 section 5.1 throttle refused their code entry.
///
/// One string for both the POST and the GET path, because they owe the user the same answer. It
/// says nothing about whether the code was real: that is the question the throttle exists to stop
/// being asked, and a page that answered it for refused attempts would hand back the oracle the
/// refusal just took away.
const THROTTLED_MESSAGE: &str = "Too many attempts. Wait and try again.";

/// Render the verification page for whatever `entered` resolves to, with a fresh CSRF token.
///
/// `status` and `message` are what the CALLER already worked out, and they win: the submit handler
/// has an outcome in hand and has chosen the status to match it. They are absent on the display
/// paths, which is where the lookup below gets to decide.
async fn render_verification<S: Storage, C: Clock>(
    state: &Inner<S, C>,
    headers: &HeaderMap,
    entered: &str,
    status: StatusCode,
    message: Option<&str>,
    entry: CodeEntry,
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

    let looked_up = match entered.is_empty() {
        true => Ok(None),
        false => pending_grant(state, entered, entry).await,
    };
    // A code that was typed but matches nothing pending is worth saying so, rather than rendering
    // a consent screen with nothing on it — but a code the THROTTLE refused matches nothing for a
    // completely different reason, and until 0.9.1 this page told those users their perfectly good
    // code was not recognised, at HTTP 200. The sibling POST path has always distinguished the two
    // (see `verification_submit_handler`); this is the deep-linked entry point RFC 8628 s5.4 warns
    // about, so it is the one that most wants the honest status.
    let (status, message) = match (message, &looked_up) {
        (Some(m), _) => (status, Some(m)),
        (None, Err(Throttled)) => (StatusCode::TOO_MANY_REQUESTS, Some(THROTTLED_MESSAGE)),
        (None, Ok(None)) if !entered.is_empty() => (status, Some("That code was not recognised.")),
        (None, _) => (status, None),
    };
    let grant = looked_up.unwrap_or(None);
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
    let pairs = match parse_pairs(uri.query().unwrap_or_default()) {
        Ok(pairs) => pairs,
        Err(TooManyParameters) => return too_many_parameters(),
    };
    let prefill = param(&pairs, "user_code").unwrap_or_default();
    // A separately-attackable entry point, and the one RFC 8628 s5.4 singles out: this request has
    // charged nothing yet, so the lookup charges it.
    render_verification(
        state,
        headers,
        prefill,
        StatusCode::OK,
        None,
        CodeEntry::Uncharged,
    )
    .await
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

    let text = String::from_utf8_lossy(body);
    let form = match parse_pairs(&text) {
        Ok(form) => form,
        Err(TooManyParameters) => return too_many_parameters(),
    };
    let user_code = param(&form, "user_code").unwrap_or_default();

    // RFC 6749 s10.12, defence in depth, in the order that refuses soonest. A host that has
    // explicitly disabled these is not browser-facing and is answering for that itself.
    let protected = !matches!(state.verification, VerificationProtection::Disabled);
    if protected {
        if !same_origin(headers, &state.origin) {
            return html_response(
                StatusCode::FORBIDDEN,
                verification_message("That request did not come from this site."),
            );
        }
        let expected =
            match &state.verification {
                VerificationProtection::Tokens { consume, .. } => consume(headers),
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
        // No code was entered, so there is nothing to look up and nothing to charge either way.
        return render_verification(
            state,
            headers,
            "",
            StatusCode::BAD_REQUEST,
            Some("Enter the code shown on your device."),
            CodeEntry::Uncharged,
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
        // Stage one of the two-stage form: this request has resolved the code nowhere else, and a
        // POST of a guessed code is exactly what the throttle counts, so it pays here.
        return render_verification(
            state,
            headers,
            user_code,
            StatusCode::OK,
            None,
            CodeEntry::Uncharged,
        )
        .await;
    }

    // Approval binds the grant to a USER, so the same rule as the authorization endpoint applies:
    // without an authenticated resource owner there is nobody to bind it to.
    let subject = match state.subject(headers) {
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
                DeviceApprovalError::RateLimited => THROTTLED_MESSAGE,
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
            //
            // `approve_device`/`deny_device` resolved this exact code entry a few lines up, and
            // charged the throttle for it. The re-render must not charge it again — that is the
            // double charge `CodeEntry` documents — and when the throttle REFUSED, it must not
            // look the code up at all, because a refused attempt that still rendered the client
            // and the scope would be the oracle handed back.
            let entry = match e {
                DeviceApprovalError::RateLimited => CodeEntry::Refused,
                _ => CodeEntry::AlreadyCharged,
            };
            render_verification(state, headers, user_code, status, Some(message), entry).await
        }
    }
}

/// Escape a value for an RFC 9110 s5.6.4 quoted-string: `\` and `"` become `\\` and `\"`.
///
/// Borrows when there is nothing to escape, which is every well-formed issuer, so the ordinary 401
/// costs no allocation. See the `challenge` construction for why a value this crate treats as a URL
/// is nonetheless escaped.
fn escape_quoted_string(value: &str) -> Cow<'_, str> {
    if !value.contains(['"', '\\']) {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    Cow::Owned(out)
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
