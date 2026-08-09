// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

// docs.rs builds this crate with `--cfg docsrs` and every feature on (see the
// `[package.metadata.docs.rs]` table in Cargo.toml), so that a reader evaluating the crate sees
// the WHOLE of it, with a badge on each item naming the feature that turns it on. `doc_cfg` is
// still nightly-only, which is why it is reached for through `cfg_attr`: a stable build never
// evaluates this attribute and so never needs the unstable feature.
#![cfg_attr(docsrs, feature(doc_cfg))]
// There is no `unsafe` in this crate and this is what keeps it that way. An authorization server
// parses attacker-supplied text on endpoints that take no credential, so "we are careful" is not a
// memory-safety argument; a compiler error is. (`tests/allocation.rs` installs a counting global
// allocator and does need `unsafe`, but a test target is a separate compilation unit and this
// attribute does not reach it.)
#![forbid(unsafe_code)]
// This is a published API. An undocumented public item is a question a consumer can only answer by
// reading the source, which is exactly the position this crate exists to spare them.
#![warn(missing_docs)]

//! An embeddable OAuth 2.1 Authorization Server library.
//!
//! This crate is the AUTHORIZATION SERVER half of OAuth: it registers clients, runs grant state
//! machines, issues and introspects tokens, and produces exactly the wire shapes the RFCs define.
//! It is a LIBRARY, not a server binary: the host owns the HTTP listener, TLS, rate limiting, and
//! persistence. The host hands request parameters to [`server::AuthorizationServer`] and
//! serializes the returned response/error types (they carry their own `serde` shapes and HTTP
//! status codes), or turns on the optional `http` feature and gets that wire surface written for
//! it.
//!
//! # What is here
//!
//! ALWAYS COMPILED, no feature and no dependency beyond serde, sha2, base64 and getrandom:
//!
//! - Protocol types mirroring the specs in OUR OWN structs (a deliberate project rule; no third
//!   party's generated types): [`client::Client`], [`grant::GrantType`], [`token::TokenResponse`],
//!   [`scope::ScopeSet`], [`authorization::AuthorizationRequest`], and the RFC 6749 section 5.2 /
//!   RFC 8628 section 3.5 error object ([`error::ErrorResponse`]).
//! - The authorization code grant with MANDATORY PKCE ([`authorization`]), the OAuth 2.1 stance:
//!   validation, single-use codes, exact redirect-URI matching, and replay detection that revokes
//!   the whole issued family.
//! - The RFC 8628 device authorization grant, as a full state machine ([`device`]):
//!   `authorization_pending`, `slow_down` (with the mandated 5 second interval increase),
//!   `expired_token`, `access_denied`, single-use redemption, and user-code normalization per RFC
//!   8628 section 6.1.
//! - Token issuance, introspection, revocation, and refresh rotation ([`token`]): single use, with
//!   an absolute family lifetime.
//! - The RFC 8414 metadata document ([`metadata`]) and RFC 7591 dynamic client registration
//!   ([`registration`]), the latter off unless configured and refusing every registration until a
//!   policy is installed.
//! - PKCE S256 primitives ([`pkce`]), verified against the RFC 7636 appendix B vector.
//! - A storage seam ([`store::Storage`]) the HOST implements, plus [`store::MemoryStorage`] for
//!   tests and single-process embedding. This crate never assumes what the host's store looks like.
//!
//! OPTIONAL, each its own cargo feature and every one of them off by default:
//!
//! - `http`, an HTTP service over all of the above, in `http` 1.x and `http-body` 1.x with no web
//!   framework and no async runtime. `axum` adds a thin `impl From<..> for axum::Router` adapter
//!   for hosts that want one; nothing else in the crate knows axum exists.
//! - `jwt` (RFC 9068 `at+jwt` access tokens and an RFC 7517 JWKS document), `dpop` (RFC 9449
//!   sender-constrained tokens), `mtls` (RFC 8705 certificate-bound tokens and client
//!   authentication), `client_assertion` (RFC 7523 `private_key_jwt` and `client_secret_jwt`).
//! - `par` and `jar` (RFC 9126 pushed authorization requests, RFC 9101 signed request objects),
//!   `rar` (RFC 9396 `authorization_details`), `token-exchange` (RFC 8693), `consent` (consent
//!   records, withdrawal with a revocation cascade, and RFC 9470 step-up authentication),
//!   `resource-metadata` (RFC 9728).
//! - `test-util`, a RUNNABLE conformance harness for the [`store::Storage`] contract that a host
//!   runs from its own test suite against its OWN store.
//!
//! On docs.rs every item above is rendered with the feature that turns it on. In a local build,
//! `cargo doc --all-features` is the equivalent view.
//!
// The quickstart wires the optional HTTP service, so it exists only when that feature does.
// Written as a `doc =` attribute rather than as `//!` because a doc comment cannot be
// conditionally compiled, and a code block that does not compile in the configuration it is
// rendered under is worse than no code block.
#![cfg_attr(
    feature = "http",
    doc = r#"
# Quick start

Four things a host owns, and none of them can be defaulted: a config, a store, a sweep, and the
two seams the interactive endpoints refuse without.

```no_run
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use oauth_as::{
    AuthorizationServer, ConsentDecision, MemoryStorage, ServerConfig, ServiceBuilder, Storage,
};

# fn wire() -> Result<(), Box<dyn std::error::Error>> {
// The issuer identity, and where a user goes to type an RFC 8628 device code.
let config = ServerConfig::new("https://as.example.com", "https://as.example.com/device");

// MemoryStorage is single process. A multi-node host implements `Storage` itself and proves
// its `take_*` really is an atomic remove-and-return with the `test-util` harness.
let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));

// THE SWEEP. Nothing in this crate reclaims an expired record; this task is the only thing
// that does, and the device authorization endpoint takes no credential, so an unswept store
// grows at a rate an attacker chooses.
let sweeper = Arc::clone(&server);
tokio::spawn(async move {
    loop {
        let _ = sweeper.store().sweep_expired(SystemTime::now()).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
});

// Both seams are REQUIRED: with no consent resolver the authorization endpoint answers 403
// rather than deciding on the user's behalf. Returning `Approve` unconditionally, as here, is
// an AUTO-APPROVING authorization server (RFC 6749 s10.12); a real host reads its own session
// here and returns `ConsentDecision::Respond` with a consent screen. See
// `examples/production_server.rs` for both done properly, plus CSRF and audit.
let service = ServiceBuilder::new(server)
    .with_subject_resolver(|_headers| Some("user-1".to_string()))
    .with_consent_resolver(|_request| ConsentDecision::Approve)
    .build()?;
# let _ = service;
# Ok(())
# }
```
"#
)]
//!
//! # Host seams: observation, throttling, and secret storage
//!
//! Three things a real deployment needs that this library deliberately does not do itself, each
//! installed on the server and each costing an uninstalled host nothing (see [`events::Hooks`]):
//!
//! - AUDIT EVENTS ([`events::EventSink`]). This crate logs nothing on its own. A host that wants
//!   to see issuance, refusal, or the two compromise events (authorization code replay, refresh
//!   token reuse) installs a sink. Events carry no credential of any kind; see the [`events`]
//!   module docs for the rule and for why the refresh `family_id` is safe to carry.
//! - RATE LIMITING ([`events::RateLimiter`]). THIS LIBRARY DOES NOT RATE LIMIT. It never sees a
//!   request, so it has no caller, IP, session or user to count against. RFC 8628 section 5.1
//!   makes the device user code's entropy adequate only IN COMBINATION WITH rate limiting of code
//!   entry, so a deployment offering the device grant MUST install one.
//! - CLIENT SECRET STORAGE ([`client::SecretHash`], [`client::SecretVerifier`]). Hosts should
//!   store a one-way verifier, not the secret. The built-in scheme needs no host code; a host
//!   whose policy names argon2id or an HSM installs a verifier.
//! - WHEN AND HOW THE USER LOGGED IN (the `consent` module's `Authentication`, behind the
//!   `consent` feature). This crate cannot authenticate anybody and will not grow a login page, so a
//!   host that wants RFC 9470 step-up authentication REPORTS when and how it authenticated
//!   the user; the library records that report and enforces `max_age` and `acr_values`
//!   against it. The report is taken at face value, because there is nothing here that
//!   could check it. See the `consent` module docs for the whole boundary.
//! - WHO MAY REGISTER ([`registration::RegistrationPolicy`]). RFC 7591 dynamic client registration
//!   is OFF unless [`server::ServerConfig::registration`] is set, and even then every registration
//!   is REFUSED until a policy is installed. RFC 7591 section 5: an open registration endpoint
//!   lets anyone on the internet mint a client, which weakens every threat model that assumed
//!   controlling a registered client was hard. See the [`registration`] module docs before
//!   enabling it.
//!
//! # Zero cost until enabled
//!
//! A host that compiles this crate in but never turns it on must pay nothing at runtime. The crate
//! keeps that promise structurally: there are NO global statics, NO lazy singletons, NO background
//! tasks, and no allocation at load time. The only allocation entry point is
//! [`server::AuthorizationServer::new`] (plus whatever `Storage` the host constructs to pass in),
//! so "enabled by config" for a host means exactly "construct the value when config says so".
//!
//! # THE SWEEP: an obligation that comes with the no-background-tasks promise
//!
//! "No background tasks" has a price and the HOST pays it. Nothing here reclaims an expired
//! record; [`store::Storage::sweep_expired`] does, and it runs when the host calls it and at no
//! other time. A host that never calls it has a store that only grows, and the growth is
//! ATTACKER-PACED: the RFC 8628 section 3.1 device authorization endpoint takes no credential
//! from a public client, so anyone who can open a socket can allocate a device grant per request
//! forever. Expiry is enforced on read, so an unswept deployment is not insecure, it is unbounded,
//! which is a process that dies rather than a grant that leaks.
//!
//! So: spawn one task per process, on an interval well under the shortest artifact lifetime
//! ([`server::ServerConfig::device_code_ttl`], 600 seconds by default), log a failure and retry on
//! the next tick rather than returning. `examples/production_server.rs` does exactly that, with
//! the reasoning, alongside every other seam a real deployment has to wire.
//!
//! # A worked production wiring
//!
//! `examples/production_server.rs` is the one to copy: it wires the storage contract, a rate
//! limiter, a real consent screen, the device form's CSRF tokens, a session-backed subject
//! resolver, the sweeper, an audit sink and signing key management, and says at each site what
//! breaks if you get it wrong. `examples/conformance_server.rs` is NOT: it is a fixture for the
//! black-box harness, and it auto-approves consent, disables the CSRF protection and signs with a
//! key printed in an RFC.
//!
//! # Concurrency contract
//!
//! Single-use artifacts (device codes at redemption, rotating refresh tokens) are consumed through
//! the storage trait's atomic `take_*` operations. [`store::MemoryStorage`] satisfies the contract
//! with a mutex; a multi-node host must back `take_*` with a genuinely atomic remove-and-return
//! (compare-and-set, `DELETE ... RETURNING`, or equivalent) or single-use guarantees become
//! per-node only.

// MODULE DECLARATIONS carry no doc comment of their own, deliberately. Each module's summary
// lives in its OWN file as `//!` docs, in one place, next to the code it describes; a second
// summary here would be a second thing to keep true. The `doc(cfg)` attributes are what tell a
// docs.rs reader which feature each one needs, and they say it on the module page too, which a
// sentence written here never did.
pub mod authorization;
pub mod client;
#[cfg(feature = "client_assertion")]
#[cfg_attr(docsrs, doc(cfg(feature = "client_assertion")))]
pub mod client_assertion;
#[cfg(feature = "consent")]
#[cfg_attr(docsrs, doc(cfg(feature = "consent")))]
pub mod consent;
pub mod device;
#[cfg(feature = "dpop")]
#[cfg_attr(docsrs, doc(cfg(feature = "dpop")))]
pub mod dpop;
pub mod error;
pub mod events;
pub mod grant;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod http;
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub mod jwt;
pub mod metadata;
#[cfg(feature = "mtls")]
#[cfg_attr(docsrs, doc(cfg(feature = "mtls")))]
pub mod mtls;
#[cfg(any(feature = "par", feature = "jar"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "par", feature = "jar"))))]
pub mod par;
pub mod pkce;
#[cfg(feature = "rar")]
#[cfg_attr(docsrs, doc(cfg(feature = "rar")))]
pub mod rar;
pub mod rate_limit;
pub mod registration;
#[cfg(feature = "resource-metadata")]
#[cfg_attr(docsrs, doc(cfg(feature = "resource-metadata")))]
pub mod resource_metadata;
pub mod scope;
pub mod server;
#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod storage_conformance;
pub mod store;
pub mod token;
#[cfg(feature = "token-exchange")]
#[cfg_attr(docsrs, doc(cfg(feature = "token-exchange")))]
pub mod token_exchange;

pub use authorization::{
    AuthorizationCodeRecord, AuthorizationCodeState, AuthorizationError,
    AuthorizationErrorRedirect, AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod,
    ResponseType, ValidatedAuthorizationRequest,
};
pub use client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash, SecretVerifier};
#[cfg(feature = "client_assertion")]
#[cfg_attr(docsrs, doc(cfg(feature = "client_assertion")))]
pub use client_assertion::{
    AssertionFailure, AssertionKeys, VerifiedAssertion, CLIENT_ASSERTION_TYPE, CLIENT_SECRET_JWT,
    PRIVATE_KEY_JWT,
};
#[cfg(feature = "consent")]
#[cfg_attr(docsrs, doc(cfg(feature = "consent")))]
pub use consent::{
    step_up_challenge, Authentication, AuthenticationRequirement, ConsentRecord, StepUpFailure,
};
pub use device::{DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState};
#[cfg(feature = "dpop")]
#[cfg_attr(docsrs, doc(cfg(feature = "dpop")))]
pub use dpop::{DpopFailure, VerifiedProof, DPOP_HEADER, DPOP_TOKEN_TYPE};
pub use error::{ErrorCode, ErrorResponse};
pub use events::{
    Attempt, AttemptOutcome, ClientAuthFailure, Event, EventSink, Hooks, RateLimitDecision,
    RateLimiter,
};
pub use grant::GrantType;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use http::{
    AuthorizationService, Body, ConsentDecision, ConsentRequest, ConsentResolver, CsrfTokenHook,
    ServiceBuilder, ServiceError, SubjectResolver,
};
pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};
#[cfg(feature = "mtls")]
#[cfg_attr(docsrs, doc(cfg(feature = "mtls")))]
pub use mtls::{
    CertificateThumbprint, ClientCertificate, ExpectedSubject, MtlsClientRegistration,
    MtlsRegistrationError, RegisteredCertificates, SELF_SIGNED_TLS_CLIENT_AUTH, TLS_CLIENT_AUTH,
    TLS_CLIENT_AUTH_SAN_DNS, TLS_CLIENT_AUTH_SAN_EMAIL, TLS_CLIENT_AUTH_SAN_IP,
    TLS_CLIENT_AUTH_SAN_URI, TLS_CLIENT_AUTH_SUBJECT_DN,
};
#[cfg(feature = "jar")]
#[cfg_attr(docsrs, doc(cfg(feature = "jar")))]
pub use par::{
    JarConfig, RegisteredRequestObjectKey, RequestObjectAlg, RequestObjectKeyError,
    RequestObjectKeys, REQUEST_OBJECT_SIGNING_ALGS, REQUEST_OBJECT_TYP,
};
#[cfg(feature = "par")]
#[cfg_attr(docsrs, doc(cfg(feature = "par")))]
pub use par::{
    ParConfig, PushedAuthorizationRequest, PushedAuthorizationResponse, REQUEST_URI_PREFIX,
};
#[cfg(feature = "rar")]
#[cfg_attr(docsrs, doc(cfg(feature = "rar")))]
pub use rar::{
    AuthorizationDetail, AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_BYTES,
    MAX_AUTHORIZATION_DETAILS_DEPTH, MAX_AUTHORIZATION_DETAILS_ELEMENTS,
};
pub use rate_limit::{FixedWindowRateLimiter, RateLimitConfig};
pub use registration::{
    ClientInformation, ClientMetadata, RegistrationAttempt, RegistrationConfig,
    RegistrationDecision, RegistrationErrorCode, RegistrationErrorResponse, RegistrationFailure,
    RegistrationPolicy,
};
#[cfg(feature = "resource-metadata")]
#[cfg_attr(docsrs, doc(cfg(feature = "resource-metadata")))]
pub use resource_metadata::{
    BearerMethod, ProtectedResourceConfig, ProtectedResourceMetadata,
    PROTECTED_RESOURCE_WELL_KNOWN_PATH,
};
pub use scope::{Scope, ScopeSet};
// `DeviceApprovalError` is re-exported here as of 0.2.0: a host's verification UI has to match on
// it to tell "unknown code" from "too many attempts", and having to reach into `server::` for the
// error type of a re-exported method was an oversight rather than a decision.
pub use server::{
    AuthorizationServer, ClientCredential, Clock, DeviceApprovalError, ServerConfig, SystemClock,
    TokenRequest, TokenRequestContext, UserApproval, MIN_USER_CODE_LENGTH,
};
pub use store::{MemoryStorage, Storage, StorageError};
#[cfg(feature = "dpop")]
#[cfg_attr(docsrs, doc(cfg(feature = "dpop")))]
pub use token::Confirmation;
pub use token::{
    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,
    TokenType, TokenTypeHint,
};
#[cfg(feature = "token-exchange")]
#[cfg_attr(docsrs, doc(cfg(feature = "token-exchange")))]
pub use token_exchange::{
    ActClaim, ExchangeSemantics, ExchangedToken, TokenExchange, TokenExchangeRequest,
    TokenExchangeResponse, TokenTypeIdentifier, TOKEN_EXCHANGE_GRANT_URN,
};
