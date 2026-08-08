// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! An embeddable OAuth 2.1 Authorization Server library.
//!
//! This crate is the AUTHORIZATION SERVER half of OAuth: it registers clients, runs grant state
//! machines, issues and introspects tokens, and produces exactly the wire shapes the RFCs define.
//! It is a LIBRARY, not a server binary: the host owns the HTTP listener, the routes, TLS, rate
//! limiting, and persistence. The host hands request parameters to [`server::AuthorizationServer`]
//! and serializes the returned response/error types (they carry their own `serde` shapes and HTTP
//! status codes).
//!
//! What is implemented in this pass:
//!
//! - Core protocol types mirroring the specs in OUR OWN structs (a deliberate project rule; no
//!   third party's generated types): [`client::Client`], [`grant::GrantType`],
//!   [`token::TokenResponse`], [`scope::ScopeSet`], [`authorization::AuthorizationRequest`], and
//!   the RFC 6749 section 5.2 / RFC 8628 section 3.5 error object ([`error::ErrorResponse`]).
//! - The RFC 8628 device authorization grant, as a full state machine: `authorization_pending`,
//!   `slow_down` (with the mandated 5 second interval increase), `expired_token`, `access_denied`,
//!   single-use redemption, and user-code normalization per RFC 8628 section 6.1.
//! - Refresh-token rotation (single use, absolute lifetime), the OAuth 2.1 stance.
//! - PKCE S256 primitives ([`pkce`]), verified against the RFC 7636 appendix B vector.
//! - A storage seam ([`store::Storage`]) the HOST implements, plus [`store::MemoryStorage`] for
//!   tests and single-process embedding. This crate never assumes what the host's store looks like.
//!
//! The interactive authorization-code endpoint machine (login page, redirects) is a later pass;
//! its request/response types are already pinned in [`authorization`] so the wire shape cannot
//! drift when it lands.
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
//! # Concurrency contract
//!
//! Single-use artifacts (device codes at redemption, rotating refresh tokens) are consumed through
//! the storage trait's atomic `take_*` operations. [`store::MemoryStorage`] satisfies the contract
//! with a mutex; a multi-node host must back `take_*` with a genuinely atomic remove-and-return
//! (compare-and-set, `DELETE ... RETURNING`, or equivalent) or single-use guarantees become
//! per-node only.

pub mod authorization;
pub mod client;
/// RFC 7523 JWT client authentication (`private_key_jwt`, `client_secret_jwt`), behind the
/// `client_assertion` cargo feature (off by default, and implying `jwt`). Without it a deployment
/// whose security policy forbids transmitting a shared secret cannot use this crate at all.
#[cfg(feature = "client_assertion")]
pub mod client_assertion;
pub mod device;
/// RFC 9449 DPoP sender-constrained access tokens, behind the `dpop` cargo feature (off by
/// default, and implying `jwt`). Without it every token this crate issues is a bearer token, so a
/// stolen one is usable by whoever stole it.
#[cfg(feature = "dpop")]
pub mod dpop;
pub mod error;
pub mod events;
pub mod grant;
/// An OPTIONAL axum router over the server, behind the `http` cargo feature (off by default).
#[cfg(feature = "http")]
pub mod http;
/// RFC 9068 `at+jwt` access tokens and the RFC 7517 JWKS document, behind the `jwt` cargo feature
/// (off by default). Opaque tokens remain the default: RFC 9068 is an optional profile, not an
/// OAuth 2.1 requirement, and signed tokens earn their keep only when resource servers are
/// separate processes that should not call introspection on every request.
#[cfg(feature = "jwt")]
pub mod jwt;
pub mod metadata;
pub mod pkce;
pub mod registration;
/// RFC 9728 protected resource metadata, behind the `resource-metadata` cargo feature
/// (off by default). Read the module docs before using it: the document RFC 9728 defines
/// is published by a RESOURCE server, which this crate is not.
#[cfg(feature = "resource-metadata")]
pub mod resource_metadata;
pub mod scope;
pub mod server;
pub mod store;
pub mod token;
/// RFC 8693 token exchange, behind the `token-exchange` cargo feature (off by default).
#[cfg(feature = "token-exchange")]
pub mod token_exchange;

pub use authorization::{
    AuthorizationCodeRecord, AuthorizationCodeState, AuthorizationError,
    AuthorizationErrorRedirect, AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod,
    ResponseType, ValidatedAuthorizationRequest,
};
pub use client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash, SecretVerifier};
#[cfg(feature = "client_assertion")]
pub use client_assertion::{
    AssertionFailure, AssertionKeys, VerifiedAssertion, CLIENT_ASSERTION_TYPE, CLIENT_SECRET_JWT,
    PRIVATE_KEY_JWT,
};
pub use device::{DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState};
#[cfg(feature = "dpop")]
pub use dpop::{DpopFailure, VerifiedProof, DPOP_HEADER, DPOP_TOKEN_TYPE};
pub use error::{ErrorCode, ErrorResponse};
pub use events::{
    Attempt, AttemptOutcome, ClientAuthFailure, Event, EventSink, Hooks, RateLimitDecision,
    RateLimiter,
};
pub use grant::GrantType;
#[cfg(feature = "http")]
pub use http::{
    ConsentDecision, ConsentRequest, ConsentResolver, CsrfTokenHook, RouterBuilder, RouterError,
    SubjectResolver,
};
pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};
pub use registration::{
    ClientInformation, ClientMetadata, RegistrationAttempt, RegistrationConfig,
    RegistrationDecision, RegistrationErrorCode, RegistrationErrorResponse, RegistrationFailure,
    RegistrationPolicy,
};
#[cfg(feature = "resource-metadata")]
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
    TokenRequest, TokenRequestContext, MIN_USER_CODE_LENGTH,
};
pub use store::{MemoryStorage, Storage, StorageError};
#[cfg(feature = "dpop")]
pub use token::Confirmation;
pub use token::{
    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,
    TokenType, TokenTypeHint,
};
#[cfg(feature = "token-exchange")]
pub use token_exchange::{
    ActClaim, ExchangeSemantics, ExchangedToken, TokenExchange, TokenExchangeRequest,
    TokenExchangeResponse, TokenTypeIdentifier, TOKEN_EXCHANGE_GRANT_URN,
};
