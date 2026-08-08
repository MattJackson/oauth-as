// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The authorization endpoint (RFC 6749 section 4.1) under the OAuth 2.1 constraints: `code` is
//! the only response type (the implicit grant is removed), PKCE is REQUIRED, only `S256` is
//! offered, and registered redirect URIs match exactly.
//!
//! # Why the request type is lenient
//!
//! [`AuthorizationRequest`] holds raw, optional text rather than parsed enums. A server cannot
//! reject what it cannot represent, and rejecting correctly is most of what this endpoint does:
//! a request with no `code_challenge`, or with `response_type=token`, has to reach the state
//! machine so the machine can answer it the way the RFC prescribes. Parsing into
//! [`ValidatedAuthorizationRequest`] is what validation MEANS here, and only the validated form
//! can mint a code.
//!
//! # Why the two error shapes are different
//!
//! RFC 6749 section 4.1.2.1 splits authorization errors in two, and the split is a security
//! boundary rather than a stylistic one. If the client or the redirect URI cannot be validated,
//! the AS MUST NOT redirect: the redirect target is precisely what an attacker would be trying to
//! choose, so reporting the error to it would hand over the thing being protected. Every other
//! error goes back to the (already validated) redirect URI as query parameters.
//!
//! # Allocation
//!
//! Request fields are [`Cow`], so a host parsing a query string that needs no percent-decoding
//! borrows it and allocates nothing. Only the validated form, which outlives the request while a
//! consent screen is shown, owns its data.

use std::borrow::Cow;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::error::{ErrorCode, ErrorResponse};
use crate::scope::ScopeSet;

/// `response_type` values this server will ever accept. OAuth 2.1 removes `token` (implicit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// The authorization-code response type.
    #[serde(rename = "code")]
    Code,
}

/// PKCE challenge methods this server offers (RFC 7636). OAuth 2.1 requires `S256`; `plain` is
/// deliberately not implemented, and is not advertised, because accepting it is a downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))`, no padding.
    S256,
}

/// The raw authorization request as it arrives on the wire (RFC 6749 section 4.1.1 plus the RFC
/// 7636 PKCE parameters). The host parses its query string into this; every member is optional
/// because every member can be absent in a real (invalid) request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorizationRequest<'a> {
    /// Must be `code`.
    pub response_type: Option<Cow<'a, str>>,
    /// The requesting client.
    pub client_id: Option<Cow<'a, str>>,
    /// Requested redirect target; must exact-match a registered URI when present.
    pub redirect_uri: Option<Cow<'a, str>>,
    /// Requested scope, space delimited; absent means the client's registered default.
    pub scope: Option<Cow<'a, str>>,
    /// Opaque client state, echoed back verbatim.
    pub state: Option<Cow<'a, str>>,
    /// The PKCE challenge (REQUIRED in OAuth 2.1 for the authorization code grant).
    pub code_challenge: Option<Cow<'a, str>>,
    /// The PKCE method; only `S256`.
    pub code_challenge_method: Option<Cow<'a, str>>,
}

impl<'a> AuthorizationRequest<'a> {
    /// Collect a request from already-decoded `(name, value)` query pairs.
    ///
    /// Unknown parameters are ignored, which RFC 6749 section 3.1 requires. A repeated parameter
    /// keeps the FIRST occurrence: section 3.1 says a parameter MUST NOT appear more than once,
    /// and last-wins is the smuggling-friendly choice when two intermediaries disagree about
    /// which copy counts.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<Cow<'a, str>>,
    {
        let mut req = AuthorizationRequest::default();
        for (k, v) in pairs {
            let slot = match k.as_ref() {
                "response_type" => &mut req.response_type,
                "client_id" => &mut req.client_id,
                "redirect_uri" => &mut req.redirect_uri,
                "scope" => &mut req.scope,
                "state" => &mut req.state,
                "code_challenge" => &mut req.code_challenge,
                "code_challenge_method" => &mut req.code_challenge_method,
                _ => continue,
            };
            if slot.is_none() {
                *slot = Some(v.into());
            }
        }
        req
    }
}

/// A request that has passed validation: the client exists, is allowed this grant, the redirect
/// URI is one of its registrations, and the PKCE parameters are well formed. Only this form can
/// mint a code, so an unvalidated request cannot reach issuance by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    /// The validated client.
    pub client_id: ClientId,
    /// The exact registered redirect URI this request resolved to.
    pub redirect_uri: String,
    /// The scope that will be granted on approval.
    pub scope: ScopeSet,
    /// The request's `state`, to be echoed on either outcome.
    pub state: Option<String>,
    /// The PKCE challenge to record against the issued code.
    pub code_challenge: String,
    /// The PKCE method (only `S256`).
    pub code_challenge_method: CodeChallengeMethod,
}

impl ValidatedAuthorizationRequest {
    /// The redirect describing the user refusing consent (RFC 6749 section 4.1.2.1
    /// `access_denied`). A refusal is an answer the client is entitled to receive, not an error
    /// page.
    pub fn denied(&self) -> AuthorizationErrorRedirect {
        AuthorizationErrorRedirect {
            redirect_uri: self.redirect_uri.clone(),
            error: ErrorResponse::new(ErrorCode::AccessDenied),
            state: self.state.clone(),
        }
    }
}

/// The success redirect parameters (RFC 6749 section 4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The single-use authorization code.
    pub code: String,
    /// The request's `state`, echoed verbatim; REQUIRED iff the request carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl AuthorizationResponse {
    /// The `Location` header value for the success redirect.
    pub fn location(&self, redirect_uri: &str) -> String {
        let mut out = String::with_capacity(redirect_uri.len() + self.encoded_len());
        out.push_str(redirect_uri);
        let mut sep = query_separator(redirect_uri);
        append_param(&mut out, &mut sep, "code", &self.code);
        if let Some(state) = &self.state {
            append_param(&mut out, &mut sep, "state", state);
        }
        out
    }

    /// A worst-case size for the appended query, so `location` allocates exactly once.
    fn encoded_len(&self) -> usize {
        6 + self.code.len() * 3 + self.state.as_ref().map_or(0, |s| 7 + s.len() * 3)
    }
}

/// An authorization error delivered by redirecting the user agent back to the client (RFC 6749
/// section 4.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationErrorRedirect {
    /// The VALIDATED redirect URI. Never a URI supplied by an unvalidated request.
    pub redirect_uri: String,
    /// The error to report.
    pub error: ErrorResponse,
    /// The request's `state`, echoed so the client can correlate the failure.
    pub state: Option<String>,
}

impl AuthorizationErrorRedirect {
    /// The `Location` header value for the error redirect.
    pub fn location(&self) -> String {
        let mut out = String::with_capacity(self.redirect_uri.len() + 96);
        out.push_str(&self.redirect_uri);
        let mut sep = query_separator(&self.redirect_uri);
        append_param(&mut out, &mut sep, "error", self.error.error.as_str());
        if let Some(d) = &self.error.error_description {
            append_param(&mut out, &mut sep, "error_description", d);
        }
        if let Some(u) = &self.error.error_uri {
            append_param(&mut out, &mut sep, "error_uri", u);
        }
        if let Some(state) = &self.state {
            append_param(&mut out, &mut sep, "state", state);
        }
        out
    }
}

/// How an authorization request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    /// RFC 6749 section 4.1.2.1: the client or the redirect URI could not be validated, so the AS
    /// MUST NOT redirect. The host renders this to the user directly; 400 is the conventional
    /// status.
    Direct(ErrorResponse),
    /// The error is reported to the client by redirecting to its validated redirect URI.
    Redirect(AuthorizationErrorRedirect),
}

impl AuthorizationError {
    /// The HTTP status the host should use: 302 for the redirect form, otherwise a direct status.
    pub fn http_status(&self) -> u16 {
        match self {
            // invalid_client's 401 belongs to the token endpoint's WWW-Authenticate exchange; at
            // the authorization endpoint there is no client authentication to challenge, so a
            // refused request is a plain 400.
            AuthorizationError::Direct(e) if e.error == ErrorCode::ServerError => 500,
            AuthorizationError::Direct(_) => 400,
            AuthorizationError::Redirect(_) => 302,
        }
    }
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationError::Direct(e) => write!(f, "{e}"),
            AuthorizationError::Redirect(r) => write!(f, "{}", r.error),
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// What an issued authorization code became, once redeemed.
///
/// Consumed codes are RETAINED until their expiry rather than deleted, because RFC 6749 section
/// 4.1.2 and RFC 9700 section 4.1.1 want a replayed code to revoke the tokens it already minted.
/// Deleting the record on redemption would make a replay indistinguishable from a typo, and the
/// stolen access token would stay live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationCodeState {
    /// Issued and not yet redeemed.
    Issued,
    /// Already redeemed, recording what it minted so a replay can revoke it.
    Consumed {
        /// The access token issued.
        access_token: String,
        /// The refresh token issued, if any.
        refresh_token: Option<String>,
    },
}

/// A persisted authorization code (RFC 6749 section 4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodeRecord {
    /// The code string (the storage key).
    pub code: String,
    /// The client the code was issued to; presentation by any other client is `invalid_grant`.
    pub client_id: ClientId,
    /// The redirect URI the authorization request used; the token request must present the same.
    pub redirect_uri: String,
    /// The scope the user approved.
    pub scope: ScopeSet,
    /// The authenticated resource owner.
    pub subject: String,
    /// The recorded PKCE challenge (RFC 7636 section 4.4).
    pub code_challenge: String,
    /// The recorded PKCE method.
    pub code_challenge_method: CodeChallengeMethod,
    /// Expiry instant; the code is dead at and after this instant.
    pub expires_at: SystemTime,
    /// Whether the code has been redeemed, and what it produced.
    pub state: AuthorizationCodeState,
}

/// `?` if the URI has no query yet, `&` if it does.
fn query_separator(uri: &str) -> char {
    if uri.contains('?') {
        '&'
    } else {
        '?'
    }
}

/// Append `name=value` with `value` percent-encoded, advancing the separator after first use.
fn append_param(out: &mut String, sep: &mut char, name: &str, value: &str) {
    out.push(*sep);
    *sep = '&';
    out.push_str(name);
    out.push('=');
    percent_encode_into(out, value);
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Deliberately conservative: encoding a character that did not strictly require it is harmless,
/// while failing to encode `&`, `=` or `#` lets a value forge or truncate the query. That is a
/// parameter-injection bug in the one place it must never happen.
fn percent_encode_into(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
}

#[cfg(test)]
#[path = "tests/authorization.rs"]
mod tests;
