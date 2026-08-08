// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Token wire and storage shapes: the RFC 6749 section 5.1 success response, plus the records the
//! server persists through [`crate::store::Storage`]. Access and refresh tokens here are OPAQUE
//! random strings; structured (JWT) access tokens are a possible later addition and would slot in
//! at issuance without changing these shapes.

use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::scope::ScopeSet;

/// `token_type` values this server issues. Only `Bearer` (RFC 6750); the registered value is
/// case-insensitive on the wire but conventionally spelled `Bearer`, which the rename pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// RFC 6750 bearer token.
    #[serde(rename = "Bearer")]
    Bearer,
    /// RFC 9449 section 5 sender-constrained token, bound to the key the client proved possession
    /// of. The spelling is `DPoP`, exactly, because RFC 9449 section 7.1 makes it the HTTP
    /// authentication scheme name the client will present the token under.
    #[cfg(feature = "dpop")]
    #[serde(rename = "DPoP")]
    Dpop,
}

/// The RFC 6749 section 5.1 successful token response.
///
/// `Debug` is hand-written (see below) rather than derived: `access_token` and `refresh_token` are
/// bearer credentials (RFC 6750 section 1 for the access token; RFC 9700 section 4.14.2 for the
/// refresh token), so a host doing the obvious `tracing::debug!(?response)` must not thereby write
/// either to its logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The opaque access token.
    pub access_token: String,
    /// Always `Bearer` from this server.
    pub token_type: TokenType,
    /// Lifetime in seconds (RECOMMENDED by the RFC; this server always includes it).
    pub expires_in: u64,
    /// The rotating refresh token, when the grant and server config produce one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Space-delimited granted scope. This server always includes it when non-empty, which also
    /// satisfies the section 3.3 requirement to report a scope differing from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Hand-written so neither `access_token` nor `refresh_token` ever prints. `refresh_token` keeps
/// its `Some`/`None` shape (via `redact_opt`, mirrored from [`crate::server::TokenRequest`]'s
/// hand-written `Debug`): whether a refresh token was issued at all is diagnostic, not secret, and
/// collapsing `Some("[redacted]")` and `None` to the same output would hide that.
impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redact_opt<T>(value: &Option<T>) -> Option<&'static str> {
            value.as_ref().map(|_| "[redacted]")
        }
        f.debug_struct("TokenResponse")
            .field("access_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &redact_opt(&self.refresh_token))
            .field("scope", &self.scope)
            .finish()
    }
}

/// The RFC 7800 section 3.1 confirmation claim: HOW a token is sender constrained, meaning
/// what a presenter has to prove in addition to holding the string.
///
/// This is what a resource server checks the binding against, and it is the whole reason
/// sender constraining is worth anything at introspection time: without it the binding is
/// known only to the authorization server, and an RS that introspects is back to trusting a
/// bearer string.
///
/// EVERY MEMBER IS OPTIONAL, and that is the design rather than an accident. RFC 7800 section
/// 3.1 defines `cnf` as a JSON OBJECT whose members are confirmation methods, and different
/// sender-constraining mechanisms register different members OF THE SAME OBJECT: RFC 9449
/// section 6.1 registers `jkt` for a DPoP key binding, RFC 8705 section 3.1 registers
/// `x5t#S256` for a certificate binding. A token can legitimately carry both, so neither may
/// be modelled as "the" confirmation and neither may overwrite the other. Adding a mechanism
/// means adding an optional member here; it never means replacing this type.
#[cfg(any(feature = "dpop", feature = "mtls"))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// RFC 9449 section 6.1 `jkt`: the RFC 7638 SHA-256 thumbprint of the client's proof
    /// key, base64url without padding.
    #[cfg(feature = "dpop")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    /// RFC 8705 section 3.1 `x5t#S256`: the SHA-256 thumbprint of the DER encoding of the
    /// X.509 certificate the client presented when the token was issued. A resource server
    /// checks it with [`Confirmation::confirms_certificate`].
    #[cfg(feature = "mtls")]
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<crate::mtls::CertificateThumbprint>,
}

#[cfg(any(feature = "dpop", feature = "mtls"))]
impl Confirmation {
    /// Wrap a DPoP key thumbprint.
    #[cfg(feature = "dpop")]
    pub fn jkt(jkt: impl Into<String>) -> Self {
        Confirmation {
            jkt: Some(jkt.into()),
            #[cfg(feature = "mtls")]
            x5t_s256: None,
        }
    }

    /// Whether this names no confirmation method at all, which is what an ordinary bearer
    /// token has. The `cnf` member is OMITTED for such a token rather than sent as an empty
    /// object: an empty `cnf` claims a constraint exists and then names none, which is worse
    /// than silence.
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "dpop")]
        if self.jkt.is_some() {
            return false;
        }
        #[cfg(feature = "mtls")]
        if self.x5t_s256.is_some() {
            return false;
        }
        true
    }
}

/// The RFC 7009 section 2.1 `token_type_hint`. A hint the server disagrees with is not an error:
/// section 2.1 requires it to keep looking, so this only chooses which lookup runs first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenTypeHint {
    /// The caller believes this is an access token.
    AccessToken,
    /// The caller believes this is a refresh token.
    RefreshToken,
}

impl std::str::FromStr for TokenTypeHint {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "access_token" => Ok(TokenTypeHint::AccessToken),
            "refresh_token" => Ok(TokenTypeHint::RefreshToken),
            _ => Err(()),
        }
    }
}

/// The RFC 7662 section 2.2 introspection response.
///
/// `active` is the only REQUIRED member, and for an inactive token it is the ONLY member: section
/// 2.2 is explicit that the server should not describe a token the caller has not proven it
/// holds, and section 4 explains why (the endpoint would otherwise answer questions about tokens
/// an attacker merely guessed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    pub active: bool,
    /// Space-delimited granted scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The resource owner the token acts for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The token type (RFC 6750 `Bearer`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,
    /// Expiry, as seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Issuance, as seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// The issuer of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// The resource server(s) the token is for: the RFC 8707 resource indicators the grant was
    /// narrowed to.
    ///
    /// RFC 7662 section 2.2 lists `aud` as OPTIONAL and defers its shape to RFC 7519 section 4.1.3,
    /// which admits either a single string or an array. This crate always emits the ARRAY form when
    /// it has an audience at all, because a caller that has to handle two shapes for one claim
    /// eventually handles only one of them; and it omits the member entirely, rather than sending
    /// an empty array, when no resource was requested. An empty array reads as "restricted to
    /// nothing", which is the opposite of the truth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// RFC 9470 section 5: when the resource owner behind this token authenticated, as seconds
    /// since the Unix epoch (OpenID Connect Core section 2 `auth_time`).
    ///
    /// This is what makes a step-up challenge answerable at all: a resource server that asked for a
    /// `max_age` has to be able to see whether the token it now holds actually satisfies it, and
    /// RFC 9470 section 5 names introspection as one of the two places it may look. Present exactly
    /// when the host REPORTED an authentication for the grant (see
    /// [`crate::consent::Authentication`]), and omitted rather than sent as `null` when it did not,
    /// because a null there reads to a careless resource server as a freshness it has checked.
    #[cfg(feature = "consent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// RFC 9470 section 5: the authentication context class the host reported for the grant
    /// (OpenID Connect Core section 2 `acr`). Opaque to this crate; see
    /// [`crate::consent::Authentication::acr`].
    #[cfg(feature = "consent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// RFC 9396 section 9.2: the authorization details this token carries, as a top-level
    /// member of the introspection response. That section is how a resource server holding
    /// an OPAQUE token learns what the token actually authorizes, which is the whole reason
    /// the parameter exists.
    ///
    /// Omitted rather than empty when the grant carried none, for the same reason `aud` is:
    /// an empty array reads as "authorized for nothing in particular", which is a statement,
    /// and the truth here is silence.
    #[cfg(feature = "rar")]
    #[serde(
        default,
        skip_serializing_if = "crate::rar::AuthorizationDetails::is_empty"
    )]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// How this token is sender constrained, present exactly when it is: RFC 9449 section 6.1
    /// `jkt` for a DPoP key, RFC 8705 section 3.2 `x5t#S256` for a client certificate, or both.
    ///
    /// RFC 7662 section 2.2 lets a server return any claim it likes here, and RFC 9449 section 5
    /// and RFC 8705 section 3.2 are each explicit that a resource server has to be able to
    /// confirm the binding. Omitted rather than sent as `null` for an unbound token, because
    /// `"cnf": null` reads to a careless RS as a confirmation it has already checked.
    #[cfg(any(feature = "dpop", feature = "mtls"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

impl IntrospectionResponse {
    /// The one-member answer for a token that is unknown, expired, or not the caller's.
    pub fn inactive() -> Self {
        IntrospectionResponse {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            token_type: None,
            exp: None,
            iat: None,
            iss: None,
            aud: None,
            #[cfg(feature = "consent")]
            auth_time: None,
            #[cfg(feature = "consent")]
            acr: None,
            #[cfg(feature = "rar")]
            authorization_details: crate::rar::AuthorizationDetails::none(),
            #[cfg(any(feature = "dpop", feature = "mtls"))]
            cnf: None,
        }
    }
}

/// A persisted access token: what introspection needs to answer for an opaque token.
///
/// `Debug` is hand-written (see below) rather than derived: `access_token` is a bearer credential
/// (RFC 6750 section 1: possession of the string is the whole of the authorization), so a host
/// doing the obvious `tracing::debug!(?record)` must not thereby write a live token to its logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedToken {
    /// The opaque access token string (the storage key).
    pub access_token: String,
    /// The client the token was issued to.
    pub client_id: ClientId,
    /// The resource owner the token acts for; `None` for client-only grants.
    pub subject: Option<String>,
    /// The granted scope.
    pub scope: ScopeSet,
    /// The RFC 8707 resource indicators this token is restricted to; empty when the grant named
    /// none. This is what RFC 7662 introspection reports as `aud`, and what the RFC 9068 `aud`
    /// claim carries when the `jwt` feature signs the wire token.
    pub resource: Vec<String>,
    /// The RFC 9396 authorization details this token carries (section 7: the AS returns the
    /// details as granted and assigned to the access token). This is what RFC 7662
    /// introspection reports as `authorization_details` (section 9.2) and what the RFC 9068
    /// claim carries when the `jwt` feature signs the wire token (section 9.1).
    #[cfg(feature = "rar")]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// Issuance instant.
    pub issued_at: SystemTime,
    /// Expiry instant; the token is dead at and after this instant.
    pub expires_at: SystemTime,
    /// RFC 9449 section 6: the RFC 7638 thumbprint of the DPoP key this token is bound to, or
    /// `None` for an ordinary bearer token.
    ///
    /// `Option<Box<str>>` rather than `Option<String>`, and feature gated, because this record is
    /// written and read on every token-plane request and `tests/allocation.rs` holds it to a size
    /// budget: the box is 16 bytes against a `String`'s 24, and a deployment without the `dpop`
    /// feature pays neither. The value is a fixed 43-character base64url digest that is never
    /// appended to, so the growable capacity a `String` carries would be dead weight.
    #[cfg(feature = "dpop")]
    pub jkt: Option<Box<str>>,
    /// RFC 8705 section 3: the SHA-256 thumbprint of the client certificate this token is
    /// bound to, or `None` for a token that is not certificate bound.
    ///
    /// Recorded on the AS side, and not only inside a signed JWT, for the same reason `jkt`
    /// next door is: this crate's default access token is OPAQUE, and RFC 8705 section 3.2
    /// has a resource server learn the binding by INTROSPECTING, which it can only be told
    /// if it was persisted.
    ///
    /// `Option<Box<_>>` rather than the 32-byte thumbprint inline, on the same measurement
    /// as `jkt`: this record is written and read on every token-plane request and
    /// `tests/allocation.rs` holds it to a size budget, so an unbound token pays one null
    /// pointer and the allocation happens only for a token that is actually bound.
    #[cfg(feature = "mtls")]
    pub x5t_s256: Option<Box<crate::mtls::CertificateThumbprint>>,
    /// The authorization grant this token belongs to (see [`RefreshTokenRecord::family_id`]).
    ///
    /// RFC 9700 section 4.14.2 requires that detecting refresh token reuse revokes "the tokens
    /// issued for that authorization grant", not merely the refresh chain, so an access token has
    /// to be reachable from the grant it came from. `None` for a grant that produced no refresh
    /// chain (RFC 6749 section 4.4 client credentials), where there is no chain to be reused and
    /// so nothing to revoke by family.
    pub family_id: Option<String>,
    /// What the host reported about the resource owner's authentication when this token's grant was
    /// approved, or `None` when it reported nothing.
    ///
    /// BOXED, so the common `None` costs one null pointer on a record that is written and read on
    /// every token-plane request rather than the whole struct; `tests/allocation.rs` holds this
    /// type to a size budget precisely so that a convenience like an inline `SystemTime` plus an
    /// `Option<String>` cannot be paid for silently. It is what RFC 9470 section 5 is answered from
    /// at introspection time.
    #[cfg(feature = "consent")]
    pub authentication: Option<Box<crate::consent::Authentication>>,
}

/// Hand-written so the opaque `access_token` never prints. Everything else is metadata ABOUT the
/// token rather than the credential itself, and stays visible so the record is still debuggable:
/// `family_id` in particular is what makes an RFC 9700 section 4.14.2 family revocation traceable,
/// and it is an internal grouping identifier, not a bearer credential.
impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("IssuedToken");
        out.field("access_token", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("subject", &self.subject)
            .field("scope", &self.scope)
            .field("resource", &self.resource);
        #[cfg(feature = "rar")]
        out.field("authorization_details", &self.authorization_details);
        out.field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("family_id", &self.family_id)
            .finish()
    }
}

/// Whether a persisted refresh token is still redeemable.
///
/// Rotated tokens are RETAINED in the `Spent` state rather than deleted, exactly as consumed
/// authorization codes are (see [`crate::authorization::AuthorizationCodeState`]) and for exactly
/// the same reason: a token deleted on rotation makes a later presentation indistinguishable from
/// a typo, and the AS then answers the one signal it gets that a token leaked by disconnecting
/// whichever party redeemed second, which in practice is the honest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefreshTokenState {
    /// Live: redeemable exactly once.
    Active,
    /// Already rotated away. Presenting it is REUSE, which OAuth 2.1 draft section 6.1 and RFC
    /// 9700 section 4.14.2 treat as evidence of compromise: the whole family dies.
    Spent,
}

/// A persisted refresh token. Single use: redemption goes through
/// [`crate::store::Storage::take_refresh_token`], and rotation issues a replacement carrying the
/// SAME `expires_at`, so a chain has an absolute lifetime rather than a sliding one.
///
/// `Debug` is hand-written (see below) rather than derived: `refresh_token` is a bearer credential
/// whose leak is exactly the compromise RFC 9700 section 4.14.2 defends against, so it must not
/// reach a host's logs through `{:?}`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    /// The opaque refresh token string (the storage key).
    pub refresh_token: String,
    /// The client the token was issued to; presentation by any other client is `invalid_grant`
    /// and leaves the record untouched.
    pub client_id: ClientId,
    /// The resource owner the chain acts for.
    pub subject: Option<String>,
    /// The scope originally granted; refreshes may narrow, never widen.
    pub scope: ScopeSet,
    /// The RFC 8707 resource indicators originally granted. Carried across rotation for the same
    /// reason `scope` is: section 2 lets a token request narrow the set and never widen it, so the
    /// chain has to remember what it started with. Empty when the grant named none.
    pub resource: Vec<String>,
    /// The RFC 9396 authorization details originally granted. Carried across rotation for
    /// the same reason `scope` and `resource` are: section 6 lets a token request narrow the
    /// set and never widen it, so the chain has to remember what it started with, and a
    /// rotation that narrowed must not be climbable back on the next one.
    #[cfg(feature = "rar")]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// Absolute chain expiry; `None` means the chain does not expire by time.
    ///
    /// On a `Spent` record this doubles as the RETENTION deadline: a spent token is kept only so
    /// that its reuse can be recognised, and a chain with no absolute expiry would otherwise keep
    /// every superseded link forever. The server therefore stamps a spent record from a
    /// never-expiring chain with `now + ServerConfig::refresh_reuse_window`, which is what makes
    /// [`crate::store::Storage::sweep_expired`] able to reclaim it.
    pub expires_at: Option<SystemTime>,
    /// RFC 9449 section 5: the RFC 7638 thumbprint of the DPoP key this refresh chain is bound
    /// to, or `None` for an unbound chain.
    ///
    /// Carried across rotation and CHECKED on redemption. Without it the binding would be
    /// decorative for anything but the first access token: a stolen refresh token could simply be
    /// re-bound to the thief's key on the next rotation, leaving the attacker holding a token they
    /// can prove possession for and the victim's key the one that gets refused.
    #[cfg(feature = "dpop")]
    pub jkt: Option<Box<str>>,
    /// RFC 8705 section 3: the client certificate this refresh chain is bound to, or `None`
    /// for an unbound chain.
    ///
    /// Carried across rotation and CHECKED on redemption, exactly as `jkt` is and for the
    /// same argument: without it the binding would be decorative past the first access
    /// token, because a stolen refresh token could simply be re-bound to whatever
    /// certificate the thief holds on the next rotation. Section 3 makes this a MUST for
    /// public clients specifically; this crate applies it to every chain that was issued
    /// over a certificate, because a chain whose holder proved possession of a key once
    /// should have to keep proving it, and for a confidential mutual-TLS client the rule
    /// costs nothing (it presents that certificate on every request anyway).
    #[cfg(feature = "mtls")]
    pub x5t_s256: Option<Box<crate::mtls::CertificateThumbprint>>,
    /// The FAMILY this token belongs to: one identifier shared by every token, access or refresh,
    /// minted from the same authorization grant, and carried across rotation unchanged.
    ///
    /// This is what makes RFC 9700 section 4.14.2 implementable at all. Without it the AS can
    /// refuse a reused token but cannot reach the tokens the thief already rotated into, which is
    /// the defence exactly inverted: the victim is locked out and the attacker is not.
    pub family_id: String,
    /// Whether this link is still redeemable, or is a retained rotated one.
    pub state: RefreshTokenState,
    /// The authentication the host reported when the grant this chain came from was approved,
    /// carried across rotation UNCHANGED.
    ///
    /// Carried rather than restamped because a rotation is not a new authentication: the user is
    /// not present, nothing has been proven again, and giving a refreshed token a fresh `auth_time`
    /// would let any client defeat an RFC 9470 `max_age` by refreshing. See
    /// [`IssuedToken::authentication`] for why it is boxed.
    #[cfg(feature = "consent")]
    pub authentication: Option<Box<crate::consent::Authentication>>,
}

/// Hand-written so the opaque `refresh_token` never prints. `state` and `family_id` stay visible
/// because they are precisely what an operator debugging an RFC 9700 section 4.14.2 family
/// revocation needs to see, and neither is a credential.
impl fmt::Debug for RefreshTokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("RefreshTokenRecord");
        out.field("refresh_token", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("subject", &self.subject)
            .field("scope", &self.scope)
            .field("resource", &self.resource);
        #[cfg(feature = "rar")]
        out.field("authorization_details", &self.authorization_details);
        out.field("expires_at", &self.expires_at)
            .field("family_id", &self.family_id)
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
#[path = "tests/token.rs"]
mod tests;
