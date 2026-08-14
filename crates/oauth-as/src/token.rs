// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Token wire and storage shapes: the RFC 6749 section 5.1 success response, plus the records the
//! server persists through [`crate::store::Storage`].
//!
//! Access and refresh tokens are OPAQUE random strings by default. Under the `jwt` feature the
//! WIRE access token becomes an RFC 9068 structured token and the opaque string becomes its `jti`;
//! the shapes here are unchanged either way, which is the point. [`IssuedToken`] is persisted
//! whichever form went out, keyed by whatever the client will actually present, so RFC 7662
//! introspection and RFC 7009 revocation keep working and a revoked JWT is genuinely dead at this
//! server rather than merely deprecated.

use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::scope::ScopeSet;

/// `token_type` values this server issues: `Bearer` (RFC 6750), and `DPoP` (RFC 9449 section 5)
/// under the `dpop` feature when the request proved possession of a key. Both registered values
/// are case-insensitive on the wire but conventionally spelled as the renames below pin them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// `#[non_exhaustive]`: the `Dpop` variant exists only under the `dpop` feature, so a host that
/// matches this exhaustively compiles today and stops compiling the day anything in its dependency
/// graph turns `dpop` on. Naming either variant still works; only the match needs a wildcard arm.
/// A `token_type` is exactly the thing a host branches on when deciding how to hand the response
/// to its client, so this is the enum most likely to be matched and the least affordable to leave
/// open.
#[non_exhaustive]
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
/// `#[non_exhaustive]`: `authorization_details` appears only under the `rar` feature, so this
/// struct's field set moves with a flag no host controls alone. This is an OUTPUT: the crate builds
/// it and the host serializes it, so the paths that matter are unaffected, and a host that needs to
/// build one anyway (a proxy, a test double) still has `Deserialize`, which is derived in here and
/// so keeps working from outside.
#[non_exhaustive]
pub struct TokenResponse {
    /// The access token: an opaque random string, or an RFC 9068 JWT under the `jwt` feature.
    pub access_token: String,
    /// `Bearer` (RFC 6750), or `DPoP` (RFC 9449 s5) when the `dpop` feature is on and the token
    /// request carried a proof, because a sender-constrained token MUST NOT be presented as a
    /// bearer token.
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
    /// The RFC 9396 authorization details as GRANTED, which section 7 makes a MUST for a response
    /// to a request that carried them.
    ///
    /// It is a MUST for the same reason RFC 6749 section 3.3 has `scope` echoed when it differs
    /// from the request: section 7.1 explicitly permits what was granted to differ from what was
    /// asked for, because the host's consent screen may narrow or enrich it. Without this member a
    /// client has no way to learn that what it holds is not what it requested, and would go on to
    /// call a resource server believing it can do something it cannot.
    ///
    /// Omitted entirely when empty, so a deployment that never uses authorization details emits
    /// exactly the body it emitted before this existed.
    ///
    /// `#[serde(default)]` is what makes that omission READABLE, and it is not optional beside a
    /// `skip_serializing_if`. The two together are a matched pair: a member left out on the way out
    /// has to be allowed to be absent on the way back in, or the type cannot parse the very body it
    /// just emitted. Without it the ordinary response above is refused with `missing field
    /// "authorization_details"`, which also falsifies the `#[non_exhaustive]` note above promising a
    /// host that `Deserialize` "keeps working from outside": a proxy or a test double reading a
    /// response back would break the moment `rar` appeared anywhere in its dependency graph.
    #[cfg(feature = "rar")]
    #[serde(
        default,
        skip_serializing_if = "crate::rar::AuthorizationDetails::is_empty"
    )]
    pub authorization_details: crate::rar::AuthorizationDetails,
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
/// DESERIALIZED THROUGH `ConfirmationWire`, for the reason [`IntrospectionResponse`] is
/// deserialized through `IntrospectionWire`, and the member set above is why it has to be
/// separate from that one. `cnf` is an OBJECT of confirmation methods and each feature registers
/// its own, so a build with `dpop` and not `mtls` carries the OUTER member and not the inner one:
/// the guard on `IntrospectionWire::cnf` passes (the member IS present), the interior deserializes
/// to a `Confirmation` with nothing in it, and [`Confirmation::is_empty`] answers `true`. That is
/// the certificate-bound-token-read-as-a-bearer-token case in full, arrived at through the guard
/// meant to stop it. The interior needs the same treatment as the exterior, and this is it.
#[cfg(any(feature = "dpop", feature = "mtls"))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ConfirmationWire")]
/// `#[non_exhaustive]`: the paragraph above says adding a sender-constraining mechanism means
/// adding an optional member here, and `dpop` and `mtls` each add one INDEPENDENTLY, so there are
/// four different field sets this type has depending on which pair of flags is on. The attribute is
/// what makes that promise cost a host nothing: build with `Confirmation::default()` (every member
/// is optional by construction) and set the members the mechanism you use registers.
#[non_exhaustive]
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

/// The deserialize-side mirror of [`Confirmation`], and the reason that type does not derive
/// `Deserialize` directly.
///
/// Same construction as [`IntrospectionWire`] and for the same reason, one level further in: a
/// confirmation METHOD this build cannot represent is parsed and refused rather than dropped. The
/// members are the ones RFC 9449 section 6.1 and RFC 8705 section 3.1 register, and a build has
/// each one either as itself or as an `IgnoredAny` that remembers only that it was there.
///
/// NOT `#[serde(deny_unknown_fields)]`, for the reason `IntrospectionWire` is not: RFC 7800
/// section 3.1 defines `cnf` as an open set of confirmation methods and registers others this
/// crate does not implement, so a `cnf` naming one of those is conformant. Only the two methods
/// this crate knows the meaning of are refused when it cannot hold them.
#[cfg(any(feature = "dpop", feature = "mtls"))]
#[derive(Deserialize)]
struct ConfirmationWire {
    #[cfg(feature = "dpop")]
    jkt: Option<String>,
    #[cfg(feature = "mtls")]
    #[serde(rename = "x5t#S256")]
    x5t_s256: Option<crate::mtls::CertificateThumbprint>,
    // The methods this build cannot represent.
    #[cfg(not(feature = "dpop"))]
    jkt: Option<serde::de::IgnoredAny>,
    #[cfg(not(feature = "mtls"))]
    #[serde(rename = "x5t#S256")]
    x5t_s256: Option<serde::de::IgnoredAny>,
}

#[cfg(any(feature = "dpop", feature = "mtls"))]
impl TryFrom<ConfirmationWire> for Confirmation {
    type Error = UnrepresentableMember;

    fn try_from(wire: ConfirmationWire) -> Result<Self, Self::Error> {
        #[cfg(not(feature = "dpop"))]
        if wire.jkt.is_some() {
            return Err(
                "confirmation carries `jkt` (RFC 9449 s6.1), so the token is bound to a DPoP key \
                 and this build of oauth-as cannot represent that: rebuild with the `dpop` feature",
            );
        }
        #[cfg(not(feature = "mtls"))]
        if wire.x5t_s256.is_some() {
            return Err(
                "confirmation carries `x5t#S256` (RFC 8705 s3.1), so the token is bound to a \
                 client certificate and this build of oauth-as cannot represent that: rebuild \
                 with the `mtls` feature",
            );
        }
        Ok(Confirmation {
            #[cfg(feature = "dpop")]
            jkt: wire.jkt,
            #[cfg(feature = "mtls")]
            x5t_s256: wire.x5t_s256,
        })
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
/// DESERIALIZED THROUGH a private mirror (`IntrospectionWire` in this module), which is what makes
/// a member this build cannot represent an ERROR rather than a silent omission: `token_type` has
/// always failed loudly for a `DPoP` token in a build without `dpop`, and the five feature-gated
/// members beside it used to fail silently for the same class of response. What is NOT refused is
/// an unknown member, which RFC 7662 section 2.2 explicitly permits a server to send.
#[serde(try_from = "IntrospectionWire")]
/// `#[non_exhaustive]`: four separate features (`consent`, `rar`, `dpop`, `mtls`) each add a member
/// here, which is more feature-driven variation than any other wire body this crate publishes.
/// [`IntrospectionResponse::inactive`] is the construction path and always was the sensible one:
/// start from the one-member refusal and fill in what the token actually is, rather than writing
/// out a literal that has to name every claim the current flag set happens to produce.
#[non_exhaustive]
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
    ///
    /// ABSENT FOR A CLIENT-CREDENTIALS TOKEN, and that is a deliberate disagreement with the
    /// signed token beside it. RFC 6749 section 4.4 has no resource owner, so RFC 7662 section
    /// 2.2's "usually a machine-readable identifier of the resource owner" has nothing to name and
    /// the member is omitted; RFC 9068 section 2.2 makes `sub` REQUIRED in a JWT access token and
    /// directs the AS to put the `client_id` there instead. Both are right, and a resource server
    /// reading one token through both channels therefore sees a subject in the JWT and no subject
    /// from introspection. Neither says a user was involved.
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
    ///
    /// UNDER `jwt`, THE SIGNED `aud` MAY BE NARROWER THAN THIS MEMBER'S ABSENCE SUGGESTS. This is
    /// the grant's RFC 8707 resource indicators and nothing else, so a grant that named none omits
    /// the member; the signed access token for that same grant carries the DEPLOYMENT-WIDE
    /// [`crate::jwt::JwtConfig::audience`] instead, because RFC 9068 section 2.2 makes `aud`
    /// required and a token has to name somebody. So "no `aud` here" means "this grant was
    /// narrowed to no particular resource server", NOT "this token is valid everywhere": a
    /// resource server enforcing audience restriction should enforce it from the token when it has
    /// one, and treat this member as the grant's narrowing on top.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// RFC 9470 section 6.2: when the resource owner behind this token authenticated, as seconds
    /// since the Unix epoch (OpenID Connect Core section 2 `auth_time`).
    ///
    /// This is what makes a step-up challenge answerable at all: a resource server that asked for a
    /// `max_age` has to be able to see whether the token it now holds actually satisfies it, and
    /// RFC 9470 section 6 names introspection (section 6.2) as one of the two places it may look,
    /// the other being the JWT itself (section 6.1). Present exactly
    /// when the host REPORTED an authentication for the grant (see
    /// [`crate::consent::Authentication`]), and omitted rather than sent as `null` when it did not,
    /// because a null there reads to a careless resource server as a freshness it has checked.
    #[cfg(feature = "consent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// RFC 9470 section 6.2: the authentication context class the host reported for the grant
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
    /// A resource server reads this member since 0.9.2, when it is registered in
    /// [`crate::ServerConfig::resource_servers`] and the token is addressed to it.
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
    /// RFC 8693 section 4.1 `act`: who authority was delegated TO, present exactly when this token
    /// came from a DELEGATION token exchange.
    ///
    /// RFC 7662 section 2.2 lets a server return any claim it likes here, and this is the claim an
    /// opaque token has nowhere else to put. Without it a resource server cannot tell "A acting
    /// for B" from "B", which is the entire distinction RFC 8693 section 1.1 draws between
    /// delegation and impersonation, and the reason a deployment would choose delegation at all.
    ///
    /// Omitted rather than sent as `null`, for the same reason `cnf` next door is: a member that
    /// is present and null invites a careless reader to treat it as answered.
    #[cfg(feature = "token-exchange")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<crate::token_exchange::ActClaim>,
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
            #[cfg(feature = "token-exchange")]
            act: None,
        }
    }
}

/// The deserialize-side mirror of [`IntrospectionResponse`], and the reason that type does not
/// derive `Deserialize` directly.
///
/// WHAT IT IS FOR: five members of the response exist only under a cargo feature (`cnf` under
/// `dpop` or `mtls`, `act` under `token-exchange`, `auth_time` and `acr` under `consent`,
/// `authorization_details` under `rar`), and a derived `Deserialize` in a build without the
/// feature DROPS them without a word. Four of the five say the token is NARROWER than a plain
/// bearer token, so the reader that loses one concludes the safest-looking thing: a
/// certificate-bound token read as an ordinary bearer token, a delegated token read as the
/// principal itself, a transaction-scoped token read as unrestricted. The same object's
/// `token_type` has never had that problem, because `"DPoP"` in a build without `dpop` is an
/// unknown enum variant and serde says so. This makes the rest of the object behave like
/// `token_type`.
///
/// NOT `#[serde(deny_unknown_fields)]`, deliberately. RFC 7662 section 2.2 says specific
/// implementations "MAY extend this structure with their own service-specific response names as
/// top-level members", so a response carrying `username` or `nbf` is conformant; denying every
/// unknown member would convert a silent drop into an inability to read a legitimate response at
/// all, which is a worse failure and a more likely one. Only the members THIS CRATE KNOWS THE
/// MEANING OF, and would therefore be discarding knowingly, are refused.
///
/// The field list is a mirror and mirrors drift, so `tests/introspection_feature_bounds.rs`
/// round-trips a fully populated response for whatever flag set it is built with.
#[derive(Deserialize)]
struct IntrospectionWire {
    active: bool,
    scope: Option<String>,
    client_id: Option<String>,
    sub: Option<String>,
    token_type: Option<TokenType>,
    exp: Option<u64>,
    iat: Option<u64>,
    iss: Option<String>,
    aud: Option<Vec<String>>,
    #[cfg(feature = "consent")]
    auth_time: Option<u64>,
    #[cfg(feature = "consent")]
    acr: Option<String>,
    #[cfg(feature = "rar")]
    #[serde(default)]
    authorization_details: crate::rar::AuthorizationDetails,
    #[cfg(any(feature = "dpop", feature = "mtls"))]
    cnf: Option<Confirmation>,
    #[cfg(feature = "token-exchange")]
    act: Option<crate::token_exchange::ActClaim>,
    // The members this build cannot represent. `IgnoredAny` parses the value and keeps nothing:
    // what is wanted is the knowledge that it was THERE, which is exactly what this build would
    // otherwise not have.
    #[cfg(not(feature = "consent"))]
    auth_time: Option<serde::de::IgnoredAny>,
    #[cfg(not(feature = "consent"))]
    acr: Option<serde::de::IgnoredAny>,
    #[cfg(not(feature = "rar"))]
    authorization_details: Option<serde::de::IgnoredAny>,
    #[cfg(not(any(feature = "dpop", feature = "mtls")))]
    cnf: Option<serde::de::IgnoredAny>,
    #[cfg(not(feature = "token-exchange"))]
    act: Option<serde::de::IgnoredAny>,
}

/// Why one of the members above could not be kept. `&'static str` rather than a formatted
/// message: this is a refusal on a parse path, and naming the member and the feature that would
/// have carried it is the whole of what a reader needs.
type UnrepresentableMember = &'static str;

impl TryFrom<IntrospectionWire> for IntrospectionResponse {
    type Error = UnrepresentableMember;

    fn try_from(wire: IntrospectionWire) -> Result<Self, Self::Error> {
        #[cfg(not(feature = "consent"))]
        if wire.auth_time.is_some() {
            return Err(
                "introspection response carries `auth_time` (RFC 9470 s6.2), which this build of \
                 oauth-as cannot represent: rebuild with the `consent` feature",
            );
        }
        #[cfg(not(feature = "consent"))]
        if wire.acr.is_some() {
            return Err(
                "introspection response carries `acr` (RFC 9470 s6.2), which this build of \
                 oauth-as cannot represent: rebuild with the `consent` feature",
            );
        }
        #[cfg(not(feature = "rar"))]
        if wire.authorization_details.is_some() {
            return Err(
                "introspection response carries `authorization_details` (RFC 9396 s9.2), which \
                 this build of oauth-as cannot represent: rebuild with the `rar` feature",
            );
        }
        #[cfg(not(any(feature = "dpop", feature = "mtls")))]
        if wire.cnf.is_some() {
            return Err(
                "introspection response carries `cnf` (RFC 9449 s6.1 / RFC 8705 s3.2), so the \
                 token is sender constrained and this build of oauth-as cannot represent that: \
                 rebuild with the `dpop` or `mtls` feature",
            );
        }
        #[cfg(not(feature = "token-exchange"))]
        if wire.act.is_some() {
            return Err(
                "introspection response carries `act` (RFC 8693 s4.1), so the token is a \
                 delegation and this build of oauth-as cannot represent that: rebuild with the \
                 `token-exchange` feature",
            );
        }
        Ok(IntrospectionResponse {
            active: wire.active,
            scope: wire.scope,
            client_id: wire.client_id,
            sub: wire.sub,
            token_type: wire.token_type,
            exp: wire.exp,
            iat: wire.iat,
            iss: wire.iss,
            aud: wire.aud,
            #[cfg(feature = "consent")]
            auth_time: wire.auth_time,
            #[cfg(feature = "consent")]
            acr: wire.acr,
            #[cfg(feature = "rar")]
            authorization_details: wire.authorization_details,
            #[cfg(any(feature = "dpop", feature = "mtls"))]
            cnf: wire.cnf,
            #[cfg(feature = "token-exchange")]
            act: wire.act,
        })
    }
}

/// The serde default for the two `grant_established_at` fields below: the epoch, because it is the
/// fail-closed answer. Every barrier is recorded after it, so a record with no stated grant instant
/// is REFUSED by a standing revocation rather than admitted by one. See
/// [`IssuedToken::grant_established_at`], which states the whole argument.
fn grant_established_at_default() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

/// A persisted access token: what introspection needs to answer for an opaque token.
///
/// `Debug` is hand-written (see below) rather than derived: `access_token` is a bearer credential
/// (RFC 6750 section 1: possession of the string is the whole of the authorization), so a host
/// doing the obvious `tracing::debug!(?record)` must not thereby write a live token to its logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
/// `#[non_exhaustive]`: `rar`, `dpop`, `mtls` and `consent` each add a field, so the shape of this
/// record is decided by the flag set the final binary is linked with rather than by the host that
/// writes against it.
///
/// A [`crate::store::Storage`] implementor does not lose anything: it is HANDED these records and
/// round-trips them through the derived `Serialize`/`Deserialize`, both of which are generated in
/// here and are unaffected. `oauth-as-postgres` persists them as a `jsonb` payload for exactly that
/// reason and never spells a field. For everyone else, including a host seeding a store or writing
/// a fixture, [`IssuedToken::new`] takes the fields a token cannot exist without and leaves the
/// rest public to assign.
///
/// THE BOUND ON THAT SENTENCE, stated because it is not obvious: "does not lose anything" holds
/// for ONE flag set. Two binaries built with different features over one store are a different
/// situation, and this type has no answer for it: a reader without `rar` deserializes a record
/// whose `authorization_details` it has no field for, the derived `Deserialize` drops the member
/// in silence, and a rotation writes the shortened record back. Serialization is not where that
/// gets caught -- [`IntrospectionResponse`] and [`Confirmation`] are read from a FOREIGN server
/// and are guarded on the way in, whereas these records are this deployment's own and the guard
/// would have to be a decision about what a store should do when it hands back a record this
/// binary cannot represent. A MIXED-FLAG FLEET OVER ONE STORE IS THEREFORE NOT A SUPPORTED
/// DEPLOYMENT of this crate, and the same caveat applies to [`RefreshTokenRecord`],
/// [`crate::authorization::AuthorizationCodeRecord`] and
/// [`crate::par::PushedAuthorizationRequest`].
#[non_exhaustive]
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
    ///
    /// THE TWO CHANNELS PART COMPANY WHEN THIS IS EMPTY, which the sentence above used to deny.
    /// Introspection then omits `aud` altogether (an empty array would read as "restricted to
    /// nothing"; see [`IntrospectionResponse::aud`]), while the signed token cannot omit it,
    /// because RFC 9068 section 2.2 makes the claim REQUIRED: it carries the deployment-wide
    /// [`crate::jwt::JwtConfig::audience`] instead. So for a grant that named no resource a
    /// caller reads "no restriction stated" from introspection and "restricted to the
    /// configured audience" from the token, for one token. Both are true statements about
    /// different things: this field is the GRANT'S narrowing, and the configured audience is the
    /// deployment's standing one. Non-empty, they agree exactly.
    ///
    /// SINCE 0.9.2 THIS FIELD ALSO DECIDES WHO MAY ASK. It is what a registered resource server is
    /// matched against, so a token whose grant named no resource is introspectable by its own
    /// client alone; see [`crate::ServerConfig::resource_servers`]. A resource server that is
    /// answered sees only its OWN identifiers here, not the whole set.
    pub resource: Vec<String>,
    /// The RFC 9396 authorization details this token carries (section 7: the AS returns the
    /// details as granted and assigned to the access token). This is what RFC 7662
    /// introspection reports as `authorization_details` (section 9.2) and what the RFC 9068
    /// claim carries when the `jwt` feature signs the wire token (section 9.1).
    ///
    /// `#[serde(default)]`, for the same reason `grant_established_at` below has one and reached
    /// by the other door: TURNING THE FEATURE ON must not make what is already in the store
    /// unreadable. A record written by a build without `rar` carries no such key, this field is not
    /// an `Option` so serde's derive supplies no default of its own, and the read fails outright
    /// with `missing field "authorization_details"`. That is not a migration an operator can plan
    /// around either, because cargo feature unification means a dependency can turn `rar` on
    /// without the host asking (see `tests/host_api_shape.rs`): the build changes and every live
    /// grant stops being readable at once. The default is the empty set, which is the truth about a
    /// grant minted before the feature existed, and it is also the safe direction: an empty set
    /// authorizes nothing extra.
    #[cfg(feature = "rar")]
    #[serde(default)]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// Issuance instant.
    pub issued_at: SystemTime,
    /// The instant the GRANT behind this token was authorized, which is NOT `issued_at`.
    ///
    /// For a code redemption it is when the code was minted; for a refresh rotation it is carried
    /// forward unchanged from the chain, so every token along a chain reports the one decision that
    /// started it. For a grant with no resource owner behind it (client credentials) it is the
    /// instant of issuance, because the client's own registration is the only authorization there
    /// is.
    ///
    /// FOR A DEVICE GRANT IT IS WHEN THE DEVICE ASKED, NOT WHEN THE USER APPROVED, and that is a
    /// known approximation rather than the intent. RFC 8628 section 3.3 approval happens at the
    /// host's own verification UI and [`crate::device::DeviceGrantState::Approved`] records only
    /// the subject, so the approval instant is never persisted and there is nothing truer to carry;
    /// [`crate::device::DeviceGrant::created_at`] is what exists. The gap is the grant's whole
    /// lifetime (RFC 8628 section 3.2 `expires_in`, typically minutes), and it errs in the
    /// FAIL-CLOSED direction: a barrier recorded inside that window refuses a decision the user
    /// made after it, so a user who withdraws consent and then re-approves the same pending device
    /// grant is refused and has to start the device flow again. A false refusal, never a false
    /// admission. Closing it properly means persisting the approval instant, which is a breaking
    /// change to that enum variant.
    ///
    /// A [`crate::store::RevocationBarrier`] is compared against this rather than against
    /// `issued_at`: a rotation and a re-approval both WRITE at `now`, so `now` cannot tell a grant
    /// that predates a revocation from one made after it. See
    /// [`crate::store::RevocationWindow::recorded_at`].
    ///
    /// `#[serde(default)]`, and the default is the epoch, which is the FAIL-CLOSED direction.
    /// This field is new in 0.9.1, so a record a 0.9.0 node wrote — or is still writing, during a
    /// rolling upgrade — carries no such key, and without a default the read fails outright and
    /// every token that release issued becomes unreadable the moment this one starts. With it, the
    /// record deserializes and dates from before every barrier that could ever be recorded, so a
    /// standing revocation REFUSES it rather than admitting it. A far-future default would
    /// deserialize just as happily and ADMIT every record 0.9.0 wrote, which is exactly the
    /// resurrection this field exists to close, reintroduced through the upgrade path. The
    /// There is deliberately NO backfill migration: a backfill cannot reach a 0.9.0 node still
    /// writing field-less payloads during a rolling upgrade, which is the window that matters, so
    /// the serde default covers strictly more than one would.
    #[serde(default = "grant_established_at_default")]
    pub grant_established_at: SystemTime,
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
    /// if it was persisted. The channel that carries it to a resource server arrived in 0.9.2;
    /// the field was persisted before that, because the RECORD, not the response, is the thing
    /// that cannot be added later.
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
    /// RFC 8693 section 4.1 `act`: who authority was delegated TO, for a token issued by a
    /// DELEGATION token exchange. `None` for every other grant, and for an impersonation exchange,
    /// which by definition names no actor.
    ///
    /// # Why this is on the RECORD and not only in the response
    ///
    /// This crate's default access token is OPAQUE, so RFC 7662 introspection is the only channel
    /// a resource server has for learning anything about it. A delegation that introspection
    /// cannot see is a delegation the resource server has to take the host's word for, which is
    /// the one thing section 1.1 delegation exists to avoid: the whole point is that the resource
    /// can tell "A acting for B" from "B".
    ///
    /// The channel that carries it to a resource server arrived in 0.9.2; the field was persisted
    /// before that, because the RECORD, not the response, is the thing that cannot be added later.
    ///
    /// It was left off through 0.9.0 for two reasons, and both are now spent. The first was
    /// allocation, and [`crate::store::Storage::get_token`] returning an `Arc<IssuedToken>` ended
    /// it: the record's shape costs a read nothing, and this field costs a deployment without the
    /// feature zero bytes and one with it 8 bytes per token plus one allocation per DELEGATED
    /// token. The second was the persistence contract, which was the real one: this is the record
    /// every host's `Storage` writes, so a new field is a migration in stores this crate does not
    /// own. That is exactly why it lands HERE, in the release that is already breaking that trait,
    /// so a host migrates once rather than twice.
    ///
    /// BOXED for the same measured reason as `authentication` below: the common case is `None`,
    /// and this record is written and read on every token-plane request.
    #[cfg(feature = "token-exchange")]
    #[cfg_attr(docsrs, doc(cfg(feature = "token-exchange")))]
    pub act: Option<Box<crate::token_exchange::ActClaim>>,
    /// What the host reported about the resource owner's authentication when this token's grant was
    /// approved, or `None` when it reported nothing.
    ///
    /// BOXED, so the common `None` costs one null pointer on a record that is written and read on
    /// every token-plane request rather than the whole struct; `tests/allocation.rs` holds this
    /// type to a size budget precisely so that a convenience like an inline `SystemTime` plus an
    /// `Option<String>` cannot be paid for silently. It is what BOTH halves of RFC 9470 section 6
    /// are answered from: 6.2 at introspection time, and 6.1 at issuance, where the same report
    /// becomes the `auth_time` and `acr` claims of the signed access token.
    #[cfg(feature = "consent")]
    pub authentication: Option<Box<crate::consent::Authentication>>,
}

impl IssuedToken {
    /// The five things a persisted access token cannot be without: the string a client will
    /// present, who it was issued to, who it acts for, what it may do, and when it lives between.
    ///
    /// Everything else describes a token that is more than the minimum (an audience restriction, a
    /// sender-constraining binding, the family it can be revoked with) and is a public field on the
    /// returned value, so a caller sets what applies and states nothing about what does not. That
    /// split is the reason the arguments stop here rather than growing one per feature: a caller
    /// building a record for a build with `dpop` off should not have to mention DPoP.
    ///
    /// `subject` is an argument rather than a field to assign because `None` is a real answer and
    /// not an omission: it means an RFC 6749 section 4.4 client-credentials token, which acts for
    /// no resource owner, and a caller should have to say so.
    pub fn new(
        access_token: impl Into<String>,
        client_id: ClientId,
        subject: Option<String>,
        scope: ScopeSet,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> Self {
        IssuedToken {
            // Same FAIL-CLOSED default as `RefreshTokenRecord::new`, and the same reason: a caller
            // that has not said when its grant was authorized must not thereby outrank a standing
            // revocation. A caller that knows sets the field on the returned value.
            grant_established_at: SystemTime::UNIX_EPOCH,
            access_token: access_token.into(),
            client_id,
            subject,
            scope,
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: crate::rar::AuthorizationDetails::none(),
            issued_at,
            expires_at,
            #[cfg(feature = "dpop")]
            jkt: None,
            #[cfg(feature = "mtls")]
            x5t_s256: None,
            family_id: None,
            #[cfg(feature = "token-exchange")]
            act: None,
            #[cfg(feature = "consent")]
            authentication: None,
        }
    }
}

/// Hand-written so the opaque `access_token` never prints. EVERY other field prints, because every
/// other field is metadata ABOUT the token rather than the credential itself, and the record has to
/// stay debuggable: `family_id` in particular is what makes an RFC 9700 section 4.14.2 family
/// revocation traceable, and it is an internal grouping identifier, not a bearer credential.
///
/// "Every other field" is the whole rule and it is stated that way deliberately. This impl used to
/// print eight of thirteen, and the five it dropped were the five added since it was written, which
/// is what a hand-written `Debug` costs if nobody restates the rule when a field arrives. The
/// worst omission was `grant_established_at`: it is the SOLE time input to every
/// [`crate::store::RevocationBarrier`] comparison and its fail-closed default is the epoch, so
/// "this token is refused by a barrier and I cannot see why" was exactly the question `{:?}` could
/// not answer. `jkt` and `x5t_s256` are public-key and certificate THUMBPRINTS, which a resource
/// server is given on the wire in the RFC 7800 `cnf` claim, so neither is secret; `act` is the RFC
/// 8693 section 4.1 delegation chain, which introspection publishes; `authentication` is the RFC
/// 9470 report, which introspection publishes as `auth_time` and `acr` (section 6.2) and which a
/// signed access token carries under the same two names (section 6.1).
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
            .field("grant_established_at", &self.grant_established_at)
            .field("expires_at", &self.expires_at);
        #[cfg(feature = "dpop")]
        out.field("jkt", &self.jkt);
        #[cfg(feature = "mtls")]
        out.field("x5t_s256", &self.x5t_s256);
        out.field("family_id", &self.family_id);
        #[cfg(feature = "token-exchange")]
        out.field("act", &self.act);
        #[cfg(feature = "consent")]
        out.field("authentication", &self.authentication);
        out.finish()
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
/// `#[non_exhaustive]`, on the same four features and the same storage argument as
/// [`IssuedToken`]: a `Storage` implementor round-trips this through serde and never names a field,
/// and anyone assembling one by hand goes through [`RefreshTokenRecord::new`].
#[non_exhaustive]
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
    ///
    /// `#[serde(default)]`, which [`IssuedToken::authorization_details`] states in full: a chain
    /// written by a build without `rar` carries no such key, this is not an `Option` so serde
    /// supplies no default of its own, and without one every live chain becomes unreadable the
    /// moment anything in the host's dependency graph turns the feature on.
    #[cfg(feature = "rar")]
    #[serde(default)]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// The instant the GRANT behind this chain was authorized, CARRIED ACROSS ROTATION and never
    /// restamped, for the same reason `scope` and `resource` are carried: the chain has to remember
    /// the one decision that started it. Restamping it on each rotation would let a chain walk
    /// forward past a revocation it was supposed to die to.
    ///
    /// See [`IssuedToken::grant_established_at`], which this is copied into on every rotation, and
    /// which states in full why the serde default below is the epoch: a chain a 0.9.0 node wrote
    /// carries no such key, and the epoch is the reading that a standing revocation REFUSES rather
    /// than the one it admits.
    #[serde(default = "grant_established_at_default")]
    pub grant_established_at: SystemTime,
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

impl RefreshTokenRecord {
    /// A LIVE link: `state` is [`RefreshTokenState::Active`], because a record nobody has rotated
    /// yet is the only kind worth minting, and a caller building a spent one for a reuse test
    /// assigns the field afterwards rather than passing a flag that is `Active` every real time.
    ///
    /// `family_id` is an argument and not a default, unlike almost everything else here, because
    /// there is no honest default for it: an invented one would put this chain in a family of its
    /// own and quietly cost RFC 9700 section 4.14.2 the access tokens minted alongside it, which is
    /// the failure the field exists to prevent. `expires_at` starts `None`, a chain with no
    /// absolute lifetime, which is what [`crate::server::ServerConfig`] produces when the host has
    /// set no refresh TTL.
    pub fn new(
        refresh_token: impl Into<String>,
        client_id: ClientId,
        subject: Option<String>,
        scope: ScopeSet,
        family_id: impl Into<String>,
    ) -> Self {
        RefreshTokenRecord {
            refresh_token: refresh_token.into(),
            client_id,
            subject,
            scope,
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: crate::rar::AuthorizationDetails::none(),
            // UNIX_EPOCH is the FAIL-CLOSED default, and it is deliberate. A record assembled by
            // hand has not said when its grant was authorized, and the epoch predates every
            // revocation, so a standing barrier refuses it. The other direction would have a
            // hand-built record silently outrank a revocation.
            grant_established_at: SystemTime::UNIX_EPOCH,
            expires_at: None,
            #[cfg(feature = "dpop")]
            jkt: None,
            #[cfg(feature = "mtls")]
            x5t_s256: None,
            family_id: family_id.into(),
            state: RefreshTokenState::Active,
            #[cfg(feature = "consent")]
            authentication: None,
        }
    }
}

/// Hand-written so the opaque `refresh_token` never prints. EVERY other field prints, on the rule
/// [`IssuedToken`]'s `Debug` states in full: `state` and `family_id` are precisely what an operator
/// debugging an RFC 9700 section 4.14.2 family revocation needs to see, `grant_established_at` is
/// what a [`crate::store::RevocationBarrier`] is compared against, and none of the three is a
/// credential.
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
        out.field("grant_established_at", &self.grant_established_at)
            .field("expires_at", &self.expires_at);
        #[cfg(feature = "dpop")]
        out.field("jkt", &self.jkt);
        #[cfg(feature = "mtls")]
        out.field("x5t_s256", &self.x5t_s256);
        out.field("family_id", &self.family_id)
            .field("state", &self.state);
        #[cfg(feature = "consent")]
        out.field("authentication", &self.authentication);
        out.finish()
    }
}

#[cfg(test)]
#[path = "tests/token.rs"]
mod tests;
