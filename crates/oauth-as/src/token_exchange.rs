// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8693 token exchange: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
//!
//! One client presents a token it holds and receives another one. That is the basis of nearly
//! every service-to-service call in a system with more than one hop: a gateway that received a
//! user's token needs a token it can send onward without handing the downstream service the
//! original credential, and without either service having to invent its own scheme for saying who
//! is really calling.
//!
//! # Delegation and impersonation, and how to tell which you got
//!
//! RFC 8693 section 1.1 draws the distinction and this module makes it observable rather than
//! implicit, because it is the whole security meaning of the call:
//!
//! - IMPERSONATION. No `actor_token`. The issued token names the subject and nothing else, so the
//!   downstream resource cannot tell the caller apart from the original principal "within some
//!   defined rights context" (section 1.1). [`ExchangeSemantics::Impersonation`].
//! - DELEGATION. An `actor_token` is presented, and it authenticates the acting party. The issued
//!   token still names the subject, but it also carries the section 4.1 `act` claim identifying
//!   who is acting for them, so the resource can log and authorize "A on behalf of B" rather than
//!   "B". [`ExchangeSemantics::Delegation`], with [`ExchangedToken::act`] populated.
//!
//! [`ExchangedToken`] tells the host which of the two it just produced. It is not a detail to be
//! inferred from whether a parameter was sent.
//!
//! # The ceiling, which is the entire risk of this grant
//!
//! An exchange must never produce a token that can do something the subject token could not.
//! Widening is the only interesting attack on token exchange: a client that legitimately holds a
//! read-only token for one resource asks for a write token for another, and if the AS obliges,
//! every access control upstream of it has been bypassed by one HTTP request.
//!
//! This crate already had the right pattern in two places, and this grant reuses THE SAME CODE
//! rather than a similar-looking copy of it (the crate-private `narrow_resources` and
//! `validate_resources` on `AuthorizationServer`, which the authorization code and refresh paths
//! call too; see the notes below):
//!
//! - SCOPE. RFC 6749 section 6 lets a refresh narrow and never widen; the same rule applies here,
//!   against the subject token's granted scope. A widening request is `invalid_scope`.
//! - RESOURCE / AUDIENCE. RFC 8707 section 2 lets a token request narrow the audience the grant
//!   obtained and never widen it. The subject token's recorded `resource` list is the ceiling, and
//!   a target outside it is `invalid_target`, which is the code RFC 8693 section 2.2.2 names for
//!   exactly this. A subject token that named NO resource has nothing to narrow, so naming one is
//!   widening from nothing and is refused, exactly as it is for the authorization code grant.
//!
//! A SECOND ceiling applies on top, which RFC 8693 does not require and this crate imposes anyway:
//! the issued token is issued TO the exchanging client, so its scope must also sit inside that
//! client's own registration ([`crate::client::Client::allowed_scopes`]). Without it, a client
//! registered for `read` could hold someone else's `write` token for a minute and mint itself a
//! `write` token of its own, which is the registration boundary defeated by a bearer string.
//!
//! # A SENDER-CONSTRAINED subject token is REFUSED, and this is the argued part
//!
//! RFC 9449 (DPoP) and RFC 8705 (mutual TLS) exist to buy ONE property: a token that leaks is worth
//! nothing to whoever finds it, because spending it needs a private key or a client certificate
//! that never left the legitimate client. An exchange takes a token STRING and returns a different
//! token. If it ignores the subject token's binding, then anyone able to authenticate as any client
//! registered for this grant, an insider, a compromised service, a leaked client secret, posts a
//! stolen bound token and receives a plain bearer token with the same subject, scope and audience.
//! The binding is gone and the theft is spendable. That is the exact property the deployment paid
//! for, defeated by one request.
//!
//! RFC 8693 does not settle this, so the choice is stated rather than assumed. Three candidates:
//!
//! - DOWNGRADE SILENTLY, which is what this crate did through 0.9.0 and is the one answer that is
//!   definitely wrong: the operator who turned DPoP on has no way to learn that a grant they also
//!   turned on removes it again.
//! - PROPAGATE the binding, so the issued token inherits the subject token's `cnf`. Attractive and
//!   still wrong here: the new token is issued TO THE EXCHANGING CLIENT, which does not hold the
//!   original client's key. The result is a token no conforming resource server would let its
//!   holder use (RFC 9449 section 7.1 requires a proof under the bound key on every request), which
//!   is a broken grant dressed as a secure one. Worse, it reads at a glance as though possession
//!   was proven, when nobody proved anything: the exchanging client presented a bearer string.
//! - REFUSE, which is what this crate does. A sender-constrained subject token is "unacceptable
//!   based on policy" in the sense of RFC 8693 section 2.2.2, and the section names `invalid_request`
//!   for exactly that. The refusal is loud, it happens at the AS rather than at some resource server
//!   later, and it cannot be mistaken for success.
//!
//! What would make an exchange of a bound token safe is the exchanging client PROVING possession of
//! the key the subject token is bound to, which is the RFC 9449 section 7 check a resource server
//! performs. That is a real design and it is deliberately not faked here: [`TokenExchangeRequest`]
//! carries no proof and no certificate, so there is nothing to check, and a seam that accepted one
//! would also have to bind the ISSUED token to the same key, at which point the exchange is a
//! delegation between two holders of one key rather than between two clients. If a deployment needs
//! that, it is an additive change to this request type and to the refusal below; it is not
//! something to approximate by waving the check through.
//!
//! # What this grant does NOT do, stated rather than left to be discovered
//!
//! - No refresh token is issued. RFC 8693 section 2.2.1 says one "will typically not be issued
//!   when the exchange is of one temporary credential for a different temporary credential", and
//!   issuing one would let an exchanged token outlive by rotation the grant it was derived from.
//! - The issued token's lifetime is the LESSER of
//!   [`crate::server::ServerConfig::access_token_ttl`] and the subject token's own remaining
//!   lifetime. Through 0.9.0 it was the former alone, and that contradicted the bullet immediately
//!   above: the exchanged token is an ordinary access token, so it is an acceptable subject token
//!   in its turn, and self-exchange is permitted. A client could therefore re-exchange just before
//!   each expiry and receive a fresh full TTL every time, renewing by exchange exactly the grant
//!   lifetime that withholding a refresh token was meant to bound. Clamping makes time behave the
//!   way scope, audience and RFC 9396 details already do here: an exchange may narrow, never widen.
//! - The `act` claim reaches a resource server BY BOTH ROUTES as of 0.9.1: it is persisted on
//!   [`crate::token::IssuedToken`] and reported by RFC 7662 introspection
//!   ([`crate::token::IntrospectionResponse::act`]), and under the `jwt` feature it is an RFC 9068
//!   claim in the signed access token ([`crate::jwt::AccessTokenClaims::act`]). This paragraph
//!   described a GAP through 0.9.0 and is kept as the record of why it closed when it did.
//!
//!   BOTH ROUTES ARE NEEDED, which an earlier draft of this paragraph got wrong by claiming the
//!   record alone had closed it. The two token formats reach a resource server differently: an
//!   OPAQUE token carries nothing, so introspection is the only channel it has, while a JWT is
//!   typically validated offline and introspected never. Persisting the claim and stopping there
//!   would have moved the deficiency from one deployment shape to the other rather than ending it.
//!
//!   Two things stood in the way and both are spent. The first was allocation, on the reasoning
//!   that [`crate::token::IssuedToken`] "is cloned on every token-plane request":
//!   [`crate::store::Storage::get_token`] returns an `Arc<IssuedToken>` now, so the record's shape
//!   costs a read nothing, and the field costs a deployment without this feature zero bytes and
//!   one with it 8 bytes per token plus one allocation per DELEGATED token.
//!
//!   The second was the real one, the PERSISTENCE CONTRACT: `IssuedToken` is the record every
//!   host's [`crate::store::Storage`] implementation writes and reads, so a new field is a
//!   migration in stores this crate does not own rather than a struct edit here. That is a
//!   coordinated change with a release behind it, and 0.9.1 is that release: it is already
//!   breaking `Storage` for the revocation-barrier rule, so a host migrates once instead of twice.
//!
//!   Why it was worth doing rather than deferring again: this crate's default access token is
//!   OPAQUE, so introspection is the ONLY channel a resource server has. A delegation it cannot
//!   see is a delegation the resource server has to take the host's word for, which collapses RFC
//!   8693 section 1.1 delegation back into impersonation from the one viewpoint the distinction
//!   exists for. Through 0.9.1 introspection answers only the token's own client, so on the opaque
//!   route that viewpoint is not yet served; the resource-server channel is 0.9.2 work, and the
//!   claim is persisted now because the record is the half that cannot be added later.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::error::{ErrorCode, ErrorResponse};
use crate::events::Event;
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::server::{AuthorizationServer, Bound, ClientCredential, Clock};
use crate::store::{Storage, StorageError};

/// The largest number of RFC 8693 section 2.1.1 `audience` values one exchange may carry.
///
/// Deliberately the SAME number as [`crate::server::MAX_RESOURCE_INDICATORS`], and not a second
/// judgement: section 2.1.1 says `audience` and `resource` name the same thing in two spellings,
/// one a logical name and one a URI, and this crate funnels both into one list against one ceiling.
/// Two constants would be two numbers a reader has to keep in step, for a distinction the RFC
/// itself does not draw.
///
/// The reason for a bound at all is the reason given on [`crate::server::MAX_RESOURCE_INDICATORS`]:
/// the parameter is repeatable and the dedup is an O(n) scan per element, so `n` is chosen by the
/// caller. This endpoint IS authenticated, which is why the finding is a rung lower, but a client
/// that has merely leaked its secret should not get an amplifier along with it.
pub const MAX_AUDIENCE_VALUES: usize = crate::server::MAX_RESOURCE_INDICATORS;

/// The longest RFC 8693 section 4.1 `act` chain this server will mint: the number of ACTORS the
/// nested claim may name, counting the current one.
///
/// A bound is required rather than tidy. Each delegation exchange nests the subject token's own
/// `act` inside the new one, and the result is PERSISTED on [`crate::token::IssuedToken`] and
/// serialized into every RFC 9068 access token and RFC 7662 introspection response the token
/// produces. Exchanging one's own token is explicitly permitted, so without a bound an
/// authenticated client can loop — exchange, then exchange the result — and each hop adds a link
/// that every later read pays for, in the store and on the wire. That is a client choosing how much
/// storage the server spends, which is the same shape as the repeatable-parameter bounds above.
///
/// Eight is chosen against real topologies rather than against the RFC, which sets no limit:
/// section 1.1's delegation is a call graph, and a request that has legitimately crossed eight
/// distinct delegating services has a shape an operator should be told about rather than one this
/// server should quietly extend. A chain at the bound is refused with section 2.2.2's
/// `invalid_request` rather than TRUNCATED, because truncation would silently discard exactly the
/// audit history the nesting exists to keep, and a server that quietly forgets who acted earlier is
/// worse than one that says it will not go further.
pub const MAX_ACT_CHAIN_DEPTH: usize = 8;

use crate::token::TokenType;

pub use crate::grant::TOKEN_EXCHANGE_GRANT_URN;

/// The RFC 8693 section 3 token type identifiers.
///
/// The URNs are the wire values, verbatim. This is a closed enum rather than a string because the
/// `subject_token_type` is a security-relevant statement about how the presented string must be
/// checked, and "a type identifier this server did not recognise" has to be a REFUSAL rather than
/// something that falls through to a default (RFC 8693 section 2.2.2: a subject token that is
/// unacceptable based on policy is an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenTypeIdentifier {
    /// `urn:ietf:params:oauth:token-type:access_token`. The only type this server accepts as a
    /// subject or actor token, and the only type it issues.
    #[serde(rename = "urn:ietf:params:oauth:token-type:access_token")]
    AccessToken,
    /// `urn:ietf:params:oauth:token-type:refresh_token`.
    #[serde(rename = "urn:ietf:params:oauth:token-type:refresh_token")]
    RefreshToken,
    /// `urn:ietf:params:oauth:token-type:id_token`.
    #[serde(rename = "urn:ietf:params:oauth:token-type:id_token")]
    IdToken,
    /// `urn:ietf:params:oauth:token-type:saml1`.
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml1")]
    Saml1,
    /// `urn:ietf:params:oauth:token-type:saml2`.
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml2")]
    Saml2,
    /// `urn:ietf:params:oauth:token-type:jwt`. Note that RFC 8693 section 3 defines this as "any
    /// JWT", which is a statement about ENCODING and not about who issued it; this server does not
    /// accept it, because accepting a JWT as a subject token means deciding whose signature to
    /// trust, and that is a policy no library can pick on a host's behalf.
    #[serde(rename = "urn:ietf:params:oauth:token-type:jwt")]
    Jwt,
}

impl TokenTypeIdentifier {
    /// Resolve a wire `*_token_type` value WITHOUT allocating, returning `None` for anything RFC
    /// 8693 section 3 does not register.
    ///
    /// This is the parse the HTTP surface uses, for the reason [`crate::grant::GrantType::parse`]
    /// exists: [`FromStr`]'s error carries the caller's value, and the router deliberately does not
    /// echo it (RFC 6749 s5.2 restricts `error_description` to a charset an attacker-supplied URN
    /// need not respect), so the copy was allocated and dropped unread. The refusal STRING here was
    /// already made a `&'static str` for exactly this rule; the allocation underneath it was
    /// missed, and it is the worse one, because the caller chooses its SIZE and this refusal
    /// happens before the presented client credential has been checked.
    ///
    /// [`FromStr`] is unchanged and still carries the value, for the host-side callers that want
    /// to report which URN they got wrong.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "urn:ietf:params:oauth:token-type:access_token" => {
                Some(TokenTypeIdentifier::AccessToken)
            }
            "urn:ietf:params:oauth:token-type:refresh_token" => {
                Some(TokenTypeIdentifier::RefreshToken)
            }
            "urn:ietf:params:oauth:token-type:id_token" => Some(TokenTypeIdentifier::IdToken),
            "urn:ietf:params:oauth:token-type:saml1" => Some(TokenTypeIdentifier::Saml1),
            "urn:ietf:params:oauth:token-type:saml2" => Some(TokenTypeIdentifier::Saml2),
            "urn:ietf:params:oauth:token-type:jwt" => Some(TokenTypeIdentifier::Jwt),
            _ => None,
        }
    }

    /// The registered URN, verbatim.
    pub fn as_str(self) -> &'static str {
        match self {
            TokenTypeIdentifier::AccessToken => "urn:ietf:params:oauth:token-type:access_token",
            TokenTypeIdentifier::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
            TokenTypeIdentifier::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            TokenTypeIdentifier::Saml1 => "urn:ietf:params:oauth:token-type:saml1",
            TokenTypeIdentifier::Saml2 => "urn:ietf:params:oauth:token-type:saml2",
            TokenTypeIdentifier::Jwt => "urn:ietf:params:oauth:token-type:jwt",
        }
    }
}

impl fmt::Display for TokenTypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The rejection for a `*_token_type` value that is not one RFC 8693 section 3 registers.
///
/// The payload is SEALED and read through [`UnknownTokenTypeIdentifier::identifier`], matching
/// [`crate::par::RequestObjectKeyError`], which is the crate's other one-payload rejection type.
/// The two disagreed: this one published its `String` as a tuple field, so a host could also
/// CONSTRUCT one and hand it to code that reasonably assumed only this crate mints them. Readable
/// and not forgeable is the rule both follow now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTokenTypeIdentifier(String);

impl UnknownTokenTypeIdentifier {
    /// The unregistered identifier, exactly as it arrived.
    ///
    /// Echoing it back is safe and useful: it is a `*_token_type` URN out of the request, not a
    /// token, and a host debugging an interoperability failure needs to see what the peer sent.
    pub fn identifier(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownTokenTypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown token type identifier {:?}", self.0)
    }
}

impl std::error::Error for UnknownTokenTypeIdentifier {}

impl FromStr for TokenTypeIdentifier {
    type Err = UnknownTokenTypeIdentifier;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TokenTypeIdentifier::parse(s).ok_or_else(|| UnknownTokenTypeIdentifier(s.to_string()))
    }
}

/// Which of RFC 8693 section 1.1's two semantics an exchange produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeSemantics {
    /// No acting party was presented: the issued token is indistinguishable from one the subject
    /// holds directly, within the rights context it covers.
    Impersonation,
    /// An acting party authenticated and is named in [`ExchangedToken::act`]: the issued token
    /// says "the actor, acting for the subject".
    Delegation,
}

/// The RFC 8693 section 4.1 `act` (actor) claim: who authority was delegated TO.
///
/// Section 4.1 is explicit about what a consumer may do with it: "the consumer of a token MUST
/// only consider the token's top-level claims and the party identified as the current actor by the
/// act claim", and a nested `act` is a PRIOR actor, kept for audit rather than for authorization.
/// That is why [`ActClaim::act`] is boxed and optional rather than a flat list: the nesting IS the
/// ordering, and flattening it would lose which actor is current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    /// The acting party's subject identifier.
    pub sub: String,
    /// RFC 8693 section 4.3 `client_id`, when the actor is (or authenticated as) a client. Present
    /// here because for a machine-to-machine actor the client identifier is frequently the only
    /// identity there is, and section 4.1's example carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// A PRIOR actor in the delegation chain (section 4.1). The outermost claim is the current
    /// actor; anything nested inside acted earlier.
    ///
    /// BOXED because the type is otherwise infinitely sized, and because the overwhelmingly common
    /// chain is one link long and should not carry the storage for more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

/// An RFC 8693 section 2.1 token exchange request, as the host parsed it off the wire.
///
/// Borrowed rather than owned: a token-endpoint request is parsed, judged and dropped, and the
/// three credentials in here (`client_secret`, `subject_token`, `actor_token`) are strings a host
/// should be copying as little as possible.
///
/// `Debug` is hand-written (see below) rather than derived, for the reason
/// [`crate::server::TokenRequest`] gives: every one of those three is a bearer credential, and this
/// is precisely the value a host is most likely to debug-print, because it is the request it just
/// parsed.
#[derive(Clone, PartialEq, Eq)]
/// `#[non_exhaustive]`: the two `client-assertion` fields appear only under that feature, so a host
/// that writes this as a literal is writing one of two different structs and does not get to choose
/// which. [`TokenExchangeRequest::new`] already exists and already says the rest is "optional and
/// set on the returned value"; the attribute is what makes that the only way in, rather than the
/// documented way in that a literal quietly bypasses.
#[non_exhaustive]
pub struct TokenExchangeRequest<'a> {
    /// The client performing the exchange. It is authenticated, and it is the client the issued
    /// token belongs to.
    pub client_id: &'a ClientId,
    /// Its secret, for a client registered for `client_secret_basic` or `client_secret_post`.
    /// A confidential credential of SOME kind is required: see [`TokenExchange::exchange_token`]
    /// on why a public client may not use this grant.
    pub client_secret: Option<&'a str>,
    /// RFC 7521 section 4.2 `client_assertion_type`, for a client registered for
    /// `private_key_jwt` or `client_secret_jwt`.
    ///
    /// This field and the one below exist because RFC 8693 section 2.1 authenticates the client
    /// "as described in Section 2.3 of \[RFC6749\]", which is a reference to every method the server
    /// offers and not to shared secrets alone. Carrying only `client_secret` meant a confidential
    /// client registered for assertion authentication was answered `invalid_client` on a grant the
    /// RFC 8414 document advertises to it: the credential it presented had nowhere to travel.
    #[cfg(feature = "client-assertion")]
    pub client_assertion_type: Option<&'a str>,
    /// RFC 7523 section 2.2 `client-assertion`: the signed JWT itself.
    #[cfg(feature = "client-assertion")]
    pub client_assertion: Option<&'a str>,
    /// REQUIRED (section 2.1). The token representing the party on whose behalf the request is
    /// made.
    pub subject_token: &'a str,
    /// REQUIRED (section 2.1). The type of `subject_token`.
    pub subject_token_type: TokenTypeIdentifier,
    /// OPTIONAL (section 2.1). The token representing the ACTING party. Its presence is what makes
    /// the exchange delegation rather than impersonation.
    pub actor_token: Option<&'a str>,
    /// REQUIRED when `actor_token` is present, and meaningless without it (section 2.1).
    pub actor_token_type: Option<TokenTypeIdentifier>,
    /// OPTIONAL (section 2.1). RFC 8707 resource indicators for the target service. May only
    /// narrow what the subject token already carries.
    pub resource: &'a [String],
    /// OPTIONAL (section 2.1). The logical name of the target service.
    ///
    /// Section 2.1.1 relates `audience` and `resource`: both name where the client intends to use
    /// the token, differing in whether the name is a URI. This crate has exactly ONE audience
    /// model, the RFC 8707 resource indicator recorded on the grant, so an `audience` value is
    /// checked against the same ceiling as a `resource` value. A logical name the subject token
    /// does not already carry can therefore never be granted, and answers `invalid_target`.
    pub audience: &'a [String],
    /// OPTIONAL (section 2.1). Narrows the issued token's scope; never widens it.
    pub scope: Option<&'a ScopeSet>,
    /// OPTIONAL (section 2.1). Absent means the server's own choice, which for this server is
    /// always an access token.
    pub requested_token_type: Option<TokenTypeIdentifier>,
}

impl<'a> TokenExchangeRequest<'a> {
    /// The minimum request RFC 8693 section 2.1 admits: a client, the subject token it is
    /// exchanging, and WHAT THE CALLER SAYS THAT TOKEN IS. Everything else is optional and set on
    /// the returned value.
    ///
    /// `subject_token_type` is an argument rather than a default because it is the parameter the
    /// exchange refuses on (see [`TokenExchange::exchange_token`]): a caller that presents a refresh
    /// token and labels it an access token is asking this server to check the string a different
    /// way than it is going to, and refusing the mismatch is what stops the type parameter being
    /// decorative. Section 2.1 makes it REQUIRED. Defaulting it here meant a host that assembled
    /// the request in code, and forgot to copy the form field across, silently converted that
    /// refusal into a pass, because the value the constructor invented is precisely the one value
    /// that passes.
    pub fn new(
        client_id: &'a ClientId,
        subject_token: &'a str,
        subject_token_type: TokenTypeIdentifier,
    ) -> Self {
        TokenExchangeRequest {
            client_id,
            client_secret: None,
            #[cfg(feature = "client-assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client-assertion")]
            client_assertion: None,
            subject_token,
            subject_token_type,
            actor_token: None,
            actor_token_type: None,
            resource: &[],
            audience: &[],
            scope: None,
            requested_token_type: None,
        }
    }
}

/// Hand-written so no credential reaches a debug format, while everything that identifies WHICH
/// exchange this is stays visible. The Some/None distinction is kept for the redacted fields
/// because it is not a credential: it is the difference between an impersonation request and a
/// delegation request, which is the first thing anyone debugging this grant needs to see.
impl fmt::Debug for TokenExchangeRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redact_opt<T>(value: &Option<T>) -> Option<&'static str> {
            value.as_ref().map(|_| "[redacted]")
        }
        let mut out = f.debug_struct("TokenExchangeRequest");
        out.field("client_id", &self.client_id)
            .field("client_secret", &redact_opt(&self.client_secret));
        // The assertion is a bearer credential for as long as it is unexpired (RFC 7523 s3), so it
        // is redacted exactly as the secret is. The TYPE is printed, because it is not a
        // credential (it is a fixed URN) and a mistyped one is the commonest way this
        // authentication method fails.
        #[cfg(feature = "client-assertion")]
        out.field("client_assertion_type", &self.client_assertion_type)
            .field("client_assertion", &redact_opt(&self.client_assertion));
        out.field("subject_token", &"[redacted]")
            .field("subject_token_type", &self.subject_token_type)
            .field("actor_token", &redact_opt(&self.actor_token))
            .field("actor_token_type", &self.actor_token_type)
            .field("resource", &self.resource)
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .field("requested_token_type", &self.requested_token_type)
            .finish()
    }
}

/// The RFC 8693 section 2.2.1 successful response.
///
/// Deliberately NOT [`crate::token::TokenResponse`]: section 2.2.1 adds `issued_token_type` as
/// REQUIRED, and the meaning of `access_token` widens to "the security token issued", which need
/// not be an OAuth access token at all. Reusing the RFC 6749 section 5.1 type would have made
/// `issued_token_type` optional in the type system, and a REQUIRED member that the type lets you
/// forget is a member that eventually goes missing.
///
/// `Debug` is hand-written so the issued token does not print, matching every other credential
/// carrying type in this crate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenExchangeResponse {
    /// REQUIRED (section 2.2.1). The security token issued.
    pub access_token: String,
    /// REQUIRED (section 2.2.1). An identifier for the representation of the issued token. Always
    /// `urn:ietf:params:oauth:token-type:access_token` from this server.
    pub issued_token_type: TokenTypeIdentifier,
    /// REQUIRED (section 2.2.1), and REQUIRED even though the issued token "need not be an OAuth
    /// access token": it states the method of using it. Always `Bearer` here (RFC 6750).
    pub token_type: TokenType,
    /// RECOMMENDED (section 2.2.1). This server always includes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// OPTIONAL if identical to the requested scope, REQUIRED otherwise (section 2.2.1). This
    /// server always includes it when non-empty, which satisfies the stronger of the two: an
    /// exchange narrows, so the issued scope frequently differs from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// OPTIONAL (section 2.2.1), and never issued by this server. See the module docs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl fmt::Debug for TokenExchangeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeResponse")
            .field("access_token", &"[redacted]")
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// What an exchange produced: the wire response, plus the two things a host needs that are NOT
/// wire response members.
///
/// `semantics` and `act` are separated from [`TokenExchangeResponse`] rather than living on it
/// with `#[serde(skip)]`, because RFC 8693 section 2.2.1 defines the response members exhaustively
/// and `act` is a TOKEN CLAIM (section 4.1), not a response parameter. A type that serialized to
/// something the RFC does not define would be wrong in the one place this crate cannot afford to
/// be approximate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangedToken {
    /// The RFC 8693 section 2.2.1 body, ready to serialize.
    pub response: TokenExchangeResponse,
    /// Whether this exchange was delegation or impersonation (section 1.1).
    pub semantics: ExchangeSemantics,
    /// The section 4.1 `act` claim, present exactly when `semantics` is
    /// [`ExchangeSemantics::Delegation`]. See the module docs for why this crate hands it back
    /// rather than putting it in its own opaque token.
    pub act: Option<ActClaim>,
}

/// RFC 8693 token exchange, as an extension trait on [`AuthorizationServer`].
///
/// A trait rather than an inherent method because the grant is behind an off-by-default cargo
/// feature, and a feature should add a name a reader can find rather than silently change the
/// shape of a type they already know.
pub trait TokenExchange {
    /// Exchange `subject_token` for a new token, per RFC 8693 section 2.
    ///
    /// The caller MUST be a confidential client. RFC 8693 gives the AS the decision (section 2.1
    /// leaves client authentication to the deployment), and this server decides the same way it
    /// decides for client credentials, introspection and revocation: a public client identifier is
    /// a string anyone may claim, so "authenticated as a public client" is a sentence true of
    /// every caller on the internet. A grant whose entire job is to convert one principal's
    /// authority into another's cannot rest on that.
    ///
    /// The client's registration must also include
    /// [`crate::grant::GrantType::TokenExchange`], or the answer is `unauthorized_client`. Who may
    /// exchange is a deployment decision, and this crate records deployment decisions about grants
    /// in exactly one place.
    fn exchange_token(
        &self,
        request: &TokenExchangeRequest<'_>,
    ) -> impl std::future::Future<Output = Result<ExchangedToken, ErrorResponse>> + Send;
}

impl<S: Storage, C: Clock> TokenExchange for AuthorizationServer<S, C> {
    async fn exchange_token(
        &self,
        request: &TokenExchangeRequest<'_>,
    ) -> Result<ExchangedToken, ErrorResponse> {
        let outcome = exchange(self, request).await;
        // The same audit answer every other grant gets from
        // `AuthorizationServer::token_with_resources`: a host that installed a sink hears about
        // refusals, and a refused exchange is a more interesting line than most, because the thing
        // being refused is usually an attempt to widen.
        if let Err(error) = &outcome {
            self.hooks().emit(|| Event::GrantRefused {
                client_id: request.client_id.as_str(),
                grant_type: GrantType::TokenExchange,
                error: error.error,
            });
        }
        outcome
    }
}

/// The host sees the real error through its own `Storage` impl; the wire gets the opaque code.
/// Same shape as `server.rs`'s own helper, which is private to that module.
fn storage_error(e: StorageError) -> ErrorResponse {
    let _ = e;
    ErrorResponse::new(ErrorCode::ServerError)
}

/// The refusal for a sender-constrained subject token. One function for both mechanisms, so DPoP
/// and mutual TLS cannot drift into two different answers for one rule.
///
/// Feature gated because both of its callers are, and a function with no caller is a warning the
/// gate treats as an error.
#[cfg(any(feature = "dpop", feature = "mtls"))]
fn sender_constrained_refusal(mechanism: &str) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest).with_description(format!(
        "subject_token is sender constrained by {mechanism} and cannot be exchanged for a token \
         that is not, because the issued token would belong to a client that cannot prove \
         possession of the binding key"
    ))
}

/// How many actors an RFC 8693 section 4.1 `act` claim names, counting the outermost (current) one.
///
/// ITERATIVE rather than recursive, and that is the point of writing it out. The claim is a linked
/// list this server READS BACK OUT OF ITS OWN STORE, and a store is something a host operates: a
/// record deeper than the stack could take would be a crash on the token endpoint rather than a
/// refusal, which is the failure mode `MAX_ACT_CHAIN_DEPTH` exists to prevent and not one to
/// reintroduce in the counting. It also stops early, because the only question the caller asks is
/// whether the bound has been reached.
fn act_chain_depth(act: &ActClaim) -> usize {
    let mut depth = 1;
    let mut current = &act.act;
    while let Some(next) = current {
        depth += 1;
        if depth >= MAX_ACT_CHAIN_DEPTH {
            return depth;
        }
        current = &next.act;
    }
    depth
}

/// The exchange itself. Split out of the trait method so the audit emission above wraps every exit
/// from it, exactly as `AuthorizationServer::emit_refusal` wraps the other four grants.
async fn exchange<S: Storage, C: Clock>(
    server: &AuthorizationServer<S, C>,
    request: &TokenExchangeRequest<'_>,
) -> Result<ExchangedToken, ErrorResponse> {
    // 1. What is being asked for (section 2.1 `requested_token_type`). Checked FIRST and before
    //    any credential is looked at, because it costs nothing and because a client asking for a
    //    SAML assertion from a server that issues opaque bearer tokens has made a mistake that no
    //    amount of correct authentication will fix.
    //
    //    Section 2.1 leaves the type to the server when the parameter is absent, and this server
    //    issues exactly one kind of token, so absent and `access_token` are the same request.
    let issued_token_type = match request.requested_token_type {
        None | Some(TokenTypeIdentifier::AccessToken) => TokenTypeIdentifier::AccessToken,
        Some(_) => {
            return Err(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                    "this server issues only urn:ietf:params:oauth:token-type:access_token",
                ),
            )
        }
    };

    // 2. The client. See `TokenExchange::exchange_token` for why confidential only.
    // RFC 8693 s2.1 authenticates the client the same way every other grant does, so it goes
    // through the same value, and it carries EVERY credential shape the request could have
    // presented rather than the shared secret alone. Section 2.1 points at RFC 6749 s2.3, which is
    // a reference to whatever methods the server offers; `Bound::secret` discarded an RFC 7523
    // assertion, so a confidential client registered for `private_key_jwt` or `client_secret_jwt`
    // was answered `invalid_client` on a grant this server's RFC 8414 document advertises to it.
    //
    // No RFC 9449 binding, and that is now ENFORCED rather than assumed: this surface is not
    // handed a proof, so a token issued here cannot be bound, and the HTTP router refuses a
    // token-exchange request that presented one rather than quietly issuing an unbound token. See
    // this module's "A SENDER-CONSTRAINED subject token is REFUSED" section, which makes the same
    // argument about the subject token and would contradict itself if the ISSUED token were
    // silently downgraded.
    let bound = Bound {
        cred: ClientCredential {
            client_secret: request.client_secret,
            #[cfg(feature = "client-assertion")]
            client_assertion_type: request.client_assertion_type,
            #[cfg(feature = "client-assertion")]
            client_assertion: request.client_assertion,
            // RFC 8705 is deliberately NOT threaded through here. A certificate authenticates AND
            // binds (section 3), and this surface has nowhere to record the binding, so accepting
            // one would issue an unbound token to a client that proved possession of a key: the
            // silent downgrade this module refuses everywhere else. An mTLS-only client is
            // refused `invalid_client` here, which is loud and is the honest answer until the
            // exchange can carry a binding.
            #[cfg(feature = "mtls")]
            certificate: None,
        },
        #[cfg(feature = "dpop")]
        jkt: None,
    };
    let client = server
        .authenticate_client(request.client_id, &bound.cred)
        .await?;
    if !client.auth.is_confidential() {
        return Err(ErrorResponse::new(ErrorCode::InvalidClient)
            .with_description("token exchange requires a confidential client"));
    }
    if !client.allows_grant(GrantType::TokenExchange) {
        return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
            .with_description("client registration does not include the token-exchange grant"));
    }

    // 3. The subject token (section 2.1). Only this server's own access tokens are accepted, and
    //    the type identifier has to SAY so: a caller that presents a refresh token and labels it
    //    an access token, or presents an access token and labels it a JWT, is asking this server
    //    to check the string a different way than it is going to. Refusing on the mismatch rather
    //    than on the lookup is what stops the type parameter becoming decorative.
    if request.subject_token_type != TokenTypeIdentifier::AccessToken {
        return Err(
            ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token",
            ),
        );
    }
    let subject = server
        .introspect(request.subject_token)
        .await
        .map_err(storage_error)?
        // Unknown, expired and revoked are one answer: the caller holds a string this server will
        // not exchange, and which of the three it is describes a token they may not hold.
        .ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("subject_token is not a live access token")
        })?;

    // 3b. The subject token's SENDER CONSTRAINING (RFC 9449 section 6, RFC 8705 section 3). A bound
    //     token may not be exchanged, because the token this server would issue is a BEARER token
    //     for a different client, and issuing it converts a token that survives theft into one that
    //     does not. The exchanging client proved possession of its own secret and of nothing else:
    //     it presented the subject token as a string, which is precisely what a thief also has. See
    //     the module docs for why this is a refusal rather than a propagated `cnf`.
    //
    //     RFC 8693 section 2.2.2 gives `invalid_request` for a subject token that is unacceptable
    //     based on policy, which is what this is. The description names the mechanism because a
    //     legitimate client hitting this needs to know WHY, and it is not a secret: the client just
    //     presented the token that carries the binding.
    //
    //     GUARDED by `ServerConfig::allow_sender_constrained_exchange`, which is `false` by
    //     default. The opt-in exists only because 0.9.0 and earlier performed this downgrade
    //     SILENTLY, so a deployment already built on it needs a migration window; a host that sets
    //     it has decided its delegation topology is trusted enough to hold the binding for it. What
    //     it gives up is stated on the field, and it is the whole of what DPoP or mutual TLS was
    //     bought for.
    #[cfg(feature = "dpop")]
    if subject.jkt.is_some() && !server.config().allow_sender_constrained_exchange {
        return Err(sender_constrained_refusal("DPoP (RFC 9449)"));
    }
    #[cfg(feature = "mtls")]
    if subject.x5t_s256.is_some() && !server.config().allow_sender_constrained_exchange {
        return Err(sender_constrained_refusal("mutual TLS (RFC 8705)"));
    }

    // 4. The actor token (section 2.1), which is what makes this delegation rather than
    //    impersonation (section 1.1).
    let (semantics, act) = match (request.actor_token, request.actor_token_type) {
        (None, None) => (ExchangeSemantics::Impersonation, None),
        // Section 2.1 makes actor_token_type REQUIRED when actor_token is present. The reverse is
        // not a defined request at all, and reading it as impersonation would silently discard a
        // parameter the client thought it was sending.
        (None, Some(_)) => {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("actor_token_type is meaningless without actor_token"))
        }
        (Some(_), None) => {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("actor_token_type is required when actor_token is present"))
        }
        (Some(actor_token), Some(actor_token_type)) => {
            if actor_token_type != TokenTypeIdentifier::AccessToken {
                return Err(
                    ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                        "actor_token_type must be urn:ietf:params:oauth:token-type:access_token",
                    ),
                );
            }
            // ONE refusal for every way an actor token can be unusable, built once so the two
            // sites below cannot drift apart. See the comment on the ownership check for why the
            // mismatch is not allowed its own wording.
            let unusable = || {
                ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("actor_token is not a live access token")
            };
            let actor = server
                .introspect(actor_token)
                .await
                .map_err(storage_error)?
                .ok_or_else(unusable)?;
            // The acting party must be the party that just authenticated. Section 4.1 has the
            // `act` claim "identify the acting party to whom authority has been delegated", and a
            // server that will write any name there on production of a bearer string is not
            // identifying anybody: it is transcribing. The client proved possession of its secret
            // one step ago; the holder of a third party's access token proved possession of a
            // string that leaks.
            //
            // THE REFUSAL IS THE SAME STRING AS THE ONE ABOVE, and that is the point rather than
            // an economy. A description naming the ownership mismatch answers a question the
            // caller was not entitled to ask: it says the string they presented IS a live access
            // token, and that it belongs to somebody else. Any client holding this grant could
            // then test arbitrary strings and learn which ones are live tokens of other clients,
            // which is exactly the oracle `introspection_response` refuses to be for the same
            // three cases ("unknown, expired, or somebody else's"), and which the subject token
            // seventy lines above already collapses. A legitimate delegating client presents its
            // OWN token here, so it never reads either string.
            if actor.client_id != client.client_id {
                return Err(unusable());
            }
            // THE PRIOR CHAIN, and how much of it this server will carry. Counted BEFORE anything
            // is built, so a refusal costs one walk of a bounded list and no allocation.
            if let Some(prior) = &subject.act {
                if act_chain_depth(prior) >= MAX_ACT_CHAIN_DEPTH {
                    return Err(
                        ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                            "the subject token's act chain is already at this server's maximum \
                         delegation depth",
                        ),
                    );
                }
            }
            let act = ActClaim {
                // RFC 9068 section 2.2's answer for a grant with no resource owner is the client
                // identifier, and the same answer is right here: an actor token minted by the
                // client credentials grant names no user, and the acting party is then the client
                // itself rather than nobody.
                sub: actor
                    .subject
                    .clone()
                    .unwrap_or_else(|| actor.client_id.as_str().to_string()),
                client_id: Some(actor.client_id.as_str().to_string()),
                // Section 4.1's nesting expresses a chain of PRIOR actors, and this is where it
                // comes from: whatever the SUBJECT token already recorded, moved one level in, so
                // the new actor is the outermost and current one.
                //
                // This was `None` with a comment saying "this server does not yet carry `act`
                // inside its own tokens", which 0.9.1 made false in the same file: the claim is
                // persisted on `IssuedToken` and reported by introspection. Truncating on the
                // strength of that stale comment turned A -> B -> C into `act={sub:C}`, where
                // section 4.1 defines `{sub:C, act:{sub:B}}`, so a resource server auditing the
                // chain was told the delegation started at B. Depth is bounded by
                // `MAX_ACT_CHAIN_DEPTH`, checked above.
                act: subject.act.clone(),
            };
            (ExchangeSemantics::Delegation, Some(act))
        }
    };

    // 5. SCOPE, first ceiling. RFC 6749 section 6's narrowing rule, applied to the subject token's
    //    granted scope. This is the attack: the whole value of an exchange to an attacker is
    //    getting out more than went in.
    let scope = match request.scope {
        None => subject.scope.clone(),
        Some(s) if s.is_subset(&subject.scope) => s.clone(),
        Some(_) => {
            return Err(
                ErrorResponse::new(ErrorCode::InvalidScope).with_description(
                    "token exchange may narrow the subject token scope, never widen it",
                ),
            )
        }
    };
    // SCOPE, second ceiling. The issued token belongs to the EXCHANGING client, so it cannot carry
    // scope that client's own registration never permitted. See the module docs: without this, a
    // read-only client that momentarily holds someone else's write token can mint itself one.
    if !scope.is_subset(&client.allowed_scopes) {
        return Err(ErrorResponse::new(ErrorCode::InvalidScope)
            .with_description("scope exceeds the exchanging client registration"));
    }
    // RFC 9396 DETAILS, and the reason this refusal sits with the scope ceilings rather than near
    // the propagation site: it is the SAME ceiling, and its absence was the whole defect.
    //
    // Scope gets two ceilings above. `authorization_details` got none: they were copied onto the
    // issued token unchanged, justified by "it is exactly what the token the client just presented
    // already carried". That is precisely the argument the second ceiling four lines up REJECTS for
    // scope, and for the same reason, which is that the issued token belongs to the EXCHANGING
    // client and not to the one the subject token was minted for.
    //
    // The asymmetry ran the wrong way. A RAR element is strictly more specific than the scope that
    // accompanies it (RFC 9396 exists because a scope token cannot say "transfer 50 euros to IBAN
    // X"), so the crate applied its weaker rule to its more dangerous grant. Concretely: a
    // downstream service registered for `read`, holding a payments client's token because
    // forwarding the caller's token is what this grant is FOR, could ask for `read`, satisfy both
    // scope ceilings, and receive a token issued to ITSELF carrying the payment authorization, with
    // a fresh lifetime that outlives the token it came from.
    //
    // There is nothing to narrow AGAINST: `Client` has `allowed_scopes` and no equivalent for
    // detail types, so the per-client ceiling that would make this safe does not exist yet and
    // adding it breaks a type hosts construct. So this refuses, and a host that has reasoned about
    // its delegation topology can say so with `allow_authorization_details_exchange`.
    //
    // RFC 8693 section 2.2.2 names `invalid_request` for a subject token unacceptable on policy,
    // which is what this is; `invalid_target` is for a requested RESOURCE the AS will not issue
    // for, and the client requested no target here. The description names the mechanism because a
    // legitimate client hitting this needs to know why, and it reveals nothing: the client is
    // holding the token whose details these are.
    //
    // SCOPED TO A CROSS-CLIENT EXCHANGE, and that scoping is the argument rather than a
    // convenience. Everything above turns on the issued token belonging to a DIFFERENT principal
    // than the subject token. When the exchanging client IS the client the subject token was issued
    // to, no boundary is crossed: it already holds those details, on a token it can already spend,
    // and refusing would block a client from exchanging its own token for a narrower one, which is
    // an ordinary and safe use of this grant. A blanket refusal here would have been over-broad,
    // and the test that caught it was right to.
    #[cfg(feature = "rar")]
    if !subject.authorization_details.is_empty()
        && subject.client_id != client.client_id
        && !server.config().allow_authorization_details_exchange
    {
        return Err(
            ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                "subject_token carries authorization_details and cannot be exchanged for a token \
             issued to a different client, because this server has no per-client registration of \
             the detail types that client may hold",
            ),
        );
    }

    // 6. RESOURCE and AUDIENCE, the audience ceiling (RFC 8707 section 2, RFC 8693 section 2.1.1).
    //    `validate_resources` and `narrow_resources` are the SAME functions the authorization code
    //    and refresh grants use. That is deliberate and is the point: a second implementation of
    //    "may narrow, never widen" is a second thing to get wrong, and this one would be the one
    //    nobody reviews.
    let mut targets = server.validate_resources(request.resource.iter().map(|r| r.as_str()))?;
    // Section 2.1.1: `audience` names the same thing as `resource` in a form that need not be a
    // URI. It is NOT run through `validate_resources`, which requires an absolute URI, because
    // that would report a well-formed logical name as malformed; it goes to the same ceiling
    // instead, where a name the subject token does not carry is `invalid_target` rather than
    // `invalid_request`. A deployment whose audiences are not resource indicators therefore finds
    // that no `audience` value is grantable here, which is the truth rather than a silent success.
    // CAPPED, for the reason `validate_resources` is capped and with the same number: `audience`
    // is repeatable, it is deduplicated against `targets` with an O(n) scan per element, and
    // nothing bounded either side. Checked on the INPUT length rather than on `targets`, because a
    // caller sending one value ten thousand times still pays a full scan per copy even though the
    // result stays small.
    if request.audience.len() > MAX_AUDIENCE_VALUES {
        return Err(ErrorResponse::new(ErrorCode::InvalidTarget)
            .with_description("too many audience values (RFC 8693 s2.1.1)"));
    }
    for audience in request.audience {
        // SKIPPING THE SYNTAX CHECK IS NOT SKIPPING THE ALLOWLIST, and through 0.9.1 it was both.
        // `ServerConfig::allowed_resources` is this server's RFC 8707 section 2 statement of what
        // it is unwilling to issue for — the way an operator decommissions a resource server — and
        // the `audience` spelling walked straight past it. An operator who removed R from that list
        // went on handing out signed tokens whose `aud` names R, to any client holding a live token
        // whose grant had recorded R, because `narrow_resources` below only asks whether the
        // SUBJECT TOKEN carries the value and never whether the server still stands behind it.
        server.target_is_permitted(audience)?;
        if !targets.iter().any(|t| t == audience) {
            targets.push(audience.clone());
        }
    }
    // `narrow_and_permit`, not `narrow_resources`: the allowlist has to apply to what is ISSUED and
    // not only to what was NAMED. The loop above covers an `audience` the request spelled out, but
    // a request naming NEITHER `resource` nor `audience` inherits the subject token's whole
    // recorded list untouched, and that list can name a resource server this deployment has since
    // decommissioned. See `AuthorizationServer::narrow_and_permit`.
    let resource = server.narrow_and_permit(&subject.resource, &targets)?;

    // 7. Issue. Through the SAME `issue` every other grant goes through, so the exchanged token is
    //    persisted, introspectable, revocable and (with the `jwt` feature) signed exactly like any
    //    other token this server mints.
    //
    //    `None` chain and `false` for refresh: RFC 8693 section 2.2.1 on why no refresh token, and
    //    a token with no chain has no family, which is right here because there is nothing to
    //    rotate and so nothing a reuse detection could revoke.
    let issued = server
        .issue(
            &client,
            &bound,
            GrantType::TokenExchange,
            // INHERITED from the subject token, not restamped. The exchanged token derives its
            // authority from that grant, so a revocation reaching the grant must reach everything
            // exchanged out of it; stamping `now` here would let an exchange launder a token past
            // the revocation of the decision it descends from.
            //
            // THE INSTANT IS INHERITED AND THE IDENTITY IS NOT, and that is a gap rather than a
            // decision. A `RevocationBarrier` for a withdrawn consent, and the cascade underneath
            // it, both ask for the (client_id, subject) pair of the grant being ended; the token
            // issued below carries the subject and the instant but belongs to the EXCHANGING
            // client, so a cross-client exchange lands outside the reach of the withdrawal of the
            // consent it descends from. `Storage::revoke_consent` states the same thing from the
            // other side, with what it costs and what closing it needs. The lifetime ceiling at the
            // end of this call is what bounds it: the descendant cannot outlive the token it was
            // exchanged out of, so the overrun is one access token lifetime and not a fresh grant.
            subject.grant_established_at,
            subject.subject.clone(),
            scope,
            resource,
            // RFC 9396: the exchanged token inherits the subject token's authorization details
            // unchanged, and reaching this line at all means the ceiling above let it. Either the
            // subject token carried no details, or the host set
            // `allow_authorization_details_exchange` and accepted what that gives up.
            //
            // The justification that used to sit here said propagation "is never a widening,
            // because it is exactly what the token the client just presented already carried". That
            // was false, and it was false in the same way for scope, where this file rejects the
            // identical argument two ceilings earlier: the issued token belongs to the EXCHANGING
            // client, so what the SUBJECT token was allowed to carry is not the question.
            crate::server::GrantedDetails::of_token(&subject),
            None,
            false,
            // RFC 8693 s1: a client is presenting a token, not a user presenting themselves.
            // Nobody authenticated during this request, so there is nothing to report, and
            // carrying the subject token's report forward would let an exchange launder a stale
            // authentication into a token that looks freshly stepped up.
            crate::server::GrantedAuthentication::default(),
            // THE DELEGATION, recorded on the token itself. `act` is `Some` only for the
            // delegation branch above; an impersonation exchange names no actor by definition.
            // This is what lets RFC 7662 introspection answer "A acting for B" rather than "B",
            // which for an OPAQUE token is the only channel that could.
            crate::server::GrantedActor {
                act: act.clone().map(Box::new),
            },
            // THE LIFETIME CEILING, and the reason it has to exist at all. The token issued here
            // is an ordinary access token, so it is itself an acceptable SUBJECT token, and
            // self-exchange is explicitly permitted a few ceilings above. Without a ceiling a
            // client could re-exchange just before each expiry and receive a fresh full
            // `access_token_ttl` every time, indefinitely, which renews the grant's lifetime
            // without limit. That is precisely what the "no refresh token is issued" rule in this
            // module's docs exists to prevent, defeated by the issued token's own type.
            //
            // `min(now + access_token_ttl, subject.expires_at)` is applied inside `issue`, so the
            // stored expiry, the RFC 9068 `exp` claim and the `expires_in` below all state the one
            // capped instant. An exchanged token can therefore be narrower in time as it is in
            // scope, details and audience, and never wider.
            Some(subject.expires_at),
        )
        .await?;

    Ok(ExchangedToken {
        response: TokenExchangeResponse {
            access_token: issued.access_token,
            issued_token_type,
            token_type: issued.token_type,
            expires_in: Some(issued.expires_in),
            scope: issued.scope,
            // `issue` was told not to, and this asserts it rather than assuming it: section 2.2.1
            // makes the member optional, so a stray refresh token would serialize silently.
            refresh_token: None,
        },
        semantics,
        act,
    })
}

#[cfg(test)]
#[path = "tests/token_exchange.rs"]
mod tests;
