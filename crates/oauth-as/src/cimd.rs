// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Client identifier metadata documents (draft-ietf-oauth-client-id-metadata-document-01): a
//! client identifies itself with an HTTPS URL, and the metadata that would otherwise have come
//! from an RFC 7591 registration is fetched from that URL instead.
//!
//! # EVERY SECTION NUMBER IN THIS MODULE IS -01's
//!
//! This module was written against draft revision **-01**, and every bare "section N" in it — in
//! this header, in [`CimdError`]'s variants, in [`ClientIdUrl::parse`] and in
//! [`ValidatedClientIdDocument::validate`] — is a section of THAT revision. Revision -02
//! (2026-07-06) reorganised the document, so eight of the nine anchors this module cites moved:
//!
//! | cited here (-01) | same rule in -02 |
//! |---|---|
//! | 3, Client Identifier | 3, retitled Client Identifier URL |
//! | 4, opening text (no redirects, `200` only) | 5, Client Information Discovery |
//! | 4.1, Client Metadata Document | 4 body, Client ID Metadata Document |
//! | 4.3, Metadata Discovery Errors | 5.1 |
//! | 4.4, Metadata Caching | 5.2 |
//! | 5, Authorization Server Metadata | 6 |
//! | 6.1, `redirect_uris` and `client_id` | 8.1 |
//! | 6.5, SSRF | 8.6 |
//! | 6.6, Maximum Response Size | 8.7 |
//!
//! The RULES are unchanged; the NUMBERS are not. A reader checking a citation against the current
//! draft should map it through the table first, and nothing in this module's behaviour follows
//! from the renumbering.
//!
//! # THE HOST FETCHES. THIS CRATE VALIDATES.
//!
//! There is no outbound HTTP request anywhere in this module, and there is not going to be one.
//! It is the same posture as the rest of the crate: the host supplies the signer, the host
//! supplies the consent resolver, the host supplies the clock, and the host owns the socket. It is
//! also the reason `jwks_uri` is recorded as an open gap in [`crate::registration`] rather than
//! quietly implemented, and the reason a document carrying `jwks` or `jwks_uri` is REFUSED here
//! rather than accepted with the key thrown away (see [`CimdError::KeyMaterialPresent`]).
//!
//! So the seam is: the host GETs the document at the client identifier URL and hands the bytes
//! here; [`ValidatedClientIdDocument::validate`] decides whether they are a client, and
//! [`ValidatedClientIdDocument::to_client`] turns them into one.
//!
//! # A VALIDATED DOCUMENT IS NOT A CORRECTLY FETCHED DOCUMENT
//!
//! That sentence is the whole security story of this module, so it is stated as a list of duties
//! the host keeps, in the same register [`crate::registration`] uses for its own gaps. Nothing
//! below can be checked from inside a library that never touches the network, and a green result
//! from this module says nothing about any of it:
//!
//! - **The fetch itself.** A `GET` with `Accept: application/json`.
//! - **Section 4: the AUTHORIZATION SERVER MUST NOT automatically follow HTTP redirects.** The
//!   duty is the fetcher's, not the client's, and the rule is in section 4's opening text rather
//!   than in any of its subsections. A crate that never fetches cannot enforce it, and it is the
//!   requirement most likely to be missed, because every HTTP client library follows redirects by
//!   default. See [`ValidatedClientIdDocument::validate`] for the one part of it this module CAN
//!   catch, and for exactly how far that goes.
//! - **Section 4: `200` only.** Also section 4's opening text, and also addressed to the
//!   authorization server: every other status is an error, including a `3xx` the host declined to
//!   follow.
//! - **Section 4.3: on fetch failure, abort the authorization request.** Do not fall back to a
//!   cached document, and do not fall back to a registration.
//! - **Section 4.4: never cache an error response, and never cache an invalid or malformed
//!   document.** The API makes this the easy path rather than a rule to remember: a
//!   [`ValidatedClientIdDocument`] cannot be constructed from a failure, so the only value there
//!   is to cache is one that passed.
//! - **DNS resolution, and the rebinding window.** See [`ClientIdUrl::parse`]: this module refuses
//!   a special-use IP LITERAL, which is the half of section 6.5 that needs no resolver. It cannot
//!   resolve a name, so it cannot discharge section 6.5, and a host that checks an address and
//!   then connects by NAME has not discharged it either. Resolve once, check THAT address, and
//!   connect to THAT address.
//! - **TLS.** Certificate verification is the host's, as everywhere else in this crate.
//!
//! # What a host does with the result
//!
//! [`ValidatedClientIdDocument::to_client`] produces a [`Client`] whose `client_id` is the URL,
//! and the host installs it in its own [`crate::store::Storage`] for the life of the
//! authorization request (subject to section 4.4's caching rules, which are the host's). From
//! that point every other endpoint in this crate treats it as any other client: the redirect URI
//! is matched exactly, the scope ceiling applies, and PKCE is required.

use serde::{Deserialize, Serialize};

use crate::client::{Client, ClientAuth, ClientId};
use crate::registration::{
    ClientMetadata, RegistrationConfig, RegistrationErrorCode, RegistrationErrorResponse,
    RegistrationFailure,
};
use crate::scope::ScopeSet;

/// The recommended maximum size of a client identifier metadata document, in bytes (section 6.6).
///
/// # Why the crate publishes it rather than only enforcing it
///
/// Enforcing it HERE, on bytes the host has already read into memory, does not prevent the read;
/// it only stops an oversized document becoming a client. The place a size limit actually costs an
/// attacker something is at the socket, and that socket belongs to the host. So the number is
/// public: a host caps its own response reader at this value, and this module then re-checks what
/// it is handed, because a cap the host forgot must not be a cap nobody applied.
///
/// The document is attacker-influenced input by construction — anyone who can publish a page can
/// publish one of these — which is why it is bounded at all, on the same reasoning as
/// [`crate::MAX_REGISTERED_REDIRECT_URIS`] and (under `rar`) `MAX_AUTHORIZATION_DETAILS_BYTES`.
pub const MAX_CLIENT_ID_DOCUMENT_BYTES: usize = 5120;

/// The largest client identifier URL this crate will parse, in bytes.
///
/// The draft sets no bound. This one exists because the client identifier arrives as a `client_id`
/// authorization request parameter, which is to say as unauthenticated text of an attacker's
/// chosen length, and every check in [`ClientIdUrl::parse`] is a scan over it. 2048 is the
/// conventional URL ceiling that intermediaries have imposed for decades; a client identifier
/// anywhere near it is not a URL anybody typed.
pub const MAX_CLIENT_ID_URL_BYTES: usize = 2048;

/// Why a client identifier URL, or a document fetched from one, was refused.
///
/// Each variant names the RULE it broke rather than echoing the offending value: this is
/// attacker-supplied text that a host is likely to log, and the same reasoning already applies to
/// [`crate::RegistrationErrorResponse`]'s descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
/// `#[non_exhaustive]`: this enum is a list of REFUSAL REASONS for a specification still in
/// working-group draft, so it will gain variants as the draft gains rules, and a host that matches
/// it exhaustively must not have its build broken by a patch release that tightens a check.
#[non_exhaustive]
pub enum CimdError {
    /// Section 3: the client identifier MUST use the `https` scheme.
    ///
    /// Spelled in lower case, and an upper-case `HTTPS://` lands here too. Section 4.1 compares
    /// the document's `client_id` to the fetch URL by RFC 3986 section 6.2.1 SIMPLE STRING
    /// COMPARISON, so normalising the scheme here would make two byte-distinct strings name one
    /// client and break that comparison rather than help it. Refusing is the only move that keeps
    /// both rules true at once.
    NotHttps,
    /// RFC 3986 section 3.2: the client identifier has no host. `https:///app` is not a URL
    /// anything can be fetched from, and accepting one would put an identifier in the client table
    /// that no fetch could ever be made against.
    NoHost,
    /// RFC 3986 section 2: the client identifier contains a byte outside printable ASCII — or a
    /// backslash or a percent sign in its AUTHORITY, which are printable ASCII and land here
    /// anyway.
    ///
    /// A URI's grammar is ASCII, and anything outside it MUST be percent-encoded, so a raw space,
    /// a control byte or a newline here is not a URI at all. This crate's RFC 8707 resource
    /// indicator check makes the same refusal for the same reason. It matters more here than
    /// there: the client identifier is echoed into audit records, and a newline in one is log
    /// injection.
    ///
    /// # The two printable-ASCII cases, and why they are here
    ///
    /// A backslash in the authority (`https://good.example\.evil.com/app`) and a percent-escape in
    /// the authority (`https://127.0.0.1%2e/app`) are both refused as `NotAscii`. Neither is a
    /// non-ASCII byte, and the name is a variant REUSED rather than earned: it is one refusal
    /// short of honest, and it is said here because docs.rs is where a host reads what this
    /// variant means.
    ///
    /// They share the reason. A WHATWG URL parser — which is what every mainstream HTTP client
    /// puts between the host and the socket — reads a backslash as a path separator and
    /// percent-DECODES the host before parsing it, while this crate reads the raw bytes. So the
    /// crate and the fetcher would derive DIFFERENT hosts from one string, which is the entire
    /// class of defect [`CimdError::SpecialUseAddress`]'s literal check exists to close. Refused
    /// rather than decoded, for the reason the module refuses everywhere else: decoding would mean
    /// two parties each deriving a host by their own rules. See [`ClientIdUrl::parse`] for the
    /// worked examples.
    NotAscii,
    /// Section 3: the client identifier MUST contain a path component. `https://client.example`
    /// has none; `https://client.example/` has one.
    NoPath,
    /// Section 3: the client identifier MUST NOT contain single-dot or double-dot path segments.
    ///
    /// Refused rather than resolved, for the reason in [`CimdError::NotHttps`]: resolving `..`
    /// would let two distinct strings name one client while section 4.1 still compares them byte
    /// for byte.
    DotSegment,
    /// Section 3: the client identifier MUST NOT contain a fragment component.
    Fragment,
    /// Section 3: the client identifier MUST NOT contain a userinfo component. `https://a@b/c` is
    /// a URL whose HOST is `b`, which is not what most readers of it see.
    Userinfo,
    /// Section 3 SHOULD NOT: the client identifier carries a query string and this deployment did
    /// not set [`CimdPolicy::allow_query_string`].
    QueryString,
    /// Section 6.5: the host of the client identifier is an IP LITERAL in a special-use range
    /// (RFC 6890), so dereferencing it would be a request to this deployment's own network.
    ///
    /// This is only HALF of section 6.5. See [`ClientIdUrl::parse`] for the half that is the
    /// host's, and for why an address that passes here can still be a rebinding attack.
    SpecialUseAddress,
    /// The client identifier is longer than [`MAX_CLIENT_ID_URL_BYTES`].
    UrlTooLong,
    /// Section 6.6: the document is larger than the policy's `max_document_bytes`.
    DocumentTooLarge,
    /// Section 4.1: the document is not the JSON object RFC 8259 defines.
    NotJson,
    /// Section 4.1: the document has no `client_id` member. It is REQUIRED, and its absence is
    /// not the same as a mismatch: nothing was claimed at all.
    MissingClientId,
    /// Section 4.1: the document's `client_id` is not, byte for byte, the URL it was fetched from.
    ///
    /// THIS IS THE CHECK THE WHOLE MECHANISM RESTS ON. Without it any document authorizes any
    /// client: an attacker publishes a document at a URL they control that claims somebody else's
    /// client identifier, and an authorization server that skipped this comparison hands them that
    /// client's redirect URIs.
    ClientIdMismatch,
    /// Section 4.1: the document carries `client_secret` or `client_secret_expires_at`.
    ///
    /// The document is world-readable by construction, so a shared secret in one is a secret
    /// published to the internet. Refused rather than dropped, on the same reasoning
    /// [`crate::registration`] gives for `software_statement`: dropping a member the client
    /// believes is being honoured registers a client on terms nobody agreed to.
    ClientSecretPresent,
    /// Section 4.1: `token_endpoint_auth_method` names a method that rests on a SHARED SYMMETRIC
    /// secret (`client_secret_basic`, `client_secret_post`, `client_secret_jwt`), which a public
    /// document cannot hold. See [`CimdError::ClientSecretPresent`].
    SharedSecretAuthMethod,
    /// Section 4.1: the document carries `jwks` or `jwks_uri`.
    ///
    /// REFUSED, NOT DROPPED, and this is the one refusal in the list that is a property of THIS
    /// BUILD rather than of the draft. The draft PERMITS these two: a public key is the only
    /// credential a world-readable document can carry, so it is the sanctioned way for a client
    /// identifier metadata document to say "I authenticate, and here is what with".
    ///
    /// This crate cannot honour that yet. [`crate::registration`] models neither member (it
    /// records the gap in its own module docs), which is why
    /// [`ValidatedClientIdDocument::to_client`] is unconditionally [`ClientAuth::Public`], and why
    /// [`crate::registration`]'s own validator refuses `private_key_jwt` outright. A document offering a
    /// key would therefore have been accepted as a PUBLIC client with no word said about the
    /// credential its author believes is in force — the exact outcome
    /// [`CimdError::ClientSecretPresent`] exists to prevent, and there is no reading on which the
    /// same facts deserve opposite treatment because one member is a secret and the other is not.
    ///
    /// It also happens to be the only place the draft's MUST NOT on PRIVATE key material is
    /// reachable at all: a private JWK arrives inside `jwks`, so a document that publishes one is
    /// refused here rather than parsed and silently dropped. Nothing else in this module looks
    /// inside the member, and nothing needs to: the whole member is refused either way.
    ///
    /// This variant is where the gap closes. When `jwks`/`jwks_uri` become registrable, a document
    /// carrying one stops being a refusal and starts being a confidential client — and this
    /// enum is `#[non_exhaustive]` precisely so that removing a refusal is a patch release.
    KeyMaterialPresent,
    /// Section 6.1: a `redirect_uris` entry is not same-origin with the client identifier, and
    /// this deployment left [`CimdPolicy::redirect_uris_same_origin`] on.
    ///
    /// Section 6.1 PERMITS rather than requires this, and it is on by default here because
    /// without it anyone who can host a document can name any redirect URI in it.
    RedirectUriNotSameOrigin,
    /// The document's metadata failed the same RFC 7591 section 2 validation a dynamic
    /// registration does, and this is that refusal, unchanged.
    ///
    /// Section 4.1 says the members come from the OAuth Dynamic Client Registration Metadata
    /// registry, so they are checked by [`crate::registration`]'s validator rather than by a
    /// second copy of it that would drift.
    Metadata(crate::registration::RegistrationErrorResponse),
}

impl std::fmt::Display for CimdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CimdError::NotHttps => f.write_str("the client identifier must use the https scheme"),
            CimdError::NoHost => f.write_str("the client identifier has no host"),
            CimdError::NotAscii => f.write_str(
                "the client identifier contains a byte outside printable ASCII, which RFC 3986 \
                 requires to be percent-encoded, or a backslash or percent sign in its authority, \
                 which a URL parser would read as a different host than this crate does",
            ),
            CimdError::NoPath => {
                f.write_str("the client identifier must contain a path component")
            }
            CimdError::DotSegment => f.write_str(
                "the client identifier must not contain single-dot or double-dot path segments",
            ),
            CimdError::Fragment => {
                f.write_str("the client identifier must not contain a fragment")
            }
            CimdError::Userinfo => {
                f.write_str("the client identifier must not contain a userinfo component")
            }
            CimdError::QueryString => f.write_str(
                "the client identifier carries a query string, which this deployment does not allow",
            ),
            CimdError::SpecialUseAddress => f.write_str(
                "the client identifier names a special-use IP address literal (RFC 6890)",
            ),
            CimdError::UrlTooLong => f.write_str("the client identifier is too long"),
            CimdError::DocumentTooLarge => {
                f.write_str("the client identifier metadata document is too large")
            }
            CimdError::NotJson => {
                f.write_str("the client identifier metadata document is not a JSON object")
            }
            CimdError::MissingClientId => f.write_str(
                "the client identifier metadata document has no client_id member",
            ),
            CimdError::ClientIdMismatch => f.write_str(
                "the document's client_id is not the URL it was fetched from",
            ),
            CimdError::ClientSecretPresent => f.write_str(
                "a client identifier metadata document must not carry a client secret",
            ),
            CimdError::SharedSecretAuthMethod => f.write_str(
                "token_endpoint_auth_method names a shared-secret method, which a public document \
                 cannot hold",
            ),
            CimdError::KeyMaterialPresent => f.write_str(
                "the document carries jwks or jwks_uri, and this server cannot register a client \
                 key, so honouring the document would mean registering a public client instead",
            ),
            CimdError::RedirectUriNotSameOrigin => f.write_str(
                "a redirect_uri is not same-origin with the client identifier",
            ),
            CimdError::Metadata(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CimdError {}

/// What this deployment will accept from a client identifier metadata document, and how far it
/// will bend the draft's SHOULDs.
///
/// Every knob here is a CEILING or a strictness switch, and the defaults are the strict ones, on
/// the same reasoning as [`RegistrationConfig::new`]: an unregistered client that anyone on the
/// internet can mint by publishing a file is exactly the shape RFC 7591 section 5 warns about, and
/// widening it should be a sentence the host wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
/// `#[non_exhaustive]`: this is a policy object for a working-group draft, so it will gain fields
/// as the draft settles. A host writes a full struct literal today and has a build that breaks on
/// a patch release; `new()` plus assignment does not. The attribute cannot be added after
/// publication, because by then the literal is in somebody's production tree.
#[non_exhaustive]
pub struct CimdPolicy {
    /// Section 6.5's carve-out: whether a LOOPBACK literal (`127.0.0.0/8`, `::1`) may be a client
    /// identifier host.
    ///
    /// `false` by default. Section 6.5 permits it only when the authorization server itself runs
    /// on that same loopback interface, which is the development case and nothing else; in any
    /// deployment where the AS is reachable from elsewhere, a loopback client identifier is a
    /// request the AS makes to ITSELF on somebody else's behalf.
    ///
    /// Note what turning it on does NOT do: it relaxes the LITERAL check only. Every other
    /// special-use range stays refused, and a NAME that resolves to loopback is not seen here at
    /// all — see [`ClientIdUrl::parse`].
    pub allow_loopback: bool,
    /// Section 6.6: the largest document, in bytes, this deployment will validate.
    /// [`MAX_CLIENT_ID_DOCUMENT_BYTES`] by default, which is the draft's recommendation.
    pub max_document_bytes: usize,
    /// Section 6.1: whether every `redirect_uris` entry must be same-origin with the client
    /// identifier URL.
    ///
    /// `true` by default. The draft PERMITS the requirement rather than imposing it, and the
    /// default is on because the alternative is that anyone who can host a document can name any
    /// redirect URI in it. A deployment that must serve native clients (a custom scheme, or a
    /// loopback redirect) turns it off knowing what it costs.
    pub redirect_uris_same_origin: bool,
    /// Section 3 SHOULD NOT: whether a client identifier may carry a query string.
    ///
    /// `false` by default, which is the SHOULD NOT honoured. A query string on an identity makes
    /// two identifiers that differ only in parameter order two different clients under section
    /// 4.1's byte comparison while naming one document to most servers.
    pub allow_query_string: bool,
    /// The ceiling on what a document may ask for: which grants, which scopes.
    ///
    /// The SAME type RFC 7591 dynamic registration uses, deliberately. Section 4.1 says the
    /// document's members come from the OAuth Dynamic Client Registration Metadata registry, so
    /// the values being bounded are the same values, and this crate holds one validator for them
    /// (see [`crate::registration`]). Three of its fields are not read on this path and have no
    /// meaning here: `registration_endpoint`, `client_secret_ttl` (nothing issues a secret to a
    /// CIMD client) and `management_enabled` (there is no registration to manage; the client
    /// edits its own document).
    pub registration_bounds: RegistrationConfig,
}

impl Default for CimdPolicy {
    fn default() -> Self {
        CimdPolicy::new()
    }
}

impl CimdPolicy {
    /// The strict defaults: no loopback, the draft's 5 KB cap, same-origin redirect URIs, no query
    /// string, and [`RegistrationConfig::new`]'s narrow grant and scope ceilings.
    pub fn new() -> Self {
        CimdPolicy {
            allow_loopback: false,
            max_document_bytes: MAX_CLIENT_ID_DOCUMENT_BYTES,
            redirect_uris_same_origin: true,
            allow_query_string: false,
            registration_bounds: RegistrationConfig::new(),
        }
    }
}

/// A client identifier URL that has passed section 3's syntax rules and section 6.5's literal
/// address check.
///
/// The inner string is PRIVATE, which is the point of the type: the only way to hold one is to
/// have called [`ClientIdUrl::parse`], so a value of this type cannot be a URL nobody checked.
/// Nothing normalises it, ever — see [`ValidatedClientIdDocument::validate`] for why normalisation
/// would be the bug rather than the fix.
///
/// # There is no `Deserialize`, deliberately
///
/// It derived one until it was caught in review, and that made the paragraph above FALSE: a
/// derived `Deserialize` on a newtype is a direct `String` to `ClientIdUrl` conversion, so
/// `serde_json::from_str("\"http://evil.example\"")` produced a value of this type that had passed
/// none of the section 3 or 6.5 checks — not https, not the length cap, not the userinfo,
/// fragment, dot-segment or special-use-address refusals. `validate` then compared the document's
/// `client_id` against that unchecked string, and byte equality with an unchecked URL proves
/// nothing.
///
/// It cannot be fixed by deserializing THROUGH `parse`, because `parse` takes a [`CimdPolicy`] and
/// serde has none to give it: two of the rules ([`CimdPolicy::allow_loopback`],
/// [`CimdPolicy::allow_query_string`]) are the host's decision, so a `Deserialize` would have to
/// pick a policy and would be wrong for every host that chose the other one.
///
/// **So a host that caches validated documents caches the URL as a STRING and calls
/// [`ClientIdUrl::parse`] on the way back in, with its own policy.** That is one line, it is the
/// only construction path, and it is what makes the invariant above true rather than aspirational.
/// `Serialize` is kept: writing out a value that has already been checked is safe, and it is what
/// a cache needs to store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ClientIdUrl(String);

impl ClientIdUrl {
    /// Check `raw` against section 3's syntax rules and the half of section 6.5 that needs no
    /// resolver. NO I/O, and no normalisation.
    ///
    /// # What is checked
    ///
    /// Section 3, every clause:
    ///
    /// - MUST be `https`, spelled in lower case ([`CimdError::NotHttps`]);
    /// - MUST have a path component ([`CimdError::NoPath`]);
    /// - MUST NOT contain single-dot or double-dot path segments ([`CimdError::DotSegment`]);
    /// - MUST NOT contain a fragment ([`CimdError::Fragment`]);
    /// - MUST NOT contain userinfo ([`CimdError::Userinfo`]);
    /// - SHOULD NOT contain a query string, which is [`CimdPolicy::allow_query_string`];
    /// - MAY contain a port, so a port is not a reason to refuse.
    ///
    /// Plus four rules section 3 does not spell out:
    ///
    /// - there must BE a host: `https:///app` is [`CimdError::NoHost`], because an identifier
    ///   nothing can be fetched from is not one;
    /// - no backslash in the authority ([`CimdError::NotAscii`]), because a WHATWG URL parser
    ///   reads it as a path separator and so connects to a different host than this crate checked;
    /// - no percent-escape in the authority ([`CimdError::NotAscii`]), because such a parser
    ///   percent-decodes the host before reading it, and the two would again disagree;
    /// - [`MAX_CLIENT_ID_URL_BYTES`].
    ///
    /// Plus section 6.5 as far as a literal goes — including an IPv4 address spelled any way but
    /// the canonical dotted-quad, which is [`CimdError::SpecialUseAddress`].
    ///
    /// # What section 6.5 still leaves with the host
    ///
    /// Section 6.5 requires that the URL does not RESOLVE to a special-use address. This function
    /// refuses a special-use IP LITERAL, which is the only part of that a library with no resolver
    /// can decide. Two things remain, and both are the host's:
    ///
    /// 1. **Resolution.** `https://internal.corp.example/app` passes here and may resolve to
    ///    `10.0.0.1`.
    /// 2. **The rebinding window.** A host that resolves the name, checks the address, and then
    ///    hands the NAME to its HTTP client has checked one answer and connected to another. The
    ///    honest instruction is: resolve once, check that address, connect to THAT address.
    ///
    /// A `Ok` from this function is therefore not a statement that dereferencing the URL is safe.
    pub fn parse(raw: &str, policy: &CimdPolicy) -> Result<Self, CimdError> {
        if raw.len() > MAX_CLIENT_ID_URL_BYTES {
            return Err(CimdError::UrlTooLong);
        }
        // RFC 3986 s2: a URI is ASCII, and everything outside the grammar is percent-encoded. Same
        // rule, and the same range, as `crate::authorization::is_valid_resource_indicator`.
        if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(CimdError::NotAscii);
        }
        // Lower case, and byte-exact. See `CimdError::NotHttps`: section 4.1's comparison is a
        // simple string comparison, so a scheme this crate case-folded would be a scheme two
        // distinct client identifiers could share.
        let rest = raw.strip_prefix("https://").ok_or(CimdError::NotHttps)?;
        // A fragment is checked over the WHOLE string rather than over the path, because `#`
        // terminates everything after it in RFC 3986 section 3.5 regardless of where it appears.
        if raw.contains('#') {
            return Err(CimdError::Fragment);
        }
        // The authority runs to the first `/`, `?` or `#`; there is no `#` left by now.
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.contains('@') {
            return Err(CimdError::Userinfo);
        }
        // Section 3: a path component is REQUIRED, so a bare origin is not a client identifier.
        // `https://client.example` has no path at all and lands here; `https://client.example/`
        // has the path `/` and does not. That is the RFC 3986 section 3.3 reading: `path-abempty`
        // may be empty, and "contains a path component" is the statement that it is not.
        if authority_end == rest.len() || rest.as_bytes()[authority_end] != b'/' {
            return Err(CimdError::NoPath);
        }
        let after_authority = &rest[authority_end..];
        let (path, query) = match after_authority.find('?') {
            Some(at) => (&after_authority[..at], Some(&after_authority[at + 1..])),
            None => (after_authority, None),
        };
        // Section 3: no single-dot or double-dot segments. Segment-wise, not substring-wise: a
        // path component that merely CONTAINS a dot (`/v1.2/client`) is fine, and only a whole
        // segment equal to `.` or `..` is not.
        if path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(CimdError::DotSegment);
        }
        if query.is_some() && !policy.allow_query_string {
            return Err(CimdError::QueryString);
        }
        // Section 6.5, the literal half. A port is explicitly permitted by section 3, so it is
        // stripped before the address is read rather than treated as part of it. An authority with
        // no host at all is refused rather than skipped: `host_of` returning `None` used to mean
        // "no address to check", which read as "nothing to refuse".
        let host = host_of(authority).ok_or(CimdError::NoHost)?;
        // AN IPv4 ADDRESS SPELLED ANY WAY BUT THE CANONICAL ONE IS REFUSED, and this is the check
        // that makes the one below mean anything.
        //
        // `is_special_use_literal` decides "is this a literal" with `Ipv4Addr::from_str`, which
        // accepts ONLY canonical dotted-quad. The host that actually performs the fetch does not:
        // every mainstream HTTP client goes through a WHATWG URL parser, which accepts decimal,
        // hexadecimal, octal and short forms and normalises them all to the same address. So the
        // two disagreed, and the crate was refusing the one spelling an attacker would never use:
        //
        //     https://127.0.0.1/app      refused
        //     https://2130706433/app     ACCEPTED, fetches 127.0.0.1
        //     https://0x7f000001/app     ACCEPTED, fetches 127.0.0.1
        //     https://0177.0.0.1/app     ACCEPTED, fetches 127.0.0.1
        //     https://127.1/app          ACCEPTED, fetches 127.0.0.1
        //     https://127.0.0.1./app     ACCEPTED, fetches 127.0.0.1
        //
        // That is the request section 6.5 exists to prevent, reaching the deployment's own network,
        // and this module's docs tell the host the LITERAL half has been discharged and only name
        // resolution is left to them. `0x7f000001` is not a name.
        //
        // The rule is WHATWG's own: a host "ends in a number" -- and is therefore an IPv4 address
        // rather than a name -- when its last non-empty label is all digits, or is `0x`-prefixed
        // hex. Such a host must be a canonical dotted-quad, so that the check below reads the same
        // address the fetcher will connect to. Anything else is refused rather than normalised,
        // because normalising an address the caller wrote ambiguously is guessing at intent on the
        // one input where guessing wrong reaches inside the network.
        // NOT for an IPv6 literal. `host_of` has stripped the brackets by here, so a host that
        // still contains a colon is v6, and WHATWG's "ends in a number" rule is part of the
        // IPv4/opaque-host path -- a v6 literal has its own parser and never reaches it. Applying
        // it here refused `::ffff:93.184.216.34`, a PUBLIC address, because its last dot-label is
        // `34` and `Ipv4Addr::from_str` then fails on the colons. The same address spelled
        // `::ffff:5db8:d822` was accepted, so the verdict depended on the spelling rather than on
        // the address. Worse, it short-circuited the v4-mapped branch of `is_special_use_literal`
        // for every dotted form, which is why the 0.9.2 sweep left seventeen survivors in there
        // and why the test asserting `[::ffff:169.254.169.254]` is refused was passing on this
        // rule rather than on the one it names.
        if !host.contains(':')
            && ends_in_a_number(host)
            && host.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Err(CimdError::SpecialUseAddress);
        }
        // A BACKSLASH IS A SLASH TO THE FETCHER AND NOT TO US, which makes it the same class of
        // defect one character wider. In `https://good.example\.evil.com/app` this crate reads the
        // authority as `good.example\.evil.com` -- so `origin()`, the same-origin redirect rule and
        // the byte-equality check are all computed against that -- while a WHATWG parser treats the
        // backslash as a path separator and connects to `good.example`, path `/.evil.com/app`.
        // Two parties, two different hosts, one string. Refused outright: there is no legitimate
        // client identifier with a backslash in it, and RFC 3986 does not admit one in an authority.
        if authority.contains('\\') {
            return Err(CimdError::NotAscii);
        }
        // A PERCENT-ESCAPE IN THE AUTHORITY IS THE SAME DEFECT ONE ENCODING LAYER DOWN, and the
        // first version of the check above missed it. `ends_in_a_number` reads the raw text; a
        // WHATWG host parser percent-DECODES the host before it applies that rule, so the two read
        // different strings -- which is exactly what this whole check exists to stop.
        //
        //     https://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/app
        //
        // was ACCEPTED, and `curl` on that URL connects to 169.254.169.254, the cloud metadata
        // service. `https://127.0.0.1%2e/app` was accepted the same way, because encoding only the
        // trailing dot defeats the last-label test.
        //
        // REFUSED rather than decoded-then-checked, for the reason the module refuses everywhere
        // else: decoding here would mean this crate and the fetcher each deriving a host from the
        // same bytes by their own rules, and the entire class of defect is those two answers
        // differing. A percent-escape has no legitimate place in a client identifier's authority
        // -- an internationalised name arrives as punycode (`xn--`), which is ASCII already, and
        // section 4.1's byte-for-byte `client_id` comparison means an escaped form could not match
        // its own document anyway.
        if authority.contains('%') {
            return Err(CimdError::NotAscii);
        }
        if is_special_use_literal(host, policy.allow_loopback) {
            return Err(CimdError::SpecialUseAddress);
        }
        Ok(ClientIdUrl(raw.to_string()))
    }

    /// The identifier, exactly as it was given. This is the string section 4.1 compares against,
    /// and the string that becomes the [`ClientId`].
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The origin: scheme, host and port, with no trailing slash. Used for section 6.1's
    /// same-origin redirect URI rule.
    fn origin(&self) -> &str {
        // TOTAL, and it does not rest on "safe by construction" any more. It used to slice at a
        // fixed byte 8 with a comment saying `parse` had refused anything shorter, which was true
        // of every value `parse` produced and false of one built any other way. A derived
        // `Deserialize` (since removed, see the type's docs) made `ClientIdUrl("x")` reachable, and
        // this line then panicked with "start byte index 8 is out of bounds for string of length
        // 1" -- inside a library, on a path the DEFAULT policy reaches, which is a process abort in
        // the host rather than an `Err`.
        //
        // The derive is gone, so the bad value is unreachable today. This stays total anyway: a
        // function that is correct only because of an invariant enforced somewhere else is one
        // refactor away from being wrong again, and the cost of not depending on that is a
        // `strip_prefix`.
        let Some(rest) = self.0.strip_prefix("https://") else {
            return &self.0;
        };
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        &self.0[.."https://".len() + end]
    }
}

impl std::fmt::Display for ClientIdUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a WHATWG URL parser would read this host as an IPv4 ADDRESS rather than as a name.
///
/// The rule is "ends in a number": take the last label, ignoring one trailing dot, and the host is
/// an address when that label is entirely ASCII digits, or is `0x`/`0X` followed by hex digits (or
/// by nothing at all -- bare `0x` is the number zero to that parser). This is what makes
/// `2130706433`, `0x7f000001`, `0177.0.0.1` and `127.1` all mean 127.0.0.1 to the client that
/// fetches, while `Ipv4Addr::from_str` calls none of them an address.
///
/// A bracketed IPv6 literal is MOSTLY not this function's business — `host_of` has already
/// stripped the brackets, and the `:` makes it unmistakable to the check that follows — with one
/// spelling that is. An IPv4-embedded address (`[::ffff:127.0.0.1]`) has a last dot-label of `1`,
/// so this returns `true`, `Ipv4Addr::from_str` then fails on the colons, and
/// [`ClientIdUrl::parse`] refuses the URL as [`CimdError::SpecialUseAddress`]. That outcome is
/// fail-closed and harmless — the address IS special-use — but it is reached by a rule wearing
/// somebody else's name, so it is written down rather than left to be rediscovered.
fn ends_in_a_number(host: &str) -> bool {
    // One trailing dot is legal in a DNS name and is dropped by the parser, so `127.0.0.1.` is the
    // same address as `127.0.0.1` and must not slip past by looking like an empty last label.
    let host = host.strip_suffix('.').unwrap_or(host);
    let Some(last) = host.rsplit('.').next() else {
        return false;
    };
    if last.is_empty() {
        return false;
    }
    if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) {
        return hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    last.chars().all(|c| c.is_ascii_digit())
}

/// The host of an authority, with any port and any IPv6 brackets removed. `None` when the
/// authority is empty.
fn host_of(authority: &str) -> Option<&str> {
    if authority.is_empty() {
        return None;
    }
    // An IPv6 literal is bracketed (RFC 3986 section 3.2.2), and only then may its host contain
    // `:`, so the bracket case has to be settled before the port is split off.
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().filter(|h| !h.is_empty());
    }
    authority.split(':').next().filter(|h| !h.is_empty())
}

/// Whether `host` is an IP address LITERAL in one of RFC 6890's special-purpose ranges.
///
/// A name is not a literal and returns `false`, which is not an assertion that the name is safe:
/// see [`ClientIdUrl::parse`] for what that leaves with the host.
///
/// Written out by octet and by segment rather than over `std::net`'s predicates, because the ones
/// that would cover this (`is_documentation`, `is_shared`, `is_benchmarking`, `is_global`) are
/// still unstable, and this crate's MSRV is 1.75. Writing them out also lets each range name the
/// RFC 6890 entry it is, which a predicate call does not.
fn is_special_use_literal(host: &str, allow_loopback: bool) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        let o = v4.octets();
        // 127.0.0.0/8, loopback. The one range a policy may re-admit (section 6.5's carve-out for
        // an AS that itself runs on loopback).
        if o[0] == 127 {
            return !allow_loopback;
        }
        return match o {
            // "This host on this network", RFC 1122 s3.2.1.3.
            [0, ..] => true,
            // Private-use, RFC 1918.
            [10, ..] => true,
            [172, b, ..] if (16..=31).contains(&b) => true,
            [192, 168, ..] => true,
            // Shared address space (carrier-grade NAT), RFC 6598: 100.64.0.0/10.
            [100, b, ..] if (64..=127).contains(&b) => true,
            // Link local, RFC 3927.
            [169, 254, ..] => true,
            // IETF protocol assignments, RFC 6890: 192.0.0.0/24.
            [192, 0, 0, _] => true,
            // Documentation, RFC 5737.
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => true,
            // 6to4 relay anycast, RFC 3068.
            [192, 88, 99, _] => true,
            // Benchmarking, RFC 2544: 198.18.0.0/15.
            [198, b, ..] if b == 18 || b == 19 => true,
            // Multicast (224/4), reserved (240/4) and the limited broadcast address.
            [a, ..] if a >= 224 => true,
            _ => false,
        };
    }

    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        let s = v6.segments();
        // ::1/128, loopback, and the same carve-out as the v4 case above.
        if v6 == Ipv6Addr::LOCALHOST {
            return !allow_loopback;
        }
        // An IPv4-mapped or IPv4-compatible address is decided by the EMBEDDED v4 address, not by
        // its v6 spelling: `::ffff:127.0.0.1` is loopback however it is written, and reading it
        // as "some v6 address in ::ffff:0:0/96" would let every v4 rule above be bypassed by
        // rewriting the literal.
        if s[0..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0) {
            let embedded = Ipv4Addr::new(
                (s[6] >> 8) as u8,
                (s[6] & 0xff) as u8,
                (s[7] >> 8) as u8,
                (s[7] & 0xff) as u8,
            );
            return is_special_use_literal(&embedded.to_string(), allow_loopback);
        }
        return match s[0] {
            // ::/128 unspecified, and everything else in ::/8 that is not the two cases above.
            0 => true,
            // 64:ff9b::/96 IPv4-IPv6 translation, RFC 6052.
            0x0064 => true,
            // 100::/64 discard-only, RFC 6666.
            0x0100 => s[1] == 0 && s[2] == 0 && s[3] == 0,
            // 2001::/23 IETF protocol assignments, RFC 2928, which covers Teredo (2001::/32) and
            // benchmarking (2001:2::/48); plus 2001:db8::/32 documentation, RFC 3849, which sits
            // outside that /23 and is listed by RFC 6890 separately.
            0x2001 => s[1] < 0x0200 || s[1] == 0x0db8,
            // 2002::/16, 6to4, RFC 3056.
            0x2002 => true,
            // fc00::/7 unique local, fe80::/10 link local, ff00::/8 multicast.
            first => {
                (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 || (first >> 8) == 0xff
            }
        };
    }

    false
}

/// The wire shape of a client identifier metadata document (section 4.1): the RFC 7591 section 2
/// members, plus `client_id`, plus the members that carry a CREDENTIAL.
///
/// The credential members are modelled precisely SO THAT they can be refused. A type that did not
/// name them would have `serde` drop them silently, and a document whose author put a credential in
/// it would be accepted as a public client with no word said about the thing they believe is in
/// force. That reasoning does not care whether the credential is a secret the draft forbids or a
/// key the draft permits and this build cannot register; see [`CimdError::KeyMaterialPresent`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct ClientIdDocument {
    /// REQUIRED (section 4.1). Compared to the fetch URL by simple string comparison.
    #[serde(default)]
    client_id: Option<String>,
    /// MUST NOT be present (section 4.1).
    #[serde(default)]
    client_secret: Option<serde_json::Value>,
    /// MUST NOT be present (section 4.1).
    #[serde(default)]
    client_secret_expires_at: Option<serde_json::Value>,
    /// PERMITTED by section 4.1, and refused by this build: see [`CimdError::KeyMaterialPresent`].
    /// Modelled as an opaque value rather than a JWK set because nothing here reads INSIDE it —
    /// the whole member is the refusal, so parsing its contents would only be a second way to
    /// fail on a document that is already going to be rejected.
    #[serde(default)]
    jwks: Option<serde_json::Value>,
    /// PERMITTED by section 4.1, and refused by this build: see [`CimdError::KeyMaterialPresent`].
    #[serde(default)]
    jwks_uri: Option<serde_json::Value>,
    /// Everything else, which is the RFC 7591 registry, parsed by the type the RFC 7591 endpoint
    /// already uses.
    #[serde(flatten)]
    metadata: ClientMetadata,
}

/// The shared-symmetric `token_endpoint_auth_method` values section 4.1 forbids.
///
/// `client_secret_basic` and `client_secret_post` transmit the secret; `client_secret_jwt` MACs
/// with it (RFC 7518 section 3.2). All three require the server to hold a secret the client also
/// holds, and a document anyone can GET cannot establish one.
const FORBIDDEN_AUTH_METHODS: &[&str] = &[
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
];

/// The `token_endpoint_auth_method` a client identifier metadata document actually gets. RFC 7591
/// section 2's default is `client_secret_basic`, and that default cannot apply here (see
/// [`ValidatedClientIdDocument::validate`]).
const AUTH_METHOD_NONE: &str = "none";

/// A document that passed every check in this module. It cannot be constructed any other way.
///
/// That is section 4.4's caching rule made structural rather than remembered: the only value a
/// host can hold is one that validated, so "MUST NOT cache an invalid or malformed document" is
/// something the type system says rather than something a comment asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClientIdDocument {
    url: ClientIdUrl,
    registered: crate::registration::Registered,
}

impl ValidatedClientIdDocument {
    /// Validate `body` as the client identifier metadata document fetched from `fetched_from`.
    ///
    /// # `fetched_from` is where the bytes CAME FROM, not what was requested
    ///
    /// This is the one signature decision in the module worth defending. Section 4.1 compares the
    /// document's `client_id` to the URL the document was retrieved from, and a host that followed
    /// a redirect — which section 4 forbids — retrieved it from somewhere else. Passing the URL
    /// the host actually GOT the bytes from therefore turns the most common redirect violation
    /// into a [`CimdError::ClientIdMismatch`] instead of a silent acceptance.
    ///
    /// It does NOT enforce the no-redirects rule. A redirect chain that ends at the same URL still
    /// passes, and a host that passes the requested URL after following a redirect elsewhere
    /// defeats the check entirely. Not following redirects remains the host's duty; this only
    /// means that getting it wrong is usually caught.
    ///
    /// # The comparison is byte equality
    ///
    /// RFC 3986 section 6.2.1 SIMPLE STRING COMPARISON, and nothing else. A `client_id` that
    /// differs from the fetch URL by a trailing slash, by the case of the host, or by
    /// percent-encoding is REFUSED, not normalised. Normalising any of them would mean two
    /// distinct strings name one client, which is the property an attacker needs: it is what lets
    /// a document published at one URL answer for another.
    ///
    /// # Every other check, and where it comes from
    ///
    /// - Section 6.6: `body` is at most [`CimdPolicy::max_document_bytes`].
    /// - Section 4.1: the body is a JSON object, and `client_id` is present.
    /// - Section 4.1: `client_secret` and `client_secret_expires_at` are absent.
    /// - Section 4.1: `jwks` and `jwks_uri` are absent, which is this BUILD's limit rather than
    ///   the draft's rule; see [`CimdError::KeyMaterialPresent`].
    /// - Section 4.1: `token_endpoint_auth_method` is not a shared-symmetric method.
    /// - Section 4.1: everything else is the RFC 7591 section 2 registry, so it goes through
    ///   [`crate::registration`]'s validator — the SAME one, not a copy: redirect URIs must be
    ///   absolute with no fragment and at most [`crate::MAX_REGISTERED_REDIRECT_URIS`] of them,
    ///   `grant_types` and `response_types` must correspond, the scope must be within the policy's
    ///   ceiling, and a `software_statement` is refused.
    /// - Section 6.1: `redirect_uris` are same-origin with `fetched_from`, unless the policy says
    ///   otherwise.
    ///
    /// # The RFC 7591 default this deliberately does not take
    ///
    /// RFC 7591 section 2 says an ABSENT `token_endpoint_auth_method` means `client_secret_basic`.
    /// Applied literally here that would refuse every document that omits the member, because
    /// section 4.1 forbids exactly that value. So an absent member is read as `none`: a document
    /// anyone can GET establishes no shared secret, so `none` is the only method it could ever
    /// have meant, and the resulting client is public. Nothing is accepted-and-ignored by this —
    /// an EXPLICIT shared-secret method is still a refusal.
    pub fn validate(
        fetched_from: &ClientIdUrl,
        body: &[u8],
        policy: &CimdPolicy,
    ) -> Result<Self, CimdError> {
        // Section 6.6, FIRST, before anything walks the bytes. A cap applied after parsing is a
        // cap that did not bound the parse.
        if body.len() > policy.max_document_bytes {
            return Err(CimdError::DocumentTooLarge);
        }
        let document: ClientIdDocument =
            serde_json::from_slice(body).map_err(|_| CimdError::NotJson)?;

        // Section 4.1, and the reason the whole mechanism is safe. Byte equality; see the doc
        // comment above for why every tempting normalisation is a defect.
        let claimed = document
            .client_id
            .as_deref()
            .ok_or(CimdError::MissingClientId)?;
        if claimed != fetched_from.as_str() {
            return Err(CimdError::ClientIdMismatch);
        }

        // Section 4.1's two prohibitions. Refused rather than dropped: see the variant's docs.
        if document.client_secret.is_some() || document.client_secret_expires_at.is_some() {
            return Err(CimdError::ClientSecretPresent);
        }

        // THE SAME RULE APPLIED TO THE MEMBER THE DRAFT PERMITS. `jwks`/`jwks_uri` are the
        // sanctioned way for one of these documents to carry a credential, and this build cannot
        // register a client key at all, so accepting one would produce a public client from a
        // document that asked to be a confidential one. Refused for the reason above it, not for a
        // different one; see `CimdError::KeyMaterialPresent`.
        if document.jwks.is_some() || document.jwks_uri.is_some() {
            return Err(CimdError::KeyMaterialPresent);
        }

        let mut metadata = document.metadata;
        match metadata.token_endpoint_auth_method.as_deref() {
            Some(m) if FORBIDDEN_AUTH_METHODS.contains(&m) => {
                return Err(CimdError::SharedSecretAuthMethod)
            }
            // See the doc comment: RFC 7591 section 2's default cannot apply to a public document.
            None => metadata.token_endpoint_auth_method = Some(AUTH_METHOD_NONE.to_string()),
            Some(_) => {}
        }

        // THE SAME VALIDATOR the RFC 7591 endpoint runs, not a second one. Section 4.1 says the
        // members come from that registry, so the rules are those rules, and this crate has
        // already been bitten by one rule living in two places.
        let registered = crate::registration::validate(&metadata, &policy.registration_bounds)
            .map_err(|failure| match failure {
                RegistrationFailure::Invalid(response) => CimdError::Metadata(response),
                // `validate` returns only `Invalid`; the other variants belong to the ENDPOINT
                // around it (an absent configuration, a policy refusal, storage), none of which
                // is reachable from here. Mapped rather than unwrapped, so that a variant added
                // later cannot become a panic on an attacker-supplied document.
                _ => CimdError::Metadata(RegistrationErrorResponse::new(
                    RegistrationErrorCode::InvalidClientMetadata,
                    "the document names metadata this server will not accept",
                )),
            })?;

        // Section 6.1, last, because it is the one rule that is a POLICY rather than the draft.
        if policy.redirect_uris_same_origin {
            let origin = fetched_from.origin();
            for uri in &registered.redirect_uris {
                let same = uri.strip_prefix(origin).is_some_and(|rest| {
                    rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')
                });
                if !same {
                    return Err(CimdError::RedirectUriNotSameOrigin);
                }
            }
        }

        Ok(ValidatedClientIdDocument {
            url: fetched_from.clone(),
            registered,
        })
    }

    /// The client identifier this document belongs to, which is the URL it was fetched from.
    pub fn client_id_url(&self) -> &ClientIdUrl {
        &self.url
    }

    /// The [`Client`] a host installs in its own [`crate::store::Storage`] for this authorization
    /// request.
    ///
    /// Always [`ClientAuth::Public`], and no document that reached here could have been anything
    /// else. Section 4.1 forbids the shared-secret methods outright; the one credential the draft
    /// DOES permit — a public key in `jwks`/`jwks_uri` — is refused by
    /// [`ValidatedClientIdDocument::validate`] rather than dropped, precisely so that this line
    /// stays true by construction instead of by silently discarding a member. So a CIMD client
    /// proves possession of nothing and the flow compensates with PKCE exactly as it does for a
    /// native app. See [`CimdError::KeyMaterialPresent`].
    ///
    /// `registration` is `None`. That field means "created by RFC 7591 dynamic registration", and
    /// this client was not: there is no registration access token, and RFC 7592 read, update and
    /// delete have no meaning for a client that edits its own document. Setting it would advertise
    /// a management surface that does not exist.
    ///
    /// `default_scopes` is EMPTY rather than the document's `scope`. RFC 6749 section 3.3's server
    /// default is a deployment's decision about what a request that names no scope receives, and a
    /// document the client wrote is not a deployment decision; `allowed_scopes` is the ceiling and
    /// is where the document's `scope` lands.
    pub fn to_client(&self) -> Client {
        Client {
            client_id: ClientId::new(self.url.as_str()),
            auth: ClientAuth::Public,
            grant_types: self.registered.grant_types.clone(),
            redirect_uris: self.registered.redirect_uris.clone(),
            allowed_scopes: self.registered.scope.clone(),
            default_scopes: ScopeSet::empty(),
            name: self.registered.client_name.clone(),
            registration: None,
        }
    }
}
