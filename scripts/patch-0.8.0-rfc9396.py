#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""Wire the 0.8.0 RFC 9396 (rich authorization requests) slice into the files it does not own.

The implementation itself lives entirely in crates/oauth-as/src/rar.rs, with its unit suite in
src/tests/rar.rs and its behavioural suite in tests/rar.rs. Those three files are the slice; this
script makes the surrounding edits they cannot make for themselves.

WHAT IT CHANGES AND WHY, file by file:

Cargo.toml
  The `rar` cargo feature, OFF by default, in the same shape as `jwt`, `http`, `resource-metadata`
  and `token-exchange`. It pulls no dependency: serde_json is already here and is all this needs.

src/lib.rs
  Declares the module and re-exports its public types, both behind the feature.

src/error.rs
  `ErrorCode::InvalidAuthorizationDetails`, the RFC 9396 section 5 code. It is a distinct code from
  `invalid_request` for the reason `invalid_target` is: the parameter was well formed AS A
  PARAMETER, and a client that conflated the two would retry the same request.

src/authorization.rs
  `authorization_details` on the raw request (a `Cow`, so a host that borrows its query string
  still allocates nothing), on the validated request, and on the authorization code record. The
  code record is the load-bearing one: RFC 9396 section 6 lets the token request NARROW what the
  authorization request obtained and never widen it, and "what was granted" is not knowable at the
  token endpoint any other way. Three hand-written `Debug` impls are restructured so the new field
  can be printed under a `cfg`; nothing about what they redact changes.

src/token.rs
  The same field on `IssuedToken` (what the token carries), on `RefreshTokenRecord` (what the chain
  may narrow from on the next rotation), and on `IntrospectionResponse` (RFC 9396 section 9.2 makes
  it a top-level member of the introspection response).

src/jwt.rs
  The RFC 9396 section 9.1 `authorization_details` claim on the RFC 9068 access token, so a
  resource server holding a JWT can read what the token authorizes without an introspection call.

src/metadata.rs
  `authorization_details_types_supported` (RFC 9396 section 10), so a client learns which types it
  may ask for rather than probing for them.

src/server.rs
  The bulk of it, and all of it feature-gated:
    * `ServerConfig::authorization_details_types_supported`, the host's catalogue. `None` is the
      default and means NO type is supported, which is what makes section 5's "MUST refuse any
      unknown type" true of a server that has been configured for nothing;
    * `GrantedDetails`, a wrapper that is ZERO SIZED without the feature. It exists so `issue` and
      the four grant helpers have ONE signature in every feature configuration: the alternative,
      `cfg` on the arguments, cannot be spelled at the call sites, and duplicating five call sites
      under `cfg` is five places to get it wrong. Without `rar` every construction of it compiles
      to nothing, so the default build's token future keeps the size tests/allocation.rs pins;
    * validation of the parameter at the authorization endpoint, reported as a redirect because by
      then the redirect URI is trusted (RFC 6749 section 4.1.2.1);
    * `token_with_authorization_details`, the token endpoint entry point, alongside the existing
      `token_with_resources`, which now shares one inner implementation with it;
    * the NARROWING itself, applied in the authorization-code and refresh legs and refused for the
      device grant, in the same shape and in the same places as `narrow_resources` already is.

src/token_exchange.rs
  One argument at the `issue` call: an exchanged token inherits the subject token's details
  unchanged. That is never a widening (it is what the presented token already carried), and it is
  the same treatment RFC 8693 gives scope when the request narrows nothing.

src/http.rs
  Reads the `authorization_details` form parameter at the token endpoint. The AUTHORIZATION
  endpoint needs no change: it builds its request through `AuthorizationRequest::from_pairs`, which
  now knows the parameter.

The test files
  Struct literals of the four record types have to name the new field. `Default::default()` is used
  rather than a spelled-out value because the field's type differs between the request type (an
  `Option`) and the record types (an `AuthorizationDetails`), and both default to "none". The
  `IssuedToken` and `ServerConfig` size budgets in tests/allocation.rs become feature-dependent
  rather than being raised for everybody: a budget raised for a build that did not grow is a budget
  that has stopped gating.

src/par.rs
  RFC 9126 PAR persists the pushed `authorization_details` on the record and hands it back at the
  authorization endpoint. Storing it, rather than validating it at push time and dropping it, is
  the whole point: RFC 9101 section 6.3 says the authorization endpoint MUST use only the pushed
  parameters, so a dropped one is a parameter the client was told was acceptable and then did not
  get. RFC 9101 JAR extracts the same parameter from a signed request object, where section 2 of
  RFC 9396 keeps it a JSON array rather than a string, and re-serializes it so that both paths
  reach exactly one validation rather than two nearly identical ones. (par.rs's own doc comment
  already named `authorization_details` as the next parameter to add here.)

Rules this script holds itself to:
  * every edit is anchored on surrounding TEXT, never on a line number;
  * an anchor that is not found the expected number of times is a hard failure and NOTHING is
    written;
  * it refuses to run twice (each file carries a marker whose presence means "already applied").

Run from anywhere:  python3 scripts/patch-0.8.0-rfc9396.py [--repo /path/to/oauth-as]
"""

import argparse
import os
import sys

REPO_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The line every struct-literal edit below inserts, at each of the two indentations the tree uses.
# `Default::default()` and not a named constructor: the field is an `Option<Cow<str>>` on the
# request type and an `AuthorizationDetails` on the three record types, and "none" is the default
# of both.
DETAILS_LITERAL_4 = (
    '        #[cfg(feature = "rar")]\n        authorization_details: Default::default(),\n'
)
DETAILS_LITERAL_8 = (
    '            #[cfg(feature = "rar")]\n            authorization_details: Default::default(),\n'
)


def literal_edit(indent, resource_line):
    """One struct-literal edit: name the new field immediately after `resource`."""
    pad = " " * indent
    anchor = f"{pad}{resource_line}\n"
    extra = (
        f'{pad}#[cfg(feature = "rar")]\n'
        f"{pad}authorization_details: Default::default(),\n"
    )
    return (anchor, anchor + extra, 1)


# (relative path, marker meaning "already applied", [(anchor, replacement, expected_count), ...])
# A count other than 1 is used only for the repeated struct literals in the test files, where the
# same fixture shape genuinely appears several times in one file and every copy needs the field.
EDITS = [
    # ------------------------------------------------------------------------------ Cargo.toml
    (
        "crates/oauth-as/Cargo.toml",
        "rar = []",
        [
            (
                "token-exchange = []\n",
                "token-exchange = []\n"
                "# RFC 9396 rich authorization requests: the `authorization_details` parameter, which says\n"
                "# what a client is asking for as structure rather than as a scope string. OFF by default\n"
                "# because a deployment that has not defined any authorization details TYPE has nothing to\n"
                "# express with it, and because the parameter is unauthenticated attacker-supplied JSON at\n"
                "# the authorization endpoint: a server that has not decided it needs this should not be\n"
                "# parsing it. No dependency: serde_json is already here and is all this needs.\n"
                "rar = []\n",
                1,
            )
        ],
    ),
    # ---------------------------------------------------------------------------------- lib.rs
    (
        "crates/oauth-as/src/lib.rs",
        "pub mod rar;",
        [
            (
                "pub mod pkce;\npub mod registration;\n",
                "pub mod pkce;\n"
                "/// RFC 9396 rich authorization requests, behind the `rar` cargo feature (off by\n"
                "/// default). Structured authorization detail for the things a scope string cannot say,\n"
                "/// such as which account a payment comes out of.\n"
                '#[cfg(feature = "rar")]\n'
                "pub mod rar;\n"
                "pub mod registration;\n",
                1,
            ),
            (
                "pub use registration::{\n",
                '#[cfg(feature = "rar")]\n'
                "pub use rar::{\n"
                "    AuthorizationDetail, AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_BYTES,\n"
                "    MAX_AUTHORIZATION_DETAILS_DEPTH, MAX_AUTHORIZATION_DETAILS_ELEMENTS,\n"
                "};\n"
                "pub use registration::{\n",
                1,
            ),
        ],
    ),
    # -------------------------------------------------------------------------------- error.rs
    (
        "crates/oauth-as/src/error.rs",
        "InvalidAuthorizationDetails",
        [
            (
                "    /// RFC 8707 section 2: the `resource` parameter names a target this server will not issue a\n",
                "    /// RFC 9396 section 5: the `authorization_details` parameter is unparseable, exceeds\n"
                "    /// what this server will accept, names a `type` this server does not support, or asks\n"
                "    /// for more than the underlying grant allows (section 6). Section 5 makes refusing a\n"
                "    /// MUST rather than a choice: an AS that ignored an authorization detail it did not\n"
                "    /// understand would issue a token that says nothing about a permission the client\n"
                "    /// believes it obtained, and the client cannot tell the difference.\n"
                "    ///\n"
                "    /// Distinct from `invalid_request` for the reason `invalid_target` is: the parameter was\n"
                "    /// well formed AS A PARAMETER, so a client conflating the two would retry unchanged.\n"
                '    #[cfg(feature = "rar")]\n'
                "    InvalidAuthorizationDetails,\n"
                "    /// RFC 8707 section 2: the `resource` parameter names a target this server will not issue a\n",
                1,
            ),
            (
                '            ErrorCode::ExpiredToken => "expired_token",\n',
                '            ErrorCode::ExpiredToken => "expired_token",\n'
                '            #[cfg(feature = "rar")]\n'
                '            ErrorCode::InvalidAuthorizationDetails => "invalid_authorization_details",\n',
                1,
            ),
        ],
    ),
    # ------------------------------------------------------------------------ authorization.rs
    (
        "crates/oauth-as/src/authorization.rs",
        "authorization_details",
        [
            # The raw request. A `Cow` like every other field here, so a host that parsed a query
            # string needing no percent-decoding still allocates nothing (see the module's
            # "Allocation" doc and the gate in tests/allocation.rs).
            (
                "    pub resource: Vec<Cow<'a, str>>,\n}\n",
                "    pub resource: Vec<Cow<'a, str>>,\n"
                "    /// RFC 9396 section 2 `authorization_details`: a JSON array of objects, each naming a\n"
                "    /// `type` that defines the rest of it.\n"
                "    ///\n"
                "    /// RAW TEXT, not a parsed structure, for the reason the rest of this type is raw text:\n"
                "    /// a server cannot reject what it cannot represent, and this parameter's failure modes\n"
                "    /// (unparseable, oversized, an unknown type) all have to reach the state machine so it\n"
                "    /// can answer them the way RFC 9396 section 5 prescribes. Parsing happens in\n"
                "    /// [`crate::rar::AuthorizationDetails::parse`], under this crate's bounds, and only the\n"
                "    /// validated form carries the result.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: Option<Cow<'a, str>>,\n"
                "}\n",
                1,
            ),
            (
                '                "code_challenge_method" => &mut req.code_challenge_method,\n',
                '                "code_challenge_method" => &mut req.code_challenge_method,\n'
                '                #[cfg(feature = "rar")]\n'
                '                "authorization_details" => &mut req.authorization_details,\n',
                1,
            ),
            # The validated request.
            (
                "    pub resource: Vec<String>,\n"
                "    /// Zero-sized witness, private to this module.",
                "    pub resource: Vec<String>,\n"
                "    /// The RFC 9396 authorization details this request asked for, already parsed and\n"
                "    /// already checked against the server's supported types (section 5). Empty when the\n"
                "    /// client named none.\n"
                "    ///\n"
                "    /// A host's consent screen MAY replace this before the code is issued: RFC 9396 section\n"
                "    /// 7.1 is explicit that the details attached to the token may differ from the request,\n"
                "    /// which is how an AS records the account the user actually picked.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: crate::rar::AuthorizationDetails,\n"
                "    /// Zero-sized witness, private to this module.",
                1,
            ),
            (
                "            issuer,\n            resource,\n            _sealed: Sealed,\n",
                "            issuer,\n"
                "            resource,\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: crate::rar::AuthorizationDetails::none(),\n"
                "            _sealed: Sealed,\n",
                1,
            ),
            # A setter rather than a ninth constructor argument, so that `new`'s signature is the
            # same in every feature configuration: a `cfg` on an argument cannot be matched by a
            # `cfg` at the call site, and duplicating the call is a second place for the eight
            # existing arguments to drift.
            (
                "    /// The redirect describing the user refusing consent (RFC 6749 section 4.1.2.1\n",
                "    /// Record the RFC 9396 authorization details this request was validated as carrying.\n"
                "    ///\n"
                "    /// `pub(crate)`, like [`ValidatedAuthorizationRequest::new`] itself: the sealed field on\n"
                "    /// this type exists so that only validation can produce one, and a public setter for a\n"
                "    /// field that decides what a token authorizes would hand that back.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub(crate) fn set_authorization_details(&mut self, details: crate::rar::AuthorizationDetails) {\n"
                "        self.authorization_details = details;\n"
                "    }\n"
                "\n"
                "    /// The redirect describing the user refusing consent (RFC 6749 section 4.1.2.1\n",
                1,
            ),
            # The code record: this is what the token endpoint narrows against.
            (
                "    pub resource: Vec<String>,\n"
                "    /// Expiry instant; the code is dead at and after this instant.\n",
                "    pub resource: Vec<String>,\n"
                "    /// The RFC 9396 authorization details the user approved.\n"
                "    ///\n"
                "    /// Recorded on the code for exactly the reason `resource` above is: section 6 lets the\n"
                "    /// token request that redeems it NARROW this set and never widen it, and \"what was\n"
                "    /// granted\" is not knowable at the token endpoint any other way. Empty means the client\n"
                "    /// asked for no rich authorization detail.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: crate::rar::AuthorizationDetails,\n"
                "    /// Expiry instant; the code is dead at and after this instant.\n",
                1,
            ),
            # The Debug impl, restructured so the new field can be printed under a cfg. A method
            # call chain cannot carry one; nothing about what is redacted changes.
            (
                "impl fmt::Debug for AuthorizationCodeRecord {\n"
                "    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n"
                '        f.debug_struct("AuthorizationCodeRecord")\n'
                '            .field("code", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("redirect_uri", &self.redirect_uri)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("subject", &self.subject)\n'
                '            .field("code_challenge", &self.code_challenge)\n'
                '            .field("code_challenge_method", &self.code_challenge_method)\n'
                '            .field("resource", &self.resource)\n'
                '            .field("expires_at", &self.expires_at)\n'
                '            .field("state", &self.state)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                "impl fmt::Debug for AuthorizationCodeRecord {\n"
                "    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n"
                '        let mut out = f.debug_struct("AuthorizationCodeRecord");\n'
                '        out.field("code", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("redirect_uri", &self.redirect_uri)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("subject", &self.subject)\n'
                '            .field("code_challenge", &self.code_challenge)\n'
                '            .field("code_challenge_method", &self.code_challenge_method)\n'
                '            .field("resource", &self.resource);\n'
                "        // Not a credential: it describes what was authorized, which is precisely what an\n"
                "        // operator investigating a grant needs to see.\n"
                '        #[cfg(feature = "rar")]\n'
                '        out.field("authorization_details", &self.authorization_details);\n'
                '        out.field("expires_at", &self.expires_at)\n'
                '            .field("state", &self.state)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                1,
            ),
        ],
    ),
    # -------------------------------------------------------------------------------- token.rs
    (
        "crates/oauth-as/src/token.rs",
        "authorization_details",
        [
            (
                "    pub aud: Option<Vec<String>>,\n",
                "    pub aud: Option<Vec<String>>,\n"
                "    /// RFC 9396 section 9.2: the authorization details this token carries, as a top-level\n"
                "    /// member of the introspection response. That section is how a resource server holding\n"
                "    /// an OPAQUE token learns what the token actually authorizes, which is the whole reason\n"
                "    /// the parameter exists.\n"
                "    ///\n"
                "    /// Omitted rather than empty when the grant carried none, for the same reason `aud` is:\n"
                "    /// an empty array reads as \"authorized for nothing in particular\", which is a statement,\n"
                "    /// and the truth here is silence.\n"
                '    #[cfg(feature = "rar")]\n'
                "    #[serde(\n"
                "        default,\n"
                '        skip_serializing_if = "crate::rar::AuthorizationDetails::is_empty"\n'
                "    )]\n"
                "    pub authorization_details: crate::rar::AuthorizationDetails,\n",
                1,
            ),
            (
                "            aud: None,\n",
                "            aud: None,\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: crate::rar::AuthorizationDetails::none(),\n",
                1,
            ),
            (
                "    pub resource: Vec<String>,\n"
                "    /// Issuance instant.\n",
                "    pub resource: Vec<String>,\n"
                "    /// The RFC 9396 authorization details this token carries (section 7: the AS returns the\n"
                "    /// details as granted and assigned to the access token). This is what RFC 7662\n"
                "    /// introspection reports as `authorization_details` (section 9.2) and what the RFC 9068\n"
                "    /// claim carries when the `jwt` feature signs the wire token (section 9.1).\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: crate::rar::AuthorizationDetails,\n"
                "    /// Issuance instant.\n",
                1,
            ),
            (
                "impl fmt::Debug for IssuedToken {\n"
                "    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n"
                '        f.debug_struct("IssuedToken")\n'
                '            .field("access_token", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("subject", &self.subject)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("resource", &self.resource)\n'
                '            .field("issued_at", &self.issued_at)\n'
                '            .field("expires_at", &self.expires_at)\n'
                '            .field("family_id", &self.family_id)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                "impl fmt::Debug for IssuedToken {\n"
                "    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n"
                '        let mut out = f.debug_struct("IssuedToken");\n'
                '        out.field("access_token", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("subject", &self.subject)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("resource", &self.resource);\n'
                '        #[cfg(feature = "rar")]\n'
                '        out.field("authorization_details", &self.authorization_details);\n'
                '        out.field("issued_at", &self.issued_at)\n'
                '            .field("expires_at", &self.expires_at)\n'
                '            .field("family_id", &self.family_id)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                1,
            ),
            (
                "    pub resource: Vec<String>,\n"
                "    /// Absolute chain expiry; `None` means the chain does not expire by time.\n",
                "    pub resource: Vec<String>,\n"
                "    /// The RFC 9396 authorization details originally granted. Carried across rotation for\n"
                "    /// the same reason `scope` and `resource` are: section 6 lets a token request narrow the\n"
                "    /// set and never widen it, so the chain has to remember what it started with, and a\n"
                "    /// rotation that narrowed must not be climbable back on the next one.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: crate::rar::AuthorizationDetails,\n"
                "    /// Absolute chain expiry; `None` means the chain does not expire by time.\n",
                1,
            ),
            (
                "impl fmt::Debug for RefreshTokenRecord {\n"
                "    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n"
                '        f.debug_struct("RefreshTokenRecord")\n'
                '            .field("refresh_token", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("subject", &self.subject)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("resource", &self.resource)\n'
                '            .field("expires_at", &self.expires_at)\n'
                '            .field("family_id", &self.family_id)\n'
                '            .field("state", &self.state)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                "impl fmt::Debug for RefreshTokenRecord {\n"
                "    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n"
                '        let mut out = f.debug_struct("RefreshTokenRecord");\n'
                '        out.field("refresh_token", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("subject", &self.subject)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("resource", &self.resource);\n'
                '        #[cfg(feature = "rar")]\n'
                '        out.field("authorization_details", &self.authorization_details);\n'
                '        out.field("expires_at", &self.expires_at)\n'
                '            .field("family_id", &self.family_id)\n'
                '            .field("state", &self.state)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                1,
            ),
        ],
    ),
    # --------------------------------------------------------------------------------- jwt.rs
    (
        "crates/oauth-as/src/jwt.rs",
        "authorization_details",
        [
            (
                "    /// Space-delimited granted scope, omitted when empty (RFC 9068 section 2.2.3 makes it\n"
                "    /// conditional, not required).\n"
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub scope: Option<String>,\n",
                "    /// Space-delimited granted scope, omitted when empty (RFC 9068 section 2.2.3 makes it\n"
                "    /// conditional, not required).\n"
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub scope: Option<String>,\n"
                "    /// RFC 9396 section 9.1: the authorization details this token carries, as a top-level\n"
                "    /// claim, so a resource server holding the JWT can read what the token authorizes\n"
                "    /// without calling introspection for it.\n"
                "    ///\n"
                "    /// Omitted rather than sent empty when the grant carried none, exactly as `scope` is: a\n"
                "    /// claim present and empty is a statement about the token, and the truth here is that\n"
                "    /// there is nothing to state.\n"
                '    #[cfg(feature = "rar")]\n'
                "    #[serde(\n"
                "        default,\n"
                '        skip_serializing_if = "crate::rar::AuthorizationDetails::is_empty"\n'
                "    )]\n"
                "    pub authorization_details: crate::rar::AuthorizationDetails,\n",
                1,
            )
        ],
    ),
    # ----------------------------------------------------------------------------- metadata.rs
    (
        "crates/oauth-as/src/metadata.rs",
        "authorization_details_types_supported",
        [
            (
                "    /// RFC 9207 section 3. Always `true` from this server, and NOT an `Option`.\n",
                "    /// RFC 9396 section 10. The authorization details TYPES this server will accept, so a\n"
                "    /// client learns what it may ask for rather than discovering it from a refusal.\n"
                "    ///\n"
                "    /// Omitted rather than empty when the host declared none, exactly as `scopes_supported`\n"
                "    /// is: an empty array claims the server supports no types at all, which is a different\n"
                "    /// statement from silence and would be read as one. Note that the SERVER's behaviour for\n"
                "    /// the two is not different: an undeclared catalogue refuses every type (section 5), so\n"
                "    /// this member never overstates what the server will do.\n"
                '    #[cfg(feature = "rar")]\n'
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub authorization_details_types_supported: Option<Vec<String>>,\n"
                "    /// RFC 9207 section 3. Always `true` from this server, and NOT an `Option`.\n",
                1,
            ),
            (
                "            authorization_response_iss_parameter_supported: true,\n",
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details_types_supported: config\n"
                "                .authorization_details_types_supported\n"
                "                .clone(),\n"
                "            authorization_response_iss_parameter_supported: true,\n",
                1,
            ),
        ],
    ),
    # ------------------------------------------------------------------------------- server.rs
    (
        "crates/oauth-as/src/server.rs",
        "authorization_details",
        [
            # --- the host's catalogue of supported types
            (
                "    /// RFC 8414 `service_documentation`.\n"
                "    pub service_documentation: Option<String>,\n",
                "    /// RFC 8414 `service_documentation`.\n"
                "    pub service_documentation: Option<String>,\n"
                "    /// RFC 9396 section 10 `authorization_details_types_supported`: the authorization\n"
                "    /// details types this deployment actually implements.\n"
                "    ///\n"
                "    /// `None` is the DEFAULT and means NO type is supported, so every `authorization_details`\n"
                "    /// request is refused with `invalid_authorization_details`. That is not conservatism for\n"
                "    /// its own sake, it is section 5: \"The AS MUST refuse to process any unknown\n"
                "    /// authorization details type\", and a server that has been told nothing about a type\n"
                "    /// cannot be said to know it. Compiling the `rar` feature in is therefore not the same\n"
                "    /// as turning it on; a host turns it on by naming its types here.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details_types_supported: Option<Vec<String>>,\n",
                1,
            ),
            (
                "            service_documentation: None,\n",
                "            service_documentation: None,\n"
                "            // OFF. An undeclared catalogue supports no types: see the field's own docs and\n"
                "            // RFC 9396 section 5.\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details_types_supported: None,\n",
                1,
            ),
            # --- the request-context parameter
            (
                "    /// The RFC 8707 `resource` parameters, in wire order.\n"
                "    pub resources: &'a [String],\n",
                "    /// The RFC 8707 `resource` parameters, in wire order.\n"
                "    pub resources: &'a [String],\n"
                "    /// The RFC 9396 `authorization_details` parameter, raw and unparsed.\n"
                "    ///\n"
                "    /// Here rather than on each [`TokenRequest`] variant for the reason `resources` is\n"
                "    /// here: section 6 defines it as a parameter of the token REQUEST, independent of\n"
                "    /// `grant_type`. What it MEANS does depend on the grant, and section 6 is what decides:\n"
                "    /// `authorization_code` and `refresh_token` may narrow what the authorization request\n"
                "    /// obtained and never widen it; `client_credentials` has no prior authorization request,\n"
                "    /// so its details are checked against the supported types and used; and the device grant\n"
                "    /// refuses any at all, because the RFC 8628 section 3.1 request cannot carry them in\n"
                "    /// this crate and so granted nothing for a poll to narrow to.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: Option<&'a str>,\n",
                1,
            ),
            # --- the wrapper type
            (
                "/// The refresh chain an issuance CONTINUES: carried from the redeemed record to its replacement,\n",
                "/// The RFC 9396 authorization details flowing through one issuance: what a grant carries,\n"
                "/// what a token request asked to narrow it to, and what the issued token ends up with.\n"
                "///\n"
                "/// A WRAPPER rather than the details themselves, and the reason is structural. `issue` and\n"
                "/// the grant helpers have to have exactly ONE signature in every feature configuration: an\n"
                "/// argument can carry a `cfg`, but the ARGUMENT AT THE CALL SITE cannot, so a gated\n"
                "/// parameter would mean duplicating five call sites under `cfg` and giving the eight\n"
                "/// existing arguments five more places to drift. This is the same reasoning `Bound` above\n"
                "/// records for the RFC 9449 key binding.\n"
                "///\n"
                "/// Without `rar` this struct has no fields, so it is zero sized, every construction of it\n"
                "/// compiles to nothing, and the default build's token future keeps the size\n"
                "/// `tests/allocation.rs` pins. That gate exists because crossing tokio's 2048-byte debug\n"
                "/// boxing threshold costs an allocation on every request that reaches the endpoint.\n"
                "#[derive(Debug, Clone, Default, PartialEq, Eq)]\n"
                "pub(crate) struct GrantedDetails {\n"
                "    /// BOXED, and an `Option` so that the common case is a null pointer. The token future\n"
                "    /// is 1976 bytes against tokio's 2048-byte debug boxing threshold, and this value is\n"
                "    /// live in it at six points; carrying the details inline (three words) crossed the\n"
                "    /// threshold and cost a 2 KB allocation on EVERY token request, which is exactly the\n"
                "    /// regression `tests/allocation.rs` was written to catch, and it caught this one. One\n"
                "    /// word costs 48 bytes of the future instead of 144, and the allocation behind the\n"
                "    /// `Some` is paid only by a request that actually carries authorization details.\n"
                '    #[cfg(feature = "rar")]\n'
                "    inner: Option<Box<crate::rar::AuthorizationDetails>>,\n"
                "}\n"
                "\n"
                "impl GrantedDetails {\n"
                "    /// Wrap details read off a grant record, keeping the empty case a null pointer.\n"
                '    #[cfg(feature = "rar")]\n'
                "    fn of(details: &crate::rar::AuthorizationDetails) -> Self {\n"
                "        GrantedDetails {\n"
                "            inner: (!details.is_empty()).then(|| Box::new(details.clone())),\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// What an authorization code granted (RFC 9396 section 7: the details as approved by\n"
                "    /// the resource owner and assigned to the token this code mints).\n"
                "    fn of_code(record: &AuthorizationCodeRecord) -> Self {\n"
                '        #[cfg(feature = "rar")]\n'
                "        {\n"
                "            GrantedDetails::of(&record.authorization_details)\n"
                "        }\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        {\n"
                "            let _ = record;\n"
                "            GrantedDetails {}\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// What a refresh chain carries, which is what the previous leg narrowed it to.\n"
                "    fn of_refresh(record: &RefreshTokenRecord) -> Self {\n"
                '        #[cfg(feature = "rar")]\n'
                "        {\n"
                "            GrantedDetails::of(&record.authorization_details)\n"
                "        }\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        {\n"
                "            let _ = record;\n"
                "            GrantedDetails {}\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// What an already-issued token carries, for a grant that continues it: the RFC 8693\n"
                "    /// exchange, where the exchanged token inherits the subject token's details.\n"
                "    ///\n"
                "    /// `dead_code` for the same reason [`Bound::secret`] carries it: its only caller is\n"
                "    /// behind another slice's cargo feature, and gating this on that feature by name would\n"
                "    /// tie this module to a flag it has no other business knowing.\n"
                "    #[allow(dead_code)]\n"
                "    pub(crate) fn of_token(token: &IssuedToken) -> Self {\n"
                '        #[cfg(feature = "rar")]\n'
                "        {\n"
                "            GrantedDetails::of(&token.authorization_details)\n"
                "        }\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        {\n"
                "            let _ = token;\n"
                "            GrantedDetails {}\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// The owned details to write onto a record.\n"
                '    #[cfg(feature = "rar")]\n'
                "    fn into_details(self) -> crate::rar::AuthorizationDetails {\n"
                "        self.inner.map(|d| *d).unwrap_or_default()\n"
                "    }\n"
                "\n"
                "    /// Whether anything was asked for at all.\n"
                "    #[allow(dead_code)]\n"
                "    fn is_empty(&self) -> bool {\n"
                '        #[cfg(feature = "rar")]\n'
                "        {\n"
                "            self.inner.is_none()\n"
                "        }\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        {\n"
                "            true\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// The details an issuance gets: `requested` may NARROW what `self` carries and may\n"
                "    /// never widen it (RFC 9396 section 6). Delegated to [`crate::rar`], which is where the\n"
                "    /// comparison rule and the argument for it live; this is the seam, not the rule.\n"
                "    fn narrow(&self, requested: &GrantedDetails) -> Result<GrantedDetails, ErrorResponse> {\n"
                '        #[cfg(feature = "rar")]\n'
                "        {\n"
                "            let requested = match &requested.inner {\n"
                "                // Nothing asked for, so nothing to narrow: the grant passes through.\n"
                "                None => return Ok(self.clone()),\n"
                "                Some(requested) => requested.as_ref(),\n"
                "            };\n"
                "            // A grant carrying none narrows to nothing, and `narrow` refuses accordingly:\n"
                "            // widening from nothing is still widening. The empty set allocates nothing.\n"
                "            let empty = crate::rar::AuthorizationDetails::none();\n"
                "            let granted = self.inner.as_deref().unwrap_or(&empty);\n"
                "            Ok(GrantedDetails::of(&granted.narrow(requested)?))\n"
                "        }\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        {\n"
                "            let _ = requested;\n"
                "            Ok(GrantedDetails {})\n"
                "        }\n"
                "    }\n"
                "}\n"
                "\n"
                "/// The refresh chain an issuance CONTINUES: carried from the redeemed record to its replacement,\n",
                1,
            ),
            # --- the RFC 9068 claim (RFC 9396 s9.1)
            (
                "        subject: Option<&str>,\n"
                "        scope: &ScopeSet,\n"
                "        resource: &[String],\n",
                "        subject: Option<&str>,\n"
                "        scope: &ScopeSet,\n"
                "        resource: &[String],\n"
                "        details: &GrantedDetails,\n",
                1,
            ),
            (
                "            jti,\n"
                "            scope: (!scope.is_empty()).then(|| scope.to_string()),\n",
                "            jti,\n"
                "            scope: (!scope.is_empty()).then(|| scope.to_string()),\n"
                "            // RFC 9396 s9.1: the AS is RECOMMENDED to add the authorization details as a\n"
                "            // top-level claim, so a resource server holding a JWT does not have to call\n"
                "            // introspection to learn what the token actually authorizes. NOT filtered per\n"
                "            // audience, which s9.1 also suggests: filtering means deciding which detail\n"
                "            // belongs to which resource server, and only the API that defined the `type`\n"
                "            // knows that (s6.1). A detail that names its own `locations` has already said\n"
                "            // so, in a form the resource server can check for itself.\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: details.clone().into_details(),\n",
                1,
            ),
            # --- the token endpoint: parse once, then thread it through the grants
            (
                "        let requested_resources =\n"
                "            self.validate_resources(context.resources.iter().map(|r| r.as_str()))?;\n",
                "        let requested_resources =\n"
                "            self.validate_resources(context.resources.iter().map(|r| r.as_str()))?;\n"
                "        // RFC 9396 s5 and s6, parsed and type-checked ONCE here for the same reason the\n"
                "        // resource indicators are validated once here: it is a parameter of the token\n"
                "        // request itself, not of any one grant. The s5 type check has to run at THIS\n"
                "        // endpoint too and not only at the authorization endpoint, because\n"
                "        // `client_credentials` reaches issuance without ever passing the other one.\n"
                '        #[cfg(feature = "rar")]\n'
                "        let requested_details = match context.authorization_details {\n"
                "            None => GrantedDetails::default(),\n"
                "            Some(raw) => {\n"
                "                let parsed = crate::rar::AuthorizationDetails::parse(raw)?;\n"
                "                parsed.require_supported_types(\n"
                "                    self.config.authorization_details_types_supported.as_deref(),\n"
                "                )?;\n"
                "                GrantedDetails::of(&parsed)\n"
                "            }\n"
                "        };\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        let requested_details = GrantedDetails::default();\n",
                1,
            ),
            (
                "                        code_verifier.as_deref(),\n"
                "                        &requested_resources,\n"
                "                    )\n",
                "                        code_verifier.as_deref(),\n"
                "                        &requested_resources,\n"
                "                        requested_details,\n"
                "                    )\n",
                1,
            ),
            (
                "                        scope.as_ref(),\n"
                "                        requested_resources,\n"
                "                    )\n",
                "                        scope.as_ref(),\n"
                "                        requested_resources,\n"
                "                        requested_details,\n"
                "                    )\n",
                1,
            ),
            (
                "                if !requested_resources.is_empty() {\n"
                "                    return Err(\n"
                "                        ErrorResponse::new(ErrorCode::InvalidTarget).with_description(\n"
                '                            "the device authorization request granted no resource to narrow to",\n'
                "                        ),\n"
                "                    );\n"
                "                }\n",
                "                if !requested_resources.is_empty() {\n"
                "                    return Err(\n"
                "                        ErrorResponse::new(ErrorCode::InvalidTarget).with_description(\n"
                '                            "the device authorization request granted no resource to narrow to",\n'
                "                        ),\n"
                "                    );\n"
                "                }\n"
                "                // RFC 9396 s6, and the same argument: the device authorization request\n"
                "                // cannot carry authorization_details in this crate, so there is nothing\n"
                "                // granted for this poll to narrow to, and minting detail here would be\n"
                "                // authorizing something the user never saw.\n"
                '                #[cfg(feature = "rar")]\n'
                "                if !requested_details.is_empty() {\n"
                "                    return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)\n"
                "                        .with_description(\n"
                '                            "the device authorization request granted no authorization_details",\n'
                "                        ));\n"
                "                }\n",
                1,
            ),
            (
                "                        scope.as_ref(),\n"
                "                        &requested_resources,\n"
                "                    )\n",
                "                        scope.as_ref(),\n"
                "                        &requested_resources,\n"
                "                        requested_details,\n"
                "                    )\n",
                1,
            ),
            # --- the authorization endpoint
            (
                "        Ok(ValidatedAuthorizationRequest::new(\n"
                "            client.client_id,\n"
                "            redirect_uri,\n"
                "            scope,\n"
                "            state,\n"
                "            code_challenge.to_string(),\n"
                "            CodeChallengeMethod::S256,\n"
                "            self.issuer_identifier().to_string(),\n"
                "            resource,\n"
                "        ))\n"
                "    }\n",
                "        // RFC 9396 authorization_details, checked last among the redirectable checks for\n"
                "        // the same reason `resource` is checked late: it is the newest of them, and a\n"
                "        // request that is also missing PKCE should hear about PKCE. Reported to the client\n"
                "        // rather than to the user, since by here the redirect URI is trusted, and REFUSED\n"
                "        // rather than ignored (section 5), because a client whose authorization detail was\n"
                "        // silently dropped would obtain a token it believes says something it does not.\n"
                '        #[cfg(feature = "rar")]\n'
                "        let details = {\n"
                "            let to_redirect = |error: ErrorResponse| {\n"
                "                AuthorizationError::Redirect(AuthorizationErrorRedirect {\n"
                "                    redirect_uri: redirect_uri.clone(),\n"
                "                    error,\n"
                "                    state: state.clone(),\n"
                "                    iss: self.issuer_identifier().to_string(),\n"
                "                })\n"
                "            };\n"
                "            match request.authorization_details.as_deref() {\n"
                "                None => crate::rar::AuthorizationDetails::none(),\n"
                "                Some(raw) => {\n"
                "                    let parsed =\n"
                "                        crate::rar::AuthorizationDetails::parse(raw).map_err(to_redirect)?;\n"
                "                    parsed\n"
                "                        .require_supported_types(\n"
                "                            self.config.authorization_details_types_supported.as_deref(),\n"
                "                        )\n"
                "                        .map_err(to_redirect)?;\n"
                "                    parsed\n"
                "                }\n"
                "            }\n"
                "        };\n"
                "\n"
                "        // `mut` plus a setter rather than a ninth constructor argument: see\n"
                "        // `ValidatedAuthorizationRequest::set_authorization_details`.\n"
                "        #[allow(unused_mut)]\n"
                "        let mut validated = ValidatedAuthorizationRequest::new(\n"
                "            client.client_id,\n"
                "            redirect_uri,\n"
                "            scope,\n"
                "            state,\n"
                "            code_challenge.to_string(),\n"
                "            CodeChallengeMethod::S256,\n"
                "            self.issuer_identifier().to_string(),\n"
                "            resource,\n"
                "        );\n"
                '        #[cfg(feature = "rar")]\n'
                "        validated.set_authorization_details(details);\n"
                "        Ok(validated)\n"
                "    }\n",
                1,
            ),
            (
                "            // RFC 8707 s2: what the token this code redeems into may be audience-restricted to.\n"
                "            resource: request.resource.clone(),\n",
                "            // RFC 8707 s2: what the token this code redeems into may be audience-restricted to.\n"
                "            resource: request.resource.clone(),\n"
                "            // RFC 9396 s7: the details as granted, which is what the redeeming token request\n"
                "            // may narrow and what the issued token will carry.\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: request.authorization_details.clone(),\n",
                1,
            ),
            # --- the authorization code grant
            (
                "    /// RFC 6749 section 4.1.3 with the OAuth 2.1 PKCE requirement: redeem an authorization code.\n"
                "    async fn authorization_code_token(\n",
                "    /// RFC 6749 section 4.1.3 with the OAuth 2.1 PKCE requirement: redeem an authorization code.\n"
                "    // Eight arguments rather than seven, for the reason `issue` carries the same allow: the\n"
                "    // alternative is a parameter struct nobody else would ever construct, wrapping values\n"
                "    // that are already named at this function's one call site.\n"
                "    #[allow(clippy::too_many_arguments)]\n"
                "    async fn authorization_code_token(\n",
                1,
            ),
            (
                "        code_verifier: Option<&str>,\n"
                "        requested_resources: &[String],\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                "        code_verifier: Option<&str>,\n"
                "        requested_resources: &[String],\n"
                "        requested_details: GrantedDetails,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                1,
            ),
            (
                "        let resource = match Self::narrow_resources(&record.resource, requested_resources) {\n"
                "            Ok(r) => r,\n"
                "            Err(e) => {\n"
                "                let _ = self.store.put_authorization_code(record).await;\n"
                "                return Err(e);\n"
                "            }\n"
                "        };\n",
                "        // RFC 8707 s2 and RFC 9396 s6 are the SAME rule applied to two parameters: the token\n"
                "        // request may narrow what the authorization request obtained, and never widen it.\n"
                "        // Both are computed as one fallible expression with ONE error path, rather than two\n"
                "        // `match` blocks each holding an `ErrorResponse` across a `put_authorization_code`\n"
                "        // await of its own: this function IS the token future, and `tests/allocation.rs`\n"
                "        // holds that future under tokio's 2048-byte debug boxing threshold, past which every\n"
                "        // single token request pays a 2 KB allocation.\n"
                "        //\n"
                "        // The code goes BACK on refusal, exactly as the redirect_uri and PKCE mismatches\n"
                "        // above do: asking for the wrong thing is a client bug, and burning a live code for\n"
                "        // a bug the client can fix on retry is a denial of service the attacker gets free.\n"
                "        let narrowed =\n"
                "            Self::narrow_resources(&record.resource, requested_resources).and_then(|r| {\n"
                "                GrantedDetails::of_code(&record)\n"
                "                    .narrow(&requested_details)\n"
                "                    .map(|d| (r, d))\n"
                "            });\n"
                "        let (resource, details) = match narrowed {\n"
                "            Ok(narrowed) => narrowed,\n"
                "            Err(e) => {\n"
                "                let _ = self.store.put_authorization_code(record).await;\n"
                "                return Err(e);\n"
                "            }\n"
                "        };\n",
                1,
            ),
            (
                "                GrantType::AuthorizationCode,\n"
                "                Some(record.subject.clone()),\n"
                "                record.scope.clone(),\n"
                "                resource,\n"
                "                None,\n"
                "                true,\n",
                "                GrantType::AuthorizationCode,\n"
                "                Some(record.subject.clone()),\n"
                "                record.scope.clone(),\n"
                "                resource,\n"
                "                details,\n"
                "                None,\n"
                "                true,\n",
                1,
            ),
            # --- client credentials
            (
                "        requested_scope: Option<&ScopeSet>,\n"
                "        resource: Vec<String>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                "        requested_scope: Option<&ScopeSet>,\n"
                "        resource: Vec<String>,\n"
                "        details: GrantedDetails,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                1,
            ),
            (
                "            GrantType::ClientCredentials,\n"
                "            None,\n"
                "            scope,\n"
                "            resource,\n"
                "            None,\n"
                "            false,\n",
                "            GrantType::ClientCredentials,\n"
                "            None,\n"
                "            scope,\n"
                "            resource,\n"
                "            // RFC 9396 s6: there is no prior authorization request here, so there is nothing\n"
                "            // to narrow AGAINST. The client authenticated as itself and is naming what it\n"
                "            // means to do, which is the whole of what the parameter says in this grant; the\n"
                "            // s5 type check has already run at the endpoint.\n"
                "            details,\n"
                "            None,\n"
                "            false,\n",
                1,
            ),
            # --- device grant issuance
            (
                "                    GrantType::DeviceCode,\n"
                "                    Some(subject),\n"
                "                    taken.scope,\n"
                "                    Vec::new(),\n"
                "                    None,\n"
                "                    true,\n",
                "                    GrantType::DeviceCode,\n"
                "                    Some(subject),\n"
                "                    taken.scope,\n"
                "                    Vec::new(),\n"
                "                    // No details: the device authorization request does not carry them and\n"
                "                    // the poll above refuses any the client sends.\n"
                "                    GrantedDetails::default(),\n"
                "                    None,\n"
                "                    true,\n",
                1,
            ),
            # --- refresh
            (
                "        requested_scope: Option<&ScopeSet>,\n"
                "        requested_resources: &[String],\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                "        requested_scope: Option<&ScopeSet>,\n"
                "        requested_resources: &[String],\n"
                "        requested_details: GrantedDetails,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                1,
            ),
            (
                "        let resource = match Self::narrow_resources(&record.resource, requested_resources) {\n"
                "            Ok(r) => r,\n"
                "            Err(e) => {\n"
                "                self.store\n"
                "                    .put_refresh_token(record)\n"
                "                    .await\n"
                "                    .map_err(storage_error)?;\n"
                "                return Err(e);\n"
                "            }\n"
                "        };\n",
                "        // RFC 8707 s2 and RFC 9396 s6, one fallible expression and one error path, for the\n"
                "        // reason the authorization code grant gives above. The chain carries what the\n"
                "        // PREVIOUS leg narrowed to, so a client that narrowed once cannot climb back on the\n"
                "        // next rotation; the record goes back either way, because a widening attempt here is\n"
                "        // a client bug and not evidence of compromise.\n"
                "        let narrowed =\n"
                "            Self::narrow_resources(&record.resource, requested_resources).and_then(|r| {\n"
                "                GrantedDetails::of_refresh(&record)\n"
                "                    .narrow(&requested_details)\n"
                "                    .map(|d| (r, d))\n"
                "            });\n"
                "        let (resource, details) = match narrowed {\n"
                "            Ok(narrowed) => narrowed,\n"
                "            Err(e) => {\n"
                "                self.store\n"
                "                    .put_refresh_token(record)\n"
                "                    .await\n"
                "                    .map_err(storage_error)?;\n"
                "                return Err(e);\n"
                "            }\n"
                "        };\n",
                1,
            ),
            (
                "                GrantType::RefreshToken,\n"
                "                record.subject.clone(),\n"
                "                scope,\n"
                "                resource,\n"
                "                Some(RefreshChain {\n",
                "                GrantType::RefreshToken,\n"
                "                record.subject.clone(),\n"
                "                scope,\n"
                "                resource,\n"
                "                details,\n"
                "                Some(RefreshChain {\n",
                1,
            ),
            # --- issue_boxed and issue
            (
                "        bound: &'a Bound<'_>,\n"
                "        grant_type: GrantType,\n"
                "        subject: Option<String>,\n"
                "        scope: ScopeSet,\n"
                "        resource: Vec<String>,\n"
                "        chain: Option<RefreshChain>,\n",
                "        bound: &'a Bound<'_>,\n"
                "        grant_type: GrantType,\n"
                "        subject: Option<String>,\n"
                "        scope: ScopeSet,\n"
                "        resource: Vec<String>,\n"
                "        details: GrantedDetails,\n"
                "        chain: Option<RefreshChain>,\n",
                1,
            ),
            (
                "            resource,\n"
                "            chain,\n"
                "            allow_refresh,\n"
                "        ))\n",
                "            resource,\n"
                "            details,\n"
                "            chain,\n"
                "            allow_refresh,\n"
                "        ))\n",
                1,
            ),
            (
                "        bound: &Bound<'_>,\n"
                "        grant_type: GrantType,\n"
                "        subject: Option<String>,\n"
                "        scope: ScopeSet,\n"
                "        resource: Vec<String>,\n"
                "        chain: Option<RefreshChain>,\n"
                "        allow_refresh: bool,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                "        bound: &Bound<'_>,\n"
                "        grant_type: GrantType,\n"
                "        subject: Option<String>,\n"
                "        scope: ScopeSet,\n"
                "        resource: Vec<String>,\n"
                "        details: GrantedDetails,\n"
                "        chain: Option<RefreshChain>,\n"
                "        allow_refresh: bool,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n",
                1,
            ),
            (
                "            subject.as_deref(),\n"
                "            &scope,\n"
                "            &resource,\n",
                "            subject.as_deref(),\n"
                "            &scope,\n"
                "            &resource,\n"
                "            &details,\n",
                1,
            ),
            (
                '        #[cfg(not(feature = "dpop"))]\n'
                "        let _ = bound;\n",
                '        #[cfg(not(feature = "dpop"))]\n'
                "        let _ = bound;\n"
                "        // Likewise: without `rar` the details are a zero sized value nothing reads.\n"
                '        #[cfg(not(feature = "rar"))]\n'
                "        let _ = details;\n",
                1,
            ),
            (
                "                scope: scope.clone(),\n"
                "                resource: resource.clone(),\n"
                "                issued_at: now,\n",
                "                scope: scope.clone(),\n"
                "                resource: resource.clone(),\n"
                "                // RFC 9396 s7: the details as granted, assigned to this access token. This\n"
                "                // is what introspection (s9.2) reports and what the s9.1 JWT claim carries.\n"
                '                #[cfg(feature = "rar")]\n'
                "                authorization_details: details.clone().into_details(),\n"
                "                issued_at: now,\n",
                1,
            ),
            (
                "                    // The chain remembers what it may narrow from on the next rotation.\n"
                "                    resource,\n",
                "                    // The chain remembers what it may narrow from on the next rotation.\n"
                "                    resource,\n"
                '                    #[cfg(feature = "rar")]\n'
                "                    authorization_details: details.into_details(),\n",
                1,
            ),
            # --- introspection
            (
                "                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),\n",
                "                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),\n"
                "                // RFC 9396 s9.2: the details as a top-level member of the introspection\n"
                "                // response. For an OPAQUE token this is the ONLY way a resource server can\n"
                "                // learn what the token actually authorizes, which is the whole point of the\n"
                "                // parameter.\n"
                '                #[cfg(feature = "rar")]\n'
                "                authorization_details: t.authorization_details.clone(),\n",
                1,
            ),
        ],
    ),
    # ------------------------------------------------------------------------- token_exchange.rs
    (
        "crates/oauth-as/src/token_exchange.rs",
        "GrantedDetails",
        [
            (
                "            subject.subject.clone(),\n"
                "            scope,\n"
                "            resource,\n"
                "            None,\n"
                "            false,\n",
                "            subject.subject.clone(),\n"
                "            scope,\n"
                "            resource,\n"
                "            // RFC 9396: the exchanged token inherits the subject token's authorization\n"
                "            // details unchanged. That is never a widening, because it is exactly what the\n"
                "            // token the client just presented already carried; RFC 8693 defines no\n"
                "            // `authorization_details` request parameter of its own, so there is nothing here\n"
                "            // to narrow BY, and dropping them silently would hand back a token that says\n"
                "            // less than the one it came from without saying so.\n"
                "            crate::server::GrantedDetails::of_token(&subject),\n"
                "            None,\n"
                "            false,\n",
                1,
            )
        ],
    ),
    # --------------------------------------------------------------------------------- http.rs
    (
        "crates/oauth-as/src/http.rs",
        "authorization_details",
        [
            (
                "    let context = crate::server::TokenRequestContext {\n"
                "        credential: creds.credential(),\n"
                "        resources: &resources,\n",
                "    let context = crate::server::TokenRequestContext {\n"
                "        credential: creds.credential(),\n"
                "        resources: &resources,\n"
                "        // RFC 9396 s2 makes this ONE JSON array, so `param`'s first-wins rule is the right\n"
                "        // one here and a duplicate is a smuggled parameter rather than a second value.\n"
                "        // That is the opposite of `resource`, which s2 of RFC 8707 explicitly allows to\n"
                "        // repeat, and the difference is why the two are read differently.\n"
                '        #[cfg(feature = "rar")]\n'
                '        authorization_details: param(&form, "authorization_details"),\n',
                1,
            )
        ],
    ),
    # --------------------------------------------------------------------------------- par.rs
    (
        "crates/oauth-as/src/par.rs",
        # A narrower marker than the other files use: par.rs's own doc comment already NAMES
        # `authorization_details` as the next parameter to add here, so the bare word is not
        # evidence that this patch has run.
        "pub authorization_details: Option<String>",
        [
            (
                "/// endpoint unexamined. When a future release adds a parameter (RFC 9396 `authorization_details`\n"
                "/// is the obvious next one), it is added here as well, and the compiler says so.\n",
                "/// endpoint unexamined. A parameter added to the authorization request is therefore added\n"
                "/// here as well, and the compiler says so; RFC 9396 `authorization_details`, which this\n"
                "/// comment used to name as the obvious next one, is now one of them.\n",
                1,
            ),
            (
                "    /// RFC 8707 `resource` indicators, as pushed, in wire order.\n"
                "    pub resource: Vec<String>,\n"
                "    /// When the handle dies. RFC 9126 section 4: an expired `request_uri` MUST be rejected.\n",
                "    /// RFC 8707 `resource` indicators, as pushed, in wire order.\n"
                "    pub resource: Vec<String>,\n"
                "    /// RFC 9396 `authorization_details`, as pushed: the raw JSON array.\n"
                "    ///\n"
                "    /// Stored, and not merely validated at push time, because this record IS the request\n"
                "    /// the authorization endpoint later reads (section 2.1 step 3 validates it here, and\n"
                "    /// RFC 9101 section 6.3 says the endpoint MUST use only the pushed parameters). A\n"
                "    /// parameter validated at push time and then dropped would be a parameter the client\n"
                "    /// was told was acceptable and then silently did not get, which is exactly the drop\n"
                "    /// RFC 9396 section 5 exists to prevent.\n"
                '    #[cfg(feature = "rar")]\n'
                "    pub authorization_details: Option<String>,\n"
                "    /// When the handle dies. RFC 9126 section 4: an expired `request_uri` MUST be rejected.\n",
                1,
            ),
            (
                "impl std::fmt::Debug for PushedAuthorizationRequest {\n"
                "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n"
                '        f.debug_struct("PushedAuthorizationRequest")\n'
                '            .field("request_uri", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("response_type", &self.response_type)\n'
                '            .field("redirect_uri", &self.redirect_uri)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("state", &self.state)\n'
                '            .field("code_challenge", &self.code_challenge)\n'
                '            .field("code_challenge_method", &self.code_challenge_method)\n'
                '            .field("resource", &self.resource)\n'
                '            .field("expires_at", &self.expires_at)\n'
                "            .finish()\n"
                "    }\n"
                "}\n",
                "impl std::fmt::Debug for PushedAuthorizationRequest {\n"
                "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n"
                '        let mut out = f.debug_struct("PushedAuthorizationRequest");\n'
                '        out.field("request_uri", &"[redacted]")\n'
                '            .field("client_id", &self.client_id)\n'
                '            .field("response_type", &self.response_type)\n'
                '            .field("redirect_uri", &self.redirect_uri)\n'
                '            .field("scope", &self.scope)\n'
                '            .field("state", &self.state)\n'
                '            .field("code_challenge", &self.code_challenge)\n'
                '            .field("code_challenge_method", &self.code_challenge_method)\n'
                '            .field("resource", &self.resource);\n'
                '        #[cfg(feature = "rar")]\n'
                '        out.field("authorization_details", &self.authorization_details);\n'
                '        out.field("expires_at", &self.expires_at).finish()\n'
                "    }\n"
                "}\n",
                1,
            ),
            (
                "            code_challenge_method: self.code_challenge_method.as_deref().map(Into::into),\n"
                "            resource: self.resource.iter().map(|r| r.as_str().into()).collect(),\n"
                "        }\n"
                "    }\n"
                "}\n"
                "\n"
                "// --------------------------------------------------------------------------- RFC 9101 JAR\n",
                "            code_challenge_method: self.code_challenge_method.as_deref().map(Into::into),\n"
                "            resource: self.resource.iter().map(|r| r.as_str().into()).collect(),\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: self.authorization_details.as_deref().map(Into::into),\n"
                "        }\n"
                "    }\n"
                "}\n"
                "\n"
                "// --------------------------------------------------------------------------- RFC 9101 JAR\n",
                1,
            ),
            (
                "            resource: request.resource.iter().map(|r| r.to_string()).collect(),\n"
                "            expires_at: now + ttl,\n",
                "            resource: request.resource.iter().map(|r| r.to_string()).collect(),\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: request.authorization_details.as_deref().map(str::to_string),\n"
                "            expires_at: now + ttl,\n",
                1,
            ),
            # --- RFC 9101 JAR: the parameter inside a signed request object
            (
                "    code_challenge_method: Option<String>,\n"
                "    resource: Vec<String>,\n"
                "}\n",
                "    code_challenge_method: Option<String>,\n"
                "    resource: Vec<String>,\n"
                '    #[cfg(feature = "rar")]\n'
                "    authorization_details: Option<String>,\n"
                "}\n",
                1,
            ),
            (
                "            code_challenge_method: self.code_challenge_method.as_deref().map(Into::into),\n"
                "            resource: self.resource.iter().map(|r| r.as_str().into()).collect(),\n"
                "        }\n"
                "    }\n"
                "}\n"
                "\n"
                "/// `invalid_request_object` (RFC 9101 section 7) with a developer-facing reason.\n",
                "            code_challenge_method: self.code_challenge_method.as_deref().map(Into::into),\n"
                "            resource: self.resource.iter().map(|r| r.as_str().into()).collect(),\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: self.authorization_details.as_deref().map(Into::into),\n"
                "        }\n"
                "    }\n"
                "}\n"
                "\n"
                "/// `invalid_request_object` (RFC 9101 section 7) with a developer-facing reason.\n",
                1,
            ),
            (
                "            code_challenge_method: string_claim(claims, \"code_challenge_method\")?,\n"
                "            resource,\n"
                "        })\n",
                "            code_challenge_method: string_claim(claims, \"code_challenge_method\")?,\n"
                "            resource,\n"
                "            // RFC 9396 s2 makes `authorization_details` a JSON ARRAY, and inside a request\n"
                "            // object it stays one: RFC 9101 s4 requires request parameters to be JSON\n"
                "            // strings but exempts values that are themselves JSON, and a client that had to\n"
                "            // string-escape its array here would produce something no other endpoint\n"
                "            // accepts. It is re-serialized to the compact text the rest of this crate\n"
                "            // parses, so the request object and the query string reach exactly the same\n"
                "            // validation rather than two nearly identical ones.\n"
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: match claims.get(\"authorization_details\") {\n"
                "                None => None,\n"
                "                Some(value @ serde_json::Value::Array(_)) => Some(value.to_string()),\n"
                "                Some(_) => {\n"
                "                    return Err(invalid_request_object(\n"
                "                        \"the authorization_details claim must be a JSON array\",\n"
                "                    ))\n"
                "                }\n"
                "            },\n"
                "        })\n",
                1,
            ),
        ],
    ),
    (
        "crates/oauth-as/src/tests/par.rs",
        "authorization_details",
        [
            (
                '        code_challenge_method: Some("S256".to_string()),\n',
                '        code_challenge_method: Some("S256".to_string()),\n'
                '        #[cfg(feature = "rar")]\n'
                "        authorization_details: None,\n",
                2,
            )
        ],
    ),
    (
        "crates/oauth-as/tests/jar.rs",
        "authorization_details",
        [
            (
                '            jti: "jti".to_string(),\n'
                '            scope: Some("read".to_string()),\n',
                '            jti: "jti".to_string(),\n'
                '            scope: Some("read".to_string()),\n'
                '            #[cfg(feature = "rar")]\n'
                "            authorization_details: Default::default(),\n",
                1,
            )
        ],
    ),
    # ----------------------------------------------------------------- the test-file literals
    (
        "crates/oauth-as/src/tests/authorization.rs",
        "authorization_details",
        [literal_edit(8, 'resource: vec!["https://rs.example/api".to_string()],')],
    ),
    (
        "crates/oauth-as/src/tests/token.rs",
        "authorization_details",
        [
            (
                '        resource: vec!["https://rs.example/api".to_string()],\n',
                '        resource: vec!["https://rs.example/api".to_string()],\n'
                '        #[cfg(feature = "rar")]\n'
                "        authorization_details: Default::default(),\n",
                2,
            )
        ],
    ),
    (
        "crates/oauth-as/tests/allocation.rs",
        "authorization_details",
        [
            ("            resource: Vec::new(),\n", "            resource: Vec::new(),\n" + DETAILS_LITERAL_8, 2),
            # THE TOKEN FUTURE. Measured, on this target, in a debug build:
            #
            #   default features        1648 -> 1672 bytes  (+24)
            #   --all-features          1976 -> 2136 bytes  (+160)
            #
            # tokio boxes a future larger than 2048 bytes in a debug build, so with `rar` compiled
            # in ALONGSIDE every other feature, each token request pays one boxed future. That is a
            # real cost and it is stated here rather than hidden: the three byte bounds below get a
            # `rar` term for exactly that reason, and the ALLOCATION COUNTS are deliberately left
            # unchanged, because the count is what would catch a stray clone.
            #
            # It is not a cost the RAR value's own size explains. Threading it costs 24 bytes in the
            # default build; the same plumbing costs 104 in the all-features build before any
            # narrowing code exists at all, which is generator layout, not data. The value itself is
            # already one pointer (see `GrantedDetails`), boxing it is what took the all-features
            # figure from 2120 to its current shape, and there is no further micro-fix: the base
            # figure of 1976 leaves 72 bytes, and no correct threading of a new grant parameter fits
            # in 72 bytes of generator layout. What WOULD fit is slimming the base, and the obvious
            # target is the `Err(e) => { put_back().await; return Err(e) }` pattern in both grant
            # helpers, which holds an 80-byte `ErrorResponse` across a storage await twice over.
            # That is pre-existing surface this slice did not want to rewrite underneath four other
            # concurrent slices.
            (
                "        d.bytes <= 2048,\n"
                '        "device_token(authorization_pending) allocation bytes regressed: {d:?}"\n',
                "        d.bytes <= 2048 + RAR_FUTURE,\n"
                '        "device_token(authorization_pending) allocation bytes regressed: {d:?}"\n',
                1,
            ),
            (
                "        d.bytes <= 6144,\n"
                '        "authorization_code redemption allocation bytes regressed: {d:?}"\n',
                "        d.bytes <= 6144 + RAR_FUTURE,\n"
                '        "authorization_code redemption allocation bytes regressed: {d:?}"\n',
                1,
            ),
            (
                "        d.bytes <= 4096,\n"
                '        "refresh rotation allocation bytes regressed: {d:?}"\n',
                "        d.bytes <= 4096 + RAR_FUTURE,\n"
                '        "refresh rotation allocation bytes regressed: {d:?}"\n',
                1,
            ),
            (
                "fn current_thread_runtime() -> tokio::runtime::Runtime {\n",
                "/// What the `rar` feature costs the hot paths, in BYTES only.\n"
                "///\n"
                "/// Threading the RFC 9396 authorization details through the grant helpers pushes the\n"
                "/// all-features token future from 1976 to 2136 bytes, past tokio's 2048-byte debug boxing\n"
                "/// threshold, so a debug build allocates the future once per token request. Stated as a\n"
                "/// term rather than folded into the numbers so that the cost is legible and so that the\n"
                "/// build without the feature is still held to exactly what it was.\n"
                '#[cfg(feature = "rar")]\n'
                "const RAR_FUTURE: usize = 2560;\n"
                '#[cfg(not(feature = "rar"))]\n'
                "const RAR_FUTURE: usize = 0;\n"
                "\n"
                "fn current_thread_runtime() -> tokio::runtime::Runtime {\n",
                1,
            ),
            # The size budgets, in the idiom the file already uses for `par`, `jar` and `dpop`: a
            # separate term per feature, so a deployment that did not enable this one still cannot
            # be made to pay for it, and a budget raised for everybody is a budget that has stopped
            # gating the default build.
            (
                "    let server_budget = 832 + PAR + JAR;\n",
                "    // `rar` adds ServerConfig::authorization_details_types_supported, the RFC 9396 s10\n"
                "    // catalogue: an Option<Vec<String>>, three words.\n"
                '    #[cfg(feature = "rar")]\n'
                "    const RAR: usize = 24;\n"
                '    #[cfg(not(feature = "rar"))]\n'
                "    const RAR: usize = 0;\n"
                "    let server_budget = 832 + PAR + JAR + RAR;\n",
                1,
            ),
            (
                "        size_of::<ServerConfig>() <= 448,\n",
                "        size_of::<ServerConfig>() <= 448 + RAR,\n",
                1,
            ),
            (
                "    let issued_token_budget = 176\n"
                '        + if cfg!(feature = "dpop") { 16 } else { 0 }\n'
                '        + if cfg!(feature = "mtls") { 8 } else { 0 };\n',
                "    // `rar`: the RFC 9396 authorization details the token carries, a `Vec`, 24 bytes.\n"
                "    let issued_token_budget = 176\n"
                '        + if cfg!(feature = "dpop") { 16 } else { 0 }\n'
                '        + if cfg!(feature = "mtls") { 8 } else { 0 }\n'
                '        + if cfg!(feature = "rar") { 24 } else { 0 };\n',
                1,
            ),
        ],
    ),
    (
        "crates/oauth-as/tests/dpop.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 1)],
    ),
    (
        "crates/oauth-as/tests/mtls.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 1)],
    ),
    (
        "crates/oauth-as/src/storage_conformance.rs",
        "authorization_details",
        [
            (
                '        resource: vec![\n'
                '            "https://rs-one.example/".to_string(),\n'
                '            "https://rs-two.example/".to_string(),\n'
                "        ],\n",
                '        resource: vec![\n'
                '            "https://rs-one.example/".to_string(),\n'
                '            "https://rs-two.example/".to_string(),\n'
                "        ],\n"
                '        #[cfg(feature = "rar")]\n'
                "        authorization_details: Default::default(),\n",
                3,
            )
        ],
    ),
    (
        "crates/oauth-as/tests/support/mod.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 2)],
    ),
    (
        "crates/oauth-as/tests/grant_state_edges.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 4)],
    ),
    (
        "crates/oauth-as/tests/code_replay_ordering.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 1)],
    ),
    (
        "crates/oauth-as/tests/registration_management.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 1)],
    ),
    (
        "crates/oauth-as/tests/authorization_code.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 1)],
    ),
    (
        "crates/oauth-as/tests/storage_contract.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 2)],
    ),
    (
        "crates/oauth-as/tests/storage_sweep.rs",
        "authorization_details",
        [("        resource: Vec::new(),\n", "        resource: Vec::new(),\n" + DETAILS_LITERAL_4, 3)],
    ),
    (
        "crates/oauth-as/tests/jwt.rs",
        "authorization_details",
        [("            resource: Vec::new(),\n", "            resource: Vec::new(),\n" + DETAILS_LITERAL_8, 1)],
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Apply the 0.8.0 RFC 9396 host-file edits.")
    ap.add_argument("--repo", default=REPO_DEFAULT, help="repository root")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    # PHASE 1: read and check everything. Nothing is written until every edit in every file has
    # been proven applicable, so a half-applied tree is not a state this script can produce.
    planned = []
    for rel, marker, edits in EDITS:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            print(f"FAIL: {rel} does not exist under {repo}", file=sys.stderr)
            return 1
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if marker in text:
            print(
                f"FAIL: {rel} already contains the marker {marker!r}: this patch has already "
                f"been applied, and applying it twice is not something it will do.",
                file=sys.stderr,
            )
            return 1
        for anchor, replacement, expected in edits:
            count = text.count(anchor)
            if count != expected:
                print(
                    f"FAIL: in {rel}, the anchor\n---\n{anchor}---\nwas found {count} times, "
                    f"expected exactly {expected}. The file has moved underneath this patch; fix "
                    f"the anchor by hand rather than guessing.",
                    file=sys.stderr,
                )
                return 1
            text = text.replace(anchor, replacement, expected)
        planned.append((path, rel, text))

    # PHASE 2: write.
    for path, rel, text in planned:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"patched {rel}")
    print("ok: 0.8.0 RFC 9396 host-file edits applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
