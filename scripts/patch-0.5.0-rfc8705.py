#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""
Apply the 0.4.0 / 0.5.0 RFC 8705 slice's edits to the files that slice does NOT own.

The new module (crates/oauth-as/src/mtls.rs, with src/tests/mtls.rs and tests/mtls.rs) is written
directly. Everything it needs from a file owned by another change lives here instead, so the two
halves can be reviewed and applied independently.

Rules this script holds itself to:
  * every edit is anchored on surrounding TEXT, never on a line number;
  * an anchor that is not found EXACTLY ONCE in its file is a hard failure and NOTHING is written;
  * it refuses to run twice (each edit carries a marker whose presence means "already applied").

Run from anywhere:  python3 scripts/patch-0.5.0-rfc8705.py [--repo /path/to/oauth-as]

WHAT IT CHANGES AND WHY, file by file:

crates/oauth-as/Cargo.toml
  One new cargo feature, OFF by default, in the same shape as `jwt` and `http`: `mtls`. It pulls no
  dependency, because the host has already parsed the certificate (see the module docs) and the
  only arithmetic RFC 8705 defines is SHA-256 over DER plus base64, both already here for RFC 7636.

crates/oauth-as/src/lib.rs
  Declares and re-exports the new module behind its feature.

crates/oauth-as/src/client.rs
  NOTE: these three anchors sit AFTER the RFC 7523 `ConfidentialAssertion` variant, its `Debug`
  arm and its `verify_with` arm, because both slices append to the same three places and 7523
  landed first. If 7523 is ever reverted, re-anchor on `ConfidentialSecretHash` instead.

  A `ClientAuth::Mtls` variant, its hand-written `Debug` arm, and its `verify_with` arm. The
  `verify_with` arm is the security-relevant one and it answers `false` unconditionally: a
  mutual-TLS registration has no secret, so no presented secret may ever authenticate it, and that
  holds even in a build with the `mtls` feature OFF, where the variant can be deserialized from a
  host's store but nothing exists to check a certificate. Fail closed, not open.

crates/oauth-as/src/token.rs
  The RFC 7800 `cnf` claim, as a `Confirmation` struct with the RFC 8705 section 3.1 `x5t#S256`
  member, plus the `cnf` member on `IssuedToken` (so an opaque token carries its binding) and on
  `IntrospectionResponse` (RFC 8705 section 3.2). `Confirmation` is a STRUCT rather than a bare
  thumbprint on purpose: RFC 7800 section 3.1 makes `cnf` a JSON object of confirmation members,
  and RFC 9449 DPoP puts its own `jkt` member in the same object, so the two must be able to
  coexist rather than one overwriting the other.

crates/oauth-as/src/events.rs
  Two `ClientAuthFailure` variants, so the host's audit channel can tell "the terminator forwarded
  no certificate" from "the certificate did not match the registration". The wire keeps answering
  one `invalid_client` for both; the enum is `#[non_exhaustive]`, so adding to it is not a breaking
  change.

crates/oauth-as/src/metadata.rs
  Advertises `tls_client_auth` and `self_signed_tls_client_auth` in
  `token_endpoint_auth_methods_supported` when (and only when) they are compiled in, and adds the
  RFC 8705 section 3.3 `tls_client_certificate_bound_access_tokens` member.

crates/oauth-as/src/server.rs
  The plumbing: one `PresentedCertificate` type threaded from the four endpoints that authenticate
  a client down to `issue`, which is where the RFC 8705 section 3 binding is recorded. With the
  feature off that type is a zero-sized `PhantomData`, so the default build's stack frames and
  token future are byte-for-byte what they were.

  Public API is ADDED, never changed: `token`, `token_with_resources`, `device_authorization`,
  `introspection_response` and `revoke` keep their exact signatures and delegate; each gains an
  `mtls`-only sibling that also takes the certificate.

crates/oauth-as/tests/grant_state_edges.rs, tests/storage_sweep.rs, src/tests/token.rs
  One `cnf` field on each `IssuedToken` literal, feature-gated, because Rust struct literals must
  name every field.
"""

import argparse
import os
import sys

REPO_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (relative path, marker meaning "already applied", [(anchor, replacement), ...])
EDITS = [
    (
        "crates/oauth-as/Cargo.toml",
        "mtls = []",
        [
            (
                'jwt = ["dep:p256"]\n',
                'jwt = ["dep:p256"]\n'
                "# RFC 8705 mutual-TLS client authentication and certificate-bound access tokens.\n"
                "# OFF by default, and it adds NO dependency: TLS termination is the host's job in this\n"
                "# crate (it never sees a socket), so the host hands in a certificate it has already\n"
                "# verified and parsed, and the only arithmetic RFC 8705 defines on it is the section 3.1\n"
                "# SHA-256 thumbprint. `sha2` and `base64` are already here for RFC 7636 PKCE. An X.509\n"
                "# parser would add attack surface to recompute what the host must already know.\n"
                "mtls = []\n",
            )
        ],
    ),
    (
        "crates/oauth-as/src/lib.rs",
        "pub mod mtls;",
        [
            (
                # Anchored on `metadata` alone, and inserted AFTER it, so this survives whatever
                # other optional modules land in between: rustfmt sorts module declarations, and
                # `metadata` < `mtls` < everything else that could appear here.
                "pub mod metadata;\n",
                "pub mod metadata;\n"
                "/// RFC 8705 mutual-TLS client authentication and certificate-bound access tokens,\n"
                "/// behind the `mtls` cargo feature (off by default). READ THE MODULE DOCS FIRST: this\n"
                "/// crate cannot validate a certificate chain it did not negotiate, so the host's TLS\n"
                "/// layer is load bearing in a way no type here can enforce.\n"
                '#[cfg(feature = "mtls")]\n'
                "pub mod mtls;\n",
            ),
            (
                "pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};\n",
                "pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};\n"
                '#[cfg(feature = "mtls")]\n'
                "pub use mtls::{\n"
                "    CertificateThumbprint, ClientCertificate, ExpectedSubject, MtlsClientRegistration,\n"
                "    MtlsRegistrationError, RegisteredCertificates, SELF_SIGNED_TLS_CLIENT_AUTH, TLS_CLIENT_AUTH,\n"
                "    TLS_CLIENT_AUTH_SAN_DNS, TLS_CLIENT_AUTH_SAN_EMAIL, TLS_CLIENT_AUTH_SAN_IP,\n"
                "    TLS_CLIENT_AUTH_SAN_URI, TLS_CLIENT_AUTH_SUBJECT_DN,\n"
                "};\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/client.rs",
        "ClientAuth::Mtls",
        [
            (
                "        keys: crate::client_assertion::AssertionKeys,\n    },\n}\n",
                "        keys: crate::client_assertion::AssertionKeys,\n"
                "    },\n"
                "    /// RFC 8705: a confidential client that authenticates with a mutual-TLS CERTIFICATE and\n"
                "    /// holds no shared secret at all. This is the variant a deployment whose policy forbids\n"
                "    /// shared secrets registers, and the only one where the credential never travels: the\n"
                "    /// client proves possession of a private key to the host's TLS layer, and this crate is\n"
                "    /// handed the resulting certificate as an established fact.\n"
                "    ///\n"
                "    /// Carried INLINE rather than boxed, on the same measurement as the assertion variant\n"
                "    /// above: the widest shape [`crate::mtls::MtlsClientRegistration`] can take is one\n"
                "    /// `String` plus a discriminant, against `ConfidentialSecretHash`'s two `String`s, so\n"
                "    /// this variant does not make `ClientAuth`, or the [`Client`] cloned out of the store on\n"
                "    /// every token-plane request, any bigger than it already was.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    Mtls {\n"
                "        /// Which RFC 8705 method, and what it expects to see.\n"
                "        registration: crate::mtls::MtlsClientRegistration,\n"
                "    },\n"
                "}\n",
            ),
            (
                '                .debug_struct("ConfidentialAssertion")\n'
                '                .field("keys", keys)\n'
                "                .finish(),\n"
                "        }\n",
                '                .debug_struct("ConfidentialAssertion")\n'
                '                .field("keys", keys)\n'
                "                .finish(),\n"
                "            // NOT redacted: a registration that names an expected subject DN or a certificate\n"
                "            // thumbprint holds no secret. Both are public facts about a public document, and\n"
                "            // an operator debugging a refused mutual-TLS client needs to see exactly which\n"
                "            // value the server expected.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            ClientAuth::Mtls { registration } => f\n"
                '                .debug_struct("Mtls")\n'
                '                .field("registration", registration)\n'
                "                .finish(),\n"
                "        }\n",
            ),
            (
                "            ClientAuth::ConfidentialAssertion { .. } => false,\n        }\n",
                "            ClientAuth::ConfidentialAssertion { .. } => false,\n"
                "            // NEVER, and for the same reason as the assertion arm above. A mutual-TLS\n"
                "            // registration has no secret to compare against, so there is no presented string\n"
                "            // that could be the right one, and `None` is not the right answer either: unlike\n"
                "            // `Public`, this client is confidential and something must be proven. The\n"
                "            // certificate is checked by `crate::mtls::verify_certificate`, which is reached\n"
                "            // only from `AuthorizationServer::authenticate_client`; every OTHER caller of\n"
                "            // this function, now or later, therefore fails closed on a mutual-TLS client\n"
                "            // rather than accidentally authenticating one with no evidence at all.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            ClientAuth::Mtls { .. } => false,\n"
                "        }\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/token.rs",
        "x5t_s256",
        [
            # The `cnf` object becomes a HOME for confirmation methods rather than one method's
            # value. See the docstring at the top of this script.
            (
                "/// The RFC 7800 section 3.1 confirmation claim, in the one shape this server produces: the\n"
                "/// RFC 9449 section 6.1 `jkt`, a JWK thumbprint.\n"
                "///\n"
                "/// This is what a resource server checks the binding against, and it is the whole reason DPoP is\n"
                "/// worth anything at introspection time: without it the binding is known only to the authorization\n"
                "/// server, and an RS that introspects is back to trusting a bearer string.\n"
                '#[cfg(feature = "dpop")]\n'
                "#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n"
                "pub struct Confirmation {\n"
                "    /// The RFC 7638 SHA-256 thumbprint of the client's proof key, base64url without padding.\n"
                "    pub jkt: String,\n"
                "}\n"
                "\n"
                '#[cfg(feature = "dpop")]\n'
                "impl Confirmation {\n"
                "    /// Wrap a thumbprint.\n"
                "    pub fn jkt(jkt: impl Into<String>) -> Self {\n"
                "        Confirmation { jkt: jkt.into() }\n"
                "    }\n"
                "}\n",
                "/// The RFC 7800 section 3.1 confirmation claim: HOW a token is sender constrained, meaning\n"
                "/// what a presenter has to prove in addition to holding the string.\n"
                "///\n"
                "/// This is what a resource server checks the binding against, and it is the whole reason\n"
                "/// sender constraining is worth anything at introspection time: without it the binding is\n"
                "/// known only to the authorization server, and an RS that introspects is back to trusting a\n"
                "/// bearer string.\n"
                "///\n"
                "/// EVERY MEMBER IS OPTIONAL, and that is the design rather than an accident. RFC 7800 section\n"
                "/// 3.1 defines `cnf` as a JSON OBJECT whose members are confirmation methods, and different\n"
                "/// sender-constraining mechanisms register different members OF THE SAME OBJECT: RFC 9449\n"
                "/// section 6.1 registers `jkt` for a DPoP key binding, RFC 8705 section 3.1 registers\n"
                "/// `x5t#S256` for a certificate binding. A token can legitimately carry both, so neither may\n"
                "/// be modelled as \"the\" confirmation and neither may overwrite the other. Adding a mechanism\n"
                "/// means adding an optional member here; it never means replacing this type.\n"
                '#[cfg(any(feature = "dpop", feature = "mtls"))]\n'
                "#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]\n"
                "pub struct Confirmation {\n"
                "    /// RFC 9449 section 6.1 `jkt`: the RFC 7638 SHA-256 thumbprint of the client's proof\n"
                "    /// key, base64url without padding.\n"
                '    #[cfg(feature = "dpop")]\n'
                '    #[serde(default, skip_serializing_if = "Option::is_none")]\n'
                "    pub jkt: Option<String>,\n"
                "    /// RFC 8705 section 3.1 `x5t#S256`: the SHA-256 thumbprint of the DER encoding of the\n"
                "    /// X.509 certificate the client presented when the token was issued. A resource server\n"
                "    /// checks it with [`Confirmation::confirms_certificate`].\n"
                '    #[cfg(feature = "mtls")]\n'
                '    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]\n'
                "    pub x5t_s256: Option<crate::mtls::CertificateThumbprint>,\n"
                "}\n"
                "\n"
                '#[cfg(any(feature = "dpop", feature = "mtls"))]\n'
                "impl Confirmation {\n"
                "    /// Wrap a DPoP key thumbprint.\n"
                '    #[cfg(feature = "dpop")]\n'
                "    pub fn jkt(jkt: impl Into<String>) -> Self {\n"
                "        Confirmation {\n"
                "            jkt: Some(jkt.into()),\n"
                '            #[cfg(feature = "mtls")]\n'
                "            x5t_s256: None,\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// Whether this names no confirmation method at all, which is what an ordinary bearer\n"
                "    /// token has. The `cnf` member is OMITTED for such a token rather than sent as an empty\n"
                "    /// object: an empty `cnf` claims a constraint exists and then names none, which is worse\n"
                "    /// than silence.\n"
                "    pub fn is_empty(&self) -> bool {\n"
                "        #[cfg(feature = \"dpop\")]\n"
                "        if self.jkt.is_some() {\n"
                "            return false;\n"
                "        }\n"
                "        #[cfg(feature = \"mtls\")]\n"
                "        if self.x5t_s256.is_some() {\n"
                "            return false;\n"
                "        }\n"
                "        true\n"
                "    }\n"
                "}\n",
            ),
            # The introspection member now reports either mechanism, so its cfg widens.
            (
                "    /// RFC 9449 section 6.1: the key this token is bound to, present exactly when it is bound to\n"
                "    /// one.\n"
                "    ///\n"
                "    /// RFC 7662 section 2.2 lets a server return any claim it likes here, and RFC 9449 section 5\n"
                "    /// is explicit that a resource server has to be able to confirm the binding. Omitted rather\n"
                "    /// than sent as `null` for an unbound token, because `\"cnf\": null` reads to a careless RS as a\n"
                "    /// confirmation it has already checked.\n"
                '    #[cfg(feature = "dpop")]\n'
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub cnf: Option<Confirmation>,\n",
                "    /// How this token is sender constrained, present exactly when it is: RFC 9449 section 6.1\n"
                "    /// `jkt` for a DPoP key, RFC 8705 section 3.2 `x5t#S256` for a client certificate, or both.\n"
                "    ///\n"
                "    /// RFC 7662 section 2.2 lets a server return any claim it likes here, and RFC 9449 section 5\n"
                "    /// and RFC 8705 section 3.2 are each explicit that a resource server has to be able to\n"
                "    /// confirm the binding. Omitted rather than sent as `null` for an unbound token, because\n"
                "    /// `\"cnf\": null` reads to a careless RS as a confirmation it has already checked.\n"
                '    #[cfg(any(feature = "dpop", feature = "mtls"))]\n'
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub cnf: Option<Confirmation>,\n",
            ),
            (
                '            #[cfg(feature = "dpop")]\n            cnf: None,\n',
                '            #[cfg(any(feature = "dpop", feature = "mtls"))]\n            cnf: None,\n',
            ),
            # The AS-side record. Boxed for the size reason its own doc gives.
            (
                '    #[cfg(feature = "dpop")]\n'
                "    pub jkt: Option<Box<str>>,\n"
                "    /// The authorization grant this token belongs to (see [`RefreshTokenRecord::family_id`]).\n",
                '    #[cfg(feature = "dpop")]\n'
                "    pub jkt: Option<Box<str>>,\n"
                "    /// RFC 8705 section 3: the SHA-256 thumbprint of the client certificate this token is\n"
                "    /// bound to, or `None` for a token that is not certificate bound.\n"
                "    ///\n"
                "    /// Recorded on the AS side, and not only inside a signed JWT, for the same reason `jkt`\n"
                "    /// next door is: this crate's default access token is OPAQUE, and RFC 8705 section 3.2\n"
                "    /// has a resource server learn the binding by INTROSPECTING, which it can only be told\n"
                "    /// if it was persisted.\n"
                "    ///\n"
                "    /// `Option<Box<_>>` rather than the 32-byte thumbprint inline, on the same measurement\n"
                "    /// as `jkt`: this record is written and read on every token-plane request and\n"
                "    /// `tests/allocation.rs` holds it to a size budget, so an unbound token pays one null\n"
                "    /// pointer and the allocation happens only for a token that is actually bound.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub x5t_s256: Option<Box<crate::mtls::CertificateThumbprint>>,\n"
                "    /// The authorization grant this token belongs to (see [`RefreshTokenRecord::family_id`]).\n",
            ),
            # The refresh chain remembers it too, so a rotation cannot launder the binding away.
            (
                '    #[cfg(feature = "dpop")]\n'
                "    pub jkt: Option<Box<str>>,\n"
                "    /// The FAMILY this token belongs to: one identifier shared by every token, access or refresh,\n",
                '    #[cfg(feature = "dpop")]\n'
                "    pub jkt: Option<Box<str>>,\n"
                "    /// RFC 8705 section 3: the client certificate this refresh chain is bound to, or `None`\n"
                "    /// for an unbound chain.\n"
                "    ///\n"
                "    /// Carried across rotation and CHECKED on redemption, exactly as `jkt` is and for the\n"
                "    /// same argument: without it the binding would be decorative past the first access\n"
                "    /// token, because a stolen refresh token could simply be re-bound to whatever\n"
                "    /// certificate the thief holds on the next rotation. Section 3 makes this a MUST for\n"
                "    /// public clients specifically; this crate applies it to every chain that was issued\n"
                "    /// over a certificate, because a chain whose holder proved possession of a key once\n"
                "    /// should have to keep proving it, and for a confidential mutual-TLS client the rule\n"
                "    /// costs nothing (it presents that certificate on every request anyway).\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub x5t_s256: Option<Box<crate::mtls::CertificateThumbprint>>,\n"
                "    /// The FAMILY this token belongs to: one identifier shared by every token, access or refresh,\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/events.rs",
        "NoCertificatePresented",
        [
            (
                "    /// The host's own [`RateLimiter`] refused the attempt before it was evaluated.\n"
                "    RateLimited,\n",
                "    /// The host's own [`RateLimiter`] refused the attempt before it was evaluated.\n"
                "    RateLimited,\n"
                "    /// The registration authenticates with RFC 8705 mutual TLS and NO certificate reached\n"
                "    /// this crate. Worth separating from a mismatch: in practice it usually means the TLS\n"
                "    /// terminator is not configured to request, verify or forward a client certificate, which\n"
                "    /// is an operational fault affecting every mutual-TLS client at once rather than an\n"
                "    /// attack on one of them.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    NoCertificatePresented,\n"
                "    /// A certificate was presented and did not match the registration (RFC 8705 section 2.1\n"
                "    /// subject values, or section 2.2 thumbprints). This one IS the attack shape: a caller\n"
                "    /// holding some valid certificate trying to be a client it is not.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    CertificateMismatch,\n",
            )
        ],
    ),
    (
        "crates/oauth-as/src/metadata.rs",
        "tls_client_certificate_bound_access_tokens",
        [
            (
                "    pub authorization_response_iss_parameter_supported: bool,\n}\n",
                "    pub authorization_response_iss_parameter_supported: bool,\n"
                "    /// RFC 8705 section 3.3. Always `true` in a build with the `mtls` feature, and absent\n"
                "    /// entirely without it, which is the same honesty rule `jwks_uri` follows.\n"
                "    ///\n"
                "    /// Constant rather than configurable because the behaviour is: with the feature compiled\n"
                "    /// in, an access token issued over a connection whose certificate the host passed in is\n"
                "    /// ALWAYS bound to it (RFC 8705 section 3), so there is no configuration under which the\n"
                "    /// claim could be false. Section 3.3's default when the member is absent is `false`, so a\n"
                "    /// build without the feature says nothing and means nothing, which is correct.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub tls_client_certificate_bound_access_tokens: bool,\n"
                "}\n",
            ),
            (
                "            authorization_response_iss_parameter_supported: true,\n",
                "            authorization_response_iss_parameter_supported: true,\n"
                '            #[cfg(feature = "mtls")]\n'
                "            tls_client_certificate_bound_access_tokens: true,\n",
            ),
        ],
    ),
]

EDITS[5][2].append(
    (
        "                    methods.push(crate::client_assertion::PRIVATE_KEY_JWT.to_string());\n"
        "                }\n"
        "                methods\n",
        "                    methods.push(crate::client_assertion::PRIVATE_KEY_JWT.to_string());\n"
        "                }\n"
        "                // RFC 8705 s2.1.1 and s2.2.1 register these two, advertised exactly when this\n"
        "                // build can actually check a certificate. Both halves matter: advertising a\n"
        "                // method the endpoint rejects is a lie a client cannot recover from, and staying\n"
        "                // silent about one it accepts is how a client ends up sending a shared secret it\n"
        "                // did not need to have.\n"
        '                #[cfg(feature = "mtls")]\n'
        "                {\n"
        "                    methods.push(crate::mtls::TLS_CLIENT_AUTH.to_string());\n"
        "                    methods.push(crate::mtls::SELF_SIGNED_TLS_CLIENT_AUTH.to_string());\n"
        "                }\n"
        "                methods\n",
    )
)

EDITS.append(
    (
        "crates/oauth-as/src/server.rs",
        "certificate: Option<&'a crate::mtls::ClientCertificate",
        [
            (
                "    /// RFC 7523 section 2.2 `client_assertion`: the signed JWT itself.\n"
                '    #[cfg(feature = "client_assertion")]\n'
                "    pub client_assertion: Option<&'a str>,\n"
                "}\n",
                "    /// RFC 7523 section 2.2 `client_assertion`: the signed JWT itself.\n"
                '    #[cfg(feature = "client_assertion")]\n'
                "    pub client_assertion: Option<&'a str>,\n"
                "    /// The RFC 8705 client certificate the HOST has ALREADY VERIFIED for this connection.\n"
                "    ///\n"
                "    /// READ [`crate::mtls`]'s trust boundary section before setting this. This library\n"
                "    /// never sees a socket, so it cannot validate a chain it did not negotiate: a host that\n"
                "    /// fills this in from an unverified source (an unstripped `X-Client-Cert` header, a\n"
                "    /// terminator that requests but does not require a certificate) has authenticated\n"
                "    /// nobody, and every comparison this crate then makes is against a value the caller\n"
                "    /// chose.\n"
                "    ///\n"
                "    /// It does two separate jobs, either of which can apply on its own:\n"
                "    ///\n"
                "    /// - section 2, AUTHENTICATION: a client registered with\n"
                "    ///   [`crate::client::ClientAuth::Mtls`] is authenticated by this certificate and by\n"
                "    ///   nothing else. Such a client cannot authenticate through a call that leaves this\n"
                "    ///   `None`, which is the point: a host that forgets to pass the certificate gets\n"
                "    ///   `invalid_client`, never a token.\n"
                "    /// - section 3, BINDING: the issued access token is bound to this certificate whatever\n"
                "    ///   the client's authentication method was, including a public client (section 4).\n"
                "    ///   Binding is not conditional on a per-client flag, because a bound token is never\n"
                "    ///   less safe than the unbound one it replaces, and a client that does not want\n"
                "    ///   binding does not present a certificate.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub certificate: Option<&'a crate::mtls::ClientCertificate<'a>>,\n"
                "}\n",
            ),
            (
                "        ClientCredential {\n"
                "            client_secret,\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion_type: None,\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion: None,\n"
                "        }\n",
                "        ClientCredential {\n"
                "            client_secret,\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion_type: None,\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion: None,\n"
                '            #[cfg(feature = "mtls")]\n'
                "            certificate: None,\n"
                "        }\n",
            ),
            (
                "        ClientCredential {\n"
                "            client_secret: None,\n"
                "            client_assertion_type,\n"
                "            client_assertion: Some(client_assertion),\n"
                "        }\n"
                "    }\n",
                "        ClientCredential {\n"
                "            client_secret: None,\n"
                "            client_assertion_type,\n"
                "            client_assertion: Some(client_assertion),\n"
                '            #[cfg(feature = "mtls")]\n'
                "            certificate: None,\n"
                "        }\n"
                "    }\n"
                "\n"
                "    /// The RFC 8705 credential: the client certificate the host verified during the TLS\n"
                "    /// handshake, and no secret at all.\n"
                "    ///\n"
                "    /// For a client that authenticates some OTHER way and still wants its token bound\n"
                "    /// (RFC 8705 section 4, including a public client), set\n"
                "    /// [`ClientCredential::certificate`] on the credential it is already using rather than\n"
                "    /// replacing it with this one.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub fn certificate(certificate: &'a crate::mtls::ClientCertificate<'a>) -> Self {\n"
                "        ClientCredential {\n"
                "            certificate: Some(certificate),\n"
                "            ..ClientCredential::secret(None)\n"
                "        }\n"
                "    }\n",
            ),
            (
                "        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this\n"
                "        // crate does not implement is decided by the host's verifier (see\n"
                "        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.\n",
                "        // RFC 8705 s2 mutual-TLS client authentication, handled apart from the secret\n"
                "        // comparison below for the same reason the assertion above is: it is a different\n"
                "        // KIND of credential. There is nothing to compare; there is a certificate the HOST\n"
                "        // verified, matched against what the registration says it expects to see.\n"
                "        //\n"
                "        // Dispatched on the REGISTRATION, never on what the request happened to present.\n"
                "        // That direction is load bearing in both senses: a certificate presented by a\n"
                "        // secret-authenticating client never reaches this path (it is for section 3 binding\n"
                "        // only), and a mutual-TLS client can never fall through to the secret comparison\n"
                "        // below.\n"
                '        #[cfg(feature = "mtls")]\n'
                "        if matches!(client.auth, crate::client::ClientAuth::Mtls { .. }) {\n"
                "            return match crate::mtls::verify_certificate(&client, cred) {\n"
                "                Ok(()) => {\n"
                "                    self.hooks.record(attempt, AttemptOutcome::Succeeded);\n"
                "                    Ok(client)\n"
                "                }\n"
                "                Err(failure) => {\n"
                "                    self.hooks.record(attempt, AttemptOutcome::Failed);\n"
                "                    self.hooks.emit(|| Event::ClientAuthenticationFailed {\n"
                "                        client_id: client_id.as_str(),\n"
                "                        failure,\n"
                "                    });\n"
                "                    // The same bare `invalid_client` every other refusal here returns: RFC\n"
                "                    // 6749 s5.2 collapses them on purpose, so a caller cannot probe a\n"
                "                    // registration. The host's audit channel was told which it was.\n"
                "                    Err(ErrorResponse::new(ErrorCode::InvalidClient))\n"
                "                }\n"
                "            };\n"
                "        }\n"
                "\n"
                "        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this\n"
                "        // crate does not implement is decided by the host's verifier (see\n"
                "        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.\n",
            ),
            (
                "            jti,\n"
                "            scope: (!scope.is_empty()).then(|| scope.to_string()),\n"
                "        };\n",
                "            jti,\n"
                "            scope: (!scope.is_empty()).then(|| scope.to_string()),\n"
                "            // RFC 8705 s3.1: the same binding the AS-side record carries, in the form a\n"
                "            // resource server can check for itself without calling introspection at all.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            cnf: bound.cred.certificate.map(|c| crate::token::Confirmation {\n"
                '                #[cfg(feature = "dpop")]\n'
                "                jkt: None,\n"
                "                x5t_s256: Some(*c.thumbprint()),\n"
                "            }),\n"
                "        };\n",
            ),
            (
                "        now: SystemTime,\n        jti: String,\n    ) -> Result<String, ErrorResponse> {\n",
                "        now: SystemTime,\n"
                "        jti: String,\n"
                "        bound: &Bound<'_>,\n"
                "    ) -> Result<String, ErrorResponse> {\n"
                "        // Only the RFC 8705 binding is read out of it here; without that feature the\n"
                "        // signed claim set does not depend on how the client authenticated.\n"
                '        #[cfg(not(feature = "mtls"))]\n'
                "        let _ = bound;\n",
            ),
            (
                "            now,\n            access_token,\n        )?;\n",
                "            now,\n            access_token,\n            bound,\n        )?;\n",
            ),
            (
                '                #[cfg(feature = "dpop")]\n'
                "                jkt: bound.jkt.map(Box::from),\n"
                "                access_token: access_token.clone(),\n",
                '                #[cfg(feature = "dpop")]\n'
                "                jkt: bound.jkt.map(Box::from),\n"
                "                // RFC 8705 s3, and the same argument as `jkt` immediately above: an opaque\n"
                "                // token carries its binding nowhere else, so s3.2 introspection could not\n"
                "                // report it if it were not written down here.\n"
                '                #[cfg(feature = "mtls")]\n'
                "                x5t_s256: bound.cred.certificate.map(|c| Box::new(*c.thumbprint())),\n"
                "                access_token: access_token.clone(),\n",
            ),
            (
                '                    #[cfg(feature = "dpop")]\n'
                "                    jkt: bound.jkt.map(Box::from),\n"
                "                    refresh_token: rt.clone(),\n",
                '                    #[cfg(feature = "dpop")]\n'
                "                    jkt: bound.jkt.map(Box::from),\n"
                "                    // RFC 8705 s3: the chain remembers the certificate it was issued to, and\n"
                "                    // rotation checks it. See the check in `refresh_token`.\n"
                '                    #[cfg(feature = "mtls")]\n'
                "                    x5t_s256: bound.cred.certificate.map(|c| Box::new(*c.thumbprint())),\n"
                "                    refresh_token: rt.clone(),\n",
            ),
            (
                '        #[cfg(feature = "dpop")]\n'
                "        if record.jkt.as_deref() != bound.jkt {\n"
                "            self.store\n"
                "                .put_refresh_token(record)\n"
                "                .await\n"
                "                .map_err(storage_error)?;\n"
                "            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)\n"
                '                .with_description("this refresh token is bound to a different DPoP key"));\n'
                "        }\n",
                '        #[cfg(feature = "dpop")]\n'
                "        if record.jkt.as_deref() != bound.jkt {\n"
                "            self.store\n"
                "                .put_refresh_token(record)\n"
                "                .await\n"
                "                .map_err(storage_error)?;\n"
                "            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)\n"
                '                .with_description("this refresh token is bound to a different DPoP key"));\n'
                "        }\n"
                "\n"
                "        // RFC 8705 s3, and word for word the same argument as the DPoP check above: a chain\n"
                "        // issued over a client certificate stays bound to THAT certificate, and a rotation\n"
                "        // has to present it again. Without this the binding is decorative past the first\n"
                "        // access token, because a stolen refresh token could be re-bound to the thief's own\n"
                "        // certificate on the next rotation. Section 3 makes it a MUST for public clients\n"
                "        // specifically; applying it to every bound chain costs a confidential mutual-TLS\n"
                "        // client nothing, since it presents that certificate on every request anyway.\n"
                '        #[cfg(feature = "mtls")]\n'
                "        if record.x5t_s256.as_deref() != bound.cred.certificate.map(|c| c.thumbprint()) {\n"
                "            self.store\n"
                "                .put_refresh_token(record)\n"
                "                .await\n"
                "                .map_err(storage_error)?;\n"
                "            return Err(\n"
                "                ErrorResponse::new(ErrorCode::InvalidGrant).with_description(\n"
                '                    "this refresh token is bound to a different client certificate",\n'
                "                ),\n"
                "            );\n"
                "        }\n",
            ),
            (
                '                #[cfg(feature = "dpop")]\n'
                "                cnf: t.jkt.as_deref().map(crate::token::Confirmation::jkt),\n",
                "                // RFC 9449 s6.1 and RFC 8705 s3.2, in ONE RFC 7800 s3.1 object. Both\n"
                "                // mechanisms register a member of `cnf` and a token can carry both, so this\n"
                "                // is built from every binding the record has rather than from whichever one\n"
                "                // happens to be checked first. Omitted entirely when there is none.\n"
                '                #[cfg(any(feature = "dpop", feature = "mtls"))]\n'
                "                cnf: {\n"
                "                    let cnf = crate::token::Confirmation {\n"
                '                        #[cfg(feature = "dpop")]\n'
                "                        jkt: t.jkt.as_deref().map(str::to_string),\n"
                '                        #[cfg(feature = "mtls")]\n'
                "                        x5t_s256: t.x5t_s256.as_deref().copied(),\n"
                "                    };\n"
                "                    (!cnf.is_empty()).then_some(cnf)\n"
                "                },\n",
            ),
        ],
    )
)

EDITS.append(
    (
        "crates/oauth-as/src/http.rs",
        "mtls",
        [
            (
                "            client_secret: self.client_secret.as_deref(),\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion_type: self.client_assertion_type.as_deref(),\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion: self.client_assertion.as_deref(),\n"
                "        }\n",
                "            client_secret: self.client_secret.as_deref(),\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion_type: self.client_assertion_type.as_deref(),\n"
                '            #[cfg(feature = "client_assertion")]\n'
                "            client_assertion: self.client_assertion.as_deref(),\n"
                "            // ALWAYS `None`, and it has to be. This router is handed a parsed request; it\n"
                "            // does not terminate TLS and never sees the connection, so there is no\n"
                "            // certificate here that anybody verified. RFC 8705 clients reach the server\n"
                "            // through `ClientCredential::certificate` from a host that DID terminate the\n"
                "            // connection. Reading one out of a proxy header here would be the exact\n"
                "            // mistake `crate::mtls`'s trust boundary section warns about, and it would be\n"
                "            // made on every deployment's behalf rather than on the one host that knows\n"
                "            // whether its terminator can be trusted.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            certificate: None,\n"
                "        }\n",
            )
        ],
    )
)

# OPTIONAL: this file belongs to the 0.6.0 JAR slice, which may or may not have landed in the
# tree this patch is applied to. Its absence is not an error; its presence with a changed shape
# still is.
OPTIONAL_FILES = {"crates/oauth-as/tests/jar.rs"}

EDITS.append(
    (
        "crates/oauth-as/tests/jar.rs",
        "x5t_s256",
        [
            (
                '            jti: "jti".to_string(),\n'
                '            scope: Some("read".to_string()),\n'
                "        })\n",
                '            jti: "jti".to_string(),\n'
                '            scope: Some("read".to_string()),\n'
                "            // Not certificate bound: this fixture is testing that an access token is\n"
                "            // not a request object, and a binding would say nothing about that.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            cnf: None,\n"
                "        })\n",
            )
        ],
    )
)

EDITS.append(
    (
        "crates/oauth-as/src/jwt.rs",
        "pub cnf:",
        [
            (
                "    /// Space-delimited granted scope, omitted when empty (RFC 9068 section 2.2.3 makes it\n"
                "    /// conditional, not required).\n"
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub scope: Option<String>,\n"
                "}\n",
                "    /// Space-delimited granted scope, omitted when empty (RFC 9068 section 2.2.3 makes it\n"
                "    /// conditional, not required).\n"
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub scope: Option<String>,\n"
                "    /// RFC 7800 `cnf`, which RFC 9068 section 2.2.1 lists as a claim an access token MAY\n"
                "    /// carry: how this token is sender constrained. RFC 8705 section 3.1 puts the\n"
                "    /// certificate thumbprint here, and a resource server that validates the JWT itself can\n"
                "    /// then check the binding without calling introspection at all. Absent for an ordinary\n"
                "    /// bearer token, and absent from the claim set entirely in a build without the feature.\n"
                '    #[cfg(feature = "mtls")]\n'
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub cnf: Option<crate::token::Confirmation>,\n"
                "}\n",
            )
        ],
    )
)

# The struct literals. Rust requires every field to be named, so each of these has to learn the
# new one; each anchor carries the literal's opening line, which is what makes it unique.
def _literal(rel, sites):
    return (rel, "x5t_s256", [
        (
            opener + '        #[cfg(feature = "dpop")]\n' + indent + "jkt: None,\n",
            opener + '        #[cfg(feature = "dpop")]\n' + indent + "jkt: None,\n"
            + '        #[cfg(feature = "mtls")]\n' + indent + "x5t_s256: None,\n",
        )
        for opener, indent in sites
    ])

EDITS.append(
    (
        "crates/oauth-as/tests/jwt.rs",
        "x5t_s256",
        [
            (
                "        .put_refresh_token(RefreshTokenRecord {\n"
                '            #[cfg(feature = "dpop")]\n'
                "            jkt: None,\n",
                "        .put_refresh_token(RefreshTokenRecord {\n"
                '            #[cfg(feature = "dpop")]\n'
                "            jkt: None,\n"
                '            #[cfg(feature = "mtls")]\n'
                "            x5t_s256: None,\n",
            )
        ],
    )
)

# The DPoP suite reads `cnf.jkt` as a bare String. It is an `Option` now, for the reason the
# `Confirmation` edit above gives: the object holds a member per confirmation method and every one
# of them has to be absent-able, or a certificate-bound token in a build with both features would
# have to invent a DPoP key it does not have. The WIRE is unchanged for a dpop-only build.
EDITS.append(
    (
        "crates/oauth-as/tests/dpop.rs",
        "Some(key.to_public_jwk().thumbprint())",
        [
            (
                '        introspected.cnf.expect("a bound token reports cnf").jkt,\n'
                "        key.to_public_jwk().thumbprint(),\n",
                '        introspected.cnf.expect("a bound token reports cnf").jkt,\n'
                "        Some(key.to_public_jwk().thumbprint()),\n",
            ),
            (
                "        introspected.cnf.unwrap().jkt,\n"
                "        key.to_public_jwk().thumbprint()\n",
                "        introspected.cnf.unwrap().jkt,\n"
                "        Some(key.to_public_jwk().thumbprint())\n",
            ),
        ],
    )
)

EDITS.append(_literal("crates/oauth-as/tests/grant_state_edges.rs", [
    ("    let token = |name: &str, family: Option<&str>| IssuedToken {\n", "        "),
    ("    let refresh = |name: &str, family: &str| RefreshTokenRecord {\n", "        "),
]))
EDITS.append(_literal("crates/oauth-as/tests/storage_sweep.rs", [
    ("fn access_token(token: &str, expires_at: SystemTime) -> IssuedToken {\n    IssuedToken {\n", "        "),
    ("fn refresh_token(token: &str, expires_at: Option<SystemTime>) -> RefreshTokenRecord {\n    RefreshTokenRecord {\n", "        "),
]))
EDITS.append(_literal("crates/oauth-as/tests/storage_contract.rs", [
    ("fn sample_refresh_token(token: &str) -> RefreshTokenRecord {\n    RefreshTokenRecord {\n", "        "),
]))
EDITS.append(_literal("crates/oauth-as/src/tests/token.rs", [
    ("    let record = IssuedToken {\n", "        "),
    ("    let record = RefreshTokenRecord {\n", "        "),
]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=REPO_DEFAULT, help="repository root")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    # PHASE 1: read and check everything. Nothing is written until every edit in every file has
    # been proven applicable, so a half-applied tree is not a state this script can produce.
    planned = []
    for rel, marker, edits in EDITS:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            if rel in OPTIONAL_FILES:
                print(f"skipped {rel} (not present in this tree)")
                continue
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
        for anchor, replacement in edits:
            count = text.count(anchor)
            if count != 1:
                print(
                    f"FAIL: in {rel}, the anchor\n---\n{anchor}---\nwas found {count} times, "
                    f"expected exactly 1. The file has moved underneath this patch; fix the "
                    f"anchor by hand rather than guessing.",
                    file=sys.stderr,
                )
                return 1
            text = text.replace(anchor, replacement, 1)
        planned.append((path, rel, text))

    # PHASE 2: write.
    for path, rel, text in planned:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"patched {rel}")
    print("ok: 0.5.0 RFC 8705 host-file edits applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
