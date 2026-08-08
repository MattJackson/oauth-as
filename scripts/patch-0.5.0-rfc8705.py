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
                "pub mod metadata;\n",
                "/// RFC 8705 mutual-TLS client authentication and certificate-bound access tokens,\n"
                "/// behind the `mtls` cargo feature (off by default). READ THE MODULE DOCS FIRST: this\n"
                "/// crate cannot validate a certificate chain it did not negotiate, so the host's TLS\n"
                "/// layer is load bearing in a way no type here can enforce.\n"
                '#[cfg(feature = "mtls")]\n'
                "pub mod mtls;\n"
                "pub mod metadata;\n",
            ),
            (
                "pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};\n",
                "pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};\n"
                '#[cfg(feature = "mtls")]\n'
                "pub use mtls::{\n"
                "    CertificateThumbprint, ClientCertificate, ExpectedSubject, MtlsClientRegistration,\n"
                "    MtlsRegistrationError, RegisteredCertificates, SELF_SIGNED_TLS_CLIENT_AUTH,\n"
                "    TLS_CLIENT_AUTH, TLS_CLIENT_AUTH_SAN_DNS, TLS_CLIENT_AUTH_SAN_EMAIL,\n"
                "    TLS_CLIENT_AUTH_SAN_IP, TLS_CLIENT_AUTH_SAN_URI, TLS_CLIENT_AUTH_SUBJECT_DN,\n"
                "};\n",
            ),
            (
                "pub use token::{\n"
                "    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,\n"
                "    TokenType, TokenTypeHint,\n"
                "};\n",
                '#[cfg(feature = "mtls")]\n'
                "pub use token::Confirmation;\n"
                "pub use token::{\n"
                "    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,\n"
                "    TokenType, TokenTypeHint,\n"
                "};\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/client.rs",
        "ClientAuth::Mtls",
        [
            (
                "    ConfidentialSecretHash {\n"
                "        /// The stored verifier.\n"
                "        hash: SecretHash,\n"
                "    },\n"
                "}\n",
                "    ConfidentialSecretHash {\n"
                "        /// The stored verifier.\n"
                "        hash: SecretHash,\n"
                "    },\n"
                "    /// RFC 8705: a confidential client that authenticates with a mutual-TLS CERTIFICATE and\n"
                "    /// holds no shared secret at all. This is the variant a deployment whose policy forbids\n"
                "    /// shared secrets registers, and the only one where the credential never travels: the\n"
                "    /// client proves possession of a private key to the host's TLS layer, and this crate is\n"
                "    /// handed the resulting certificate as an established fact.\n"
                "    ///\n"
                "    /// Carried INLINE rather than boxed, which is measured rather than assumed: the widest\n"
                "    /// shape [`crate::mtls::MtlsClientRegistration`] can take is one `String` plus a\n"
                "    /// discriminant, against `ConfidentialSecretHash`'s two `String`s, so this variant does\n"
                "    /// not make `ClientAuth` (or the [`Client`] cloned on every token request) any bigger.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    Mtls {\n"
                "        /// Which RFC 8705 method, and what it expects to see.\n"
                "        registration: crate::mtls::MtlsClientRegistration,\n"
                "    },\n"
                "}\n",
            ),
            (
                "            ClientAuth::ConfidentialSecretHash { hash } => f\n"
                '                .debug_struct("ConfidentialSecretHash")\n'
                '                .field("hash", hash)\n'
                "                .finish(),\n"
                "        }\n",
                "            ClientAuth::ConfidentialSecretHash { hash } => f\n"
                '                .debug_struct("ConfidentialSecretHash")\n'
                '                .field("hash", hash)\n'
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
                "            ClientAuth::ConfidentialSecretHash { hash } => match presented {\n"
                "                Some(p) => hash.verify(p, verifier),\n"
                "                None => false,\n"
                "            },\n"
                "        }\n",
                "            ClientAuth::ConfidentialSecretHash { hash } => match presented {\n"
                "                Some(p) => hash.verify(p, verifier),\n"
                "                None => false,\n"
                "            },\n"
                "            // NEVER, and not because the check lives elsewhere. A mutual-TLS registration has\n"
                "            // no secret to compare against, so there is no presented string that could be the\n"
                "            // right one, and `None` is not the right one either (unlike `Public`, this client\n"
                "            // is confidential and something must be proven). The certificate is checked by\n"
                "            // `crate::mtls::verify_client_credentials`, which is reached only from\n"
                "            // `AuthorizationServer::authenticate_client`; every OTHER caller of this function,\n"
                "            // now or later, therefore fails closed on a mutual-TLS client rather than\n"
                "            // accidentally authenticating one with no evidence at all.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            ClientAuth::Mtls { .. } => false,\n"
                "        }\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/token.rs",
        "pub struct Confirmation",
        [
            (
                "/// The RFC 7009 section 2.1 `token_type_hint`.",
                "/// The RFC 7800 `cnf` (confirmation) claim: how a token is SENDER CONSTRAINED, meaning what\n"
                "/// a presenter has to prove in addition to holding the string.\n"
                "///\n"
                "/// A struct with one optional member per confirmation method, rather than a bare thumbprint,\n"
                "/// and that shape is the point. RFC 7800 section 3.1 defines `cnf` as a JSON OBJECT whose\n"
                "/// members are confirmation methods, and different sender-constraining mechanisms register\n"
                "/// different members in the same object: RFC 8705 section 3.1 registers `x5t#S256` for a\n"
                "/// certificate binding, and RFC 9449 section 6.1 registers `jkt` for a DPoP key binding. A\n"
                "/// token can legitimately carry both, so neither may be modelled as \"the\" confirmation.\n"
                "/// Adding a method means adding an optional member here; it never means replacing this type.\n"
                "///\n"
                "/// Omitted entirely from a serialized token or introspection response when it is empty (see\n"
                "/// [`Confirmation::is_empty`]): an empty `cnf` object would claim a constraint exists and\n"
                "/// then name none, which is worse than silence.\n"
                '#[cfg(feature = "mtls")]\n'
                "#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]\n"
                "pub struct Confirmation {\n"
                "    /// RFC 8705 section 3.1 `x5t#S256`: the SHA-256 thumbprint of the DER encoding of the\n"
                "    /// X.509 certificate the client presented when the token was issued. A resource server\n"
                "    /// checks it with [`Confirmation::confirms_certificate`].\n"
                '    #[cfg(feature = "mtls")]\n'
                '    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]\n'
                "    pub x5t_s256: Option<crate::mtls::CertificateThumbprint>,\n"
                "}\n"
                "\n"
                '#[cfg(feature = "mtls")]\n'
                "impl Confirmation {\n"
                "    /// Whether this carries no confirmation method at all, which is what an ordinary bearer\n"
                "    /// token has.\n"
                "    pub fn is_empty(&self) -> bool {\n"
                "        self.x5t_s256.is_none()\n"
                "    }\n"
                "}\n"
                "\n"
                "/// The RFC 7009 section 2.1 `token_type_hint`.",
            ),
            (
                "    /// The resource server(s) the token is for: the RFC 8707 resource indicators the grant was\n"
                "    /// narrowed to.\n",
                "    /// RFC 8705 section 3.2: the confirmation method this token is bound to, so a resource\n"
                "    /// server that introspects can check the binding rather than being told it exists.\n"
                "    /// Absent for an ordinary bearer token.\n"
                '    #[cfg(feature = "mtls")]\n'
                '    #[serde(default, skip_serializing_if = "Option::is_none")]\n'
                "    pub cnf: Option<Confirmation>,\n"
                "    /// The resource server(s) the token is for: the RFC 8707 resource indicators the grant was\n"
                "    /// narrowed to.\n",
            ),
            (
                "            iss: None,\n            aud: None,\n        }\n",
                "            iss: None,\n"
                "            aud: None,\n"
                "            // An inactive answer describes nothing, including how the token was constrained.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            cnf: None,\n"
                "        }\n",
            ),
            (
                "    /// The RFC 8707 resource indicators this token is restricted to; empty when the grant named\n"
                "    /// none.",
                "    /// RFC 8705 section 3: the confirmation this token is BOUND to, `None` for an ordinary\n"
                "    /// bearer token. Recorded on the AS-side record, not only in a signed JWT, because this\n"
                "    /// crate's default access token is opaque: RFC 8705 section 3.2 has a resource server\n"
                "    /// learn the binding by INTROSPECTING, and it can only be reported if it was persisted.\n"
                "    ///\n"
                "    /// BOXED, for the same reason [`crate::client::Client::registration`] is. This record is\n"
                "    /// cloned out of the host's store on every introspection and written on every issuance,\n"
                "    /// and `tests/allocation.rs` holds it to a size budget; one null pointer costs 8 bytes for\n"
                "    /// the deployments that issue plain bearer tokens, and the confirmation itself is\n"
                "    /// allocated only for a token that actually has one. It also means the DPoP `jkt` member\n"
                "    /// can join [`Confirmation`] later without growing this record again.\n"
                '    #[cfg(feature = "mtls")]\n'
                '    #[serde(default, skip_serializing_if = "Option::is_none")]\n'
                "    pub cnf: Option<Box<Confirmation>>,\n"
                "    /// The RFC 8707 resource indicators this token is restricted to; empty when the grant named\n"
                "    /// none.",
            ),
            (
                '            .field("resource", &self.resource)\n'
                '            .field("issued_at", &self.issued_at)\n',
                '            .field("resource", &self.resource)\n'
                "            // Not a credential: a thumbprint is a hash of a public document, and it is\n"
                "            // exactly what an operator needs when a bound token is being refused.\n"
                '            #[cfg(feature = "mtls")]\n'
                '            .field("cnf", &self.cnf)\n'
                '            .field("issued_at", &self.issued_at)\n',
            ),
        ],
    ),
    (
        "crates/oauth-as/src/events.rs",
        "NoCertificatePresented",
        [
            (
                "    /// The host's own [`RateLimiter`] refused the attempt before it was evaluated.\n"
                "    RateLimited,\n"
                "}\n",
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
                "    CertificateMismatch,\n"
                "}\n",
            )
        ],
    ),
    (
        "crates/oauth-as/src/metadata.rs",
        "tls_client_certificate_bound_access_tokens",
        [
            (
                "    /// RFC 8707 (resource indicators), which this server also implements, registers NO metadata\n"
                "    /// member of its own, so there is deliberately nothing here to advertise it.\n"
                "    pub authorization_response_iss_parameter_supported: bool,\n"
                "}\n",
                "    /// RFC 8707 (resource indicators), which this server also implements, registers NO metadata\n"
                "    /// member of its own, so there is deliberately nothing here to advertise it.\n"
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
                "        let endpoint = |override_: &Option<String>, path: &str| {\n"
                "            override_\n"
                "                .clone()\n"
                "                .unwrap_or_else(|| under_issuer(&iss, path))\n"
                "        };\n",
                "        let endpoint = |override_: &Option<String>, path: &str| {\n"
                "            override_\n"
                "                .clone()\n"
                "                .unwrap_or_else(|| under_issuer(&iss, path))\n"
                "        };\n"
                "        // Exactly the client authentication methods the token endpoint accepts. `mut` only\n"
                "        // when the optional mutual-TLS methods are compiled in, which is what the allow below\n"
                "        // is for: advertising a method this build cannot honor is the lie this document\n"
                "        // exists to avoid, and so is staying silent about one it does honor (a client that\n"
                "        // cannot discover `tls_client_auth` has no way to know not to send a secret).\n"
                "        #[allow(unused_mut)]\n"
                "        let mut token_endpoint_auth_methods_supported = vec![\n"
                '            "client_secret_basic".to_string(),\n'
                '            "client_secret_post".to_string(),\n'
                "            // RFC 8414 s2: the registered value a public client uses. This server accepts\n"
                "            // public clients, so omitting it would understate what it does.\n"
                '            "none".to_string(),\n'
                "        ];\n"
                "        // RFC 8705 s2.1.1 and s2.2.1 register these two values; RFC 8414 s2 is what makes\n"
                "        // advertising them the way a client learns mutual TLS is available without probing.\n"
                '        #[cfg(feature = "mtls")]\n'
                "        token_endpoint_auth_methods_supported.extend([\n"
                "            crate::mtls::TLS_CLIENT_AUTH.to_string(),\n"
                "            crate::mtls::SELF_SIGNED_TLS_CLIENT_AUTH.to_string(),\n"
                "        ]);\n",
            ),
            (
                "            token_endpoint_auth_methods_supported: vec![\n"
                '                "client_secret_basic".to_string(),\n'
                '                "client_secret_post".to_string(),\n'
                "                // RFC 8414 s2: the registered value a public client uses. This server accepts\n"
                "                // public clients, so omitting it would understate what it does.\n"
                '                "none".to_string(),\n'
                "            ],\n",
                "            token_endpoint_auth_methods_supported,\n",
            ),
            (
                "            authorization_response_iss_parameter_supported: true,\n",
                "            authorization_response_iss_parameter_supported: true,\n"
                '            #[cfg(feature = "mtls")]\n'
                "            tls_client_certificate_bound_access_tokens: true,\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/server.rs",
        "PresentedCertificate",
        [
            # ---------------------------------------------------------------- the threaded type
            (
                "/// The refresh chain an issuance CONTINUES:",
                "/// The client certificate a request presented, threaded from the endpoints that authenticate\n"
                "/// a client down to [`AuthorizationServer::issue`], which is where RFC 8705 section 3 records\n"
                "/// the binding.\n"
                "///\n"
                "/// Two spellings, so the plumbing is written once rather than once per feature set. With\n"
                "/// `mtls` on it is one pointer; with the feature OFF it is a zero-sized `PhantomData`, so\n"
                "/// every parameter it is passed in costs nothing at all: not a byte on the stack and not a\n"
                "/// byte in the token future, which sits inside tokio's 2048-byte boxing threshold and which\n"
                "/// `tests/allocation.rs` exists to keep there. Threading an `Option<&_>` that is always `None`\n"
                "/// would have read more simply and made every default build pay for a feature it did not\n"
                "/// enable.\n"
                '#[cfg(feature = "mtls")]\n'
                "pub(crate) type PresentedCertificate<'a> = Option<&'a crate::mtls::ClientCertificate<'a>>;\n"
                '#[cfg(not(feature = "mtls"))]\n'
                "pub(crate) type PresentedCertificate<'a> = std::marker::PhantomData<&'a ()>;\n"
                "\n"
                "/// \"No certificate was presented\", in whichever of the two spellings this build uses.\n"
                '#[cfg(feature = "mtls")]\n'
                "pub(crate) fn no_certificate<'a>() -> PresentedCertificate<'a> {\n"
                "    None\n"
                "}\n"
                "\n"
                '#[cfg(not(feature = "mtls"))]\n'
                "pub(crate) fn no_certificate<'a>() -> PresentedCertificate<'a> {\n"
                "    std::marker::PhantomData\n"
                "}\n"
                "\n"
                "/// The refresh chain an issuance CONTINUES:",
            ),
            # ------------------------------------------------------------- authenticate_client
            (
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "    ) -> Result<Client, ErrorResponse> {\n",
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<Client, ErrorResponse> {\n",
            ),
            (
                "        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this\n"
                "        // crate does not implement is decided by the host's verifier (see\n"
                "        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.\n"
                "        if !client\n"
                "            .auth\n"
                "            .verify_with(client_secret, self.hooks.secret_verifier())\n"
                "        {\n"
                "            self.hooks.record(attempt, AttemptOutcome::Failed);\n"
                "            self.hooks.emit(|| Event::ClientAuthenticationFailed {\n"
                "                client_id: client_id.as_str(),\n"
                "                failure: ClientAuthFailure::SecretMismatch,\n"
                "            });\n"
                "            return Err(ErrorResponse::new(ErrorCode::InvalidClient));\n"
                "        }\n",
                "        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this\n"
                "        // crate does not implement is decided by the host's verifier (see\n"
                "        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.\n"
                "        //\n"
                "        // RFC 8705 s2 adds a SECOND family of credential, and `crate::mtls` is the one place\n"
                "        // the two meet: a mutual-TLS registration is decided by the certificate and never by a\n"
                "        // secret, every other registration is decided exactly as it was before, and neither\n"
                "        // family can be authenticated with the other's evidence. Without the feature there is\n"
                "        // no certificate to consider and this is the call it always was.\n"
                '        #[cfg(feature = "mtls")]\n'
                "        let verified = crate::mtls::verify_client_credentials(\n"
                "            &client,\n"
                "            client_secret,\n"
                "            certificate,\n"
                "            self.hooks.secret_verifier(),\n"
                "        );\n"
                '        #[cfg(not(feature = "mtls"))]\n'
                "        let verified = {\n"
                "            let _ = certificate;\n"
                "            if client\n"
                "                .auth\n"
                "                .verify_with(client_secret, self.hooks.secret_verifier())\n"
                "            {\n"
                "                Ok(())\n"
                "            } else {\n"
                "                Err(ClientAuthFailure::SecretMismatch)\n"
                "            }\n"
                "        };\n"
                "        if let Err(failure) = verified {\n"
                "            self.hooks.record(attempt, AttemptOutcome::Failed);\n"
                "            self.hooks.emit(|| Event::ClientAuthenticationFailed {\n"
                "                client_id: client_id.as_str(),\n"
                "                failure,\n"
                "            });\n"
                "            return Err(ErrorResponse::new(ErrorCode::InvalidClient));\n"
                "        }\n",
            ),
            # ------------------------------------------------------------- device_authorization
            (
                "    /// RFC 8628 section 3.1/3.2: start a device authorization.\n"
                "    pub async fn device_authorization(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        requested_scope: Option<&ScopeSet>,\n"
                "    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n"
                "        if !client.allows_grant(GrantType::DeviceCode) {\n",
                "    /// RFC 8628 section 3.1/3.2: start a device authorization.\n"
                "    pub async fn device_authorization(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        requested_scope: Option<&ScopeSet>,\n"
                "    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {\n"
                "        self.device_authorization_inner(\n"
                "            client_id,\n"
                "            client_secret,\n"
                "            requested_scope,\n"
                "            no_certificate(),\n"
                "        )\n"
                "        .await\n"
                "    }\n"
                "\n"
                "    /// RFC 8628 section 3.1/3.2 for a client that authenticates with RFC 8705 mutual TLS.\n"
                "    ///\n"
                "    /// `certificate` is the certificate the HOST has already verified; read\n"
                "    /// [`crate::mtls`]'s trust boundary section before wiring it up.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub async fn device_authorization_with_certificate(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        requested_scope: Option<&ScopeSet>,\n"
                "        certificate: Option<&crate::mtls::ClientCertificate<'_>>,\n"
                "    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {\n"
                "        self.device_authorization_inner(client_id, client_secret, requested_scope, certificate)\n"
                "            .await\n"
                "    }\n"
                "\n"
                "    async fn device_authorization_inner(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        requested_scope: Option<&ScopeSet>,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n"
                "        if !client.allows_grant(GrantType::DeviceCode) {\n",
            ),
            # -------------------------------------------------------------------- token endpoint
            (
                "    pub async fn token_with_resources(\n"
                "        &self,\n"
                "        request: TokenRequest,\n"
                "        resources: &[String],\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let requested_resources = Self::validate_resources(resources.iter().map(|r| r.as_str()))?;\n",
                "    pub async fn token_with_resources(\n"
                "        &self,\n"
                "        request: TokenRequest,\n"
                "        resources: &[String],\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        self.token_inner(request, resources, no_certificate()).await\n"
                "    }\n"
                "\n"
                "    /// The token endpoint for a request that arrived over a mutual-TLS connection (RFC 8705).\n"
                "    ///\n"
                "    /// `certificate` is the client certificate the HOST verified during the TLS handshake, and\n"
                "    /// it does two separate jobs, either of which can apply on its own:\n"
                "    ///\n"
                "    /// - section 2, AUTHENTICATION: a client registered with [`crate::client::ClientAuth::Mtls`]\n"
                "    ///   is authenticated by this certificate and by nothing else. Such a client cannot\n"
                "    ///   authenticate through [`AuthorizationServer::token`] at all, which is the point: a\n"
                "    ///   host that forgets to pass the certificate gets `invalid_client`, never a token.\n"
                "    /// - section 3, BINDING: the issued access token is bound to this certificate whatever the\n"
                "    ///   client's authentication method was, including a public client (section 4). Binding is\n"
                "    ///   not conditional on a per-client flag, because a bound token is never less safe than\n"
                "    ///   the unbound one it replaces, and a client that does not want binding does not present\n"
                "    ///   a certificate.\n"
                "    ///\n"
                "    /// READ [`crate::mtls`]'s trust boundary section first. This crate cannot validate a\n"
                "    /// certificate chain it did not negotiate.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub async fn token_with_certificate(\n"
                "        &self,\n"
                "        request: TokenRequest,\n"
                "        resources: &[String],\n"
                "        certificate: Option<&crate::mtls::ClientCertificate<'_>>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        self.token_inner(request, resources, certificate).await\n"
                "    }\n"
                "\n"
                "    async fn token_inner(\n"
                "        &self,\n"
                "        request: TokenRequest,\n"
                "        resources: &[String],\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let requested_resources = Self::validate_resources(resources.iter().map(|r| r.as_str()))?;\n",
            ),
            (
                "                        redirect_uri.as_deref(),\n"
                "                        code_verifier.as_deref(),\n"
                "                        &requested_resources,\n"
                "                    )\n",
                "                        redirect_uri.as_deref(),\n"
                "                        code_verifier.as_deref(),\n"
                "                        &requested_resources,\n"
                "                        certificate,\n"
                "                    )\n",
            ),
            (
                "                        client_secret.as_deref(),\n"
                "                        scope.as_ref(),\n"
                "                        requested_resources,\n"
                "                    )\n",
                "                        client_secret.as_deref(),\n"
                "                        scope.as_ref(),\n"
                "                        requested_resources,\n"
                "                        certificate,\n"
                "                    )\n",
            ),
            (
                "                    .device_token(&client_id, client_secret.as_deref(), &device_code)\n",
                "                    .device_token(\n"
                "                        &client_id,\n"
                "                        client_secret.as_deref(),\n"
                "                        &device_code,\n"
                "                        certificate,\n"
                "                    )\n",
            ),
            (
                "                        &refresh_token,\n"
                "                        scope.as_ref(),\n"
                "                        &requested_resources,\n"
                "                    )\n",
                "                        &refresh_token,\n"
                "                        scope.as_ref(),\n"
                "                        &requested_resources,\n"
                "                        certificate,\n"
                "                    )\n",
            ),
            # --------------------------------------------------------- authorization_code_token
            (
                "        code_verifier: Option<&str>,\n"
                "        requested_resources: &[String],\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n"
                "        if !client.allows_grant(GrantType::AuthorizationCode) {\n",
                "        code_verifier: Option<&str>,\n"
                "        requested_resources: &[String],\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n"
                "        if !client.allows_grant(GrantType::AuthorizationCode) {\n",
            ),
            (
                "                record.scope.clone(),\n"
                "                resource,\n"
                "                None,\n"
                "                true,\n"
                "            )\n",
                "                record.scope.clone(),\n"
                "                resource,\n"
                "                None,\n"
                "                true,\n"
                "                certificate,\n"
                "            )\n",
            ),
            # ---------------------------------------------------------- client_credentials_token
            (
                "        requested_scope: Option<&ScopeSet>,\n"
                "        resource: Vec<String>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n",
                "        requested_scope: Option<&ScopeSet>,\n"
                "        resource: Vec<String>,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n",
            ),
            (
                "            GrantType::ClientCredentials,\n"
                "            None,\n"
                "            scope,\n"
                "            resource,\n"
                "            None,\n"
                "            false,\n"
                "        )\n",
                "            GrantType::ClientCredentials,\n"
                "            None,\n"
                "            scope,\n"
                "            resource,\n"
                "            None,\n"
                "            false,\n"
                "            certificate,\n"
                "        )\n",
            ),
            # ------------------------------------------------------------------------ device_token
            (
                "        client_secret: Option<&str>,\n"
                "        device_code: &str,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n",
                "        client_secret: Option<&str>,\n"
                "        device_code: &str,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n",
            ),
            (
                "                    Some(subject),\n"
                "                    taken.scope,\n"
                "                    Vec::new(),\n"
                "                    None,\n"
                "                    true,\n"
                "                )\n",
                "                    Some(subject),\n"
                "                    taken.scope,\n"
                "                    Vec::new(),\n"
                "                    None,\n"
                "                    true,\n"
                "                    certificate,\n"
                "                )\n",
            ),
            # ----------------------------------------------------------------------- refresh_token
            (
                "        requested_scope: Option<&ScopeSet>,\n"
                "        requested_resources: &[String],\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n",
                "        requested_scope: Option<&ScopeSet>,\n"
                "        requested_resources: &[String],\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n",
            ),
            (
                "                Some(RefreshChain {\n"
                "                    family_id: record.family_id.clone(),\n"
                "                    expires_at: record.expires_at,\n"
                "                }),\n"
                "                true,\n"
                "            )\n",
                "                Some(RefreshChain {\n"
                "                    family_id: record.family_id.clone(),\n"
                "                    expires_at: record.expires_at,\n"
                "                }),\n"
                "                true,\n"
                "                certificate,\n"
                "            )\n",
            ),
            # ------------------------------------------------------------------------------ issue
            (
                "        chain: Option<RefreshChain>,\n"
                "        allow_refresh: bool,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let now = self.clock.now();\n",
                "        chain: Option<RefreshChain>,\n"
                "        allow_refresh: bool,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<TokenResponse, ErrorResponse> {\n"
                "        let now = self.clock.now();\n"
                "\n"
                "        // RFC 8705 s3: an access token issued over a mutual-TLS connection is BOUND to the\n"
                "        // certificate that connection used, so a stolen copy of the string is worth nothing to\n"
                "        // anyone who cannot also complete a handshake with that client's private key. Recorded\n"
                "        // on the AS-side record and not only in a signed JWT, because this crate's default\n"
                "        // token is opaque and s3.2 has a resource server learn the binding by introspecting.\n"
                "        // BOXED for the reason `IssuedToken::cnf` states.\n"
                '        #[cfg(feature = "mtls")]\n'
                "        let cnf = certificate\n"
                "            .map(|c| Box::new(crate::token::Confirmation::for_certificate(c)));\n",
            ),
            (
                "        #[cfg(feature = \"jwt\")]\n"
                "        let access_token = self.wire_access_token(\n"
                "            client,\n"
                "            subject.as_deref(),\n"
                "            &scope,\n"
                "            &resource,\n"
                "            now,\n"
                "            access_token,\n"
                "        )?;\n"
                "        self.store\n"
                "            .put_token(IssuedToken {\n"
                "                access_token: access_token.clone(),\n",
                "        #[cfg(feature = \"jwt\")]\n"
                "        let access_token = self.wire_access_token(\n"
                "            client,\n"
                "            subject.as_deref(),\n"
                "            &scope,\n"
                "            &resource,\n"
                "            now,\n"
                "            access_token,\n"
                "            certificate,\n"
                "        )?;\n"
                "        self.store\n"
                "            .put_token(IssuedToken {\n"
                '                #[cfg(feature = "mtls")]\n'
                "                cnf,\n"
                "                access_token: access_token.clone(),\n",
            ),
            # ------------------------------------------------------------------ wire_access_token
            (
                "        now: SystemTime,\n"
                "        jti: String,\n"
                "    ) -> Result<String, ErrorResponse> {\n",
                "        now: SystemTime,\n"
                "        jti: String,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<String, ErrorResponse> {\n",
            ),
            (
                "            jti,\n"
                "            scope: (!scope.is_empty()).then(|| scope.to_string()),\n"
                "        };\n",
                "            jti,\n"
                "            scope: (!scope.is_empty()).then(|| scope.to_string()),\n"
                "            // RFC 8705 s3.1: the same binding the AS-side record carries, in the form a\n"
                "            // resource server can check without calling introspection at all.\n"
                '            #[cfg(feature = "mtls")]\n'
                "            cnf: certificate.map(crate::token::Confirmation::for_certificate),\n"
                "        };\n",
            ),
            # ------------------------------------------------------------- introspection_response
            (
                "    pub async fn introspection_response(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "    ) -> Result<IntrospectionResponse, ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n",
                "    pub async fn introspection_response(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "    ) -> Result<IntrospectionResponse, ErrorResponse> {\n"
                "        self.introspection_response_inner(client_id, client_secret, token, no_certificate())\n"
                "            .await\n"
                "    }\n"
                "\n"
                "    /// RFC 7662 introspection for a caller that authenticates with RFC 8705 mutual TLS.\n"
                "    ///\n"
                "    /// The RESPONSE reports the RFC 8705 section 3.2 `cnf` binding either way; this entry\n"
                "    /// point exists so that a deployment whose policy forbids shared secrets can also\n"
                "    /// introspect, rather than being able to obtain tokens and not to ask about them.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub async fn introspection_response_with_certificate(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "        certificate: Option<&crate::mtls::ClientCertificate<'_>>,\n"
                "    ) -> Result<IntrospectionResponse, ErrorResponse> {\n"
                "        self.introspection_response_inner(client_id, client_secret, token, certificate)\n"
                "            .await\n"
                "    }\n"
                "\n"
                "    async fn introspection_response_inner(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<IntrospectionResponse, ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n",
            ),
            (
                "                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),\n",
                "                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),\n"
                "                // RFC 8705 s3.2. This is the whole point of persisting the binding rather\n"
                "                // than only signing it into a JWT: a resource server holding an OPAQUE token\n"
                "                // has no other way to discover that the token is certificate bound, and a\n"
                "                // binding nobody can read is a binding nobody enforces.\n"
                '                #[cfg(feature = "mtls")]\n'
                "                cnf: t.cnf.as_deref().cloned(),\n",
            ),
            # ------------------------------------------------------------------------------ revoke
            (
                "    pub async fn revoke(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "        token_type_hint: Option<TokenTypeHint>,\n"
                "    ) -> Result<(), ErrorResponse> {\n"
                "        let client = self.authenticate_client(client_id, client_secret).await?;\n",
                "    pub async fn revoke(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "        token_type_hint: Option<TokenTypeHint>,\n"
                "    ) -> Result<(), ErrorResponse> {\n"
                "        self.revoke_inner(\n"
                "            client_id,\n"
                "            client_secret,\n"
                "            token,\n"
                "            token_type_hint,\n"
                "            no_certificate(),\n"
                "        )\n"
                "        .await\n"
                "    }\n"
                "\n"
                "    /// RFC 7009 revocation for a client that authenticates with RFC 8705 mutual TLS.\n"
                "    ///\n"
                "    /// Present for the same reason the introspection sibling is: a client that can obtain a\n"
                "    /// token and cannot revoke it has no answer to its own compromise.\n"
                '    #[cfg(feature = "mtls")]\n'
                "    pub async fn revoke_with_certificate(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "        token_type_hint: Option<TokenTypeHint>,\n"
                "        certificate: Option<&crate::mtls::ClientCertificate<'_>>,\n"
                "    ) -> Result<(), ErrorResponse> {\n"
                "        self.revoke_inner(client_id, client_secret, token, token_type_hint, certificate)\n"
                "            .await\n"
                "    }\n"
                "\n"
                "    async fn revoke_inner(\n"
                "        &self,\n"
                "        client_id: &ClientId,\n"
                "        client_secret: Option<&str>,\n"
                "        token: &str,\n"
                "        token_type_hint: Option<TokenTypeHint>,\n"
                "        certificate: PresentedCertificate<'_>,\n"
                "    ) -> Result<(), ErrorResponse> {\n"
                "        let client = self\n"
                "            .authenticate_client(client_id, client_secret, certificate)\n"
                "            .await?;\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/token_exchange.rs",
        "no_certificate",
        [
            # RFC 8693 goes through the same `authenticate_client` and the same `issue` as every
            # other grant (that reuse is the whole point of the 0.7.0 patch), so it has to name the
            # new parameter. It passes "no certificate" in both places, deliberately: exchanging a
            # token is not a mutual-TLS flow in this crate yet, and a grant that silently accepted a
            # certificate for authentication without anybody having designed that path would be a
            # worse answer than a grant that plainly does not offer it.
            (
                "    let client = server\n"
                "        .authenticate_client(request.client_id, request.client_secret)\n"
                "        .await?;\n",
                "    let client = server\n"
                "        .authenticate_client(\n"
                "            request.client_id,\n"
                "            request.client_secret,\n"
                "            crate::server::no_certificate(),\n"
                "        )\n"
                "        .await?;\n",
            ),
            (
                "            scope,\n"
                "            resource,\n"
                "            None,\n"
                "            false,\n"
                "        )\n"
                "        .await?;\n",
                "            scope,\n"
                "            resource,\n"
                "            None,\n"
                "            false,\n"
                "            crate::server::no_certificate(),\n"
                "        )\n"
                "        .await?;\n",
            ),
        ],
    ),
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
    ),
    (
        "crates/oauth-as/src/tests/token.rs",
        "cnf:",
        [
            (
                "    let record = IssuedToken {\n"
                '        access_token: "at-secret-value".into(),\n',
                "    let record = IssuedToken {\n"
                '        #[cfg(feature = "mtls")]\n'
                "        cnf: None,\n"
                '        access_token: "at-secret-value".into(),\n',
            )
        ],
    ),
    (
        "crates/oauth-as/tests/grant_state_edges.rs",
        "cnf:",
        [
            (
                "    let token = |name: &str, family: Option<&str>| IssuedToken {\n"
                "        resource: Vec::new(),\n",
                "    let token = |name: &str, family: Option<&str>| IssuedToken {\n"
                '        #[cfg(feature = "mtls")]\n'
                "        cnf: None,\n"
                "        resource: Vec::new(),\n",
            )
        ],
    ),
    (
        "crates/oauth-as/tests/storage_sweep.rs",
        "cnf:",
        [
            (
                "    IssuedToken {\n        resource: Vec::new(),\n",
                "    IssuedToken {\n"
                '        #[cfg(feature = "mtls")]\n'
                "        cnf: None,\n"
                "        resource: Vec::new(),\n",
            )
        ],
    ),
]


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
