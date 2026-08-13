// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8705 mutual-TLS client authentication (`tls_client_auth`, `self_signed_tls_client_auth`)
//! and certificate-bound access tokens. Compiled ONLY under the off-by-default `mtls` cargo
//! feature; with the feature off this module does not exist, no type here appears in the public
//! API, and the crate's dependency set and runtime cost are unchanged.
//!
//! # THE TRUST BOUNDARY. Read this before wiring anything up.
//!
//! **This library never sees a socket, so it cannot validate a certificate chain it did not
//! negotiate.** TLS termination is the HOST's job in this design (see the crate docs), which means
//! the host, and only the host, is the party that can know whether the certificate on the
//! connection was actually presented, actually matched a private key the client proved possession
//! of during the handshake, and actually chained to a trust anchor the deployment accepts.
//!
//! Everything in this module runs AFTER that. A [`ClientCertificate`] handed to this crate is
//! taken as an established fact, exactly the way a `client_secret` read out of a request body is
//! taken as a presented string. **A host that constructs a [`ClientCertificate`] from an
//! unverified source has authenticated nobody**, and the comparisons below then compare attacker
//! chosen values against registered ones, which is a check that passes whenever the attacker wants
//! it to. Two ways to get that wrong, both of which have shipped in real deployments:
//!
//! - Reading a certificate out of a request HEADER (`X-Client-Cert`, `X-SSL-Client-S-DN`, and
//!   friends) without stripping that header on the way in. If a client can set the header, the
//!   client can set its own subject DN. The header is only trustworthy when the TLS terminator
//!   overwrites it unconditionally on every request AND the terminator is the only route to the
//!   application.
//! - Configuring the terminator to REQUEST a client certificate but not to REQUIRE and verify one.
//!   An unverified certificate is a public document; anybody can replay somebody else's.
//!
//! RFC 8705 section 2 is explicit that the authorization server validates the certificate chain
//! for the PKI method. In this crate that sentence is addressed to the host, and this module can
//! neither perform nor check that validation. It is stated here, rather than only in a changelog,
//! because it is the one thing an integrator can get wrong in a way that produces a working
//! deployment which authenticates nothing.
//!
//! # Why this module does not parse X.509
//!
//! It does not need to, and the crate's dependency policy (see `Cargo.toml`) does not admit an
//! ASN.1 parser for a job the host has already done. The host terminated the TLS connection, so it
//! already holds the parsed certificate: every TLS stack exposes the subject and the subjectAltName
//! entries, and every reverse proxy exposes them as strings. This module therefore takes the FACTS
//! (a subject DN, the SAN entries, the DER bytes) and derives the one value RFC 8705 section 3.1
//! actually defines arithmetic on: the SHA-256 thumbprint, which is `sha2` over bytes and
//! `base64`, both of which this crate already depends on for RFC 7636. Adding an X.509 parser
//! would add attack surface (a parser fed attacker-controlled DER) to buy a result the host must
//! compute anyway to have completed the handshake at all.

use std::fmt;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::client::{Client, ClientAuth};
use crate::events::ClientAuthFailure;
use crate::server::ClientCredential;
use crate::token::Confirmation;

/// The RFC 8705 section 2.1.1 `token_endpoint_auth_method` value for the PKI method: the client is
/// identified by a certificate issued by a CA the deployment trusts, matched against ONE registered
/// expected subject value.
pub const TLS_CLIENT_AUTH: &str = "tls_client_auth";

/// The RFC 8705 section 2.2.1 `token_endpoint_auth_method` value for the self-signed method: the
/// client is identified by a certificate it registered itself, matched by thumbprint.
pub const SELF_SIGNED_TLS_CLIENT_AUTH: &str = "self_signed_tls_client_auth";

/// RFC 8705 section 2.1.1 client metadata: the expected subject distinguished name, in the RFC 4514
/// string representation.
pub const TLS_CLIENT_AUTH_SUBJECT_DN: &str = "tls_client_auth_subject_dn";
/// RFC 8705 section 2.1.1 client metadata: the expected `dNSName` subjectAltName entry.
pub const TLS_CLIENT_AUTH_SAN_DNS: &str = "tls_client_auth_san_dns";
/// RFC 8705 section 2.1.1 client metadata: the expected `uniformResourceIdentifier` SAN entry.
pub const TLS_CLIENT_AUTH_SAN_URI: &str = "tls_client_auth_san_uri";
/// RFC 8705 section 2.1.1 client metadata: the expected `iPAddress` SAN entry.
pub const TLS_CLIENT_AUTH_SAN_IP: &str = "tls_client_auth_san_ip";
/// RFC 8705 section 2.1.1 client metadata: the expected `rfc822Name` SAN entry.
pub const TLS_CLIENT_AUTH_SAN_EMAIL: &str = "tls_client_auth_san_email";

/// The RFC 8705 section 3.1 `x5t#S256` value: the SHA-256 hash of the DER encoding of an X.509
/// certificate.
///
/// Held as the 32 RAW bytes rather than as the base64url text, and the first reason is the one
/// that decides it: comparison is then a fixed 32-byte compare that cannot be confused by an
/// encoding difference (padded against unpadded, standard alphabet against URL-safe), which is the
/// classic way two implementations agree about a certificate and disagree about a string. A
/// `String` would make an equality test a question about text that has two legal spellings.
///
/// It is also `Copy` and allocates nothing, where the 43-character base64url text would be a heap
/// allocation per value. That was originally argued from this type appearing inside
/// [`crate::token::IssuedToken`], "which is cloned out of the host's store on every
/// introspection"; that premise is GONE, because [`crate::store::Storage::get_token`] hands back
/// an `Arc<IssuedToken>` and introspection clones nothing. What survives is the write side and the
/// size gate: the token record is built on every issuance and `tests/allocation.rs` holds its
/// `size_of` to a budget, and the binding is stored as `Option<Box<CertificateThumbprint>>` there,
/// so an unbound token pays 8 bytes and no allocation while a bound one pays 32 bytes rather than
/// a 43-byte string. The base64url form is produced only where it is actually needed: on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateThumbprint([u8; 32]);

impl CertificateThumbprint {
    /// Compute the thumbprint of a DER-encoded X.509 certificate (RFC 8705 section 3.1).
    ///
    /// `der` is the certificate itself, NOT a PEM block: base64 text with `-----BEGIN
    /// CERTIFICATE-----` around it hashes to something that matches nothing. See
    /// [`CertificateThumbprint::from_pem`] for that form.
    pub fn from_der(der: &[u8]) -> Self {
        CertificateThumbprint(Sha256::digest(der).into())
    }

    /// Compute the thumbprint of a PEM-encoded certificate, ignoring the armour lines and all
    /// whitespace. Present because a host's certificate almost always arrives as PEM (from a file,
    /// from a proxy header, from a KMS), and re-deriving the DER by hand is precisely where the
    /// "hashed the wrong bytes" mistake happens.
    ///
    /// Only the FIRST certificate in the file is used: RFC 8705 binds to the end-entity
    /// certificate, and a PEM bundle carries its issuers after it.
    pub fn from_pem(pem: &str) -> Result<Self, MtlsRegistrationError> {
        let body = match pem.find("-----BEGIN CERTIFICATE-----") {
            Some(start) => {
                let after = &pem[start + "-----BEGIN CERTIFICATE-----".len()..];
                match after.find("-----END CERTIFICATE-----") {
                    Some(end) => &after[..end],
                    None => return Err(MtlsRegistrationError::MalformedCertificate),
                }
            }
            None => return Err(MtlsRegistrationError::MalformedCertificate),
        };
        let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| MtlsRegistrationError::MalformedCertificate)?;
        Ok(CertificateThumbprint::from_der(&der))
    }

    /// The raw 32 byte hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The RFC 8705 section 3.1 wire form: base64url, no padding, 43 characters.
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Parse the wire form. Rejects anything that is not exactly a 32 byte hash: an `x5t#S256`
    /// value of some other length was never produced by SHA-256, so accepting it would store a
    /// binding that can never match a certificate and would fail at token-presentation time
    /// instead of at configuration time.
    pub fn from_base64url(text: &str) -> Result<Self, MtlsRegistrationError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text.as_bytes())
            .map_err(|_| MtlsRegistrationError::MalformedThumbprint)?;
        let fixed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| MtlsRegistrationError::MalformedThumbprint)?;
        Ok(CertificateThumbprint(fixed))
    }
}

/// The base64url form, which is what RFC 8705 section 3.1 puts on the wire and what an operator
/// reading a log needs to compare against a certificate fingerprint.
impl fmt::Display for CertificateThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64url())
    }
}

/// NOT redacted, unlike every other hand-written `Debug` in this crate. A certificate thumbprint is
/// a hash of a PUBLIC document: it authenticates nobody, it is published inside every bound access
/// token, and an operator diagnosing "this token is bound to a certificate the client is not
/// presenting" needs to be able to see both values.
impl fmt::Debug for CertificateThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateThumbprint({})", self.to_base64url())
    }
}

/// Serialized as the RFC 8705 section 3.1 base64url text, not as an array of 32 numbers.
///
/// This is what a host's store persists and what [`crate::token::IntrospectionResponse`] emits, so
/// the two are the same string and a host can grep for one and find the other.
impl Serialize for CertificateThumbprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for CertificateThumbprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        CertificateThumbprint::from_base64url(&text).map_err(D::Error::custom)
    }
}

/// A client certificate the HOST has already verified, decomposed into the facts RFC 8705 matches
/// on.
///
/// Read the module docs on the trust boundary before constructing one. Nothing in this type is a
/// secret and nothing here is redacted in `Debug`: a certificate is a public document, and what
/// authenticates the client is possession of the private key, which the TLS handshake proved to the
/// HOST and which this crate never sees.
///
/// Everything borrows, so building one allocates nothing but the thumbprint's hash, and passing it
/// into the token endpoint costs one pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate<'a> {
    thumbprint: CertificateThumbprint,
    subject_dn: Option<&'a str>,
    san_dns: &'a [&'a str],
    san_uri: &'a [&'a str],
    san_ip: &'a [&'a str],
    san_email: &'a [&'a str],
}

impl<'a> ClientCertificate<'a> {
    /// From the DER encoding of the VERIFIED certificate: this crate cannot check the chain and
    /// takes the bytes as an established fact, so read this module's trust boundary section before
    /// choosing where they come from. Bytes off an unstripped `X-Client-Cert` header authenticate
    /// nobody.
    ///
    /// The thumbprint (RFC 8705 section 3.1) is
    /// computed here, once, so no caller has to decide which bytes to hash or which base64 alphabet
    /// to use.
    ///
    /// The subject DN and the SAN entries default to absent; add whichever the deployment registers
    /// clients by. A certificate with no facts attached can still be BOUND to a token (section 3),
    /// which is why they are optional rather than required: section 4 makes certificate binding
    /// available to a client that does not authenticate with mutual TLS at all.
    pub fn from_der(der: &[u8]) -> Self {
        ClientCertificate::from_thumbprint(CertificateThumbprint::from_der(der))
    }

    /// From a thumbprint the host computed itself, for a deployment whose TLS terminator forwards a
    /// fingerprint rather than the certificate (nginx's `$ssl_client_fingerprint`, an ALB's
    /// header). The host is then responsible for the encoding, which is why
    /// [`ClientCertificate::from_der`] is the constructor to prefer where the DER is available.
    pub fn from_thumbprint(thumbprint: CertificateThumbprint) -> Self {
        ClientCertificate {
            thumbprint,
            subject_dn: None,
            san_dns: &[],
            san_uri: &[],
            san_ip: &[],
            san_email: &[],
        }
    }

    /// The subject distinguished name, in the RFC 4514 string representation.
    ///
    /// The comparison this crate performs is EXACT STRING EQUALITY against the registered value
    /// (see [`ExpectedSubject::SubjectDn`]), so the host must produce the same spelling its
    /// registrations use. RFC 8705 section 2.1 allows a server to implement a more sophisticated
    /// DN comparison; this crate deliberately does not, because a partial DN parser that gets
    /// attribute ordering, escaping or case folding subtly wrong is a way to make two different
    /// subjects compare equal, and that is an authentication bypass rather than an inconvenience.
    pub fn with_subject_dn(mut self, dn: &'a str) -> Self {
        self.subject_dn = Some(dn);
        self
    }

    /// The `dNSName` subjectAltName entries.
    pub fn with_san_dns(mut self, entries: &'a [&'a str]) -> Self {
        self.san_dns = entries;
        self
    }

    /// The `uniformResourceIdentifier` subjectAltName entries.
    pub fn with_san_uri(mut self, entries: &'a [&'a str]) -> Self {
        self.san_uri = entries;
        self
    }

    /// The `iPAddress` subjectAltName entries, in their textual form.
    pub fn with_san_ip(mut self, entries: &'a [&'a str]) -> Self {
        self.san_ip = entries;
        self
    }

    /// The `rfc822Name` subjectAltName entries.
    pub fn with_san_email(mut self, entries: &'a [&'a str]) -> Self {
        self.san_email = entries;
        self
    }

    /// This certificate's RFC 8705 section 3.1 thumbprint, which is what a token gets bound to.
    pub fn thumbprint(&self) -> &CertificateThumbprint {
        &self.thumbprint
    }

    /// Whether this certificate satisfies ONE registered expected subject value (RFC 8705 section
    /// 2.1).
    ///
    /// Every comparison is exact. No wildcard is honoured (a `*.example.com` SAN matches only a
    /// registration whose value is literally `*.example.com`), no case folding is applied even for
    /// DNS names where the protocol would allow it, and no normalisation is applied to IP address
    /// or URI text. Exactness is the whole security property here: each relaxation is a way for a
    /// certificate issued to one subject to authenticate as another, and a host that needs a
    /// normalised form can register the normalised form.
    fn satisfies(&self, expected: &ExpectedSubject) -> bool {
        match expected {
            ExpectedSubject::SubjectDn(dn) => self.subject_dn == Some(dn.as_str()),
            ExpectedSubject::SanDns(v) => self.san_dns.contains(&v.as_str()),
            ExpectedSubject::SanUri(v) => self.san_uri.contains(&v.as_str()),
            ExpectedSubject::SanIp(v) => self.san_ip.contains(&v.as_str()),
            ExpectedSubject::SanEmail(v) => self.san_email.contains(&v.as_str()),
        }
    }
}

/// The ONE registered value a `tls_client_auth` client is identified by (RFC 8705 section 2.1.1).
///
/// Section 2.1.2 requires that exactly one of the five metadata parameters is registered, and this
/// enum is how that requirement is enforced: with one variant per parameter and no way to hold two
/// at once, a registration carrying both a subject DN and a SAN is not a state this crate can
/// represent, rather than a state it checks for and hopefully rejects. The wire-facing check, for a
/// registration document that CAN spell two, is
/// [`ExpectedSubject::from_registration_parameters`].
///
/// Why the rule matters: the five parameters are alternatives, not a conjunction, so a server that
/// accepted two would have to decide whether to require both or either. "Either" is a strictly
/// weaker credential than the operator asked for, and a server that quietly picks it turns a
/// registration mistake into an authentication bypass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedSubject {
    /// `tls_client_auth_subject_dn`: the expected subject DN, RFC 4514 string form.
    SubjectDn(String),
    /// `tls_client_auth_san_dns`: the expected `dNSName` SAN entry.
    SanDns(String),
    /// `tls_client_auth_san_uri`: the expected `uniformResourceIdentifier` SAN entry.
    SanUri(String),
    /// `tls_client_auth_san_ip`: the expected `iPAddress` SAN entry.
    SanIp(String),
    /// `tls_client_auth_san_email`: the expected `rfc822Name` SAN entry.
    SanEmail(String),
}

impl ExpectedSubject {
    /// Build from the RFC 8705 section 2.1.1 client metadata parameters, enforcing section 2.1.2.
    ///
    /// This is the seam for a registration document (RFC 7591 dynamic registration, or a host's own
    /// admin API) where "two parameters were sent" is expressible. Exactly one recognised parameter
    /// must be present with a non-empty value; zero and two are both refused, and refused BEFORE a
    /// client exists rather than at the first token request.
    ///
    /// An empty value is refused for the same reason a malformed thumbprint is: it can never match
    /// a real certificate, so accepting it registers a client that can never authenticate and
    /// reports the problem at the worst possible moment.
    pub fn from_registration_parameters<'a, I>(parameters: I) -> Result<Self, MtlsRegistrationError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut found: Option<ExpectedSubject> = None;
        for (name, value) in parameters {
            let candidate = match name {
                TLS_CLIENT_AUTH_SUBJECT_DN => ExpectedSubject::SubjectDn(value.to_string()),
                TLS_CLIENT_AUTH_SAN_DNS => ExpectedSubject::SanDns(value.to_string()),
                TLS_CLIENT_AUTH_SAN_URI => ExpectedSubject::SanUri(value.to_string()),
                TLS_CLIENT_AUTH_SAN_IP => ExpectedSubject::SanIp(value.to_string()),
                TLS_CLIENT_AUTH_SAN_EMAIL => ExpectedSubject::SanEmail(value.to_string()),
                // Not one of the five; a registration document carries plenty of other members.
                _ => continue,
            };
            if value.is_empty() {
                return Err(MtlsRegistrationError::EmptySubjectValue);
            }
            // Section 2.1.2. Refused rather than resolved: there is no correct way to pick, and
            // every way of picking is weaker than what the operator wrote down. Note this fires on
            // the SECOND parameter whichever order they arrived in, so the answer does not depend
            // on how the host happened to iterate its own registration document.
            if found.is_some() {
                return Err(MtlsRegistrationError::MoreThanOneSubjectValue);
            }
            found = Some(candidate);
        }
        found.ok_or(MtlsRegistrationError::NoSubjectValue)
    }

    /// The registered parameter name this value came from.
    pub fn parameter_name(&self) -> &'static str {
        match self {
            ExpectedSubject::SubjectDn(_) => TLS_CLIENT_AUTH_SUBJECT_DN,
            ExpectedSubject::SanDns(_) => TLS_CLIENT_AUTH_SAN_DNS,
            ExpectedSubject::SanUri(_) => TLS_CLIENT_AUTH_SAN_URI,
            ExpectedSubject::SanIp(_) => TLS_CLIENT_AUTH_SAN_IP,
            ExpectedSubject::SanEmail(_) => TLS_CLIENT_AUTH_SAN_EMAIL,
        }
    }

    /// The registered value.
    pub fn value(&self) -> &str {
        match self {
            ExpectedSubject::SubjectDn(v)
            | ExpectedSubject::SanDns(v)
            | ExpectedSubject::SanUri(v)
            | ExpectedSubject::SanIp(v)
            | ExpectedSubject::SanEmail(v) => v,
        }
    }
}

/// The certificates a `self_signed_tls_client_auth` client registered, as RFC 8705 section 3.1
/// thumbprints (RFC 8705 section 2.2).
///
/// Section 2.2 has the client register its certificates in a JWK Set, and has the server compare
/// the presented certificate against them. This crate stores the comparison in its cheapest exact
/// form, the SHA-256 thumbprint of the DER, rather than the certificates themselves: the
/// comparison section 2.2 asks for is "is this the same certificate", the thumbprint answers
/// exactly that question in 32 bytes, and keeping whole certificates in the client record would put
/// kilobytes into a value this crate clones on every token request.
///
/// It is deliberately a LIST. A client re-keying has to be able to present either the old or the
/// new certificate for the overlap window, and a deployment with no way to express that gets a
/// flag day instead of a rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredCertificates(Vec<CertificateThumbprint>);

impl RegisteredCertificates {
    /// From thumbprints already computed.
    ///
    /// An EMPTY list is refused, exactly as [`RegisteredCertificates::from_jwks`] refuses a key set
    /// that yields no certificate, and for the identical reason: a registration with nothing to
    /// compare against can never authenticate anybody, so it is a configuration mistake and not a
    /// permissive setting. Accepting it here and refusing it there would have made the outcome of
    /// one mistake depend on which constructor the host happened to reach for.
    pub fn from_thumbprints(
        thumbprints: Vec<CertificateThumbprint>,
    ) -> Result<Self, MtlsRegistrationError> {
        if thumbprints.is_empty() {
            return Err(MtlsRegistrationError::NoCertificates);
        }
        Ok(RegisteredCertificates(thumbprints))
    }

    /// From the DER encodings of the registered certificates. An empty iterator is refused, for the
    /// reason [`RegisteredCertificates::from_thumbprints`] gives.
    pub fn from_der_certificates<'a, I>(certificates: I) -> Result<Self, MtlsRegistrationError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        RegisteredCertificates::from_thumbprints(
            certificates
                .into_iter()
                .map(CertificateThumbprint::from_der)
                .collect(),
        )
    }

    /// From the client's registered RFC 7517 JWK Set, which is the form RFC 8705 section 2.2
    /// actually defines the registration in: each key's `x5c` member (RFC 7517 section 4.7) is a
    /// chain whose FIRST entry is the certificate holding that key, base64 encoded with the
    /// standard alphabet and padding (NOT base64url: section 4.7 is explicit, and it is the
    /// difference that makes a hand-rolled version of this function hash the wrong bytes).
    ///
    /// Provided rather than left to the host because this is the one place a self-signed
    /// registration goes wrong silently: a host that decodes with the wrong alphabet, or that
    /// hashes the second chain entry, produces a registration that simply never authenticates.
    ///
    /// A key with no `x5c` is SKIPPED, not an error: a JWK Set may legitimately carry keys for
    /// other purposes (RFC 9101 request object signing, say). A set that yields no certificate at
    /// all IS an error, because that registration can never authenticate anybody.
    pub fn from_jwks(jwks: &str) -> Result<Self, MtlsRegistrationError> {
        let document: serde_json::Value =
            serde_json::from_str(jwks).map_err(|_| MtlsRegistrationError::MalformedJwks)?;
        let keys = document
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or(MtlsRegistrationError::MalformedJwks)?;
        // Sized from the key count: at most one certificate per key, and this runs at
        // registration time where the count is already in hand.
        let mut thumbprints = Vec::with_capacity(keys.len());
        for key in keys {
            let chain = match key.get("x5c").and_then(|c| c.as_array()) {
                Some(chain) => chain,
                None => continue,
            };
            let leaf = chain
                .first()
                .and_then(|c| c.as_str())
                .ok_or(MtlsRegistrationError::MalformedJwks)?;
            let der = STANDARD
                .decode(leaf.as_bytes())
                .map_err(|_| MtlsRegistrationError::MalformedCertificate)?;
            thumbprints.push(CertificateThumbprint::from_der(&der));
        }
        if thumbprints.is_empty() {
            return Err(MtlsRegistrationError::NoCertificateInJwks);
        }
        Ok(RegisteredCertificates(thumbprints))
    }

    /// The registered thumbprints.
    pub fn thumbprints(&self) -> &[CertificateThumbprint] {
        &self.0
    }

    /// Whether `thumbprint` is one of them.
    ///
    /// A plain comparison, not a constant-time one, and that is not an oversight. Both sides are
    /// hashes of PUBLIC documents: the presented certificate travels in the clear in the TLS
    /// handshake and the registered one is whatever the client published. There is no secret here
    /// for a timing side channel to leak, and what actually authenticates the client is possession
    /// of the private key, which the handshake proved to the host. Compare with
    /// [`crate::client::ClientAuth::verify_with`], where the value IS a secret and the comparison
    /// is constant time for that reason.
    pub fn contains(&self, thumbprint: &CertificateThumbprint) -> bool {
        self.0.contains(thumbprint)
    }
}

/// How a mutual-TLS client is recognised: the RFC 8705 section 2.1 PKI method or the section 2.2
/// self-signed method.
///
/// Held INLINE in [`crate::client::ClientAuth`] rather than boxed, and that is measured rather than
/// assumed: the largest variant here is one `String` plus a discriminant (40 bytes) against the
/// existing `ConfidentialSecretHash` variant's two `String`s (48 bytes), so a client registered for
/// mutual TLS makes `ClientAuth`, and therefore `Client`, exactly as big as it already was. A box
/// would have bought nothing and cost an allocation on every `Client` clone, which happens on every
/// token request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MtlsClientRegistration {
    /// RFC 8705 section 2.1 (`tls_client_auth`): a CA-issued certificate, matched against exactly
    /// one registered subject value. The DEPLOYMENT's trust anchors decide which CAs count, and
    /// that decision is made by the host's TLS terminator, not here.
    TlsClientAuth(ExpectedSubject),
    /// RFC 8705 section 2.2 (`self_signed_tls_client_auth`): a certificate the client registered
    /// itself, matched by thumbprint. No CA is involved and none is needed: the registration IS the
    /// trust anchor.
    SelfSignedTlsClientAuth(RegisteredCertificates),
}

impl MtlsClientRegistration {
    /// The RFC 8705 `token_endpoint_auth_method` value this registration corresponds to, which is
    /// also what the RFC 8414 metadata document advertises.
    pub fn method_name(&self) -> &'static str {
        match self {
            MtlsClientRegistration::TlsClientAuth(_) => TLS_CLIENT_AUTH,
            MtlsClientRegistration::SelfSignedTlsClientAuth(_) => SELF_SIGNED_TLS_CLIENT_AUTH,
        }
    }

    /// Whether `certificate` authenticates this client.
    ///
    /// This answer is only ever as good as the certificate handed in. READ this module's trust
    /// boundary section: a `true` here means "the presented certificate matches what was
    /// registered" and NOTHING about whether it was presented on a TLS connection whose handshake
    /// proved possession of the private key. That part is the host's, it happened before this call,
    /// and a [`ClientCertificate`] built from an unverified header makes this function return
    /// whatever the caller wanted it to.
    pub fn accepts(&self, certificate: &ClientCertificate<'_>) -> bool {
        match self {
            MtlsClientRegistration::TlsClientAuth(expected) => certificate.satisfies(expected),
            MtlsClientRegistration::SelfSignedTlsClientAuth(registered) => {
                registered.contains(certificate.thumbprint())
            }
        }
    }
}

/// A registration this crate refuses to build, because the result could never authenticate anybody
/// or could authenticate the wrong body.
///
/// These are CONFIGURATION errors, reported to whoever is registering a client, and none of them
/// reaches a token-endpoint response: RFC 6749 section 5.2 collapses every client authentication
/// failure into `invalid_client` precisely so that a caller cannot probe a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MtlsRegistrationError {
    /// None of the five RFC 8705 section 2.1.1 subject parameters was present.
    NoSubjectValue,
    /// More than one was present, which RFC 8705 section 2.1.2 forbids.
    MoreThanOneSubjectValue,
    /// A subject parameter was present with an empty value, which no certificate can match.
    EmptySubjectValue,
    /// A JWK Set that could not be parsed, or that has no `keys` array.
    MalformedJwks,
    /// A JWK Set that parsed but carries no certificate for this crate to match against.
    NoCertificateInJwks,
    /// A certificate registration built from an empty list, which can never match anything.
    NoCertificates,
    /// A certificate that is not the DER (or PEM-wrapped DER) this crate can hash.
    MalformedCertificate,
    /// An `x5t#S256` value that is not the base64url encoding of a 32 byte hash.
    MalformedThumbprint,
}

impl fmt::Display for MtlsRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            MtlsRegistrationError::NoSubjectValue => {
                "tls_client_auth requires one of the RFC 8705 s2.1.1 subject parameters"
            }
            MtlsRegistrationError::MoreThanOneSubjectValue => {
                "RFC 8705 s2.1.2 permits exactly one tls_client_auth subject parameter"
            }
            MtlsRegistrationError::EmptySubjectValue => {
                "a tls_client_auth subject parameter was empty, which no certificate can match"
            }
            MtlsRegistrationError::MalformedJwks => "the JWK Set could not be parsed",
            MtlsRegistrationError::NoCertificateInJwks => {
                "the JWK Set carries no x5c certificate to match against"
            }
            MtlsRegistrationError::NoCertificates => {
                "a certificate registration must name at least one certificate"
            }
            MtlsRegistrationError::MalformedCertificate => {
                "the certificate is not DER or PEM-wrapped DER"
            }
            MtlsRegistrationError::MalformedThumbprint => {
                "an x5t#S256 value is base64url of exactly 32 bytes"
            }
        };
        f.write_str(text)
    }
}

impl std::error::Error for MtlsRegistrationError {}

impl Confirmation {
    /// RESOURCE SERVER side of RFC 8705 section 3: whether the certificate on the connection the
    /// token was presented over is the one the token is bound to.
    ///
    /// A resource server that has introspected a token (section 3.2 — a channel this server opens
    /// to resource servers in 0.9.2; through 0.9.1 introspection answers only the token's own
    /// client) or verified a JWT (section
    /// 3.1) calls this with the DER of the client certificate ITS OWN TLS layer verified. The two
    /// halves are equally load bearing, and this method can only do the second one: a certificate
    /// the resource server did not verify proves nothing, exactly as set out in this module's docs.
    ///
    /// Answers `false` for a token that carries no certificate binding at all. That is the safe
    /// direction and the only one this method can take: a resource server calling it is asking "is
    /// this token bound to my caller", and an unbound token is not. A resource server that ACCEPTS
    /// unbound tokens (a mixed deployment, mid-migration) must ask that question separately, with
    /// [`Confirmation::certificate_thumbprint`], rather than reading a `false` here as permission.
    pub fn confirms_certificate(&self, der: &[u8]) -> bool {
        match self.certificate_thumbprint() {
            Some(bound) => *bound == CertificateThumbprint::from_der(der),
            None => false,
        }
    }

    /// The RFC 8705 section 3.1 `x5t#S256` this token is bound to, or `None` for an unbound token.
    pub fn certificate_thumbprint(&self) -> Option<&CertificateThumbprint> {
        self.x5t_s256.as_ref()
    }

    /// The confirmation an access token issued over `certificate` carries (RFC 8705 section 3.1).
    ///
    /// The RFC 9449 `jkt` member, when that feature is also compiled in, is left absent rather
    /// than overwritten: a token can be bound by both mechanisms at once and neither owns the
    /// object. See [`Confirmation`].
    pub fn for_certificate(certificate: &ClientCertificate<'_>) -> Self {
        Confirmation {
            #[cfg(feature = "dpop")]
            jkt: None,
            x5t_s256: Some(*certificate.thumbprint()),
        }
    }
}

/// Whether the certificate on this request authenticates `client`, for a registration that
/// authenticates BY certificate.
///
/// Reached from `AuthorizationServer::authenticate_client`, which dispatches on the REGISTRATION
/// rather than on what the request happened to present. That direction is the security argument:
///
/// - a [`ClientAuth::Mtls`] registration is decided here and ONLY here. It has no secret, so there
///   is no string that could be the right one, and it never reaches the secret comparison:
///   [`ClientAuth::verify_with`] answers `false` for the variant, so no presented secret can
///   authenticate an mTLS client by that route either.
/// - every other registration is decided exactly as it was before, and a certificate presented
///   alongside is NOT an authentication credential there. It is used only for RFC 8705 section 3
///   token binding, which section 4 makes available to clients that authenticate some other way,
///   and to public clients, which authenticate not at all.
pub(crate) fn verify_certificate(
    client: &Client,
    cred: &ClientCredential<'_>,
) -> Result<(), ClientAuthFailure> {
    let registration = match &client.auth {
        ClientAuth::Mtls { registration } => registration,
        // Not reachable through `authenticate_client`. A direct caller that lands here has asked
        // whether a certificate authenticates a client that does not authenticate by certificate,
        // and the answer to that is no rather than "try something else".
        _ => return Err(ClientAuthFailure::SecretMismatch),
    };
    // RFC 6749 s2.3, and OAuth 2.1 s2.4 in the same words: a client uses exactly ONE
    // authentication method per request. A request carrying a secret as well has not said which
    // credential it is relying on, and a server that picks one behaves differently from the next
    // server, which is the ambiguity an intermediary exploits.
    if cred.client_secret.is_some() {
        return Err(ClientAuthFailure::SecretMismatch);
    }
    let certificate = cred
        .certificate
        .ok_or(ClientAuthFailure::NoCertificatePresented)?;
    // The registration decides, and it is the ONLY thing that decides. "The host verified this
    // certificate" says the chain is good, not that it belongs to this client: every deployment
    // that trusts a CA for client certificates has more than one certificate under it, and for the
    // section 2.2 self-signed method a certificate is something the caller can mint for themselves
    // in a second.
    if registration.accepts(certificate) {
        Ok(())
    } else {
        Err(ClientAuthFailure::CertificateMismatch)
    }
}

#[cfg(test)]
#[path = "tests/mtls.rs"]
mod tests;
