#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""Wire the 0.6.0 RFC 9126 (PAR) / RFC 9101 (JAR) slice into the files that slice does not own.

The implementation itself lives entirely in crates/oauth-as/src/par.rs (plus its tests). This
script makes the eight surrounding edits that par.rs cannot make for itself:

  Cargo.toml     the two off-by-default cargo features, `par` and `jar`
  src/lib.rs     the module declaration and the public re-exports
  src/error.rs   the RFC 9101 section 7 error codes this server can emit
  src/events.rs  the Hooks slot for the request object key source
  src/server.rs  ServerConfig::par / ServerConfig::jar, the client-authentication and
                 issuer-identifier visibility par.rs needs, the `with_request_object_keys`
                 installer, and the split of validate_authorization_request into a policy wrapper
                 (which enforces require_pushed_authorization_requests /
                 require_signed_request_object) and the reusable inner validation par.rs calls
  src/store.rs   the two Storage methods that make a request_uri single use, their MemoryStorage
                 implementation, and their place in delete_client and sweep_expired
  src/metadata.rs the RFC 9126 section 5 and RFC 9101 section 4 / 9.2 metadata members

Every edit is anchored on surrounding TEXT, never on a line number, so the script survives the
other 0.6.0 slices editing the same files. It is not idempotent and does not pretend to be: it
refuses to run at all if it can already see its own output, and it fails loudly (changing nothing)
if any anchor is missing or appears more than once.
"""

import sys
from pathlib import Path

# ---------------------------------------------------------------- the edits, file by file

CARGO_TOML_ANCHOR = 'jwt = ["dep:p256"]\n'

CARGO_TOML_ADDITION = '''# RFC 9126 pushed authorization requests: the client POSTs the authorization request to a
# back-channel endpoint and gets a single-use `request_uri` handle, so the parameters (the PKCE
# challenge above all) never traverse the browser. Adds no dependency: it is storage plus the
# validation the authorization endpoint already performs.
par = []
# RFC 9101 JWT-secured authorization requests: a signed request object, verified against the key
# the client registered. Enables `jwt` because verification is ES256 over the same p256 dependency
# the RFC 9068 signer already uses, and because the JWS primitives being added there for RFC 7523
# and DPoP are where this verification belongs once they land (see the SEAM note in src/par.rs).
jar = ["jwt"]
'''

LIB_MODULE_ANCHOR = '''pub mod metadata;
pub mod pkce;
'''

LIB_MODULE_REPLACEMENT = '''pub mod metadata;
/// RFC 9126 pushed authorization requests and RFC 9101 signed request objects, behind the `par`
/// and `jar` cargo features (both off by default). They are the two ways an authorization request
/// reaches this server without travelling through the browser as rewritable query text.
#[cfg(any(feature = "par", feature = "jar"))]
pub mod par;
pub mod pkce;
'''

LIB_REEXPORT_ANCHOR = (
    "pub use metadata::{well_known_path, AuthorizationServerMetadata, WELL_KNOWN_PATH};\n"
)

LIB_REEXPORT_ADDITION = '''#[cfg(feature = "jar")]
pub use par::{
    JarConfig, RegisteredRequestObjectKey, RequestObjectAlg, RequestObjectKeyError,
    RequestObjectKeys, REQUEST_OBJECT_SIGNING_ALGS, REQUEST_OBJECT_TYP,
};
#[cfg(feature = "par")]
pub use par::{
    ParConfig, PushedAuthorizationRequest, PushedAuthorizationResponse, REQUEST_URI_PREFIX,
};
'''

# RE-ANCHORED: the DPoP slice landed `InvalidDpopProof` after `InvalidTarget`, so the end of the
# enum is no longer `InvalidTarget,\n}`. Re-anchored on the new last variant rather than loosened,
# exactly as the failure message asks; the three variants below still land at the end of the enum.
ERROR_VARIANT_ANCHOR = """    #[cfg(feature = "dpop")]
    InvalidDpopProof,
}
"""

ERROR_VARIANT_REPLACEMENT = '''    #[cfg(feature = "dpop")]
    InvalidDpopProof,
    /// RFC 9101 section 7: the `request_uri` in the authorization request returns an error or
    /// contains invalid data. This server mints its own `request_uri` values at its RFC 9126
    /// endpoint and fetches nothing, so "invalid data" here means unknown, already used, expired,
    /// or issued to a different client.
    #[cfg(feature = "par")]
    InvalidRequestUri,
    /// RFC 9101 section 7: the `request` parameter contains an invalid Request Object. Sections
    /// 6.1 and 6.2 make this the REQUIRED answer for a request object that fails to decrypt, fails
    /// signature validation, or is signed with a key that is not the client's.
    #[cfg(feature = "jar")]
    InvalidRequestObject,
    /// RFC 9101 section 7: this server does not support the `request` parameter. Emitted when the
    /// host has not enabled signed request objects at all, which is distinct from a request object
    /// that was offered and refused.
    #[cfg(feature = "jar")]
    RequestNotSupported,
}
'''

# RE-ANCHORED for the same reason as ERROR_VARIANT_ANCHOR above.
ERROR_ASSTR_ANCHOR = """            #[cfg(feature = "dpop")]
            ErrorCode::InvalidDpopProof => "invalid_dpop_proof",
        }
"""

ERROR_ASSTR_REPLACEMENT = '''            #[cfg(feature = "dpop")]
            ErrorCode::InvalidDpopProof => "invalid_dpop_proof",
            #[cfg(feature = "par")]
            ErrorCode::InvalidRequestUri => "invalid_request_uri",
            #[cfg(feature = "jar")]
            ErrorCode::InvalidRequestObject => "invalid_request_object",
            #[cfg(feature = "jar")]
            ErrorCode::RequestNotSupported => "request_not_supported",
        }
'''

EVENTS_FIELD_ANCHOR = """    registration_policy: Option<Box<dyn RegistrationPolicy>>,
}
"""

EVENTS_FIELD_REPLACEMENT = '''    registration_policy: Option<Box<dyn RegistrationPolicy>>,
    #[cfg(feature = "jar")]
    request_object_keys: Option<Box<dyn crate::par::RequestObjectKeys>>,
}
'''

EVENTS_INSTALL_ANCHOR = """    /// Install the RFC 7591 registration policy, replacing any previous one.
    pub fn install_registration_policy(&mut self, policy: Box<dyn RegistrationPolicy>) {
        self.installed().registration_policy = Some(policy);
    }
"""

EVENTS_INSTALL_REPLACEMENT = '''    /// Install the RFC 7591 registration policy, replacing any previous one.
    pub fn install_registration_policy(&mut self, policy: Box<dyn RegistrationPolicy>) {
        self.installed().registration_policy = Some(policy);
    }

    /// Install the RFC 9101 request object verification keys, replacing any previous source.
    #[cfg(feature = "jar")]
    pub fn install_request_object_keys(&mut self, keys: Box<dyn crate::par::RequestObjectKeys>) {
        self.installed().request_object_keys = Some(keys);
    }

    /// The installed RFC 9101 request object key source.
    ///
    /// `None` is NOT read as "accept anything", for the same reason as
    /// [`Hooks::registration_policy`] and the opposite of the [`RateLimiter`] default: a server
    /// that cannot check a signature must refuse the request, because "cannot check" must never
    /// read as "checked out".
    #[cfg(feature = "jar")]
    pub fn request_object_keys(&self) -> Option<&dyn crate::par::RequestObjectKeys> {
        match &self.0 {
            Some(installed) => installed.request_object_keys.as_deref(),
            None => None,
        }
    }
'''

SERVER_CONFIG_FIELD_ANCHOR = (
    "    pub registration: Option<Box<crate::registration::RegistrationConfig>>,\n"
)

SERVER_CONFIG_FIELD_REPLACEMENT = '''    pub registration: Option<Box<crate::registration::RegistrationConfig>>,
    /// RFC 9126 pushed authorization requests. `None` is the DEFAULT and means PAR is OFF: no
    /// `pushed_authorization_request_endpoint` is advertised and
    /// [`AuthorizationServer::pushed_authorization_request`] refuses.
    ///
    /// BOXED for the same reason as [`ServerConfig::registration`]: the overwhelmingly common
    /// `None` costs one null pointer on every [`ServerConfig`] rather than the whole struct, and
    /// allocates nothing.
    #[cfg(feature = "par")]
    pub par: Option<Box<crate::par::ParConfig>>,
    /// RFC 9101 signed request objects. `None` is the DEFAULT and means JAR is OFF: a `request`
    /// parameter is answered with `request_not_supported` rather than parsed.
    #[cfg(feature = "jar")]
    pub jar: Option<Box<crate::par::JarConfig>>,
'''

SERVER_CONFIG_NEW_ANCHOR = """            // OFF. See the field's own docs, and RFC 7591 section 5.
            registration: None,
"""

SERVER_CONFIG_NEW_REPLACEMENT = '''            // OFF. See the field's own docs, and RFC 7591 section 5.
            registration: None,
            // OFF. PAR is a capability a host opts into, not a default: see the field's docs.
            #[cfg(feature = "par")]
            par: None,
            #[cfg(feature = "jar")]
            jar: None,
'''

SERVER_AUTHENTICATE_ANCHOR = """    async fn authenticate_client(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
    ) -> Result<Client, ErrorResponse> {
"""

SERVER_AUTHENTICATE_REPLACEMENT = '''    // `pub(crate)` rather than private: RFC 9126 section 2.1 step 1 has the PAR endpoint
    // authenticate the client "in the same way as at the token endpoint", and
    // `AuthorizationServer::pushed_authorization_request` (in `par.rs`, a sibling module) is the
    // only other caller. Reusing this rather than copying it is the point: a second client
    // authentication path is a second place for the rate-limit ordering and the audit events to
    // drift.
    pub(crate) async fn authenticate_client(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
    ) -> Result<Client, ErrorResponse> {
'''

SERVER_ISSUER_ANCHOR = "    fn issuer_identifier(&self) -> &str {\n"

SERVER_ISSUER_REPLACEMENT = (
    "    // `pub(crate)` so `par.rs` can check an RFC 9101 request object's `aud` claim against the\n"
    "    // ONE spelling this server publishes, rather than re-deriving it and risking a second one.\n"
    "    pub(crate) fn issuer_identifier(&self) -> &str {\n"
)

SERVER_POLICY_ANCHOR = """    pub async fn validate_authorization_request(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        let direct = |code: ErrorCode, why: &str| {
"""

SERVER_POLICY_REPLACEMENT = '''    pub async fn validate_authorization_request(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        // The POLICY gate, ahead of the validation itself: a deployment may declare that
        // parameters in the query are not an acceptable way to ask for authorization at all.
        //
        // RFC 9126 section 4 lets a server require PAR globally, and RFC 9101 section 10.5
        // requires the equivalent for signed request objects, both for the same reason: an
        // attacker who can rewrite the browser's URL will simply strip the protection and send a
        // plain RFC 6749 request unless the server refuses one. This is the only entry point that
        // takes query parameters, so refusing here is what makes the policy hold; `par.rs` reaches
        // the validation below directly, having already established that the request was pushed or
        // signed.
        #[cfg(feature = "par")]
        if matches!(&self.config.par, Some(par) if par.require_pushed_authorization_requests) {
            return Err(AuthorizationError::Direct(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                    "this server accepts authorization request data only via PAR (RFC 9126 s4)",
                ),
            ));
        }
        #[cfg(feature = "jar")]
        if matches!(&self.config.jar, Some(jar) if jar.require_signed_request_object) {
            return Err(AuthorizationError::Direct(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                    "this server requires a signed request object (RFC 9101 s10.5)",
                ),
            ));
        }
        self.validate_direct_authorization_request(request).await
    }

    /// The validation itself, with no policy gate in front of it.
    ///
    /// Split out for RFC 9126 / RFC 9101: a pushed or signed request has ALREADY satisfied the
    /// policy the wrapper above enforces, and it arrives as parameters rather than as a query, so
    /// it needs this and not the wrapper. Everything else about it is unchanged, which is the
    /// point: the PAR endpoint validates a pushed request by calling exactly the function the
    /// authorization endpoint calls, so the two cannot drift.
    pub(crate) async fn validate_direct_authorization_request(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
        let direct = |code: ErrorCode, why: &str| {
'''

SERVER_INSTALLER_ANCHOR = """    pub fn with_registration_policy(
        mut self,
        policy: Box<dyn crate::registration::RegistrationPolicy>,
    ) -> Self {
        self.hooks.install_registration_policy(policy);
        self
    }
"""

SERVER_INSTALLER_REPLACEMENT = '''    pub fn with_registration_policy(
        mut self,
        policy: Box<dyn crate::registration::RegistrationPolicy>,
    ) -> Self {
        self.hooks.install_registration_policy(policy);
        self
    }

    /// Install the RFC 9101 request object verification keys: which public key, under which
    /// algorithm, each client registered for signing request objects.
    ///
    /// Required, not optional, for a host that sets [`ServerConfig::jar`]: with no key source
    /// installed every `request` parameter is refused, because a server that cannot check a
    /// signature must not act on the claims under it. See [`crate::par::RequestObjectKeys`].
    #[cfg(feature = "jar")]
    pub fn with_request_object_keys(
        mut self,
        keys: Box<dyn crate::par::RequestObjectKeys>,
    ) -> Self {
        self.hooks.install_request_object_keys(keys);
        self
    }
'''

STORE_INNER_ANCHOR = """    codes: HashMap<String, AuthorizationCodeRecord>,
"""

STORE_INNER_REPLACEMENT = '''    codes: HashMap<String, AuthorizationCodeRecord>,
    #[cfg(feature = "par")]
    pushed: HashMap<String, crate::par::PushedAuthorizationRequest>,
'''

STORE_TRAIT_ANCHOR = """    /// Persist an issued access token.
    fn put_token(
"""

STORE_TRAIT_REPLACEMENT = '''    /// Insert or replace a pushed authorization request (RFC 9126 section 2.2), keyed by its
    /// `request_uri`.
    #[cfg(feature = "par")]
    fn put_pushed_authorization_request(
        &self,
        record: crate::par::PushedAuthorizationRequest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically remove and return a pushed authorization request. This is what makes a
    /// `request_uri` single use: RFC 9126 section 4 says a client MUST use one once and section
    /// 7.3 asks the server to enforce it rather than trust that, so under concurrent authorization
    /// requests exactly one caller receives the record and every other caller sees `None`. A plain
    /// read-then-delete reintroduces the replay this is here to prevent.
    ///
    /// Unlike [`Storage::take_authorization_code`], nothing is put back after a SUCCESSFUL
    /// resolution: a spent handle minted no credential of its own, so there is nothing a later
    /// presentation of it could need to be recognised for, and retaining it would only keep a live
    /// capability string in the store. The server DOES put it back when the handle was presented by
    /// the wrong client, so that a stranger cannot destroy a legitimate client's request.
    #[cfg(feature = "par")]
    fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> impl Future<Output = Result<Option<crate::par::PushedAuthorizationRequest>, StorageError>> + Send;

    /// Persist an issued access token.
    fn put_token(
'''

STORE_DELETE_ANCHOR = """        g.codes.retain(|_, c| &c.client_id != client_id);
"""

STORE_DELETE_REPLACEMENT = '''        g.codes.retain(|_, c| &c.client_id != client_id);
        // RFC 9126 s2.2 binds a request_uri to the client that pushed it, so a deleted client's
        // outstanding handles are handles nobody may ever redeem.
        #[cfg(feature = "par")]
        g.pushed.retain(|_, p| &p.client_id != client_id);
'''

STORE_SWEEP_ANCHOR = """        let before = g.codes.len();
        g.codes.retain(|_, c| now < c.expires_at);
        removed += (before - g.codes.len()) as u64;
"""

STORE_SWEEP_REPLACEMENT = '''        let before = g.codes.len();
        g.codes.retain(|_, c| now < c.expires_at);
        removed += (before - g.codes.len()) as u64;

        // RFC 9126 s4: an expired request_uri MUST be rejected, and once it is expired there is
        // nothing left to recognise it for, so it is swept like anything else. A swept handle and
        // a used one are the same answer at the authorization endpoint, deliberately.
        #[cfg(feature = "par")]
        {
            let before = g.pushed.len();
            g.pushed.retain(|_, p| now < p.expires_at);
            removed += (before - g.pushed.len()) as u64;
        }
'''

STORE_DOC_ANCHOR = """//! - `take_*` operations are ATOMIC remove-and-return. They are how single-use artifacts (device
//!   codes at redemption, rotating refresh tokens) stay single use under concurrency."""

STORE_DOC_REPLACEMENT = """//! - `take_*` operations are ATOMIC remove-and-return. They are how single-use artifacts (device
//!   codes at redemption, rotating refresh tokens, RFC 9126 pushed authorization request handles)
//!   stay single use under concurrency."""

METADATA_FIELD_ANCHOR = """    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
"""

METADATA_FIELD_REPLACEMENT = '''    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// RFC 9126 section 5. Present ONLY when the host enabled PAR
    /// ([`crate::server::ServerConfig::par`]): section 5 says its presence is sufficient for a
    /// client to decide it may use PAR, so advertising an endpoint that is not served would be a
    /// promise this server cannot keep.
    #[cfg(feature = "par")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// RFC 9126 section 5. `Some(false)` states the default explicitly when PAR is offered;
    /// omitted entirely when PAR is off, since section 5 gives an absent member the meaning
    /// `false` and a server with no PAR endpoint has nothing to require.
    #[cfg(feature = "par")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    /// RFC 9101 section 4: the `alg` values this server will verify a request object with.
    /// Present only when signed request objects are enabled.
    #[cfg(feature = "jar")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9101 section 10.5, registered by its section 9.2. Present only when signed request
    /// objects are enabled; `true` means a plain RFC 6749 authorization request is refused, which
    /// is the downgrade that section describes.
    #[cfg(feature = "jar")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_signed_request_object: Option<bool>,
'''

METADATA_FROM_CONFIG_ANCHOR = """            scopes_supported: config.scopes_supported.clone(),
"""

METADATA_FROM_CONFIG_REPLACEMENT = '''            scopes_supported: config.scopes_supported.clone(),
            #[cfg(feature = "par")]
            pushed_authorization_request_endpoint: config
                .par
                .as_ref()
                .map(|par| par.endpoint(&iss)),
            #[cfg(feature = "par")]
            require_pushed_authorization_requests: config
                .par
                .as_ref()
                .map(|par| par.require_pushed_authorization_requests),
            #[cfg(feature = "jar")]
            request_object_signing_alg_values_supported: config.jar.as_ref().map(|_| {
                crate::par::REQUEST_OBJECT_SIGNING_ALGS
                    .iter()
                    .map(|alg| alg.to_string())
                    .collect()
            }),
            #[cfg(feature = "jar")]
            require_signed_request_object: config
                .jar
                .as_ref()
                .map(|jar| jar.require_signed_request_object),
'''

EDITS = [
    ("crates/oauth-as/Cargo.toml", CARGO_TOML_ANCHOR, CARGO_TOML_ANCHOR + CARGO_TOML_ADDITION),
    ("crates/oauth-as/src/lib.rs", LIB_MODULE_ANCHOR, LIB_MODULE_REPLACEMENT),
    (
        "crates/oauth-as/src/lib.rs",
        LIB_REEXPORT_ANCHOR,
        LIB_REEXPORT_ANCHOR + LIB_REEXPORT_ADDITION,
    ),
    ("crates/oauth-as/src/error.rs", ERROR_VARIANT_ANCHOR, ERROR_VARIANT_REPLACEMENT),
    ("crates/oauth-as/src/error.rs", ERROR_ASSTR_ANCHOR, ERROR_ASSTR_REPLACEMENT),
    ("crates/oauth-as/src/events.rs", EVENTS_FIELD_ANCHOR, EVENTS_FIELD_REPLACEMENT),
    ("crates/oauth-as/src/events.rs", EVENTS_INSTALL_ANCHOR, EVENTS_INSTALL_REPLACEMENT),
    ("crates/oauth-as/src/server.rs", SERVER_CONFIG_FIELD_ANCHOR, SERVER_CONFIG_FIELD_REPLACEMENT),
    ("crates/oauth-as/src/server.rs", SERVER_CONFIG_NEW_ANCHOR, SERVER_CONFIG_NEW_REPLACEMENT),
    ("crates/oauth-as/src/server.rs", SERVER_ISSUER_ANCHOR, SERVER_ISSUER_REPLACEMENT),
    ("crates/oauth-as/src/server.rs", SERVER_POLICY_ANCHOR, SERVER_POLICY_REPLACEMENT),
    ("crates/oauth-as/src/server.rs", SERVER_INSTALLER_ANCHOR, SERVER_INSTALLER_REPLACEMENT),
    ("crates/oauth-as/src/store.rs", STORE_DOC_ANCHOR, STORE_DOC_REPLACEMENT),
    ("crates/oauth-as/src/store.rs", STORE_INNER_ANCHOR, STORE_INNER_REPLACEMENT),
    ("crates/oauth-as/src/store.rs", STORE_TRAIT_ANCHOR, STORE_TRAIT_REPLACEMENT),
    ("crates/oauth-as/src/store.rs", STORE_DELETE_ANCHOR, STORE_DELETE_REPLACEMENT),
    ("crates/oauth-as/src/store.rs", STORE_SWEEP_ANCHOR, STORE_SWEEP_REPLACEMENT),
    ("crates/oauth-as/src/metadata.rs", METADATA_FIELD_ANCHOR, METADATA_FIELD_REPLACEMENT),
    (
        "crates/oauth-as/src/metadata.rs",
        METADATA_FROM_CONFIG_ANCHOR,
        METADATA_FROM_CONFIG_REPLACEMENT,
    ),
]

# The MemoryStorage implementation of the two new Storage methods, inserted before `put_token`'s
# implementation rather than before its declaration; the two anchors differ by the `async` keyword,
# which is what keeps each of them unique in the file.
STORE_IMPL_ANCHOR = """    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
"""

STORE_IMPL_REPLACEMENT = '''    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: crate::par::PushedAuthorizationRequest,
    ) -> Result<(), StorageError> {
        self.lock()
            .pushed
            .insert(record.request_uri.clone(), record);
        Ok(())
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<crate::par::PushedAuthorizationRequest>, StorageError> {
        // Atomic by construction, like every other `take_*` here: one mutex, one `remove`.
        Ok(self.lock().pushed.remove(request_uri))
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
'''

EDITS.append(("crates/oauth-as/src/store.rs", STORE_IMPL_ANCHOR, STORE_IMPL_REPLACEMENT))

# The shared integration-test fixture implements `Storage` too, so the two new methods have to
# reach it or every test binary that uses it stops compiling under `--features par`. It delegates
# to `MemoryStorage` for everything it does not deliberately break, and these are no exception.
SUPPORT_ANCHOR = """    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        self.inner.put_token(token).await
    }
"""

SUPPORT_REPLACEMENT = '''    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::PushedAuthorizationRequest,
    ) -> Result<(), StorageError> {
        self.inner.put_pushed_authorization_request(record).await
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::PushedAuthorizationRequest>, StorageError> {
        self.inner
            .take_pushed_authorization_request(request_uri)
            .await
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        self.inner.put_token(token).await
    }
'''

EDITS.append(("crates/oauth-as/tests/support/mod.rs", SUPPORT_ANCHOR, SUPPORT_REPLACEMENT))

# `authenticate_client` is one word of visibility that MORE THAN ONE 0.6.0/0.7.0 slice needs: PAR
# (RFC 9126 s2.1 step 1) and RFC 8693 token exchange both authenticate a client the way the token
# endpoint does. Whichever patch runs first should make the change and the other should not fail
# over it, so this edit is applied ONLY if the private form is still there, and is a no-op (with a
# note) if a sibling patch already widened it.
OPTIONAL_EDITS = [
    (
        "crates/oauth-as/src/server.rs",
        SERVER_AUTHENTICATE_ANCHOR,
        SERVER_AUTHENTICATE_REPLACEMENT,
        "    pub(crate) async fn authenticate_client(",
        "authenticate_client is already pub(crate); a sibling patch widened it first",
    ),
]

# If any of these strings is already present, the script has run before (or somebody hand-applied
# part of it), and running again would duplicate declarations rather than fail a build in an
# obvious place.
ALREADY_APPLIED_MARKERS = [
    ("crates/oauth-as/Cargo.toml", "par = []"),
    ("crates/oauth-as/src/lib.rs", "pub mod par;"),
    ("crates/oauth-as/src/server.rs", "validate_direct_authorization_request"),
    ("crates/oauth-as/src/store.rs", "take_pushed_authorization_request"),
    ("crates/oauth-as/src/metadata.rs", "pushed_authorization_request_endpoint"),
    ("crates/oauth-as/src/error.rs", "InvalidRequestObject"),
    ("crates/oauth-as/src/events.rs", "request_object_keys"),
]


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    if not (root / "crates" / "oauth-as" / "Cargo.toml").is_file():
        print(f"FAIL: {root} does not look like the oauth-as workspace root", file=sys.stderr)
        return 1

    # Refuse to run twice, BEFORE writing anything.
    for relative, marker in ALREADY_APPLIED_MARKERS:
        path = root / relative
        if path.is_file() and marker in path.read_text(encoding="utf-8"):
            print(
                f"FAIL: {relative} already contains {marker!r}; this patch has already been "
                "applied. Nothing was written.",
                file=sys.stderr,
            )
            return 1

    # Apply every edit in memory first, so a missing anchor leaves the tree untouched.
    pending: dict[Path, str] = {}
    for relative, anchor, replacement in EDITS:
        path = root / relative
        if not path.is_file():
            print(f"FAIL: {relative} does not exist", file=sys.stderr)
            return 1
        text = pending.get(path, path.read_text(encoding="utf-8"))
        occurrences = text.count(anchor)
        if occurrences != 1:
            head = anchor.strip().splitlines()[0] if anchor.strip() else anchor
            print(
                f"FAIL: anchor in {relative} matched {occurrences} times, expected exactly 1.\n"
                f"      anchor begins: {head!r}\n"
                "      The file has moved on since this patch was written; re-anchor it rather "
                "than loosening the match. Nothing was written.",
                file=sys.stderr,
            )
            return 1
        pending[path] = text.replace(anchor, replacement, 1)

    for relative, anchor, replacement, already, note in OPTIONAL_EDITS:
        path = root / relative
        text = pending.get(path, path.read_text(encoding="utf-8"))
        if already in text:
            print(f"skipped {relative}: {note}")
            continue
        if text.count(anchor) != 1:
            print(
                f"FAIL: optional anchor in {relative} matched {text.count(anchor)} times and the "
                "change is not already present. Nothing was written.",
                file=sys.stderr,
            )
            return 1
        pending[path] = text.replace(anchor, replacement, 1)

    for path, text in pending.items():
        path.write_text(text, encoding="utf-8")
        print(f"patched {path.relative_to(root)}")

    print(
        "\nDone. crates/oauth-as/src/par.rs, src/tests/par.rs, tests/par.rs and tests/jar.rs are "
        "the slice itself and are added as files, not by this script."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
