#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""Wire the RFC 7523 (client_assertion) and RFC 9449 (dpop) slices into the files their
implementation modules do not own.

WHY THIS IS A SCRIPT AND NOT A DIFF. The 0.4.0/0.5.0 slice was built alongside other slices in the
same working tree, and its author owns only src/jwt.rs, src/client_assertion.rs, src/dpop.rs and
their tests. Everything else it needs to touch (the storage seam, the client registration model, the
token wire types, the server, the metadata document, the optional HTTP surface) belongs to another
author who is editing the same files. A unified diff would be stale the moment either side moved.
Every edit below is therefore anchored on surrounding TEXT rather than on a line number, and asserts
that its anchor occurs EXACTLY the expected number of times before it changes anything: an anchor
that has drifted stops the script instead of silently corrupting a file.

Idempotence: the script refuses to run twice. Half-applying is worse than not applying, so nothing
is written until every anchor in every file has been located.

Run from the repository root:  python3 scripts/patch-client-assertion-and-dpop.py
It rewrites files in place and then runs `cargo fmt --all`.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRATE = os.path.join(ROOT, "crates", "oauth-as")

# id -> (path, [(old, new, expected_count), ...])
PLAN = {}
FILES = {}


def load(rel):
    path = os.path.join(CRATE, rel)
    if not os.path.exists(path):
        die("expected file does not exist: %s" % path)
    with open(path, "r", encoding="utf-8") as fh:
        FILES[rel] = fh.read()
    return FILES[rel]


def die(msg):
    sys.stderr.write("patch-client-assertion-and-dpop: FAILED: %s\n" % msg)
    sys.exit(1)


def edit(rel, old, new, count=1):
    """Replace `old` with `new` in `rel`, insisting `old` occurs exactly `count` times."""
    text = FILES[rel]
    found = text.count(old)
    if found != count:
        die(
            "anchor in %s occurred %d times, expected %d.\n--- anchor ---\n%s\n--------------"
            % (rel, found, count, old)
        )
    FILES[rel] = text.replace(old, new)


def already_applied():
    store = os.path.join(CRATE, "src", "store.rs")
    with open(store, "r", encoding="utf-8") as fh:
        return "claim_replay_id" in fh.read()


# =================================================================================================
# Cargo.toml: the two cargo features. Both OFF by default and both implying `jwt`.
# =================================================================================================
def patch_cargo():
    rel = "Cargo.toml"
    load(rel)
    edit(
        rel,
        'jwt = ["dep:p256"]',
        '''jwt = ["dep:p256"]
# RFC 7523 JWT client authentication: `private_key_jwt` (asymmetric, ES256) and `client_secret_jwt`
# (HMAC, HS256), so that a deployment whose security policy forbids transmitting a shared secret can
# use this crate at all. It is also required by FAPI 2.0.
#
# IMPLIES `jwt`, and that is a decision rather than an accident. This and `dpop` both rest on JWS
# VERIFICATION, and this crate holds exactly ONE copy of that code (see the VERIFICATION banner in
# src/jwt.rs). Two half-built verifiers behind two independent feature flags is how a codebase ends
# up with an algorithm-confusion bug in whichever half nobody reviewed. Neither feature adds a
# dependency: ES256 verification is the `p256` that `jwt` already pulls in, and HMAC-SHA-256 is
# twenty lines over the `sha2` that PKCE already required.
client_assertion = ["jwt"]
# RFC 9449 DPoP: sender-constrained access tokens, bound to a key the client proves possession of on
# every request. Without it every token this crate issues is a bearer token, so a stolen one is
# usable by whoever stole it; this changes what a leak costs. IMPLIES `jwt` for the reason above.
dpop = ["jwt"]''',
    )


# =================================================================================================
# src/error.rs: the RFC 9449 s5 error code.
# =================================================================================================
def patch_error():
    rel = "src/error.rs"
    load(rel)
    edit(
        rel,
        """    InvalidTarget,
}""",
        """    InvalidTarget,
    /// RFC 9449 section 5: the DPoP proof on this request is missing, malformed, does not bind to
    /// this request, or has already been used. Registered by RFC 9449 section 12.3.
    ///
    /// A DISTINCT code from `invalid_client` on purpose, and the distinction is actionable: the
    /// client's credential may be perfectly good and only its proof wrong, and a client told
    /// `invalid_client` would go and check the wrong thing. Feature gated, so a build without
    /// `dpop` has exactly the code set it had before.
    #[cfg(feature = "dpop")]
    InvalidDpopProof,
}""",
    )
    edit(
        rel,
        """            ErrorCode::InvalidTarget => "invalid_target",""",
        """            ErrorCode::InvalidTarget => "invalid_target",
            #[cfg(feature = "dpop")]
            ErrorCode::InvalidDpopProof => "invalid_dpop_proof",""",
    )


# =================================================================================================
# src/store.rs: the replay-prevention seam.
# =================================================================================================
def patch_store():
    rel = "src/store.rs"
    load(rel)

    edit(
        rel,
        """//! - Nothing in this crate evicts anything on a timer: there is no background task, by design.""",
        """//! - `claim_replay_id` is an ATOMIC claim-if-absent, and it is what makes RFC 7523 client
//!   assertions and RFC 9449 DPoP proofs single use. A store that implements it as "look, then
//!   insert" has reintroduced exactly the replay the two RFCs require to be prevented, and unlike
//!   the `take_*` operations the damage is silent: nothing else in the system notices.
//! - Nothing in this crate evicts anything on a timer: there is no background task, by design.""",
    )

    edit(
        rel,
        """    /// Remove every record that is dead at `now`, and return how many were removed.""",
        '''    /// Atomically CLAIM a single-use identifier, returning `true` when this caller is the first
    /// to claim it and `false` when it has already been claimed.
    ///
    /// This is the replay-prevention primitive behind two REQUIREMENTS, not two optimisations:
    /// RFC 7523 section 3 makes a client assertion's `jti` single use within the assertion's
    /// validity, and RFC 9449 section 4.3 makes a DPoP proof's `jti` single use within the proof's
    /// acceptance window. An implementation that verifies the signature and skips this has built a
    /// credential that anybody who observed one request can send again, which is the whole of what
    /// those two mechanisms exist to prevent.
    ///
    /// `expires_at` is when the claim may be reclaimed by [`Storage::sweep_expired`], and it is the
    /// caller's job to pass the instant past which the artifact would be refused on time alone
    /// (the assertion's `exp`, the proof's `iat` plus the acceptance window). Reclaiming EARLIER
    /// than that reopens the replay window; the two callers in this crate both derive it from the
    /// artifact rather than from a policy of their own.
    ///
    /// ATOMICITY IS THE CONTRACT, exactly as for the `take_*` operations above. A shared multi-node
    /// store must implement this with a genuinely atomic primitive (`INSERT ... ON CONFLICT DO
    /// NOTHING` and check the row count, `SET NX`, a compare-and-set); a read-then-write lets two
    /// concurrent presentations of the SAME assertion both be told they were first, which is the
    /// replay this method exists to refuse. Failing CLOSED on a storage error is the caller's job
    /// and this crate does it: a claim that could not be recorded is treated as a claim that
    /// failed.
    ///
    /// Claiming an id that is already present but EXPIRED is at the store's discretion: this crate
    /// never presents such an id, because the artifact carrying it would have been refused on time
    /// first. [`MemoryStorage`] treats a live entry as claimed regardless of its deadline and lets
    /// `sweep_expired` do the reclaiming, which is the conservative reading.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Remove every record that is dead at `now`, and return how many were removed.''',
    )

    edit(
        rel,
        """    /// - refresh records with `Some(expires_at) <= now`. A record with `expires_at: None` is a""",
        """    /// - claimed replay identifiers (see [`Storage::claim_replay_id`]) with `expires_at <= now`
    /// - refresh records with `Some(expires_at) <= now`. A record with `expires_at: None` is a""",
    )

    edit(
        rel,
        """    refresh: HashMap<String, RefreshTokenRecord>,
}""",
        """    refresh: HashMap<String, RefreshTokenRecord>,
    /// Claimed RFC 7523 / RFC 9449 single-use identifiers, mapped to when they may be reclaimed.
    /// Present only under the features that produce them, so a default build's store is byte for
    /// byte the store it was before.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    replay_ids: HashMap<String, std::time::SystemTime>,
}""",
    )

    edit(
        rel,
        """    async fn sweep_expired(&self, now: std::time::SystemTime) -> Result<u64, StorageError> {""",
        """    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> Result<bool, StorageError> {
        // Atomic by construction: the whole claim happens under the one mutex, so two concurrent
        // presentations of the same identifier cannot both observe it absent. The `id` is only
        // allocated when the claim is actually taken, which keeps a replayed request from costing
        // an allocation as well as a lookup.
        let mut g = self.lock();
        if g.replay_ids.contains_key(id) {
            return Ok(false);
        }
        g.replay_ids.insert(id.to_string(), expires_at);
        Ok(true)
    }

    async fn sweep_expired(&self, now: std::time::SystemTime) -> Result<u64, StorageError> {""",
    )

    edit(
        rel,
        """        removed += (before - g.refresh.len()) as u64;

        Ok(removed)""",
        """        removed += (before - g.refresh.len()) as u64;

        // The replay set is the one collection here that an unauthenticated caller can grow: every
        // refused-but-well-formed assertion or proof adds an entry. It is bounded by the artifact
        // lifetime caps in `client_assertion.rs` and `dpop.rs`, but only a sweep actually reclaims
        // it, exactly as for everything else in this store.
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        {
            let before = g.replay_ids.len();
            g.replay_ids.retain(|_, exp| now < *exp);
            removed += (before - g.replay_ids.len()) as u64;
        }

        Ok(removed)""",
    )


# =================================================================================================
# src/client.rs: the registration that authenticates with an assertion.
# =================================================================================================
def patch_client():
    rel = "src/client.rs"
    load(rel)

    edit(
        rel,
        """    /// A confidential client stored as a one-way VERIFIER rather than as its secret. This is the
    /// variant to reach for: see [`SecretHash`].
    ConfidentialSecretHash {
        /// The stored verifier.
        hash: SecretHash,
    },
}""",
        """    /// A confidential client stored as a one-way VERIFIER rather than as its secret. This is the
    /// variant to reach for: see [`SecretHash`].
    ConfidentialSecretHash {
        /// The stored verifier.
        hash: SecretHash,
    },
    /// A confidential client that authenticates with an RFC 7523 signed assertion rather than by
    /// presenting a secret: `private_key_jwt` or `client_secret_jwt`.
    ///
    /// The keys are held INLINE rather than behind a `Box`, unlike `Client::registration`. A
    /// `Client` is cloned out of the store on every token-plane request, so the question is what
    /// this costs a deployment that does not use it, and the answer is nothing: the widest existing
    /// variant is `ConfidentialSecretHash` (two `String`s), and
    /// [`crate::client_assertion::AssertionKeys`] is narrower than that, so `ClientAuth` does not
    /// grow by a byte. Boxing would have ADDED an allocation to every clone of a client that does
    /// use it, to save a struct size that was already paid for.
    #[cfg(feature = "client_assertion")]
    ConfidentialAssertion {
        /// What the registration expects the assertion to be signed with. This, and never the
        /// token's own header, is what decides the algorithm: see
        /// [`crate::client_assertion::verify_assertion`].
        keys: crate::client_assertion::AssertionKeys,
    },
}""",
    )

    edit(
        rel,
        """            ClientAuth::ConfidentialSecretHash { hash } => f
                .debug_struct("ConfidentialSecretHash")
                .field("hash", hash)
                .finish(),
        }""",
        """            ClientAuth::ConfidentialSecretHash { hash } => f
                .debug_struct("ConfidentialSecretHash")
                .field("hash", hash)
                .finish(),
            // `AssertionKeys`'s own Debug redacts a `client_secret_jwt` secret and prints the
            // PUBLIC keys of a `private_key_jwt` registration, which are public.
            #[cfg(feature = "client_assertion")]
            ClientAuth::ConfidentialAssertion { keys } => f
                .debug_struct("ConfidentialAssertion")
                .field("keys", keys)
                .finish(),
        }""",
    )

    edit(
        rel,
        """            ClientAuth::ConfidentialSecretHash { hash } => match presented {
                Some(p) => hash.verify(p, verifier),
                None => false,
            },
        }""",
        """            ClientAuth::ConfidentialSecretHash { hash } => match presented {
                Some(p) => hash.verify(p, verifier),
                None => false,
            },
            // NEVER, and not because it is unimplemented. This registration's credential is a
            // SIGNATURE over a claim set (RFC 7523 section 3), and there is no presented string
            // that is the right answer here. Returning `true` for any input would let a client
            // registered for `private_key_jwt` be authenticated by the `client_secret_post` path
            // instead, which is the downgrade the registration exists to forbid; the assertion path
            // is `AuthorizationServer::authenticate_client` and it does not come through here.
            #[cfg(feature = "client_assertion")]
            ClientAuth::ConfidentialAssertion { .. } => false,
        }""",
    )


# =================================================================================================
# src/token.rs: the DPoP token type, the binding on the records, and the RFC 7800 confirmation.
# =================================================================================================
def patch_token():
    rel = "src/token.rs"
    load(rel)

    edit(
        rel,
        """    /// RFC 6750 bearer token.
    #[serde(rename = "Bearer")]
    Bearer,
}""",
        """    /// RFC 6750 bearer token.
    #[serde(rename = "Bearer")]
    Bearer,
    /// RFC 9449 section 5 sender-constrained token, bound to the key the client proved possession
    /// of. The spelling is `DPoP`, exactly, because RFC 9449 section 7.1 makes it the HTTP
    /// authentication scheme name the client will present the token under.
    #[cfg(feature = "dpop")]
    #[serde(rename = "DPoP")]
    Dpop,
}""",
    )

    edit(
        rel,
        """/// The RFC 7009 section 2.1 `token_type_hint`.""",
        """/// The RFC 7800 section 3.1 confirmation claim, in the one shape this server produces: the
/// RFC 9449 section 6.1 `jkt`, a JWK thumbprint.
///
/// This is what a resource server checks the binding against, and it is the whole reason DPoP is
/// worth anything at introspection time: without it the binding is known only to the authorization
/// server, and an RS that introspects is back to trusting a bearer string.
#[cfg(feature = "dpop")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// The RFC 7638 SHA-256 thumbprint of the client's proof key, base64url without padding.
    pub jkt: String,
}

#[cfg(feature = "dpop")]
impl Confirmation {
    /// Wrap a thumbprint.
    pub fn jkt(jkt: impl Into<String>) -> Self {
        Confirmation { jkt: jkt.into() }
    }
}

/// The RFC 7009 section 2.1 `token_type_hint`.""",
    )

    edit(
        rel,
        """    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
}""",
        """    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// RFC 9449 section 6.1: the key this token is bound to, present exactly when it is bound to
    /// one.
    ///
    /// RFC 7662 section 2.2 lets a server return any claim it likes here, and RFC 9449 section 5
    /// is explicit that a resource server has to be able to confirm the binding. Omitted rather
    /// than sent as `null` for an unbound token, because `"cnf": null` reads to a careless RS as a
    /// confirmation it has already checked.
    #[cfg(feature = "dpop")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}""",
    )

    edit(
        rel,
        """            iss: None,
            aud: None,
        }""",
        """            iss: None,
            aud: None,
            #[cfg(feature = "dpop")]
            cnf: None,
        }""",
    )

    edit(
        rel,
        """    /// The authorization grant this token belongs to (see [`RefreshTokenRecord::family_id`]).""",
        """    /// RFC 9449 section 6: the RFC 7638 thumbprint of the DPoP key this token is bound to, or
    /// `None` for an ordinary bearer token.
    ///
    /// `Option<Box<str>>` rather than `Option<String>`, and feature gated, because this record is
    /// written and read on every token-plane request and `tests/allocation.rs` holds it to a size
    /// budget: the box is 16 bytes against a `String`'s 24, and a deployment without the `dpop`
    /// feature pays neither. The value is a fixed 43-character base64url digest that is never
    /// appended to, so the growable capacity a `String` carries would be dead weight.
    #[cfg(feature = "dpop")]
    pub jkt: Option<Box<str>>,
    /// The authorization grant this token belongs to (see [`RefreshTokenRecord::family_id`]).""",
    )

    edit(
        rel,
        """            .field("family_id", &self.family_id)
            .finish()
    }
}

/// Whether a persisted refresh token is still redeemable.""",
        """            .field("family_id", &self.family_id)
            .finish()
    }
}

/// Whether a persisted refresh token is still redeemable.""",
    )

    edit(
        rel,
        """    /// The FAMILY this token belongs to: one identifier shared by every token, access or refresh,""",
        """    /// RFC 9449 section 5: the RFC 7638 thumbprint of the DPoP key this refresh chain is bound
    /// to, or `None` for an unbound chain.
    ///
    /// Carried across rotation and CHECKED on redemption. Without it the binding would be
    /// decorative for anything but the first access token: a stolen refresh token could simply be
    /// re-bound to the thief's key on the next rotation, leaving the attacker holding a token they
    /// can prove possession for and the victim's key the one that gets refused.
    #[cfg(feature = "dpop")]
    pub jkt: Option<Box<str>>,
    /// The FAMILY this token belongs to: one identifier shared by every token, access or refresh,""",
    )


# =================================================================================================
# src/metadata.rs: advertise what the two features actually accept.
# =================================================================================================
def patch_metadata():
    rel = "src/metadata.rs"
    load(rel)

    edit(
        rel,
        """    /// RFC 7636 / RFC 8414 section 2. Always exactly `["S256"]`""",
        """    /// RFC 8414 section 2. The signing algorithms the token endpoint accepts on an RFC 7523
    /// client assertion.
    ///
    /// Section 2 makes this REQUIRED whenever `token_endpoint_auth_methods_supported` contains
    /// `client_secret_jwt` or `private_key_jwt`, and the requirement is not bureaucratic: a client
    /// cannot construct an assertion at all without knowing which algorithm the server will accept,
    /// and guessing wrong is indistinguishable from a wrong key. Absent when this build does not
    /// have the `client_assertion` feature, in which case neither method is advertised either.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9449 section 5.1: the JWS algorithms this server will verify a DPoP proof under.
    ///
    /// Its PRESENCE is how a client learns DPoP is available here at all, so it appears only when
    /// this build can actually verify a proof. Advertising it on a server that would refuse every
    /// proof is worse than omitting it, because a client that acts on it has no way to discover the
    /// mistake except by failing to get a token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 7636 / RFC 8414 section 2. Always exactly `["S256"]`""",
    )

    edit(
        rel,
        """            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                // RFC 8414 s2: the registered value a public client uses. This server accepts
                // public clients, so omitting it would understate what it does.
                "none".to_string(),
            ],""",
        """            token_endpoint_auth_methods_supported: {
                // `mut` only matters under `client_assertion`, which is what the allow is for. The
                // alternative is two copies of the list, which is how two lists drift apart.
                #[allow(unused_mut)]
                let mut methods = vec![
                    "client_secret_basic".to_string(),
                    "client_secret_post".to_string(),
                    // RFC 8414 s2: the registered value a public client uses. This server accepts
                    // public clients, so omitting it would understate what it does.
                    "none".to_string(),
                ];
                // RFC 7523 s2.2, advertised exactly when this build can verify an assertion. The
                // list and the verifier are derived from the same feature, so they cannot drift.
                #[cfg(feature = "client_assertion")]
                {
                    methods.push(crate::client_assertion::CLIENT_SECRET_JWT.to_string());
                    methods.push(crate::client_assertion::PRIVATE_KEY_JWT.to_string());
                }
                methods
            },
            #[cfg(feature = "client_assertion")]
            token_endpoint_auth_signing_alg_values_supported: Some(
                crate::client_assertion::ASSERTION_SIGNING_ALGS
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            ),
            #[cfg(not(feature = "client_assertion"))]
            token_endpoint_auth_signing_alg_values_supported: None,
            #[cfg(feature = "dpop")]
            dpop_signing_alg_values_supported: Some(
                crate::dpop::DPOP_SIGNING_ALG_VALUES_SUPPORTED
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            ),
            #[cfg(not(feature = "dpop"))]
            dpop_signing_alg_values_supported: None,""",
    )


# =================================================================================================
# src/server.rs: the endpoint wiring.
# =================================================================================================
def patch_server():
    rel = "src/server.rs"
    load(rel)

    edit(
        rel,
        """use crate::grant::GrantType;""",
        """#[cfg(feature = "client_assertion")]
use crate::client_assertion::{verify_assertion, CLIENT_ASSERTION_TYPE};
#[cfg(feature = "dpop")]
use crate::dpop::verify_proof;
use crate::grant::GrantType;""",
    )

    # ---- config
    edit(
        rel,
        """    /// User code length in symbols, excluding the display hyphen. Default""",
        """    /// RFC 9449: whether EVERY token request must carry a DPoP proof.
    ///
    /// `false` by default, which means "DPoP is available, and a client that wants a
    /// sender-constrained token asks for one by presenting a proof". `true` is the FAPI 2.0
    /// posture: it refuses every token request without a proof, which is a breaking change for
    /// every existing client of the deployment and therefore a sentence somebody has to write on
    /// purpose rather than a default anybody inherits.
    #[cfg(feature = "dpop")]
    pub require_dpop: bool,
    /// User code length in symbols, excluding the display hyphen. Default""",
    )

    edit(
        rel,
        """            user_code_length: MIN_USER_CODE_LENGTH,""",
        """            #[cfg(feature = "dpop")]
            require_dpop: false,
            user_code_length: MIN_USER_CODE_LENGTH,""",
    )

    # ---- the two new public request types, plus the internal per-request bundle
    edit(
        rel,
        """/// Rejections for the host-driven verification-UI actions""",
        '''/// How a client is authenticating on one request.
///
/// A value of its own rather than more fields on every [`TokenRequest`] variant, for the same
/// reason RFC 8707's `resource` is a separate argument: client authentication is a property of the
/// REQUEST and is identical across every grant, so putting it on each variant would state the same
/// thing four times, grow an enum every host copies around, and make each future grant repeat it
/// again.
///
/// [`Default`] is a PUBLIC client: no secret, no assertion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientCredential<'a> {
    /// The RFC 6749 section 2.3.1 shared secret, from `Authorization: Basic` or from the form body.
    /// `None` for a public client, and `None` when an assertion is presented instead.
    pub client_secret: Option<&'a str>,
    /// RFC 7521 section 4.2 `client_assertion_type`. It MUST be
    /// [`crate::client_assertion::CLIENT_ASSERTION_TYPE`]; any other value is refused rather than
    /// ignored, because an assertion format this server does not implement is a credential it
    /// cannot check, and "cannot check" must never read as "checked out".
    #[cfg(feature = "client_assertion")]
    pub client_assertion_type: Option<&'a str>,
    /// RFC 7523 section 2.2 `client_assertion`: the signed JWT itself.
    #[cfg(feature = "client_assertion")]
    pub client_assertion: Option<&'a str>,
}

impl<'a> ClientCredential<'a> {
    /// The credential of a client presenting a shared secret, or of a public client presenting
    /// none.
    pub fn secret(client_secret: Option<&'a str>) -> Self {
        ClientCredential {
            client_secret,
            #[cfg(feature = "client_assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client_assertion")]
            client_assertion: None,
        }
    }

    /// The RFC 7523 credential: the assertion, and the type that names its format.
    #[cfg(feature = "client_assertion")]
    pub fn assertion(client_assertion_type: Option<&'a str>, client_assertion: &'a str) -> Self {
        ClientCredential {
            client_secret: None,
            client_assertion_type,
            client_assertion: Some(client_assertion),
        }
    }

    /// Fall back to the secret carried on the [`TokenRequest`] variant when the context named none,
    /// so a host may present it either way and neither is silently ignored.
    fn or_secret(mut self, secret: Option<&'a str>) -> Self {
        if self.client_secret.is_none() {
            self.client_secret = secret;
        }
        self
    }
}

/// Everything about a token request that is not part of the grant itself.
///
/// Passed by reference to [`AuthorizationServer::token_with_context`]. Growing this struct is
/// cheap; growing [`TokenRequest`] is not, because a host copies that around and
/// `tests/allocation.rs` holds it to a size budget.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenRequestContext<'a> {
    /// How the client is authenticating.
    pub credential: ClientCredential<'a>,
    /// The RFC 8707 `resource` parameters, in wire order.
    pub resources: &'a [String],
    /// The RFC 9449 `DPoP` request header, verbatim and unparsed.
    ///
    /// `None` means the client sent none, which is refused only when
    /// [`ServerConfig::require_dpop`] is set. When it is present and valid, the issued token is
    /// BOUND to the proof's key: `token_type` becomes `DPoP` and RFC 7662 introspection reports
    /// `cnf.jkt`.
    #[cfg(feature = "dpop")]
    pub dpop_proof: Option<&'a str>,
}

/// What each grant helper needs about the REQUEST rather than about the grant.
///
/// One reference wide at every call site, which is actually SMALLER than the `Option<&str>` client
/// secret it replaces there. That is not incidental: these helpers are the token future, and
/// `tests/allocation.rs` fails if that future crosses tokio's 2048-byte debug boxing threshold.
pub(crate) struct Bound<'a> {
    /// The credential to authenticate with.
    pub(crate) cred: ClientCredential<'a>,
    /// The RFC 9449 section 6.1 thumbprint the issued token must be bound to, when the request
    /// carried a valid proof.
    #[cfg(feature = "dpop")]
    pub(crate) jkt: Option<&'a str>,
}

impl<'a> Bound<'a> {
    /// A request authenticating with a shared secret and asking for no RFC 9449 binding.
    ///
    /// For the grant surfaces that reach `issue` from outside this module (RFC 8693 token
    /// exchange). They get an unbound token, which is honest: they have not been given a proof to
    /// bind one to. Wiring DPoP into them is a matter of threading a `Bound` in, not of changing
    /// anything here.
    ///
    /// `dead_code` because its only caller is behind another slice's cargo feature, and gating it
    /// on that feature by name would tie this module to a flag it has no other business knowing.
    #[allow(dead_code)]
    pub(crate) fn secret(client_secret: Option<&'a str>) -> Self {
        Bound {
            cred: ClientCredential::secret(client_secret),
            #[cfg(feature = "dpop")]
            jkt: None,
        }
    }
}

/// Rejections for the host-driven verification-UI actions''',
    )

    # ---- authenticate_client
    edit(
        rel,
        """    pub(crate) async fn authenticate_client(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
    ) -> Result<Client, ErrorResponse> {""",
        """    pub(crate) async fn authenticate_client(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
    ) -> Result<Client, ErrorResponse> {""",
    )

    edit(
        rel,
        """        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this
        // crate does not implement is decided by the host's verifier (see
        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.
        if !client
            .auth
            .verify_with(client_secret, self.hooks.secret_verifier())
        {""",
        """        // RFC 7523 client authentication, when the request presented an assertion. Handled apart
        // from the secret comparison below because it is a different KIND of credential: there is
        // nothing to compare, there is a signature to verify against the REGISTRATION's key and a
        // `jti` to spend so the request cannot be repeated.
        #[cfg(feature = "client_assertion")]
        if cred.client_assertion.is_some() {
            // BOXED at the call site, and this is a measurement rather than a style. `authenticate_client`
            // is inlined into all four grant helpers and so into the token future, which
            // `tests/allocation.rs` holds under tokio's 2048-byte debug boxing threshold. Inlining
            // the assertion state (a claim set, two owned Strings, a storage future) into every
            // token request, including the overwhelming majority that carry no assertion, pushed it
            // over: the gate caught it. One allocation, paid only on the path that actually
            // presents an assertion.
            return match Box::pin(self.authenticate_by_assertion(&client, cred)).await {
                Ok(()) => {
                    self.hooks.record(attempt, AttemptOutcome::Succeeded);
                    Ok(client)
                }
                Err(error) => {
                    self.hooks.record(attempt, AttemptOutcome::Failed);
                    self.hooks.emit(|| Event::ClientAuthenticationFailed {
                        client_id: client_id.as_str(),
                        failure: ClientAuthFailure::AssertionInvalid,
                    });
                    Err(error)
                }
            };
        }

        // `verify_with` rather than `verify`: a registration stored as a hash in a scheme this
        // crate does not implement is decided by the host's verifier (see
        // `crate::client::SecretVerifier`), and by nobody at all when none is installed.
        if !client
            .auth
            .verify_with(cred.client_secret, self.hooks.secret_verifier())
        {""",
    )

    edit(
        rel,
        """    /// Resolve the scope a request will be granted: the client default when the request names""",
        '''    /// RFC 7523 section 3, plus the single-use claim that makes it worth anything.
    ///
    /// Returns `Ok(())` for an authenticated client. Every refusal is the SAME bare
    /// `invalid_client` the wrong-secret path returns, with no description: this function is only
    /// reached once the client id is known to exist, so a description naming which check failed
    /// would be the difference between "this client id is real" and "it is not", which is exactly
    /// the distinction `authenticate_client` collapses on purpose. The host's audit channel is
    /// told (`ClientAuthFailure::AssertionInvalid`); the wire is not.
    #[cfg(feature = "client_assertion")]
    async fn authenticate_by_assertion(
        &self,
        client: &Client,
        cred: &ClientCredential<'_>,
    ) -> Result<(), ErrorResponse> {
        let refused = || ErrorResponse::new(ErrorCode::InvalidClient);
        let assertion = cred.client_assertion.ok_or_else(refused)?;

        // RFC 7521 section 4.2: the type is what says which assertion format this is, and this
        // server implements exactly one. An absent or unrecognised type is refused rather than
        // assumed, because assuming would mean verifying a credential in a format nobody declared.
        if cred.client_assertion_type != Some(CLIENT_ASSERTION_TYPE) {
            return Err(refused());
        }
        // RFC 6749 section 2.3: "The client MUST NOT use more than one authentication method in
        // each request." A request carrying both a secret and an assertion has not said which
        // credential it means, and a server that picks one behaves differently from the next
        // server, which is exactly the ambiguity an intermediary would exploit.
        if cred.client_secret.is_some() {
            return Err(refused());
        }

        // THE REGISTRATION DECIDES, and this is where that starts. A client registered for
        // `client_secret_basic` cannot promote itself to `private_key_jwt` by sending an assertion,
        // because there is no key here that anybody vouched for on its behalf.
        let keys = match &client.auth {
            crate::client::ClientAuth::ConfidentialAssertion { keys } => keys,
            _ => return Err(refused()),
        };

        // RFC 7523 section 3 (3) admits either the token endpoint URL or, by long-established
        // practice (OpenID Connect Core section 9), the issuer identifier.
        let token_endpoint = self.token_endpoint();
        let verified = verify_assertion(
            keys,
            assertion,
            client.client_id.as_str(),
            &[token_endpoint.as_str(), self.issuer_identifier()],
            self.clock.now(),
        )
        .map_err(|_| refused())?;

        // RFC 7523 section 3: the `jti` is single use within the assertion's validity. THIS is the
        // check that makes an observed request unrepeatable, and it is the whole difference between
        // an authentication mechanism and a bearer credential that happens to be signed. It is
        // namespaced by client id so that two clients choosing the same `jti` (a counter, a
        // timestamp) cannot lock each other out.
        let claimed = self
            .store
            .claim_replay_id(
                &replay_key("ca", client.client_id.as_str(), &verified.jti),
                verified.expires_at,
            )
            .await
            // FAILING CLOSED. A claim that could not be recorded is a claim that did not happen,
            // and treating a storage outage as "probably fine" would turn every assertion into a
            // replayable one for the duration of the outage.
            .map_err(|_| refused())?;
        if !claimed {
            return Err(refused());
        }
        Ok(())
    }

    /// The token endpoint URL this server answers on, which is what RFC 7523 section 3 (3) and RFC
    /// 9449 section 4.3 (7) compare against.
    ///
    /// Derived the same way `AuthorizationServerMetadata::from_config` derives it, and it MUST stay
    /// that way: the document tells a client where to send its request and what to put in `aud` and
    /// `htu`, so a server whose own idea of its token endpoint differs from the one it published
    /// refuses every conforming client.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    fn token_endpoint(&self) -> String {
        match &self.config.token_endpoint {
            Some(endpoint) => endpoint.clone(),
            None => format!("{}/token", self.issuer_identifier()),
        }
    }

    /// RFC 9449 section 4.3, and the single-use claim on the proof's `jti`.
    ///
    /// The proof is checked BEFORE the grant is looked at, because it binds to the REQUEST rather
    /// than to the grant: a proof that does not verify means this request is refused whatever it
    /// asked for, and spending its `jti` here means a replayed proof costs the attacker a lookup
    /// and gains them nothing.
    ///
    /// `htm` is `POST` because RFC 6749 section 3.2 makes the token endpoint POST-only, and `htu`
    /// is this server's own token endpoint rather than something the host passes in. That is
    /// deliberate: the value a conforming client puts in `htu` is the one it read from the RFC 8414
    /// document, which is exactly what `token_endpoint` returns, so taking it from the host would
    /// add a seam whose only possible use is to get it wrong.
    #[cfg(feature = "dpop")]
    async fn verify_dpop(&self, proof: Option<&str>) -> Result<Option<Box<str>>, ErrorResponse> {
        let proof = match proof {
            Some(proof) => proof,
            None if self.config.require_dpop => {
                return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)
                    .with_description("this server requires a DPoP proof on every token request"))
            }
            None => return Ok(None),
        };
        let verified = verify_proof(proof, "POST", &self.token_endpoint(), self.clock.now())
            .map_err(|_| ErrorResponse::new(ErrorCode::InvalidDpopProof))?;
        // Namespaced by THUMBPRINT rather than by client id: a proof is bound to a key, not to a
        // registration (a public client's proof arrives before anything has authenticated), so the
        // key is the only identity available at this point that an attacker cannot choose freely.
        let claimed = self
            .store
            .claim_replay_id(
                &replay_key("dpop", &verified.jkt, &verified.jti),
                verified.replay_until,
            )
            .await
            .map_err(storage_error)?;
        if !claimed {
            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)
                .with_description("this DPoP proof has already been used"));
        }
        Ok(Some(verified.jkt.into_boxed_str()))
    }

    /// Resolve the scope a request will be granted: the client default when the request names''',
    )

    # ---- device_authorization: keep the old signature, add the credential-taking form
    edit(
        rel,
        """    pub async fn device_authorization(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
                .with_description("client registration does not include the device_code grant"));""",
        """    pub async fn device_authorization(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        self.device_authorization_with_credential(
            client_id,
            &ClientCredential::secret(client_secret),
            requested_scope,
        )
        .await
    }

    /// RFC 8628 section 3.1/3.2 for a client authenticating with any credential this server
    /// accepts, including an RFC 7523 assertion.
    ///
    /// Added ALONGSIDE [`AuthorizationServer::device_authorization`] rather than replacing it: the
    /// three-argument form is what every existing host already calls and a shared secret remains
    /// the commonest credential. Both go through the same `authenticate_client`, so there is one
    /// authentication path and not two.
    pub async fn device_authorization_with_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        requested_scope: Option<&ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, cred).await?;
        if !client.allows_grant(GrantType::DeviceCode) {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
                .with_description("client registration does not include the device_code grant"));""",
    )

    # ---- the token entry points
    edit(
        rel,
        """    pub async fn token(&self, request: TokenRequest) -> Result<TokenResponse, ErrorResponse> {
        self.token_with_resources(request, &[]).await
    }""",
        """    pub fn token(
        &self,
        request: TokenRequest,
    ) -> impl std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + '_ {
        self.token_with_resources(request, &[])
    }""",
    )

    edit(
        rel,
        """    pub async fn token_with_resources(
        &self,
        request: TokenRequest,
        resources: &[String],
    ) -> Result<TokenResponse, ErrorResponse> {""",
        """    pub fn token_with_resources<'a>(
        &'a self,
        request: TokenRequest,
        resources: &'a [String],
    ) -> impl std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + 'a {""",
    )

    edit(
        rel,
        """        let requested_resources = Self::validate_resources(resources.iter().map(|r| r.as_str()))?;
        match request {""",
        """        self.token_with_context(
            request,
            TokenRequestContext {
                resources,
                ..Default::default()
            },
        )
    }

    /// The token endpoint with everything about the request that does not belong inside
    /// [`TokenRequest`]: the RFC 8707 resource indicators, the RFC 7523 client assertion, and the
    /// RFC 9449 DPoP proof.
    ///
    /// [`AuthorizationServer::token`] and [`AuthorizationServer::token_with_resources`] are this
    /// with an emptier context, so there is one implementation of the token endpoint and not three.
    /// Both of them are plain functions returning THIS future rather than `async fn`s that await
    /// it, and that is a measurement rather than a style: an `async fn` wrapper is a second
    /// generator frame holding its own copy of the 160-byte [`TokenRequest`] while the inner future
    /// holds another, and adding one pushed the token future over tokio's 2048-byte debug boxing
    /// threshold. `tests/allocation.rs` caught it.
    ///
    /// The client secret may be presented EITHER on the [`TokenRequest`] variant (where it has
    /// always lived) or on [`TokenRequestContext::credential`]; the context wins when both are set,
    /// and neither is silently dropped.
    pub async fn token_with_context(
        &self,
        request: TokenRequest,
        context: TokenRequestContext<'_>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let requested_resources =
            Self::validate_resources(context.resources.iter().map(|r| r.as_str()))?;
        // RFC 9449 s4.3, before anything else touches the store: see `verify_dpop`.
        #[cfg(feature = "dpop")]
        let jkt = Box::pin(self.verify_dpop(context.dpop_proof)).await?;
        match request {""",
    )

    edit(
        rel,
        """                let outcome = self
                    .authorization_code_token(
                        &client_id,
                        client_secret.as_deref(),
                        &code,
                        redirect_uri.as_deref(),
                        code_verifier.as_deref(),
                        &requested_resources,
                    )
                    .await;""",
        """                let bound = Bound {
                    cred: context.credential.or_secret(client_secret.as_deref()),
                    #[cfg(feature = "dpop")]
                    jkt: jkt.as_deref(),
                };
                let outcome = self
                    .authorization_code_token(
                        &client_id,
                        &bound,
                        &code,
                        redirect_uri.as_deref(),
                        code_verifier.as_deref(),
                        &requested_resources,
                    )
                    .await;""",
    )

    edit(
        rel,
        """                let outcome = self
                    .client_credentials_token(
                        &client_id,
                        client_secret.as_deref(),
                        scope.as_ref(),
                        requested_resources,
                    )
                    .await;""",
        """                let bound = Bound {
                    cred: context.credential.or_secret(client_secret.as_deref()),
                    #[cfg(feature = "dpop")]
                    jkt: jkt.as_deref(),
                };
                let outcome = self
                    .client_credentials_token(
                        &client_id,
                        &bound,
                        scope.as_ref(),
                        requested_resources,
                    )
                    .await;""",
    )

    edit(
        rel,
        """                let outcome = self
                    .device_token(&client_id, client_secret.as_deref(), &device_code)
                    .await;""",
        """                let bound = Bound {
                    cred: context.credential.or_secret(client_secret.as_deref()),
                    #[cfg(feature = "dpop")]
                    jkt: jkt.as_deref(),
                };
                let outcome = self.device_token(&client_id, &bound, &device_code).await;""",
    )

    edit(
        rel,
        """                let outcome = self
                    .refresh_token(
                        &client_id,
                        client_secret.as_deref(),
                        &refresh_token,
                        scope.as_ref(),
                        &requested_resources,
                    )
                    .await;""",
        """                let bound = Bound {
                    cred: context.credential.or_secret(client_secret.as_deref()),
                    #[cfg(feature = "dpop")]
                    jkt: jkt.as_deref(),
                };
                let outcome = self
                    .refresh_token(
                        &client_id,
                        &bound,
                        &refresh_token,
                        scope.as_ref(),
                        &requested_resources,
                    )
                    .await;""",
    )

    # ---- the four grant helpers
    edit(
        rel,
        """        client_secret: Option<&str>,
        code: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        requested_resources: &[String],
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;
        if !client.allows_grant(GrantType::AuthorizationCode) {""",
        """        bound: &Bound<'_>,
        code: &str,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        requested_resources: &[String],
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;
        if !client.allows_grant(GrantType::AuthorizationCode) {""",
    )

    edit(
        rel,
        """        client_secret: Option<&str>,
        requested_scope: Option<&ScopeSet>,
        resource: Vec<String>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;""",
        """        bound: &Bound<'_>,
        requested_scope: Option<&ScopeSet>,
        resource: Vec<String>,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;""",
    )

    edit(
        rel,
        """        client_secret: Option<&str>,
        device_code: &str,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;""",
        """        bound: &Bound<'_>,
        device_code: &str,
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;""",
    )

    edit(
        rel,
        """        client_secret: Option<&str>,
        refresh_token: &str,
        requested_scope: Option<&ScopeSet>,
        requested_resources: &[String],
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;""",
        """        bound: &Bound<'_>,
        refresh_token: &str,
        requested_scope: Option<&ScopeSet>,
        requested_resources: &[String],
    ) -> Result<TokenResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, &bound.cred).await?;""",
    )

    # ---- RFC 9449 s5: a bound refresh chain stays bound to the same key
    edit(
        rel,
        """        if let Some(expires_at) = record.expires_at {
            if self.clock.now() >= expires_at {""",
        """        // RFC 9449 s5: a refresh chain issued to a DPoP-bound grant stays bound to the SAME key,
        // and a rotation has to prove possession of it. Without this the binding would be
        // decorative past the first access token: a stolen refresh token could simply be re-bound
        // to the thief's key on the next rotation, leaving the attacker holding a token they can
        // prove possession for while the victim's key is the one refused. The record goes BACK, as
        // for every other judgement here that is not evidence of compromise.
        #[cfg(feature = "dpop")]
        if record.jkt.as_deref() != bound.jkt {
            self.store
                .put_refresh_token(record)
                .await
                .map_err(storage_error)?;
            return Err(ErrorResponse::new(ErrorCode::InvalidDpopProof)
                .with_description("this refresh token is bound to a different DPoP key"));
        }

        if let Some(expires_at) = record.expires_at {
            if self.clock.now() >= expires_at {""",
    )

    # ---- issue()
    edit(
        rel,
        """    pub(crate) async fn issue(
        &self,
        client: &Client,
        grant_type: GrantType,""",
        """    /// [`AuthorizationServer::issue`] behind one heap allocation.
    ///
    /// Every caller of `issue` goes through here, and the reason is a measurement rather than a
    /// preference. `issue` is the widest frame on the token path: it holds a whole `IssuedToken`
    /// and a whole `RefreshTokenRecord` across its storage awaits, and because a generator's size
    /// is the MAXIMUM over all of its states, that width is paid by every token request including
    /// the polls and refusals that never issue anything. Inlined, it puts the token future over
    /// tokio's 2048-byte debug boxing threshold as soon as `dpop` adds a binding to both records,
    /// and tokio's answer to that is to box the WHOLE token future on every single request.
    ///
    /// So: one allocation, paid only when a token is actually issued, instead of one allocation the
    /// size of the entire token future paid on every request that reaches this endpoint. The
    /// allocation gates in `tests/allocation.rs` are what settled this, and they measure both.
    #[allow(clippy::too_many_arguments)]
    fn issue_boxed<'a>(
        &'a self,
        client: &'a Client,
        bound: &'a Bound<'_>,
        grant_type: GrantType,
        subject: Option<String>,
        scope: ScopeSet,
        resource: Vec<String>,
        chain: Option<RefreshChain>,
        allow_refresh: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TokenResponse, ErrorResponse>> + Send + 'a>>
    {
        Box::pin(self.issue(
            client,
            bound,
            grant_type,
            subject,
            scope,
            resource,
            chain,
            allow_refresh,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn issue(
        &self,
        client: &Client,
        bound: &Bound<'_>,
        grant_type: GrantType,""",
    )

    edit(
        rel,
        """            .issue(
                &client,
                GrantType::AuthorizationCode,""",
        """            .issue_boxed(
                &client,
                bound,
                GrantType::AuthorizationCode,""",
    )

    edit(
        rel,
        """        self.issue(
            &client,
            GrantType::ClientCredentials,""",
        """        self.issue_boxed(
            &client,
            bound,
            GrantType::ClientCredentials,""",
    )

    edit(
        rel,
        """                self.issue(
                    &client,
                    GrantType::DeviceCode,""",
        """                self.issue_boxed(
                    &client,
                    bound,
                    GrantType::DeviceCode,""",
    )

    edit(
        rel,
        """            .issue(
                &client,
                GrantType::RefreshToken,""",
        """            .issue_boxed(
                &client,
                bound,
                GrantType::RefreshToken,""",
    )

    edit(
        rel,
        """            .put_token(IssuedToken {
                access_token: access_token.clone(),""",
        """            .put_token(IssuedToken {
                // RFC 9449 s6: the binding is recorded on the AS side too, not only in the token,
                // so that RFC 7662 introspection can report it and a resource server can check it
                // without having to parse a token this server may have issued as opaque.
                #[cfg(feature = "dpop")]
                jkt: bound.jkt.map(Box::from),
                access_token: access_token.clone(),""",
    )

    edit(
        rel,
        """                .put_refresh_token(RefreshTokenRecord {
                    refresh_token: rt.clone(),""",
        """                .put_refresh_token(RefreshTokenRecord {
                    // RFC 9449 s5: the chain remembers the key it was issued to, and rotation
                    // checks it. See the check in `refresh_token`.
                    #[cfg(feature = "dpop")]
                    jkt: bound.jkt.map(Box::from),
                    refresh_token: rt.clone(),""",
    )

    edit(
        rel,
        """        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer,""",
        """        Ok(TokenResponse {
            access_token,
            // RFC 9449 s5: a token bound to a proof key is a `DPoP` token and not a `Bearer` one,
            // and the difference is exactly what tells the client, and any resource server reading
            // the response, that the token must be presented with a proof.
            #[cfg(feature = "dpop")]
            token_type: match bound.jkt {
                Some(_) => TokenType::Dpop,
                None => TokenType::Bearer,
            },
            #[cfg(not(feature = "dpop"))]
            token_type: TokenType::Bearer,""",
    )

    # ---- introspection
    edit(
        rel,
        """    pub async fn introspection_response(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
    ) -> Result<IntrospectionResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;""",
        """    pub async fn introspection_response(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
    ) -> Result<IntrospectionResponse, ErrorResponse> {
        self.introspection_response_with_credential(
            client_id,
            &ClientCredential::secret(client_secret),
            token,
        )
        .await
    }

    /// RFC 7662 introspection for a caller authenticating with any credential this server accepts,
    /// including an RFC 7523 assertion. See
    /// [`AuthorizationServer::device_authorization_with_credential`] on why this is an addition
    /// rather than a replacement.
    pub async fn introspection_response_with_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        token: &str,
    ) -> Result<IntrospectionResponse, ErrorResponse> {
        let client = self.authenticate_client(client_id, cred).await?;""",
    )

    edit(
        rel,
        """                token_type: Some(TokenType::Bearer),""",
        """                #[cfg(feature = "dpop")]
                token_type: Some(match t.jkt {
                    Some(_) => TokenType::Dpop,
                    None => TokenType::Bearer,
                }),
                #[cfg(not(feature = "dpop"))]
                token_type: Some(TokenType::Bearer),""",
    )

    edit(
        rel,
        """                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),""",
        """                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),
                // RFC 9449 s6.1 with RFC 7800 s3.1. A resource server that introspects must be
                // able to confirm the binding, or the binding stops at this server and the RS is
                // back to trusting a bearer string.
                #[cfg(feature = "dpop")]
                cnf: t
                    .jkt
                    .as_deref()
                    .map(crate::token::Confirmation::jkt),""",
    )

    # ---- revocation
    edit(
        rel,
        """    pub async fn revoke(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
        token_type_hint: Option<TokenTypeHint>,
    ) -> Result<(), ErrorResponse> {
        let client = self.authenticate_client(client_id, client_secret).await?;""",
        """    pub async fn revoke(
        &self,
        client_id: &ClientId,
        client_secret: Option<&str>,
        token: &str,
        token_type_hint: Option<TokenTypeHint>,
    ) -> Result<(), ErrorResponse> {
        self.revoke_with_credential(
            client_id,
            &ClientCredential::secret(client_secret),
            token,
            token_type_hint,
        )
        .await
    }

    /// RFC 7009 revocation for a caller authenticating with any credential this server accepts,
    /// including an RFC 7523 assertion. See
    /// [`AuthorizationServer::device_authorization_with_credential`] on why this is an addition
    /// rather than a replacement.
    pub async fn revoke_with_credential(
        &self,
        client_id: &ClientId,
        cred: &ClientCredential<'_>,
        token: &str,
        token_type_hint: Option<TokenTypeHint>,
    ) -> Result<(), ErrorResponse> {
        let client = self.authenticate_client(client_id, cred).await?;""",
    )

    edit(
        rel,
        """    ) -> Result<TokenResponse, ErrorResponse> {
        let now = self.clock.now();

        let issues_refresh = allow_refresh""",
        """    ) -> Result<TokenResponse, ErrorResponse> {
        // `bound` carries only the RFC 9449 key binding, so with that feature off it is genuinely
        // unused HERE. It stays in the signature regardless, so the four call sites do not have to
        // differ by feature: a call site that differs by feature is a call site that gets it wrong
        // under the configuration nobody builds locally.
        #[cfg(not(feature = "dpop"))]
        let _ = bound;
        let now = self.clock.now();

        let issues_refresh = allow_refresh""",
    )

    # ---- the replay key helper
    edit(
        rel,
        """fn storage_error(e: StorageError) -> ErrorResponse {""",
        '''/// The storage key one single-use identifier is claimed under.
///
/// NAMESPACED, and both halves matter. `kind` keeps an RFC 7523 assertion's `jti` from colliding
/// with an RFC 9449 proof's, which are different credentials with different lifetimes that a client
/// may well number from the same counter. `owner` (the client id for an assertion, the key
/// thumbprint for a proof) keeps one client from locking another out by choosing its `jti` values:
/// without it, an attacker could spend a victim's future `jti` values in advance, which is a denial
/// of service bought for the price of a refused request.
///
/// One allocation per assertion or proof, on a path that only exists when the feature is on.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
fn replay_key(kind: &str, owner: &str, jti: &str) -> String {
    let mut key = String::with_capacity(kind.len() + owner.len() + jti.len() + 2);
    key.push_str(kind);
    key.push(':');
    key.push_str(owner);
    key.push(':');
    key.push_str(jti);
    key
}

fn storage_error(e: StorageError) -> ErrorResponse {''',
    )


# =================================================================================================
# src/token_exchange.rs: the RFC 8693 slice calls the two functions whose signatures moved.
#
# Applied only if that module is present, because the two slices land independently and neither
# should be able to block the other.
# =================================================================================================
def patch_token_exchange():
    rel = "src/token_exchange.rs"
    if not os.path.exists(os.path.join(CRATE, rel)):
        sys.stdout.write("src/token_exchange.rs absent; skipping its call sites\n")
        return
    load(rel)
    edit(
        rel,
        "use crate::server::{AuthorizationServer, Clock};",
        "use crate::server::{AuthorizationServer, Bound, Clock};",
    )
    edit(
        rel,
        "        .authenticate_client(request.client_id, request.client_secret)",
        "        .authenticate_client(request.client_id, &bound.cred)",
    )
    edit(
        rel,
        """    let client = server
        .authenticate_client(""",
        """    // RFC 8693 s2.1 authenticates the client the same way every other grant does, so it goes
    // through the same value. No RFC 9449 binding: this surface is not handed a proof, and a token
    // that claimed a binding nobody proved would be worse than an honest bearer token.
    let bound = Bound::secret(request.client_secret);
    let client = server
        .authenticate_client(""",
    )
    edit(
        rel,
        """        .issue(
            &client,
            GrantType::TokenExchange,""",
        """        .issue(
            &client,
            &bound,
            GrantType::TokenExchange,""",
    )


# =================================================================================================
# src/events.rs: the audit channel learns to name an assertion failure.
# =================================================================================================
def patch_events():
    rel = "src/events.rs"
    load(rel)
    edit(
        rel,
        """    /// The host's own [`RateLimiter`] refused the attempt before it was evaluated.
    RateLimited,
}""",
        """    /// The host's own [`RateLimiter`] refused the attempt before it was evaluated.
    RateLimited,
    /// The registration exists and an RFC 7523 client assertion was presented that did not verify:
    /// a bad signature, an `alg` the registration does not use, an audience naming another server,
    /// an expired assertion, or a `jti` that had already been spent.
    ///
    /// Separated from [`ClientAuthFailure::SecretMismatch`] because the responses differ. A run of
    /// wrong secrets is credential stuffing; a run of REPLAYED assertions is somebody who has
    /// captured a client's traffic, which is a different incident and a much worse one.
    #[cfg(feature = "client_assertion")]
    AssertionInvalid,
}""",
    )


# =================================================================================================
# src/lib.rs: module declarations and re-exports.
# =================================================================================================
def patch_lib():
    rel = "src/lib.rs"
    load(rel)

    edit(
        rel,
        """pub mod authorization;
pub mod client;
pub mod device;""",
        """pub mod authorization;
pub mod client;
/// RFC 7523 JWT client authentication (`private_key_jwt`, `client_secret_jwt`), behind the
/// `client_assertion` cargo feature (off by default, and implying `jwt`). Without it a deployment
/// whose security policy forbids transmitting a shared secret cannot use this crate at all.
#[cfg(feature = "client_assertion")]
pub mod client_assertion;
pub mod device;
/// RFC 9449 DPoP sender-constrained access tokens, behind the `dpop` cargo feature (off by
/// default, and implying `jwt`). Without it every token this crate issues is a bearer token, so a
/// stolen one is usable by whoever stole it.
#[cfg(feature = "dpop")]
pub mod dpop;""",
    )

    edit(
        rel,
        """pub use client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash, SecretVerifier};""",
        """pub use client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash, SecretVerifier};
#[cfg(feature = "client_assertion")]
pub use client_assertion::{
    AssertionFailure, AssertionKeys, VerifiedAssertion, CLIENT_ASSERTION_TYPE, CLIENT_SECRET_JWT,
    PRIVATE_KEY_JWT,
};
#[cfg(feature = "dpop")]
pub use dpop::{DpopFailure, VerifiedProof, DPOP_HEADER, DPOP_TOKEN_TYPE};""",
    )

    edit(
        rel,
        """pub use server::{
    AuthorizationServer, Clock, DeviceApprovalError, ServerConfig, SystemClock, TokenRequest,
    MIN_USER_CODE_LENGTH,
};""",
        """pub use server::{
    AuthorizationServer, ClientCredential, Clock, DeviceApprovalError, ServerConfig, SystemClock,
    TokenRequest, TokenRequestContext, MIN_USER_CODE_LENGTH,
};""",
    )

    edit(
        rel,
        """pub use token::{
    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,
    TokenType, TokenTypeHint,
};""",
        """#[cfg(feature = "dpop")]
pub use token::Confirmation;
pub use token::{
    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,
    TokenType, TokenTypeHint,
};""",
    )


# =================================================================================================
# src/http.rs: read the two new credentials off the wire.
# =================================================================================================
def patch_http():
    rel = "src/http.rs"
    load(rel)

    edit(
        rel,
        """/// Authenticated (or merely identified) client credentials from one request.
#[derive(Debug)]
struct Credentials {
    client_id: String,
    /// `None` for a public client, which has no secret to present.
    client_secret: Option<String>,
}""",
        """/// Authenticated (or merely identified) client credentials from one request.
#[derive(Debug)]
struct Credentials {
    client_id: String,
    /// `None` for a public client, which has no secret to present.
    client_secret: Option<String>,
    /// RFC 7521 s4.2 `client_assertion_type`, verbatim.
    #[cfg(feature = "client_assertion")]
    client_assertion_type: Option<String>,
    /// RFC 7523 `client_assertion`, verbatim.
    #[cfg(feature = "client_assertion")]
    client_assertion: Option<String>,
}

impl Credentials {
    /// The borrowed form the server takes. Borrowed rather than owned so that reading a credential
    /// off the wire costs the same as it did before these two parameters existed.
    fn credential(&self) -> crate::server::ClientCredential<'_> {
        crate::server::ClientCredential {
            client_secret: self.client_secret.as_deref(),
            #[cfg(feature = "client_assertion")]
            client_assertion_type: self.client_assertion_type.as_deref(),
            #[cfg(feature = "client_assertion")]
            client_assertion: self.client_assertion.as_deref(),
        }
    }
}""",
    )

    edit(
        rel,
        """fn credentials(headers: &HeaderMap, form: &[Pair<'_>]) -> Result<Credentials, ErrorResponse> {
    let basic = basic_attempted(headers);
    let body_id = param(form, "client_id");
    let body_secret = param(form, "client_secret");
    match (basic, body_id, body_secret) {""",
        """fn credentials(headers: &HeaderMap, form: &[Pair<'_>]) -> Result<Credentials, ErrorResponse> {
    let basic = basic_attempted(headers);
    let body_id = param(form, "client_id");
    let body_secret = param(form, "client_secret");

    // RFC 7523 s2.2 / RFC 7521 s4.2. Handled BEFORE the three older methods, because an assertion
    // is a complete client authentication on its own and s2.2 makes `client_id` OPTIONAL alongside
    // it: the assertion already names the client, so requiring the parameter would refuse a
    // conforming client over a redundancy.
    #[cfg(feature = "client_assertion")]
    if let Some(assertion) = param(form, "client_assertion") {
        // RFC 6749 s2.3: one authentication method per request. Basic credentials or a
        // `client_secret` alongside an assertion is two, and a server that resolves the ambiguity
        // by precedence is a server whose behaviour differs from the next one's.
        if basic || body_secret.is_some() {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("more than one client authentication method (RFC 6749 s2.3)"));
        }
        // UNVERIFIED, and only used to LOCATE the registration. The registration then decides the
        // algorithm and the key, and `verify_assertion` re-checks `iss`/`sub` against the client id
        // resolved here, so nothing is trusted on the strength of this read. A form `client_id`
        // wins when present, because that is the value the client explicitly asserted.
        let client_id = match body_id {
            Some(id) => id.to_string(),
            None => crate::client_assertion::unverified_subject(assertion)
                .ok_or_else(|| {
                    ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("the client assertion names no client")
                })?
                .to_string(),
        };
        return Ok(Credentials {
            client_id,
            client_secret: None,
            client_assertion_type: param(form, "client_assertion_type").map(str::to_string),
            client_assertion: Some(assertion.to_string()),
        });
    }

    match (basic, body_id, body_secret) {""",
    )

    edit(
        rel,
        """            let (client_id, client_secret) = decode_basic(headers)?;
            Ok(Credentials {
                client_id,
                client_secret: Some(client_secret),
            })""",
        """            let (client_id, client_secret) = decode_basic(headers)?;
            Ok(Credentials {
                client_id,
                client_secret: Some(client_secret),
                #[cfg(feature = "client_assertion")]
                client_assertion_type: None,
                #[cfg(feature = "client_assertion")]
                client_assertion: None,
            })""",
    )

    edit(
        rel,
        """        (false, Some(id), secret) => Ok(Credentials {
            client_id: id.to_string(),
            client_secret: secret.map(str::to_string),
        }),""",
        """        (false, Some(id), secret) => Ok(Credentials {
            client_id: id.to_string(),
            client_secret: secret.map(str::to_string),
            #[cfg(feature = "client_assertion")]
            client_assertion_type: None,
            #[cfg(feature = "client_assertion")]
            client_assertion: None,
        }),""",
    )

    # --- the token handler
    edit(
        rel,
        """    let creds = match credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let client_id = ClientId::new(creds.client_id);
    let client_secret = creds.client_secret;""",
        """    let creds = match credentials(&headers, &form) {
        Ok(c) => c,
        Err(e) => return error_response(&e, via_header, &state.challenge),
    };
    let client_id = ClientId::new(creds.client_id.clone());
    // NOT moved onto the TokenRequest variant any more: every credential this endpoint accepts now
    // travels together on the request CONTEXT, so there is one place a reader has to look to see
    // what the client presented, rather than one for secrets and another for everything else.
    let client_secret: Option<String> = None;""",
    )

    edit(
        rel,
        """    // RFC 8707 s2: `resource` is a parameter of the token request itself, independent of
    // `grant_type`, so it is collected once here rather than inside each arm above.
    let resources = resource_indicators(&form);
    match state.server.token_with_resources(request, &resources).await {
        Ok(response) => ok_json(&response),
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}""",
        """    // RFC 8707 s2: `resource` is a parameter of the token request itself, independent of
    // `grant_type`, so it is collected once here rather than inside each arm above.
    let resources = resource_indicators(&form);

    // RFC 9449 s4.3 (1): there must be exactly ONE `DPoP` header. Several is not a request this
    // server may pick a favourite from: an intermediary that appended one, or a client that sent
    // two, leaves it ambiguous which proof the client meant to bind the token to.
    #[cfg(feature = "dpop")]
    let dpop_proof = {
        let mut values = headers.get_all(crate::dpop::DPOP_HEADER).iter();
        let first = values.next();
        if values.next().is_some() {
            return error_response(
                &ErrorResponse::new(ErrorCode::InvalidDpopProof)
                    .with_description("more than one DPoP header (RFC 9449 s4.3)"),
                via_header,
                &state.challenge,
            );
        }
        match first.map(|v| v.to_str()) {
            None => None,
            Some(Ok(value)) => Some(value),
            // A header that is not visible ASCII cannot be a compact JWS, so this is a malformed
            // proof rather than an absent one, and answering "absent" would silently downgrade a
            // client that asked for a bound token to a bearer one.
            Some(Err(_)) => {
                return error_response(
                    &ErrorResponse::new(ErrorCode::InvalidDpopProof)
                        .with_description("the DPoP header is not a compact JWS"),
                    via_header,
                    &state.challenge,
                )
            }
        }
    };

    let context = crate::server::TokenRequestContext {
        credential: creds.credential(),
        resources: &resources,
        #[cfg(feature = "dpop")]
        dpop_proof,
    };
    match state.server.token_with_context(request, context).await {
        Ok(response) => ok_json(&response),
        Err(e) => error_response(&e, via_header, &state.challenge),
    }
}""",
    )

    # --- the other three client-authenticated handlers
    edit(
        rel,
        """        .device_authorization(
            &ClientId::new(creds.client_id),
            creds.client_secret.as_deref(),
            scope.as_ref(),
        )""",
        """        .device_authorization_with_credential(
            &ClientId::new(creds.client_id.clone()),
            &creds.credential(),
            scope.as_ref(),
        )""",
    )

    edit(
        rel,
        """        .introspection_response(
            &ClientId::new(creds.client_id),
            creds.client_secret.as_deref(),
            token,
        )""",
        """        .introspection_response_with_credential(
            &ClientId::new(creds.client_id.clone()),
            &creds.credential(),
            token,
        )""",
    )


# =================================================================================================
# tests/support/mod.rs: the fault-injecting Storage has to satisfy the new method too.
# =================================================================================================
def patch_test_support():
    rel = "tests/support/mod.rs"
    load(rel)
    edit(
        rel,
        """    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {""",
        """    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        self.inner.claim_replay_id(id, expires_at).await
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {""",
    )


# =================================================================================================
# The struct literals that gain a feature-gated field.
# =================================================================================================
def patch_literals():
    # (file, the exact literal opener at that site, how many times it occurs there)
    #
    # Anchored on enough of the line to exclude a RETURN TYPE spelled the same way
    # (`fn access_token(..) -> IssuedToken {`), which is why these are not just the type name.
    sites = [
        ("tests/storage_sweep.rs", "\n    IssuedToken {\n", 1),
        ("tests/storage_sweep.rs", "\n    RefreshTokenRecord {\n", 1),
        ("tests/jwt.rs", ".put_refresh_token(RefreshTokenRecord {\n", 1),
        ("tests/grant_state_edges.rs", "| IssuedToken {\n", 1),
        ("tests/grant_state_edges.rs", "| RefreshTokenRecord {\n", 1),
        ("tests/storage_contract.rs", "\n    RefreshTokenRecord {\n", 1),
        ("src/tests/token.rs", "let record = IssuedToken {\n", 1),
        ("src/tests/token.rs", "let record = RefreshTokenRecord {\n", 1),
    ]
    for rel, opener, count in sites:
        if rel not in FILES:
            load(rel)
        # Every one of these is a PLAIN struct literal, never a functional-update
        # (`..record`) one, so `jkt: None` is the right value at each. `cargo fmt` at
        # the end of this script fixes the indentation an anchored insert cannot know.
        edit(
            rel,
            opener,
            opener + '#[cfg(feature = "dpop")]\njkt: None,\n',
            count,
        )


# =================================================================================================
# tests/allocation.rs: the size budget the two feature-gated fields move.
# =================================================================================================
def patch_allocation():
    rel = "tests/allocation.rs"
    load(rel)
    edit(
        rel,
        """    // IssuedToken carries the opaque token string, a ClientId, an Option<String> subject, a
    // ScopeSet (a BTreeSet, 1 pointer-ish word), and two SystemTime instants.
    assert!(
        size_of::<IssuedToken>() <= 176,
        "IssuedToken grew past its size budget: {}",
        size_of::<IssuedToken>()
    );""",
        """    // IssuedToken carries the opaque token string, a ClientId, an Option<String> subject, a
    // ScopeSet (a BTreeSet, 1 pointer-ish word), and two SystemTime instants.
    //
    // The `dpop` feature adds the RFC 9449 s6 key binding, an `Option<Box<str>>`. Budgeted
    // SEPARATELY rather than by raising the number, so that a deployment which does not enable
    // sender-constrained tokens still cannot be made to pay 16 bytes per issued token for them.
    #[cfg(feature = "dpop")]
    let issued_token_budget = 192;
    #[cfg(not(feature = "dpop"))]
    let issued_token_budget = 176;
    assert!(
        size_of::<IssuedToken>() <= issued_token_budget,
        "IssuedToken grew past its size budget: {}",
        size_of::<IssuedToken>()
    );""",
    )


def main():
    if already_applied():
        die(
            "this patch is already applied (src/store.rs already declares claim_replay_id). "
            "Applying it twice would duplicate every insertion; refusing."
        )

    patch_cargo()
    patch_error()
    patch_store()
    patch_client()
    patch_token()
    patch_metadata()
    patch_server()
    patch_token_exchange()
    patch_events()
    patch_lib()
    patch_http()
    patch_test_support()
    patch_literals()
    patch_allocation()

    # Nothing is written until every anchor in every file has been found.
    for rel, text in FILES.items():
        with open(os.path.join(CRATE, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    sys.stdout.write("patched %d files\n" % len(FILES))

    # The insertions above are correct Rust but not correctly indented, because an anchored edit
    # cannot know the indentation of the site it lands in. rustfmt is the authority on that and the
    # gate runs `cargo fmt --all --check`, so the patch leaves the tree in the state that gate wants.
    subprocess.check_call(["cargo", "fmt", "--all"], cwd=ROOT)
    sys.stdout.write("cargo fmt --all: done\n")


if __name__ == "__main__":
    main()
