#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""Wire the 0.8.0 consent / revocation-cascade / RFC 9470 step-up slice into the files it does not own.

The slice itself is four files: crates/oauth-as/src/consent.rs, its unit suite in
src/tests/consent.rs, and the two behavioural suites tests/consent.rs and tests/step_up.rs. This
script makes the surrounding edits those four cannot make for themselves.

WHAT IT CHANGES AND WHY, file by file:

Cargo.toml
  The `consent` cargo feature, OFF by default, in the same shape as `jwt`, `http`, `par` and
  `token-exchange`. It pulls no dependency: it is serde shapes and comparisons over what is
  already here.

src/lib.rs
  Declares the module and re-exports its public types, both behind the feature, and adds the
  authentication seam to the "host seams" list in the crate docs, because the boundary this slice
  draws (the host authenticates, the library records and ENFORCES) is exactly the kind of thing
  that list exists to state up front.

src/error.rs
  `ErrorCode::InsufficientUserAuthentication`, the RFC 9470 section 3 code. Registered there for
  the RESOURCE server's challenge; this crate reuses it for the authorization server's own refusal
  because it is the true statement (the authentication is still not sufficient), while
  `invalid_request` would say the parameters were malformed and invite an identical retry. See
  `StepUpFailure::error_response` for the argument in full.

src/store.rs
  Five consent operations on `Storage`, all feature gated, plus their `MemoryStorage`
  implementations and the one map they need. The load-bearing one is `revoke_consent`: it is
  `revoke_token_family` at a BROADER granularity, and it is ONE operation rather than five so a
  host's database can do the whole cascade in one transaction. `delete_client` also drops the
  consents naming a deleted client, for the same reason it already drops that client's tokens.

src/token.rs
  `authentication` on `IssuedToken` (what the token reports) and on `RefreshTokenRecord` (what a
  rotation carries forward, unchanged), and `auth_time` / `acr` on `IntrospectionResponse`
  (RFC 9470 section 5). Both records get one `Option<Box<Authentication>>`, which is one null
  pointer for a host that reports nothing.

src/authorization.rs
  The same field on `AuthorizationCodeRecord`: it is the only path by which the authentication the
  user actually performed can reach the token the code mints, because the token endpoint has no
  user in front of it and cannot ask.

src/events.rs
  `Event::ConsentWithdrawn`. A cascade nobody can observe is a cascade nobody can trust, and this
  is the one event in the set a USER causes rather than a client.

src/server.rs
  * `GrantedAuthentication`, a wrapper that is ZERO SIZED without the feature, threaded through
    `issue` and its five call sites. A `cfg` on an argument cannot be matched by a `cfg` at the
    call site, which is the same reason `Bound` exists for the RFC 9449 binding.
  * `issue_authorization_code` keeps its signature and delegates to a private inner form;
    `issue_authorization_code_with_authentication` is the step-up entry point and it ENFORCES the
    requirement before anything is minted.
  * `record_consent`, `remembered_consent`, `consents_for_subject`, `withdraw_consent`.
  * RFC 7662 introspection reports `auth_time` and `acr` (RFC 9470 section 5).
  * RFC 7009 section 2.1's SHOULD: revoking a refresh token now also revokes the access tokens
    issued under the same authorization grant. NOT feature gated, because it is core RFC 7009 and
    was simply missing; `tests/revocation.rs` gains the test that was seen to fail without it.

src/http.rs
  The `AuthenticationReporter` seam (the host's answer to "when, and how, did you authenticate this
  user"), `ConsentRequest::remembered` so the host's resolver is TOLD about a remembered consent
  rather than the library acting on one, and `ConsentDecision::ApproveAndRemember` so that
  remembering stays a decision the host makes.

The test files
  Struct literals of the three record types have to name the new field. `None` and not a
  constructor: the field is an `Option<Box<_>>` on all three, and "the host reported nothing" is
  the truthful value for a fixture. tests/allocation.rs gets a feature-dependent budget line rather
  than a raised number: a budget raised for a build that did not grow is a budget that has stopped
  gating.

WHAT IT DELIBERATELY DOES NOT CHANGE:

src/metadata.rs. `acr_values_supported` is an OpenID Connect Discovery member, not an RFC 8414 one,
and RFC 9470 does not require it. Publishing it would be this crate asserting a vocabulary it does
not own (see `Authentication::acr`), so the catalogue stays the host's.

src/par.rs. A pushed authorization request could carry `acr_values` and `max_age`. When it does,
that belongs in the PAR slice's own type rather than being smuggled in from here, and
`AuthenticationRequirement::from_pairs` is already the one parser both would share.

ONE EDIT THIS SCRIPT MAKES THAT ITS OWN GATE CANNOT VERIFY: src/storage_conformance.rs is not in
the module tree in the state this slice was built against (its `test-util` feature is unwired), so
the two struct literals patched there are not compiled by any build this script can run. They are
patched anyway, because the alternative is an `--all-features` build that breaks the moment that
slice lands, and a missing field there is a compile error rather than a silent drop.

Rules this script holds itself to:
  * every edit is anchored on surrounding TEXT, never on a line number;
  * an anchor that is not found the expected number of times is a hard failure and NOTHING is
    written;
  * it refuses to run twice (each file carries a marker whose presence means "already applied").

Run from anywhere:  python3 scripts/patch-0.8.0-consent.py [--repo /path/to/oauth-as]
"""

import argparse
import os
import sys

REPO_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The marker that means "this file already carries the slice". One per file, chosen to be text the
# patch itself inserts and that nothing else in the tree would produce.
MARKERS = {
    "crates/oauth-as/Cargo.toml": "\nconsent = []",
    "crates/oauth-as/src/lib.rs": "pub mod consent;",
    "crates/oauth-as/src/error.rs": "InsufficientUserAuthentication",
    "crates/oauth-as/src/store.rs": "fn revoke_consent",
    "crates/oauth-as/src/token.rs": "pub auth_time: Option<u64>",
    "crates/oauth-as/src/authorization.rs": "consent-0.8.0 slice",
    "crates/oauth-as/src/events.rs": "ConsentWithdrawn",
    "crates/oauth-as/src/server.rs": "GrantedAuthentication",
    "crates/oauth-as/src/http.rs": "AuthenticationReporter",
    "crates/oauth-as/src/token_exchange.rs": "GrantedAuthentication",
    "crates/oauth-as/tests/allocation.rs": 'cfg!(feature = "consent")',
    "crates/oauth-as/tests/revocation.rs": "also_kills_the_access_tokens_of_the_same_grant",
    "crates/oauth-as/tests/support/mod.rs": "fn revoke_consent",
    "crates/oauth-as/tests/http_verification_outcomes.rs": "fn revoke_consent",
    "crates/oauth-as/tests/storage_conformance_selftest.rs": "fn revoke_consent",
}

# The two lines every struct-literal edit inserts, at the indentation of the field it joins.
FIELD = '#[cfg(feature = "consent")]\nauthentication: None,\n'


def literal(tail, indent):
    """One struct-literal edit: name the new field just before the literal's closing brace.

    `tail` is the text from the start of the literal's LAST field through its closing brace, which
    is what makes the anchor unique inside its file; `indent` is the field indentation.
    """
    pad = " " * indent
    closing = "\n" + " " * (indent - 4) + "}"
    assert tail.endswith(closing), tail
    body = tail[: -len(closing)]
    extra = "\n" + pad + FIELD.replace("\n", "\n" + pad).rstrip() + closing
    return (tail, body + extra, 1)


def edits_for():
    """Every edit, as {relative path: [(find, replace, expected_count), ...]}."""
    e = {}

    # -------------------------------------------------------------------- Cargo.toml
    e["crates/oauth-as/Cargo.toml"] = [
        (
            "token-exchange = []\n",
            "token-exchange = []\n"
            "# Consent records, consent withdrawal with a revocation cascade, and RFC 9470 step-up\n"
            "# authentication. OFF by default because it changes what a host is expected to tell the\n"
            "# server: with it on the host REPORTS when and how it authenticated the user, and the\n"
            "# library enforces the client's `max_age` and `acr_values` against that report. A\n"
            "# deployment that has not decided how to answer that question should not have the seam\n"
            "# compiled in. No dependency: serde shapes and comparisons over what is already here.\n"
            "consent = []\n",
            1,
        ),
    ]

    # -------------------------------------------------------------------- src/lib.rs
    e["crates/oauth-as/src/lib.rs"] = [
        (
            "pub mod device;\n",
            "/// Consent records, consent withdrawal with a revocation cascade, and RFC 9470 step-up\n"
            "/// authentication, behind the `consent` cargo feature (off by default). Read the module\n"
            "/// docs before using it: it draws a blunt line between what the HOST does (authenticate\n"
            "/// the user) and what this library does (record that report, and enforce `max_age`).\n"
            '#[cfg(feature = "consent")]\n'
            "pub mod consent;\n"
            "pub mod device;\n",
            1,
        ),
        (
            "pub use device::{DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState};\n",
            '#[cfg(feature = "consent")]\n'
            "pub use consent::{\n"
            "    step_up_challenge, Authentication, AuthenticationRequirement, ConsentRecord, StepUpFailure,\n"
            "};\n"
            "pub use device::{DeviceAuthorizationResponse, DeviceGrant, DeviceGrantState};\n",
            1,
        ),
        (
            "//! - WHO MAY REGISTER ([`registration::RegistrationPolicy`]).",
            "//! - WHEN AND HOW THE USER LOGGED IN ([`consent::Authentication`], behind the `consent`\n"
            "//!   feature). This crate cannot authenticate anybody and will not grow a login page, so a\n"
            "//!   host that wants RFC 9470 step-up authentication REPORTS when and how it authenticated\n"
            "//!   the user; the library records that report and enforces `max_age` and `acr_values`\n"
            "//!   against it. The report is taken at face value, because there is nothing here that\n"
            "//!   could check it. See the [`consent`] module docs for the whole boundary.\n"
            "//! - WHO MAY REGISTER ([`registration::RegistrationPolicy`]).",
            1,
        ),
    ]

    # -------------------------------------------------------------------- src/error.rs
    e["crates/oauth-as/src/error.rs"] = [
        (
            "    InvalidTarget,\n",
            "    InvalidTarget,\n"
            "    /// RFC 9470 section 3: the authentication the user performed is not enough for what is\n"
            "    /// being asked. Registered by RFC 9470 for the RESOURCE server's challenge; this server\n"
            "    /// emits it from the AUTHORIZATION endpoint when the host's reported authentication\n"
            "    /// cannot satisfy the request's `acr_values` or `max_age`.\n"
            "    ///\n"
            "    /// Reusing the resource server's code is deliberate. It is the code the client was just\n"
            "    /// handed, so re-sending it says the true thing: the authentication is STILL not\n"
            "    /// sufficient. `invalid_request` would say the parameters were malformed and invite the\n"
            "    /// client to retry the identical request, which is the one thing that cannot help.\n"
            '    #[cfg(feature = "consent")]\n'
            "    InsufficientUserAuthentication,\n",
            1,
        ),
        (
            '            ErrorCode::InvalidTarget => "invalid_target",\n',
            '            ErrorCode::InvalidTarget => "invalid_target",\n'
            '            #[cfg(feature = "consent")]\n'
            '            ErrorCode::InsufficientUserAuthentication => "insufficient_user_authentication",\n',
            1,
        ),
    ]

    # -------------------------------------------------------------------- src/store.rs
    e["crates/oauth-as/src/store.rs"] = store_edits()

    # -------------------------------------------------------------------- src/token.rs
    e["crates/oauth-as/src/token.rs"] = token_edits()

    # -------------------------------------------------------------------- src/authorization.rs
    e["crates/oauth-as/src/authorization.rs"] = [
        (
            """    /// Whether the code has been redeemed, and what it produced.
    pub state: AuthorizationCodeState,
}
""",
            """    /// Whether the code has been redeemed, and what it produced.
    pub state: AuthorizationCodeState,
    /// What the host reported about the resource owner's authentication when this code was
    /// approved (the consent-0.8.0 slice; see [`crate::consent::Authentication`]).
    ///
    /// Recorded on the CODE because that is the only path by which the authentication the user
    /// actually performed can reach the token the code mints: the token endpoint has no user in
    /// front of it and cannot ask. Without it, RFC 9470 section 5's `auth_time` and `acr` could
    /// only ever be guessed at.
    #[cfg(feature = "consent")]
    pub authentication: Option<Box<crate::consent::Authentication>>,
}
""",
            1,
        ),
    ]

    # -------------------------------------------------------------------- src/events.rs
    e["crates/oauth-as/src/events.rs"] = [
        (
            "    /// A client registered itself through RFC 7591 dynamic client registration.",
            """    /// A resource owner WITHDREW a consent, and everything issued under it was revoked.
    ///
    /// The one event in this set a USER causes rather than a client, and it is worth recording for
    /// the same reason the two compromise events are: the cascade logs a client out of an account
    /// it was in the middle of working with, so a host will be asked what happened.
    /// `records_revoked` is how many tokens, codes and approved device grants the withdrawal
    /// actually removed, which is what distinguishes "the user ended a live session" from "the
    /// user revoked something that had already expired".
    #[cfg(feature = "consent")]
    ConsentWithdrawn {
        /// The client that may no longer act for this user.
        client_id: &'a str,
        /// The user who withdrew it.
        subject: &'a str,
        /// How many records the cascade removed.
        records_revoked: u64,
    },
    /// A client registered itself through RFC 7591 dynamic client registration.""",
            1,
        ),
    ]

    # -------------------------------------------------------------------- src/server.rs
    e["crates/oauth-as/src/server.rs"] = server_edits()

    # -------------------------------------------------------------------- src/token_exchange.rs
    # The fifth `issue` call site. An exchanged token inherits nothing about a user authentication:
    # RFC 8693 s1 has a client presenting a token rather than a user presenting themselves, and
    # nobody has logged in during this request.
    e["crates/oauth-as/src/token_exchange.rs"] = [
        (
            """            crate::server::GrantedDetails::of_token(&subject),
            None,
            false,
        )
        .await?;""",
            """            crate::server::GrantedDetails::of_token(&subject),
            None,
            false,
            // RFC 8693 s1: a client is presenting a token, not a user presenting themselves.
            // Nobody authenticated during this request, so there is nothing to report, and
            // carrying the subject token's report forward would let an exchange launder a stale
            // authentication into a token that looks freshly stepped up.
            crate::server::GrantedAuthentication::default(),
        )
        .await?;""",
            1,
        ),
    ]

    # -------------------------------------------------------------------- src/http.rs
    e["crates/oauth-as/src/http.rs"] = http_edits()

    # -------------------------------------------------------------------- the test tree
    e.update(test_edits())
    return e


def store_edits():
    return [
        (
            "use crate::device::DeviceGrant;\n",
            "use crate::device::DeviceGrant;\n"
            '#[cfg(feature = "consent")]\n'
            "use crate::device::DeviceGrantState;\n",
            1,
        ),
        # The trait methods, immediately after the family revocation they generalise.
        (
            """    fn revoke_token_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
""",
            """    fn revoke_token_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;

    /// Insert or replace a consent record, keyed by its `consent_id`.
    ///
    /// The server keeps at most ONE live consent per (`client_id`, `subject`) pair and widens it
    /// in place, so a store that indexes that pair (see [`Storage::find_consent`]) must keep the
    /// index consistent with this write.
    #[cfg(feature = "consent")]
    fn put_consent(
        &self,
        record: crate::consent::ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up a consent record by its identifier.
    #[cfg(feature = "consent")]
    fn get_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<crate::consent::ConsentRecord>, StorageError>> + Send;

    /// The live consent for one (client, subject) pair, if there is one.
    ///
    /// This is what remembered consent is read from, and unlike the rest of the consent operations
    /// it runs on the AUTHORIZATION ENDPOINT'S path, so a store SHOULD index the pair rather than
    /// scanning.
    #[cfg(feature = "consent")]
    fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> impl Future<Output = Result<Option<crate::consent::ConsentRecord>, StorageError>> + Send;

    /// Every consent one resource owner has granted, so a host can show a user what they have
    /// approved. Order is not specified; a host that wants one sorts what it gets back.
    #[cfg(feature = "consent")]
    fn consents_for_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<crate::consent::ConsentRecord>, StorageError>> + Send;

    /// WITHDRAW a consent: remove the record AND everything issued under it, returning how many
    /// records were removed (the consent record itself is not counted).
    ///
    /// This is [`Storage::revoke_token_family`] at a BROADER granularity, and it is deliberately
    /// the same primitive rather than a parallel mechanism. A family is one refresh chain and the
    /// tokens minted along it; a consent is every grant one client ever obtained for one user, and
    /// one consent spans many families over time because every fresh trip through the
    /// authorization endpoint mints another one. Withdrawing a consent and revoking only the newest
    /// family would leave every earlier chain live, which is this feature failing silently, and
    /// silently is the worst way for it to fail: the user has been told they stopped something they
    /// did not.
    ///
    /// "Everything issued under it" means, for the consent's (`client_id`, `subject`) pair:
    ///
    /// - access tokens for that subject;
    /// - refresh records for that subject, whatever family they belong to;
    /// - authorization codes issued to that subject, which are grants in flight and would otherwise
    ///   mint a token seconds after the user said stop;
    /// - device grants that subject has APPROVED but the device has not yet polled, for the same
    ///   reason. A PENDING device grant is left alone: nobody has consented to it yet, so there is
    ///   nothing there to withdraw.
    ///
    /// It is ONE operation rather than five so a real database can do it in one transaction. A
    /// withdrawal that half succeeded leaves a user believing they revoked something they did not,
    /// which is the failure this whole feature exists to prevent.
    ///
    /// Withdrawing a consent that is already gone is `Ok(0)`, not an error, for the same reason
    /// [`Storage::revoke_token_family`] tolerates a concurrent revocation: a user who clicks twice
    /// has not made a mistake.
    ///
    /// This runs when a person clicks something, never on a token-plane request, so it is not a hot
    /// path. It must simply complete.
    #[cfg(feature = "consent")]
    fn revoke_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
""",
            1,
        ),
        # The map behind it.
        (
            "    refresh: HashMap<String, RefreshTokenRecord>,\n",
            "    refresh: HashMap<String, RefreshTokenRecord>,\n"
            "    /// Consent records by `consent_id`. Present only under the `consent` feature, so a\n"
            "    /// default build's store is byte for byte the store it was before.\n"
            '    #[cfg(feature = "consent")]\n'
            "    consents: HashMap<String, crate::consent::ConsentRecord>,\n",
            1,
        ),
        # delete_client takes the consents with it.
        (
            """        g.device_by_code.retain(|_, d| &d.client_id != client_id);
""",
            """        g.device_by_code.retain(|_, d| &d.client_id != client_id);
        // A consent names a client that no longer exists; leaving it would show a user an
        // application they cannot revoke, on a registration nothing can reach. The same
        // "everything the registration holds goes with it" rule as the four lines above.
        #[cfg(feature = "consent")]
        g.consents.retain(|_, c| &c.client_id != client_id);
""",
            1,
        ),
        # The implementations, after the family revocation.
        (
            """        g.refresh.retain(|_, r| r.family_id != family_id);
        Ok((before - (g.tokens.len() + g.refresh.len())) as u64)
    }
""",
            """        g.refresh.retain(|_, r| r.family_id != family_id);
        Ok((before - (g.tokens.len() + g.refresh.len())) as u64)
    }

    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: crate::consent::ConsentRecord) -> Result<(), StorageError> {
        self.lock()
            .consents
            .insert(record.consent_id.to_string(), record);
        Ok(())
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<crate::consent::ConsentRecord>, StorageError> {
        Ok(self.lock().consents.get(consent_id).cloned())
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<crate::consent::ConsentRecord>, StorageError> {
        // A scan, honestly, for a map with no secondary index; a host with a real database indexes
        // the pair, and the trait doc says so because this one IS on the authorization path.
        Ok(self
            .lock()
            .consents
            .values()
            .find(|c| &c.client_id == client_id && c.subject.as_ref() == subject)
            .cloned())
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<crate::consent::ConsentRecord>, StorageError> {
        Ok(self
            .lock()
            .consents
            .values()
            .filter(|c| c.subject.as_ref() == subject)
            .cloned()
            .collect())
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        // The whole cascade under the ONE mutex, which is this store's version of the single
        // transaction the trait doc asks a real database for: no request can observe a
        // half-withdrawn consent, and nothing can be issued between the lookup and the sweep.
        let mut g = self.lock();
        let consent = match g.consents.remove(consent_id) {
            Some(c) => c,
            // Already withdrawn, or never existed. Both are success; see the trait doc.
            None => return Ok(0),
        };
        let client_id = &consent.client_id;
        let subject: &str = consent.subject.as_ref();
        let before = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        g.tokens
            .retain(|_, t| !(&t.client_id == client_id && t.subject.as_deref() == Some(subject)));
        g.refresh
            .retain(|_, r| !(&r.client_id == client_id && r.subject.as_deref() == Some(subject)));
        // An unredeemed code is a grant in flight. Leaving it would let the client mint a token
        // seconds after the user withdrew, which is the withdrawal failing in the way nobody
        // notices until it matters.
        g.codes
            .retain(|_, c| !(&c.client_id == client_id && c.subject == subject));
        // Same for a device grant this user has already approved but the device has not polled for
        // yet. A PENDING one is left alone: nobody has consented to it, and killing it would end a
        // login the user may be in the middle of.
        g.device_by_code.retain(|_, d| {
            !(&d.client_id == client_id
                && matches!(&d.state, DeviceGrantState::Approved { subject: s } if s == subject))
        });
        // The user-code index points at grants rather than being a record of its own, so a dangling
        // entry would make a reaped code resolve to nothing. The same pass `sweep_expired` makes.
        let live = &g.device_by_code;
        let stale: Vec<String> = g
            .user_code_index
            .iter()
            .filter(|(_, dc)| !live.contains_key(*dc))
            .map(|(uc, _)| uc.clone())
            .collect();
        for uc in stale {
            g.user_code_index.remove(&uc);
        }
        let after = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        Ok((before - after) as u64)
    }
""",
            1,
        ),
    ]


def token_edits():
    return [
        # IntrospectionResponse: the RFC 9470 s5 members.
        (
            """    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
""",
            """    #[serde(skip_serializing_if = "Option::is_none")]
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
""",
            1,
        ),
        (
            """            iss: None,
            aud: None,
""",
            """            iss: None,
            aud: None,
            #[cfg(feature = "consent")]
            auth_time: None,
            #[cfg(feature = "consent")]
            acr: None,
""",
            1,
        ),
        # IssuedToken.
        (
            """    pub family_id: Option<String>,
}
""",
            """    pub family_id: Option<String>,
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
""",
            1,
        ),
        # RefreshTokenRecord.
        (
            """    pub family_id: String,
    /// Whether this link is still redeemable, or is a retained rotated one.
    pub state: RefreshTokenState,
""",
            """    pub family_id: String,
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
""",
            1,
        ),
    ]


def server_edits():
    return [
        # ---- the wrapper type, next to the constant it precedes.
        (
            "/// How many times user-code generation may redraw on a collision before giving up.",
            """/// The host-reported authentication an issuance carries, in a wrapper that is ZERO SIZED without
/// the `consent` feature.
///
/// It exists so [`AuthorizationServer::issue`] and its five call sites have ONE signature in every
/// feature configuration. The alternative, a `cfg` on the argument, cannot be matched by a `cfg` at
/// the call site, and duplicating five call sites under a `cfg` is five places to get it wrong in
/// the configuration nobody builds locally. Same reason `Bound` exists for the RFC 9449 binding.
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct GrantedAuthentication {
    #[cfg(feature = "consent")]
    pub(crate) authentication: Option<Box<crate::consent::Authentication>>,
}

impl GrantedAuthentication {
    /// What an authorization code carries into the token it mints.
    #[cfg(feature = "consent")]
    pub(crate) fn from_code(record: &AuthorizationCodeRecord) -> Self {
        GrantedAuthentication {
            authentication: record.authentication.clone(),
        }
    }

    /// Without the feature there is no field to fill, and no field on the record to fill it from.
    #[cfg(not(feature = "consent"))]
    pub(crate) fn from_code(_record: &AuthorizationCodeRecord) -> Self {
        GrantedAuthentication {}
    }

    /// What a refresh chain carries across a rotation: the ORIGINAL authentication, unchanged. See
    /// [`crate::token::RefreshTokenRecord::authentication`] on why a rotation is not a new one.
    #[cfg(feature = "consent")]
    pub(crate) fn from_refresh(record: &RefreshTokenRecord) -> Self {
        GrantedAuthentication {
            authentication: record.authentication.clone(),
        }
    }

    /// Without the feature, as above.
    #[cfg(not(feature = "consent"))]
    pub(crate) fn from_refresh(_record: &RefreshTokenRecord) -> Self {
        GrantedAuthentication {}
    }
}

/// How many times user-code generation may redraw on a collision before giving up.""",
            1,
        ),
        # ---- issue_boxed: the parameter, and passing it through.
        (
            """        chain: Option<RefreshChain>,
        allow_refresh: bool,
    ) -> std::pin::Pin<""",
            """        chain: Option<RefreshChain>,
        allow_refresh: bool,
        authentication: GrantedAuthentication,
    ) -> std::pin::Pin<""",
            1,
        ),
        (
            """            details,
            chain,
            allow_refresh,
        ))
    }""",
            """            details,
            chain,
            allow_refresh,
            authentication,
        ))
    }""",
            1,
        ),
        # ---- issue itself.
        (
            """        chain: Option<RefreshChain>,
        allow_refresh: bool,
    ) -> Result<TokenResponse, ErrorResponse> {""",
            """        chain: Option<RefreshChain>,
        allow_refresh: bool,
        authentication: GrantedAuthentication,
    ) -> Result<TokenResponse, ErrorResponse> {""",
            1,
        ),
        (
            """        #[cfg(not(feature = "dpop"))]
        let _ = bound;
""",
            """        #[cfg(not(feature = "dpop"))]
        let _ = bound;
        // Same for the RFC 9470 authentication report: without `consent` the wrapper is empty and
        // genuinely unused here, and an unused parameter is a warning rather than a signature that
        // differs by feature.
        #[cfg(not(feature = "consent"))]
        let _ = authentication;
""",
            1,
        ),
        (
            """                issued_at: now,
                expires_at: now + self.config.access_token_ttl,
                family_id: family_id.clone(),
            })""",
            """                issued_at: now,
                expires_at: now + self.config.access_token_ttl,
                family_id: family_id.clone(),
                // RFC 9470 s5: the token reports the authentication behind it, so introspection can
                // answer the question the resource server's challenge asked.
                #[cfg(feature = "consent")]
                authentication: authentication.authentication.clone(),
            })""",
            1,
        ),
        (
            """                    family_id: family_id.unwrap_or_default(),
                    state: RefreshTokenState::Active,
                })""",
            """                    family_id: family_id.unwrap_or_default(),
                    state: RefreshTokenState::Active,
                    // Carried, never restamped: see `RefreshTokenRecord::authentication`.
                    #[cfg(feature = "consent")]
                    authentication: authentication.authentication,
                })""",
            1,
        ),
        # ---- the five call sites.
        (
            """                Some(record.subject.clone()),
                record.scope.clone(),
                resource,
                details,
                None,
                true,
            )""",
            """                Some(record.subject.clone()),
                record.scope.clone(),
                resource,
                details,
                None,
                true,
                GrantedAuthentication::from_code(&record),
            )""",
            1,
        ),
        (
            """            GrantType::ClientCredentials,
            None,
            scope,
            resource,
            // RFC 9396 s6: there is no prior authorization request here, so there is nothing
            // to narrow AGAINST. The client authenticated as itself and is naming what it
            // means to do, which is the whole of what the parameter says in this grant; the
            // s5 type check has already run at the endpoint.
            details,
            None,
            false,
        )""",
            """            GrantType::ClientCredentials,
            None,
            scope,
            resource,
            // RFC 9396 s6: there is no prior authorization request here, so there is nothing
            // to narrow AGAINST. The client authenticated as itself and is naming what it
            // means to do, which is the whole of what the parameter says in this grant; the
            // s5 type check has already run at the endpoint.
            details,
            None,
            false,
            // RFC 6749 s4.4 has no resource owner, so there is no user authentication to report.
            GrantedAuthentication::default(),
        )""",
            1,
        ),
        (
            """                    Some(subject),
                    taken.scope,
                    Vec::new(),
                    // No details: the device authorization request does not carry them and
                    // the poll above refuses any the client sends.
                    GrantedDetails::default(),
                    None,
                    true,
                )""",
            """                    Some(subject),
                    taken.scope,
                    Vec::new(),
                    // No details: the device authorization request does not carry them and
                    // the poll above refuses any the client sends.
                    GrantedDetails::default(),
                    None,
                    true,
                    // The device grant carries no authentication report: RFC 8628 s3.3 approval
                    // happens at the host's own verification UI, which is where the report would
                    // have to be taken, and inventing one here would be this server asserting
                    // something it never witnessed.
                    GrantedAuthentication::default(),
                )""",
            1,
        ),
        (
            """                resource,
                details,
                Some(RefreshChain {
                    family_id: record.family_id.clone(),
                    expires_at: record.expires_at,
                }),
                true,
            )""",
            """                resource,
                details,
                Some(RefreshChain {
                    family_id: record.family_id.clone(),
                    expires_at: record.expires_at,
                }),
                true,
                GrantedAuthentication::from_refresh(&record),
            )""",
            1,
        ),
        # ---- issue_authorization_code: an inner form plus two entry points.
        (
            """    pub async fn issue_authorization_code(
        &self,
        request: &ValidatedAuthorizationRequest,
        subject: impl Into<String>,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        let now = self.clock.now();""",
            """    pub async fn issue_authorization_code(
        &self,
        request: &ValidatedAuthorizationRequest,
        subject: impl Into<String>,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        self.issue_authorization_code_inner(request, subject, GrantedAuthentication::default())
            .await
    }

    /// Mint an authorization code for a request the user has approved, holding the request's RFC
    /// 9470 step-up requirement to the authentication the HOST reports it performed.
    ///
    /// This is the enforcement half of RFC 9470, and it is a library job rather than a host job on
    /// purpose: a `max_age` the host is trusted to check for itself is a `max_age` that gets checked
    /// in whichever code path somebody remembered. The host still owns the authentication itself,
    /// and `authentication` is its REPORT of one; this crate cannot verify that report and does not
    /// pretend to. See the [`crate::consent`] module docs for the whole boundary.
    ///
    /// A requirement the report does not satisfy is refused with RFC 9470 section 3's
    /// `insufficient_user_authentication`, delivered as a REDIRECT (RFC 6749 section 4.1.2.1):
    /// by this point the redirect URI has been validated, and the client is both the party that
    /// asked the question and the party that has to decide whether to send the user back to log in.
    /// Nothing is minted and no consent is touched.
    #[cfg(feature = "consent")]
    pub async fn issue_authorization_code_with_authentication(
        &self,
        request: &ValidatedAuthorizationRequest,
        subject: impl Into<String>,
        requirement: &crate::consent::AuthenticationRequirement,
        authentication: Option<&crate::consent::Authentication>,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        if let Err(failure) = requirement.satisfied_by(authentication, self.clock.now()) {
            return Err(AuthorizationError::Redirect(AuthorizationErrorRedirect {
                redirect_uri: request.redirect_uri.clone(),
                error: failure.error_response(),
                state: request.state.clone(),
                iss: request.issuer.clone(),
            }));
        }
        self.issue_authorization_code_inner(
            request,
            subject,
            GrantedAuthentication {
                authentication: authentication.cloned().map(Box::new),
            },
        )
        .await
    }

    /// The issuance itself, shared by both entry points above so that they cannot drift.
    async fn issue_authorization_code_inner(
        &self,
        request: &ValidatedAuthorizationRequest,
        subject: impl Into<String>,
        authentication: GrantedAuthentication,
    ) -> Result<AuthorizationResponse, AuthorizationError> {
        #[cfg(not(feature = "consent"))]
        let _ = authentication;
        let now = self.clock.now();""",
            1,
        ),
        (
            """            expires_at: now + self.config.authorization_code_ttl,
            state: AuthorizationCodeState::Issued,
        };""",
            """            expires_at: now + self.config.authorization_code_ttl,
            state: AuthorizationCodeState::Issued,
            // RFC 9470 s5: recorded here because the token endpoint has no user in front of it and
            // could not ask. See `AuthorizationCodeRecord::authentication`.
            #[cfg(feature = "consent")]
            authentication: authentication.authentication,
        };""",
            1,
        ),
        # ---- introspection reports the RFC 9470 s5 members.
        (
            "                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),",
            """                aud: (!t.resource.is_empty()).then(|| t.resource.clone()),
                // RFC 9470 s5. A resource server that sent a step-up challenge has to be able to
                // see whether the token it now holds satisfies it; without these two it would have
                // to take the client's word for that, which is the whole thing the challenge exists
                // to avoid.
                #[cfg(feature = "consent")]
                auth_time: t
                    .authentication
                    .as_ref()
                    .and_then(|a| unix_seconds(a.auth_time)),
                #[cfg(feature = "consent")]
                acr: t
                    .authentication
                    .as_ref()
                    .and_then(|a| a.acr.as_deref().map(str::to_string)),""",
            1,
        ),
        # ---- the consent surface, ahead of the revocation endpoint it generalises.
        (
            "    /// RFC 7009 token revocation.",
            """    /// Record that a resource owner has consented to a client acting for them.
    ///
    /// One live consent per (client, subject) pair: an existing record is WIDENED in place, keeping
    /// its identifier and its original `granted_at`, so a user who approves one more scope next
    /// month still sees one entry rather than two and withdrawing it withdraws the whole
    /// relationship. See [`crate::consent::ConsentRecord::extend`].
    ///
    /// The library NEVER calls this for itself. Recording consent is a statement that a user agreed
    /// to something, and this crate has no way to know that: it never sees a user. The host calls
    /// it once its own consent step has actually been answered.
    #[cfg(feature = "consent")]
    pub async fn record_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
        scope: &ScopeSet,
        resource: &[String],
        authentication: Option<crate::consent::Authentication>,
    ) -> Result<crate::consent::ConsentRecord, StorageError> {
        let now = self.clock.now();
        let mut record = match self.store.find_consent(client_id, subject).await? {
            Some(existing) => existing,
            None => crate::consent::ConsentRecord {
                // 16 bytes of OS randomness, hex encoded, the same shape as every other opaque
                // identifier this server mints. It is not a credential (see the field's own docs),
                // but it names a record that can end a user's sessions, so it must not be something
                // a third party can produce by guessing two strings it already knows.
                consent_id: random_hex(16).into_boxed_str(),
                client_id: client_id.clone(),
                subject: subject.into(),
                scope: ScopeSet::empty(),
                resource: Vec::new(),
                granted_at: now,
                authentication: None,
            },
        };
        record.extend(scope, resource);
        // The LATEST authentication replaces the previous one: it is what the user just did, and it
        // is what an RFC 9470 `max_age` on the next request has to be measured against. A host that
        // reports nothing this time leaves the previous report standing rather than erasing it,
        // because "did not say" is not "no longer authenticated".
        if let Some(a) = authentication {
            record.authentication = Some(Box::new(a));
        }
        self.store.put_consent(record.clone()).await?;
        Ok(record)
    }

    /// The consent this user has already given this client, if any.
    ///
    /// This ANSWERS a question; it does not make a decision, and nothing in this crate approves an
    /// authorization request on the strength of it. See
    /// [`crate::http::RouterBuilder::with_consent_resolver`]: the library reports what it remembers
    /// and the host decides what that is worth, because "the user agreed to this once" and "the
    /// user agrees to this now" are different sentences and only the host can tell them apart.
    #[cfg(feature = "consent")]
    pub async fn remembered_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<crate::consent::ConsentRecord>, StorageError> {
        self.store.find_consent(client_id, subject).await
    }

    /// Everything one resource owner has consented to, so a host can show a user what they have
    /// granted. Without this a user cannot SEE what they gave away, which is half of why this
    /// feature exists at all.
    #[cfg(feature = "consent")]
    pub async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<crate::consent::ConsentRecord>, StorageError> {
        self.store.consents_for_subject(subject).await
    }

    /// WITHDRAW a consent, revoking everything issued under it. Returns how many records the
    /// cascade removed.
    ///
    /// This is the point of the whole feature. A withdrawal that left tokens alive would be worse
    /// than no withdrawal at all, because the user would believe they had stopped something they
    /// had not, so the cascade is one storage operation
    /// ([`crate::store::Storage::revoke_consent`]) and it reaches every family the consent ever
    /// produced, plus the authorization codes and approved-but-unpolled device grants that would
    /// otherwise mint tokens seconds later.
    ///
    /// Withdrawing a consent that is already gone is `Ok(0)`, not an error.
    #[cfg(feature = "consent")]
    pub async fn withdraw_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        // Read first, purely so the audit event can name the client and the user. Two round trips
        // on a path a person drives by hand is not a cost worth optimising away, and an event that
        // said only "some consent was withdrawn" is an event nobody can act on.
        let record = self.store.get_consent(consent_id).await?;
        let records_revoked = self.store.revoke_consent(consent_id).await?;
        if let Some(record) = &record {
            self.hooks.emit(|| Event::ConsentWithdrawn {
                client_id: record.client_id.as_str(),
                subject: record.subject.as_ref(),
                records_revoked,
            });
        }
        Ok(records_revoked)
    }

    /// RFC 7009 token revocation.""",
            1,
        ),
        # ---- RFC 7009 s2.1: the cascade that was simply missing.
        (
            """                    self.store
                        .take_refresh_token(token)
                        .await
                        .map_err(storage_error)?;
                    self.hooks.emit(|| Event::TokenRevoked {""",
            """                    self.store
                        .take_refresh_token(token)
                        .await
                        .map_err(storage_error)?;
                    // RFC 7009 section 2.1: "If the particular token is a refresh token and the
                    // authorization server supports the revocation of access tokens, then the
                    // authorization server SHOULD also invalidate all access tokens based on the
                    // same authorization grant." This server does support it, so the SHOULD
                    // applies, and the grant is exactly what `family_id` names (see
                    // `RefreshTokenRecord::family_id`): every token, access or refresh, minted from
                    // the same authorization. Killing only the presented string would leave the
                    // access token that came out of the same redemption live for its whole TTL,
                    // which is the opposite of what a client asking for revocation has just said.
                    //
                    // Deliberately NOT fatal on a storage failure. Section 2.2 makes the presented
                    // token's own revocation the answer and that has already succeeded; a cascade
                    // that could turn a completed revocation into a 503 would leave the client
                    // believing nothing was revoked when the token it named is already gone.
                    let _ = self.store.revoke_token_family(&record.family_id).await;
                    self.hooks.emit(|| Event::TokenRevoked {""",
            1,
        ),
    ]


def http_edits():
    return [
        # ---- the reporter seam, next to the two seams it joins.
        (
            "pub type ConsentResolver = Arc<dyn Fn(&ConsentRequest<'_>) -> ConsentDecision + Send + Sync>;",
            """pub type ConsentResolver = Arc<dyn Fn(&ConsentRequest<'_>) -> ConsentDecision + Send + Sync>;

/// How the host answers "when, and how, did you authenticate this user".
///
/// The third identity seam, and the one RFC 9470 needs: a subject resolver answers WHO, a consent
/// resolver answers WHETHER THEY AGREED, and this answers HOW STRONGLY AND HOW RECENTLY. `None`
/// means the host is not reporting one, which satisfies no `acr_values` and no `max_age`; see
/// [`RouterBuilder::with_authentication_reporter`].
#[cfg(feature = "consent")]
pub type AuthenticationReporter =
    Arc<dyn Fn(&HeaderMap) -> Option<crate::consent::Authentication> + Send + Sync>;""",
            1,
        ),
        # ---- the decision variant.
        (
            """    /// Serve this response instead, unchanged: a consent screen, a login redirect, a step-up
    /// challenge. Nothing is issued.
    Respond(Box<Response>),""",
            """    /// The resource owner agreed AND asked not to be asked again: mint the code, and record (or
    /// widen) the consent so a later request can be recognised as already granted.
    ///
    /// A separate variant rather than something the library infers, because remembering is a
    /// statement about a user's intent and this crate never sees a user. It will not remember a
    /// consent nobody asked it to remember, and it will not approve one it does remember.
    #[cfg(feature = "consent")]
    ApproveAndRemember,
    /// Serve this response instead, unchanged: a consent screen, a login redirect, a step-up
    /// challenge. Nothing is issued.
    Respond(Box<Response>),""",
            1,
        ),
        # ---- what the resolver is told.
        (
            """    /// The full request URI, so a host that renders a consent screen can round-trip the user
    /// back to exactly this request after they answer.
    pub uri: &'a Uri,
}""",
            """    /// The full request URI, so a host that renders a consent screen can round-trip the user
    /// back to exactly this request after they answer.
    pub uri: &'a Uri,
    /// What this user has already granted this client, if anything.
    ///
    /// This is the library REPORTING and the host DECIDING, and that split is the whole design.
    /// [`crate::consent::ConsentRecord::covers`] answers whether the remembered grant already
    /// covers what is being asked for now; whether that is a good enough reason to skip the prompt
    /// depends on how long ago it was, what the scope means in this deployment, and whether the
    /// user is on a device the host trusts, none of which this crate knows. So it is handed over,
    /// and nothing here ever approves on the strength of it.
    #[cfg(feature = "consent")]
    pub remembered: Option<&'a crate::consent::ConsentRecord>,
}""",
            1,
        ),
        # ---- Inner and RouterBuilder carry the seam.
        (
            """    subject: Option<SubjectResolver>,
    consent: Option<ConsentResolver>,
    verification: VerificationProtection,
}

impl<S: Storage, C: Clock> Inner<S, C> {""",
            """    subject: Option<SubjectResolver>,
    consent: Option<ConsentResolver>,
    #[cfg(feature = "consent")]
    authentication: Option<AuthenticationReporter>,
    verification: VerificationProtection,
}

impl<S: Storage, C: Clock> Inner<S, C> {""",
            1,
        ),
        (
            """    subject: Option<SubjectResolver>,
    consent: Option<ConsentResolver>,
    verification: VerificationProtection,
}

impl<S: Storage + 'static, C: Clock + 'static> RouterBuilder<S, C> {""",
            """    subject: Option<SubjectResolver>,
    consent: Option<ConsentResolver>,
    #[cfg(feature = "consent")]
    authentication: Option<AuthenticationReporter>,
    verification: VerificationProtection,
}

impl<S: Storage + 'static, C: Clock + 'static> RouterBuilder<S, C> {""",
            1,
        ),
        (
            """            subject: None,
            consent: None,
            verification: VerificationProtection::Unwired,
        }""",
            """            subject: None,
            consent: None,
            #[cfg(feature = "consent")]
            authentication: None,
            verification: VerificationProtection::Unwired,
        }""",
            1,
        ),
        (
            "            consent: self.consent,",
            """            consent: self.consent,
            #[cfg(feature = "consent")]
            authentication: self.authentication,""",
            1,
        ),
        # ---- the builder method.
        (
            "    /// Supply the host's session-bound CSRF token for the device verification form.",
            """    /// Supply the host's answer to "when, and how, did you authenticate this user".
    ///
    /// REQUIRED for RFC 9470 step-up authentication and useless without it. A client answering a
    /// resource server's `insufficient_user_authentication` challenge repeats its authorization
    /// request with `acr_values` and/or `max_age`; this server enforces those against whatever the
    /// reporter returns, and a host with no reporter wired fails every such request. That is the
    /// correct answer rather than a bug: an authorization server that cannot say when the user
    /// logged in cannot honestly claim they logged in recently.
    ///
    /// Ordinary requests, which carry neither parameter, are unaffected whether this is wired or
    /// not.
    ///
    /// The report is taken at FACE VALUE. This crate cannot authenticate anyone and has nothing to
    /// check it against; see the [`crate::consent`] module docs.
    #[cfg(feature = "consent")]
    pub fn with_authentication_reporter<F>(mut self, reporter: F) -> Self
    where
        F: Fn(&HeaderMap) -> Option<crate::consent::Authentication> + Send + Sync + 'static,
    {
        self.authentication = Some(Arc::new(reporter));
        self
    }

    /// Supply the host's session-bound CSRF token for the device verification form.""",
            1,
        ),
        # ---- the handler.
        (
            """    let consent = match &state.consent {
        Some(resolver) => resolver(&ConsentRequest {
            headers: &headers,
            subject: &subject,
            client_id: &validated.client_id,
            scope: &validated.scope,
            redirect_uri: &validated.redirect_uri,
            state: validated.state.as_deref(),
            uri: &uri,
        }),""",
            """    // RFC 9470 s4: `acr_values` and `max_age`, read off the same query pairs the request came
    // from. A malformed `max_age` is redirectable rather than direct, because by here the redirect
    // URI has been validated (RFC 6749 s4.1.2.1) and the client is the party that sent it.
    #[cfg(feature = "consent")]
    let requirement = match crate::consent::AuthenticationRequirement::from_pairs(
        pairs.iter().map(|(k, v)| (k.as_ref(), v.as_ref())),
    ) {
        Ok(r) => r,
        Err(e) => {
            return redirect(
                crate::authorization::AuthorizationErrorRedirect {
                    redirect_uri: validated.redirect_uri.clone(),
                    error: e,
                    state: validated.state.clone(),
                    iss: validated.issuer.clone(),
                }
                .location(),
            )
        }
    };

    // What this user has already granted this client, handed to the resolver below. A storage
    // failure reads as "nothing remembered", which makes the host ask again: the failure mode of
    // this lookup has to be an extra prompt, never a skipped one.
    #[cfg(feature = "consent")]
    let remembered = state
        .server
        .remembered_consent(&validated.client_id, &subject)
        .await
        .unwrap_or(None);

    let consent = match &state.consent {
        Some(resolver) => resolver(&ConsentRequest {
            headers: &headers,
            subject: &subject,
            client_id: &validated.client_id,
            scope: &validated.scope,
            redirect_uri: &validated.redirect_uri,
            state: validated.state.as_deref(),
            uri: &uri,
            #[cfg(feature = "consent")]
            remembered: remembered.as_ref(),
        }),""",
            1,
        ),
        (
            """    match consent {
        ConsentDecision::Approve => {}
        // A refusal is an answer the client is entitled to receive at its (validated) redirect
        // URI, which is exactly what RFC 6749 s4.1.2.1 `access_denied` is for.
        ConsentDecision::Deny => return redirect(validated.denied().location()),
        ConsentDecision::Respond(response) => return *response,
    }

    match state
        .server
        .issue_authorization_code(&validated, subject)
        .await
    {""",
            """    // Only ever set by the host's own `ApproveAndRemember`; see that variant's docs.
    #[cfg(feature = "consent")]
    let mut remember = false;
    match consent {
        ConsentDecision::Approve => {}
        #[cfg(feature = "consent")]
        ConsentDecision::ApproveAndRemember => remember = true,
        // A refusal is an answer the client is entitled to receive at its (validated) redirect
        // URI, which is exactly what RFC 6749 s4.1.2.1 `access_denied` is for.
        ConsentDecision::Deny => return redirect(validated.denied().location()),
        ConsentDecision::Respond(response) => return *response,
    }

    // The host's report of how and when it authenticated this user, for RFC 9470 s4's parameters to
    // be enforced against. An unwired host reports `None`, which satisfies no requirement.
    #[cfg(feature = "consent")]
    let authentication = state.authentication.as_ref().and_then(|f| f(&headers));
    #[cfg(feature = "consent")]
    let issued = state
        .server
        .issue_authorization_code_with_authentication(
            &validated,
            subject.clone(),
            &requirement,
            authentication.as_ref(),
        )
        .await;
    #[cfg(not(feature = "consent"))]
    let issued = state
        .server
        .issue_authorization_code(&validated, subject)
        .await;

    // AFTER issuance, and only on success: a consent records that the user granted something, and
    // nothing was granted if the code was refused.
    #[cfg(feature = "consent")]
    if remember && issued.is_ok() {
        // A failure to remember is not a failure to authorize. The user consented and the code is
        // already minted; turning that into an error would throw away an approval the user actually
        // gave, and the only consequence of the lost record is being asked again next time.
        let _ = state
            .server
            .record_consent(
                &validated.client_id,
                &subject,
                &validated.scope,
                &validated.resource,
                authentication,
            )
            .await;
    }

    match issued {""",
            1,
        ),
    ]


def test_edits():
    e = {}

    # ---- every struct literal of the three record types, by explicit anchor.
    e["crates/oauth-as/src/storage_conformance.rs"] = [
        literal(
            """            refresh_token: Some("rt-minted-by-this-code".to_string()),
        },
    }""",
            8,
        ),
        # The two `sample_*` fixtures end on the same `x5t_s256` line, so each anchor carries the
        # item that FOLLOWS the literal, which is what tells them apart.
        (
            """        ))),
    }
}

fn sample_refresh""",
            """        ))),
        #[cfg(feature = "consent")]
        authentication: None,
    }
}

fn sample_refresh""",
            1,
        ),
        (
            """        ))),
    }
}

#[cfg(test)]""",
            """        ))),
        #[cfg(feature = "consent")]
        authentication: None,
    }
}

#[cfg(test)]""",
            1,
        ),
    ]

    e["crates/oauth-as/src/tests/authorization.rs"] = [
        literal(
            """            refresh_token: Some("the-secret-refresh-token".to_string()),
        },
    }""",
            8,
        ),
    ]

    e["crates/oauth-as/src/tests/token.rs"] = [
        literal("""        family_id: Some("fam-1".into()),
    }""", 8),
        literal("""        state: RefreshTokenState::Spent,
    }""", 8),
    ]

    e["crates/oauth-as/tests/grant_state_edges.rs"] = [
        literal("""        family_id: family.map(str::to_string),
    }""", 8),
        literal("""        state: RefreshTokenState::Active,
    }""", 8),
    ]

    e["crates/oauth-as/tests/jwt.rs"] = [
        literal("""            state: RefreshTokenState::Active,
        }""", 12),
    ]

    e["crates/oauth-as/tests/storage_contract.rs"] = [
        literal("""        state: RefreshTokenState::Active,
    }""", 8),
        literal("""        state: AuthorizationCodeState::Issued,
    }""", 8),
    ]

    e["crates/oauth-as/tests/storage_sweep.rs"] = [
        literal("""            refresh_token: None,
        },
    }""", 8),
        literal("""        family_id: None,
    }""", 8),
        literal("""        state: RefreshTokenState::Active,
    }""", 8),
    ]

    # ---- tests/allocation.rs: the budget line, feature-dependent.
    e["crates/oauth-as/tests/allocation.rs"] = [
        (
            """    let issued_token_budget = 176
        + if cfg!(feature = "dpop") { 16 } else { 0 }
        + if cfg!(feature = "mtls") { 8 } else { 0 }
        + if cfg!(feature = "rar") { 24 } else { 0 };""",
            """    // `consent`: the RFC 9470 authentication report, an `Option<Box<Authentication>>`, 8
    // bytes, because the report itself lives behind the pointer and only a grant the host
    // actually described allocates it.
    let issued_token_budget = 176
        + if cfg!(feature = "dpop") { 16 } else { 0 }
        + if cfg!(feature = "mtls") { 8 } else { 0 }
        + if cfg!(feature = "rar") { 24 } else { 0 }
        + if cfg!(feature = "consent") { 8 } else { 0 };""",
            1,
        ),
    ]

    # ---- tests/support/mod.rs: the delegating store the suites drive faults through has to
    #      implement the new trait methods too.
    e["crates/oauth-as/tests/support/mod.rs"] = [
        (
            """    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        self.inner.revoke_token_family(family_id).await
    }
""",
            """    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        self.inner.revoke_token_family(family_id).await
    }

    // The consent operations delegate straight through: this store's two fault switches are about
    // the token plane, and a consent path that could not be driven through it is a path no suite
    // can test under a failing store.
    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.inner.put_consent(record).await
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<oauth_as::ConsentRecord>, StorageError> {
        self.inner.get_consent(consent_id).await
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<oauth_as::ConsentRecord>, StorageError> {
        self.inner.find_consent(client_id, subject).await
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<oauth_as::ConsentRecord>, StorageError> {
        self.inner.consents_for_subject(subject).await
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        self.inner.revoke_consent(consent_id).await
    }
""",
            1,
        ),
    ]

    # ---- tests/http_verification_outcomes.rs: the delegating store whose user-code lookup fails.
    e["crates/oauth-as/tests/http_verification_outcomes.rs"] = [
        (
            """    fn revoke_token_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.0.revoke_token_family(family_id)
    }
""",
            """    fn revoke_token_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.0.revoke_token_family(family_id)
    }
    // Delegated like everything else: the one behaviour this fixture breaks is the user-code
    // lookup, and a store that also lost its consents would be testing two failures at once.
    #[cfg(feature = "consent")]
    fn put_consent(
        &self,
        record: oauth_as::ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.put_consent(record)
    }
    #[cfg(feature = "consent")]
    fn get_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<oauth_as::ConsentRecord>, StorageError>> + Send {
        self.0.get_consent(consent_id)
    }
    #[cfg(feature = "consent")]
    fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> impl Future<Output = Result<Option<oauth_as::ConsentRecord>, StorageError>> + Send {
        self.0.find_consent(client_id, subject)
    }
    #[cfg(feature = "consent")]
    fn consents_for_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<oauth_as::ConsentRecord>, StorageError>> + Send {
        self.0.consents_for_subject(subject)
    }
    #[cfg(feature = "consent")]
    fn revoke_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.0.revoke_consent(consent_id)
    }
""",
            1,
        ),
    ]

    # ---- tests/storage_conformance_selftest.rs: the deliberately naive store the exported harness
    #      is proven able to fail. Its consent operations are the CORRECT ones: this file's faults
    #      are about atomicity on the token plane, and a wrong consent implementation here would be
    #      a second variable in a suite built to isolate one.
    e["crates/oauth-as/tests/storage_conformance_selftest.rs"] = [
        (
            """            removed += (before - g.tokens.len()) as u64;
        }
        Ok(removed)
    }
""",
            """            removed += (before - g.tokens.len()) as u64;
        }
        Ok(removed)
    }

    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.lock()
            .consents
            .insert(record.consent_id.to_string(), record);
        Ok(())
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<oauth_as::ConsentRecord>, StorageError> {
        Ok(self.lock().consents.get(consent_id).cloned())
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<oauth_as::ConsentRecord>, StorageError> {
        Ok(self
            .lock()
            .consents
            .values()
            .find(|c| &c.client_id == client_id && c.subject.as_ref() == subject)
            .cloned())
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<oauth_as::ConsentRecord>, StorageError> {
        Ok(self
            .lock()
            .consents
            .values()
            .filter(|c| c.subject.as_ref() == subject)
            .cloned()
            .collect())
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        let mut g = self.lock();
        let consent = match g.consents.remove(consent_id) {
            Some(c) => c,
            None => return Ok(0),
        };
        let client_id = &consent.client_id;
        let subject: &str = consent.subject.as_ref();
        let before = g.tokens.len() + g.refresh.len() + g.codes.len();
        g.tokens
            .retain(|_, t| !(&t.client_id == client_id && t.subject.as_deref() == Some(subject)));
        g.refresh
            .retain(|_, r| !(&r.client_id == client_id && r.subject.as_deref() == Some(subject)));
        g.codes
            .retain(|_, c| !(&c.client_id == client_id && c.subject == subject));
        let after = g.tokens.len() + g.refresh.len() + g.codes.len();
        Ok((before - after) as u64)
    }
""",
            1,
        ),
        (
            """    refresh: HashMap<String, RefreshTokenRecord>,
""",
            """    refresh: HashMap<String, RefreshTokenRecord>,
    #[cfg(feature = "consent")]
    consents: HashMap<String, oauth_as::ConsentRecord>,
""",
            1,
        ),
    ]

    # ---- tests/revocation.rs: the RFC 7009 s2.1 cascade. It lives here rather than with the
    #      consent suites because it is core revocation behaviour and must run in a DEFAULT build.
    e["crates/oauth-as/tests/revocation.rs"] = [
        (RFC7009_ANCHOR, RFC7009_TEST + RFC7009_ANCHOR, 1),
    ]
    return e


RFC7009_ANCHOR = """/// RFC 7009 s2.1: revoking a refresh token must break the chain it belonged to, so the next
/// attempt to use it is `invalid_grant` rather than a fresh token."""

RFC7009_TEST = '''/// RFC 7009 s2.1: "If the particular token is a refresh token and the authorization server
/// supports the revocation of access tokens, then the authorization server SHOULD also invalidate
/// all access tokens based on the same authorization grant."
///
/// This is the half of revocation a client cannot do for itself. A client that revokes its refresh
/// token has said "this session is over"; leaving the access token minted from the same grant live
/// means the session is over for the party that asked and not for whoever holds the token, which is
/// exactly inverted when the reason for revoking is that something leaked.
#[tokio::test]
async fn revoking_a_refresh_token_also_kills_the_access_tokens_of_the_same_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh_token = issued.refresh_token.clone().expect("a refresh token");

    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &refresh_token,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("revoking a live refresh token must succeed");

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert_eq!(
        resp,
        IntrospectionResponse::inactive(),
        "the access token issued with the revoked refresh token is still live"
    );
}

'''


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=REPO_DEFAULT)
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, "crates", "oauth-as", "src")):
        print("FAIL: --repo does not look like the oauth-as workspace root", file=sys.stderr)
        return 2

    edits = edits_for()

    # 1. REFUSE TO RUN TWICE. Checked before anything is staged, so a second run cannot produce a
    #    half-applied tree.
    for rel, marker in MARKERS.items():
        path = os.path.join(repo, rel)
        if os.path.exists(path) and marker in open(path).read():
            print(
                f"FAIL: {rel} already contains {marker!r}; this patch has been applied already",
                file=sys.stderr,
            )
            return 1

    # 2. STAGE EVERY EDIT IN MEMORY. Nothing is written until every anchor in every file has
    #    resolved exactly the number of times it was expected to.
    staged = {}
    for rel, file_edits in sorted(edits.items()):
        path = os.path.join(repo, rel)
        if not os.path.exists(path):
            print(f"FAIL: {rel} does not exist", file=sys.stderr)
            return 1
        text = open(path).read()
        for find, replace, expected in file_edits:
            found = text.count(find)
            if found != expected:
                print(
                    f"FAIL: in {rel}, the anchor\n---\n{find}\n---\n"
                    f"was found {found} times, expected exactly {expected}. The file has moved "
                    f"underneath this patch; fix the anchor by hand rather than guessing.",
                    file=sys.stderr,
                )
                return 1
            text = text.replace(find, replace)
        staged[path] = text

    # 3. WRITE.
    for path, text in sorted(staged.items()):
        open(path, "w").write(text)
        print(f"patched {os.path.relpath(path, repo)}")
    print("ok: 0.8.0 consent / step-up host-file edits applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
