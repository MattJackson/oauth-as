// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Faults the exported [`oauth_as::storage_conformance`] harness could not see, found by mutating
//! the harness itself.
//!
//! # Why this file is separate from the selftest, and why it matters more than an ordinary gap
//!
//! `tests/storage_conformance_selftest.rs` plants deliberate faults and proves the harness catches
//! them. That is the right shape, and every fault it plants IS caught. What a `cargo mutants` run
//! of `src/storage_conformance.rs` adds is the other half of the question: which parts of the
//! harness could be DELETED with the selftest still green? Those are the checks that fire for no
//! planted fault, which means they have never been observed doing anything, which means a host
//! reading a green run is being told something nobody has demonstrated.
//!
//! That is worse than an ordinary hole in a test suite. This harness is a published surface: a
//! host enables `test-util` and runs it against its OWN store to obtain evidence that its store is
//! atomic and its cascades are correct. A hole here does not weaken this crate's confidence in
//! itself, it weakens a STRANGER'S confidence in THEIR store, and it does so silently, by
//! reporting green.
//!
//! Six such regions turned up. Three whole round-trip checks (`round_trip_client`,
//! `round_trip_device_grant`, `round_trip_authorization_code`) could each be replaced with an
//! empty body; the `StorageError` arm of `judge_race` could never fire; two `match` guards that
//! decide whether a store answered with the RIGHT record could be replaced with `true`; and
//! `check_storage`, the convenience entry point the module documents for hosts, could return an
//! empty violation list unconditionally.
//!
//! The faults below are written the same way the selftest's are: one edit away from a correct
//! store, of a shape a host writes by accident, never a store that is wrong everywhere.

#![cfg(feature = "test-util")]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use oauth_as::storage_conformance::{check_storage, StorageConformance, Violation, CHECKS};
use oauth_as::{
    AuthorizationCodeRecord, Client, ClientId, DeviceGrant, IssuedToken, MemoryStorage,
    RefreshTokenRecord, ScopeSet, Storage, StorageError,
};

// ---------------------------------------------------------------------- check names
//
// Taken as literals rather than imported, because the harness keeps them private and publishes
// them only through `CHECKS`. `every_name_this_file_asserts_on_is_a_published_check` below pins
// them against that list, so a rename shows up here as a failure rather than as a test that
// quietly stops matching anything.

const ROUND_TRIP_CLIENT: &str = "round_trip/client";
const ROUND_TRIP_DEVICE_GRANT: &str = "round_trip/device_grant";
const ROUND_TRIP_AUTHORIZATION_CODE: &str = "round_trip/authorization_code";
const ROUND_TRIP_CONSENT: &str = "round_trip/consent";
const ATOMIC_TAKE_DEVICE_GRANT: &str = "atomic_take/take_device_grant";
const INDEX_REFUSAL_WRITES_NOTHING: &str = "user_code_index/refusal_writes_nothing";

#[test]
fn every_name_this_file_asserts_on_is_a_published_check() {
    for name in [
        ROUND_TRIP_CLIENT,
        ROUND_TRIP_DEVICE_GRANT,
        ROUND_TRIP_AUTHORIZATION_CODE,
        ROUND_TRIP_CONSENT,
        ATOMIC_TAKE_DEVICE_GRANT,
        INDEX_REFUSAL_WRITES_NOTHING,
    ] {
        assert!(
            CHECKS.contains(&name),
            "{name} is not in the published CHECKS list, so every assertion in this file that \
             names it has silently stopped matching anything"
        );
    }
}

// ---------------------------------------------------------------------- the faulty store

/// One defect, one field. All false is a CORRECT store, and the harness must report nothing for
/// it; the tests below turn on exactly one at a time.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// `put_client` persists everything except the scope ceilings. A store whose schema has no
    /// column for them, or whose migration added the grant list and forgot these two.
    drops_client_scopes: bool,
    /// `put_device_grant` persists everything except the RFC 8628 section 3.2 polling interval.
    drops_device_grant_interval: bool,
    /// `put_authorization_code` persists everything except the RFC 7636 code challenge.
    drops_code_challenge: bool,
    /// `take_device_grant` hands the record to the first caller and fails everyone else with a
    /// `StorageError`, which is what an optimistic-concurrency store does when it surfaces the
    /// write conflict instead of retrying it.
    takes_conflict_after_the_first: bool,
    /// `put_device_grant` REFUSES a user code that belongs to another device, correctly, and has
    /// already written the new grant and repointed the index by the time it decides to.
    repoints_the_index_then_refuses: bool,
    /// `find_consent` is indexed on the client alone, so it answers with whichever consent that
    /// client holds rather than the one belonging to the subject asked about.
    #[cfg(feature = "consent")]
    find_consent_ignores_the_subject: bool,
    /// `take_refresh_token` reads, suspends, then deletes. The selftest's headline fault, needed
    /// here only as something for `check_storage` to find.
    read_then_delete: bool,
    /// Which `put_*` fails, if any. Named rather than boolean because the harness guards each
    /// check on the specific records it managed to plant.
    put_that_fails: Option<&'static str>,
}

struct Faulty {
    faults: Faults,
    inner: MemoryStorage,
    takes: AtomicUsize,
}

impl Faulty {
    fn new(faults: Faults) -> Self {
        Faulty {
            faults,
            inner: MemoryStorage::new(),
            takes: AtomicUsize::new(0),
        }
    }

    fn refuse(&self, which: &'static str) -> Option<StorageError> {
        (self.faults.put_that_fails == Some(which))
            .then(|| StorageError::new(format!("{which} is not available in this store")))
    }
}

/// A suspension point, so that a read-then-delete store behaves the way a store that talks to a
/// database behaves: the task yields while the read is in flight.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Storage for Faulty {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        self.inner.get_client(client_id).await
    }

    async fn put_client(&self, mut client: Client) -> Result<(), StorageError> {
        if let Some(e) = self.refuse("put_client") {
            return Err(e);
        }
        if self.faults.drops_client_scopes {
            client.allowed_scopes = ScopeSet::empty();
            client.default_scopes = ScopeSet::empty();
        }
        self.inner.put_client(client).await
    }

    async fn delete_client(&self, client_id: &ClientId) -> Result<bool, StorageError> {
        self.inner.delete_client(client_id).await
    }

    async fn put_device_grant(&self, mut grant: DeviceGrant) -> Result<(), StorageError> {
        if let Some(e) = self.refuse("put_device_grant") {
            return Err(e);
        }
        if self.faults.drops_device_grant_interval {
            grant.interval = Duration::from_secs(0);
        }
        if self.faults.repoints_the_index_then_refuses {
            // The write happens FIRST and the refusal comes after, which is the ordering a store
            // gets when it validates by reading back what it just wrote.
            let clash = match self
                .inner
                .find_device_grant_by_user_code(&oauth_as::device::normalize_user_code(
                    &grant.user_code,
                ))
                .await?
            {
                Some(existing) => existing.device_code != grant.device_code,
                None => false,
            };
            if clash {
                // Written, indexed, and only then refused: the index now names the grant that was
                // supposed not to exist. The retirement of the previous owner is what a store does
                // when its "upsert the index" step runs before its uniqueness check does.
                let previous = self
                    .inner
                    .find_device_grant_by_user_code(&oauth_as::device::normalize_user_code(
                        &grant.user_code,
                    ))
                    .await?;
                if let Some(previous) = previous {
                    self.inner.take_device_grant(&previous.device_code).await?;
                }
                self.inner.put_device_grant(grant).await?;
                return Err(StorageError::new(
                    "user code already belongs to another device",
                ));
            }
        }
        self.inner.put_device_grant(grant).await
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner.get_device_grant(device_code).await
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner
            .find_device_grant_by_user_code(normalized_user_code)
            .await
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        if self.faults.takes_conflict_after_the_first {
            // The first caller wins, exactly as an atomic store's would; every other concurrent
            // caller is handed the conflict instead of `None`.
            if self.takes.fetch_add(1, Ordering::SeqCst) > 0 {
                return Err(StorageError::new(
                    "write conflict: concurrent modification, retry",
                ));
            }
        }
        self.inner.take_device_grant(device_code).await
    }

    async fn compare_and_swap_device_grant(
        &self,
        expected: &oauth_as::DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        self.inner
            .compare_and_swap_device_grant(expected, updated)
            .await
    }

    async fn put_authorization_code(
        &self,
        mut record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        if let Some(e) = self.refuse("put_authorization_code") {
            return Err(e);
        }
        if self.faults.drops_code_challenge {
            record.code_challenge = String::new();
        }
        self.inner.put_authorization_code(record).await
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        self.inner.take_authorization_code(code).await
    }

    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> Result<(), StorageError> {
        self.inner.put_pushed_authorization_request(record).await
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::par::PushedAuthorizationRequest>, StorageError> {
        self.inner
            .take_pushed_authorization_request(request_uri)
            .await
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        if let Some(e) = self.refuse("put_token") {
            return Err(e);
        }
        // The two family-conditional variants exist because `revoke_family` seeds tokens through
        // two separate accumulators, one for the tokens that carry a family and one for the RFC
        // 6749 s4.4 token that carries none. A store that fails BOTH cannot tell the two guards
        // apart: whichever one is bypassed, the other still stops the check.
        if token.family_id.is_some() {
            if let Some(e) = self.refuse("put_token(with a family)") {
                return Err(e);
            }
        } else if let Some(e) = self.refuse("put_token(with no family)") {
            return Err(e);
        }
        self.inner.put_token(token).await
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Arc<IssuedToken>>, StorageError> {
        self.inner.get_token(access_token).await
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        self.inner.delete_token(access_token).await
    }

    async fn put_refresh_token(&self, record: RefreshTokenRecord) -> Result<(), StorageError> {
        if let Some(e) = self.refuse("put_refresh_token") {
            return Err(e);
        }
        self.inner.put_refresh_token(record).await
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Arc<RefreshTokenRecord>>, StorageError> {
        self.inner.get_refresh_token(refresh_token).await
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        if self.faults.read_then_delete {
            let seen = self.inner.get_refresh_token(refresh_token).await?;
            YieldOnce(false).await;
            self.inner.take_refresh_token(refresh_token).await?;
            return Ok(seen.map(|a| (*a).clone()));
        }
        self.inner.take_refresh_token(refresh_token).await
    }

    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        self.inner.revoke_token_family(family_id).await
    }

    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.inner.put_consent(record).await
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.get_consent(consent_id).await
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError> {
        if self.faults.find_consent_ignores_the_subject {
            // Indexed on the client alone. Deterministic here (the highest consent_id wins) only
            // so the test is not at the mercy of hash order; a real store of this shape answers
            // with whichever row its index reaches first, which is just as wrong and less
            // predictable.
            let mut all = self
                .inner
                .consents_for_subject("subject-conformance")
                .await?;
            all.extend(self.inner.consents_for_subject("subject-other").await?);
            let mut best: Option<Arc<oauth_as::ConsentRecord>> = None;
            for c in all {
                if &c.client_id == client_id
                    // `Option::is_none_or` reads better and is stable only since 1.82. This crate
                    // declares 1.75 and the MSRV job builds the whole package, tests included.
                    && best.as_ref().map_or(true, |b| c.consent_id > b.consent_id)
                {
                    best = Some(c);
                }
            }
            return Ok(best);
        }
        self.inner.find_consent(client_id, subject).await
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.consents_for_subject(subject).await
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        self.inner.revoke_consent(consent_id).await
    }

    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        self.inner.claim_replay_id(id, expires_at).await
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        self.inner.sweep_expired(now).await
    }
}

async fn run_against(faults: Faults) -> Vec<Violation> {
    StorageConformance::new(move || async move { Faulty::new(faults) })
        .run()
        .await
}

fn fired(violations: &[Violation], check: &str) -> bool {
    violations.iter().any(|v| v.check == check)
}

fn detail_of(violations: &[Violation], check: &str) -> String {
    violations
        .iter()
        .filter(|v| v.check == check)
        .map(|v| v.detail.clone())
        .collect::<Vec<_>>()
        .join(" | ")
}

// ---------------------------------------------------------------------- the round-trip checks

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:442:9: replace
/// StorageConformance<F>::round_trip_client with ()`, and
/// `2222:5: replace scopes -> ScopeSet with Default::default()`.
///
/// The entire client round-trip check could be deleted, and separately the fixture's scope sets
/// could be emptied, with the whole selftest still green. Both say the same thing: NO planted
/// fault ever exercised the client round trip, so a host was being told its `put_client` and
/// `get_client` had been checked when nothing had ever been observed to fail there.
///
/// The scope ceilings are the field to plant. [`oauth_as::Client::allowed_scopes`] is what bounds
/// every token this client can obtain, so a store that loses it does not fail: it hands back a
/// client that may request NOTHING, and every request that client makes is refused as exceeding a
/// ceiling that is empty because a column was dropped. The failure looks like a scope
/// configuration problem, and nothing points at persistence.
#[tokio::test]
async fn a_store_that_drops_a_clients_scope_ceilings_is_caught() {
    let violations = run_against(Faults {
        drops_client_scopes: true,
        ..Faults::default()
    })
    .await;
    assert!(
        fired(&violations, ROUND_TRIP_CLIENT),
        "a store that silently drops allowed_scopes and default_scopes was reported clean. The \
         registration comes back with an empty ceiling, so every token request that client makes \
         is refused for exceeding a scope set the store lost: {violations:#?}"
    );
    let detail = detail_of(&violations, ROUND_TRIP_CLIENT);
    assert!(
        detail.contains("allowed_scopes"),
        "the violation must NAME the field that was dropped, or a host is handed two records to \
         diff by eye: {detail}"
    );
}

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:486:9: replace
/// StorageConformance<F>::round_trip_device_grant with ()`.
///
/// Same shape, on the device grant. The field planted here is the RFC 8628 section 3.2 polling
/// `interval`, because losing it is the version of this defect that a host cannot see from either
/// end: the grant works, the flow completes, and every device polls at whatever default it chose.
/// RFC 8628 section 3.5 makes `slow_down` the server's only lever over poll rate, and it is
/// expressed as an increase to THIS number, so a store that reads it back as zero has disabled
/// rate control for the one endpoint RFC 8628 section 5.1 says must be rate limited.
#[tokio::test]
async fn a_store_that_drops_a_device_grants_polling_interval_is_caught() {
    let violations = run_against(Faults {
        drops_device_grant_interval: true,
        ..Faults::default()
    })
    .await;
    assert!(
        fired(&violations, ROUND_TRIP_DEVICE_GRANT),
        "a store that drops the RFC 8628 s3.2 polling interval was reported clean: slow_down is \
         expressed as an increase to that number, so losing it disables the server's only lever \
         over poll rate: {violations:#?}"
    );
    assert!(
        detail_of(&violations, ROUND_TRIP_DEVICE_GRANT).contains("interval"),
        "the violation must name the field"
    );
}

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:541:9: replace
/// StorageConformance<F>::round_trip_authorization_code with ()`.
///
/// Same shape, on the authorization code, and this is the most consequential of the three. The
/// planted field is the RFC 7636 `code_challenge`. A store that loses it does not break the flow;
/// it turns PKCE OFF. The redemption compares the presented verifier against a challenge that came
/// back empty, and OAuth 2.1 section 4.1.1 makes PKCE mandatory precisely because without it a
/// stolen authorization code is redeemable by whoever stole it.
#[tokio::test]
async fn a_store_that_drops_an_authorization_codes_pkce_challenge_is_caught() {
    let violations = run_against(Faults {
        drops_code_challenge: true,
        ..Faults::default()
    })
    .await;
    assert!(
        fired(&violations, ROUND_TRIP_AUTHORIZATION_CODE),
        "a store that drops the RFC 7636 code_challenge was reported clean. That store has turned \
         PKCE off at rest, and OAuth 2.1 s4.1.1 requires it precisely because a stolen code is \
         otherwise redeemable by whoever stole it: {violations:#?}"
    );
    assert!(
        detail_of(&violations, ROUND_TRIP_AUTHORIZATION_CODE).contains("code_challenge"),
        "the violation must name the field"
    );
}

// ---------------------------------------------------------------------- judge_race

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:1115:19: replace > with < in
/// judge_race`.
///
/// The line is `if errors > 0`, the arm that reports concurrent takes failing with a
/// `StorageError`. Since `errors` is a `usize`, `errors < 0` is false for every input, so the arm
/// becomes unreachable and the harness reports NOTHING for a store that fails its callers under
/// contention.
///
/// No planted fault ever produced an erroring take, which is why nothing noticed. It is a real
/// deployment shape and not an exotic one: a store built on optimistic concurrency (a conditional
/// update, a compare-and-set) surfaces the write conflict to its caller rather than retrying it
/// internally. The server maps a `StorageError` to `server_error`, so what the user sees is a
/// legitimate device redemption or refresh failing with a 500 whenever two requests overlap, which
/// is exactly the load at which nobody can reproduce it.
///
/// The fault is deliberately arranged so that exactly ONE racer still wins: a store where every
/// racer errors would also trip the "none of N received it" arm, and the mutation would be caught
/// for the wrong reason.
#[tokio::test]
async fn a_store_that_surfaces_write_conflicts_to_concurrent_takers_is_caught() {
    let violations = run_against(Faults {
        takes_conflict_after_the_first: true,
        ..Faults::default()
    })
    .await;
    let detail = detail_of(&violations, ATOMIC_TAKE_DEVICE_GRANT);
    assert!(
        detail.contains("StorageError"),
        "a store that hands its losing racers a write conflict instead of `None` was reported \
         clean. The server maps that to server_error, so an ordinary concurrent redemption becomes \
         a 500: {violations:#?}"
    );
}

// ---------------------------------------------------------------------- the match guards

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:1298:28: replace match guard
/// g.device_code == "dc-first" with true`.
///
/// The guard is the whole of the `user_code_index/refusal_writes_nothing` check: after a put has
/// been correctly REFUSED for naming a user code that belongs to another device, the code must
/// still resolve to the grant that owned it. Replacing the guard with `true` accepts any answer at
/// all, including the index having been repointed at the very grant the store just refused to
/// create.
///
/// The selftest could not see it. Its `index_overwrites` fault makes the clashing put SUCCEED, so
/// the run stops at the earlier `refuses_duplicate` check and the guard is never the thing being
/// judged. The store planted here is the other, subtler shape: it refuses correctly, and has
/// already written by the time it decides to, which is what a store that validates by reading back
/// what it wrote does. RFC 8628 section 6.1 makes the user code the credential a human types, so
/// the consequence is that the person reading a code off their television approves a DIFFERENT
/// device's grant.
#[tokio::test]
async fn a_refusal_that_has_already_repointed_the_index_is_caught() {
    let violations = run_against(Faults {
        repoints_the_index_then_refuses: true,
        ..Faults::default()
    })
    .await;
    let detail = detail_of(&violations, INDEX_REFUSAL_WRITES_NOTHING);
    assert!(
        detail.contains("not to the grant that owned it") || detail.contains("repointed"),
        "a store that repointed the user-code index and THEN refused the put was reported as \
         having written nothing. RFC 8628 s6.1 makes that code the credential a human types, so \
         the person reading it off their screen now approves the grant the store refused to \
         create: {violations:#?}"
    );
}

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:916:28: replace match guard
/// f.consent_id == mine.consent_id with true`.
///
/// The guard checks that `find_consent` answered with the consent belonging to the SUBJECT it was
/// asked about, not merely with some consent of that client. Replaced with `true`, any record
/// satisfies it.
///
/// The store planted here is the mistake that guard exists for, and it is an easy one: an index on
/// `client_id` alone, because that is the column a developer reaches for first and it looks right
/// in every single-user test. [`oauth_as::Storage::find_consent`] runs on the AUTHORIZATION
/// endpoint's path and is what remembered consent is read from, so answering with another user's
/// record means one user's approval silently authorizes a different user's request, at whatever
/// scope and for whatever RFC 8707 resources that other person agreed to.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_find_consent_indexed_on_the_client_alone_is_caught() {
    let violations = run_against(Faults {
        find_consent_ignores_the_subject: true,
        ..Faults::default()
    })
    .await;
    assert!(
        fired(&violations, ROUND_TRIP_CONSENT),
        "a store whose find_consent ignores the subject was reported clean. That lookup is on the \
         authorization endpoint's path, so one user's remembered consent would authorize another \
         user's request: {violations:#?}"
    );
    assert!(
        detail_of(&violations, ROUND_TRIP_CONSENT).contains("different consent"),
        "the violation must say the record belonged to somebody else, not merely that something \
         was wrong"
    );
}

// ---------------------------------------------------------------------- check_storage

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:1956:5: replace check_storage ->
/// Vec<Violation> with vec![]`.
///
/// [`oauth_as::storage_conformance::check_storage`] is a PUBLISHED entry point: the module
/// documents it as the convenience for a host with a single-threaded test runtime and no spawner
/// to offer. Nothing anywhere called it, so it could return "no violations" unconditionally.
///
/// A host that wrote the two lines the documentation shows would get a permanently green test. It
/// would not merely fail to find defects, it would actively certify a read-then-delete store as
/// conformant, which is the single failure this whole module exists to detect, and the host would
/// have written a test whose passing means nothing at all.
#[tokio::test]
async fn the_published_convenience_entry_point_reports_what_the_builder_reports() {
    let broken = Faults {
        read_then_delete: true,
        ..Faults::default()
    };

    let violations = check_storage(move || async move { Faulty::new(broken) }).await;
    assert!(
        !violations.is_empty(),
        "check_storage certified a read-then-delete store as conformant. It is the entry point \
         the module documentation hands a host, so a host following that documentation would have \
         a green test that means nothing"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.check == "atomic_take/take_refresh_token"),
        "check_storage must find the same thing the builder finds: {violations:#?}"
    );

    // And it agrees with the long form on a store that is correct, so the assertion above is not
    // passing because `check_storage` reports something unconditionally.
    let clean = check_storage(|| async { MemoryStorage::new() }).await;
    assert!(
        clean.is_empty(),
        "check_storage reported violations against the reference store: {clean:#?}"
    );
}

// ---------------------------------------------------------------------- the seeding guards

/// SURVIVORS, eleven of them: `replace &= with |=` at
/// `storage_conformance.rs:1413`, `:1418`, `:1427`, `:1432` (`sweep`), `:1581`, `:1594`, `:1604`
/// (`revoke_family`), and `:1715`, `:1731`, `:1743`, `:1756` (`delete_client`).
///
/// Each is one of the `planted &= report.ok(...)` accumulators that decide whether a check has
/// managed to establish its fixture. `planted` starts `true`, so `|=` pins it to `true` for ever
/// and the `if !planted { return; }` that follows never fires.
///
/// The consequence is not a missed violation, it is an INVENTED one, and that is the reason this
/// is worth a test rather than a shrug. A store that simply cannot accept a record is judged on
/// the records it never managed to plant, so the harness reports "the sweep removed an access
/// token that had not expired" and "delete_client removed another client's access token" about a
/// store that did neither. Those are false accusations about specific methods, and the host acting
/// on this report goes and rewrites a `delete_client` that was correct.
///
/// The property asserted is therefore the one the early return encodes: when a check cannot plant
/// its fixture, every violation it reports is a DIRECT report of the storage failure it observed,
/// and never a conclusion derived from a fixture that was never established.
///
/// The consent checks are excluded, and the exclusion is itself worth recording: three of the four
/// records the consent cascade seeds are put with `let _ =`, so that check draws conclusions from
/// an unestablished fixture by construction, not by mutation.
#[tokio::test]
async fn a_store_that_cannot_write_a_record_is_not_judged_on_records_it_never_stored() {
    for which in [
        "put_client",
        "put_device_grant",
        "put_authorization_code",
        "put_token",
        "put_token(with a family)",
        "put_token(with no family)",
        "put_refresh_token",
    ] {
        let violations = run_against(Faults {
            put_that_fails: Some(which),
            ..Faults::default()
        })
        .await;

        assert!(
            !violations.is_empty(),
            "a store whose {which} always fails must be reported at all"
        );

        let invented: Vec<&Violation> = violations
            .iter()
            .filter(|v| !v.check.starts_with("revoke_consent/") && v.check != ROUND_TRIP_CONSENT)
            .filter(|v| !v.detail.contains("failed unexpectedly"))
            .collect();
        assert!(
            invented.is_empty(),
            "with {which} failing, the harness went on to judge the store on fixtures it never \
             managed to plant, and accused it of defects it does not have. Every violation here \
             is a conclusion drawn from records that were never stored: {invented:#?}"
        );
    }
}

// ---------------------------------------------------------------------- the latch

/// SURVIVOR: `crates/oauth-as/src/storage_conformance.rs:2122:58: replace == with != in
/// Latch::done`.
///
/// `Latch::done` wakes the waiting harness when the count reaches zero:
/// `if self.remaining.fetch_sub(1, SeqCst) == 1 { wake }`. Flipped to `!=`, the wake fires on
/// every completion EXCEPT the last one, which is the only one that matters. That is a classic
/// lost wakeup, and the symptom in a host's CI is not a failure, it is a test suite that HANGS.
///
/// Nothing caught it because the existing tests let the wakes from the earlier racers do the work:
/// if the harness happens to be re-polled after the final racer has already finished, it observes
/// `remaining == 0` and proceeds, and whether that happens is a matter of scheduling.
///
/// This spawner removes the accident. It runs every racer but the last one to COMPLETION before
/// returning, so their `done()` calls all happen before the harness ever awaits, leaving no
/// pending wake to be lucky with; the last racer is deferred so that it completes strictly after
/// the harness has parked. The final wake is then the only thing that can make progress, which is
/// exactly the situation any real runtime produces whenever the last racer is the slowest.
///
/// `harness/race_setup` is expected in this run and is not the point: a spawner that runs its
/// tasks one at a time is one the harness is documented to report on, and it does. The point is
/// that `run()` RETURNS.
#[tokio::test]
async fn the_harness_returns_when_the_last_racer_finishes_after_it_has_parked() {
    let spawned = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&spawned);
    let harness = StorageConformance::new(|| async { MemoryStorage::new() })
        // Two racers: the smallest number that can race, and the smallest that has a "last".
        .racers(2)
        .with_spawn(move |task| {
            if counter.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
                // Run to completion here and now, so this racer's `done()` lands long before the
                // harness parks and leaves no pending wake behind.
                std::thread::spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("racer runtime")
                        .block_on(task)
                })
                .join()
                .expect("the first racer ran to completion");
            } else {
                // Deferred, so its `done()` is the LAST one and lands after the harness has
                // registered its waker and returned Pending.
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("racer runtime")
                        .block_on(task)
                });
            }
        });

    let outcome = tokio::time::timeout(Duration::from_secs(30), harness.run()).await;
    assert!(
        outcome.is_ok(),
        "the harness never returned: the final racer's completion did not wake it, so a host \
         whose slowest racer finishes last gets a test suite that hangs rather than a report"
    );
}

/// The whole file rests on the reference store being clean under this file's own machinery, or a
/// green assertion above could be green because the harness reports nothing for anything.
#[tokio::test]
async fn the_faultless_store_is_reported_clean() {
    let violations = run_against(Faults::default()).await;
    assert!(
        violations.is_empty(),
        "the delegating store with no fault turned on must pass every check, or every assertion \
         in this file is measuring the wrapper rather than the fault: {violations:#?}"
    );
}
