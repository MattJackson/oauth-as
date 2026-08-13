// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE THREE COMPARE-AND-SWAP CHECKS IN THE EXPORTED STORAGE HARNESS, EACH ABLE TO ACCEPT A STORE
//! THAT FAILS IT.
//!
//! Survivors of the `--all-features` mutation sweep at commit `42fa851`:
//!
//! ```text
//! storage_conformance.rs replace match guard got.state == DeviceGrantState::Denied with true
//! storage_conformance.rs replace match guard got.state == DeviceGrantState::Denied with true
//! storage_conformance.rs replace match guard index_already_dirty with true
//! ```
//!
//! `compare_and_swap_device_grant` is the newest check in this harness and the reason it exists is
//! written in its own doc comment: a store gets the swap wrong in two ATOMIC ways that no other
//! check here can see. Each of the three checks reads the store back afterwards, and in all three
//! the READ-BACK is guarded by a `match` arm that a mutant can replace with `true`. What that
//! removes is not the check's ability to notice a wrong ANSWER, which the `applied` flag covers,
//! but its ability to notice a wrong WRITE, which is the half a lying store gets away with.
//!
//! This is the class `tests/storage_conformance_gaps.rs` calls worse than an ordinary hole: a host
//! enables `test-util`, runs this harness against its own Postgres or DynamoDB store, and takes an
//! empty violation list as evidence. A hole here reports GREEN for a store that resurrects a
//! redeemed RFC 8628 device code.
//!
//! Every fault below is ONE edit away from a correct store, and each is a shape a real store
//! reaches by accident: an `UPDATE` whose `rows_affected` is read optimistically, a swap that
//! writes before it decides, and an index kept as its own row that an insert-or-update puts back.

// `test-util` alone is NOT enough, and the difference is a build that exists in CI. This file
// implements `Storage` by hand, so it must supply EVERY method the trait declares in the build it
// is compiled for, and seven of those methods are themselves feature-gated: two behind `par`, five
// behind `consent`, plus `claim_replay_id` behind the assertion and DPoP pair. A default
// `cargo test --workspace` turns `test-util` on (oauth-as-postgres asks for it as a
// dev-dependency) and turns those off, so gating on `test-util` alone compiled a hand-written impl
// against a trait with a different method set: twenty-two errors, none of them about the thing this
// file tests.
#![cfg(all(
    feature = "test-util",
    feature = "par",
    feature = "consent",
    feature = "client-assertion"
))]

use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use oauth_as::storage_conformance::{StorageConformance, Violation, CHECKS};
use oauth_as::{
    AuthorizationCodeRecord, Client, ClientId, DeviceGrant, DeviceGrantState, IssuedToken,
    MemoryStorage, RefreshTokenRecord, Storage, StorageError,
};

// Literals rather than imports: the harness keeps the constants private and publishes them only
// through `CHECKS`, which the test below pins them against.
const SWAP_APPLIES_ON_MATCH: &str = "compare_and_swap_device_grant/applies_when_the_state_matches";
const SWAP_HONOURS_EXPECTED: &str = "compare_and_swap_device_grant/honours_expected";
const SWAP_NEVER_RESURRECTS: &str = "compare_and_swap_device_grant/never_resurrects";

#[test]
fn every_name_this_file_asserts_on_is_a_published_check() {
    for name in [
        SWAP_APPLIES_ON_MATCH,
        SWAP_HONOURS_EXPECTED,
        SWAP_NEVER_RESURRECTS,
    ] {
        assert!(
            CHECKS.contains(&name),
            "{name} is not in the published CHECKS list, so every assertion in this file that \
             names it has silently stopped matching anything"
        );
    }
}

/// One defect, one variant. `None` is a CORRECT store and the harness must report nothing for it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// A correct store.
    None,
    /// The swap reports that it applied and writes NOTHING. What an `UPDATE ... WHERE` becomes
    /// when its `rows_affected` is assumed rather than read, or when the write goes to a replica.
    ClaimsItAppliedAndWritesNothing,
    /// The swap reports that it did NOT apply, and writes anyway. The read-modify-write shape:
    /// the store decides after it has already written, and reports the decision.
    ClaimsItDidNotApplyAndWritesAnyway,
    /// The swap does not resurrect the grant itself, but puts it back into the USER-CODE INDEX.
    /// The ordinary Redis or DynamoDB shape, where the index is its own row and the swap upserts
    /// it: the primary lookup stays clean and the verification UI reads the other path.
    ResurrectsIntoTheUserCodeIndex,
}

struct Faulty {
    fault: Fault,
    inner: MemoryStorage,
    /// A user-code index entry this store put back after the grant itself was redeemed. Held here
    /// rather than in `inner`, because the whole point of the fault is that the two disagree.
    resurrected: Mutex<Option<DeviceGrant>>,
}

impl Faulty {
    fn new(fault: Fault) -> Self {
        Faulty {
            fault,
            inner: MemoryStorage::new(),
            resurrected: Mutex::new(None),
        }
    }
}

impl Storage for Faulty {
    async fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        match self.fault {
            Fault::None => {
                self.inner
                    .compare_and_swap_device_grant(expected, updated)
                    .await
            }
            Fault::ClaimsItAppliedAndWritesNothing => Ok(true),
            Fault::ClaimsItDidNotApplyAndWritesAnyway => {
                self.inner.put_device_grant(updated).await?;
                Ok(false)
            }
            Fault::ResurrectsIntoTheUserCodeIndex => {
                let applied = self
                    .inner
                    .compare_and_swap_device_grant(expected, updated.clone())
                    .await?;
                // ONLY when the row is genuinely gone, which is the resurrection case. A swap
                // that merely declined a stale `expected` has a live row and an index that is
                // already correct, and dirtying it there would make the harness's
                // `index_already_dirty` guard excuse the fault this fixture exists to plant.
                if !applied
                    && self
                        .inner
                        .get_device_grant(&updated.device_code)
                        .await?
                        .is_none()
                {
                    // The swap correctly declined to bring the row back, and then the index
                    // upsert ran anyway, which is the half nobody writes a test for.
                    *self.resurrected.lock().expect("no panic while held") = Some(updated);
                }
                Ok(applied)
            }
        }
    }

    async fn find_device_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        if let Some(grant) = self
            .resurrected
            .lock()
            .expect("no panic while held")
            .clone()
        {
            if grant.user_code == user_code
                || oauth_as::device::normalize_user_code(&grant.user_code) == user_code
            {
                return Ok(Some(grant));
            }
        }
        self.inner.find_device_grant_by_user_code(user_code).await
    }

    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        self.inner.get_client(client_id).await
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        self.inner.put_client(client).await
    }

    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, StorageError> {
        self.inner.compare_and_swap_client(expected, updated).await
    }

    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<bool, StorageError> {
        self.inner.delete_client(client_id, window).await
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        self.inner.put_device_grant(grant).await
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner.get_device_grant(device_code).await
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner.take_device_grant(device_code).await
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        self.inner.put_authorization_code(record).await
    }

    async fn compare_and_swap_authorization_code(
        &self,
        expected: &oauth_as::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> Result<bool, StorageError> {
        self.inner
            .compare_and_swap_authorization_code(expected, updated)
            .await
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        self.inner.take_authorization_code(code).await
    }

    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        self.inner.put_pushed_authorization_request(record).await
    }

    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::par::PushedAuthorizationRequest>, StorageError> {
        self.inner
            .take_pushed_authorization_request(request_uri)
            .await
    }

    async fn put_token(
        &self,
        token: IssuedToken,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
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

    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
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
        self.inner.take_refresh_token(refresh_token).await
    }

    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        self.inner.revoke_token_family(family_id, window).await
    }

    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.inner.put_consent(record).await
    }

    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.get_consent(consent_id).await
    }

    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.find_consent(client_id, subject).await
    }

    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.consents_for_subject(subject).await
    }

    async fn compare_and_swap_consent(
        &self,
        expected: Option<&oauth_as::ConsentRecord>,
        updated: oauth_as::ConsentRecord,
    ) -> Result<bool, StorageError> {
        self.inner.compare_and_swap_consent(expected, updated).await
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        self.inner.revoke_consent(consent_id, window).await
    }

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

async fn run(fault: Fault) -> Vec<Violation> {
    StorageConformance::new(move || async move { Faulty::new(fault) })
        .run()
        .await
}

fn reports(violations: &[Violation], check: &str) -> bool {
    violations.iter().any(|v| v.check == check)
}

/// The wrapper with no fault is a correct store, so every "this fault is reported" assertion below
/// is a statement about the fault rather than about the wrapper.
#[tokio::test]
async fn the_wrapper_with_no_fault_is_reported_clean() {
    let violations = run(Fault::None).await;
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A store that says the swap applied and writes nothing is caught.
///
/// Kills `556:30: replace match guard got.state == DeviceGrantState::Denied with true`. The
/// `applied` flag is `true`, which is what a correct store returns, so the ONLY thing that can
/// notice is the read-back; with the guard forced true, any state at all satisfies it. What is
/// lost is the whole of `applies_when_the_state_matches`: the user's decision at the RFC 8628
/// verification UI is reported as recorded and is not recorded.
#[tokio::test]
async fn a_swap_that_claims_success_and_writes_nothing_is_caught() {
    let violations = run(Fault::ClaimsItAppliedAndWritesNothing).await;
    assert!(
        reports(&violations, SWAP_APPLIES_ON_MATCH),
        "a swap that reported success must have changed the stored state: {violations:#?}"
    );
}

/// A store that says the swap did NOT apply and writes anyway is caught.
///
/// Kills `597:30`. The `applied` flag is `false`, which is the correct answer for the STALE
/// `expected` this check presents, so the flag branch stays silent and the read-back is again the
/// only witness. The store has just reverted a `Denied` grant to `Pending`: the user pressed deny,
/// and a poll holding a stale read put the grant back, which is exactly the lost update
/// `compare_and_swap_device_grant` exists to prevent.
#[tokio::test]
async fn a_swap_that_denies_applying_and_writes_anyway_is_caught() {
    let violations = run(Fault::ClaimsItDidNotApplyAndWritesAnyway).await;
    assert!(
        reports(&violations, SWAP_HONOURS_EXPECTED),
        "a swap against a stale expected state must leave the store alone: {violations:#?}"
    );
}

/// A store that puts a redeemed grant back into the USER-CODE INDEX is caught.
///
/// Kills `671:28: replace match guard index_already_dirty with true`. That guard exists to excuse
/// a store whose index was ALREADY dirty before the swap, so that this check reports the swap's
/// own damage and not somebody else's; forced true it excuses every store, including one whose
/// index was clean until the swap dirtied it. What is lost is the user-code half of the
/// resurrection: `get_device_grant` is clean, so nothing else here looks, and the code a human
/// typed into the verification page resolves to a grant that has already been exchanged for a
/// token.
#[tokio::test]
async fn a_swap_that_resurrects_only_the_user_code_index_is_caught() {
    let violations = run(Fault::ResurrectsIntoTheUserCodeIndex).await;
    assert!(
        reports(&violations, SWAP_NEVER_RESURRECTS),
        "the user-code index must not name a redeemed grant: {violations:#?}"
    );
}
