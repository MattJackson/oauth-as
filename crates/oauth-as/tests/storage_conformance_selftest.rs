// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Proves the exported `Storage` conformance harness can go RED.
//!
//! A conformance harness nobody has watched fail is exactly the thing this project refuses to
//! trust: it is indistinguishable, from the outside, from a harness that returns an empty vector
//! whatever it is handed. So this file implements a store that is WRONG in one specific way at a
//! time, in the ways a host writing an honest-looking implementation actually gets it wrong, runs
//! the harness against it, and asserts that the harness reports exactly the violation that
//! deliberate defect deserves.
//!
//! The green side is here too, and is not a formality: the harness must report NOTHING against
//! `MemoryStorage`, and nothing against `NaiveStore` with every fault switched off. Two
//! independent correct implementations passing is what stops the checks from being a description
//! of `MemoryStorage`'s incidental behaviour rather than of the documented contract.

#![cfg(feature = "test-util")]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::SystemTime;

use oauth_as::device::normalize_user_code;
use oauth_as::storage_conformance::{StorageConformance, Violation, CHECKS};
use oauth_as::{
    AuthorizationCodeRecord, Client, ClientId, DeviceGrant, IssuedToken, MemoryStorage,
    RefreshTokenRecord, Storage, StorageError,
};

// ---------------------------------------------------------------------- the broken store

/// Which defect this instance carries. All false is a CORRECT store, which the green tests below
/// depend on: every fault is one edit away from the right implementation, which is the point. A
/// host does not write a store that is wrong everywhere, it writes one that is wrong in one place
/// that compiles, type-checks and passes a single-node test suite.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// `take_*` implemented as read, then delete, with the suspension point a shared store has
    /// between the two. The defect this whole harness exists for.
    read_then_delete: bool,
    /// `put_device_grant` writes the new index entry and nothing else: no retirement of the old
    /// entry, no refusal when the code belongs to another device.
    index_overwrites: bool,
    /// `sweep_expired` reaps every record rather than the dead ones.
    sweep_removes_everything: bool,
    /// `delete_client` removes the registration row only, leaving everything it was issued live.
    delete_client_leaves_credentials: bool,
    /// `revoke_token_family` removes the refresh chain and leaves the access tokens.
    family_revocation_spares_access_tokens: bool,
    /// `delete_token` errors when the token is already gone.
    delete_token_errors_when_absent: bool,
    /// `put_refresh_token` persists every column except `family_id`.
    drops_family_id: bool,
    /// `find_device_grant_by_user_code` normalizes the query on the caller's behalf.
    normalizes_user_codes: bool,
    /// `put_token` persists every column except the RFC 9449 `jkt` binding.
    #[cfg(feature = "dpop")]
    drops_jkt: bool,
    /// `claim_replay_id` implemented as look-then-insert, with the suspension point a shared store
    /// has between the two. The RFC 7523 / RFC 9449 half of the same defect.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    look_then_insert_claim: bool,
    /// `revoke_consent` removes the consent row and returns a count, and leaves every credential
    /// it was supposed to take with it. The user is told the application was stopped; it was not.
    #[cfg(feature = "consent")]
    withdrawal_leaves_credentials: bool,
    /// `revoke_consent` removes every record of the CLIENT rather than of the (client, subject)
    /// pair, so withdrawing one user's consent logs out every other user of that application.
    #[cfg(feature = "consent")]
    withdrawal_takes_other_subjects: bool,
}

#[derive(Default)]
struct Inner {
    clients: HashMap<String, std::sync::Arc<Client>>,
    device_by_code: HashMap<String, DeviceGrant>,
    user_code_index: HashMap<String, String>,
    codes: HashMap<String, AuthorizationCodeRecord>,
    tokens: HashMap<String, std::sync::Arc<IssuedToken>>,
    refresh: HashMap<String, std::sync::Arc<RefreshTokenRecord>>,
    #[cfg(feature = "consent")]
    consents: HashMap<String, std::sync::Arc<oauth_as::ConsentRecord>>,
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    replay_ids: HashMap<String, SystemTime>,
    #[cfg(feature = "par")]
    pushed: HashMap<String, oauth_as::par::PushedAuthorizationRequest>,
}

struct NaiveStore {
    faults: Faults,
    inner: Mutex<Inner>,
}

impl NaiveStore {
    fn new(faults: Faults) -> Self {
        NaiveStore {
            faults,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The suspension point that makes read-then-delete a double spend rather than a curiosity: a
/// shared store's read is a round trip, and the task yields while it is in flight. Written
/// explicitly here because this test's store is an in-process map that would otherwise never
/// suspend, so without it this file would be testing something no host actually deploys.
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

async fn round_trip_to_the_store() {
    YieldOnce(false).await
}

impl Storage for NaiveStore {
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<std::sync::Arc<Client>>, StorageError> {
        Ok(self.lock().clients.get(client_id.as_str()).cloned())
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        self.lock().clients.insert(
            client.client_id.as_str().to_string(),
            std::sync::Arc::new(client),
        );
        Ok(())
    }

    async fn delete_client(&self, client_id: &ClientId) -> Result<bool, StorageError> {
        let mut g = self.lock();
        let existed = g.clients.remove(client_id.as_str()).is_some();
        if self.faults.delete_client_leaves_credentials {
            return Ok(existed);
        }
        g.tokens.retain(|_, t| &t.client_id != client_id);
        g.refresh.retain(|_, r| &r.client_id != client_id);
        g.codes.retain(|_, c| &c.client_id != client_id);
        g.device_by_code.retain(|_, d| &d.client_id != client_id);
        let live: Vec<String> = g.device_by_code.keys().cloned().collect();
        g.user_code_index.retain(|_, dc| live.contains(dc));
        Ok(existed)
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut g = self.lock();
        let normalized = normalize_user_code(&grant.user_code);
        if self.faults.index_overwrites {
            g.user_code_index
                .insert(normalized, grant.device_code.clone());
            g.device_by_code.insert(grant.device_code.clone(), grant);
            return Ok(());
        }
        if let Some(owner) = g.user_code_index.get(&normalized) {
            if owner != &grant.device_code {
                return Err(StorageError::new(
                    "user code belongs to another device_code",
                ));
            }
        }
        if let Some(previous) = g.device_by_code.get(&grant.device_code) {
            let previous_normalized = normalize_user_code(&previous.user_code);
            if previous_normalized != normalized {
                g.user_code_index.remove(&previous_normalized);
            }
        }
        g.user_code_index
            .insert(normalized, grant.device_code.clone());
        g.device_by_code.insert(grant.device_code.clone(), grant);
        Ok(())
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        Ok(self.lock().device_by_code.get(device_code).cloned())
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let key = if self.faults.normalizes_user_codes {
            normalize_user_code(normalized_user_code)
        } else {
            normalized_user_code.to_string()
        };
        let g = self.lock();
        Ok(g.user_code_index
            .get(&key)
            .and_then(|dc| g.device_by_code.get(dc))
            .cloned())
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        if self.faults.read_then_delete {
            let grant = self.lock().device_by_code.get(device_code).cloned();
            round_trip_to_the_store().await;
            if let Some(grant) = &grant {
                let mut g = self.lock();
                g.device_by_code.remove(device_code);
                g.user_code_index
                    .remove(&normalize_user_code(&grant.user_code));
            }
            return Ok(grant);
        }
        let mut g = self.lock();
        let grant = g.device_by_code.remove(device_code);
        if let Some(grant) = &grant {
            let normalized = normalize_user_code(&grant.user_code);
            g.user_code_index.remove(&normalized);
        }
        Ok(grant)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        self.lock().codes.insert(record.code.clone(), record);
        Ok(())
    }

    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> Result<(), StorageError> {
        self.lock()
            .pushed
            .insert(record.request_uri.clone(), record);
        Ok(())
    }

    /// Honours the same `read_then_delete` fault as the other takes: a `request_uri` is single use
    /// (RFC 9126 s4), so a store that reads then deletes double-spends it exactly as it would a
    /// refresh token, and the harness should be able to catch it here too.
    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::par::PushedAuthorizationRequest>, StorageError> {
        if self.faults.read_then_delete {
            let record = self.lock().pushed.get(request_uri).cloned();
            round_trip_to_the_store().await;
            if record.is_some() {
                self.lock().pushed.remove(request_uri);
            }
            return Ok(record);
        }
        Ok(self.lock().pushed.remove(request_uri))
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        if self.faults.read_then_delete {
            let record = self.lock().codes.get(code).cloned();
            round_trip_to_the_store().await;
            if record.is_some() {
                self.lock().codes.remove(code);
            }
            return Ok(record);
        }
        Ok(self.lock().codes.remove(code))
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        #[cfg(feature = "dpop")]
        let token = {
            let mut token = token;
            if self.faults.drops_jkt {
                token.jkt = None;
            }
            token
        };
        self.lock()
            .tokens
            .insert(token.access_token.clone(), std::sync::Arc::new(token));
        Ok(())
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<std::sync::Arc<IssuedToken>>, StorageError> {
        Ok(self.lock().tokens.get(access_token).cloned())
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        let removed = self.lock().tokens.remove(access_token);
        if self.faults.delete_token_errors_when_absent && removed.is_none() {
            return Err(StorageError::new("no such token"));
        }
        Ok(())
    }

    async fn put_refresh_token(&self, mut record: RefreshTokenRecord) -> Result<(), StorageError> {
        if self.faults.drops_family_id {
            record.family_id = String::new();
        }
        self.lock()
            .refresh
            .insert(record.refresh_token.clone(), std::sync::Arc::new(record));
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<std::sync::Arc<RefreshTokenRecord>>, StorageError> {
        Ok(self.lock().refresh.get(refresh_token).cloned())
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        if self.faults.read_then_delete {
            let record = self.lock().refresh.get(refresh_token).cloned();
            round_trip_to_the_store().await;
            if record.is_some() {
                self.lock().refresh.remove(refresh_token);
            }
            return Ok(record.map(|a| (*a).clone()));
        }
        Ok(self
            .lock()
            .refresh
            .remove(refresh_token)
            .map(|a| std::sync::Arc::try_unwrap(a).unwrap_or_else(|a| (*a).clone())))
    }

    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        let mut g = self.lock();
        let before = g.refresh.len();
        g.refresh.retain(|_, r| r.family_id != family_id);
        let mut removed = (before - g.refresh.len()) as u64;
        if !self.faults.family_revocation_spares_access_tokens {
            let before = g.tokens.len();
            g.tokens
                .retain(|_, t| t.family_id.as_deref() != Some(family_id));
            removed += (before - g.tokens.len()) as u64;
        }
        Ok(removed)
    }

    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.lock()
            .consents
            .insert(record.consent_id.to_string(), std::sync::Arc::new(record));
        Ok(())
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        Ok(self.lock().consents.get(consent_id).cloned())
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
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
    ) -> Result<Vec<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
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
        if self.faults.withdrawal_leaves_credentials {
            // The row is gone and a plausible count is returned, so the endpoint answers 200 and
            // the audit log records a withdrawal. Everything it was meant to revoke still works.
            return Ok(5);
        }
        if self.faults.withdrawal_takes_other_subjects {
            let client_id = consent.client_id.clone();
            let before = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
            g.tokens.retain(|_, t| t.client_id != client_id);
            g.refresh.retain(|_, r| r.client_id != client_id);
            g.codes.retain(|_, c| c.client_id != client_id);
            g.device_by_code.retain(|_, d| d.client_id != client_id);
            let after = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
            return Ok((before - after) as u64 + 1);
        }
        let client_id = consent.client_id.clone();
        let subject: String = consent.subject.to_string();
        let before = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        g.tokens
            .retain(|_, t| !(t.client_id == client_id && t.subject.as_deref() == Some(&*subject)));
        g.refresh
            .retain(|_, r| !(r.client_id == client_id && r.subject.as_deref() == Some(&*subject)));
        g.codes
            .retain(|_, c| !(c.client_id == client_id && c.subject == subject));
        // APPROVED device grants for that subject, and their index entries. A grant the user has
        // approved but the device has not polled yet mints a token seconds after the user said
        // stop, so leaving it is the withdrawal failing in the window that matters most. PENDING
        // grants stay: nobody consented to those, so there is nothing there to withdraw.
        //
        // This arm was missing until the harness grew a check for it, which is the whole argument
        // for the check existing.
        let doomed: Vec<String> = g
            .device_by_code
            .iter()
            .filter(|(_, d)| {
                d.client_id == client_id
                    && matches!(
                        &d.state,
                        oauth_as::DeviceGrantState::Approved { subject: s } if *s == subject
                    )
            })
            .map(|(k, _)| k.clone())
            .collect();
        for device_code in doomed {
            if let Some(grant) = g.device_by_code.remove(&device_code) {
                let normalized = oauth_as::device::normalize_user_code(&grant.user_code);
                g.user_code_index.remove(&normalized);
            }
        }
        let after = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        Ok((before - after) as u64)
    }

    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        if self.faults.look_then_insert_claim {
            let seen = self.lock().replay_ids.contains_key(id);
            round_trip_to_the_store().await;
            if seen {
                return Ok(false);
            }
            self.lock().replay_ids.insert(id.to_string(), expires_at);
            return Ok(true);
        }
        let mut g = self.lock();
        if g.replay_ids.contains_key(id) {
            return Ok(false);
        }
        g.replay_ids.insert(id.to_string(), expires_at);
        Ok(true)
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        let mut g = self.lock();
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        let claimed = g.replay_ids.len();
        #[cfg(not(any(feature = "client_assertion", feature = "dpop")))]
        let claimed = 0usize;
        if self.faults.sweep_removes_everything {
            let removed = (g.device_by_code.len()
                + g.codes.len()
                + g.tokens.len()
                + g.refresh.len()
                + claimed) as u64;
            g.device_by_code.clear();
            g.user_code_index.clear();
            g.codes.clear();
            g.tokens.clear();
            g.refresh.clear();
            #[cfg(any(feature = "client_assertion", feature = "dpop"))]
            g.replay_ids.clear();
            return Ok(removed);
        }
        let mut removed = 0u64;
        let before = g.device_by_code.len();
        g.device_by_code.retain(|_, grant| now < grant.expires_at);
        removed += (before - g.device_by_code.len()) as u64;
        let live: Vec<String> = g.device_by_code.keys().cloned().collect();
        g.user_code_index.retain(|_, dc| live.contains(dc));

        let before = g.codes.len();
        g.codes.retain(|_, c| now < c.expires_at);
        removed += (before - g.codes.len()) as u64;

        let before = g.tokens.len();
        g.tokens.retain(|_, t| now < t.expires_at);
        removed += (before - g.tokens.len()) as u64;

        let before = g.refresh.len();
        g.refresh.retain(|_, r| match r.expires_at {
            Some(exp) => now < exp,
            None => true,
        });
        removed += (before - g.refresh.len()) as u64;

        // Claimed replay ids are records like any other: the only thing that reclaims them is this
        // sweep, and there is one per authenticated request.
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        {
            g.replay_ids.retain(|_, exp| now < *exp);
            removed += (claimed - g.replay_ids.len()) as u64;
        }
        Ok(removed)
    }
}

// ---------------------------------------------------------------------- helpers

/// The distinct check names in a report, sorted, so a test can assert on the SET of checks that
/// fired rather than on a count of violations that would move whenever a message is reworded.
fn checks_that_fired(violations: &[Violation]) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = violations.iter().map(|v| v.check).collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn detail_of(violations: &[Violation], check: &str) -> String {
    violations
        .iter()
        .filter(|v| v.check == check)
        .map(|v| v.detail.as_str())
        .collect::<Vec<_>>()
        .join(" | ")
}

async fn run_against(faults: Faults) -> Vec<Violation> {
    StorageConformance::new(move || async move { NaiveStore::new(faults) })
        .run()
        .await
}

// ---------------------------------------------------------------------- GREEN: correct stores

#[tokio::test]
async fn the_reference_store_passes_every_check() {
    let violations = StorageConformance::new(|| async { MemoryStorage::new() })
        .run()
        .await;
    assert!(
        violations.is_empty(),
        "MemoryStorage is the reference implementation of the contract and must pass: {violations:#?}"
    );
}

/// The same, driven through the host's runtime as independent tasks, which is the mode a host is
/// told to use. On this crate's own single-threaded dev runtime that is still interleaving rather
/// than parallelism (see the module docs); it is run anyway because the spawned path has its own
/// collection and completion machinery, and an untested path is not a path.
#[tokio::test]
async fn the_reference_store_passes_with_the_racers_on_the_runtime() {
    let violations = StorageConformance::new(|| async { MemoryStorage::new() })
        .with_spawn(|task| {
            tokio::spawn(task);
        })
        .racers(16)
        .run()
        .await;
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A SECOND correct implementation, written independently of `MemoryStorage` in this file. If the
/// checks had quietly become a description of `MemoryStorage`'s incidental behaviour rather than
/// of the documented contract, this is where that would show.
#[tokio::test]
async fn a_second_correct_store_passes_every_check() {
    let violations = run_against(Faults::default()).await;
    assert!(violations.is_empty(), "{violations:#?}");
}

// ---------------------------------------------------------------------- RED: one fault at a time

/// THE headline defect. Read-then-delete compiles, type-checks, and passes any single-node test
/// suite; on two nodes it is refresh token double spend, authorization code replay detection
/// silently disabled, and device grant double issuance. The harness must catch all three.
#[tokio::test]
async fn read_then_delete_takes_are_caught_on_all_three_single_use_records() {
    let violations = run_against(Faults {
        read_then_delete: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "atomic_take/take_authorization_code",
            "atomic_take/take_device_grant",
            #[cfg(feature = "par")]
            "atomic_take/take_pushed_authorization_request",
            "atomic_take/take_refresh_token",
        ],
        "a read-then-delete store must fail exactly the atomicity checks and nothing else: \
         {violations:#?}"
    );
    for check in checks_that_fired(&violations) {
        let detail = detail_of(&violations, check);
        assert!(
            detail.contains("concurrent takes each received"),
            "{check} must report the double spend it found, got: {detail}"
        );
    }
}

/// The same defect, with the racers handed to the runtime rather than polled together, so both
/// modes of the harness are proven able to see it.
#[tokio::test]
async fn read_then_delete_is_caught_with_the_racers_on_the_runtime_too() {
    let violations = StorageConformance::new(|| async {
        NaiveStore::new(Faults {
            read_then_delete: true,
            ..Faults::default()
        })
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .run()
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "atomic_take/take_authorization_code",
            "atomic_take/take_device_grant",
            #[cfg(feature = "par")]
            "atomic_take/take_pushed_authorization_request",
            "atomic_take/take_refresh_token",
        ],
        "{violations:#?}"
    );
}

#[tokio::test]
async fn a_user_code_index_that_overwrites_is_caught_on_both_halves() {
    let violations = run_against(Faults {
        index_overwrites: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "user_code_index/refusal_writes_nothing",
            "user_code_index/refuses_duplicate",
            "user_code_index/retires_old_entry",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "user_code_index/retires_old_entry").contains("OLD user code"),
        "the superseded-code half must be named for what it is"
    );
}

#[tokio::test]
async fn a_store_that_normalizes_user_codes_for_the_caller_is_caught() {
    let violations = run_against(Faults {
        normalizes_user_codes: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["user_code_index/store_does_not_normalize"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "user_code_index/store_does_not_normalize");
    assert!(detail.contains("WDJB-MJHT"), "{detail}");
    assert!(detail.contains("wdjbmjht"), "{detail}");
}

#[tokio::test]
async fn a_sweep_that_removes_live_records_is_caught() {
    let violations = run_against(Faults {
        sweep_removes_everything: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/count", "sweep_expired/keeps_live"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "sweep_expired/keeps_live");
    // Every kind that was alive must be named, not just the first one noticed.
    assert!(detail.contains("device grant"), "{detail}");
    assert!(detail.contains("access token"), "{detail}");
    assert!(detail.contains("refresh record"), "{detail}");
    assert!(detail.contains("authorization code"), "{detail}");
    assert!(
        detail.contains("expires_at is None"),
        "a chain with no absolute lifetime is not dead, and the harness must say so: {detail}"
    );
}

#[tokio::test]
async fn a_family_revocation_that_spares_access_tokens_is_caught() {
    let violations = run_against(Faults {
        family_revocation_spares_access_tokens: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "revoke_token_family/count",
            "revoke_token_family/removes_the_family",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "revoke_token_family/removes_the_family").contains("4.14.2"),
        "the violation must cite what the remedy is for"
    );
}

#[tokio::test]
async fn a_delete_client_that_leaves_credentials_behind_is_caught() {
    let violations = run_against(Faults {
        delete_client_leaves_credentials: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_client/cascades"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "delete_client/cascades");
    for expected in [
        "access token",
        "refresh chain",
        "authorization code",
        "device grant",
        "user-code index",
    ] {
        assert!(
            detail.contains(expected),
            "the cascade violation must name the {expected} it found: {detail}"
        );
    }
}

#[tokio::test]
async fn a_delete_token_that_is_not_idempotent_is_caught() {
    let violations = run_against(Faults {
        delete_token_errors_when_absent: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_token/idempotent"],
        "{violations:#?}"
    );
}

/// A dropped column is the quiet one: everything works, right up until a refresh token is stolen
/// and the RFC 9700 section 4.14.2 remedy has nothing to walk. The harness must catch it at the
/// round trip, and the family revocation failing alongside is the consequence made visible.
#[tokio::test]
async fn a_store_that_silently_drops_family_id_is_caught() {
    let violations = run_against(Faults {
        drops_family_id: true,
        ..Faults::default()
    })
    .await;

    let fired = checks_that_fired(&violations);
    assert!(
        fired.contains(&"round_trip/refresh_token"),
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/refresh_token");
    assert!(
        detail.contains("family_id") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
    assert!(
        fired.contains(&"revoke_token_family/removes_the_family"),
        "dropping family_id disables reuse revocation, and the harness sees that too: {fired:?}"
    );
}

/// A dropped DPoP binding is the same quiet class of defect as a dropped `family_id`: every
/// request works, and the sender-constrained token the deployment paid for is a bearer token
/// again. RFC 9449 s6 puts the thumbprint in the token's confirmation claim, so losing it at rest
/// is losing the binding for every resource server that introspects.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_store_that_silently_drops_the_dpop_binding_is_caught() {
    let violations = run_against(Faults {
        drops_jkt: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/token");
    assert!(
        detail.contains("jkt") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
}

/// The RFC 7523 / RFC 9449 half of the headline defect. A look-then-insert claim tells two
/// concurrent presentations of the SAME assertion that each of them was the first, which is the
/// replay both RFCs exist to refuse, and nothing downstream notices: the replayed request is
/// exactly the request the client meant to send.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
#[tokio::test]
async fn a_look_then_insert_replay_claim_is_caught() {
    let violations = run_against(Faults {
        look_then_insert_claim: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["atomic_claim/claim_replay_id"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "atomic_claim/claim_replay_id")
            .contains("concurrent takes each received"),
        "the violation must report the double claim it found"
    );
}

// ---------------------------------------------------------------------- the harness's own limits

/// A "spawner" that runs each racer to completion before returning is not concurrency, and an
/// atomicity result obtained that way proves nothing. The harness must SAY so rather than report
/// a clean run, even when the store underneath is a correct one.
#[tokio::test]
async fn a_sequential_spawner_is_reported_rather_than_mistaken_for_a_pass() {
    let violations = StorageConformance::new(|| async { MemoryStorage::new() })
        .with_spawn(|task| {
            // Each task gets its own thread and its own single-threaded runtime, and is joined
            // before the next one is even created: strictly one at a time, which is exactly the
            // shape the gate exists to detect.
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("current-thread runtime")
                    .block_on(task);
            })
            .join()
            .expect("racer thread");
        })
        .racers(2)
        .run()
        .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["harness/race_setup"],
        "a correct store run through a sequential spawner must report the useless race, and \
         nothing else: {violations:#?}"
    );
}

/// Hosts are invited to group, filter and waive by check name, so a name that is not in the
/// published list would be a waiver that silently never matches.
#[tokio::test]
async fn every_violation_names_a_published_check() {
    let violations = run_against(Faults {
        read_then_delete: true,
        index_overwrites: true,
        sweep_removes_everything: true,
        delete_client_leaves_credentials: true,
        family_revocation_spares_access_tokens: true,
        delete_token_errors_when_absent: true,
        drops_family_id: true,
        normalizes_user_codes: true,
        #[cfg(feature = "dpop")]
        drops_jkt: true,
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        look_then_insert_claim: true,
        // Only one of the two withdrawal faults can be set at a time: they are mutually exclusive
        // branches of the same method, and the "leaves credentials" one returns before the other
        // is reachable. Under-revoking is the worse of the two, so it is the one exercised here.
        #[cfg(feature = "consent")]
        withdrawal_leaves_credentials: true,
        #[cfg(feature = "consent")]
        withdrawal_takes_other_subjects: false,
    })
    .await;

    assert!(
        !violations.is_empty(),
        "a store that is wrong in every way must not pass"
    );
    for violation in &violations {
        assert!(
            CHECKS.contains(&violation.check),
            "{} is not in the published CHECKS list",
            violation.check
        );
        assert!(
            !violation.detail.is_empty(),
            "{} reported no detail, so a host cannot act on it",
            violation.check
        );
        // Display is what a host prints; it has to carry both halves.
        let shown = violation.to_string();
        assert!(shown.contains(violation.check) && shown.contains(&violation.detail));
    }
}

/// A withdrawal that removes the consent row, reports a plausible count, and leaves every
/// credential alive. This is the worst failure mode the consent feature has: the endpoint answers
/// 200, the record is gone, the audit log records a withdrawal, and the application the user just
/// revoked keeps working. Nothing anywhere reports it, which is why the harness has to.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_that_leaves_credentials_alive_is_caught() {
    let violations = run_against(Faults {
        withdrawal_leaves_credentials: true,
        ..Faults::default()
    })
    .await;

    let fired = checks_that_fired(&violations);
    assert!(
        fired.contains(&"revoke_consent/cascades"),
        "a withdrawal that revoked nothing must be caught: {violations:#?}"
    );
    assert!(
        detail_of(&violations, "revoke_consent/cascades").contains("was not"),
        "the violation must say what the user was told versus what happened"
    );
}

/// The opposite fault, which is just as real and easier to write by accident: a withdrawal keyed
/// on the CLIENT rather than the (client, subject) pair. One user withdrawing consent logs out
/// every other user of that application, and the count still looks right.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_that_takes_other_subjects_with_it_is_caught() {
    let violations = run_against(Faults {
        withdrawal_takes_other_subjects: true,
        ..Faults::default()
    })
    .await;

    assert!(
        checks_that_fired(&violations).contains(&"revoke_consent/spares_other_subjects"),
        "over-revoking must be caught, not just under-revoking: {violations:#?}"
    );
}

/// The RFC 9126 s4 half of the read-then-delete defect. `take_pushed_authorization_request` is the
/// only thing making a `request_uri` single use, so a store that reads then deletes lets two
/// concurrent authorization requests resolve the same pushed request.
#[cfg(feature = "par")]
#[tokio::test]
async fn a_read_then_delete_pushed_request_take_is_caught() {
    let violations = run_against(Faults {
        read_then_delete: true,
        ..Faults::default()
    })
    .await;

    assert!(
        checks_that_fired(&violations).contains(&"atomic_take/take_pushed_authorization_request"),
        "the PAR handle must be held to the same atomicity as the other take_* operations: \
         {violations:#?}"
    );
}
