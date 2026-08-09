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
    /// `take_device_grant` removes the grant and leaves its user-code row behind. The row carries
    /// its own copy of the grant (see `Inner::user_code_index`), so the code a human typed goes on
    /// resolving to a grant that has already been redeemed.
    index_outlives_the_taken_grant: bool,
    /// `sweep_expired` reaps every record rather than the dead ones.
    sweep_removes_everything: bool,
    /// `sweep_expired` reaps NOTHING and reports zero: the opposite miss, and the one a host never
    /// notices, because a sweep that removes too little looks exactly like a store with nothing to
    /// remove until the disk fills.
    sweep_removes_nothing: bool,
    /// `sweep_expired` fails when it matched no rows, the way a driver that treats "no rows
    /// affected" as an error does. The host runs this on a timer against a store that is usually
    /// idle, so it is the common case that breaks, not the rare one.
    sweep_errors_when_it_removed_nothing: bool,
    /// `delete_client` removes the registration row only, leaving everything it was issued live.
    delete_client_leaves_credentials: bool,
    /// `delete_client` answers true whether or not a registration was there, the way an
    /// implementation that returns "the statement ran" rather than "a row went away" does. RFC 7592
    /// section 2.3 is answered from this boolean, so the management endpoint reports 204 for a
    /// client id that never existed.
    delete_client_always_reports_true: bool,
    /// `revoke_token_family` removes the refresh chain and leaves the access tokens.
    family_revocation_spares_access_tokens: bool,
    /// `revoke_token_family` removes EVERY family, not the one named: a predicate that was dropped
    /// or that matched on the wrong column. Reuse detection on one stolen chain then logs out every
    /// client in the deployment.
    family_revocation_takes_every_family: bool,
    /// `delete_token` errors when the token is already gone.
    delete_token_errors_when_absent: bool,
    /// `put_refresh_token` persists every column except `family_id`.
    drops_family_id: bool,
    /// `put_client` persists every column except the credential: the registration reads back as a
    /// PUBLIC client. Nothing errors, and every request that was supposed to prove possession of a
    /// secret is now answered by anyone who knows the client id.
    drops_the_client_secret: bool,
    /// `find_device_grant_by_user_code` normalizes the query on the caller's behalf.
    normalizes_user_codes: bool,
    /// `put_token` persists every column except the RFC 9449 `jkt` binding.
    #[cfg(feature = "dpop")]
    drops_jkt: bool,
    /// `claim_replay_id` implemented as look-then-insert, with the suspension point a shared store
    /// has between the two. The RFC 7523 / RFC 9449 half of the same defect.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    look_then_insert_claim: bool,
    /// `claim_replay_id` is keyed on nothing: the first claim takes the one slot the store has (a
    /// unique constraint on the wrong column, a fixed key name), so it is atomic under a race and
    /// still refuses every id that follows.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    claim_is_keyed_on_nothing: bool,
    /// `sweep_expired` reclaims every record kind except the claimed replay ids: the table nothing
    /// else deletes from, growing once per authenticated request forever.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    sweep_forgets_replay_ids: bool,
    /// `revoke_consent` removes the consent row and returns a count, and leaves every credential
    /// it was supposed to take with it. The user is told the application was stopped; it was not.
    #[cfg(feature = "consent")]
    withdrawal_leaves_credentials: bool,
    /// `revoke_consent` removes every record of the CLIENT rather than of the (client, subject)
    /// pair, so withdrawing one user's consent logs out every other user of that application.
    #[cfg(feature = "consent")]
    withdrawal_takes_other_subjects: bool,
    /// `revoke_consent` revokes exactly the right credentials and counts the consent row along with
    /// them. The count is what an operator investigating an incident reads, and the trait is
    /// explicit that the row itself is not one of the credentials.
    #[cfg(feature = "consent")]
    withdrawal_counts_the_consent_row: bool,
}

#[derive(Default)]
struct Inner {
    clients: HashMap<String, std::sync::Arc<Client>>,
    device_by_code: HashMap<String, DeviceGrant>,
    /// The user-code lookup, keyed by NORMALIZED code, holding its OWN COPY of the grant rather
    /// than a pointer into `device_by_code`.
    ///
    /// Denormalized on purpose, and it is what makes `user_code_index/cleared_by_take` observable
    /// at all. A store that joins a pointer table back to the primary table cannot fail that check
    /// however badly it maintains the index: an entry left pointing at a row that is gone resolves
    /// to nothing, which is the right answer by accident. The stores that DO fail it are the ones
    /// where the lookup is its own row, which is the ordinary shape of a Redis or DynamoDB
    /// implementation (`SET usercode:WDJBMJHT <the serialized grant>`), and the one this store
    /// therefore models.
    user_code_index: HashMap<String, DeviceGrant>,
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
        let client = if self.faults.drops_the_client_secret {
            // The shape a host writes when the credential column is added to the struct and not to
            // the INSERT: the row is there, the client authenticates as a public client, and
            // nothing in the request path can tell that a secret was ever registered.
            Client {
                auth: oauth_as::ClientAuth::Public,
                ..client
            }
        } else {
            client
        };
        self.lock().clients.insert(
            client.client_id.as_str().to_string(),
            std::sync::Arc::new(client),
        );
        Ok(())
    }

    async fn delete_client(&self, client_id: &ClientId) -> Result<bool, StorageError> {
        let mut g = self.lock();
        let existed = g.clients.remove(client_id.as_str()).is_some();
        // Reported instead of `existed` by the fault: the answer is "the statement ran", not "a
        // registration went away".
        let reported = existed || self.faults.delete_client_always_reports_true;
        if self.faults.delete_client_leaves_credentials {
            return Ok(reported);
        }
        g.tokens.retain(|_, t| &t.client_id != client_id);
        g.refresh.retain(|_, r| &r.client_id != client_id);
        g.codes.retain(|_, c| &c.client_id != client_id);
        g.device_by_code.retain(|_, d| &d.client_id != client_id);
        g.user_code_index.retain(|_, d| &d.client_id != client_id);
        Ok(reported)
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut g = self.lock();
        let normalized = normalize_user_code(&grant.user_code);
        if self.faults.index_overwrites {
            g.user_code_index.insert(normalized, grant.clone());
            g.device_by_code.insert(grant.device_code.clone(), grant);
            return Ok(());
        }
        if let Some(owner) = g.user_code_index.get(&normalized) {
            if owner.device_code != grant.device_code {
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
        g.user_code_index.insert(normalized, grant.clone());
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
        Ok(self.lock().user_code_index.get(&key).cloned())
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        // The index row is a second write, and the fault is that the take does not make it.
        let clears_the_index = !self.faults.index_outlives_the_taken_grant;
        if self.faults.read_then_delete {
            let grant = self.lock().device_by_code.get(device_code).cloned();
            round_trip_to_the_store().await;
            if let Some(grant) = &grant {
                let mut g = self.lock();
                g.device_by_code.remove(device_code);
                if clears_the_index {
                    g.user_code_index
                        .remove(&normalize_user_code(&grant.user_code));
                }
            }
            return Ok(grant);
        }
        let mut g = self.lock();
        let grant = g.device_by_code.remove(device_code);
        if let Some(grant) = &grant {
            if clears_the_index {
                let normalized = normalize_user_code(&grant.user_code);
                g.user_code_index.remove(&normalized);
            }
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
        if self.faults.family_revocation_takes_every_family {
            let removed = (g.refresh.len() + g.tokens.len()) as u64;
            g.refresh.clear();
            g.tokens.clear();
            return Ok(removed);
        }
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
        // The consent row was removed at the top of this method, and counting it here is the whole
        // fault: everything else about this withdrawal is right.
        let counts_the_row = u64::from(self.faults.withdrawal_counts_the_consent_row);
        Ok((before - after) as u64 + counts_the_row)
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
        if self.faults.claim_is_keyed_on_nothing {
            // One slot for every id there will ever be. Atomic, and useless: the first jti this
            // process sees is claimed and every later one collides with it.
            let mut g = self.lock();
            if !g.replay_ids.is_empty() {
                return Ok(false);
            }
            g.replay_ids.insert(id.to_string(), expires_at);
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
        if self.faults.sweep_removes_nothing {
            return Ok(0);
        }
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
        // The index rows expire with the grants they carry: one row per grant, so the same
        // predicate, and the count is taken from the primary table only.
        g.user_code_index.retain(|_, grant| now < grant.expires_at);

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
        if !self.faults.sweep_forgets_replay_ids {
            g.replay_ids.retain(|_, exp| now < *exp);
            removed += (claimed - g.replay_ids.len()) as u64;
        }
        if removed == 0 && self.faults.sweep_errors_when_it_removed_nothing {
            return Err(StorageError::new("no rows affected"));
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
        index_outlives_the_taken_grant: true,
        sweep_removes_everything: true,
        // Mutually exclusive with `sweep_removes_everything`, which returns first, and with each
        // other: a sweep cannot both remove nothing and fail, and the harness would only ever see
        // whichever branch runs.
        sweep_removes_nothing: false,
        sweep_errors_when_it_removed_nothing: false,
        delete_client_leaves_credentials: true,
        delete_client_always_reports_true: true,
        family_revocation_spares_access_tokens: true,
        // Mutually exclusive with the line above: this one returns before it.
        family_revocation_takes_every_family: false,
        delete_token_errors_when_absent: true,
        drops_family_id: true,
        drops_the_client_secret: true,
        normalizes_user_codes: true,
        #[cfg(feature = "dpop")]
        drops_jkt: true,
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        look_then_insert_claim: true,
        // Mutually exclusive with `look_then_insert_claim`, which returns first.
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        claim_is_keyed_on_nothing: false,
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        sweep_forgets_replay_ids: true,
        // Only one of the two withdrawal faults can be set at a time: they are mutually exclusive
        // branches of the same method, and the "leaves credentials" one returns before the other
        // is reachable. Under-revoking is the worse of the two, so it is the one exercised here.
        #[cfg(feature = "consent")]
        withdrawal_leaves_credentials: true,
        #[cfg(feature = "consent")]
        withdrawal_takes_other_subjects: false,
        // Unreachable behind `withdrawal_leaves_credentials`, which returns first.
        #[cfg(feature = "consent")]
        withdrawal_counts_the_consent_row: false,
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

// ------------------------------------------------------- the checks nobody had watched go red
//
// Every check in `CHECKS` above this line had a fault behind it. These nine did not, which made
// them indistinguishable from checks that cannot fail at all: a harness a host runs against its
// own store to be told it is safe, reporting green from a check that has never been observed to
// report anything else. Each fault below drives ONE named check, and where a fault necessarily
// trips a neighbouring check as well (a sweep that removes nothing cannot report the right count)
// the test says which and asserts both, so the two are still told apart.

/// A take that removes the grant and leaves the user-code row. RFC 8628 s6.1 makes the user code
/// the credential a human types, so a redeemed grant that still answers to it is a second
/// redemption waiting for anyone who saw the code on the screen.
#[tokio::test]
async fn a_take_that_leaves_the_user_code_row_behind_is_caught() {
    let violations = run_against(Faults {
        index_outlives_the_taken_grant: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["user_code_index/cleared_by_take"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "user_code_index/cleared_by_take").contains("user code"),
        "the violation must name the path the redeemed grant is still reachable by"
    );
}

/// The opposite of the sweep fault that already existed. `sweep_removes_everything` proves
/// `keeps_live` and `count` can fire; nothing proved `removes_dead` could, and a sweep that
/// removes nothing is the miss a host never notices, because an idle store and a broken sweep look
/// identical until the disk fills.
#[tokio::test]
async fn a_sweep_that_removes_nothing_is_caught() {
    let violations = run_against(Faults {
        sweep_removes_nothing: true,
        ..Faults::default()
    })
    .await;

    // `count` and `reclaims_replay_ids` necessarily go with it: a sweep that removes nothing
    // cannot report the right number, and the replay ids are records it did not remove either.
    // Asserted by name so the three are still told apart rather than counted together.
    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "sweep_expired/count",
            #[cfg(any(feature = "client_assertion", feature = "dpop"))]
            "sweep_expired/reclaims_replay_ids",
            "sweep_expired/removes_dead",
        ],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "sweep_expired/removes_dead");
    // Every dead kind must be named, so a store is told which sweep it did not write.
    for expected in [
        "device grant",
        "authorization code",
        "access token",
        "refresh record",
        "user code",
    ] {
        assert!(
            detail.contains(expected),
            "the violation must name the {expected} that survived: {detail}"
        );
    }
}

/// A sweep that fails when it matched no rows. The host runs this on a timer against a store that
/// is usually idle, so the failing case is the common one, and a host that wires the result to an
/// alert learns to ignore the alert.
#[tokio::test]
async fn a_sweep_that_errors_when_there_is_nothing_to_do_is_caught() {
    let violations = run_against(Faults {
        sweep_errors_when_it_removed_nothing: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/empty_is_zero"],
        "{violations:#?}"
    );
}

/// A sweep that reclaims everything except the claimed replay ids. RFC 7523 s3 and RFC 9449 s4.3
/// make a jti single use, so the store keeps one row per authenticated request and this sweep is
/// the only thing that ever deletes one.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
#[tokio::test]
async fn a_sweep_that_never_reclaims_replay_ids_is_caught() {
    let violations = run_against(Faults {
        sweep_forgets_replay_ids: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/reclaims_replay_ids"],
        "{violations:#?}"
    );
}

/// A family revocation that matches every family. RFC 9700 s4.14.2 runs this on evidence that ONE
/// chain was stolen; a predicate that was dropped turns that into a deployment-wide logout, and
/// the operator reading the count sees a bigger number and no reason to doubt it.
#[tokio::test]
async fn a_family_revocation_that_takes_every_family_is_caught() {
    let violations = run_against(Faults {
        family_revocation_takes_every_family: true,
        ..Faults::default()
    })
    .await;

    // `count` goes with it, because a revocation that removed 7 records cannot report the 4 the
    // named family held. Both are asserted by name so the over-revocation is not mistaken for a
    // miscount.
    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "revoke_token_family/count",
            "revoke_token_family/spares_other_families",
        ],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "revoke_token_family/spares_other_families");
    assert!(
        detail.contains("access token of another") && detail.contains("refresh record of another"),
        "both kinds belonging to the untouched family must be named: {detail}"
    );
    assert!(
        detail.contains("no family_id at all"),
        "RFC 6749 s4.4 tokens carry no family and must not be swept up by matching None: {detail}"
    );
}

/// A `delete_client` that answers true whether or not anything was there. RFC 7592 s2.3 is
/// answered from this boolean, so the management endpoint confirms the deletion of a client id
/// that never existed, which is both a lie and an existence oracle.
#[tokio::test]
async fn a_delete_client_that_always_reports_true_is_caught() {
    let violations = run_against(Faults {
        delete_client_always_reports_true: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_client/reports_whether_it_removed"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "delete_client/reports_whether_it_removed").contains("already gone"),
        "the violation must say which of the two answers was wrong"
    );
}

/// A claim that is atomic and still useless: one slot for every id there will ever be. The race
/// check passes, because exactly one racer wins it; the SEQUENTIAL check is the only thing that
/// sees that the second id, belonging to a different client and a different request, is refused as
/// a replay of the first.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
#[tokio::test]
async fn a_replay_claim_keyed_on_nothing_is_caught_even_though_it_wins_the_race() {
    let violations = run_against(Faults {
        claim_is_keyed_on_nothing: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["claim_replay_id/refuses_a_second_claim"],
        "the RACE check must stay green here, or this proves nothing about the sequential one: \
         {violations:#?}"
    );
    assert!(
        detail_of(&violations, "claim_replay_id/refuses_a_second_claim")
            .contains("never claimed answered false"),
        "the violation must name the half that failed: this store refuses ids it has not seen, \
         which is the opposite of the double-claim the race check looks for"
    );
}

/// A withdrawal that revokes exactly the right credentials and reports one too many, because it
/// counted the consent row. The count is what an operator reads while deciding whether a
/// withdrawal did what the user asked, so a number that does not describe the credentials is a
/// wrong answer to the only question being asked.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_that_counts_the_consent_row_is_caught() {
    let violations = run_against(Faults {
        withdrawal_counts_the_consent_row: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["revoke_consent/count"],
        "the cascade itself is correct here, so only the count may fire: {violations:#?}"
    );
    assert!(
        detail_of(&violations, "revoke_consent/count").contains("not counted"),
        "the violation must state the rule the count broke"
    );
}

/// A client row that persists without its credential. The registration reads back PUBLIC, so
/// every confidential-client authentication succeeds for anyone holding the client id alone, and
/// there is no error anywhere: the client authenticates, exactly as a public client is supposed
/// to. Field-drop faults existed for the refresh token and the access token; the client, which is
/// the record that decides who is allowed to ask at all, had none.
#[tokio::test]
async fn a_client_that_loses_its_credential_on_the_way_in_is_caught() {
    let violations = run_against(Faults {
        drops_the_client_secret: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/client"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/client");
    assert!(
        detail.contains("field auth") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
    // The stored secret is a one-way hash and the violation prints what it read back, so this is
    // also where a harness that logged the credential itself would show up.
    assert!(
        !detail.contains("conformance-secret"),
        "a violation must not print the credential it compared: {detail}"
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
