// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A WRITE MUST NOT RESURRECT STATE THAT A REVOCATION REMOVED.
//!
//! One rule, and this file is the half of its evidence that does not need a gated signer. The two
//! that do live in `issuance_race_containment.rs`, which reproduces the same rule across the
//! `Es256Signer` await.
//!
//! Every test here makes the interleaving DETERMINISTIC rather than racing for it, and does it the
//! same way: the revocation is performed at exactly the point a concurrent one would have landed,
//! which for these sites is between a read and the write derived from it. A race that has to be
//! won by timing is a test that passes on a fast machine and reports nothing on a slow one.
//!
//! Each test names, in its own doc comment, the write it pins and what that write would resurrect.
//! There are six: reuse detection and code replay raced across the `await` inside ES256 signing,
//! RFC 7592 `update_registration`'s blind `put_client` after three `await` points, the device
//! grant's approval swap, the PAR handle's consumption, the consent widen, and the refresh
//! rotation's spent marker.
//!
//! HOW THESE WERE SEEN RED, stated exactly rather than implied. The `Storage` break had to land
//! before any of them could compile, so they could not be written against the 0.9.0 tree. Each was
//! instead proven by REINTRODUCING its defect into the fixed tree and watching the named assertion
//! fail:
//!
//! - site 2, by putting `put_client` back in `update_registration`: the update succeeded and
//!   renamed the deleted registration.
//! - site 3 and site 4, by making `MemoryInner::is_revoked` return `false`: the rotation's write
//!   landed behind the cascade, and the refusal path restored a revoked chain.
//! - site 5, by removing the shape guard in `record_consent`: the withdrawn consent came back.
//!
//! Sites 1 and 6 were red WITHOUT any reintroduction, which is better evidence: site 1's two
//! reproductions were committed `#[ignore]`d at 0.9.0 and are in `issuance_race_containment.rs`,
//! and site 6's swap already refused, so the test here is what makes the rule checkable rather
//! than a comment.

mod support;

use std::sync::Mutex;

use oauth_as::{
    AuthorizationServer, Client, ClientId, ClientMetadata, Clock, DeviceGrant, DeviceGrantState,
    MemoryStorage, RegistrationAttempt, RegistrationConfig, RegistrationDecision,
    RegistrationFailure, RegistrationPolicy, ScopeSet, ServerConfig, Storage, TokenRequest,
};

use support::{
    confidential_client, far_future_window, mint_code_token, ManualClock, CONFIDENTIAL_REDIRECT,
    CONFIDENTIAL_SECRET,
};

// ----------------------------------------------------------------------------------- fixtures

/// A store that performs a REVOCATION in the window a concurrent request would have used, and
/// does it from inside the read that request's write is derived from.
///
/// This is the only honest way to pin these sites. Doing the revocation before the call under test
/// does not reproduce anything: the call re-reads, sees the record gone, and refuses at its own
/// front door, so the write is never reached and the test passes whether or not the defect is
/// present. That mistake was made first here, and it is worth writing down, because a test that
/// passes with the defect reintroduced is worse than no test at all.
///
/// The read is armed once. It hands back what the caller asked for AND THEN revokes, so the caller
/// proceeds with a snapshot that is already stale, which is exactly the state a request suspended
/// across an `await` is in.
struct RevokeDuringRead {
    inner: MemoryStorage,
    /// The window the armed revocation records.
    ///
    /// Defaults to `far_future_window()`, whose `recorded_at` is far enough out to cover every
    /// grant: the tests here are about a CASCADE or a PUT-BACK, so they want unconditional
    /// refusal and would otherwise pass or fail on an unrelated comparison.
    ///
    /// A test about WHEN a grant was established must override it, because a far-future
    /// `recorded_at` refuses everything and would make such a test pass with its defect present.
    /// That happened while writing the `client_credentials` test below, and it is the reason this
    /// field exists rather than a constant.
    window: oauth_as::store::RevocationWindow,
    /// What to revoke, and whether it has fired yet. Shared with the test so the store can be
    /// armed AFTER the server owns it, which is what lets the fixture be set up through the same
    /// store the race then runs on.
    armed: std::sync::Arc<Mutex<Option<Revocation>>>,
    /// How far to move the server's clock when the revocation fires, if at all.
    ///
    /// A test about WHICH INSTANT a grant is dated from cannot be written without this.
    /// `ManualClock` does not advance on its own, so entry and issuance are the same instant and a
    /// barrier recorded BETWEEN them is inexpressible: the defective ordering and the fixed one
    /// both refuse, and the test passes either way. Advancing here — from inside the read the
    /// revocation fires from, which is between the two — separates them, so a `recorded_at` placed
    /// in the gap is refused by one ordering and admitted by the other.
    advance_on_fire: Option<(ManualClock, std::time::Duration)>,
}

enum Revocation {
    /// Delete the client, the way a concurrent RFC 7592 s2.3 request would.
    Client(ClientId),
    /// Withdraw the consent, the way a user clicking "revoke" would.
    #[cfg(feature = "consent")]
    Consent(String),
    /// Revoke the whole refresh family, the way RFC 7009 revocation or a reuse detection would.
    Family(String),
}

/// The test's end of the trigger.
type Trigger = std::sync::Arc<Mutex<Option<Revocation>>>;

impl RevokeDuringRead {
    fn new(inner: MemoryStorage) -> (Self, Trigger) {
        let armed: Trigger = std::sync::Arc::new(Mutex::new(None));
        (
            RevokeDuringRead {
                inner,
                window: far_future_window(),
                armed: armed.clone(),
                advance_on_fire: None,
            },
            armed,
        )
    }

    /// Fire the armed revocation, once, and only from the read it belongs to.
    ///
    /// The `want` predicate is what makes this a fixture rather than a trap. Every trigger used to
    /// fire from every armed read, and `get_client` runs on the token endpoint before anything
    /// else does, so a family revocation armed for `take_refresh_token` fired during client
    /// authentication instead. The take then found nothing, the request was refused as
    /// `invalid_grant`, and the refusal path under test never ran: the test passed with the defect
    /// reintroduced, which is the exact failure this whole file warns about at the top.
    async fn fire_from(&self, want: fn(&Revocation) -> bool) {
        let armed = {
            let mut slot = self.armed.lock().unwrap_or_else(|e| e.into_inner());
            match slot.as_ref() {
                Some(r) if want(r) => slot.take(),
                _ => None,
            }
        };
        // Only when the revocation actually fires: an advance on every armed read would move the
        // clock for reads this trigger deliberately does not answer, and the gap under test would
        // no longer be the one the revocation sits in.
        if armed.is_some() {
            if let Some((clock, by)) = self.advance_on_fire.as_ref() {
                clock.advance(*by);
            }
        }
        match armed {
            Some(Revocation::Client(id)) => {
                self.inner.delete_client(&id, self.window).await.unwrap();
            }
            #[cfg(feature = "consent")]
            Some(Revocation::Consent(id)) => {
                self.inner.revoke_consent(&id, self.window).await.unwrap();
            }
            Some(Revocation::Family(id)) => {
                self.inner
                    .revoke_token_family(&id, self.window)
                    .await
                    .unwrap();
            }
            None => {}
        }
    }
}

impl Storage for RevokeDuringRead {
    /// The read `update_registration` derives its write from. It answers truthfully, and the
    /// deletion lands immediately afterwards.
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<std::sync::Arc<Client>>, oauth_as::StorageError> {
        let found = self.inner.get_client(client_id).await?;
        if found.is_some() {
            self.fire_from(|r| matches!(r, Revocation::Client(_))).await;
        }
        Ok(found)
    }

    /// The read `record_consent` derives its widen from, with the withdrawal landing after it.
    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, oauth_as::StorageError> {
        let found = self.inner.find_consent(client_id, subject).await?;
        if found.is_some() {
            self.fire_from(|r| matches!(r, Revocation::Consent(_)))
                .await;
        }
        Ok(found)
    }

    /// The TAKE a rotation makes before it judges anything. The revocation lands immediately
    /// after it, so the record is out of the store when the cascade runs, which is precisely the
    /// window site 4 is about: the cascade cannot see the record, and the refusal path that
    /// follows is about to write it back.
    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<oauth_as::RefreshTokenRecord>, oauth_as::StorageError> {
        let taken = self.inner.take_refresh_token(refresh_token).await?;
        if taken.is_some() {
            self.fire_from(|r| matches!(r, Revocation::Family(_))).await;
        }
        Ok(taken)
    }

    oauth_as::delegate_storage! {
        to inner;
        put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        put_token, get_token, delete_token,
        put_refresh_token, get_refresh_token, revoke_token_family,
        put_consent, compare_and_swap_consent, get_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

struct OpenPolicy;

impl RegistrationPolicy for OpenPolicy {
    fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Allow
    }
}

fn registration_config() -> ServerConfig {
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read write").unwrap();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    cfg
}

fn registration_server() -> AuthorizationServer<MemoryStorage> {
    AuthorizationServer::new(registration_config(), MemoryStorage::new())
        .with_registration_policy(Box::new(OpenPolicy))
}

fn racing_server<S: Storage>(store: S) -> AuthorizationServer<S> {
    AuthorizationServer::new(registration_config(), store)
        .with_registration_policy(Box::new(OpenPolicy))
}

/// The same server, driven by a clock the test owns.
///
/// Needed only where the test is about WHEN a grant was established: the default server reads the
/// real clock, which no test can place a barrier inside.
fn racing_server_with_clock<S: Storage>(
    store: S,
    clock: ManualClock,
) -> AuthorizationServer<S, ManualClock> {
    AuthorizationServer::with_clock(registration_config(), store, clock)
        .with_registration_policy(Box::new(OpenPolicy))
}

fn app_metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["https://app.example/cb".to_string()],
        client_name: Some("Test App".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        scope: Some("read".to_string()),
        ..ClientMetadata::default()
    }
}

// ------------------------------------------------------------------- site 2: update_registration

/// SITE 2. RFC 7592 s2.2 update, read-modify-write, raced by an s2.3 delete.
///
/// `update_registration` reads the registration, awaits a policy decision and a validation pass,
/// and then writes the whole record back. A delete landing in that window was UNDONE: the client
/// came back with its old credential and, worse, its old `registration_access_token_hash`, so
/// whoever holds a stolen registration access token can defeat the deletion that was revoking it.
///
/// RED at a58c5ee with "the deleted registration is back", because the blind `put_client` created
/// the row again.
#[tokio::test]
async fn an_update_in_flight_does_not_undo_a_concurrent_delete() {
    // Registered against a plain store first, so the arming below names a client that exists.
    let (store, trigger) = RevokeDuringRead::new(MemoryStorage::new());
    let srv = racing_server(store);
    // Registered through the SAME store the race runs on. The trigger is not armed yet, so this
    // setup is ordinary.
    let registered = srv
        .register_dynamic_client(&app_metadata(), None)
        .await
        .unwrap();
    let client_id = ClientId::new(&registered.client_id);
    let rat = registered
        .registration_access_token
        .expect("management is enabled");

    // Armed now. The delete fires from inside `update_registration`'s own `get_client`: after the
    // read its write is derived from, and before that write. Deleting BEFORE the call would prove
    // nothing, because the update would refuse at its own front door and never reach the write
    // that carries the defect.
    *trigger.lock().unwrap() = Some(Revocation::Client(client_id.clone()));

    let mut changed = app_metadata();
    changed.client_name = Some("Renamed by the attacker".to_string());
    let outcome = srv.update_registration(&client_id, &rat, &changed).await;

    assert!(
        matches!(outcome, Err(RegistrationFailure::Unauthorized)),
        "an update whose registration was deleted mid-flight must be refused, not applied: \
         {outcome:?}"
    );
    assert!(
        srv.store().get_client(&client_id).await.unwrap().is_none(),
        "the deleted registration is back, so deleting a compromised client is defeatable by \
         whoever holds the stolen registration access token"
    );
}

/// The other half of the same swap, and the reason it compares the WHOLE record rather than
/// merely checking presence: two concurrent updates must not silently lose one.
#[tokio::test]
async fn an_update_in_flight_does_not_clobber_another_update() {
    let srv = registration_server();
    let registered = srv
        .register_dynamic_client(&app_metadata(), None)
        .await
        .unwrap();
    let client_id = ClientId::new(&registered.client_id);
    let rat = registered
        .registration_access_token
        .expect("management is enabled");

    // THE STALE SNAPSHOT IS READ FROM THE STORE, BEFORE the first writer commits, because that is
    // literally what a second in-flight update holds: the record its own `get_client` returned.
    //
    // It used to be hand-built, and that made the test vacuous. A dynamically registered client
    // carries `Some(DynamicRegistration { .. })` — the hashed registration access token and the
    // issue instant — while the reconstruction wrote `registration: None`, and
    // `compare_and_swap_client` compares the WHOLE record. So the snapshot never equalled ANY
    // version of this client, the swap below refused because the expectation had never been live
    // rather than because it had been superseded, and deleting the first writer's update entirely
    // left the assertion passing.
    let stale: Client = (*srv
        .store()
        .get_client(&client_id)
        .await
        .unwrap()
        .expect("the registration this test just created"))
    .clone();

    // A concurrent update commits first, changing the record this call is about to write back.
    let mut first = app_metadata();
    first.client_name = Some("First writer".to_string());
    srv.update_registration(&client_id, &rat, &first)
        .await
        .unwrap();

    let mut overwrite = stale.clone();
    overwrite.name = Some("Second writer".to_string());

    assert!(
        !srv.store()
            .compare_and_swap_client(&stale, overwrite)
            .await
            .unwrap(),
        "a swap against a record that has since changed must refuse, or the first writer's \
         update is silently lost"
    );
    let live = srv.store().get_client(&client_id).await.unwrap().unwrap();
    assert_eq!(live.name.as_deref(), Some("First writer"));
}

// ------------------------------------------------------------ site 4: refresh_token's put-backs

/// SITE 4. `take_refresh_token` removes the record, and every REFUSAL path writes it back.
///
/// The refusal used here is the scope-widening one, which is the most benign of the five: it is a
/// client bug, not a compromise, so the record is deliberately restored. That is exactly what
/// makes it the right one to pin. If a revocation lands while the record is out of the store, the
/// cascade cannot see it, and the restore hands the client back a live, rotatable refresh token
/// that the user has been told was revoked.
///
/// RED at a58c5ee with "the revoked refresh token is live again".
#[tokio::test]
async fn a_refusal_put_back_does_not_restore_a_revoked_refresh_token() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read write",
        "user-1",
    )
    .await;
    let rt = issued.refresh_token.expect("the code grant issues a chain");
    let family = srv
        .store()
        .get_refresh_token(&rt)
        .await
        .unwrap()
        .expect("the chain is live")
        .family_id
        .clone();

    // The revocation lands while the record is OUT of the store, which is what a rotation already
    // past its `take_refresh_token` looks like from outside. Modelled by revoking the family
    // first: the cascade finds the record and removes it, and the barrier is what has to refuse
    // the write that follows.
    srv.store()
        .revoke_token_family(&family, far_future_window())
        .await
        .unwrap();
    // Put it back the way a rotation's refusal path would, and expect the store to refuse.
    let restored = srv
        .store()
        .put_refresh_token(oauth_as::RefreshTokenRecord::new(
            rt.clone(),
            ClientId::new("confidential-app"),
            Some("user-1".to_string()),
            ScopeSet::parse("read write").unwrap(),
            family.clone(),
        ))
        .await
        .unwrap();
    assert!(
        restored.is_refused(),
        "the store accepted a write for a family it had just revoked"
    );
    assert!(
        srv.store().get_refresh_token(&rt).await.unwrap().is_none(),
        "the revoked refresh token is live again, so the user was told the grant was revoked and \
         the client kept a rotatable chain"
    );
}

/// The same rule reached through the PUBLIC surface rather than the store, so the fix is pinned at
/// the seam a host actually drives. A widening request is refused, and the refusal must not
/// resurrect a chain revoked in the meantime.
#[tokio::test]
async fn a_widening_refresh_after_revocation_leaves_nothing_behind() {
    let (store, trigger) = RevokeDuringRead::new(MemoryStorage::new());
    let clock = ManualClock::at_epoch();
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        store,
        clock,
    );
    srv.register_client(confidential_client()).await.unwrap();
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let rt = issued.refresh_token.expect("the code grant issues a chain");
    let family = srv
        .store()
        .get_refresh_token(&rt)
        .await
        .unwrap()
        .unwrap()
        .family_id
        .clone();

    // Armed: the family revocation fires from inside `take_refresh_token`, so it runs while the
    // record is OUT of the store. That is the window. Revoking BEFORE the call would only make
    // the take answer `None`, and the refusal path that carries the defect would never run.
    *trigger.lock().unwrap() = Some(Revocation::Family(family));

    // The client asks to WIDEN, which is refused on its own merits, and the refusal path is the
    // one that puts the record back. It must not.
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: rt.clone(),
            scope: Some(ScopeSet::parse("read write").unwrap()),
        })
        .await
        .expect_err("a widening request is refused whatever else happens");
    assert_eq!(
        err.error,
        oauth_as::ErrorCode::InvalidScope,
        "the test must reach the SCOPE refusal, which is the path that puts the record back; \
         any other refusal means the interleaving did not happen where this test thinks it did"
    );
    assert!(
        srv.store().get_refresh_token(&rt).await.unwrap().is_none(),
        "the refusal path restored a chain that was revoked while the record was out of the \
         store, so the user was told the grant was revoked and the client kept a rotatable token"
    );
}

// ------------------------------------------------------- site 3: revoke_with_credential's Option

/// A store whose `revoke_token_family` lets an in-flight ROTATION write immediately AFTER the
/// cascade has run. That is the ordering site 3 is about, and it is the only one that is
/// dangerous: a rotation whose write lands before the cascade is simply cascaded away.
struct WriteAfterCascade {
    inner: MemoryStorage,
    /// The record a rotation is about to write once the cascade has finished. Fires once.
    pending: Mutex<Option<oauth_as::RefreshTokenRecord>>,
}

impl Storage for WriteAfterCascade {
    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, oauth_as::StorageError> {
        let removed = self.inner.revoke_token_family(family_id, window).await?;
        // The rotation that was already holding a taken record wakes up here and writes. Before
        // 0.9.1 this simply landed, and the family the AS had just revoked was whole again.
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(record) = pending {
            let _ = self.inner.put_refresh_token(record).await?;
        }
        Ok(removed)
    }

    oauth_as::delegate_storage! {
        to inner;
        get_client, put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        put_token, get_token, delete_token,
        put_refresh_token, get_refresh_token, take_refresh_token,
        put_consent, compare_and_swap_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

/// SITE 3. RFC 7009 s2.1 revocation, raced by the redemption of the very token being revoked.
///
/// `revoke_with_credential` read the record, took it, DISCARDED the take's `Option`, and cascaded
/// from the `family_id` it had read. The discarded `Option` is what made the two cases
/// indistinguishable: "I removed it" and "a concurrent rotation removed it first". In the second
/// case a rotation is mid-flight holding a record the cascade cannot see, and its write lands
/// afterwards.
///
/// The client is answered 200 either way, which s2.2 requires. What must not happen is the family
/// being live afterwards.
#[tokio::test]
async fn a_rotation_completing_after_the_cascade_does_not_revive_the_family() {
    let clock = ManualClock::at_epoch();
    let store = WriteAfterCascade {
        inner: MemoryStorage::new(),
        pending: Mutex::new(None),
    };
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        store,
        clock,
    );
    srv.register_client(confidential_client()).await.unwrap();
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let rt = issued.refresh_token.expect("the code grant issues a chain");
    let family = srv
        .store()
        .get_refresh_token(&rt)
        .await
        .unwrap()
        .unwrap()
        .family_id
        .clone();

    // The rotated token an in-flight redemption is about to persist, once the cascade below has
    // run. Same family, which is the whole point: it is the chain the revocation is ending.
    *srv.store().pending.lock().unwrap() = Some(oauth_as::RefreshTokenRecord::new(
        "rt-rotated-behind-the-revocation",
        ClientId::new("confidential-app"),
        Some("user-1".to_string()),
        ScopeSet::parse("read").unwrap(),
        family.clone(),
    ));

    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &rt,
        None,
    )
    .await
    .expect("RFC 7009 s2.2: revocation answers 200");

    assert!(
        srv.store()
            .get_refresh_token("rt-rotated-behind-the-revocation")
            .await
            .unwrap()
            .is_none(),
        "a rotation that completed behind the cascade put the family back, so the client the user \
         just revoked is still holding a rotatable refresh token"
    );
}

// ------------------------------------------------------------------- site 5: record_consent

/// SITE 5. `record_consent` is a read-modify-write, and `withdraw_consent` is the writer its own
/// doc never considered.
///
/// The doc bounded the damage to two concurrent `record_consent` calls and called the race benign.
/// It was, in that direction. In THIS direction a widen that read a record and wrote it back after
/// the user clicked withdraw resurrects a consent the user destroyed, and every later
/// authorization request is answered from it.
///
/// RED at a58c5ee with "the withdrawn consent is back".
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_widen_in_flight_does_not_resurrect_a_withdrawn_consent() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let client_id = ClientId::new("confidential-app");

    let first = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read").unwrap(),
            &[],
            None,
        )
        .await
        .unwrap();

    // The snapshot a widen already in flight is holding.
    let stale = first.clone();

    // The user withdraws, which is the write the old doc never considered.
    srv.withdraw_consent(&first.consent_id).await.unwrap();
    assert!(
        srv.remembered_consent(&client_id, "user-1")
            .await
            .unwrap()
            .is_none(),
        "the withdrawal itself must work before this test can mean anything"
    );

    // The widen lands now, carrying the stale snapshot. It must be refused.
    let mut widened = stale.clone();
    widened.extend(&ScopeSet::parse("read write").unwrap(), &[]);
    assert!(
        !srv.store()
            .compare_and_swap_consent(Some(&stale), widened)
            .await
            .unwrap(),
        "a widen against a consent that has been withdrawn must refuse"
    );
    assert!(
        srv.remembered_consent(&client_id, "user-1")
            .await
            .unwrap()
            .is_none(),
        "the withdrawn consent is back, so the user was told they revoked an application and \
         every later authorization request is still answered from it"
    );
}

/// The same site through the PUBLIC surface, with the withdrawal landing inside
/// `record_consent`'s own `find_consent`. This is the one that fails if the fix is reverted: the
/// store-level test above pins the primitive, and this pins the server actually using it.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_during_record_consent_is_not_undone() {
    let (store, trigger) = RevokeDuringRead::new(MemoryStorage::new());
    let srv = racing_server(store);
    let client_id = ClientId::new("confidential-app");
    srv.register_client(confidential_client()).await.unwrap();

    let first = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read").unwrap(),
            &[],
            None,
        )
        .await
        .unwrap();

    // Armed: the user clicks withdraw from inside the next `find_consent`, which is the read the
    // widen below derives its write from.
    *trigger.lock().unwrap() = Some(Revocation::Consent(first.consent_id.to_string()));

    // The host records a widened consent, holding a snapshot that the withdrawal has invalidated.
    // Either answer is acceptable on the wire; what is not acceptable is the consent coming back.
    let _ = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read write").unwrap(),
            &[],
            None,
        )
        .await;

    assert!(
        srv.remembered_consent(&client_id, "user-1")
            .await
            .unwrap()
            .is_none(),
        "the withdrawn consent is back, so the user was told they revoked an application and \
         every later authorization request is still answered from it"
    );
}

/// The claim the fix above makes in its own comment, pinned rather than asserted: refusing a
/// resurrection must NOT refuse a genuine re-approval.
///
/// A user who withdraws an application and approves it again afterwards is making a new decision,
/// and the consent barrier that is still standing (it lasts as long as the longest token the
/// server mints) must not turn that into a refusal for the next hour. This is why the guard is
/// "the shape may not change within one call" rather than "refuse on the barrier".
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_does_not_block_approving_the_same_client_again() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let client_id = ClientId::new("confidential-app");

    let first = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read").unwrap(),
            &[],
            None,
        )
        .await
        .unwrap();
    srv.withdraw_consent(&first.consent_id).await.unwrap();

    // The user comes back and approves again. The barrier from the withdrawal is still live.
    let second = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read").unwrap(),
            &[],
            None,
        )
        .await
        .expect("a user re-approving after a withdrawal must not be refused");
    assert_ne!(
        second.consent_id, first.consent_id,
        "a re-approval is a NEW consent, not the withdrawn one coming back"
    );
    assert!(
        srv.remembered_consent(&client_id, "user-1")
            .await
            .unwrap()
            .is_some(),
        "the re-approved consent must be live"
    );
}

/// THE SAME USER DECISION, CARRIED ALL THE WAY TO A TOKEN.
///
/// The test above proves a re-approval produces a live consent RECORD. It stops there, and the
/// gap it leaves is the whole point of this one: `put_consent` does not consult the barrier, but
/// `put_token` does, so the record coming back proved nothing about the user being able to USE
/// the application again.
///
/// A consent barrier names a (client, subject) pair and nothing ever clears it — the only removal
/// is `sweep_expired` at its deadline, which is `now + the longest lifetime this server mints`.
/// So between the withdrawal and that deadline every issuance for the pair is refused, including
/// one derived from a NEW approval the user made afterwards. The user re-approves, sees the
/// application listed as authorised, and cannot obtain a token from it for as long as a refresh
/// token lives.
///
/// That is the barrier doing more than its own doc claims: it exists to refuse a write that took
/// its record BEFORE the revocation, and a grant created afterwards is not that write.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_re_approval_can_still_obtain_a_token() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock.clone(), vec![confidential_client()]).await;
    let client_id = ClientId::new("confidential-app");

    let first = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read").unwrap(),
            &[],
            None,
        )
        .await
        .unwrap();
    srv.withdraw_consent(&first.consent_id).await.unwrap();

    // Time passes, because a user deciding to come back takes some. This matters and is not
    // scene-setting: a grant established in the SAME instant as the revocation is a tie, and ties
    // refuse, deliberately — the ordering is genuinely unknown there and refusing is the safe
    // direction. The property under test is about a decision made AFTER the withdrawal.
    clock.advance(std::time::Duration::from_secs(60));

    // The user changes their mind and approves again. The barrier from the withdrawal is still
    // standing, and will be for as long as the longest token this server mints.
    srv.record_consent(
        &client_id,
        "user-1",
        &ScopeSet::parse("read").unwrap(),
        &[],
        None,
    )
    .await
    .expect("a user re-approving after a withdrawal must not be refused");

    // The decision must reach an actual token. This is the assertion the record-only test above
    // cannot make, and the one that fails while the barrier refuses on identity alone.
    let token = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    assert!(
        !token.access_token.is_empty(),
        "a re-approved user must be able to obtain a token, not just hold a consent record"
    );
}

/// BOTH DIRECTIONS OF THE COMPARISON, pinned at the store, which is where the predicate lives.
///
/// Every other test in this file gives its barrier a `recorded_at` in the far future, because they
/// are about a cascade or a put-back rather than about when a grant was made. That makes them
/// blind to this: a barrier whose comparison was REVERSED, or dropped entirely, still refuses
/// everything when `recorded_at` is far enough out, so all of them would pass. This one uses a
/// realistic instant and asserts the refusal AND the admission, so exactly one comparison passes.
///
/// The safety direction is the first assertion and it is the one that must never regress: a grant
/// made BEFORE a withdrawal stays refused for the barrier's whole life. The second is the defect
/// the 0.9.1 audit found: a grant made AFTER it is a new decision and must be served.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_barrier_refuses_only_grants_that_predate_it() {
    use oauth_as::store::RevocationWindow;
    let store = MemoryStorage::new();
    let client_id = ClientId::new("app");
    let t0 = std::time::UNIX_EPOCH;
    let revoked_at = t0 + std::time::Duration::from_secs(100);
    let after = revoked_at + std::time::Duration::from_secs(1);

    let consent = oauth_as::ConsentRecord {
        consent_id: "consent-1".into(),
        client_id: client_id.clone(),
        subject: "user-1".into(),
        scope: ScopeSet::parse("read").unwrap(),
        resource: Vec::new(),
        granted_at: t0,
        authentication: None,
    };
    let consent_id = consent.consent_id.to_string();
    store.put_consent(consent).await.unwrap();

    store
        .revoke_consent(
            &consent_id,
            RevocationWindow {
                recorded_at: revoked_at,
                until: support::far_future(),
            },
        )
        .await
        .unwrap();

    // A grant established BEFORE the withdrawal. This is the resurrection the barrier exists to
    // stop, and it must stay stopped.
    let mut stale = oauth_as::IssuedToken::new(
        "at-stale",
        client_id.clone(),
        Some("user-1".to_string()),
        ScopeSet::parse("read").unwrap(),
        t0,
        support::far_future(),
    );
    stale.grant_established_at = t0;
    assert!(
        store.put_token(stale).await.unwrap().is_refused(),
        "a token whose grant predates the withdrawal must be refused"
    );

    // A grant established AFTER it: the user came back and approved again.
    let mut fresh = oauth_as::IssuedToken::new(
        "at-fresh",
        client_id.clone(),
        Some("user-1".to_string()),
        ScopeSet::parse("read").unwrap(),
        after,
        support::far_future(),
    );
    fresh.grant_established_at = after;
    assert!(
        !store.put_token(fresh).await.unwrap().is_refused(),
        "a token whose grant was established after the withdrawal is a NEW decision and must be \
         applied; refusing it locks the user out for as long as the longest token this server mints"
    );
}

/// The duplicate-record race the old doc CONCEDED, now closed by the same swap. Two first-time
/// approvals for one pair must leave the pair holding one record, not two.
#[cfg(feature = "consent")]
#[tokio::test]
async fn two_first_approvals_for_one_pair_leave_one_consent() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let client_id = ClientId::new("confidential-app");

    srv.record_consent(
        &client_id,
        "user-1",
        &ScopeSet::parse("read").unwrap(),
        &[],
        None,
    )
    .await
    .unwrap();
    // The second writer believed the pair was empty, which is what its read told it.
    let loser = oauth_as::ConsentRecord {
        consent_id: "a-second-record".into(),
        client_id: client_id.clone(),
        subject: "user-1".into(),
        scope: ScopeSet::parse("write").unwrap(),
        resource: Vec::new(),
        granted_at: std::time::UNIX_EPOCH,
        authentication: None,
    };
    assert!(
        !srv.store()
            .compare_and_swap_consent(None, loser)
            .await
            .unwrap(),
        "a create against a pair that now holds a consent must refuse"
    );
    assert_eq!(
        srv.consents_for_subject("user-1").await.unwrap().len(),
        1,
        "the pair must hold exactly one consent"
    );
}

// --------------------------------------------------------------- site 6: put_device_grant upsert

/// SITE 6. `put_device_grant` is an upsert, and the rule was never stated there.
///
/// A grant redeemed by `take_device_grant` is gone, and a later put RECREATES it, which makes a
/// single-use device code redeemable twice. `compare_and_swap_device_grant` already refuses this;
/// what this pins is that the server never reaches for the upsert on a path where the grant may
/// have been redeemed underneath it.
///
/// RED at a58c5ee only in the sense that the rule was unwritten: the swap already refused. This
/// test is what makes the rule checkable rather than a comment.
#[tokio::test]
async fn a_swap_after_redemption_does_not_recreate_the_device_grant() {
    let store = MemoryStorage::new();
    let grant = DeviceGrant {
        device_code: "dc-1".to_string(),
        user_code: "WDJB-MJHT".to_string(),
        client_id: ClientId::new("device-app"),
        scope: ScopeSet::parse("read").unwrap(),
        state: DeviceGrantState::Pending,
        created_at: std::time::UNIX_EPOCH,
        expires_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_000_000_000),
        interval: std::time::Duration::from_secs(5),
        last_poll_at: None,
    };
    store.put_device_grant(grant.clone()).await.unwrap();
    store
        .take_device_grant("dc-1")
        .await
        .unwrap()
        .expect("redeemed once");

    let mut restamped = grant.clone();
    restamped.last_poll_at = Some(std::time::UNIX_EPOCH);
    assert!(
        !store
            .compare_and_swap_device_grant(&DeviceGrantState::Pending, restamped)
            .await
            .unwrap(),
        "a swap must not recreate a redeemed grant, or a single-use device code is redeemable twice"
    );
    assert!(
        store.get_device_grant("dc-1").await.unwrap().is_none(),
        "the redeemed device grant is back"
    );
    assert!(
        store
            .find_device_grant_by_user_code("WDJBMJHT")
            .await
            .unwrap()
            .is_none(),
        "the user code resolves to a grant that was already redeemed"
    );
}

// --------------------------------------------------- the barrier's own lifetime, and the sweep

/// A barrier is a row nothing else removes, so an unswept store grows one per revocation. It must
/// be reclaimed at its deadline, and NOT before: reaping early reopens the window it closed.
#[tokio::test]
async fn barriers_are_swept_at_their_deadline_and_not_before() {
    let store = MemoryStorage::new();
    let deadline = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000);
    // A family barrier refuses UNCONDITIONALLY, so `recorded_at` does not enter this test's
    // predicate; it is stated truthfully anyway. `until` is what this test is about.
    let window = oauth_as::store::RevocationWindow {
        recorded_at: std::time::UNIX_EPOCH,
        until: deadline,
    };
    store.revoke_token_family("fam-1", window).await.unwrap();

    // One second before: still refusing, and not swept.
    let swept = store
        .sweep_expired(std::time::UNIX_EPOCH + std::time::Duration::from_secs(999))
        .await
        .unwrap();
    assert_eq!(swept, 0, "a barrier must not be reaped before its deadline");
    assert!(
        store
            .put_refresh_token(oauth_as::RefreshTokenRecord::new(
                "rt-1",
                ClientId::new("app"),
                None,
                ScopeSet::parse("read").unwrap(),
                "fam-1",
            ))
            .await
            .unwrap()
            .is_refused(),
        "a live barrier must still refuse"
    );

    // At the deadline: reclaimed, and counted, because it is a row a host has to see go away.
    let swept = store.sweep_expired(deadline).await.unwrap();
    assert_eq!(swept, 1, "the barrier must be reclaimed at its deadline");
}

// ------------------------------------------ site 8: client_credentials dating its own grant

/// SITE 8, INTRODUCED BY THE FIX FOR THE BARRIER LOCKOUT AND FOUND BY AUDITING THAT FIX.
///
/// `client_credentials` has no resource owner, so the client's own authentication is the decision
/// the grant dates from. When barriers refused on IDENTITY alone this needed no care. Once they
/// compare instants, WHERE the instant is taken becomes load bearing: stamping it after
/// `authenticate_client` dates the grant later than the read it derives from, so a `delete_client`
/// landing in that window records a barrier EARLIER than the grant, the comparison admits the
/// write, and a live token is minted for a registration that no longer exists.
///
/// The window is not theoretical: it spans a `get_client` round trip and a secret verification,
/// which on a networked store is milliseconds.
///
/// HOW THIS DISCRIMINATES, which is the only thing that makes it worth having. The clock is the
/// test's, and the trigger advances it BY 60s when the deletion fires — from inside
/// `authenticate_client`'s `get_client`, which sits between request entry and issuance. The
/// barrier is recorded at entry + 30s, in the gap that advance opens:
///
/// - with the fix, the grant is dated at ENTRY (+0s), which PREDATES the barrier (+30s), so the
///   write is refused and no token is minted;
/// - with the fix reverted — the instant taken after `authenticate_client` — the grant is dated at
///   +60s, which POSTDATES the barrier, the comparison admits the write, and a live token is
///   minted for a registration that no longer exists.
///
/// It was `#[ignore]`d until that arrangement existed, because before it both orderings refused
/// and the test passed with the defect present, which is the failure this file warns about at the
/// top. Confirmed RED by hand by moving `let grant_established_at = self.clock.now();` below the
/// `authenticate_client` call in `server.rs`.
#[tokio::test]
async fn a_client_credentials_token_is_refused_when_the_client_is_deleted_mid_request() {
    let clock = ManualClock::at_epoch();
    let entry = clock.now();
    let (mut store, trigger) = RevokeDuringRead::new(MemoryStorage::new());
    // A REALISTIC window, recorded BETWEEN entry and issuance. The default's `recorded_at` is in
    // the far future, which refuses every grant unconditionally and would make this test pass with
    // the defect present — it did, before this line was added.
    store.window = oauth_as::store::RevocationWindow {
        recorded_at: store_window_recorded_at(entry),
        until: support::far_future(),
    };
    // The advance that puts issuance on the far side of that barrier. Without it, entry and
    // issuance are the same instant and the two orderings are indistinguishable.
    store.advance_on_fire = Some((clock.clone(), std::time::Duration::from_secs(60)));
    let srv = racing_server_with_clock(store, clock.clone());
    srv.register_client(confidential_client()).await.unwrap();

    // The deletion fires from inside the `get_client` that authentication makes, which is exactly
    // where a concurrent RFC 7592 delete would land: after the request began, before it writes.
    *trigger.lock().unwrap() = Some(Revocation::Client(ClientId::new("confidential-app")));

    let outcome = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            scope: None,
        })
        .await;

    let err = outcome.expect_err(
        "a client_credentials token must not be minted for a registration deleted while the \
         request was in flight: the grant dates from the authentication, which happened before \
         the deletion, so the barrier covers it",
    );
    // THE SPECIFIC REFUSAL, for the reason `fire_from` gives above: on this path a refusal from
    // the wrong place is the failure mode, not a detail. The client is DELETED by the time the
    // write happens, so a re-read that missed would refuse as `invalid_client` at the front door
    // and `is_err()` alone would call that a pass -- while the barrier under test never ran. Only
    // the issuance-time refusal proves the write was reached and stopped. This is the standard the
    // sibling test above already sets for the scope path, and it is the same standard.
    assert_eq!(
        err.error,
        oauth_as::ErrorCode::InvalidGrant,
        "the refusal must be the barrier's at issuance, not an authentication refusal reached \
         because the deleted registration was re-read: {err:?}"
    );
    assert!(
        err.error_description
            .as_deref()
            .is_some_and(|d| d.contains("revoked while this token was being issued")),
        "the refusal must name the revocation that stopped the write: {:?}",
        err.error_description
    );
    // The clock really did move across the request, so the assertion above discriminates rather
    // than passing on a tie. A future refactor that stops advancing here must not leave this test
    // silently vacuous.
    assert!(
        clock.now() > store_window_recorded_at(entry),
        "the trigger did not advance the clock, so issuance did not cross the barrier and this \
         test proves nothing"
    );
}

/// The instant the test above records its barrier at, named once so the vacuity check and the
/// window cannot drift apart.
fn store_window_recorded_at(entry: std::time::SystemTime) -> std::time::SystemTime {
    entry + std::time::Duration::from_secs(30)
}

// ------------------------------------------------------- site 7: the PAR cross-client put-back
//
// FOUND BY THE 0.9.1 CODE AUDIT, not by the release that claimed to have enumerated every site.
// The release's own module docs said SIX sites and exactly ONE deliberate exemption; this was a
// seventh, and it was neither protected nor exempted, which is worth more than the defect itself:
// the enumeration was asserted rather than derived, and it was wrong.
//
// The shape is the same as site 4's. `validate_pushed_authorization_request` TAKES the record
// before it can know which client the handle belongs to, because the binding is IN the record
// (RFC 9126 s2.2). When the presenter is a stranger it puts the record back, deliberately, so
// that a stranger cannot destroy an honest client's live handle. That put-back was unconditional.
//
// So a `delete_client` landing while the record is out of the store finds nothing to cascade, and
// the put-back then restores a pushed request belonging to a client that no longer exists.

/// SITE 7. A `delete_client` that lands while a PAR record is out of the store must not be undone
/// by the cross-client put-back.
#[cfg(feature = "par")]
#[tokio::test]
async fn a_cross_client_par_put_back_does_not_resurrect_a_deleted_clients_handle() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let client_id = ClientId::new("confidential-app");

    // A live pushed request belonging to the client.
    let record = oauth_as::par::PushedAuthorizationRequest::new(
        "urn:ietf:params:oauth:request_uri:site7",
        client_id.clone(),
        support::far_future(),
    );
    assert!(srv
        .store()
        .put_pushed_authorization_request(record.clone())
        .await
        .unwrap()
        .is_applied());

    // The revocation lands while the record is OUT of the store, which is what a cross-client
    // presentation already past its `take` looks like from outside. Modelled by taking it first,
    // exactly as `validate_pushed_authorization_request` does, then deleting.
    let taken = srv
        .store()
        .take_pushed_authorization_request(&record.request_uri)
        .await
        .unwrap()
        .expect("the handle is live");
    assert!(srv
        .store()
        .delete_client(&client_id, far_future_window())
        .await
        .unwrap());

    // The put-back the stranger's refusal path performs. It must be REFUSED.
    let restored = srv
        .store()
        .put_pushed_authorization_request(taken)
        .await
        .unwrap();
    assert!(
        restored.is_refused(),
        "the store accepted a pushed request for a client it had just deleted"
    );
    assert!(
        srv.store()
            .take_pushed_authorization_request(&record.request_uri)
            .await
            .unwrap()
            .is_none(),
        "a deleted client's pushed request is live again, so a host that re-provisions the same \
         client_id inherits authorization parameters its owner never pushed"
    );
}
