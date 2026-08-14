// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A REVOCATION AND AN IN-FLIGHT WRITE, INTERLEAVED ON PURPOSE.
//!
//! `tests/two_connection.rs` proves the `take_*` methods pick one winner. This file proves the
//! other half of the 0.9.1 claim: that a revocation which commits WHILE a write for the same
//! identity is in flight cannot be undone by that write. The core's in-process harness cannot
//! reach this at all — it runs one process, and `MemoryStorage` closes the whole check-and-write
//! under one mutex, so the harness never has to say what a store made of two statements must do.
//!
//! # Why these tests do not race, and why that is the point
//!
//! A timing race would prove nothing on a fast local database and would flap on a slow one. The
//! interleaving is instead FORCED, using two facts about PostgreSQL that hold at the pool's
//! default READ COMMITTED:
//!
//! 1. An `INSERT` blocks on an UNCOMMITTED row with the same primary key, and resumes when that
//!    row's transaction ends. So a third connection holding an uncommitted duplicate stops the
//!    write under test at exactly the point after its refusal check and before its own insert.
//! 2. That same uncommitted row is INVISIBLE to a concurrent `DELETE` — it is not a row the
//!    cascade waits for, it is a row the cascade cannot see. So the revocation runs to completion
//!    with nothing to remove, which is precisely the resurrection the barrier exists to stop.
//!
//! With those two, the sequence the audit described is reproduced deterministically: the write
//! checks the barrier, the revocation commits whole, and the write then lands. The assertion at
//! the end of every test is the USER-VISIBLE outcome — after both operations have returned, the
//! store must hold no credential for the identity that was revoked. It is deliberately not "the
//! write was refused": a write that got there first and was then cascaded away is a correct
//! outcome too, and asserting the refusal would fail a correct store.
//!
//! # What makes them go red
//!
//! Take the `lock_barrier_scopes` call out of the write under test (or the matching
//! `lock_barrier_scope_exclusive` out of the revocation) and every test here fails with a live
//! credential for a client, family or consent that was revoked.

#![cfg(feature = "pg-integration")]

use std::time::{Duration, SystemTime};

use oauth_as::authorization::AuthorizationCodeRecord;
use oauth_as::client::ClientId;
use oauth_as::consent::ConsentRecord;
use oauth_as::par::PushedAuthorizationRequest;
use oauth_as::scope::ScopeSet;
use oauth_as::store::{RevocationWindow, Storage};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use oauth_as_postgres::{to_nanos, PostgresStorage};
use sqlx::{Executor, Postgres, Transaction};

mod support;

/// How long the revocation is given to finish before the blocking row is released.
///
/// This is not a race that a longer wait would win: with the defect present the revocation is a
/// six-statement transaction on empty tables and completes in single-digit milliseconds, and with
/// the fix present it is blocked on an advisory lock and would never finish however long it waited.
/// The wait exists so that "the revocation had every opportunity to commit first" is a fact rather
/// than an assumption, which is what stops the test passing vacuously.
const REVOCATION_GRACE: Duration = Duration::from_millis(750);

/// A window whose `recorded_at` is NOW, which is the only honest value for a revocation a test is
/// performing now.
///
/// Deliberately not the far-future `recorded_at` a barrier fixture elsewhere uses: that value
/// refuses every grant unconditionally, so a test built on it passes whether or not the ordering
/// under test is correct. Here the grants are established at `now` too, so nothing is refused for
/// being old and the only thing that can remove a token is the cascade.
fn window_now() -> RevocationWindow {
    let now = SystemTime::now();
    RevocationWindow {
        recorded_at: now,
        until: now + Duration::from_secs(3600),
    }
}

fn scopes() -> ScopeSet {
    ScopeSet::parse("read").expect("a valid RFC 6749 s3.3 scope")
}

fn access_token(
    name: &str,
    client: &str,
    subject: Option<&str>,
    family: Option<&str>,
) -> IssuedToken {
    let now = SystemTime::now();
    let mut token = IssuedToken::new(
        name,
        ClientId::new(client),
        subject.map(str::to_string),
        scopes(),
        now,
        now + Duration::from_secs(600),
    );
    token.family_id = family.map(str::to_string);
    // The grant behind this token was established NOW, which is what a token being minted right
    // now means. Leaving the constructor's fail-closed `UNIX_EPOCH` would let a barrier refuse it
    // for being old and hide whether the ordering under test works.
    token.grant_established_at = now;
    token
}

fn refresh_record(
    name: &str,
    client: &str,
    subject: Option<&str>,
    family: &str,
) -> RefreshTokenRecord {
    let mut record = RefreshTokenRecord::new(
        name,
        ClientId::new(client),
        subject.map(str::to_string),
        scopes(),
        family,
    );
    record.grant_established_at = SystemTime::now();
    record
}

/// A transaction on a THIRD connection holding an uncommitted row, left open for the caller to
/// roll back when it wants the write under test to proceed.
///
/// `statement` binds `binds` in order and then the expiry, which every one of these tables has and
/// none of these tests cares about. The columns are spelled out rather than written through the
/// store because the whole point is to plant a row the store's own `put_*` blocks on: it shares
/// the primary key of the record the test is about to write.
async fn blocker<'a>(
    pool: &'a sqlx::Pool<Postgres>,
    statement: &str,
    binds: &[&str],
) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.expect("begin the blocking transaction");
    let mut query = sqlx::query(statement);
    for bind in binds {
        query = query.bind(*bind);
    }
    query
        .bind(to_nanos(SystemTime::now() + Duration::from_secs(600)))
        .execute(&mut *tx)
        .await
        .expect("plant the blocking row");
    tx
}

/// AN ACCESS TOKEN MINTED FOR A CLIENT BEING DELETED.
///
/// The RFC 7592 section 2.3 kill switch: an operator deletes a compromised registration while a
/// token request for it is in flight. If the token survives, the attacker holding that request has
/// a credential for a client that no longer exists, valid for its whole lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_cannot_land_behind_a_client_deletion() {
    const SCHEMA: &str = "oauth_as_race_delete_client";
    const CLIENT: &str = "race-delete-client";
    support::fresh_schema(SCHEMA).await;
    let writer = support::store(SCHEMA, 1).await;
    let revoker = support::store(SCHEMA, 1).await;
    let bystander = support::pool(SCHEMA, 1).await;

    let held = blocker(
        &bystander,
        "INSERT INTO oauth_as_access_tokens \
             (access_token, client_id, subject, family_id, expires_at_ns, payload) \
         VALUES ($1, $2, NULL, NULL, $3, '{}'::jsonb)",
        &["blocked-token", CLIENT],
    )
    .await;

    let write = tokio::spawn(async move {
        writer
            .put_token(access_token("blocked-token", CLIENT, None, None))
            .await
            .expect("put_token")
    });
    let revoke = tokio::spawn(async move {
        revoker
            .delete_client(&ClientId::new(CLIENT), window_now())
            .await
            .expect("delete_client")
    });

    tokio::time::sleep(REVOCATION_GRACE).await;
    held.rollback().await.expect("release the blocking row");
    // Whether this says `Applied` or `RefusedRevoked` depends on which side reached the lock
    // first, and both are correct: see the module docs on why the assertion below is the outcome
    // and not the return value.
    let _ = write.await.expect("the writer did not panic");
    revoke.await.expect("the revoker did not panic");

    let after = support::store(SCHEMA, 1).await;
    assert!(
        after
            .get_token("blocked-token")
            .await
            .expect("get_token")
            .is_none(),
        "a live access token survived the deletion of its client: either the write was refused or \
         the cascade removed it, and neither happened"
    );
}

/// A REFRESH RECORD WRITTEN BEHIND A FAMILY REVOCATION.
///
/// RFC 9700 section 4.14.2: reuse was detected and the family is being revoked while the rotation
/// that detected it is still writing. A surviving record is a live chain for the thief, and one
/// the honest client will never present, so the reuse signal never fires again either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_record_cannot_land_behind_a_family_revocation() {
    const SCHEMA: &str = "oauth_as_race_revoke_family";
    const CLIENT: &str = "race-revoke-family";
    const FAMILY: &str = "family-race-revoke";
    support::fresh_schema(SCHEMA).await;
    let writer = support::store(SCHEMA, 1).await;
    let revoker = support::store(SCHEMA, 1).await;
    let bystander = support::pool(SCHEMA, 1).await;

    let held = blocker(
        &bystander,
        "INSERT INTO oauth_as_refresh_tokens \
             (refresh_token, client_id, subject, family_id, expires_at_ns, payload) \
         VALUES ($1, $2, NULL, $3, $4, '{}'::jsonb)",
        &["blocked-refresh", CLIENT, FAMILY],
    )
    .await;

    let write = tokio::spawn(async move {
        writer
            .put_refresh_token(refresh_record("blocked-refresh", CLIENT, None, FAMILY))
            .await
            .expect("put_refresh_token")
    });
    let revoke = tokio::spawn(async move {
        revoker
            .revoke_token_family(FAMILY, window_now())
            .await
            .expect("revoke_token_family")
    });

    tokio::time::sleep(REVOCATION_GRACE).await;
    held.rollback().await.expect("release the blocking row");
    // Whether this says `Applied` or `RefusedRevoked` depends on which side reached the lock
    // first, and both are correct: see the module docs on why the assertion below is the outcome
    // and not the return value.
    let _ = write.await.expect("the writer did not panic");
    revoke.await.expect("the revoker did not panic");

    let after = support::store(SCHEMA, 1).await;
    assert!(
        after
            .get_refresh_token("blocked-refresh")
            .await
            .expect("get_refresh_token")
            .is_none(),
        "a live refresh record survived the revocation of its own family"
    );
}

/// A TOKEN MINTED FOR A CONSENT THE USER IS WITHDRAWING.
///
/// The user pressed the button. If the token lands behind the withdrawal, the application they
/// just disconnected keeps calling resource servers with a credential minted after they said no.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_cannot_land_behind_a_consent_withdrawal() {
    const SCHEMA: &str = "oauth_as_race_revoke_consent";
    const CLIENT: &str = "race-revoke-consent";
    const SUBJECT: &str = "subject-race-revoke";
    support::fresh_schema(SCHEMA).await;
    let writer = support::store(SCHEMA, 1).await;
    let revoker = support::store(SCHEMA, 1).await;
    let bystander = support::pool(SCHEMA, 1).await;

    writer
        .put_consent(ConsentRecord {
            consent_id: "consent-race".into(),
            client_id: ClientId::new(CLIENT),
            subject: SUBJECT.into(),
            scope: scopes(),
            resource: Vec::new(),
            granted_at: SystemTime::now(),
            authentication: None,
        })
        .await
        .expect("put_consent");

    let held = blocker(
        &bystander,
        "INSERT INTO oauth_as_access_tokens \
             (access_token, client_id, subject, family_id, expires_at_ns, payload) \
         VALUES ($1, $2, $3, NULL, $4, '{}'::jsonb)",
        &["blocked-consent-token", CLIENT, SUBJECT],
    )
    .await;

    let write = tokio::spawn(async move {
        writer
            .put_token(access_token(
                "blocked-consent-token",
                CLIENT,
                Some(SUBJECT),
                None,
            ))
            .await
            .expect("put_token")
    });
    let revoke = tokio::spawn(async move {
        revoker
            .revoke_consent("consent-race", window_now())
            .await
            .expect("revoke_consent")
    });

    tokio::time::sleep(REVOCATION_GRACE).await;
    held.rollback().await.expect("release the blocking row");
    // Whether this says `Applied` or `RefusedRevoked` depends on which side reached the lock
    // first, and both are correct: see the module docs on why the assertion below is the outcome
    // and not the return value.
    let _ = write.await.expect("the writer did not panic");
    revoke.await.expect("the revoker did not panic");

    let after = support::store(SCHEMA, 1).await;
    assert!(
        after
            .get_token("blocked-consent-token")
            .await
            .expect("get_token")
            .is_none(),
        "a live access token survived the withdrawal of the consent it was issued under"
    );
}

/// TWO REVOCATIONS OF THE SAME CLIENT, CASCADING THROUGH THE SAME TWO TABLES.
///
/// The rest of this file forces a write against a revocation. This one forces two REVOCATIONS
/// against each other, and the hazard is not resurrection but DEADLOCK: `delete_client` and
/// `revoke_consent` both touch `oauth_as_consents` and `oauth_as_access_tokens`, and their
/// advisory keys are deliberately different (`client` and `consent`), so nothing serialises them.
/// If they take the two tables in opposite orders, PostgreSQL breaks the cycle with `40P01` and
/// the loser's revocation FAILS — surfacing to the caller as `server_error`, on the one operation
/// a host is least able to retry blindly. The audit found exactly that: `revoke_consent` claimed
/// the consent row first and cascaded into tokens, while `delete_client` cascaded into tokens
/// first and reached consents last.
///
/// # Why this is forced rather than raced
///
/// Two row locks are held on a separate pool, and released in the one order that builds the cycle:
///
/// 1. Both revocations start. `delete_client` blocks on the TOKEN row, `revoke_consent` on the
///    CONSENT row. `delete_client` is started first so that it is ahead of `revoke_consent` in the
///    token row's wait queue, which is what makes the cycle rather than a plain queue.
/// 2. The consent row is released. `revoke_consent` claims it, then asks for the token row and
///    joins that queue BEHIND `delete_client`.
/// 3. The token row is released. `delete_client` takes it, finishes its other cascades, and asks
///    for the consent row — which `revoke_consent` has deleted and not yet committed. Each now
///    waits on a row the other holds.
///
/// With the tables cascaded in the SAME order by both methods there is no step 3: whichever
/// revocation reaches `oauth_as_consents` first also reaches `oauth_as_access_tokens` first, and
/// the second simply queues behind it. That is the fix this test is the proof of, and it is why
/// the assertion is that BOTH calls return `Ok` rather than anything about what they removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "consent")]
async fn a_client_deletion_and_a_consent_withdrawal_do_not_deadlock() {
    const SCHEMA: &str = "oauth_as_race_cascade_order";
    const CLIENT: &str = "race-cascade-order";
    const SUBJECT: &str = "subject-cascade-order";
    const CONSENT: &str = "consent-cascade-order";
    const TOKEN: &str = "cascade-order-token";
    support::fresh_schema(SCHEMA).await;
    let planter = support::store(SCHEMA, 1).await;
    let deleter = support::store(SCHEMA, 1).await;
    let withdrawer = support::store(SCHEMA, 1).await;
    let holders = support::pool(SCHEMA, 2).await;

    // One consent and one access token for the same (client, subject): the two rows both
    // revocations have to pass through, and the only two rows in the schema that matter here.
    planter
        .put_consent(ConsentRecord {
            consent_id: CONSENT.into(),
            client_id: ClientId::new(CLIENT),
            subject: SUBJECT.into(),
            scope: scopes(),
            resource: Vec::new(),
            granted_at: SystemTime::now(),
            authentication: None,
        })
        .await
        .expect("put_consent");
    // No barrier stands yet, so this is `Applied`; it is bound rather than dropped because
    // `WriteOutcome` is `#[must_use]` and a silently refused plant would empty the fixture.
    let planted = planter
        .put_token(access_token(TOKEN, CLIENT, Some(SUBJECT), None))
        .await
        .expect("put_token");
    assert!(
        planted.is_applied(),
        "the fixture token was refused before either revocation ran: {planted:?}"
    );

    // `FOR UPDATE` rather than the uncommitted INSERT the other tests plant: the row has to be
    // one the cascade WAITS for, not one it cannot see.
    let mut consent_row = holders.begin().await.expect("begin the consent row hold");
    sqlx::query("SELECT 1 FROM oauth_as_consents WHERE consent_id = $1 FOR UPDATE")
        .bind(CONSENT)
        .execute(&mut *consent_row)
        .await
        .expect("hold the consent row");
    let mut token_row = holders.begin().await.expect("begin the token row hold");
    sqlx::query("SELECT 1 FROM oauth_as_access_tokens WHERE access_token = $1 FOR UPDATE")
        .bind(TOKEN)
        .execute(&mut *token_row)
        .await
        .expect("hold the access token row");

    // Started FIRST, so it is ahead of the withdrawal in the token row's wait queue. See step 1.
    let delete = tokio::spawn(async move {
        deleter
            .delete_client(&ClientId::new(CLIENT), window_now())
            .await
    });
    tokio::time::sleep(REVOCATION_GRACE).await;
    let withdraw =
        tokio::spawn(async move { withdrawer.revoke_consent(CONSENT, window_now()).await });
    tokio::time::sleep(REVOCATION_GRACE).await;

    consent_row
        .rollback()
        .await
        .expect("release the consent row");
    tokio::time::sleep(REVOCATION_GRACE).await;
    token_row.rollback().await.expect("release the token row");

    let deleted = delete.await.expect("the deleter did not panic");
    let withdrawn = withdraw.await.expect("the withdrawer did not panic");
    assert!(
        deleted.is_ok() && withdrawn.is_ok(),
        "a client deletion and a consent withdrawal for the same client deadlocked, so one \
         revocation failed and the caller was told `server_error`: delete_client => {deleted:?}, \
         revoke_consent => {withdrawn:?}"
    );
}

/// THE SAME HAZARD ONE LEVEL DOWN: THE ORDER THE WRITE TAKES ITS OWN BARRIER LOCKS IN.
///
/// The test above forces two revocations against each other and is closed by the TABLE ORDER of
/// their cascades. It exercises two transactions, and it stays green under the defect this test is
/// about, which is why this one exists rather than an extra assertion there.
///
/// `lock_barrier_scopes` takes every key one write needs in ONE statement over an array, and
/// `unnest` acquires them one at a time — so a writer part-way through the array HOLDS the keys it
/// already took and WAITS for the next. Through 0.9.1 the comment on that function argued no such
/// hold-and-wait existed, and therefore that the order within the array did not matter. It does.
/// Three transactions close a cycle when `consent` is taken before `client`:
///
/// 1. `delete_client` takes `client:C` (its first act) and then cascades into `oauth_as_consents`.
/// 2. `revoke_consent` claims its consent ROW first (`DELETE ... RETURNING`) and only then asks
///    for `consent:(C, S)` — the one revocation that holds a row lock while waiting for an
///    advisory one.
/// 3. `put_token` for that (C, S) holds `consent:(C, S)` shared and waits for `client:C`.
///
/// 3 waits on 1, 2 waits on 3, and 1 waits on 2's row. PostgreSQL breaks it with `40P01`, and the
/// loser can be either revocation, which reaches the caller as `server_error` with the grant still
/// live.
///
/// # Why this is forced rather than raced
///
/// The interleaving needs `revoke_consent` to hold the consent row BEFORE `delete_client` reaches
/// that table, while `delete_client` already holds `client:C`. An uncommitted duplicate of
/// `delete_client`'s own BARRIER row is what buys that: `record_barrier` upserts against
/// `UNIQUE (scope, client_id, family_id, subject)`, so a third connection holding an uncommitted
/// `('client', C)` barrier stops `delete_client` at exactly the point after its advisory lock and
/// before its cascade. The other two transactions are then started into that gap in order, and the
/// blocking row is released last.
///
/// With `client` acquired first there is no step 3: the writer waits for `client:C` holding
/// NOTHING, `revoke_consent` gets its advisory lock immediately and commits, and `delete_client`
/// finds the consent row already gone. The assertion is that all three calls return `Ok`, because
/// what a deadlock costs here is a revocation, not a write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "consent")]
async fn a_writer_waiting_for_the_client_barrier_cannot_hold_the_consent_one() {
    const SCHEMA: &str = "oauth_as_race_barrier_key_order";
    const CLIENT: &str = "race-barrier-key-order";
    const SUBJECT: &str = "subject-barrier-key-order";
    const CONSENT: &str = "consent-barrier-key-order";
    const TOKEN: &str = "barrier-key-order-token";
    support::fresh_schema(SCHEMA).await;
    let planter = support::store(SCHEMA, 1).await;
    let deleter = support::store(SCHEMA, 1).await;
    let withdrawer = support::store(SCHEMA, 1).await;
    let writer = support::store(SCHEMA, 1).await;
    let holders = support::pool(SCHEMA, 1).await;

    // The row `revoke_consent` claims, and the row `delete_client`'s cascade goes on to wait for.
    // No registration row is planted: `delete_client` runs its whole cascade whether or not the
    // client exists (it answers `Ok(false)` in that case, which is not what this asserts on), and
    // the cascade is the only part of it this cycle passes through.
    planter
        .put_consent(ConsentRecord {
            consent_id: CONSENT.into(),
            client_id: ClientId::new(CLIENT),
            subject: SUBJECT.into(),
            scope: scopes(),
            resource: Vec::new(),
            granted_at: SystemTime::now(),
            authentication: None,
        })
        .await
        .expect("put_consent");

    // `delete_client`'s own barrier row, uncommitted, so its `record_barrier` blocks here — after
    // it holds `client:C` and before it reaches `oauth_as_consents`. Written out rather than
    // through `blocker` because a barrier carries two timestamps, not one.
    let mut barrier_row = holders.begin().await.expect("begin the barrier row hold");
    let far = to_nanos(SystemTime::now() + Duration::from_secs(600));
    sqlx::query(
        "INSERT INTO oauth_as_revocation_barriers \
             (scope, client_id, family_id, subject, expires_at_ns, recorded_at_ns) \
         VALUES ('client', $1, '', '', $2, $2)",
    )
    .bind(CLIENT)
    .bind(far)
    .execute(&mut *barrier_row)
    .await
    .expect("plant the blocking barrier row");

    // FIRST: it must hold `client:C` before anything else moves.
    let delete = tokio::spawn(async move {
        deleter
            .delete_client(&ClientId::new(CLIENT), window_now())
            .await
    });
    tokio::time::sleep(REVOCATION_GRACE).await;
    // SECOND: with the defect it now holds `consent:(C, S)` and waits for `client:C`; without it
    // it holds nothing and waits for `client:C`.
    let write = tokio::spawn(async move {
        writer
            .put_token(access_token(TOKEN, CLIENT, Some(SUBJECT), None))
            .await
    });
    tokio::time::sleep(REVOCATION_GRACE).await;
    // THIRD: claims the consent ROW, then asks for `consent:(C, S)`.
    let withdraw =
        tokio::spawn(async move { withdrawer.revoke_consent(CONSENT, window_now()).await });
    tokio::time::sleep(REVOCATION_GRACE).await;

    // Releases `delete_client` into its cascade, which is the last edge of the cycle.
    barrier_row
        .rollback()
        .await
        .expect("release the blocking barrier row");

    let deleted = delete.await.expect("the deleter did not panic");
    let withdrawn = withdraw.await.expect("the withdrawer did not panic");
    let written = write.await.expect("the writer did not panic");
    assert!(
        deleted.is_ok() && withdrawn.is_ok() && written.is_ok(),
        "a client deletion, a consent withdrawal and an issuance for the same (client, subject) \
         deadlocked over the barrier advisory locks, so an operation failed and its caller was \
         told `server_error`: delete_client => {deleted:?}, revoke_consent => {withdrawn:?}, \
         put_token => {written:?}"
    );
}

/// A PUSHED REQUEST WRITTEN BEHIND THE DELETION OF THE CLIENT THAT PUSHED IT.
///
/// RFC 9126 section 2.2 binds a `request_uri` to its client, so a surviving handle is one nobody
/// may redeem — and if the host re-provisions the same `client_id`, one that resolves against a
/// registration whose owner never pushed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pushed_request_cannot_land_behind_a_client_deletion() {
    const SCHEMA: &str = "oauth_as_race_par";
    const CLIENT: &str = "race-par-client";
    support::fresh_schema(SCHEMA).await;
    let writer = support::store(SCHEMA, 1).await;
    let revoker = support::store(SCHEMA, 1).await;
    let bystander = support::pool(SCHEMA, 1).await;

    let held = blocker(
        &bystander,
        "INSERT INTO oauth_as_pushed_requests \
             (request_uri, client_id, expires_at_ns, payload) \
         VALUES ($1, $2, $3, '{}'::jsonb)",
        &["urn:ietf:params:oauth:request_uri:blocked", CLIENT],
    )
    .await;

    let write = tokio::spawn(async move {
        let mut record = PushedAuthorizationRequest::new(
            "urn:ietf:params:oauth:request_uri:blocked",
            ClientId::new(CLIENT),
            SystemTime::now() + Duration::from_secs(90),
        );
        record.pushed_at = SystemTime::now();
        writer
            .put_pushed_authorization_request(record)
            .await
            .expect("put_pushed_authorization_request")
    });
    let revoke = tokio::spawn(async move {
        revoker
            .delete_client(&ClientId::new(CLIENT), window_now())
            .await
            .expect("delete_client")
    });

    tokio::time::sleep(REVOCATION_GRACE).await;
    held.rollback().await.expect("release the blocking row");
    // Whether this says `Applied` or `RefusedRevoked` depends on which side reached the lock
    // first, and both are correct: see the module docs on why the assertion below is the outcome
    // and not the return value.
    let _ = write.await.expect("the writer did not panic");
    revoke.await.expect("the revoker did not panic");

    let after = support::store(SCHEMA, 1).await;
    assert!(
        after
            .take_pushed_authorization_request("urn:ietf:params:oauth:request_uri:blocked")
            .await
            .expect("take_pushed_authorization_request")
            .is_none(),
        "a redeemable pushed request survived the deletion of the client it is bound to"
    );
}

/// How many standing barriers the cost check below plants.
///
/// Enough that a scan of them is unmistakable against a probe of them, and small enough that
/// planting them is a second of one test's time.
const PLANTED_BARRIERS: i32 = 20_000;

/// How many shared buffers the refusal lookup may touch with [`PLANTED_BARRIERS`] standing.
///
/// A probe of three indexes is a handful of blocks: measured at 6 on PostgreSQL 16. Reading every
/// family barrier instead was 113, and that number grows with the table while this one does not.
/// Thirty-two leaves room for a different page layout or a deeper index without leaving room for a
/// scan.
const BARRIER_LOOKUP_BUFFER_BUDGET: i64 = 32;

/// THE REFUSAL LOOKUP COSTS THE SAME WHETHER A DEPLOYMENT HAS REVOKED ONCE OR TWENTY THOUSAND
/// TIMES.
///
/// A cost test rather than a correctness one, and it is here because the cost is paid on the
/// hottest path there is: `put_token` and `put_refresh_token` run this query inside the
/// transaction that issues EVERY credential. If one arm of the three-way `OR` has no cheap index
/// probe, the planner drops the whole `EXISTS` to a sequential scan and issuance latency starts
/// growing with the number of revocations the deployment has recorded and not yet swept — worst
/// exactly after the mass revocation that follows an incident, which is when it can least afford
/// it. Nothing fails; the server just gets slower, which is why this needs an assertion rather
/// than a reader.
///
/// BUFFERS RATHER THAN THE PLAN TEXT, because "is there a sequential scan" is the wrong question:
/// the `UNIQUE (scope, client_id, family_id, subject)` constraint's index can technically be
/// probed for the family arm, so a plan-shape assertion passes while the query still reads every
/// family barrier standing. Blocks touched is the thing that actually grows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_barrier_lookup_does_not_scan_the_barrier_table() {
    const SCHEMA: &str = "oauth_as_barrier_cost";
    support::fresh_schema(SCHEMA).await;
    let store = support::store(SCHEMA, 1).await;

    let mut conn = store.pool().acquire().await.expect("a connection");
    // Family barriers specifically: the client and consent arms have had a leading-column index
    // since this table existed, and it is the family arm that decides the plan.
    sqlx::query(
        "INSERT INTO oauth_as_revocation_barriers \
             (scope, client_id, family_id, subject, expires_at_ns, recorded_at_ns) \
         SELECT 'family', '', 'planted-' || g, '', 0, 0 FROM generate_series(1, $1) g",
    )
    .bind(PLANTED_BARRIERS)
    .execute(&mut *conn)
    .await
    .expect("plant the standing barriers");
    // Without this the planner is working from the statistics of an empty table and would choose
    // as if there were nothing to scan.
    conn.execute("ANALYZE oauth_as_revocation_barriers")
        .await
        .expect("analyze");

    // The same three-way OR `barrier_covers` issues, for an identity that matches NOTHING, which
    // is what every issuance in a healthy deployment looks like and is also the worst case: a
    // scan that finds no match has read the whole table.
    let plan: serde_json::Value = sqlx::query_scalar(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT EXISTS ( \
             SELECT 1 FROM oauth_as_revocation_barriers WHERE \
                 (scope = 'client'  AND client_id = 'absent' AND recorded_at_ns >= 0) \
              OR (scope = 'family'  AND family_id = 'absent') \
              OR (scope = 'consent' AND client_id = 'absent' AND subject = 'absent' \
                                    AND recorded_at_ns >= 0) \
         )",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("explain the barrier lookup");

    let root = &plan[0]["Plan"];
    let blocks = root["Shared Hit Blocks"].as_i64().unwrap_or_default()
        + root["Shared Read Blocks"].as_i64().unwrap_or_default();
    assert!(
        blocks <= BARRIER_LOOKUP_BUFFER_BUDGET,
        "the refusal lookup touched {blocks} shared buffers with {PLANTED_BARRIERS} barriers \
         standing, over a budget of {BARRIER_LOOKUP_BUFFER_BUDGET}, so its cost grows with the \
         number of revocations recorded and every token issued pays it:\n{plan:#}"
    );
}

/// SEVERAL NODES BOOTING AT ONCE ALL FINISH MIGRATING.
///
/// `migrate()` says it is safe to run concurrently from several nodes, and a Kubernetes rollout
/// takes that at its word. `CREATE ... IF NOT EXISTS` does not provide it: the existence check and
/// the catalogue insert are not atomic, so two sessions can both pass the check and the loser gets
/// a duplicate key on `pg_type_typname_nsp_index` and crash-loops.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_migrations_all_succeed() {
    const SCHEMA: &str = "oauth_as_concurrent_migrate";
    support::fresh_schema(SCHEMA).await;

    let mut nodes = Vec::new();
    for _ in 0..8 {
        // A pool each, established before any of them migrates, so that what races is the
        // migration rather than eight simultaneous connects.
        let pool = support::pool(SCHEMA, 1).await;
        let node = PostgresStorage::from_pool(pool);
        nodes.push(tokio::spawn(async move { node.migrate().await }));
    }
    for node in nodes {
        node.await
            .expect("a migrating node did not panic")
            .expect("every node's migration succeeds");
    }
}

/// A payload as 0.9.0 wrote it: the record this build serializes, minus the field this release
/// added.
///
/// Built by REMOVING the key rather than by pasting a captured document, so it cannot drift into
/// testing something 0.9.0 never wrote: whatever else this build's serializer does, the only
/// difference between what goes into the database here and what comes out of `encode` is the one
/// field the upgrade is about.
fn payload_without<T: serde::Serialize>(record: &T, field: &str) -> serde_json::Value {
    let mut value = serde_json::to_value(record).expect("serialize the record");
    let object = value.as_object_mut().expect("a record is a JSON object");
    assert!(
        object.remove(field).is_some(),
        "{field} is not a field of this record, so this test is no longer testing the upgrade it \
         was written for"
    );
    value
}

/// EVERY RECORD A 0.9.0 DEPLOYMENT PERSISTED IS STILL READABLE AFTER THE UPGRADE, AND READS BACK
/// FAIL-CLOSED.
///
/// 0.9.1 added required fields to four record types, and every record is stored as ONE SERIALIZED
/// DOCUMENT, which is the decision that makes this a storage question rather than a core one: a
/// payload written by 0.9.0 carries no such key, so without the `#[serde(default)]` the core gives
/// them, `serde_json` fails with "missing field", this crate's `decode` turns that into a
/// `StorageError`, and the server answers `server_error` for every credential minted before the
/// restart. Introspection, refresh and in-flight code redemption all stop working, and a refresh
/// chain with no absolute lifetime never expires its way out of it. The defaults live in the core
/// and the core tests them as values; what is checked HERE is the whole path an operator actually
/// upgrades through — a real row, written the way 0.9.0 wrote it, read back through this store's
/// own `decode`.
///
/// THE VALUE IS THE ASSERTION, not merely that the read succeeded. All four instants name when the
/// grant behind the record was established, and a barrier refuses a write whose grant instant is at
/// or before the revocation, so the EPOCH means a pre-upgrade record is refused by any standing
/// revocation. A far-future default would read back just as successfully and would quietly
/// un-revoke everything revoked before the upgrade, which is the resurrection this release exists
/// to close. That is why each field is compared rather than counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_written_by_0_9_0_survive_the_upgrade() {
    const SCHEMA: &str = "oauth_as_upgrade_backfill";
    const CLIENT: &str = "upgrade-client";
    support::fresh_schema(SCHEMA).await;
    // The 0.9.0 deployment: the tables, without the backfill having anything to do yet.
    let store = support::store(SCHEMA, 1).await;
    let mut conn = store.pool().acquire().await.expect("a connection");
    let deadline = SystemTime::now() + Duration::from_secs(600);

    sqlx::query(
        "INSERT INTO oauth_as_access_tokens \
             (access_token, client_id, subject, family_id, expires_at_ns, payload) \
         VALUES ('legacy-token', $1, NULL, NULL, $2, $3)",
    )
    .bind(CLIENT)
    .bind(to_nanos(deadline))
    .bind(payload_without(
        &access_token("legacy-token", CLIENT, None, None),
        "grant_established_at",
    ))
    .execute(&mut *conn)
    .await
    .expect("plant a 0.9.0 access token");

    sqlx::query(
        "INSERT INTO oauth_as_refresh_tokens \
             (refresh_token, client_id, subject, family_id, expires_at_ns, payload) \
         VALUES ('legacy-refresh', $1, NULL, 'legacy-family', $2, $3)",
    )
    .bind(CLIENT)
    .bind(to_nanos(deadline))
    .bind(payload_without(
        &refresh_record("legacy-refresh", CLIENT, None, "legacy-family"),
        "grant_established_at",
    ))
    .execute(&mut *conn)
    .await
    .expect("plant a 0.9.0 refresh record");

    let code = AuthorizationCodeRecord::new(
        "legacy-code",
        ClientId::new(CLIENT),
        "https://rp.example/cb",
        scopes(),
        "legacy-subject",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        deadline,
    );
    sqlx::query(
        "INSERT INTO oauth_as_authorization_codes \
             (code, client_id, subject, expires_at_ns, payload) \
         VALUES ('legacy-code', $1, 'legacy-subject', $2, $3)",
    )
    .bind(CLIENT)
    .bind(to_nanos(deadline))
    .bind(payload_without(&code, "issued_at"))
    .execute(&mut *conn)
    .await
    .expect("plant a 0.9.0 authorization code");

    let pushed = PushedAuthorizationRequest::new(
        "urn:ietf:params:oauth:request_uri:legacy",
        ClientId::new(CLIENT),
        deadline,
    );
    sqlx::query(
        "INSERT INTO oauth_as_pushed_requests (request_uri, client_id, expires_at_ns, payload) \
         VALUES ('urn:ietf:params:oauth:request_uri:legacy', $1, $2, $3)",
    )
    .bind(CLIENT)
    .bind(to_nanos(deadline))
    .bind(payload_without(&pushed, "pushed_at"))
    .execute(&mut *conn)
    .await
    .expect("plant a 0.9.0 pushed request");
    drop(conn);

    // The upgrade: the same call the crate's own docs tell an operator to run on every boot. It
    // creates no table these rows did not already have and rewrites no payload — the point is that
    // the rows below are read back by the NEW build, not that anything repaired them.
    store.migrate().await.expect("apply the upgrade");

    let token = store
        .get_token("legacy-token")
        .await
        .expect("a 0.9.0 access token is still readable")
        .expect("the access token is still there");
    assert_eq!(
        token.grant_established_at,
        SystemTime::UNIX_EPOCH,
        "an upgraded record must read back FAIL-CLOSED: a pre-upgrade grant instant that outranks a \
         barrier un-revokes everything revoked before the upgrade"
    );
    let refresh = store
        .get_refresh_token("legacy-refresh")
        .await
        .expect("a 0.9.0 refresh record is still readable")
        .expect("the refresh record is still there");
    assert_eq!(refresh.grant_established_at, SystemTime::UNIX_EPOCH);
    let code = store
        .take_authorization_code("legacy-code")
        .await
        .expect("a 0.9.0 authorization code is still readable")
        .expect("the code is still there");
    assert_eq!(code.issued_at, SystemTime::UNIX_EPOCH);
    let pushed = store
        .take_pushed_authorization_request("urn:ietf:params:oauth:request_uri:legacy")
        .await
        .expect("a 0.9.0 pushed request is still readable")
        .expect("the pushed request is still there");
    assert_eq!(pushed.pushed_at, SystemTime::UNIX_EPOCH);
}
