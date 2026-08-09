// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Behaviours of the reference [`oauth_as::MemoryStorage`] that a `cargo mutants --all-features`
//! sweep of `src/store.rs` found nothing pinning.
//!
//! Every test here names the surviving mutant it kills and says what the mutation would have done
//! to a host. That framing is deliberate: `MemoryStorage` is not a toy. It is the store this
//! crate's own suite runs on, it is what `StorageConformance` is calibrated against, and it is
//! what a single-process embedding is invited to deploy. A defect here is therefore a defect in
//! the reference every other implementation is compared to.
//!
//! Two themes run through the survivors, and they are worth naming because they are the two things
//! a store is easiest to get wrong in a way no ordinary test notices:
//!
//! - THE CASCADES MATCH THE WRONG SET. `delete_client` and `revoke_consent` both remove records
//!   belonging to one principal and must spare everything else. A `!=` flipped to `==` inside one
//!   `retain` predicate reverses exactly that, and the endpoint still answers success.
//! - THE COUNTS ARE NOT CHECKED AGAINST AN ASYMMETRIC FIXTURE. Every count these methods return is
//!   a difference of two sums. With two of everything planted, `a + b` and `a * b` agree, so a
//!   fixture that plants two of each cannot see an arithmetic defect at all.

mod support;

// Ungated: the RFC 8628 device-grant tests below need every one of these and are themselves
// ungated, so a narrower gate here would only be a second place to get the feature set wrong.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{ClientId, MemoryStorage, ScopeSet, Storage};

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[cfg(feature = "consent")]
fn scope() -> ScopeSet {
    ScopeSet::parse("read").unwrap()
}

// ---------------------------------------------------------------------- delete_client

/// SURVIVOR: `crates/oauth-as/src/store.rs:535:45: replace != with == in delete_client`.
///
/// The line is the RFC 9126 half of the cascade,
/// `g.pushed.retain(|_, p| &p.client_id != client_id)`. Flipped, `delete_client` keeps exactly the
/// deleted client's pushed authorization requests and DESTROYS every other client's.
///
/// Both halves of that are live defects. The surviving handles belong to a registration that no
/// longer exists, which is the thing RFC 7592 section 2.3 deletion is for; the destroyed ones
/// belong to clients that did nothing, and their next `/authorize` on a handle they were told was
/// good answers as though it had already been used. Deleting one registration would intermittently
/// break every other client's PAR flow, which is close to the hardest class of bug to attribute.
///
/// Nothing noticed because the exported `StorageConformance` harness seeds no pushed request for
/// its bystander client, so the whole `pushed` line was unconstrained in the sparing direction.
#[cfg(feature = "par")]
#[tokio::test]
async fn delete_client_takes_only_its_own_pushed_authorization_requests() {
    use oauth_as::par::PushedAuthorizationRequest;

    fn pushed(uri: &str, client: &str) -> PushedAuthorizationRequest {
        PushedAuthorizationRequest {
            request_uri: uri.to_string(),
            client_id: ClientId::new(client),
            response_type: Some("code".into()),
            redirect_uri: Some("https://app.example/cb".into()),
            scope: None,
            state: None,
            code_challenge: Some("x".repeat(43)),
            code_challenge_method: Some("S256".into()),
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: None,
            #[cfg(feature = "consent")]
            acr_values: None,
            #[cfg(feature = "consent")]
            max_age: None,
            expires_at: now() + Duration::from_secs(60),
        }
    }

    let store = MemoryStorage::new();
    store
        .put_pushed_authorization_request(pushed("urn:doomed", "client-doomed"))
        .await
        .unwrap();
    store
        .put_pushed_authorization_request(pushed("urn:bystander", "client-bystander"))
        .await
        .unwrap();

    store
        .delete_client(&ClientId::new("client-doomed"))
        .await
        .unwrap();

    assert!(
        store
            .take_pushed_authorization_request("urn:doomed")
            .await
            .unwrap()
            .is_none(),
        "a deleted client's pushed request survived: RFC 7592 s2.3 deletion invalidates what the \
         registration holds, and a request_uri is a capability to obtain a code"
    );
    assert!(
        store
            .take_pushed_authorization_request("urn:bystander")
            .await
            .unwrap()
            .is_some(),
        "deleting one client destroyed ANOTHER client's pushed request: that client's next \
         authorization request fails on a handle it was told was good, with nothing linking the \
         failure to the deletion that caused it"
    );
}

/// SURVIVOR: `crates/oauth-as/src/store.rs:548:31: delete ! in delete_client`.
///
/// The line filters the user-code index down to the entries that no longer name a live grant,
/// `.filter(|(_, dc)| !live.contains_key(*dc))`, so the cascade can drop them. Without the `!` the
/// filter selects the entries that DO name a live grant, so `delete_client` deletes the index
/// entries of the grants it just spared and keeps the dangling ones.
///
/// What a user sees: a device that was in the middle of RFC 8628 verification, belonging to a
/// client nobody deleted, has its user code stop resolving. The person typing it is told the code
/// is not recognised, and the grant it names is still sitting in the store, unreachable forever.
///
/// The exported harness cannot see this. It checks that the DELETED client's code no longer
/// resolves, and that passes either way: `find_device_grant_by_user_code` walks the index into
/// `device_by_code`, and the grant is gone from there, so a dangling entry resolves to `None`
/// anyway. What is unchecked is the spared client's code, which is the direction that breaks.
#[tokio::test]
async fn delete_client_keeps_the_user_code_index_of_the_grants_it_spared() {
    use oauth_as::{DeviceGrant, DeviceGrantState};

    fn grant(device_code: &str, user_code: &str, client: &str) -> DeviceGrant {
        DeviceGrant {
            device_code: device_code.to_string(),
            user_code: user_code.to_string(),
            client_id: ClientId::new(client),
            scope: ScopeSet::parse("read").unwrap(),
            state: DeviceGrantState::Pending,
            created_at: now(),
            expires_at: now() + Duration::from_secs(600),
            interval: Duration::from_secs(5),
            last_poll_at: None,
        }
    }

    let store = MemoryStorage::new();
    store
        .put_device_grant(grant("dc-doomed", "DOOMAAAA", "client-doomed"))
        .await
        .unwrap();
    store
        .put_device_grant(grant("dc-bystander", "BYSTAAAA", "client-bystander"))
        .await
        .unwrap();

    store
        .delete_client(&ClientId::new("client-doomed"))
        .await
        .unwrap();

    assert!(
        store
            .find_device_grant_by_user_code("BYSTAAAA")
            .await
            .unwrap()
            .is_some(),
        "deleting one client unindexed ANOTHER client's live device grant: the user code the \
         person is reading off their television stops resolving, and the grant it names can never \
         be approved again"
    );
    assert!(
        store
            .find_device_grant_by_user_code("DOOMAAAA")
            .await
            .unwrap()
            .is_none(),
        "the deleted client's user code still resolves"
    );
}

// ---------------------------------------------------------------------- revoke_consent

/// SURVIVOR, two of them:
/// `crates/oauth-as/src/store.rs:773:55` and `:773:71`, `replace + with * in revoke_consent`.
///
/// `revoke_consent` returns how many credentials it removed, measured as a sum of four map lengths
/// before and the same sum after. Turning one of those `+` into a `*` makes the returned count
/// wrong.
///
/// The count is not decoration. [`oauth_as::Storage::revoke_consent`]'s contract says it is what an
/// operator investigating an incident reads, and the exported conformance harness FAILS a store
/// whose count is wrong, so a wrong count here is also this crate's reference implementation
/// failing its own published check.
///
/// Why nothing caught it: every existing fixture, including the harness's own, plants exactly TWO
/// of each record kind, and `2 + 2` and `2 * 2` are the same number. This one plants THREE access
/// tokens against one of everything else, so sum and product cannot agree.
#[cfg(feature = "consent")]
#[tokio::test]
async fn revoke_consent_counts_what_it_removed_even_when_the_kinds_are_uneven() {
    use oauth_as::{
        AuthorizationCodeRecord, AuthorizationCodeState, CodeChallengeMethod, ConsentRecord,
        DeviceGrant, DeviceGrantState, IssuedToken, RefreshTokenRecord, RefreshTokenState,
    };

    const CLIENT: &str = "client-uneven";
    const SUBJECT: &str = "subject-uneven";

    let store = MemoryStorage::new();
    store
        .put_consent(ConsentRecord {
            consent_id: "consent-uneven".into(),
            client_id: ClientId::new(CLIENT),
            subject: SUBJECT.into(),
            scope: scope(),
            resource: Vec::new(),
            granted_at: now(),
            authentication: None,
        })
        .await
        .unwrap();

    // THREE access tokens, and one each of the other three kinds. Three is the smallest count that
    // makes the sum and the product of the four map lengths differ.
    for token in ["at-1", "at-2", "at-3"] {
        store
            .put_token(IssuedToken {
                #[cfg(feature = "dpop")]
                jkt: None,
                #[cfg(feature = "mtls")]
                x5t_s256: None,
                resource: Vec::new(),
                #[cfg(feature = "rar")]
                authorization_details: Default::default(),
                access_token: token.into(),
                client_id: ClientId::new(CLIENT),
                subject: Some(SUBJECT.into()),
                scope: scope(),
                issued_at: now(),
                expires_at: now() + Duration::from_secs(3600),
                family_id: None,
                authentication: None,
            })
            .await
            .unwrap();
    }
    store
        .put_refresh_token(RefreshTokenRecord {
            #[cfg(feature = "dpop")]
            jkt: None,
            #[cfg(feature = "mtls")]
            x5t_s256: None,
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: Default::default(),
            refresh_token: "rt-1".into(),
            client_id: ClientId::new(CLIENT),
            subject: Some(SUBJECT.into()),
            scope: scope(),
            expires_at: None,
            family_id: "fam-1".into(),
            state: RefreshTokenState::Active,
            authentication: None,
        })
        .await
        .unwrap();
    store
        .put_authorization_code(AuthorizationCodeRecord {
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: Default::default(),
            code: "code-1".into(),
            client_id: ClientId::new(CLIENT),
            redirect_uri: "https://app.example/cb".into(),
            scope: scope(),
            subject: SUBJECT.into(),
            code_challenge: "x".repeat(43),
            code_challenge_method: CodeChallengeMethod::S256,
            expires_at: now() + Duration::from_secs(60),
            state: AuthorizationCodeState::Issued,
            authentication: None,
        })
        .await
        .unwrap();
    store
        .put_device_grant(DeviceGrant {
            device_code: "dc-1".into(),
            user_code: "UNEVAAAA".into(),
            client_id: ClientId::new(CLIENT),
            scope: scope(),
            state: DeviceGrantState::Approved {
                subject: SUBJECT.into(),
            },
            created_at: now(),
            expires_at: now() + Duration::from_secs(600),
            interval: Duration::from_secs(5),
            last_poll_at: None,
        })
        .await
        .unwrap();

    let removed = store.revoke_consent("consent-uneven").await.unwrap();
    assert_eq!(
        removed, 6,
        "revoke_consent removed 3 access tokens, 1 refresh record, 1 authorization code and 1 \
         approved device grant, and must report 6. The count is what an operator reads while \
         deciding whether a withdrawal did what the user was told it did, and the exported \
         StorageConformance harness fails a store that reports the wrong one"
    );
}

/// SURVIVOR: `crates/oauth-as/src/store.rs:796:31: delete ! in revoke_consent`.
///
/// The same user-code index pass as `delete_client`'s, with the same inversion and the same
/// consequence one level narrower: withdrawing ONE user's consent unindexes the device grants of
/// every user who withdrew nothing.
///
/// This is the failure mode the consent feature's whole design is arranged against: the user is
/// told an application was stopped, and what actually happened is that unrelated people's
/// in-flight device logins stopped instead, silently, with the withdrawal reporting success.
#[cfg(feature = "consent")]
#[tokio::test]
async fn revoke_consent_keeps_the_user_code_index_of_the_grants_it_spared() {
    use oauth_as::{ConsentRecord, DeviceGrant, DeviceGrantState};

    const CLIENT: &str = "client-shared";

    fn grant(device_code: &str, user_code: &str, subject: &str) -> DeviceGrant {
        DeviceGrant {
            device_code: device_code.to_string(),
            user_code: user_code.to_string(),
            client_id: ClientId::new(CLIENT),
            scope: ScopeSet::parse("read").unwrap(),
            state: DeviceGrantState::Approved {
                subject: subject.to_string(),
            },
            created_at: now(),
            expires_at: now() + Duration::from_secs(600),
            interval: Duration::from_secs(5),
            last_poll_at: None,
        }
    }

    let store = MemoryStorage::new();
    store
        .put_consent(ConsentRecord {
            consent_id: "consent-mine".into(),
            client_id: ClientId::new(CLIENT),
            subject: "subject-mine".into(),
            scope: scope(),
            resource: Vec::new(),
            granted_at: now(),
            authentication: None,
        })
        .await
        .unwrap();
    store
        .put_device_grant(grant("dc-mine", "MINEAAAA", "subject-mine"))
        .await
        .unwrap();
    store
        .put_device_grant(grant("dc-theirs", "THEMAAAA", "subject-other"))
        .await
        .unwrap();

    store.revoke_consent("consent-mine").await.unwrap();

    assert!(
        store
            .find_device_grant_by_user_code("THEMAAAA")
            .await
            .unwrap()
            .is_some(),
        "one user's withdrawal unindexed ANOTHER user's device grant: their code stops resolving \
         mid-login, and nothing they did caused it"
    );
    assert!(
        store
            .find_device_grant_by_user_code("MINEAAAA")
            .await
            .unwrap()
            .is_none(),
        "the withdrawn subject's approved grant is still reachable by its user code"
    );
}

// ---------------------------------------------------------------------- sweep_expired

/// SURVIVOR: `crates/oauth-as/src/store.rs:855:40: replace < with <= in sweep_expired`.
///
/// The RFC 9126 pushed-request line, `g.pushed.retain(|_, p| now < p.expires_at)`. Relaxed to
/// `<=`, a handle whose `expires_at` is exactly `now` is retained.
///
/// [`oauth_as::Storage::sweep_expired`]'s contract defines dead as `expires_at <= now`, and the
/// boundary is the whole of what this mutation moves, which is why no fixture that plants a
/// comfortably-expired handle can see it. It matters because RFC 9126 section 4 requires an
/// expired `request_uri` to be REJECTED, and because a host schedules its sweep on the returned
/// count: a store that reports 0 while holding a dead record looks idle while it grows.
#[cfg(feature = "par")]
#[tokio::test]
async fn sweep_expired_reaps_a_pushed_request_at_the_instant_it_expires() {
    use oauth_as::par::PushedAuthorizationRequest;

    let store = MemoryStorage::new();
    store
        .put_pushed_authorization_request(PushedAuthorizationRequest {
            request_uri: "urn:boundary".into(),
            client_id: ClientId::new("client-boundary"),
            response_type: Some("code".into()),
            redirect_uri: Some("https://app.example/cb".into()),
            scope: None,
            state: None,
            code_challenge: Some("x".repeat(43)),
            code_challenge_method: Some("S256".into()),
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: None,
            #[cfg(feature = "consent")]
            acr_values: None,
            #[cfg(feature = "consent")]
            max_age: None,
            // Exactly `now`: the contract says `expires_at <= now` is dead, so this is dead.
            expires_at: now(),
        })
        .await
        .unwrap();

    let removed = store.sweep_expired(now()).await.unwrap();
    assert_eq!(
        removed, 1,
        "a pushed request whose expires_at is exactly `now` is dead by the sweep_expired contract \
         and must be counted"
    );
    assert!(
        store
            .take_pushed_authorization_request("urn:boundary")
            .await
            .unwrap()
            .is_none(),
        "an expired request_uri survived the sweep. RFC 9126 s4 requires it to be rejected, and a \
         handle the store still holds is one the authorization endpoint may still resolve"
    );
}

/// SURVIVOR: `crates/oauth-as/src/store.rs:880:46: replace < with > in sweep_expired`.
///
/// The replay-claim line, `g.replay_ids.retain(|_, exp| now < *exp)`. Reversed, the sweep keeps
/// exactly the claims that are already dead and REMOVES the ones that are still live.
///
/// That is a security defect, not a tidiness one. A claimed `jti` is the only thing making an
/// RFC 7523 client assertion (section 3) or an RFC 9449 DPoP proof (section 4.3) single use, so
/// releasing a live claim re-opens the replay window for every artifact still inside its validity.
/// The host is TOLD to run the sweep on a timer, so every tick would hand an observer of one
/// request the ability to send it again.
///
/// The exported harness misses this by an unlucky fixture: it claims an id whose deadline IS the
/// sweep instant, and `now < exp` and `now > exp` are both false at the boundary, so the mutant
/// and the original reap it identically. This test claims a comfortably LIVE id, which is the only
/// shape that separates them.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
#[tokio::test]
async fn sweep_expired_leaves_replay_claims_that_are_still_live_claimed() {
    use oauth_as::{MemoryStorage, Storage};
    let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let store = MemoryStorage::new();
    assert!(
        store
            .claim_replay_id("jti-live", base + Duration::from_secs(600))
            .await
            .unwrap(),
        "the first claim of an unseen id is the claim"
    );

    store.sweep_expired(base).await.unwrap();

    assert!(
        !store
            .claim_replay_id("jti-live", base + Duration::from_secs(600))
            .await
            .unwrap(),
        "the sweep released a replay claim that was still live, so the assertion or DPoP proof \
         carrying that jti can be replayed by anyone who observed one request. RFC 7523 s3 and \
         RFC 9449 s4.3 both make the jti single use for the whole of its validity"
    );
}

/// SURVIVOR: `crates/oauth-as/src/store.rs:881:32: replace - with + in sweep_expired`.
///
/// The replay-claim tally, `removed += (before - g.replay_ids.len())`, becomes an ADDITION, so the
/// sweep reports the number of claims it started with plus the number it kept.
///
/// The harness misses it because its fixture holds exactly one dead claim and nothing else: with
/// `before = 1` and nothing left, `1 - 0` and `1 + 0` are the same number. This test plants one
/// dead claim and one live one, which is the smallest fixture where the two disagree, and the
/// difference is visible to the host: the sweep interval is tuned on this number, and a store that
/// over-reports looks like it is reclaiming steadily while the table grows.
#[cfg(any(feature = "client_assertion", feature = "dpop"))]
#[tokio::test]
async fn sweep_expired_counts_only_the_replay_claims_it_actually_reclaimed() {
    use oauth_as::{MemoryStorage, Storage};
    let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let store = MemoryStorage::new();
    store
        .claim_replay_id("jti-dead", base - Duration::from_secs(10))
        .await
        .unwrap();
    store
        .claim_replay_id("jti-live", base + Duration::from_secs(600))
        .await
        .unwrap();

    let removed = store.sweep_expired(base).await.unwrap();
    assert_eq!(
        removed, 1,
        "exactly one of the two claims was dead at `now`, so the sweep must report 1. A host \
         schedules its sweep on this number"
    );
    assert!(
        !store
            .claim_replay_id("jti-live", base + Duration::from_secs(600))
            .await
            .unwrap(),
        "the live claim must still be claimed"
    );
}
