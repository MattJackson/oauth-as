// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The parts of `Storage`'s cascade and sweep definitions that only prose used to state.
//!
//! `delete_client`, `revoke_consent` and `sweep_expired` each carry an ENUMERATION of what they
//! remove, and that enumeration is the only specification a host has: no trait method can force a
//! cascade, and `storage_conformance` can only check what the enumeration requires. So an
//! enumeration that is NARROWER than the reference implementation is invisible in both directions
//! at once. A host that implemented the list to the letter left records behind, and nothing
//! anywhere said so.
//!
//! These tests pin the kinds that were missing from those lists, against `MemoryStorage`, so that
//! the reference implementation cannot quietly drift back to matching the old, shorter text. What
//! they CANNOT do is hold a host's own store to it; that is `storage_conformance`'s job, and it can
//! only ask for what the doc requires.
//!
//! The last test in this file is about a different enumeration in the same file for the same
//! reason: the resurrection rule's list of EXEMPT writes, which was found short three separate
//! times by reading. It is a source scan rather than a behaviour test, because what it checks is
//! that a write which no revocation predicate protects has an argument written down beside it.

use std::time::{Duration, SystemTime};

/// THE RESURRECTION RULE'S OWN ENUMERATION, checked instead of asserted.
///
/// `store.rs`'s module docs state the rule and then state its exceptions: "a write on a record that
/// any revocation cascade removes must consult this predicate or be listed above with its argument.
/// Deriving that list means reading every cascade in this trait and asking what it removes, not
/// counting the call sites that already do the right thing."
///
/// Nothing checked the second half, and it had already been wrong TWICE. First
/// `put_pushed_authorization_request` was a genuine resurrection with neither a predicate nor an
/// exemption. Then `put_device_grant` was harmless but unlisted, while the doc claimed the exemption
/// count was "one, by construction". Both were found by reading, months apart, and the second is the
/// one this test is really for: an enumeration that omits a site BECAUSE the site is harmless is an
/// enumeration nobody can check, and it fails silently in exactly the direction where the next
/// omission is not harmless.
///
/// So the derivation is mechanised as far as source can carry it. Every `fn put_*` on `Storage` is
/// a write; a write is answered EITHER by returning [`oauth_as::WriteOutcome`], which is how a
/// method says it consults the [`oauth_as::RevocationBarrier`] predicate, OR by being named in the
/// exemption block with the argument for why it is safe. This test cannot judge the argument. It can
/// insist that one exists in the place a host reads, which is the property that failed both times.
///
/// A SOURCE SCAN because the alternative does not exist: a return type is visible to the compiler
/// but prose is not, and the pairing of the two is the whole assertion. `tests/host_api_shape.rs`
/// and `tests/allocation.rs` scan for the same reason.
#[test]
fn every_storage_write_either_consults_the_barrier_or_is_an_argued_exemption() {
    let source = include_str!("../src/store.rs");

    // The EXEMPTION BLOCK, bounded by the two headings around it. The opening heading is matched on
    // "WRITES ARE EXEMPT" rather than on the full "TWO WRITES ARE EXEMPT", deliberately: the count
    // is part of what the doc is asked to keep true, so it MUST be free to change without silently
    // turning this scan into a no-op that finds no block and exempts nothing.
    let open = source
        .find("WRITES ARE EXEMPT")
        .expect("the resurrection rule's exemption list has to still be there, by that name");
    let close = source[open..]
        .find("THE RULE FOR ANYONE ADDING A METHOD")
        .expect("the exemption list is bounded below by the rule it is an exception to")
        + open;
    let exemptions = &source[open..close];

    // The TRAIT BODY only. `impl Storage for MemoryStorage` further down the same file has a
    // `put_` for every one of these, and scanning it would make the reference implementation stand
    // in for the contract, which is the substitution this whole test file exists to prevent.
    let trait_at = source
        .find("pub trait Storage: Send + Sync {")
        .expect("the trait has to still be there");
    let trait_end = source[trait_at..]
        .find("\n}\n")
        .expect("the trait has to end")
        + trait_at;
    let body = &source[trait_at..trait_end];

    let mut writes = Vec::new();
    let mut unanswered = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("fn put_") else {
            continue;
        };
        // Only the trait's own declarations are indented by exactly four spaces; nothing else in
        // the body is a method signature.
        if !line.starts_with("    fn ") {
            continue;
        }
        let name: String = std::iter::once("put_".to_string())
            .chain(std::iter::once(
                rest.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<String>(),
            ))
            .collect();
        // Signatures wrap, so join forward to the terminating semicolon before reading the return
        // type: `put_token`'s `-> impl Future<...>` is four lines below its `fn`.
        let mut signature = String::new();
        for onward in body.lines().skip(i) {
            signature.push(' ');
            signature.push_str(onward.trim());
            if onward.trim_end().ends_with(';') {
                break;
            }
        }
        writes.push(name.clone());
        if signature.contains("WriteOutcome") {
            continue;
        }
        if exemptions.contains(&name) {
            continue;
        }
        unanswered.push(name);
    }

    assert!(
        writes.len() >= 5,
        "the scan found only {} `fn put_*` methods on Storage, so it has stopped finding them and \
         is no longer testing anything: {writes:?}",
        writes.len()
    );
    assert!(
        unanswered.is_empty(),
        "these Storage writes neither return WriteOutcome (which is how a method says it consults \
         the RevocationBarrier predicate) nor appear in the exemption block in store.rs's module \
         docs with the argument for why they are safe: {unanswered:?}\n\
         A revocation cascade in this trait removes the kind each one writes, so leaving it out of \
         both is the defect the exemption list was rewritten to stop. Add the method to the list \
         with its argument, or make it consult the predicate."
    );
}

/// A revocation-barrier deadline far enough out that the barrier stands for the whole test.
/// Local rather than shared: this file does not otherwise pull in the test support module.
fn far_future() -> SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000)
}

/// The whole window for these tests, which are about the CASCADE rather than about when a grant
/// was established: `recorded_at` is as far out as `until`, so every record they plant is covered.
fn far_future_window() -> oauth_as::store::RevocationWindow {
    oauth_as::store::RevocationWindow {
        recorded_at: far_future(),
        until: far_future(),
    }
}

use oauth_as::{ClientId, DeviceGrant, DeviceGrantState, MemoryStorage, ScopeSet, Storage};

const CLIENT: &str = "client-under-test";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn grant(device_code: &str, user_code: &str, expires_in: u64) -> DeviceGrant {
    DeviceGrant {
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        client_id: ClientId::new(CLIENT),
        scope: ScopeSet::parse("read").unwrap(),
        state: DeviceGrantState::Pending,
        created_at: now(),
        expires_at: now() + Duration::from_secs(expires_in),
        interval: Duration::from_secs(5),
        last_poll_at: None,
    }
}

/// The user-code index is a pointer rather than a record, which is why the sweep does not COUNT it,
/// and why it was left out of the doc's per-kind list for years. Leaving the entry behind is not
/// merely untidy: `put_device_grant` must refuse a user code already indexed for a different
/// `device_code`, so a stale entry takes that code out of circulation permanently, and the server's
/// generation loop cannot see it coming because the lookup it makes resolves to nothing.
#[tokio::test]
async fn a_swept_device_grant_takes_its_user_code_index_entry_with_it() {
    let store = MemoryStorage::new();
    store
        .put_device_grant(grant("dc-1", "WDJB-MJHT", 600))
        .await
        .unwrap();

    let removed = store
        .sweep_expired(now() + Duration::from_secs(601))
        .await
        .unwrap();
    assert_eq!(removed, 1, "the grant itself is the counted record");

    // The lookup already answers None with a stale entry present, so ask the question that a stale
    // entry actually answers differently: can the code be issued again?
    store
        .put_device_grant(grant("dc-2", "WDJB-MJHT", 600))
        .await
        .expect("a swept user code must be reusable, which a stale index entry prevents");
    let found = store
        .find_device_grant_by_user_code("WDJBMJHT")
        .await
        .unwrap()
        .expect("the new grant answers to the reissued code");
    assert_eq!(found.device_code, "dc-2");
}

/// RFC 7592 section 2.3 deletion, for the same reason.
#[tokio::test]
async fn deleting_a_client_takes_its_user_code_index_entries_with_it() {
    let store = MemoryStorage::new();
    store
        .put_device_grant(grant("dc-1", "WDJB-MJHT", 600))
        .await
        .unwrap();
    store
        .delete_client(&ClientId::new(CLIENT), far_future_window())
        .await
        .unwrap();

    assert!(store
        .find_device_grant_by_user_code("WDJBMJHT")
        .await
        .unwrap()
        .is_none());
    let mut reissued = grant("dc-2", "WDJB-MJHT", 600);
    reissued.client_id = ClientId::new("some-other-client");
    store
        .put_device_grant(reissued)
        .await
        .expect("the deleted client's user code must be reusable");
}

/// RFC 9126 section 2.2 binds a `request_uri` to the client that pushed it, so a deleted client's
/// outstanding handles are handles nobody may ever redeem, and nothing but this cascade and the
/// sweep ever removes one: `take_pushed_authorization_request` only removes a handle that is
/// actually REDEEMED.
#[cfg(feature = "par")]
#[tokio::test]
async fn deleting_a_client_removes_its_pushed_authorization_requests() {
    let store = MemoryStorage::new();
    let _ = store
        .put_pushed_authorization_request(oauth_as::PushedAuthorizationRequest::new(
            "urn:ietf:params:oauth:request_uri:abc",
            ClientId::new(CLIENT),
            now() + Duration::from_secs(60),
        ))
        .await
        .unwrap();

    store
        .delete_client(&ClientId::new(CLIENT), far_future_window())
        .await
        .unwrap();

    assert!(store
        .take_pushed_authorization_request("urn:ietf:params:oauth:request_uri:abc")
        .await
        .unwrap()
        .is_none());
}

/// A pushed request that was abandoned rather than redeemed is the ORDINARY case whenever a client
/// errors out after pushing, and only the sweep reclaims it.
#[cfg(feature = "par")]
#[tokio::test]
async fn an_abandoned_pushed_authorization_request_is_swept() {
    let store = MemoryStorage::new();
    let _ = store
        .put_pushed_authorization_request(oauth_as::PushedAuthorizationRequest::new(
            "urn:ietf:params:oauth:request_uri:abc",
            ClientId::new(CLIENT),
            now() + Duration::from_secs(60),
        ))
        .await
        .unwrap();

    let removed = store
        .sweep_expired(now() + Duration::from_secs(61))
        .await
        .unwrap();
    assert_eq!(removed, 1);
}

#[cfg(feature = "consent")]
fn consent(id: &str, client: &str, subject: &str) -> oauth_as::ConsentRecord {
    oauth_as::ConsentRecord {
        consent_id: id.into(),
        client_id: ClientId::new(client),
        subject: subject.into(),
        scope: ScopeSet::parse("read").unwrap(),
        resource: Vec::new(),
        granted_at: now(),
        authentication: None,
    }
}

/// The consent cascade is the one with a second-order consequence, and it is why the enumeration
/// being short mattered. `client_id` is chosen by the HOST (`register_client` takes whatever it is
/// given), so a consent record that outlives its client is not just an entry the user cannot
/// withdraw: the next client provisioned under the same id inherits a stranger's standing approval,
/// with its scope and its resource set, without that user ever being asked.
#[cfg(feature = "consent")]
#[tokio::test]
async fn deleting_a_client_removes_the_consents_that_name_it() {
    let store = MemoryStorage::new();
    store
        .put_consent(consent("consent-1", CLIENT, "user-1"))
        .await
        .unwrap();
    // Another client's consent for the same user must survive: a cascade that is too wide ends
    // sessions nobody asked to end.
    store
        .put_consent(consent("consent-2", "other-client", "user-1"))
        .await
        .unwrap();

    store
        .delete_client(&ClientId::new(CLIENT), far_future_window())
        .await
        .unwrap();

    let listed = store.consents_for_subject("user-1").await.unwrap();
    assert_eq!(listed.len(), 1, "only the other client's consent remains");
    assert_eq!(listed[0].consent_id.as_ref(), "consent-2");
    assert!(store
        .find_consent(&ClientId::new(CLIENT), "user-1")
        .await
        .unwrap()
        .is_none());
}

/// Withdrawal removes approved device grants, so it makes the same dangling index entry the sweep
/// and the client deletion do.
#[cfg(feature = "consent")]
#[tokio::test]
async fn withdrawing_a_consent_takes_the_user_code_index_with_the_grants_it_kills() {
    let store = MemoryStorage::new();
    let mut approved = grant("dc-1", "WDJB-MJHT", 600);
    approved.state = DeviceGrantState::Approved {
        subject: "user-1".to_string(),
    };
    store.put_device_grant(approved).await.unwrap();
    store
        .put_consent(consent("consent-1", CLIENT, "user-1"))
        .await
        .unwrap();

    let removed = store
        .revoke_consent("consent-1", far_future_window())
        .await
        .unwrap();
    assert_eq!(removed, 1, "the approved device grant");

    assert!(store
        .find_device_grant_by_user_code("WDJBMJHT")
        .await
        .unwrap()
        .is_none());
    store
        .put_device_grant(grant("dc-2", "WDJB-MJHT", 600))
        .await
        .expect("the withdrawn grant's user code must be reusable");
}
