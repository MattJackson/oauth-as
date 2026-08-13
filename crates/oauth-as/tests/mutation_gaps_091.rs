// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE MUTANTS THAT SURVIVED THE 0.9.1 SWEEP, killed here.
//!
//! A surviving mutant is a hole in the suite, not a curiosity: it is a line no test was actually
//! checking. Three of these sit in code 0.9.1 ADDED, which makes them holes in the fix this
//! release exists to make, and the sweep found them precisely because that code was new.
//!
//! Each test below names the mutation it kills, so that a later reader can re-apply it by hand and
//! watch this file go red rather than taking the claim on trust. That is how each was verified.

mod support;

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::store::WriteOutcome;
#[cfg(feature = "consent")]
use oauth_as::ConsentRecord;
use oauth_as::{
    AuthorizationServer, ClientCredential, ClientId, Clock, MemoryStorage, RefreshTokenRecord,
    ScopeSet, ServerConfig, Storage, StorageError, TokenRequest, TokenRequestContext,
};
use support::{
    confidential_client, mint_code_token, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
};

// ------------------------------------------------------------------ server.rs: undo_issuance
//
// KILLS: `replace AuthorizationServer::undo_issuance with ()`
//
// Issuance is two writes with no transaction spanning them, so a revocation landing between them
// leaves the access token standing while the refresh record is refused. `undo_issuance` is what
// takes that token back. Nothing proved it did anything at all: the mutant emptied the function
// and every test still passed, which means the orphaned-token path was never observed.

/// Accepts the access token, RECORDS which one it was, and refuses the refresh record. That is
/// exactly the state the store is in when a revocation lands between issuance's two writes.
struct RefusesTheRefreshWrite {
    inner: MemoryStorage,
    /// What `put_token` was asked to store. The caller is answered with an error and never sees
    /// the token, so this is the only way a test can name it afterwards, which is also precisely
    /// why an orphan here is dangerous: nobody can revoke a string nobody holds.
    wrote: Mutex<Option<String>>,
}

impl Storage for RefusesTheRefreshWrite {
    async fn put_token(&self, token: oauth_as::IssuedToken) -> Result<WriteOutcome, StorageError> {
        *self.wrote.lock().unwrap_or_else(|e| e.into_inner()) = Some(token.access_token.clone());
        self.inner.put_token(token).await
    }

    async fn put_refresh_token(
        &self,
        _record: RefreshTokenRecord,
    ) -> Result<WriteOutcome, StorageError> {
        Ok(WriteOutcome::RefusedRevoked)
    }

    oauth_as::delegate_storage! {
        to inner;
        get_client, put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        get_token, delete_token,
        get_refresh_token, take_refresh_token, revoke_token_family,
        put_consent, compare_and_swap_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

#[tokio::test]
async fn a_refused_refresh_write_takes_the_access_token_back_with_it() {
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        RefusesTheRefreshWrite {
            inner: MemoryStorage::new(),
            wrote: Mutex::new(None),
        },
        ManualClock::at_epoch(),
    );
    srv.register_client(confidential_client()).await.unwrap();

    // A code grant issues an access token AND a refresh chain: two writes, and the second is
    // refused here, which is what a revocation landing between them looks like from inside.
    let outcome = redeem_a_code(&srv).await;
    assert!(
        outcome.is_err(),
        "the caller must be told the grant did not survive"
    );

    let minted = srv
        .store()
        .wrote
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .expect("issuance got as far as writing an access token");

    assert!(
        srv.store().get_token(&minted).await.unwrap().is_none(),
        "an access token survived an issuance whose refresh write was refused: undo_issuance did \
         not take it back, so the store holds a live credential nobody was handed and nobody can \
         name in order to revoke it"
    );
}

/// Drive the authorization code grant far enough to reach issuance, and hand back whatever the
/// token endpoint answered.
///
/// It has to be the CODE grant, not client credentials: RFC 6749 s4.4 issues no refresh token, so
/// with client credentials the second write never happens and the refusal under test is never
/// reached. That mistake made this test pass against the defect, which is the failure mode this
/// whole file is about.
async fn redeem_a_code(
    srv: &AuthorizationServer<RefusesTheRefreshWrite, ManualClock>,
) -> Result<oauth_as::TokenResponse, oauth_as::ErrorResponse> {
    use oauth_as::server::UserApproval;
    use oauth_as::AuthorizationRequest;
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let req = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "confidential-app"),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("state", "undo-issuance-state"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();
    srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        code: response.code,
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
        code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
    })
    .await
}

// --------------------------------------------------- server.rs: revocation_window's sign
//
// KILLS: mutants of `saturating_deadline`, which is where the arithmetic actually is.
//
// THERE IS NO `+` IN `revocation_window`. It computes `until: saturating_deadline(recorded_at,
// longest)`, and the addition lives inside that helper as a `checked_add` with a halving fallback
// for the platform ceiling. This header named `replace + with - in revocation_window` until 0.9.1
// and that described a mutant cargo-mutants will never generate — the same failure the
// `mutation_gaps_request_object.rs` header calls out, so it is corrected the same way: name what
// is there. What this case constrains is the SIGN AND DIRECTION of the deadline, whichever
// operator produces it.
//
// The deadline must land in the FUTURE. Landing in the past makes the barrier reclaimable the
// instant it is recorded. Nothing else caught that, because `is_revoked` deliberately ignores the
// deadline (an expired barrier still refuses until the sweep takes it), so the only observation
// that can tell the two apart is a SWEEP.

#[tokio::test]
async fn a_sweep_right_after_a_revocation_does_not_reclaim_the_barrier() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock.clone(), vec![confidential_client()]).await;
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

    // Revoke through the SERVER, so the deadline is the one `revocation_window` computed
    // rather than one the test chose.
    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &rt,
        None,
    )
    .await
    .expect("RFC 7009 s2.2: revocation answers 200");

    // A sweep at the CURRENT instant. A correctly signed deadline is in the future, so this
    // reclaims nothing; a deadline in the past is reclaimed immediately.
    srv.store().sweep_expired(Clock::now(&clock)).await.unwrap();

    let after_sweep = srv
        .store()
        .put_refresh_token(RefreshTokenRecord::new(
            "rt-after-the-sweep",
            ClientId::new("confidential-app"),
            Some("user-1".to_string()),
            ScopeSet::parse("read").unwrap(),
            family,
        ))
        .await
        .unwrap();
    assert!(
        after_sweep.is_refused(),
        "a sweep run immediately after a revocation reclaimed the barrier it had just recorded, \
         so the revoked family is writable again: the barrier deadline is in the past, which \
         means `saturating_deadline` moved it the wrong way"
    );
}

// ------------------------------------------------------- server.rs: record_consent's shape guard
//
// KILLS: `replace match guard expected.is_none() with true in record_consent`
//
// The guard exists so a call that started as a WIDEN cannot become a CREATE on its retry, because
// the only way the record can vanish between attempts is a withdrawal. With the guard always true,
// the retry refuses even when the record is still there and the first attempt merely lost an
// ordinary race, which turns a recoverable conflict into a hard failure.

/// Fails the first `compare_and_swap_consent` and then behaves. That is the ordinary lost race:
/// another writer got there first and the record is still present, so the retry must succeed.
#[cfg(feature = "consent")]
struct FailsTheFirstConsentSwap {
    inner: MemoryStorage,
    /// How many swaps have been asked for. The one that must fail is the WIDEN's first attempt,
    /// which is the second swap overall: the create ahead of it has to succeed, or the widen has
    /// no record to widen and the call is a create again, which does not reach the guard at all.
    swaps: Mutex<u32>,
}

#[cfg(feature = "consent")]
impl Storage for FailsTheFirstConsentSwap {
    async fn compare_and_swap_consent(
        &self,
        expected: Option<&ConsentRecord>,
        updated: ConsentRecord,
    ) -> Result<bool, StorageError> {
        {
            let mut swaps = self.swaps.lock().unwrap_or_else(|e| e.into_inner());
            *swaps += 1;
            if *swaps == 2 {
                return Ok(false);
            }
        }
        self.inner.compare_and_swap_consent(expected, updated).await
    }

    oauth_as::delegate_storage! {
        to inner;
        get_client, put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        put_token, get_token, delete_token,
        put_refresh_token, get_refresh_token, take_refresh_token, revoke_token_family,
        put_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

#[cfg(feature = "consent")]
#[tokio::test]
async fn a_widen_that_loses_one_race_still_succeeds_on_the_retry() {
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        FailsTheFirstConsentSwap {
            inner: MemoryStorage::new(),
            swaps: Mutex::new(0),
        },
    );
    srv.register_client(confidential_client()).await.unwrap();
    let client_id = ClientId::new("confidential-app");

    // The create succeeds. It has to: the widen below is what reaches the guard, and it can only
    // be a widen if there is a record to widen.
    srv.record_consent(
        &client_id,
        "user-1",
        &ScopeSet::parse("read").unwrap(),
        &[],
        None,
    )
    .await
    .expect("the create must succeed so that the call below is a widen");

    // And the widen, with the record present throughout, must also succeed.
    let widened = srv
        .record_consent(
            &client_id,
            "user-1",
            &ScopeSet::parse("read write").unwrap(),
            &[],
            None,
        )
        .await
        .expect(
            "a widen whose record is still present must succeed: refusing here turns an ordinary \
             lost race into a hard failure, and the guard is meant to catch a WITHDRAWAL, which \
             this is not",
        );
    assert!(
        widened.scope.contains("write"),
        "the widen must have applied"
    );
}

// ------------------------------------------------ authorization.rs: the Replayed Debug arm
//
// KILLS: `delete match arm AuthorizationCodeState::Replayed{..} in Debug`
//
// `Replayed` shares an or-pattern with `Consumed` and picks its name with an inner match, so
// deleting the arm changes only which NAME prints. That name is the whole diagnostic value of the
// variant: an operator reading a dump has to be able to tell a redemption from a detected replay.

#[test]
fn the_replayed_state_prints_its_own_name_and_still_redacts() {
    let replayed = oauth_as::AuthorizationCodeState::Replayed {
        access_token: Some("at-secret-value".to_string()),
        refresh_token: Some("rt-secret-value".to_string()),
    };
    let rendered = format!("{replayed:?}");
    assert!(
        rendered.starts_with("Replayed"),
        "a detected replay must be distinguishable from an ordinary redemption in a debug dump, \
         which is the only place an operator sees it: {rendered}"
    );
    assert!(
        !rendered.contains("at-secret-value") && !rendered.contains("rt-secret-value"),
        "the credentials this code minted must not print: {rendered}"
    );

    // And the sibling still prints as itself, so the name is chosen rather than constant.
    let consumed = oauth_as::AuthorizationCodeState::Consumed {
        access_token: None,
        refresh_token: None,
    };
    assert!(format!("{consumed:?}").starts_with("Consumed"));
}

// -------------------------------------------------- server.rs: TokenRequestContext::with_resources
//
// KILLS: `replace TokenRequestContext::with_resources -> Self with Default::default()`
//
// The builder returning a DEFAULT context rather than itself throws away everything set before it,
// including the credential. Nothing noticed, which means no test built a context through this
// method and then observed what came out of it.

#[tokio::test]
async fn with_resources_keeps_what_the_context_already_carried() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let resources = vec!["https://rs.example/api".to_string()];

    let ctx = TokenRequestContext::new(ClientCredential::secret(Some(CONFIDENTIAL_SECRET)))
        .with_resources(&resources);

    let issued = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
                scope: None,
            },
            ctx,
        )
        .await
        .expect("the context must still carry the request it was built with");
    let stored = srv
        .store()
        .get_token(&issued.access_token)
        .await
        .unwrap()
        .expect("issued token is stored");
    assert_eq!(
        stored.resource, resources,
        "the RFC 8707 resource the context carried did not reach the token, so the builder threw \
         away what was set before it"
    );
}

// ------------------------------------------------------------------ unused import guard
const _: Option<SystemTime> = None;
const _: Option<Duration> = None;
const _: Option<fn() -> SystemTime> = Some(|| UNIX_EPOCH);
