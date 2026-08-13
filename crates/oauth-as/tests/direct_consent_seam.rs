// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 6749 s10.12 on the DIRECT API, which is the adoption path with no builder in front of it.
//!
//! `ServiceBuilder` refuses to build a router with no consent resolver, so the `http` path cannot
//! reach code issuance without the host having written the word "approve". The direct path had no
//! such step: the old `issue_authorization_code(&validated, "alice")` read as a lookup and minted
//! a code.
//! That is the path this crate's DEFAULT build invites (no `http`, no listener, the host owns the
//! routes), so the auto-approving authorization server was the one a host got by doing nothing.
//!
//! The seam is [`oauth_as::server::UserApproval`]. It is not a proof and cannot be: the `http`
//! resolver's `ApprovalDecision::Approve` is not a proof either, and a host can wire `|_| Approve`
//! there just as it can call `UserApproval::granted` here. What both do is the same thing, which
//! is the whole of what a library at this boundary can do: make the approval a SENTENCE THE HOST
//! WROTE rather than a default it inherited.

mod support;

use oauth_as::server::UserApproval;
use oauth_as::{AuthorizationRequest, ErrorCode, Storage};
use support::{public_client, server_with, ManualClock, PUBLIC_REDIRECT, RFC7636_VERIFIER};

fn request(scope: &str) -> AuthorizationRequest<'static> {
    AuthorizationRequest::from_pairs([
        ("response_type", "code".to_string()),
        ("client_id", "public-app".to_string()),
        ("redirect_uri", PUBLIC_REDIRECT.to_string()),
        ("scope", scope.to_string()),
        (
            "code_challenge",
            oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER),
        ),
        ("code_challenge_method", "S256".to_string()),
    ])
}

/// A code is minted only from a [`UserApproval`], which names the subject AND the request it is an
/// approval of. There is no two-argument "here is a validated request, here is a user name" form
/// left for a host to reach for without having decided anything.
#[tokio::test]
async fn a_code_is_minted_from_an_approval_and_carries_its_subject() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let validated = srv
        .validate_authorization_request(&request("read"))
        .await
        .expect("a well formed request");

    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "alice"))
        .await
        .expect("an approved request mints a code");

    let record = srv
        .store()
        .take_authorization_code(&response.code)
        .await
        .expect("storage")
        .expect("the code was persisted");
    assert_eq!(record.subject, "alice");
}

/// The approval BORROWS the request it approves, so the subject and the request cannot be paired
/// up wrongly at the call site: there is no second request argument left to disagree with the one
/// the approval was built from. That is the bug class the two-argument form left open, where a
/// host prompts for request A and issues for request B, approving a narrow scope and minting a
/// wide one.
#[tokio::test]
async fn an_approval_carries_the_request_it_approves() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let narrow = srv
        .validate_authorization_request(&request("read"))
        .await
        .expect("a well formed request");
    let wide = srv
        .validate_authorization_request(&request("read write"))
        .await
        .expect("a well formed request");
    assert_eq!(wide.scope.to_string(), "read write");

    let response = srv
        .issue_authorization_code(UserApproval::granted(&narrow, "alice"))
        .await
        .expect("an approved request mints a code");
    let record = srv
        .store()
        .take_authorization_code(&response.code)
        .await
        .expect("storage")
        .expect("the code was persisted");
    assert_eq!(
        record.scope.to_string(),
        "read",
        "the code carries the scope the approval was built from"
    );
}

/// Denial still needs no approval to spell: RFC 6749 s4.1.2.1 `access_denied` at the (already
/// validated) redirect URI. The new argument gates the ISSUANCE, and nothing else.
#[tokio::test]
async fn a_refusal_still_needs_no_approval_to_spell() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let validated = srv
        .validate_authorization_request(&request("read"))
        .await
        .expect("a well formed request");
    assert_eq!(validated.denied().error.error, ErrorCode::AccessDenied);
}

/// The RFC 9470 entry point takes the same approval, so step-up enforcement and s10.12 consent are
/// not two separate questions with a path that answers only one of them.
#[cfg(feature = "consent")]
#[tokio::test]
async fn the_step_up_entry_point_takes_the_same_approval() {
    use oauth_as::consent::AuthenticationRequirement;
    use oauth_as::AuthorizationError;

    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let mut asked = request("read");
    asked.acr_values = Some("phr".into());
    let validated = srv
        .validate_authorization_request(&asked)
        .await
        .expect("a well formed request");
    let requirement = AuthenticationRequirement::from_request(&asked).expect("parses");

    // The user approved, and the host reported no authentication at all, so RFC 9470 s3 refuses.
    // Approval is necessary for issuance, never sufficient.
    let refused = srv
        .issue_authorization_code_with_authentication(
            UserApproval::granted(&validated, "alice"),
            &requirement,
            None,
        )
        .await;
    match refused {
        Err(AuthorizationError::Redirect(r)) => {
            assert_eq!(r.error.error, ErrorCode::InsufficientUserAuthentication);
        }
        other => panic!("expected an RFC 9470 refusal, got {other:?}"),
    }
}
