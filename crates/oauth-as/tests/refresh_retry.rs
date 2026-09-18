//! Bounded refresh retries use the real issuance and storage seams.
mod support;
use oauth_as::{AuthorizationServer, ErrorCode, MemoryStorage, Storage};
use std::time::Duration;
use support::{
    refresh_retry::{config, exercise, mint, request},
    ManualClock,
};

#[tokio::test]
async fn retries_coalesce_without_extending_expiry_or_crossing_bindings() {
    let clock = ManualClock::at_epoch();
    let server = AuthorizationServer::with_clock(config(), MemoryStorage::new(), clock.clone());
    exercise(&server, &clock).await;
}

#[tokio::test]
async fn absolute_expiry_and_revocation_override_retry_material() {
    let clock = ManualClock::at_epoch();
    let server = AuthorizationServer::with_clock(config(), MemoryStorage::new(), clock.clone());
    let initial = mint(&server).await;
    clock.advance(Duration::from_secs(110));
    let rotated = server
        .token(request(initial.refresh_token.as_deref().unwrap()))
        .await
        .unwrap();
    clock.advance(Duration::from_secs(10));
    assert_eq!(
        server
            .token(request(rotated.refresh_token.as_deref().unwrap()))
            .await
            .unwrap_err()
            .error,
        ErrorCode::InvalidGrant
    );

    let initial = mint(&server).await;
    let rotated = server
        .token(request(initial.refresh_token.as_deref().unwrap()))
        .await
        .unwrap();
    let next = server
        .store()
        .get_refresh_token(rotated.refresh_token.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    server
        .store()
        .revoke_token_family(&next.family_id, support::far_future_window())
        .await
        .unwrap();
    assert_eq!(
        server
            .token(request(initial.refresh_token.as_deref().unwrap()))
            .await
            .unwrap_err()
            .error,
        ErrorCode::InvalidGrant
    );
    assert!(server
        .introspect(&rotated.access_token)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_new_rotation_after_the_window_preserves_absolute_chain_expiry() {
    let clock = ManualClock::at_epoch();
    let server = AuthorizationServer::with_clock(config(), MemoryStorage::new(), clock.clone());
    let initial = mint(&server).await;
    let original = initial.refresh_token.as_deref().unwrap();
    let expiry = server
        .store()
        .get_refresh_token(original)
        .await
        .unwrap()
        .unwrap()
        .expires_at;
    let first = server.token(request(original)).await.unwrap();
    clock.advance(Duration::from_secs(30));
    let second = server
        .token(request(first.refresh_token.as_deref().unwrap()))
        .await
        .unwrap();
    assert_ne!(first.refresh_token, second.refresh_token);
    assert_eq!(
        server
            .store()
            .get_refresh_token(second.refresh_token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        expiry
    );
}

#[tokio::test]
async fn retry_cannot_change_the_effective_resource_or_owner() {
    let server =
        AuthorizationServer::with_clock(config(), MemoryStorage::new(), ManualClock::at_epoch());
    let initial = mint(&server).await;
    let original = initial.refresh_token.as_deref().unwrap();
    let mut record = (*server
        .store()
        .get_refresh_token(original)
        .await
        .unwrap()
        .unwrap())
    .clone();
    record.resource = vec![
        "https://one.example/mcp".into(),
        "https://two.example/mcp".into(),
    ];
    assert!(server
        .store()
        .put_refresh_token(record)
        .await
        .unwrap()
        .is_applied());
    let rotated = server
        .token_with_resources(request(original), &["https://one.example/mcp".into()])
        .await
        .unwrap();
    assert_eq!(
        server
            .token_with_resources(request(original), &["https://two.example/mcp".into()])
            .await
            .unwrap_err()
            .error,
        ErrorCode::InvalidTarget
    );
    let retry = server
        .token_with_resources(request(original), &["https://one.example/mcp".into()])
        .await
        .unwrap();
    assert_eq!(retry, rotated);
    // Corrupted/substituted recovery metadata must never release another owner's token.
    let mut record = (*server
        .store()
        .get_refresh_token(original)
        .await
        .unwrap()
        .unwrap())
    .clone();
    record.subject = Some("other-owner".into());
    assert!(server
        .store()
        .put_refresh_token(record)
        .await
        .unwrap()
        .is_applied());
    assert_eq!(
        server
            .token_with_resources(request(original), &["https://one.example/mcp".into()])
            .await
            .unwrap_err()
            .error,
        ErrorCode::InvalidGrant
    );
}
