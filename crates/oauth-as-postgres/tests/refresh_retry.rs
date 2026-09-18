#![cfg(feature = "pg-integration")]
#[path = "../../oauth-as/tests/support/mod.rs"]
mod oauth_support;
mod support;
use oauth_as::{token::RefreshTokenState, AuthorizationServer, ErrorCode, Storage};
use oauth_support::{
    refresh_retry::{config, exercise, mint, request},
    ManualClock,
};
use sqlx::Executor;

#[tokio::test]
async fn retry_contract_runs_against_postgres() {
    let schema = "refresh_retry_contract";
    support::fresh_schema(schema).await;
    let clock = ManualClock::at_epoch();
    let server =
        AuthorizationServer::with_clock(config(), support::store(schema, 2).await, clock.clone());
    exercise(&server, &clock).await;
}

#[tokio::test]
async fn independent_connections_and_restart_recover_one_response() {
    let schema = "refresh_retry_concurrency";
    support::fresh_schema(schema).await;
    let clock = ManualClock::at_epoch();
    let first =
        AuthorizationServer::with_clock(config(), support::store(schema, 1).await, clock.clone());
    let initial = mint(&first).await;
    let second =
        AuthorizationServer::with_clock(config(), support::store(schema, 1).await, clock.clone());
    let original = initial.refresh_token.as_deref().unwrap();
    let (a, b) = tokio::join!(
        first.token(request(original)),
        second.token(request(original))
    );
    let a = a.unwrap();
    assert_eq!(a, b.unwrap());
    drop(first);
    drop(second);
    let restarted =
        AuthorizationServer::with_clock(config(), support::store(schema, 1).await, clock.clone());
    assert_eq!(restarted.token(request(original)).await.unwrap(), a);
    assert_eq!(
        restarted
            .token(request(a.refresh_token.as_deref().unwrap()))
            .await
            .unwrap(),
        a
    );
    clock.advance(std::time::Duration::from_secs(30));
    assert_eq!(
        restarted.token(request(original)).await.unwrap_err().error,
        ErrorCode::InvalidGrant
    );
    assert!(restarted
        .introspect(&a.access_token)
        .await
        .unwrap()
        .is_none());
    // No orphan credential from the losing transaction.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_as_access_tokens")
        .fetch_one(restarted.store().pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn a_failed_atomic_rotation_leaves_the_original_retryable() {
    let schema = "refresh_retry_rollback";
    support::fresh_schema(schema).await;
    let server = AuthorizationServer::with_clock(
        config(),
        support::store(schema, 1).await,
        ManualClock::at_epoch(),
    );
    let initial = mint(&server).await;
    let original = initial.refresh_token.as_deref().unwrap();
    server.store().pool().execute("CREATE FUNCTION reject_access() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$").await.unwrap();
    server.store().pool().execute("CREATE TRIGGER reject_access BEFORE INSERT ON oauth_as_access_tokens FOR EACH ROW EXECUTE FUNCTION reject_access()").await.unwrap();
    assert_eq!(
        server.token(request(original)).await.unwrap_err().error,
        ErrorCode::ServerError
    );
    let unchanged = server
        .store()
        .get_refresh_token(original)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.state, RefreshTokenState::Active);
    assert!(unchanged.retry.is_none());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_as_refresh_tokens")
        .fetch_one(server.store().pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    server
        .store()
        .pool()
        .execute("DROP TRIGGER reject_access ON oauth_as_access_tokens")
        .await
        .unwrap();
    server.token(request(original)).await.unwrap();
}
