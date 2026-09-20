// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

use super::{mint_code_token, public_client, ManualClock, PUBLIC_REDIRECT};
use oauth_as::{
    AuthorizationServer, ClientId, ErrorCode, ScopeSet, ServerConfig, Storage, TokenRequest,
    TokenResponse,
};
use std::time::Duration;

pub fn config() -> ServerConfig {
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    config.refresh_retry_window = Duration::from_secs(30);
    config.refresh_token_ttl = Some(Duration::from_secs(120));
    config
}

pub fn request(token: &str) -> TokenRequest {
    TokenRequest::RefreshToken {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        refresh_token: token.to_string(),
        scope: None,
    }
}

pub async fn mint<S: Storage>(server: &AuthorizationServer<S, ManualClock>) -> TokenResponse {
    server.register_client(public_client()).await.unwrap();
    mint_code_token(
        server,
        "public-app",
        None,
        PUBLIC_REDIRECT,
        "read write",
        "owner",
    )
    .await
}

pub async fn exercise<S: Storage>(
    server: &AuthorizationServer<S, ManualClock>,
    clock: &ManualClock,
) {
    let initial = mint(server).await;
    let original = initial.refresh_token.as_deref().unwrap();
    let expiry = server
        .store()
        .get_refresh_token(original)
        .await
        .unwrap()
        .unwrap()
        .expires_at;
    let rotated = server.token(request(original)).await.unwrap();
    assert_ne!(rotated.refresh_token, initial.refresh_token);
    assert_eq!(server.token(request(original)).await.unwrap(), rotated);
    let spent = server
        .store()
        .get_refresh_token(original)
        .await
        .unwrap()
        .unwrap();
    let printed = format!("{spent:?}");
    assert!(!printed.contains(original));
    assert!(!printed.contains(&rotated.access_token));
    assert!(!printed.contains(rotated.refresh_token.as_deref().unwrap()));
    // Existing persisted records without the new optional field still decode.
    let mut legacy = serde_json::to_value(&*spent).unwrap();
    legacy.as_object_mut().unwrap().remove("retry");
    let legacy: oauth_as::RefreshTokenRecord = serde_json::from_value(legacy).unwrap();
    assert!(legacy.retry.is_none());
    let next = rotated.refresh_token.as_deref().unwrap();
    // A successor refreshed early must not invalidate responses still in flight.
    assert_eq!(server.token(request(next)).await.unwrap(), rotated);
    assert_eq!(
        server
            .store()
            .get_refresh_token(next)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        expiry
    );
    clock.advance(Duration::from_secs(5));
    let retry = server.token(request(original)).await.unwrap();
    assert_eq!(retry.access_token, rotated.access_token);
    assert_eq!(retry.expires_in, rotated.expires_in - 5);

    let mut stranger = public_client();
    stranger.client_id = ClientId::new("other-client");
    server.register_client(stranger).await.unwrap();
    let mut wrong_client = request(original);
    if let TokenRequest::RefreshToken { client_id, .. } = &mut wrong_client {
        *client_id = ClientId::new("other-client");
    }
    assert_eq!(
        server.token(wrong_client).await.unwrap_err().error,
        ErrorCode::InvalidGrant
    );
    let mut different_scope = request(original);
    if let TokenRequest::RefreshToken { scope, .. } = &mut different_scope {
        *scope = Some(ScopeSet::parse("read").unwrap());
    }
    assert_eq!(
        server.token(different_scope).await.unwrap_err().error,
        ErrorCode::InvalidScope
    );
    assert!(server
        .introspect(&rotated.access_token)
        .await
        .unwrap()
        .is_some());
    // Deadline is fixed, not extended by either retry above.
    clock.advance(Duration::from_secs(25));
    assert_eq!(
        server.token(request(original)).await.unwrap_err().error,
        ErrorCode::InvalidGrant
    );
    assert!(server
        .introspect(&rotated.access_token)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        server.token(request(next)).await.unwrap_err().error,
        ErrorCode::InvalidGrant
    );
}
