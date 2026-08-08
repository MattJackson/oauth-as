// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8628 device authorization grant: boundary behaviour not already pinned by
//! `tests/device_flow.rs` (which this file deliberately does not modify or share fixtures with,
//! per this pass's file-ownership split): user-code normalization edges, the very first poll,
//! cumulative slow_down under hammering, single delivery of the two terminal answers, the
//! non-destructive cross-client poll, and `verification_uri_complete` configurability.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode, GrantType, MemoryStorage,
    ScopeSet, ServerConfig, Storage, TokenRequest,
};

/// A hand-cranked clock shared between the test and the server under test (copied locally, not
/// via `tests/support`, per this file's ownership rules). Expiry and poll pacing are exercised by
/// advancing it; nothing here sleeps.
#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
    fn advance(&self, d: Duration) {
        let mut t = self.0.lock().unwrap();
        *t += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Test device".into()),
    }
}

fn other_device_client() -> Client {
    Client {
        client_id: ClientId::new("other-device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
    }
}

async fn server_with_config(
    clock: ManualClock,
    cfg: ServerConfig,
    clients: Vec<Client>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}

async fn server_with(
    clock: ManualClock,
    clients: Vec<Client>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    server_with_config(clock, cfg, clients).await
}

fn poll(client_id: &str, device_code: &str) -> TokenRequest {
    TokenRequest::DeviceCode {
        client_id: ClientId::new(client_id),
        client_secret: None,
        device_code: device_code.to_string(),
    }
}

// ------------------------------------------------------------- user-code normalization

/// RFC 8628 section 6.1: the verification UI SHOULD accept user entry that varies in case,
/// hyphenation, and surrounding whitespace. Each variant here is exercised against its OWN fresh
/// grant (rather than reusing one grant across several `approve_device` calls, which would only
/// prove the first variant, since a grant is no longer `Pending` after the first approval).
#[tokio::test]
async fn sloppy_user_code_entry_resolves_to_the_same_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;

    let variants: [fn(&str) -> String; 4] = [
        |code: &str| code.to_lowercase(),
        |code: &str| code.replace('-', ""),
        |code: &str| format!("  {code}  "),
        |code: &str| code.replace('-', " "),
    ];

    for (i, variant) in variants.iter().enumerate() {
        let auth = srv
            .device_authorization(&ClientId::new("device-client"), None, None)
            .await
            .unwrap();
        let entered = variant(&auth.user_code);
        srv.approve_device(&entered, "u")
            .await
            .unwrap_or_else(|e| panic!("variant {i} ({entered:?}) must resolve the grant: {e}"));
    }
}

/// The negative half: entry that differs in an actual SYMBOL (not case, hyphenation, or
/// whitespace) is a different code and must not resolve. A normalization routine that was too
/// permissive (for example, one that also ignored a trailing/leading extra character) would pass
/// this only by accident.
#[tokio::test]
async fn user_code_entry_differing_in_a_real_symbol_does_not_resolve() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    // Replace the first alphabet symbol with a character that is guaranteed to differ: the
    // alphabet is `BCDFGHJKLMNPQRSTVWXZ`, so `Q` is never adjacent-confusable with itself, and if
    // the real first character already is `Q` this still produces a different code (`Q` != `Q`'s
    // neighbor would be the only failure mode, so pick a fixed replacement that cannot equal the
    // original by construction: flip case-normalized identity by using a symbol NOT in the
    // alphabet at all, which can never equal any real code).
    let mut chars: Vec<char> = auth.user_code.chars().collect();
    let first_alpha = chars.iter().position(|c| c.is_ascii_alphabetic()).unwrap();
    chars[first_alpha] = 'Q';
    if chars[first_alpha] == auth.user_code.chars().nth(first_alpha).unwrap() {
        chars[first_alpha] = 'K';
    }
    let mutated: String = chars.into_iter().collect();
    assert_ne!(
        mutated, auth.user_code,
        "the mutation must actually change the code"
    );

    let err = srv.approve_device(&mutated, "u").await.unwrap_err();
    assert!(matches!(
        err,
        oauth_as::server::DeviceApprovalError::UnknownUserCode
    ));

    // The real code still works: the mutation did not corrupt the original grant.
    srv.approve_device(&auth.user_code, "u").await.unwrap();
}

// ------------------------------------------------------------- first poll / slow_down pacing

/// RFC 8628 section 3.5: `slow_down` is a response to polling FASTER than the required interval.
/// There is no prior poll to be faster than on the very first one, so the first poll can never be
/// `slow_down`, no matter how little time has elapsed since the device_code was issued (here,
/// none at all: the clock is not advanced before this poll).
#[tokio::test]
async fn the_first_poll_is_never_slow_down_even_with_zero_elapsed_time() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    let err = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::AuthorizationPending,
        "the first ever poll must never be slow_down"
    );
}

/// RFC 8628 section 3.5: the client MUST increase its poll interval by at least 5 seconds on
/// every `slow_down`. This drives many rapid ("hammering") polls and checks two properties at
/// once: the required interval grows CUMULATIVELY (not capped, not reset by a later success), and
/// each rejected poll restarts the window, so hammering can never "wait out" the penalty by
/// polling often instead of politely.
#[tokio::test]
async fn hammering_raises_the_interval_cumulatively_and_never_drains_the_wait() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    // First poll: establishes last_poll_at, never slow_down.
    let err = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::AuthorizationPending);

    // Hammer with 1-second gaps. The configured interval starts at 5s and grows by 5s on each
    // rejected poll, so every one of these (all under the CURRENT required spacing at the time it
    // fires) must be slow_down, and the required spacing must strictly increase each time.
    const HAMMER_ROUNDS: u32 = 6;
    for round in 1..=HAMMER_ROUNDS {
        clock.advance(Duration::from_secs(1));
        let err = srv
            .token(poll("device-client", &auth.device_code))
            .await
            .unwrap_err();
        assert_eq!(
            err.error,
            ErrorCode::SlowDown,
            "hammer round {round}: 1s after a rejected poll must still be slow_down, however \
             many times the required interval has already grown"
        );
    }

    // At this point the required interval is 5 + 5*HAMMER_ROUNDS = 35 seconds, and the window
    // restarted at the LAST hammer poll. Waiting the ORIGINAL 5s interval is nowhere near enough:
    // hammering never drains the requirement back down. This poll is ALSO too fast, so it is
    // itself a rejected poll: it restarts the window again (to this poll's own time) and grows
    // the interval once more, to 40s. That growth-on-every-rejection is exactly the property
    // under test, so the next wait has to clear the NEW 40s requirement, not the 35s one.
    clock.advance(Duration::from_secs(5));
    let err = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::SlowDown,
        "the original 5s interval must not suffice after repeated slow_down growth"
    );

    // Waiting out the FULL grown interval (40s from the poll just above, which reset the window
    // and grew the interval again by being rejected) finally succeeds.
    clock.advance(Duration::from_secs(40));
    let err = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::AuthorizationPending,
        "a poll spaced by the full grown interval must finally be accepted (as pending, since \
         nobody approved it)"
    );
}

// ------------------------------------------------------------- terminal answers, delivered once

/// RFC 8628 section 3.5: `expired_token` is the answer for a poll after the device_code's
/// lifetime has passed. This pins that it is delivered exactly once: the expiry removes the
/// grant, so a SECOND poll (even one that arrives before any further time passes) cannot see
/// `expired_token` again, because as far as storage is concerned the code no longer exists.
#[tokio::test]
async fn expired_token_is_delivered_once_then_a_later_poll_is_plain_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    clock.advance(Duration::from_secs(600));
    let first = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(first.error, ErrorCode::ExpiredToken);

    // No further time passes: this is the immediate next poll, and it must NOT repeat
    // expired_token.
    let second = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(
        second.error,
        ErrorCode::InvalidGrant,
        "expired_token must be delivered exactly once; the grant is gone afterward"
    );

    assert!(srv
        .store()
        .get_device_grant(&auth.device_code)
        .await
        .unwrap()
        .is_none());
}

/// RFC 8628 section 3.5 / 3.4: `access_denied` is the terminal answer for a denied grant,
/// delivered once. A second poll after the denial has been reported must be `invalid_grant`, not
/// a repeat of `access_denied`, because the grant was consumed along with its answer.
#[tokio::test]
async fn denied_grant_answers_access_denied_once_then_is_consumed() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    srv.deny_device(&auth.user_code).await.unwrap();

    clock.advance(Duration::from_secs(5));
    let first = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(first.error, ErrorCode::AccessDenied);

    clock.advance(Duration::from_secs(5));
    let second = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(
        second.error,
        ErrorCode::InvalidGrant,
        "access_denied must be delivered exactly once"
    );

    assert!(srv
        .store()
        .get_device_grant(&auth.device_code)
        .await
        .unwrap()
        .is_none());
}

// ------------------------------------------------------------- cross-client poll is non-destructive

/// A device_code belongs to the client it was issued to. Polling it from a DIFFERENT, otherwise
/// legitimately registered client must fail (`invalid_grant`) without touching the grant at all:
/// neither its approval state nor its poll-pacing window. This checks both halves explicitly:
/// (1) the cross-client poll itself is refused, and (2) the legitimate device can still complete
/// its flow immediately afterward, at the pace it was already keeping, as if the cross-client
/// attempt had never happened.
#[tokio::test]
async fn cross_client_poll_does_not_consume_or_disturb_the_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client(), other_device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    // The legitimate device polls once, pending, establishing pacing.
    let err = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::AuthorizationPending);

    // A different registered client polls the SAME device_code: refused, not pending.
    clock.advance(Duration::from_secs(5));
    let err = srv
        .token(poll("other-device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::InvalidGrant,
        "a device_code belongs to the client it was issued to"
    );

    // The user approves in the meantime.
    srv.approve_device(&auth.user_code, "u").await.unwrap();

    // More cross-client polling, hammered even, must still not disturb anything: the pacing
    // window the legitimate device already established is untouched, so it does not need to
    // wait any longer than it otherwise would have.
    let err = srv
        .token(poll("other-device-client", &auth.device_code))
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    // The legitimate device polls again, at exactly the pace it was already keeping (5s after
    // its last real poll): it must succeed, proving the cross-client attempts never touched the
    // grant's state or its pacing window.
    clock.advance(Duration::from_secs(5));
    let token = srv
        .token(poll("device-client", &auth.device_code))
        .await
        .expect("the legitimate device must still be able to complete after cross-client polls");
    assert!(!token.access_token.is_empty());
}

// ------------------------------------------------------------- verification_uri_complete

/// RFC 8628 section 3.2: `verification_uri_complete` is OPTIONAL, and this crate makes it
/// host-configurable. When enabled it must be present and must embed the user code (so a QR code
/// or deep link can skip manual entry).
#[tokio::test]
async fn verification_uri_complete_is_present_and_contains_the_user_code_when_configured_on() {
    let clock = ManualClock::at_epoch();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.include_verification_uri_complete = true;
    let srv = server_with_config(clock, cfg, vec![device_client()]).await;

    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    let complete = auth
        .verification_uri_complete
        .as_deref()
        .expect("must be present when configured on");
    assert!(
        complete.contains(&auth.user_code),
        "verification_uri_complete {complete:?} must contain the user code {:?}",
        auth.user_code
    );
    assert!(complete.starts_with(&auth.verification_uri));
}

/// The other half: when the host configures it off, the field is genuinely absent (not present
/// with an empty string), matching RFC 8628 section 3.2's "OPTIONAL" and this server's `serde`
/// contract of omitting rather than nulling absent optional fields.
#[tokio::test]
async fn verification_uri_complete_is_absent_when_configured_off() {
    let clock = ManualClock::at_epoch();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.include_verification_uri_complete = false;
    let srv = server_with_config(clock, cfg, vec![device_client()]).await;

    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    assert_eq!(auth.verification_uri_complete, None);

    // The wire form must OMIT the member entirely, never serialize it as null.
    let json = serde_json::to_value(&auth).unwrap();
    assert!(
        !json
            .as_object()
            .unwrap()
            .contains_key("verification_uri_complete"),
        "an absent verification_uri_complete must be omitted from the JSON body, not null"
    );
}
