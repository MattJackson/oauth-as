// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The rate limiting seam (`crates/oauth-as/src/events.rs`), from outside the crate.
//!
//! WHY THIS SEAM EXISTS. RFC 8628 section 5.1 says the device user code's entropy is adequate
//! "in combination with" rate limiting of user code entry, and this crate's own
//! `ServerConfig::user_code_length` doc has always admitted the arithmetic: 8 symbols over the
//! 20-symbol alphabet is about 2^34.6, and at a thousand attempts a second against a pool of
//! concurrently live grants an attacker lands on SOME live grant with meaningful probability
//! inside one code lifetime. A hit on approve binds a stranger's device to the attacker's account.
//! Until 0.2.0 the library counted nothing and, worse, gave the host nowhere to put a counter.
//!
//! What the library can and cannot do is a fixed boundary and these tests pin the library's half
//! of it: it never sees an IP, a session or a user, so it cannot COUNT; what it can do is ASK
//! before it acts and TELL afterwards, which is exactly [`RateLimiter::check`] and
//! [`RateLimiter::record`].

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use oauth_as::{Attempt, AttemptOutcome, Hooks, RateLimitDecision, RateLimiter};

/// The seam is READ through [`Hooks`] and INSTALLED through the server's builder, which is the
/// only installation verb this crate publishes as of 0.9.1. These tests exercise the seam itself
/// rather than an endpoint, so they take the shortest route to a `&Hooks`: build a server, install
/// through `with_rate_limiter`, and borrow. Constructing a bare `Hooks` and calling an
/// `install_...` method on it was the second, unreachable installation API that 0.9.1 removed.
fn hooks_with(
    limiter: Box<dyn RateLimiter>,
) -> oauth_as::AuthorizationServer<oauth_as::MemoryStorage> {
    oauth_as::AuthorizationServer::new(
        oauth_as::ServerConfig::new("https://as.example", "https://as.example/device"),
        oauth_as::MemoryStorage::new(),
    )
    .with_rate_limiter(limiter)
}

/// A limiter that refuses after `allow_first` attempts, recording every call it is handed.
#[derive(Default)]
struct CountingLimiter {
    allow_first: usize,
    checks: AtomicUsize,
    recorded: Mutex<Vec<(String, AttemptOutcome)>>,
}

impl CountingLimiter {
    fn new(allow_first: usize) -> Self {
        CountingLimiter {
            allow_first,
            ..Default::default()
        }
    }

    fn label(attempt: Attempt<'_>) -> String {
        match attempt {
            Attempt::ClientAuthentication { client_id } => format!("client:{client_id}"),
            Attempt::DeviceUserCodeEntry => "device-user-code".to_string(),
            _ => "unknown".to_string(),
        }
    }
}

impl RateLimiter for CountingLimiter {
    fn check(&self, _attempt: Attempt<'_>) -> RateLimitDecision {
        let seen = self.checks.fetch_add(1, Ordering::SeqCst);
        if seen < self.allow_first {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Deny
        }
    }

    fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
        self.recorded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((Self::label(attempt), outcome));
    }
}

/// A host that installs nothing is not rate limited BY THE LIBRARY, and must not be refused by it
/// either. The default answer is `Allow`, because a library that silently throttled would be
/// making a policy decision it has none of the information to make.
#[test]
fn an_unconfigured_hook_allows_every_attempt() {
    let hooks = Hooks::new();
    for _ in 0..10_000 {
        assert_eq!(
            hooks.check(Attempt::DeviceUserCodeEntry),
            RateLimitDecision::Allow
        );
    }
    // And recording against no limiter is a no-op rather than a panic.
    hooks.record(Attempt::DeviceUserCodeEntry, AttemptOutcome::Failed);
}

/// RFC 8628 section 5.1: the host must be able to refuse user code entry outright. The seam's
/// `Deny` is what the server turns into `DeviceApprovalError::RateLimited`.
#[test]
fn an_installed_limiter_can_deny_device_user_code_entry() {
    let server = hooks_with(Box::new(CountingLimiter::new(3)));
    let hooks = server.hooks();

    for _ in 0..3 {
        assert_eq!(
            hooks.check(Attempt::DeviceUserCodeEntry),
            RateLimitDecision::Allow
        );
    }
    assert_eq!(
        hooks.check(Attempt::DeviceUserCodeEntry),
        RateLimitDecision::Deny,
        "the fourth attempt must be refused by the host's limiter"
    );
}

/// A limiter counts FAILURES, so the outcome has to come back to it: `check` before the work,
/// `record` after. Without `record` a host could only throttle traffic, not wrong guesses, which
/// is the wrong axis for a guessing attack against a short code.
#[test]
fn outcomes_are_reported_back_to_the_limiter() {
    let limiter = std::sync::Arc::new(CountingLimiter::new(usize::MAX));
    let server = hooks_with(Box::new(LimiterHandle(limiter.clone())));
    let hooks = server.hooks();

    hooks.record(Attempt::DeviceUserCodeEntry, AttemptOutcome::Failed);
    hooks.record(
        Attempt::ClientAuthentication {
            client_id: "some-app",
        },
        AttemptOutcome::Succeeded,
    );

    let seen = limiter
        .recorded
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen,
        vec![
            ("device-user-code".to_string(), AttemptOutcome::Failed),
            ("client:some-app".to_string(), AttemptOutcome::Succeeded),
        ]
    );
}

/// `record` has a default no-op body, so a host that only wants a hard ceiling implements one
/// method. This pins that the default exists and does not panic.
#[test]
fn recording_is_optional_for_a_limiter_implementation() {
    struct CeilingOnly;
    impl RateLimiter for CeilingOnly {
        fn check(&self, _attempt: Attempt<'_>) -> RateLimitDecision {
            RateLimitDecision::Deny
        }
    }
    let server = hooks_with(Box::new(CeilingOnly));
    let hooks = server.hooks();
    hooks.record(Attempt::DeviceUserCodeEntry, AttemptOutcome::Failed);
    assert_eq!(
        hooks.check(Attempt::DeviceUserCodeEntry),
        RateLimitDecision::Deny
    );
}

/// The user code itself must NEVER reach the limiter: RFC 8628 section 6.1 makes it the credential
/// a human types, and a limiter is exactly the kind of component a host wires to a metrics
/// backend or a log. A limiter keyed on the attempted code would also be useless, since every
/// guess is a different code. Structural check of the declaration, same technique as the event
/// seam's credential scan.
#[test]
fn the_attempt_type_carries_no_credential() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/events.rs");
    let text = std::fs::read_to_string(path).expect("src/events.rs must exist");
    let start = text
        .find("pub enum Attempt<'a> {")
        .expect("src/events.rs must declare `pub enum Attempt<'a>`");
    let body = &text[start..];
    let end = body
        .find("\n}\n")
        .expect("the Attempt declaration must be closed at column 0");
    for (lineno, line) in body[..end].lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        for word in ["user_code", "secret", "device_code", "token"] {
            assert!(
                !trimmed.contains(word),
                "Attempt line {} carries a credential: {trimmed}",
                lineno + 1
            );
        }
    }
}

struct LimiterHandle(std::sync::Arc<CountingLimiter>);

impl RateLimiter for LimiterHandle {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        self.0.check(attempt)
    }

    fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
        self.0.record(attempt, outcome)
    }
}

// ------------------------------------------------------------------ end to end
//
// The tests above pin the SEAM. These pin the WIRING: that the server asks the limiter at the two
// points RFC 8628 section 5.1 and RFC 9700 section 4.13 care about, and honours a refusal.

mod support;

use oauth_as::{
    AuthorizationServer, ClientId, DeviceApprovalError, ErrorCode, MemoryStorage, ServerConfig,
    TokenRequest,
};
use support::{confidential_client, device_only_client, ManualClock};

/// A limiter that refuses ONE kind of attempt and records everything it was asked about. Two
/// kinds, so a test can throttle user-code entry without also locking the device's own client out
/// of the token endpoint, which is exactly the distinction a real deployment draws.
struct DenyOnly {
    deny: &'static str,
    asked: Mutex<Vec<String>>,
}

impl DenyOnly {
    fn new(deny: &'static str) -> Self {
        DenyOnly {
            deny,
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl RateLimiter for DenyOnly {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        let label = CountingLimiter::label(attempt);
        let deny = label.starts_with(self.deny);
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(label);
        if deny {
            RateLimitDecision::Deny
        } else {
            RateLimitDecision::Allow
        }
    }
}

struct DenyHandle(std::sync::Arc<DenyOnly>);

impl RateLimiter for DenyHandle {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        self.0.check(attempt)
    }
}

async fn device_server(
    limiter: Box<dyn RateLimiter>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch())
        .with_rate_limiter(limiter);
    srv.register_client(device_only_client()).await.unwrap();
    srv.register_client(confidential_client()).await.unwrap();
    srv
}

/// RFC 8628 section 5.1, the whole reason this seam exists: the host can stop user-code guessing
/// at the door. A refused attempt must not even reach the store, so a correct code presented while
/// throttled is refused too (an attacker who has just guessed right must not be rescued by having
/// guessed right).
#[tokio::test]
async fn a_denying_limiter_refuses_device_user_code_entry() {
    let limiter = std::sync::Arc::new(DenyOnly::new("device-user-code"));
    let srv = device_server(Box::new(DenyHandle(limiter.clone()))).await;
    let auth = srv
        .device_authorization(
            &ClientId::new("device-only"),
            Some("s3cret-value-for-tests"),
            None,
        )
        .await
        .expect("this limiter throttles user-code entry, not the device's own client auth");

    assert_eq!(
        srv.approve_device(&auth.user_code, "user-1").await,
        Err(DeviceApprovalError::RateLimited),
        "a throttled approval must be refused, even with the RIGHT code"
    );
    assert_eq!(
        srv.deny_device(&auth.user_code).await,
        Err(DeviceApprovalError::RateLimited),
        "the denial endpoint answers the same question and must be throttled too"
    );

    let asked = limiter
        .asked
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert!(
        asked.iter().filter(|a| *a == "device-user-code").count() >= 2,
        "the limiter must have been asked about both entries: {asked:?}"
    );
}

/// The grant is untouched by a throttled attempt: the throttle refuses BEFORE the lookup, so a
/// legitimate user typing their code a moment later still finds it pending.
#[tokio::test]
async fn a_throttled_attempt_does_not_disturb_the_grant() {
    let srv = device_server(Box::new(DenyOnly::new("device-user-code"))).await;
    let auth = srv
        .device_authorization(
            &ClientId::new("device-only"),
            Some("s3cret-value-for-tests"),
            None,
        )
        .await
        .unwrap();
    let _ = srv.approve_device(&auth.user_code, "attacker").await;

    // The device's own poll still reports `authorization_pending`, not an approval.
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some("s3cret-value-for-tests".to_string()),
            device_code: auth.device_code,
        })
        .await
        .expect_err("nothing was approved");
    assert_eq!(err.error, ErrorCode::AuthorizationPending);
}

/// A wrong code is reported to the limiter as a FAILURE, which is the signal a guessing attack
/// actually produces; a correct one is reported as a success. Counting traffic instead would
/// throttle a busy legitimate verification page just as hard as an attacker.
#[tokio::test]
async fn user_code_outcomes_are_reported_to_the_limiter() {
    let limiter = std::sync::Arc::new(CountingLimiter::new(usize::MAX));
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch())
        .with_rate_limiter(Box::new(LimiterHandle(limiter.clone())));
    srv.register_client(device_only_client()).await.unwrap();
    let auth = srv
        .device_authorization(
            &ClientId::new("device-only"),
            Some("s3cret-value-for-tests"),
            None,
        )
        .await
        .unwrap();

    let _ = srv.approve_device("ZZZZ-ZZZZ", "user-1").await;
    srv.approve_device(&auth.user_code, "user-1").await.unwrap();

    // Client authentication is recorded too (the device grant authenticates its client); this
    // gate is about the user-code axis, so it looks at that one.
    let seen: Vec<_> = limiter
        .recorded
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|(what, _)| what == "device-user-code")
        .cloned()
        .collect();
    assert_eq!(
        seen,
        vec![
            ("device-user-code".to_string(), AttemptOutcome::Failed),
            ("device-user-code".to_string(), AttemptOutcome::Succeeded),
        ],
        "a wrong code must count as a failure and a right one as a success"
    );
}

/// Client authentication is the other place a bounded credential is guessed at (RFC 9700 section
/// 4.13 treats credential stuffing at the token endpoint as a first-class threat), and the attempt
/// carries the `client_id` because RFC 6749 section 2.2 makes it explicitly NOT a secret, so a
/// limiter may key on it. Nothing else about the request is available to the library.
///
/// The assertion is the LABEL the limiter was handed, character for character. Until the 0.9.1
/// audit this test handed a `client_id` to a limiter whose `check` discarded its argument and
/// asserted only that the answer was `Deny`, which it was for any input at all: replacing the
/// server's `client_id.as_str()` with `""` changed nothing it looked at.
#[tokio::test]
async fn client_authentication_attempts_name_the_client() {
    let limiter = std::sync::Arc::new(DenyOnly::new("client:"));
    let srv = device_server(Box::new(DenyHandle(limiter.clone()))).await;
    let _ = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(support::CONFIDENTIAL_SECRET.to_string()),
            scope: None,
        })
        .await;

    let asked = limiter
        .asked
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        asked,
        vec!["client:confidential-app".to_string()],
        "the limiter must be told WHICH client is authenticating, or it can only throttle the \
         endpoint as a whole"
    );
}

/// RFC 9700 section 4.13: credential stuffing at the token endpoint. A throttled client
/// authentication is refused with the SAME `invalid_client` a wrong secret gets, so the throttle
/// does not become an oracle telling an attacker they had found a live registration.
///
/// The comparison is the whole `ErrorResponse`, not just its code, for the reason
/// `tests/client_auth.rs` compares whole values too: a description attached on one path and not
/// the other is the oracle, in a field the code alone does not cover. Until the 0.9.1 audit this
/// asserted `ErrorCode::InvalidClient` and nothing else, and adding a `.with_description("rate
/// limited")` to the throttle's refusal left it green.
#[tokio::test]
async fn a_denying_limiter_refuses_client_authentication() {
    let srv = device_server(Box::new(DenyOnly::new("client:"))).await;
    let throttled = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(support::CONFIDENTIAL_SECRET.to_string()),
            scope: None,
        })
        .await
        .expect_err("a throttled client must not authenticate, right secret or not");
    assert_eq!(throttled.error, ErrorCode::InvalidClient);

    // The same request against an unthrottled server, with the secret wrong instead: what an
    // attacker probing for live registrations would otherwise be comparing against.
    let open = device_server(Box::new(CountingLimiter::new(usize::MAX))).await;
    let wrong_secret = open
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some("not-the-secret".to_string()),
            scope: None,
        })
        .await
        .expect_err("a wrong secret must not authenticate");
    assert_eq!(
        throttled, wrong_secret,
        "the throttle must be indistinguishable from a wrong secret, description and all"
    );
}
