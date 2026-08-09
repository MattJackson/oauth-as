// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The audit and event seam (`crates/oauth-as/src/events.rs`), from outside the crate.
//!
//! Two things are being pinned here, and they pull in opposite directions, which is why they sit
//! in one file:
//!
//! 1. A host that installs a sink must actually SEE what happened. The events that matter most are
//!    the two that are evidence of compromise (authorization code replay, refresh token reuse):
//!    the crate revokes on both, and a revocation nobody can observe is a revocation nobody can
//!    act on.
//! 2. A host that installs NOTHING must pay nothing: no allocation, no formatting, no vtable call,
//!    and not even the construction of the [`oauth_as::Event`] value itself. That is the crate
//!    doc's "zero cost until enabled" promise applied to this seam, and it is checked here with
//!    the same counting allocator `tests/allocation.rs` uses, plus a closure that PANICS if it is
//!    ever called.
//!
//! # Why this file is ONE `#[test]`
//!
//! Same reason as `tests/allocation.rs`: a `#[global_allocator]` is process wide and `std`'s test
//! harness starts a thread per `#[test]`, so a neighbouring test's startup can land inside a
//! measurement window. One test, gates run in sequence, failures collected.

mod support;

use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use oauth_as::{
    AuthorizationServer, ClientAuthFailure, ClientId, Event, EventSink, GrantType, Hooks,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest, TokenTypeHint,
};
use support::alloc::{measure, CountingAllocator, Delta, TEST_LOCK};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

#[test]
fn event_seam_gates() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let gates: &[(&str, fn())] = &[
        (
            "an_unconfigured_hook_never_builds_the_event",
            an_unconfigured_hook_never_builds_the_event,
        ),
        (
            "an_unconfigured_hook_allocates_nothing",
            an_unconfigured_hook_allocates_nothing,
        ),
        (
            "the_hook_slot_is_one_pointer_wide",
            the_hook_slot_is_one_pointer_wide,
        ),
        (
            "an_installed_sink_sees_every_event_it_is_handed",
            an_installed_sink_sees_every_event_it_is_handed,
        ),
        (
            "no_event_variant_carries_a_credential",
            no_event_variant_carries_a_credential,
        ),
        (
            "an_authorization_code_replay_reaches_the_sink",
            an_authorization_code_replay_reaches_the_sink,
        ),
        (
            "a_refresh_token_reuse_reaches_the_sink",
            a_refresh_token_reuse_reaches_the_sink,
        ),
        (
            "issuance_reaches_the_sink_without_carrying_a_token",
            issuance_reaches_the_sink_without_carrying_a_token,
        ),
        (
            "client_authentication_failures_are_distinguished_for_the_host_only",
            client_authentication_failures_are_distinguished_for_the_host_only,
        ),
        (
            "device_approval_and_denial_reach_the_sink",
            device_approval_and_denial_reach_the_sink,
        ),
        ("revocation_reaches_the_sink", revocation_reaches_the_sink),
    ];

    let mut failures = Vec::new();
    for (name, gate) in gates {
        if let Err(cause) = catch_unwind(AssertUnwindSafe(gate)) {
            let msg = cause
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| cause.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panicked with a non-string payload".to_string());
            failures.push(format!("{name}: {msg}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} event-seam gate(s) failed:\n{}",
        failures.len(),
        gates.len(),
        failures.join("\n")
    );
}

/// The event value is built by a CLOSURE, so that a host with no sink installed does not pay for
/// assembling a value nobody will read. This is the strongest available statement of that: the
/// closure panics, and an unconfigured [`Hooks`] must still return normally.
fn an_unconfigured_hook_never_builds_the_event() {
    let hooks = Hooks::new();
    hooks.emit(|| panic!("an unconfigured hook must not build the event"));
}

/// The allocation half of the same promise, measured rather than reasoned about: a thousand
/// emissions through an unconfigured hook must move the allocator's counters by exactly zero.
/// Zero, not a bound: zero is the actual claim.
fn an_unconfigured_hook_allocates_nothing() {
    let hooks = Hooks::new();
    let scope = ScopeSet::parse("read write").unwrap();
    let (_, d) = measure(|| {
        for _ in 0..1000 {
            hooks.emit(|| Event::TokenIssued {
                client_id: "some-client",
                grant_type: GrantType::AuthorizationCode,
                subject: Some("user-1"),
                scope: &scope,
                family_id: Some("f00d"),
                refresh_issued: true,
            });
        }
    });
    assert_eq!(
        d,
        Delta::default(),
        "an unconfigured event hook must not allocate: {d:?}"
    );
}

/// The hook slot lives on [`oauth_as::AuthorizationServer`], which `tests/allocation.rs` holds to a
/// size budget. Three installed seams behind three fat pointers would be 48 bytes on every server
/// value whether or not the host uses any of them, so the three live behind ONE boxed inner struct
/// that is never allocated until something is installed. What the server carries is one pointer.
fn the_hook_slot_is_one_pointer_wide() {
    assert_eq!(
        size_of::<Hooks>(),
        size_of::<usize>(),
        "Hooks must stay one pointer wide, or every AuthorizationServer pays for seams it does \
         not use"
    );
}

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl EventSink for Recorder {
    fn on_event(&self, event: Event<'_>) {
        // A real host would push a structured record; the discriminant name is enough here.
        let name = match event {
            Event::ClientAuthenticationFailed { .. } => "ClientAuthenticationFailed",
            Event::TokenIssued { .. } => "TokenIssued",
            Event::GrantRefused { .. } => "GrantRefused",
            Event::DeviceGrantApproved { .. } => "DeviceGrantApproved",
            Event::DeviceGrantDenied { .. } => "DeviceGrantDenied",
            Event::AuthorizationCodeReplayDetected { .. } => "AuthorizationCodeReplayDetected",
            Event::RefreshTokenReuseDetected { .. } => "RefreshTokenReuseDetected",
            Event::TokenRevoked { .. } => "TokenRevoked",
            _ => "unknown",
        };
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(name.to_string());
    }
}

/// Every event the seam defines reaches an installed sink. The two that matter most are the last
/// two checked: RFC 9700 section 4.1.1 (authorization code replay) and section 4.14.2 (refresh
/// token reuse) both make the AS revoke, and this crate does; a host that cannot see that fire
/// cannot start an incident response.
fn an_installed_sink_sees_every_event_it_is_handed() {
    let recorder = std::sync::Arc::new(Recorder::default());
    let mut hooks = Hooks::new();
    hooks.install_event_sink(Box::new(RecorderHandle(recorder.clone())));

    let scope = ScopeSet::parse("read").unwrap();
    hooks.emit(|| Event::ClientAuthenticationFailed {
        client_id: "c",
        failure: ClientAuthFailure::SecretMismatch,
    });
    hooks.emit(|| Event::TokenIssued {
        client_id: "c",
        grant_type: GrantType::DeviceCode,
        subject: Some("user-1"),
        scope: &scope,
        family_id: Some("f00d"),
        refresh_issued: true,
    });
    hooks.emit(|| Event::GrantRefused {
        client_id: "c",
        grant_type: GrantType::RefreshToken,
        error: oauth_as::ErrorCode::InvalidGrant,
    });
    hooks.emit(|| Event::DeviceGrantApproved {
        client_id: "c",
        subject: "user-1",
    });
    hooks.emit(|| Event::DeviceGrantDenied { client_id: "c" });
    hooks.emit(|| Event::AuthorizationCodeReplayDetected {
        client_id: "c",
        family_id: Some("f00d"),
        tokens_revoked: true,
        containment_failed: false,
    });
    hooks.emit(|| Event::RefreshTokenReuseDetected {
        client_id: "c",
        family_id: "f00d",
        records_revoked: 3,
    });
    hooks.emit(|| Event::TokenRevoked {
        client_id: "c",
        token_type: TokenTypeHint::RefreshToken,
        cascade_failed: false,
    });

    let seen = recorder.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen,
        vec![
            "ClientAuthenticationFailed",
            "TokenIssued",
            "GrantRefused",
            "DeviceGrantApproved",
            "DeviceGrantDenied",
            "AuthorizationCodeReplayDetected",
            "RefreshTokenReuseDetected",
            "TokenRevoked",
        ],
        "an installed sink must see every emitted event, in order"
    );
}

/// `Box<dyn EventSink>` takes ownership, and this test also wants to read what was recorded, so
/// the sink installed is a thin handle over the shared recorder.
struct RecorderHandle(std::sync::Arc<Recorder>);

impl EventSink for RecorderHandle {
    fn on_event(&self, event: Event<'_>) {
        self.0.on_event(event)
    }
}

/// The crate has just finished redacting `Debug` on every type that holds a credential (security
/// finding C13). The event channel is a second way out of the process for exactly the same values,
/// so this scans the [`Event`] declaration itself and refuses any field whose name is one of the
/// credentials: an access token, a refresh token, an authorization code, a device code, a user
/// code, a client secret, or a PKCE verifier.
///
/// A structural source scan rather than a runtime assertion because the property is about what the
/// type CAN carry, not about what one constructed value happens to hold. Same technique, and the
/// same no-new-dependency reasoning, as `tests/allocation.rs`'s static scan.
fn no_event_variant_carries_a_credential() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/events.rs");
    let text = std::fs::read_to_string(path).expect("src/events.rs must exist");

    let start = text
        .find("pub enum Event<'a> {")
        .expect("src/events.rs must declare `pub enum Event<'a>`");
    let body = &text[start..];
    let end = body
        .find("\n}\n")
        .expect("the Event declaration must be closed at column 0");
    let body = &body[..end];

    // Field names, not prose: the doc comments in that file discuss these words at length, and
    // saying WHY a secret is absent must not be what trips the gate.
    const FORBIDDEN: &[&str] = &[
        "access_token",
        "refresh_token:",
        "authorization_code",
        "device_code",
        "user_code",
        "secret",
        "code_verifier",
        "code_challenge",
        "token:",
    ];
    let mut offending = Vec::new();
    for (lineno, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        for word in FORBIDDEN {
            if trimmed.contains(word) {
                offending.push(format!("Event line {}: {trimmed}", lineno + 1));
            }
        }
    }
    assert!(
        offending.is_empty(),
        "an Event variant carries a credential; the event channel must not reintroduce the leak \
         C13 closed:\n{}",
        offending.join("\n")
    );
}

// ------------------------------------------------------------------ end to end
//
// The gates above pin the SEAM. These pin the WIRING: that the server actually reaches for it at
// the moments that matter. They run inside this file's single `#[test]` for the reason the module
// doc gives, each building its own current-thread runtime exactly as `tests/allocation.rs` does.

/// A sink that keeps the `Debug` rendering of every event, which is enough for these gates to
/// assert on both the variant and its fields without a second bespoke type per test.
#[derive(Default)]
struct Transcript(Mutex<Vec<String>>);

impl EventSink for Transcript {
    fn on_event(&self, event: Event<'_>) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{event:?}"));
    }
}

struct TranscriptHandle(std::sync::Arc<Transcript>);

impl EventSink for TranscriptHandle {
    fn on_event(&self, event: Event<'_>) {
        self.0.on_event(event)
    }
}

fn transcript_server() -> (
    tokio::runtime::Runtime,
    std::sync::Arc<Transcript>,
    AuthorizationServer<MemoryStorage, support::ManualClock>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    let transcript = std::sync::Arc::new(Transcript::default());
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(
        cfg,
        MemoryStorage::new(),
        support::ManualClock::at_epoch(),
    )
    .with_event_sink(Box::new(TranscriptHandle(transcript.clone())));
    rt.block_on(async {
        srv.register_client(support::confidential_client())
            .await
            .unwrap();
        srv.register_client(support::device_only_client())
            .await
            .unwrap();
    });
    (rt, transcript, srv)
}

fn lines(transcript: &Transcript) -> Vec<String> {
    transcript
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// RFC 6749 section 4.1.2 / RFC 9700 section 4.1.1: a replayed authorization code makes the server
/// revoke what the code minted. Before 0.2.0 that revocation was completely invisible. The event
/// must name the client and the family that was killed, so an operator can find the rest of the
/// grant in their own store.
fn an_authorization_code_replay_reaches_the_sink() {
    let (rt, transcript, srv) = transcript_server();
    rt.block_on(async {
        let (_issued, code) = support::mint_code_token_keeping_code(
            &srv,
            "confidential-app",
            Some(support::CONFIDENTIAL_SECRET),
            support::CONFIDENTIAL_REDIRECT,
            "read",
            "user-1",
        )
        .await;
        // The replay: the same code, a second time.
        let err = srv
            .token(TokenRequest::AuthorizationCode {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(support::CONFIDENTIAL_SECRET.to_string()),
                code,
                redirect_uri: Some(support::CONFIDENTIAL_REDIRECT.to_string()),
                code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
            })
            .await
            .expect_err("a replayed code must be refused");
        assert_eq!(err.error, oauth_as::ErrorCode::InvalidGrant);
    });

    let seen = lines(&transcript);
    let replay = seen
        .iter()
        .find(|l| l.starts_with("AuthorizationCodeReplayDetected"))
        .unwrap_or_else(|| panic!("no replay event in {seen:?}"));
    assert!(
        replay.contains("confidential-app") && replay.contains("tokens_revoked: true"),
        "the replay event must name the client and say what it revoked: {replay}"
    );
    assert!(
        seen.iter()
            .any(|l| l.starts_with("GrantRefused") && l.contains("InvalidGrant")),
        "the refusal itself must also be reported: {seen:?}"
    );
}

/// OAuth 2.1 draft section 6.1 / RFC 9700 section 4.14.2: presenting a rotated-away refresh token
/// revokes the whole family, INCLUDING the legitimate client's live tokens. That is the event a
/// host will be asked to explain, so it carries the family id and how many records went with it.
fn a_refresh_token_reuse_reaches_the_sink() {
    let (rt, transcript, srv) = transcript_server();
    rt.block_on(async {
        let issued = support::mint_code_token(
            &srv,
            "confidential-app",
            Some(support::CONFIDENTIAL_SECRET),
            support::CONFIDENTIAL_REDIRECT,
            "read",
            "user-1",
        )
        .await;
        let first_refresh = issued
            .refresh_token
            .expect("the code flow issues a refresh token");
        // Rotate once, so `first_refresh` becomes the superseded token.
        srv.token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(support::CONFIDENTIAL_SECRET.to_string()),
            refresh_token: first_refresh.clone(),
            scope: None,
        })
        .await
        .expect("the first rotation must succeed");
        // The reuse.
        let err = srv
            .token(TokenRequest::RefreshToken {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(support::CONFIDENTIAL_SECRET.to_string()),
                refresh_token: first_refresh,
                scope: None,
            })
            .await
            .expect_err("a spent refresh token must be refused");
        assert_eq!(err.error, oauth_as::ErrorCode::InvalidGrant);
    });

    let seen = lines(&transcript);
    let reuse = seen
        .iter()
        .find(|l| l.starts_with("RefreshTokenReuseDetected"))
        .unwrap_or_else(|| panic!("no reuse event in {seen:?}"));
    assert!(
        reuse.contains("confidential-app") && reuse.contains("records_revoked: "),
        "the reuse event must name the client and how much it revoked: {reuse}"
    );
    assert!(
        !reuse.contains("records_revoked: 0"),
        "a detected reuse must have revoked something: {reuse}"
    );
}

/// Issuance is reported with the grant that produced it, the subject, and whether a refresh token
/// went with it, and it carries NO token. The wire answer is a token; the audit record is not.
fn issuance_reaches_the_sink_without_carrying_a_token() {
    let (rt, transcript, srv) = transcript_server();
    let issued = rt.block_on(support::mint_code_token(
        &srv,
        "confidential-app",
        Some(support::CONFIDENTIAL_SECRET),
        support::CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    ));

    let seen = lines(&transcript);
    let event = seen
        .iter()
        .find(|l| l.starts_with("TokenIssued"))
        .unwrap_or_else(|| panic!("no issuance event in {seen:?}"));
    assert!(event.contains("AuthorizationCode"), "{event}");
    assert!(event.contains("user-1"), "{event}");
    assert!(event.contains("refresh_issued: true"), "{event}");
    assert!(
        !event.contains(&issued.access_token),
        "the issuance event must not carry the access token: {event}"
    );
    let refresh = issued.refresh_token.expect("refresh token");
    assert!(
        !event.contains(&refresh),
        "the issuance event must not carry the refresh token: {event}"
    );
}

/// RFC 6749 section 5.2 collapses "no such client" and "wrong secret" into one `invalid_client` on
/// the WIRE, so an attacker cannot enumerate registrations. The host's audit channel separates
/// them, because the host is not the attacker and the two are different incidents.
fn client_authentication_failures_are_distinguished_for_the_host_only() {
    let (rt, transcript, srv) = transcript_server();
    rt.block_on(async {
        let unknown = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("no-such-client"),
                client_secret: Some("whatever".to_string()),
                scope: None,
            })
            .await
            .expect_err("an unknown client must not authenticate");
        let wrong = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some("wrong-secret".to_string()),
                scope: None,
            })
            .await
            .expect_err("a wrong secret must not authenticate");
        // Identical on the wire.
        assert_eq!(unknown.error, oauth_as::ErrorCode::InvalidClient);
        assert_eq!(wrong.error, oauth_as::ErrorCode::InvalidClient);
    });

    let seen = lines(&transcript);
    assert!(
        seen.iter().any(|l| l.contains("UnknownClient")),
        "the host must be told an unknown client id was tried: {seen:?}"
    );
    assert!(
        seen.iter().any(|l| l.contains("SecretMismatch")),
        "the host must be told a real client presented a wrong secret: {seen:?}"
    );
    assert!(
        !seen.iter().any(|l| l.contains("wrong-secret")),
        "no event may carry the presented secret: {seen:?}"
    );
}

/// RFC 8628 section 3.3: the two verification-UI outcomes. A host running a consent screen needs
/// both in its audit trail, because "who approved this device, and when" is the first question
/// asked after a device turns out to belong to somebody else.
fn device_approval_and_denial_reach_the_sink() {
    let (rt, transcript, srv) = transcript_server();
    rt.block_on(async {
        let first = srv
            .device_authorization(
                &ClientId::new("device-only"),
                Some("s3cret-value-for-tests"),
                None,
            )
            .await
            .expect("device authorization");
        srv.approve_device(&first.user_code, "user-1")
            .await
            .expect("approval");
        let second = srv
            .device_authorization(
                &ClientId::new("device-only"),
                Some("s3cret-value-for-tests"),
                None,
            )
            .await
            .expect("device authorization");
        srv.deny_device(&second.user_code).await.expect("denial");
    });

    let seen = lines(&transcript);
    assert!(
        seen.iter()
            .any(|l| l.starts_with("DeviceGrantApproved") && l.contains("user-1")),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|l| l.starts_with("DeviceGrantDenied")),
        "{seen:?}"
    );
    assert!(
        !seen.iter().any(|l| l.contains("user_code")),
        "no event may carry the user code: {seen:?}"
    );
}

/// RFC 7009: revocation is reported, with which kind of token it was. A revocation the host cannot
/// see is a revocation it cannot reconcile against its own session state.
fn revocation_reaches_the_sink() {
    let (rt, transcript, srv) = transcript_server();
    rt.block_on(async {
        let issued = support::mint_code_token(
            &srv,
            "confidential-app",
            Some(support::CONFIDENTIAL_SECRET),
            support::CONFIDENTIAL_REDIRECT,
            "read",
            "user-1",
        )
        .await;
        srv.revoke(
            &ClientId::new("confidential-app"),
            Some(support::CONFIDENTIAL_SECRET),
            &issued.access_token,
            Some(oauth_as::TokenTypeHint::AccessToken),
        )
        .await
        .expect("revocation");
    });

    let seen = lines(&transcript);
    assert!(
        seen.iter()
            .any(|l| l.starts_with("TokenRevoked") && l.contains("AccessToken")),
        "{seen:?}"
    );
}
