// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `AuthorizationServer::hooks` hands the host back the seams it installed.
//!
//! The crate's own code paths read the private field, not this accessor, so nothing exercised it
//! and a mutation run found it could return a fresh empty `Hooks` with every test still passing.
//! That is not cosmetic: the accessor exists so a host can consult its OWN limiter and emit onto
//! the same event channel from its own consent step, and one that silently answers "nothing is
//! installed" turns a host's rate limit into a no-op at exactly the call sites the host wrote it
//! for.

use oauth_as::events::{Attempt, RateLimitDecision, RateLimiter};
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;

/// A limiter with an answer nothing else in the crate would produce.
struct RefuseCodeEntry;

impl RateLimiter for RefuseCodeEntry {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        match attempt {
            Attempt::DeviceUserCodeEntry => RateLimitDecision::Deny,
            _ => RateLimitDecision::Allow,
        }
    }
}

fn config() -> ServerConfig {
    ServerConfig::new("https://as.example", "https://as.example/device")
}

/// RFC 8628 section 5.1 makes rate limiting user code entry part of what makes the code's entropy
/// adequate, and a host that puts its verification UI in front of the library has to be able to
/// ask the SAME limiter before it ever calls in. That is what this accessor is for, so it has to
/// return the installed seams rather than an empty set.
#[test]
fn the_accessor_returns_the_seams_the_host_installed() {
    let server = AuthorizationServer::new(config(), MemoryStorage::new())
        .with_rate_limiter(Box::new(RefuseCodeEntry));
    assert_eq!(
        server.hooks().check(Attempt::DeviceUserCodeEntry),
        RateLimitDecision::Deny,
        "the host's own limiter must be reachable through the accessor it was given"
    );
    // The other attempt kind is still allowed, so this is the installed limiter answering rather
    // than a blanket refusal.
    assert_eq!(
        server.hooks().check(Attempt::ClientAuthentication {
            client_id: "anyone"
        }),
        RateLimitDecision::Allow
    );
}

/// And a host that installed nothing sees nothing: an absent limiter allows, which is what keeps
/// the seam free for every deployment that does not want it.
#[test]
fn an_uninstalled_seam_allows_rather_than_inventing_a_policy() {
    let server = AuthorizationServer::new(config(), MemoryStorage::new());
    assert_eq!(
        server.hooks().check(Attempt::DeviceUserCodeEntry),
        RateLimitDecision::Allow
    );
    assert!(!server.hooks().is_observed(), "no event sink was installed");
}
