// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The bounds that are NOT per-request, plus the two feature-gated arrays that share the argument.
//!
//! `tests/request_size_bounds.rs` covers the arrays whose cost dies with the request. This file
//! covers the one whose cost does not: [`oauth_as::ConsentRecord`]'s `resource` list is the UNION
//! of every resource ever approved for one (client, subject) pair, it is only ever widened, it is
//! never pruned, and it is scanned linearly by `covers` on every authorization request that
//! consults it. An uncapped per-request array is a spike; an uncapped persisted one is a deployment
//! that gets slower every month and never gets faster.

mod support;

#[cfg(feature = "consent")]
mod consent_bounds {
    use oauth_as::consent::{ConsentRecord, RequestedDetails, MAX_CONSENT_RESOURCES};
    use oauth_as::{ClientId, ScopeSet};
    use std::time::{Duration, UNIX_EPOCH};

    fn record() -> ConsentRecord {
        ConsentRecord {
            consent_id: "c1".into(),
            client_id: ClientId::new("app"),
            subject: "alice".into(),
            scope: ScopeSet::parse("read").unwrap(),
            resource: Vec::new(),
            granted_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            authentication: None,
        }
    }

    fn resources(from: usize, n: usize) -> Vec<String> {
        (from..from + n)
            .map(|i| format!("https://rs{i}.example/api"))
            .collect()
    }

    /// THE FINDING, and the worst of the three because the cost is DURABLE. Nothing bounded the
    /// persisted list, so a client that names a fresh resource indicator on each authorization
    /// request grows the record without limit, and every later `extend` dedups the new values
    /// against the whole of it.
    #[test]
    fn a_consent_record_stops_widening_at_the_cap() {
        let mut r = record();
        r.extend(&ScopeSet::empty(), &resources(0, MAX_CONSENT_RESOURCES));
        assert_eq!(r.resource.len(), MAX_CONSENT_RESOURCES);

        r.extend(&ScopeSet::empty(), &resources(1000, 500));
        assert_eq!(
            r.resource.len(),
            MAX_CONSENT_RESOURCES,
            "the persisted list is a ceiling, not a suggestion"
        );
    }

    /// The cap fails in the HARMLESS direction, and this pins which direction that is. A resource
    /// that did not fit is simply not covered, so `covers` answers false and the host re-prompts
    /// the user. That is the same direction `extend`'s scope-union failure already takes, and the
    /// opposite of the dangerous one: it must never silently report coverage it does not have.
    #[test]
    fn a_resource_that_did_not_fit_is_not_reported_as_covered() {
        let mut r = record();
        r.extend(&ScopeSet::empty(), &resources(0, MAX_CONSENT_RESOURCES));
        let extra = resources(9000, 1);
        r.extend(&ScopeSet::empty(), &extra);
        assert!(
            !r.covers(&ScopeSet::empty(), &extra, RequestedDetails::none()),
            "an unrecorded resource must read as not covered, so the user is asked again"
        );
    }

    /// What was already recorded is untouched: the cap refuses to GROW, it never prunes. Dropping
    /// an approved resource would narrow a consent silently while tokens carrying it are still
    /// live, which is the lie `extend`'s own docs refuse to tell.
    #[test]
    fn the_cap_never_removes_something_the_user_already_approved() {
        let mut r = record();
        let first = resources(0, MAX_CONSENT_RESOURCES);
        r.extend(&ScopeSet::empty(), &first);
        r.extend(&ScopeSet::empty(), &resources(1000, 50));
        assert!(
            r.covers(&ScopeSet::empty(), &first, RequestedDetails::none()),
            "everything approved before the cap was reached stays approved"
        );
    }
}

#[cfg(feature = "token-exchange")]
mod exchange_bounds {
    use oauth_as::token_exchange::MAX_AUDIENCE_VALUES;

    /// RFC 8693 section 2.1.1 makes `audience` repeatable and this crate deduplicates it against
    /// `targets` with an O(n) scan per element, on top of an already-validated `resource` list.
    /// Neither side was capped, so the exchange endpoint carried the same quadratic that
    /// `validate_resources` did.
    #[test]
    fn the_audience_cap_exists_and_matches_the_resource_cap() {
        assert_eq!(
            MAX_AUDIENCE_VALUES,
            oauth_as::server::MAX_RESOURCE_INDICATORS,
            "audience and resource name the same thing in two spellings (s2.1.1), so one number"
        );
    }
}

/// RFC 7591 section 3.2.1 `client_secret_expires_at`: this server MINTS that value, PUBLISHES it to
/// the registrant, and then never looked at it again. A secret this deployment itself declared
/// dead on the wire went on authenticating forever, which makes the field a promise the server
/// does not keep.
#[tokio::test]
async fn a_dynamically_registered_secret_stops_working_when_it_expires() {
    use oauth_as::{
        Client, ClientAuth, ClientId, DynamicRegistration, ErrorCode, GrantType, ScopeSet,
        TokenRequest,
    };
    use std::time::{Duration, UNIX_EPOCH};

    let clock = support::ManualClock::at_epoch();
    // The fixture clock sits at this instant, so the secret has 60 seconds of life left.
    let now = 1_700_000_000u64;
    let client = Client {
        client_id: ClientId::new("dyn-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "dyn-secret-value".into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("api:read").unwrap(),
        default_scopes: ScopeSet::parse("api:read").unwrap(),
        name: None,
        registration: Some(Box::new(DynamicRegistration {
            registration_access_token_hash: oauth_as::SecretHash::sha256("unused-here"),
            client_id_issued_at: Some(now),
            client_secret_expires_at: Some(now + 60),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
        })),
    };
    let srv = support::server_with(clock.clone(), vec![client]).await;

    let request = || TokenRequest::ClientCredentials {
        client_id: ClientId::new("dyn-app"),
        client_secret: Some("dyn-secret-value".to_string()),
        scope: None,
    };

    srv.token(request())
        .await
        .expect("the secret is still live before its stated expiry");

    clock.advance(Duration::from_secs(61));
    let refused = srv
        .token(request())
        .await
        .expect_err("past client_secret_expires_at the secret is not a credential any more");
    assert_eq!(
        refused.error,
        ErrorCode::InvalidClient,
        "RFC 6749 s5.2 collapses every client authentication failure into one answer"
    );

    let _ = UNIX_EPOCH;
}

/// RFC 7591 section 3.2.1 gives `0` a specific meaning: the secret NEVER expires. It must not be
/// read as "expired at the epoch", which is what a naive comparison does and which would break
/// every registration that took the default.
#[tokio::test]
async fn client_secret_expires_at_zero_means_never() {
    use oauth_as::{
        Client, ClientAuth, ClientId, DynamicRegistration, GrantType, ScopeSet, TokenRequest,
    };
    use std::time::Duration;

    let clock = support::ManualClock::at_epoch();
    let client = Client {
        client_id: ClientId::new("forever-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "forever-secret".into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("api:read").unwrap(),
        default_scopes: ScopeSet::parse("api:read").unwrap(),
        name: None,
        registration: Some(Box::new(DynamicRegistration {
            registration_access_token_hash: oauth_as::SecretHash::sha256("unused-here"),
            client_id_issued_at: Some(1_700_000_000),
            client_secret_expires_at: Some(0),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
        })),
    };
    let srv = support::server_with(clock.clone(), vec![client]).await;
    clock.advance(Duration::from_secs(86_400 * 3650));
    srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("forever-app"),
        client_secret: Some("forever-secret".to_string()),
        scope: None,
    })
    .await
    .expect("0 means never, ten years later included");
}

/// `lib.rs` re-exports [`oauth_as::DeviceApprovalError`] specifically so a host's verification UI
/// can match on it, and every other host-facing failure enum in this crate is `#[non_exhaustive]`
/// so that a later release can add a case without breaking that host's build. This one was not,
/// which makes adding any new refusal a semver-major change.
///
/// A SOURCE scan, for the same reason `tests/events.rs` scans the `Event` declaration: the property
/// is about what the declaration says, and `#[non_exhaustive]` is invisible from inside the crate
/// that declares it, so no runtime assertion can see it.
#[test]
fn device_approval_error_is_non_exhaustive() {
    let source = include_str!("../src/server.rs");
    let at = source
        .find("pub enum DeviceApprovalError")
        .expect("the enum has to still be there");
    let preamble = &source[at.saturating_sub(400)..at];
    assert!(
        preamble.contains("#[non_exhaustive]"),
        "DeviceApprovalError is re-exported for hosts to match on, so a new variant must not be \
         a breaking change"
    );
}
