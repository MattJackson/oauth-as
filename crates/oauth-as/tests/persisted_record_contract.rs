// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE TWO PROMISES A PERSISTED RECORD MAKES TO THE NEXT BUILD THAT READS IT.
//!
//! The first is that turning a FEATURE on does not make what is already in the store unreadable.
//! `tests/host_api_shape.rs` states why that is not a theoretical worry: cargo feature unification
//! means a host's dependency graph can turn `rar` on without the host asking for it, so "the build
//! changed" is not a decision an operator made and cannot be one they planned a migration around.
//! `IssuedToken::grant_established_at` documents the same failure reached by the other door, in the
//! doc that gives it a serde default: "without a default the read fails outright and every token
//! that release issued becomes unreadable the moment this one starts". A non-`Option` field added
//! under a feature gate is that same missing key, and serde's derive gives an `Option` a `None`
//! default but gives a non-`Option` nothing, so every one of them needs `#[serde(default)]`
//! spelled out.
//!
//! The second is that a record's `Debug` shows what its own doc says it shows. These are hand
//! written rather than derived so a credential never prints, and each says in prose that everything
//! else "stays visible so the record is still debuggable". A field the impl silently drops is a
//! field an operator cannot see at the moment they most need to, and for `grant_established_at`
//! that moment is exactly the one it exists for: it is the sole time input to every
//! `RevocationBarrier` comparison, its fail-closed default is the epoch, and "this token is refused
//! by a barrier and I cannot see why" is the symptom.
//!
//! `tests/revocation_races.rs::records_written_by_0_9_0_survive_the_upgrade` is the same shape for
//! the version axis; this file is the feature axis, plus the `Debug` promise both axes rely on to
//! be diagnosable.

mod support;

use oauth_as::{
    AuthorizationCodeRecord, ClientId, IssuedToken, RefreshTokenRecord, ScopeSet, TokenResponse,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn instant(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn token() -> IssuedToken {
    let mut t = IssuedToken::new(
        "at",
        ClientId::new("app"),
        Some("alice".into()),
        ScopeSet::parse("read").unwrap(),
        instant(1_700_000_000),
        instant(1_700_003_600),
    );
    t.grant_established_at = instant(1_699_000_000);
    t.family_id = Some("fam".into());
    t
}

fn refresh() -> RefreshTokenRecord {
    let mut r = RefreshTokenRecord::new(
        "rt",
        ClientId::new("app"),
        Some("alice".into()),
        ScopeSet::parse("read").unwrap(),
        "fam",
    );
    r.grant_established_at = instant(1_699_000_000);
    r
}

fn code() -> AuthorizationCodeRecord {
    let mut c = AuthorizationCodeRecord::new(
        "code",
        ClientId::new("app"),
        "https://app.example/cb",
        ScopeSet::parse("read").unwrap(),
        "alice",
        "challenge",
        instant(1_700_000_060),
    );
    c.issued_at = instant(1_699_000_000);
    c
}

/// A record a build WITHOUT `rar` wrote, read by a build WITH it.
///
/// Serializing here and REMOVING the key is how a no-`rar` build's bytes are reproduced without
/// running two builds: the only difference between the two encodings is the presence of that one
/// member, because every other field is gated on nothing or is an `Option` serde already defaults.
/// The direction matters and is the only one worth testing: a feature turning ON is the upgrade a
/// host's dependency graph can perform for them.
#[cfg(feature = "rar")]
mod rar_upgrade {
    use super::*;

    fn survives_without_the_key<T>(record: &T, what: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut value = serde_json::to_value(record).expect("a record serializes");
        let object = value
            .as_object_mut()
            .expect("records encode as JSON objects");
        assert!(
            object.remove("authorization_details").is_some(),
            "{what} must carry the key at all for this test to be testing anything"
        );
        let read: Result<T, _> = serde_json::from_value(value);
        assert!(
            read.is_ok(),
            "{what} written by a build without `rar` must still read: {:?}",
            read.err()
        );
    }

    #[test]
    fn an_access_token_written_without_rar_reads_with_it() {
        survives_without_the_key(&token(), "IssuedToken");
        let mut value = serde_json::to_value(token()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("authorization_details");
        let read: IssuedToken = serde_json::from_value(value).expect("reads");
        assert!(
            read.authorization_details.is_empty(),
            "a grant that predates the feature carried no details, and the default must say so"
        );
    }

    #[test]
    fn a_refresh_chain_written_without_rar_reads_with_it() {
        survives_without_the_key(&refresh(), "RefreshTokenRecord");
    }

    #[test]
    fn an_authorization_code_written_without_rar_reads_with_it() {
        survives_without_the_key(&code(), "AuthorizationCodeRecord");
    }
}

/// The wire response has to be readable by the type that writes it.
///
/// `TokenResponse` omits `authorization_details` when empty, which its own doc justifies as
/// emitting "exactly the body it emitted before this existed". `skip_serializing_if` without
/// `default` makes that omission unreadable by the same type, which also falsifies the
/// `#[non_exhaustive]` note promising a host that `Deserialize` "keeps working from outside".
#[test]
fn a_token_response_round_trips_through_its_own_deserialize() {
    let body = r#"{"access_token":"at","token_type":"Bearer","expires_in":3600,"scope":"read"}"#;
    let read: Result<TokenResponse, _> = serde_json::from_str(body);
    assert!(
        read.is_ok(),
        "the ordinary token response body must read back: {:?}",
        read.err()
    );
    let read = read.unwrap();
    assert_eq!(read.access_token, "at");
    #[cfg(feature = "rar")]
    assert!(read.authorization_details.is_empty());
}

/// Everything the `Debug` docs call metadata is actually printed.
///
/// `grant_established_at` is named first in each assertion on purpose: it is the field whose
/// absence costs the most, because it is what a `RevocationBarrier` is compared against and its
/// fail-closed default is the epoch, so a record refused by a barrier looks identical to a record
/// refused for any other reason unless the instant prints.
mod debuggable {
    use super::*;

    fn must_show(printed: &str, fields: &[&str], what: &str) {
        for field in fields {
            assert!(
                printed.contains(field),
                "{what}'s Debug says its metadata stays visible, but `{field}` is missing: \
                 {printed}"
            );
        }
    }

    #[test]
    fn an_access_token_prints_the_instant_a_barrier_is_compared_against() {
        let printed = format!("{:?}", token());
        must_show(&printed, &["grant_established_at"], "IssuedToken");
        assert!(
            !printed.contains("\"at\""),
            "and the credential still must not print: {printed}"
        );
    }

    #[test]
    fn a_refresh_chain_prints_the_instant_a_barrier_is_compared_against() {
        let printed = format!("{:?}", refresh());
        must_show(&printed, &["grant_established_at"], "RefreshTokenRecord");
        assert!(
            !printed.contains("\"rt\""),
            "and the credential still must not print: {printed}"
        );
    }

    #[test]
    fn an_authorization_code_prints_the_instant_it_was_minted() {
        let printed = format!("{:?}", code());
        must_show(&printed, &["issued_at"], "AuthorizationCodeRecord");
        assert!(
            !printed.contains("\"code\": \"code\""),
            "and the credential still must not print: {printed}"
        );
    }

    /// The sender-constraining bindings and the RFC 8693 `act` are metadata too, and each is the
    /// answer to a question an operator asks: "why was this DPoP token refused at the resource
    /// server", "who is this token acting for". None of them is a credential; a `jkt` is a public
    /// key thumbprint and an `x5t#S256` is a certificate thumbprint.
    // Every assertion in this test is feature-gated, so with none of the four on there is nothing
    // to assert and `printed` is an unused binding under `-D warnings`. Gated as a whole, which is
    // the idiom the rest of this file uses.
    #[cfg(any(
        feature = "dpop",
        feature = "mtls",
        feature = "token-exchange",
        feature = "consent"
    ))]
    #[test]
    fn the_bindings_and_the_actor_print_too() {
        let printed = format!("{:?}", token());
        #[cfg(feature = "dpop")]
        must_show(&printed, &["jkt"], "IssuedToken");
        #[cfg(feature = "mtls")]
        must_show(&printed, &["x5t_s256"], "IssuedToken");
        #[cfg(feature = "token-exchange")]
        must_show(&printed, &["act"], "IssuedToken");
        #[cfg(feature = "consent")]
        must_show(&printed, &["authentication"], "IssuedToken");
    }
}

/// `pushed_at` is the field `PushedAuthorizationRequest::new`'s own doc singles out as the one a
/// caller must set, because leaving it at the epoch makes every push fail against any standing
/// client barrier and the endpoint blames a deletion that never happened: "a silent per-client
/// outage if nobody says so". An operator diagnosing that outage reaches for `{:?}` and the one
/// field that would end the investigation was the one field not printed.
#[cfg(feature = "par")]
#[test]
fn a_pushed_request_prints_when_it_was_pushed() {
    use oauth_as::PushedAuthorizationRequest;

    let mut record = PushedAuthorizationRequest::new(
        "urn:ietf:params:oauth:request_uri:handle",
        ClientId::new("app"),
        instant(1_700_000_060),
    );
    record.pushed_at = instant(1_700_000_000);
    let printed = format!("{record:?}");
    assert!(
        printed.contains("pushed_at"),
        "the instant a client barrier is compared against must be visible: {printed}"
    );
    assert!(
        !printed.contains("request_uri:handle"),
        "and the handle is a credential, so it still must not print: {printed}"
    );
}
