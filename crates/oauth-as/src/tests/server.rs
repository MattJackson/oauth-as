// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::server`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn user_codes_use_the_alphabet_and_are_unbiased_in_shape() {
    let code = random_user_code(8).expect("the OS provides randomness in a test process");
    assert_eq!(code.len(), 8);
    assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
}

#[test]
fn display_form_hyphenates_even_lengths() {
    assert_eq!(display_user_code("WDJBMJHT"), "WDJB-MJHT");
    assert_eq!(display_user_code("ABCDEF"), "ABC-DEF");
    assert_eq!(display_user_code("ABCDE"), "ABCDE");
}

/// RFC 8628 section 5.1: the user code is short because a human types it, and its entropy is only
/// sufficient in combination with host rate limiting. That makes every bit of it worth defending,
/// so the byte-to-symbol mapping must be exactly uniform rather than approximately so.
///
/// Checked EXHAUSTIVELY over all 256 byte values, which is why `user_code_symbol` exists as a
/// separate function: uniformity is not observable in any single generated code, and a test that
/// could only look at sampled output would have to be a statistical argument instead of a proof.
/// The three facts below are what "unbiased rejection sampling" actually means:
///
/// 1. exactly 240 of the 256 byte values are accepted (240 is the largest multiple of the 20
///    symbol alphabet that fits in a byte),
/// 2. every accepted value maps into the alphabet, and
/// 3. every symbol has exactly the same number of preimages, so no symbol is more likely.
///
/// Widening the accepted range by even one value (`<` becoming `<=`) breaks fact 3 by giving the
/// first symbol a thirteenth preimage; narrowing or inverting it breaks facts 1 and 3; replacing
/// the modulo with a division breaks fact 3 by making the last eight symbols unreachable.
#[test]
fn the_user_code_symbol_draw_is_exactly_uniform_over_the_alphabet() {
    let mut counts = std::collections::BTreeMap::new();
    let mut accepted = 0usize;
    for byte in 0u8..=255 {
        match user_code_symbol(byte) {
            Some(symbol) => {
                accepted += 1;
                assert!(
                    USER_CODE_ALPHABET.contains(&symbol),
                    "byte {byte} produced {symbol}, which is outside the RFC 8628 s6.1 alphabet"
                );
                *counts.entry(symbol).or_insert(0usize) += 1;
            }
            None => assert!(
                byte >= USER_CODE_REJECT_AT,
                "byte {byte} is below the rejection bound and must have been accepted"
            ),
        }
    }

    assert_eq!(
        accepted, 240,
        "exactly the 240 values below the rejection bound may be folded into the alphabet"
    );
    assert_eq!(
        counts.len(),
        USER_CODE_ALPHABET.len(),
        "every symbol in the alphabet must be reachable"
    );
    for (symbol, count) in &counts {
        assert_eq!(
            *count, 12,
            "symbol {} has {count} preimages, not the uniform 12: the draw is biased",
            *symbol as char
        );
    }
}

/// The generator itself, on top of the mapping above: it must keep drawing until it has exactly
/// `len` symbols (a rejected byte costs a redraw, never a short code), and never emit anything
/// outside the RFC 8628 section 6.1 alphabet.
#[test]
fn random_user_code_redraws_rejections_rather_than_shortening_the_code() {
    for len in [MIN_USER_CODE_LENGTH, 9, 16] {
        let code = random_user_code(len).expect("the OS provides randomness in a test process");
        assert_eq!(code.len(), len, "a rejected byte must cost a redraw");
        assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
    }
}

#[test]
fn random_hex_has_the_stated_entropy_width() {
    let h = try_random_hex(32).expect("the OS provides randomness in a test process");
    assert_eq!(h.len(), 64);
    assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(h, try_random_hex(32).unwrap());
}

/// C13: every credential a token request carries is a credential in the RFC's own terms
/// (`client_secret` is a password per RFC 6749 section 2.3.1; `code`, `refresh_token` and
/// `device_code` are bearer artifacts per sections 4.1.2 and 6 and RFC 8628 section 3.4), so none
/// of them may appear in a debug format. Pins that `{:?}` cannot become a credential leak for a
/// host that debug-prints the request it just parsed.
#[test]
fn c13_token_request_debug_redacts_every_credential() {
    let cases = vec![
        TokenRequest::AuthorizationCode {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            code: "code-value".into(),
            redirect_uri: Some("https://app.example/cb".into()),
            code_verifier: Some("verifier-value".into()),
        },
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            scope: None,
        },
        TokenRequest::DeviceCode {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            device_code: "device-value".into(),
        },
        TokenRequest::RefreshToken {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            refresh_token: "refresh-value".into(),
            scope: None,
        },
    ];
    for request in &cases {
        let printed = format!("{request:?}");
        for leaked in [
            "secret-value",
            "code-value",
            "verifier-value",
            "device-value",
            "refresh-value",
        ] {
            assert!(
                !printed.contains(leaked),
                "debug format leaked {leaked}: {printed}"
            );
        }
        assert!(
            printed.contains("[redacted]"),
            "debug format should say what was redacted: {printed}"
        );
        // client_id is explicitly NOT a secret (RFC 6749 section 2.2), so it must stay visible or
        // the redaction has made the type useless to debug.
        assert!(
            printed.contains("app"),
            "client_id must stay visible: {printed}"
        );
    }
}

/// C13: redaction must not erase the SHAPE of the request. Whether a secret or a PKCE verifier was
/// presented at all is the difference between an `invalid_client` and a missing-credential
/// rejection (RFC 6749 section 5.2), and it is not itself a secret, so `Some` and `None` must stay
/// distinguishable.
#[test]
fn c13_token_request_debug_keeps_the_some_none_distinction() {
    let with_secret = TokenRequest::AuthorizationCode {
        client_id: ClientId::new("app"),
        client_secret: Some("secret-value".into()),
        code: "code-value".into(),
        redirect_uri: None,
        code_verifier: Some("verifier-value".into()),
    };
    let without_secret = TokenRequest::AuthorizationCode {
        client_id: ClientId::new("app"),
        client_secret: None,
        code: "code-value".into(),
        redirect_uri: None,
        code_verifier: None,
    };
    let with = format!("{with_secret:?}");
    let without = format!("{without_secret:?}");
    assert_ne!(
        with, without,
        "a presented secret and an absent one must not debug-print identically"
    );
    assert!(with.contains("Some(\"[redacted]\")"), "{with}");
    assert!(without.contains("client_secret: None"), "{without}");
    assert!(without.contains("code_verifier: None"), "{without}");
}

/// C13: the variant name says which grant is being redeemed and is not a secret, so redaction must
/// leave it readable.
#[test]
fn c13_token_request_debug_still_names_the_grant() {
    let request = TokenRequest::RefreshToken {
        client_id: ClientId::new("app"),
        client_secret: None,
        refresh_token: "refresh-value".into(),
        scope: Some(ScopeSet::parse("read").unwrap()),
    };
    let printed = format!("{request:?}");
    assert!(printed.starts_with("RefreshToken"), "{printed}");
    // The requested scope is a permission boundary the operator must be able to read.
    assert!(printed.contains("read"), "{printed}");
}

/// The replay-set key is what makes RFC 7523 s3 and RFC 9449 s4.3 single use MEAN single use, and
/// its shape is not observable through either endpoint: any injective function of the three parts
/// gives the same accept/refuse answers. So the shape is pinned here, directly.
///
/// INJECTIVITY is the property, and a separator alone did not buy it: `jti` and the client id are
/// both caller-chosen and neither is restricted to a charset that excludes the separator. The
/// length prefix is what makes the split unambiguous whatever they contain. See `replay_key` for
/// the argument, and `tests/replay_key_collision.rs` for the attack the old encoding admitted.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[test]
fn a_replay_key_separates_its_three_parts() {
    assert_eq!(replay_key("ca", "client-1", "jti-1"), "ca:8:client-1jti-1");
    assert_eq!(replay_key("dpop", "thumb", "jti-1"), "dpop:5:thumbjti-1");
    // The two mechanisms never share a key even when the owner and the `jti` are identical: a
    // captured DPoP proof's `jti` must not be spendable as a client assertion's, or the two replay
    // caches would lock each other out.
    assert_ne!(replay_key("ca", "x", "j"), replay_key("dpop", "x", "j"));
    // The prefix collision the old encoding was already asserted against.
    assert_ne!(replay_key("ca", "ab", "c"), replay_key("ca", "a", "bc"));
    // The one it was NOT: a separator inside the caller's own values. Both of these produced
    // `ca:urn:client:foo:42` before the length prefix.
    assert_ne!(
        replay_key("ca", "urn", "client:foo:42"),
        replay_key("ca", "urn:client:foo", "42")
    );
    // The same shape one part along, for a `jti` that ends where the next field begins.
    assert_ne!(
        replay_key("dpop", "thumb", ":x"),
        replay_key("dpop", "thumb:", "x")
    );
}

/// The decimal width the capacity arithmetic depends on. Off by one here is a reallocation on
/// every DPoP-carrying token request, which is exactly what the exactness test below would catch,
/// so this pins the boundaries it would otherwise only catch by accident.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[test]
fn the_decimal_width_is_the_number_of_digits() {
    for (n, width) in [
        (0usize, 1usize),
        (1, 1),
        (9, 1),
        (10, 2),
        (99, 2),
        (100, 3),
        (999, 3),
        (1000, 4),
    ] {
        assert_eq!(decimal_width(n), width, "{n}");
    }
}

/// The capacity hint is EXACT, so building a replay key is one allocation with no slack.
///
/// This is bought on the hottest path a DPoP deployment has: one of these is built for every single
/// token request, and it is thrown away immediately. A hint that is too small makes `push_str`
/// reallocate (two allocations and a copy for a string that was sized in advance); a hint that is
/// too large asks the allocator for bytes that are never written. `String::with_capacity` allocates
/// exactly what it is asked for, so both are visible as the pair of facts below: the capacity is
/// what the arithmetic in `replay_key` computes, and the string ends up exactly full.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[test]
fn a_replay_key_is_built_in_exactly_one_correctly_sized_allocation() {
    for (kind, owner, jti) in [
        ("ca", "client-1", "jti-1"),
        ("dpop", "0OXy9SbXe0Y7YQ8Xw3sYQ2h1lKQ", "01234567-89ab-cdef"),
        ("ca", "", ""),
    ] {
        let key = replay_key(kind, owner, jti);
        let exact = kind.len() + owner.len() + jti.len() + 2 + decimal_width(owner.len());
        assert_eq!(
            key.len(),
            exact,
            "the two separators and the length prefix are the whole of the difference between \
             the parts and the key"
        );
        assert_eq!(
            key.capacity(),
            exact,
            "the hint must be exactly the final length: smaller reallocates, larger over-asks"
        );
    }
}

/// The three request-reachable randomness draws are FALLIBLE, not panicking.
///
/// `getrandom` failing is a real runtime condition — an exhausted descriptor table on the platforms
/// where it opens `/dev/urandom`, a seccomp policy, a container without the syscall — and every
/// other fallible step on these paths becomes `ErrorCode::ServerError` and returns. Panicking makes
/// a library abort its host's request handler, and in a host built with `panic = "abort"` it
/// takes the whole process with it: an authorization server that stops serving the requests it
/// could still serve because one of them could not be given thirty-two bytes.
///
/// This is a TYPE-LEVEL guard rather than a behavioural one, deliberately, and it is the only kind
/// available: a test cannot make the OS refuse randomness, so what can be pinned is that the
/// signature admits the refusal at all. It does not compile against the `expect`-ing forms these
/// replaced, which is exactly the regression worth catching.
#[test]
fn the_request_reachable_randomness_draws_report_failure_rather_than_panicking() {
    let hex: Option<String> = try_random_hex(32);
    assert_eq!(
        hex.expect("the OS provides randomness in a test process")
            .len(),
        64
    );
    let code: Option<String> = random_user_code(MIN_USER_CODE_LENGTH);
    assert_eq!(
        code.expect("the OS provides randomness in a test process")
            .len(),
        MIN_USER_CODE_LENGTH
    );
    // And the refusal they map to is the same opaque `server_error` a storage failure becomes, so
    // a caller cannot tell which internal thing went wrong.
    assert_eq!(randomness_error().error, ErrorCode::ServerError);
    assert!(randomness_error().error_description.is_none());
}

// ------------------------------------------------- what the installed RateLimiter is told, exactly

/// A limiter that ALLOWS the first `allow` checks and denies everything after, keeping every
/// `record` it is handed. The two halves are what the tests below read: which attempt was refused,
/// and what the limiter was subsequently told about it.
#[cfg(test)]
struct CountingLimiter {
    allow: usize,
    checks: std::sync::Mutex<usize>,
    records: std::sync::Mutex<Vec<AttemptOutcome>>,
}

impl RateLimiter for std::sync::Arc<CountingLimiter> {
    fn check(&self, _attempt: Attempt<'_>) -> RateLimitDecision {
        let mut checks = self.checks.lock().expect("no panic while held");
        *checks += 1;
        if *checks <= self.allow {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Deny
        }
    }

    fn record(&self, _attempt: Attempt<'_>, outcome: AttemptOutcome) {
        self.records
            .lock()
            .expect("no panic while held")
            .push(outcome);
    }
}

fn limited_server(
    limiter: std::sync::Arc<CountingLimiter>,
) -> AuthorizationServer<crate::store::MemoryStorage> {
    AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        crate::store::MemoryStorage::new(),
    )
    .with_rate_limiter(Box::new(limiter))
}

fn limited_client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: crate::client::ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// RFC 7636 appendix B's worked example verifier, which is 43 characters: the minimum the RFC
/// permits, and what this crate's integration suite uses.
#[cfg(test)]
const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn limited_request(challenge: &str) -> AuthorizationRequest<'static> {
    AuthorizationRequest::from_pairs([
        ("response_type", "code".to_string()),
        ("client_id", "app".to_string()),
        ("redirect_uri", "https://app.example/cb".to_string()),
        ("scope", "read".to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ])
}

/// [`RateLimiter::record`] is documented as reporting "how an ALLOWED attempt turned out", and a
/// denied one never became an attempt at all. Reporting the deny back as
/// [`AttemptOutcome::Failed`] drives the failure count with traffic the limiter itself refused,
/// which is a feedback loop: a client that merely exceeded its ceiling then reads, to a host
/// alerting on failure rate (which this crate tells hosts to do), exactly like a caller walking
/// the redirect-URI space.
///
/// Every other classification site in this crate returns after a `Deny` WITHOUT recording —
/// `authenticate_client`, `validate_direct_authorization_request`, `pending_grant_by_user_code`,
/// `register_dynamic_client` — and says so in a comment. The second charge on the issuance path
/// was the one that did not.
#[tokio::test]
async fn a_denied_authorization_request_is_never_reported_back_as_a_failure() {
    // One allowance: the validation's charge. The issuance's second charge is the one denied.
    let limiter = std::sync::Arc::new(CountingLimiter {
        allow: 1,
        checks: std::sync::Mutex::new(0),
        records: std::sync::Mutex::new(Vec::new()),
    });
    let srv = limited_server(limiter.clone());
    srv.register_client(limited_client()).await.unwrap();

    let challenge = crate::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&limited_request(&challenge))
        .await
        .expect("the first charge is allowed");
    let refused = srv
        .issue_authorization_code(crate::server::UserApproval::granted(&validated, "user-1"))
        .await
        .expect_err("the second charge is denied");
    assert!(
        matches!(refused, AuthorizationError::Redirect(_)),
        "the refusal shape is unchanged: RFC 6749 s4.1.2.1 sends it to the validated redirect URI"
    );

    let records = limiter.records.lock().expect("no panic while held").clone();
    assert_eq!(
        records,
        vec![AttemptOutcome::Succeeded],
        "the only outcome is the ALLOWED validation's; a deny must be reported to nobody"
    );
}

/// `SystemTime + Duration` PANICS on overflow, and [`ServerConfig::refresh_reuse_window`] is a
/// plain public field with no validating constructor, so an absurd value from a host's config file
/// is a panic inside the host's request handler rather than a startup failure. Every other TTL
/// addition on a request path goes through [`saturating_deadline`]; the spent marker written by a
/// refresh rotation was the one that did not.
///
/// The branch is the DEFAULT configuration's: `refresh_token_ttl` is `None`, so the chain has no
/// absolute expiry and every rotation takes the `or_else`.
#[tokio::test]
async fn a_rotation_survives_an_absurd_reuse_window_rather_than_panicking() {
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    // The shape a config file holding a nonsense number produces. `refresh_token_ttl` stays at its
    // default `None`, which is what makes the rotation read this field at all.
    config.refresh_reuse_window = Duration::MAX;
    assert!(config.refresh_token_ttl.is_none());
    let srv = AuthorizationServer::new(config, crate::store::MemoryStorage::new());
    srv.register_client(limited_client()).await.unwrap();

    let verifier = RFC7636_VERIFIER;
    let challenge = crate::pkce::code_challenge_s256(verifier);
    let validated = srv
        .validate_authorization_request(&limited_request(&challenge))
        .await
        .unwrap();
    let code = srv
        .issue_authorization_code(crate::server::UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("app"),
            client_secret: None,
            code: code.code,
            redirect_uri: Some("https://app.example/cb".to_string()),
            code_verifier: Some(verifier.to_string()),
        })
        .await
        .unwrap();

    let rotated = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("app"),
            client_secret: None,
            refresh_token: issued.refresh_token.expect("the grant mints one"),
            scope: None,
        })
        .await
        .expect("a rotation must not panic on a host-configured duration");
    assert!(rotated.refresh_token.is_some(), "the chain continues");
}

/// The dummy assertion verification must be a COMPLETE one, or it does not cost what it is there
/// to cost. A signature that is malformed, or a public key whose coordinates are not a point on
/// P-256, is refused in the parse for a fraction of the work of a real verification, which is the
/// timing leak `dummy_assertion_verify` exists to close, reintroduced at half the size and much
/// harder to see. Checked against the crate's own backend: the constants verify, so the operation
/// runs to the end.
#[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
#[test]
fn the_dummy_assertion_material_costs_a_complete_es256_verification() {
    use crate::jwt::Es256Verifier as _;
    assert!(
        crate::jwt::P256Verifier.verify(
            &dummy_assertion_key(),
            DUMMY_ASSERTION_SIGNING_INPUT.as_bytes(),
            &DUMMY_ASSERTION_SIGNATURE,
        ),
        "the dummy signature must verify under the dummy key, or the verification short-circuits"
    );
}

/// The largest `SystemTime` this platform can represent: the point beyond which `checked_add`
/// returns `None`. Found rather than hardcoded, because the ceiling differs by platform (a 64-bit
/// `timespec` on one host, a 128-bit intermediate on another), and the whole subject of the test
/// below is what [`saturating_deadline`] does when it reaches that ceiling.
#[cfg(test)]
fn system_time_ceiling() -> SystemTime {
    use std::time::{Duration, UNIX_EPOCH};

    // Largest whole second still representable as an offset from the epoch.
    let mut lo: u64 = 0;
    let mut hi: u64 = u64::MAX;
    while lo < hi {
        let mid = lo + (hi - lo) / 2 + 1;
        if UNIX_EPOCH.checked_add(Duration::from_secs(mid)).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let secs = lo;
    // Then the largest sub-second remainder that still fits on top of it.
    let mut nlo: u32 = 0;
    let mut nhi: u32 = 999_999_999;
    while nlo < nhi {
        let mid = nlo + (nhi - nlo) / 2 + 1;
        if UNIX_EPOCH.checked_add(Duration::new(secs, mid)).is_some() {
            nlo = mid;
        } else {
            nhi = mid - 1;
        }
    }
    UNIX_EPOCH
        .checked_add(Duration::new(secs, nlo))
        .expect("the searched value is representable by construction")
}

/// KILLS the three `saturating_deadline` mutants on the halving loop's guard (`server.rs`
/// `while span > Duration::from_secs(1)`): `>` replaced by `==`, by `<`, and by `>=`.
///
/// The loop only runs when `base.checked_add(span)` has ALREADY overflowed the platform ceiling,
/// so nothing on any ordinary request path exercises it — every caller adds a sane TTL to `now`,
/// which fits, and the function returns on its first line. The existing coverage
/// (`tests/mutation_gaps_091.rs`) drives the fits-exactly path and so never enters the loop at all.
///
/// To reach it we place `base` a hair below the ceiling and add a span that cannot fit, so the
/// function must fall back to halving. With `base = ceiling - 7.75s` and `span = 8s`:
///
/// - `ceiling` is unreachable, so `checked_add(8s)` overflows and the loop is entered.
/// - The real guard `span > 1s` halves `8s -> 4s -> 2s -> 1s`, accumulating `+4s +2s +1s` onto
///   `base` and stopping the instant `span` reaches `1s`. The result is `base + 7s`.
/// - `==` and `<` are both false for the initial `8s`, so the loop body never runs and the result
///   is `base` unchanged — a deadline in the PAST relative to the real one, which for an expiry
///   means a token that is born already expired.
/// - `>=` runs one extra iteration at `span == 1s`, adding another `+0.5s`, giving `base + 7.5s`:
///   a deadline half a second later than the real one, observable through `unix_seconds` whenever
///   it crosses a second boundary.
///
/// The exact `base + 7s` is asserted, which distinguishes the real result from all three mutants at
/// once.
#[test]
fn saturating_deadline_halves_toward_the_ceiling_when_the_sum_overflows() {
    use std::time::Duration;

    let ceiling = system_time_ceiling();
    // A hair below the ceiling: close enough that `+ 8s` cannot fit (forcing the halving fallback),
    // but with enough headroom that every partial add the real loop makes DOES fit, and so does the
    // extra half-second the `>=` mutant would add — otherwise that add would overflow and be
    // silently skipped, hiding the mutant.
    let base = ceiling
        .checked_sub(Duration::from_millis(7_750))
        .expect("7.75s below the ceiling is representable");

    assert!(
        base.checked_add(Duration::from_secs(8)).is_none(),
        "the fixture is only meaningful if the 8s span genuinely overflows and forces the halving \
         path"
    );

    let deadline = saturating_deadline(base, Duration::from_secs(8));
    assert_eq!(
        deadline,
        base + Duration::from_secs(7),
        "the halving loop must accumulate 4s + 2s + 1s and stop the instant the remaining span \
         reaches one second: a loop that never runs leaves the deadline in the past, and one that \
         runs a step too far pushes it half a second beyond where the real code lands"
    );
}
