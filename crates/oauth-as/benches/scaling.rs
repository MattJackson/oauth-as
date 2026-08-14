// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Scaling sweeps: the hunt for accidental quadratic behaviour.
//!
//! This target is not looking for a performance nit. It is looking for a DENIAL OF SERVICE. Every
//! input swept here is one a CALLER controls: how many scopes it asks for, how many resource
//! indicators it names, how many `authorization_details` elements it sends, how long a token
//! string it presents, and, over time, how many records it has caused this server to store. If any
//! of those is superlinear, the cheapest request an attacker can send is the most expensive one
//! this server can serve, and the ratio grows with the attack.
//!
//! Read the `ns/element` column, not the medians. Flat means linear. Rising means worse.
//!
//! # The store-size sweeps are the ones that matter most
//!
//! `MemoryStorage` is documented as a single-process store for tests and small embeddings, so a
//! linear scan inside it is not automatically a defect. It IS a defect if the scan sits on a
//! per-request path, because then the cost of one request grows with how much state the deployment
//! has accumulated, and a host that read "MemoryStorage" and shipped it has no way to know. Each
//! store-size row below says which of the two it is.
//!
//! All of this is against [`oauth_as::MemoryStorage`]. A host with a real database has different
//! constants and, for the scans, a different shape entirely (an index makes them logarithmic). What
//! carries over is the SHAPE OF THE CRATE'S OWN CODE around the store: how many store calls a
//! request makes, and whether that number is constant.

#[path = "harness/mod.rs"]
mod harness;

use std::time::SystemTime;

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, Storage, TokenRequest, TokenTypeHint, UserApproval,
};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const SECRET: &str = "a-high-entropy-registered-client-secret";

fn config() -> ServerConfig {
    ServerConfig::new("https://as.example", "https://as.example/device")
}

/// `n` distinct RFC 6749 section 3.3 scope tokens, space separated.
fn scope_string(n: usize) -> String {
    (0..n)
        .map(|i| format!("scope{i}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn confidential_client(id: &str, scopes: &ScopeSet) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![
            GrantType::ClientCredentials,
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
        ],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: scopes.clone(),
        default_scopes: ScopeSet::parse("scope0").unwrap(),
        name: None,
        registration: None,
    }
}

fn main() {
    harness::print_environment();
    let mut b = harness::Bench::from_args("scaling sweeps (MemoryStorage, in process)");
    let rt = harness::runtime();

    // ============================================================== caller-controlled input sizes

    // --- ScopeSet::parse. RFC 6749 s3.3 puts no bound on how many scope tokens a request may
    // name, so this is unauthenticated attacker-controlled length on the authorization and token
    // endpoints both. `ScopeSet` is a SORTED `Vec` (it was a `BTreeSet` through 0.9.1), so parsing
    // one still sorts and the expectation is n log n either way, which shows up
    // here as a slowly rising ns/element rather than a flat one; anything steeper is a finding.
    const SCOPE_SIZES: &[usize] = &[1, 10, 100, 1000];
    for &n in SCOPE_SIZES {
        let raw = scope_string(n);
        b.bench_fast(&format!("scope_parse[n={n}]"), || ScopeSet::parse(&raw));
    }

    // --- Registered redirect URIs. RFC 6749 s3.1.2.3 and OAuth 2.1 s4.1.3 require EXACT string
    // matching of the presented redirect_uri against the registered set, and this crate holds that
    // set as a `Vec<String>`, so the match is a linear scan. That is correct and cheap for the
    // handful of URIs a real client registers; what this sweep checks is that it stays linear and
    // that nothing quadratic hides behind it. The presented URI is the LAST registered one, which
    // is the worst case for a scan.
    const URI_SIZES: &[usize] = &[1, 10, 100, 1000];
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            let scopes = ScopeSet::parse("read write").unwrap();
            for &n in URI_SIZES {
                let mut client = Client {
                    client_id: ClientId::new(format!("uris-{n}")),
                    auth: ClientAuth::Public,
                    grant_types: vec![GrantType::AuthorizationCode],
                    redirect_uris: (0..n)
                        .map(|i| format!("https://app{i}.example/cb"))
                        .collect(),
                    allowed_scopes: scopes.clone(),
                    default_scopes: ScopeSet::parse("read").unwrap(),
                    name: None,
                    registration: None,
                };
                // The matching URI last, so every row measures the full scan rather than an early
                // hit that would flatter the large-n rows.
                client
                    .redirect_uris
                    .push("https://app.example/cb".to_string());
                srv.register_client(client).await.unwrap();
            }
            srv
        });
        let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
        for &n in URI_SIZES {
            let client_id = format!("uris-{n}");
            let pairs = [
                ("response_type", "code".to_string()),
                ("client_id", client_id.clone()),
                ("redirect_uri", "https://app.example/cb".to_string()),
                ("scope", "read".to_string()),
                ("code_challenge", challenge.clone()),
                ("code_challenge_method", "S256".to_string()),
            ];
            // `.is_ok()`: `AuthorizationError` is a large enum and clippy's `result_large_err`
            // fires on a closure that returns one. The call and the drop both stay inside the
            // clock; only the discriminant leaves the closure.
            b.bench_fast(&format!("redirect_uri_match[n={n}]"), || {
                let req = AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (*k, &**v)));
                rt.block_on(srv.validate_authorization_request(&req))
                    .is_ok()
            });
        }
    }

    // --- RFC 8707 resource indicators on the token request. Another unbounded caller-controlled
    // list, checked against the server's `allowed_resources`, which is itself a list: the naive
    // shape of that check is a nested loop, so this is the sweep that would expose it.
    const RESOURCE_SIZES: &[usize] = &[1, 10, 100, 1000];
    {
        let srv = rt.block_on(async {
            let mut cfg = config();
            cfg.allowed_resources = Some(
                (0..1000)
                    .map(|i| format!("https://rs{i}.example").into_boxed_str())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            );
            let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
            srv.register_client(confidential_client(
                "resource-app",
                &ScopeSet::parse("scope0 scope1").unwrap(),
            ))
            .await
            .unwrap();
            srv
        });
        for &n in RESOURCE_SIZES {
            let resources: Vec<String> = (0..n).map(|i| format!("https://rs{i}.example")).collect();
            b.bench_fast(&format!("token_with_resources[n={n}]"), || {
                rt.block_on(srv.token_with_resources(
                    TokenRequest::ClientCredentials {
                        client_id: ClientId::new("resource-app"),
                        client_secret: Some(SECRET.to_string()),
                        scope: None,
                    },
                    &resources,
                ))
            });
        }
    }

    // --- Token STRING length. An attacker introspecting a 64 KiB "token" is asking this server to
    // hash and look up 64 KiB. Constant-time client secret comparison in this crate is SHA-256 of
    // both sides (src/client.rs), which is linear in the presented length by construction, so the
    // question is only whether anything AMPLIFIES that.
    const TOKEN_LEN: &[usize] = &[32, 1024, 65536];
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(confidential_client(
                "long-token-app",
                &ScopeSet::parse("scope0").unwrap(),
            ))
            .await
            .unwrap();
            srv
        });
        let cid = ClientId::new("long-token-app");
        for &n in TOKEN_LEN {
            let token = "a".repeat(n);
            b.bench_fast(&format!("introspection_unknown_token[len={n}]"), || {
                rt.block_on(srv.introspection_response(&cid, Some(SECRET), &token))
            });
        }
    }

    // --- RFC 9396 authorization details. Attacker-supplied JSON at the authorization endpoint,
    // which is why the crate caps it (`MAX_AUTHORIZATION_DETAILS_ELEMENTS`). `narrow` is
    // O(requested * granted) by construction and says so in its source; the cap is what keeps that
    // bounded, so this sweep exists to confirm the cap is what is actually load bearing.
    #[cfg(feature = "rar")]
    // 16 is `MAX_AUTHORIZATION_DETAILS_ELEMENTS`, the crate's own cap, so it is the largest input an
    // attacker can actually get parsed and narrowed. The sweep stops there deliberately: the point
    // is to show that the cap, not the algorithm, is what bounds `narrow`'s O(requested * granted).
    const RAR_SIZES: &[usize] = &[1, 4, 8, 16];
    #[cfg(feature = "rar")]
    {
        use oauth_as::AuthorizationDetails;
        for &n in RAR_SIZES {
            let raw = format!(
                "[{}]",
                (0..n)
                    .map(|i| format!(
                        r#"{{"type":"payment_initiation{i}","actions":["read","write"],"locations":["https://rs.example"]}}"#
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            b.bench_fast(&format!("rar_parse[n={n}]"), || {
                AuthorizationDetails::parse(&raw)
            });
            let granted = AuthorizationDetails::parse(&raw).expect("fixture parses");
            b.bench_fast(&format!("rar_narrow[n={n}]"), || granted.narrow(&granted));
        }
    }

    // --- RFC 8628 user code length. This one is NOT about a caller-controlled input: it is a
    // CONFIG knob, and it is swept because `random_user_code` draws its entropy one byte at a time
    // with a fresh `getrandom` call per byte and rejection sampling on top. If that is what it
    // costs, the slope here is a per-symbol syscall and the intercept is everything else the
    // endpoint does. See the report; this is the row that settles it.
    const USER_CODE_LENS: &[usize] = &[8, 16, 32, 64];
    {
        for &len in USER_CODE_LENS {
            let srv = rt.block_on(async {
                let mut cfg = config();
                cfg.user_code_length = len;
                let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
                srv.register_client(Client {
                    client_id: ClientId::new("device-client"),
                    auth: ClientAuth::Public,
                    grant_types: vec![GrantType::DeviceCode],
                    redirect_uris: vec![],
                    allowed_scopes: ScopeSet::parse("read").unwrap(),
                    default_scopes: ScopeSet::parse("read").unwrap(),
                    name: None,
                    registration: None,
                })
                .await
                .unwrap();
                srv
            });
            let cid = ClientId::new("device-client");
            b.bench_fast(
                &format!("device_authorization[user_code_len={len}]"),
                || rt.block_on(srv.device_authorization(&cid, None, None)),
            );
        }
    }

    // ============================================================ accumulated store size sweeps

    // --- Introspection against a store holding n live tokens. This is the highest-QPS endpoint in
    // an opaque-token deployment (see benches/token.rs), so if it were anything but flat, every
    // deployment would get slower simply by staying up. `MemoryStorage::tokens` is a `HashMap`, so
    // flat is the expectation; the row exists to PROVE it rather than to assume the map.
    const STORE_SIZES: &[usize] = &[1, 1_000, 10_000, 100_000];
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(confidential_client(
                "bulk-app",
                &ScopeSet::parse("scope0").unwrap(),
            ))
            .await
            .unwrap();
            srv
        });
        let cid = ClientId::new("bulk-app");
        let mut issued = 0usize;
        let mut probe = String::new();
        for &n in STORE_SIZES {
            while issued < n {
                let t = rt
                    .block_on(srv.token(TokenRequest::ClientCredentials {
                        client_id: cid.clone(),
                        client_secret: Some(SECRET.to_string()),
                        scope: None,
                    }))
                    .expect("seed issuance");
                if issued == 0 {
                    probe = t.access_token;
                }
                issued += 1;
            }
            // ALL THREE of these rows are measured INSIDE the seeding loop, at the store size the
            // row is named for. Measuring them in three separate loops after the seeding finished
            // (as the first draft of this file did) silently measures all four sizes against the
            // fully seeded 100,000-record store, which reports a perfectly flat scan and hides
            // exactly the growth this file exists to find.
            b.bench_fast(&format!("introspection_active[store={n}]"), || {
                rt.block_on(srv.introspection_response(&cid, Some(SECRET), &probe))
            });

            // --- Revocation of a token that is NOT in the store. `MemoryStorage`'s
            // `revoke_token_family` is an explicit full scan of both the token and refresh maps
            // ("A scan is honest for a map with no secondary index", per its own comment), but a
            // token that is not found never reaches it. This row is the CONTROL for
            // `refresh_reuse_detection` below: same endpoint, same store, no scan.
            b.bench_fast(&format!("revoke_unknown[store={n}]"), || {
                rt.block_on(srv.revoke(
                    &cid,
                    Some(SECRET),
                    "not-a-token-we-ever-issued",
                    Some(TokenTypeHint::AccessToken),
                ))
            });

            // --- The sweep. This one IS a full scan by definition (it is the thing that reclaims
            // expired records) and the host is told to run it on a timer, so linear is correct
            // here. What matters is the CONSTANT, because the whole scan happens under one mutex
            // and every request on every other task is blocked behind it for the duration.
            // `UNIX_EPOCH` as `now` means nothing is expired, so this measures the scan itself
            // without also measuring the removal.
            b.bench_fast(&format!("sweep_expired[store={n}]"), || {
                rt.block_on(srv.store().sweep_expired(SystemTime::UNIX_EPOCH))
            });
        }
    }

    // --- The refresh-token-reuse compromise path at store scale. RFC 9700 s4.14.2 makes a reused
    // refresh token revoke the whole family, which is the scan above, and this is the path an
    // ATTACKER triggers (that is what reuse detection is for). Measured separately from
    // `revoke_unknown` because it does the scan for real rather than finding nothing.
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(confidential_client(
                "reuse-app",
                &ScopeSet::parse("scope0").unwrap(),
            ))
            .await
            .unwrap();
            srv
        });
        let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
        let pairs = [
            ("response_type", "code".to_string()),
            ("client_id", "reuse-app".to_string()),
            ("redirect_uri", "https://app.example/cb".to_string()),
            ("scope", "scope0".to_string()),
            ("code_challenge", challenge.clone()),
            ("code_challenge_method", "S256".to_string()),
        ];
        let mut grants = 0usize;
        for &n in &[1usize, 1_000, 10_000] {
            while grants < n {
                rt.block_on(async {
                    let req =
                        AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (*k, &**v)));
                    let validated = srv.validate_authorization_request(&req).await.unwrap();
                    let code = srv
                        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
                        .await
                        .unwrap()
                        .code;
                    srv.token(TokenRequest::AuthorizationCode {
                        client_id: ClientId::new("reuse-app"),
                        client_secret: Some(SECRET.to_string()),
                        code,
                        redirect_uri: Some("https://app.example/cb".to_string()),
                        code_verifier: Some(VERIFIER.to_string()),
                    })
                    .await
                    .unwrap();
                });
                grants += 1;
            }
            // A fresh family per iteration: rotate once so the ORIGINAL refresh token is spent,
            // then present the spent one, which is what triggers the family revocation scan.
            b.bench_with(
                &format!("refresh_reuse_detection[store={n}]"),
                || {
                    rt.block_on(async {
                        let req =
                            AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (*k, &**v)));
                        let validated = srv.validate_authorization_request(&req).await.unwrap();
                        let code = srv
                            .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
                            .await
                            .unwrap()
                            .code;
                        let first = srv
                            .token(TokenRequest::AuthorizationCode {
                                client_id: ClientId::new("reuse-app"),
                                client_secret: Some(SECRET.to_string()),
                                code,
                                redirect_uri: Some("https://app.example/cb".to_string()),
                                code_verifier: Some(VERIFIER.to_string()),
                            })
                            .await
                            .unwrap()
                            .refresh_token
                            .unwrap();
                        srv.token(TokenRequest::RefreshToken {
                            client_id: ClientId::new("reuse-app"),
                            client_secret: Some(SECRET.to_string()),
                            refresh_token: first.clone(),
                            scope: None,
                        })
                        .await
                        .unwrap();
                        first
                    })
                },
                |spent| {
                    rt.block_on(srv.token(TokenRequest::RefreshToken {
                        client_id: ClientId::new("reuse-app"),
                        client_secret: Some(SECRET.to_string()),
                        refresh_token: spent,
                        scope: None,
                    }))
                },
            );
        }
        harness::print_growth(
            &b,
            "refresh reuse detection vs store size",
            &[1, 1_000, 10_000],
            |n| format!("refresh_reuse_detection[store={n}]"),
        );
    }

    // --- Consent lookup. `MemoryStorage::find_consent` is a linear scan over the consent map by
    // (client_id, subject), and the crate's own source says it is on the authorization path. That
    // makes it the one scan in this file that is NOT amortized over a timer: it runs on a request,
    // and the store it scans grows with one record per (user, client) pair the deployment has ever
    // approved. Swept last because it is the sweep most likely to be a finding.
    #[cfg(feature = "consent")]
    const CONSENT_SIZES: &[usize] = &[1, 1_000, 10_000, 100_000];
    #[cfg(feature = "consent")]
    {
        let srv = rt.block_on(async {
            let srv = AuthorizationServer::new(config(), MemoryStorage::new());
            srv.register_client(confidential_client(
                "consent-app",
                &ScopeSet::parse("scope0").unwrap(),
            ))
            .await
            .unwrap();
            srv
        });
        let mut seeded = 0usize;
        for &n in CONSENT_SIZES {
            while seeded < n {
                rt.block_on(srv.store().put_consent(oauth_as::ConsentRecord {
                    consent_id: format!("consent-{seeded}").into_boxed_str(),
                    client_id: ClientId::new(format!("other-client-{seeded}")),
                    subject: format!("user-{seeded}").into_boxed_str(),
                    scope: ScopeSet::parse("scope0").unwrap(),
                    resource: Vec::new(),
                    granted_at: SystemTime::UNIX_EPOCH,
                    authentication: None,
                }))
                .expect("seed consent");
                seeded += 1;
            }
            // The subject that is NOT in the store: the worst case, and the case an attacker
            // driving the authorization endpoint with fresh subjects produces every time.
            b.bench_fast(&format!("find_consent_miss[store={n}]"), || {
                rt.block_on(
                    srv.store()
                        .find_consent(&ClientId::new("consent-app"), "nobody"),
                )
            });
        }
    }

    b.finish();
    harness::print_growth(&b, "ScopeSet::parse", SCOPE_SIZES, |n| {
        format!("scope_parse[n={n}]")
    });
    harness::print_growth(&b, "redirect URI exact match", URI_SIZES, |n| {
        format!("redirect_uri_match[n={n}]")
    });
    harness::print_growth(&b, "RFC 8707 resource indicators", RESOURCE_SIZES, |n| {
        format!("token_with_resources[n={n}]")
    });
    harness::print_growth(&b, "presented token length", TOKEN_LEN, |n| {
        format!("introspection_unknown_token[len={n}]")
    });
    harness::print_growth(&b, "RFC 8628 user code length", USER_CODE_LENS, |n| {
        format!("device_authorization[user_code_len={n}]")
    });
    harness::print_growth(&b, "introspection vs store size", STORE_SIZES, |n| {
        format!("introspection_active[store={n}]")
    });
    harness::print_growth(
        &b,
        "revocation of an unknown token vs store size",
        STORE_SIZES,
        |n| format!("revoke_unknown[store={n}]"),
    );
    harness::print_growth(&b, "sweep_expired vs store size", STORE_SIZES, |n| {
        format!("sweep_expired[store={n}]")
    });
    #[cfg(feature = "rar")]
    {
        harness::print_growth(&b, "RFC 9396 parse", RAR_SIZES, |n| {
            format!("rar_parse[n={n}]")
        });
        harness::print_growth(&b, "RFC 9396 narrow", RAR_SIZES, |n| {
            format!("rar_narrow[n={n}]")
        });
    }
    #[cfg(feature = "consent")]
    harness::print_growth(&b, "find_consent vs store size", CONSENT_SIZES, |n| {
        format!("find_consent_miss[store={n}]")
    });
}
