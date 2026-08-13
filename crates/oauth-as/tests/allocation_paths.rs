// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Allocation gates for the request paths `tests/allocation.rs` does not cover.
//!
//! That file pins the token plane: device authorization, the device poll, code redemption, refresh
//! rotation, introspection and a refusal. Everything else this crate serves was ungated, which
//! means most of the surface a deployment actually exercises had no number attached to it at all:
//! the authorization endpoint, code issuance, revocation, device approval, dynamic registration,
//! and every optional feature's own endpoint.
//!
//! # What a gate here is worth, and what it is not
//!
//! A bound whose number nobody can justify is worse than none, because it launders a guess into a
//! check. Every bound below therefore records the OBSERVED figure it was set from and the margin it
//! carries, and the doc comment says what the path is dominated by, so a failing run can be read as
//! "this changed and here is what it used to be" rather than "some number moved".
//!
//! The margins are wider than `tests/allocation_footprint.rs`'s because these paths run against
//! `HashMap`s whose growth points are not this crate's contract (the reasoning is
//! `tests/allocation.rs`'s and is not repeated here): roughly 30 percent, which still fails the
//! moment somebody adds a clone or an intermediate `String` to a path.
//!
//! # Why a separate binary, and one `#[test]`
//!
//! Same two reasons as the other two allocation files. A `#[global_allocator]` is process-wide and
//! each integration test file is its own binary; `std`'s harness starts one OS thread per `#[test]`
//! and thread creation touches the allocator outside any lock this crate can take, so the whole
//! file is one `#[test]` running its gates in sequence and collecting failures.

// `measure(|| ...)` closures return the endpoint's own `Result`, so clippy sees a large `Err` here
// that it does not see at the endpoints themselves. The finding was MEASURED and REJECTED rather
// than silenced blind: `AuthorizationError` is 128 bytes (`Direct(ErrorResponse)` 56,
// `Redirect(AuthorizationErrorRedirect)` 128), and boxing the redirect variant would take it to 64.
// But the `Result` these functions return is 232 bytes either way, because
// `ValidatedAuthorizationRequest` is 232 and an enum is as wide as its widest arm. So the box would
// buy nothing at the call sites that exist, and would ADD one heap allocation to every
// redirect-form refusal, which is a path an attacker sets the rate of. Strictly worse, measured.
#![allow(clippy::result_large_err)]

mod support;

use std::panic::{catch_unwind, AssertUnwindSafe};

use oauth_as::server::UserApproval;
use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};
use support::alloc::{measure, CountingAllocator, Delta, TEST_LOCK};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

#[test]
fn ungated_path_allocation_gates() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let gates: &[(&str, fn())] = &[
        (
            "authorization_request_validation_bound",
            authorization_request_validation_bound,
        ),
        (
            "authorization_code_issuance_bound",
            authorization_code_issuance_bound,
        ),
        ("device_approval_bound", device_approval_bound),
        ("revocation_bound", revocation_bound),
        (
            "revocation_of_an_unknown_token_bound",
            revocation_of_an_unknown_token_bound,
        ),
        ("dynamic_registration_bound", dynamic_registration_bound),
        ("par_push_bound", par_push_bound),
        ("par_redemption_bound", par_redemption_bound),
        #[cfg(all(feature = "dpop", feature = "jwt-p256"))]
        (
            "dpop_proof_verification_bound",
            dpop_proof_verification_bound,
        ),
        (
            "token_request_with_no_dpop_proof_bound",
            token_request_with_no_dpop_proof_bound,
        ),
        (
            "client_assertion_verification_bound",
            client_assertion_verification_bound,
        ),
        ("token_exchange_bound", token_exchange_bound),
        ("rar_parse_bound", rar_parse_bound),
        ("rar_narrowing_bound", rar_narrowing_bound),
        ("consent_lookup_bound", consent_lookup_bound),
        ("acr_values_refusal_bound", acr_values_refusal_bound),
        // `jwt-p256`, not `jwt`: both fixtures need a key that can actually sign, and after the
        // `Es256Signer` seam landed `jwt` carries the trait and no curve.
        #[cfg(feature = "jwt-p256")]
        ("jwks_serving_bound", jwks_serving_bound),
        #[cfg(feature = "jwt-p256")]
        ("jwt_signing_bound", jwt_signing_bound),
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
        "{} of {} path gate(s) failed:\n{}",
        failures.len(),
        gates.len(),
        failures.join("\n")
    );
}

// ------------------------------------------------------------------------------------ fixtures

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}

const REDIRECT: &str = "https://app.example/cb";
const SECRET: &str = "a-high-entropy-registered-client-secret";

fn config() -> ServerConfig {
    ServerConfig::new("https://as.example", "https://as.example/device")
}

/// The confidential client every gate here authenticates as, registered for every grant so one
/// fixture serves the whole file.
fn app_client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
            #[cfg(feature = "token-exchange")]
            GrantType::TokenExchange,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn server(rt: &tokio::runtime::Runtime, cfg: ServerConfig) -> AuthorizationServer<MemoryStorage> {
    rt.block_on(async {
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        srv.register_client(app_client()).await.unwrap();
        srv
    })
}

/// The query pairs of a well-formed RFC 6749 s4.1.1 authorization request, as they arrive: BORROWED
/// `&str`, which is the shape `AuthorizationRequest::from_pairs` is built to consume without
/// copying (`tests/allocation.rs` pins that at zero).
fn authorization_pairs(challenge: &str) -> [(&str, &str); 7] {
    [
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", REDIRECT),
        ("scope", "read write"),
        ("state", "opaque-state"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

// -------------------------------------------------------------- the authorization endpoint

/// RFC 6749 s4.1.1 plus RFC 7636 s4.3: validating one authorization request against a warm store.
///
/// This is the endpoint a BROWSER hits, so it runs at least once per user login, and until now it
/// had no gate at all. What it is dominated by is the `ValidatedAuthorizationRequest` it returns:
/// the request arrives borrowed and every field the server has to keep past the borrow has to be
/// owned. `get_client` is a pointer clone and contributes nothing.
fn authorization_request_validation_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let pairs = authorization_pairs(&challenge);
    // Built outside the window: parsing borrowed pairs is already gated at zero elsewhere, and
    // including it here would only re-measure that.
    let request = AuthorizationRequest::from_pairs(pairs);

    let (validated, d) = measure(|| rt.block_on(srv.validate_authorization_request(&request)));
    assert_eq!(validated.unwrap().client_id, ClientId::new("app"));
    check("authorization request validation", d, AUTHZ_VALIDATE);
}

/// RFC 6749 s4.1.2: minting the code once the host says the user approved.
///
/// Dominated by the fresh 32 bytes of OS randomness that becomes the code, then owned once more
/// into the persisted `AuthorizationCodeRecord` and once more as that record's map key.
fn authorization_code_issuance_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let pairs = authorization_pairs(&challenge);
    let request = AuthorizationRequest::from_pairs(pairs);
    let validated = rt
        .block_on(srv.validate_authorization_request(&request))
        .unwrap();
    // Warm: the FIRST insert into the code map allocates its bucket table, which is a one-time
    // store cost and not a per-issuance one. Measuring it would charge every future reader of this
    // gate for a 1.6 KB allocation that happens once in a process's life.
    rt.block_on(srv.issue_authorization_code(UserApproval::granted(&validated, "user-1")))
        .unwrap();

    let (response, d) = measure(|| {
        rt.block_on(srv.issue_authorization_code(UserApproval::granted(&validated, "user-1")))
    });
    assert!(!response.unwrap().code.is_empty());
    check("authorization code issuance", d, AUTHZ_ISSUE);
}

// -------------------------------------------------------------------- the device user plane

/// RFC 8628 s3.3: the user enters the code and the host reports approval.
///
/// This runs once per device login and it is a READ-MODIFY-WRITE of the grant, through the
/// user-code index: `find_device_grant_by_user_code` hands back an owned `DeviceGrant` (see
/// `tests/allocation.rs` on why that one is deliberately not an `Arc`), the state is replaced, and
/// the whole record is written back.
fn device_approval_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let user_code = rt
        .block_on(srv.device_authorization(&ClientId::new("app"), Some(SECRET), None))
        .unwrap()
        .user_code;

    let (approved, d) = measure(|| rt.block_on(srv.approve_device(&user_code, "user-1")));
    approved.expect("the grant is approved");
    check("device approval", d, DEVICE_APPROVE);
}

// ------------------------------------------------------------------------------- revocation

/// RFC 7009 s2.1: a confidential client revoking its own refresh token, which cascades to every
/// token in the family (s2.1's SHOULD).
fn revocation_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let refresh = rt
        .block_on(async {
            let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
            let pairs = authorization_pairs(&challenge);
            let request = AuthorizationRequest::from_pairs(pairs);
            let validated = srv.validate_authorization_request(&request).await.unwrap();
            let code = srv
                .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
                .await
                .unwrap()
                .code;
            srv.token(TokenRequest::AuthorizationCode {
                client_id: ClientId::new("app"),
                client_secret: Some(SECRET.to_string()),
                code,
                redirect_uri: Some(REDIRECT.to_string()),
                code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
            })
            .await
        })
        .unwrap()
        .refresh_token
        .unwrap();

    // Built OUTSIDE the window: `ClientId::new` owns its string and that allocation is the
    // caller's, not the endpoint's, exactly as `tests/allocation.rs` argues for its refusal gate.
    let client_id = ClientId::new("app");
    let (result, d) = measure(|| rt.block_on(srv.revoke(&client_id, Some(SECRET), &refresh, None)));
    result.expect("a client may revoke its own token");
    check("revocation", d, REVOKE);
}

/// RFC 7009 s2.2: revoking a string this server never issued is a 200 with no work done, and this
/// is the gate that says so in allocations.
///
/// It is separated from the success case because an ATTACKER chooses how many of these arrive: a
/// revocation endpoint is authenticated, so this is not unauthenticated traffic, but any
/// confidential client can send it at whatever rate it likes and get a 200 every time. Nothing
/// should be minted, copied or stored to answer it.
fn revocation_of_an_unknown_token_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let client_id = ClientId::new("app");
    let (result, d) = measure(|| {
        rt.block_on(srv.revoke(
            &client_id,
            Some(SECRET),
            "not-a-token-this-server-ever-issued",
            None,
        ))
    });
    result.expect("RFC 7009 s2.2: an unknown token is still a 200");
    check("revocation of an unknown token", d, REVOKE_UNKNOWN);
}

// ------------------------------------------------------------------- RFC 7591 registration

struct AllowAll;
impl oauth_as::RegistrationPolicy for AllowAll {
    fn authorize(
        &self,
        _attempt: &oauth_as::RegistrationAttempt<'_>,
    ) -> oauth_as::RegistrationDecision {
        oauth_as::RegistrationDecision::Allow
    }
}

/// RFC 7591 s3: one dynamic client registration.
///
/// This is the coldest path in the crate (a client registers once and then exists), so the gate is
/// not here to protect a request rate. It is here because registration is the one capability with
/// NO cargo feature, so every default build compiles it, and a cost that grows here is a cost
/// nobody opted into. Dominated by the three secrets it mints (client id, client secret,
/// registration access token), their hashes, and the `ClientInformation` document it hands back,
/// which by design is the only copy of two of them.
fn dynamic_registration_bound() {
    let rt = current_thread_runtime();
    let mut cfg = config();
    let mut registration = oauth_as::RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read write").unwrap();
    cfg.registration = Some(Box::new(registration));
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(AllowAll));
    let metadata = oauth_as::ClientMetadata {
        redirect_uris: vec![REDIRECT.to_string()],
        ..Default::default()
    };
    // Warm: the first registration pays for the client map's first bucket table.
    rt.block_on(srv.register_dynamic_client(&metadata, None))
        .unwrap();

    let (info, d) = measure(|| rt.block_on(srv.register_dynamic_client(&metadata, None)));
    assert!(info.unwrap().client_secret.is_some());
    check("dynamic registration", d, REGISTRATION);
}

// ------------------------------------------------------------------------------- RFC 9126 PAR

#[cfg(feature = "par")]
fn par_config() -> ServerConfig {
    let mut cfg = config();
    cfg.par = Some(Box::new(oauth_as::ParConfig::new()));
    cfg
}

/// RFC 9126 s2: one pushed authorization request.
///
/// Runs once per authorization when a deployment requires PAR, so it is on the browser-login path
/// exactly as `validate_authorization_request` is. Dominated by the record it stores: every
/// parameter arrives BORROWED and every one of them has to be owned to survive the push, so this
/// path pays roughly one `String` per authorization parameter plus the `request_uri` it mints.
#[cfg(feature = "par")]
fn par_push_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, par_config());
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let parameters = authorization_pairs(&challenge);
    // Warm: first push pays for the pushed-request map's first bucket table.
    rt.block_on(srv.pushed_authorization_request(&ClientId::new("app"), Some(SECRET), &parameters))
        .unwrap();

    let (pushed, d) = measure(|| {
        rt.block_on(srv.pushed_authorization_request(
            &ClientId::new("app"),
            Some(SECRET),
            &parameters,
        ))
    });
    assert!(pushed.unwrap().request_uri.starts_with("urn:"));
    check("PAR push", d, PAR_PUSH);
}

#[cfg(not(feature = "par"))]
fn par_push_bound() {}

/// RFC 9126 s4: redeeming the handle at the authorization endpoint, which consumes it atomically.
///
/// The stored record comes back OWNED (a `take_*`, which the trait's atomicity contract requires),
/// is turned back into a borrowing `AuthorizationRequest` by `as_request`, and revalidated. The
/// revalidation is deliberate and is not free; this gate is what keeps the cost of it visible.
#[cfg(feature = "par")]
fn par_redemption_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, par_config());
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let parameters = authorization_pairs(&challenge);
    let request_uri = rt
        .block_on(srv.pushed_authorization_request(
            &ClientId::new("app"),
            Some(SECRET),
            &parameters,
        ))
        .unwrap()
        .request_uri;

    let (validated, d) =
        measure(|| rt.block_on(srv.validate_pushed_authorization_request("app", &request_uri)));
    assert_eq!(validated.unwrap().client_id, ClientId::new("app"));
    check("PAR redemption", d, PAR_REDEEM);
}

#[cfg(not(feature = "par"))]
fn par_redemption_bound() {}

// ------------------------------------------------------------------------------ RFC 9449 DPoP

#[cfg(all(feature = "jwt-p256", feature = "dpop"))]
fn dpop_proof(key: &oauth_as::jwt::EcdsaP256Key, jti: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = serde_json::json!({
        "jti": jti, "htm": "POST", "htu": "https://as.example/token", "iat": now,
    });
    oauth_as::jwt::compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

/// RFC 9449 s4.3: one token request carrying a valid proof, against the same request WITHOUT one.
///
/// The interesting number is the DIFFERENCE, which is what a deployment pays to turn bearer tokens
/// into sender-constrained ones: a base64url decode of two JWS segments, a `serde_json` parse of
/// each, an RFC 7638 thumbprint over the embedded JWK, a P-256 signature verification, and a
/// `claim_replay_id` insert that has to keep the `jti` until the proof's window closes. None of it
/// was gated before, so nothing would have caught the cost of it doubling.
#[cfg(all(feature = "jwt-p256", feature = "dpop"))]
fn dpop_proof_verification_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let key = oauth_as::jwt::EcdsaP256Key::generate("client-key");
    // Warm: the replay map's first bucket table, and the first signature verification, which may
    // initialise lazily inside p256.
    rt.block_on(srv.token_with_context(
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        },
        oauth_as::TokenRequestContext::default().with_dpop_proof(&dpop_proof(&key, "warm")),
    ))
    .unwrap();

    let proof = dpop_proof(&key, "measured");
    // Built OUTSIDE the window: the `ClientId` and the secret `String` are the caller's
    // allocations, not the endpoint's.
    let request = TokenRequest::ClientCredentials {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    };
    let (response, d) = measure(|| {
        rt.block_on(srv.token_with_context(
            request,
            oauth_as::TokenRequestContext::default().with_dpop_proof(&proof),
        ))
    });
    assert_eq!(response.unwrap().token_type, oauth_as::TokenType::Dpop);
    check("DPoP proof verification", d, DPOP_PROOF);
}

/// What a token request costs under `dpop` when NO proof was presented, which is the number that
/// says whether enabling the feature taxes the clients that are not using it.
///
/// It used to. Through 0.9.0 `token_with_context` reached the RFC 9449 proof check through a
/// `Box::pin`, paid whether or not a proof arrived, and `tests/allocation.rs` carried that as a
/// named exception on its refusal gate. Re-measuring it showed the box had stopped buying the
/// future-size headroom it was introduced for, so it is gone and this path pays nothing for a
/// feature it is not using.
///
/// The assertion below is therefore twofold: an absent proof is bounded, AND a presented proof
/// costs strictly more. The second half is what stops this gate passing vacuously if the proof
/// check were ever short-circuited: a DPoP verification that allocated the same as no verification
/// at all would be doing no work.
// `jwt-p256` as well as the feature itself: the fixture has to SIGN, and after the
// `Es256Signer` seam landed neither `dpop` nor `client-assertion` implies a curve.
#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
fn token_request_with_no_dpop_proof_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    // Warmed so the measured call is not the one that grows the token map.
    rt.block_on(srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    }))
    .unwrap();

    // Both requests are built OUTSIDE their windows, for the same reason and so that the two
    // figures differ only by the proof.
    let credentials = || TokenRequest::ClientCredentials {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    };
    let with_proof = {
        let key = oauth_as::jwt::EcdsaP256Key::generate("client-key");
        let proof = dpop_proof(&key, "isolate");
        let request = credentials();
        let (_, d) = measure(|| {
            rt.block_on(srv.token_with_context(
                request,
                oauth_as::TokenRequestContext::default().with_dpop_proof(&proof),
            ))
        });
        d.allocs
    };
    let request = credentials();
    let (_, without) = measure(|| rt.block_on(srv.token(request)));
    assert!(
        with_proof > without.allocs,
        "a presented proof must cost more than an absent one: {with_proof} against {without:?}"
    );
    check("token request with no DPoP proof", without, DPOP_ABSENT);
}

#[cfg(not(all(feature = "dpop", feature = "jwt-p256")))]
fn token_request_with_no_dpop_proof_bound() {}

// -------------------------------------------------------------------- RFC 7523 client assertion

/// RFC 7523 s3: one `private_key_jwt` token request.
///
/// This is the client authentication FAPI 2.0 requires and that a deployment forbidding shared
/// secrets has no alternative to, so it runs on every token request those deployments make.
/// Dominated by the same JWS machinery DPoP uses plus the single-use `jti` claim, and it had no
/// gate.
// `jwt-p256` as well as the feature itself: the fixture has to SIGN, and after the
// `Es256Signer` seam landed neither `dpop` nor `client-assertion` implies a curve.
#[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
fn client_assertion_verification_bound() {
    use oauth_as::client_assertion::{AssertionKeys, CLIENT_ASSERTION_TYPE};
    use std::time::{SystemTime, UNIX_EPOCH};

    let rt = current_thread_runtime();
    let key = oauth_as::jwt::EcdsaP256Key::generate("client-key");
    let srv = rt.block_on(async {
        let srv = AuthorizationServer::new(config(), MemoryStorage::new());
        srv.register_client(Client {
            client_id: ClientId::new("pkjwt"),
            auth: ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::PublicKeys {
                    keys: vec![key.to_public_jwk()],
                },
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read write").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
        srv
    });
    let assertion = |jti: &str| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "iss": "pkjwt", "sub": "pkjwt", "aud": "https://as.example/token",
            "exp": now + 120, "iat": now, "jti": jti,
        });
        oauth_as::jwt::compact_jws(
            br#"{"alg":"ES256","typ":"JWT"}"#,
            &serde_json::to_vec(&claims).unwrap(),
            |input| key.sign_signing_input(input).unwrap(),
        )
    };
    let request = || TokenRequest::ClientCredentials {
        client_id: ClientId::new("pkjwt"),
        client_secret: None,
        scope: None,
    };
    fn context(a: &str) -> oauth_as::TokenRequestContext<'_> {
        oauth_as::TokenRequestContext::new(oauth_as::ClientCredential::assertion(
            Some(CLIENT_ASSERTION_TYPE),
            a,
        ))
    }
    let warm = assertion("warm");
    rt.block_on(srv.token_with_context(request(), context(&warm)))
        .unwrap();

    let measured = assertion("measured");
    let measured_request = request();
    let (response, d) =
        measure(|| rt.block_on(srv.token_with_context(measured_request, context(&measured))));
    assert!(!response.unwrap().access_token.is_empty());
    check("client assertion verification", d, CLIENT_ASSERTION);
}

#[cfg(not(all(feature = "client-assertion", feature = "jwt-p256")))]
fn client_assertion_verification_bound() {}

// ------------------------------------------------------------------- RFC 8693 token exchange

/// RFC 8693 s2.1: exchanging a live access token for a narrower one.
///
/// A grant that mints a token FROM a token, so it does everything issuance does plus reading and
/// type-checking the subject token first.
#[cfg(feature = "token-exchange")]
fn token_exchange_bound() {
    use oauth_as::token_exchange::{TokenExchange, TokenExchangeRequest, TokenTypeIdentifier};

    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let subject = rt
        .block_on(srv.token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        }))
        .unwrap()
        .access_token;
    let client_id = ClientId::new("app");
    let exchange = || {
        let mut request =
            TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
        request.client_secret = Some(SECRET);
        request
    };
    rt.block_on(srv.exchange_token(&exchange())).unwrap();

    let (response, d) = measure(|| rt.block_on(srv.exchange_token(&exchange())));
    assert!(!response.unwrap().response.access_token.is_empty());
    check("token exchange", d, TOKEN_EXCHANGE);
}

#[cfg(not(feature = "token-exchange"))]
fn token_exchange_bound() {}

// ---------------------------------------------------------------------------- RFC 9396 RAR

/// RFC 9396 s2: parsing the `authorization_details` parameter.
///
/// This is UNAUTHENTICATED attacker-supplied JSON at the authorization endpoint, which is the
/// argument the feature's own Cargo.toml comment makes for it being off by default. That also makes
/// it the one parse in the crate whose allocation cost an attacker sets directly, so a gate on it
/// is about a denial-of-service budget and not about tidiness.
#[cfg(feature = "rar")]
fn rar_parse_bound() {
    let raw = r#"[{"type":"payment_initiation","actions":["initiate","status"],
                   "locations":["https://rs.example/payments"]}]"#;
    let (parsed, d) = measure(|| oauth_as::rar::AuthorizationDetails::parse(raw));
    assert_eq!(parsed.unwrap().len(), 1);
    check("RAR parse", d, RAR_PARSE);
}

#[cfg(not(feature = "rar"))]
fn rar_parse_bound() {}

/// RFC 9396 s6: checking that a requested detail set is a NARROWING of what was granted, and
/// producing the narrowed set.
///
/// Runs on the token path whenever a grant carries authorization details, so unlike the parse it is
/// per token request rather than per authorization request.
#[cfg(feature = "rar")]
fn rar_narrowing_bound() {
    let granted = oauth_as::rar::AuthorizationDetails::parse(
        r#"[{"type":"payment_initiation","actions":["initiate","status"]}]"#,
    )
    .unwrap();
    let requested = oauth_as::rar::AuthorizationDetails::parse(
        r#"[{"type":"payment_initiation","actions":["status"]}]"#,
    )
    .unwrap();
    let (narrowed, d) = measure(|| granted.narrow(&requested));
    assert_eq!(narrowed.unwrap().len(), 1);
    check("RAR narrowing", d, RAR_NARROW);
}

#[cfg(not(feature = "rar"))]
fn rar_narrowing_bound() {}

// -------------------------------------------------------------------------- the consent seam

/// The consent LOOKUP, which is the half of the seam that runs per request: a host asks what this
/// user has already granted this client every time it decides whether to show a consent screen.
///
/// `find_consent` returns an `Arc`, so this should be a pointer clone and nothing else. That is the
/// claim, and this is the gate that holds it: the WRITE side (`record_consent`) deliberately pays
/// a clone instead, because it widens the record it read, and the argument for that trade is only
/// sound if the read really is free.
#[cfg(feature = "consent")]
fn consent_lookup_bound() {
    let rt = current_thread_runtime();
    let srv = server(&rt, config());
    let scope = ScopeSet::parse("read").unwrap();
    rt.block_on(srv.record_consent(&ClientId::new("app"), "user-1", &scope, &[], None))
        .unwrap();

    let client_id = ClientId::new("app");
    let (found, d) = measure(|| rt.block_on(srv.remembered_consent(&client_id, "user-1")));
    assert!(found.unwrap().is_some());
    check("consent lookup", d, CONSENT_LOOKUP);
}

#[cfg(not(feature = "consent"))]
fn consent_lookup_bound() {}

/// RFC 9470 s4 `acr_values`, which is ONE parameter carrying a space-delimited list, arriving
/// unauthenticated at `GET /authorize` and at the RFC 9126 push.
///
/// This is a denial-of-service budget and not a tidiness gate. Parsing stores one `Box<str>`, which
/// is one heap allocation, per non-empty segment. The cheapest input is `"a a a ..."` at two bytes
/// a token, so before `MAX_ACR_VALUES` existed a 64 KiB body (`MAX_BODY_BYTES`) bought about 32,768
/// allocations from a single parameter, and a URL is not bounded by that constant at all. MEASURED
/// on the 20,000-class input below by putting the pre-cap parse back and running this gate,
/// `--all-features`: 20,010 allocations and 1,067,552 bytes of traffic, of which 523,264 was freed
/// again as the `Vec` grew through the buffers it doubled out of. One parameter.
///
/// The bound is EXACTLY ZERO because zero is the claim: an oversized parameter is refused after a
/// counting pass that allocates nothing, and the refusal's own description is a `&'static str`. The
/// refusal is asserted alongside it, so the gate cannot pass by the parse having been deleted.
#[cfg(feature = "consent")]
fn acr_values_refusal_bound() {
    use oauth_as::consent::{AuthenticationRequirement, MAX_ACR_VALUES};

    // Built OUTSIDE the window: the attacker's bytes are the wire's allocation, not the parse's.
    let oversized = "a ".repeat(20_000);
    let (refused, d) =
        measure(|| AuthenticationRequirement::from_pairs([("acr_values", &oversized)]));
    // The allocation gate is asserted FIRST so that a regression reports the figure rather than
    // `Debug`-printing twenty thousand parsed classes.
    check("acr_values refusal", d, ACR_REFUSAL);
    assert!(
        refused.is_err(),
        "acr_values past the cap is refused, not truncated: it parsed {} classes",
        refused.map(|r| r.acr_values.len()).unwrap_or(0)
    );

    // The cap REFUSES rather than truncates, so the largest accepted list is stored whole. Anything
    // else would answer a step-up challenge with a class the user never satisfied.
    let at_cap = vec!["urn:acr:phr"; MAX_ACR_VALUES].join(" ");
    let accepted = AuthenticationRequirement::from_pairs([("acr_values", &at_cap)])
        .expect("a list AT the cap is accepted");
    assert_eq!(accepted.acr_values.len(), MAX_ACR_VALUES);
}

#[cfg(not(feature = "consent"))]
fn acr_values_refusal_bound() {}

// -------------------------------------------------------------------------- RFC 7517 JWKS

/// RFC 7517: building the JWKS document a resource server fetches to verify RFC 9068 tokens
/// without calling this server.
///
/// The `http` feature serializes this ONCE at router build and hands out a refcounted `Bytes`
/// afterwards, so a host on that path pays this exactly once. A host that serves `jwks_uri` itself,
/// which is the documented contract when `http` is off, pays it on EVERY fetch: `jwks()` rebuilds
/// the document each call, re-encoding the public point and cloning every retired key.
///
/// The bound is therefore not a hot-path budget, it is a record of what that per-fetch rebuild
/// costs, so that a decision to cache it can be justified with a number.
#[cfg(feature = "jwt-p256")]
fn jwks_serving_bound() {
    let rt = current_thread_runtime();
    let mut cfg = config();
    cfg.access_token_format =
        oauth_as::jwt::AccessTokenFormat::Jwt(Box::new(oauth_as::jwt::JwtConfig::new(
            oauth_as::jwt::EcdsaP256Key::generate("sign"),
            "https://rs.example",
        )));
    let srv = server(&rt, cfg);
    // Warm: the first call may initialise lazily inside p256's point encoding.
    let _ = srv.jwks();

    let (jwks, d) = measure(|| srv.jwks());
    assert_eq!(jwks.unwrap().keys.len(), 1);
    check("JWKS document build", d, JWKS_BUILD);
}

/// RFC 9068: issuing ONE `at+jwt` access token, against the same issuance with opaque tokens.
///
/// The difference is what the JWT profile costs per token: a claim set serialized, a JOSE header
/// serialized, three base64url encodes, one ES256 signature, and the `format!`s that join them.
/// Opaque tokens are this crate's default precisely because a resource server can introspect
/// instead, so this gate is what makes the trade a number rather than a preference.
#[cfg(feature = "jwt-p256")]
fn jwt_signing_bound() {
    let rt = current_thread_runtime();
    let mut cfg = config();
    cfg.access_token_format =
        oauth_as::jwt::AccessTokenFormat::Jwt(Box::new(oauth_as::jwt::JwtConfig::new(
            oauth_as::jwt::EcdsaP256Key::generate("sign"),
            "https://rs.example",
        )));
    let srv = server(&rt, cfg);
    let credentials = || TokenRequest::ClientCredentials {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    };
    // Warm: the token map's first bucket table, and p256's first signature.
    rt.block_on(srv.token(credentials())).unwrap();

    let request = credentials();
    let (response, d) = measure(|| rt.block_on(srv.token(request)));
    assert!(
        response.unwrap().access_token.starts_with("eyJ"),
        "the fixture must actually be signing JWTs"
    );
    check("JWT access token issuance", d, JWT_SIGN);
}

// -------------------------------------------------------------------------------- the bounds

/// Check one measurement against its bound and report the observed figure either way, so a passing
/// run under `--nocapture` re-derives the numbers recorded below rather than asking a reader to
/// trust them.
fn check(name: &str, d: Delta, bound: (usize, usize)) {
    let (allocs, bytes) = bound;
    assert!(
        d.allocs <= allocs,
        "{name} allocation count regressed past {allocs}: {d:?}"
    );
    assert!(
        d.bytes <= bytes,
        "{name} allocation bytes regressed past {bytes}: {d:?}"
    );
    println!("{name}: {} allocs, {} bytes", d.allocs, d.bytes);
}

// Each bound is (allocs, bytes), set from the OBSERVED figure with roughly 30 percent of margin,
// rounded. The observed figures are in the comments so a failure can be compared against them.
// Where a feature changes the shape of a path, the widest observed figure is the one recorded.

/// Observed 9 allocs / 390 bytes on every feature set: the owned fields of the
/// `ValidatedAuthorizationRequest`, and nothing for the client read, which is a pointer clone.
const AUTHZ_VALIDATE: (usize, usize) = (12, 512);

/// Observed 13 / 617 on every feature set, against a WARM code map. Measured cold it is 13 / 1653,
/// the difference being the map's first bucket table, which is a one-time store cost.
const AUTHZ_ISSUE: (usize, usize) = (17, 800);

/// Observed 11 / 518 on every feature set. Ten of the eleven are freed again inside the same call:
/// this is a read-modify-write, so the grant is cloned out of the map and the old copy dropped.
const DEVICE_APPROVE: (usize, usize) = (14, 672);

/// Observed 9 / 662 on every feature set, and it FREES 1798: revocation is the one endpoint whose
/// job is to give memory back, and the family cascade is why it gives back nearly three times what
/// it takes.
///
/// It was 7 / 394 through 0.9.0. The two extra allocations and 268 extra bytes are the
/// [`oauth_as::store::RevocationBarrier`] this path now records: the `Box<str>` holding the
/// `family_id`, and the barrier map's first bucket table, which is a one-time store cost the way
/// every other map's is. That is what a revocation which a concurrent rotation cannot undo costs,
/// on the endpoint whose entire purpose is to revoke, and it is paid once per revocation rather
/// than per request.
const REVOKE: (usize, usize) = (12, 800);

/// EXACTLY ZERO, on every feature set, and the bound is zero rather than a budget because zero is
/// the claim. RFC 7009 s2.2 makes an unknown token a 200, which means any authenticated client can
/// ask for this answer as fast as it can send, and the server must not buy work to give it.
const REVOKE_UNKNOWN: (usize, usize) = (0, 0);

/// Observed 32 / 1249 on every feature set, warm. The three minted secrets and their hashes account
/// for most of it, and the `ClientInformation` document holds the only copy of two of them by
/// design (they are unrecoverable afterwards), so those allocations are the feature, not overhead.
const REGISTRATION: (usize, usize) = (42, 1620);

/// Observed 23 / 915 with `rar` and `consent` also on, which is the record's widest shape: roughly
/// one owned `String` per authorization parameter, because every parameter arrives borrowed and has
/// to outlive the request that pushed it.
#[cfg(feature = "par")]
const PAR_PUSH: (usize, usize) = (30, 1200);

/// Observed 9 / 390: the same figure as validating a fresh authorization request, which is the
/// point. RFC 9126 s2.1 step 3 revalidates rather than trusting the stored record, and this says
/// what that costs.
#[cfg(feature = "par")]
const PAR_REDEEM: (usize, usize) = (12, 512);

/// Observed 54 / 4670 `--all-features`, against 11 / 1683 for the same request with no proof: RFC
/// 9449 verification costs 43 allocations and about 3 KB of transient traffic, nearly all of it
/// freed again. That is the price of turning a bearer token into a sender-constrained one. It was
/// 58 before the `Box::pin` came off, 57 before `Storage`'s reads returned `Arc`, and 56 before
/// the server's own token endpoint URL stopped being `format!`ed once per proof.
#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
const DPOP_PROOF: (usize, usize) = (74, 6144);

/// Observed 12 / 1707 `--all-features`, down from 13 / 1875 when the proof check was boxed. This is
/// a full `client_credentials` issuance and the DPoP feature now adds nothing to it.
#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
const DPOP_ABSENT: (usize, usize) = (16, 2224);

/// Observed 35 / 3338 `--all-features`, down from 40 / 3752: one allocation from the assertion
/// `Box::pin` coming off, one from the DPoP one, and one more from the token endpoint URL being
/// precomputed on the server rather than formatted per verification. For a `private_key_jwt`
/// deployment this is every token request it makes.
#[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
const CLIENT_ASSERTION: (usize, usize) = (49, 4448);

/// Observed 11 / 1051: reading and type-checking the subject token, then a full issuance. Cheaper
/// than a code redemption because there is no code record to consume and no refresh chain to start.
#[cfg(feature = "token-exchange")]
const TOKEN_EXCHANGE: (usize, usize) = (14, 1368);

/// Observed 9 / 715 for a two-action, one-location detail. Attacker-supplied JSON, so this is a
/// denial-of-service budget: the input is already length-capped by
/// `MAX_AUTHORIZATION_DETAILS_BYTES`, and this pins that the cost stays proportional to it.
#[cfg(feature = "rar")]
const RAR_PARSE: (usize, usize) = (12, 930);

/// Observed 5 / 161 for one granted element narrowed to one requested element. The `vec![false; n]`
/// the distinct-element matching needs is one of the five, and it is what stops N copies of one
/// grant satisfying N requests.
#[cfg(feature = "rar")]
const RAR_NARROW: (usize, usize) = (7, 210);

/// EXACTLY ZERO, and zero is the claim, not a budget: `Storage::find_consent` returns an `Arc`, so
/// asking what a user has already granted is a pointer clone. The WRITE side pays a record clone
/// instead, deliberately, and that trade is only sound while this stays at zero.
#[cfg(feature = "consent")]
const CONSENT_LOOKUP: (usize, usize) = (0, 0);

/// EXACTLY ZERO, and zero is the claim: refusing an oversized `acr_values` costs a counting pass
/// over borrowed bytes and a `&'static str` description. Observed 20,010 allocs / 1,067,552 bytes
/// with the cap taken back out, on the same input, all of it chosen by an unauthenticated request.
#[cfg(feature = "consent")]
const ACR_REFUSAL: (usize, usize) = (0, 0);

/// Observed 19 allocs / 3255 bytes `--all-features`, against 11 / 1683 for the same issuance with
/// opaque tokens: the RFC 9068 profile costs roughly 8 allocations and 1.6 KB of transient traffic
/// per token, nearly all of it freed again. It was 28 / 4767 before the JOSE header was
/// precomputed in `JwtConfig`, 26 / 4733 after that, and 25 / 4709 once `Storage`'s reads returned
/// `Arc`; the last six came off when the compact serialization stopped being assembled with two
/// `format!` calls, which had been allocating and fully copying the whole token twice.
///
/// This is the number behind opaque tokens being the DEFAULT: a resource server introspects
/// instead, and introspection is 4 allocations.
#[cfg(feature = "jwt-p256")]
const JWT_SIGN: (usize, usize) = (26, 4352);

/// Observed 4 / 226 for a one-key set. Small, and pinned anyway because `jwks()` REBUILDS the
/// document on every call: the `http` feature serializes it once at router build and hands out a
/// refcounted `Bytes` afterwards, but a host serving `jwks_uri` itself (the documented contract
/// when `http` is off) pays this per fetch, and a verifier fetches on every cold cache. Four
/// allocations is small enough that caching it is not worth an API change; the gate is what would
/// tell us if that stopped being true.
#[cfg(feature = "jwt-p256")]
const JWKS_BUILD: (usize, usize) = (6, 296);
