// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A DETERMINISTIC state-machine / model test for the refresh-token lifecycle.
//!
//! The lifecycle has four axes that interact: ROTATION (a live token is spent and a successor
//! minted), RETRY coalescing (a lost-response replay inside `refresh_retry_window` recovers the
//! winning rotation's cached tokens), REUSE detection (a spent token re-presented past any retry
//! material revokes the whole family), and DPoP RE-KEY (a confidential client MAY rotate a bound
//! chain onto a NEW key; a public client may NOT). These are not independent: the correct answer to
//! a retry depends on which key the WINNING rotation bound, which for a confidential re-key is the
//! NEW key, not the spent predecessor's.
//!
//! The class of bug this guards against — the one the audit found — is exactly that drift: the
//! retry-coalescing path compared the presented proof against the SPENT PREDECESSOR's key
//! (`record.jkt`) instead of the WINNING rotation's key (`retry.jkt`, set from `bound.jkt` in
//! `commit_refresh_retry`). The re-key relaxation (rotation) and the retry path had drifted apart:
//! a legitimate re-keyed retry was refused, and — worse — a stale proof from the predecessor key
//! would have been ACCEPTED. A single-scenario test can miss that; a model over
//! rotation × retry × reuse × client-type × DPoP re-key cannot.
//!
//! HOW THIS IS A MODEL, NOT A PILE OF CASES. The expected behaviour is written once, as three pure
//! functions ([`model_rotate`], [`model_retry`], and the reuse verdict) that `match` on
//! state + action. The real [`AuthorizationServer`] is then driven through an EXHAUSTIVE matrix of
//! transitions and its observable outcome is asserted equal to the model's at every step. Nothing
//! is randomised; the matrix is enumerated by hand so a failure names the exact transition.
//!
//! THE DISCRIMINATING TRANSITION. In `retry_group`, a confidential chain bound to `original` is
//! rotated onto `rekeyed` (a legal re-key), then retried. The model says a retry presenting
//! `rekeyed` (the winning key) COALESCES and a retry presenting `original` (the predecessor) is
//! REFUSED `invalid_dpop_proof`. If `refresh_retry_response` is reverted to compare `record.jkt`
//! (the predecessor) instead of `retry.jkt` (the winner), BOTH of those assertions flip — the
//! predecessor retry would wrongly coalesce and the winning-key retry would be wrongly refused — so
//! this test fails red. That is the tautology check the audit fix needs.

#![cfg(all(feature = "dpop", feature = "jwt-p256"))]
// `jwt-p256` because every transition has to PRODUCE a real ES256 DPoP proof; `jwt` alone carries
// the signer/verifier seam and no curve arithmetic, so nothing here could run in that build.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use oauth_as::jwt::{compact_jws, EcdsaP256Key};
use oauth_as::server::UserApproval;
use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode,
    ErrorResponse, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
    TokenRequestContext, TokenResponse, TokenType,
};
use support::ManualClock;

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const CONF_SECRET: &str = "confidential-secret-for-state-machine";
const REDIRECT: &str = "https://app.example/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// A single monotonic source of DPoP `jti` values across the whole test. Every proof must be
// single-use (RFC 9449 s4.3 (2)); a per-proof unique `jti` keeps the replay defence from refusing a
// proof for a reason this test is not about.
static JTI: AtomicU64 = AtomicU64::new(0);

fn next_jti() -> String {
    format!("jti-{}", JTI.fetch_add(1, Ordering::Relaxed))
}

// ------------------------------------------------------------------------------------ the clients

/// A confidential client, registered for the code and refresh grants. RFC 9449 s5 lets it rotate a
/// DPoP-bound chain onto a NEW key, because the chain is bound to the client through its credential.
fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("conf-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: CONF_SECRET.into(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A public client (no credential), so its DPoP key is the ONLY thing binding the chain: RFC 9449
/// s5 holds it to an EXACT key match on rotation.
fn public_client() -> Client {
    Client {
        client_id: ClientId::new("pub-app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientKind {
    Public,
    Confidential,
}

impl ClientKind {
    fn id(self) -> ClientId {
        match self {
            ClientKind::Public => ClientId::new("pub-app"),
            ClientKind::Confidential => ClientId::new("conf-app"),
        }
    }
    fn secret(self) -> Option<String> {
        match self {
            ClientKind::Public => None,
            ClientKind::Confidential => Some(CONF_SECRET.to_string()),
        }
    }
}

// ------------------------------------------------------------------------------------ the harness

fn server(
    clock: ManualClock,
    retry_window: Duration,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut config = ServerConfig::new(ISSUER, "https://as.example/device");
    config.token_endpoint = Some(TOKEN_ENDPOINT.into());
    config.refresh_retry_window = retry_window;
    AuthorizationServer::with_clock(config, MemoryStorage::new(), clock)
}

fn now_secs(clock: &ManualClock) -> u64 {
    use oauth_as::Clock;
    clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// One RFC 9449 s4.2 proof for `POST {TOKEN_ENDPOINT}`, signed by `key`, dated on the MANUAL clock
/// so the `iat` window check (RFC 9449 s4.3 (10)) is measured against the same time the server sees.
fn proof(key: &EcdsaP256Key, clock: &ManualClock) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = serde_json::json!({
        "jti": next_jti(),
        "htm": "POST",
        "htu": TOKEN_ENDPOINT,
        "iat": now_secs(clock),
    });
    compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

/// Drive a full PKCE authorization-code redemption, optionally binding the chain to `key`, and
/// return the issued refresh token. This is how a real chain is seeded before any rotation.
async fn mint_chain(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    client: ClientKind,
    key: Option<&EcdsaP256Key>,
    clock: &ManualClock,
) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let mut request = AuthorizationRequest::default();
    request.response_type = Some("code".into());
    request.client_id = Some(client.id().as_str().to_string().into());
    request.redirect_uri = Some(REDIRECT.into());
    request.scope = Some("read".into());
    request.state = Some("s".into());
    request.code_challenge = Some(challenge.into());
    request.code_challenge_method = Some("S256".into());
    let validated = srv.validate_authorization_request(&request).await.unwrap();
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap()
        .code;

    let dpop = key.map(|k| proof(k, clock));
    let context = match &dpop {
        Some(p) => TokenRequestContext::default().with_dpop_proof(p),
        None => TokenRequestContext::default(),
    };
    srv.token_with_context(
        TokenRequest::AuthorizationCode {
            client_id: client.id(),
            client_secret: client.secret(),
            code,
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: Some(VERIFIER.to_string()),
        },
        context,
    )
    .await
    .expect("the authorization code grant issues a refresh token")
    .refresh_token
    .expect("the code grant issues a chain")
}

/// Present `token` at the refresh endpoint, optionally with a DPoP proof from `key`.
async fn present(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    client: ClientKind,
    token: &str,
    key: Option<&EcdsaP256Key>,
    clock: &ManualClock,
) -> Result<TokenResponse, ErrorResponse> {
    let request = TokenRequest::RefreshToken {
        client_id: client.id(),
        client_secret: client.secret(),
        refresh_token: token.to_string(),
        scope: None,
    };
    match key {
        Some(k) => {
            let p = proof(k, clock);
            srv.token_with_context(request, TokenRequestContext::default().with_dpop_proof(&p))
                .await
        }
        None => srv.token(request).await,
    }
}

// ------------------------------------------------------------------------------------- THE MODEL

/// A symbolic key. The model reasons over these; the driver maps each to a real `EcdsaP256Key`.
/// `None` (no proof) is represented by `Option::None` throughout, so presence parity is just
/// `is_some()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Original,
    Rekeyed,
    Thief,
}

/// The outcome the model predicts. `Coalesce`/`Rotated` are both `Ok` on the wire; they differ in
/// what the response must EQUAL, which is the whole point of retry coalescing.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// A successful rotation: a fresh token bound to the presented key/binding.
    Rotated,
    /// A successful retry: the winning rotation's cached tokens, byte for byte.
    Coalesce,
    /// Refused for a DPoP binding mismatch, WITHOUT revoking the family.
    DpopProof,
    /// Refused `invalid_grant`, having revoked the whole family (reuse).
    GrantRevoked,
}

/// ROTATION (RFC 9449 s5). `chain` is the binding the live token carries; `presented` is the proof
/// on this request. A public client's chain is bound only by its key, so an EXACT match (including
/// no-proof-vs-no-proof) is required. A confidential client's chain is bound by its credential, so
/// it MAY re-key — only the PRESENCE of a proof must match (a bound chain cannot silently downgrade
/// to bearer, a bearer chain cannot acquire a binding).
fn model_rotate(client: ClientKind, chain: Option<Key>, presented: Option<Key>) -> Verdict {
    match client {
        ClientKind::Public => {
            if chain == presented {
                Verdict::Rotated
            } else {
                Verdict::DpopProof
            }
        }
        ClientKind::Confidential => {
            if chain.is_some() == presented.is_some() {
                Verdict::Rotated
            } else {
                Verdict::DpopProof
            }
        }
    }
}

/// RETRY coalescing INSIDE the window. A lost-response retry is a byte-identical replay, so it
/// coalesces IFF it presents the key the WINNING rotation bound (`winning`) — for a confidential
/// re-key that is the NEW key, NOT the predecessor's. Any other key (a thief holding the credential
/// but a different key, or the stale predecessor key) is refused without coalescing and without
/// revoking. This is the exact rule `refresh_retry_response` must implement against `retry.jkt`.
fn model_retry(winning: Option<Key>, presented: Option<Key>) -> Verdict {
    if winning == presented {
        Verdict::Coalesce
    } else {
        Verdict::DpopProof
    }
}

/// REUSE. A spent token re-presented with no live retry material — either because the window is
/// closed (`refresh_retry_window` = 0) or because it has elapsed — is unambiguous evidence of
/// compromise: `invalid_grant`, and the whole family is revoked (RFC 9700 s4.14.2). This holds
/// regardless of the key presented, because reuse detection runs before the binding check.
fn model_reuse() -> Verdict {
    Verdict::GrantRevoked
}

/// Assert the AS refused with `invalid_grant` (a revoked family), the reuse verdict.
fn assert_reuse(what: &str, model: Verdict, actual: &Result<TokenResponse, ErrorResponse>) {
    assert_eq!(
        model,
        Verdict::GrantRevoked,
        "{what}: reuse models as GrantRevoked"
    );
    let err = actual
        .as_ref()
        .expect_err(&format!("{what}: model says reuse revokes the grant"));
    assert_eq!(
        err.error,
        ErrorCode::InvalidGrant,
        "{what}: detected reuse is invalid_grant"
    );
}

/// Assert the AS's real result matches the model's verdict for a ROTATION.
fn assert_rotation(what: &str, model: Verdict, actual: &Result<TokenResponse, ErrorResponse>) {
    match model {
        Verdict::Rotated => {
            actual
                .as_ref()
                .unwrap_or_else(|e| panic!("{what}: model says the rotation succeeds, got {e}"));
        }
        Verdict::DpopProof => {
            let err = actual
                .as_ref()
                .expect_err(&format!("{what}: model says the rotation is refused"));
            assert_eq!(
                err.error,
                ErrorCode::InvalidDpopProof,
                "{what}: a binding mismatch is invalid_dpop_proof"
            );
        }
        other => panic!("{what}: a rotation cannot model as {other:?}"),
    }
}

/// Assert the AS's real result matches the model's verdict for a RETRY, given the response the
/// winning rotation produced.
fn assert_retry(
    what: &str,
    model: Verdict,
    actual: &Result<TokenResponse, ErrorResponse>,
    winning_response: &TokenResponse,
) {
    match model {
        Verdict::Coalesce => {
            let got = actual
                .as_ref()
                .unwrap_or_else(|e| panic!("{what}: model says the retry coalesces, got {e}"));
            assert_eq!(
                got.access_token, winning_response.access_token,
                "{what}: a coalesced retry returns the winning rotation's access token"
            );
            assert_eq!(
                got.refresh_token, winning_response.refresh_token,
                "{what}: a coalesced retry returns the winning rotation's refresh token"
            );
        }
        Verdict::DpopProof => {
            let err = actual
                .as_ref()
                .expect_err(&format!("{what}: model says the retry is refused"));
            assert_eq!(
                err.error,
                ErrorCode::InvalidDpopProof,
                "{what}: a non-winning key is refused invalid_dpop_proof, never coalesced"
            );
        }
        other => panic!("{what}: a retry cannot model as {other:?}"),
    }
}

// ------------------------------------------------------------------------------------- the driver

/// Map a symbolic [`Key`] onto a real one for this scenario.
struct Keys {
    original: EcdsaP256Key,
    rekeyed: EcdsaP256Key,
    thief: EcdsaP256Key,
}

impl Keys {
    fn fresh() -> Self {
        Keys {
            original: EcdsaP256Key::generate("original"),
            rekeyed: EcdsaP256Key::generate("rekeyed"),
            thief: EcdsaP256Key::generate("thief"),
        }
    }
    fn real(&self, k: Option<Key>) -> Option<&EcdsaP256Key> {
        k.map(|k| match k {
            Key::Original => &self.original,
            Key::Rekeyed => &self.rekeyed,
            Key::Thief => &self.thief,
        })
    }
}

// ============================================================================ 1. ROTATION matrix
//
// Public client requires an exact key match; confidential MAY re-key but presence parity holds.
// A fresh chain and server per row, because a rotation SPENDS the chain and a refusal must not be
// contaminated by a previous row's state.
#[tokio::test]
async fn rotation_group() {
    // (client, chain binding, presented proof) — the exhaustive presence/identity matrix.
    let matrix = [
        // Public: exact key match, both directions of presence.
        (ClientKind::Public, Some(Key::Original), Some(Key::Original)),
        (ClientKind::Public, Some(Key::Original), Some(Key::Thief)),
        (ClientKind::Public, Some(Key::Original), None),
        (ClientKind::Public, None, None),
        (ClientKind::Public, None, Some(Key::Original)),
        // Confidential: presence parity, re-key allowed.
        (
            ClientKind::Confidential,
            Some(Key::Original),
            Some(Key::Original),
        ),
        (
            ClientKind::Confidential,
            Some(Key::Original),
            Some(Key::Rekeyed),
        ),
        (ClientKind::Confidential, Some(Key::Original), None),
        (ClientKind::Confidential, None, None),
        (ClientKind::Confidential, None, Some(Key::Original)),
    ];

    for (client, chain, presented) in matrix {
        let what = format!("rotate {client:?} chain={chain:?} presented={presented:?}");
        let clock = ManualClock::at_epoch();
        let srv = server(clock.clone(), Duration::from_secs(30));
        srv.register_client(confidential_client()).await.unwrap();
        srv.register_client(public_client()).await.unwrap();
        let keys = Keys::fresh();

        let token = mint_chain(&srv, client, keys.real(chain), &clock).await;
        let actual = present(&srv, client, &token, keys.real(presented), &clock).await;

        let model = model_rotate(client, chain, presented);
        assert_rotation(&what, model, &actual);

        // On a successful rotation, the sender-constraint STATUS of the successor must match the
        // presented binding: a bound rotation stays Dpop, a bearer rotation stays Bearer. (For a
        // confidential client we can also introspect the exact bound key; see `rekey_binding`.)
        if let Ok(rotated) = &actual {
            let expected = if presented.is_some() {
                TokenType::Dpop
            } else {
                TokenType::Bearer
            };
            assert_eq!(rotated.token_type, expected, "{what}: successor token_type");
        }
    }
}

/// The re-key binding, asserted on the exact key. A confidential chain bound to `original`, rotated
/// onto `rekeyed`, must produce an access token bound to `rekeyed` — not to the predecessor. This
/// is the rotation-side half of the property the retry path must stay consistent with.
#[tokio::test]
async fn rekey_binding() {
    let clock = ManualClock::at_epoch();
    let srv = server(clock.clone(), Duration::from_secs(30));
    srv.register_client(confidential_client()).await.unwrap();
    let keys = Keys::fresh();

    let token = mint_chain(&srv, ClientKind::Confidential, Some(&keys.original), &clock).await;
    let rotated = present(
        &srv,
        ClientKind::Confidential,
        &token,
        Some(&keys.rekeyed),
        &clock,
    )
    .await
    .expect("a confidential client may re-key a bound chain");

    let introspected = srv
        .introspection_response(
            &ClientKind::Confidential.id(),
            Some(CONF_SECRET),
            &rotated.access_token,
        )
        .await
        .unwrap();
    assert_eq!(
        introspected.cnf.expect("a bound token reports cnf").jkt,
        Some(keys.rekeyed.to_public_jwk().thumbprint()),
        "the re-keyed successor binds to the NEW key, not the predecessor's"
    );
}

// ============================================================================ 2. RETRY matrix
//
// Retry coalescing inside the window, keyed on the WINNING rotation's binding. This is where the
// audited drift lives: for a confidential re-key the winning key is `rekeyed`, and the predecessor
// `original` must be REFUSED, not coalesced.
#[tokio::test]
async fn retry_group() {
    // (client, chain binding, rotation's presented proof == winning key)
    let scenarios = [
        // Confidential re-key: winning key is `rekeyed`. THE DISCRIMINATING SCENARIO.
        (
            ClientKind::Confidential,
            Some(Key::Original),
            Some(Key::Rekeyed),
        ),
        // Public same-key rotation: winning key is `original`.
        (ClientKind::Public, Some(Key::Original), Some(Key::Original)),
        // Bearer chain (no key anywhere): retry coalesces on a byte-identical no-proof replay.
        (ClientKind::Confidential, None, None),
        (ClientKind::Public, None, None),
    ];

    for (client, chain, winning) in scenarios {
        let head = format!("retry {client:?} chain={chain:?} winning={winning:?}");
        let clock = ManualClock::at_epoch();
        let srv = server(clock.clone(), Duration::from_secs(30));
        srv.register_client(confidential_client()).await.unwrap();
        srv.register_client(public_client()).await.unwrap();
        let keys = Keys::fresh();

        let token = mint_chain(&srv, client, keys.real(chain), &clock).await;

        // The winning rotation.
        let rotated = present(&srv, client, &token, keys.real(winning), &clock)
            .await
            .unwrap_or_else(|e| panic!("{head}: the winning rotation must succeed, got {e}"));

        // Every candidate the retry could present. `winning` coalesces; everything else with a
        // different presence/identity is refused WITHOUT revoking, so we can drive them all against
        // the SAME spent token in sequence and the winning one still coalesces at the end.
        let candidates: &[Option<Key>] = match chain {
            // Bound chains: try the predecessor, a thief key, no-proof, and the winner.
            Some(_) => &[
                Some(Key::Original),
                Some(Key::Rekeyed),
                Some(Key::Thief),
                None,
                // The winner LAST, to prove the refusals above did not revoke the family.
                // (Re-listed explicitly per scenario below.)
            ],
            // Bearer chains: try a spurious key, then the no-proof winner.
            None => &[Some(Key::Thief), None],
        };

        for &presented in candidates {
            // Advance a second between presentations so each proof's `iat` is fresh and we stay
            // comfortably inside the 30s window.
            clock.advance(Duration::from_secs(1));
            let what = format!("{head}; retry presenting {presented:?}");
            let actual = present(&srv, client, &token, keys.real(presented), &clock).await;
            let model = model_retry(winning, presented);
            assert_retry(&what, model, &actual, &rotated);
        }

        // Finally, the WINNING key again, still inside the window: it must STILL coalesce, proving
        // none of the refused retries above revoked the family.
        clock.advance(Duration::from_secs(1));
        let what = format!("{head}; final winning-key retry");
        let actual = present(&srv, client, &token, keys.real(winning), &clock).await;
        assert_retry(&what, Verdict::Coalesce, &actual, &rotated);
    }
}

// ============================================================================ 3. RETRY after the
// window falls through to reuse detection and revokes the family.
#[tokio::test]
async fn retry_after_window_revokes_the_family() {
    let clock = ManualClock::at_epoch();
    let srv = server(clock.clone(), Duration::from_secs(30));
    srv.register_client(confidential_client()).await.unwrap();
    let keys = Keys::fresh();

    let token = mint_chain(&srv, ClientKind::Confidential, Some(&keys.original), &clock).await;
    let rotated = present(
        &srv,
        ClientKind::Confidential,
        &token,
        Some(&keys.rekeyed),
        &clock,
    )
    .await
    .expect("the winning re-keying rotation succeeds");

    // Inside the window the winning-key retry coalesces (sanity: the material exists).
    clock.advance(Duration::from_secs(5));
    let inside = present(
        &srv,
        ClientKind::Confidential,
        &token,
        Some(&keys.rekeyed),
        &clock,
    )
    .await
    .expect("inside the window the winning retry coalesces");
    assert_eq!(inside.access_token, rotated.access_token);

    // Past the window, the SAME spent token — even with the correct winning key — is reuse: the
    // retry material has expired, so it falls through to reuse detection and the family dies.
    clock.advance(Duration::from_secs(40));
    let actual = present(
        &srv,
        ClientKind::Confidential,
        &token,
        Some(&keys.rekeyed),
        &clock,
    )
    .await;
    assert_reuse(
        "past the retry window a spent token is reuse",
        model_reuse(),
        &actual,
    );

    // The successor is dead too: the revocation took the whole family (RFC 9700 s4.14.2).
    let successor = rotated.refresh_token.as_deref().unwrap();
    let dead = present(
        &srv,
        ClientKind::Confidential,
        successor,
        Some(&keys.rekeyed),
        &clock,
    )
    .await;
    assert_reuse(
        "the live successor is revoked with the family",
        model_reuse(),
        &dead,
    );
    assert!(
        srv.introspect(&rotated.access_token)
            .await
            .unwrap()
            .is_none(),
        "the family's access tokens are revoked too"
    );
}

// ============================================================================ 4. REUSE with no
// retry material at all (`refresh_retry_window` = 0): a spent token re-presented is immediate reuse.
#[tokio::test]
async fn reuse_without_retry_material_revokes_the_family() {
    let clock = ManualClock::at_epoch();
    let srv = server(clock.clone(), Duration::ZERO);
    srv.register_client(confidential_client()).await.unwrap();

    // A bearer chain keeps this case about REUSE alone, with no DPoP binding in play.
    let token = mint_chain(&srv, ClientKind::Confidential, None, &clock).await;
    let rotated = present(&srv, ClientKind::Confidential, &token, None, &clock)
        .await
        .expect("the first rotation of a live token succeeds");
    let successor = rotated
        .refresh_token
        .clone()
        .expect("rotation issues a successor");

    // With no retry window, re-presenting the spent token is reuse straight away.
    let actual = present(&srv, ClientKind::Confidential, &token, None, &clock).await;
    assert_reuse(
        "a spent token with the window closed is reuse",
        model_reuse(),
        &actual,
    );

    // And the family is gone: the live successor cannot mint either (RFC 9700 s4.14.2).
    let dead = present(&srv, ClientKind::Confidential, &successor, None, &clock).await;
    assert_reuse(
        "the successor is revoked with the family",
        model_reuse(),
        &dead,
    );
}
