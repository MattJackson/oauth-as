// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT EVERY REFUSAL OF CLIENT AUTHENTICATION COSTS, as a matrix rather than as a site.
//!
//! `tests/client_auth.rs` holds one test per instance of this defect, written as each was found:
//! round 7 (an unknown id verified nothing), round 8 (a request that could not reach a verification
//! paid for one anyway), round 9 (four known-id paths that verified nothing) and round 10 (two
//! refusals inside `authenticate_by_assertion` that paid nothing). Four rounds, four fixes, four
//! findings that the fix before it was incomplete. Those tests are kept: each one pins the exact
//! request that was found leaking.
//!
//! This file asks the question they each asked once, over the WHOLE PRODUCT of the registration
//! kinds a deployment can hold and the credential shapes a caller can present. That is the shape of
//! the claim the restructure makes — `AuthorizationServer::authenticate_client` has one exit and it
//! charges unconditionally, so a refusal's cost is a function of what was PRESENTED and of nothing
//! the store holds — and a matrix is what can falsify it. A new refusal that forgets to charge shows
//! up as one cell disagreeing with its column's unknown-id control, whichever cell it is.
//!
//! # Why call counts and not a clock
//!
//! For the reason `tests/client_auth.rs` gives: what a wall clock would measure here is how many
//! times the EXPENSIVE operation was reached, and counting that directly is both exact and not
//! flaky. Both expensive operations are host seams this crate calls through, so both can be counted
//! from outside: `SecretVerifier::verify` stands in for the host's argon2id, and
//! `Es256Verifier::verify` for the ES256 backend an RFC 7523 `private_key_jwt` verification uses.
//!
//! Every registration below that verifies a secret is stored in the COUNTING verifier's own scheme,
//! so a real verification and the dummy one both go through the counter. A `ConfidentialSecret`
//! (plaintext) registration deliberately does not appear: it is compared by this crate itself with
//! `constant_time_eq` and never reaches the host seam, which is the THIRD residual documented on
//! `authenticate_client` and is a property of that variant rather than of the exit under test.

#![cfg(feature = "jwt")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::client::{SecretHash, SecretVerifier};
use oauth_as::jwt::{Es256Verifier, PublicJwk};
use oauth_as::server::{ClientCredential, TokenRequestContext};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, DynamicRegistration, ErrorCode,
    GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};

/// A hand-cranked clock, copied locally per this suite's file-ownership rules. Far past the epoch,
/// so an `client_secret_expires_at` of 1 is dead.
#[derive(Clone)]
struct ManualClock(SystemTime);

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// The two expensive operations, counted. Nothing else in this file measures anything.
#[derive(Clone, Default)]
struct Meter {
    secret: Arc<AtomicUsize>,
    es256: Arc<AtomicUsize>,
}

impl Meter {
    fn read(&self) -> (usize, usize) {
        (
            self.secret.load(Ordering::SeqCst),
            self.es256.load(Ordering::SeqCst),
        )
    }
}

/// Stands in for a host's argon2id. It answers `false` always: this file measures refusals, and
/// every registration in it is probed with a credential nobody holds.
struct CountingSecrets(Meter);

impl SecretVerifier for CountingSecrets {
    fn verify(&self, _stored: &SecretHash, _presented: &str) -> bool {
        self.0.secret.fetch_add(1, Ordering::SeqCst);
        false
    }

    fn dummy_hash(&self) -> Option<SecretHash> {
        // In this verifier's OWN scheme, which is what the method's doc asks for: one in a scheme it
        // did not recognise would be rejected on inspection and cost nothing, which is the leak the
        // method exists to close.
        Some(SecretHash::custom("host-scheme", "nobody-holds-this"))
    }
}

/// Stands in for the ES256 backend. `false` always, for the same reason.
struct CountingEs256(Meter);

impl Es256Verifier for CountingEs256 {
    fn verify(&self, _key: &PublicJwk, _signing_input: &[u8], _signature: &[u8]) -> bool {
        self.0.es256.fetch_add(1, Ordering::SeqCst);
        false
    }
}

/// The registration kind under probe. `Unknown` is the CONTROL: it registers nothing, so the
/// server's answer for it is the one every other row must match.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Registration {
    /// No registration at all. The control.
    Unknown,
    /// RFC 6749 s2.3 public: `verify_with` refuses a presented secret without hashing.
    Public,
    /// A confidential registration in the host's scheme, which really does verify.
    HostScheme,
    /// RFC 7591 s3.2.1: a secret this server itself declared dead. Refused before every credential
    /// branch.
    Expired,
    /// RFC 7523: authenticates by signed assertion, never by a presented secret.
    #[cfg(feature = "client-assertion")]
    Assertion,
    /// RFC 8705: authenticates by certificate, and holds no secret at all.
    #[cfg(feature = "mtls")]
    Mtls,
}

/// The credential shape a caller PRESENTS. This is the only thing a refusal's cost is allowed to
/// depend on, which is what the assertions below check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Presented {
    /// Nothing at all: no secret, no assertion.
    Nothing,
    /// A junk `client_secret`, which is what a registry-enumeration probe sends.
    JunkSecret,
    /// A junk assertion with the RFC 7521 s4.2 type this server implements: the shape a
    /// `private_key_jwt` request has.
    #[cfg(feature = "client-assertion")]
    Assertion,
    /// A junk assertion carrying a type nobody registered, which is refused before any decoding.
    #[cfg(feature = "client-assertion")]
    AssertionWrongType,
    /// Both at once, which RFC 6749 s2.3 forbids: the round-10 probe.
    #[cfg(feature = "client-assertion")]
    AssertionAndSecret,
}

const CLIENT: &str = "probed-client";

fn client_with(auth: ClientAuth, registration: Option<DynamicRegistration>) -> Client {
    Client {
        client_id: ClientId::new(CLIENT),
        auth,
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: registration.map(Box::new),
    }
}

fn registration_fixture(kind: Registration) -> Option<Client> {
    match kind {
        Registration::Unknown => None,
        Registration::Public => Some(client_with(ClientAuth::Public, None)),
        Registration::HostScheme => Some(client_with(
            ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::custom("host-scheme", "whatever-the-host-stored"),
            },
            None,
        )),
        Registration::Expired => Some(client_with(
            ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::custom("host-scheme", "whatever-the-host-stored"),
            },
            Some(DynamicRegistration {
                registration_access_token_hash: SecretHash::sha256("unused-for-this-probe"),
                client_id_issued_at: Some(0),
                // Dead one second past the epoch; the clock above is far beyond that.
                client_secret_expires_at: Some(1),
                token_endpoint_auth_method: "client_secret_post".to_string(),
            }),
        )),
        #[cfg(feature = "client-assertion")]
        Registration::Assertion => {
            use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey};

            Some(client_with(
                ClientAuth::ConfidentialAssertion {
                    keys: AssertionKeys::ClientSecret {
                        secret: ClientSecretKey::new("a-secret-long-enough-to-clear-the-floor")
                            .expect("fixture secret clears the entropy floor"),
                    },
                },
                None,
            ))
        }
        #[cfg(feature = "mtls")]
        Registration::Mtls => {
            use oauth_as::mtls::{ExpectedSubject, MtlsClientRegistration};

            Some(client_with(
                ClientAuth::Mtls {
                    registration: MtlsClientRegistration::TlsClientAuth(ExpectedSubject::SanDns(
                        "probed.example".to_string(),
                    )),
                },
                None,
            ))
        }
    }
}

/// Run ONE probe against a server holding `kind`, and report what the two seams were asked to do.
///
/// The refusal itself is asserted here rather than in the caller: a cell that stopped REFUSING
/// would otherwise pass the cost comparison by accident, which is the failure mode a matrix is
/// worst at noticing.
async fn cost(kind: Registration, presented: Presented) -> (usize, usize) {
    let meter = Meter::default();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(
        cfg,
        MemoryStorage::new(),
        ManualClock(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
    )
    .with_secret_verifier(Box::new(CountingSecrets(meter.clone())))
    .with_es256_verifier(Arc::new(CountingEs256(meter.clone())));
    if let Some(client) = registration_fixture(kind) {
        srv.register_client(client).await.unwrap();
    }

    #[allow(unused_mut)]
    let mut cred = ClientCredential::secret(match presented {
        Presented::JunkSecret => Some("junk-secret"),
        #[cfg(feature = "client-assertion")]
        Presented::AssertionAndSecret => Some("junk-secret"),
        _ => None,
    });
    #[cfg(feature = "client-assertion")]
    match presented {
        Presented::Assertion | Presented::AssertionAndSecret => {
            cred.client_assertion = Some("x.y.z");
            cred.client_assertion_type = Some(oauth_as::CLIENT_ASSERTION_TYPE);
        }
        Presented::AssertionWrongType => {
            cred.client_assertion = Some("x.y.z");
            cred.client_assertion_type = Some("urn:example:not-a-real-assertion-type");
        }
        Presented::Nothing | Presented::JunkSecret => {}
    }

    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new(CLIENT),
                client_secret: None,
                scope: None,
            },
            TokenRequestContext::new(cred),
        )
        .await
        .expect_err("every cell of this matrix must be refused");
    assert_eq!(
        refused.error,
        ErrorCode::InvalidClient,
        "{kind:?} presented {presented:?}: every one of these is the same bare invalid_client"
    );
    meter.read()
}

/// THE MATRIX. Every registration kind, against every credential shape, compared with the unknown
/// id sending the identical bytes.
///
/// The single exit is what makes this hold: nothing in the credential path refuses on its own any
/// more, so a cell cannot be cheap because its branch forgot to charge. A `return` added anywhere
/// in `classify_client_credential` that goes to the wire directly, rather than handing back a
/// `ClientAuthVerdict::Refused`, turns its column red.
#[tokio::test]
async fn every_refusal_costs_what_the_unknown_id_costs_for_the_same_request() {
    let registrations = [
        Registration::Public,
        Registration::HostScheme,
        Registration::Expired,
        #[cfg(feature = "client-assertion")]
        Registration::Assertion,
        #[cfg(feature = "mtls")]
        Registration::Mtls,
    ];
    let presentations = [
        Presented::Nothing,
        Presented::JunkSecret,
        #[cfg(feature = "client-assertion")]
        Presented::Assertion,
        #[cfg(feature = "client-assertion")]
        Presented::AssertionWrongType,
        #[cfg(feature = "client-assertion")]
        Presented::AssertionAndSecret,
    ];

    let mut disagreements = Vec::new();
    for presented in presentations {
        let control = cost(Registration::Unknown, presented).await;
        for kind in registrations {
            // THE ONE KNOWN GAP, pinned rather than hidden. An assertion-registered client handed a
            // MALFORMED assertion is refused by `verify_assertion` before it reaches any signature
            // work, so it pays nothing while the unknown id pays one dummy verification. That is
            // the FOURTH residual documented on `authenticate_client`: closing it needs
            // `verify_assertion` to report whether it reached the signature, which is a change to a
            // public function rather than to the exit this file is about. If this cell ever starts
            // AGREEING, that residual has been closed and this exception must be deleted — which is
            // why it is written as an expectation rather than as a skip.
            #[cfg(feature = "client-assertion")]
            if kind == Registration::Assertion && presented == Presented::Assertion {
                let observed = cost(kind, presented).await;
                assert_eq!(
                    (observed, control),
                    ((0, 0), (0, 1)),
                    "the FOURTH residual on authenticate_client has changed shape: an assertion \
                     registration handed a malformed assertion paid {observed:?} against the \
                     unknown id's {control:?}"
                );
                continue;
            }
            let observed = cost(kind, presented).await;
            if observed != control {
                disagreements.push(format!(
                    "  {kind:?} presenting {presented:?}: (secret, es256) = {observed:?}, \
                     unknown id = {control:?}"
                ));
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "a refusal must cost what the unknown-id refusal costs for the SAME request, or the token \
         endpoint tells an attacker which client ids are registered:\n{}",
        disagreements.join("\n")
    );
}

/// The other half of the same property, and the one a matrix of refusals cannot see: a refusal must
/// not cost MORE than the unknown id either, and the exit must not charge a request that COULD NOT
/// have reached a verification on either path.
///
/// This is round 8's finding stated as a rule rather than as an instance. A request carrying an
/// assertion with a type nobody registered is refused before any decoding whoever sent it, so
/// neither path may pay for a verification; charging the unknown one leaked the same bit pointing
/// the other way.
#[tokio::test]
async fn a_request_that_could_not_reach_a_verification_pays_for_nothing() {
    assert_eq!(
        cost(Registration::Unknown, Presented::Nothing).await,
        (0, 0),
        "a request presenting no credential at all has nothing to verify"
    );
    #[cfg(feature = "client-assertion")]
    assert_eq!(
        cost(Registration::Unknown, Presented::AssertionWrongType).await,
        (0, 0),
        "an unregistered RFC 7521 s4.2 assertion type is refused before any decoding, so it must \
         not buy a verification"
    );
}

/// THE RATE-LIMIT GATE IS NOT ONE OF THE REFUSALS THE EXIT OWNS, and this pins the reason.
///
/// It answers from a public `client_id` and nothing else, before the store is touched, so it cannot
/// vary with a fact about a registration — and it must stay free. Past the failure ceiling
/// (`CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR`) a denial is what an attacker buys at
/// `ATTEMPT_COST` apiece, thousands per window per client id, so routing it through the charging
/// exit would sell them the host's password hashing at that price.
#[tokio::test]
async fn a_throttled_attempt_buys_no_verification() {
    use oauth_as::events::{Attempt, AttemptOutcome, RateLimitDecision, RateLimiter};

    /// Denies everything, which is the state the gate exists for.
    struct DenyAll;
    impl RateLimiter for DenyAll {
        fn check(&self, _attempt: Attempt<'_>) -> RateLimitDecision {
            RateLimitDecision::Deny
        }
        fn record(&self, _attempt: Attempt<'_>, _outcome: AttemptOutcome) {}
    }

    let meter = Meter::default();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(
        cfg,
        MemoryStorage::new(),
        ManualClock(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
    )
    .with_secret_verifier(Box::new(CountingSecrets(meter.clone())))
    .with_es256_verifier(Arc::new(CountingEs256(meter.clone())))
    .with_rate_limiter(Box::new(DenyAll));

    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new(CLIENT),
                client_secret: None,
                scope: None,
            },
            TokenRequestContext::new(ClientCredential::secret(Some("junk-secret"))),
        )
        .await
        .expect_err("a denied attempt is refused");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
    assert_eq!(
        meter.read(),
        (0, 0),
        "a throttled attempt must not buy the host's verification work: that is what the failure \
         ceiling exists to bound"
    );
}
