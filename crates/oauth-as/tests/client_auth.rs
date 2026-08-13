// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 6749 section 2.3 client authentication: the public/confidential split, and the boundary
//! that keeps the token endpoint from being usable to enumerate registered client ids.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode, GrantType, MemoryStorage,
    ScopeSet, ServerConfig, TokenRequest,
};

/// A hand-cranked clock shared between the test and the server under test. Copied locally (per
/// this suite's file-ownership rules) rather than shared, so this file has no dependency on
/// `tests/support`.
#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

const SECRET: &str = "hunter2-correct-secret";

/// A public client: no secret exists for it at all.
fn public_client() -> Client {
    Client {
        client_id: ClientId::new("public-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A confidential client holding `SECRET`, registered for every grant type so each grant's
/// authentication path is reachable through one fixture.
fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("confidential-client"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
        ],
        redirect_uris: vec!["https://app.example/cb".into()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A confidential client registered for NO grant type at all, so every grant request against it
/// must fail on the registration check, never on authentication (its secret is presented
/// correctly by every test that uses it).
fn no_grants_client() -> Client {
    Client {
        client_id: ClientId::new("no-grants-client"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server_with(clients: Vec<Client>) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}

// ------------------------------------------------------------ ClientAuth::verify boundary cases

/// RFC 6749 section 2.3: a public client has no secret, so presenting one proves nothing and is
/// refused outright, not merely ignored. Accepting any presented secret for a public client would
/// let a client mixup (a caller that thinks it is confidential, talking to a registration that
/// isn't) through silently.
#[test]
fn public_client_accepts_no_secret_and_rejects_any_presented_secret() {
    let auth = ClientAuth::Public;
    assert!(
        auth.verify(None),
        "no secret presented: the only correct case for a public client"
    );
    assert!(
        !auth.verify(Some("")),
        "an empty presented secret is still a presented secret"
    );
    assert!(!auth.verify(Some("anything")));
    assert!(
        !auth.verify(Some(SECRET)),
        "even a string equal to another client's real secret"
    );
}

/// RFC 6749 section 2.3: a confidential client's secret must match exactly. Every near miss that
/// a lazy `starts_with` or length-truncated comparison would let through is exercised here.
#[test]
fn confidential_client_requires_the_exact_secret() {
    let auth = ClientAuth::ConfidentialSecret {
        secret: SECRET.into(),
    };
    assert!(auth.verify(Some(SECRET)), "the exact secret must succeed");
    assert!(!auth.verify(None), "no secret presented");
    assert!(!auth.verify(Some("")), "empty secret presented");
    assert!(
        !auth.verify(Some(&SECRET[..SECRET.len() - 1])),
        "a correct prefix, one byte short, must not verify"
    );
    assert!(
        !auth.verify(Some(&format!("{SECRET}x"))),
        "a superstring of the real secret (the real secret plus one byte) must not verify"
    );
    assert!(
        !auth.verify(Some(&SECRET.to_uppercase())),
        "secrets are compared byte for byte, not case-insensitively"
    );
    assert!(!auth.verify(Some("totally-different")));
}

// -------------------------------------------------------------- AuthorizationServer level

/// The same public/confidential boundary, exercised through the token endpoint rather than
/// `ClientAuth::verify` directly: a public client's device-authorization request carrying a
/// secret it was never issued is refused as `invalid_client`.
#[tokio::test]
async fn public_client_presenting_a_secret_at_the_server_is_invalid_client() {
    let srv = server_with(vec![public_client()]).await;
    let err = srv
        .device_authorization(&ClientId::new("public-client"), Some("unexpected"), None)
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidClient);
    assert_eq!(err.http_status(), 401);
}

/// RFC 6749 section 2.3 / RFC 6749 section 5.2: an unknown `client_id` and a known client with the
/// wrong secret must be INDISTINGUISHABLE at the token endpoint. If they produced different
/// errors, a caller could use the token endpoint as an oracle to enumerate which client ids are
/// registered by testing candidate ids with a wrong secret and watching for the error to change.
/// This compares the full `ErrorResponse` value (code, description, and uri), not just the code,
/// because a differing description would leak the same distinction through a side channel.
#[tokio::test]
async fn unknown_client_id_and_wrong_secret_produce_the_identical_error() {
    let srv = server_with(vec![confidential_client()]).await;

    let unknown_id = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("this-client-id-was-never-registered"),
            client_secret: Some("does-not-matter".into()),
            scope: None,
        })
        .await
        .unwrap_err();

    let wrong_secret = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-client"),
            client_secret: Some("wrong-secret".into()),
            scope: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        unknown_id, wrong_secret,
        "an unknown client_id and a known client with a wrong secret must be the same error \
         value in every field, or the token endpoint becomes a client-id oracle"
    );
    assert_eq!(unknown_id.error, ErrorCode::InvalidClient);
    assert_eq!(unknown_id.http_status(), 401);

    // The same equality holds when no secret at all is presented for the known client, so a
    // caller cannot distinguish "unknown id" from "known id, no credential" either.
    let no_secret = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-client"),
            client_secret: None,
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(unknown_id, no_secret);
}

/// The same enumeration-resistance property holds on the device-authorization path, which
/// authenticates a client before any grant exists to look up.
#[tokio::test]
async fn unknown_client_id_and_wrong_secret_agree_on_the_device_authorization_path() {
    let srv = server_with(vec![confidential_client()]).await;

    let unknown_id = srv
        .device_authorization(
            &ClientId::new("also-never-registered"),
            Some("irrelevant"),
            None,
        )
        .await
        .unwrap_err();
    let wrong_secret = srv
        .device_authorization(
            &ClientId::new("confidential-client"),
            Some("wrong-secret"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(unknown_id, wrong_secret);
}

/// RFC 6749 section 3.3 / section 4: a client is refused any grant its registration does not
/// list, and the refusal is `unauthorized_client`, distinct from `invalid_client`. This is
/// checked across every grant type this crate implements: authorization_code, client_credentials,
/// the device code grant, and refresh_token. The fixture client authenticates correctly every
/// time (its secret is presented), so a failure here can only be the registration check, not a
/// mislabeled authentication failure.
#[tokio::test]
async fn client_without_the_grant_in_its_registration_is_unauthorized_client_for_every_grant_type()
{
    let srv = server_with(vec![no_grants_client()]).await;
    let client_id = ClientId::new("no-grants-client");

    let authorization_code = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            code: "irrelevant-code".into(),
            redirect_uri: None,
            code_verifier: None,
        })
        .await
        .unwrap_err();
    assert_eq!(authorization_code.error, ErrorCode::UnauthorizedClient);

    let client_credentials = srv
        .token(TokenRequest::ClientCredentials {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(client_credentials.error, ErrorCode::UnauthorizedClient);

    let device_code = srv
        .token(TokenRequest::DeviceCode {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            device_code: "irrelevant-device-code".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(device_code.error, ErrorCode::UnauthorizedClient);

    let refresh_token = srv
        .token(TokenRequest::RefreshToken {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            refresh_token: "irrelevant-refresh-token".into(),
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(refresh_token.error, ErrorCode::UnauthorizedClient);

    // The device-authorization endpoint (not a `token()` request, but the same registration
    // check) refuses the same way.
    let device_authorization = srv
        .device_authorization(&client_id, Some(SECRET), None)
        .await
        .unwrap_err();
    assert_eq!(device_authorization.error, ErrorCode::UnauthorizedClient);
}

// --------------------------------------------------- what the AUDIT channel is told, and how much

/// A sink that keeps every event it is shown, so a test can ask what an operator would have seen.
///
/// Gated on the two features whose tests use it: without either, the audit-channel questions below
/// do not exist, and an unused item is a warning this workspace treats as an error.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[derive(Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

#[cfg(any(feature = "client-assertion", feature = "dpop"))]
impl oauth_as::events::EventSink for Recorder {
    fn on_event(&self, event: oauth_as::events::Event<'_>) {
        self.0.lock().unwrap().push(format!("{event:?}"));
    }
}

/// RFC 7523 assertion failures collapse to one `invalid_client` ON THE WIRE, deliberately. The
/// HOST's audit channel is a different reader, and `AssertionFailure` documents itself as existing
/// for exactly that: "the distinction exists for the host's audit channel, where the reader is not
/// the attacker". Through 0.9.1 the server threw the reason away — `.map_err(|_| refused())` — so
/// the sink was handed a constant with no payload, and the promise was in writing twice while the
/// code kept it nowhere.
///
/// What an operator loses without it: a burst of `AssertionInvalid` for one client is
/// indistinguishable between a clock skewed past the leeway (`Expired`/`NotYetValid` — fix NTP), a
/// key rotation the registration did not follow (`BadSignature` — fix the registration), and
/// assertions captured at another authorization server and replayed here (`WrongAudience` — an
/// incident). The mutual-TLS arm eleven lines away already forwarded its failure verbatim, which is
/// how this was found: it is an omission, not a second deliberate collapse.
///
/// TWO DISTINCT REASONS are asserted rather than one. A single reason would pass against a
/// hard-coded constant, which is the defect.
#[cfg(feature = "client-assertion")]
#[tokio::test]
async fn an_assertion_refusal_tells_the_audit_channel_which_check_failed() {
    use oauth_as::client_assertion::AssertionFailure;
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let srv = server_with(vec![confidential_client()])
        .await
        .with_event_sink(Box::new(Recorder(seen.clone())));
    let client_id = ClientId::new("confidential-client");

    // REASON ONE: the RFC 7521 s4.2 `client_assertion_type` is not the one this server implements,
    // so nothing is decoded at all.
    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: client_id.clone(),
                client_secret: None,
                scope: None,
            },
            TokenRequestContext::new(ClientCredential::assertion(
                Some("urn:example:some-other-assertion-format"),
                "not.a.jwt",
            )),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refused.error,
        ErrorCode::InvalidClient,
        "the WIRE collapse is unchanged: that is the half that must not move"
    );
    assert!(
        refused.error_description.is_none(),
        "and the wire still says nothing about which check failed"
    );

    // REASON TWO: the right type, but this registration authenticates with a shared secret, so
    // there is no key any assertion of its could have been signed with.
    srv.token_with_context(
        TokenRequest::ClientCredentials {
            client_id,
            client_secret: None,
            scope: None,
        },
        TokenRequestContext::new(ClientCredential::assertion(
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            "not.a.jwt",
        )),
    )
    .await
    .unwrap_err();

    let events = seen.lock().unwrap().clone();
    let malformed = format!("{}", AssertionFailure::Malformed);
    let wrong_principal = format!("{}", AssertionFailure::WrongPrincipal);
    assert!(
        events.iter().any(|e| e.contains("Malformed")),
        "the first refusal must reach the sink as its own reason ({malformed}), got {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("WrongPrincipal")),
        "and the second as a DIFFERENT one ({wrong_principal}); one reason for both is the \
         collapse this test exists to forbid, got {events:?}"
    );
}

/// The same promise, made in `dpop.rs` ("the distinction here is for the host's audit channel, not
/// for the wire") and kept even less well: the reason was discarded AND no event was emitted at
/// all, so a deployment running RFC 9449 learned nothing whatever about refused proofs. An operator
/// could not tell a fleet with a skewed clock from proofs being captured and replayed.
/// `jwt-p256` as well as `dpop`, because reaching `verify_proof` at all needs an ES256 backend:
/// without one the refusal happens a step earlier, and that refusal has its own test below.
#[cfg(all(feature = "dpop", feature = "jwt-p256"))]
#[tokio::test]
async fn a_refused_dpop_proof_reaches_the_audit_channel_with_its_reason() {
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let srv = server_with(vec![confidential_client()])
        .await
        .with_event_sink(Box::new(Recorder(seen.clone())));

    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-client"),
                client_secret: Some(SECRET.into()),
                scope: None,
            },
            TokenRequestContext::new(ClientCredential::secret(Some(SECRET)))
                .with_dpop_proof("this-is-not-a-compact-jws"),
        )
        .await
        .unwrap_err();
    // The wire answer is unchanged: RFC 9449 s5 makes every one of these `invalid_dpop_proof`.
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    let events = seen.lock().unwrap().clone();
    assert!(
        events.iter().any(|e| e.contains("DpopProofRefused")),
        "a refused proof must be reported at all; through 0.9.0 nothing was emitted, got {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("Malformed")),
        "and it must carry WHICH check failed, or the event is the same non-answer the wire gives: \
         {events:?}"
    );
}

// ------------------------------------------- a storage outage is not an attack, and must not read as one

/// [`MemoryStorage`] with one fault: `claim_replay_id` fails, which is what a replay table behind a
/// database briefly does. Every other method delegates, so the assertion under test verifies fully
/// and fails at exactly the step this fixture breaks.
// Gated on BOTH features, matching its single construction site: the test that uses it needs
// `jwt-p256` to mint the key it signs the assertion with. Gated on `client-assertion` alone, a
// build with the assertion feature and no ES256 backend compiles a struct nothing constructs, and
// `-D warnings` makes that dead code an error rather than a lint.
#[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
struct ReplayStoreOutage(MemoryStorage);

#[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
impl oauth_as::Storage for ReplayStoreOutage {
    async fn claim_replay_id(
        &self,
        _id: &str,
        _expires_at: SystemTime,
    ) -> Result<bool, oauth_as::store::StorageError> {
        Err(oauth_as::store::StorageError::new(
            "the replay table is unreachable",
        ))
    }

    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<Arc<Client>>, oauth_as::store::StorageError> {
        self.0.get_client(client_id).await
    }
    async fn put_client(&self, client: Client) -> Result<(), oauth_as::store::StorageError> {
        self.0.put_client(client).await
    }
    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, oauth_as::store::StorageError> {
        self.0.compare_and_swap_client(expected, updated).await
    }
    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<bool, oauth_as::store::StorageError> {
        self.0.delete_client(client_id, window).await
    }
    async fn put_device_grant(
        &self,
        grant: oauth_as::device::DeviceGrant,
    ) -> Result<(), oauth_as::store::StorageError> {
        self.0.put_device_grant(grant).await
    }
    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<oauth_as::device::DeviceGrant>, oauth_as::store::StorageError> {
        self.0.get_device_grant(device_code).await
    }
    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<oauth_as::device::DeviceGrant>, oauth_as::store::StorageError> {
        self.0
            .find_device_grant_by_user_code(normalized_user_code)
            .await
    }
    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<oauth_as::device::DeviceGrant>, oauth_as::store::StorageError> {
        self.0.take_device_grant(device_code).await
    }
    async fn compare_and_swap_device_grant(
        &self,
        expected: &oauth_as::device::DeviceGrantState,
        updated: oauth_as::device::DeviceGrant,
    ) -> Result<bool, oauth_as::store::StorageError> {
        self.0
            .compare_and_swap_device_grant(expected, updated)
            .await
    }
    async fn put_authorization_code(
        &self,
        record: oauth_as::authorization::AuthorizationCodeRecord,
    ) -> Result<(), oauth_as::store::StorageError> {
        self.0.put_authorization_code(record).await
    }
    async fn compare_and_swap_authorization_code(
        &self,
        expected: &oauth_as::authorization::AuthorizationCodeState,
        updated: oauth_as::authorization::AuthorizationCodeRecord,
    ) -> Result<bool, oauth_as::store::StorageError> {
        self.0
            .compare_and_swap_authorization_code(expected, updated)
            .await
    }
    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<
        Option<oauth_as::authorization::AuthorizationCodeRecord>,
        oauth_as::store::StorageError,
    > {
        self.0.take_authorization_code(code).await
    }
    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> Result<oauth_as::store::WriteOutcome, oauth_as::store::StorageError> {
        self.0.put_pushed_authorization_request(record).await
    }
    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::par::PushedAuthorizationRequest>, oauth_as::store::StorageError>
    {
        self.0.take_pushed_authorization_request(request_uri).await
    }
    async fn put_token(
        &self,
        token: oauth_as::token::IssuedToken,
    ) -> Result<oauth_as::store::WriteOutcome, oauth_as::store::StorageError> {
        self.0.put_token(token).await
    }
    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Arc<oauth_as::token::IssuedToken>>, oauth_as::store::StorageError> {
        self.0.get_token(access_token).await
    }
    async fn delete_token(&self, access_token: &str) -> Result<(), oauth_as::store::StorageError> {
        self.0.delete_token(access_token).await
    }
    async fn put_refresh_token(
        &self,
        record: oauth_as::token::RefreshTokenRecord,
    ) -> Result<oauth_as::store::WriteOutcome, oauth_as::store::StorageError> {
        self.0.put_refresh_token(record).await
    }
    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Arc<oauth_as::token::RefreshTokenRecord>>, oauth_as::store::StorageError>
    {
        self.0.get_refresh_token(refresh_token).await
    }
    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<oauth_as::token::RefreshTokenRecord>, oauth_as::store::StorageError> {
        self.0.take_refresh_token(refresh_token).await
    }
    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, oauth_as::store::StorageError> {
        self.0.revoke_token_family(family_id, window).await
    }
    #[cfg(feature = "consent")]
    async fn put_consent(
        &self,
        record: oauth_as::consent::ConsentRecord,
    ) -> Result<(), oauth_as::store::StorageError> {
        self.0.put_consent(record).await
    }
    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent(
        &self,
        expected: Option<&oauth_as::consent::ConsentRecord>,
        updated: oauth_as::consent::ConsentRecord,
    ) -> Result<bool, oauth_as::store::StorageError> {
        self.0.compare_and_swap_consent(expected, updated).await
    }
    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<Arc<oauth_as::consent::ConsentRecord>>, oauth_as::store::StorageError> {
        self.0.get_consent(consent_id).await
    }
    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<Arc<oauth_as::consent::ConsentRecord>>, oauth_as::store::StorageError> {
        self.0.find_consent(client_id, subject).await
    }
    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<Arc<oauth_as::consent::ConsentRecord>>, oauth_as::store::StorageError> {
        self.0.consents_for_subject(subject).await
    }
    #[cfg(feature = "consent")]
    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, oauth_as::store::StorageError> {
        self.0.revoke_consent(consent_id, window).await
    }
    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, oauth_as::store::StorageError> {
        self.0.sweep_expired(now).await
    }
}

/// FAILING CLOSED is right; calling it a replay is not.
///
/// RFC 7523 section 3 single use is enforced by `claim_replay_id`, and a claim that could not be
/// recorded must refuse the assertion — treating a storage outage as "probably fine" would make
/// every assertion replayable for the duration of the outage. What must NOT happen is the audit
/// channel being told this was `AssertionFailure::Replayed`, whose own doc says the `jti` "has been
/// seen before within the assertion's own validity window" and which `Event::ClientAuthFailure`
/// documents as "somebody who has captured a client's traffic, which is a different incident and a
/// much worse one". A store outage fails EVERY `private_key_jwt` client at once, so the mislabel
/// does not produce one misleading event, it produces a burst of the crate's worst-incident signal
/// at exactly the moment an operator is reading the audit channel to find out what broke.
///
/// The DPoP twin of this call propagates the same store failure with `map_err(storage_error)`.
#[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
#[tokio::test]
async fn a_replay_store_outage_is_not_reported_as_a_captured_and_replayed_assertion() {
    use oauth_as::client_assertion::AssertionKeys;
    use oauth_as::jwt::{compact_jws, EcdsaP256Key};
    use oauth_as::server::{ClientCredential, TokenRequestContext};
    use oauth_as::Storage as _;

    let key = EcdsaP256Key::generate("client-key");
    let store = ReplayStoreOutage(MemoryStorage::new());
    store
        .put_client(Client {
            client_id: ClientId::new("pkjwt"),
            auth: ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::PublicKeys {
                    keys: vec![key.to_public_jwk()],
                },
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        store,
    )
    .with_event_sink(Box::new(Recorder(seen.clone())));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({
        "iss": "pkjwt",
        "sub": "pkjwt",
        "aud": "https://as.example/token",
        "exp": now + 120,
        "iat": now,
        "jti": "a-1",
    });
    let assertion = compact_jws(
        br#"{"alg":"ES256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    );

    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("pkjwt"),
                client_secret: None,
                scope: None,
            },
            TokenRequestContext::new(ClientCredential::assertion(
                Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                &assertion,
            )),
        )
        .await
        .expect_err("a claim that could not be recorded fails closed");
    assert_eq!(
        refused.error,
        ErrorCode::InvalidClient,
        "the WIRE answer is unchanged: failing closed is the correct posture"
    );

    let events = seen.lock().unwrap().clone();
    assert!(
        events.iter().any(|e| e.contains("AssertionInvalid")),
        "the refusal must still reach the audit channel: {events:?}"
    );
    assert!(
        !events.iter().any(|e| e.contains("Replayed")),
        "a store outage must not be reported as a captured-and-replayed assertion: {events:?}"
    );
}

// ------------------------------------------- the DPoP refusals that reached NO audit channel at all

/// A build with `dpop` and no ES256 backend refuses EVERY proof, and through 0.9.0 it did so in
/// total silence: the one refusal that means the DEPLOYMENT is misconfigured rather than the client
/// was the one the audit channel never heard about. `jwt` carries the verifier SEAM and `jwt-p256`
/// carries the arithmetic, so this configuration is supported and reachable, which is why this test
/// exists in the shape it does: it can only run where the fallback verifier is not compiled in.
#[cfg(all(feature = "dpop", not(feature = "jwt-p256")))]
#[tokio::test]
async fn a_proof_refused_for_want_of_a_verifier_still_reaches_the_audit_channel() {
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let srv = server_with(vec![confidential_client()])
        .await
        .with_event_sink(Box::new(Recorder(seen.clone())));

    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-client"),
                client_secret: Some(SECRET.into()),
                scope: None,
            },
            TokenRequestContext::new(ClientCredential::secret(Some(SECRET)))
                .with_dpop_proof("any.proof.at.all"),
        )
        .await
        .unwrap_err();
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    let events = seen.lock().unwrap().clone();
    assert!(
        events.iter().any(|e| e.contains("DpopProofRefused")),
        "a deployment refusing every proof for want of a backend must be able to SEE that: \
         {events:?}"
    );
}

/// The three DPoP refusals the HTTP service performs for itself, before `AuthorizationServer` sees
/// the proof at all: two `DPoP` headers, a header that is not visible ASCII, and a proof presented
/// with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, which cannot bind a token.
/// All three are correct refusals and all three emitted NOTHING through 0.9.0, so the event
/// `Event::DpopProofRefused` documents as existing to tell failure modes apart was absent for every
/// failure mode the service, rather than the verifier, decides.
#[cfg(all(feature = "http", feature = "dpop", feature = "token-exchange"))]
#[tokio::test]
async fn the_service_s_own_dpop_refusals_reach_the_audit_channel() {
    use oauth_as::http::{Body, ServiceBuilder};

    async fn events_for(extra: Vec<(&str, Vec<u8>)>, body: String) -> Vec<String> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let srv = server_with(vec![confidential_client()])
            .await
            .with_event_sink(Box::new(Recorder(seen.clone())));
        let service = ServiceBuilder::new(Arc::new(srv)).build().expect("service");

        let mut request = http::Request::builder()
            .method("POST")
            .uri("/token")
            .header("content-type", "application/x-www-form-urlencoded");
        for (name, value) in extra {
            request = request.header(name, http::HeaderValue::from_bytes(&value).unwrap());
        }
        let response = service
            .handle(
                request
                    .body(Body::from(body))
                    .expect("a well-formed request"),
            )
            .await;
        assert_eq!(
            response.status(),
            http::StatusCode::BAD_REQUEST,
            "the wire answer is unchanged: RFC 9449 s5 invalid_dpop_proof"
        );
        let events = seen.lock().unwrap().clone();
        events
    }

    let credentials = format!(
        "grant_type=client_credentials&client_id=confidential-client&client_secret={SECRET}"
    );

    // ONE: two proofs, which RFC 9449 s4.3 leaves ambiguous and this service refuses.
    let events = events_for(
        vec![
            ("DPoP", b"first.proof.here".to_vec()),
            ("DPoP", b"second.proof.here".to_vec()),
        ],
        credentials.clone(),
    )
    .await;
    assert!(
        events.iter().any(|e| e.contains("DpopProofRefused")),
        "two DPoP headers must reach the audit channel: {events:?}"
    );

    // TWO: a header that is not visible ASCII, so it cannot be a compact JWS.
    let events = events_for(vec![("DPoP", vec![0x80, 0x81])], credentials).await;
    assert!(
        events.iter().any(|e| e.contains("DpopProofRefused")),
        "a non-ASCII DPoP header must reach the audit channel: {events:?}"
    );

    // THREE: RFC 8693 token exchange, which this server cannot issue a bound token for, so a proof
    // is refused rather than silently ignored.
    let events = events_for(
        vec![("DPoP", b"a.proof.here".to_vec())],
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=confidential-client\
             &client_secret={SECRET}&subject_token=x&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
    )
    .await;
    assert!(
        events.iter().any(|e| e.contains("DpopProofRefused")),
        "a proof sent with token exchange must reach the audit channel: {events:?}"
    );
}

/// The timing collapse `dummy_verify` performs for SECRETS, on the path that has no secret.
///
/// An RFC 7523 `private_key_jwt` request carries a `client_assertion` and no `client_secret` —
/// `authenticate_by_assertion` refuses a request carrying both — so `dummy_verify(None)` returned
/// without doing anything, and its doc's justification ("`verify_with` answers `false` for a
/// confidential registration with no secret presented without verifying anything either") is true
/// only of the secret path. On the assertion path a KNOWN id pays a real ES256 verification, which
/// this crate's own docs price at about 133 microseconds, and an UNKNOWN id paid one store read.
/// The probed id is attacker-chosen and free: the HTTP layer reads it from the UNSIGNED `sub` of
/// the assertion, and a garbage signature never reaches `claim_replay_id`, so the probe is
/// repeatable and averageable while per-id throttling sees one request per candidate.
///
/// What is asserted is the CALL COUNT rather than a wall clock: the clock is what the call is made
/// of, and a wall-clock assertion would be flaky on shared CI. Two requests, two verifications.
#[cfg(feature = "client-assertion")]
#[tokio::test]
async fn an_unknown_client_id_costs_an_es256_verification_on_the_assertion_path_too() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oauth_as::client_assertion::AssertionKeys;
    use oauth_as::jwt::{Es256Verifier, Jwk, PublicJwk};
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    struct Counting(Arc<AtomicUsize>);
    impl Es256Verifier for Counting {
        fn verify(&self, _key: &PublicJwk, _signing_input: &[u8], _signature: &[u8]) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            // Never authenticates anything. The property under test is the COST, and a verifier
            // that said yes would be answering about a client nobody registered.
            false
        }
    }

    // A key of the shape a `private_key_jwt` registration holds. Its coordinates are a real P-256
    // point so that nothing refuses it before the verifier is reached.
    let registered = Jwk {
        kty: "EC",
        crv: "P-256",
        x: "LIZkYOSRaSLc5uMxzlzV9pgt1ARaDl_3tZfRkt9mzFY".to_string(),
        y: "fBSzqWfCploda0TpKf3N56v6fk-fORAiVsXUmkWYWkw".to_string(),
        kid: "client-key".to_string(),
        use_: "sig",
        alg: "ES256",
    }
    .to_public_jwk();

    let calls = Arc::new(AtomicUsize::new(0));
    let srv = server_with(vec![Client {
        client_id: ClientId::new("pkjwt-client"),
        auth: ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![registered],
            },
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }])
    .await
    .with_es256_verifier(Arc::new(Counting(calls.clone())));

    // One well-formed assertion per id, differing only in whom it names. Neither verifies; the
    // point is what each COSTS on the way to the identical `invalid_client`.
    async fn probe(
        srv: &oauth_as::AuthorizationServer<oauth_as::MemoryStorage, impl oauth_as::Clock>,
        client_id: &str,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": "https://as.example/token",
            "exp": now + 120,
            "iat": now,
            "jti": format!("probe-{client_id}"),
        });
        let assertion = oauth_as::jwt::compact_jws(
            br#"{"alg":"ES256","typ":"JWT"}"#,
            &serde_json::to_vec(&claims).unwrap(),
            |_input| vec![7u8; 64],
        );
        let refused = srv
            .token_with_context(
                TokenRequest::ClientCredentials {
                    client_id: ClientId::new(client_id),
                    client_secret: None,
                    scope: None,
                },
                TokenRequestContext::new(ClientCredential::assertion(
                    Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    &assertion,
                )),
            )
            .await
            .expect_err("neither probe authenticates");
        assert_eq!(
            refused.error,
            ErrorCode::InvalidClient,
            "the wire answer is the same for both, which is the half that already worked"
        );
    }

    probe(&srv, "pkjwt-client").await;
    probe(&srv, "no-such-client").await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an unknown client id must cost the same ES256 verification a known one does, or the \
         wall clock answers the question the wire refuses to"
    );
}

/// THE MIRROR IMAGE of the test above, which the fix for it opened.
///
/// The dummy was charged on the unknown-id path whenever a `client_assertion` parameter was
/// present at all, but the KNOWN-id path reaches a verification only when three further conditions
/// hold: `authenticate_by_assertion` requires the RFC 7521 s4.2 `client_assertion_type`, refuses a
/// request carrying a `client_secret` alongside (RFC 6749 s2.3), and requires the REGISTRATION to
/// be `ConfidentialAssertion`. So a known id registered for `client_secret_basic` refused in
/// nanoseconds while an unknown id sent the identical bytes paid a full ES256 verification, and one
/// request per candidate id separated "registered, but not with `private_key_jwt`" from "not
/// registered at all". That is the same single-request, un-throttleable enumeration the mechanism
/// exists to close, running the other way.
///
/// Call counts rather than a wall clock, for the reason the test above gives.
#[cfg(feature = "client-assertion")]
#[tokio::test]
async fn a_registered_client_that_does_not_use_assertions_costs_what_an_unknown_id_costs() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oauth_as::jwt::{Es256Verifier, PublicJwk};
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    struct Counting(Arc<AtomicUsize>);
    impl Es256Verifier for Counting {
        fn verify(&self, _key: &PublicJwk, _signing_input: &[u8], _signature: &[u8]) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    /// One syntactically valid assertion naming whoever the probe names. Nothing about it verifies;
    /// the property under test is what the server SPENDS before saying `invalid_client`.
    fn assertion_for(client_id: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": "https://as.example/token",
            "exp": now + 120,
            "iat": now,
            "jti": format!("kind-probe-{client_id}"),
        });
        oauth_as::jwt::compact_jws(
            br#"{"alg":"ES256","typ":"JWT"}"#,
            &serde_json::to_vec(&claims).unwrap(),
            |_input| vec![7u8; 64],
        )
    }

    async fn probe(
        srv: &AuthorizationServer<MemoryStorage, ManualClock>,
        client_id: &str,
        assertion_type: Option<&str>,
    ) {
        let assertion = assertion_for(client_id);
        let refused = srv
            .token_with_context(
                TokenRequest::ClientCredentials {
                    client_id: ClientId::new(client_id),
                    client_secret: None,
                    scope: None,
                },
                TokenRequestContext::new(ClientCredential::assertion(assertion_type, &assertion)),
            )
            .await
            .expect_err("neither probe authenticates");
        assert_eq!(refused.error, ErrorCode::InvalidClient);
    }

    async fn counts(assertion_type: Option<&str>) -> (usize, usize) {
        let calls = Arc::new(AtomicUsize::new(0));
        // Registered for `client_secret_basic`, which is the whole point: this id EXISTS and does
        // not authenticate with an assertion, so it is the id an attacker is trying to tell apart
        // from one that does not exist.
        let srv = server_with(vec![Client {
            client_id: ClientId::new("secret-client"),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.into(),
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        }])
        .await
        .with_es256_verifier(Arc::new(Counting(calls.clone())));

        probe(&srv, "secret-client", assertion_type).await;
        let known = calls.load(Ordering::SeqCst);
        probe(&srv, "no-such-client", assertion_type).await;
        let unknown = calls.load(Ordering::SeqCst) - known;
        (known, unknown)
    }

    // ONE: the correct RFC 7521 type, so the request is exactly what a `private_key_jwt` client
    // sends. The registration is what differs, and the registration is precisely what the attacker
    // is probing, so it must not be readable off the clock.
    let (known, unknown) = counts(Some(oauth_as::CLIENT_ASSERTION_TYPE)).await;
    assert_eq!(
        known, unknown,
        "a registered id that does not use assertions must cost what an unknown id costs \
         (known {known}, unknown {unknown})"
    );

    // TWO: a type nobody registered, which `authenticate_by_assertion` refuses before decoding a
    // byte. Neither id can reach a verification, so NEITHER may pay for one: charging the unknown
    // path here bought nothing and leaked the same bit.
    let (known, unknown) = counts(Some("urn:example:not-a-real-assertion-type")).await;
    assert_eq!(
        (known, unknown),
        (0, 0),
        "a request that could not have reached a verification must not pay for one"
    );
}

/// THE THIRD DIRECTION the timing collapse was found incomplete in, and the one with the widest
/// blast radius: FOUR known-id paths did no verification AT ALL, one per registration kind that
/// cannot verify a posted secret plus the expiry gate that returns before all of them.
///
/// `verify_with` answers `false` in nanoseconds for a `Public` or `ConfidentialAssertion`
/// registration handed a posted `client_secret` (there is no presented string that could be right
/// for either), a mutual-TLS registration is dispatched to a thumbprint comparison that finds no
/// certificate, and the `client_secret_expires_at` check returns before every credential branch.
/// Meanwhile the UNKNOWN id pays `dummy_verify` through the host's scheme, which
/// `SecretVerifier::dummy_hash` prices at argon2id milliseconds. So the FAST answer positively
/// identified a registered client id, from one unauthenticated request per candidate carrying any
/// junk at all as the secret, which is precisely the single-request registry enumeration
/// `dummy_hash` was created to close.
///
/// Call counts rather than a wall clock, for the reason the two tests above give.
#[tokio::test]
async fn a_known_id_that_verifies_nothing_costs_what_an_unknown_id_costs() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oauth_as::client::{SecretHash, SecretVerifier};
    use oauth_as::server::{ClientCredential, TokenRequestContext};
    use oauth_as::DynamicRegistration;

    /// Stands in for a host's argon2id: what is counted is how many times the EXPENSIVE operation
    /// is reached, which is the whole of what the wall clock would have measured.
    struct Counting(Arc<AtomicUsize>);
    impl SecretVerifier for Counting {
        fn verify(&self, _stored: &SecretHash, _presented: &str) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            false
        }
        fn dummy_hash(&self) -> Option<SecretHash> {
            // A hash in this verifier's own scheme, which is what the doc on the method asks for:
            // one in a scheme it did not recognise would be rejected on inspection and cost
            // nothing, which is the leak the method exists to close.
            Some(SecretHash::custom(
                "host-scheme",
                "dummy-encoding-nobody-knows-the-secret-for",
            ))
        }
    }

    async fn counts(known: Client) -> (usize, usize) {
        let calls = Arc::new(AtomicUsize::new(0));
        let srv = server_with(vec![known])
            .await
            .with_secret_verifier(Box::new(Counting(calls.clone())));

        async fn probe(srv: &AuthorizationServer<MemoryStorage, ManualClock>, client_id: &str) {
            let refused = srv
                .token_with_context(
                    TokenRequest::ClientCredentials {
                        client_id: ClientId::new(client_id),
                        client_secret: None,
                        scope: None,
                    },
                    TokenRequestContext::new(ClientCredential::secret(Some("junk-secret"))),
                )
                .await
                .expect_err("neither probe authenticates");
            assert_eq!(refused.error, ErrorCode::InvalidClient);
        }

        probe(&srv, "probed-client").await;
        let known_calls = calls.load(Ordering::SeqCst);
        probe(&srv, "no-such-client").await;
        (known_calls, calls.load(Ordering::SeqCst) - known_calls)
    }

    fn client_with(auth: ClientAuth, registration: Option<DynamicRegistration>) -> Client {
        let registration = registration.map(Box::new);
        Client {
            client_id: ClientId::new("probed-client"),
            auth,
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration,
        }
    }

    // ONE: a public registration. `verify_with` refuses a presented secret without hashing.
    let (known, unknown) = counts(client_with(ClientAuth::Public, None)).await;
    assert_eq!(
        known, unknown,
        "a registered public client must cost what an unknown id costs (known {known}, \
         unknown {unknown})"
    );

    // TWO: a registration whose secret this server itself declared dead (RFC 7591 s3.2.1). The
    // expiry check returns before every credential branch, so nothing was verified.
    let registration = DynamicRegistration {
        registration_access_token_hash: SecretHash::sha256("unused-for-this-probe"),
        client_id_issued_at: Some(0),
        // Dead at one second past the epoch, and this server's clock is far past that.
        client_secret_expires_at: Some(1),
        token_endpoint_auth_method: "client_secret_post".to_string(),
    };
    let (known, unknown) = counts(client_with(
        ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        Some(registration),
    ))
    .await;
    assert_eq!(
        known, unknown,
        "an expired registration must cost what an unknown id costs (known {known}, \
         unknown {unknown})"
    );

    // THREE: an RFC 7523 registration handed a posted `client_secret`. `verify_with`'s
    // `ConfidentialAssertion` arm answers `false` without hashing, for the stated reason that no
    // presented string could be right for it. Refusing correctly and refusing CHEAPLY are different
    // things, and this is the second half of case ONE: a `private_key_jwt` deployment's whole
    // registry was sortable from unknown ids by one junk-secret request each.
    #[cfg(feature = "client-assertion")]
    {
        use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey};

        let (known, unknown) = counts(client_with(
            ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::ClientSecret {
                    secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
                },
            },
            None,
        ))
        .await;
        assert_eq!(
            known, unknown,
            "an assertion registration must cost what an unknown id costs (known {known}, \
             unknown {unknown})"
        );
    }

    // FOUR: an RFC 8705 mutual-TLS registration handed the same posted secret. This one does not
    // reach `verify_with` at all: `authenticate_client` dispatches on the REGISTRATION, so the
    // probe lands in `crate::mtls::verify_certificate`, which finds no certificate and refuses on a
    // thumbprint comparison in microseconds. Same bit, third door. A real mutual-TLS request
    // carries no `client_secret`, so nothing about the legitimate path is charged.
    #[cfg(feature = "mtls")]
    {
        use oauth_as::mtls::{ExpectedSubject, MtlsClientRegistration};

        let (known, unknown) = counts(client_with(
            ClientAuth::Mtls {
                registration: MtlsClientRegistration::TlsClientAuth(ExpectedSubject::SanDns(
                    "probed.example".to_string(),
                )),
            },
            None,
        ))
        .await;
        assert_eq!(
            known, unknown,
            "a mutual-TLS registration must cost what an unknown id costs (known {known}, \
             unknown {unknown})"
        );
    }
}

/// THE NINE RFC 9449 SECTION 4.3 CHECKS ARE COLLAPSED ON THE WIRE, AND SO ARE THE OTHER TWO.
///
/// `dpop.rs` and `events.rs` both say the distinction between DPoP failures is "for the host's
/// audit channel, not for the wire", and the nine checks `verify_proof` performs already answer a
/// BARE `invalid_dpop_proof`. Two siblings did not: a replayed proof was told "this DPoP proof has
/// already been used" and a build with no ES256 backend was told "no ES256 verifier is installed".
///
/// `verify_dpop` runs BEFORE any client authentication, so both strings were reachable by an
/// ANONYMOUS caller. The first is the one that costs: it says the proof presented is in the replay
/// cache, which is only reached AFTER its signature, `htu`, `htm` and `iat` have all passed, so a
/// captured proof could be tested for freshness against the very server that would have accepted
/// it. The second publishes a deployment misconfiguration to anyone who asks.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_dpop_refusal_says_no_more_on_the_wire_than_any_other_dpop_refusal() {
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    // No ES256 verifier installed, which is the second case: every proof is refused for a reason
    // that is about this deployment rather than about the caller.
    let srv = server_with(vec![confidential_client()]).await;
    let refused = srv
        .token_with_context(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("confidential-client"),
                client_secret: Some(SECRET.into()),
                scope: None,
            },
            TokenRequestContext::new(ClientCredential::secret(Some(SECRET)))
                .with_dpop_proof("a.proof.here"),
        )
        .await
        .unwrap_err();
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);
    assert_eq!(
        refused.error_description, None,
        "RFC 9449 s5 gives every one of these the same code, and this crate's own docs put the \
         distinction in the audit channel rather than on the wire: {refused:?}"
    );
}

/// THE FOURTH DIRECTION, and the one that matters most, because the round that CLOSED the third
/// opened this one.
///
/// `authenticate_client` enters the RFC 7523 branch on `cred.client_assertion.is_some()` ALONE.
/// `authenticate_by_assertion` then made three refusals before decoding a byte, and two of them
/// paid nothing: an unrecognised RFC 7521 s4.2 `client_assertion_type`, and RFC 6749 s2.3's ban on
/// presenting two credentials at once. So a request carrying `client_assertion` AND
/// `client_secret` was refused by a KNOWN id in nanoseconds, while an UNKNOWN id sending the same
/// bytes took the not-found arm, which charges `dummy_verify(cred.client_secret)` unconditionally
/// and therefore runs the host's `SecretVerifier` scheme. `assertion_could_be_verified` is false on
/// both sides (a secret is present), so the ASSERTION dummy is skipped either way and only the
/// SECRET dummy separates them: argon2id milliseconds against nanoseconds, one un-throttleable
/// request per candidate id, which is the round-7 enumeration oracle reopened.
///
/// The guard's own doc had already written the rule this broke: "The two conditions have to be kept
/// in step; if a refusal is ever added there before the verification, it belongs here too." Two
/// refusals already existed there. A comment cannot hold an invariant across two functions, so the
/// fix makes them ONE expression: `authenticate_by_assertion` now refuses on
/// `!assertion_could_be_verified(cred)` itself, charging the same dummy the unknown path charges.
/// The wire answer and the `AssertionFailure::Malformed` the audit channel hears are unchanged;
/// all three refusals gave that variant already.
#[cfg(feature = "client-assertion")]
#[tokio::test]
async fn a_known_id_refused_before_reading_its_assertion_costs_what_an_unknown_id_costs() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oauth_as::client::{SecretHash, SecretVerifier};
    use oauth_as::server::{ClientCredential, TokenRequestContext};

    struct Counting(Arc<AtomicUsize>);
    impl SecretVerifier for Counting {
        fn verify(&self, _stored: &SecretHash, _presented: &str) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            false
        }
        fn dummy_hash(&self) -> Option<SecretHash> {
            Some(SecretHash::custom(
                "host-scheme",
                "dummy-encoding-nobody-knows-the-secret-for",
            ))
        }
    }

    /// Both credentials at once, which is what RFC 6749 s2.3 forbids and what the probe exploits.
    /// The assertion never has to be well formed: the refusal under test happens before any byte of
    /// it is decoded, which is exactly why it was free.
    async fn counts(assertion_type: Option<&str>) -> (usize, usize) {
        let calls = Arc::new(AtomicUsize::new(0));
        let srv = server_with(vec![Client {
            client_id: ClientId::new("probed-client"),
            // A registration that DOES verify secrets, so the known id is the one an attacker most
            // wants to find and the one the mechanism must hide.
            auth: ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::custom("host-scheme", "whatever-the-host-stored"),
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        }])
        .await
        .with_secret_verifier(Box::new(Counting(calls.clone())));

        async fn probe(
            srv: &AuthorizationServer<MemoryStorage, ManualClock>,
            client_id: &str,
            assertion_type: Option<&str>,
        ) {
            let mut cred = ClientCredential::secret(Some("junk-secret"));
            cred.client_assertion_type = assertion_type;
            cred.client_assertion = Some("x.y.z");
            let refused = srv
                .token_with_context(
                    TokenRequest::ClientCredentials {
                        client_id: ClientId::new(client_id),
                        client_secret: None,
                        scope: None,
                    },
                    TokenRequestContext::new(cred),
                )
                .await
                .expect_err("two credentials at once is refused either way (RFC 6749 s2.3)");
            assert_eq!(refused.error, ErrorCode::InvalidClient);
        }

        probe(&srv, "probed-client", assertion_type).await;
        let known = calls.load(Ordering::SeqCst);
        probe(&srv, "no-such-client", assertion_type).await;
        (known, calls.load(Ordering::SeqCst) - known)
    }

    // ONE: the CORRECT assertion type, so the only thing refusing the request is RFC 6749 s2.3's
    // ban on two credentials. This is the site at `authenticate_by_assertion`'s secret check.
    let (known, unknown) = counts(Some(oauth_as::CLIENT_ASSERTION_TYPE)).await;
    assert_eq!(
        known, unknown,
        "a known id refused for presenting two credentials must cost what an unknown id costs \
         (known {known}, unknown {unknown})"
    );

    // TWO: an unrecognised RFC 7521 s4.2 type, WITH a secret. The type check refuses first, and it
    // is the same shape: safe only while no secret is present, which is precisely the case an
    // attacker chooses not to send.
    let (known, unknown) = counts(Some("urn:example:not-a-real-assertion-type")).await;
    assert_eq!(
        known, unknown,
        "a known id refused for an unrecognised assertion type must cost what an unknown id costs \
         (known {known}, unknown {unknown})"
    );

    // THREE: no type at all, which is the same refusal reached by a third route.
    let (known, unknown) = counts(None).await;
    assert_eq!(
        known, unknown,
        "a known id refused for a missing assertion type must cost what an unknown id costs \
         (known {known}, unknown {unknown})"
    );
}
