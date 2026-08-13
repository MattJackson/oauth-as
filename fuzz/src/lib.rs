// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Shared fixtures and invariant predicates for the fuzz targets.
//!
//! # Why this is a library and not an `#[path]` include per target
//!
//! Every target that drives an [`oauth_as::AuthorizationServer`] needs the SAME registered
//! clients, the SAME keys and the SAME clock, because the interesting invariants are of the form
//! "no input the fuzzer can produce authenticates as this client" and that sentence is only
//! meaningful if every target agrees on which client it means. One definition, here.
//!
//! # Why every key and secret in this file is a hard-coded constant
//!
//! Reproducibility. libFuzzer's contract is that re-running a target on a saved crash input
//! reproduces the crash; a freshly generated P-256 key on each process start would break that for
//! every target that verifies a signature, and would turn a real finding into a "works on my
//! machine". [`oauth_as::jwt::EcdsaP256Key::generate`] is therefore never used here.
//!
//! These are fixtures for a fuzzer. They authenticate nothing anywhere.

use std::sync::OnceLock;

use oauth_as::client_assertion::AssertionKeys;
use oauth_as::http::{AuthorizationService, ServiceBuilder};
use oauth_as::jwt::{compact_jws, EcdsaP256Key};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage,
    RegisteredRequestObjectKey, RequestObjectKeys, ScopeSet, ServerConfig, SystemClock,
};

/// The issuer every fixture is built for. Also the base of every endpoint path, which is what
/// makes [`Fixture::paths`] derivable rather than assumed.
pub const ISSUER: &str = "https://as.example";
/// This server's own token endpoint, which is the `aud` an RFC 7523 assertion and the `htu` of an
/// RFC 9449 proof must both name.
pub const TOKEN_ENDPOINT: &str = "https://as.example/token";

/// The confidential client, authenticating with a secret (RFC 6749 s2.3.1).
pub const CONFIDENTIAL_ID: &str = "fuzz-confidential";
/// Its secret. High entropy on purpose: a target asserts that no fuzzer-generated credential ever
/// authenticates, and that assertion is only sound if the fuzzer cannot plausibly guess this.
pub const CONFIDENTIAL_SECRET: &str = "1d7bb0d3ad3f4e7f9a0c5be2f77c5f2a-fuzz-fixture-secret";
/// The public client (RFC 6749 s2.1), for the authorization endpoint targets.
pub const PUBLIC_ID: &str = "fuzz-public";
/// The client authenticating with `private_key_jwt` (RFC 7523 s2.2), for the assertion target.
pub const ASSERTION_ID: &str = "fuzz-assertion";
/// The client whose RFC 9101 request objects are signed by [`request_object_key`].
pub const JAR_ID: &str = "fuzz-jar";
/// The one registered redirect URI. Anything else must be refused.
pub const REDIRECT_URI: &str = "https://app.example/cb";

/// Every scope a fixture client is ALLOWED to request.
pub const ALLOWED_SCOPES: &str = "read write";

/// The scope a fixture client is granted when a request names NONE (RFC 6749 s3.3 leaves that to
/// the server, and this crate fills in the registration's default).
///
/// A PROPER SUBSET of [`ALLOWED_SCOPES`], and it has to stay one: targets assert that a signed
/// `scope` claim is carried through rather than replaced by this, and if the two were equal that
/// assertion would hold for a validator that always substituted the default.
pub const DEFAULT_SCOPE: &str = "read";

/// The RFC 7636 appendix B code verifier and the S256 challenge it hashes to. Quoted from the RFC
/// so that a seed built from them is a seed built from the specification's own bytes.
pub const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// RFC 7636 appendix B, the `code_challenge` for [`RFC7636_VERIFIER`].
pub const RFC7636_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The scalar for the client's assertion signing key. Any 32 bytes below the group order will do;
/// what matters is that it never changes, so a crash input reproduces.
const ASSERTION_SCALAR: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x21,
];

/// The scalar for the RFC 9101 request-object signing key. DIFFERENT from the assertion key on
/// purpose: a target that could accidentally sign a request object with the assertion key would
/// prove nothing about key selection.
const REQUEST_OBJECT_SCALAR: [u8; 32] = [
    0x7f, 0x0e, 0x1d, 0x2c, 0x3b, 0x4a, 0x59, 0x68, 0x77, 0x86, 0x95, 0xa4, 0xb3, 0xc2, 0xd1, 0xe0,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x11,
];

/// The client's `private_key_jwt` key (RFC 7523 s2.2).
pub fn assertion_key() -> &'static EcdsaP256Key {
    static KEY: OnceLock<EcdsaP256Key> = OnceLock::new();
    KEY.get_or_init(|| {
        EcdsaP256Key::from_scalar_bytes("fuzz-assertion-kid", &ASSERTION_SCALAR)
            .expect("the fixture scalar is a valid P-256 private key")
    })
}

/// The client's RFC 9101 request-object signing key.
pub fn request_object_key() -> &'static EcdsaP256Key {
    static KEY: OnceLock<EcdsaP256Key> = OnceLock::new();
    KEY.get_or_init(|| {
        EcdsaP256Key::from_scalar_bytes("fuzz-jar-kid", &REQUEST_OBJECT_SCALAR)
            .expect("the fixture scalar is a valid P-256 private key")
    })
}

/// The one key this server will verify a request object against.
struct JarKeys;

impl RequestObjectKeys for JarKeys {
    fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
        if client_id.as_str() != JAR_ID {
            return None;
        }
        let jwk = request_object_key().public_jwk();
        RegisteredRequestObjectKey::es256_from_jwk_coordinates(
            Some(jwk.kid.clone()),
            &jwk.x,
            &jwk.y,
        )
        .ok()
    }
}

/// The current-thread runtime the async targets block on.
///
/// One runtime for the whole process, built lazily. A runtime per iteration would cost a thread
/// park and two allocations on every single input and would swamp the parser under measurement.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime always builds")
    })
}

fn scopes() -> ScopeSet {
    ScopeSet::parse(ALLOWED_SCOPES).expect("fixture scopes are RFC 6749 s3.3 tokens")
}

fn client(id: &str, auth: ClientAuth, grant_types: Vec<GrantType>) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth,
        grant_types,
        redirect_uris: vec![REDIRECT_URI.to_string()],
        allowed_scopes: scopes(),
        default_scopes: ScopeSet::parse(DEFAULT_SCOPE).expect("fixture default scope"),
        name: None,
        registration: None,
    }
}

/// The server under test, with every fixture client registered.
///
/// [`SystemClock`] rather than a hand-cranked one: the targets here are PARSERS, and a parser's
/// behaviour must not depend on the clock. Where a target does reach code that reads the clock
/// (an assertion's `exp`, a proof's `iat`) the invariant asserted is a refusal, and a refusal is
/// what a wrong clock produces too, so no invariant here can be made to hold by a clock accident.
pub fn server() -> &'static std::sync::Arc<AuthorizationServer<MemoryStorage, SystemClock>> {
    static SERVER: OnceLock<std::sync::Arc<AuthorizationServer<MemoryStorage, SystemClock>>> =
        OnceLock::new();
    SERVER.get_or_init(|| {
        let mut config = ServerConfig::new(ISSUER, format!("{ISSUER}/device"));
        // RFC 9126 and RFC 9101 both OFF by default, and both switched on here. Without them the
        // PAR endpoint is not routed and every request object is refused with
        // `request_not_supported` before the claim walk runs, which would leave two of the
        // targets in this directory fuzzing a single early return.
        config.par = Some(Box::new(oauth_as::ParConfig::new()));
        config.jar = Some(Box::new(oauth_as::JarConfig::new()));
        // RFC 7591 dynamic registration, so the registration and RFC 7592 management routes exist
        // for `http_request` to reach. Its policy is the default, which refuses everything it is
        // not explicitly told to accept.
        config.registration = Some(Box::new(oauth_as::RegistrationConfig::default()));
        let server = AuthorizationServer::new(config, MemoryStorage::new())
            .with_request_object_keys(Box::new(JarKeys));
        runtime().block_on(async {
            for c in [
                client(
                    CONFIDENTIAL_ID,
                    ClientAuth::ConfidentialSecret {
                        secret: CONFIDENTIAL_SECRET.to_string(),
                    },
                    vec![
                        GrantType::AuthorizationCode,
                        GrantType::RefreshToken,
                        GrantType::ClientCredentials,
                        GrantType::DeviceCode,
                    ],
                ),
                client(
                    PUBLIC_ID,
                    ClientAuth::Public,
                    vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                ),
                client(
                    ASSERTION_ID,
                    ClientAuth::ConfidentialAssertion {
                        keys: AssertionKeys::PublicKeys {
                            keys: vec![assertion_key().to_public_jwk()],
                        },
                    },
                    vec![GrantType::ClientCredentials],
                ),
                client(
                    JAR_ID,
                    ClientAuth::Public,
                    vec![GrantType::AuthorizationCode],
                ),
            ] {
                server
                    .register_client(c)
                    .await
                    .expect("MemoryStorage accepts a registration");
            }
        });
        std::sync::Arc::new(server)
    })
}

/// The HTTP service, plus the routed paths taken from its own RFC 8414 metadata document.
pub struct Fixture {
    /// The service under test.
    pub service: AuthorizationService<MemoryStorage, SystemClock>,
    /// Every path this service routes, DERIVED from the metadata document rather than hard coded.
    /// A hard-coded list is a list that silently stops covering an endpoint the day it moves, and
    /// a fuzz target that no longer reaches the code it names is the failure mode this whole
    /// directory exists to avoid.
    pub paths: Vec<String>,
}

/// The service under test, built once.
pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        // A subject resolver and a consent resolver are installed so that the authorization
        // endpoint reaches ISSUANCE rather than stopping at "this host cannot tell me who the
        // user is". Without them the whole second half of that handler is unreachable and the
        // target would be fuzzing a 500 responder.
        let service = ServiceBuilder::new(std::sync::Arc::clone(server()))
            .with_subject_resolver(|_headers| Some("fuzz-subject".to_string()))
            .with_approval_resolver(|_req| oauth_as::http::ApprovalDecision::Approve)
            // CSRF TOKENS, and this one was FOUND rather than foreseen. Without them
            // `ServiceBuilder` leaves the RFC 8628 s3.3 verification page in its `Unwired` state,
            // which answers every GET with a deliberate 500 saying the host never supplied a CSRF
            // seam (RFC 6749 s10.12). The first run of `http_request` minimised straight to
            // `GET /device` and reported that 500 as a violated invariant: correctly, in that the
            // invariant did its job, and uselessly, in that it was measuring an unconfigured
            // fixture rather than the library. A fuzz target whose fixture short-circuits before
            // the parser is a target that proves nothing, so the seam is wired here.
            //
            // Constant tokens, because the target is the PARSER and not the session store: the
            // interesting inputs are the ones where the form body, the `Origin` header and the
            // token disagree, and a token that varies would make those unreachable by chance
            // rather than by construction.
            .with_csrf_tokens(
                |_headers| Some("fuzz-csrf-token".to_string()),
                |_headers| Some("fuzz-csrf-token".to_string()),
            )
            .build()
            .expect("the fixture configuration routes without collision");

        // The paths the RFC 8414 document does NOT name, which is the floor the derivation below
        // cannot discover for itself:
        //
        // - the document's own location. RFC 8414 s3.1 puts the well-known string between the host
        //   and the issuer's path, so it is not a member of the document it locates.
        // - the device verification page, which is a `ServerConfig` value rather than an RFC 8414
        //   member.
        // - `/introspect`. THE ROUTE IS UNCONDITIONAL AND THE ADVERTISEMENT IS NOT, as of 0.9.1.
        //   `ServiceBuilder::build` mounts the introspection route whether or not the host named
        //   `ServerConfig::introspection_endpoint`, because the endpoint answers the token's own
        //   client and always has; `from_config` publishes the member only where the host named it,
        //   because advertising it claims a resource-server channel that does not exist until
        //   0.9.2. This fixture does not name one, so the document omits it and the route serves
        //   it. The fuzzer found exactly that gap -- `GET /introspect` answered non-404 while this
        //   oracle called it unrouted -- and it was a defect in the ORACLE, not in the server.
        //
        // The lesson for anyone adding a route: if advertisement and routing can disagree, this
        // list is where the disagreement has to be written down.
        let mut paths = vec![
            "/.well-known/oauth-authorization-server".to_string(),
            "/device".to_string(),
            "/introspect".to_string(),
        ];
        // The metadata document is the authority on what is routed. Anything it advertises that
        // is on this issuer is a path, and the list above is only a floor.
        let doc = runtime().block_on(async {
            let response = service
                .handle(
                    http::Request::builder()
                        .method("GET")
                        .uri("/.well-known/oauth-authorization-server")
                        .body(oauth_as::http::Body::empty())
                        .expect("a well formed request"),
                )
                .await;
            let bytes = response.into_body().into_bytes();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or(serde_json::Value::Null)
        });
        if let Some(members) = doc.as_object() {
            for value in members.values() {
                if let Some(url) = value.as_str() {
                    if let Some(rest) = url.strip_prefix(ISSUER) {
                        if rest.starts_with('/') && !paths.iter().any(|p| p == rest) {
                            paths.push(rest.to_string());
                        }
                    }
                }
            }
        }
        Fixture { service, paths }
    })
}

// --------------------------------------------------------------------- RFC charset predicates

/// RFC 6749 section 5.2's `error` production: `*NQSCHAR`, which is
/// `%x20-21 / %x23-5B / %x5D-7E`.
///
/// This is a SECURITY property, not a style one. `error` and `error_description` are the two
/// members of an error body that can carry anything derived from the request, and section 5.2
/// fixes their charset precisely so that a value cannot close the JSON string it sits in or carry
/// a control byte into whatever logs it. A parser that lets an input byte reach one of them
/// unfiltered is an injection, and it will show up here as a violated invariant rather than as a
/// panic.
pub fn is_nqschar(s: &str) -> bool {
    s.bytes()
        .all(|b| b == 0x20 || b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

/// Assert everything this crate promises about any response it emits, whatever the input.
///
/// Checked here rather than per target so that every HTTP-shaped target gets the same guarantees
/// and a new target cannot forget one.
pub fn assert_response_invariants(status: u16, content_type: Option<&str>, body: &[u8]) {
    // INVARIANT 1. No input reaches a 5xx. `MemoryStorage` is infallible, so the only way to a
    // 500 from here is the server failing to handle something it was handed, which is exactly
    // what a fuzzer is for.
    assert!(
        status < 500,
        "attacker-supplied input produced a {status}; body={:?}",
        String::from_utf8_lossy(body)
    );

    let is_json = content_type.is_some_and(|ct| ct.starts_with("application/json"));
    if !is_json || body.is_empty() {
        return;
    }

    // INVARIANT 2. A body announced as JSON IS JSON. A handler that formats a body by hand from
    // request-derived text can announce `application/json` and emit something that is not.
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "a response declared application/json is not JSON ({e}): {:?}",
            String::from_utf8_lossy(body)
        )
    });

    // INVARIANT 3. RFC 6749 s5.2's charset on both text members of an error body.
    if let Some(object) = value.as_object() {
        for name in ["error", "error_description"] {
            if let Some(text) = object.get(name).and_then(|v| v.as_str()) {
                assert!(
                    is_nqschar(text),
                    "{name} is outside RFC 6749 s5.2 NQSCHAR: {text:?}"
                );
            }
        }
        // INVARIANT 4. An error body carries no token. An error path that still emits an
        // `access_token` has issued a credential on a request it just refused.
        if object.contains_key("error") {
            for leaked in ["access_token", "refresh_token", "device_code"] {
                assert!(
                    !object.contains_key(leaked),
                    "an RFC 6749 s5.2 error body carries a {leaked}"
                );
            }
        }
    }
}

// ------------------------------------------------------------------------ JWS construction

/// Build a compact JWS with a signature that is whatever the caller says it is.
///
/// Used by the targets that must be able to produce a WELL FORMED but WRONGLY SIGNED token: that
/// is the input class that matters, because a token the parser rejects in its first ten lines
/// never reaches the verification the target is about.
pub fn jws_with_signature(header: &[u8], payload: &[u8], signature: Vec<u8>) -> String {
    compact_jws(header, payload, |_| signature)
}

/// Sign `header`/`payload` with `key` (ES256, RFC 7518 s3.4).
pub fn jws_signed(key: &EcdsaP256Key, header: &[u8], payload: &[u8]) -> String {
    compact_jws(header, payload, |input| {
        key.sign_signing_input(input)
            .expect("a fixture key signs any input")
    })
}
