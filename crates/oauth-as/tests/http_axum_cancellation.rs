// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What happens to a store sequence when the CLIENT hangs up half way through it.
//!
//! Every "which way does this pair of writes fail" argument in `src/server.rs` reasons about a
//! store that ERRORS. There is a third outcome neither half covers: the future is DROPPED, so the
//! code after an `.await` simply never runs, nothing fails, and no error path is taken because no
//! path is taken at all.
//!
//! The refresh rotation is where it costs the most. `Storage::take_refresh_token` removes the
//! record (that is what makes redemption single use), and the spent marker that arms RFC 9700
//! s4.14.2 reuse detection is written afterwards. A drop in between leaves the chain removed with
//! no spent record, which is verbatim the state `src/server.rs` describes as the defect its write
//! ordering exists to prevent: "the token is gone with NO spent record, so a later presentation of
//! it reads as an unknown string rather than as reuse". Against a store error that ordering holds.
//! Against a drop it fails NEITHER way.
//!
//! And the drop is chosen by the party this crate is defending against: hyper drops the service
//! future when the connection closes, and whoever presents a stolen refresh token is whoever
//! decides when to close the socket.
//!
//! This crate cannot fix that where the host owns the runtime, because the `http` feature
//! deliberately has none. It CAN fix it in the one place it ships a runtime itself: the `axum`
//! adapter, which the module docs call "the whole wiring". See the adapter's own doc comment.
//!
//! THE FIXTURE. The window is microseconds wide in memory, so it is held open where a real
//! deployment holds it open anyway: inside the store, whose `take_refresh_token` here does the
//! real take and then waits before returning, exactly as a network round trip to a database does.
//! What is asserted is the call the server makes NEXT.

#![cfg(feature = "axum")]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oauth_as::authorization::AuthorizationCodeRecord;
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::device::DeviceGrant;
use oauth_as::grant::GrantType;
use oauth_as::http::ServiceBuilder;
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::{MemoryStorage, Storage, StorageError};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};

const CLIENT_ID: &str = "rotating-client";
const SECRET: &str = "a-high-entropy-registered-client-secret";
const REFRESH_TOKEN: &str = "the-refresh-token-being-rotated";
/// Long enough that the client's disconnect lands inside it on any machine, and short enough that
/// the test costs a fraction of a second.
const TAKE_DELAY: Duration = Duration::from_millis(400);

/// A store that behaves exactly like [`MemoryStorage`] except that `take_refresh_token` waits
/// after taking, and every call is recorded.
///
/// The wait is where a real store's is: the record is ALREADY gone when it happens, which is the
/// property that makes the window dangerous rather than merely slow.
struct SlowTake {
    inner: MemoryStorage,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl SlowTake {
    fn record(&self, what: &'static str) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(what);
    }
}

impl Storage for SlowTake {
    fn get_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<Arc<Client>>, StorageError>> + Send {
        self.inner.get_client(client_id)
    }
    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_client(client)
    }
    fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.compare_and_swap_client(expected, updated)
    }
    fn delete_client(
        &self,
        client_id: &ClientId,
        window: oauth_as::store::RevocationWindow,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.delete_client(client_id, window)
    }
    fn put_device_grant(
        &self,
        grant: DeviceGrant,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_device_grant(grant)
    }
    fn get_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.inner.get_device_grant(device_code)
    }
    fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.inner
            .find_device_grant_by_user_code(normalized_user_code)
    }
    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.inner.take_device_grant(device_code)
    }
    fn compare_and_swap_device_grant(
        &self,
        expected: &oauth_as::DeviceGrantState,
        updated: DeviceGrant,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.compare_and_swap_device_grant(expected, updated)
    }
    #[cfg(feature = "par")]
    fn put_pushed_authorization_request(
        &self,
        record: oauth_as::PushedAuthorizationRequest,
    ) -> impl Future<Output = Result<oauth_as::store::WriteOutcome, StorageError>> + Send {
        self.inner.put_pushed_authorization_request(record)
    }
    #[cfg(feature = "par")]
    fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> impl Future<Output = Result<Option<oauth_as::PushedAuthorizationRequest>, StorageError>> + Send
    {
        self.inner.take_pushed_authorization_request(request_uri)
    }
    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_authorization_code(record)
    }
    fn compare_and_swap_authorization_code(
        &self,
        expected: &oauth_as::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner
            .compare_and_swap_authorization_code(expected, updated)
    }
    fn take_authorization_code(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCodeRecord>, StorageError>> + Send {
        self.inner.take_authorization_code(code)
    }
    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<oauth_as::store::WriteOutcome, StorageError>> + Send {
        self.inner.put_token(token)
    }
    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<IssuedToken>>, StorageError>> + Send {
        self.inner.get_token(access_token)
    }
    fn delete_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.delete_token(access_token)
    }
    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<oauth_as::store::WriteOutcome, StorageError>> + Send {
        self.record("put_refresh_token");
        self.inner.put_refresh_token(record)
    }
    fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<RefreshTokenRecord>>, StorageError>> + Send {
        self.inner.get_refresh_token(refresh_token)
    }
    /// The take is REAL and happens first; the wait models the round trip a networked store makes
    /// before the caller is resumed. Anything the server does after this point is what a dropped
    /// future costs.
    fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send {
        self.record("take_refresh_token");
        let taken = self.inner.take_refresh_token(refresh_token);
        async move {
            let taken = taken.await;
            tokio::time::sleep(TAKE_DELAY).await;
            taken
        }
    }
    fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.inner.revoke_token_family(family_id, window)
    }
    #[cfg(feature = "consent")]
    fn put_consent(
        &self,
        record: oauth_as::ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.inner.put_consent(record)
    }
    #[cfg(feature = "consent")]
    fn get_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError>> + Send
    {
        self.inner.get_consent(consent_id)
    }
    #[cfg(feature = "consent")]
    fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> impl Future<Output = Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError>> + Send
    {
        self.inner.find_consent(client_id, subject)
    }
    #[cfg(feature = "consent")]
    fn consents_for_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<Arc<oauth_as::ConsentRecord>>, StorageError>> + Send {
        self.inner.consents_for_subject(subject)
    }
    #[cfg(feature = "consent")]
    fn compare_and_swap_consent(
        &self,
        expected: Option<&oauth_as::ConsentRecord>,
        updated: oauth_as::ConsentRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.compare_and_swap_consent(expected, updated)
    }
    #[cfg(feature = "consent")]
    fn revoke_consent(
        &self,
        consent_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.inner.revoke_consent(consent_id, window)
    }
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.inner.claim_replay_id(id, expires_at)
    }
    fn sweep_expired(
        &self,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.inner.sweep_expired(now)
    }
}

fn rotating_client() -> Client {
    Client {
        client_id: ClientId::new(CLIENT_ID),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A live chain, seeded straight into the store: this test is about the rotation, and minting the
/// first link through the wire would only add ways for it to fail.
async fn serve() -> (SocketAddr, Arc<Mutex<Vec<&'static str>>>) {
    let inner = MemoryStorage::new();
    let seeded = inner
        .put_refresh_token(RefreshTokenRecord::new(
            REFRESH_TOKEN,
            ClientId::new(CLIENT_ID),
            Some("user-1".to_string()),
            ScopeSet::parse("read").unwrap(),
            "family-1",
        ))
        .await
        .expect("seeded");
    assert!(
        !seeded.is_refused(),
        "the fixture's own chain has to exist before the rotation can be about anything"
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let store = SlowTake {
        inner,
        calls: calls.clone(),
    };

    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        store,
    );
    srv.register_client(rotating_client())
        .await
        .expect("client");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let router = axum::Router::from(ServiceBuilder::new(Arc::new(srv)).build().expect("service"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, calls)
}

fn refresh_body() -> String {
    format!(
        "grant_type=refresh_token&refresh_token={REFRESH_TOKEN}&client_id={CLIENT_ID}\
         &client_secret={SECRET}"
    )
}

async fn write_refresh_request(addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    // RST rather than FIN on drop, which is what a client that vanishes looks like and is what
    // makes the server's read fail while it is still working rather than when it tries to answer.
    // A plain FIN leaves the server free to finish and only discover the loss at write time, which
    // is a different scenario from the one under test.
    //
    // `set_linger` is deprecated in tokio because SO_LINGER can block the thread on drop; with a
    // ZERO timeout there is nothing to linger over, the close is an immediate reset, and this is a
    // test client rather than a server socket.
    #[allow(deprecated)]
    stream
        .set_linger(Some(Duration::ZERO))
        .expect("linger is settable on a TCP socket");
    let body = refresh_body();
    let request = format!(
        "POST /token HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");
    stream
}

/// THE CONTROL. The same request, read to completion, so the sequence the test below asserts is
/// known to happen when nobody hangs up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_rotation_writes_the_spent_marker() {
    let (addr, calls) = serve().await;
    let stream = write_refresh_request(addr).await;
    tokio::time::sleep(TAKE_DELAY + Duration::from_millis(400)).await;
    drop(stream);

    let seen = calls.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        seen.contains(&"take_refresh_token") && seen.contains(&"put_refresh_token"),
        "the rotation writes the spent marker after the take: {seen:?}"
    );
}

/// THE DEFECT. The client closes the connection while the store is mid-take. The record is
/// already gone; whether the spent marker that arms reuse detection is ever written is the whole
/// question, and it must not depend on how long the presenter kept the socket open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotation_survives_the_client_hanging_up_mid_take() {
    let (addr, calls) = serve().await;
    let stream = write_refresh_request(addr).await;
    // Inside the take, which is the window: the record has been removed and nothing else has been
    // written yet.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(stream);
    // Well past what the rotation needs, so this is not a timing assertion.
    tokio::time::sleep(TAKE_DELAY + Duration::from_millis(600)).await;

    let seen = calls.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        seen.contains(&"take_refresh_token"),
        "the fixture must actually have reached the take: {seen:?}"
    );
    assert!(
        seen.contains(&"put_refresh_token"),
        "the take removed the chain; without the spent marker RFC 9700 s4.14.2 reuse detection \
         for this family is off permanently and silently, and the party who chose the moment to \
         disconnect is the party presenting the token: {seen:?}"
    );
}
