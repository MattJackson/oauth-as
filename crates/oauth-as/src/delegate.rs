// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! [`delegate_storage!`](crate::delegate_storage), the answer to "I want Postgres for clients and
//! memory for codes".
//!
//! [`crate::store::Storage`] has no default method bodies, and its own docs argue at length for
//! why: there is no method here whose obvious default is safe, and a defaulted one fails in
//! production in the direction that loses credentials. The cost of that decision falls on the host
//! who wants to specialise ONE method, because they then have to hand-write the other twenty-eight
//! as forwarding calls.
//!
//! That forwarding is mechanical, so this macro writes it. It is the answer the trait's docs
//! promise, and it lands after the 0.9.1 `Storage` break so that it forwards the FINAL method set
//! rather than a set about to change.
//!
//! # Why the feature gating goes through `__oauth_as_if_*` and not through `#[cfg]`
//!
//! `macro_rules!` has hygiene for identifiers and NONE for `cfg`. An attribute a macro EMITS is
//! evaluated where the macro EXPANDS, so a `#[cfg(feature = "par")]` written in this file and
//! expanded into a host crate asks whether THE HOST has a feature called `par`. Almost no host
//! does. rustc says this in as many words when it sees it: "using a cfg inside a macro will use the
//! cfgs from the destination crate and not the ones from the defining crate".
//!
//! THIS SHIPPED WRONG AND IS WORTH RECORDING. Through 0.9.1 the nine feature-gated arms carried
//! their `#[cfg]` inline, so in every real host crate they expanded to NOTHING, whatever features
//! `oauth-as` itself had been built with. A host that turned on `consent` and `par` and listed all
//! twenty-nine names got E0046 naming `put_pushed_authorization_request`,
//! `take_pushed_authorization_request`, the six consent methods and `claim_replay_id`, and was
//! pushed straight back to hand-writing the forwarders this macro exists to spare them.
//!
//! The fix moves the DECISION to a place `oauth-as` compiles: a pair of `#[macro_export]` macros per
//! gate, selected by `#[cfg]` HERE, one passing its input through and one swallowing it. The gated
//! arms then call `$crate::__oauth_as_if_par! { ... }`, which is an ordinary macro path and carries
//! this crate's answer with it. Nothing is emitted into the host that the host has to be able to
//! evaluate.
//!
//! Nothing else works. `cfg_attr` has the same problem for the same reason; `cfg!()` is an
//! expression and cannot delete an item; a proc macro could read `CARGO_FEATURE_*` but that is a
//! `syn` dependency in the ONE crate whose whole argument is that it has almost none.
//!
//! `crates/oauth-as-delegate-fixture` is the standing gate, and it has to be a separate crate: the
//! doctest below CANNOT catch this, because rustdoc compiles doctests with the declaring crate's
//! cfg flags, so the doctest and the bug agreed with each other for as long as both existed.

// THE THREE GATES, resolved HERE and carried into the host as macro paths. See the module docs for
// why this shape rather than an emitted `#[cfg]`. Each pair is exhaustive and mutually exclusive, so
// exactly one definition of each name exists in any build, and `#[macro_export]` puts it at this
// crate's root where `$crate::` can reach it.
//
// `#[doc(hidden)]`: these are an implementation detail of `delegate_storage!`, not API. They are
// nonetheless PUBLIC macros with a stable-looking name, which is unavoidable (`macro_rules!` has no
// `pub(crate)` for exported macros), hence the `__oauth_as_` prefix. Do not call them.

/// Emits its input when `oauth-as` was built with `par`, and nothing otherwise.
#[doc(hidden)]
#[macro_export]
#[cfg(feature = "par")]
macro_rules! __oauth_as_if_par {
    ($($item:tt)*) => { $($item)* };
}

/// Emits its input when `oauth-as` was built with `par`, and nothing otherwise.
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "par"))]
macro_rules! __oauth_as_if_par {
    ($($item:tt)*) => {};
}

/// Emits its input when `oauth-as` was built with `consent`, and nothing otherwise.
#[doc(hidden)]
#[macro_export]
#[cfg(feature = "consent")]
macro_rules! __oauth_as_if_consent {
    ($($item:tt)*) => { $($item)* };
}

/// Emits its input when `oauth-as` was built with `consent`, and nothing otherwise.
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "consent"))]
macro_rules! __oauth_as_if_consent {
    ($($item:tt)*) => {};
}

/// Emits its input when `oauth-as` was built with `client-assertion` or `dpop`, and nothing
/// otherwise. The two features share one gate because they share one method: RFC 7523 assertion
/// replay and RFC 9449 DPoP proof replay are the same claim-if-absent operation.
#[doc(hidden)]
#[macro_export]
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
macro_rules! __oauth_as_if_replay {
    ($($item:tt)*) => { $($item)* };
}

/// Emits its input when `oauth-as` was built with `client-assertion` or `dpop`, and nothing
/// otherwise.
#[doc(hidden)]
#[macro_export]
#[cfg(not(any(feature = "client-assertion", feature = "dpop")))]
macro_rules! __oauth_as_if_replay {
    ($($item:tt)*) => {};
}

/// Forward the named [`crate::store::Storage`] methods to an inner store.
///
/// # Usage
///
/// Name the FIELD holding the inner store, then the methods to forward. Anything you do NOT list, you write
/// yourself in the same `impl` block. Listing is EXPLICIT rather than "everything except", and
/// that is deliberate: `macro_rules!` cannot subtract a set, and more to the point a host reading
/// this call should be able to see which methods are their own without cross-referencing the
/// trait. If you forget one, the compiler names it, which is exactly the signal the trait's
/// no-defaults rule exists to produce.
///
/// ```
/// use oauth_as::store::{MemoryStorage, Storage, StorageError, WriteOutcome};
/// use oauth_as::{ClientId, IssuedToken};
///
/// /// Counts issuance, and is otherwise an ordinary in-memory store.
/// struct CountingStore {
///     inner: MemoryStorage,
///     issued: std::sync::atomic::AtomicU64,
/// }
///
/// impl Storage for CountingStore {
///     // The one method this store is actually for.
///     async fn put_token(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
///         let outcome = self.inner.put_token(token).await?;
///         if outcome.is_applied() {
///             self.issued.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
///         }
///         Ok(outcome)
///     }
///
///     // Everything else, including the feature-gated methods: each gated one is generated only
///     // when `oauth-as` itself has the feature, so naming one you have not enabled produces
///     // nothing rather than an error. Your OWN crate's features are not consulted and do not
///     // need to exist.
///     oauth_as::delegate_storage! {
///         to inner;
///         get_client, put_client, compare_and_swap_client, delete_client,
///         put_device_grant, get_device_grant, find_device_grant_by_user_code,
///         take_device_grant, compare_and_swap_device_grant,
///         put_authorization_code, compare_and_swap_authorization_code,
///         take_authorization_code,
///         put_pushed_authorization_request, take_pushed_authorization_request,
///         get_token, delete_token,
///         put_refresh_token, get_refresh_token, take_refresh_token, revoke_token_family,
///         put_consent, compare_and_swap_consent, get_consent, find_consent,
///         consents_for_subject, revoke_consent,
///         claim_replay_id,
///         sweep_expired,
///     }
/// }
/// ```
///
/// # What it does not do
///
/// It forwards. It does not make two stores atomic with respect to each other, and no macro
/// could: if clients live in Postgres and codes live in memory, then
/// [`crate::store::Storage::delete_client`]'s cascade spans both, and the trait requires that
/// cascade to be ONE event. A host splitting a store across backends owns that problem, and
/// [`crate::storage_conformance`] is how they find out whether they have solved it.
///
/// The feature-gated methods are forwarded only when the feature is on IN `oauth-as`, so a name
/// listed under a feature you have not enabled is simply not generated. Listing one you do not have
/// is not an error; it produces nothing.
///
/// "in `oauth-as`" is the load-bearing part and it has to be said, because the obvious reading is
/// wrong and was ALSO what the macro did until this was fixed: the gate is NOT your crate's feature
/// set. Your crate does not need a feature called `par` and almost certainly does not have one.
/// Note also that this means cargo FEATURE UNIFICATION can turn a forwarder on: an unrelated
/// dependency enabling `consent` enables it for your build of `oauth-as` too, and the macro will
/// then generate `put_consent` and the rest. That is the correct outcome, since the trait grew the
/// methods at the same moment, and it is the reason this macro is worth having.
///
/// # Why it takes a FIELD and not an expression
///
/// `to inner`, not `to self.inner`, and that is macro hygiene rather than taste. A `self` written
/// at the call site is a different `self` from the one in the generated method, so an expression
/// containing it does not resolve and the error (`expected value, found module self`) points at
/// the macro rather than at anything a host can act on. Taking the field name lets the macro build
/// `self.$f` itself, out of its own `self`. A tuple field works too: `to 0`.
#[macro_export]
macro_rules! delegate_storage {
    (to $field:tt; $($method:ident),* $(,)?) => {
        $($crate::delegate_storage!(@one $field, $method);)*
    };

    // ------------------------------------------------------------------------------- clients
    (@one $f:tt, get_client) => {
        async fn get_client(
            &self,
            client_id: &$crate::ClientId,
        ) -> ::core::result::Result<
            ::core::option::Option<::std::sync::Arc<$crate::Client>>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::get_client(&self.$f, client_id).await
        }
    };
    (@one $f:tt, put_client) => {
        async fn put_client(
            &self,
            client: $crate::Client,
        ) -> ::core::result::Result<(), $crate::store::StorageError> {
            $crate::store::Storage::put_client(&self.$f, client).await
        }
    };
    (@one $f:tt, compare_and_swap_client) => {
        async fn compare_and_swap_client(
            &self,
            expected: &$crate::Client,
            updated: $crate::Client,
        ) -> ::core::result::Result<bool, $crate::store::StorageError> {
            $crate::store::Storage::compare_and_swap_client(&self.$f, expected, updated).await
        }
    };
    (@one $f:tt, delete_client) => {
        async fn delete_client(
            &self,
            client_id: &$crate::ClientId,
            window: $crate::store::RevocationWindow,
        ) -> ::core::result::Result<bool, $crate::store::StorageError> {
            $crate::store::Storage::delete_client(&self.$f, client_id, window).await
        }
    };

    // -------------------------------------------------------------------------- device grants
    (@one $f:tt, put_device_grant) => {
        async fn put_device_grant(
            &self,
            grant: $crate::DeviceGrant,
        ) -> ::core::result::Result<(), $crate::store::StorageError> {
            $crate::store::Storage::put_device_grant(&self.$f, grant).await
        }
    };
    (@one $f:tt, get_device_grant) => {
        async fn get_device_grant(
            &self,
            device_code: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<$crate::DeviceGrant>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::get_device_grant(&self.$f, device_code).await
        }
    };
    (@one $f:tt, find_device_grant_by_user_code) => {
        async fn find_device_grant_by_user_code(
            &self,
            normalized_user_code: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<$crate::DeviceGrant>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::find_device_grant_by_user_code(&self.$f, normalized_user_code).await
        }
    };
    (@one $f:tt, take_device_grant) => {
        async fn take_device_grant(
            &self,
            device_code: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<$crate::DeviceGrant>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::take_device_grant(&self.$f, device_code).await
        }
    };
    (@one $f:tt, compare_and_swap_device_grant) => {
        async fn compare_and_swap_device_grant(
            &self,
            expected: &$crate::DeviceGrantState,
            updated: $crate::DeviceGrant,
        ) -> ::core::result::Result<bool, $crate::store::StorageError> {
            $crate::store::Storage::compare_and_swap_device_grant(&self.$f, expected, updated).await
        }
    };

    // --------------------------------------------------------------------- authorization codes
    (@one $f:tt, put_authorization_code) => {
        async fn put_authorization_code(
            &self,
            record: $crate::AuthorizationCodeRecord,
        ) -> ::core::result::Result<(), $crate::store::StorageError> {
            $crate::store::Storage::put_authorization_code(&self.$f, record).await
        }
    };
    (@one $f:tt, compare_and_swap_authorization_code) => {
        async fn compare_and_swap_authorization_code(
            &self,
            expected: &$crate::AuthorizationCodeState,
            updated: $crate::AuthorizationCodeRecord,
        ) -> ::core::result::Result<bool, $crate::store::StorageError> {
            $crate::store::Storage::compare_and_swap_authorization_code(&self.$f, expected, updated)
                .await
        }
    };
    (@one $f:tt, take_authorization_code) => {
        async fn take_authorization_code(
            &self,
            code: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<$crate::AuthorizationCodeRecord>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::take_authorization_code(&self.$f, code).await
        }
    };

    // ----------------------------------------------------------------------------------- PAR
    (@one $f:tt, put_pushed_authorization_request) => {
        $crate::__oauth_as_if_par! {
            async fn put_pushed_authorization_request(
                &self,
                record: $crate::par::PushedAuthorizationRequest,
            ) -> ::core::result::Result<$crate::store::WriteOutcome, $crate::store::StorageError> {
                $crate::store::Storage::put_pushed_authorization_request(&self.$f, record).await
            }
        }
    };
    (@one $f:tt, take_pushed_authorization_request) => {
        $crate::__oauth_as_if_par! {
            async fn take_pushed_authorization_request(
                &self,
                request_uri: &str,
            ) -> ::core::result::Result<
                ::core::option::Option<$crate::par::PushedAuthorizationRequest>,
                $crate::store::StorageError,
            > {
                $crate::store::Storage::take_pushed_authorization_request(&self.$f, request_uri)
                    .await
            }
        }
    };

    // -------------------------------------------------------------------------------- tokens
    (@one $f:tt, put_token) => {
        async fn put_token(
            &self,
            token: $crate::IssuedToken,
        ) -> ::core::result::Result<$crate::store::WriteOutcome, $crate::store::StorageError> {
            $crate::store::Storage::put_token(&self.$f, token).await
        }
    };
    (@one $f:tt, get_token) => {
        async fn get_token(
            &self,
            access_token: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<::std::sync::Arc<$crate::IssuedToken>>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::get_token(&self.$f, access_token).await
        }
    };
    (@one $f:tt, delete_token) => {
        async fn delete_token(
            &self,
            access_token: &str,
        ) -> ::core::result::Result<(), $crate::store::StorageError> {
            $crate::store::Storage::delete_token(&self.$f, access_token).await
        }
    };
    (@one $f:tt, put_refresh_token) => {
        async fn put_refresh_token(
            &self,
            record: $crate::RefreshTokenRecord,
        ) -> ::core::result::Result<$crate::store::WriteOutcome, $crate::store::StorageError> {
            $crate::store::Storage::put_refresh_token(&self.$f, record).await
        }
    };
    (@one $f:tt, get_refresh_token) => {
        async fn get_refresh_token(
            &self,
            refresh_token: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<::std::sync::Arc<$crate::RefreshTokenRecord>>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::get_refresh_token(&self.$f, refresh_token).await
        }
    };
    (@one $f:tt, take_refresh_token) => {
        async fn take_refresh_token(
            &self,
            refresh_token: &str,
        ) -> ::core::result::Result<
            ::core::option::Option<$crate::RefreshTokenRecord>,
            $crate::store::StorageError,
        > {
            $crate::store::Storage::take_refresh_token(&self.$f, refresh_token).await
        }
    };
    (@one $f:tt, revoke_token_family) => {
        async fn revoke_token_family(
            &self,
            family_id: &str,
            window: $crate::store::RevocationWindow,
        ) -> ::core::result::Result<u64, $crate::store::StorageError> {
            $crate::store::Storage::revoke_token_family(&self.$f, family_id, window).await
        }
    };

    // ------------------------------------------------------------------------------- consent
    (@one $f:tt, put_consent) => {
        $crate::__oauth_as_if_consent! {
            async fn put_consent(
                &self,
                record: $crate::ConsentRecord,
            ) -> ::core::result::Result<(), $crate::store::StorageError> {
                $crate::store::Storage::put_consent(&self.$f, record).await
            }
        }
    };
    (@one $f:tt, compare_and_swap_consent) => {
        $crate::__oauth_as_if_consent! {
            async fn compare_and_swap_consent(
                &self,
                expected: ::core::option::Option<&$crate::ConsentRecord>,
                updated: $crate::ConsentRecord,
            ) -> ::core::result::Result<bool, $crate::store::StorageError> {
                $crate::store::Storage::compare_and_swap_consent(&self.$f, expected, updated).await
            }
        }
    };
    (@one $f:tt, get_consent) => {
        $crate::__oauth_as_if_consent! {
            async fn get_consent(
                &self,
                consent_id: &str,
            ) -> ::core::result::Result<
                ::core::option::Option<::std::sync::Arc<$crate::ConsentRecord>>,
                $crate::store::StorageError,
            > {
                $crate::store::Storage::get_consent(&self.$f, consent_id).await
            }
        }
    };
    (@one $f:tt, find_consent) => {
        $crate::__oauth_as_if_consent! {
            async fn find_consent(
                &self,
                client_id: &$crate::ClientId,
                subject: &str,
            ) -> ::core::result::Result<
                ::core::option::Option<::std::sync::Arc<$crate::ConsentRecord>>,
                $crate::store::StorageError,
            > {
                $crate::store::Storage::find_consent(&self.$f, client_id, subject).await
            }
        }
    };
    (@one $f:tt, consents_for_subject) => {
        $crate::__oauth_as_if_consent! {
            async fn consents_for_subject(
                &self,
                subject: &str,
            ) -> ::core::result::Result<
                ::std::vec::Vec<::std::sync::Arc<$crate::ConsentRecord>>,
                $crate::store::StorageError,
            > {
                $crate::store::Storage::consents_for_subject(&self.$f, subject).await
            }
        }
    };
    (@one $f:tt, revoke_consent) => {
        $crate::__oauth_as_if_consent! {
            async fn revoke_consent(
                &self,
                consent_id: &str,
                window: $crate::store::RevocationWindow,
            ) -> ::core::result::Result<u64, $crate::store::StorageError> {
                $crate::store::Storage::revoke_consent(&self.$f, consent_id, window).await
            }
        }
    };

    // --------------------------------------------------------------------------------- replay
    (@one $f:tt, claim_replay_id) => {
        $crate::__oauth_as_if_replay! {
            async fn claim_replay_id(
                &self,
                id: &str,
                expires_at: ::std::time::SystemTime,
            ) -> ::core::result::Result<bool, $crate::store::StorageError> {
                $crate::store::Storage::claim_replay_id(&self.$f, id, expires_at).await
            }
        }
    };

    // ---------------------------------------------------------------------------------- sweep
    (@one $f:tt, sweep_expired) => {
        async fn sweep_expired(
            &self,
            now: ::std::time::SystemTime,
        ) -> ::core::result::Result<u64, $crate::store::StorageError> {
            $crate::store::Storage::sweep_expired(&self.$f, now).await
        }
    };
}
