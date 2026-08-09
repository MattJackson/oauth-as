// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9396 rich authorization requests: the `authorization_details` parameter, which says what a
//! client is asking for as STRUCTURE rather than as a scope string.
//!
//! # Why this exists
//!
//! A scope is a bare token. "payments" cannot say "transfer 50 euros to IBAN X, once, today", so
//! any deployment doing payments, or transaction-level consent of any kind, has to express the
//! transaction somewhere. RFC 9396 section 2 is that somewhere: a JSON array of objects, each with
//! a REQUIRED `type` that names whose vocabulary the rest of the object is written in.
//!
//! # The two rules this module is really about
//!
//! 1. **Unknown members are PRESERVED, not dropped.** Section 2 makes `type` the thing that
//!    defines every other member, so an AS that keeps the members it recognises and silently
//!    discards the rest has granted something OTHER than what was requested, and neither the
//!    client nor the resource owner is told. [`AuthorizationDetail::other`] is where everything
//!    this crate has no opinion about is kept, byte for byte, through storage, through
//!    introspection and into the RFC 9068 token.
//! 2. **An unknown `type` is REFUSED, not ignored.** Section 5: "The AS MUST refuse to process any
//!    unknown authorization details type or authorization details not conforming to the respective
//!    type definition", answering `invalid_authorization_details`. Ignoring the element instead
//!    would issue a token that says nothing about a permission the client believes it obtained.
//!
//! # Bounds, because this is attacker-supplied JSON
//!
//! `authorization_details` arrives unauthenticated at the authorization endpoint, before any user
//! interaction, in a parameter whose grammar is "some JSON". An AS that parses whatever it is sent
//! is a denial of service with extra steps, so three limits are applied. They are constants rather
//! than configuration on purpose: a host cannot accidentally raise them, and nothing in RFC 9396
//! asks for values larger than these.
//!
//! WHERE each one runs is stated precisely, because it decides what the limit actually buys:
//!
//! - [`MAX_AUTHORIZATION_DETAILS_BYTES`], on the RAW parameter, before `serde_json` is handed
//!   anything. This is the only one that runs before a structure is built, and it is the one that
//!   makes every cost below it finite, including the parser's own.
//! - [`MAX_AUTHORIZATION_DETAILS_ELEMENTS`], on the PARSED array, and
//! - [`MAX_AUTHORIZATION_DETAILS_DEPTH`], on nesting inside a parsed element.
//!
//! The last two run on an already-built tree. That is a deliberate choice and not an oversight:
//! applying them earlier would mean a second JSON scanner, written here, that has to agree with
//! `serde_json` about strings and escapes in order to count brackets correctly, and a second
//! scanner that disagrees with the first is a parser differential, which is a worse class of bug
//! than the one it would prevent. What makes it safe to let the parser run first is the byte bound
//! above it, and the arithmetic is worth writing down: 4096 bytes of raw JSON cannot express more
//! than about 2047 levels of nesting, since each level costs at least one byte, so the parser's
//! recursion and the resulting tree's recursive `Drop` are both bounded at a few hundred kilobytes
//! of stack whatever the input says. That argument depends on nothing but this crate's own
//! constant. `serde_json` also refuses past its own limit near 128, which would refuse such input
//! sooner, but that limit is a dependency's implementation detail rather than a contract and
//! nothing here is allowed to rest on it.
//!
//! See each constant for the number and why it is that number.
//!
//! # What this module does NOT decide
//!
//! Whether the resource owner should approve a detail. That is the host's consent screen, and RFC
//! 9396 section 7.1 explicitly allows the granted detail to differ from the requested one. This
//! module decides only what is well formed, what type names are admissible, and (the security core
//! of the slice) whether a later leg of the same grant is asking for MORE than was granted.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{ErrorCode, ErrorResponse};

/// The largest `authorization_details` parameter this server will parse, in bytes of raw JSON.
///
/// 4096 is chosen against the two places the parameter actually travels. At the authorization
/// endpoint it is a query parameter, so it is percent-encoded and lands somewhere near three times
/// this in the request line, which is the region where deployed proxies and browsers start
/// refusing URLs: a host fronted by one of those will refuse before this does, and that is fine,
/// because both answers are "no". At the token endpoint it is a form field, where nothing forces a
/// limit at all, which is exactly why one is imposed here.
///
/// It is generous against real payloads: every example in RFC 9396 (including the appendix A
/// payment initiation ones, which are the largest published) is a few hundred bytes. A request
/// that needs more than an order of magnitude over the RFC's own worst example is not a request
/// this server has to be able to serve.
pub const MAX_AUTHORIZATION_DETAILS_BYTES: usize = 4096;

/// The largest number of elements in the array (RFC 9396 section 2).
///
/// 16 distinct authorization details in ONE request is already beyond anything the RFC
/// illustrates; the point of the parameter is that a request names the specific things it needs.
/// The bound matters because narrowing at the token endpoint compares every requested element
/// against every granted one, which is quadratic: bounded at 16 that is 256 comparisons, and
/// unbounded it is a CPU denial of service that a single request can aim at this server.
pub const MAX_AUTHORIZATION_DETAILS_ELEMENTS: usize = 16;

/// The deepest JSON nesting allowed, counting the array itself as level 1 and an element object as
/// level 2.
///
/// 8 leaves six levels inside an element, which is more than any published RFC 9396 type uses
/// (appendix A's deepest is three).
///
/// It is enforced on the PARSED tree, so it is not what keeps the parser off the stack: read the
/// module docs for what does, which is [`MAX_AUTHORIZATION_DETAILS_BYTES`] and an argument that
/// rests on this crate's own constant rather than on `serde_json`'s recursion limit. What this
/// bound buys is that every recursive walk THIS module performs afterwards, over a value that will
/// be stored on an authorization code, carried across a rotation, and compared element by element
/// at every narrowing, is shallow by contract rather than by whatever the parser happened to
/// accept.
pub const MAX_AUTHORIZATION_DETAILS_DEPTH: usize = 8;

/// The depth budget left for a member VALUE inside an element: the total, minus the array and the
/// element object that necessarily enclose it.
const MAX_MEMBER_DEPTH: usize = MAX_AUTHORIZATION_DETAILS_DEPTH - 2;

/// One element of `authorization_details` (RFC 9396 section 2).
///
/// Every field is WRITE ONCE, so each is a `Box<str>` or a `Box<[Box<str>]>` rather than a `String`
/// or a `Vec`: nothing here is ever pushed to or truncated after parsing, and the capacity word a
/// growable type carries would be 8 bytes of nothing, per field, in every stored authorization
/// code, access token and refresh record for the life of the grant. That is 48 bytes an element
/// against roughly 190, and a store holds one of these per live grant, not one per process.
///
/// `type` is REQUIRED (section 2) and is what gives every other member its meaning. The named
/// fields below are the section 2.2 COMMON data fields, which are common precisely because their
/// meaning does not depend on the type; everything else lands in [`AuthorizationDetail::other`]
/// and is carried unchanged.
///
/// # Why `other` is not a convenience
///
/// It is the correctness of the whole feature. Section 2 says the type defines the object, so a
/// member this crate does not recognise is a member this crate is not entitled to have an opinion
/// about, least of all the opinion "it did not matter". Dropping it would mean the token that
/// comes back describes a different authorization from the one that was asked for and approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// RFC 9396 section 2: REQUIRED, and the identifier of the API-defined vocabulary the rest of
    /// this object is written in. Named `detail_type` in Rust because `type` is a keyword; the
    /// wire spelling is pinned by the `serde` rename and is the only spelling that exists off-host.
    #[serde(rename = "type")]
    pub detail_type: Box<str>,
    /// RFC 9396 section 2.2 `locations`: the resource server(s) this detail is for. Empty means
    /// the member was absent.
    #[serde(default, skip_serializing_if = "is_empty_list")]
    pub locations: Box<[Box<str>]>,
    /// RFC 9396 section 2.2 `actions`: the actions taken at the resource.
    #[serde(default, skip_serializing_if = "is_empty_list")]
    pub actions: Box<[Box<str>]>,
    /// RFC 9396 section 2.2 `datatypes`: the kinds of data being asked for.
    #[serde(default, skip_serializing_if = "is_empty_list")]
    pub datatypes: Box<[Box<str>]>,
    /// RFC 9396 section 2.2 `identifier`: the specific resource this detail is about. A string,
    /// not an array: section 2.2 defines exactly one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Box<str>>,
    /// RFC 9396 section 2.2 `privileges`: the level of access asked for.
    #[serde(default, skip_serializing_if = "is_empty_list")]
    pub privileges: Box<[Box<str>]>,
    /// Every other member, exactly as it arrived. See the type's doc comment: this is preservation,
    /// not tolerance.
    ///
    /// `serde_json::Map` is a `BTreeMap` in this crate's dependency configuration (the
    /// `preserve_order` feature is not enabled), so serialization is deterministic and two
    /// structurally equal details compare equal whatever order their members were sent in. That
    /// determinism is load bearing for [`AuthorizationDetails::narrow`], which compares these
    /// members for equality.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl AuthorizationDetail {
    /// Whether `self` asks for no more than `granted` does, so that issuing `self` grants nothing
    /// the resource owner did not already approve (RFC 9396 section 6).
    ///
    /// Section 6.1 is explicit that "there is no standardized mechanism to compare two arbitrary
    /// authorization detail requests", because only the API that defined the type knows what its
    /// members mean. This crate therefore does the one comparison that is sound WITHOUT knowing the
    /// type: it narrows on the section 2.2 common fields, whose meaning the RFC does fix, and
    /// requires everything else to be IDENTICAL.
    ///
    /// The consequences are deliberate and worth stating, because they are refusals:
    ///
    /// - a different `type`, or a different `identifier`, is not a narrowing of anything. In
    ///   particular a request that DROPS an `identifier` the grant carried is asking for the whole
    ///   class instead of the one resource, which is the widest possible move dressed as an
    ///   omission;
    /// - `locations`, `actions`, `datatypes` and `privileges` must each be a subset. An absent
    ///   list on the granted side is an EMPTY list here, so it can only be narrowed to itself.
    ///   Reading absent as "unrestricted, so anything is narrower" would let the token endpoint
    ///   name a location the authorization request never obtained, and this crate already refuses
    ///   the same move for RFC 8707 resource indicators (`AuthorizationServer::narrow_resources`);
    /// - any other member must match exactly. A type-specific member could mean anything, and
    ///   "anything" includes "an amount", so accepting a changed one on the theory that it looked
    ///   smaller is how an AS authorizes a transfer nobody approved.
    ///
    /// A deployment whose API genuinely admits a partial-order narrowing of its own members can
    /// still express it: it narrows at its consent screen, where the type IS known, and asks the
    /// token endpoint for exactly what it was granted.
    pub fn is_narrowing_of(&self, granted: &AuthorizationDetail) -> bool {
        self.detail_type == granted.detail_type
            && self.identifier == granted.identifier
            && is_subset(&self.locations, &granted.locations)
            && is_subset(&self.actions, &granted.actions)
            && is_subset(&self.datatypes, &granted.datatypes)
            && is_subset(&self.privileges, &granted.privileges)
            && self.other == granted.other
    }
}

/// Every value in `subset` also appears in `superset`.
///
/// A linear scan rather than a set: these lists are bounded by
/// [`MAX_AUTHORIZATION_DETAILS_BYTES`] and are in practice two or three entries, so building a
/// `BTreeSet` per comparison would allocate more than it saved.
fn is_subset(subset: &[Box<str>], superset: &[Box<str>]) -> bool {
    subset.iter().all(|want| superset.iter().any(|g| g == want))
}

/// `skip_serializing_if` for the section 2.2 list members. A named function rather than
/// `<[_]>::is_empty` because `skip_serializing_if` takes a path and the `Box<[T]>` receiver has to
/// reach `&[T]` by deref coercion, which only happens at a call site.
fn is_empty_list(list: &[Box<str>]) -> bool {
    list.is_empty()
}

/// The `authorization_details` array (RFC 9396 section 2).
///
/// Empty is the ordinary case and is what "the client sent no `authorization_details`" means; an
/// empty `Vec` allocates nothing, so a deployment that never uses RAR pays for the field and
/// nothing else. That mirrors [`crate::authorization::AuthorizationCodeRecord::resource`], which
/// made the same choice for RFC 8707 for the same reason.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorizationDetails(Vec<AuthorizationDetail>);

impl AuthorizationDetails {
    /// The empty set: no rich authorization detail at all. `const`, and allocation-free: an empty
    /// `Vec` has no heap block, so the overwhelmingly common "this grant carries no rich
    /// authorization detail" costs nothing at all.
    pub const fn none() -> Self {
        AuthorizationDetails(Vec::new())
    }

    /// Parse the raw parameter as RFC 9396 section 2 defines it, applying this module's bounds.
    ///
    /// Every failure is `invalid_authorization_details` (section 5), and none of them echoes the
    /// offending text: RFC 6749 section 5.2 restricts `error_description` to a charset that
    /// arbitrary JSON does not respect, and reflecting attacker-controlled bytes into an error body
    /// is how an error message becomes an injection.
    pub fn parse(raw: &str) -> Result<Self, ErrorResponse> {
        // SIZE FIRST, before the parser is handed anything. This is the bound that makes every
        // other cost in this function finite.
        if raw.len() > MAX_AUTHORIZATION_DETAILS_BYTES {
            return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                .with_description("authorization_details is larger than this server accepts"));
        }
        let details: Vec<AuthorizationDetail> = serde_json::from_str(raw).map_err(|e| {
            // The parser's message can quote the input, so it is dropped rather than forwarded.
            let _ = e;
            ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails).with_description(
                "authorization_details must be a JSON array of objects, each with a string type \
                 member (RFC 9396 s2)",
            )
        })?;
        if details.len() > MAX_AUTHORIZATION_DETAILS_ELEMENTS {
            return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                .with_description(
                    "authorization_details has more elements than this server accepts",
                ));
        }
        for detail in &details {
            // An empty type is not a type: section 2 makes it an identifier for the API's
            // vocabulary, and the empty string names nothing that could be looked up.
            if detail.detail_type.is_empty() {
                return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                    .with_description(
                        "each authorization_details element needs a non-empty type (RFC 9396 s2)",
                    ));
            }
            for value in detail.other.values() {
                if depth(value) > MAX_MEMBER_DEPTH {
                    return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                        .with_description(
                            "authorization_details is nested more deeply than this server accepts",
                        ));
                }
            }
        }
        Ok(AuthorizationDetails(details))
    }

    /// RFC 9396 section 5: refuse any type this server was not told it supports.
    ///
    /// `supported` is the host's `authorization_details_types_supported`
    /// ([`crate::server::ServerConfig::authorization_details_types_supported`]). `None` means the
    /// host declared no types, and therefore that EVERY type is unknown: a server that has not been
    /// told which vocabularies it speaks cannot be said to know one, and section 5's MUST is not
    /// satisfied by hoping. That is also what makes the feature safe to compile in before it is
    /// configured.
    pub fn require_supported_types(
        &self,
        supported: Option<&[String]>,
    ) -> Result<(), ErrorResponse> {
        let supported = supported.unwrap_or(&[]);
        for detail in &self.0 {
            if !supported.iter().any(|s| s.as_str() == &*detail.detail_type) {
                // The type is NOT echoed, for the reason `parse` gives.
                return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                    .with_description("unknown authorization_details type (RFC 9396 s5)"));
            }
        }
        Ok(())
    }

    /// The details an issuance actually gets: `requested` may NARROW what `self` carries, and may
    /// never widen it (RFC 9396 section 6).
    ///
    /// This is deliberately the same SHAPE as the three narrowing rules this crate already applies
    /// (RFC 6749 section 6 scope on refresh, RFC 8707 section 2 resources, RFC 8693 exchange), and
    /// it is the same argument in each: the resource owner approved a specific thing, and a later
    /// leg of the same grant asking for more than that is either a client bug or an escalation,
    /// and the AS cannot tell which.
    ///
    /// An empty `requested` asks for no narrowing, so the grant passes through unchanged. A grant
    /// that carries NO details has nothing to narrow, so any request against it is widening from
    /// nothing and is refused; answering otherwise would let the token endpoint mint authorization
    /// detail that no authorization request ever obtained.
    pub fn narrow(
        &self,
        requested: &AuthorizationDetails,
    ) -> Result<AuthorizationDetails, ErrorResponse> {
        if requested.is_empty() {
            return Ok(self.clone());
        }
        // Each requested element must consume a DISTINCT granted element.
        //
        // Matching every requested element independently is the obvious implementation and it is
        // wrong in one specific way: an exact copy of a granted element is, individually, a
        // perfect narrowing of it, so N copies all match the same grant and one authorization
        // becomes N. Nothing is added or broadened, only repeated, which is why a per-element
        // check cannot see it.
        //
        // Whether N copies MEAN N of anything is type defined, and RFC 9396 s6.1 is explicit that
        // the authorization server cannot know: only the API that defined the `type` does. Every
        // other ambiguity in `is_narrowing_of` is resolved by refusing (a changed `identifier`, a
        // dropped one, a changed type defined member), and duplication was the one that got the
        // permissive answer. It gets the same answer as the rest now.
        //
        // Genuine narrowing is untouched: a narrowed element still matches its granted element
        // once, and two distinct grants still satisfy two distinct requests.
        let mut consumed = vec![false; self.0.len()];
        for want in &requested.0 {
            let matched = self
                .0
                .iter()
                .enumerate()
                .position(|(i, granted)| !consumed[i] && want.is_narrowing_of(granted));
            match matched {
                Some(i) => consumed[i] = true,
                None => {
                    return Err(ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
                        .with_description(
                            "authorization_details was not granted by the authorization request \
                         (RFC 9396 s6)",
                        ))
                }
            }
        }
        Ok(requested.clone())
    }

    /// No elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many elements.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The elements, in the order they were requested. RFC 9396 gives the array no ordering
    /// semantics, so this is the client's order preserved rather than a sorted one: re-ordering
    /// what is handed back to a resource server would be another way of changing it.
    pub fn iter(&self) -> impl Iterator<Item = &AuthorizationDetail> {
        self.0.iter()
    }

    /// The elements as a slice.
    pub fn as_slice(&self) -> &[AuthorizationDetail] {
        &self.0
    }

    /// Build from already-constructed elements, for a host whose consent screen ENRICHED what the
    /// client asked for (RFC 9396 section 7.1 permits exactly that: the details attached to the
    /// token may differ from the request).
    ///
    /// No bound is applied here, and that is not an oversight: this is the HOST's own data, not the
    /// wire's, and the bounds in [`AuthorizationDetails::parse`] exist to defend against an
    /// unauthenticated stranger rather than against the deployment itself.
    pub fn from_elements(elements: Vec<AuthorizationDetail>) -> Self {
        AuthorizationDetails(elements)
    }
}

/// The nesting depth of one JSON value: 1 for a scalar, 1 + the deepest child for a container.
///
/// Recursive, and safely so, but NOT because of `serde_json`'s recursion limit, which is a
/// dependency's implementation detail. The tree this walks came from at most
/// [`MAX_AUTHORIZATION_DETAILS_BYTES`] of raw JSON, and a level of nesting costs at least a byte,
/// so it is at most about 2047 deep however the parser was configured. The check exists to make
/// the bound THIS crate promises ([`MAX_AUTHORIZATION_DETAILS_DEPTH`]) an actual refusal rather
/// than a comment.
fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(members) => 1 + members.values().map(depth).max().unwrap_or(0),
        _ => 1,
    }
}

#[cfg(test)]
#[path = "tests/rar.rs"]
mod tests;
