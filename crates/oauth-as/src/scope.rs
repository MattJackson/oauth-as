// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Access-token scope, mirrored from RFC 6749 section 3.3: a scope is a space-delimited set of
//! case-sensitive tokens, each drawn from `%x21 / %x23-5B / %x5D-7E` (printable ASCII minus space,
//! double quote, and backslash).

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// One scope token, charset-validated at construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(String);

/// The rejection for a malformed scope token (empty, or a byte outside the RFC 6749 section 3.3
/// charset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidScopeToken(pub String);

impl fmt::Display for InvalidScopeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid scope token {:?}", self.0)
    }
}

impl std::error::Error for InvalidScopeToken {}

fn scope_char_ok(b: u8) -> bool {
    b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b)
}

impl Scope {
    /// Validate and wrap one scope token.
    pub fn new(token: impl Into<String>) -> Result<Self, InvalidScopeToken> {
        let token = token.into();
        if token.is_empty() || !token.bytes().all(scope_char_ok) {
            return Err(InvalidScopeToken(token));
        }
        Ok(Scope(token))
    }

    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An ordered, deduplicated set of scope tokens. The wire form (both directions) is the RFC's
/// space-delimited string; ordering here is lexicographic so serialization is deterministic.
///
/// # Why a sorted `Vec` and not a `BTreeSet`
///
/// This was a `BTreeSet<Scope>` through 0.9.1, and the INVARIANT is unchanged: the tokens are held
/// sorted and deduplicated, so `Display`, `Serialize`, `PartialEq` and `is_subset` all answer
/// exactly what the tree answered. What changed is the code the invariant costs.
///
/// The set this type actually holds is tiny. A scope set is the `scope` parameter of one request or
/// the `allowed_scopes` of one client: single digits of tokens, each a handful of bytes. A B-tree
/// is machinery for a set that is large enough for the log factor to pay for the node bookkeeping,
/// and at these sizes it never does — it allocates a whole node to hold one token, and every
/// operation on it links a distinct instantiation of `BTreeMap`'s insert, clone and comparison
/// paths into the binary.
///
/// MEASURED 2026-08-13 by `scripts/size-report.sh` on the `default` row (aarch64-apple-darwin,
/// rustc 1.97.0): 15,394 bytes, taking the row from 234,623 to 219,229. That is not the tree's
/// insert alone; it is every `BTreeMap` instantiation this type forced into a linked binary —
/// insert with its node splitting, `clone_subtree`, `PartialEq::eq`, `is_subset`'s range descent,
/// the iterators and the drop glue — none of which a host that only ever holds five scope tokens
/// was getting anything for. It is the same trade, for the same reason, as the one `crate::store`'s
/// barrier list records: an ordered container whose reads were a linear scan anyway does not need a
/// tree to be one.
///
/// It is also a much smaller heap footprint per stored record, which is the part that scales with
/// a deployment rather than with the binary. A `BTreeSet` allocates a whole leaf node the moment it
/// holds anything, and that node is the same size for one token as for eleven. MEASURED with
/// `tests/support/alloc.rs`, `ScopeSet::parse`:
///
/// | tokens | before          | after         |
/// |--------|-----------------|---------------|
/// | 1      | 2 allocs, 284 B | 2 allocs, 28 B |
/// | 3      | 4 allocs, 294 B | 4 allocs, 86 B |
///
/// Same allocation COUNT — the vector is sized once from the token count, so it does not trade
/// bytes for calls — and 90% fewer bytes at the size a real `scope` parameter actually is. Every
/// `Client`, `IssuedToken`, `AuthorizationCodeRecord`, `RefreshTokenRecord`, `DeviceGrant` and
/// consent record in a store was carrying one of those 256-byte nodes to hold a word or two.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    /// The empty set (serializes to the empty string; hosts normally omit the parameter instead).
    pub fn empty() -> Self {
        ScopeSet(Vec::new())
    }

    /// Establish the type's invariant on a freshly built vector: sorted lexicographically, with
    /// duplicates removed. Every constructor ends here, so there is one place the invariant is
    /// made true and one place to read to check that it is.
    fn sorted(mut tokens: Vec<Scope>) -> Self {
        tokens.sort_unstable();
        tokens.dedup();
        ScopeSet(tokens)
    }

    /// Parse a space-delimited scope string. Repeated whitespace is tolerated; each token is
    /// charset-validated.
    ///
    /// # There is NO cap on the token count, and that is a decision with a cost
    ///
    /// MEASURED by `benches/scaling.rs`, both implementations on the same machine in the same
    /// session, 2026-08-13:
    ///
    /// | tokens | `BTreeSet` (through 0.9.1) | sorted `Vec` |
    /// |--------|---------------------------|--------------|
    /// | 1      | 32.0 ns                   | 39.0 ns      |
    /// | 10     | 330 ns                    | 340 ns       |
    /// | 100    | 6.05 us                   | 4.41 us      |
    /// | 1000   | 81.09 us                  | 48.68 us     |
    ///
    /// The seven nanoseconds at one token are the pre-pass that COUNTS the tokens, and they are what
    /// buys the single correctly-sized allocation; from a hundred tokens up the sort is the faster
    /// structure by a wide margin. The growth is n log n either way, so this is not the accidental
    /// quadratic that [`crate::server::MAX_RESOURCE_INDICATORS`] exists to bound; it is a
    /// straightforward "how big may the parameter be" question, and reaching the top of that range
    /// takes roughly ten kilobytes of `scope`, which a host's own request-size limit is the right
    /// place to refuse.
    ///
    /// A cap here was considered and NOT taken, because it cannot be expressed without a breaking
    /// change that is out of proportion to the problem: [`InvalidScopeToken`] is a tuple struct
    /// with a public field, so it cannot gain a "too many" variant, and this same function is the
    /// [`serde::Deserialize`] implementation for every persisted record that carries a scope, as
    /// well as the constructor a host uses for its own `allowed_scopes`. A limit applied here would
    /// therefore be a limit on what a deployment may REGISTER and on what it can read back out of
    /// its own store, which is a different and much larger decision than bounding a request.
    ///
    /// If a bound is wanted, the place for it is the wire boundary, alongside the other request
    /// caps, and it needs an error type this one cannot currently express.
    pub fn parse(s: &str) -> Result<Self, InvalidScopeToken> {
        // Counted first so the vector is allocated ONCE at the right size. The count is a scan of a
        // string already in cache and is what keeps a parse at one allocation plus one `String` per
        // token, which `tests/allocation.rs` pins.
        let count = s.split(' ').filter(|t| !t.is_empty()).count();
        let mut tokens = Vec::with_capacity(count);
        for tok in s.split(' ').filter(|t| !t.is_empty()) {
            tokens.push(Scope::new(tok)?);
        }
        Ok(ScopeSet::sorted(tokens))
    }

    /// Build from tokens, validating each.
    pub fn from_tokens<I, T>(tokens: I) -> Result<Self, InvalidScopeToken>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let iter = tokens.into_iter();
        let mut out = Vec::with_capacity(iter.size_hint().0);
        for t in iter {
            out.push(Scope::new(t)?);
        }
        Ok(ScopeSet::sorted(out))
    }

    /// True when every token in `self` is also in `other`.
    ///
    /// A merge walk over two sorted, deduplicated slices: linear in the two lengths, with no
    /// allocation and no tree descent. Same answer the `BTreeSet` gave.
    pub fn is_subset(&self, other: &ScopeSet) -> bool {
        let mut theirs = other.0.iter();
        'mine: for mine in &self.0 {
            for other in theirs.by_ref() {
                match other.cmp(mine) {
                    std::cmp::Ordering::Less => continue,
                    std::cmp::Ordering::Equal => continue 'mine,
                    // `other` has passed `mine` in sort order, so `mine` is not in `other`.
                    std::cmp::Ordering::Greater => return false,
                }
            }
            return false;
        }
        true
    }

    /// True when the set holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Membership test.
    pub fn contains(&self, token: &str) -> bool {
        self.0.iter().any(|s| s.as_str() == token)
    }

    /// Iterate tokens in lexicographic order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for s in &self.0 {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            f.write_str(s.as_str())?;
        }
        Ok(())
    }
}

impl Serialize for ScopeSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ScopeSet::parse(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
#[path = "tests/scope.rs"]
mod tests;
