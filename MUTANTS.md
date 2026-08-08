# Equivalent mutants

`cargo mutants -p oauth-as` is part of Gate 4 in `GOAL.md`: every surviving mutant is either killed
by a new test or recorded here, in writing, with the reason no test can kill it. A surviving mutant
is a hole in the suite, not a curiosity, so this file is deliberately short and each entry has to
argue that the mutated code is INDISTINGUISHABLE to a caller, not merely that killing it looked
inconvenient.

The bar an entry has to clear: there must be no observation a caller can make, including timing,
allocator traffic (`crates/oauth-as/tests/support/alloc.rs` provides a counting allocator, and
`crates/oauth-as/tests/allocation.rs` uses it), storage-call order (`support::FaultStorage` records
it), or serialized output, that differs between the original and the mutant. "I could not think of a
test" is not the bar.

## crates/oauth-as/src/scope.rs, `ScopeSet::empty`

```
crates/oauth-as/src/scope.rs:65:9: replace ScopeSet::empty -> Self with Default::default()
```

Original:

```rust
pub fn empty() -> Self {
    ScopeSet(BTreeSet::new())
}
```

Mutant: `Default::default()`.

`ScopeSet` is `#[derive(Default)]` over a single `BTreeSet<Scope>` field, so `ScopeSet::default()`
expands to `ScopeSet(BTreeSet::<Scope>::default())`, and `BTreeSet::default()` is documented and
implemented as `BTreeSet::new()`. The mutant is therefore the same expression written a different
way: same type, same value, same `PartialEq`, same `Display` (the empty string), same serialization
(`""`), same `len` (0), same `is_empty` (true), same iteration (no items).

It is not distinguishable by cost either. `BTreeSet::new()` is a `const fn` that allocates nothing:
an empty `BTreeSet` has no root node, so there is no allocation to count on either side and the
counting allocator sees a zero delta for both. There is no interior mutability, no capacity hint,
and no `Drop` behaviour that could differ.

No test can distinguish these, because there is nothing to distinguish. Kept as `BTreeSet::new()`
rather than `Default::default()` only because it names what it builds.

## Note on the `http` feature

A plain `cargo mutants -p oauth-as` run reports a large number of missed mutants in
`crates/oauth-as/src/http.rs`. Those are an artifact of the default feature set, not holes: the HTTP
surface is behind the off-by-default `http` feature, so with default features the module is not
compiled and its tests do not run, yet `cargo mutants` still lists mutants for it. Judge that module
with `cargo mutants -p oauth-as --features http` instead.
