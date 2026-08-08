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

## Where this actually stands, so nobody reads the file above as "done"

Last authoritative run: `cargo mutants -p oauth-as --features http,jwt --timeout 180`, at commit
`5f663c0`, with NOTHING excluded. This is the first run that ever compiled `src/http.rs`, so the
"artifact of the default feature set" note above no longer describes reality: the HTTP surface is
now measured like everything else.

**617 mutants: 498 caught, 36 missed, 77 unviable, 6 timeout.**

A note on how that number was obtained, because it matters for whether it can be trusted. The
first pass was run at `-j 10` on a machine that was busy, and 185 mutants hit the 180 second
timeout: an overloaded machine timing out proves nothing about the suite. Those 185 were re-run at
`-j 3 --timeout 300`, and the counts above are the first pass with every one of those results
replaced by its re-run. Only 6 survived the longer timeout, and each of those 6 is genuinely
non-terminating rather than merely slow:

- four in `http.rs` `decode_component`, where `i += 1` becomes `i -= 1` or `i *= 1` and the index
  never advances past the `while i < bytes.len()` bound;
- `jwt.rs` `from_scalar_bytes`, where `scalar.len() != 32` becomes `== 32` so EVERY 32 byte scalar
  is rejected and `EcdsaP256Key::generate`'s rejection-sampling loop can never accept one;
- `server.rs` `user_code_symbol -> None`, the same rejection-sampling case recorded before.

`cargo mutants` counts a timeout as caught, because the suite does not pass. That is the right
answer for all six.

### The 36 survivors

They are being worked through now; this section is updated as each is closed. By file:

- 19 in `crates/oauth-as/src/http.rs`
- 10 in `crates/oauth-as/src/jwt.rs`
- 4 in `crates/oauth-as/src/metadata.rs`
- 1 in `crates/oauth-as/src/scope.rs` (the `ScopeSet::empty` entry recorded above)
- 1 in `crates/oauth-as/src/events.rs`, 1 in `crates/oauth-as/src/server.rs`

So Gate 4 in `GOAL.md` is NOT met yet. It is met when every survivor above is either killed by a
test or recorded here with its argument. Anyone tempted to tick that gate early should re-read the
bar at the top of this file.
