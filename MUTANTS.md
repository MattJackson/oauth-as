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

## crates/oauth-as/src/http.rs, `decode_component`, `|` to `^`

```
crates/oauth-as/src/http.rs: replace | with ^ in decode_component
```

Original: `out.push((h << 4) | l);`

Mutant: `out.push((h << 4) ^ l);`

`h` and `l` are not arbitrary bytes. They are exactly what `hex_value` returns, and `hex_value`
returns `Some(v)` only for `v` in `0..=15`: `b - b'0'` over `b'0'..=b'9'`, and `b - b'a' + 10` or
`b - b'A' + 10` over the two hex-letter ranges. So `h <= 15`, which makes `h << 4` a value whose
low four bits are all zero, and `l <= 15`, which makes `l` a value whose high four bits are all
zero. The two operands have NO set bit in common.

For operands with disjoint set bits, `a | b` and `a ^ b` are the same value, bit for bit, for every
input: they differ only where both operands have a 1, and here that never happens. The mutant is
not merely hard to distinguish, it computes the identical function on the whole of its reachable
domain, and `tests/http.rs::hex_value_is_exhaustively_correct_over_every_byte` pins that domain
over all 256 input bytes, so the premise cannot drift without a test failing.

Nothing else differs either. Both are a single register operation on `u8`, so there is no
allocation to count, no branch to time, and no storage call to order. The output byte is the same,
so every serialized form downstream of it is the same.

`|` is kept because it says what is meant: two nibbles are being ASSEMBLED, not combined.

## crates/oauth-as/src/events.rs, `RateLimiter::record`'s default body

```
crates/oauth-as/src/events.rs: replace RateLimiter::record with ()
```

Original:

```rust
fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
    let _ = (attempt, outcome);
}
```

Mutant: an empty body.

The original body is already a no-op, and `let _ = expr;` is the specific spelling that is a no-op
even in principle: it discards without binding, so nothing is moved into a place that would later
be dropped. Both parameters are `Copy` (`Attempt` and `AttemptOutcome` both derive it), so there is
no `Drop` implementation for the discard to run and no ownership to transfer. The tuple is never
constructed in any observable sense.

So the default `record` does nothing, and the mutant does nothing. There is no return value, no
`&mut self`, no interior mutability on `&self` (the trait's `self` is shared and the method takes
no state), no allocation, and no call into anything. A host that overrides `record` is unaffected:
overriding replaces the body entirely, and every test that cares about `record` installs a limiter
that overrides it.

The `let _ = ...;` is kept because without it the two parameters are unused and the compiler warns,
and `#[allow(unused)]` on a public trait method is worse documentation than one line that says
"deliberately ignored".

## crates/oauth-as/src/metadata.rs, `advertised_jwks_uri` under `#[cfg(not(feature = "jwt"))]`

```
crates/oauth-as/src/metadata.rs: replace advertised_jwks_uri -> Option<String> with None
crates/oauth-as/src/metadata.rs: replace advertised_jwks_uri -> Option<String> with Some(String::new())
crates/oauth-as/src/metadata.rs: replace advertised_jwks_uri -> Option<String> with Some("xyzzy".into())
```

These are NOT equivalent and they are NOT holes. They are the same feature-gating artifact the
`http` note used to describe, pointing the other way.

`metadata.rs` defines `advertised_jwks_uri` twice: once under `#[cfg(feature = "jwt")]` and once
under `#[cfg(not(feature = "jwt"))]`. A run with `--features http,jwt` compiles only the first, so
mutating the second changes nothing that is built, the suite passes, and `cargo mutants` records a
miss. The three above are all in the `not(jwt)` copy.

The behaviour they describe IS pinned, in the configuration where it exists:
`src/tests/metadata.rs::without_the_jwt_feature_jwks_uri_is_whatever_the_host_declared` is itself
`#[cfg(not(feature = "jwt"))]` and asserts both directions (absent when the host declared nothing,
and exactly the host's value when it did). A default-features run is what judges these, and it
kills them.

The general rule this makes explicit, and it cuts both ways: a mutation run judges only the
configuration it was built with. Any `#[cfg]`-selected alternative needs its own run, and a "miss"
in a block the run did not compile is a statement about the run, not about the suite.

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

### The 36 survivors, and what happened to each

All 36 are now accounted for. Thirty are killed by tests, three are recorded above as equivalent,
and three are the `#[cfg]` artifact recorded above.

| File | Survivors | Killed | Equivalent | `cfg` artifact |
| --- | --- | --- | --- | --- |
| `src/http.rs` | 19 | 18 | 1 | 0 |
| `src/jwt.rs` | 10 | 10 | 0 | 0 |
| `src/metadata.rs` | 4 | 1 | 0 | 3 |
| `src/scope.rs` | 1 | 0 | 1 | 0 |
| `src/events.rs` | 1 | 0 | 1 | 0 |
| `src/server.rs` | 1 | 1 | 0 | 0 |
| **total** | **36** | **30** | **3** | **3** |

The tests that close them:

- `crates/oauth-as/tests/jwt_key_identity.rs`, new: the `kid`, `PartialEq` over the public identity,
  both error `Display` implementations, and the `Debug` redaction, including through
  `ServerConfig`, which is the path a host actually takes when it logs its configuration.
- `crates/oauth-as/src/tests/jwt.rs`, new: `unix_seconds`, the only reachable source of a
  `JwtError`, so its refusal and its message are testable at all.
- `crates/oauth-as/src/tests/http.rs`, appended: `hex_value` exhaustively over all 256 bytes,
  lowercase percent escapes, a truncated escape one byte from the end, RFC 8707 repeated resource
  indicators, `optional_scope`, every `RouterError` message, and the message page.
- `crates/oauth-as/tests/http_verification_outcomes.rs`, new: the subject seam, the approve and deny
  outcome text, the two `render_verification` message cases, and the 500 and 429 statuses.
- `crates/oauth-as/src/tests/metadata.rs`, appended: `issuer_path` against a SHORT authority, which
  is the only shape where a wrong offset into the issuer stops being invisible.
- `crates/oauth-as/tests/server_hook_accessor.rs`, new: `AuthorizationServer::hooks` returns the
  seams the host installed.

### Proof that those tests actually kill them

Writing a test that passes is not evidence. The 36 survivor descriptions were re-run as a filter
(`cargo mutants -p oauth-as --features http,jwt --timeout 300 -j 3 -F <the 36 descriptions>`)
against the tree WITH the new tests. That filter matched 49 mutants, since some descriptions occur
at more than one site, and the result was:

**49 mutants: 43 caught, 2 missed, 4 timeout.**

The 2 missed are exactly `events.rs` `RateLimiter::record` and `http.rs` `decode_component`'s
`|` to `^`, the two argued as equivalent above, and nothing else. Of the 4 timeouts, three are the
`advertised_jwks_uri` `cfg` artifact and one is `ScopeSet::empty`; the baseline suite took 257
seconds against a 300 second timeout on a machine several other builds were sharing, so those are
load, not detection. Neither reading changes the position, because all four are already accounted
for above.

Every other one of the 36 went from missed to caught. That is the red-before-green evidence for
this file.

### What is NOT covered by this run, stated so it is not mistaken for coverage

- Only the `http,jwt` configuration was measured. `#[cfg]`-selected alternatives (the
  `not(feature = "jwt")` bodies, and the `client_assertion`, `dpop`, `par`, `rar` and `mtls`
  features as they land) each need their own run.
- The run is at commit `5f663c0`. Modules added after it (`registration`, `resource_metadata`,
  `token_exchange`, and whatever follows) have NEVER been mutation tested, exactly as `http.rs` had
  not been before this one. They need a run of their own before Gate 4 can be ticked.

So Gate 4 in `GOAL.md` is NOT met yet, and this is the honest reason: every survivor the measured
surface produced is now closed, but the measured surface is no longer the whole crate. It is met
when a run at the release commit, over the feature set that ships, comes back with every survivor
either killed or recorded here. Anyone tempted to tick that gate early should re-read the bar at
the top of this file.
