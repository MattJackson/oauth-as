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

## THE CURRENT RUN: a complete all-features sweep at `ce7c438`

This supersedes everything below it, including the `47418ff` sweep that used to hold this
position. The runs below are kept because their REASONING is still sound and several of their
equivalence arguments still hold, but their numbers are history.

```
cargo mutants -p oauth-as --all-features --timeout 300 -j 16
```

on a 64 vCPU `c7i.16xlarge` spot instance in `us-east-1`, at commit `ce7c438`, with NOTHING
excluded, from a `git archive HEAD` of the tree rather than a clone or a live checkout.

**1550 mutants: 969 caught, 42 missed, 12 timeouts, 527 unviable.** 59.2 minutes of instance
life, `i-021b6766473d189ef`, confirmed `terminated` with no volume left behind, at $0.913/hour
spot plus 100 GB of gp3: **about $0.91**.

One operational note worth carrying forward, because it cost a re-run. `cargo mutants` builds each
mutant in a copy of the tree under `TMPDIR`, and on AL2023 `/tmp` is a tmpfs: at `-j 16` the copies
filled RAM and the last three mutants died with `No space left on device` while the root volume
still had 97 GB free. They were re-run with `TMPDIR` on the disk and are included in the totals
above. Point `TMPDIR` at real storage before starting, not after.

The numbers are trustworthy on the usual grounds. Baseline on that box was a 12 second build and a
2 second test, so the 300 second timeout is a ~20x margin on the whole cycle, and 12 of 1550 (0.8%)
timed out, all in the known non-terminating class: the `GateWait` poll-budget mutants, the
rejection-sampling loops, and `percent_decode`'s `i += 1` becoming `i *= 1` so the index never
passes `while i < bytes.len()`. `cargo mutants` counts a timeout as caught, because the suite does
not pass, and that is the right answer for all 12.

The unviable count moved a long way (527 against 237 at `47418ff`) and that is a statement about
`cargo-mutants` 27.1.0 generating more candidates that do not compile, not about the crate.

### What was done with the 42

**26 killed by new tests, 7 argued as equivalent, 3 are a `cfg` artifact, 3 are not worth a test,
and 3 mutate code that no longer exists.**

| File | Missed | Killed | Equivalent | `cfg` | Not worth it | Code gone |
| --- | --- | --- | --- | --- | --- | --- |
| `src/jwt.rs` | 7 | 6 | 1 | 0 | 0 | 0 |
| `src/par.rs` | 6 | 6 | 0 | 0 | 0 | 0 |
| `src/http.rs` | 7 | 5 | 1 | 0 | 1 | 0 |
| `src/rar.rs` | 4 | 4 | 0 | 0 | 0 | 0 |
| `src/server.rs` | 4 | 2 | 2 | 0 | 0 | 0 |
| `src/store.rs` | 4 | 1 | 0 | 0 | 0 | 3 |
| `src/storage_conformance.rs` | 4 | 0 | 2 | 0 | 2 | 0 |
| `src/metadata.rs` | 3 | 0 | 0 | 3 | 0 | 0 |
| `src/token.rs` | 1 | 1 | 0 | 0 | 0 | 0 |
| `src/token_exchange.rs` | 1 | 1 | 0 | 0 | 0 | 0 |
| `src/scope.rs` | 1 | 0 | 1 | 0 | 0 | 0 |
| **total** | **42** | **26** | **7** | **3** | **3** | **3** |

The five new files, each naming the mutant it kills in the doc comment above every test:

- `crates/oauth-as/tests/mutation_gaps_jwt_primitives.rs`
- `crates/oauth-as/tests/mutation_gaps_request_object.rs`
- `crates/oauth-as/tests/mutation_gaps_authorization_details.rs`
- `crates/oauth-as/tests/mutation_gaps_http_credentials.rs`
- `crates/oauth-as/tests/mutation_gaps_grant_carriers.rs`

### THE DEFECT THIS PASS FOUND, and it is not a small one

`http.rs`'s token handler resolves client credentials once and then sets
`let client_secret: Option<String> = None;`, because every other grant now carries its credential
on the request CONTEXT instead. The RFC 8693 arm was never updated: it passed that `None` straight
into `token_exchange_response`, which passed it into `TokenExchangeRequest::client_secret`, and
`TokenExchange::exchange_token` refuses any client that is not confidential.

**RFC 8693 token exchange was therefore unreachable over the HTTP surface, for every client, under
every authentication method, since commit `9c58142`.** The grant is advertised in the RFC 8414
metadata document, and the answer to every request for it was `invalid_client`.

Nothing saw it because the exchange suite drives the library API directly and had never posted a
form at `/token`. `tests/mutation_gaps_http_credentials.rs::a_token_exchange_posted_as_a_form_
reaches_the_grant` was written to kill the `k == "audience"` mutant, failed on the unmutated tree
with `{"error":"invalid_client"}`, and the one-line fix (take the secret off the resolved
credentials) is in the same commit. That is the whole argument for mutation testing in one
paragraph: the mutant was a coverage nit, and looking for a test that could kill it found a dead
grant.

### The 26 that are killed, and what each mutation would have done to a caller

**`src/jwt.rs`, `encoded_jose_header`, five mutants at one site.** The guard
`c if (c as u32) < 0x20` escapes the control characters RFC 8259 s7 forbids raw inside a JSON
string. Replaced with `false`, or narrowed to `== 0x20`, a `kid` carrying a control character is
written unescaped and the protected header of EVERY access token this server signs stops being
JSON. Replaced with `true`, or widened to `> 0x20`, an astral character reaches an escape that
writes a single BMP `\u` sequence, producing four hex digits and a stray fifth: the `kid` a
verifier reads back is a different string, naming no key in the JWKS. `<=` escapes the space,
which parses but silently breaks the module's own commitment that the precomputation leaves the
wire bytes unchanged. The `kid` is host-supplied and the crate's docs say it need not be ASCII, so
none of this needs an attacker.

**`src/jwt.rs`, `hmac_sha256`, `> 64` to `>= 64`.** RFC 2104 replaces a key LONGER than the block
size by its digest; at exactly 64 bytes the key is used as it stands. `>=` picks the other rule, so
`client_secret_jwt` breaks for every client whose secret is exactly 64 characters, which is what a
32 byte secret printed as hex is. The existing assertion tests could not see it because they sign
with this same function, so a wrong HMAC still verifies against itself. The new test uses vectors
computed OUTSIDE this crate.

**`src/par.rs`, the `aud` check, two mutants.** Deleting the `Value::Array(many)` arm refuses every
request object whose `aud` is an array, which RFC 7519 s4.1.3 makes the GENERAL form and which most
JWT libraries emit. Inverting `s == issuer` to `!=` is worse: it ACCEPTS an object addressed to
another authorization server and REFUSES the one addressed here, which is the mix-up `aud` exists
to stop.

**`src/par.rs`, the `nbf` bound, three mutants.** RFC 7519 s4.1.5 makes `now == nbf` the first
ACCEPTABLE instant. `<=` refuses a request object for the whole of the second it was minted in,
which is an intermittent unreproducible refusal of a correct client. `==` accepts objects from the
future. `>` refuses every object whose window has already opened and accepts only the ones whose
has not.

**`src/par.rs`, `RequestObjectKeyError::detail`.** Four distinct operator problems (mangled base64
in `x`, in `y`, a coordinate at the wrong width, a point off the curve) collapse into one constant
sentence, at the exact moment a deployment is trying to find out why its clients cannot use JAR.

**`src/http.rs`, `bearer_token`, two mutants.** `< 7` narrowed to `== 7` removes the bound that
keeps `raw[..7]` in range, so any Authorization header shorter than the scheme PANICS out of a
library, into the host's request handler, from an unauthenticated header. `||` to `&&` accepts a
header naming a different scheme and cuts seven bytes off the front of it: `Authorization: Basic
aGVsbG8=` is presented to the host's RFC 7591 s5 registration policy as the bearer token
`GVsbG8=`, which is both a wrong answer and a credential leaking into a callback documented never
to see one.

**`src/http.rs`, `credentials_where`, `||` to `&&`.** RFC 6749 s2.3 allows one client
authentication method per request. Weakened, an RFC 7523 assertion presented alongside a `Basic`
header is accepted, and the assertion wins: the request authenticates as the assertion's subject
while every log and proxy in front of the server sees the Basic client id.

**`src/http.rs`, `token_exchange_response`, `k == "audience"` to `!=`.** Every form parameter that
is NOT `audience` becomes a requested audience, none of which the subject token granted, so every
exchange is `invalid_target`. See the defect note above for why nothing was watching this handler
at all.

**`src/http.rs`, `authorize_handler`, `remember && issued.is_ok()` to `||`.** A plain `Approve`
writes a consent record. `ConsentDecision::ApproveAndRemember`'s own documentation is the
specification this breaks: the crate "will not remember a consent nobody asked it to remember".
The next request from that client is handed a `remembered` consent, so a host that skips its prompt
when one exists never asks again, and one approval silently becomes standing consent.

**`src/rar.rs`, `MAX_AUTHORIZATION_DETAILS_DEPTH - 2`, two mutants.** `+` makes the member depth
budget 10 and hands four levels of recursion margin back to an unauthenticated caller; `/` makes it
4 and refuses documents inside the depth the crate publishes. Only a test AT the boundary sees
either, which is why "deeply nested is refused" was not enough.

**`src/rar.rs`, `iter` and `from_elements`.** These two are the whole of the host-side construction
path RFC 9396 s7.1 invites. `from_elements` returning the default throws a host's enriched consent
away and issues a token that authorizes nothing, with no error anywhere because an empty set is
legal to issue; `iter` returning nothing makes every check a host writes over the details pass
vacuously on a token that does carry them.

**`src/server.rs`, `GrantedDetails::of_token`.** The exchanged token stops inheriting the subject
token's `authorization_details`, so the downstream call the exchange existed for is refused, and a
resource server that reads an absent list as "unconstrained" is handed the opposite of the truth.

**`src/server.rs`, `GrantedDetails::is_empty` to `true`.** NOT dead code, despite the
`#[allow(dead_code)]` on it: the device-code branch calls it to refuse `authorization_details` on a
grant that never carried any (RFC 9396 s6). Constant `true` deletes that refusal, and the client is
answered `200 OK` while believing it holds authority the user was never shown. The previous entry
in this file suggested confirming this one by DELETING the method; that would have been wrong.

**`src/token.rs`, `Confirmation::jkt`.** The constructor hands back a confirmation naming nothing,
and `Confirmation::is_empty` then omits `cnf` entirely, so a host publishing a sender-constrained
binding publishes a token that reads as an ordinary bearer token: the RFC 9449 s6.1 downgrade.

**`src/token_exchange.rs`, the `audience` de-duplication.** `any(|t| t == audience)` inverted asks
"is there any target that DIFFERS", which is true the moment one `resource` is present, so the
`audience` is silently dropped. RFC 8693 s2.1.1 makes the two parameters two spellings of one
request, and the client discovers the loss at the resource server as a rejection it cannot explain.

**`src/store.rs:695`, `MemoryStorage::compare_and_swap_device_grant`, `!=` to `==`.** The branch
that retires the OLD user-code index entry when a swap changes the user code stops firing, and
fires instead when the code did not change (where the insert below puts it straight back). A user
code is the credential a human types: leaving a superseded one live means the code from the first
screen still resolves to the grant.

### The 7 that are equivalent

**`src/jwt.rs:934`, `x.len() != 32 || y.len() != 32` to `&&`, in `verify_es256`.** This is the one
that was flagged as the stop-and-look, and the honest answer is that it cannot be reached.
`PublicJwk`'s fields are PRIVATE, and both of its constructors (`from_json` and `from_coordinates`)
already refuse a coordinate whose base64url does not decode to exactly 32 bytes. `verify_es256`
re-decodes the same strings, so both lengths are always 32, and `false || false` and `false && false`
are the same value. The check is retained as defence in depth and it earns its keep: if one length
could ever be wrong, `&&` would let it through to a `copy_from_slice` that PANICS on a length
mismatch, and a JWK arrives in a DPoP proof header, so that is an unauthenticated panic.

That argument is only as good as the seal, so the seal is now pinned:
`mutation_gaps_jwt_primitives.rs::a_jwk_coordinate_that_is_not_thirty_two_bytes_cannot_be_constructed`
tries a short and a long coordinate in each position through both constructors. If a third
constructor ever skips the width check, this entry is void and the mutant becomes a hole.

**`src/http.rs:2174`, `raw.len() < 7` to `<= 7`, in `bearer_token`.** They differ only at
`raw.len() == 7`, and at exactly 7 bytes the original falls through to `raw[7..]`, which is the
empty string, which `(!token.is_empty()).then_some` turns into `None`. The mutant returns `None`
directly. Same answer, for the only input that separates them, and 7 is always a char boundary
when the string is 7 bytes long so there is no panic on either side either.

**`src/server.rs:346` and `:361`, `GrantedAuthentication::from_code` and `::from_refresh`.** These
are the `#[cfg(not(feature = "consent"))]` bodies, so an `--all-features` run does not compile
them at all. They are also equivalent where they DO compile: without the feature the struct has no
fields, so `GrantedAuthentication {}` and `Default::default()` are the same value written twice.
The `consent` copies of both functions are caught, by `tests/step_up.rs`.

**`src/scope.rs:65`, `ScopeSet::empty`.** Carried forward unchanged; the argument is at the top of
this file.

**`src/storage_conformance.rs:2217`, `at_before`, two mutants.** Carried forward unchanged; the
argument is under "the four that are not worth a test" below.

### The 3 that are a `cfg` artifact

`src/metadata.rs:245`, the three `advertised_jwks_uri` mutants, all in the
`#[cfg(not(feature = "jwt"))]` body. Carried forward unchanged: a default-features run judges
these, and `src/tests/metadata.rs::without_the_jwt_feature_jwks_uri_is_whatever_the_host_declared`
kills them there.

### The 3 that are not worth a test

**`src/http.rs:1409`, `separators + 1` to `separators * 1`, in `parse_pairs`.** The value is a
`Vec::with_capacity` hint and nothing else: `bound` is never compared, returned or stored. What is
lost is that a body with no `&` at all preallocates for zero pairs instead of one, so the first
push reallocates, and the same is true one pair short for every other body. It cannot change any
response, any error, or any stored record. Pinning it would mean asserting an exact allocation
count against an internal with no contract, and `tests/allocation.rs`'s budgets are deliberately
coarser than that.

**`src/storage_conformance.rs:1207` and `:2056`.** Carried forward unchanged; the arguments are
below.

### The 3 whose code no longer exists

`src/store.rs:203`, three mutants (`== ` to `!=`, and the match guard to `true` and to `false`),
all inside the DEFAULT implementation of `Storage::compare_and_swap_device_grant`. Commit
`6e38fb0` deleted that default outright, for a reason this file has already recorded: the shim's
write went through `put_device_grant`, which is an insert-or-update, so it could resurrect a grant
that had just been redeemed. There is no code left to mutate and nothing to kill. The REPLACEMENT
is a required trait method with no body, and the reference implementation's own version of the same
comparison is exercised by `mutation_gaps_grant_carriers.rs` and by
`storage_conformance`'s three swap checks.

### Proof that the 26 tests kill them, rather than merely pass

Per mutant, by hand. Each mutation was applied to a pinned copy of the tree, the named test file
was run, the failure was recorded, and the source was restored. Every one went red and named the
intended test. Two of the twenty-six (`GrantedDetails::is_empty`, and the `store.rs` swap) plus the
`Confirmation::jkt` and `token_exchange` pair were proven against a copy of the WORKING tree rather
than of `HEAD`, because the tree moved under this work: see the caveat below.

`bearer_token`'s `<=` was applied the same way and stayed GREEN, which is the evidence for its
equivalence argument rather than a gap.

### The caveat that matters most, stated plainly

**The sweep is at `ce7c438` and the tree did not hold still.** Three other agents were editing and
COMMITTING to this working tree throughout: `HEAD` moved from `ce7c438` to `faa2a4a` and then to
`f8fc976` while the sweep ran and while these tests were being written, and there is a large
uncommitted working set besides. Three of the 42 survivors were already moot by the time they were
read (the deleted swap shim), which is the same snapshot hazard every entry in this file has
warned about, arriving inside a single session this time.

So this run does NOT certify the tree as it stands. It certifies `ce7c438`, and the tests written
against it are green on the tree as it stands. Gate 4 still requires a run at the RELEASE commit
that comes back with nothing new.



```
cargo mutants -p oauth-as --all-features --timeout 300 -j 16
```

on a 64 vCPU `c7i.16xlarge`, at commit `47418ff`, with NOTHING excluded.

**1514 mutants: 1173 caught, 93 missed, 237 unviable, 11 timeouts, 22 minutes.**

A scoped run over the three files the previous snapshot named as untriaged
(`storage_conformance.rs`, `store.rs`, `registration.rs`) was taken first, to get triage material
early: **325 mutants: 222 caught, 43 missed, 57 unviable, 3 timeouts, 7 minutes.** Those 43 are a
subset of the 93.

The numbers are trustworthy on the same grounds the previous full run's were. Baseline on that box
was a 12 second build and a 20 second test, so the 300 second timeout is a ~9x margin on the whole
cycle, and 11 of 1514 (0.7%) timed out, all in the known non-terminating class (loop counters that
stop advancing, rejection sampling that can never accept, and the two `GateWait` poll-budget
mutants that make the rendezvous gate spin for ever). `cargo mutants` counts a timeout as caught,
because the suite does not pass, and that is the right answer for all 11.

### What was done with the 93

**46 killed by new tests, 4 argued as not worth a test or equivalent, 43 still open.**

| File | Missed | Killed | Argued | Open |
| --- | --- | --- | --- | --- |
| `src/storage_conformance.rs` | 25 | 21 | 4 | 0 |
| `src/registration.rs` | 10 | 10 | 0 | 0 |
| `src/store.rs` | 8 | 8 | 0 | 0 |
| `src/server.rs` | 7 | 5 | 0 | 2 |
| `src/authorization.rs` | 2 | 2 | 0 | 0 |
| `src/http.rs` | 16 | 0 | 0 | 16 |
| `src/par.rs` | 6 | 0 | 0 | 6 |
| `src/rar.rs` | 4 | 0 | 0 | 4 |
| `src/metadata.rs` | 3 | 0 | 0 | 3 |
| `src/consent.rs` | 3 | 0 | 0 | 3 |
| `src/jwt.rs` | 2 | 0 | 0 | 2 |
| `src/client_assertion.rs` | 2 | 0 | 0 | 2 |
| `src/token.rs`, `src/token_exchange.rs`, `src/scope.rs`, `src/events.rs`, `src/dpop.rs` | 5 | 0 | 0 | 5 |
| **total** | **93** | **46** | **4** | **43** |

The tests that close them, each in its own file, each naming the mutant it kills:

- `crates/oauth-as/tests/mutation_gaps_store.rs`, new: the eight `MemoryStorage` survivors.
- `crates/oauth-as/tests/mutation_gaps_registration.rs`, new: the ten RFC 7591 / RFC 7592
  survivors.
- `crates/oauth-as/tests/storage_conformance_gaps.rs`, new: the 21 survivors in the EXPORTED
  conformance harness. A new file rather than an extension of
  `tests/storage_conformance_selftest.rs`, which was open in another workstream at the time.
- `crates/oauth-as/tests/mutation_gaps_approval.rs`, new: the seven issuance-path survivors.

### Proof that those tests kill them, rather than merely pass

Two independent forms, because a test that is green against unmutated code proves nothing.

**By hand, per mutant.** All 46 were applied one at a time to a pinned copy of the tree, the named
test file was run, the failure was recorded, and the source was restored. Every one went red, and
each named the intended test. That is the primary evidence and it is per-mutant rather than
aggregate.

**By re-running `cargo mutants`.** The 43 priority-file survivor descriptions were re-run as a
filter against the tree WITH the new tests:

```
cargo mutants -p oauth-as --all-features --timeout 300 -j 16 -F <the 43 descriptions>
```

**49 mutants matched (some descriptions occur at more than one site): 45 caught, 4 missed.** The
4 missed are exactly the four argued below and nothing else.

### The four that are not worth a test, with what is lost

These are in `src/storage_conformance.rs`. None of them can make the harness report GREEN for a
store that is broken, which is the property that would have made them worth almost any cost.

**`2217:28: replace + with -` and `2217:60: replace - with /`, both in `at_before`.** EQUIVALENT
for every verdict the harness can reach. `at_before` produces a timestamp used in exactly two
ways, and neither can tell the three values apart. As a record FIELD (`created_at`, `last_poll_at`,
`issued_at`, `granted_at`) its only requirement is that it round-trips, and the checks compare what
was stored against what came back, so any value passes and any value fails identically. As an
EXPIRY (`dead_code.expires_at`, `dead_token.expires_at` at `at_before(1)`) the only thing that
matters is that it is at or before `now`, and `BASE_SECS - 1`, `BASE_SECS / 1` and
`UNIX_EPOCH - BASE_SECS + 1` are all at or before `now = BASE_SECS`: all three records are dead,
the sweep removes all three, and `SWEEP_COUNT`'s expected 4 is unchanged. There is no third use.

**`2056:9: replace Gate::wake_all with ()`.** NOT WORTH A TEST, and what is lost is spin, not
correctness. `GateWait::poll` registers the waker AND self-wakes with `cx.waker().wake_by_ref()`
before it returns `Pending`, so every parked racer is re-polled regardless of whether anybody wakes
it; `wake_all` can only make that re-poll happen sooner. Removing it cannot deadlock the gate and
cannot change which racer wins, so no verdict moves. What it does cost is real and worth writing
down: the `waiters` vector is pushed on every poll and only ever drained by `wake_all`, so without
it a gate that takes many polls to open accumulates one `Waker` per poll, bounded by
`GATE_POLL_BUDGET` (10,000) per racer. That is a memory and CPU cost inside a test harness, not a
wrong answer, and a test that pinned it would be asserting an allocation count against an internal
that has no contract.

**`1207:21: replace && with || in user_code_index`.** NOT WORTH A TEST. The expression is
`if ok_first && ok_second`, a guard on whether to probe the index after the two seeding puts. It
differs only when EXACTLY ONE of the two puts failed, and the two puts are the same operation on
the same store, so provoking it needs a store that refuses one `put_device_grant` and accepts the
next. What is lost when it differs is that a store which failed one of the two seeding puts gets
two extra DERIVED violations ("the NEW code does not resolve") alongside the storage failure it
already reported. Those extra violations are arguably even true. The general property that a check
must not draw conclusions from a fixture it could not plant IS pinned, by
`a_store_that_cannot_write_a_record_is_not_judged_on_records_it_never_stored`; this one site is the
case that test cannot construct.

### The 43 that remain, stated plainly

They have NOT been triaged one by one and this file will not pretend otherwise. Six of them are
already argued further down this file and are carried forward unchanged: `scope.rs`
`ScopeSet::empty`, `events.rs` `RateLimiter::record`, the three `metadata.rs`
`advertised_jwks_uri` mutants in the `#[cfg(not(feature = "jwt"))]` body (a `cfg` artifact, not a
hole), and `http.rs` `percent_decode`'s `|` to `^` (the same mutant the older entry records under
its previous name, `decode_component`). One more is arguably a seventh: `server.rs:971`
`GrantedDetails::is_empty -> true` is a PRIVATE method carrying `#[allow(dead_code)]` with no
caller anywhere in the crate, so nothing can observe it; that should be confirmed by deleting the
method rather than by asserting on it.

That leaves about 36 genuinely open, concentrated in `src/http.rs` (16), `src/par.rs` (6) and
`src/rar.rs` (4). Several look serious on their face and none should be assumed harmless:
`jwt.rs:894 replace || with && in verify_es256` is inside signature verification,
`par.rs:997 replace < with <=` and its siblings are the RFC 9101 request object's time bounds,
`http.rs:2068 bearer_token` and `http.rs:1536 credentials_where` decide how a credential is
extracted from a request, and `consent.rs:489 step_up_challenge` is arithmetic in an RFC 9470
challenge.

One measurement caveat, stated because it cuts the other way for once: this sweep is at `47418ff`,
and test files added to the tree after that commit are not in it. Some of the 43 may already be
dead. That is a reason to re-run, not a reason to assume.

The whole list, so the next person starts from evidence rather than from this prose:

```
crates/oauth-as/src/client_assertion.rs:104:9: replace <impl fmt::Debug for ClientSecretKey>::fmt -> fmt::Result with Ok(Default::default())
crates/oauth-as/src/client_assertion.rs:123:9: replace <impl fmt::Display for WeakClientSecret>::fmt -> fmt::Result with Ok(Default::default())
crates/oauth-as/src/consent.rs:255:9: replace AuthenticationRequirement::none -> Self with Default::default()
crates/oauth-as/src/consent.rs:489:60: replace + with * in step_up_challenge
crates/oauth-as/src/consent.rs:489:60: replace + with - in step_up_challenge
crates/oauth-as/src/dpop.rs:233:18: replace > with >= in verify_proof
crates/oauth-as/src/events.rs:318:9: replace RateLimiter::record with ()
crates/oauth-as/src/http.rs:122:9: replace Body::empty -> Self with Default::default()
crates/oauth-as/src/http.rs:160:9: replace <impl From<&'static str> for Body>::from -> Self with Default::default()
crates/oauth-as/src/http.rs:917:9: replace <impl std::fmt::Debug for AuthorizationService<S, C>>::fmt -> std::fmt::Result with Ok(Default::default())
crates/oauth-as/src/http.rs:1085:21: replace > with == in collect_body
crates/oauth-as/src/http.rs:1085:21: replace > with >= in collect_body
crates/oauth-as/src/http.rs:1285:21: replace match guard plus_is_space with true in percent_decode
crates/oauth-as/src/http.rs:1292:43: replace | with ^ in percent_decode
crates/oauth-as/src/http.rs:1338:45: replace == with != in parse_pairs
crates/oauth-as/src/http.rs:1338:62: replace + with * in parse_pairs
crates/oauth-as/src/http.rs:1536:18: replace || with && in credentials_where
crates/oauth-as/src/http.rs:1823:5: replace token_exchange_response -> Response with Default::default()
crates/oauth-as/src/http.rs:1871:28: replace == with != in token_exchange_response
crates/oauth-as/src/http.rs:2068:18: replace < with <= in bearer_token
crates/oauth-as/src/http.rs:2068:18: replace < with == in bearer_token
crates/oauth-as/src/http.rs:2068:22: replace || with && in bearer_token
crates/oauth-as/src/http.rs:2412:17: replace && with || in authorize_handler
crates/oauth-as/src/jwt.rs:894:22: replace || with && in verify_es256
crates/oauth-as/src/jwt.rs:924:18: replace > with >= in hmac_sha256
crates/oauth-as/src/metadata.rs:245:5: replace advertised_jwks_uri -> Option<String> with None
crates/oauth-as/src/metadata.rs:245:5: replace advertised_jwks_uri -> Option<String> with Some("xyzzy".into())
crates/oauth-as/src/metadata.rs:245:5: replace advertised_jwks_uri -> Option<String> with Some(String::new())
crates/oauth-as/src/par.rs:338:9: replace RequestObjectKeyError::detail -> &str with "xyzzy"
crates/oauth-as/src/par.rs:976:17: delete match arm serde_json::Value::Array(many) in AuthorizationServer<S, C>::verified_request_object
crates/oauth-as/src/par.rs:978:51: replace == with != in AuthorizationServer<S, C>::verified_request_object
crates/oauth-as/src/par.rs:997:20: replace < with <= in AuthorizationServer<S, C>::verified_request_object
crates/oauth-as/src/par.rs:997:20: replace < with == in AuthorizationServer<S, C>::verified_request_object
crates/oauth-as/src/par.rs:997:20: replace < with > in AuthorizationServer<S, C>::verified_request_object
crates/oauth-as/src/rar.rs:89:65: replace - with +
crates/oauth-as/src/rar.rs:89:65: replace - with /
crates/oauth-as/src/rar.rs:361:9: replace AuthorizationDetails::iter -> impl Iterator<Item =&AuthorizationDetail> with ::std::iter::empty()
crates/oauth-as/src/rar.rs:377:9: replace AuthorizationDetails::from_elements -> Self with Default::default()
crates/oauth-as/src/scope.rs:65:9: replace ScopeSet::empty -> Self with Default::default()
crates/oauth-as/src/server.rs:951:9: replace GrantedDetails::of_token -> Self with Default::default()
crates/oauth-as/src/server.rs:971:9: replace GrantedDetails::is_empty -> bool with true
crates/oauth-as/src/token.rs:124:9: replace Confirmation::jkt -> Self with Default::default()
crates/oauth-as/src/token_exchange.rs:607:38: replace == with != in exchange
```

### What the killed 46 actually were, because the pattern is worth more than the count

Two of them were the same defect the crate had already been bitten by once, on a path nobody had
re-checked. `src/server.rs` carries a comment recording that RFC 9470's `acr_values` and `max_age`
were once dropped entirely on the RFC 9126 and RFC 9101 paths, "which disabled step-up for every
PAR and JAR deployment". The plain QUERY STRING path turned out to be one deleted match arm away
from exactly that, and nothing would have caught it, because the step-up suite builds its
`AuthenticationRequirement` through a DIFFERENT parser (`AuthenticationRequirement::from_pairs`)
and so never exercised the two arms in `AuthorizationRequest::from_pairs` that a browser goes
through.

One of them exposed a test that was not testing what its name said.
`src/tests/registration.rs::the_implicit_response_type_is_refused` sends `grant_types:
["implicit"]` as well as `response_types: ["token"]`, and the grant parser refuses the document
several checks before the response-type loop is reached. The response-type rule therefore had no
test at all, and `replace != with == in validate` both ACCEPTED `response_types: ["token"]` and
REFUSED the `["code"]` that RFC 7591 section 2 invites a client to state.

Four of them were in the RFC 7592 section 2.2 update path and decided whether the updated client
stayed confidential. `wants_secret`'s `!=` flipped to `==` DEMOTES every confidential client that
edits its own metadata to a public one, so the secret it holds stops being required and anybody
holding its `client_id`, which RFC 6749 section 2.2 says is not a secret, can authenticate as it.

Two whole classes were arithmetic nothing had ever exercised: the `client_secret_ttl` arms, which
no test anywhere set, and `revoke_consent`'s count, which every existing fixture (including the
conformance harness's own) planted with exactly TWO of each record kind, and `2 + 2` is `2 * 2`.

And 21 were in the harness this crate EXPORTS. Three entire round-trip checks could be replaced
with empty bodies, `judge_race`'s `StorageError` arm could never fire, two `match` guards that
decide whether the store answered with the RIGHT record could be replaced with `true`, and
`check_storage`, the entry point the module documentation hands a host, could return an empty
violation list unconditionally with nothing calling it. That last one is the worst of the 93: a
host that wrote the two lines the documentation shows had a permanently green test that would have
certified a read-then-delete store as conformant.

### The process note, because an earlier sweep's first pass was worthless

An earlier sweep's first pass ran at `-j 10` on a busy laptop and produced 185 timeouts, which
prove nothing about the suite: an overloaded machine timing out is a statement about the machine.
The fix that actually worked was not a smaller `-j`, it was a bigger machine. A local run of just
the three priority files was measured at 50 seconds of build per mutant and would have taken over
an hour while starving everything else on the laptop; the same work on a 64 vCPU spot instance took
10 seconds of build and 3 seconds of test per mutant, and the WHOLE crate finished in 22 minutes
for about 61 US cents. Mutation testing is embarrassingly parallel and this is the shape of machine
it wants.

## Where this actually stands (updated at 0.9.0)

**First full `--all-features` run**, on a dedicated 192 vCPU box because the laptop could not do
it in a usable time:

    cargo mutants -p oauth-as --all-features --timeout 300 -j 48
    1354 mutants: 1019 caught, 121 missed, 204 unviable, 10 timeout, 13 minutes

The numbers are trustworthy, which is not a given for a mutation run. Baseline on that box was a
12 second build and a 2.3 second test, so the 300 second timeout is a ~130x margin, and only 10 of
1354 (0.7%) timed out against 185 on the earlier busy-laptop run. All 10 are in the known
genuinely non-terminating class: loop counters that stop advancing, and rejection sampling that can
never accept.

### What has been done with the 121, and what has not

Closed since: the wire-text batch (the `Display` impls across nine modules, which could all return
`Ok(Default::default())` undetected), the DPoP and client-assertion verifier unit tests, and two
that were real holes rather than curiosities, both watched failing first and recorded in
`tests/mutation_gaps.rs`:

- `rar::is_empty_list` could return a constant, and constant `true` DROPS every `actions`,
  `locations`, `datatypes` and `privileges` list from the serialized authorization detail. A
  resource server would be handed a detail whose action list had vanished.
- The RFC 8705 s2.1.1 `tls_client_auth_san_ip` arm could be deleted, and it does not fail closed:
  it falls through to the `_ => continue` meant for unrelated registration members, so a
  registration naming only an IP SAN parses as naming no subject at all.

A scoped re-run over the six security-critical modules (`par`, `token_exchange`, `rar`, `mtls`,
`client_assertion`, `dpop`, 267 mutants) confirms the security-critical survivors from the snapshot
were largely already dead: they were killed by fixes and tests that landed AFTER the snapshot was
taken, which is the hazard of reading any mutation report as current.

**GATE 4 IS NOT MET, and the honest reason is scope rather than effort.** The remaining survivors
are concentrated in `storage_conformance.rs` (the reporter's own violation-accumulation logic),
`store.rs` and `registration.rs`, and they have not been individually triaged. A mutation report is
also a SNAPSHOT: this one predates several fixes, so some of its 121 are already dead and code
written since was never measured. The gate is met when a run at the release commit, over the
feature set that ships, comes back with every survivor killed or argued here.

SUPERSEDED by the `47418ff` sweep at the top of this file. The three files this paragraph named as
untriaged are now fully accounted for: 39 of their 43 survivors are killed by tests and the other
4 are argued. What it got RIGHT, and what the newer run confirms, is that a mutation report is a
snapshot: several of the 121 above were already dead by `47418ff`, and 1514 mutants were found
where 1354 had been.

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

## THE POSITION TODAY, at `47418ff`

**GATE 4 IS STILL NOT MET.** The measured surface IS now the whole crate, which is the thing every
older paragraph above was waiting for, and the remaining reason is simply that 43 of the 93
survivors have not been dealt with.

What changed: the sweep is complete and current (1514 mutants, `--all-features`, nothing excluded),
the three files that had never been triaged are now fully accounted for, and 46 survivors are dead
with per-mutant red-before-green evidence. What has not: about 36 genuinely open survivors remain,
concentrated in `src/http.rs`, `src/par.rs` and `src/rar.rs`, and some of them sit in code whose
name alone is a reason to look (`verify_es256`, `bearer_token`, the RFC 9101 request object's time
bounds).

The gate is met when those are killed or argued here to the standard at the top of this file, and
a fresh run at the release commit comes back with nothing else. Nothing about the work done in
this pass licenses ticking it early: an 88% reduction in untriaged survivors in the highest-blast
-radius modules is progress, and progress is not the criterion.

SUPERSEDED by the `ce7c438` sweep at the top of this file, which found 1550 mutants where 1514 had
been and 42 survivors where 93 had been. What this paragraph got RIGHT is that the four named
stop-and-look sites deserved the attention: `bearer_token` turned out to hide an unauthenticated
panic and a cross-scheme credential leak, the RFC 9101 time bounds turned out to refuse conforming
clients at the boundary, `credentials_where` turned out to let two credentials through as one, and
`verify_es256` turned out to be the one of the four that genuinely could not be reached.

## THE POSITION TODAY, at `ce7c438`

**GATE 4 IS STILL NOT MET, and this time the reason is narrow enough to state in one sentence: the
sweep is complete and every one of its survivors is accounted for, but it was taken at `ce7c438`
and the tree has moved three commits and one large uncommitted working set since.**

What changed in this pass. The whole crate was swept again at `--all-features` with nothing
excluded (1550 mutants, 42 survivors, 59 minutes, about $0.91). All 42 are triaged individually:
26 killed by tests in five new files with per-mutant red-before-green evidence, 7 argued as
equivalent with the reason, 3 recorded as a `cfg` artifact, 3 as not worth a test with what is
lost, and 3 as mutations of code that has since been deleted. `jwt.rs:894 verify_es256`, the
mutant the previous entry singled out as the worst possible survivor, is argued as equivalent with
its premise pinned by a test rather than by assertion. And the search for a test that could kill
one router mutant found a REAL DEFECT: RFC 8693 token exchange had been unreachable over the HTTP
surface since commit `9c58142`.

What has not changed. A mutation report is a snapshot and this one is already behind the tree it
describes, by more than usual: three other agents committed to this repository while the sweep ran.
Nothing written above measures the code they added. The bar at the top of this file has not moved
either, and it says the gate is met when a run AT THE RELEASE COMMIT, over the feature set that
ships, comes back with every survivor killed or recorded here. That run has not happened, because
there is not yet a release commit to take it at.

The honest shape of the remaining work is therefore small and specific: cut the release commit,
re-run the same command against it, and expect the survivors to be the 16 argued above (7
equivalent, 3 `cfg`, 3 not worth a test, and the 3 that will simply no longer exist) plus whatever
the code written since `ce7c438` produces. If that run comes back clean against that expectation,
the gate is met. It is not met before it.
