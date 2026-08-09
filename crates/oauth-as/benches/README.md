<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (C) 2026 Matthew Jackson -->

# oauth-as benchmarks

This crate had allocation gates before it had a clock. `tests/allocation.rs` pins how many times
the hot paths call the allocator; nothing pinned, or even reported, how long any of them took.
Allocation count is a PROXY for speed and the two are allowed to disagree, so this suite exists to
measure the thing itself. The first run found a case where they disagree by a factor of five; see
"What the first run found" below.

## Running them

```
cargo bench -p oauth-as --all-features          # everything
cargo bench -p oauth-as                         # default features only: no http, jwt, dpop, par, rar
cargo bench -p oauth-as --all-features --bench token
cargo bench -p oauth-as --all-features --bench scaling -- introspection   # substring filter
cargo bench -p oauth-as --all-features --no-run # compile only; this is what CI runs
```

Six targets:

| target | what it measures |
| --- | --- |
| `token` | the token plane: introspection, client credentials, code redemption, refresh rotation, the device flow |
| `parsing` | pure functions: PKCE, `AuthorizationRequest::from_pairs`, `ScopeSet::parse`, RFC 8414 metadata, refusals |
| `extensions` | what each optional feature costs: ES256, DPoP, RFC 7523 assertions, PAR, RAR, mTLS thumbprints |
| `http_surface` | `AuthorizationService::handle` end to end, so routing, body reading and serialization are inside the clock |
| `scaling` | the hunt for accidental quadratic behaviour, and for DoS-shaped growth |
| `constant_time` | a timing-oracle probe on the client secret and PKCE verifier comparisons |

## What the numbers mean

Each row reports:

- **median**: the middle of 51 measured rounds, each round being enough iterations to take about
  20 ms. This is the headline. It is a median rather than a mean because a laptop preempts things.
- **min**: the fastest round. For a deterministic single-threaded workload this is the closest
  available thing to "the cost with no interference". A big gap between min and median means the
  machine was busy, not that the code is variable.
- **spread**: the median absolute deviation of the round means, as a percentage of the median.
  Read it as "do not trust digits beyond this". A row at 0.5% has measured something. A row at
  15% has not, and should be re-run on a quiet machine before anybody acts on it.
- **per second**: `1 / median`. A single-threaded, single-core figure for ONE operation in
  isolation, not a server throughput prediction. See the caveats.
- **iters/round**: how many iterations went into each round, for context on how small the
  measured unit was.

The `scaling` target additionally prints growth tables. In those, read the **ns/element** column,
not the medians: flat means linear, rising means worse than linear, and "worse than linear on an
input a caller controls" is a denial of service rather than a performance nit.

## What the numbers do NOT mean

Read this before quoting any figure anywhere.

1. **`MemoryStorage`, not a database.** Every row measures this crate against
   `oauth_as::MemoryStorage`, an in-process `HashMap` behind a `Mutex`. That is deliberate: it
   isolates the crate's own cost from a store nobody can hold constant. It is also the single
   largest caveat on every number here. A real deployment's token endpoint is dominated by its
   database round trip, and the figures below are what is left when you take that away. Treat them
   as "what this crate adds", never as "what your authorization server will do".
2. **No network, no TLS, no HTTP framing, no scheduler.** Even the `http_surface` target hands
   `handle` a `http::Request` value directly. There is no socket, no `accept`, no TLS handshake, no
   header parsing off the wire and no runtime multiplexing. A real request pays all of those, and
   they are the host's, not this crate's.
3. **One machine, one run.** The table in the audit report states the machine and the toolchain
   beside it. Numbers from a different CPU, a different allocator, or a machine doing something
   else at the time are different numbers.
4. **Single threaded.** `MemoryStorage` serialises every operation behind one mutex, so these rows
   say nothing about what happens under concurrency. A `sweep_expired` row of 279 us at 100,000
   records is 279 us during which every other request in the process is blocked; that is visible in
   the number only once you know to look for it.
5. **The harness has its own overhead.** Each async row pays one
   `tokio::runtime::Runtime::block_on` per iteration, which a host serving from an already-running
   reactor does not. `benches/token.rs` measures an empty `block_on` as
   `runtime_block_on_baseline` (about 38 ns) so it can be subtracted rather than guessed at. Rows
   measured with `bench_with` also pay one `Instant::now` pair per iteration, because their setup
   has to be excluded from the clock.
6. **`constant_time` cannot prove constant time.** It can only disprove it. A "not distinguishable"
   verdict means no oracle was visible from user space, on one machine, at roughly nanosecond
   resolution. It is not a side-channel audit. Read that target's module docs before citing it.

## Why there is no criterion, and no divan

MEASURED, not preferred. Both break `cargo +1.75 test -p oauth-as --locked`, which is `GOAL.md`
Gate 6's own CHECK command:

- `criterion` 0.8.2 declares `rust-version = "1.86"`. Pinning back to `criterion` 0.5.1 does not
  help: it resolves `clap_lex` 1.1.0, which is edition 2024, and cargo 1.75 cannot parse that
  manifest at all. The observed failure is `feature edition2024 is required`, during dependency
  download, before any of this crate's code compiles.
- `divan` 0.1.21 declares `rust-version = "1.80.0"` and resolves the same `clap_lex`.

Package counts in this workspace's lockfile: 256 today, 265 with `divan`, 278 with `criterion`.
This repository has already deleted a dev-dependency (`jsonschema`) for costing 88 packages and for
declaring an MSRV that stopped the 1.75 job from running the tests. Adding one back to draw a chart
would undo that decision for a smaller reason.

So `benches/harness/mod.rs` is hand rolled, zero dependency, about 300 lines, following the same
rule the counting allocator in `tests/support/alloc.rs` follows. What is given up is real and worth
naming: no bootstrap confidence intervals, no outlier classification, no saved-baseline regression
detection, no plots. If any of those becomes load bearing, reopen the dependency question with the
MSRV numbers above rather than growing that file into a worse criterion.

## Why these are not a CI pass/fail gate

They are not in CI as a threshold, on purpose. A timing gate on a shared runner fails for reasons
that have nothing to do with the change under test: a noisy neighbour, a different instance type, a
CPU frequency decision. A gate that goes red without a defect trains people to ignore CI, and this
repository depends on CI being believed.

What IS worth protecting is the suite ROTTING. Signatures move, and a bench target that stopped
compiling six months ago is worse than no bench target because it looks like coverage. So CI runs:

```
cargo bench -p oauth-as --all-features --no-run
```

which compiles every target and times nothing. If someone later finds a way to make a timing
threshold genuinely stable here (a dedicated runner, a ratio against an in-run reference row rather
than an absolute figure), that is the moment to revisit; not before.

The bench targets are declared `test = false` so `cargo test --workspace` does not run them. The
contributor gate in `CONTRIBUTING.md` runs on every commit and should stay fast.

## They are not in the published tarball

`crates/oauth-as/Cargo.toml` excludes `benches` from the package, so `cargo package --list` is
unchanged by this suite and `cargo package` prints one "ignoring benchmark" warning per target.
That is expected. The reasoning is in the comment above `exclude` in that file.

## What the first run found

Recorded here because "the benchmarks found nothing" and "nobody has run the benchmarks" look
identical from outside.

- **`device_authorization` is about 85% one-byte `getrandom` calls.** RFC 8628 user code generation
  draws its entropy one byte at a time with a fresh syscall per byte plus rejection sampling. The
  `scaling` target sweeps `user_code_length` and finds a slope of roughly 1000 ns per code SYMBOL,
  so the default 8-symbol code costs about 8.5 us of the endpoint's 9.3 us. The allocation gates
  cannot see this at all: buffering the draw changes the time by 5x and the allocation count by
  zero. This is the clearest illustration in the repository of why allocation count is a proxy.
- **`MemoryStorage::find_consent` is a linear scan on the authorization endpoint's path**, and the
  consent map grows by one record per (user, client) pair forever: 47 ns at one record, 137 us at
  100,000.
- **Refresh-token reuse detection scans the whole token and refresh maps**, so the cost of the
  RFC 9700 s4.14.2 compromise response grows with store size: 667 ns at one grant, 51 us at 10,000.
  This is a path an attacker triggers by definition.
- **Introspection is genuinely flat** against store size, 388 ns from one token to 100,000. The
  `Arc<IssuedToken>` change that took it from 18 allocations to 4 shows up in time as well.
- **The constant-time probe found no oracle**, and its deliberately-should-differ control row
  correctly reported one, which is what makes the first half believable.

Full analysis, with the machine and the profile stated beside every figure, lives in the audit
report that accompanied this suite.
