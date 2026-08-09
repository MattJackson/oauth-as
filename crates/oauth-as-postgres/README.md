# oauth-as-postgres

A PostgreSQL implementation of the [`oauth-as`](../oauth-as) `Storage` trait.

**NOT PUBLISHED.** This crate has never been released to crates.io. Its version number tracks the
`oauth-as` it implements and means nothing else; `publish = false` is set in its manifest. Do not
read the `0.9.0` as a claim that it is available, supported, or that its schema is stable.

## Why this exists

`Storage` is the only persistence abstraction `oauth-as` has, and until this crate the only
implementation that had ever existed was `MemoryStorage`. That store is atomic trivially: it is one
mutex in one process. So the hardest requirement in the whole design, that every `take_*` is an
**atomic remove-and-return**, had never been met by code that runs against a shared store.

The failure mode when it is not met is the worst kind in the project, because it looks correct:

```sql
SELECT payload FROM refresh_tokens WHERE token = $1;   -- both nodes see the record
DELETE          FROM refresh_tokens WHERE token = $1;  -- both nodes delete it
```

On one node it is indistinguishable from the right answer. On two, a thief and the honest client
both read the record, both delete it, and both rotate: two live chains from one token. And because
the honest client is never locked out, RFC 9700 section 4.14.2 refresh-token reuse detection, the
feature built specifically to catch stolen tokens, silently becomes a no-op.

Every `take_*` here is therefore one statement, and the **database** picks the winner:

| Operation | Statement |
| --------- | --------- |
| `take_device_grant` | `DELETE FROM oauth_as_device_grants WHERE device_code = $1 RETURNING payload` |
| `take_authorization_code` | `DELETE FROM oauth_as_authorization_codes WHERE code = $1 RETURNING payload` |
| `take_refresh_token` | `DELETE FROM oauth_as_refresh_tokens WHERE refresh_token = $1 RETURNING payload` |
| `take_pushed_authorization_request` | `DELETE FROM oauth_as_pushed_requests WHERE request_uri = $1 RETURNING payload` |
| `claim_replay_id` | `INSERT INTO oauth_as_replay_ids (id, expires_at_ns) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING RETURNING id` |

There is no `SELECT` on any single-use artifact's redemption path in this crate.

## Why a separate crate, not a feature of `oauth-as`

Two reasons, and both are about what the core crate is for.

- **The core's premise is a tiny dependency set.** An *optional* dependency is still a line in the
  published manifest, still something a security team has to reason about, and still something that
  appears in a consumer's `cargo tree` the moment anything in their workspace turns it on. Keeping
  the driver out here means the core's manifest never mentions a database at all.
- **It proves something a feature cannot.** A feature would implement the trait from *inside*, with
  access to private items. This crate implements it from *outside*, through the public API only. If
  the seam were leaky, this crate would not compile.

## Why sqlx

`sqlx 0.8` with `postgres` and `runtime-tokio`, `default-features = false`, and no TLS backend.
The alternative considered was `tokio-postgres` plus `deadpool-postgres`.

sqlx wins on what this crate actually needs. The connection pool, transactions and typed row
decoding are in the box, where `tokio-postgres` needs a second crate for the pool and hand-written
plumbing for the rest, so the "smaller driver" is not smaller once it is usable. The decisive point
is the one that usually counts *against* sqlx: its compile-time-verified `query!` macros need a live
database to **compile**, which would make this crate unbuildable in any CI without a Postgres. So
the macros are not used. Every statement here goes through the **runtime** API, `sqlx::query`, which
takes a plain `&str`, verifies nothing at compile time, and needs no database to build. That is a
deliberate trade: this crate gives up compile-time SQL checking, and buys it back at runtime with
the conformance harness and the atomicity tests below, which run against a real server and check the
*behaviour* rather than the *types*. `default-features = false` drops the macros, the migration CLI
support, and every TLS backend, so nothing is compiled that this crate does not call.

## Schema

Four checked-in migrations, applied by `PostgresStorage::migrate()` or by whatever migration tool
the host already runs. They are plain, idempotent SQL.

| File | Applied when | Tables |
| ---- | ------------ | ------ |
| `migrations/0001_core.sql` | always | `oauth_as_clients`, `oauth_as_device_grants`, `oauth_as_authorization_codes`, `oauth_as_access_tokens`, `oauth_as_refresh_tokens` |
| `migrations/0002_par.sql` | `par` | `oauth_as_pushed_requests` |
| `migrations/0003_consent.sql` | `consent` | `oauth_as_consents` |
| `migrations/0004_replay.sql` | `client_assertion` or `dpop` | `oauth_as_replay_ids` |

Each row is one of the core's own record types serialized whole into a `jsonb` `payload`, plus the
few columns a query keys on. Column-per-field was rejected because the core gates *fields* on cargo
features (`dpop` adds `jkt`, `mtls` adds `x5t_s256`, `rar` adds `authorization_details`, `consent`
adds `authentication`), so that schema would need a migration per feature combination and would
silently drop a field whose column a deployment had not created. Dropping `jkt` is not cosmetic: it
turns a sender-constrained token back into a bearer token, and nothing on the token plane notices.

The indexes are on what the reads actually key on: the user-code index, the refresh family id, the
consent `(client_id, subject)` pair, and every expiry column the sweep scans.

**The user-code index is a column of the grant, not a second table.** That is what makes both halves
of `put_device_grant`'s contract fall out of the schema rather than out of code: a put that *changes*
the user code retires the old entry because the upsert overwrites the column, and a `take_*` clears
the index with the record because `DELETE ... RETURNING` removes the row that holds both. The refusal
half is a `UNIQUE` index, so "is this code taken" is answered by the database without a race, which
is the only way the server's collision retry loop means anything.

Expiries are `BIGINT` nanoseconds since the epoch rather than `timestamptz`: the trait speaks
`SystemTime` and `sweep_expired` compares on a boundary the core's harness plants a record exactly
on, and `timestamptz` is microsecond-resolution. The authoritative instant is always the one in the
payload; the column exists so the sweep can range-scan.

There are **no foreign keys**, deliberately. See the module docs at the top of `src/store.rs`.

## Errors

Nothing from the driver's own message reaches `StorageError`. That text becomes a line in the host's
log, and a driver error can carry the connection string (with the password) or the statement and its
bound parameters, which on every `take_*` path is a live bearer credential. What is forwarded is the
operation that failed and the SQLSTATE, which are what an operator needs to route the problem and
cannot contain a secret.

`PostgresStorage::connect` and `migrate` use a separate `SetupError` that *does* keep the driver's
diagnosis: they run at startup, not on a request path, and a host debugging a bad URL needs to see
it.

## Running the evidence

```
./scripts/postgres-conformance.sh
```

It starts a throwaway `postgres:16-alpine`, runs everything, and removes the container. Point
`OAUTH_AS_POSTGRES_TEST_URL` at your own server to skip the container.

Two suites run:

- **`tests/conformance.rs`** runs the core crate's own exported harness
  (`oauth_as::storage_conformance`, feature `test-util`) against a real PostgreSQL, in
  `with_spawn` mode on a multi-threaded runtime, over a pool large enough that the racers hold
  different connections. Once at the default eight racers and once at twenty-four.
- **`tests/two_connection.rs`** does the part the harness says it cannot. Each racer holds its own
  `PostgresStorage` over its own pool of exactly **one** connection, so the two takes provably
  travel over two different sessions. One hundred rounds of `take_refresh_token`, one hundred of
  `claim_replay_id`, exactly one winner each time.

**The detector is proved to work on every run.** `src/naive.rs` holds the deliberately non-atomic
read-then-delete and look-then-insert, and the same race is run against them and asserted to
double-spend. This is not a commit that was reverted; if the naive store ever stops double-spending,
the suite fails and says the detector has gone blind. Measured on the run that produced this README:
read-then-delete double-spent in **100 of 100** rounds and look-then-insert double-claimed in
**100 of 100**.

The REAL implementation was also broken deliberately, once, to check that the tests are pointed at
the thing they claim to test rather than only at `naive.rs`. `take_refresh_token` was rewritten as a
`SELECT` followed by a `DELETE` and both suites went red, on a real server, immediately:

```
take_refresh_token_has_exactly_one_winner_across_two_connections ... FAILED
  round 0: DELETE ... RETURNING handed the same refresh token to 2 callers
           over two separate connections

storage_conformance_against_real_postgres ... FAILED
  atomic_take/take_refresh_token: 8 of 8 concurrent takes each received the
  refresh record: the operation is not an atomic remove-and-return
```

Worth recording, because it is a correction to an assumption: the core's in-process harness DID
catch this one, at 8 of 8 racers. Its module docs say it cannot prove atomicity across processes,
and that remains true, but the defect it cannot see is a store whose atomicity comes from an
in-process LOCK around a read-then-delete pair. A store with no such lock, which is what any real
database client is, suspends between the two round trips, and the harness's racers interleave there.
The two-connection test is still the stronger evidence, because it removes the possibility that an
in-process lock is what produced the green.

These tests are behind `--features pg-integration`, off by default, so `cargo test --workspace` on a
machine with no database is honest rather than red. The default build carries one test whose *name*
is the notice that they did not run, and with the feature on a missing
`OAUTH_AS_POSTGRES_TEST_URL` is a **panic**, not a skip.

## Features

Each feature exists only to turn on the matching feature of `oauth-as`, because the trait methods
they gate are `#[cfg]`-ed in the trait itself: `par`, `consent`, `client_assertion`, `dpop`, plus
`mtls` and `rar`, which change the *fields* on the persisted records rather than the method set.

**A workspace that enables `oauth-as/consent` from another crate but leaves
`oauth-as-postgres/consent` off will not compile**, because cargo unifies the core's features and
the trait then has a method this crate did not implement. That is inherent to `#[cfg]`-gated trait
methods and is not something this crate can paper over; enable the pair together.

## Status

The implementation is complete against the trait as of `oauth-as` 0.9.0 and passes the core's
conformance harness plus the two-connection atomicity proof. What it has **not** had is production
traffic, a load test, a failure-injection run (connection dropped mid-transaction), or a review of
its behaviour under a non-default isolation level. Nothing here has been measured for throughput.
