# oauth-as-postgres

A PostgreSQL implementation of the [`oauth-as`](../oauth-as) `Storage` trait.

**NOT PUBLISHED.** This crate has never been released to crates.io. Its version number tracks the
`oauth-as` it implements and means nothing else; `publish = false` is set in its manifest. Do not
read the `0.9.1` as a claim that it is available, supported, or that its schema is stable.

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

Five checked-in migrations, applied by `PostgresStorage::migrate()` or by whatever migration tool
the host already runs. They are plain, idempotent SQL.

| File | Applied when | Tables |
| ---- | ------------ | ------ |
| `migrations/0001_core.sql` | always | `oauth_as_clients`, `oauth_as_device_grants`, `oauth_as_authorization_codes`, `oauth_as_access_tokens`, `oauth_as_refresh_tokens` |
| `migrations/0002_par.sql` | `par` | `oauth_as_pushed_requests` |
| `migrations/0003_consent.sql` | `consent` | `oauth_as_consents` |
| `migrations/0004_replay.sql` | `client-assertion` or `dpop` | `oauth_as_replay_ids` |
| `migrations/0005_revocation_barriers.sql` | always | `oauth_as_revocation_barriers` |

`migrate()` runs the ones this build needs, in **one transaction holding one advisory lock**, so
several nodes starting at once is safe. Not all five: the "Applied when" column above is the whole
rule, and a default build applies exactly two (`0001` and `0005`), because nothing in it could write
to the other three tables. `CREATE ... IF NOT EXISTS` on its own would not make it safe: PostgreSQL's
existence check and catalogue insert are not one step, so two nodes can both pass the check and the
loser gets a duplicate-key error on `pg_type_typname_nsp_index` and crash-loops until the winner
commits.

### Upgrading a live 0.9.0 deployment

**There is nothing to run. Apply the schema and roll the nodes.** This section exists because the
question is a fair one: 0.9.1 added required fields to four persisted record types
(`IssuedToken::grant_established_at`, `RefreshTokenRecord::grant_established_at`,
`AuthorizationCodeRecord::issued_at`, `PushedAuthorizationRequest::pushed_at`, plus
`AuthorizationCodeRecord::redirect_uri_was_explicit`), and every record here is stored as one
serialized document, so a payload written by 0.9.0 carries none of those keys. Without a plan that
would be an outage on upgrade: every access token, refresh record, authorization code and pushed
request already in the database would fail to deserialize, which this crate reports as a
`StorageError` and the server maps to `server_error` — introspection, refresh and in-flight code
redemption broken for every credential minted before the restart, and a refresh chain with no
absolute lifetime never expiring its way out of it.

The plan is in the core, not here: all five fields carry a `#[serde(default)]`, so an old payload
reads back with the default rather than failing. The four instants default to the **Unix epoch**,
which fails *closed* — all four name the instant the grant behind the record was established, and a
revocation barrier refuses a write whose grant instant is at or before the revocation, so a
pre-upgrade record is refused by any standing revocation rather than admitted by it. A far-future
default would have read back just as successfully and quietly un-revoked everything revoked before
the upgrade. `tests/revocation_races.rs` asserts that end to end, through this store.

A migration that backfilled those fields into the stored payloads was written for 0.9.1 and then
**removed**, deliberately. It covered strictly less than the serde defaults do (it could not reach
a 0.9.0 node still *writing* during a rolling upgrade), and it was the wrong shape for this crate:
an unbounded single-statement rewrite of every live credential row, holding a lock on each — the
thing `SWEEP_BATCH_ROWS` exists to avoid on the sweep — inside the one transaction every other
node's boot is waiting on.

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

**`oauth_as_revocation_barriers` is the one table that is not a serialized record.** It has no
`jsonb` `payload` column at all: a barrier is a `scope` tag (`client`, `family` or `consent`) plus
`client_id`, `family_id` and `subject` columns that together spell out which of the three it names,
plus two instants: the deadline the sweep may reclaim it at, and `recorded_at_ns`, when the
revocation happened. The only question a write path ever asks of it is "does any row cover this
write", which is a single indexed lookup rather than a document to deserialize — and for the
`client` and `consent` scopes that question includes whether the grant behind the write was
established before `recorded_at_ns`, so a re-provisioned client or a re-approved consent is served
rather than refused for the barrier's whole life. Unlike the other four migrations it is applied unconditionally rather than gated behind
a feature: only a `consent` build ever *writes* a consent-scoped barrier, but every build *reads*
this table on every token issuance, because `put_token` consults it whether or not `consent` is on,
so a feature-gated migration would turn a default-features deployment's first token into a
missing-table error. See `migrations/0005_revocation_barriers.sql` for the schema and why the scope
columns are `NOT NULL` with `''` rather than nullable.

## One obligation this store puts on the host

**Sweep on a timer, forever.** Nothing here evicts anything by itself; `Storage::sweep_expired` runs
when the host runs it and at no other time. The sweep deletes in batches of `SWEEP_BATCH_ROWS`,
committing each one, so reclaiming a large backlog is a sequence of short row locks rather than one
long lock over every dead row in the store. A single call still drains the whole backlog and still
returns how many rows it removed; what batching changes is how long the store holds a lock while
doing it. This now includes `oauth_as_revocation_barriers` too: nothing reclaims a barrier row
before its own deadline, so a store that is never swept keeps accumulating them at one row per
revocation, forever, on top of whatever it was already leaking.

`delete_client`, `revoke_token_family` and `revoke_consent` used to put a second obligation on the
host, and this README used to describe it: because the cascade only removed what existed *as of the
moment it ran*, a request that read a registration (or a token family, or a consent) before the
delete committed could still write a fresh record after, and no store could close that window on its
own, so the host had to stop issuing for the client first and delete a second time once every
in-flight request had drained. That is no longer the contract. All three now take a
`RevocationWindow` and record a `RevocationBarrier` in the SAME transaction as the cascade (`oauth_as_revocation_barriers`,
`migrations/0005_revocation_barriers.sql`), and every write a barrier could cover, `put_token`,
`put_refresh_token` and `put_pushed_authorization_request`, consults it first and returns
`WriteOutcome::RefusedRevoked` rather than writing. A request that read the old registration and
tries to write its token, refresh record or pushed request after the delete now finds the write
refused, rather than resurrecting a record the revocation just removed. The host's remaining job is
choosing a `RevocationWindow::until` far enough out to outlive anything that could still be in
flight, which for `delete_client` means at least the longest access-token or refresh-chain lifetime
the deployment is configured to mint; too short a deadline reopens exactly the window the barrier
exists to close, one sweep cycle after it is chosen.

The window's other half, `recorded_at`, is when the revocation happened, and it is what a later
write is compared against. A `client` or `consent` barrier refuses a write only when the GRANT
behind it was established at or before that instant, so a `client_id` the host re-provisions after
a deletion — or a user who withdraws an application and approves it again — is served rather than
locked out for the barrier's whole life. A `family` barrier ignores it and refuses
unconditionally, because a rotation legitimately mints fresh records inside an existing family. See the
module docs at the top of `src/store.rs` and the `RevocationBarrier` docs in the core crate's
`src/store.rs` for the full reasoning, including why a foreign key, a higher isolation level and a
different statement order each fail to close this window on their own.

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

Five suites run:

- **`tests/conformance.rs`** runs the core crate's own exported harness
  (`oauth_as::storage_conformance`, feature `test-util`) against a real PostgreSQL, in
  `with_spawn` mode on a multi-threaded runtime, over a pool large enough that the racers hold
  different connections. Once at the default eight racers and once at twenty-four.
- **`tests/two_connection.rs`** does the part the harness says it cannot. Each racer holds its own
  `PostgresStorage` over its own pool of exactly **one** connection, so the two operations provably
  travel over two different sessions. Eight tests: three races run one hundred rounds each
  (`take_refresh_token`, `claim_replay_id` and `compare_and_swap_device_grant`, exactly one winner
  every round), one check that a swap arriving after the grant was redeemed does not put it back,
  and the deliberately-wrong counterpart of each of those four.
- **`tests/revocation_races.rs`** interleaves a revocation with a write for the same identity, on
  purpose and without racing: a third connection holds an uncommitted row with the primary key the
  write is about to use, which stops that write between its refusal check and its own insert, while
  the revocation commits whole. It is not a timing race — an uncommitted row blocks the insert and
  is invisible to the revocation's cascade, so the interleaving is forced rather than hoped for.
  Four writes are covered (`put_token` against `delete_client` and against `revoke_consent`,
  `put_refresh_token` against `revoke_token_family`, `put_pushed_authorization_request` against
  `delete_client`), and each asserts the user-visible outcome: no live credential for the identity
  that was revoked. The same file checks the two other things only a real server can answer —
  that eight nodes calling `migrate()` at once all succeed, and that the refusal lookup's cost does
  not grow with the number of standing barriers.
- **`tests/sweep_batching.rs`** checks that a backlog spanning several `SWEEP_BATCH_ROWS` batches is
  drained by one call and counted truthfully, and that a live record survives it.
- **`tests/persisted_shape.rs`** checks what the ROW holds after a write rather than what the call
  returned: that `compare_and_swap_authorization_code` rewrites the index columns and not only the
  payload (they are a projection of it, and the `revoke_consent` cascade and `sweep_expired` key on
  them), and that the three feature-gated fields on `IssuedToken` (`act`, `x5t_s256`,
  `authorization_details`) survive a round trip through a real server.

**The detector is proved to work on every run.** `src/naive.rs` holds three deliberately wrong
implementations, and the same check is run against each and asserted to fail: the read-then-delete
take, the look-then-insert replay claim, and the read-compare-write device-grant swap, which is the
body the core trait used to supply as a default and has two failure modes rather than one (a lost
update, and a write that RESURRECTS a grant already redeemed, because its write is an upsert). This
is not a commit that was reverted; if a naive implementation ever stops failing, the suite fails and
says the detector has gone blind. Measured on the runs that produced this README: read-then-delete
double-spent in **100 of 100** rounds and read-compare-write lost an update in **100 of 100**, both
on every run; look-then-insert double-claimed in **99 of 100** on one run and **100 of 100** on the
next, which is why every assertion here is "more than zero rounds" rather than a fixed count. The
two resurrection checks need no rounds and no race at all, so they carry no figure: the swap simply
lands after the redemption.

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

They also run in CI, which for the whole of 0.9.0 they did not: the `postgres-atomicity` job in
`.github/workflows/qa.yml` supplies a real server as a service container and runs the same
`scripts/postgres-conformance.sh` a workstation runs. That job does not trust its own green. It
first feeds a DEFAULT-feature test log (the exact shape of the old defect: every real test absent,
`cargo test` exiting 0) to the guard that checks the run, and fails if the guard accepts it; only
then does it run the suite and require the named tests, a floor on the count, zero ignored, zero
filtered out, and the naive implementations' observed race counts in the log.

## Features

Each feature exists only to turn on the matching feature of `oauth-as`. For `par`, `consent`,
`client-assertion` and `dpop` that is because the trait methods they gate are `#[cfg]`-ed in the
trait itself, so this crate genuinely compiles different code. `mtls`, `rar` and `token-exchange`
change the *fields* on the persisted records rather than the method set, and nothing under `src/`
or `tests/` is `#[cfg]`-ed on them at all: the payload is serde over the core's own types, so the
store writes whatever those types are in this build.

Those three are therefore **pure re-exports**, and the reason to have them is not what this README
said until the 0.9.1 audit. It claimed that a host whose core had them on must switch them on here
too "or the two crates disagree about the shape of a record". That cannot happen: cargo unifies
features across a build graph, so there is exactly one compiled `oauth-as` and exactly one
`IssuedToken`. What the three lines actually buy is the ability to **enable the core feature from a
manifest that names only this crate**: one line here instead of a second direct dependency on
`oauth-as` carrying the feature, which is precisely the coupling this crate exists to spare a host.

**A workspace that enables `oauth-as/consent` from another crate but leaves
`oauth-as-postgres/consent` off will not compile**, because cargo unifies the core's features and
the trait then has a method this crate did not implement. That is inherent to `#[cfg]`-gated trait
methods and is not something this crate can paper over; enable the pair together.

## Status

The implementation is complete against the trait as of `oauth-as` 0.9.1 and passes the core's
conformance harness plus the two-connection atomicity proof. What it has **not** had is production
traffic, a load test, a failure-injection run (connection dropped mid-transaction), or a review of
its behaviour under a non-default isolation level. Nothing here has been measured for throughput.
