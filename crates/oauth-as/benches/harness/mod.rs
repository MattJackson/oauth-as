// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A zero-dependency timing harness for this crate's benchmarks.
//!
//! # Why this is hand rolled rather than criterion or divan
//!
//! MEASURED on 2026-08-09, not assumed. Both of the obvious off-the-shelf choices break
//! `cargo +1.75 test -p oauth-as --locked`, which is `GOAL.md` Gate 6's own CHECK command, and
//! they break it for the exact reason `KICKOFF.md`'s MSRV entry already records about
//! `base64ct` and `zeroize`:
//!
//! - `criterion` 0.8.2 declares `rust-version = "1.86"`, eleven minors above this crate's
//!   measured 1.75 floor. Pinning back to `criterion` 0.5.1 does not help: it resolves
//!   `clap_lex` 1.1.0, which is edition 2024, and cargo 1.75 cannot PARSE that manifest at all.
//!   The observed failure is `feature edition2024 is required`, during dependency download,
//!   before any of this crate's code is compiled.
//! - `divan` 0.1.21 declares `rust-version = "1.80.0"` and resolves the same `clap_lex`. Same
//!   failure, same place.
//!
//! A dev-dependency does not reach a consumer, which is true and is not the whole cost. It DOES
//! reach `Cargo.lock`, and `Cargo.lock` is what makes `--locked` at the floor honest. Measured
//! package counts in this workspace's lockfile: 256 today, 265 with `divan`, 278 with
//! `criterion`. This repository has already deleted a dev-dependency (`jsonschema`) for costing
//! 88 packages and for declaring an MSRV that stopped the 1.75 job from running the tests; see
//! the note above `[dev-dependencies]` in `crates/oauth-as/Cargo.toml`. Adding one back to draw
//! a chart would undo that decision for a smaller reason.
//!
//! So this file follows the same rule the counting allocator in `tests/support/alloc.rs` follows,
//! and for the same reason: what is needed here is small enough to write, and writing it costs
//! nothing that anybody downstream has to carry.
//!
//! # What it does, and what that buys
//!
//! For each benchmark:
//!
//! 1. ESTIMATE. Run the closure once, timed, and pick an iteration count `n` so that one round
//!    takes about [`ROUND_TARGET`]. This keeps the per-round total far above the clock's own
//!    resolution, so the division by `n` is not measuring `Instant::now`.
//! 2. WARM UP. Run whole rounds, discarded, until [`WARMUP`] has elapsed. This pays for the
//!    first-touch page faults, the branch predictor, and any lazily grown `HashMap` bucket table
//!    inside `MemoryStorage`, none of which a steady-state server pays per request.
//! 3. MEASURE. Run [`ROUNDS`] rounds and keep each round's per-iteration mean.
//! 4. REPORT the MEDIAN of those round means as the headline figure, alongside the MINIMUM and a
//!    spread figure.
//!
//! The median is the headline because it is robust: on a laptop, a scheduler preemption or a
//! frequency change inflates a round, and a mean would carry that inflation into the number
//! forever. The minimum is reported next to it because for a deterministic, single-threaded,
//! allocation-bounded workload like this one the minimum is the closest thing available to "the
//! cost with no interference", and a large gap between minimum and median is itself the signal
//! that the machine was busy.
//!
//! The spread column is the MEDIAN ABSOLUTE DEVIATION of the round means, as a percentage of the
//! median. It is not a confidence interval and is not claimed to be one: criterion's bootstrap
//! resampling is genuinely better statistics than this. What MAD does give, cheaply and without a
//! dependency, is an honest "do not trust digits beyond this" marker. A row with 15% spread is a
//! row that has not measured anything you should act on. See `benches/README.md`.
//!
//! # What it deliberately does not do
//!
//! No outlier classification, no bootstrap confidence intervals, no regression detection against
//! a saved baseline, no plots. If any of those becomes load bearing, the honest move is to
//! reopen the dependency question with the MSRV numbers above rather than to grow this file into
//! a worse criterion.

#![allow(dead_code)] // each bench target uses a different subset of this module

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Target wall time for one round. Large enough that dividing by the iteration count is not
/// measuring the clock, small enough that a preempted round is cheap to discard by the median.
const ROUND_TARGET: Duration = Duration::from_millis(20);
/// Discarded warm-up time before the measured rounds begin.
const WARMUP: Duration = Duration::from_millis(150);
/// Number of measured rounds. Odd, so the median is an actual observation rather than a mean of
/// two, which keeps the headline figure something that really happened.
const ROUNDS: usize = 51;
/// Ceiling on the estimated iteration count, so a closure that the optimizer manages to reduce to
/// nothing cannot spin for minutes.
const MAX_ITERS: u64 = 50_000_000;

/// One measured benchmark.
pub struct Row {
    pub name: String,
    /// Median of the per-round mean per-iteration times.
    pub median: Duration,
    /// Fastest per-round mean seen.
    pub min: Duration,
    /// Median absolute deviation of the per-round means, as a percentage of `median`.
    pub spread_pct: f64,
    /// Iterations per measured round.
    pub iters: u64,
}

impl Row {
    /// Operations per second implied by the median.
    pub fn per_sec(&self) -> f64 {
        let secs = self.median.as_secs_f64();
        if secs > 0.0 {
            1.0 / secs
        } else {
            f64::INFINITY
        }
    }
}

/// A group of benchmarks that prints one table.
pub struct Bench {
    title: &'static str,
    filter: Option<String>,
    rows: Vec<Row>,
    /// Set when `cargo bench -- --list` or a `--no-run`-style invocation is detected, in which
    /// case names are printed and nothing is timed.
    list_only: bool,
}

impl Bench {
    /// Build from the process arguments.
    ///
    /// `cargo bench` passes `--bench` (and, if the target were `test = true`, `--test`) plus any
    /// user arguments after `--`. Unrecognized flags are IGNORED rather than rejected: a bench
    /// harness that aborts on an argument cargo chose to add is a harness that breaks on a cargo
    /// upgrade, and there is nothing here worth failing a build over.
    pub fn from_args(title: &'static str) -> Self {
        let mut filter = None;
        let mut list_only = false;
        for arg in std::env::args().skip(1) {
            if arg == "--list" {
                list_only = true;
            } else if !arg.starts_with('-') {
                filter = Some(arg);
            }
        }
        Bench {
            title,
            filter,
            rows: Vec::new(),
            list_only,
        }
    }

    fn selected(&self, name: &str) -> bool {
        match &self.filter {
            None => true,
            Some(f) => name.contains(f.as_str()),
        }
    }

    /// Time `body`, which is re-run from scratch on every iteration.
    ///
    /// The return value is passed through [`black_box`] so the optimizer cannot delete the work
    /// that produced it. Use this when the closure needs no per-iteration input.
    pub fn bench<T, F: FnMut() -> T>(&mut self, name: &str, mut body: F) {
        self.bench_with(name, || (), move |()| body())
    }

    /// Time `body` against a fresh `input` built by `setup` on every iteration, with `setup`
    /// excluded from the measurement.
    ///
    /// This is what makes SINGLE-USE artifacts measurable at all. An authorization code, a device
    /// code and a rotating refresh token are each redeemable exactly once by design, so the
    /// second iteration of a naive loop would be measuring the refusal path, not the redemption
    /// path. `setup` mints a fresh one per iteration, outside the clock.
    ///
    /// The cost of that: `setup` still runs inside the round, so it perturbs cache and allocator
    /// state that the timed section then sees. That is unavoidable without a much more invasive
    /// design, and it is the reason the setup-using rows in these tables are noisier than the
    /// pure-function rows.
    pub fn bench_with<I, T, S, F>(&mut self, name: &str, mut setup: S, mut body: F)
    where
        S: FnMut() -> I,
        F: FnMut(I) -> T,
    {
        if !self.selected(name) {
            return;
        }
        if self.list_only {
            println!("{name}: bench");
            return;
        }

        // 1. Estimate an iteration count from a single timed call.
        let probe_start = Instant::now();
        black_box(body(setup()));
        let probe = probe_start.elapsed().max(Duration::from_nanos(1));
        let iters = (ROUND_TARGET.as_nanos() / probe.as_nanos().max(1))
            .max(1)
            .min(MAX_ITERS as u128) as u64;

        // 2. Warm up. Whole rounds, so the warm-up shape matches the measured shape.
        let warm_start = Instant::now();
        while warm_start.elapsed() < WARMUP {
            for _ in 0..iters {
                black_box(body(setup()));
            }
        }

        // 3. Measure. `setup` is called outside the clock, once per iteration.
        let mut means = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let input = setup();
                let start = Instant::now();
                black_box(body(input));
                total += start.elapsed();
            }
            means.push(total.as_secs_f64() / iters as f64);
        }

        self.rows.push(summarize(name, means, iters));
    }

    /// Time `body` with no per-iteration setup and no per-iteration clock read: the clock is read
    /// once per ROUND and the whole round is divided by the iteration count.
    ///
    /// For a closure in the tens-of-nanoseconds range, `Instant::now` around each iteration (as
    /// [`Bench::bench_with`] does, because it must, to exclude setup) is a significant fraction of
    /// what is being measured. This variant removes that, and is what the pure-function rows use.
    pub fn bench_fast<T, F: FnMut() -> T>(&mut self, name: &str, mut body: F) {
        if !self.selected(name) {
            return;
        }
        if self.list_only {
            println!("{name}: bench");
            return;
        }

        let probe_start = Instant::now();
        black_box(body());
        let probe = probe_start.elapsed().max(Duration::from_nanos(1));
        let iters = (ROUND_TARGET.as_nanos() / probe.as_nanos().max(1))
            .max(1)
            .min(MAX_ITERS as u128) as u64;

        let warm_start = Instant::now();
        while warm_start.elapsed() < WARMUP {
            for _ in 0..iters {
                black_box(body());
            }
        }

        let mut means = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            let start = Instant::now();
            for _ in 0..iters {
                black_box(body());
            }
            means.push(start.elapsed().as_secs_f64() / iters as f64);
        }

        self.rows.push(summarize(name, means, iters));
    }

    /// Look a measured row back up by name, for a bench target that wants to COMPARE two rows
    /// (the constant-time gate does this) rather than only print them.
    pub fn row(&self, name: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.name == name)
    }

    /// Print the table. Called once at the end of a bench target's `main`.
    pub fn finish(&self) {
        if self.list_only || self.rows.is_empty() {
            return;
        }
        let width = self
            .rows
            .iter()
            .map(|r| r.name.len())
            .max()
            .unwrap_or(4)
            .max(20);
        println!();
        println!("== {} ==", self.title);
        println!(
            "{:<width$}  {:>12}  {:>12}  {:>8}  {:>14}  {:>10}",
            "benchmark", "median", "min", "spread", "per second", "iters/round"
        );
        println!("{}", "-".repeat(width + 66));
        for r in &self.rows {
            println!(
                "{:<width$}  {:>12}  {:>12}  {:>7.1}%  {:>14}  {:>10}",
                r.name,
                fmt_dur(r.median),
                fmt_dur(r.min),
                r.spread_pct,
                fmt_rate(r.per_sec()),
                r.iters
            );
        }
    }
}

/// Print a growth table for a family of rows measured at increasing input sizes, and say whether
/// the growth is linear.
///
/// This is the part of the suite that is looking for a DENIAL OF SERVICE rather than for a
/// performance nit. A path that is linear at n=10 and quadratic at n=1000 is not slow, it is a
/// lever an attacker pulls: the request that costs them one packet costs the server a thousand
/// times more than the shape of the input suggests. The column that answers the question is
/// `ns/element`, which is FLAT for linear growth and RISING for anything worse. `factor` is the
/// growth in total time from one row to the next, printed next to the growth in `n`, because a
/// factor of 10 in n against a factor of 100 in time is what quadratic looks like from outside.
///
/// `rows` are looked up by the names the caller measured under, so this prints nothing if a row
/// was filtered out.
pub fn print_growth(
    bench: &Bench,
    title: &str,
    sizes: &[usize],
    name_of: impl Fn(usize) -> String,
) {
    let found: Vec<(usize, &Row)> = sizes
        .iter()
        .filter_map(|&n| bench.row(&name_of(n)).map(|r| (n, r)))
        .collect();
    if found.len() < 2 {
        return;
    }
    println!();
    println!("-- growth: {title} --");
    println!(
        "{:>10}  {:>12}  {:>14}  {:>10}  {:>10}",
        "n", "median", "ns/element", "n factor", "t factor"
    );
    let mut prev: Option<(usize, f64)> = None;
    for (n, row) in found {
        let ns = row.median.as_secs_f64() * 1e9;
        let per = ns / n as f64;
        let (nf, tf) = match prev {
            None => (String::from("-"), String::from("-")),
            Some((pn, pns)) => (
                format!("{:.1}x", n as f64 / pn as f64),
                format!("{:.1}x", ns / pns),
            ),
        };
        println!(
            "{n:>10}  {:>12}  {per:>14.1}  {nf:>10}  {tf:>10}",
            fmt_dur(row.median)
        );
        prev = Some((n, ns));
    }
}

fn summarize(name: &str, mut means: Vec<f64>, iters: u64) -> Row {
    means.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = means[means.len() / 2];
    let min = means[0];
    // Median absolute deviation: the median of |x - median|. Robust to the one preempted round
    // that a standard deviation would let dominate.
    let mut devs: Vec<f64> = means.iter().map(|m| (m - median).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = devs[devs.len() / 2];
    Row {
        name: name.to_string(),
        median: Duration::from_secs_f64(median),
        min: Duration::from_secs_f64(min),
        spread_pct: if median > 0.0 {
            mad / median * 100.0
        } else {
            0.0
        },
        iters,
    }
}

fn fmt_dur(d: Duration) -> String {
    let ns = d.as_secs_f64() * 1e9;
    if ns < 1_000.0 {
        format!("{ns:.1} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} us", ns / 1e3)
    } else {
        format!("{:.2} ms", ns / 1e6)
    }
}

fn fmt_rate(per_sec: f64) -> String {
    if per_sec >= 1e6 {
        format!("{:.2} M/s", per_sec / 1e6)
    } else if per_sec >= 1e3 {
        format!("{:.1} k/s", per_sec / 1e3)
    } else {
        format!("{per_sec:.0} /s")
    }
}

/// Print the machine and build profile, so a table pasted anywhere carries its own context.
///
/// Anything that cannot be read without a dependency (the exact CPU model, the core count) is
/// left to the reader to state; what IS printed is what the compiler and cargo already know.
pub fn print_environment() {
    println!("target : {}", std::env::consts::ARCH);
    println!("os     : {}", std::env::consts::OS);
    println!(
        "profile: {} (cargo bench uses the `bench` profile, which inherits `release`)",
        if cfg!(debug_assertions) {
            "debug_assertions ON, these numbers are NOT a release measurement"
        } else {
            "optimized, debug_assertions off"
        }
    );
    println!(
        "storage: MemoryStorage, in process, no network, no TLS, no database. \
         See benches/README.md for what that means and does not mean."
    );
}

/// A current-thread tokio runtime.
///
/// `new_current_thread`, never `rt-multi-thread`, for the same reason `tests/allocation.rs` gives:
/// no extra OS thread should be alive while a window is being measured. Every async benchmark in
/// this suite pays one `block_on` per iteration; the `runtime_block_on_baseline` row in
/// `benches/token.rs` measures that cost on its own so a reader can subtract it.
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}
