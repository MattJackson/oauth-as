// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A rate limiter the crate SHIPS, so that "the host must throttle this" is a line of code rather
//! than a paragraph of documentation.
//!
//! # Why a library that "cannot rate limit" ships a rate limiter
//!
//! [`crate::events::RateLimiter`] is a seam because this crate never sees a request: it has no IP,
//! no session, no TLS peer and no request context, so it cannot key a counter on the things a real
//! throttle wants to key on. That reasoning is sound and it is unchanged. What it does NOT justify
//! is shipping the seam EMPTY.
//!
//! RFC 8628 section 5.1 is explicit that the device user code's entropy is adequate only IN
//! COMBINATION WITH rate limiting of user code entry. This crate's default user code is
//! [`crate::server::MIN_USER_CODE_LENGTH`] symbols over a 20-symbol alphabet: 20^8 is about
//! 2.56e10, or 2^34.6. Against an unthrottled
//! [`crate::server::AuthorizationServer::approve_device`], at a conservative 1000 attempts per
//! second, an attacker makes 6e5 guesses inside the default 600 second
//! [`crate::server::ServerConfig::device_code_ttl`]. They do not need to hit one PARTICULAR code,
//! only SOME live one, so with a pool of `N` concurrently live grants the expected number of hits
//! per code lifetime is `6e5 * N / 2.56e10`, which passes 1 at about 43,000 live grants and is
//! already a 2.3% chance per lifetime at 1000. A hit binds a STRANGER'S DEVICE to the ATTACKER'S
//! account, because the attacker supplies the `subject`.
//!
//! So the entropy argument in section 5.1 is only half a defence, and the other half is a counter.
//! A crate that ships the half it can and leaves the half it "cannot" as an exercise has shipped a
//! deployment where the odds above are the real odds. [`FixedWindowRateLimiter`] is the half this
//! crate can ship: an in-memory, per-process, weighted fixed-window counter with no new dependency,
//! which a host installs in one line:
//!
//! ```
//! # use oauth_as::{AuthorizationServer, FixedWindowRateLimiter, MemoryStorage, ServerConfig};
//! # let config = ServerConfig::new("https://as.example", "https://as.example/device");
//! let server = AuthorizationServer::new(config, MemoryStorage::new())
//!     .with_rate_limiter(Box::new(FixedWindowRateLimiter::new()));
//! ```
//!
//! It is a FLOOR, not a ceiling. Read "What this cannot do" below before deciding it is enough,
//! because the difference between a useful default and a false sense of safety is whether the host
//! was told plainly what they still owe.
//!
//! # What this cannot do
//!
//! - IT IS PER PROCESS. The counters live in this process's memory and nowhere else. On a
//!   multi-node deployment EVERY NODE HAS ITS OWN COUNTERS and the effective limit is multiplied by
//!   the node count: ten nodes behind a load balancer that spreads attempts evenly means ten times
//!   the default budget, and an attacker who can pick their node gets a fresh budget per node. A
//!   deployment at that scale needs a SHARED store (Redis, a database counter, the edge proxy's own
//!   limiter) behind the same [`crate::events::RateLimiter`] trait. This type is the right answer
//!   for a single-node deployment and a useful second layer for a larger one; it is not a
//!   distributed limiter and no amount of tuning makes it one.
//! - IT RESETS ON RESTART. In-memory means a redeploy, a crash, or an OOM kill hands the attacker a
//!   fresh budget. An attacker who can induce restarts can defeat it.
//! - IT HAS NO CALLER IDENTITY, so the device user code budget is GLOBAL. Every user of the
//!   verification page shares one counter, because the library has no IP to separate them by. The
//!   consequence runs in both directions and the host should understand both: an attacker's
//!   failures consume budget a legitimate user might have wanted (a sustained attack degrades the
//!   verification page for everyone), and the budget must therefore be set high enough not to
//!   strangle real activation traffic. The weighting below is what makes that tension survivable,
//!   not something that removes it. A host that DOES have request context should key its own
//!   limiter on the IP or session and keep this one underneath as a backstop.
//! - IT IS A FIXED WINDOW, NOT A SLIDING ONE. A burst straddling a window boundary can land up to
//!   twice the budget in quick succession (the tail of one window plus the head of the next). This
//!   is the classic fixed-window artefact. It is accepted here because the alternative that fixes
//!   it (a sliding log) stores a timestamp per attempt, which is exactly the unbounded
//!   attacker-driven allocation the "bounded" requirement below rules out. Set the window shorter
//!   if the doubling matters.
//! - IT IS NOT A LOCKOUT. Nothing is disabled, no account is suspended, no client is deregistered.
//!   When the window rolls the budget is whole again, deliberately: a throttle that never lifts is
//!   an outage, and an attacker who can trigger a permanent lockout of a client id has a denial of
//!   service. Locking out is a policy decision with an operator in the loop, which is what the
//!   [`crate::events::EventSink`] channel is for.
//! - IT DOES NOT REPLACE THE AUDIT CHANNEL. The counter refuses; it does not tell anyone. A
//!   deployment being held at its ceiling for hours looks identical, from the inside, to a quiet
//!   one. Install an [`crate::events::EventSink`] as well and alert on the rate of
//!   [`crate::events::Event::ClientAuthenticationFailed`].
//!
//! # How the budget is spent
//!
//! One budget per key, in abstract COST UNITS, refilled to full at the start of every window.
//!
//! - Every attempt that is ALLOWED costs [`ATTEMPT_COST`] (1) at [`RateLimiter::check`] time.
//!   That is the ceiling on traffic.
//! - Every allowed attempt that then FAILS costs a further `failure_cost` at
//!   [`RateLimiter::record`] time.
//!
//! The weighting is the point, and it is why this implementation uses `record` rather than only
//! `check`. A guessing attack does not show up as VOLUME, it shows up as FAILURES: an attacker
//! spraying user codes fails essentially every time, while a legitimate user typing the code off
//! their television screen succeeds essentially every time. A limiter that counted traffic alone
//! would have to choose between a ceiling low enough to stop guessing (which throttles a busy
//! verification page into an outage) and one high enough for real traffic (which is no obstacle to
//! guessing). Charging failures ten times what successes cost lets one budget be both.
//!
//! # The default numbers, and why they are those numbers
//!
//! A default nobody can justify is worse than no default, so each of these is derived rather than
//! chosen, and each is a [`RateLimitConfig`] field a host can move.
//!
//! ## Window: 60 seconds ([`DEFAULT_WINDOW`])
//!
//! Long enough that the fixed-window doubling artefact is bounded by something a human notices,
//! short enough that a legitimate user caught behind somebody else's burst waits under a minute
//! rather than being locked out of activating their device. It also makes the numbers below
//! readable as "per minute", which matters when an operator has to reason about them at 3am.
//!
//! ## Device user code entry: 200 units, failures cost 10 ([`DEFAULT_DEVICE_USER_CODE_CAPACITY`],
//! [`DEFAULT_DEVICE_USER_CODE_FAILURE_COST`])
//!
//! Read as two numbers at once, which is what the weighting buys:
//!
//! - AT MOST 200 code entries per minute per process, so a deployment can activate about 3.3
//!   devices a second on one node before the ceiling bites. That is the "do not strangle real
//!   traffic" side.
//! - AT MOST 20 WRONG code entries per minute per process (each costs `1 + 9 = 10`). That is the
//!   RFC 8628 section 5.1 side, and it is the number the arithmetic is about.
//!
//! Twenty wrong codes a minute is 200 guesses inside the default 600 second code lifetime. Against
//! a pool of 1000 concurrently live grants that is `200 * 1000 / 2.56e10`, about 7.8e-6 expected
//! hits per code lifetime, versus the 2.3e-2 an unthrottled endpoint gives the same attacker at
//! 1000 attempts a second: a reduction of roughly three thousand fold. Stated honestly the other
//! way, because a security default should be stated at its worst: an attack sustained at EXACTLY
//! this ceiling, unnoticed, against a deployment continuously holding 1000 live device grants,
//! accumulates about 0.4 expected hits over a YEAR. That is not "impossible", it is "a year-long
//! visible campaign for a coin flip", which is what a throttle is for: it converts minutes into a
//! sustained, loud, long-running operation. It is also why the paragraph above says to install an
//! event sink, and why a host with a larger live-grant pool should lower
//! `device_user_code_capacity` (the odds scale linearly with both) or raise
//! [`crate::server::ServerConfig::user_code_length`] (they scale by a factor of 20 per symbol).
//!
//! Twenty wrong entries a minute is also, as a legitimate-traffic number, generous: the user is
//! reading the code off a screen in front of them, the alphabet excludes the vowels and digits that
//! cause transcription errors, and this crate normalises case and hyphens before comparing. A
//! process seeing twenty genuine mistypes a minute is a process with a UI problem.
//!
//! ## Client authentication: 6000 units per client id, failures cost 200
//! ([`DEFAULT_CLIENT_AUTHENTICATION_CAPACITY`], [`DEFAULT_CLIENT_AUTHENTICATION_FAILURE_COST`])
//!
//! Keyed per `client_id`, which RFC 6749 section 2.2 states explicitly is not a secret, so keying
//! on it leaks nothing. Again two numbers:
//!
//! - AT MOST 6000 authentications per minute per client per process, which is 100 a second: above
//!   the rate at which a single client's token traffic on a single node is already an architecture
//!   discussion, so the ceiling should not be reached by a healthy deployment.
//! - AT MOST 30 FAILED authentications per minute per client (each costs `1 + 199 = 200`), which is
//!   the RFC 9700 section 4.13 credential-stuffing number.
//!
//! Thirty is chosen against what a client secret actually is: a machine-held value this crate mints
//! or the host provisions, not a human-chosen password. A correctly configured client fails
//! authentication ZERO times, so any sustained failure rate for one `client_id` is either a
//! misconfiguration the operator wants to hear about or an attack, and both are better served by
//! refusing than by continuing. The budget is per client id rather than global specifically so one
//! client being stuffed cannot lock every other client out of the token endpoint.
//!
//! ## Tracked clients: 4096 ([`DEFAULT_MAX_TRACKED_CLIENTS`])
//!
//! See [`FixedWindowRateLimiter`] for the bounding argument. 4096 is chosen to comfortably exceed
//! the number of registrations a single deployment realistically authenticates within one 60 second
//! window while keeping the worst-case footprint under a megabyte.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::events::{Attempt, AttemptOutcome, RateLimitDecision, RateLimiter};

/// What one allowed attempt costs, charged at [`RateLimiter::check`] time.
///
/// This is the UNIT the capacities are denominated in: a capacity of 200 means "200 attempts, if
/// they all succeed". Fixing it at 1 rather than making it configurable keeps the two numbers a
/// host actually reasons about (how many attempts, how much worse is a failure) down to two.
pub const ATTEMPT_COST: u64 = 1;

/// 60 seconds. See the module docs for why.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// 200 cost units per window for [`Attempt::DeviceUserCodeEntry`]: 200 entries a minute, or 20
/// wrong ones. See the module docs for the RFC 8628 section 5.1 arithmetic.
pub const DEFAULT_DEVICE_USER_CODE_CAPACITY: u64 = 200;

/// The EXTRA cost of a failed user code entry, on top of [`ATTEMPT_COST`], so a wrong code costs
/// ten times a right one.
pub const DEFAULT_DEVICE_USER_CODE_FAILURE_COST: u64 = 9;

/// 6000 cost units per window per `client_id`: 6000 authentications a minute, or 30 failed ones.
/// See the module docs for the RFC 9700 section 4.13 reasoning.
pub const DEFAULT_CLIENT_AUTHENTICATION_CAPACITY: u64 = 6000;

/// The EXTRA cost of a failed client authentication, on top of [`ATTEMPT_COST`], so a wrong
/// credential costs two hundred times a right one.
pub const DEFAULT_CLIENT_AUTHENTICATION_FAILURE_COST: u64 = 199;

/// How many distinct `client_id` values get their own counter within a window.
pub const DEFAULT_MAX_TRACKED_CLIENTS: usize = 4096;

/// The longest `client_id` that gets its own counter, in bytes.
///
/// Not configurable, because it is not a policy: it is the second half of the memory bound. A
/// `client_id` is attacker-supplied, so without a length cap a spray of 4096 identifiers of a
/// megabyte each would be 4 GB of "bounded" map. 128 bytes is far above anything this crate mints
/// (RFC 7591 registration produces 32 hex characters) or a host plausibly provisions; longer
/// identifiers still authenticate normally, they just share the overflow counter described on
/// [`FixedWindowRateLimiter`].
pub const MAX_TRACKED_CLIENT_ID_LEN: usize = 128;

/// The shortest window that can be configured.
///
/// A zero window would divide by zero when computing the window index, and a sub-millisecond one is
/// indistinguishable from no limiter at all on any real clock. [`RateLimitConfig::with_window`]
/// clamps up to this rather than rejecting, for the same reason
/// [`crate::server::ServerConfig::user_code_length`] clamps: a misconfiguration should not become a
/// runtime failure at the one moment a user is standing in front of a device.
pub const MIN_WINDOW: Duration = Duration::from_millis(1);

/// The knobs on [`FixedWindowRateLimiter`]. [`RateLimitConfig::default`] is the reasoned default
/// set documented at the module level; every field is public so a host can move one without the
/// builder.
///
/// `#[non_exhaustive]` because later releases will gain budgets for attempt kinds
/// [`Attempt`] does not yet have, and adding one must not break a host that built this by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimitConfig {
    /// How long a budget lasts. Clamped up to [`MIN_WINDOW`] at use.
    pub window: Duration,
    /// Cost units per window for [`Attempt::DeviceUserCodeEntry`], globally.
    pub device_user_code_capacity: u64,
    /// Extra cost charged when a user code entry FAILS.
    pub device_user_code_failure_cost: u64,
    /// Cost units per window for [`Attempt::ClientAuthentication`], per `client_id`.
    pub client_authentication_capacity: u64,
    /// Extra cost charged when a client authentication FAILS.
    pub client_authentication_failure_cost: u64,
    /// How many distinct `client_id` values get their own counter within a window. See
    /// [`FixedWindowRateLimiter`] for what happens past it.
    pub max_tracked_clients: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            window: DEFAULT_WINDOW,
            device_user_code_capacity: DEFAULT_DEVICE_USER_CODE_CAPACITY,
            device_user_code_failure_cost: DEFAULT_DEVICE_USER_CODE_FAILURE_COST,
            client_authentication_capacity: DEFAULT_CLIENT_AUTHENTICATION_CAPACITY,
            client_authentication_failure_cost: DEFAULT_CLIENT_AUTHENTICATION_FAILURE_COST,
            max_tracked_clients: DEFAULT_MAX_TRACKED_CLIENTS,
        }
    }
}

impl RateLimitConfig {
    /// Set the window, clamped up to [`MIN_WINDOW`].
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window.max(MIN_WINDOW);
        self
    }

    /// Set the [`Attempt::DeviceUserCodeEntry`] budget: `capacity` cost units per window, with
    /// `failure_cost` charged on top of [`ATTEMPT_COST`] for each failure.
    ///
    /// A capacity of 0 refuses every user code entry, which is a legitimate way to turn the
    /// verification endpoint off; it is not treated as "unlimited".
    pub fn with_device_user_code_budget(mut self, capacity: u64, failure_cost: u64) -> Self {
        self.device_user_code_capacity = capacity;
        self.device_user_code_failure_cost = failure_cost;
        self
    }

    /// Set the per-`client_id` [`Attempt::ClientAuthentication`] budget, in the same units as
    /// [`RateLimitConfig::with_device_user_code_budget`].
    pub fn with_client_authentication_budget(mut self, capacity: u64, failure_cost: u64) -> Self {
        self.client_authentication_capacity = capacity;
        self.client_authentication_failure_cost = failure_cost;
        self
    }

    /// Set how many distinct `client_id` values get their own counter within a window.
    pub fn with_max_tracked_clients(mut self, max: usize) -> Self {
        self.max_tracked_clients = max;
        self
    }

    /// The window, never zero. Every window computation goes through this.
    fn effective_window(&self) -> Duration {
        self.window.max(MIN_WINDOW)
    }
}

/// The counters for one window. Replaced wholesale when the window rolls.
#[derive(Debug, Default)]
struct Window {
    /// Which window these counters belong to: elapsed since the limiter's base instant, divided by
    /// the configured window length. A change means everything below is stale.
    index: u64,
    /// Cost spent on [`Attempt::DeviceUserCodeEntry`], which needs no map: the library has no
    /// caller identity to key it on, so there is exactly one counter.
    device_user_code: u64,
    /// Cost spent per `client_id`, bounded by `max_tracked_clients` entries and
    /// [`MAX_TRACKED_CLIENT_ID_LEN`] bytes of key.
    clients: HashMap<Box<str>, u64>,
    /// The shared counter for every `client_id` that did not get its own. See
    /// [`FixedWindowRateLimiter`].
    overflow: u64,
}

/// An in-memory, per-process, weighted fixed-window [`RateLimiter`] the crate ships so that
/// throttling is one line rather than a project.
///
/// Read the module documentation before installing it. In particular: it is PER PROCESS, so on a
/// multi-node deployment the effective limit is multiplied by the node count.
///
/// # How it is bounded
///
/// A limiter that grows a map keyed on an attacker-supplied `client_id` is itself a denial of
/// service, so the map is bounded three ways at once and every bound is a hard one:
///
/// 1. AT MOST `max_tracked_clients` ENTRIES. When the map is full, an identifier that is not
///    already in it is charged against a single shared OVERFLOW counter instead of getting an entry
///    of its own. Nothing is allocated for it.
/// 2. AT MOST [`MAX_TRACKED_CLIENT_ID_LEN`] BYTES OF KEY. A longer identifier goes straight to the
///    overflow counter, so the worst case is bounded in bytes and not only in entries: 4096 * (128
///    + 8 + `HashMap` overhead), comfortably under a megabyte at the defaults.
/// 3. AT MOST ONE WINDOW OF LIFETIME. The whole map is cleared when the window rolls, which costs
///    nothing semantically because every counter in it was about to be reset anyway. No entry
///    survives a window, so there is no eviction policy to get wrong and no slow leak of keys that
///    were seen once.
///
/// The overflow counter FAILS CLOSED, which is the important half: a spray of a million distinct
/// identifiers does not get a million fresh budgets, it gets one budget shared between all of them,
/// so the spray throttles itself harder than a repeat offender would. The cost of that choice, and
/// it is a real one, is that a legitimate client whose first authentication of a window arrives
/// after an attacker has filled the map shares the overflow counter for the rest of that window.
/// That is a bounded, self-clearing degradation, and it is preferable to the alternative (evicting
/// live counters to make room) which would let an attacker RESET a budget on demand by spraying,
/// turning the limiter off exactly when it is needed.
///
/// # Cost
///
/// One [`Mutex`] and one [`HashMap`] per limiter, allocated when the host constructs it and never
/// otherwise: a host that does not install this pays nothing, and [`crate::events::Hooks`] is
/// unchanged by its existence. Each check is one lock, one integer division and at most two hash
/// lookups. The lock is held only for the arithmetic, never across a store call or an await.
#[derive(Debug)]
pub struct FixedWindowRateLimiter {
    config: RateLimitConfig,
    /// The instant windows are measured from. [`Instant`] and not [`std::time::SystemTime`] on
    /// purpose: it is monotonic, so an NTP step or a host clock adjustment cannot hand an attacker
    /// a free budget by moving the wall clock backwards.
    base: Instant,
    state: Mutex<Window>,
}

impl Default for FixedWindowRateLimiter {
    fn default() -> Self {
        Self::with_config(RateLimitConfig::default())
    }
}

impl FixedWindowRateLimiter {
    /// A limiter with the reasoned defaults documented at the module level.
    pub fn new() -> Self {
        Self::default()
    }

    /// A limiter with a host's own budgets.
    pub fn with_config(config: RateLimitConfig) -> Self {
        FixedWindowRateLimiter {
            config,
            base: Instant::now(),
            state: Mutex::new(Window::default()),
        }
    }

    /// The configuration in force.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// How many `client_id` values currently hold a counter of their own.
    ///
    /// Exposed so a host (and this crate's own gate on the bound) can SEE that the map is bounded
    /// rather than trust that it is. Never exceeds `max_tracked_clients`.
    pub fn tracked_clients(&self) -> usize {
        self.lock().clients.len()
    }

    /// Poisoning is recovered from rather than propagated: a panic somewhere else in the process
    /// must not turn this limiter into a source of panics, and the worst a poisoned counter can be
    /// is arithmetically stale for the rest of one window.
    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Which window `now` falls in. Fixed windows anchored at [`FixedWindowRateLimiter::base`],
    /// which is what makes the roll deterministic: advancing by more than one whole window always
    /// crosses at least one boundary, whatever phase the caller started in.
    fn window_index(&self, now: Instant) -> u64 {
        let window = self.config.effective_window().as_nanos();
        let elapsed = now.saturating_duration_since(self.base).as_nanos();
        // `window` is at least MIN_WINDOW, so this cannot divide by zero. The saturating cast only
        // matters after roughly 584 years of uptime, and saturating there is still correct: the
        // index simply stops advancing, and a limiter that stops rolling refuses rather than
        // admits.
        (elapsed / window).min(u128::from(u64::MAX)) as u64
    }

    /// Charge `cost` if the budget can pay for it, and say whether it could.
    ///
    /// On refusal the counter is NOT advanced. That is deliberate: it keeps a denied flood from
    /// growing the counter without bound (it pins at the capacity instead of overflowing), and it
    /// means the budget is spent by attempts that actually happened.
    fn charge(counter: &mut u64, capacity: u64, cost: u64) -> RateLimitDecision {
        if cost > capacity.saturating_sub(*counter) {
            return RateLimitDecision::Deny;
        }
        *counter += cost;
        RateLimitDecision::Allow
    }

    /// Add `cost` to an already-allowed attempt's counter, clamped at the capacity so it can
    /// neither overflow nor grow past the point where it changes any answer.
    fn penalise(counter: &mut u64, capacity: u64, cost: u64) {
        *counter = counter.saturating_add(cost).min(capacity);
    }

    /// The decision, at an explicit instant. [`RateLimiter::check`] is this with
    /// [`Instant::now`]; the split exists so `src/tests/rate_limit.rs` can drive the window
    /// boundary exactly instead of sleeping.
    fn check_at(&self, attempt: Attempt<'_>, now: Instant) -> RateLimitDecision {
        let index = self.window_index(now);
        let mut state = self.lock();
        state.roll_to(index);
        // Matched WITHOUT a wildcard arm. `Attempt` is `#[non_exhaustive]` for hosts, but this
        // module is inside the crate that declares it, so an exhaustive match here turns "somebody
        // added a throttle point and did not give it a budget" into a compile error rather than
        // into a silently unthrottled endpoint.
        match attempt {
            Attempt::DeviceUserCodeEntry => {
                let capacity = self.config.device_user_code_capacity;
                Self::charge(&mut state.device_user_code, capacity, ATTEMPT_COST)
            }
            Attempt::ClientAuthentication { client_id } => {
                let capacity = self.config.client_authentication_capacity;
                let max_tracked = self.config.max_tracked_clients;
                let counter = state.client_counter(client_id, max_tracked);
                Self::charge(counter, capacity, ATTEMPT_COST)
            }
        }
    }

    /// The outcome report, at an explicit instant. See [`FixedWindowRateLimiter::check_at`].
    fn record_at(&self, attempt: Attempt<'_>, outcome: AttemptOutcome, now: Instant) {
        // A success has already paid `ATTEMPT_COST` at check time and owes nothing more. Only
        // failures are charged again, because failures are what a guessing attack is made of.
        if outcome == AttemptOutcome::Succeeded {
            return;
        }
        let index = self.window_index(now);
        let mut state = self.lock();
        // The window may have rolled between the check and the report. Charging the penalty to the
        // NEW window is the safe direction: it can only make the limiter stricter, whereas skipping
        // it would let an attacker time their guesses to land the penalty in a window nobody reads.
        state.roll_to(index);
        match attempt {
            Attempt::DeviceUserCodeEntry => {
                let capacity = self.config.device_user_code_capacity;
                let cost = self.config.device_user_code_failure_cost;
                Self::penalise(&mut state.device_user_code, capacity, cost);
            }
            Attempt::ClientAuthentication { client_id } => {
                let capacity = self.config.client_authentication_capacity;
                let cost = self.config.client_authentication_failure_cost;
                let max_tracked = self.config.max_tracked_clients;
                let counter = state.client_counter(client_id, max_tracked);
                Self::penalise(counter, capacity, cost);
            }
        }
    }
}

impl Window {
    /// Start a fresh budget if `index` is not the window these counters belong to.
    ///
    /// Clearing the map here is the whole of the eviction policy (see [`FixedWindowRateLimiter`]):
    /// every counter in it was about to be reset to zero anyway, so dropping the keys costs no
    /// information and bounds every entry's lifetime at one window.
    fn roll_to(&mut self, index: u64) {
        if self.index == index {
            return;
        }
        self.index = index;
        self.device_user_code = 0;
        self.overflow = 0;
        // `clear` keeps the allocated capacity, which is already bounded by `max_tracked_clients`,
        // so the map never grows across windows and the common case does not re-allocate.
        self.clients.clear();
    }

    /// The counter this `client_id` is charged against: its own if it has one or can have one, and
    /// the shared overflow counter otherwise.
    fn client_counter(&mut self, client_id: &str, max_tracked: usize) -> &mut u64 {
        if client_id.len() > MAX_TRACKED_CLIENT_ID_LEN {
            return &mut self.overflow;
        }
        // Two hash lookups on the hit path rather than one. A single `match self.clients.get_mut()`
        // with an insert in the `None` arm does not compile under this crate's MSRV borrow checker
        // (the `&mut` from the failed lookup is held across the arm), and the alternative that does
        // compile, `entry(client_id.to_string())`, would allocate an owned key on EVERY call
        // including the overwhelming majority that hit an existing entry. Two lookups of a short
        // string is the cheaper of the two.
        if !self.clients.contains_key(client_id) {
            if self.clients.len() >= max_tracked {
                return &mut self.overflow;
            }
            // The only allocation on this path, and only for a `client_id` seen for the first time
            // this window. `Box<str>` rather than `String`: the key is never grown, so the spare
            // capacity word a `String` carries would be paid on every tracked client for nothing.
            self.clients.insert(Box::from(client_id), 0);
        }
        self.clients
            .get_mut(client_id)
            .expect("the entry was just confirmed or inserted")
    }
}

impl RateLimiter for FixedWindowRateLimiter {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        self.check_at(attempt, Instant::now())
    }

    fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
        self.record_at(attempt, outcome, Instant::now());
    }
}

#[cfg(test)]
#[path = "tests/rate_limit.rs"]
mod tests;
