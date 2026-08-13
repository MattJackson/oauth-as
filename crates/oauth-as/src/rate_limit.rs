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
//!   [`crate::events::EventSink`] channel is for. ACROSS windows that is unconditional. WITHIN a
//!   window it is a PRICE rather than a guarantee, and the failure reserve below is what sets the
//!   price: a trickle of wrong secrets can no longer empty a client's budget, so denying one
//!   `client_id` for the rest of a window costs 3000 requests a minute at the defaults instead of
//!   30. A hundred times dearer, and still not impossible. See "Why failures cannot spend a
//!   client's whole budget" for the derivation.
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
//! Both numbers are counted in CODE ENTRIES, which is what an [`Attempt::DeviceUserCodeEntry`] is,
//! and one activation is not always one code entry. The `http` feature's verification page is a
//! two-stage form (RFC 8628 section 3.3 requires an explicit confirmation step, so the user types
//! the code, sees what it is for, and then decides), and each stage resolves the code against the
//! store: that is two lookups, both of which answer "is this a live code" and both of which must
//! therefore be charged, or an attacker would simply walk the code space using the cheaper stage. A
//! deployment serving that page should read the ceiling as roughly 100 ACTIVATIONS a minute rather
//! than 200, and one that also publishes the RFC 8628 section 3.3.1
//! `verification_uri_complete` deep link should read it as roughly 66, because the deep link
//! resolves the code a third time to render the page it lands on. Raise
//! `device_user_code_capacity` accordingly.
//!
//! The rule that keeps the wrong-code arithmetic above intact is the other half of the same
//! statement: ONE code entry is charged ONCE, however many times a handler happens to resolve it.
//! A submission whose code did not match re-renders the form so the user can correct it, and that
//! re-render must not resolve the code again — the attempt it would be charging for is the one
//! already counted a few lines earlier in the same request. A page that charges it twice halves
//! every number in this section without changing a constant, which is the sort of drift only
//! arithmetic stated out loud catches.
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
//! - THE FIRST 15 FAILED authentications per minute per client cost 200 each (`1 + 199`), which
//!   spends half the budget: that is the RFC 9700 section 4.13 credential-stuffing weighting, and
//!   the point at which it stops is the failure reserve described in the next section. The penalty
//!   accumulates in 199-unit steps and CLAMPS at the 3000-unit reserve, so 15 failures leave the
//!   counter at 2985 and the SIXTEENTH pays only the 15 units still under the clamp — 16 units in
//!   all, with its attempt unit, rather than 200 and rather than 1. The seventeenth failure and
//!   every one after it costs [`ATTEMPT_COST`] and nothing more, so failures past that point are
//!   bounded by the traffic ceiling and by nothing else.
//!
//! The weighting is chosen against what a client secret actually is: a machine-held value this
//! crate mints or the host provisions, not a human-chosen password. A correctly configured client
//! fails authentication ZERO times, so any sustained failure rate for one `client_id` is either a
//! misconfiguration the operator wants to hear about or an attack, and both are better served by
//! refusing than by continuing. The budget is per client id rather than global specifically so one
//! client being stuffed cannot lock every other client out of the token endpoint.
//!
//! ## Why failures cannot spend a client's whole budget
//!
//! [`RateLimiter::check`] is asked BEFORE the credential is examined, and the only thing it is
//! given is the `client_id` (see [`Attempt::ClientAuthentication`]). RFC 6749 section 2.2 makes
//! that identifier public, so the impostor and the real client arrive at this limiter looking
//! IDENTICAL: same key, nothing else to tell them apart. Any refusal rule that is a function of the
//! `client_id` alone therefore refuses BOTH of them or NEITHER. That is not a defect of this
//! implementation, it is what the seam can see, and it has one consequence that has to be designed
//! around rather than documented away: if failures could drive a `client_id`'s counter all the way
//! to its capacity, an attacker who sent 30 wrong secrets a minute — one request every two seconds,
//! from anywhere, needing nothing but a public identifier — would take that client's every
//! authenticated endpoint away for the rest of the window. Token, introspection, revocation, device
//! authorization and PAR all go through the same check. The "IT IS NOT A LOCKOUT" bullet above
//! would have been false, and it would have been false at a cost to the attacker of nothing.
//!
//! So HALF OF EVERY CLIENT'S BUDGET IS RESERVED FOR ATTEMPTS AND CANNOT BE SPENT BY FAILURES
//! ([`CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR`]). The failure penalty accumulates in a
//! counter of its own that saturates at half the capacity; past that line a failure still costs its
//! [`ATTEMPT_COST`], but it can no longer eat into what the real client needs.
//!
//! What that buys is a PRICE and not an immunity, and it is written out as one because the
//! difference is the whole value of the paragraph. The attempt half is charged for EVERY request,
//! the attacker's included, so at the defaults:
//!
//! - The CHEAPEST complete spray is 16 wrong secrets: 199 units a failure against a 3000-unit
//!   ceiling, so 15 reach 2985 and the sixteenth clamps it. That leaves the real client
//!   `3000 - 16 = 2984` further authentications in the window, about 49 a second on one node.
//! - Denying that `client_id` outright means spending the whole reserved half at [`ATTEMPT_COST`]
//!   apiece: 3000 requests inside one 60 second window, 50 a second, sustained. They do NOT have to
//!   be well-formed traffic — 3000 wrong secrets do it just as well, because past the ceiling a
//!   wrong secret and an ordinary request cost exactly the same one unit.
//!
//! 3000 requests a minute is a hundred times the 30 the same denial cost with no reserve, and it is
//! a rate an operator's own edge already meters: the reserve converts a trickle into a flood. It
//! does not make the denial impossible, and nothing this seam can see would, because
//! [`RateLimiter::check`] cannot tell the impostor from the client being impersonated.
//!
//! What that costs, stated plainly because a security default should be stated at its worst: the
//! hard bound on WRONG SECRETS per client per minute is no longer 30, it is the traffic ceiling
//! less the reserve, exactly 3000 — which is the same 3000 as the denial above, because at this
//! point a wrong secret and a denial-of-service request are the same request. That trade is worth taking here and it would NOT be worth taking
//! for the device user code, and the difference between the two is the entropy of what is being
//! guessed. A user code is 2^34.6 and RFC 8628 section 5.1 says so: 3000 guesses a minute against
//! it is a real attack, which is why the device budget has no reserve and its global denial-of-
//! service is accepted and documented above instead. A client secret is a machine-held value this
//! crate mints as 32 hex characters; 30 guesses a minute and 3000 guesses a minute against it are
//! the same number, which is zero. Trading a guessing bound that was never the defence for an
//! availability property that an attacker could otherwise break for free is the right way round.
//!
//! THE SAME DIVISOR GOVERNS THE AUTHORIZATION-REQUEST BUDGET. This section is written in terms of
//! client authentication only because that is where the argument is sharpest, not because the
//! reserve is a client-authentication property: [`RateLimitConfig`] derives both ceilings from
//! [`CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR`] and `record` clamps both. The reasoning
//! transfers unchanged and arrives somewhere slightly worse.
//! [`Attempt::AuthorizationRequest`] is keyed on nothing but a `client_id` too, and its caller has
//! not authenticated AT ALL — the identifier is whatever arrived in the query string — so a refusal
//! rule that is a function of that identifier alone would let anybody take a client's LOGIN PAGE
//! away. Its numbers, derived the same way from
//! [`DEFAULT_AUTHORIZATION_REQUEST_CAPACITY`]: a 1500-unit reserve, 9 units a refusal so 167
//! refusals fill it (166 reach 1494 and the 167th clamps), and 1500 refused requests a minute for
//! one `client_id` before that client's authorization endpoint closes for the rest of the window.
//!
//! The reserve is not configurable, for the same reason [`MAX_TRACKED_CLIENT_ID_LEN`] is not: it is
//! not a policy, it is the property that makes the type safe to install. A host that wants failures
//! to bite sooner lowers `client_authentication_capacity`, which moves the reserve with it.
//!
//! ## Tracked clients: 4096 ([`DEFAULT_MAX_TRACKED_CLIENTS`])
//!
//! See [`FixedWindowRateLimiter`] for the bounding argument. 4096 is chosen to comfortably exceed
//! the number of registrations a single deployment realistically authenticates within one 60 second
//! window while keeping the worst-case footprint under two megabytes. It caps EACH of the two
//! per-`client_id` maps rather than the pair, so the worst case is about 768 KiB apiece and about
//! 1.5 MiB in all; [`FixedWindowRateLimiter::tracked_clients`] and
//! [`FixedWindowRateLimiter::tracked_authorization_clients`] report them separately.

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

/// 6000 cost units per window per `client_id`: 6000 authentications a minute, of which the first 15
/// failures cost 200 each. See the module docs for the RFC 9700 section 4.13 reasoning.
pub const DEFAULT_CLIENT_AUTHENTICATION_CAPACITY: u64 = 6000;

/// The EXTRA cost of a failed client authentication, on top of [`ATTEMPT_COST`], so a wrong
/// credential costs two hundred times a right one until the failure ceiling is reached.
pub const DEFAULT_CLIENT_AUTHENTICATION_FAILURE_COST: u64 = 199;

/// How much of a `client_id`'s budget FAILURES may consume, as a divisor of the capacity: `2` means
/// half of it, and half reserved for attempts.
///
/// Not configurable, because it is not a policy: it is what keeps "IT IS NOT A LOCKOUT" true. See
/// "Why failures cannot spend a client's whole budget" in the module docs for the argument, which
/// turns on [`RateLimiter::check`] having nothing but a public `client_id` to tell the real client
/// and the impostor apart.
pub const CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR: u64 = 2;

/// 3000 cost units per window per `client_id` for [`Attempt::AuthorizationRequest`]: 3000 trips
/// through the authorization endpoint a minute for one client, or 1500 refused ones.
///
/// The two numbers are not `3000` and `3000 / 10`. Half of this budget is reserved for attempts on
/// exactly the terms client authentication's is (see "Why failures cannot spend a client's whole
/// budget" in the module docs), so a refusal costs 10 units only until the 1500-unit reserve is
/// full — 167 of them — and 1 unit each after that. The endpoint therefore admits 1500 refused
/// requests for one `client_id` in a window, not the 300 the weighting alone would give.
///
/// Every one of these is a USER's browser arriving at a login page, and a busy client's traffic is
/// genuinely bursty (a mobile app updating, a working day starting), so the ceiling has to sit well
/// above real volume; it sits below the client-authentication ceiling because one login produces
/// one arrival here and a stream of token, introspection and revocation calls there. Refusals are
/// the opposite: a correctly configured client's authorization requests are refused essentially
/// never, because its `client_id` and `redirect_uri` are constants baked into its own build. A
/// sustained refusal rate for one client is somebody walking the redirect-URI space looking for a
/// matcher bug, which is what `Event::AuthorizationRequestRefused` exists to make visible and what
/// this budget exists to slow — to 1500 a window rather than to nothing, which is the price of not
/// letting that same somebody take the login page down by walking it. A deployment
/// that would rather have the tighter refusal bound lowers `authorization_request_capacity`, which
/// moves the reserve with it.
pub const DEFAULT_AUTHORIZATION_REQUEST_CAPACITY: u64 = 3000;

/// The EXTRA cost of a refused authorization request, on top of [`ATTEMPT_COST`], so a refusal
/// costs ten times an ordinary arrival.
pub const DEFAULT_AUTHORIZATION_REQUEST_FAILURE_COST: u64 = 9;

/// 60 cost units per window for [`Attempt::ClientRegistration`], globally: 60 dynamic
/// registrations a minute, or 6 refused ones.
///
/// The tightest budget here, and the reason is that an RFC 7591 registration is the only request in
/// this crate that creates a PERMANENT row. A [`crate::client::Client`] has no expiry and no sweep
/// reclaims it, so an unthrottled registration endpoint is not a burst a window absorbs, it is
/// unbounded growth in the host's storage. Sixty a minute is far above what a real deployment
/// onboards and far below what a script achieves.
///
/// GLOBAL rather than per-anything, because a registration request names no client: the client is
/// what it is asking to create. A host that can identify the caller — an admin session, an API key,
/// a source address — should throttle on that in front of this, which is what the module docs say
/// about every budget here.
pub const DEFAULT_CLIENT_REGISTRATION_CAPACITY: u64 = 60;

/// The EXTRA cost of a refused registration, on top of [`ATTEMPT_COST`], so a refusal costs ten
/// times an accepted one. A refusal here is a `RegistrationPolicy` saying no, which is the signal
/// that somebody is probing what the policy will accept.
pub const DEFAULT_CLIENT_REGISTRATION_FAILURE_COST: u64 = 9;

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
    /// Cost units per window for [`Attempt::AuthorizationRequest`], per `client_id`.
    pub authorization_request_capacity: u64,
    /// Extra cost charged when an authorization request is REFUSED.
    pub authorization_request_failure_cost: u64,
    /// Cost units per window for [`Attempt::ClientRegistration`], globally.
    pub client_registration_capacity: u64,
    /// Extra cost charged when a dynamic registration is REFUSED.
    pub client_registration_failure_cost: u64,
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
            authorization_request_capacity: DEFAULT_AUTHORIZATION_REQUEST_CAPACITY,
            authorization_request_failure_cost: DEFAULT_AUTHORIZATION_REQUEST_FAILURE_COST,
            client_registration_capacity: DEFAULT_CLIENT_REGISTRATION_CAPACITY,
            client_registration_failure_cost: DEFAULT_CLIENT_REGISTRATION_FAILURE_COST,
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

    /// The most of one `client_id`'s budget that the failure penalty may ever occupy.
    ///
    /// Derived from the capacity at every use rather than stored, exactly as
    /// [`RateLimitConfig::effective_window`] re-clamps: `client_authentication_capacity` is a
    /// public field, so a host that lowers it without going through the builder must still get a
    /// reserve that moved with it rather than one frozen at construction.
    fn client_authentication_failure_ceiling(&self) -> u64 {
        self.client_authentication_capacity / CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR
    }

    /// The authorization-endpoint failure reserve, on the same terms and re-derived at every use so
    /// that a host lowering the capacity by assigning the public field still gets a reserve that
    /// moved with it.
    fn authorization_request_failure_ceiling(&self) -> u64 {
        self.authorization_request_capacity / CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR
    }
}

/// One `client_id`'s two counters for one window, kept apart so that the failure penalty can be
/// bounded independently of the attempts.
///
/// Two counters rather than one sum is the whole of the fix for the lockout described in the module
/// docs: a single counter cannot express "failures have spent as much as they are allowed to spend
/// and attempts have not", because by the time the two are added together the information that
/// distinguishes them is gone.
#[derive(Debug, Default)]
struct ClientBudget {
    /// Cost charged at [`RateLimiter::check`] time: [`ATTEMPT_COST`] per ALLOWED attempt.
    attempts: u64,
    /// Cost charged at [`RateLimiter::record`] time for FAILURES, saturating at the failure ceiling
    /// of whichever budget this is — [`RateLimitConfig::client_authentication_failure_ceiling`] or
    /// [`RateLimitConfig::authorization_request_failure_ceiling`] — so that it can never reach the
    /// capacity on its own.
    failures: u64,
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
    clients: HashMap<Box<str>, ClientBudget>,
    /// The shared counters for every `client_id` that did not get its own. See
    /// [`FixedWindowRateLimiter`].
    ///
    /// It carries the same two-counter split, and for the same reason: an attacker who has filled
    /// the map can also spray FAILURES at it, and if those failures could reach the shared capacity
    /// then every untracked client — including a legitimate one whose first authentication of the
    /// window arrives late — would be refused for the rest of the window on the strength of about
    /// thirty requests. The reserve does not make that refusal impossible, it makes it cost the
    /// whole reserved half in requests — 3000 in a window at the defaults, against 30 without it.
    overflow: ClientBudget,
    /// Cost spent on [`Attempt::AuthorizationRequest`], per `client_id`, in the same bounded map
    /// as client authentication and with the same two-counter split.
    ///
    /// A separate map rather than a second field on `ClientBudget`, because the two budgets are
    /// about different things: one client hammering `/authorize` must not spend the budget its own
    /// token requests need, and a client that cannot authenticate must still be able to be
    /// throttled at the endpoint that writes records.
    authorization: HashMap<Box<str>, ClientBudget>,
    /// The shared authorization-endpoint counter for identifiers that did not get their own.
    authorization_overflow: ClientBudget,
    /// Cost spent on [`Attempt::ClientRegistration`], which needs no map: a registration request
    /// names no client, because the client does not exist yet.
    registration: u64,
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
/// service, so the maps are bounded three ways at once and every bound is a hard one.
///
/// THERE ARE TWO MAPS, which is the first thing to hold on to, because every figure below is a
/// figure per map: one keyed on `client_id` for [`Attempt::ClientAuthentication`] and one for
/// [`Attempt::AuthorizationRequest`], kept apart so that neither endpoint can spend the other's
/// budget (see `Window::authorization_counter`). Each is capped INDEPENDENTLY, so every bound
/// below is doubled in total. The authorization map is the one an attacker reaches first, because
/// its caller has not authenticated: the identifier it is keyed on is whatever arrived in the
/// query string.
///
/// 1. AT MOST `max_tracked_clients` ENTRIES PER MAP, so at most `2 * max_tracked_clients` entries
///    in all — 8192 at the defaults. When a map is full, an identifier that is not already in it is
///    charged against that map's single shared OVERFLOW counter instead of getting an entry of its
///    own. Nothing is allocated for it.
/// 2. AT MOST [`MAX_TRACKED_CLIENT_ID_LEN`] BYTES OF KEY. A longer identifier goes straight to the
///    overflow counter, so the worst case is bounded in bytes and not only in entries. Per map:
///    4096 keys of 128 bytes on the heap is 512 KiB, and the table holding them is 8192 slots (a
///    `HashMap` keeps its load under 7/8, so 4096 entries take the next power of two up) of 32
///    bytes each — a 16-byte `Box<str>` handle and a `ClientBudget`'s two `u64`s — which is
///    256 KiB. About 768 KiB a map, so about 1.5 MiB for both at the defaults.
/// 3. AT MOST ONE WINDOW OF LIFETIME. BOTH maps are cleared when the window rolls, which costs
///    nothing semantically because every counter in them was about to be reset anyway. No entry
///    survives a window, so there is no eviction policy to get wrong and no slow leak of keys that
///    were seen once.
///
/// [`FixedWindowRateLimiter::tracked_clients`] and
/// [`FixedWindowRateLimiter::tracked_authorization_clients`] report the two maps separately, so a
/// host — and this crate's own gates — can SEE both bounds rather than watch one and infer the
/// other.
///
/// Each overflow counter FAILS CLOSED, which is the important half: a spray of a million distinct
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

    /// How many `client_id` values currently hold a CLIENT-AUTHENTICATION counter of their own.
    ///
    /// Exposed so a host (and this crate's own gate on the bound) can SEE that the map is bounded
    /// rather than trust that it is. Never exceeds `max_tracked_clients`.
    ///
    /// This is ONE of the two bounded maps, and it is not the one an attacker reaches first: see
    /// [`FixedWindowRateLimiter::tracked_authorization_clients`], which a gate watching only this
    /// number is blind to.
    pub fn tracked_clients(&self) -> usize {
        self.lock().clients.len()
    }

    /// How many `client_id` values currently hold an AUTHORIZATION-REQUEST counter of their own.
    ///
    /// The sibling of [`FixedWindowRateLimiter::tracked_clients`], and the one to watch if only one
    /// is watched: this map is filled by callers who have not authenticated at all, because the
    /// identifier an `/authorize` request is keyed on is whatever arrived in the query string,
    /// whereas the client-authentication map is filled by callers who at least presented a
    /// credential. It is capped by the same `max_tracked_clients` and never exceeds it.
    pub fn tracked_authorization_clients(&self) -> usize {
        self.lock().authorization.len()
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
        // added a VARIANT and did not give it a budget" into a compile error rather than into a
        // silently unbudgeted one.
        //
        // Note what that does NOT cover, because the difference has been read the wrong way round
        // before: it says nothing about an ENDPOINT that is unthrottled. An endpoint with no
        // `Attempt` variant of its own never reaches this match at all, so no exhaustiveness check
        // here can notice it. Only a variant that exists is protected by this, and adding the
        // variant is the step a compiler cannot prompt anyone to take.
        //
        // WHAT IS UNTHROTTLED TODAY, since this comment is the only place the crate enumerates it:
        // RFC 7592 registration MANAGEMENT. `read_registration`, `update_registration` and
        // `delete_registration` take no `Attempt` at all, so the only thing standing in front of
        // them is the registration access token the caller was handed at registration time. The
        // authorization endpoint and RFC 7591 registration were named here until 0.9.1 and are NOT
        // in that position any more: they have `Attempt::AuthorizationRequest` and
        // `Attempt::ClientRegistration` below, called from `server.rs` and `registration.rs`
        // respectively. A comment naming the wrong endpoints is worse than none, because this is
        // where a reader comes to find out which ones are exposed.
        match attempt {
            Attempt::DeviceUserCodeEntry => {
                let capacity = self.config.device_user_code_capacity;
                Self::charge(&mut state.device_user_code, capacity, ATTEMPT_COST)
            }
            Attempt::ClientAuthentication { client_id } => {
                let capacity = self.config.client_authentication_capacity;
                let max_tracked = self.config.max_tracked_clients;
                let budget = state.client_counter(client_id, max_tracked);
                // The attempt is charged against what the FAILURE counter has not already taken,
                // which is how the two budgets share one capacity without either being able to
                // exhaust the other's half. See the module docs.
                let headroom = capacity.saturating_sub(budget.failures);
                Self::charge(&mut budget.attempts, headroom, ATTEMPT_COST)
            }
            Attempt::AuthorizationRequest { client_id } => {
                let capacity = self.config.authorization_request_capacity;
                let max_tracked = self.config.max_tracked_clients;
                let budget = state.authorization_counter(client_id, max_tracked);
                let headroom = capacity.saturating_sub(budget.failures);
                Self::charge(&mut budget.attempts, headroom, ATTEMPT_COST)
            }
            Attempt::ClientRegistration => {
                let capacity = self.config.client_registration_capacity;
                Self::charge(&mut state.registration, capacity, ATTEMPT_COST)
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
                // Clamped at the FAILURE CEILING and not at the capacity, which is the whole of the
                // lockout fix: past the ceiling a failure has already cost its `ATTEMPT_COST` at
                // check time and costs nothing further, so no number of failures can take the
                // reserved half of this client's budget away from the client itself.
                let ceiling = self.config.client_authentication_failure_ceiling();
                let cost = self.config.client_authentication_failure_cost;
                let max_tracked = self.config.max_tracked_clients;
                let budget = state.client_counter(client_id, max_tracked);
                Self::penalise(&mut budget.failures, ceiling, cost);
            }
            Attempt::AuthorizationRequest { client_id } => {
                // Same split, same reasoning as client authentication: a refused authorization
                // request is what walking the `client_id`/`redirect_uri` space looks like, so it
                // costs more than an honest one — but it may not spend the half of the budget the
                // honest client's own users need, or an attacker would take a client's login page
                // off the air by guessing at it.
                let ceiling = self.config.authorization_request_failure_ceiling();
                let cost = self.config.authorization_request_failure_cost;
                let max_tracked = self.config.max_tracked_clients;
                let budget = state.authorization_counter(client_id, max_tracked);
                Self::penalise(&mut budget.failures, ceiling, cost);
            }
            Attempt::ClientRegistration => {
                // No reserve here, and deliberately: there is no client to protect from anyone
                // else's failures, because a registration request names no client. The budget is
                // global for the same reason the device one is, and an operator who needs a higher
                // ceiling has a `RegistrationPolicy` that should be doing the deciding.
                let capacity = self.config.client_registration_capacity;
                let cost = self.config.client_registration_failure_cost;
                Self::penalise(&mut state.registration, capacity, cost);
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
        self.registration = 0;
        self.authorization_overflow = ClientBudget::default();
        self.authorization.clear();
        self.overflow = ClientBudget::default();
        // `clear` keeps the allocated capacity, which is already bounded by `max_tracked_clients`,
        // so the map never grows across windows and the common case does not re-allocate.
        self.clients.clear();
    }

    /// The authorization-endpoint budget this `client_id` is charged against, on exactly the terms
    /// [`Window::client_counter`] describes: its own if it has one or can have one, and the shared
    /// overflow budget otherwise.
    ///
    /// A SECOND map rather than a third counter on `ClientBudget`, because the two budgets protect
    /// different things and must not be able to spend each other: a client being hammered at
    /// `/authorize` must still be able to redeem the codes it already issued, and a client that
    /// cannot authenticate must still be throttled at the endpoint that writes records. The memory
    /// bound is unchanged in kind and doubled in size, which is stated on
    /// [`FixedWindowRateLimiter`] rather than left for a reader to work out.
    fn authorization_counter(&mut self, client_id: &str, max_tracked: usize) -> &mut ClientBudget {
        if client_id.len() > MAX_TRACKED_CLIENT_ID_LEN {
            return &mut self.authorization_overflow;
        }
        if !self.authorization.contains_key(client_id) {
            if self.authorization.len() >= max_tracked {
                return &mut self.authorization_overflow;
            }
            self.authorization
                .insert(Box::from(client_id), ClientBudget::default());
        }
        self.authorization
            .get_mut(client_id)
            .expect("the entry was just confirmed or inserted")
    }

    /// The budget this `client_id` is charged against: its own if it has one or can have one, and
    /// the shared overflow budget otherwise.
    fn client_counter(&mut self, client_id: &str, max_tracked: usize) -> &mut ClientBudget {
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
            self.clients
                .insert(Box::from(client_id), ClientBudget::default());
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
