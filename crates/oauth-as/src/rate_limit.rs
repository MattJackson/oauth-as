// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RED STEP STUB. The real counter lands in the next commit; this compiles the API the tests
//! address so the gate can be watched go RED for the reason that matters (nothing is counted),
//! rather than for a missing symbol.

use std::time::Duration;

use crate::events::{Attempt, AttemptOutcome, RateLimitDecision, RateLimiter};

/// Placeholder configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimitConfig {
    /// Counting window.
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            window: Duration::from_secs(60),
        }
    }
}

impl RateLimitConfig {
    /// Set the counting window.
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Placeholder.
    pub fn with_device_user_code_budget(self, _capacity: u64, _failure_cost: u64) -> Self {
        self
    }

    /// Placeholder.
    pub fn with_client_authentication_budget(self, _capacity: u64, _failure_cost: u64) -> Self {
        self
    }

    /// Placeholder.
    pub fn with_max_tracked_clients(self, _max: usize) -> Self {
        self
    }
}

/// Placeholder limiter that counts nothing.
#[derive(Debug, Default)]
pub struct FixedWindowRateLimiter {
    config: RateLimitConfig,
}

impl FixedWindowRateLimiter {
    /// A limiter with the default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// A limiter with the given configuration.
    pub fn with_config(config: RateLimitConfig) -> Self {
        FixedWindowRateLimiter { config }
    }

    /// The configuration in force.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Placeholder.
    pub fn tracked_clients(&self) -> usize {
        0
    }
}

impl RateLimiter for FixedWindowRateLimiter {
    fn check(&self, _attempt: Attempt<'_>) -> RateLimitDecision {
        RateLimitDecision::Allow
    }

    fn record(&self, _attempt: Attempt<'_>, _outcome: AttemptOutcome) {}
}
