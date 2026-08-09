// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The clock-skew allowance, defined once.
//!
//! Two credentials this crate verifies carry a "not before this instant" claim minted by the
//! CLIENT: an RFC 7523 client assertion (`iat`, `nbf`) and an RFC 9449 DPoP proof (`iat`). Both
//! ask the same question of the same wall clock, so both get the same answer, and through 0.9.0
//! both had their own `pub const CLOCK_SKEW_LEEWAY = Duration::from_secs(60)` with a comment on
//! one pointing at the other. Two numbers that must stay equal, and a comment saying so, is a
//! drift waiting for whoever changes one of them.
//!
//! It cannot live in either module, because `client_assertion` and `dpop` are INDEPENDENT
//! features and a build may have either alone. It lives here, private, and each of them
//! re-exports it, so `oauth_as::client_assertion::CLOCK_SKEW_LEEWAY` and
//! `oauth_as::dpop::CLOCK_SKEW_LEEWAY` both still resolve: unifying the definition is not a
//! breaking change to either path.

use std::time::Duration;

/// How far a client's clock may be AHEAD of this server's before a claim about the present is
/// refused.
///
/// ONE MINUTE, and granted in that direction ONLY. Leeway that accepts a credential minted
/// slightly in the future can only ever admit a request that was going to be fine a second later;
/// leeway on `exp` would keep a DEAD credential alive, which is why neither verifier grants any
/// there. Neither RFC fixes a number: RFC 7523 section 3 and RFC 9449 section 4.3 both leave the
/// acceptance window to the server, and one minute is the usual answer for hosts whose clocks are
/// NTP-disciplined, which is every host that can serve TLS at all.
// `pub` in a PRIVATE module, so the only ways to name it are the two re-exports: `pub use` cannot
// re-export a `pub(crate)` item, and the alternative (making each module's re-export
// `pub(crate)`) would break the two public paths this unification exists not to break.
pub const CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(60);
