// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A TIMING ORACLE PROBE for the two secret comparisons on the token plane.
//!
//! `tests/constant_time.rs` already proves that [`oauth_as::ClientAuth::verify`] AGREES WITH `==`
//! across lengths and contents. That is a functional property and it is necessary. It is not
//! sufficient: a comparison can return the right answer and still tell an attacker, through how
//! long it took, how many leading bytes of their guess were right. That turns guessing a 32-byte
//! secret from 256^32 work into 32 * 256 work, which is not a performance problem, it is the whole
//! secret.
//!
//! So this file measures what the functional test cannot see: does the time depend on WHERE the
//! first differing byte is?
//!
//! # What a PASS here does and does not mean
//!
//! A benchmark can DISPROVE constant time. It cannot prove it. If the "differs at byte 0" row and
//! the "differs at byte 31" row are measurably apart, there is an oracle and this file has found
//! it. If they are indistinguishable at this resolution, all that has been shown is that no oracle
//! is visible from user space, on this machine, at roughly nanosecond resolution, against a
//! deterministic scalar implementation. An attacker with a shared cache, hardware performance
//! counters, or millions of samples over a network has better resolution than this file does.
//!
//! The real assurance is STRUCTURAL and it lives in `src/client.rs`: the comparison SHA-256-hashes
//! both sides and then folds a fixed 32-byte XOR with no early exit, so the work is a function of
//! the input LENGTHS and nothing else. This file's job is to catch the day somebody replaces that
//! with `a == b` because it looked equivalent.
//!
//! # Why length is deliberately held constant within each group
//!
//! Hashing is linear in input length, so a longer guess genuinely costs more, and that is not a
//! leak: the attacker chose the length of their own guess and already knows it. What would be a
//! leak is the time depending on the CONTENT of the guess relative to the secret. Every row inside
//! a comparison group therefore presents exactly the same number of bytes, so content is the only
//! thing that varies.

#[path = "harness/mod.rs"]
mod harness;

use oauth_as::{ClientAuth, ScopeSet};

/// A realistic 32-character client secret.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// `SECRET` with the byte at `index` changed, same length.
fn differing_at(index: usize) -> String {
    let mut bytes = SECRET.as_bytes().to_vec();
    bytes[index] = if bytes[index] == b'z' { b'y' } else { b'z' };
    String::from_utf8(bytes).expect("ASCII in, ASCII out")
}

/// Report on one group of rows that MUST be indistinguishable from each other.
///
/// The threshold is derived from the harness's own measured spread rather than picked: the widest
/// median-absolute-deviation among the rows in the group, tripled, is the band inside which this
/// harness cannot tell two rows apart. A group whose medians all fall inside that band has told us
/// nothing (correctly). A group that escapes it has told us something, and the something is a
/// security finding.
fn verdict(b: &harness::Bench, group: &str, names: &[&str]) {
    let rows: Vec<&harness::Row> = names.iter().filter_map(|n| b.row(n)).collect();
    if rows.len() < 2 {
        return;
    }
    let medians: Vec<f64> = rows.iter().map(|r| r.median.as_secs_f64()).collect();
    let lo = medians.iter().cloned().fold(f64::INFINITY, f64::min);
    let hi = medians.iter().cloned().fold(0.0_f64, f64::max);
    let worst_spread = rows.iter().map(|r| r.spread_pct).fold(0.0_f64, f64::max);
    let observed_pct = if lo > 0.0 {
        (hi / lo - 1.0) * 100.0
    } else {
        0.0
    };
    let band_pct = worst_spread * 3.0;

    println!();
    println!("-- constant-time verdict: {group} --");
    for r in &rows {
        println!(
            "   {:<44} {:>10.2} ns  (spread {:.1}%)",
            r.name,
            r.median.as_secs_f64() * 1e9,
            r.spread_pct
        );
    }
    println!("   spread between fastest and slowest : {observed_pct:.2}%");
    println!("   this harness's own noise band (3x MAD): {band_pct:.2}%");
    if observed_pct > band_pct.max(2.0) {
        println!(
            "   VERDICT: DISTINGUISHABLE. Treat as a SECURITY finding, not a performance note: \
             the position of the first differing byte is observable in the response time."
        );
    } else {
        println!(
            "   VERDICT: not distinguishable at this resolution. This is not a proof of \
             constant time; see this file's module docs for what it is and is not."
        );
    }
}

fn main() {
    harness::print_environment();
    let mut b = harness::Bench::from_args("constant-time probes");

    // ------------------------------------------------------- RFC 6749 s2.3.1 client secret
    //
    // Driven through the PUBLIC `ClientAuth::verify`, not through a private helper, because the
    // public method is what the token endpoint calls and what a consumer can call, and an oracle
    // introduced anywhere between the two would be missed by probing the primitive directly.
    {
        let auth = ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        };
        let first = differing_at(0);
        let middle = differing_at(16);
        let last = differing_at(SECRET.len() - 1);

        // INTERLEAVED, not four rows measured one after another: see
        // `harness::Bench::bench_interleaved`. Measuring them in sequence made this probe report
        // "not distinguishable" and "DISTINGUISHABLE" on consecutive runs of the same binary,
        // because several seconds of CPU frequency drift landed on whichever variant was being
        // measured at the time. A probe that answers differently each run has not measured the
        // code, and a security verdict is the last place to accept that.
        let presented = [SECRET, first.as_str(), middle.as_str(), last.as_str()];
        b.bench_interleaved(
            &[
                "client_secret_correct",
                "client_secret_differs_at_byte_0",
                "client_secret_differs_at_byte_16",
                "client_secret_differs_at_byte_31",
            ],
            |i| auth.verify(Some(presented[i])),
        );
    }

    // --------------------------------------------------------------- RFC 7636 code verifier
    //
    // `verify_s256` recomputes the challenge from the presented verifier and compares against the
    // stored one, so the same question applies: can an attacker tell how much of their guessed
    // VERIFIER was right? Note that this comparison is against the CHALLENGE, which is a public
    // value derived by SHA-256, so even a leaky compare here would leak far less than a leaky
    // client secret compare. It is probed anyway, because "less bad" is not an argument for not
    // measuring it.
    {
        let challenge =
            oauth_as::pkce::code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        // All three presented verifiers are the same length as the real one, so only content
        // varies. The "near" one shares its first 42 characters with the real verifier.
        let real = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let near = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXA";
        let far = "ZBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let presented = [real, near, far];
        b.bench_interleaved(
            &[
                "pkce_verifier_correct",
                "pkce_verifier_differs_in_last_char",
                "pkce_verifier_differs_in_first_char",
            ],
            |i| oauth_as::pkce::verify_s256(presented[i], &challenge),
        );
    }

    // ------------------------------------------------------------------------ a control row
    //
    // Something whose cost genuinely DOES depend on its input, measured with the same harness on
    // the same run, so that a reader can see this file is capable of reporting a difference at all.
    // Without it, "no difference detected" is indistinguishable from "the probe does not work".
    {
        let inputs = [
            "read",
            "read write admin openid profile email offline_access",
        ];
        b.bench_interleaved(
            &[
                "control_scope_parse_1_token",
                "control_scope_parse_7_tokens",
            ],
            |i| ScopeSet::parse(inputs[i]),
        );
    }

    b.finish();

    verdict(
        &b,
        "RFC 6749 s2.3.1 client secret (all guesses 32 bytes)",
        &[
            "client_secret_correct",
            "client_secret_differs_at_byte_0",
            "client_secret_differs_at_byte_16",
            "client_secret_differs_at_byte_31",
        ],
    );
    verdict(
        &b,
        "RFC 7636 code verifier (all guesses 43 bytes)",
        &[
            "pkce_verifier_correct",
            "pkce_verifier_differs_in_last_char",
            "pkce_verifier_differs_in_first_char",
        ],
    );
    verdict(
        &b,
        "CONTROL: a comparison that SHOULD differ (this probe must be able to say so)",
        &[
            "control_scope_parse_1_token",
            "control_scope_parse_7_tokens",
        ],
    );
}
