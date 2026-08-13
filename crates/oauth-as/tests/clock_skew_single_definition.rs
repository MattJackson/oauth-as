// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `CLOCK_SKEW_LEEWAY` is ONE constant, defined once.
//!
//! It is public from two modules, `client-assertion` (RFC 7523 `iat`/`nbf`) and `dpop`
//! (RFC 9449 `iat`), because the same allowance answers the same question for both: how far a
//! client's clock may be AHEAD of this server's before a credential minted in the near future is
//! refused. Through 0.9.0 each module declared its own `pub const ... = Duration::from_secs(60)`,
//! and `dpop`'s doc comment pointed at `client-assertion`'s "for the same reason", which is a
//! comment admitting that two numbers have to be kept equal by hand. This file makes the source
//! answer for it: there is exactly one DEFINITION in the crate, and the other module re-exports it.
//!
//! A text scan rather than a `syn` parse, in the same idiom (and for the same dependency-policy
//! reason) as `tests/allocation.rs`'s scan for module-level statics.

/// The values agree. This is the property a host cares about, and it is the one that held even
/// while there were two definitions, which is exactly why it is not sufficient on its own.
#[cfg(all(feature = "client-assertion", feature = "dpop"))]
#[test]
fn both_modules_publish_the_same_leeway() {
    use std::time::Duration;

    assert_eq!(
        oauth_as::client_assertion::CLOCK_SKEW_LEEWAY,
        oauth_as::dpop::CLOCK_SKEW_LEEWAY
    );
    assert_eq!(
        oauth_as::dpop::CLOCK_SKEW_LEEWAY,
        Duration::from_secs(60),
        "RFC 9449 s4.3 and RFC 7523 s3 both leave the window to the server; this crate's answer \
         is one minute of leeway, in the EARLY direction only"
    );
}

/// And they agree because there is one of them. Two constants that must stay equal drift the day
/// somebody changes one; the only structural defence is that there is nothing to keep in step.
#[test]
fn the_crate_defines_the_leeway_exactly_once() {
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut definitions: Vec<String> = Vec::new();
    let mut walk = vec![std::path::PathBuf::from(src_dir)];
    while let Some(dir) = walk.pop() {
        for entry in std::fs::read_dir(&dir).expect("the crate's src/ must be readable") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                walk.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a readable source file");
            for line in text.lines() {
                let trimmed = line.trim_start();
                // A DEFINITION, not a use and not a re-export: `const CLOCK_SKEW_LEEWAY:` after an
                // optional visibility. `pub use ...::CLOCK_SKEW_LEEWAY;` does not match.
                let trimmed = trimmed
                    .strip_prefix("pub ")
                    .unwrap_or(trimmed)
                    .trim_start_matches("(crate) ");
                if trimmed.starts_with("const CLOCK_SKEW_LEEWAY:") {
                    definitions.push(format!("{}: {}", path.display(), line.trim()));
                }
            }
        }
    }
    assert_eq!(
        definitions.len(),
        1,
        "CLOCK_SKEW_LEEWAY must be defined exactly once and re-exported where it is also \
         published; found {} definitions:\n{}",
        definitions.len(),
        definitions.join("\n")
    );
}
