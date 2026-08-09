// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The shape a HOST codes against, as gates rather than as habits.
//!
//! Five properties, each of which was inconsistent across the crate rather than absent from it,
//! which is the worse failure: a host that learns the rule from one type is entitled to expect it
//! from the next one.
//!
//! - [`error_code_is_non_exhaustive`]: a public enum that GAINS variants with a cargo feature must
//!   not break a host's exhaustive `match` when a feature flag moves.
//! - [`error_code_http_status_chooses_a_status_for_every_variant`]: a new variant must force its
//!   author to choose a status rather than inheriting 400 from a catch-all.
//! - [`registration_error_response_is_a_std_error`]: a public type with a `Display` that describes
//!   a failure is an error, and a host's `?` and `Box<dyn Error>` should say so.
//! - [`must_use_on_consuming_builders_is_all_or_nothing`]: one `#[must_use]` out of twenty-nine
//!   builders is a rule nobody is following.
//! - [`every_public_request_cap_is_reexported_at_the_crate_root`]: a host sizing its own gateway
//!   limits needs all of them, from one place.
//!
//! Three of the five are SOURCE scans, in the same idiom (and for the same dependency-policy
//! reason) as `tests/allocation.rs`'s scan for module-level statics: `#[non_exhaustive]` and
//! `#[must_use]` are invisible from inside the crate that declares them, so no runtime assertion
//! can see either.

/// `ErrorCode` is the most widely matched enum this crate publishes, and its VARIANT SET depends on
/// cargo features: `rar`, `consent`, `dpop`, `par` and `jar` each add one. Without
/// `#[non_exhaustive]` a host that matches it exhaustively breaks when somebody in its dependency
/// graph turns a feature on, which is a build failure with no release behind it. Every sibling
/// failure enum in this crate is already marked; this one was missed.
#[test]
fn error_code_is_non_exhaustive() {
    let source = include_str!("../src/error.rs");
    let at = source
        .find("pub enum ErrorCode")
        .expect("the enum has to still be there");
    let preamble = &source[at.saturating_sub(400)..at];
    assert!(
        preamble.contains("#[non_exhaustive]"),
        "ErrorCode gains variants with a cargo feature, so a host's exhaustive match must not \
         break on a feature flag"
    );
}

/// `ErrorCode::as_str` lists every variant explicitly, so a new one does not compile until its
/// wire spelling is written down. `http_status` ended in `_ => 400`, so a new one compiled
/// immediately and silently took 400. The two answers are the same kind of decision about the same
/// enum, and only one of them was being asked.
#[test]
fn error_code_http_status_chooses_a_status_for_every_variant() {
    let source = include_str!("../src/error.rs");
    let at = source
        .find("pub fn http_status(self) -> u16 {")
        .expect("the method has to still be there");
    let body = &source[at..];
    let end = body.find("\n    }").expect("the method has to end");
    assert!(
        !body[..end].contains("_ =>"),
        "http_status must match every variant explicitly, so that adding one forces the author \
         to choose its status rather than inheriting 400"
    );
}

/// [`oauth_as::RegistrationErrorResponse`] is what an RFC 7591 refusal hands a host, and its direct
/// sibling [`oauth_as::ErrorResponse`] is both `Display` and `std::error::Error`. A host that
/// propagates one with `?` into a `Box<dyn Error>` should not have to care which of the two it is
/// holding.
#[test]
fn registration_error_response_is_a_std_error() {
    fn as_boxed_error<E: std::error::Error + Send + Sync + 'static>(
        e: E,
    ) -> Box<dyn std::error::Error> {
        Box::new(e)
    }

    let refusal = oauth_as::RegistrationErrorResponse::new(
        oauth_as::RegistrationErrorCode::InvalidRedirectUri,
        "redirect_uri must be an absolute URI",
    );
    let text = refusal.to_string();
    let boxed = as_boxed_error(refusal);
    assert_eq!(boxed.to_string(), text);
}

/// `#[must_use]` on the crate's consuming builders is ALL or NOTHING, and today it is nothing.
///
/// Through 0.9.0 it was neither: exactly one of twenty-nine `fn with_...(mut self) -> Self`
/// builders carried it, which is the worst of the three states because it teaches a reader a rule
/// the other twenty-eight do not follow, and it makes the next reviewer's question "why not here"
/// rather than "why at all".
///
/// NOTHING is the answer this crate settled on, and the reason is that these builders CONSUME
/// their receiver. `cfg.with_jwks_uri(uri);` as a statement moves `cfg` away, so the very next use
/// of `cfg` is a compile error: the borrow checker already refuses the misconfiguration the
/// attribute exists to catch. What `#[must_use]` would add is the case where the whole expression
/// is discarded and the value never used again, which is dead code rather than a setting silently
/// lost. (For a `&self -> Self` builder the analysis is the opposite, because the receiver stays
/// usable and the loss really is silent. This crate has none.)
///
/// The gate is stated as CONSISTENCY rather than as absence, so that a later decision to mark them
/// all is a decision somebody makes rather than a rule this test forbids.
#[test]
fn must_use_on_consuming_builders_is_all_or_nothing() {
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut marked = Vec::new();
    let mut unmarked = Vec::new();
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(src_dir)
        .expect("the crate's src/ must be readable")
        .map(|e| e.expect("a readable directory entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    files.sort();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("pub fn ") {
                continue;
            }
            // Signatures wrap, so join forward to the opening brace before deciding.
            let mut signature = line.trim_start().to_string();
            let mut j = i;
            while !signature.contains('{') && j + 1 < lines.len() {
                j += 1;
                signature.push(' ');
                signature.push_str(lines[j].trim_start());
            }
            let signature = signature.split('{').next().unwrap_or("").to_string();
            // WHITESPACE REMOVED before matching, because a wrapped signature joins as
            // `pub fn with_x( mut self, ...) -> Self` and a scan looking for `(mut self` misses
            // every one of them. Five of this crate's builders wrap, including three on
            // `AuthorizationServer`, so a scan that missed them would report a property about
            // three quarters of the set while claiming to cover it.
            let packed: String = signature.chars().filter(|c| !c.is_whitespace()).collect();
            // A CONSUMING builder: takes `self` or `mut self` BY VALUE and returns `Self`.
            // `&self` and `&mut self` are not builders and are not in scope here.
            let consumes = packed.contains("(mutself")
                || packed.contains("(self,")
                || packed.contains("(self)");
            if !consumes || !packed.contains("->Self") {
                continue;
            }
            // The attribute sits in the contiguous doc/attribute block above the signature.
            let has_must_use = lines[..i]
                .iter()
                .rev()
                .take_while(|prev| {
                    let p = prev.trim_start();
                    p.starts_with("///") || p.starts_with("#[") || p.starts_with("//")
                })
                .any(|prev| prev.trim_start().starts_with("#[must_use"));
            let site = format!("{}:{}: {}", path.display(), i + 1, signature.trim());
            if has_must_use {
                marked.push(site);
            } else {
                unmarked.push(site);
            }
        }
    }
    assert!(
        !marked.is_empty() || !unmarked.is_empty(),
        "the scan found no consuming builders at all, so it has stopped testing anything"
    );
    assert!(
        marked.is_empty() || unmarked.is_empty(),
        "#[must_use] on consuming builders must be all or nothing; {} of {} carry it:\n{}\n\
         and these do not:\n{}",
        marked.len(),
        marked.len() + unmarked.len(),
        marked.join("\n"),
        unmarked.join("\n")
    );
}

/// The request caps are the numbers a host needs to size its OWN gateway limits: a proxy that
/// truncates a body at less than [`oauth_as::MAX_BODY_BYTES`], or that allows more query
/// parameters than [`oauth_as::MAX_FORM_PARAMETERS`], has moved the refusal somewhere this crate
/// cannot describe. They are of no use one at a time, so they are published in one place.
///
/// This test is a COMPILE-time assertion first: naming a constant that is not re-exported fails to
/// build, which is the whole of the property.
#[test]
fn every_public_request_cap_is_reexported_at_the_crate_root() {
    // Collected rather than asserted one at a time, so the runtime check is about a value the
    // compiler has not folded away, and so a failure names WHICH cap. Naming a constant that is
    // not re-exported is a compile error, which is the property that actually matters here.
    // `mut` is cfg-dependent: the feature-gated `caps.extend(..)` calls below are the only writers,
    // so a build with none of those features enabled sees a `mut` nothing uses. Allowed rather than
    // removed, because removing it would break every build that DOES enable one.
    #[allow(unused_mut)]
    let mut caps: Vec<(&str, usize)> = vec![
        ("MIN_USER_CODE_LENGTH", oauth_as::MIN_USER_CODE_LENGTH),
        ("MAX_RESOURCE_INDICATORS", oauth_as::MAX_RESOURCE_INDICATORS),
        (
            "MAX_REGISTERED_REDIRECT_URIS",
            oauth_as::MAX_REGISTERED_REDIRECT_URIS,
        ),
    ];
    #[cfg(feature = "rar")]
    caps.extend([
        (
            "MAX_AUTHORIZATION_DETAILS_BYTES",
            oauth_as::MAX_AUTHORIZATION_DETAILS_BYTES,
        ),
        (
            "MAX_AUTHORIZATION_DETAILS_ELEMENTS",
            oauth_as::MAX_AUTHORIZATION_DETAILS_ELEMENTS,
        ),
        (
            "MAX_AUTHORIZATION_DETAILS_DEPTH",
            oauth_as::MAX_AUTHORIZATION_DETAILS_DEPTH,
        ),
    ]);
    #[cfg(feature = "token-exchange")]
    caps.push(("MAX_AUDIENCE_VALUES", oauth_as::MAX_AUDIENCE_VALUES));
    #[cfg(feature = "consent")]
    caps.push(("MAX_CONSENT_RESOURCES", oauth_as::MAX_CONSENT_RESOURCES));
    #[cfg(feature = "dpop")]
    caps.push(("MAX_PROOF_BYTES", oauth_as::MAX_PROOF_BYTES));
    #[cfg(feature = "http")]
    caps.extend([
        ("MAX_FORM_PARAMETERS", oauth_as::MAX_FORM_PARAMETERS),
        ("MAX_BODY_BYTES", oauth_as::MAX_BODY_BYTES),
    ]);

    for (name, value) in &caps {
        assert!(*value > 0, "{name} must be a positive cap");
    }
    #[cfg(feature = "token-exchange")]
    {
        let audience = caps
            .iter()
            .find(|(n, _)| *n == "MAX_AUDIENCE_VALUES")
            .expect("it was just pushed");
        let resource = caps
            .iter()
            .find(|(n, _)| *n == "MAX_RESOURCE_INDICATORS")
            .expect("it is unconditional");
        assert_eq!(
            audience.1, resource.1,
            "RFC 8693 s2.1.1 makes audience and resource two spellings of one thing, and this \
             crate holds them to one number"
        );
    }
}
