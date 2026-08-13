// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The shape a HOST codes against, as gates rather than as habits.
//!
//! Seven properties, each of which was inconsistent across the crate rather than absent from it,
//! which is the worse failure: a host that learns the rule from one type is entitled to expect it
//! from the next one.
//!
//! - [`error_code_is_non_exhaustive`]: a public enum that GAINS variants with a cargo feature must
//!   not break a host's exhaustive `match` when a feature flag moves.
//! - [`every_feature_varying_public_type_is_non_exhaustive`]: and so must EVERY other one, which is
//!   the general form of the rule the test above states about a single enum.
//! - [`error_code_http_status_chooses_a_status_for_every_variant`]: a new variant must force its
//!   author to choose a status rather than inheriting 400 from a catch-all.
//! - [`registration_error_response_is_a_std_error`]: a public type with a `Display` that describes
//!   a failure is an error, and a host's `?` and `Box<dyn Error>` should say so.
//! - [`must_use_on_consuming_builders_is_all_or_nothing`]: one `#[must_use]` out of twenty-nine
//!   builders is a rule nobody is following.
//! - [`every_public_request_cap_is_reexported_at_the_crate_root`]: a host sizing its own gateway
//!   limits needs all of them, from one place.
//! - [`every_type_in_a_storage_signature_is_reexported_at_the_crate_root`]: the general form of
//!   that one, over the API a host cannot route around. It caught `RevocationWindow`, which a host
//!   MUST name to declare three `Storage` methods and which was reachable only through
//!   `oauth_as::store::`.
//!
//! Five of the seven are SOURCE scans, in the same idiom (and for the same dependency-policy
//! reason) as `tests/allocation.rs`'s scan for module-level statics: `#[non_exhaustive]`,
//! `#[must_use]` and a MISSING re-export are all invisible from inside the crate that declares
//! them, so no runtime assertion can see any of them.

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

/// THE GENERAL FORM of the test above, and the reason that one was not enough.
///
/// `ErrorCode` was found by reading; the rule it is an instance of covers twenty public types, and
/// sixteen of them were missing the attribute at 0.9.0. Every one of this crate's fifteen features
/// is OFF by default, so the failure always looks the same from a host's side: they write a struct
/// literal or an exhaustive `match` against the feature set THEY enabled, it compiles, and it stops
/// compiling the day an unrelated crate in their dependency graph enables a feature they never
/// asked for. Cargo feature unification means they cannot prevent that and did nothing to cause it.
///
/// `#[non_exhaustive]` cannot be added after the fact, because by then the literal is in somebody's
/// production tree, so this is a gate rather than a lint: a NEW feature-gated field or variant on a
/// public type fails this test until its type carries the attribute, which is the moment the
/// decision is still free.
///
/// The scan reads source rather than asserting at runtime for the reason the module doc gives: the
/// attribute has no effect inside the crate that declares it, so there is nothing for a test
/// compiled as part of this crate to observe. This one is compiled as a separate crate and STILL
/// cannot observe it, because the only observable consequence is a compile error.
#[test]
fn every_feature_varying_public_type_is_non_exhaustive() {
    /// Public types whose field or variant set varies with a feature and which are deliberately
    /// NOT marked, each with the reason it would be redundant rather than merely unwanted. A name
    /// here that the scan no longer finds is itself a failure, so the list cannot rot into a set of
    /// excuses for types that have since changed shape.
    const DELIBERATELY_UNMARKED: &[(&str, &str)] = &[
        (
            "ValidatedAuthorizationRequest",
            "sealed by a private zero-sized field, so it is already unconstructible and \
             un-destructurable from outside this crate; see its own doc comment",
        ),
        (
            "ServiceBuilder",
            "every field is private, so the attribute would add nothing: a host builds it with \
             new() and the with_* seams and can name none of its insides",
        ),
        (
            "AuthorizationServer",
            "every field is private, for the same reason as ServiceBuilder. Its `token_endpoint` \
             is derived under client-assertion or dpop and is not something a host may ever spell",
        ),
    ];

    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(src_dir)
        .expect("the crate's src/ must be readable")
        .map(|e| e.expect("a readable directory entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    files.sort();

    let mut varying = Vec::new();
    let mut offenders = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            let rest = match trimmed
                .strip_prefix("pub struct ")
                .or_else(|| trimmed.strip_prefix("pub enum "))
            {
                Some(rest) => rest,
                None => continue,
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            // The BODY, by brace balance from the declaration's opening brace. A tuple or unit
            // struct reaches `(` or `;` first and has no field the scan can be about.
            let mut depth = 0usize;
            let mut started = false;
            let mut body = Vec::new();
            for body_line in lines[i..].iter() {
                // Doc and comment lines are skipped for COUNTING, because a field's prose
                // legitimately contains braces (`{issuer}/par` is one) and a stray one would
                // truncate the body or run it to the end of the file.
                let t = body_line.trim_start();
                let is_prose = t.starts_with("///") || t.starts_with("//");
                if !is_prose {
                    if !started {
                        if let Some(stop) = body_line.find(['{', '(', ';']) {
                            if body_line.as_bytes()[stop] != b'{' {
                                break;
                            }
                            started = true;
                        }
                    }
                    if started {
                        depth += body_line.matches('{').count();
                        depth -= body_line.matches('}').count().min(depth);
                    }
                }
                if started {
                    body.push(*body_line);
                    if depth == 0 {
                        break;
                    }
                }
            }
            if !started {
                continue;
            }
            let varies = body.iter().any(|b| {
                let t = b.trim_start();
                t.starts_with("#[cfg(") && t.contains("feature")
            });
            if !varies {
                continue;
            }
            varying.push(name.clone());
            // The attribute sits in the contiguous doc/attribute block above the declaration.
            // `starts_with` and not `contains`, because the house style is to explain the
            // attribute in a doc comment that quotes it directly above the attribute itself.
            let marked = lines[..i]
                .iter()
                .rev()
                .take_while(|prev| {
                    let p = prev.trim_start();
                    p.starts_with("///") || p.starts_with("#[") || p.starts_with("//")
                })
                .any(|prev| prev.trim_start().starts_with("#[non_exhaustive]"));
            if marked || DELIBERATELY_UNMARKED.iter().any(|(n, _)| *n == name) {
                continue;
            }
            offenders.push(format!("{}:{}: {}", path.display(), i + 1, name));
        }
    }

    assert!(
        varying.len() > 10,
        "the scan found only {} feature-varying public types, so it has stopped finding them and \
         is no longer testing anything",
        varying.len()
    );
    for (name, why) in DELIBERATELY_UNMARKED {
        assert!(
            varying.iter().any(|v| v == name),
            "{name} is on the deliberately-unmarked list ({why}) but the scan no longer finds it \
             varying with a feature; drop the entry rather than leaving it to excuse a type that \
             has changed shape since"
        );
    }
    assert!(
        offenders.is_empty(),
        "these public types gain a field or a variant with a cargo feature and are not \
         #[non_exhaustive], so a host's struct literal or exhaustive match against them breaks \
         when anything in their dependency graph enables a feature they did not ask for:\n{}",
        offenders.join("\n")
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
    // A COUNT, not a non-emptiness, and the sibling guard on the `#[non_exhaustive]` scan above
    // already had it right. `!marked.is_empty() || !unmarked.is_empty()` is satisfied by finding
    // ONE builder out of the twenty-odd this crate has, so a signature pattern that silently
    // stopped matching -- a rename, a `where` clause moved onto its own line, a file the walk no
    // longer reaches -- would leave this scan reporting on a single method while reading as though
    // it had swept the crate. That is the same shape as an anti-rot guard that cannot rot.
    let found = marked.len() + unmarked.len();
    assert!(
        found > 10,
        "the scan found only {found} consuming builders, so it has stopped finding them and is no \
         longer testing anything"
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

/// THE SIBLING OF THE TEST BELOW, for the one API surface a host cannot route around.
///
/// `lib.rs` states the rule beside the `Storage` re-exports: "A host implementing `Storage` MUST
/// name `WriteOutcome`, because it is what `put_token`, `put_refresh_token` and
/// `put_pushed_authorization_request` return". That is right, and it is a rule about the whole
/// signature set rather than about the two types it was written for. `RevocationWindow` sat two
/// lines away from that comment, un-re-exported, while being a BY-VALUE parameter of
/// `delete_client`, `revoke_token_family` and `revoke_consent`. Its obligation is the STRONGER one:
/// a store may satisfy `RevocationBarrier` in SQL and never match on the type, but nobody can write
/// `async fn delete_client(&self, _: &ClientId, window: ???)` without spelling the parameter. This
/// crate's own Postgres backend paid for it four times, writing `oauth_as::store::RevocationWindow`
/// inline at each of the three methods plus a helper.
///
/// The rule this gate states is therefore: EVERY type this crate defines and names in a `Storage`
/// method signature is reachable from the crate root. A host should be able to write the impl from
/// `use oauth_as::*` and the trait's own docs, without learning which module each parameter happens
/// to live in.
///
/// A source scan, and it has to be: a re-export that is MISSING is not an error anywhere inside this
/// crate, because `crate::store::RevocationWindow` resolves perfectly well from here. It is only an
/// absence, and only from outside. Same idiom and same reason as the scans above.
#[test]
fn every_type_in_a_storage_signature_is_reexported_at_the_crate_root() {
    /// Names that appear in `Storage` signatures and belong to `std`/`core` rather than to this
    /// crate, so re-exporting them would be wrong rather than merely unnecessary. Kept as a literal
    /// list because the alternative is a heuristic about which CamelCase words are ours, and a
    /// heuristic that guesses wrong in the quiet direction turns this test off.
    const NOT_OURS: &[&str] = &[
        "Future",
        "Output",
        "Result",
        "Option",
        "Some",
        "None",
        "Send",
        "Sync",
        "Sized",
        "Arc",
        "Vec",
        "String",
        "SystemTime",
        "Duration",
        "Self",
    ];

    let store_src = include_str!("../src/store.rs");
    let lib_src = include_str!("../src/lib.rs");

    // The TRAIT BODY only: the `impl Storage for MemoryStorage` below it names private helpers that
    // are nobody's business, and the free items above it are not part of the host's obligation.
    let trait_at = store_src
        .find("pub trait Storage: Send + Sync {")
        .expect("the trait has to still be there");
    let trait_end = store_src[trait_at..]
        .find("\n}\n")
        .expect("the trait has to end")
        + trait_at;
    let body = &store_src[trait_at..trait_end];

    // The re-export surface: every `pub use` line in lib.rs, joined, so that a name inside a braced
    // multi-line list counts. Matching the whole file would let a doc comment mentioning a type
    // stand in for actually exporting it, which is the failure this test is about.
    let mut reexports = String::new();
    let mut in_use = false;
    for line in lib_src.lines() {
        if line.starts_with("pub use ") {
            in_use = true;
        }
        if in_use {
            reexports.push_str(line);
            reexports.push('\n');
            if line.trim_end().ends_with(';') {
                in_use = false;
            }
        }
    }

    let mut named = Vec::new();
    let mut missing = Vec::new();
    let mut signature = String::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//") {
            continue;
        }
        if signature.is_empty() && !line.starts_with("    fn ") {
            continue;
        }
        signature.push(' ');
        signature.push_str(trimmed);
        if !trimmed.ends_with(';') {
            continue;
        }
        // Split on anything that cannot be part of an identifier, then keep the CamelCase words.
        for word in signature.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            let mut chars = word.chars();
            let Some(first) = chars.next() else { continue };
            if !first.is_ascii_uppercase() || NOT_OURS.contains(&word) {
                continue;
            }
            if !named.iter().any(|n| n == word) {
                named.push(word.to_string());
            }
            // Word boundaries matter: `Client` must not be satisfied by `ClientId`, and this crate
            // publishes both.
            let exported = reexports
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|t| t == word);
            if !exported && !missing.iter().any(|m| m == word) {
                missing.push(word.to_string());
            }
        }
        signature.clear();
    }

    assert!(
        named.len() > 8,
        "the scan found only {} crate-defined types in Storage signatures, so it has stopped \
         finding them and is no longer testing anything: {named:?}",
        named.len()
    );
    assert!(
        missing.is_empty(),
        "these types appear in a `Storage` method signature and are NOT re-exported at the crate \
         root, so a host cannot write the impl from `oauth_as::` alone: {missing:?}\n\
         A re-export that is missing is an absence rather than an error, invisible from inside this \
         crate; add each to the `pub use` list in lib.rs under the SAME `#[cfg]` its item carries."
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
