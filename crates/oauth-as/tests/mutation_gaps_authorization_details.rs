// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9396 `authorization_details`: the nesting bound at its exact boundary, and the two public
//! accessors a host builds its own details with.
//!
//! `tests/rar.rs` drives the details through a grant. What it never does is stand at the edge of
//! the depth bound, or construct a set the way a host enriching consent would (RFC 9396 section
//! 7.1), and a mutation sweep found both gaps: the depth constant could be computed two other ways
//! and `iter` and `from_elements` could both hand back nothing.

#![cfg(feature = "rar")]

use oauth_as::rar::{AuthorizationDetail, AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_DEPTH};

/// One `authorization_details` element whose single unknown member is a value nested `depth`
/// levels deep: 1 is a scalar, 2 is an object around a scalar, and so on.
fn element_with_member_of_depth(depth: usize) -> String {
    let mut value = String::from("\"leaf\"");
    for _ in 1..depth {
        value = format!("{{\"deeper\":{value}}}");
    }
    format!(r#"[{{"type":"payment","detail":{value}}}]"#)
}

/// KILLS: `rar.rs replace - with + at MAX_AUTHORIZATION_DETAILS_DEPTH - 2` and `replace - with /`
/// at the same site.
///
/// `MAX_MEMBER_DEPTH` is the budget left for a member VALUE once the enclosing array and element
/// object are paid for, so it is the total minus two: 6. The two mutants make it 10 and 4, and
/// both change what a client may send.
///
/// The bound is not decoration. Its stated purpose is that every recursive walk in this module,
/// AND `serde_json`'s own `Drop`, is bounded by it, so nothing a client posts can be made to
/// recurse until the stack runs out. Widening it to 10 hands back four levels of that margin to an
/// unauthenticated caller. Narrowing it to 4 refuses documents that are inside the depth this
/// crate publishes as its limit, which is a conforming client being told its request is malformed.
///
/// Only a test AT the boundary can see either. A single "deeply nested is refused" example passes
/// against all three constants.
#[test]
fn the_member_depth_budget_is_the_total_minus_the_array_and_the_element() {
    // The array and the element object are the two levels the budget subtracts.
    let budget = MAX_AUTHORIZATION_DETAILS_DEPTH - 2;
    assert_eq!(
        budget, 6,
        "the published bound is 8, and two levels are structural"
    );

    assert!(
        AuthorizationDetails::parse(&element_with_member_of_depth(budget)).is_ok(),
        "a member value at exactly the budget is inside the bound this crate publishes"
    );
    assert!(
        AuthorizationDetails::parse(&element_with_member_of_depth(budget + 1)).is_err(),
        "one level past the budget is the first refusal, or the bound is not the bound"
    );
    // And the two levels either side, so that a constant shifted by more than one cannot slip
    // through the pair of assertions above.
    assert!(
        AuthorizationDetails::parse(&element_with_member_of_depth(budget - 1)).is_ok(),
        "well inside the bound must be accepted"
    );
    assert!(
        AuthorizationDetails::parse(&element_with_member_of_depth(budget + 2)).is_err(),
        "well outside the bound must be refused"
    );
}

/// KILLS: `rar.rs replace AuthorizationDetails::from_elements -> Self with Default::default()` and
/// `replace AuthorizationDetails::iter -> impl Iterator<Item = &AuthorizationDetail> with
/// std::iter::empty()`.
///
/// These two are the whole of the host-side construction path RFC 9396 section 7.1 invites: the
/// details attached to the token MAY differ from the ones requested, so a host whose consent
/// screen enriched or replaced them builds a new set with `from_elements` and hands it back.
///
/// `from_elements` returning the default silently throws that away: the host approves a payment
/// detail, the server issues a token that authorizes NOTHING, and no error is raised anywhere,
/// because an empty detail set is a legal thing to issue. `iter` returning nothing is the same
/// failure one layer out, aimed at the host that walks the details to enforce them: every check it
/// writes passes vacuously, on a token that does carry details.
#[test]
fn details_a_host_builds_are_the_details_that_come_back() {
    let parsed = AuthorizationDetails::parse(
        r#"[{"type":"payment","actions":["initiate"]},{"type":"account_information"}]"#,
    )
    .expect("a well formed RFC 9396 document");
    let elements: Vec<AuthorizationDetail> = parsed.as_slice().to_vec();

    let built = AuthorizationDetails::from_elements(elements);
    assert_eq!(
        built.len(),
        2,
        "a host that built two elements must hold two elements"
    );
    assert!(
        !built.is_empty(),
        "a set built from two elements is not the empty set"
    );
    assert_eq!(
        built.iter().count(),
        2,
        "iter must yield what the set holds: a host walking it to enforce the details would \
         otherwise enforce nothing"
    );
    assert_eq!(
        built, parsed,
        "rebuilding a set from its own elements must produce the same set"
    );
    // The wire form is what a resource server is handed (RFC 9396 s9.1 as a JWT claim, s9.2
    // through introspection), so it is the observation that matters most.
    assert_eq!(
        serde_json::to_string(&built).expect("details serialize"),
        r#"[{"type":"payment","actions":["initiate"]},{"type":"account_information"}]"#,
        "the serialized details must carry both elements a host approved"
    );
}
