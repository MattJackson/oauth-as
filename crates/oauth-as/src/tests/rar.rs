// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for RFC 9396 parsing, bounds and the narrowing predicate.
//!
//! These sit here rather than in `tests/rar.rs` because they reach the module's private parts: the
//! depth walker, the subset helper, and the derived member-depth budget. `tests/rar.rs` is the
//! behavioural suite and drives the same rules through the public server API.

use super::*;

fn detail(json: &str) -> AuthorizationDetail {
    serde_json::from_str(json).expect("test fixture must parse")
}

/// RFC 9396 s2: an array of objects, each carrying a `type`. The parse is where the wire shape is
/// pinned, so the accepted shape is asserted rather than assumed.
#[test]
fn parse_accepts_the_rfc_shape_and_keeps_the_common_fields() {
    let details = AuthorizationDetails::parse(
        r#"[{"type":"payment_initiation","locations":["https://rs.example/"],"actions":["initiate"],"datatypes":["contacts"],"identifier":"acct-1","privileges":["admin"]}]"#,
    )
    .expect("the RFC's own shape must parse");
    assert_eq!(details.len(), 1);
    let d = &details.as_slice()[0];
    assert_eq!(d.detail_type, "payment_initiation");
    assert_eq!(d.locations, vec!["https://rs.example/".to_string()]);
    assert_eq!(d.actions, vec!["initiate".to_string()]);
    assert_eq!(d.datatypes, vec!["contacts".to_string()]);
    assert_eq!(d.identifier.as_deref(), Some("acct-1"));
    assert_eq!(d.privileges, vec!["admin".to_string()]);
    assert!(
        d.other.is_empty(),
        "the section 2.2 common fields must not also land in `other`, or they would be compared \
         twice and serialized twice"
    );
}

/// The preservation rule (see the module docs) at the level the rest of the crate depends on: what
/// goes in comes out, in the same shape, through a full serialize/deserialize round trip, because
/// that round trip is what storage and introspection actually do to these values.
#[test]
fn unknown_members_round_trip_unchanged() {
    let raw = r#"[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"50.00"},"creditorAccount":{"iban":"DE02100100109307118603"},"count":3,"flag":true,"nothing":null}]"#;
    let parsed = AuthorizationDetails::parse(raw).expect("must parse");
    let json = serde_json::to_string(&parsed).expect("must serialize");
    let again = AuthorizationDetails::parse(&json).expect("must re-parse");
    assert_eq!(parsed, again, "a round trip must be the identity");

    let d = &parsed.as_slice()[0];
    assert_eq!(d.other.get("count"), Some(&serde_json::json!(3)));
    assert_eq!(d.other.get("flag"), Some(&serde_json::json!(true)));
    assert_eq!(
        d.other.get("nothing"),
        Some(&serde_json::Value::Null),
        "an explicit null is a member that was sent; dropping it would change the object"
    );
    assert_eq!(
        d.other.get("creditorAccount"),
        Some(&serde_json::json!({"iban": "DE02100100109307118603"}))
    );
}

/// Serialization has to be deterministic, because `narrow` compares `other` for equality and two
/// details that differ only in member ORDER are the same request. `serde_json::Map` is a
/// `BTreeMap` here (the `preserve_order` feature is not enabled), which is what makes that true;
/// this test is the tripwire for somebody enabling it.
#[test]
fn member_order_does_not_change_identity() {
    let a = AuthorizationDetails::parse(r#"[{"type":"t","b":1,"a":2}]"#).unwrap();
    let b = AuthorizationDetails::parse(r#"[{"type":"t","a":2,"b":1}]"#).unwrap();
    assert_eq!(a, b);
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

/// The size bound is checked BEFORE the parser runs, so the check has to be on the raw text. The
/// boundary is asserted from both sides: a bound that refused everything would pass a
/// one-sided test.
#[test]
fn the_byte_bound_is_exact_at_the_boundary() {
    let head = r#"[{"type":"t","n":""#;
    let tail = r#""}]"#;
    let filler = MAX_AUTHORIZATION_DETAILS_BYTES - head.len() - tail.len();
    let at_limit = format!("{head}{}{tail}", "x".repeat(filler));
    assert_eq!(at_limit.len(), MAX_AUTHORIZATION_DETAILS_BYTES);
    assert!(
        AuthorizationDetails::parse(&at_limit).is_ok(),
        "exactly at the limit must be accepted"
    );

    let over = format!("{head}{}{tail}", "x".repeat(filler + 1));
    assert_eq!(over.len(), MAX_AUTHORIZATION_DETAILS_BYTES + 1);
    assert_eq!(
        AuthorizationDetails::parse(&over).unwrap_err().error,
        ErrorCode::InvalidAuthorizationDetails,
        "one byte over must be refused"
    );
}

/// Same, for the element count.
#[test]
fn the_element_bound_is_exact_at_the_boundary() {
    let one = r#"{"type":"t"}"#;
    let at_limit = format!(
        "[{}]",
        vec![one; MAX_AUTHORIZATION_DETAILS_ELEMENTS].join(",")
    );
    assert_eq!(
        AuthorizationDetails::parse(&at_limit).unwrap().len(),
        MAX_AUTHORIZATION_DETAILS_ELEMENTS
    );
    let over = format!(
        "[{}]",
        vec![one; MAX_AUTHORIZATION_DETAILS_ELEMENTS + 1].join(",")
    );
    assert_eq!(
        AuthorizationDetails::parse(&over).unwrap_err().error,
        ErrorCode::InvalidAuthorizationDetails
    );
}

/// The depth walker, checked directly. A scalar is 1, and each container adds one; the budget a
/// member value gets is the total minus the array and the element object that enclose it, and the
/// boundary is asserted on both sides so an off-by-one in either direction fails.
#[test]
fn depth_counts_containers_and_the_member_budget_is_exact() {
    assert_eq!(depth(&serde_json::json!(1)), 1);
    assert_eq!(depth(&serde_json::json!([])), 1);
    assert_eq!(depth(&serde_json::json!([1])), 2);
    assert_eq!(depth(&serde_json::json!({"a": {"b": 1}})), 3);
    assert_eq!(
        depth(&serde_json::json!({"a": 1, "b": [[[2]]]})),
        5,
        "the deepest child decides, not the first: the object plus three arrays plus the scalar"
    );

    let nest = |n: usize| format!(r#"[{{"type":"t","n":{}1{}}}]"#, "[".repeat(n), "]".repeat(n));
    // n nested arrays around a scalar is depth n + 1.
    let at_limit = nest(MAX_MEMBER_DEPTH - 1);
    assert!(
        AuthorizationDetails::parse(&at_limit).is_ok(),
        "exactly at the member depth budget must be accepted"
    );
    let over = nest(MAX_MEMBER_DEPTH);
    assert_eq!(
        AuthorizationDetails::parse(&over).unwrap_err().error,
        ErrorCode::InvalidAuthorizationDetails,
        "one level over must be refused"
    );
}

/// RFC 9396 s5, at the unit level: `None` supported types means every type is unknown. This is the
/// DEFAULT configuration, so getting it backwards would make the feature open by default.
#[test]
fn no_declared_types_means_no_type_is_supported() {
    let details = AuthorizationDetails::parse(r#"[{"type":"payment_initiation"}]"#).unwrap();
    assert_eq!(
        details.require_supported_types(None).unwrap_err().error,
        ErrorCode::InvalidAuthorizationDetails
    );
    assert_eq!(
        details.require_supported_types(Some(&[])).unwrap_err().error,
        ErrorCode::InvalidAuthorizationDetails
    );
    assert!(details
        .require_supported_types(Some(&["payment_initiation".to_string()]))
        .is_ok());
    // One unknown type among known ones is still a refusal: section 5 is about the request, not
    // about the majority of it.
    let mixed =
        AuthorizationDetails::parse(r#"[{"type":"payment_initiation"},{"type":"other"}]"#).unwrap();
    assert_eq!(
        mixed
            .require_supported_types(Some(&["payment_initiation".to_string()]))
            .unwrap_err()
            .error,
        ErrorCode::InvalidAuthorizationDetails
    );
}

/// The narrowing predicate, one case per rule, because this is the security core of the module and
/// a table is the only way to see that every field is actually consulted.
#[test]
fn is_narrowing_of_consults_every_field() {
    let granted = detail(
        r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
    );

    // Identity narrows itself; that is what a client asking for exactly what it was granted does.
    assert!(granted.is_narrowing_of(&granted));

    for (why, narrower) in [
        (
            "dropping a location",
            r#"{"type":"t","locations":["l1"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "dropping every action",
            r#"{"type":"t","locations":["l1","l2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "dropping a privilege and a datatype",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1"],"identifier":"i1","amount":"50"}"#,
        ),
    ] {
        assert!(
            detail(narrower).is_narrowing_of(&granted),
            "{why} is a narrowing and must be allowed"
        );
    }

    for (why, wider) in [
        (
            "a different type",
            r#"{"type":"u","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "a different identifier",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i2","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "no identifier at all, which asks for the whole class",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "an added location",
            r#"{"type":"t","locations":["l1","l2","l3"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "an added action",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2","a3"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "an added datatype",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1","d2"],"identifier":"i1","privileges":["p1"],"amount":"50"}"#,
        ),
        (
            "an added privilege",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1","p2"],"amount":"50"}"#,
        ),
        (
            "a changed type-defined member",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"5000"}"#,
        ),
        (
            "a dropped type-defined member, whose absence this server cannot interpret",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"]}"#,
        ),
        (
            "an added type-defined member",
            r#"{"type":"t","locations":["l1","l2"],"actions":["a1","a2"],"datatypes":["d1"],"identifier":"i1","privileges":["p1"],"amount":"50","extra":true}"#,
        ),
    ] {
        assert!(
            !detail(wider).is_narrowing_of(&granted),
            "{why} is not a narrowing and must be refused"
        );
    }
}

/// An absent list on the GRANTED side is an empty list, and the only subset of the empty set is the
/// empty set. Stated as its own test because the tempting alternative reading ("absent means
/// unrestricted, so anything is narrower") is the one that hands out a location nobody approved.
#[test]
fn an_absent_granted_list_can_only_be_narrowed_to_itself() {
    let granted = detail(r#"{"type":"t"}"#);
    assert!(detail(r#"{"type":"t"}"#).is_narrowing_of(&granted));
    assert!(!detail(r#"{"type":"t","locations":["l1"]}"#).is_narrowing_of(&granted));
    assert!(!detail(r#"{"type":"t","actions":["a1"]}"#).is_narrowing_of(&granted));
}

/// `narrow` at the set level: empty means "no narrowing asked for", a granted-empty set has nothing
/// to narrow, and every requested element has to be covered by SOME granted element.
#[test]
fn narrow_covers_every_requested_element_against_the_whole_granted_set() {
    let granted =
        AuthorizationDetails::parse(r#"[{"type":"a","actions":["x"]},{"type":"b"}]"#).unwrap();

    assert_eq!(
        granted.narrow(&AuthorizationDetails::none()).unwrap(),
        granted,
        "no narrowing asked for means the grant passes through"
    );

    // The SECOND granted element is what covers this one, so a first-element-only comparison fails
    // here.
    let just_b = AuthorizationDetails::parse(r#"[{"type":"b"}]"#).unwrap();
    assert_eq!(granted.narrow(&just_b).unwrap(), just_b);

    let ungranted = AuthorizationDetails::parse(r#"[{"type":"c"}]"#).unwrap();
    assert_eq!(
        granted.narrow(&ungranted).unwrap_err().error,
        ErrorCode::InvalidAuthorizationDetails
    );

    // Widening from nothing.
    assert_eq!(
        AuthorizationDetails::none()
            .narrow(&just_b)
            .unwrap_err()
            .error,
        ErrorCode::InvalidAuthorizationDetails
    );
}

/// `is_subset` is a linear scan, so its duplicate and empty behaviour is worth pinning rather than
/// inferring from the set-theoretic name.
#[test]
fn is_subset_handles_empties_and_duplicates() {
    let l1 = vec!["a".to_string()];
    let l2 = vec!["a".to_string(), "b".to_string()];
    assert!(is_subset(&[], &[]));
    assert!(is_subset(&[], &l2));
    assert!(is_subset(&l1, &l2));
    assert!(!is_subset(&l2, &l1));
    // A repeated value asks for the same thing twice, which is not more than once.
    assert!(is_subset(&["a".to_string(), "a".to_string()], &l1));
}
