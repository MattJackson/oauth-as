//! `invalid_authorization_details` has to EXIST in a build without `rar`, because that is the
//! build with the most to refuse.
//!
//! RFC 9396 section 5 makes refusal a MUST: an authorization server that receives an
//! `authorization_details` it cannot honour "MUST refuse" rather than ignore it, because a client
//! whose detail was silently dropped obtains a token it believes says something the token does not
//! say. A build of this crate WITHOUT `rar` supports no authorization detail type at all, which is
//! the strongest form of that case, and yet the error code registered for saying so used to be
//! gated on `rar` itself: the one build that always has to refuse was the one build with no code
//! to refuse with.
//!
//! This suite locks the code's existence and its registered wire spelling for EVERY flag set. The
//! endpoints that must emit it live in `src/server.rs`; see the audit note there. The precedent is
//! `jar`'s posture for a `request` parameter it cannot process, which answers
//! `request_not_supported` rather than proceeding as though the parameter had not been sent.

use oauth_as::error::{ErrorCode, ErrorResponse};

/// Section 10 of RFC 9396 registers the code in the OAuth Extensions Error Registry with this
/// exact spelling, so it is a wire contract and not an internal name.
#[test]
fn the_code_exists_and_keeps_its_registered_spelling() {
    assert_eq!(
        ErrorCode::InvalidAuthorizationDetails.as_str(),
        "invalid_authorization_details"
    );
}

/// RFC 6749 section 5.2's default status for a request the server will not act on. A code with no
/// status decided for it inherits one by accident; this states the choice for the build where the
/// code is newly reachable.
#[test]
fn the_code_answers_with_400() {
    assert_eq!(ErrorCode::InvalidAuthorizationDetails.http_status(), 400);
}

/// The code has to survive the serde round trip an error body takes, in every build: a host that
/// parses this crate's own `ErrorResponse` must read back what was sent.
#[test]
fn the_code_round_trips_through_an_error_body() {
    let sent = ErrorResponse::new(ErrorCode::InvalidAuthorizationDetails)
        .with_description("this server does not support authorization_details");
    let text = serde_json::to_string(&sent).expect("serialize");
    assert!(
        text.contains("\"invalid_authorization_details\""),
        "unexpected body {text}"
    );
    let back: ErrorResponse = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(back.error, ErrorCode::InvalidAuthorizationDetails);
}
