// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Parsing, validation and the pure functions underneath them.
//!
//! Nothing here touches storage or the async runtime, so these rows are the cleanest numbers in
//! the suite: no `block_on`, no mutex, no `HashMap`. They are also the rows that tell you what is
//! left after the store is taken out of the picture, which is what a host with a fast database
//! actually pays inside this crate.
//!
//! # What to compare against what
//!
//! `pkce_verify_s256` is SHA-256 over a 43-character verifier plus a fixed-length compare, and it
//! is the floor: a token request cannot be cheaper than the crypto it is required to do. If a
//! whole-endpoint row in `benches/token.rs` is within a small multiple of this, the endpoint is
//! doing very little beyond its own required work, which is the right answer. If it is a hundred
//! times this, the time is going somewhere else and that somewhere is worth naming.

#[path = "harness/mod.rs"]
mod harness;

use oauth_as::{
    AuthorizationRequest, AuthorizationServerMetadata, ErrorCode, ErrorResponse, ScopeSet,
    ServerConfig,
};

/// RFC 7636 appendix B, so these rows measure the same input the correctness tests pin.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn main() {
    harness::print_environment();
    let mut b = harness::Bench::from_args("parsing, validation and primitives");

    // ------------------------------------------------------------------------------------- PKCE
    //
    // RFC 7636. `code_challenge_s256` is one SHA-256 plus one base64url encode; `verify_s256`
    // recomputes the challenge and compares. Both are mandatory on every authorization code
    // redemption under OAuth 2.1, so they are the irreducible floor of that endpoint.
    b.bench_fast("pkce_code_challenge_s256", || {
        oauth_as::pkce::code_challenge_s256(VERIFIER)
    });
    b.bench_fast("pkce_verify_s256_match", || {
        oauth_as::pkce::verify_s256(VERIFIER, CHALLENGE)
    });
    // The MISMATCH case, because that is the one an attacker drives. It must not be measurably
    // cheaper than the match, or the difference is an oracle; see benches/constant_time.rs, which
    // tests that properly rather than eyeballing these two rows.
    b.bench_fast("pkce_verify_s256_mismatch", || {
        oauth_as::pkce::verify_s256("a-verifier-that-is-not-the-registered-one", CHALLENGE)
    });

    // ------------------------------------------------------------------- the authorization request
    //
    // `from_pairs` on borrowed `&str` is the crate's zero-allocation claim (`tests/allocation.rs`
    // pins it at exactly zero). This is what that costs in TIME, which the allocation gate cannot
    // see: zero allocations is not the same as zero work.
    {
        let borrowed = [
            ("response_type", "code"),
            ("client_id", "public-app"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "read write"),
            ("state", "opaque-state"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        b.bench_fast("authorization_request_from_pairs", || {
            AuthorizationRequest::from_pairs(borrowed)
        });
    }

    // ------------------------------------------------------------------------------------ scopes
    b.bench_fast("scope_set_parse_3", || ScopeSet::parse("read write admin"));
    b.bench_fast("scope_set_parse_1", || ScopeSet::parse("read"));

    // ------------------------------------------------------------------------------- RFC 8414
    //
    // Derivation and serialization of the metadata document. A host that serves
    // `/.well-known/oauth-authorization-server` uncached rebuilds this on every discovery request,
    // and these two rows are what that costs; a host that caches it pays them once. The suite
    // measures both halves separately so the caching decision can be made on a number.
    {
        let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        b.bench_fast("metadata_from_config", || {
            AuthorizationServerMetadata::from_config(&cfg)
        });
        let doc = AuthorizationServerMetadata::from_config(&cfg);
        b.bench_fast("metadata_serialize_json", || {
            serde_json::to_string(&doc).unwrap()
        });
    }

    // ------------------------------------------------------------------------------ the refusal
    //
    // A refusal is a request an ATTACKER sets the rate of, so it is measured on purpose. The
    // borrowed variant is the crate's `Cow<'static, str>` claim: a description that is a string
    // constant must not be copied onto the heap, and the two rows next to each other are what that
    // choice is worth.
    b.bench_fast("error_response_borrowed_description", || {
        ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("this server does not offer pushed authorization requests")
    });
    b.bench_fast("error_response_owned_description", || {
        ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description(String::from("this description was built at runtime"))
    });
    {
        let err = ErrorResponse::new(ErrorCode::InvalidGrant)
            .with_description("the authorization code is not valid");
        b.bench_fast("error_response_serialize_json", || {
            serde_json::to_string(&err).unwrap()
        });
    }

    b.finish();
}
