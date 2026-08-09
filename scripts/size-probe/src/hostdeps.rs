// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The "host already has the dependencies" simulation.
//!
//! A host that embeds an authorization server is very unlikely to be a binary that parses no JSON
//! and speaks no HTTP. So the standalone delta overstates what adding oauth-as costs THAT host:
//! some of the serde_json, http, bytes and sha2 machinery is already linked and is shared.
//!
//! How much is shared is a real question rather than an obvious one, and the answer is "less than
//! the dependency list suggests". serde and serde_json are GENERIC: the deserializer instantiated
//! for a host's types is different machine code from the same deserializer instantiated for
//! oauth-as's types. Only the non-generic core (the JSON tokenizer, the `Value` machinery, the
//! error paths, sha2's compression function, http's header map) is genuinely shared.
//!
//! This module exercises exactly that non-generic core plus one derived type of its own, which is
//! what a host has. It must be exercised and not merely referenced, for the reason in main.rs:
//! a dependency the linker deleted is not a dependency the host has.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A host's OWN serde type, deliberately not one of oauth-as's. The monomorphized
/// serialize/deserialize glue for this struct is code oauth-as can never share, which is the
/// point being measured.
#[derive(Serialize, Deserialize)]
struct HostRecord {
    id: String,
    count: u64,
    tags: Vec<String>,
    nested: Option<Box<HostRecord>>,
}

pub fn exercise() -> u64 {
    let mut acc: u64 = 0;

    // serde_json: derive-driven serialization, derive-driven deserialization, and the untyped
    // `Value` path. All three are separate bodies of code in serde_json.
    let record = HostRecord {
        id: std::env::args().next().unwrap_or_default(),
        count: std::env::args().count() as u64,
        tags: std::env::args().collect(),
        nested: None,
    };
    let text = serde_json::to_string(&record).unwrap_or_default();
    acc = acc.wrapping_add(text.len() as u64);
    if let Ok(round) = serde_json::from_str::<HostRecord>(&text) {
        acc = acc.wrapping_add(round.count);
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        acc = acc.wrapping_add(value.to_string().len() as u64);
    }

    // sha2: the compression function and the fixed-output digest API.
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    acc = acc.wrapping_add(u64::from(hasher.finalize()[0]));

    // http and bytes: a request with a header map and a body, built and taken apart, which is the
    // shape any host with an HTTP surface already has linked.
    let body = bytes::Bytes::from(text.into_bytes());
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://host.example/anything")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("x-probe", "1")
        .body(body)
        .expect("static request parts are valid");
    acc = acc.wrapping_add(request.headers().len() as u64);
    acc = acc.wrapping_add(request.uri().path().len() as u64);
    acc = acc.wrapping_add(request.into_body().len() as u64);

    let response = http::Response::builder()
        .status(http::StatusCode::CREATED)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(bytes::Bytes::from_static(b"ok"))
        .expect("static response parts are valid");
    acc = acc.wrapping_add(u64::from(response.status().as_u16()));

    std::hint::black_box(acc)
}
