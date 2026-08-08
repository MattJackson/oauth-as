#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""
Apply the 0.7.0 RFC 9728 / RFC 8693 slice's edits to the files that slice does NOT own.

The two new modules (crates/oauth-as/src/resource_metadata.rs and src/token_exchange.rs, with
their tests) are written directly. Everything they need from a file owned by another change lives
here instead, so the two halves can be reviewed and applied independently.

Rules this script holds itself to:
  * every edit is anchored on surrounding TEXT, never on a line number;
  * an anchor that is not found EXACTLY ONCE in its file is a hard failure and NOTHING is written;
  * it refuses to run twice (each edit carries a marker whose presence means "already applied").

Run from anywhere:  python3 scripts/patch-0.7.0-rfc9728-rfc8693.py [--repo /path/to/oauth-as]

WHAT IT CHANGES AND WHY, file by file:

crates/oauth-as/Cargo.toml
  Two new cargo features, OFF by default, in the same shape as `jwt` and `http`:
  `resource-metadata` and `token-exchange`. Neither pulls a dependency.

crates/oauth-as/src/lib.rs
  Declares and re-exports the two new modules, each behind its feature.

crates/oauth-as/src/grant.rs
  Adds the RFC 8693 section 2.1 grant type URN and a `GrantType::TokenExchange` variant, BOTH
  behind `token-exchange`. A grant a client may be registered for has to be spellable in
  `Client::grant_types`, which is the only place this crate records "who may use this grant";
  inventing a second, parallel authorization list for one grant type would be a worse answer.

crates/oauth-as/src/metadata.rs
  Advertises the exchange grant in `grant_types_supported` when (and only when) it is compiled in,
  and adds the RFC 9728 section 4 `protected_resources` authorization server metadata member.

crates/oauth-as/src/http.rs
  Serves the exchange grant on the optional axum router. Required, not optional: `GrantType` is
  matched exhaustively there, and beyond that, the RFC 8414 document advertises the grant when the
  feature is on, so a router that refused it would be exactly the lie that document exists to
  avoid. The handler answers the RFC 8693 section 2.2.1 body and nothing more; the section 1.1
  semantics and the section 4.1 `act` claim are not response parameters and stay on the library
  API.

crates/oauth-as/src/server.rs
  Widens FIVE existing items from private to `pub(crate)` so the token exchange grant can reuse
  them instead of reimplementing them: `authenticate_client`, `issue`, `RefreshChain`,
  `narrow_resources`, `validate_resources`. This is the security-relevant part of the patch and it
  is deliberately visibility-only: a second copy of client authentication, or of the RFC 8707
  narrowing rule, is a second place for them to drift, and the whole point of RFC 8693's ceiling is
  that it is the SAME ceiling the refresh grant already enforces. Also adds the
  `ServerConfig::protected_resources` field behind `resource-metadata`.
"""

import argparse
import os
import sys

REPO_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (relative path, marker meaning "already applied", [(anchor, replacement), ...])
EDITS = [
    (
        "crates/oauth-as/Cargo.toml",
        'resource-metadata = []',
        [
            (
                'jwt = ["dep:p256"]\n',
                'jwt = ["dep:p256"]\n'
                "# RFC 9728 protected resource metadata. This crate is an AUTHORIZATION SERVER, not a\n"
                "# resource server, so what this feature adds is the TYPE a host publishes for its OWN\n"
                "# resource, plus the section 4 `protected_resources` member on the AS metadata document.\n"
                "# It does not make this crate a resource server and does not serve anything by itself.\n"
                "# No dependency: it is serde shapes over the serde that is already here.\n"
                "resource-metadata = []\n"
                "# RFC 8693 token exchange: delegation and impersonation for service-to-service calls.\n"
                "# OFF by default because it is a grant that mints a token from a token, and a deployment\n"
                "# that has not decided its delegation policy should not have the endpoint compiled in.\n"
                "token-exchange = []\n",
            )
        ],
    ),
    (
        "crates/oauth-as/src/lib.rs",
        "pub mod resource_metadata;",
        [
            (
                "pub mod registration;\n",
                "pub mod registration;\n"
                "/// RFC 9728 protected resource metadata, behind the `resource-metadata` cargo feature\n"
                "/// (off by default). Read the module docs before using it: the document RFC 9728 defines\n"
                "/// is published by a RESOURCE server, which this crate is not.\n"
                '#[cfg(feature = "resource-metadata")]\n'
                "pub mod resource_metadata;\n",
            ),
            (
                "pub mod token;\n",
                "pub mod token;\n"
                "/// RFC 8693 token exchange, behind the `token-exchange` cargo feature (off by default).\n"
                '#[cfg(feature = "token-exchange")]\n'
                "pub mod token_exchange;\n",
            ),
            (
                "pub use scope::{Scope, ScopeSet};\n",
                '#[cfg(feature = "resource-metadata")]\n'
                "pub use resource_metadata::{\n"
                "    BearerMethod, ProtectedResourceConfig, ProtectedResourceMetadata,\n"
                "    PROTECTED_RESOURCE_WELL_KNOWN_PATH,\n"
                "};\n"
                "pub use scope::{Scope, ScopeSet};\n",
            ),
            (
                "pub use token::{\n"
                "    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,\n"
                "    TokenType, TokenTypeHint,\n"
                "};\n",
                "pub use token::{\n"
                "    IntrospectionResponse, IssuedToken, RefreshTokenRecord, RefreshTokenState, TokenResponse,\n"
                "    TokenType, TokenTypeHint,\n"
                "};\n"
                '#[cfg(feature = "token-exchange")]\n'
                "pub use token_exchange::{\n"
                "    ActClaim, ExchangeSemantics, ExchangedToken, TokenExchange, TokenExchangeRequest,\n"
                "    TokenExchangeResponse, TokenTypeIdentifier, TOKEN_EXCHANGE_GRANT_URN,\n"
                "};\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/grant.rs",
        "TOKEN_EXCHANGE_GRANT_URN",
        [
            (
                'pub const DEVICE_CODE_GRANT_URN: &str = "urn:ietf:params:oauth:grant-type:device_code";\n',
                'pub const DEVICE_CODE_GRANT_URN: &str = "urn:ietf:params:oauth:grant-type:device_code";\n'
                "\n"
                "/// The RFC 8693 section 2.1 `grant_type` URN, verbatim.\n"
                '#[cfg(feature = "token-exchange")]\n'
                "pub const TOKEN_EXCHANGE_GRANT_URN: &str = "
                '"urn:ietf:params:oauth:grant-type:token-exchange";\n',
            ),
            (
                "    /// RFC 8628.\n"
                '    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]\n'
                "    DeviceCode,\n"
                "}\n",
                "    /// RFC 8628.\n"
                '    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]\n'
                "    DeviceCode,\n"
                "    /// RFC 8693 token exchange. A registration carries this exactly when the deployment has\n"
                "    /// decided this client may exchange a token it holds for another one; see\n"
                "    /// [`crate::token_exchange`], and note that the grant can only ever NARROW what the\n"
                "    /// subject token already carries.\n"
                '    #[cfg(feature = "token-exchange")]\n'
                '    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]\n'
                "    TokenExchange,\n"
                "}\n",
            ),
            (
                "            GrantType::DeviceCode => DEVICE_CODE_GRANT_URN,\n",
                "            GrantType::DeviceCode => DEVICE_CODE_GRANT_URN,\n"
                '            #[cfg(feature = "token-exchange")]\n'
                "            GrantType::TokenExchange => TOKEN_EXCHANGE_GRANT_URN,\n",
            ),
            (
                "            DEVICE_CODE_GRANT_URN => Ok(GrantType::DeviceCode),\n",
                "            DEVICE_CODE_GRANT_URN => Ok(GrantType::DeviceCode),\n"
                '            #[cfg(feature = "token-exchange")]\n'
                "            TOKEN_EXCHANGE_GRANT_URN => Ok(GrantType::TokenExchange),\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/metadata.rs",
        "protected_resources",
        [
            (
                "    /// OPTIONAL (section 2). A page of human-readable developer documentation.\n"
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub service_documentation: Option<String>,\n",
                "    /// OPTIONAL (section 2). A page of human-readable developer documentation.\n"
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub service_documentation: Option<String>,\n"
                "    /// RFC 9728 section 4. The resource identifiers of the protected resources this AS\n"
                "    /// issues tokens for, so a client that fetched a resource's own RFC 9728 document can\n"
                "    /// cross-check that the AS agrees the relationship exists (section 7.6: an\n"
                "    /// `authorization_servers` entry is a claim made by the RESOURCE, and believing it\n"
                "    /// unchecked is how a resource points clients at an AS that never heard of it).\n"
                "    ///\n"
                "    /// OPTIONAL, and omitted rather than empty when the host declared none: an empty array\n"
                "    /// would state that this AS protects nothing, which is a different claim from silence.\n"
                '    #[cfg(feature = "resource-metadata")]\n'
                '    #[serde(skip_serializing_if = "Option::is_none")]\n'
                "    pub protected_resources: Option<Vec<String>>,\n",
            ),
            (
                "            // Exactly the grants AuthorizationServer::token will honor.\n"
                "            grant_types_supported: vec![\n"
                '                "authorization_code".to_string(),\n'
                '                "refresh_token".to_string(),\n'
                '                "client_credentials".to_string(),\n'
                "                DEVICE_CODE_GRANT_URN.to_string(),\n"
                "            ],\n",
                "            // Exactly the grants AuthorizationServer::token will honor.\n"
                "            grant_types_supported,\n",
            ),
            (
                "    pub fn from_config(config: &ServerConfig) -> Self {\n"
                '        let iss = config.issuer.trim_end_matches(\'/\').to_string();\n',
                "    pub fn from_config(config: &ServerConfig) -> Self {\n"
                '        let iss = config.issuer.trim_end_matches(\'/\').to_string();\n'
                "        // Exactly the grants AuthorizationServer::token will honor. `mut` only when the\n"
                "        // optional exchange grant is compiled in, which is what the allow below is for:\n"
                "        // advertising a grant this build does not implement is the lie this document exists\n"
                "        // to avoid, so the list is built rather than written out once for each feature set.\n"
                "        #[allow(unused_mut)]\n"
                "        let mut grant_types_supported = vec![\n"
                '            "authorization_code".to_string(),\n'
                '            "refresh_token".to_string(),\n'
                '            "client_credentials".to_string(),\n'
                "            DEVICE_CODE_GRANT_URN.to_string(),\n"
                "        ];\n"
                "        // RFC 8693 s2.1 registers the URN; RFC 8414 s2 is what makes advertising it the way a\n"
                "        // client learns the grant is available without probing.\n"
                '        #[cfg(feature = "token-exchange")]\n'
                "        grant_types_supported.push(crate::grant::TOKEN_EXCHANGE_GRANT_URN.to_string());\n",
            ),
            (
                "            service_documentation: config.service_documentation.clone(),\n",
                "            service_documentation: config.service_documentation.clone(),\n"
                '            #[cfg(feature = "resource-metadata")]\n'
                "            protected_resources: config.protected_resources.clone(),\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/http.rs",
        "token_exchange_response",
        [
            (
                "            TokenRequest::RefreshToken {\n"
                "                client_id,\n"
                "                client_secret,\n"
                "                refresh_token,\n"
                "                scope,\n"
                "            }\n"
                "        }\n"
                "    };\n",
                "            TokenRequest::RefreshToken {\n"
                "                client_id,\n"
                "                client_secret,\n"
                "                refresh_token,\n"
                "                scope,\n"
                "            }\n"
                "        }\n"
                "        // RFC 8693 s2 shares the token endpoint with the RFC 6749 grants but NOT their\n"
                "        // response body (s2.2.1 adds a REQUIRED member), so it answers from here rather\n"
                "        // than producing a `TokenRequest`. Serving it matters beyond convenience: the RFC\n"
                "        // 8414 document advertises the grant when this feature is on, and an advertised\n"
                "        // grant this router refused would be exactly the lie that document exists to\n"
                "        // avoid.\n"
                '        #[cfg(feature = "token-exchange")]\n'
                "        GrantType::TokenExchange => {\n"
                "            return token_exchange_response(&state, &form, client_id, client_secret, via_header)\n"
                "                .await\n"
                "        }\n"
                "    };\n",
            ),
            (
                "/// RFC 8628 s3.1: the device authorization request.\n"
                "async fn device_authorization_handler<S: Storage, C: Clock>(\n",
                "/// RFC 8693 s2: the token exchange grant.\n"
                "///\n"
                "/// The router serves the WIRE response only. A host that needs to know whether the exchange\n"
                "/// was delegation or impersonation (s1.1), or that needs the s4.1 `act` claim to put into a\n"
                "/// token of its own, calls [`crate::token_exchange::TokenExchange::exchange_token`] directly:\n"
                "/// neither is a response parameter RFC 8693 defines, so neither belongs in this body.\n"
                '#[cfg(feature = "token-exchange")]\n'
                "async fn token_exchange_response<S: Storage, C: Clock>(\n"
                "    state: &Inner<S, C>,\n"
                "    form: &[Pair<'_>],\n"
                "    client_id: ClientId,\n"
                "    client_secret: Option<String>,\n"
                "    via_header: bool,\n"
                ") -> Response {\n"
                "    fn token_type(\n"
                "        name: &'static str,\n"
                "        value: &str,\n"
                "    ) -> Result<crate::token_exchange::TokenTypeIdentifier, ErrorResponse> {\n"
                "        // The VALUE is not echoed, for the reason `grant_type` is not echoed above: RFC\n"
                "        // 6749 s5.2 restricts error_description to a charset an attacker-supplied URN need\n"
                "        // not respect, and naming the parameter is enough for the developer who sent it.\n"
                "        value.parse().map_err(|_| {\n"
                "            ErrorResponse::new(ErrorCode::InvalidRequest)\n"
                '                .with_description(format!("{name} is not a token type RFC 8693 s3 registers"))\n'
                "        })\n"
                "    }\n"
                "\n"
                '    let subject_token = match required(form, "subject_token") {\n'
                "        Ok(v) => v,\n"
                "        Err(e) => return error_response(&e, via_header, &state.challenge),\n"
                "    };\n"
                '    let subject_token_type = match required(form, "subject_token_type")\n'
                '        .and_then(|v| token_type("subject_token_type", v))\n'
                "    {\n"
                "        Ok(v) => v,\n"
                "        Err(e) => return error_response(&e, via_header, &state.challenge),\n"
                "    };\n"
                '    let actor_token = param(form, "actor_token");\n'
                '    let actor_token_type = match param(form, "actor_token_type")\n'
                '        .map(|v| token_type("actor_token_type", v))\n'
                "        .transpose()\n"
                "    {\n"
                "        Ok(v) => v,\n"
                "        Err(e) => return error_response(&e, via_header, &state.challenge),\n"
                "    };\n"
                '    let requested_token_type = match param(form, "requested_token_type")\n'
                '        .map(|v| token_type("requested_token_type", v))\n'
                "        .transpose()\n"
                "    {\n"
                "        Ok(v) => v,\n"
                "        Err(e) => return error_response(&e, via_header, &state.challenge),\n"
                "    };\n"
                "    let scope = match optional_scope(form) {\n"
                "        Ok(s) => s,\n"
                "        Err(e) => return error_response(&e, via_header, &state.challenge),\n"
                "    };\n"
                "    // Both target parameters may repeat (RFC 8693 s2.1, RFC 8707 s2), so neither may go\n"
                "    // through `param`'s first-wins rule: dropping the second occurrence would silently\n"
                "    // narrow the request to half of what the client asked for.\n"
                "    let resource = resource_indicators(form);\n"
                "    let audience: Vec<String> = form\n"
                "        .iter()\n"
                '        .filter(|(k, _)| k == "audience")\n'
                "        .map(|(_, v)| v.as_ref().to_string())\n"
                "        .collect();\n"
                "\n"
                "    let request = crate::token_exchange::TokenExchangeRequest {\n"
                "        client_id: &client_id,\n"
                "        client_secret: client_secret.as_deref(),\n"
                "        subject_token,\n"
                "        subject_token_type,\n"
                "        actor_token,\n"
                "        actor_token_type,\n"
                "        resource: &resource,\n"
                "        audience: &audience,\n"
                "        scope: scope.as_ref(),\n"
                "        requested_token_type,\n"
                "    };\n"
                "    match crate::token_exchange::TokenExchange::exchange_token(&*state.server, &request).await {\n"
                "        Ok(exchanged) => ok_json(&exchanged.response),\n"
                "        Err(e) => error_response(&e, via_header, &state.challenge),\n"
                "    }\n"
                "}\n"
                "\n"
                "/// RFC 8628 s3.1: the device authorization request.\n"
                "async fn device_authorization_handler<S: Storage, C: Clock>(\n",
            ),
        ],
    ),
    (
        "crates/oauth-as/src/server.rs",
        "pub(crate) async fn authenticate_client(",
        [
            # Visibility only. See the module docstring above for why the exchange grant reuses
            # these rather than growing a second copy of them.
            (
                "    async fn authenticate_client(\n",
                "    pub(crate) async fn authenticate_client(\n",
            ),
            ("    async fn issue(\n", "    pub(crate) async fn issue(\n"),
            ("struct RefreshChain {\n", "pub(crate) struct RefreshChain {\n"),
            ("    fn narrow_resources(\n", "    pub(crate) fn narrow_resources(\n"),
            (
                "    fn validate_resources<'a>(\n",
                "    pub(crate) fn validate_resources<'a>(\n",
            ),
            (
                "    /// RFC 8414 `service_documentation`.\n"
                "    pub service_documentation: Option<String>,\n",
                "    /// RFC 8414 `service_documentation`.\n"
                "    pub service_documentation: Option<String>,\n"
                "    /// RFC 9728 section 4 `protected_resources`: the resource identifiers of the protected\n"
                "    /// resources this AS issues tokens for. `None` (the default) omits the member; see\n"
                "    /// [`crate::metadata::AuthorizationServerMetadata::protected_resources`], and note that\n"
                "    /// this is the AS half only. The DOCUMENT each of those resources publishes is\n"
                "    /// [`crate::resource_metadata::ProtectedResourceMetadata`], and publishing it is the\n"
                "    /// resource's own job, not this server's.\n"
                '    #[cfg(feature = "resource-metadata")]\n'
                "    pub protected_resources: Option<Vec<String>>,\n",
            ),
            (
                "            service_documentation: None,\n",
                "            service_documentation: None,\n"
                '            #[cfg(feature = "resource-metadata")]\n'
                "            protected_resources: None,\n",
            ),
        ],
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=REPO_DEFAULT, help="repository root")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    # PHASE 1: read and check everything. Nothing is written until every edit in every file has
    # been proven applicable, so a half-applied tree is not a state this script can produce.
    planned = []
    for rel, marker, edits in EDITS:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            print(f"FAIL: {rel} does not exist under {repo}", file=sys.stderr)
            return 1
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if marker in text:
            print(
                f"FAIL: {rel} already contains the marker {marker!r}: this patch has already "
                f"been applied, and applying it twice is not something it will do.",
                file=sys.stderr,
            )
            return 1
        for anchor, replacement in edits:
            count = text.count(anchor)
            if count != 1:
                print(
                    f"FAIL: in {rel}, the anchor\n---\n{anchor}---\nwas found {count} times, "
                    f"expected exactly 1. The file has moved underneath this patch; fix the "
                    f"anchor by hand rather than guessing.",
                    file=sys.stderr,
                )
                return 1
            text = text.replace(anchor, replacement, 1)
        planned.append((path, rel, text))

    # PHASE 2: write.
    for path, rel, text in planned:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"patched {rel}")
    print("ok: 0.7.0 RFC 9728 / RFC 8693 host-file edits applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
