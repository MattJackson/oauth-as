// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7662 introspection for a RESOURCE SERVER, which is the caller the document is written for:
//! the abstract defines "a method for a protected resource to query an OAuth 2.0 authorization
//! server", and section 1 a protocol that "allows authorized protected resources to query the
//! authorization server". Through 0.9.1 this server had no channel
//! for one, and a resource server that did what the RFC told it to do was answered
//! `{"active": false}` about every live token it held.
//!
//! The channel exists now, and almost everything worth pinning here is a REFUSAL rather than the
//! happy path. Authenticating as a resource server buys the right to ask about tokens addressed to
//! THAT resource server and nothing else. The alternative -- any authenticated resource server may
//! read any token -- is section 4's token-scanning oracle with a credential stapled to it, and it
//! is a worse oracle than the anonymous one because it returns a subject.
//!
//! The two refusals that carry the most weight:
//!
//! - a resource server asking about a token addressed to a DIFFERENT resource server, and
//! - a resource server asking about a token whose grant named NO resource at all.
//!
//! The second is the fail-open reading that [`oauth_as::jwt::Audience::names_a_resource_server`]
//! exists to refuse, arriving through the other door. An empty audience restricts the token to
//! nothing in particular; reading that as "so anybody may ask" would hand every resource server in
//! the deployment every token that did not happen to use RFC 8707, which is most of them.

mod support;

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, ClientId, MemoryStorage, ResourceServerRegistration,
    ServerConfig, TokenRequest, TokenResponse, UserApproval,
};
use support::{
    client_credentials_client, confidential_client, other_confidential_client, ManualClock,
    CC_SECRET, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, OTHER_CONFIDENTIAL_SECRET,
    RFC7636_VERIFIER,
};

/// The resource server under test, and a second one it must never be able to read.
const RS_MINE: &str = "https://api.example/";
const RS_THEIRS: &str = "https://payroll.example/";

/// `other-app` is the RESOURCE SERVER in this suite: an ordinary confidential client, registered
/// the ordinary way, that the deployment additionally declares to be the protected resource for
/// `RS_MINE`. That it needs no special registration and no special credential is the design being
/// tested, not an accident of the fixture.
async fn server_with_resource_server() -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.resource_servers = Some(Box::new([ResourceServerRegistration::new(
        ClientId::new("other-app"),
        [RS_MINE],
    )]));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    for c in [
        confidential_client(),
        other_confidential_client(),
        client_credentials_client(),
    ] {
        srv.register_client(c).await.unwrap();
    }
    srv
}

/// A token minted for `confidential-app`, narrowed by RFC 8707 to `resources`.
async fn token_for_resources(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    resources: &[&str],
) -> TokenResponse {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", "confidential-app"),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    for r in resources {
        pairs.push(("resource", r));
    }
    let validated = srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs(pairs))
        .await
        .expect("fixture authorization request must validate");
    let code = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("fixture code issuance must succeed");
    srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        code: code.code,
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    })
    .await
    .expect("fixture code redemption must succeed")
}

/// THE ONE THAT MATTERS. RFC 7662 s4: a resource server authenticated as itself must not be able
/// to read a token addressed to somebody else. If this passes only because the endpoint refuses
/// everyone, the happy-path test below fails, so the pair has to hold together.
#[tokio::test]
async fn a_resource_server_is_refused_a_token_addressed_to_a_different_resource_server() {
    let srv = server_with_resource_server().await;
    let issued = token_for_resources(&srv, &[RS_THEIRS]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("other-app"),
            Some(OTHER_CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("an authenticated caller gets an answer, not an error");

    assert!(
        !resp.active,
        "RFC 7662 s4: `other-app` is the resource server for {RS_MINE}, and this token is \
         addressed to {RS_THEIRS}. Answering it would make the endpoint a token-scanning oracle \
         for every resource server in the deployment."
    );
    // s2.2 gives ONE answer for a token the caller has no relationship to, and it carries nothing
    // else. Checked against the JSON because a struct check would pass on a leaked member that
    // happened to be `None` for this fixture.
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "active": false }),
        "RFC 7662 s2.2: the refusal is `active: false` and NOTHING else"
    );
}

/// The other half of the same defence, and the one a reader is most likely to think is an
/// oversight. A grant that named no RFC 8707 resource is restricted to nothing in particular. It
/// must NOT therefore be readable by every resource server: "restricted to nobody" is not
/// "addressed to everybody". Most tokens in most deployments look like this, so getting it wrong
/// would expose nearly the whole store rather than an edge of it.
#[tokio::test]
async fn a_resource_server_is_refused_a_token_whose_grant_named_no_resource_at_all() {
    let srv = server_with_resource_server().await;
    let issued = token_for_resources(&srv, &[]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("other-app"),
            Some(OTHER_CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("an authenticated caller gets an answer, not an error");

    assert!(
        !resp.active,
        "an empty `resource` names no resource server, so no resource server may read it; \
         this is `Audience::names_a_resource_server`'s fail-open refusal reached by the other door"
    );
}

/// A confidential client that authenticates perfectly well but was never declared a resource
/// server is exactly where it was before 0.9.2: it can read its own tokens and nothing else.
/// Registering the channel must not open it to every client that happens to hold a secret.
#[tokio::test]
async fn a_confidential_client_that_is_not_a_registered_resource_server_reads_nothing() {
    let srv = server_with_resource_server().await;
    let issued = token_for_resources(&srv, &[RS_MINE]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("cc-app"),
            Some(CC_SECRET),
            &issued.access_token,
        )
        .await
        .expect("an authenticated caller gets an answer, not an error");

    assert!(
        !resp.active,
        "`cc-app` authenticates but is not the resource server for anything; being a confidential \
         client is not by itself a licence to introspect other clients' tokens"
    );
}

/// The capability itself: the resource server the token was actually addressed to is answered, and
/// answered with the members it needs to make an access-control decision. Without this the three
/// refusals above would be satisfied by an endpoint that simply says no to everybody, which is
/// what 0.9.1 shipped.
#[tokio::test]
async fn the_resource_server_a_token_is_addressed_to_is_answered_in_full() {
    let srv = server_with_resource_server().await;
    let issued = token_for_resources(&srv, &[RS_MINE]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("other-app"),
            Some(OTHER_CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("the addressed resource server must get an answer");

    assert!(
        resp.active,
        "RFC 7662 s1: this is the caller the endpoint exists for, asking about a live token \
         addressed to it"
    );
    // s2.2. `sub` is the member the whole exchange is for: a resource server that cannot identify
    // the user cannot do per-user access control, and would be reduced to trusting the client's
    // word, which is what introspection replaces. The privacy control on it (s5) is the
    // authorization check above -- a resource server only ever learns about tokens minted for it
    // -- rather than redaction of a member the RFC defines.
    assert_eq!(resp.sub.as_deref(), Some("user-1"));
    assert_eq!(resp.scope.as_deref(), Some("read"));
    assert_eq!(
        resp.client_id.as_deref(),
        Some("confidential-app"),
        "RFC 7662 s2.2: the resource server needs to know which client is calling it"
    );
    assert!(resp.exp.is_some(), "RFC 7662 s2.2: exp for an active token");
    assert_eq!(resp.iss.as_deref(), Some("https://as.example"));
}

/// RFC 7662 s5, and the ONE member the two viewpoints do not share. A token good at two resource
/// servers tells each of them only about ITSELF. The rest of `aud` is a list of the other services
/// this user's token works at, and disclosing it to a third party describes the shape of somebody's
/// account to a party with no part in it.
#[tokio::test]
async fn a_resource_server_sees_only_its_own_identifier_in_aud_not_its_co_audiences() {
    let srv = server_with_resource_server().await;
    let issued = token_for_resources(&srv, &[RS_MINE, RS_THEIRS]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("other-app"),
            Some(OTHER_CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("the token names this resource server, so it is answered");

    assert!(resp.active, "the token does name {RS_MINE}");
    assert_eq!(
        resp.aud.as_deref(),
        Some(&[RS_MINE.to_string()][..]),
        "RFC 7662 s5: {RS_THEIRS} is none of {RS_MINE}'s business"
    );
}

/// The vice-versa, which is what stops the narrowing above from being applied to everybody. The
/// token's OWN client asked for both resources and already holds the token; reporting a narrowed
/// `aud` to it would be a false statement about its own grant.
#[tokio::test]
async fn the_owning_client_still_sees_every_resource_its_grant_was_narrowed_to() {
    let srv = server_with_resource_server().await;
    let issued = token_for_resources(&srv, &[RS_MINE, RS_THEIRS]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("the owning client must still be answered");

    assert!(resp.active);
    assert_eq!(
        resp.aud.as_deref(),
        Some(&[RS_MINE.to_string(), RS_THEIRS.to_string()][..]),
        "the owning client's own grant is not narrowed to it"
    );
}

/// Ownership outranks the resource-server role. A client that is both the token's own client and a
/// registered resource server must get the OWNER's document, or adding a resource-server
/// registration would silently narrow what a client can learn about its own tokens.
#[tokio::test]
async fn a_client_that_is_also_a_resource_server_reads_its_own_token_as_the_owner() {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.resource_servers = Some(Box::new([ResourceServerRegistration::new(
        ClientId::new("confidential-app"),
        [RS_MINE],
    )]));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(confidential_client()).await.unwrap();
    let issued = token_for_resources(&srv, &[RS_MINE, RS_THEIRS]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("the owning client must be answered");

    assert_eq!(
        resp.aud.as_deref(),
        Some(&[RS_MINE.to_string(), RS_THEIRS.to_string()][..]),
        "ownership is the wider document and wins; the resource-server role must not take away \
         what a client may learn about a token it holds"
    );
}

/// RFC 9396 s9.2, and the member that re-disclosed what the `aud` narrowing above suppresses.
///
/// A section 2.2 element carries `locations`, which NAMES RESOURCE SERVERS BY URI. Handing a
/// resource server the whole array tells it every other service this grant reaches, together with
/// the actions and privileges granted there -- the same sentence the `aud` narrowing refuses to
/// say, said in a different member and with more detail attached. Section 9.2 is explicit that the
/// details are "filtered and extended for the RS making the introspection request".
#[cfg(feature = "rar")]
mod details {
    use super::*;
    use oauth_as::rar::AuthorizationDetail;

    const MINE: &str = "payment_initiation";
    const THEIRS: &str = "account_information";
    const UNLOCATED: &str = "customer_information";

    /// One element for each of the three cases the filter has to tell apart: named at this resource
    /// server, named at another, and named nowhere at all.
    const DETAILS: &str = r#"[
        {"type":"payment_initiation","actions":["initiate"],"locations":["https://api.example/"],"identifier":"acct-1"},
        {"type":"account_information","actions":["list","balance"],"locations":["https://payroll.example/"],"identifier":"salary-1"},
        {"type":"customer_information","actions":["read"]}
    ]"#;

    /// The same server as the suite above, additionally told which RFC 9396 types it speaks --
    /// without that, section 5 makes every element `invalid_authorization_details`.
    async fn server_with_rar() -> AuthorizationServer<MemoryStorage, ManualClock> {
        let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        cfg.resource_servers = Some(Box::new([ResourceServerRegistration::new(
            ClientId::new("other-app"),
            [RS_MINE],
        )]));
        cfg.authorization_details_types_supported = Some(vec![
            MINE.to_string(),
            THEIRS.to_string(),
            UNLOCATED.to_string(),
        ]);
        let srv =
            AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
        for c in [confidential_client(), other_confidential_client()] {
            srv.register_client(c).await.unwrap();
        }
        srv
    }

    /// A token for `confidential-app`, addressed to both resource servers and carrying `details`,
    /// on the one scope the detail tests do not care about.
    async fn token_with_details(
        srv: &AuthorizationServer<MemoryStorage, ManualClock>,
        details: &str,
    ) -> TokenResponse {
        token_with_details_and_scope(srv, details, "read").await
    }

    /// The same, with the grant's scope set spelled out. Split from `token_with_details` for
    /// `the_resource_server_still_sees_the_whole_scope_set`, which cannot say anything about
    /// "whole" against a one-element set.
    async fn token_with_details_and_scope(
        srv: &AuthorizationServer<MemoryStorage, ManualClock>,
        details: &str,
        scope: &str,
    ) -> TokenResponse {
        let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
        let validated = srv
            .validate_authorization_request(&AuthorizationRequest::from_pairs(vec![
                ("response_type", "code"),
                ("client_id", "confidential-app"),
                ("redirect_uri", CONFIDENTIAL_REDIRECT),
                ("scope", scope),
                ("resource", RS_MINE),
                ("resource", RS_THEIRS),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("authorization_details", details),
            ]))
            .await
            .expect("fixture authorization request must validate");
        let code = srv
            .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
            .await
            .expect("fixture code issuance must succeed");
        srv.token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: code.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("fixture code redemption must succeed")
    }

    async fn introspected_as(
        srv: &AuthorizationServer<MemoryStorage, ManualClock>,
        client_id: &str,
        secret: &str,
        access_token: &str,
    ) -> Vec<AuthorizationDetail> {
        let resp = srv
            .introspection_response(&ClientId::new(client_id), Some(secret), access_token)
            .await
            .expect("an authenticated caller gets an answer");
        assert!(resp.active, "the fixture token is live and addressed here");
        resp.authorization_details.as_slice().to_vec()
    }

    /// The disclosure itself. An element whose `locations` names ONLY another resource server is
    /// not this resource server's business, and it is the `aud` narrowing's own sentence: telling
    /// api.example that this grant also authorizes two actions at payroll.example describes the
    /// shape of somebody's account to a party with no part in it.
    ///
    /// An element with NO `locations` is kept. Section 2.2 makes the member optional, so an absent
    /// one is not a statement that the element belongs elsewhere, and dropping it would hide from
    /// the only party that can enforce it a detail the resource owner did approve.
    #[tokio::test]
    async fn a_resource_server_is_not_told_the_details_that_name_only_another_resource_server() {
        let srv = server_with_rar().await;
        let issued = token_with_details(&srv, DETAILS).await;

        let seen = introspected_as(
            &srv,
            "other-app",
            OTHER_CONFIDENTIAL_SECRET,
            &issued.access_token,
        )
        .await;

        let types: Vec<&str> = seen.iter().map(|d| &*d.detail_type).collect();
        assert_eq!(
            types,
            vec![MINE, UNLOCATED],
            "RFC 9396 s9.2: filtered for the RS making the request. {THEIRS} is located at \
             {RS_THEIRS} and naming it here re-discloses exactly what the `aud` narrowing refuses \
             to say"
        );
    }

    /// The second half, and the one a filter over whole elements would miss. An element that names
    /// this resource server AND another still carries the other one's URI in its own `locations`,
    /// so the element is narrowed as well as kept.
    #[tokio::test]
    async fn a_kept_detail_does_not_carry_the_co_locations_of_the_element_it_came_from() {
        let srv = server_with_rar().await;
        let issued = token_with_details(
            &srv,
            r#"[{"type":"payment_initiation","actions":["initiate"],"locations":["https://api.example/","https://payroll.example/"],"identifier":"acct-1"}]"#,
        )
        .await;

        let seen = introspected_as(
            &srv,
            "other-app",
            OTHER_CONFIDENTIAL_SECRET,
            &issued.access_token,
        )
        .await;

        assert_eq!(seen.len(), 1, "the element does name {RS_MINE}");
        assert_eq!(
            seen[0].locations.iter().map(|l| &**l).collect::<Vec<_>>(),
            vec![RS_MINE],
            "RFC 7662 s5: keeping the element must not smuggle {RS_THEIRS} through in its own \
             `locations`"
        );
        assert_eq!(
            seen[0].actions.iter().map(|a| &**a).collect::<Vec<_>>(),
            vec!["initiate"],
            "only `locations` is narrowed: everything else is what was granted here"
        );
    }

    /// The vice-versa, exactly as for `aud`. The owning client asked for these details, approved
    /// them and holds the token; a filtered array would be a false statement about its own grant,
    /// and it is the only caller that can tell "not granted" from "not for you".
    #[tokio::test]
    async fn the_owning_client_still_sees_every_detail_its_grant_carries() {
        let srv = server_with_rar().await;
        let issued = token_with_details(&srv, DETAILS).await;

        let seen = introspected_as(
            &srv,
            "confidential-app",
            CONFIDENTIAL_SECRET,
            &issued.access_token,
        )
        .await;

        let types: Vec<&str> = seen.iter().map(|d| &*d.detail_type).collect();
        assert_eq!(types, vec![MINE, THEIRS, UNLOCATED]);
        assert_eq!(
            seen[1].locations.iter().map(|l| &**l).collect::<Vec<_>>(),
            vec![RS_THEIRS],
            "the owning client's own grant is not filtered for it"
        );
    }

    /// The members that are NOT narrowed, pinned so that the decision is a test rather than a
    /// comment. `scope` is the whole grant's scope set: this crate has no per-resource-server scope
    /// catalogue, so any filtering would be a guess, and a resource server that silently loses a
    /// scope denies access the resource owner granted. See `introspection_response`.
    ///
    /// THREE SCOPES, and that is the test rather than the fixture. This case was written against a
    /// grant whose only scope was `read` and asserted that introspection returned `read`: an answer
    /// a filter that narrowed the set to its first element, or to the ones it recognised, or to
    /// nothing but `read`, would all have produced as well. "Whole" is not a statement a
    /// one-element set can make. `read write admin` are three scopes `confidential-app` is
    /// registered for, and any narrowing of them gives a different answer here.
    #[tokio::test]
    async fn the_resource_server_still_sees_the_whole_scope_set() {
        let srv = server_with_rar().await;
        let issued = token_with_details_and_scope(&srv, DETAILS, "read write admin").await;

        let resp = srv
            .introspection_response(
                &ClientId::new("other-app"),
                Some(OTHER_CONFIDENTIAL_SECRET),
                &issued.access_token,
            )
            .await
            .expect("the addressed resource server is answered");
        let mut seen: Vec<&str> = resp
            .scope
            .as_deref()
            .expect("a grant with scopes reports them")
            .split(' ')
            .collect();
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec!["admin", "read", "write"],
            "RFC 7662 s2.2: the scope of the grant, WHOLE, because nothing here knows which scope \
             belongs to which resource server. A resource server that silently loses one denies \
             access the resource owner granted."
        );
    }
}
