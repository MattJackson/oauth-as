# FAPI 2.0 suite config

`config.json` in this directory is the OIDF conformance-suite configuration for the
`fapi2-security-profile-final-test-plan[openid=plain_oauth][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]`
plan (the string derived and cited in
`crates/oauth-as-conformance/EXTERNAL-TOOLING.md` s2.1). Its field names and shapes match
`AbstractFAPI2SPFinalServerTestModule`'s `@ConfigurationFields`
(`client.client_id`, `client.jwks`, `client2.client_id`, `client2.jwks`, `resource.resourceUrl`)
and the suite's documented top-level `browser` task-list format (EXTERNAL-TOOLING.md s2.2).

Its values are now REAL, matched to the fixture
(`crates/oauth-as/examples/fapi2_conformance_server.rs`, EXTERNAL-TOOLING.md s2.3 item 1) as it
actually behaves, not guessed:

* `server.discoveryUrl`, `resource.resourceUrl` are the fixture's default issuer
  (`https://localhost.emobix.co.uk:8443`) metadata and protected-resource URLs, i.e. the fixture
  run with no environment overrides.
* `client` / `client2` are the fixture's two static `private_key_jwt` clients (`client_id`
  `"client"` / `"client2"`), each with its own DISTINCT EC P-256 key
  (`client-pkjwt-1` / `client2-pkjwt-1`). The `jwks.keys` entries include the PRIVATE `d` value
  deliberately: in this configuration field the suite itself acts as the client and signs its own
  `private_key_jwt` client assertions with that key, so it must hold the private half. This is the
  suite's copy of the fixture's hard-coded `CLIENT_KEY_SCALAR` / `CLIENT2_KEY_SCALAR`
  (`fapi2_conformance_server.rs`), not a secret that leaves the fixture -- the fixture itself only
  ever registers and holds the PUBLIC half.
* `client.scope` / `client2.scope` (`"read write offline_access"`) are drawn from the scope set
  the fixture actually registers for both clients (`openid, profile, email, read, write,
  offline_access` -- see `scope_names` in `fapi2_conformance_server.rs`); `offline_access` is
  included so the plan's refresh-token steps have something to exercise against the
  refresh-rotation-OFF switch (EXTERNAL-TOOLING.md s2.3 item 7). This plan is `openid=plain_oauth`,
  so `openid` itself is deliberately NOT requested.
* `browser` is an empty task list, deliberately. The fixture wires
  `ServiceBuilder::with_subject_resolver` to a constant subject and
  `with_approval_resolver` to an unconditional `ApprovalDecision::Approve`:

  > `with_subject_resolver` returning a constant: every request is the same user. ...
  > `with_approval_resolver` returning `Approve`: RFC 6749 s10.12 consent, DELETED. Any
  > cross-site navigation would silently issue a code for the logged-in user.

  (`fapi2_conformance_server.rs`, comment above the `ServiceBuilder::new(...)` call). There is no
  login form and no consent screen for the suite's headless HtmlUnit browser to click through --
  every valid authorization request is approved server-side, and the browser only needs to follow
  the redirect chain the AS itself issues. Do not add `click`/`text` commands here unless the
  fixture grows an actual interactive page; there is nothing on it today to select.

## Alias and redirect URI

The one thing left for an operator to check before a run: the OIDF suite derives each test
instance's callback URL from `alias` as
`https://localhost.emobix.co.uk:8443/test/a/<alias>/callback`. With `alias` set to
`oauth-as-fapi2-plain-oauth` (as above), that is
`https://localhost.emobix.co.uk:8443/test/a/oauth-as-fapi2-plain-oauth/callback` -- which does
NOT match the fixture's own default redirect URI. The fixture defaults
`OAUTH_AS_FAPI_REDIRECT_URIS` to `{issuer}/test/a/oauth-as/callback` (see the doc comment at the
top of `fapi2_conformance_server.rs`), a shorter path chosen before this file's `alias` was
settled.

Before running the suite against this `alias`, start the fixture with the matching redirect URI
override:

```
OAUTH_AS_FAPI_REDIRECT_URIS=https://localhost.emobix.co.uk:8443/test/a/oauth-as-fapi2-plain-oauth/callback \
  cargo run --example fapi2_conformance_server -p oauth-as
```

(If `alias` is ever changed in `config.json`, update this environment variable to match --
FAPI 2.0 requires exact redirect URI matching, so the two sides must agree exactly, the same way
the client keys on each side are matched to each other.)

## Running it

```
scripts/fapi2-conformance.sh
```

or, from the Actions tab: **Actions -> FAPI 2.0 conformance -> Run workflow**
(`.github/workflows/fapi2-conformance.yml`, `workflow_dispatch` only, never on push).

Both read this file via the `FAPI2_CONFIG` environment variable
(default: `crates/oauth-as-conformance/fapi2/config.json`, i.e. this file), and the plan string
via `FAPI2_PLAN` / the workflow's `plan` input. See `scripts/fapi2-conformance.sh`'s header for
every other overridable variable (the suite checkout directory and pinned ref, the fixture example
name, the log directory, and `OAUTH_AS_FAPI_REDIRECT_URIS` per the alias note above).

Running the suite itself requires no OpenID Foundation membership or payment
(EXTERNAL-TOOLING.md s2.4). Only formal CERTIFICATION -- a separate manual submission at
https://submissions.openid.net/ -- does, and neither this script nor this workflow performs that
submission.
