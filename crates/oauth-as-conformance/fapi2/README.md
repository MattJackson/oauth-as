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
(`.github/workflows/fapi2-conformance.yml`, which also runs on every push to `qa` and gates
it; see its header).

Both read this file via the `FAPI2_CONFIG` environment variable
(default: `crates/oauth-as-conformance/fapi2/config.json`, i.e. this file), and the plan string
via `FAPI2_PLAN` / the workflow's `plan` input. See `scripts/fapi2-conformance.sh`'s header for
every other overridable variable (the suite checkout directory and pinned ref, the fixture example
name, the log directory, and `OAUTH_AS_FAPI_REDIRECT_URIS` per the alias note above).

Running the suite itself requires no OpenID Foundation membership or payment
(EXTERNAL-TOOLING.md s2.4). Only formal CERTIFICATION -- a separate manual submission at
https://submissions.openid.net/ -- does, and neither this script nor this workflow performs that
submission.

## `expected-failures.json`: recorded gaps, not passes

`expected-failures.json` in this directory is the OIDF runner's own
`--expected-failures-file` (`scripts/run-test-plan.py` at the pinned suite commit), which
`scripts/fapi2-conformance.sh` always passes (`FAPI2_EXPECTED_FAILURES`; a missing file is a
hard stop at preflight, not an empty list). It records, one entry per failing CONDITION, the
two D2 modules from `FINDINGS.md`:

* `user-rejects-authentication` (six entries: two blocks, first client and second client,
  times three conditions, two of which the suite logs at WARNING level) -- the fixture has no
  consent page to cancel; the AS `access_denied` path itself is conformant. Category fixture.
* `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (one entry; its
  `condition` is the module id, because the module throws a raw `RuntimeException` rather than
  failing a condition class) -- the fixture authenticates on the first visit AND the crate
  consumes the `request_uri` when the page loads rather than at authorization (FAPI 2.0 SP
  Final s5.3.2.2 NOTE 3, RFC 9126 s4). Category fixture and core.

An entry is a documented gap the gate keeps in front of us, with its justification in the
`comment` field and the evidence in `FINDINGS.md` D2. It is NOT a pass and it does not make the
job green (D1, D3, D4, D5 and D7 still fail). The runner's accounting cuts both ways: an
unlisted FAILURE or WARNING exits 1, and a listed condition that STOPS failing also exits 1
(`EXPECTED_FAILURES_NOT_HAPPEN` / `EXPECTED_WARNINGS_NOT_HAPPEN`), so landing a fix REQUIRES
deleting its entries, and an entry can never hide a regression elsewhere.

Rules for editing it, read from the runner's matching code:

* Every entry MUST carry all six keys: `test-name`, `variant`, `configuration-filename`,
  `condition`, `current-block`, `expected-result` (`comment` is free text the runner never
  reads). A missing key is not "ignored": the runner indexes them directly and raises at
  analysis time, AFTER the whole plan has run. The script checks the shape at preflight so that
  cannot happen thirty minutes in.
* `expected-result` must be the level the suite logs, `failure` for a FAILURE entry and
  `warning` for a WARNING entry. There is no cross-match; a mismatch counts BOTH as an
  unexpected result and as an expected one that did not happen.
* `test-name`, `condition` and `current-block` are pinned EXACTLY, and `variant` is an object.
  `"*"` is FORBIDDEN in this repository even where the runner would accept it (`test-name`,
  `current-block`, `variant`): one wildcard can swallow an unrelated regression. The preflight
  refuses it.
* `configuration-filename` is `fnmatch`ed against the config path EXACTLY as passed on the
  runner's command line, with no basename step. The script passes an absolute path
  (`$repo_root/crates/oauth-as-conformance/fapi2/config.json`; in CI that is
  `/home/runner/work/oauth-as/oauth-as/...`), so the value is the glob `*/fapi2/config.json`
  (`fnmatch`'s `*` spans `/`). A bare `config.json` never matches an absolute path; the entries
  would then be reported as "not found in any test module" and the runner exits 1 -- loudly, not
  silently.
* `variant` is subset-matched: the four plan dimensions from `FAPI2_PLAN` are listed; the
  module's extra baseline dimensions (`fapi_request_method`, `fapi_response_mode`,
  `authorization_request_type`) are left unlisted, which the runner treats as "any".
* To capture the strings for a new entry, do not guess. Run the plan, then either read the
  `--verbose` output in `target/fapi2-conformance/run.log` (it prints a ready-to-paste entry
  template per unexpected result) or read `target/fapi2-conformance/modules/<test id>.json`:
  every element with `result` FAILURE or WARNING is one entry, its `src` is the `condition`,
  and its `blockId` maps to the `msg` of the `-START-BLOCK-` element with that id, which is
  the `current-block` (empty when the element has no `blockId`).
