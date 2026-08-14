# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Publishing note, so this file is not read out of context: the crate publishes to
crates.io at **0.9.0**, not 0.1.0. Versions 0.1.0 through 0.8.0 are built, tested, and pushed
through the `dev` -> `qa` -> `main` promotion pipeline, but they are not published; only 0.0.1 and
whatever version is current at each real crates.io release appear as published on crates.io.

## [0.9.2] - 2026-08-14

### Added: RFC 7662 introspection answers a RESOURCE SERVER

0.9.1 made the documentation honest about this; 0.9.2 makes it unnecessary. Through 0.9.1 this
server answered introspection only for the token's own client, and roughly twenty places in the
source said so in writing and named this release. Those sentences are gone, because the thing they
described is gone.

A resource server authenticates as an ordinary confidential client, through the same client
authentication every other endpoint uses: `client_secret_basic`, `client_secret_post`,
`private_key_jwt`, `client_secret_jwt`, mTLS. There is no new principal and no new credential type,
deliberately — a second credential path is a second place to get constant-time comparison, rotation
and revocation right. What makes a client ALSO a resource server is a deployment statement, the new
`ServerConfig::resource_servers`.

**Which tokens an RS may read.** Only those whose RFC 8707 `resource` set names one of its
registered identifiers. Anything else answers `{"active": false}` — never an error, because an
error channel that distinguishes "not yours" from "not a token" is the same scanning oracle by
another route. **A token whose grant named no resource at all is refused to every resource server**:
an empty set means "restricted to nothing in particular", and reading that as "so anyone may ask"
would expose every token that never used RFC 8707, which is most of them.

**What differs from what the owning client sees: the two members that name OTHER SERVICES,**
`aud` and `authorization_details`, each narrowed to the RS that asked. The rest of that set names
the other services a user's token works at, and handing it to a third party describes the shape of
someone's account (RFC 7662 section 5). Everything else, `sub` included, goes to both — a resource
server that cannot identify the user cannot do per-user access control, which is what it is
introspecting for. See the "Fixed" entry below for why the second member is on that list.

`introspection_endpoint` stays `Option<String>` and is still advertised only where the host names
it. 0.9.1 recorded an intent to make it unconditional again once this landed; that is deliberately
NOT done. The capability is configuration-dependent in a way that sentence did not anticipate — a
deployment that registers no resource server still answers only the token's own client, so
advertising unconditionally would restore the original false claim for exactly the deployments the
0.9.1 change was written to protect.

### Added: a per-`client_id` client-authentication capacity, because a resource server is not a client

`RateLimitConfig::with_client_authentication_capacity_for` and the
`client_authentication_capacity_overrides` field behind it: one `client_id` gets its own
`Attempt::ClientAuthentication` ceiling, everybody else stays on
`client_authentication_capacity`. The failure reserve moves with it, derived from whichever
capacity applies rather than from the global one.

This exists because of the introspection entry above. **A resource server authenticates once per
call at the protected resource it guards**, not once per grant, and that traffic is charged to the
same per-`client_id` budget a client's token requests are. The 6000-a-minute default was derived
from a client's token traffic — the module docs defended it as "above the rate at which a single
client's token traffic on a single node is already an architecture discussion", which is true of a
client and is not true of an API. Left at the default, registering a resource server caps that
protected resource at 100 requests a second per node.

**And it does not look like a throttle when it bites.** Introspection over the ceiling is refused
with a bare `invalid_client`, the same answer a wrong secret gets, deliberately — a distinct code
would tell an attacker they had found a live client id. A resource server failing closed then
refuses every request it is handling, and its operator is reading what looks like a credential
fault. The audit channel is where the two separate: `Event::ClientAuthenticationFailed` carries
`ClientAuthFailure::RateLimited` for a throttle and `ClientAuthFailure::SecretMismatch` for a
credential that did not verify. `ServerConfig::resource_servers`, the `rate_limit` module docs and
`Attempt::ClientAuthentication` all now say this; before, none of them did.

**Why an override and not a global raise.** The per-`client_id` ceiling is what bounds how many
WRONG SECRETS one identifier can push through the host's secret verifier in a window — 3000 at the
defaults, each of which can cost an argon2id. Advice to raise `client_authentication_capacity`
twentyfold would raise that for every registration an attacker can name, to buy headroom one of
them needed.

**Why there is no `Attempt::Introspection`.** `Attempt` is `#[non_exhaustive]`, so adding a variant
compiles everywhere — and lands in the wildcard arm of every host `RateLimiter` already written. A
wildcard answering `Allow`, which is the ordinary shape for "budgets I have not configured", would
silently stop throttling introspection altogether on upgrade: bounded to unbounded, with no
compiler error and no log line. A ceiling that is too low and says so is the better failure.

An override never applies to the shared overflow counter — an identifier that did not get a counter
of its own, because the tracked map was full or because it is longer than
`MAX_TRACKED_CLIENT_ID_LEN`, is charged the shared capacity whatever its override says. That
counter is spent by several identifiers at once and cannot carry any one of their exceptions.

### Added: `cimd`, a client identifier metadata document VALIDATOR

draft-ietf-oauth-client-id-metadata-document-**01**, behind a new off-by-default `cimd` feature,
the sixteenth. The revision matters: every section number the module cites is -01's, and -02
(2026-07-06) reorganised the document without changing the rules, so the module header carries a
table mapping each citation onto its -02 number. **This crate does not fetch.** The host fetches
the document at the client-id URL and hands the bytes over; the crate validates them and turns them
into a `Client`. That is the same
posture as every other seam here — the host owns the listener, the signer, the clock — and it is a
design position rather than a gap to close later: a library embedded in someone else's server does
not get to open sockets on its own initiative.

The security property is one comparison: the document's own `client_id` must equal the URL it was
fetched from, byte for byte, normalising nothing. Without it, any document authorizes any client.
`ValidatedClientIdDocument` and `ClientIdUrl` have private fields and no public constructor, so
neither can exist except as the output of validation — which makes the specification's "never cache
an invalid document" structural rather than a rule somebody has to remember.

Redirect URIs, grant and response types, auth method and the scope ceiling are validated by the
same function the RFC 7591 dynamic registration path uses, not a second copy of it.

Two readings are worth stating because a future reader will otherwise assume the opposite. An
absent `token_endpoint_auth_method` is taken as `none`, not RFC 7591 section 2's
`client_secret_basic` default, which the draft forbids — read literally, the two together refuse
every document that omits the member. And `client_id_metadata_document_supported` is derived from
the host's configuration, not from whether the feature was compiled in: compiling a validator does
not mean a deployment performs the fetch, and advertising on the strength of a `cfg` would claim a
capability the build always refuses.

### Changed: `ScopeSet` is a sorted `Vec`, not a `BTreeSet`

No API change — the field is private and the invariant, sorted and deduplicated, is unchanged, so
`Display`, `Serialize`, `PartialEq` and `is_subset` answer exactly as before.

It is in the changelog because of what it costs a deployment. A `BTreeSet` allocates a whole leaf
node the moment it holds anything, and that node is the same size for one scope token as for
eleven, while a real scope set holds one to five short words. Measured, resident bytes per record:
access token 688 to 432, refresh token 723 to 491, authorization code 1066 to 834, consent record
573 to 341, device grant 1009 to 753. **A store holding 10,000 access tokens drops from 6,719 KiB
to 4,218 KiB.** The linked binary drops 15,394 bytes on the default feature set, which is every
`BTreeMap` instantiation the type dragged in.

It is also faster from a hundred tokens up (81.09 to 48.68 microseconds at a thousand) and slightly
slower below that — 32 to 39 nanoseconds at one token, which buys the single correctly-sized
allocation the rest of the table rests on.

### Changed: every client-authentication refusal now leaves through ONE exit that charges

A structural fix for a defect class that four previous releases each fixed one site at a time. The
costly property was never that the function branches; it is that the branches were also the EXITS,
so every refusal had to remember to charge for verification work it had skipped, and each new
refusal path was a new opportunity to forget. Four rounds of audit found four different sites.

Refusals are now values rather than early returns, what was actually spent is tracked in a ledger,
and one function charges for whatever the presented credential has not paid for — deciding from the
PRESENTED credential and never from the registration, which is the property that makes a known
client id cost what an unknown one costs. The refusal exits went from six, with eight scattered
charge sites, to one. It is reviewable by counting exits, which is the point of doing it this way.

**One residual is preserved rather than closed, and pinned by a test so it cannot be forgotten.**
A client registered for RFC 7523 that presents an assertion malformed enough to be refused before
any signature work pays less than an unknown client id sending the same bytes. Closing it needs the
assertion verifier to report whether it reached the signature, which is a public API change; the
alternative — inferring it from the failure variant — is exactly the kind of coupling kept in step
by a comment that this restructure exists to remove.

### Changed: four `Debug` impls stopped printing the credential they carry

`ClientCredential`, `AuthorizationResponse`, `PushedAuthorizationResponse` (under `par`) and
`CompactJws` (under `jwt`) had derived `Debug`, so `{:?}` on any of them wrote a live credential
into whatever the host logs. Each now redacts, and a host feels this the moment it prints one of
them: the value it used to see is `"[redacted]"`.

Which is the point. The RECORD forms of two of these have been hand-redacted since they were
written — `AuthorizationCodeRecord` because RFC 6749 section 4.1.2 makes a code a credential in its
own right, the stored pushed request because RFC 9126 section 7.1 makes the `request_uri` a
capability while it is live — and the RESPONSE forms, which carry the same string outward to the
client, were left deriving. `ClientCredential` is the one a host builds by hand and passes in, so
it is also the one most likely to appear in a host's own tracing on the path that refused it: it
carries the shared secret and the RFC 7523 assertion. `CompactJws` is worse than it looks, because
its `signing_input` and `signature` together rebuild the whole token: printing a refused DPoP proof
or client assertion yielded a bearer credential still live until its `exp`, and `jti` single-use
only bounds a proof that was ACCEPTED.

**What still prints is what an operator debugging a refusal actually needs**, and that is the line
each impl draws rather than blanket opacity. `ClientCredential` keeps the `Some`/`None` shape,
because WHICH credential a request presented is a diagnostic and is not itself secret, and
`client_assertion_type` prints in full because RFC 7521 section 4.2 makes it a fixed registered
URN. `AuthorizationResponse` keeps `state` (the client's own opaque value) and `iss` (this server's
public identifier). `PushedAuthorizationResponse` keeps `expires_in`. `CompactJws` keeps the
decoded `header` and `payload` — which `alg`, which `iss`, which `aud` — because what makes a token
spendable is the signature over the exact input bytes, and that is what is withheld.

### Added: `ResourceServerRegistration` is `#[non_exhaustive]`, sealed in the release that introduces it

A host writes `ResourceServerRegistration::new(client_id, resources)` rather than a struct literal.

The attribute cannot be added after publication, because by then the literal is in somebody's
production tree and adding it is the breaking change it exists to prevent. This is a DEPLOYMENT
POLICY object for a channel that will grow — a per-RS claim filter, a per-RS introspection policy
and a `token_endpoint_auth_method` constraint are all plausible next fields — and each of those
would be a major-version event if a host could write the literal. Its sibling `CimdPolicy` is
sealed for the same reason and says so in the same terms.

Worth stating because the `tests/host_api_shape.rs` gate does not catch this one, and is not wrong
to miss it: that scan flags types whose field set VARIES WITH A CARGO FEATURE, and this one's does
not. The rule the crate follows is broader than the gate that enforces part of it.

### Added: RFC 9470 step-up reaches a resource server by both routes

`acr` and `auth_time` are now claims in the signed RFC 9068 access token, under the `consent`
feature, alongside the RFC 7662 introspection members that already carried them.

RFC 9470 section 6 has exactly two subsections because a token reaches a resource server in exactly
two ways, and this crate answered one of them. Section 6.2 is introspection, which is all an OPAQUE
token has; section 6.1 is the JWT, which is read OFFLINE by a resource server that never
introspects at all. The party that needs this is the resource server that SENT the section 3
`insufficient_user_authentication` challenge and now has to decide whether the token in front of it
answers it — and on the JWT route that server had nothing in the token to decide with. It could
only take the client's word for the step-up, which is the whole thing the challenge exists to
avoid. Same shape as the RFC 8693 `act` claim in 0.9.1, and the same argument.

What a host feels: nothing to change, and one member appears in tokens issued by a build with both
`consent` and `jwt` when the host reported an authentication for the grant. `AccessTokenClaims` is
`#[non_exhaustive]` with an `AccessTokenClaims::new` that takes the seven RFC 9068 section 2.2
REQUIRED claims, so the two new fields are NOT a breaking change for a host that constructs one:
a host outside this crate could never have used a struct literal, and `new` fills them with `None`.
Both are omitted rather than sent as `null` when the host reported nothing, and both are answered
from the same stored report, through the same conversion, that introspection answers from, so the
two channels cannot state different things about one token. A refreshed token still states the
ORIGINAL `auth_time`: a rotation is not a new login, and restamping it would let any client defeat
any `max_age` by refreshing.

### Fixed: two HTTP doors accepted `authorization_details` and dropped it

RFC 9396 section 5 requires an authorization server to REFUSE an `authorization_details` it will
not honour. The core refuses at every door where the parameter reaches it; two doors of the `http`
service are the only place the request exists, and they were silently dropping it:

- `POST /device_authorization`. RFC 9396 section 3 names the RFC 8628 device authorization request
  explicitly as a place the parameter may be used, and this crate's `DeviceGrant` has no field for
  one. The request was accepted and the client was handed a `user_code` for a permission that could
  never appear on the token.
- `POST /token` under `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. That grant
  answers from its own arm of the router and returns before the token endpoint's shared parameter
  handling, so the SAME POST to the SAME URL refused for `authorization_code` and dropped for the
  exchange.

Both now answer `invalid_authorization_details`, before the credential and before the grant, so the
client is told which parameter is wrong rather than being answered about whatever was checked
first. The refusals are UNGATED, unlike the core's: there the answer turns on whether the build
supports any detail TYPE, here it turns on the GRANT, which has nowhere to put a detail whether the
type is supported or not — `AuthorizationServer::token` already refuses to mint detail for a device
grant under `rar` for exactly this reason.

What a host feels: a client that was sending this parameter to either endpoint and having it
dropped now gets a 400 naming the parameter. That is the point; the token it was getting did not
say what it believed it said.

### Fixed: a client identifier metadata document offering a key was accepted with the key dropped

`cimd` refused a document carrying `client_secret` — on the stated reasoning that dropping a member
the client believes is being honoured registers a client on terms nobody agreed to — and then did
the opposite with `jwks` and `jwks_uri`. Neither member is modelled by `ClientMetadata`, and the
document type flattens into it without denying unknown fields, so `serde` dropped them silently and
`to_client()` returned an unconditional `ClientAuth::Public`. A client that published a key and
believed it authenticated with it was registered as a client that authenticates with nothing, and
was told so nowhere.

Both members are now REFUSED, with a new `CimdError::KeyMaterialPresent`. This is the one refusal
in that enum that is a property of this BUILD rather than of the draft — the draft PERMITS public
keys, and a public key is the only credential a world-readable document can carry — but this crate
cannot register a client key at all (`registration` models neither member and refuses
`private_key_jwt` outright), so accepting the document would produce a public client out of a
document asking to be a confidential one. `CimdError` is `#[non_exhaustive]`, so when the
`jwks`/`jwks_uri` gap closes, removing this refusal is a patch release.

It also happens to be where the draft's MUST NOT on PRIVATE key material becomes reachable: a
private JWK arrives inside `jwks`, and before this it was parsed away and never seen. Nothing else
in the module inspected it, and nothing needs to — the whole member is the refusal either way.

### Fixed: introspection told a caller which client ids are registered

RFC 7662 introspection refused a PUBLIC client with an `invalid_client` carrying the description
`"introspection requires a confidential client"`, while an unknown client id and a confidential
client presenting the wrong secret both got a BARE `invalid_client` with no description at all. So
the description was the one answer meaning "this client id is registered, and it is public" — the
client-existence distinction the whole credential path collapses on purpose, rebuilt one endpoint
downstream of it, one probe per candidate id.

Pre-existing rather than introduced here, but 0.9.2 turns introspection into an advertised
resource-server-facing surface, which is what makes it worth a release note: the probe is now one a
deployment invites. All THREE sites of the shape now answer with a bare `invalid_client`,
byte-identical to the unknown-id and wrong-secret answers — introspection, the RFC 6749 section 4.4
client credentials grant (which the introspection comment cites as its authority for the refusal),
and RFC 8693 token exchange under the `token-exchange` feature. Each was reachable by a caller
presenting NO credential at all, because a public registration authenticates trivially. The
neighbouring `unauthorized_client` refusals are NOT the same exposure and are unchanged: reaching
one requires having already proved a confidential credential.

The reason did not vanish, it moved to the channel where the reader is not the attacker: a new
`ClientAuthFailure::NotConfidential` reaches the host's event sink as
`Event::ClientAuthenticationFailed`. That matters because the usual cause here is a resource server
registered with the wrong `token_endpoint_auth_method` rather than an attack, and a bare refusal
with nothing in the log would be unactionable. `ClientAuthFailure` is `#[non_exhaustive]`, so the
new variant is not a breaking change for a host that matches on it. The rate limiter is not charged
a second time: client authentication has already recorded this attempt's outcome.

### Fixed: RFC 7592 registration management was unthrottled

`read_registration`, `update_registration` and `delete_registration` share one
`authenticate_registration`, and it took no `Attempt` at all, so a host that had installed a
`RateLimiter` still had this plane wide open. The crate's own note beside that function said the
host "is expected to throttle anyway" — advice the host could not take through this crate, because
nothing reached the seam. That is the doc-truth failure this project keeps finding, and the
enumeration in `crates/oauth-as/src/rate_limit.rs` of what is unthrottled has been corrected with
it rather than left to rot.

The attempt is `Attempt::ClientAuthentication`, keyed on the `client_id` being managed — the SAME
budget the token endpoint spends, not a new one. It is the same question (may this caller keep
presenting credentials as this client), the registration access token is the more powerful of that
client's two bearer credentials since it REWRITES and DELETES the registration, and one budget is
the answer that cannot be walked around by moving from one endpoint to the other. It also adds no
new denial of service: that budget is already keyed on a `client_id` RFC 6749 section 2.2 makes
public, so anyone who could exhaust it here could already exhaust it by spraying wrong secrets at
the token endpoint.

The limiter is asked BEFORE the store is touched, so a throttled `DELETE` deletes nothing, and its
refusal is the same `Unauthorized` a wrong token gets, so the throttle is not an oracle telling an
attacker they found a live registration. Outcomes are reported, so a failure-weighted limiter
charges a wrong registration access token what a guess costs and a correct one what a request
costs.

What a host feels: a host with no limiter installed is unaffected (the seam's default is Allow). A
host with one now has RFC 7592 management counted against its per-client budget — including,
deliberately, its own clients' legitimate management traffic, which is small.

### Fixed: the introspection `aud` narrowing was undone by the member next to it

The resource-server channel above narrows `aud` so that api.example is not told this token also
works at payroll.example. It then handed the same resource server the whole
`authorization_details` array — and an RFC 9396 section 2.2 element has `locations`, which NAMES
RESOURCE SERVERS BY URI. The sentence the narrowing refused to say was said in full by the member
beside it, with the actions and privileges granted at those other services attached. The policy
was written in a comment and not implemented.

`authorization_details` is now filtered for the asking resource server, which is what RFC 9396
section 9.2 asks for in those words: "filtered and extended for the RS making the introspection
request". An element whose `locations` names one of that RS's registered identifiers is kept, with
its `locations` reduced to the intersection, so an element addressed to two resource servers no
longer hands each of them the other's URI. An element with no `locations` is kept: section 2.2
makes the member optional, so its absence is not a statement that the element belongs elsewhere,
and dropping it would withhold an approved detail from the only party that can enforce it.
Everything else is dropped.

The other resolution — stop narrowing `aud`, and call a registered resource server a semi-trusted
party that sees the grant as granted — was considered and rejected. A resource server is registered
for the identifiers it answers for and nothing wider, so under that reading a deployment adding a
second protected resource would be quietly telling the first one about it, and the person who pays
is the user, who is not in the room.

`scope` and `act` are deliberately NOT narrowed, and the reasoning is now in the method's
documentation rather than implied by its silence. Nothing here maps a scope to a resource server,
so filtering would be a guess, and a resource server that silently loses a scope refuses access the
resource owner granted; `act` says who is acting in the call being made, not where else the grant
reaches.

What a host feels: nothing, unless it has set `ServerConfig::resource_servers` AND its grants carry
`authorization_details` with `locations`. Those resource servers now receive a shorter array. The
cost is real and worth naming — a filtered array cannot distinguish "not granted" from "not for
you" — but both readings oblige the resource server to refuse, which is the harmless direction, and
the disclosure direction has no such symmetry. The token's OWN client, and a host calling
`AuthorizationServer::introspect`, still see the record whole.

### Fixed: `AuthorizationResponse` lost its rustdoc, and `redirect` named the wrong open door

Two documentation defects that a reader acts on. The doc comment explaining why
`AuthorizationResponse` hand-writes `Debug` — the paragraph added earlier in 0.9.2 — was written
above the `impl` rather than above the struct, which left the public type with NO rendered
documentation at all and the crate's `#![warn(missing_docs)]` firing on it. The struct's half is
back on the struct.

And the note beside `crate::http`'s `redirect` explained the reachable `HeaderValue::from_str`
failure by saying "only the RFC 7591 dynamic path validates [the redirect URI] — a host calling
`register_client` directly supplies a bare `Vec<String>`". `register_client` validates, through the
same predicate, and has since 0.9.1. The conclusion was right and the mechanism was wrong, which
sends whoever meets the 500 to a door that is shut. The open one is below both registration APIs:
`Storage::put_client` and `Storage::compare_and_swap_client` take a `Client` as given, so a host
that provisions by writing rows puts a `redirect_uris` entry into circulation that no validator in
this crate ever saw. `tests/authorization_code.rs` now pins that asymmetry, so the corrected
sentence cannot drift back.

### Fixed: RFC 7591 registration parsed a stranger's JSON before it asked the throttle

`POST {registration_endpoint}` ran `serde_json::from_slice` over up to `MAX_BODY_BYTES` (64 KiB)
and only then reached `register_dynamic_client`, where `Attempt::ClientRegistration` is consulted.
An anonymous caller therefore set the rate at which this server parsed 64 KiB documents, which is
the shape the comment beside `MAX_FORM_PARAMETERS` argues against: a refusal is work an attacker
sets the rate of. This is the residual of the class the RFC 7592 `PUT` handler fixed one function
down — that handler authenticates first, and RFC 7591 s3.1 registration may be ANONYMOUS, so there
is no credential to check first here. There did not need to be: the throttle is keyed on nothing at
all, and nothing stopped it being asked first.

The HTTP handler now asks it before the parse. The refusal is byte-for-byte the one a throttled
registration already got (`401` with `WWW-Authenticate: Bearer` and no body), so no caller can
learn from the wire whether its document parsed, and a deployment with registration disabled still
answers `Disabled` rather than spending budget on an endpoint it does not serve.

The throttle is asked exactly ONCE per request, which is the difference from how the RFC 7592 `PUT`
handler is arranged: that plane's budget is per-`client_id` at 6000 a window and can afford a
second check, while this one is GLOBAL at 60, where a second charge would silently halve a host's
configured ceiling. `register_dynamic_client` is internally two halves to make that possible.

What a host feels: nothing, unless it had installed a `RateLimiter` that denies
`Attempt::ClientRegistration`, in which case a throttled registration is now refused without its
body being read. `AuthorizationServer::register_dynamic_client` is unchanged for a host calling it
directly — same signature, same throttle, same order.

### Documented: `Storage::get_client` is handed an ATTACKER-CHOSEN identifier

`ClientId::new` validates nothing (RFC 6749 section 2.2 leaves the syntax to the server, and a host
names its own clients), so the value arriving at a host-implemented `Storage::get_client` is a
string an unauthenticated stranger picked. The trait never said so. It does now, on `get_client`,
naming the routes it arrives from and — for the RFC 7592 management route, whose segment is
percent-decoded — the exact shapes that decode produces: `%2F` becomes a real `/`, `%2E%2E` becomes
`..`, `%00` becomes a NUL, and invalid UTF-8 becomes U+FFFD, because the decode is lossy.

Nothing is refused, and that is the decision rather than an omission. Routing is settled on the RAW
path before any decoding, so no request can reach an endpoint mounted under the registration
endpoint. A host whose client ids are HTTPS URLs has a `/` in every one of them, so refusing the
character would break a legitimate naming scheme. And it is not a shape unique to that route: the
authorization and token endpoints hand the same seam an arbitrary unauthenticated string, so
validating the RFC 7592 segment alone would close nothing while suggesting to a host that something
had been closed. `crates/oauth-as/tests/storage_client_id_contract.rs` pins all of it, that last
point included.

A store using the id as an opaque key — a `HashMap`, a parameterised query, a key-value `GET`, so
both `MemoryStorage` and `oauth-as-postgres` — is unaffected. A store that interpolates it into a
filesystem path, an object key, an LDAP filter or SQL text must encode or reject it itself;
answering `Ok(None)` for an id its own scheme could not have minted is always safe.

### Documented: the RFC 7591/7592 plane is not cancellation safe either, and one drop is unrecoverable

`AuthorizationServer::token` and `AuthorizationServer::revoke` carry a stated cancellation
contract; `register_dynamic_client`, `update_registration` and `delete_registration` carried
nothing, in the release that finally took this plane seriously enough to throttle it. They now
carry one, and the cost is not the same as the token plane's.

The sharp one is `update_registration`. When an update moves a client to an auth method that needs
a secret it MINTS one, writes the hash through `compare_and_swap_client`, and returns the secret
itself only at the end of the function. A future dropped after that swap resolves leaves the store
holding a verifier for a string that exists nowhere — and the client's retry cannot repair it,
because the stored registration is now confidential, so the second pass takes the arm that KEEPS
the existing verifier rather than minting again. That arm is right for what it was written for (a
metadata edit must not log a client out) and nothing on the wire tells the two cases apart. The
only way out is RFC 7592 section 2.3: the registration access token is never rotated by an update,
so the client can delete and register afresh. `register_dynamic_client` has the same shape at
`put_client`, where a drop strands a permanent row whose registration access token — and, for a
confidential registration, whose client secret — is gone with the frame, leaving a client nobody
can authenticate as and section 2.3 cannot delete. `delete_registration` is the cheap one: nothing
is left half-written, and what a drop costs is the audit event, plus a retry that reads to an
operator like a guess at a registration access token.

Reversing the order — returning a credential before the write — was considered and rejected: it
hands a client a live-looking secret for a write that a concurrent section 2.3 delete is entitled
to refuse, which is what the compare-and-swap exists to allow.

What a host feels: nothing changes in the code. A host on the `axum` adapter was already covered,
because that adapter spawns per request inside a single `fallback`. A host that mounts
`AuthorizationService::handle` itself, or calls these methods directly, must drive them from a task
the connection cannot cancel — spawn, and await the join handle.

The `axum` adapter's own note on what detaching costs has been corrected in the same pass. It
claimed a handler "does a bounded number of store calls with no unbounded waits of its own"; the
number is bounded but the LATENCY is the host's — `Storage` has no timeout anywhere in this crate,
the token path awaits an `Es256Signer` that may be a KMS round trip, and `SecretVerifier::verify`
occupies an executor thread for its KDF. The remedy that paragraph already named (a concurrency
limit in front of the service) is the one that holds.

## [0.9.1] - 2026-08-13

**0.9.1 is the BETA.** 0.9.0 was an alpha published so it could be built against; this is the
release meant to be tested in earnest, and it exists because that alpha was audited hard the day it
shipped. Three audit rounds over the published code found 42 items, and the ones that mattered were
not in the protocol surface, which several earlier rounds had already swept. They were in the
places nobody had read: the cryptographic seam, the `Storage` contract, and the gates themselves.

### UPGRADING FROM 0.9.0: persisted records gain fields, and a rolling upgrade needs both halves

The resurrection rule below works by comparing WHEN a grant was authorized against WHEN a
revocation was recorded, so four persisted records gained an instant: `IssuedToken` and
`RefreshTokenRecord` gained `grant_established_at`, `AuthorizationCodeRecord` gained `issued_at`
(and, separately, `redirect_uri_was_explicit`), and `PushedAuthorizationRequest` gained `pushed_at`.

A record written by 0.9.0 carries none of them. **There is nothing to run.** Every one of the new
fields has a `#[serde(default)]` whose default is the FAIL-CLOSED value — the epoch for the four
instants, which predates every barrier that could be recorded, so an old record is REFUSED by a
standing revocation rather than admitted by one. Without the default the read fails outright and
the endpoint answers `server_error`; with a far-future default it would deserialize just as happily
and ADMIT every record written by 0.9.0, which is the resurrection this whole release is about.

A Postgres backfill migration was written for this and then deliberately REMOVED, which is worth
recording because it looks like the obvious thing to do. It covered strictly LESS than the serde
defaults — it cannot reach a 0.9.0 node still writing field-less payloads during a rolling upgrade,
which is the window that actually matters — and it was the wrong shape by this crate's own
standards: an unbounded single-statement rewrite of every live credential row, inside the
transaction holding the advisory lock every other node's boot waits on. That is a multi-minute boot
stall and a full table of dead tuples on a large deployment, bought for nothing.

`oauth-as-postgres`'s `records_written_by_0_9_0_survive_the_upgrade` is the test that holds this:
it writes a row whose payload is missing each new instant in turn — the shape a 0.9.0 node wrote
for that field — and asserts each reads back as the epoch, so flipping any of these defaults to a fail-open value is red rather than silent. Note that
it lives in the Postgres crate but guards the CORE crate's defaults.

This is a patch bump that changes how stored records are interpreted, so it deserves saying plainly:
no outage, no coordinated restart, no migration — but a grant that predates the upgrade is treated
as maximally old, which for an access token means its next refresh is refused if any revocation
stands against its client or subject.

### BREAKING: `Storage` gains a rule, and the methods to enforce it

**A write must not resurrect state that a revocation removed.** This is the reason 0.9.1 exists,
and it is a breaking change to the `Storage` trait, which hosts implement. A host on
`MemoryStorage` or `oauth-as-postgres` does not have to do anything beyond taking the new version
and running the migration; a host with its own store does.

WHAT WAS WRONG. Every revocation in this crate removes records that a concurrent request may
already be holding, mid read-modify-write, and every one of those requests ends in a write. There
was no way to express "put this back only if nothing deleted it", so the last writer won, and the
last writer was the one that had been told to stop. Seven confirmed sites, including the one shipped
as a known defect in 0.9.0: reuse detection and code replay raced across the `await` inside ES256
signing, which was effectively closed for the built-in backend and OPEN for an `Es256Signer`
fronting a remote KMS.

ONE RULE, TWO EVIDENCES, because there are exactly two shapes of the problem:

- Where a revocation leaves DURABLE ABSENCE, the write states what it believed the store held, and
  a deleted record fails the comparison. New: `compare_and_swap_client`,
  `compare_and_swap_authorization_code`, `compare_and_swap_consent`, joining the
  `compare_and_swap_device_grant` that already existed.
- Where the writer ITSELF took the record, absence is the normal case and proves nothing: a
  rotation that took a refresh token cannot tell "I took this" from "a revocation took this".
  There the evidence is a `RevocationBarrier`, recorded BY the revocation and consulted BY the
  write.

WHAT A HOST HAS TO CHANGE:

- `put_token`, `put_refresh_token` and `put_pushed_authorization_request` return `WriteOutcome`
  instead of `()`. They must consult the
  barriers covering the record's own `client_id`, `family_id` and `subject`, and answer
  `RefusedRevoked` instead of writing. The check and the write must be ONE atomic step.
- `delete_client`, `revoke_token_family` and `revoke_consent` take a `RevocationWindow`
  and must record a barrier ATOMICALLY with their removals.
- `sweep_expired` must reclaim barriers at (and not before) that deadline, and count them.
- The four `compare_and_swap_*` methods must compare and write as one step, and MUST NOT insert.
- `AuthorizationCodeState` gains a third variant, `Replayed`. A detected replay records it, which
  is what lets a redemption suspended in the host's signer discover that the grant it is halfway
  through issuing was contained while it slept.

`oauth_as::storage_conformance` now publishes twenty-two checks for all of this, each with a planted
fault that has been watched to make it go red. Run it against your store: the failure this rule is
about is invisible to every other check, because a cascade only reaches what is in the store when
it runs and the write that undoes it arrives afterwards.

ONE WRITE IS DELIBERATELY EXEMPT and says so: `put_authorization_code`. Refusing it would disarm
replay detection at the moment a grant is being revoked, because the consumed record is written
BEFORE issuance precisely so a store failure cannot take the alarm offline. What the exemption
leaves behind is a consumed code row belonging to no live grant, which mints nothing and which
`sweep_expired` reclaims: a row, not a capability.

Postgres: a new unconditional migration, `0005_revocation_barriers.sql`. `PostgresStorage::migrate`
applies it. If you run migrations yourself, apply it before upgrading.

### BREAKING: a barrier refuses a grant, not an identity

FOUND BY THE 0.9.1 CODE AUDIT, in the mechanism 0.9.1 exists to add. Two independent reviewers
landed on it, and it was red-proven before it was fixed.

A `RevocationBarrier` was keyed on identity — a `client_id`, or a (`client_id`, `subject`) pair —
and consulted by every `put_token`. Nothing clears a barrier but the sweep at its deadline, which
is `now + the longest lifetime this server mints`. So a user who withdrew an application and then
approved it again held a live consent record and COULD NOT OBTAIN A TOKEN FROM IT for as long as a
refresh token lives. The same shape locked out any `client_id` a host re-provisioned after an RFC
7592 deletion.

The refusal tests all passed, and that is the part worth keeping. Refusing MORE than intended is
invisible to a test that asks "did it refuse?", and the one existing test aimed at this asserted
that the consent RECORD came back — `put_consent` does not consult the barrier; `put_token` does.
It stopped one step short of the property it claimed.

WHAT CHANGED. `Storage`'s three revocation methods take a `RevocationWindow` (`recorded_at`,
`until`) in place of a bare deadline, and records carry the instant their GRANT was authorized:

- `IssuedToken::grant_established_at` and `RefreshTokenRecord::grant_established_at`, the latter
  carried across rotation and never restamped.
- `AuthorizationCodeRecord::issued_at` and `PushedAuthorizationRequest::pushed_at`, because
  `expires_at` cannot stand in for either: a code minted a minute before a withdrawal expires
  minutes AFTER it, so comparing the deadline would admit the very redemption a barrier exists to
  refuse.

A `Client` or `Consent` barrier now refuses only a grant established at or before `recorded_at`.
A `TokenFamily` barrier still refuses UNCONDITIONALLY, deliberately: rotation mints fresh records
inside an existing family, so comparing there would admit the rotation-after-cascade that RFC 9700
section 4.14.2 containment exists to stop. Ties refuse, because the ordering is genuinely unknown.

The instant compared is the GRANT's, never the write's. Comparing `issued_at` would have cost
nothing and been wrong: a rotation and a code redemption both write at `now`.

New host-facing conformance check `revocation_barrier/admits_a_later_grant`, with a planted fault,
because a store that refuses on identity alone passes every other barrier check in the harness.

### BREAKING: the `http` consent types are named for approval, not consent

Four renames, with no deprecated alias. A host using the `http` feature's consent seam will not
compile until it renames; that is deliberate, because a silent alias would leave two names for one
concept in a public API that is about to be depended on in earnest.

| 0.9.0 | 0.9.1 |
|-------|-------|
| `http::ConsentDecision` | `http::ApprovalDecision` |
| `http::ConsentRequest` | `http::ApprovalRequest` |
| `http::ConsentResolver` | `http::ApprovalResolver` |
| `ServiceBuilder::with_consent_resolver` | `ServiceBuilder::with_approval_resolver` |

The reason is that these three types never carried a `ConsentRecord`. They are the seam by which
the host reports what the resource owner decided AT THIS REQUEST — an approval — and the crate's
consent records are the separate, persisted, `consent`-feature thing that a withdrawal cascades
over. Two different concepts sharing a word made every doc about either one ambiguous, and the
step-up work in this release made that ambiguity load-bearing. `ConsentRecord`, `revoke_consent`
and the `consent` feature keep their names, because those are consent.

`ApprovalRequest` also gains two fields, `resource` and `authorization_details`, so a resolver can
see what the request actually asked for before deciding.

### BREAKING: `ConsentRecord::covers` takes a fourth argument

`covers(&self, scope, resource, details: RequestedDetails<'_>)`. The new parameter is how a stored
consent is asked whether it covers the RFC 9396 `authorization_details` in front of it; without it
the method answered "covered" for a request whose details the record had never seen.
`RequestedDetails::none()` is the honest value for a caller that has none, and is what a build
without the `rar` feature passes.

### BREAKING: the `Hooks` installers are no longer public

`Hooks::{install_event_sink, install_rate_limiter, install_secret_verifier,
install_registration_policy, install_request_object_keys, install_es256_verifier}` are now
`pub(crate)`. They were never the supported way to do this and they let a host mutate a running
server's hooks from outside; the supported way is and was the builder, which takes the same values
before the server exists: `AuthorizationServer::with_event_sink`, `with_rate_limiter`,
`with_secret_verifier`, `with_registration_policy`, `with_request_object_keys`,
`with_es256_verifier`.

### Changed: `introspection_endpoint` is advertised only where the host names it

RFC 8414 metadata now carries `introspection_endpoint` only where the host set
`ServerConfig::introspection_endpoint`. It used to be advertised unconditionally, defaulting to
`/introspect`.

**This is not a compile break.** Both `ServerConfig::introspection_endpoint` and
`AuthorizationServerMetadata::introspection_endpoint` were already `Option<String>` at 0.9.0 and
are unchanged; only the population changed. An earlier draft of this entry called it a breaking
type change, which was wrong. It is a WIRE change: a deployment that did not set the field, and
was relying on the default appearing in the document, will find the member absent.

This is the visible half of an honesty ruling rather than a capability change. Through 0.9.1 this
server answers introspection for the token's own client; it does not yet authenticate a resource
server and answer for one. Advertising `introspection_endpoint` unconditionally in a document whose
whole purpose is to tell a resource server what it can call was a claim the code did not support.
So the member is now opt-in, and a host that publishes it is stating that its deployment has a use
for it. The resource-server channel is 0.9.2 work. When it lands this member becomes unconditional
again, and that is an addition to the document rather than a withdrawal.

### Fixed: `verification_uri_complete` corrupted a verification URI that already had a query

RFC 8628 section 3.3.1. The deep link was built with a hardcoded `?`, so a host whose
`verification_uri` already carried a query got the user code folded into the previous parameter's
value — `tenant=a?user_code=WDJB-MJHT` is one pair, not two. The page the link exists to prefill
read no user code and rendered an empty form. The crate already had `query_separator` and used it
for every authorization-response URL; this was the one place that answered the question twice.

The existing test could not see it: its `verification_uri` had no query, so appending `?` happened
to be right, and it asserted `contains(user_code)`, which stays true while the link stops working.

### Fixed: arithmetic that panicked on host-configured values

`SystemTime + Duration` panics on overflow, and `Duration += Duration` with it. Every
ATTACKER-supplied duration in this crate already used `checked_add` with the reasoning written
beside it; every HOST-supplied one used bare `+`, against `ServerConfig` TTL fields that are public
and validated nowhere. A deployment reading a TTL from a config file could panic on an ordinary
request rather than fail at startup. Now saturating, via `saturating_deadline`, at every token,
code, device-grant, PAR and barrier deadline; `client_secret_expires_at` is a saturating `u64` add,
which also stops a release-mode WRAP reporting a fresh secret as already expired; and the
device-poll interval saturates rather than overflowing on a client-paced accumulation.

### Fixed: Postgres did not serialize two concurrent first-time consents

`compare_and_swap_consent` documented that `SELECT ... FOR UPDATE` made two concurrent creates for
one pair serialize. It does not: a row lock on a query returning ZERO rows locks nothing, so at
READ COMMITTED both transactions saw an empty pair and both inserted, and the pair index is
deliberately not `UNIQUE`. `MemoryStorage` serializes both halves under its one mutex, so the two
backends disagreed. The consequence is not untidiness: `revoke_consent` withdraws one `consent_id`,
so the surviving duplicate keeps answering `find_consent` and the withdrawal is undone. Now taken
under a transaction-scoped `pg_advisory_xact_lock` over the pair, which serializes when the pair is
empty.

### Fixed: an empty identifier revoked everything in memory and nothing in Postgres

`delete_client("")` cascaded every record through `MemoryStorage` and — because the barrier insert
runs first and violates a CHECK constraint — deleted NOTHING through `PostgresStorage` while
returning an error. Same divergence for an empty `family_id` or `subject`. An empty string does not
name an identity a barrier can be recorded for, so all three revocations now refuse it in both
backends, before anything is mutated.

### Fixed: the PKCE appendix B guard proved nothing

`rfc7636_challenge_is_unpadded_base64url_of_a_32_byte_digest` said it decoded the challenge and
pinned the RFC's bytes, as "a red-proof of the harness itself". It asserted only length 43, no
padding, and a base64url alphabet — satisfied by ANY 43-character base64url string. The crate's
headline PKCE claim rested on a single constant that the only other test compared the
implementation against, so corrupting `code_challenge_s256` and updating the constant to match
would have shipped green. It now decodes with a base64url decoder written for the test alone and
compares against RFC 7636 appendix B's digest bytes.

### Documented: DPoP `ath` is not verified, and a resource server must check it

`verify_proof` is documented as the function a host's RESOURCE server can use for the RFC 9449
section 7 check. It takes no access token, so it cannot verify the section 4.3 step 11 `ath`
binding and does not. The module listed two unimplemented section 8 and section 10 features and
did not list this one, so an RS built on it would accept a proof bound to a key and a request line
but not to a token. The gap was in the docs, not the code; both now say so.

### Added: `delegate_storage!`

A macro that writes the forwarding methods for a store that specialises only some of them, which
is what a host wants when clients live in Postgres and codes live in memory. It lands in the same
release as the `Storage` break so that it forwards the final method set rather than one about to
change. It takes a FIELD name, not an expression (`to inner`, not `to self.inner`), because macro
hygiene makes a call-site `self` a different `self` from the generated method's.

It forwards. It does not make two backends atomic with respect to each other, and no macro could;
`delete_client`'s cascade spans both and the trait requires that to be one event.

### Added: RFC 8693 `act` reaches a resource server by both routes

The delegation claim is now persisted on `IssuedToken`, reported by RFC 7662 introspection, and
carried as an RFC 9068 claim in the signed access token.

Both are needed, and shipping only one is how this nearly went wrong: an OPAQUE token carries
nothing itself, so introspection is its only channel, while a JWT is typically validated OFFLINE by
a resource server that never introspects. Doing one and not the other moves the deficiency between
deployment shapes rather than ending it, and RFC 8693 section 1.1's whole distinction between
delegation and impersonation is a distinction FOR the resource server.

Through 0.9.1 introspection answers only the token's own client, so on the opaque route the
delegation is visible to that client rather than to a resource server; the resource-server channel
is 0.9.2 work. The JWT route reaches a resource server today. The claim is persisted now because
the RECORD, not the response, is the thing that cannot be added later.

This was a known gap through 0.9.0, blocked on the persistence contract: `IssuedToken` is the
record every host's `Storage` writes, so a new field is a migration in stores this crate does not
own. 0.9.1 is already breaking that trait, so hosts migrate once instead of twice.

### Added: RFC 7592 policy refusals reach the event sink

`Event::ClientRegistrationRefusedByPolicy`. The three authentication failures on the management
plane already emitted; the host's own `RegistrationPolicy` saying no did not, on either the
registration or the management endpoint.

The management one is the one worth having: by the time the policy is consulted the caller has
already presented a registration access token this server verified, so a stream of these is a
client with a WORKING credential repeatedly attempting something the deployment forbids. That is a
different investigation from a brute force, and it was invisible in both directions, because the
wire answer is deliberately uninformative so a policy refusing on content does not confirm what
content it dislikes.

It carries `Option<&str>`: an initial registration is refused before any client id is minted, and
inventing one to fill the field would be the event asserting something that never existed.

### Fixed: the Postgres integration tests actually run in CI

They never had. CI ran `--all-features` only for `-p oauth-as`, so the one file that documents
itself as the only evidence for cross-connection atomicity was silent. There is now a
`postgres-atomicity` job with a health-gated PostgreSQL service.

The important half is that a SKIPPED run is red. No assertion reachable from inside that suite can
detect its own absence: drop the `pg-integration` feature and the support module is not compiled,
every real test vanishes, and `cargo test` exits 0. So the guard is external, pins twenty-three
test names,
requires the observed race counts to appear, and rejects any ignored or filtered line. The job runs
it against a deliberate default build FIRST and fails if the guard accepts, so the guard that runs
is the guard that has been watched to fail.

### Changed: behaviour a host feels without changing a line of its own code

- **The authorization endpoint and RFC 7591 dynamic registration are now rate limited.** `Attempt`
  gains `AuthorizationRequest { client_id }` and `ClientRegistration`, and `RateLimitConfig` gains
  `authorization_request_capacity`, `authorization_request_failure_cost`,
  `client_registration_capacity` and `client_registration_failure_cost` to size them. `Attempt` is
  `#[non_exhaustive]`, so a host's own `RateLimiter` implementation still compiles — but it now
  sees two variants it has never seen, and two endpoints that were never throttled now are. A host
  that counts attempts per variant should look at its own arms before upgrading.
- **The device-entry limiter no longer double-charges.** A `DeviceUserCodeEntry` was charged twice
  per attempt, so a host's configured device throttle was effectively half what it wrote down.
  Fixing it DOUBLES the effective allowance on upgrade. If the doubled figure is not what the
  deployment wants, halve the configured capacity.
- **The axum adapter now `tokio::spawn`s each request.** A client that disconnects mid-request no
  longer cancels the handler, which is the point: the store sequence behind an issuance gets to
  finish rather than leaving a token written and a code unconsumed. The consequence is that
  in-flight work is now bounded by request RATE rather than by concurrent connections, so a
  disconnecting client sheds no load. A host that relied on disconnects for backpressure should put
  a concurrency limit in front of the service.
- **Routing matches the raw wire path byte for byte.** Routes are percent-encoded at build time by
  the router itself, and only the RFC 7592 client id captured from the path is decoded, after
  routing. Both directions are a change: `/%74oken` no longer reaches the token endpoint, and an
  issuer whose path component contains a percent-encoded byte now routes correctly where it
  previously did not.
- **`IntrospectionResponse` refuses a response it cannot represent.** Deserializing an
  introspection response that carries a member this build has no field for is now an error instead
  of a silently discarded value. A client parsing a richer server's response gets a refusal where
  it used to get a lossy struct, which is the safer direction for a decision made on the result.
- **New ceilings refuse requests that were previously accepted**: `acr_values` at `MAX_ACR_VALUES`
  (16), RFC 9396 section 2.2 lists at `MAX_DETAIL_LIST_ENTRIES` (16), the `act` chain at
  `MAX_ACT_CHAIN_DEPTH` (8), a client assertion at `MAX_ASSERTION_BYTES` (4096), a DPoP `jti` at
  `MAX_JTI_BYTES` (128), and a pushed request URI lifetime at `MIN_REQUEST_URI_TTL`. Each is a
  public constant so a host can check its own limits against them rather than discovering one in
  production.
- **New response headers on the HTML and redirect responses** the `http` feature serves.

### Added: public API not covered by the sections above

Types and modules: `RequestedDetails` (with `of` and `none`), `RevocationBarrier`, `pub mod
delegate`.

Methods and associated functions: `WriteOutcome::{is_applied, is_refused}`;
`AuthorizationCodeState::minted`; `CompactJws::reject_unknown_crit`;
`Audience::names_a_resource_server`; `SecretVerifier::dummy_hash`;
`FixedWindowRateLimiter::tracked_authorization_clients`;
`TokenRequestContext::{with_resources, with_authorization_details, with_dpop_proof}`; and `::new`
constructors on `IssuedToken`, `RefreshTokenRecord`, `AuthorizationCodeRecord`,
`PushedAuthorizationRequest`, `AccessTokenClaims` and `TokenRequestContext` — which exist because
every one of those structs is `#[non_exhaustive]`, so a host outside the crate cannot build one
with a struct literal and had no way to construct one at all.

Fields and variants: `ServerConfig::allow_authorization_details_exchange`;
`JarConfig::max_request_object_lifetime`; `UserApproval::{granted_at, decided_at}`;
`Event::ClientRegistrationAuthenticationFailed`; `Event::DpopProofRefused`;
`ClientAuthFailure::{NoDynamicRegistration, AssertionInvalid { reason }}`;
`AssertionFailure::ReplayCheckUnavailable`.

Constants: `CLIENT_AUTHENTICATION_FAILURE_CEILING_DIVISOR`,
`DEFAULT_AUTHORIZATION_REQUEST_CAPACITY`, `DEFAULT_AUTHORIZATION_REQUEST_FAILURE_COST`,
`DEFAULT_CLIENT_REGISTRATION_CAPACITY`, `DEFAULT_CLIENT_REGISTRATION_FAILURE_COST`, plus the six
ceilings named above.

### KNOWN, AND NOT FIXED IN THIS RELEASE

Written for the same reason 0.9.0's list was: a third party finding a defect is a success of the
method, and a third party finding that a CLAIM was false is not.

**1. Mutation coverage is incomplete.** Surviving mutants are tracked individually rather than as
a percentage, and each one that no test kills is argued in writing beside the code it mutates. Read
those arguments before relying on "the tests constrain the code".

**2. FIXED before promotion: `publish.yml`'s pre-publish gate ran DEFAULT FEATURES ONLY.** It ran
`cargo clippy --workspace --all-targets --locked` and `cargo test --workspace --locked` and
nothing else, which is roughly a third of the suite immediately before a permanent crates.io
version, with every feature-gated capability unexercised. The defence was that `main` is only
reached through `qa`; nothing enforces that, and this release found three separate defects that
one matrix could not see while another could, so "the other branch checked it" is not a check. It
now runs all three matrices plus rustdoc under `-D warnings`.

**3. FIXED before promotion: `qa` was a strictly weaker gate than `dev`.**
`scripts/size-report.sh --check` ran on `dev` and not on `qa`, so "qa green" meant less than "dev
green", which is backwards for a promotion branch. The anti-drift check that exists to prevent
exactly this compares step names WITHIN one job, so it could not see a whole job that was missing.
`qa` now runs it too.

It stays on `dev` as well, and that is measured rather than assumed: on the 0.9.1 green run the
three `dev` jobs ran in parallel and the size job finished 50 seconds BEFORE the lint job, so it
costs `dev` no wall-clock time. What it buys there is EARLY detection, which is what makes a budget
get fixed rather than argued with: the 0.9.1 growth was caught on `dev`, and that is why the
redundant `HashMap` behind it was found and removed instead of the number simply being raised.

**4. FIXED before promotion: the storage conformance selftest now compiles and RUNS at
`--features test-util` alone.** It did not, at 0.9.0 or through most of 0.9.1, so the guard that
proves that harness can go red was exercised only under richer feature sets, and
`not_runnable_in_this_build()`, whose entire purpose is the narrow build, was never exercised by
one. Gating the consent fault fields closed it as a side effect of an unrelated fix, which is why
it is stated as MEASURED rather than reasoned: 46 tests pass in that configuration, including
`every_check_has_a_planted_fault`.

**5. The `crates-io-publish` GitHub Environment still does not exist with reviewers.** Reaching
`main` publishes, decided by the version number in `Cargo.toml`, and GitHub auto-creates a
referenced environment UNPROTECTED on first use, which is why 0.9.0 published with no approval
pause. Until that environment exists with required reviewers and a deployment-branches rule of
`main` only, the `environment:` line in the workflow is decoration. This is an owner action; it
cannot be done from inside a workflow file.

### BREAKING: the `client_assertion` feature is now `client-assertion`

The cargo feature is renamed. There is NO alias, deliberately: 0.9.x is pre-1.0, adoption is hours
old, and an alias would carry the inconsistency into 1.0 where it could not be removed.

To migrate, change the spelling wherever you name the feature:

```toml
oauth-as = { version = "0.9.1", features = ["client-assertion"] }
```

WHAT DOES NOT CHANGE, and it is the reason this rename is narrower than a search-and-replace: the
RFC 7523 section 2.2 WIRE PARAMETER is also spelled `client_assertion`, as are
`client_assertion_type` and the `TokenRequest` field that carries it. Those are protocol, not
configuration, and renaming them would break every conforming client. The Rust module path
`oauth_as::client_assertion` is unchanged too, because a Rust path cannot contain a hyphen.

So a host changes its `Cargo.toml`, its `--features` lists and any `#[cfg(feature = ...)]` it
wrote; it changes nothing it sends or receives.

The hyphen matches every other multi-word feature in this crate (`token-exchange`,
`resource-metadata`, `jwt-p256`), which is what made the odd one out worth fixing at all.
`scripts/feature-mirrors.py` checks that the manifest, both CI no-backend lists, the size probe and
the size report all agree, so the rename could not land in some of those places and not others.

### The version number moved, and what that means

`dev` carries 0.9.1 from the moment work on it starts, so a build from `dev` never claims to be the
published 0.9.0. Publication is still decided by the version number reaching `main`, not by this
line.

### Fixed: feature-varying public types are sealed before anyone builds against them

Twenty-six public types have a field or variant set that VARIES WITH CARGO FEATURES. Nineteen of
them were not `#[non_exhaustive]`; sixteen are now sealed, and the remaining three are listed in
`tests/host_api_shape.rs::DELIBERATELY_UNMARKED` with the argument for leaving them open. Two more
that do not vary by feature — `ParConfig` and `JarConfig` — were sealed at the same time. Adding
`ProtectedResourceMetadata` (recorded separately below) and `RequestedDetails`, a type new in this
release and sealed at birth, the attribute count on public structs and enums moved from 19 to 39.

Those numbers are stated exactly because the first version of this entry said "twenty", which was
not the count of anything: not the types that vary, not the ones that were unmarked, not the ones
that changed. It understated the change by six types and named none of them, in the one entry a
host reads to decide whether 0.9.1 breaks their struct literals and their exhaustive matches. The
0.9.1 audit caught it by re-running the project's own scan (`tests/host_api_shape.rs`) against
`v0.9.0` and against this tree; that test asserts only `varying.len() > 10`, so nothing had gated
the claim.

Every one of the fifteen features is off by default, so a host writes a struct literal or an
exhaustive `match` against the features THEY enabled, and their build breaks the day anything else
in their dependency graph turns one on. `#[non_exhaustive]` cannot be added later without breaking
people, which made this the last cheap moment to do it: 0.9.0 had been published for roughly an
hour.

### Changed (BREAKING): `ProtectedResourceMetadata` is `#[non_exhaustive]`

The RFC 9728 document type was all-`pub` with no attribute, though the module header gives it the
same argument the sealed types got: it is DERIVED from configuration rather than hand-written, and
the members are an IANA registry that takes new entries. Nothing in this crate, its tests or its
examples builds one by literal — `from_config` is the only constructor — so the change is invisible
to every use the crate knows about. It is breaking for a host that wrote the literal by hand, and it
is in 0.9.1 because 0.9.0 was published for an hour and this is the last release in which the
attribute can go on at all. Deserialization, field reads and matches are unaffected.

### Fixed: claims the code did not support

Nine of them, in the documents a stranger reads before deciding whether to trust the crate. The
README said the 1.75 floor "tests clean"; it does not and cannot, because `litemap 0.7.5`
arrives through a dev-dependency and needs 1.81. The project's own planning notes named a
dependency that had been made optional, and a `cargo +1.75 test` gate that cannot pass. The
workspace manifest said
`oauth-as-postgres` did not implement the PAR and replay methods; it implements all three. A
manifest comment credited bench rot protection to a CI step that does not exist.

### Fixed: gates that could not fail

`qa` was missing dev's feature-combination build, so every promotion passed through a stage that
checked LESS than the one before it, on precisely the check that catches under-gated `cfg` code. The
publish workflow treated an unparseable crates.io response as "not yet published" and would have
armed a publish on a proxy error page served with HTTP 200. Three hand-maintained copies of the
feature list were cross-checked by nobody. A published `Storage` conformance check had no planted
fault, so it had never been shown able to go red.

## [0.9.0] - 2026-08-09

**This is the first release with an implementation in it.** It is an ALPHA, published so that a
third party can build a real authorization server against it and report what breaks. It is not
recommended for production, and the two defects below are the specific reasons why.

### KNOWN DEFECTS in this release

These are CONFIRMED, reproduced by tests, and NOT fixed in 0.9.0. They are written here because a
third party finding a defect is a success of the method, and a third party finding that a CLAIM
was false is not. Both are scheduled for 0.9.1.

**1. Reuse detection does not contain a token minted during the signing window. (HIGH)**

Refresh-token reuse detection and authorization-code replay detection both revoke a family, and
both can be raced by an issuance that is already in flight. The window is the `await` inside ES256
signing: the tombstone is written before the token is minted, the racing revocation removes the
tombstone, and the in-flight issuance then completes and stores a LIVE access token that the
revocation has already passed by. The result is that detecting the attack revokes nothing.

The window is proportional to how long signing takes, so it is effectively closed for the built-in
`jwt-p256` backend (local, microseconds) and OPEN for a host `Es256Signer` that makes a network
call, which is exactly the KMS and HSM case the signing seam exists to serve. **If you implement
`Es256Signer` against a remote signer, assume reuse detection is advisory in this release.**

Reproduced by two tests, held back from the tree because they are red:
`the access token minted during a detected-reuse window is live, so the revocation contained
nothing` and `the access token minted during a detected code replay is live, so the replay revoked
nothing`.

The fix is a durable "this family is revoked" predicate that `put_token` and `put_refresh_token`
consult, rather than a narrower window: a marker that a later write cannot resurrect. That is a
breaking change to the `Storage` trait and it is why it is not in this release rather than rushed
into it.

**2. Mutation coverage is incomplete.**

Surviving mutants are tracked individually rather than as a percentage, and each is argued in
writing beside the code it mutates. Do not assume a green test run means the tests would have
caught a given change.

### Everything else in 0.9.0

### Fixed: an unauthenticated caller SIZED an allocation on two refusal paths

`GrantType`'s and `TokenTypeIdentifier`'s `FromStr` errors each carry an owned copy of the value
that failed to parse. The HTTP token endpoint resolves `grant_type` BEFORE client authentication
(deliberately, so an unimplemented grant is answered `unsupported_grant_type`) and deliberately
does NOT echo the value back, so that `String` was allocated, copied into and dropped unread on
every refused request. `MAX_BODY_BYTES` is 64 KiB and `MAX_FORM_PARAMETERS` is 64, so one form
parameter can be nearly the whole body: an unauthenticated caller posting
`grant_type=<60 KiB of junk>` bought the server a 60 KiB malloc and memcpy per refusal, at
whatever rate it could open sockets. RFC 8693's `subject_token_type` was the same defect one seam
along, and it is the one whose refusal STRING had already been made a `&'static str` for exactly
this rule; the allocation underneath it was missed.

**New, additive:** `GrantType::parse(&str) -> Option<Self>` and
`TokenTypeIdentifier::parse(&str) -> Option<Self>`, non-allocating, used by the HTTP surface and
by RFC 7591 registration. `FromStr` is UNCHANGED on both types and still carries the value, for
host-side callers parsing their own configuration where knowing which spelling was wrong is the
point and where an attacker does not set the rate.

Measured through `AuthorizationService::handle`, growing the parameter by 61,432 bytes: before,
the refusal grew by 122,888 bytes and one extra allocation; after, by 61,456 bytes and no extra
allocation, which is the single request-body buffer that reading a form body requires. The gates
are `unknown_grant_type_refusal_is_not_sized_by_the_caller` and
`unknown_token_type_refusal_is_not_sized_by_the_caller` in `tests/refusal_cost.rs`; the existing
token-exchange gate there dropped from 10 allocations / 4,549 bytes to 9 / 4,523.

### Fixed: RFC 8693 token exchange refused every assertion-authenticated client over HTTP

The token-exchange arm of the HTTP token handler forwarded `client_secret` and nothing else. RFC
8693 s2.1 authenticates the client "as described in Section 2.3 of [RFC6749]", which is a
reference to every method the server offers, and an RFC 7523 credential arrives in
`client_assertion`. A confidential client registered for `private_key_jwt` or `client_secret_jwt`
was therefore answered `invalid_client` on a grant this server's RFC 8414 document advertises to
it. This is the second half of a defect whose first half (the arm carrying `None` and refusing
EVERY client) was repaired earlier; restoring the secret alone left the rest of it in place.

`TokenExchangeRequest` gains `client_assertion_type` and `client_assertion` under the
`client_assertion` feature, and `token_exchange::exchange` now builds a full `ClientCredential`
rather than `Bound::secret`. Additive: existing hosts construct this type through
`TokenExchangeRequest::new` and set fields, so nothing breaks. RFC 8705 is deliberately still not
threaded through; see the comment at the construction site for why an mTLS-only client is refused
rather than silently issued an unbound token.

### Fixed: a DPoP proof sent with `grant_type=token-exchange` was silently ignored

The token-exchange arm RETURNS from the token handler, and the RFC 9449 s4.3 `DPoP` header was
read after the dispatch, so on that one grant the header was never looked at: no duplicate-header
check, no proof verification, and an issued token with no `jkt`. A client that asked for a
sender-constrained token got a bearer token and no way to find out. `crate::token_exchange`'s own
module documentation argues at length that a silent sender-constraint downgrade is "the one answer
that is definitely wrong", about the SUBJECT token, while the same module was issuing a silently
unbound token to a DPoP client.

The header is now resolved BEFORE the grant is dispatched, so the duplicate-header rule reaches
every grant, and a token-exchange request that presents a proof is refused `invalid_dpop_proof`
rather than served. Honouring the proof instead would need a `jkt` to travel on
`TokenExchangeRequest` and `Bound`; refusing is the answer that cannot be mistaken for success.
Attacks in `tests/token_exchange_wire_credentials.rs`.

### Fixed: `client_secret_jwt` required an ES256 backend it does not use

RFC 7523 `client_secret_jwt` is an HS256 HMAC over the registered secret (RFC 7518 s3.2). It
involves no elliptic curve, no public key and no `Es256Verifier`. The ES256 signing seam
nonetheless resolved a verifier UNCONDITIONALLY before looking at the registration, so a build of
`--features client_assertion` (which pulls `jwt`, not `jwt-p256`) with no host verifier installed
refused every valid HMAC assertion with `invalid_client`.

`client_assertion::verify_assertion` now takes `Option<&dyn Es256Verifier>`, and only the
`AssertionKeys::PublicKeys` (ES256) arm needs one: `None` there is a refusal, for the unchanged
reason that a signature this server cannot check has authenticated nobody. **This is a breaking
change to a public function's signature**, taken now because there is no consumer yet.

### Fixed: the single-use replay key could collide across clients

The RFC 7523 s3 and RFC 9449 s11.1 replay key was `kind:owner:jti` with an unescaped separator.
`ClientId::new` imposes no character restriction and URN-style client ids are ordinary, so a
client registered as `urn` presenting the `jti` `client:foo:42` produced exactly the key that the
client registered as `urn:client:foo` produces for its `jti` `42`. Whoever claimed it first denied
it to the other: one client could spend another's single-use slot, and the victim's conforming
assertion was then refused as a replay of something nobody sent.

The encoding is now `kind ":" LEN(owner) ":" owner jti`, which is INJECTIVE rather than merely
separated: the length prefix says where the owner stops whatever either value contains, so every
part is recoverable from the key and no two distinct triples can produce the same one. The attack
is in `tests/replay_key_collision.rs`.

### Fixed: the metadata document advertised `private_key_jwt` in builds that always refuse it

After the signing seam, the `client_assertion` feature no longer guarantees an ES256 backend
exists, so `private_key_jwt` could be advertised by a server that refuses every such assertion.
The two RFC 7523 methods are now advertised on their own terms: `client_secret_jwt` whenever the
feature is compiled in, because HS256 needs nothing else, and `private_key_jwt` exactly when this
server can verify ES256. The same rule now covers `token_endpoint_auth_signing_alg_values_supported`
(ES256 only with a backend), RFC 9101's `request_object_signing_alg_values_supported` and RFC
9449's `dpop_signing_alg_values_supported`.

Since a host-installed verifier is not visible to a `&ServerConfig`, there is a new
`AuthorizationServer::metadata()` that derives the document from the server, including its
installed seams; `AuthorizationServerMetadata::from_config` advertises only what the configuration
alone establishes, which is the direction that fails safe. `oauth_as::http::ServiceBuilder::build`
uses the new one.

### Fixed: an assertion-authenticated client could not revoke a token over HTTP

`oauth_as::http`'s revocation handler forwarded only `client_secret` and dropped the rest of the
resolved credential, so an RFC 7523 client (whose credential arrives in `client_assertion`) was
refused `invalid_client` at `/revoke` every time. Every other protected handler in that router
already passed the whole credential. Same shape and same cause as the RFC 8693 defect below, and
`tests/wire_reachability.rs` now covers revocation and introspection under an assertion.

### Fixed: the origin derivation could slice inside a character

`http::issuer_origin` computed a byte index by subtracting a trailing-slash-trimmed path length
from the untrimmed issuer, so an issuer with both a non-ASCII path and a trailing slash split
inside a character and panicked. Not reachable through `ServiceBuilder::build`, which passes an
already-trimmed issuer, so this is hardening rather than a fixed outage; the origin is now found
by searching for the path separator, which cannot land off a boundary.

### Fixed: the consent example's open-redirect guard missed `/\`

`examples/production_server.rs` rejected `//host` but accepted `/\host`, which WHATWG URL 4.3
makes the same URL in every browser. The example is documented as the one to copy, so its guard is
held to the rule its own comment states.

### Fixed: RFC 7009 revocation refused every public client, and RFC 8693 was unreachable over HTTP

Two defects with one shape: a capability the RFC 8414 metadata document ADVERTISES, which no
client could actually use, and which nothing noticed because the tests that covered it drove the
library API rather than the wire.

- **A public client may now revoke its own token.** `AuthorizationServer::revoke` and
  `revoke_with_credential` refused every `ClientAuth::Public` caller with `invalid_client`. RFC
  7009 s2.1 scopes the credential check in a parenthesis, "(in case of a confidential client)",
  and makes the OWNERSHIP check the unconditional half; s5 names "a valid `client_id`, in the case
  of a public client" as what such a request carries, and settles the objection in terms: a caller
  holding somebody's token "could do much worse damage by using the token elsewhere than by
  revoking it". This server issues tokens to public clients through code + PKCE and through the
  device grant, so the refusal left every native and browser app with no standard way to make a
  logout mean anything.

  **A host that read the old refusal as a security property should read this paragraph.** What
  replaces it is not nothing: the ownership check against the stored RECORD is unchanged and is
  what refuses a caller presenting somebody else's token, so naming a public client id buys an
  attacker no token they did not already hold. INTROSPECTION IS UNCHANGED and still refuses a
  public client, because RFC 7662 s4 says that endpoint "MUST NOT be publicly available": it
  DESCRIBES a token rather than destroying one, which is a capability the holder of a leaked
  string does not otherwise have. The two arrived bundled under one citation pair and only the
  RFC 7662 half of it held.
- **RFC 8693 token exchange is reachable over the HTTP surface.** The token handler resolved the
  client's credential and then passed `None` into the exchange, because every other grant now
  carries its credential on the request context. `exchange_token` refuses a client that is not
  confidential, so the grant was advertised in the metadata document and answered `invalid_client`
  to every client under every authentication method.

### Tested: every advertised capability, proven over the wire

`tests/wire_reachability.rs` derives its checklist from the SERVED RFC 8414 document rather than
from the router: it iterates `grant_types_supported`, `token_endpoint_auth_methods_supported`,
`response_types_supported` and `code_challenge_methods_supported` at runtime and fails on any
value with no wire proof, and it probes every member named `*_endpoint` (plus `jwks_uri`) for a
non-404 with no per-endpoint list written down. Adding an advertised capability without proving it
over HTTP is now a test failure rather than an oversight.

Recorded there rather than fixed, because it is a deliberate trust boundary: the two RFC 8705
authentication methods (`tls_client_auth`, `self_signed_tls_client_auth`) are advertised by an
`mtls` build and CANNOT succeed through `oauth_as::http::AuthorizationService`, which never sees
the TLS layer and therefore always passes `certificate: None`. A host terminating mTLS must call
`token_with_context` (or the `*_with_credential` entry points) with a certificate it verified
itself; a host mounting only the HTTP service should not register mTLS clients.

### Changed (BREAKING): the ES256 signing and verification seam

`jwt` no longer contains an elliptic curve. It carries the JWT surface plus two traits, and the
arithmetic is a BACKEND: `jwt-p256` is the one this crate ships, and a host may install its own.

The reason is a capability the crate could not offer at all: `JwtConfig` held a concrete
`EcdsaP256Key`, so the private signing key was STRUCTURALLY required to live in this process, and
`oauth-as` could not be deployed with its key in a cloud KMS or an HSM. The signing key is the one
secret whose compromise forges every token a deployment will ever issue, and "the key is in the
process" is precisely what a regulated deployment must avoid. The dependency reduction is real but
secondary: `jwt` used to add 20 packages, a complete second elliptic curve implementation, to a host
that already had one through `rustls`.

**Migration in one line, for a host that has no opinion about where its key lives:**
`features = ["jwt"]` becomes `features = ["jwt-p256"]`. Nothing else changes: the same tokens, the
same JWKS, the same `kid`, the same `EcdsaP256Key` constructors, the same `verify_es256`.

- **`jwt` no longer implies `p256`.** `jwt-p256 = ["jwt", "dep:p256"]` is the built-in backend.
  Nothing is mutually exclusive: a dependency graph that unifies `jwt-p256` on cannot take a host's
  own backend away, because the host's wins by being INSTALLED rather than by a feature being
  picked. `dpop`, `jar` and `client_assertion` continue to imply `jwt` (the verification surface)
  and now imply no backend.
- **`jwt-pkcs8` hangs off `jwt-p256`** rather than off `jwt`. `EcdsaP256Key::from_pkcs8_der` and
  `to_pkcs8_der` are the p256 backend's constructors and cannot exist without it.
- **`JwtConfig::new` and `JwtConfig::rotate_to` take an `impl Es256Signer`** rather than an
  `EcdsaP256Key`. `EcdsaP256Key` implements the trait, so every existing call site compiles
  unchanged under `jwt-p256`.
- **`JwtConfig::sign_access_token` is `async`.** `Es256Signer::sign` is async because a KMS call is
  a network round trip and a PKCS#11 call blocks. The in-process backend does no I/O, so its future
  is ready on its first poll. Add `.await`.
  Measured cost: ONE allocation per signed token, the `Box::pin` that makes `Arc<dyn Es256Signer>`
  possible, and ZERO bytes on the token endpoint's future (1704 bytes on `--all-features` before and
  after), because the claim set is built and consumed on the sync side of the await.
- **`dpop::verify_proof` and `client_assertion::verify_assertion` take a `&dyn Es256Verifier`** as
  their first argument. It is a parameter rather than an `Option`, because there is no "none" that
  could be safe: a caller with no verifier must refuse.
- **`AuthorizationServer::with_es256_verifier`** installs the verifier for RFC 9449 DPoP proofs, RFC
  9101 request objects and RFC 7523 client assertions. With `jwt-p256` compiled in and nothing
  installed, `P256Verifier` is the default, which is why a `jwt-p256` consumer sees no change. With
  NEITHER, every signed credential is refused: `invalid_dpop_proof`, `invalid_request_object`,
  `invalid_client`. Same posture as an absent consent resolver or an absent registration policy.
- **`RegisteredRequestObjectKey` no longer validates that the registered point is ON P-256 at
  registration time**, because `jar` no longer contains a curve. Every ENCODING mistake is still
  refused there (non-base64url, a coordinate that is not 32 bytes, a SEC 1 blob that is not 65 bytes
  or does not begin `0x04`, which is a new refusal). The curve equation is checked by the installed
  verifier, per request, and still fails closed. This also collapsed the crate's SECOND copy of
  ES256 verification, which `par.rs` had carried privately since the `jar` feature landed.

### Added

- **`oauth_as::signer_conformance`**, behind `test-util`, a runnable conformance harness for a
  host's `Es256Signer` and `Es256Verifier`, in the same shape as the `Storage` one. A broken signer
  fails SILENTLY: at a resource server a wrong signature is indistinguishable from a tampered token,
  so the deployment learns about it from its users. Fourteen checks, including the RFC 7515 appendix
  A.3 known-answer vector, the fixed-width `R || S` of RFC 7518 s3.4 against the ASN.1 DER nearly
  every KMS returns by default, and that `public_jwk()` is the public half OF the key that signed.
  Every one of them has a planted fault in `tests/signer_conformance_selftest.rs` that has been
  watched go red.

### Changed (BREAKING): types that made the wrong thing easy

Every item here is an API-safety change, pre-1.0, and the crate's existing posture applied
consistently: an absent consent resolver refuses, an absent registration policy refuses, and a
`user_code_length` below the floor is clamped up rather than honoured.

- **`AuthorizationServer::issue_authorization_code` now takes a `UserApproval`** rather than
  `(&ValidatedAuthorizationRequest, subject)`, and so does
  `issue_authorization_code_with_authentication`. RFC 6749 s10.12: knowing WHO the user is does not
  establish that they agreed, and the direct API had no step that made a host say so. The `http`
  feature's `ServiceBuilder` refuses to build without a consent resolver; the DIRECT path, which is
  what this crate's default build (no HTTP surface at all) invites, had no equivalent, so a host
  embedding the library got an auto-approving authorization server that compiled and passed its own
  tests. `UserApproval::granted(&validated, subject)` is not a proof and cannot be, exactly as
  `ConsentDecision::Approve` is not; what it is, is the same statement on both adoption paths, and
  a compile error naming s10.12 for the host that never made it. It also borrows the request it
  approves, so a host cannot prompt for one request and issue for another.

  Migration: `srv.issue_authorization_code(&validated, subject)` becomes
  `srv.issue_authorization_code(UserApproval::granted(&validated, subject))`.
- **`ServerConfig::include_verification_uri_complete` now defaults to `false`.** A BEHAVIOUR
  change: a default-configured device authorization response no longer carries the
  `verification_uri_complete` deep link. RFC 8628 s5.4 (Remote Phishing) is the reason. The attack
  is that an attacker starts a device grant for their own client and mails the victim the link;
  s5.4 names typing the code as the friction that makes that hard, and this member is exactly its
  removal. s3.3.1 makes the member OPTIONAL, so omitting it is conformant and costs a deployment
  only the QR-code convenience, whereas including it by default charged every host that never read
  the section for a capability it did not ask for. Set it back to `true` explicitly, and pair it
  with a verification page that names the client and the scope and requires an affirmative action
  (s3.3), which is what the `http` feature's page does.
- **`TokenExchangeRequest::new` takes `subject_token_type` as a third argument** instead of
  defaulting it to `TokenTypeIdentifier::AccessToken`. RFC 8693 s2.1 makes it REQUIRED, and the
  exchange refuses on it; the default was precisely the one value that passes, so a host that built
  the request in code and forgot to copy the form field turned that refusal into a pass.
- **`PublicJwk`'s fields are sealed** behind `kty()`, `crv()`, `x()`, `y()` and `kid()`, with
  `PublicJwk::from_coordinates` and `with_kid` as the constructors. The type documented that "there
  is no route into this type that skips the private-parameter rejection", and a struct literal was
  exactly that route: verification revalidates and fails closed, but `thumbprint()` would emit a
  `cnf.jkt` over anything a host wrote.
- **`AssertionKeys::ClientSecret` carries a `ClientSecretKey`**, not a `String`, and refuses a key
  shorter than `MIN_CLIENT_SECRET_JWT_KEY_LENGTH` (22 characters) at construction AND at
  deserialization. A `client_secret_jwt` assertion is an HMAC over public inputs, so an attacker
  who observes one assertion can grind the key offline at their own pace with no rate limit that
  reaches them; RFC 6749 s10.10 asks for 128 bits, which is 22 characters at base64url's 6 bits
  each.
- **`RegisteredCertificates::from_thumbprints` and `from_der_certificates` return
  `Result<_, MtlsRegistrationError>`** and refuse an empty list, matching `from_jwks`, which already
  refused the identical state. A registration with nothing to compare against can never
  authenticate anybody, and which constructor a host reached for should not decide whether that is
  a refusal or a live-but-useless registration. New variant:
  `MtlsRegistrationError::NoCertificates`.
- **`UnknownTokenTypeIdentifier`'s payload is sealed**, read through `identifier()`, and
  `RequestObjectKeyError` gains `detail()`. The two one-payload rejection types had opposite
  exposure rules: one published a `pub String` a caller could also forge, the other kept it
  entirely. Both are readable and neither is forgeable now.

### Changed (BREAKING): `ErrorCode` is `#[non_exhaustive]`

`ErrorCode` is the most widely matched type this crate publishes, and its VARIANT SET depends on
cargo features: `rar`, `consent`, `dpop`, `par` and `jar` each add one. Without the attribute a
host's exhaustive `match` compiled or failed depending on which features something ELSE in its
dependency graph had turned on, which is a build break with no release behind it. Every sibling
failure enum was already marked (`ConsentDecision`, `ConsentRequest`, `ServiceError` and
`DeviceApprovalError` were fixed earlier in this cycle); this one was missed.

Migration: add a `_` arm. `ErrorCode::as_str` still gives the wire spelling of whatever arrives
there, so an unknown code is reportable rather than opaque.

`ErrorCode::http_status` also lost its `_ => 400` catch-all and now names every variant, so adding
a code forces its author to choose a status instead of inheriting one. No status changed.

### Added: the request caps a host needs to size its own limits

`MAX_RESOURCE_INDICATORS`, `MAX_REGISTERED_REDIRECT_URIS`, `MAX_AUDIENCE_VALUES`,
`MAX_CONSENT_RESOURCES`, `MAX_PROOF_BYTES`, `MAX_FORM_PARAMETERS` and `MAX_BODY_BYTES` are now
re-exported at the crate root, where `MIN_USER_CODE_LENGTH` and the three
`MAX_AUTHORIZATION_DETAILS_*` constants already were. They are the numbers a host sizes its own
gateway, proxy and client limits against, and they are of no use one at a time: a proxy that
truncates a body below `MAX_BODY_BYTES` moves the refusal somewhere this crate cannot describe.
Nothing moved; the module paths still resolve.

`RegistrationErrorResponse` now implements `std::error::Error`, as its direct sibling
`ErrorResponse` already did. A host propagating a refusal with `?` into a `Box<dyn Error>` should
not have to care which of the two it is holding.

### Performance: three refusals and two signing paths that formatted what was already fixed

Measured with the counting allocator; the gates are in `tests/refusal_cost.rs` and
`tests/allocation_paths.rs`. The rule being applied is the one on
`tests/allocation.rs`'s `refused_token_request_allocation_bound`: a refusal is work the attacker
buys.

- **The RFC 9068 compact serialization is built in ONE buffer.** `JwtConfig::sign_access_token`
  assembled `header.payload` with `format!` and then formatted THAT into a second `format!`, so a
  token close to a kilobyte was allocated and fully copied twice. The signing input is a PREFIX of
  the compact form (RFC 7515 s5.1 steps 5 and 7), so the signature is appended to the buffer that
  was signed. MEASURED: signing alone goes from 9 allocations / 1960 bytes to 3 / 746, and one
  whole `at+jwt` issuance from 25 / 4709 to 19 / 3255. `jwt::compact_jws`, the helper a host uses
  to build the CLIENT half of RFC 7523 and RFC 9449, got the same treatment. No wall-clock change
  is measurable: `cargo bench --bench extensions` puts `issue_token_rfc9068_jwt` at 84.13 us before
  and 83.53 us after, because a P-256 signature is 80 us of it and 6 allocations are not.
- **The server's own token endpoint URL is derived once, at construction.**
  `AuthorizationServer::token_endpoint` `format!`ed a value fixed for the life of the server, once
  per RFC 9449 proof verification AND once per RFC 7523 assertion verification, so a
  `private_key_jwt` client sending DPoP paid it twice per token request. MEASURED: DPoP proof
  verification 56 allocations to 54, client assertion verification 37 to 35. The precomputed
  `Box<str>` costs 16 bytes on `AuthorizationServer` and only under the two features that read it,
  declared in `tests/allocation.rs`'s size gate rather than absorbed into its margin.
- **Three refusal descriptions that were `format!`ed from a fixed set of `&'static str` are now
  borrowed.** RFC 9101's "the header/payload/signature is not base64url" is reached at the
  UNAUTHENTICATED authorization endpoint, and RFC 8693's "... is not a token type RFC 8693 s3
  registers" is reached before the presented client credential has been checked. Roughly 50 of the
  crate's description sites already passed a constant, which is what `Cow<'static, str>` is there
  for; these were the ones that did not.

REJECTED from the same finding, with the measurement that settles it:
`AuthorizationErrorRedirect`'s owned `redirect_uri`, `state` and `iss`. A redirectable refusal
costs 6 allocations and 71 bytes against the 8 allocations of the VALID request it replaces, and
reaching it already requires a registered `client_id` and an exactly matching registered
`redirect_uri` (OAuth 2.1 s4.1.3), so it is not the cheaper request to send in volume. Borrowing
the three fields would put a lifetime on a public error enum for a saving the attacker cannot
exploit, and the redirect URI is materialised from an `Arc<Client>` inside the call, so there is
nothing for it to borrow FROM. `tests/refusal_cost.rs` pins the relation rather than the wish.

### Removed: the crate's only `#[must_use]`

`JwtConfig::forget_retired_key_breaking_its_live_tokens` carried one; the other twenty-eight
consuming builders did not, which taught a reader a rule nobody was following. Every builder here
takes `self` BY VALUE, so dropping the result moves the receiver away and the borrow checker
already refuses the next use of it; what the attribute added was the case where the whole
expression is discarded and the value never used again, which is dead code rather than a setting
silently lost. (For a `&self -> Self` builder the analysis is the opposite. This crate has none.)
`tests/host_api_shape.rs` now gates it as ALL or NOTHING, so a later decision to mark them all
stays available and a second lone attribute does not.

### Changed: one hex encoder instead of two

`server::hex_encode` (device codes, authorization codes, opaque tokens) and `client::hex_lower`
(the stored secret verifier) were byte-for-byte identical, down to a private
`b"0123456789abcdef"` table each. They are now one function in a private `crate::hex`, following
the precedent `src/skew.rs` set for `CLOCK_SKEW_LEEWAY`, and `tests/hex_single_definition.rs`
keeps it at one. Only one of the two copies carried the measurement that chose a nibble table over
`write!(out, "{b:02x}")` (1092 ns against 1335 ns for 32 bytes), so a reader improving the other
had nothing telling them the question was settled.

### Documented: three rationales that one optimisation had made false

When `Storage`'s pure reads moved to `Arc`, three separate design arguments lost their premise and
none was updated. Each is re-examined here rather than reworded, and the DECISION is stated
either way:

- **`Client::registration` stays boxed.** The argument was that a `Client` is deep cloned out of
  the store on every token-plane request; `get_client` returns `Arc<Client>` now, so the struct's
  size is not on that path at all. The box is more clearly right than when it was chosen, because
  the optimisation removed its only cost: it used to add an allocation to every clone of a
  registered client, and there are no such clones now. What it buys is memory in the store, and it
  is measured rather than asserted: 8 bytes against 104 inline, a `Client` of 200 bytes rather than
  296, paid per registration whether or not RFC 7591 is enabled.
- **`CertificateThumbprint` stays 32 raw bytes.** Of the three reasons given, the load-bearing one
  never depended on the premise: a fixed 32-byte compare cannot be confused by an encoding
  difference (padded against unpadded, standard alphabet against URL-safe), which is the classic
  way two implementations agree about a certificate and disagree about a string. The clause about
  `IssuedToken` being "cloned out of the host's store on every introspection" is gone, because
  `get_token` returns an `Arc` and introspection clones nothing.
- **The RFC 8693 `act` claim is still not on `IssuedToken`, and that is now a GAP rather than a
  design.** The reason given was that the record is cloned on every token-plane request; it is not.
  On the merits, a delegation that RFC 7662 introspection cannot see is a deficiency, because
  introspection is the only channel an opaque token has. What stands in the way now is the
  PERSISTENCE CONTRACT: `IssuedToken` is the record every host's `Storage` implementation writes,
  so a new field is a schema migration in stores this crate does not own. The module docs say that
  instead of the allocation argument they used to make.

`AuthorizationServer::register_client` also stopped saying that RFC 7591 dynamic registration
"will layer on this" in the future tense: it shipped, and `register_dynamic_client` is it.
`src/registration.rs`'s refusal of an unregisterable `token_endpoint_auth_method` stopped saying
"not one this server advertises", which was false and sent the developer back to a document that
says the opposite: the RFC 8414 list describes the TOKEN ENDPOINT, which accepts four methods that
cannot be REGISTERED because `ClientMetadata` models neither `jwks`/`jwks_uri` nor the RFC 8705
s2.1.1 subject parameters. The constants now carry that containment, and the module docs no longer
claim the crate "does not yet do RFC 7523 client assertions".

`README.md`'s feature count is re-derived rather than picked: the MSRV section said "the other
nine features add no dependency" and the feature table said "ten of the fourteen", and neither was
right once `serde_json` became optional. FIVE features add nothing to a dependency tree at all
(`par`, `consent`, `token-exchange`, `resource-metadata`, `test-util`); three more add no crate of
their own; the rest each bring at least one, and every one of those crates declares a floor below
this crate's 1.75.

### Changed (BREAKING): the storage seam stopped copying what the caller only reads

Measured with the counting allocator against `MemoryStorage`, not asserted. The whole point of a
`get_*` is that the caller reads; handing back an owned clone charged every read for a copy nobody
mutated.

- **`Storage::get_client`, `get_token` and `get_refresh_token` return `Arc<T>`**, as do
  `get_consent`, `find_consent` and `consents_for_subject` under the `consent` feature. Every
  `take_*` and `claim_replay_id` still returns an OWNED value, deliberately: those hand over a
  record the caller is about to be the only owner of, and single-use redemption is the one place
  where sharing would be a bug rather than a saving. `AuthorizationServer::introspect`,
  `remembered_consent` and `consents_for_subject` follow their storage methods.

  RFC 7662 introspection went from 18 allocations to 4. That is the number that mattered most:
  this crate's default access token is opaque, so the client introspects — and a 0.9.2 resource
  server will introspect — on every protected request it serves.

  `get_device_grant` and `find_device_grant_by_user_code` were tried and REVERTED. The device poll
  mutates what it read (`last_poll_at`, and `interval` on a too-fast poll) and writes it back, so an
  `Arc` only moves the clone from the read to the mutation and adds one: measured net +1 on the
  hottest path in the crate.

  Migration for a host's `Storage` impl: wrap the returned record in `Arc::new`. A database-backed
  store pays one allocation on a path that has already done I/O.
- **`ErrorResponse` and `RegistrationErrorResponse` hold `Cow<'static, str>`**, not `String`, and
  `with_description` / `RegistrationErrorResponse::new` take `impl Into<Cow<'static, str>>`, which
  is source-compatible with both `&'static str` and `String`. `ErrorResponse` gains `with_uri`.
  Nearly every description this crate emits is a literal, and each one was being copied onto the
  heap to be handed straight back out. A refused token request now allocates ZERO times end to end,
  down from one. The struct is 56 bytes before and after: `Option<Cow<'static, str>>` and
  `Option<String>` are both 24.

### Changed (BREAKING): `serde_json` is optional, and PKCS#8 key loading has its own feature

Both are dependency-surface changes, both measured, and both free to make now.

- **`serde_json` is an optional dependency**, enabled by `http`, `jwt` (and so `jar`, `dpop`,
  `client_assertion`), `mtls` and `rar`. It was unconditional, and MEASURED, no default build could
  reach it: every use site is behind one of those features, and `#[derive(Serialize)]` needs
  `serde` only, never a format crate. A default build's dependency graph goes from 23 packages to
  19, dropping `serde_json`, `itoa`, `ryu` and `memchr`. Zero linked bytes were at stake (the
  linker already dropped what nothing called); what was at stake is four crates in the audit
  surface of a consumer who never asked for JSON. Nothing a host writes changes unless it was
  relying on this crate to pull `serde_json` into its own tree.
- **`EcdsaP256Key::from_pkcs8_der` and `to_pkcs8_der` now require the `jwt-pkcs8` feature**, which
  is `jwt` plus `p256/pkcs8`. This one comes with a CORRECTION to the figure that motivated it.
  ROADMAP recorded "20,764 linked bytes for ONE constructor". Measured on a release binary
  (`opt-level = "z"`, `strip = true`): a host that enables `jwt` and never calls the loaders paid
  ZERO under `lto = true`, and 192 bytes without LTO, because the linker had already dropped it.
  The ~16.7 KiB of DER decoder is paid only by a host that actually calls it, which is the host
  that wants it. What the split really buys is one crate (`pkcs8` v0.10.2) off a `--features jwt`
  dependency tree, which is this crate's stated dependency policy rather than a byte count.

  Migration: a host loading PKCS#8 DER adds `features = ["jwt-pkcs8"]`. A host loading a raw
  32-byte scalar through `EcdsaP256Key::from_scalar_bytes` changes nothing.

### Changed: the RFC 9068 JOSE header is serialized once, not once per token

`JwtConfig` now precomputes the base64url protected header. It is a function of the active key's
`kid` and two constants, fixed for the life of a configuration and rebuilt only by `rotate_to`, and
it was being serialized and encoded again for every access token signed, producing identical bytes
every time. MEASURED on one `client_credentials` issuance under `--features jwt`: 28 allocations /
4767 bytes before, 26 / 4581 after. The wire bytes are unchanged.

It is built without `serde_json`, and that is what makes precomputing it INFALLIBLE: a `Result` here
would have made `JwtConfig::new` and `rotate_to` fallible, or forced an `expect` into a library that
must not panic, for an error that cannot occur on three string members.

### Changed: two `Box::pin`s that had stopped paying for themselves

Both were introduced with a measurement and both were RE-measured rather than trusted, which is the
only reason either was found. Neither is an API change.

- **The RFC 9449 DPoP proof check is no longer boxed.** `token_with_context` reached it through a
  `Box::pin` so the proof-check state would stay out of the token future, which
  `tests/allocation.rs` holds under tokio's 2048-byte debug boxing threshold. Measured both ways on
  four feature sets, the future is byte for byte identical: 1136 under `dpop` alone, 1248 with
  `rar`, 1280 with `mtls,consent,rar,par`, 1344 `--all-features`. The earlier restructuring of
  `token_with_context` had already moved the high-water mark elsewhere, so the box was buying
  nothing and costing one 168-byte allocation on EVERY token request under the feature, INCLUDING
  every refusal, which is traffic an attacker sets the rate of. A refused token request now
  allocates exactly zero on every feature set; `refused_token_request_allocation_bound` had been
  carrying `dpop` as a named exception and no longer needs to.
- **The RFC 7523 client-assertion check is no longer boxed**, for the same reason and with the same
  kind of measurement: 1144 under `client_assertion` alone, 1256 with `rar`, 1344 with
  `dpop,mtls,consent,rar,par` and `--all-features`, identical boxed and unboxed. What it was
  costing is one allocation on every token request that presents an assertion, which for a
  `private_key_jwt` deployment is every token request it makes. Measured on that path: 40
  allocations to 38 `--all-features` (the second saving is the DPoP box above).

`issue_boxed` was re-measured too and KEPT. Inlining it takes the `--all-features` token future from
1344 to 1608, leaving 440 bytes of headroom against tokio's 2048 rather than 704, to save one
allocation out of the 39 a code redemption already costs. This crate has crossed that threshold
twice, once for 120 bytes and once for 344, and the failure mode on the other side is a 2 KB heap
allocation on every token request. The trade is refused, with the number, in the function's docs.

### Fixed (security): the reuse alarm that went dark exactly when the store was flaky

Two redemptions destroy a credential and mint replacements: the authorization code grant (RFC 6749
s4.1.3) and refresh rotation (OAuth 2.1 draft s6.1). Both begin with an ATOMIC TAKE, which is what
makes them single use under concurrency, and both then have to write a record saying the taken
credential was spent, because that record IS the replay and reuse alarm (RFC 6749 s4.1.2, RFC 9700
s4.1.1 and s4.14.2). `Storage` deliberately has no transaction, so the take and that write cannot be
made one operation; the only thing that can be chosen is the ORDER, and the order decides which way
the pair fails.

Both wrote the spent record AFTER minting and persisting the new tokens, which fails OPEN. If
anything in issuance failed, the old credential was gone from the store with no spent record, so a
later presentation of it read as an UNKNOWN STRING rather than as reuse: detection for that family
was off, permanently and silently, at exactly the moment a deployment's storage was misbehaving. The
freshly minted tokens meanwhile stayed live and orphaned, because the caller was answered with an
error and never saw them. The same ordering also left the credential entirely absent from the store
for the whole duration of minting on the HAPPY path, so a presentation racing the legitimate client
in that window was answered `invalid_grant` and never counted as reuse either.

- **The spent refresh record is now written BEFORE issuance.** This fails CLOSED: a failed write
  means nothing was minted and the client re-authenticates; a write that succeeds and an issuance
  that then fails means the client is locked out of that chain and re-authenticates, with the alarm
  ARMED. Locking a client out is an inconvenience it recovers from without help; a
  compromise-detection capability going offline is not. The argument is in the code, at the call
  site, because a host reading `Storage`'s lack of a transaction needs to know this is a design seam
  and not a slip.
- **The consumed authorization code record is now written BEFORE issuance**, for the same reason and
  with the same argument. What the code minted is not knowable until it has been minted, so a SECOND
  write records that afterwards; if that one fails the alarm is already armed, the redemption is
  refused, and the two orphaned artifacts are cleaned up best effort.
- **BREAKING: `AuthorizationCodeState::Consumed::access_token` is `Option<String>`.** `None` is a
  code that was marked consumed by a redemption whose issuance did not complete: a replay of it is
  still recognised and reported, and there is genuinely nothing to revoke. Persisted records written
  by earlier versions deserialize unchanged, since a JSON string reads back as `Some`.
- **The authorization-code replay branch no longer reads a storage FAILURE as "no chain to
  revoke".** `if let Ok(Some(rec)) = get_refresh_token(..)` folded the `Err` arm into the `Ok(None)`
  arm, so a store that could not answer left `containment_failed` FALSE while the family revocation
  was never even attempted. That flag exists precisely to stop the audit event overstating what the
  server achieved, and this path defeated it.

### Fixed (security): lost updates on the device grant

- **BEHAVIOUR CHANGE: a device-grant poll can no longer revert the user's decision.**
  `device_token` read the grant, then blind-wrote it back through `put_device_grant` on both its
  non-terminal paths (`authorization_pending` and `slow_down`). A concurrent `approve_device` or
  `deny_device` landing between that read and that write was silently reverted, with the
  verification UI having already told the user their answer was recorded. The worst case is a
  DENIAL being thrown away: the grant returns to `Pending` and goes on to be approved by whoever
  reaches the code next. Both writes are now compare-and-swaps against the state the poll read, and
  a missed swap is neither retried nor reported as an error: the poll simply declines to write. The
  asymmetry is deliberate and is argued at the call site. A lost poll timestamp costs at most one
  extra `slow_down`; a lost decision is a lost human answer, so the timestamp is the losable half.
- **BEHAVIOUR CHANGE: `approve_device` and `deny_device` are first-decision-wins.** Both were
  read-modify-writes with no compare-and-swap, so two concurrent verification-UI actions on one user
  code clobbered each other and the winner was whichever wrote last. Both now swap against
  `Pending`, and the loser is answered `DeviceApprovalError::NotPending`, which is exactly the
  answer it would have received had it arrived a moment later. Hosts that call these from a UI where
  two actions on one code are possible will now see `NotPending` where a write previously succeeded.
- **`Storage::compare_and_swap_device_grant`**, the primitive the two items above rest on. It is a
  REQUIRED method with NO default implementation; see the next section for why the default it
  briefly had was removed. `MemoryStorage` performs the whole operation under one lock, and
  `oauth-as-postgres` performs it as one conditional `UPDATE ... WHERE`.

### Documented: three claims that had stopped being true

- **`src/token.rs`'s module docs** said structured RFC 9068 access tokens were "a possible later
  addition"; the `jwt` feature implements them. **`TokenResponse::token_type`** said "Always
  `Bearer` from this server"; under `dpop` the server sets `DPoP`, because RFC 9449 s5 forbids
  presenting a sender-constrained token as a bearer token. Both were stale docs on a published API,
  which is the kind that gets believed.
- **`src/rar.rs`'s module docs** said all three `authorization_details` bounds are applied "BEFORE
  any structure is built". Only `MAX_AUTHORIZATION_DETAILS_BYTES` is; the element count and the
  depth run on the already-parsed tree. The docs now say which runs where, and say why the order is
  deliberate: checking the other two earlier would mean a second JSON scanner here that has to
  agree with `serde_json` about strings and escapes, and a scanner that disagrees is a parser
  differential, a worse class of bug than the one it would prevent.

  The depth constant's own claim that "nothing here can be made to recurse until the stack runs
  out" was resting on `serde_json`'s recursion limit near 128, which is a dependency's
  implementation detail and not a contract. It now rests on this crate's own byte bound instead: 4096
  bytes of raw JSON cannot express more than about 2047 levels, since a level costs at least a
  byte, so the parse and the tree's recursive `Drop` are bounded whatever the parser was
  configured to allow. `tests/cap_boundaries.rs` sends exactly that worst case.

### Tested: the accepting side of three caps

A bound tested only one PAST its limit is half tested. `>=` where `>` was meant refuses a request
the constant says is legal, every assertion about the refusal still passes, and the defect surfaces
as a client that cannot make a request the documentation permits. Most of this crate's caps already
had an at-cap acceptance case; these did not, and both new ones were watched failing with the
operator flipped:

- `MAX_PROOF_BYTES`, with a real ES256 proof of exactly 4096 bytes (the padding is solved for, not
  searched, because base64url without padding cannot reach every total length from one knob).
- `MAX_RESOURCE_INDICATORS` at the TOKEN endpoint. The authorization endpoint's half already had
  one, and both run through the same `validate_resources`, so an off-by-one would have broken both
  while only one could see it.

REJECTED from the same finding: `MAX_AUDIENCE_VALUES`, `MAX_CONSENT_RESOURCES`,
`MAX_REGISTERED_REDIRECT_URIS` and `MAX_FORM_PARAMETERS` already have at-cap acceptance cases, as
do all three `authorization_details` bounds.

### Fixed: two silent failures, one on the wire and one in the exported harness

- **A pushed authorization request that cannot be restored is `server_error`, not
  `invalid_request_uri`.** RFC 9126 s7.5 request URI swapping is refused by putting the record
  BACK, since the take that resolved it has already removed it, and that write's `Result` was
  discarded. If it failed, an honest client's live handle had just been destroyed by a stranger's
  request and the answer was the same routine refusal any made-up handle gets: the owner would
  arrive a moment later, be told `invalid_request_uri` too, and nobody would connect the two. The
  authorization code path in `src/server.rs` argues exactly this and propagates; the two are now
  consistent. It leaks nothing, because reaching that branch requires a real handle and the
  difference between the answers is a store failure no caller can provoke.
- **`revoke_consent/cascades` fails loudly when a fixture does not persist.** The check seeds four
  kinds of record per subject and discarded the `Result` of three of the four puts. Every assertion
  that follows is "the record is gone", and a record that was never written is gone, so a store
  that silently failed to persist a fixture PASSED the cascade check for the wrong reason. This is
  the exported harness, so that false pass would have certified a stranger's broken store. Each
  seed is now reported by name.

### Fixed (security): the compare-and-swap shim resurrected redeemed device grants

`Storage::compare_and_swap_device_grant` shipped in this same unreleased cycle with a default body
that did the read, the comparison and the write as three calls, documented as a compatibility shim
that narrowed the race without closing it. That account was wrong in a way the docs did not cover,
and three independent review lenses converged on it.

The shim's write went through `put_device_grant`, which is an INSERT-OR-UPDATE. `take_device_grant`
is RFC 8628 single-use redemption. A grant redeemed between the shim's read and the shim's write is
GONE, and an upsert neither fails nor no-ops against a row that is not there: it puts the grant
BACK. So the shim did not merely fail to prevent a lost update, it manufactured a device code that
could be exchanged for a token TWICE, which is a worse defect than the one it mitigated, and it
contradicted the method's own doc two paragraphs above it ("a swap must never bring it back").

- **BREAKING: `Storage::compare_and_swap_device_grant` has no default implementation.** A default
  that is silently incorrect is worse than none, because the host who never reads the doc gets no
  signal at all: their store compiles, their tests pass, and the first-decision-wins guarantee is
  void in production. Requiring the method makes that a compile error naming the method, which is
  the loudest and cheapest signal available and costs a host who has already written the other four
  device-grant methods exactly one more.
- **`PostgresStorage` implements it**, as ONE conditional statement,
  `UPDATE ... WHERE device_code = $1 AND payload -> 'state' = $7`, so the database performs the
  comparison and the write together. It is an `UPDATE` and not an upsert deliberately: an `UPDATE`
  cannot create a row, so a redeemed grant cannot be resurrected by construction. This is the one
  shipped backend that is by definition shared and multi-process, so it was precisely the
  deployment the shim could not serve, and it inherited the shim. `tests/two_connection.rs` proves
  both properties against a real database, each with a permanent red proof against
  `naive::compare_and_swap_device_grant_read_then_write`: the conditional update has exactly one
  winner in 100/100 rounds where the shim loses an update in 100/100, and the shim resurrects a
  redeemed grant where the update leaves it gone.
- **The exported conformance harness now checks it**, which it did not: a host could implement the
  swap as an unconditional `UPDATE ... WHERE device_code = $1`, or as Redis `GET` / compare /
  `SET` with no `WATCH`, run `StorageConformance` as the docs instruct, get an empty violation
  list and ship. Three new checks, all in `CHECKS`:
  `compare_and_swap_device_grant/applies_when_the_state_matches`,
  `compare_and_swap_device_grant/honours_expected` and
  `compare_and_swap_device_grant/never_resurrects`. Both failure modes are perfectly ATOMIC, so no
  `atomic_take/*` check could ever have seen them. `tests/storage_conformance_selftest.rs` plants
  each fault and watches the harness go red on it.
- **`MemoryStorage::compare_and_swap_device_grant` enforces the user-code uniqueness requirement**
  that `put_device_grant` does. Its doc claimed the index maintenance was delegated to that method
  and therefore could not drift; it was not delegated, and it had already drifted, so a swap could
  hand one RFC 8628 s6.1 user code to two grants where a put would have refused.

### Performance: the entropy draw, where the allocation gates and the clock disagreed

No behaviour change and no API change: the artifacts are byte for byte what they were, drawn from
the same OS randomness with the same rejection sampling. What changed is the number of SYSCALLS.
`getrandom::fill`'s cost is almost entirely per CALL and barely at all per byte (MEASURED: 875 ns
for one byte, 1025 ns for thirty-two), which the crate's allocation gates cannot see: they reported
19 allocations before and after, while the clock reported a factor of five. Numbers are medians from
`crates/oauth-as/benches`, `--all-features`, same machine and profile, before and after.

- **`random_user_code` drew one byte per call**, so the syscall count was the length of the code.
  `device_authorization` 9.36 us -> 2.66 us. It now fills a 64-byte stack buffer and refills it if a
  run of rejections exhausts it; no allocation is added and the uniformity argument is untouched.
- **`issue` drew the family id, the access token and the refresh token separately.** One 80-byte
  draw now feeds all three, in a scope with no await inside it so the buffer never joins the
  coroutine state (the token future is held under tokio's 2048-byte boxing threshold).
  `authorization_code_redemption` 4.84 us -> 2.21 us, `refresh_rotation` 3.50 us -> 2.13 us,
  `client_credentials_issue` 1.97 us -> 1.84 us.
- **`random_hex` formatted each byte through `core::fmt`.** A nibble table instead: 1335 ns ->
  1092 ns for a 32-byte artifact.

Not taken, with the reason recorded in the code rather than only here: **`verify_dpop` still runs
before `authenticate_client`**. A DPoP proof with a wrong signature costs a full P-256 verification
(133.18 us, indistinguishable from a valid one until it finishes, against 34 ns for a merely
malformed proof), so an unauthenticated caller buys that per request. Reordering would change the
wire answer for a request with both a bad secret and a bad proof, from `invalid_dpop_proof` to
`invalid_client`, and would not help against a caller holding any valid client credential; RFC 9449
offers nothing cheaper to pre-filter on, since the verifying key is learned FROM the proof. The
honest mitigation is the rate limiter, and the cost is now documented at the call site so a host can
size one. Likewise **`ScopeSet::parse` is still uncapped** (31 ns at one token, 80.37 us at a
thousand): the growth is n log n rather than quadratic, and a cap cannot be expressed without
breaking `InvalidScopeToken`, which is also the deserializer for every persisted record carrying a
scope. Both are written up on the items themselves.

### Fixed (security): failures reported as successes

The wire cannot carry any of these, so the audit sink is the only place the truth can be told. An
event that overstates a containment is worse than no event, because it is what an operator reads
while deciding not to investigate.

- **BREAKING: `Event::AuthorizationCodeReplayDetected` gains `containment_failed: bool`, and
  `tokens_revoked` now means what it says.** On a replayed authorization code the family
  revocation's `Result` was DISCARDED while `tokens_revoked: true` was set unconditionally, so a
  store that failed at the one moment this server was responding to a detected compromise reported
  a clean containment: the attacker's refresh chain still live, the audit log saying it was killed.
  The fallback deletion of the access token the code minted, and the write that puts the consumed
  code record back (which is what makes the NEXT replay detectable at all), were fire-and-forget
  too. All three now feed `containment_failed`. Hosts matching this variant exhaustively must add
  the field.
- **BREAKING: `Event::RefreshTokenReuseDetected` gains `containment_failed: bool`, and a reuse the
  server could not contain is now REPORTED rather than swallowed.** This is the other half of the
  argument above, and the refresh path had the worse version of it: the event was not overstated,
  it was ABSENT. `take_refresh_token` has already removed the spent record by the time the family
  revocation runs, and that revocation's error was propagated with `?`, so three things were true
  at once — the family was not revoked and the thief's rotated chain stayed live; the spent record
  was gone and never put back, so RFC 9700 s4.14.2 reuse detection for that family was off
  PERMANENTLY and a later presentation of the same string read as an unknown token; and no event
  fired, so the host's only audit channel was never told. The event now fires on BOTH outcomes
  (with `records_revoked: 0` on the failure), the spent record goes back so the alarm stays armed,
  and the wire answer is `invalid_grant` either way, as it already was. Hosts matching this variant
  exhaustively must add the field: `Event` is `#[non_exhaustive]`, but the VARIANT's fields are
  not, so a `match` arm that destructures it without `..` fails to compile until it is updated.
  The same is true of the two variants below and was true of them in this release already.
- **BREAKING: `Event::TokenRevoked` gains `cascade_failed: bool`.** RFC 7009 s2.1's SHOULD, that
  revoking a refresh token also invalidates the access tokens of the same grant, remains
  deliberately non-fatal (turning a completed revocation into an error would tell an honest client
  nothing happened when the token it named is already gone), but it fired the event unconditionally,
  so an operator could not tell a complete revocation from one that left every access token of the
  grant alive for its full TTL. Always `false` for an access token, which has no grant-wide cascade.
- **BEHAVIOUR CHANGE: a storage failure while restoring an authorization code after a client-id
  mismatch is now `server_error`, not `invalid_grant`.** The restore was fire-and-forget, so a
  failure destroyed a LIVE code belonging to an honest client and answered as though it had merely
  refused a stranger. The honest client would then be told `invalid_grant` a moment later and
  nobody would connect the two. Reaching this branch requires a real code, and the difference
  between the two answers is a store failure the caller cannot provoke, so it is not an oracle.

### Fixed (security): work an unauthenticated caller could buy by sending more

RFC 9396's `authorization_details` array had an explicit element cap and a stated reason for its
number; the other repeatable arrays reachable from the same endpoints had neither. That asymmetry
was the finding. In every case the fix is the CAP and not the algorithm: at sixteen a linear scan
beats a `HashSet` (which pays a hash of the whole string per lookup), and the defect was never the
loop, it was that nothing bounded `n`.

- **BEHAVIOUR CHANGE: `oauth_as::server::MAX_RESOURCE_INDICATORS` (16).** RFC 8707 s2 makes
  `resource` repeatable, it is accepted at the authorization endpoint (which takes no client
  credential), and validation was O(n) against the allowlist plus an O(n) dedup scan per element.
  MEASURED: 2.16 us at n=1, 16.93 us at 100, 1.08 ms at 1000, with the per-element cost RISING from
  167 ns to 1030 ns, which is the quadratic signature. A request past the cap is now
  `invalid_target`. It REFUSES rather than truncating: silently dropping indicators would issue a
  token whose audience is not the one the client asked for, with nothing told to anybody. The count
  is taken on the INPUT, not on the deduplicated result, so ten thousand copies of one URI are
  refused too.
- **BEHAVIOUR CHANGE: `oauth_as::token_exchange::MAX_AUDIENCE_VALUES` (16).** The same unbounded
  O(n*m) dedup of RFC 8693 s2.1.1 `audience` against the validated `resource` list. Deliberately the
  same constant as above, because s2.1.1 says the two parameters name the same thing in two
  spellings.
- **BEHAVIOUR CHANGE: `oauth_as::consent::MAX_CONSENT_RESOURCES` (32),** and the worst of the three
  because the cost was DURABLE rather than per request. `ConsentRecord::extend` deduplicated newly
  requested resources against the PERSISTED list, which is the union of everything ever approved for
  a (client, subject) pair, was only ever widened, and is walked linearly by `covers` on every
  authorization request that consults it. A client naming one fresh indicator per request bought a
  permanently larger record and a permanently slower check. The cap refuses to GROW and never
  prunes: a resource that did not fit reads as not covered, so the host re-prompts, which is the
  harmless direction and the same one the scope union already fails in.
- **BEHAVIOUR CHANGE: `oauth_as::registration::MAX_REGISTERED_REDIRECT_URIS` (16).** RFC 7591 s2 set
  no bound, and `redirect_uris` is scanned linearly with exact string comparison (OAuth 2.1 s4.1.3
  allows nothing cheaper) on every authorization request for the client. A registration is durable,
  so an unbounded list bought once at an endpoint a policy may have opened to anonymous callers is a
  per-request cost that lasts as long as the registration. Past the cap is `invalid_redirect_uri`.
- **BEHAVIOUR CHANGE: the `invalid_scope` refusal no longer echoes the requested scope, and no
  longer allocates.** `resolve_scope` built its `error_description` with `format!`, interpolating
  the caller's own scope string, on a refusal an UNAUTHENTICATED caller can drive at will through
  the RFC 8628 s3.1 device authorization endpoint. That contradicts the crate's own stated rule,
  documented on `tests/allocation.rs`'s `refused_token_request_allocation_bound`, that a refusal is
  work the attacker buys. It is now a `&'static str`, like the roughly fifty other refusal sites.

### Fixed (security)

- **BEHAVIOUR CHANGE: an expired dynamically-registered client secret stops authenticating.**
  `authenticate_client` never consulted `DynamicRegistration::client_secret_expires_at`, so a secret
  this server itself MINTED, and published an expiry for in its RFC 7591 s3.2.1 registration
  response, went on working forever. A rotation window a server announces and does not enforce is
  worse than none, because the operator believes the old secret stopped working on the stated day.
  The check sits before every credential branch, so `client_secret_jwt` (which also authenticates
  with the shared secret) cannot route around it; s3.2.1's `0` still means never. The wire answer is
  the same bare `invalid_client` as every other client authentication failure; the audit channel is
  told, through the new `ClientAuthFailure::SecretExpired`.
- **BEHAVIOUR CHANGE: RFC 8693 token exchange REFUSES a sender-constrained subject token.** A
  DPoP-bound (RFC 9449 `cnf.jkt`) or certificate-bound (RFC 8705 `x5t#S256`) access token presented
  as `subject_token` was exchanged into a new UNBOUND bearer token, with no proof of possession
  asked for at any point: the exchange read neither binding off the record it introspected. That
  hands anyone who can authenticate as any client registered for the grant, an insider, a
  compromised service, a leaked client secret, a laundry for stolen bound tokens, and destroys the
  one property sender constraining is bought for, which is that a leaked token is worth nothing
  without the key. The answer is now `invalid_request`, which RFC 8693 s2.2.2 names for a
  `subject_token` that is unacceptable based on policy. Propagating the `cnf` instead was
  considered and rejected: the issued token belongs to the EXCHANGING client, which does not hold
  the original client's key, so the token would be unusable at any resource server that checks the
  binding (RFC 9449 s7.1) while looking as though possession had been proven. An unbound subject
  token exchanges exactly as before. See the module docs in `src/token_exchange.rs`.

  The refusal is now guarded by **`ServerConfig::allow_sender_constrained_exchange`, `false` by
  default**, which is a MIGRATION path and not a tuning knob: 0.9.0 and earlier performed the
  downgrade silently, so a deployment already built on it needs a way to keep running while it
  moves off. Setting it to `true` restores the old behaviour, and what that gives up is exactly the
  property above: a leaked bound token becomes spendable again via one request to this endpoint.
  The field's own docs say so in those words.
- **`DeviceApprovalError` is `#[non_exhaustive]`.** BREAKING for a host that matches it
  exhaustively, and the reason it should not have been possible to do so: `lib.rs` re-exports this
  type specifically so a host's verification UI can match on it, and every sibling host-facing
  failure enum in the crate already carried the attribute. Without it, any new way to refuse an
  entered user code is a semver-major change for every host.
- **Three `SystemTime` overflow panics on attacker-supplied time claims**, all reachable from an
  unauthenticated request: `iat` in a DPoP proof (`src/dpop.rs`), and `exp`, `nbf` and `iat` in an
  RFC 7523 client assertion (`src/client_assertion.rs`). Each value is a `u64` out of JSON that
  nobody has authenticated yet, and `UNIX_EPOCH + Duration::from_secs(u64::MAX)` panics rather than
  wrapping, before any bound was compared: a `DPoP` header reading `{"iat": 18446744073709551615}`
  panicked the request. In a library that panic unwinds into the host's request handler. The
  arithmetic is `checked_add` now, and an unrepresentable instant takes the refusal the module
  already had for a time claim it will not accept (`DpopFailure::StaleProof`,
  `AssertionFailure::Expired`, `AssertionFailure::NotYetValid`), which is correct on the merits: a
  time that cannot be represented is outside every acceptance window a server could pick.

### Added

- **`oauth_as::dpop::MAX_PROOF_BYTES` (4096)**, the first bound this crate has ever put on a DPoP
  proof, checked BEFORE the proof is parsed. The proof arrives in a request HEADER, so the `http`
  feature's 64 KiB body cap never applied to it, and an unauthenticated string went straight into a
  base64 decode and two JSON parses. 4096 is derived from what RFC 9449 s4.2 says a proof contains
  (a P-256 JWK, `htm`, `htu`, `iat`, `jti`, an ES256 signature: a little over 500 bytes in
  practice), with room for a long `htu` and future claims. A host's HTTP server usually caps header
  size too, so this is defence in depth rather than the only line; it is here because this library
  never sees the socket and because `verify_proof` is public. Over the cap is `DpopFailure::Malformed`.
- **`oauth_as::http::MAX_FORM_PARAMETERS` (64)**, a cap on how many form or query parameters one
  request may carry, checked before any of them is decoded. `MAX_BODY_BYTES` bounded the BYTES an
  anonymous caller could make the service hold and did not bound the WORK, because decoding is per
  parameter: measured with `benches/http_surface.rs` before and after, `POST /token` cost 2.65 us
  with no extra parameters and 83.33 us with 1024 ignored ones, against 163 ns for a 404; with the
  cap the same request costs 14.50 us, and what remains is buffering the body rather than decoding
  it. 64 KiB of `&a=b` pairs is roughly 2300 parameters, so one unauthenticated packet bought about
  three orders of magnitude more work than the cheapest thing the service can do, and the GET
  endpoints were worse because their parameters arrive in a URL the body cap never applied to.
  64 is about three times the
  largest request this crate can construct (an RFC 9126 push carrying every authorization
  parameter is about twenty), with the headroom left for repeated RFC 8707 `resource` indicators
  and for extension parameters the server ignores. Over the cap is a 413 with no protocol body, the
  same shape the byte cap uses, decided by a count of `&` separators that stops reading at the cap.
- `impl std::error::Error` (and `Display`) `for ClientAuthFailure`. It is the `Err` payload of
  `authenticate_via_mtls`, exactly as `AssertionFailure`, `DpopFailure`, `StepUpFailure`,
  `RegistrationFailure` and `MtlsRegistrationError` are of theirs, and it was the last one a host
  could not put behind `?` or into a `Box<dyn Error>`. The `Display` strings are the OPERATOR's
  sentences: the wire still collapses every variant into one `invalid_client`.
- `impl std::error::Error for StepUpFailure`. It was one of the two error-shaped types in the crate
  without one; `ClientAuthFailure`, above, was the other.
- `ServerConfig::refresh_token_ttl` and `ServerConfig::include_verification_uri_complete` document
  the risk their defaults carry, matching what `allowed_resources` already did: `None` on a refresh
  chain means a token exfiltrated once is a credential forever, and RFC 9700 s4.14.2 reuse
  detection catches only the thief whose victim comes back.
- Pointer sentences on the three items a host's fingers touch and whose one-line docs hid a
  load-bearing caveat: `MtlsClientRegistration::accepts`, `ClientCertificate::from_der` (both back
  to the `mtls` trust boundary section) and `Authentication::at` (do not stamp `auth_time` with
  `now`).

### Changed: one clock-skew constant instead of two that had to be kept equal

- **`dpop::CLOCK_SKEW_LEEWAY` and `client_assertion::CLOCK_SKEW_LEEWAY` are now the same
  constant**, defined once in a private module and re-exported by both. NOT a breaking change: both
  public paths still resolve and the value is unchanged (60 seconds). They were two `pub const`
  declarations of the same number, one of whose doc comments pointed at the other "for the same
  reason", which is a comment admitting that two values had to be kept in step by hand. Neither
  module could own it, because `dpop` and `client_assertion` are independent features and a build
  may have either alone. `tests/clock_skew_single_definition.rs` scans the source and fails if a
  second definition appears.

### Changed: a refusal that allocated, and a sweep that took one long lock

- **A missing-required-parameter refusal borrows its description** instead of formatting one.
  `http.rs`'s `required()` built a `String` per refusal although the parameter name is always a
  `&'static str` from a set of six; every other refusal in the file passes a literal into
  `error_description`, which is a `Cow<'static, str>`. The rule is the one `tests/allocation.rs`
  states on `refused_token_request_allocation_bound`: a refusal is work an attacker sets the rate
  of. The unit test reads the call sites out of `http.rs`'s own source, so a new `required(..)`
  whose name is not in the borrowing table fails rather than quietly allocating again.
- **`oauth-as-postgres`: `sweep_expired` deletes in committed batches** of
  `oauth_as_postgres::SWEEP_BATCH_ROWS` (5000) per table, looping until the table is drained,
  instead of one unbounded `DELETE` per table inside one transaction. The old form took a row lock
  on every dead row and held all of them until the statement finished, so a table with millions of
  dead rows blocked the live redemptions that touched them. The CONTRACT is unchanged: one call
  still removes every record dead at `now` and still returns how many it removed. The transaction
  is gone deliberately and is not a weakening, because every row removed is one the server already
  refuses on time alone, and because locks are released at commit, so batching inside one
  transaction would have held every lock to the end exactly as the single statement did. Batches
  use `FOR UPDATE SKIP LOCKED`, so several nodes sweeping at once no longer queue behind each
  other; each call's count is what that call removed.

### Documented

- **`oauth-as-postgres`: `delete_client` is not a kill switch**, stated where a host reads it (the
  crate README and the `src/store.rs` module docs). It removes the registration and everything the
  store holds for it as of the moment it runs, in one transaction, and a token request that read
  the registration before the delete committed still writes its token after. No store can close
  that window: a foreign key would turn the losing write into a `server_error` on a request that
  did nothing wrong (and would break the legitimate writes the schema's no-foreign-keys note
  already describes), PostgreSQL's serializable isolation only detects a conflict between
  transactions that are both `SERIALIZABLE` (`put_token` is a single autocommit statement), and the
  statement order inside one transaction is invisible from outside it. The obligation is the
  host's: stop issuing for a client before deleting it, and delete a second time once in-flight
  requests have drained.

## [0.9.0-rc.1] - 2026-08-08 (development snapshot, superseded by 0.9.0 above)

**0.9.0 adds no new protocol surface. It exists to prove the crate against the outside world**,
and the most valuable thing in it is an honest account of what could and could not
be proven. Everything between 0.1.0 and 0.8.0 is folded in here, because those versions were built
and promoted but never published: from crates.io's point of view this is the first release with an
implementation in it.

### Added: external verification (the point of this release)

- **A SECOND independent third-party client**, in a different language and from a different
  author: `golang.org/x/oauth2 v0.36.0`, maintained by the Go project, pinned exactly with a
  committed `go.sum`. It is deliberately not a second opinion on the same questions: it drives the
  RFC 6749 section 4.4 client credentials grant and the section 6 refresh grant with rotation,
  neither of which the pinned Rust `oauth2 = "=5.0.0"` drive covers, as well as the device grant
  and authorization code with PKCE. Lives in `crates/oauth-as-conformance/interop/go`, run by
  `scripts/oauth-interop.sh`, whose `--selftest` shows the gate red on both axes before any green
  is trusted. Two independently written client libraries now accept this server's wire bytes.
- **A third-party scanner now reaches this crate's RFC 8414 document**: the `authgent` MCP-OAuth
  scanner, pinned at `authgent-server==0.3.4` and wired into `qa.yml` through its own composite
  action `authgent/authgent/.github/actions/mcp-lint@v0.3.4`. That scanner bails without RFC 9728
  protected resource metadata; RFC 9728 landed in the crate, so the
  blocker is now removable honestly, with a loopback fixture resource that publishes a document
  that is TRUE about the deployment under test. **This project is not an MCP server and does not
  claim to be one; the scanner's MCP verdict is quoted nowhere.** What is claimed is exactly that
  its RFC 8414, RFC 7636, RFC 9207, RFC 8707 and RFC 7591 checks were applied to this crate's
  metadata document by a tool nobody here wrote. The full argument for why the fixture is
  legitimate rather than a dodge is at the top of `scripts/oauth-mcp-lint.sh`.
- **The scanner's findings are recorded, not silenced.** `crates/oauth-as-conformance/authgent-baseline.json`
  holds three accepted findings with the reason for each, and the gate is on anything NEW rather
  than on zero: `MCP-AUD-001` (error) wants a `resource_indicators_supported` metadata member that
  RFC 8707 does not register and this crate does not emit; `MCP-DCR-001` and `MCP-REFRESH-001`
  (warnings) want a registration endpoint and DPoP algorithms, both implemented in the crate and
  both deliberately off in the conformance example.
- `crates/oauth-as/examples/protected_resource_fixture.rs`, a worked example of the RFC 9728 host
  seam: where the document goes (section 3.1 INSERTS the well-known string between host and path),
  and the section 5.1 `WWW-Authenticate: Bearer resource_metadata="..."` challenge an
  unauthenticated request gets. `ProtectedResourceMetadata` previously had no consumer anywhere in
  the tree.
- **`crates/oauth-as-conformance/EXTERNAL-TOOLING.md`**, the written record of what external
  tooling was run, what was refused, and why. It includes the FAPI 2.0 verdict below.

### Changed: the FAPI 2.0 record, which was wrong

- **The OpenID Foundation suite CAN test a non-OIDC authorization server, and the previous claim
  in `qa.yml` and `crates/oauth-as-conformance/Cargo.toml` that it "presupposes OpenID Connect
  semantics" is corrected.** The FAPI 2.0 Security Profile plans carry an `openid=plain_oauth`
  variant that discovers through `/.well-known/oauth-authorization-server`, never asks for an
  `id_token`, and yields a real certification profile name. A run is achievable headless, entirely
  on localhost, with a self-signed certificate: the suite trusts all server certificates and
  drives its browser steps through an in-JVM HtmlUnit driver.
- **It is still not run**, and the reasons are now a finite written list rather than a category
  error: the plan requires a protected resource endpoint that verifies a sender-constrained token,
  HTTPS, two static clients with distinct keys, mandatory PAR, and
  `require_pushed_authorization_requests` present as a boolean. Citations in
  `EXTERNAL-TOOLING.md`.
- One genuine conflict, recorded rather than resolved: **FAPI 2.0 section 5.3.2.1-9 says the
  authorization server shall NOT use refresh token rotation**, while OAuth 2.1 section 6.1 and RFC
  9700 section 4.14.2 are why this crate rotates and revokes the family on reuse. A FAPI 2.0 run
  would need rotation configurable off. Neither side is wrong; they are optimising different
  things.
- One thing could not be confirmed from any primary source and is stated as unknown: whether the
  OpenID Foundation accepts logs from a locally deployed suite for a certification submission.

### Added: protocol surface, 0.2.0 through 0.8.0

Folded in here because none of those versions was published.

- **RFC 7523 JWT client assertions**: `private_key_jwt` (ES256) and `client_secret_jwt` (HS256),
  behind an off-by-default `client_assertion` feature. Until this landed, a deployment whose
  security policy forbids transmitting a shared secret could not use this crate at all. The
  feature IMPLIES `jwt` on purpose: this and `dpop` both rest on JWS verification, and the crate
  holds exactly one copy of that code, because two half-built verifiers behind two independent
  flags is how a codebase acquires an algorithm-confusion bug in whichever half nobody reviewed.
- **RFC 9449 DPoP** sender-constrained access tokens, behind an off-by-default `dpop` feature.
  This is the change that alters what a token leak costs: without it every token this crate issues
  is a bearer token, usable by whoever stole it.
- **RFC 8705 mutual-TLS client authentication and certificate-bound access tokens**, with a seam
  for the host to pass in the verified client certificate, since TLS termination is the host's job
  in this design.
- **RFC 9126 pushed authorization requests** and **RFC 9101 signed request objects**, behind
  off-by-default `par` and `jar` features, so authorization parameters need never traverse the
  browser.
- **RFC 9728 protected resource metadata**, behind an off-by-default `resource-metadata` feature.
  What it adds is the TYPE a host publishes for its OWN resource, plus the section 4
  `protected_resources` member on the RFC 8414 document. It does NOT make this crate a resource
  server, does not route anything, and does not validate access tokens; section 3.1 places that
  document under the resource's identifier, not the issuer's.
- **RFC 8693 token exchange**, behind an off-by-default `token-exchange` feature. Off by default
  because it is a grant that mints a token from a token, and a deployment that has not decided its
  delegation policy should not have the endpoint compiled in.
- **RFC 9396 rich authorization requests**, structured authorization detail beyond scope strings.
- **An exportable `Storage` conformance harness** (`storage_conformance`), so a host can prove its
  own `Storage` implementation satisfies the atomicity contract. This matters more than it sounds:
  a host implementing `take_*` as read-then-delete gets undetectable refresh token double spend on
  a multi-node deployment, and nothing else in the crate can catch that. It is proven able to go
  red against a no-op implementation, and covers `claim_replay_id` atomicity and the RFC 9449
  `jkt` binding at rest.
- **A client secret verifier seam** (`SecretHash`), so a host stores a one-way verifier rather than
  the secret, compared in constant time. Registration access tokens are stored the same way.

### Fixed (security), 0.2.0 through 0.8.0

Each began as a test that reproduced the attack and failed.

- **An allowlist for RFC 8707 `resource` values (HIGH).** Syntactic validity is not authorisation:
  accepting any well-formed absolute URI let a client name a resource server this AS was never
  meant to mint for.
- **The RFC 7592 registration policy is consulted on UPDATE, not only on registration (HIGH).** A
  client could otherwise register within policy and then update itself out of it.
- **One issuer spelling everywhere (MEDIUM)**, and a throttle on device code lookup.
- Parser-level holes exposed by a mutation run over the HTTP surface, closed.

### Added: the earlier slices, in the detail they were written with

- **RFC 7591 dynamic client registration** and **RFC 7592 registration management**, OFF by
  default. Enabling them is two explicit acts, not one: `ServerConfig::registration` must be set,
  AND a `RegistrationPolicy` must be installed, or every registration is refused. RFC 7591 section
  5 is the reason: an open registration endpoint lets anyone on the internet mint a client, which
  weakens every threat model that assumed controlling a registered client was hard. What a
  registrant may obtain is bounded by `RegistrationConfig`, whose defaults are the narrow ones (the
  authorization code grant with refresh, no `client_credentials`, no device grant, no scopes).
  Validation uses the section 3.2.2 error registry (`invalid_redirect_uri`,
  `invalid_client_metadata`, `invalid_software_statement`), which is modelled separately from the
  RFC 6749 section 5.2 token codes because it is a separate registry. Redirect URIs are validated
  on the way in with the strictness the authorization endpoint applies on the way out (RFC 6749
  section 3.1.2: absolute, no fragment), since exact-match comparison makes anything else a
  registration that can never be used. The RFC 8414 `registration_endpoint` member is advertised
  exactly when registration is enabled. Registration, update and deletion each emit an audit event
  carrying no credential.
- **Registration access tokens** (RFC 7592 section 2), stored as one-way `SecretHash` verifiers and
  compared in constant time, exactly as client secrets now are. Consequence, stated rather than
  buried: a read or update response cannot return `registration_access_token` or `client_secret`,
  because this server keeps a verifier and not the credential. Both are returned exactly once, by
  the registration that minted them. Software statements (section 2.3) are not evaluated and are
  refused with `invalid_software_statement` rather than silently ignored.
- `Storage::delete_client`, which removes a registration AND every access token, refresh record,
  device grant and authorization code issued to it, in one operation so a real store can do it in
  one transaction. RFC 7592 section 2.3: a deleted client that still has live tokens is a client
  that no longer exists still calling resource servers.

- **RFC 9068 JWT access tokens** (`at+jwt`, ES256) with an RFC 7517 JWKS document, behind an
  off-by-default `jwt` feature. Opaque tokens remain the default: RFC 9068 is an optional profile,
  not an OAuth 2.1 requirement. The AS-side record is still persisted when signing, keyed by
  whatever the client actually presents, so introspection and revocation keep working and a
  revoked JWT is genuinely dead here rather than merely deprecated. `jwks_uri` is advertised
  exactly when the server signs.
- **The independent conformance harness passes completely**: 8 of 8 black box tests, 9 of 9
  hermetic RFC vector tests, and both pinned third party `oauth2 = "=5.0.0"` client drives. No
  file in the harness was modified to achieve it.
- **RFC 9207 `iss` authorization response parameter**, the mix-up countermeasure RFC 9700 section
  4.4 names, on BOTH the success redirect and every error redirect (RFC 9207 section 2 returns it
  in the authorization response regardless of outcome). The value is the issuer identifier in the
  same spelling the RFC 8414 metadata document publishes, because section 2.4 has the client
  compare the two for equality. The metadata document advertises
  `authorization_response_iss_parameter_supported: true` (section 3); it is a plain `bool`, not an
  `Option`, and `AuthorizationResponse::iss` / `AuthorizationErrorRedirect::iss` are plain
  `String`s, so the claim and the behaviour cannot drift apart. A directly rendered (non
  redirecting) error carries no `iss`: RFC 6749 section 4.1.2.1 forbids redirecting there, so
  there is no authorization response for section 2 to apply to.
- **RFC 8707 resource indicators** at the authorization endpoint and the token endpoint. The
  parameter may be repeated (section 2), each value must be an absolute URI with no fragment (a
  query component is explicitly permitted), and a value this server will not honour is refused
  with the new `ErrorCode::InvalidTarget` (`invalid_target`). The requested resources are recorded
  on the authorization code, carried through issuance onto the access token and the refresh chain,
  and a token request may NARROW that set but never widen it, the same rule and the same shape as
  RFC 6749 section 6's scope rule for refresh. Introspection reports them as `aud` (RFC 7662
  section 2.2, array form, omitted when there is no audience), and under the `jwt` feature they
  REPLACE the configured audience in the RFC 9068 `aud` claim. RFC 8707 registers no metadata
  member, so nothing new is advertised for it.
- A CSRF seam, a consent seam, and a rate limiting obligation stated on the device approval API.
- `Storage::get_refresh_token`, `Storage::revoke_token_family`, and `Storage::sweep_expired`.
- Allocation and size gates, each proven able to fail before being trusted.

### Fixed (security): the adversarial review

An adversarial security review traced seventeen findings through the code. Each fix began as a
test that reproduced the attack and failed.

- **Refresh token reuse detection.** Rotation previously deleted the old record, so a replay was
  `invalid_grant` and nothing more. A thief who redeemed first kept a working chain while the
  honest client was locked out, which is precisely inverted. Tokens now carry a family, rotated
  tokens are retained as spent, and presenting one revokes the whole family (OAuth 2.1 section
  6.1, RFC 9700 section 4.14.2).
- **Cross site device approval (critical).** The verification form had no CSRF protection, so an
  auto-submitting cross-origin form plus a victim's session approved an attacker's device grant,
  yielding a token for the victim's account.
- **Silent authorization.** The authorization endpoint issued codes with no consent step. With no
  consent resolver wired it now refuses rather than approving.
- **Replay revocation ordering.** Revocation on code replay ran before the client ownership check,
  so any public client could destroy a victim's live tokens using only a leaked code.
- **Unauthenticated introspection and revocation** when the named client was public (RFC 7662
  section 2.1, RFC 7009 section 2.1).
- **Constant time comparison** folded only 16 bits of the length difference, so `"hunter2"` and
  `"hunter2"` followed by 65536 NUL bytes compared EQUAL; it also leaked the secret's length by
  loop count.
- Credential bearing types no longer print secrets under `Debug`.
- `ValidatedAuthorizationRequest` is now genuinely unconstructible outside validation, which its
  documentation had already claimed.

### Changed: everything else

- **MSRV lowered from a declared 1.86 to a measured 1.75.** 1.74 fails only on return position
  `impl Trait` in the `Storage` trait; 1.75 compiles clean. `Cargo.lock` moved to format v3, and
  `base64ct` and `zeroize` are pinned below the versions that moved to edition 2024, because a
  floor that only holds without `--locked` is not a floor.
- `Storage` gained required methods (breaking, and deliberately taken before anything is
  published rather than after).
- **Breaking, for RFC 9207 and RFC 8707** (0.x, and nothing is published yet, so these are taken
  now rather than later): `AuthorizationResponse` and `AuthorizationErrorRedirect` gained `iss`;
  `AuthorizationRequest` gained `resource: Vec<Cow<str>>` (empty by default, so
  `AuthorizationRequest::from_pairs` still allocates nothing on borrowed input);
  `ValidatedAuthorizationRequest` gained `issuer` and `resource`; `AuthorizationCodeRecord`,
  `IssuedToken` and `RefreshTokenRecord` gained `resource`; `IntrospectionResponse` gained `aud`;
  `ErrorCode` gained `InvalidTarget`. `AuthorizationServer::token_with_resources` is new and
  `token` now delegates to it with an empty list. The RFC 8707 parameter is an argument there
  rather than a field on all four `TokenRequest` variants because section 2 defines it as a
  parameter of the token request independent of `grant_type`: a field per variant would state the
  same thing four times, grow an enum every host copies, and make every future grant repeat it.
- RFC 7662 introspection now reports `iss` in the same trimmed spelling as the RFC 8414 metadata
  `issuer` and the RFC 9207 `iss` parameter, rather than the raw configured string. One server,
  one identity, in every place it states it.
- `resource` is not accepted on the RFC 8628 device authorization request, so a device token poll
  naming one is refused with `invalid_target` rather than silently ignored: there is nothing
  granted for it to narrow to, and a client that believes it holds an audience restricted token
  and does not is worse off than one told plainly it cannot have one.
- `conformance-serve.sh` excluded from the published tarball: it resolves the workspace root as
  `../..` and cannot work from an unpacked crate.

### Notes

- `cargo publish --dry-run --locked` passes at 0.9.0: 101 files, 1.7 MiB (446.9 KiB compressed).
  The tarball carries no absolute path, no machine-specific string and no credential beyond the
  conformance fixtures, which are labelled as fixtures in their own module docs; the one packaged
  test that reads a repo-only file (`tests/jwt.rs`, the vendored RFC vectors) already detects its
  absence and says so rather than pretending to have checked something.
- There is still **no OAuth 2.1 certification programme in existence**, so no implementation can
  hold one, including this one. The independent judges of this release are the vendored RFC
  vectors, two pinned third-party client libraries in two languages, and one third-party scanner
  whose checks of an RFC 8414 document reached this crate for the first time. That is a real bar,
  it is not certification, and nothing here implies otherwise.

## [0.1.0] - 2026-08-08 (built and tested, not published to crates.io)

The first real release: a complete, coherent OAuth 2.1 core, plus the independent conformance
harness that judges it.

### Added

- RFC 6749 section 4.1 authorization code grant under OAuth 2.1 constraints: PKCE required,
  `S256` only (an absent `code_challenge_method` is refused rather than defaulted to `plain`, per
  RFC 7636 section 4.3), exact redirect URI matching, single-use codes, and replay of a spent code
  revoking the tokens it already minted (RFC 6749 section 4.1.2, RFC 9700 section 4.1.1).
- RFC 8628 device authorization grant as a full state machine: `authorization_pending`,
  `slow_down` with the mandated interval increase, `expired_token`, `access_denied`, single-use
  redemption, and user code normalization per section 6.1.
- RFC 6749 section 6 refresh token rotation: single use, absolute chain lifetime.
- RFC 6749 section 4.4 client credentials grant, confidential clients only, no refresh token
  (section 4.4.3).
- RFC 7636 PKCE primitives, verified against the RFC's Appendix B test vector.
- RFC 8414 authorization server metadata, derived from `ServerConfig` rather than hand written, so
  an advertised endpoint or capability is one the server actually has.
- RFC 7662 token introspection, and RFC 7009 token revocation (idempotent, ownership verified,
  `token_type_hint` treated as an optimization only).
- Client authentication: `client_secret_basic`, `client_secret_post`, and public clients (`none`).
- A `store::Storage` trait the host implements, plus `store::MemoryStorage` for tests and single
  process embedding.
- An optional `http` feature, off by default, adding an axum router over
  `AuthorizationServer` for hosts that would rather not write the wire layer themselves. Nothing
  in the library depends on it.
- `crates/oauth-as-conformance`: an independent black-box conformance harness, written by an
  author who could not see this crate's source, never published. Vendored RFC test vectors with
  per-entry citations, response-shape validators transcribed from RFC 6749 section 5 and RFC 8628
  sections 3.2 and 3.5, and a drive of the pinned third-party client `oauth2 = "=5.0.0"` through a
  full device flow and a full authorization-code-with-PKCE flow against the live server.
- `scripts/oauth-conformance.sh`, with `--selftest` (proves the gate can go red on both the
  hermetic vector suite and the black-box suite before any green is trusted) and `--check` (serves
  the AS and runs the black-box suite against it).
- A three-stage CI promotion pipeline: `dev` runs the fast gate (fmt, clippy, test) on every push
  and pull request; `qa` runs the full suite (MSRV verification against Rust 1.86, the conformance
  self-test, the live black-box conformance check, a packaging dry run, and a non-blocking
  mutation-testing report) on every push to `qa`; `main` publishes to crates.io only by explicit,
  manually approved `workflow_dispatch`, never on push.
- Dual license, `MIT OR Apache-2.0`, from this release onward.

### Notes

- Several of the gates that define "done" for this project are not yet closed at 0.1.0, including
  the RFC 9068 JWT access token feature, the HTTP serve shim required for a live `--check` run,
  and mutation testing.
- On third-party conformance tooling: there is
  no OAuth 2.1 certification programme in existence, the OpenID Foundation suite has zero
  references to RFC 8628, and neither `authgent` nor OAuch could be wired into CI honestly as of
  2026-08-08. The independent judges of this release are the vendored RFC vectors and the pinned
  `oauth2 = "=5.0.0"` client, and nothing stronger is claimed.

## [0.0.1] - 2026-08-08

Published to crates.io. A placeholder release only: it reserves the crate name, contains no
protocol implementation, and says so in its own docs and README. Superseded by the unpublished
0.1.0 and later work in this repository; do not depend on 0.0.1 for anything functional.

No comparison links for 0.1.0 or Unreleased: neither has a git tag yet, since 0.1.0 has not been
promoted through `main` or published. Links will be added once tags exist.

[0.0.1]: https://crates.io/crates/oauth-as/0.0.1
