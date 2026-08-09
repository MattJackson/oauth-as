# Security policy

`oauth-as` is an OAuth 2.1 authorization server. It is the component that decides who gets access
to everything else, so a defect here is rarely cosmetic. Reports are welcome and are taken
seriously.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). That creates a private advisory only the maintainers can
see.

Please include, as far as you can:

- the affected version or commit,
- which crate feature set was enabled (the exact `features = [...]` list, since the default set is
  EMPTY and most of the wire surface is behind an optional feature, so a report that does not name
  them may describe code the reader cannot even compile),
- a concrete attack: the requests, the order they are sent in, and what the attacker ends up
  holding that they should not,
- the RFC section you believe is violated, if one applies.

A working proof of concept is the most useful thing you can send. A description of a class of
problem without a traced path through the code is much harder to act on, though it is still
welcome.

## What to expect

- Acknowledgement within 3 working days.
- An initial assessment, with our understanding of severity and whether we agree it is exploitable,
  within 10 working days.
- Regular updates while a fix is developed.
- Credit in the advisory and the changelog, unless you would rather not be named.

If you do not hear back within 3 working days, please assume the message was lost rather than
ignored, and try again.

## Disclosure

We prefer coordinated disclosure. We will agree a date with you, publish a GitHub Security
Advisory with a CVE where one is warranted, release a fixed version, and yank affected versions
from crates.io where that is the right call. A crates.io version can be yanked but never deleted,
so a yank hides a version from new resolution without breaking builds that already pinned it.

We will not ask you to delay indefinitely. If a fix is taking too long, that is our problem to
explain, not yours to absorb.

## Scope

In scope:

- Anything that lets a party obtain, use, or destroy a token or grant it should not have.
- Any violation of a MUST or MUST NOT in RFC 6749, RFC 6750, RFC 7009, RFC 7517, RFC 7523,
  RFC 7636, RFC 7662, RFC 8414, RFC 8628, RFC 9068, RFC 9207, RFC 9449, RFC 9700, or the OAuth 2.1
  draft.
- Timing, error-shape, or response-shape differences that let an attacker learn something the
  protocol intends to keep from them.
- Defects in the optional `http` feature's wire handling.

Known and documented, so not a finding on their own (though a concrete exploit built on one still
is):

- **The host owns transport security, rate limiting, and the consent experience.** This crate is a
  library and does not open sockets, terminate TLS, or count requests. RFC 8628 section 5.1 makes
  device user-code entropy adequate only in combination with rate limiting, and providing that is
  the host's job.
- **The `Storage` trait's `take_*` operations must be genuinely atomic.** A host that implements
  them as read-then-delete on a multi-node deployment reintroduces double-spend. This is documented
  on the trait, and it is a host obligation.
- **Anything in `crates/oauth-as-conformance`**, which is a test harness, is never published, and
  is not part of the attack surface.
- **The seeded conformance example** (`examples/conformance_server.rs`) deliberately auto-approves
  requests and ships fixed test credentials. It exists so an external harness can drive the server
  and it says so loudly. It is not a deployment target.

## Supported versions

While the crate is pre-1.0, only the latest released version is supported. Fixes land on the
newest version rather than being backported.

## Our own practice

- Every behavioural change is developed red first: a test that reproduces the problem and fails,
  then the fix.
- Security fixes specifically must begin with a test that reproduces the ATTACK. A security fix
  with no test that failed beforehand is not a fix, it is a hope.
- An independently authored conformance harness, written by an author who could not see the
  library's source, drives the server as a black box.
- The project runs adversarial security review, and mutation testing to check that the tests
  actually constrain the code rather than merely accompanying it. Mutation coverage is NOT yet
  complete: `GOAL.md` gate 4 is open, and `MUTANTS.md` names every surviving mutant individually
  rather than reporting a percentage. Read that file before assuming a green test run means the
  tests would have caught a given change.

None of that makes the crate correct. It makes the claims checkable, which is the most any project
can honestly offer.
