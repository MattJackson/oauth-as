# 1.1.0 changed-code audit

Scope: every change from 4726677 (1.0.1 dev baseline), including provider modules,
protocol wiring, examples, tests, feature/dependency graphs, CI, package contents,
and documentation. Review covered capability/algorithm confusion, entropy/error
paths, secret comparisons, untrusted key parsing, metadata, compatibility, allocation
costs, and release/conformance wiring. Compilation and tests run only in Actions.

Findings corrected during development and audit:

| Severity | Finding | Correction and evidence |
| --- | --- | --- |
| Medium | FIPS RSA policy checked byte count and allowed non-approved verification sizes | Enforce exact 2048/3072/4096-bit moduli; validate private keys with AWS-LC's FIPS key check. A valid 3071-bit signature reproduced the defect in run 43570275650, job 132372931576. Provider tests pass after the fix in run 43570493605. |
| Medium | Explicit-provider metadata inherited the compiled ES256 default | Rebuild verifier-dependent metadata from the selected provider. A provider with no asymmetric operations plus an accepting legacy hook reproduced the defect in run 43570275650, job 132372931467; fixed in ecfeea5. |
| Medium | FAPI fixture broadened DPoP policy when selecting AWS-LC | Apply AlgAllowList::fapi at the AS and protected resource. OIDF run 43570014751, job 132372143931 rejected the previous implementation for accepting RS256. Fixed in c90292e; all three full FAPI jobs pass in run 43570734321. |
| Medium | Backend-free mTLS and storage conformance retained legacy hash helpers | Add provider-aware certificate-list/JWKS/confirmation methods; use fixed storage fixture hashes. All-protocol consumer build reproduced seven missing symbols in run 43570275650, job 132372931274. Fixed in ecfeea5. |
| Low | FIPS release fixture used incompatible GCC-generated assembly | Select Clang in the FAPI workflow without modifying the validated module source. Build failure recorded in run 43570014751, job 132372143791; all three full FAPI jobs pass in run 43570734321. |
| Low | SQLx umbrella pulled unused SQLite with an advisory | Use the same SQLx 0.8 PostgreSQL driver directly; no advisory exemption added. Supply-chain workflow passes. Missing adapter imports exposed by the full suite were corrected. |
| Low | Default-feature and provider-free documentation was stale | Update README, API links, backend selection and deployment requirements. Include backend-free rustdoc in CI. |
| Low | Server allocation budget omitted its provider pointer | Account explicitly for the measured 16-byte Arc trait object; no per-request provider allocation. Existing efficiency tests remain active. |

Initial red proof: run 43568192111 failed the new provider API and banned dependency
checks before implementation. The independent consumer checks the requested
http,jwt,consent,resource-metadata graph and additionally compiles every protocol
feature with no backend. Provider tests exercise RFC 7636, 4231, 7638, 7515 and
8032 vectors, invalid signatures, entropy errors, forbidden algorithms and metadata.

Compatibility decisions: default RustCrypto behavior and serialized storage formats
are preserved. EcdsaP256Key::generate remains deprecated with its existing panic;
try_generate is fallible. Backend-free callers use the new explicit APIs. Existing
RSA signing's documented upstream Marvin limitation is unchanged. FIPS compliance
requires the module's supported deployment configuration; conformance runs do not
extend the existing 1.0.0 OpenID certification to a new version.

The 1.1 provider seam has an intentional linked-size cost: QA measured axum
692,648 bytes, P-256 361,962 bytes and HTTP+JWT 487,636 bytes. The provider vtable
retains its operations, including P-256 verification in a signing-only probe.
Those three bands are rebased to approximately +/-1.5%; other budgets are retained.
Key generation also avoids cloning the key identifier on every rejection-sampling
attempt. This is a documented capability/size tradeoff, not a net source-size saving.

Further QA findings: the MCP scanner fixture needed `jwt-pkcs8` for the new provider
key factory (reproduced as UnsupportedAlgorithm in job 132375619924); both scanner
build commands now enable it. The package manifest needed C-locale sorting; backend-free
rustdoc links needed provider-aware targets; clippy required moving the RSA salt
adapter before the existing test module. The failing QA/publish logs reproduced
these before correction. GitHub's pre-existing jsonwebtoken claim-type advisory
(GHSA-h395-gr6q-cpjc) in the unpublished conformance harness is removed by upgrading
to patched 10.3.0, using AWS-LC and omitting unused PEM support. The harness performs
signature checks only; it is not a dependency of the published library.

QA run 43572198514 also exposed Clippy's `needless_bool` in the existing
`Confirmation::is_empty` implementation under DPoP-only features. Each supported
field combination now returns its direct `is_none` expression; the existing
feature-pair tests cover this behavior. This is a simplification without a policy
change. The run passed size budgets, MSRVs, packaging, coverage and live checks
before that narrow lint failure. Full FAPI run 43572198570 passed all three
backends. Main provider run 43572204068 and CodeQL run 43572204020 passed.

The pre-existing CodeQL cleartext-logging alerts identify synthetic test values
and assertion output, not new production logging. Existing Scorecard policy and
upstream RSA advisory notices are distinct from this changed-code audit; they
have not been dismissed to claim a zero-alert repository.

Status: no identified code finding remains without a correction. Provider contracts
and HTTP conformance passed on all backends; backend-free compilation and rustdoc
passed. Full FAPI run 43570734321 passed on RustCrypto, AWS-LC and FIPS. QA run
43571128509 passed the MSRV checks, PostgreSQL atomicity, package dry-run, independent
client and live black-box checks. Publish run 43571134773 passed full coverage but
stopped on the corrected clippy ordering issue. Final publication is verified separately;
a passed conformance run is not a new OpenID certification.
