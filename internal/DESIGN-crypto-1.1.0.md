# Crypto provider, 1.1.0

The host selects one instance of an object-safe CryptoProvider at construction. It owns
SHA-256, HMAC-SHA-256, entropy, constant-time equality and asymmetric verifier/key factories.
There are no global providers. Protocol parsing, key representations, algorithm pinning,
and metadata remain backend-neutral. Unsupported algorithms fail closed; selecting a
provider never consults another backend when it cannot handle a request.

Existing async JwsSigner and synchronous JwsVerifier contracts remain. Provider keys use
an object-safe adapter; network/KMS signers remain possible. Verification retains the
closed JwsAlg slots and the intersection of provider capabilities and configured policy.

RustCrypto remains the default primitive implementation; existing asymmetric backend
features stay opt-in. AWS-LC and FIPS are optional implementations of the same seam.
FIPS policy is conservative and tied to a pinned module, with construction-time rejection
of disallowed configured signing algorithms and runtime refusal of client-selected ones.
Cargo features compile implementations, while explicit provider selection chooses behavior.

No-default-features consumers can compile the protocol and HTTP APIs with no crypto
implementation in the normal dependency graph. Legacy standalone convenience functions
are available with a built-in provider; explicit *_with_crypto variants serve custom hosts.
Default convenience constructors preserve their signatures. New try_new/new_with_crypto
constructors return typed errors. Existing generate() remains deprecated with its documented
panic for compatibility; try_generate and all server paths propagate entropy failures.

Validation: independent consumer graph bans, provider known-answer tests, entropy-failure
injection, algorithm refusal/metadata tests, existing tests, and conformance per backend.
All compilation and execution happens on GitHub Actions. Local work is source editing and
formatting only. Tests land first to establish red; implementation follows. After dev,
audit all changes to zero outstanding severity findings, then promote qa/main and publish.

Version 1.1.0 preserves default callers and stored formats. Hosts opting out of the new
default backend must explicitly supply crypto and use provider-aware standalone APIs.
