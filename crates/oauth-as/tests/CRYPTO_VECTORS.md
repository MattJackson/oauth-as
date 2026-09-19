# Crypto vectors and dependency facts for Phase B (RS256) and Phase C (EdDSA/Ed25519)

Reference doc for the crypto-agility work that adds RS256 and EdDSA backends beside the
existing `jwt-p256` (ES256) backend in this crate. Everything below was checked against a
primary source (an RFC text, or a crate's published `Cargo.toml`/docs.rs page) on 2026-09-18;
each section says which source and how. Nothing here is invented — where a fact could not be
pinned down from a primary source, that is called out explicitly instead of guessing.

Compact JWS strings below are given exactly as they appear in the cited RFC, with only the
RFC's own line-wrapping (an artifact of the fixed-width text RFC) removed so each value is a
single copy-pasteable token. Where the RFC itself wraps a JSON string value across lines with
leading whitespace (the RSA `n`/`d` members), that whitespace is not part of the value and has
been stripped the same way `json` parsing would strip it — verify by regenerating the SHA-256
JWK thumbprint (RFC 7638) if these are hand-copied again.

---

## 1. RS256 test vector — RFC 7515 Appendix A.2

Source: <https://www.rfc-editor.org/rfc/rfc7515.txt>, Appendix A.2 ("Example JWS Using
RSASSA-PKCS1-v1_5 SHA-256"), fetched directly and transcribed verbatim (line-wrap-collapsed
below).

### 1.1 RSA private key (JWK, RFC 7517 §6.3.2 members)

```json
{
  "kty": "RSA",
  "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  "e": "AQAB",
  "d": "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
  "p": "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
  "q": "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
  "dp": "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
  "dq": "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
  "qi": "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
}
```

This is a 2048-bit modulus (the RFC does not label the bit length, but the decoded `n` is 256
bytes/2048 bits — consistent with the 256-byte signature below and comfortably at, not below,
the ≥2048-bit floor in §4).

### 1.2 Public JWK shape (what a verifier — and this crate's JWKS endpoint — publishes)

```json
{ "kty": "RSA", "n": "<same n as above>", "e": "AQAB" }
```

Only `kty`, `n`, `e` are REQUIRED for RSA public-key use (RFC 7517 §6.3.1); `d`, `p`, `q`, `dp`,
`dq`, `qi` are the private-key-only members (§6.3.2) and MUST NEVER be published.

### 1.3 RFC 7638 JWK thumbprint member ordering — RSA

Per RFC 7638 §3.2, the thumbprint input is the JSON object containing **only** the REQUIRED
public members, with keys in **lexicographic (codepoint) order** and no insignificant
whitespace:

```
{"e":"AQAB","kty":"RSA","n":"<n>"}
```

Order is `e`, `kty`, `n` (ASCII `e` < `k` < `n`). The thumbprint is `BASE64URL(SHA-256(that
exact byte string))`.

### 1.4 Signing input

- Protected header: `{"alg":"RS256"}`
- Base64url header: `eyJhbGciOiJSUzI1NiJ9`
- Payload: `{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}` (the RFC's
  payload octets include the literal `\r\n` — this is the *same* payload used in RFC 7515
  Appendix A.1's HS256 example; RS256 A.2 reuses it to make the two examples comparable)
- Base64url payload:
  `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`
- **JWS Signing Input** (`ASCII(BASE64URL(UTF8(header)))` + `.` + `BASE64URL(payload)`):

```
eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
```

### 1.5 Expected signature

Base64url-encoded JWS Signature (256 bytes decoded — matches the 2048-bit modulus):

```
cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw
```

Full compact serialization = `<1.4 signing input>.<the signature above>`.

RFC 7515 A.2.2 states validation is: pass the public key `(n, e)`, the base64url-decoded
signature, and the Signing Input to "an RSASSA-PKCS1-v1_5 signature verifier that has been
configured to use the SHA-256 hash function" — i.e. exactly RFC 8017 (PKCS#1 v2.2) RSASSA-PKCS1-
v1_5 with SHA-256, which is what RFC 7518 §3.3 defines `RS256` to be.

---

## 2. EdDSA / Ed25519 test vector — RFC 8037 Appendix A.4

Source: <https://www.rfc-editor.org/rfc/rfc8037.txt>, Appendix A.4 ("Ed25519 Signing Example"),
fetched directly and transcribed verbatim.

### 2.1 OKP private key (JWK)

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
```

`d` is the 32-byte private seed/scalar; `x` is the 32-byte public key, both base64url with no
padding (RFC 8037 §2).

### 2.2 Public JWK shape

```json
{ "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }
```

Only `kty`, `crv`, `x` are the public members; `d` is private-key-only and must never be
published.

### 2.3 RFC 7638 JWK thumbprint member ordering — OKP

RFC 8037 does not itself define the thumbprint (RFC 7638 predates OKP), but RFC 7638 §3.2's
rule — REQUIRED public members only, lexicographic key order — extends unambiguously to OKP's
required set `{crv, kty, x}` (RFC 8037 §2 lists `kty`, `crv`, `x` as required for public use).
ASCII order `c` < `k` < `x`:

```
{"crv":"Ed25519","kty":"OKP","x":"<x>"}
```

This exact member set/order for OKP is also the one implemented by widely used JOSE libraries
(e.g. `jose`, `node-jose`) and is the de facto interoperable answer, but note it is an
extrapolation of RFC 7638's general rule rather than text written into RFC 8037 itself.

### 2.4 Signing input

- Protected header: `{"alg":"EdDSA"}`
- Base64url header: `eyJhbGciOiJFZERTQSJ9`
- Payload (raw text, not JSON): `Example of Ed25519 signing`
- Base64url payload: `RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc`
- **JWS Signing Input**:

```
eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc
```

### 2.5 Expected signature / full compact JWS

RFC 8037 A.4 gives the complete compact serialization directly (64-byte Ed25519 signature,
base64url, no padding):

```
eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg
```

So the base64url signature alone is:

```
hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg
```

---

## 3. Dependency facts

Checked 2026-09-18 against docs.rs `source/Cargo.toml.orig` pages (the exact published
manifest, not the repo's in-development `main` branch — the `main` branches of both crates are
already ahead, at `rsa` 0.10.0-rc.18 and `ed25519-dalek` 3.0.0, which is *not* what `cargo add`
resolves to today) and the RustSec advisory database. Method noted per fact below.

### 3.1 `rsa` crate (RustCrypto)

- **Current stable line**: 0.9.x. Latest published patch is **0.9.10**. Checked via
  `docs.rs/crate/rsa/` version list, cross-checked against `docs.rs/crate/rsa/0.9.10/source/Cargo.toml.orig`.
  (0.10.0-rc.18 also exists but is a pre-release — `cargo add rsa` / an unqualified `"0.9"`
  requirement will not resolve to it.)
- **MSRV**: `rust-version = "1.65"` in the published 0.9.10 manifest — comfortably below this
  crate's 1.75 floor.
- **Edition**: 2021.
- **Feature needed for RS256 (PKCS#1 v1.5 sign+verify with SHA-256)**: the `sha2` feature.
  `sha2` is an *optional* dependency declared plainly (`sha2 = { version = "0.10.6", optional =
  true, default-features = false, features = ["oid"] }`), not `dep:`-renamed, so Cargo
  auto-generates a same-named feature `sha2` that must be enabled to pull the `sha2` crate in
  and get `rsa::pkcs1v15::{SigningKey,VerifyingKey}<Sha256>`. The `pkcs1v15` module itself is
  unconditionally compiled (not behind a feature) — confirmed by reading the 0.9.10
  `[features]` table verbatim: `default = ["std","pem","u64_digit"]`, plus `hazmat`,
  `getrandom`, `nightly`, `serde`, `pem`, `pkcs5`, `u64_digit`, `std`; no `pkcs1v15`-named
  feature exists because there is nothing to gate.
- **Can `default-features` be off?** Yes. Doing so drops `std` (needs re-adding explicitly —
  the crate is not meaningfully usable `no_std` for our purposes anyway since this crate is std
  throughout), `pem` (PEM I/O — not needed here since JWK-shaped RSA numbers arrive as base64url
  integers the same way `p256`'s raw-scalar path already works) and `u64_digit` (a pure
  performance feature for `num-bigint-dig`'s internal digit width; correctness is unaffected
  either way).
- **`sys`/C toolchain?** None. Reading the 0.9.10 manifest's `[dependencies]` directly:
  `num-bigint-dig`, `num-traits`, `num-integer`, `rand_core`, `const-oid`, `subtle`, `digest`,
  `pkcs1`, `pkcs8`, `signature`, `spki`, `zeroize`, plus optional `sha1`/`sha2` — all pure Rust,
  no `*-sys` crate anywhere in the direct dependency list. (Not independently re-verified
  transitively for every leaf of `num-bigint-dig`'s own tree, but `num-bigint-dig` is the
  well-known pure-Rust RustCrypto bignum fork and does not link a C bignum library.)
- **RUSTSEC-2023-0071 (Marvin Attack)** — checked via
  `raw.githubusercontent.com/RustSec/advisory-db/main/crates/rsa/RUSTSEC-2023-0071.md`:
  - Still **unpatched** as of the current 0.9.10 / 0.10.0-rc.18 (no fixed version exists at time
    of writing — the advisory-db copy fetched today lists no patched version).
  - CVSS vector `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` — confidentiality-only impact (key
    material leaks via timing), no integrity/availability impact. This is the signature of a
    **private-key-operation** timing side channel: any use of the private exponent `d` (RSA
    **decryption**, and RSA **signing**, since signing is also a private-key modular
    exponentiation) is potentially timing-observable if an attacker can measure operation
    latency over a network. **RSA verification uses only the public exponent `e` and no secret
    material, so verification has no side channel to exploit here** — the advisory's own
    mitigation text ("avoid using the rsa crate in settings where attackers can observe timing")
    is about the private-key path, not verification.
  - **Practical mitigation for Phase B**: keep RS256 **signing** out of this process, the same
    way ES256 signing already is — an `RsaSigner` seam mirroring `Es256Signer` (async, so a KMS
    or HSM can be on the other end of it) rather than an in-process `rsa::RsaPrivateKey`.
    Verification is safe to do in-process with the `rsa` crate directly (`VerifyingKey<Sha256>`,
    public exponent only, no timing-sensitive secret).
- **Recommended Cargo.toml feature line** (mirroring the existing `jwt-p256` pattern):

```toml
jwt-rsa = ["jwt", "dep:rsa"]
```

```toml
rsa = { version = "0.9", default-features = false, features = ["std", "sha2"] }
```

  (Add `"u64_digit"` back in if the Phase B implementation cares about verification throughput;
  it changes no observable behavior.)

### 3.2 `ed25519-dalek` (dalek-cryptography)

- **Current lines**: the `main` branch has already moved to **3.0.0** (edition 2024,
  MSRV 1.85 by the repo's own Cargo.toml — well above this crate's 1.75 floor and outright
  incompatible with it, edition 2024 alone requires a newer toolchain than 1.75 supports), so
  "current" and "the v2.x line the task means" are different answers as of 2026-09-18:
  - Latest 2.x: **2.2.0**, published 2025-07-09. Checked via `docs.rs/crate/ed25519-dalek/`
    version list.
  - **2.2.0's own MSRV is 1.81** — checked via `docs.rs/crate/ed25519-dalek/2.2.0/source/Cargo.toml.orig`.
    That is *also* above this crate's 1.75 floor, so pinning bare `"2"` (which a fresh
    `cargo add`/an unlocked resolve would take to 2.2.0) would raise the floor exactly the way
    the crate's own MSRV comment warns `base64ct`/`zeroize` already did once.
  - **2.1.1** (published 2024-02-07) has **MSRV 1.60** — checked via
    `docs.rs/crate/ed25519-dalek/2.1.1/source/Cargo.toml.orig` — which fits comfortably under
    1.75. Its own dependency `curve25519-dalek = "4"` has MSRV 1.60 too (checked against
    `docs.rs/crate/curve25519-dalek/4.1.3/source/Cargo.toml.orig`), so the whole tree stays
    under the floor at 2.1.1.
  - **Recommendation: pin to the 2.1.x line specifically** (`~2.1`, not a bare `"2"`), to avoid
    an unlocked resolve silently adopting 2.2.0 and raising the crate's MSRV floor from 1.75 to
    1.81 with no code change — the exact failure mode this crate's own `rust-version` comment
    already calls out for other deps.
- **Edition**: 2021 for both 2.1.1 and 2.2.0 (3.0.0 moved to edition 2024).
- **Features needed for verify**: `default-features = false`, feature `"std"` (matches this
  crate's std-only posture). `rand_core` is **not** needed for verification — Ed25519
  verification takes only the signature, message, and public key. `VerifyingKey::verify_strict`
  (see below) needs nothing beyond `std`/`alloc` either.
- **Features needed for sign** (if this crate ever signs Ed25519 in-process, e.g. for a
  test fixture key or a non-KMS deployment): also just `std` — Ed25519 signing per RFC 8032 is
  **deterministic**, it does not consume randomness at sign time. `rand_core`/the `rand_core`
  feature is only needed for `SigningKey::generate` (key generation), not for `sign` itself.
- **`default-features = false` works?** Yes for both sign and verify as described; default
  pulls in `fast` (precomputed tables — a pure perf tradeoff, safe to drop) and `zeroize`
  (zeroizes secret key material on drop — recommend keeping this one explicitly even with
  `default-features = false`, i.e. `features = ["std", "zeroize"]`, since it costs nothing and
  is exactly the kind of secret-hygiene property this crate already cares about for `p256`).
- **`*-sys`/C toolchain?** None in either 2.1.1 or 2.2.0's direct dependencies
  (`curve25519-dalek`, `ed25519`, `sha2`, `subtle`, plus optional `rand_core`/`serde`/`zeroize`/
  `merlin`) — all pure Rust, checked by reading the manifests directly. `curve25519-dalek`
  itself has no `-sys` dependency either (checked its own 4.1.3 manifest) and does not require
  nightly or inline asm by default.
- **Strict verification**: `VerifyingKey::verify_strict` (and `verify_strict_prehashed`) exists
  in the 2.x API — confirmed via search results describing it as rejecting weak/non-canonical
  public keys, i.e. the small-order/cofactor and signature-malleability hardening beyond RFC
  8032's bare minimum (the "ZIP215"-style strict check dalek added to close the historical
  Ed25519 malleability ambiguity). **Phase C must call `verify_strict`, not `verify`**, for
  exactly the reason this crate's ES256 path already treats signature verification as the one
  place an algorithm-confusion or malleability bug would be catastrophic (see the "VERIFICATION"
  banner in `src/jwt.rs`). I was not able to fetch the exact rustdoc prose for `verify_strict` in
  this session (docs.rs fetches for the item page did not return full text); the *existence* and
  *purpose* of the API is corroborated by multiple independent sources but the precise wording
  of its guarantees should be re-read from `docs.rs/ed25519-dalek/2.1.1/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict`
  directly by the Phase C implementer before relying on specific claims about which attacks it closes.
- **Recommended Cargo.toml feature line**:

```toml
jwt-ed25519 = ["jwt", "dep:ed25519-dalek"]
```

```toml
ed25519-dalek = { version = "~2.1", default-features = false, features = ["std", "zeroize"] }
```

### 3.3 `#![forbid(unsafe_code)]` in this crate

`crates/oauth-as/src/lib.rs:15` has `#![forbid(unsafe_code)]` today. That attribute only
forbids `unsafe` blocks written *in this crate's own source*; it says nothing about a
dependency's internals. Both `rsa` (pure Rust, `num-bigint-dig` arithmetic, no asm/sys) and
`ed25519-dalek`/`curve25519-dalek` (pure Rust; `curve25519-dalek` has an optional `asm` internal
backend but it is not `-sys`/C and is not required) may contain `unsafe` internally — that is
irrelevant to this crate's `forbid` attribute and does not need to be checked. What *would*
break `forbid(unsafe_code)]` here is only: (a) this crate's own code using `unsafe`, or (b) a
dependency requiring a `build.rs` that needs `cc`/`bindgen`/a C or asm toolchain such that the
*build* — not this crate's Rust source — depends on unsafe FFI surface. Neither `rsa` nor
`ed25519-dalek` (2.1.1, with the feature sets above) pulls a `-sys` crate or a C/asm build
requirement, so `#![forbid(unsafe_code)]` remains fully satisfiable in this crate with either
dependency added.

---

## 4. RSA key-size policy and signature representation

**Policy**: RS256 keys MUST be rejected at load time if the modulus is below 2048 bits. This is
not a rule the `rsa` crate enforces for you — checked via docs.rs for 0.9.10: no minimum-key-size
constant or check is documented on `RsaPrivateKey::new`/`from_pkcs1`/`from_pkcs8` in the material
available in this session (I could not positively confirm the crate enforces *any* floor by
reading source in this session, only that its docs make no mention of one). Treat "the `rsa`
crate will reject a weak key for you" as **unverified and likely false** — the size check has to
be this crate's own responsibility at key-load time, exactly like the async/KMS boundary above:
a library that hands out a `Signer`/`Verifier` seam cannot assume every implementation behind
that seam already validated its own key.

**Why 2048 bits**: this matches NIST SP 800-57's current floor for RSA (2048-bit modulus ≈ 112
bits of security) and is the de facto minimum every current TLS/JOSE guidance recommends; RFC
7518 (JWA) itself only recommends "a key size of 2048 bits or larger" for RS256 in §3.3, which is
the same floor this crate's policy should mirror.

**Signature length is not fixed across key sizes**:

| Modulus size | RSASSA-PKCS1-v1_5 signature length |
|---|---|
| 2048 bits | 256 bytes |
| 3072 bits | 384 bytes |
| 4096 bits | 512 bytes |

RSASSA-PKCS1-v1_5's signature is exactly `k` octets where `k` is the RSA modulus size in octets
(RFC 8017 §8.2.1/§8.2.2: the signature `S` is `I2OSP(s, k)`, i.e. always padded/represented as
exactly `k` octets, one octet count per modulus, not per hash). So a 2048-bit key's RS256
signature is always 256 bytes, a 3072-bit key's is always 384 bytes, and a 4096-bit key's is
always 512 bytes — the signature length is determined by the **key**, not by SHA-256.

**Design check — `JwsSignature::Rsa(Box<[u8]>)`**: I did not find an existing `JwsSignature` enum
in this crate's current `src/jwt.rs` (this appears to be a Phase B/C design not yet landed, not
something already in the tree — grepped `src/jwt.rs` for `JwsSignature`/`enum.*Signature` and
found no match), so this is evaluated as a proposed design, not verified against existing code.
Given the table above, `JwsSignature::Rsa(Box<[u8]>)` (a variable-length, heap-allocated byte
slice, with the length checked against the *loaded key's* modulus size at verify time) is the
correct shape. A fixed-size variant such as `JwsSignature::Rsa([u8; 256])` would hard-code the
2048-bit case and:

1. Make a 3072-bit or 4096-bit key **unrepresentable** — `[u8; 384]` and `[u8; 512]` are
   different, incompatible array types in Rust, so a single fixed-size array variant can only
   ever hold one specific key size, not "any RS256 key ≥ 2048 bits."
2. Force either truncation (silently corrupting/dropping signature bytes for larger keys — a
   correctness bug, not just a limitation) or a second enum variant per key size (defeating the
   point of a single `Rsa` variant and requiring the caller to know the modulus size before it
   can even name the type it's constructing).

So `Box<[u8]>` (or equivalently `Vec<u8>`), with the length constraint enforced as a runtime
check against the specific key's modulus size at verification time (not baked into the type),
is the only representation that is correct for "RS256 with a policy-enforced 2048-bit *minimum*"
rather than "RS256 at exactly one fixed size."

---

## Summary of anything not independently verified from source

- `num-bigint-dig`'s full transitive dependency tree was not walked leaf-by-leaf for `-sys`
  crates; only the direct `rsa` 0.9.10 manifest was read directly. It is the standard
  RustCrypto pure-Rust bignum fork and not expected to link C, but this is inference from
  reputation, not a read of every `Cargo.toml` in its tree.
- The exact rustdoc prose/guarantees of `ed25519-dalek::VerifyingKey::verify_strict` (which
  specific attacks — small-order points, non-canonical S, cofactor issues — it closes, in the
  library's own words) was not fetched successfully in this session; only its existence and
  general purpose (weak/non-canonical public key rejection) is corroborated. Re-read the method's
  own docs before writing Phase C's verifier.
- Whether the `rsa` crate enforces *any* minimum modulus size internally (e.g. on `RsaPublicKey`
  construction or `pkcs1v15::VerifyingKey` construction) was not confirmed either way from
  source in this session — treat it as **not enforced by the dependency** and implement the
  2048-bit floor explicitly in this crate regardless.
- The OKP RFC 7638 thumbprint member ordering (`{crv,kty,x}`) is a well-established
  interoperable convention, but is an extrapolation from RFC 7638's general rule rather than
  text present in RFC 8037 itself — called out inline in §2.3 above.
