# SecureD Security Audit

This document records security findings from the SecureD audit and the fixes applied. Public API shapes and envelope data structures were preserved where possible; SemVer-compatible additive API was used for residual issues that could not be fixed without new parameters or members.

## Severity legend

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Direct break of confidentiality, integrity, or key material under normal use |
| **HIGH** | Significant weakness enabling practical attacks or silent security degradation |
| **MEDIUM** | Incorrect security parameters, silent fallback, or misuse-prone defaults |
| **LOW** | Hardening, validation, or documentation gaps with limited direct impact |

---

## Fixed issues

### CRITICAL

| ID | Issue | Location | Fix |
|----|-------|----------|-----|
| C1 | **scrypt cost parameter `N` was wrong** — OpenSSL `EVP_PBE_scrypt` was called with an incorrect `N`, producing weak or non-standard derived keys. | `source/secured/kdf.d` | Corrected `N` (and related parameters) to the intended SecureD scrypt profile. |

### HIGH

| ID | Issue | Location | Fix |
|----|-------|----------|-----|
| H1 | **Non-AEAD encrypt-then-MAC used the public IV as the HMAC key** — CBC/CTR/CFB/ChaCha20 authentication was not keyed by secret material. | `source/secured/symmetric.d` | MAC key is now `hash(encryptionKey)`; IV is bound into the MAC input (`iv ~ hash(ciphertext) ~ hash(aad)`). **Breaking for non-AEAD ciphertext:** decrypt with v3.0.0, re-encrypt with v3.1.0 (see README). |
| H2 | **HMAC with long keys did not hash the key first** — keys longer than the hash block size were not reduced per RFC 2104. | `source/secured/mac.d` | Long keys are hashed before HMAC as required. |
| H3 | **`/dev/urandom` reads could be short** — partial reads were not retried, yielding under-filled random buffers. | `source/secured/random.d` | Full-length read loop until the requested number of bytes is obtained (or hard failure). |
| H4 | **Constant-time equality was not constant-time** — early exit / non-constant comparison. | `source/secured/util.d` | Fixed to a constant-time comparison suitable for secrets and MACs. |

### MEDIUM

| ID | Issue | Location | Fix |
|----|-------|----------|-----|
| M1 | **Password-based symmetric keys used a null/empty salt** — `generateSymmetricKey(password)` derived keys without a random salt, enabling precomputation and identical keys for identical passwords. | `source/secured/symmetric.d` | Generates a 32-byte random salt into `SymmetricKey._salt` / `salt` property; callers must persist the salt with the ciphertext. Unittest updated (fixed null-salt vector was incorrect). |
| M2 | **RSA seal OAEP hash was fixed / not selectable** — hybrid seal could not choose OAEP/MGF1 hash; SHA-1 or provider defaults were implicit. | `source/secured/rsa.d`, all `system/*` backends, OpenSSL/Security bindings | Additive `HashAlgorithm` parameter on `seal`/`open` (default **SHA2-384**). SHA-3 requires provider support; unsupported hashes throw `AlgorithmNotSupportedException`. |
| M3 | **OpenSSL PKCS#8 export ignored requested PBKDF2 iterations** — always used `PKCS5_DEFAULT_ITER` (2048) while the API default was 25000. | `source/secured/system/openssl.d`, `bindings/openssl.d` | Throws `CryptographicException` if requested `iterations != 2048`, naming the supported count in the message. |
| M4 | **`use3Des` silently ignored on CNG / CommonCrypto** — password-protected private keys always used AES-256-GCM containers. | `source/secured/system/windows.d`, `macos.d` | Throws if `use3Des` is requested, stating that AES-256-GCM is used instead. |
| M5 | **RSA seal ignored the requested symmetric algorithm on native backends** — CNG/macOS always used AES-256-GCM regardless of the `algorithm` argument. | `source/secured/system/windows.d`, `macos.d`, `openssl.d` | Honors the requested cipher when supported; throws `AlgorithmNotSupportedException` otherwise. Default `seal()` algorithm is **AES-256-GCM** so the no-arg path works on every native provider (CNG has no AES-CTR). |
| M6 | **CNG AES-GCM context not fully zero-initialized** — padding/auth info structs could contain stack garbage. | `source/secured/system/windows.d` | Zero-initialize GCM-related structures before use. |
| M7 | **HKDF context / buffers not always freed on error paths** | OpenSSL KDF path | Proper cleanup / free on failure. |
| M8 | **RSA PEM load missing null checks** | OpenSSL RSA load path | Null checks with clear `CryptographicException`s. |
| M9 | **`rsaOpen` insufficient envelope validation** — short or truncated sealed messages could mis-parse. | All hybrid seal backends | Length checks for wrapped-key length, IV, tag length, and remaining ciphertext. |
| M10 | **Password-protected RSA private key iteration count not round-tripped on CNG/macOS** — custom iteration counts could not be recovered. | `windows.d`, `macos.d` | Container flag 1 = legacy 25000; flag 2 embeds a 32-bit little-endian iteration count. |
| M11 | **OpenSSL encrypt with null/empty AAD edge cases** | OpenSSL AEAD encrypt path | Correct handling of null vs empty associated data. |

### LOW / hardening

| ID | Issue | Location | Fix |
|----|-------|----------|-----|
| L1 | Hybrid RSA seal envelope lacked an explicit tag-length byte for variable AEAD/non-AEAD tags. | All hybrid seal backends | Envelope layout: `[uint32 le wrappedKeyLen][wrappedKey][iv][ubyte tagLen][tag][ciphertext]`. |
| L2 | Provider capability gaps (e.g. SHA-3 on older Windows, ChaCha20 on CNG) were easy to misuse. | Provider modules | Runtime support probes + `AlgorithmNotSupportedException`; polyfill config for full coverage. |

---

## Residual / intentional limitations

1. **OpenSSL PKCS#8 iterations fixed at 2048** — cannot be changed via the OpenSSL PEM API SecureD uses; callers must pass `2048` (or accept the throw). CNG/CommonCrypto honour arbitrary positive iteration counts in their custom containers.
2. **`use3Des` only on OpenSSL-family backends** — native CNG/macOS password containers use AES-256-GCM only.
3. **Default RSA `seal()` uses AES-256-GCM** — not AES-CTR, so CNG succeeds without polyfill. Explicit CTR/CFB still requires provider support or polyfill.
4. **Default OAEP hash for seal is SHA2-384** — SHA-3 OAEP requires provider support (OpenSSL yes; CNG version-dependent; CommonCrypto no without polyfill).
5. **Legacy `encrypt`/`decrypt` RSA paths remain OAEP-SHA1** — retained for interop with existing data; new hybrid seal uses the selected hash.
6. **Non-AEAD v3.0.0 ciphertext is not readable by v3.1.0** — migrate by decrypt-then-re-encrypt (README).

---

## Verification

- Unittests: `dub test --config=cng` and `dub test --config=openssl` (and platform-native / polyfill as applicable).
- Unittests were only changed when they enforced incorrect security behavior (null-salt password key vector; OpenSSL iteration / 3DES expectations on backends that cannot honour them).
