# SecureD

SecureD is a cryptography library for D that is designed to make working with cryptography simple. Simplicity encourages developers to use cryptography in a safe and correct manner.

## Design Philosophy

- SecureD does not present a menu of options by default. This is because the dizzying array of options presented to developers by other cryptography libraries creates confusion about what they should actually be using 95% of the time. SecureD presents sensible defaults that should be used in 95% of implementations. However, a selection of options is available under the extended API's should a situation arise where such flexibility is required.
- SecureD reserves the right to change which algorithms and defaults it presents should significant weaknesses be found. If such change is required, this will trigger an increase of the major version number.
- SecureD takes a situational approach to it's construction. Identify a situation then apply best practices to implement with a solution. Situations that SecureD supports are:
  - Data Integrity
  - Data Storage
  - Message Authentication
  - Key Derivation (Both PKI and KDF based)

### Developer-Friendly Misuse-Resistant API
One of the largest problems with most cryptography libraries available today is that their convoluted API's actively encourage broken implementations. SecureD aims to provide a simple API that exposes a reasonable amount of choice.

### Focus on Non Transport-Layer Usages
SecureD is designed to support a wide-variety of uses. However, SecureD is explicitly NOT intended to be used as a transport-layer security API. Implementing transport security protocols is a complex task that involves multiple layers of defenses. If you need such services please use TLS instead.

### Safe by Design
Use only safe algorithms with safe modes. Make conservative choices in the implementation.

### Do Not Re-implement Cryptography Algorithms
Use industry standard libraries instead. SecureD delegates every cryptographic operation to the cryptographic provider supplied by the host operating system or a well-known industry library — it never implements primitives itself. By default it uses the OS-native provider (Windows CNG, Apple CommonCrypto, or OpenSSL on Linux/FreeBSD) and can also target LibreSSL or BoringSSL. See [Cryptographic Providers](#cryptographic-providers) for details. Botan support was removed in V2 of SecureD due to the extensiveness of the rewrite that SecureD underwent. If someone is willing to update with new implementations they will be considered for inclusion.

### Minimal Code
Keep the code to a minimum. This ensures high-maintainability and facilitates understanding of the code.

### Unittesting
All API's are unittested using D's built in unittests. Any developer can verify the implementation with a simple 'dub test' command. This ensures that the library will perform as advertised.

## Algorithms

- Hash + HMAC:
  - SHA2: 256, 384, 512, 512/224, 512/256
  - SHA3: 224, 256, 384, 512
- Symmetric:
  - Algorithms: AES (128/192/256), ChaCha20
  - Stream Modes: GCM, CTR, Poly1305 (ChaCha20 only)
  - Block Modes: CFB, CBC (PKCS7 Padding Only)
- KDF:              PBKDF2, HKDF, SCrypt
- Asymmetric:       ECC: P256, P384, P521 - (Key Derivation + Sign/Verify with SHA2-384 or SHA2-256)
- Asymmetric:       RSA-AES Seal/Open, RSA Encrypt/Decrypt, and RSA Sign/Verify
- RNG:              System RNG on POSIX and Windows
- Other:            Constant Time Equality

## Cryptographic Providers

SecureD does not implement any cryptographic primitives itself. Instead it dispatches each operation to a cryptographic **provider** that is selected at build time. The public API acts purely as an algorithm-availability detector and forwards to the private implementation for the selected provider.

By default SecureD uses the **OS-native** provider:

| Platform         | Default provider      |
|------------------|-----------------------|
| Windows          | CNG (bcrypt/ncrypt)   |
| macOS            | CommonCrypto + Security framework |
| Linux / FreeBSD  | OpenSSL               |

### Build configurations

Each provider has a corresponding dub configuration. Select one with `dub build --config=<name>` or `dub test --config=<name>`:

| Configuration   | Provider                                     |
|-----------------|----------------------------------------------|
| `library`       | OS-native (default)                          |
| `openssl`       | OpenSSL                                      |
| `libressl`      | LibreSSL                                     |
| `boringssl`     | BoringSSL                                    |
| `cng`           | Windows CNG                                  |
| `commoncrypto`  | Apple CommonCrypto                           |
| `polyfill`      | OS-native provider + OpenSSL fallback        |

### The polyfill configuration

Not every provider supports every algorithm. The `polyfill` configuration keeps the OS-native provider as the primary backend and uses OpenSSL to fill in any algorithm the native provider cannot supply. By default (without polyfill) the native provider is used exclusively.

If an unsupported algorithm is requested while the polyfill is disabled, SecureD emits a compile-time error where the incompatibility is known at compile time, and otherwise throws a `CryptographicException` (specifically an `AlgorithmNotSupportedException`) at runtime. Some algorithms — for example SHA-3 on Windows CNG — depend on the OS version and are detected at runtime; if the running OS does not provide them a `CryptographicException` is thrown.

### Provider capability matrix

✅ native &middot; ⚠️ runtime/version dependent &middot; ↩ provided by the polyfill

| Algorithm                    | OpenSSL / LibreSSL / BoringSSL | CNG (Windows) | CommonCrypto (macOS) |
|------------------------------|--------------------------------|---------------|----------------------|
| SHA-2 256 / 384 / 512        | ✅                             | ✅            | ✅                  |
| SHA-2 512/224, 512/256       | ✅                             | ↩             | ↩                   |
| SHA-3 224/256/384/512        | ✅ (⚠️ BoringSSL/LibreSSL)     | ⚠️ / ↩        | ↩                  |
| HMAC (supported hashes)      | ✅                             | ✅            | ✅                  |
| AES-GCM / AES-CBC            | ✅                             | ✅            | ✅                  |
| AES-CTR / AES-CFB            | ✅                             | ↩             | ✅                  |
| ChaCha20 / ChaCha20-Poly1305 | ✅                             | ↩             | ↩                   |
| PBKDF2                       | ✅                             | ✅            | ✅                  |
| HKDF                         | ✅                             | ↩             | ↩                   |
| SCrypt                       | ✅ (↩ BoringSSL)               | ↩             | ↩                  |
| ECC (P-256 / 384 / 521)      | ✅                             | ✅            | ✅ †                |
| RSA (seal / OAEP / sign)     | ✅                             | ✅            | ✅ †                |

† On macOS, RSA and ECC are provided by the **Security framework** (`SecKey`), not CommonCrypto, whose asymmetric interfaces are private SPI. On Windows, ECC uses CNG's ECDSA / ECDH providers. `EccCurve.P256`, `P384` and `P521` are the NIST prime curves (P-256, P-384 — the default — and P-521) on every backend.

To run the complete test suite on a platform whose native provider does not cover every algorithm, use the `polyfill` configuration (for example `dub test --config=polyfill`). When run against a native-only configuration, tests for algorithms the provider does not support print a skip notice instead of failing.

## Versioning

SecureD follows SemVer. This means that the API surface and cryptographic implementations may be different between major versions. Minor and Point versions are cryptographically compatible. Minor versions may add new cryptographic algorithms to existing capabilities. Newer versions will provide an upgrade path from older versions where feasible.

When an OpenSSL-family provider is used (OpenSSL, LibreSSL, BoringSSL, or the polyfill), SecureD is built against OpenSSL 3.0.12 (or a compatible LibreSSL/BoringSSL) or greater. The OpenSSL API declarations SecureD requires are vendored directly into the library (see `source/secured/bindings/openssl.d`), so there is no external Deimos binding dependency.

### Non-AEAD ciphertext compatibility (v3.0.0 → v3.1.0)

In v3.0.0, non-AEAD modes (AES-CBC / AES-CTR / AES-CFB / ChaCha20) used the public IV as the HMAC secret when computing the encrypt-then-MAC authentication tag. That construction is incorrect: the IV is not secret and must not be used as a MAC key.

v3.1.0 derives the MAC key as `hash(encryptionKey)` and binds the IV into the MAC input instead. Ciphertexts produced with non-AEAD modes under v3.0.0 therefore cannot be decrypted with v3.1.0 (authentication will fail).

**Migration:** decrypt affected data with SecureD **v3.0.0**, then re-encrypt with **v3.1.0** (or later). AEAD modes (AES-GCM, ChaCha20-Poly1305) are unaffected.

## Examples

### Hashing/HMAC
```D
import secured;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
ubyte[] data = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";
string filePath = "/usr/local/bin/dmd";

ubyte[] result1 = hash(data);
ubyte[] result2 = hash_ex(filePath, HashAlgorithm.SHA3_384);
ubyte[] result3 = hmac(key, data);
ubyte[] result4 = hmac_ex(key, filePath, HashAlgorithm.SHA3_384);
```

### PBKDF2
```D
import secured.kdf;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
string password = "Test";
uint iterations = 25000; //Defaut value
uint outputLength = 48; //Default value, must be 48 bytes or less

KdfResult derived = pbkdf2(password);
pbkdf2_verify(derived.key, derived.salt, password);
```

### Encryption/Decryption
The encrypt and decrypt functions work on arbitrarily sized plaintexts of data. By default if a plaintext is larger than 256MiB it will be broken into multiple blocks with new derived keys for each block to prevent auth tag collisions. Using the defaults it is possible to securely store up to 1024PiB of information in a single file, however, it is possible to store up to store up to 16384PiB of plaintext. In practice, the lack of streams in D make this infeasible as no computer on earth has enough memory to achieve these numbers.

By default the encrypt and decrypt functions include all infromation required to decrypt, except the key. This information is stored in a "header" which is prepended to the actual encrypted payload. If the cipher is an AEAD cipher, then any Additional Data will be included between the header and the encrypted payload.

The encrypt_ex and decrypt_ex functions are provided to enable custom encryption and decryption scenarios and do not include any of the additional header information.

```D
import secured.symmetric;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
ubyte[] data = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";

SymmetricKey skey = initializeSymmetricKey(key);
EncryptedData enc = encrypt(skey, data);
//Note that decrypt performs a validation and will throw an exception if the validation fails.
ubyte[] dec = decrypt(skey, enc);
```

### ECC Key Derivation
```D
import secured.ecc;

EllipticCurve eckey1 = new EllipticCurve();
EllipticCurve eckey2 = new EllipticCurve();

string pubKey1 = eckey1.getPublicKey();
string pubKey2 = eckey2.getPublicKey();
ubyte[] key1 = eckey1.derive(pubKey2);
ubyte[] key2 = eckey2.derive(pubKey1);

assert(constantTimeEquality(key1, key2));
```

### Random Number Generation
```D
import secured.random;

uint numBytes = 128;
ubyte[] randomBytes = random(numBytes);
```

### Constant Time Equality
```D
import secured.util;

ubyte[] a = [ 0x01 ];
ubyte[] b = [ 0x01 ];
bool isEqual = constantTimeEquality(a, b);
```
