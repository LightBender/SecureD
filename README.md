# SecureD

SecureD is a cryptography library for D that is designed to make working with cryptography simple. Simplicity encourages developers to use cryptography in a safe and correct manner.

[![Build Status](https://travis-ci.org/LightBender/SecureD.svg?branch=master)](https://travis-ci.org/LightBender/SecureD)

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

### Do no Re-implement Cryptography Algorithms
Use industry standard libraries instead. SecureD is based on OpenSSL. Botan support was removed in V2 of SecureD due to the extensiveness of the rewrite that SecureD underwent. If someone is willing to update with new implementations they will be considered for inclusion.

### Minimal Code
Keep the code to a minimum. This ensures high-maintainability and facilitates understanding of the code.

### Unittesting
All API's are unittested using D's built in unittests. Any developer can verify the implementation with a simple 'dub test' command. This ensures that the library will perform as advertised.

## Algorithms

- Hash + HMAC:
  - SHA2: 224, 256, 384, 512, 512/224, 512/256
  - SHA3: 224, 256, 384, 512
- Symmetric:
  - Algorithms: AES (128/192/256), ChaCha20
  - Stream Modes: GCM, CTR, Poly1305 (ChaCha20 only)
  - Block Modes: OFB, CFB, CBC (PKCS7 Padding Only)
- KDF:              PBKDF2, HKDF, SCrypt
- Asymmetric:       ECC: P256, P384, P521 - (Key Derivation + Sign/Verify with SHA2-384 or SHA2-256)
- Asymmetric:       RSA-AES Seal/Open, RSA Encrypt/Decrypt, and RSA Sign/Verify
- RNG:              System RNG on POSIX and Windows
- Other:            Constant Time Equality

## Versioning

SecureD follows SemVer. This means that the API surface and cryptographic implementations may be different between major versions. Minor and Point versions are cryptographically compatible. Minor versions may add new cryptographic algorithms to existing capabilities. Newer versions will provide an upgrade path from older versions where feasible.

SecureD is built against OpenSSL 1.1.1 or greater.

## Examples

### Hashing/HMAC
```D
import secured;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
ubyte[] data = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";
string filePath = "/usr/local/bin/dmd";

ubyte[] result1 = hash(key, data);
ubyte[] result2 = hash(key, filePath);
ubyte[] result3 = hmac(key, data);
ubyte[] result4 = hmac(key, filePath);
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

ubyte[] key = pbkdf2(key, password, iterations, outputLength);
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

ubyte[] enc = encrypt(key, data, null);
//Note that decrypt performs a validation and will throw an exception if the validation fails.
ubyte[] dec = decrypt(key, enc, null);
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

NOTE: SecureD is built against OpenSSL 1.1.0 or greater. If you need to use OpenSSL 1.0.x add version 'OpenSSL10' to your command line.