# SecureD

SecureD is a cryptography library for D that is designed to make working with cryptography simple. Simplicity encourages developers to use cryptography in a safe and correct manner.

[![Build Status](https://travis-ci.org/LightBender/SecureD.svg?branch=master)](https://travis-ci.org/LightBender/SecureD)

## Design Philosophy

### Developer-Friendly Misuse-Resistant API
One of the largest problems with most cryptography libraries available today is that their convoluted API's actively encourage broken implementations. SecureD aims to provide a simple API that exposes a reasonable amount of choice.

### Focus on  Usages
SecureD is designed to support a wide-variety of uses. Examples include:
- Hashing
- Signing/Verification
- Long-Term Data Storage

However, SecureD is explicitly NOT intended to be used as a streaming transport security API. Implementing transport security protocols is a complex task that involves multiple layers of defenses. If you need such services please use SSL/TLS instead.

### Safe by Design
Use only safe algorithms with safe modes. Make conservative choices in the implementation.

### Do no Re-implement Cryptography Algorithms
Use industry standard libraries instead. SecureD is based on OpenSSL and, optionally, Botan.

### Minimal Code
Keep the code to a minimum. This ensures high-maintainability and facilitates understanding of the code.

### Unittesting
All API's are unittested using D's built in unittests. Any developer can verify the implementation with a simple 'dub test' command. This ensures that the library will perform as advertised.

## Algorithms

- Hash + HMAC:
  - SHA2: 224, 256, 384, 512, 512/224, 512/256
  - SHA3: 224, 256, 384, 512
- Symmetric:
  - Algorithms: AES (128/192/256)
  - Modes: CTR, CBC (PCKS7 Padding)
- KDF:              PBKDF2
- Asymmetric:       ECC-P384 (Key Derivation + Sign/Verify with SHA2-384)
- Asymmetric:       RSA-AES-256-CTR Seal/Open, RSA only Encrypt/Decrypt and RSA only Sign/Verify
- RNG:              System RNG on POSIX and Windows
- Other:            Constant Time Equality

## Why these Algorithms?

AES-CTR is an alternative for GCM that offers greater security for long-term data storage when paired with a strong HMAC. GCM use a 96-bit authentication tag where the HMAC tag is at least 256 bits.

AES-CBC is included for compatibility and should not be used for new projects.

## Versioning

SecureD follows SemVer. This means that the API surface and cryptographic implementations may be different between major versions. Minor and Point versions are cryptographically compatible. Minor versions may add new cryptographic algorithms to existing capabilities. Newer versions will provide an upgrade path from older versions where feasible.

SecureD is built against OpenSSL 1.1.0 or greater. If you need to use OpenSSL 1.0.x add 'version=OpenSSL10' to your command line.

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
```D
import secured.aes;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
ubyte[] data = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";

ubyte[] enc = encrypt(key, data);
if (validate(key, enc))
{
    //Note that decrypt performs a validation and will throw an exception if the validation fails.
    ubyte[] dec = decrypt(key, enc);
}
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