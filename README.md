# SecureD

SecureD is a cryptography library for D that is designed to make working with cryptography simple. Simplicity encourages developers to use cryptography in a safe and correct manner.

[![Build Status](https://travis-ci.org/LightBender/SecureD.svg?branch=master)](https://travis-ci.org/LightBender/SecureD)

## Design Philosophy

### Developer-Friendly Misuse-Resistant API
One of the largest problems with most cryptography libraries available today is that their API's practically encourage broken implementations.

### Focus on Data Storage
The primary intended use case for this library is for long-term data storage. It is not intended to be used as an SSL or streaming communications cryptography library.

### Safe by Design
Use only safe algorithms with safe modes. Make conservative choices in the implementation.

### Do no re-implement Cryptography Algorithms
Use industry standard libraries instead. SecureD is based on OpenSSL.

### Minimal Code
Keep the code to a minimum. This ensures high-maintainability and eases understanding of the code.

### Unittesting
All API's are unittested using D's built in unittests. Any developer can verify the implementation with a simple 'dub test' command. This ensures that the library will perform as advertised.

## Algorithms

- HASH:				SHA2-384
- HMAC:				SHA2-384
- KDF:				PBKDF2 (HMAC/SHA2-384)
- AE Symmetric: 	AES-256-CTR-HMAC384
- Asymmetric:		ECC-P384 (Key Derivation + Sign/Verify with SHA2-384)
- Asymmetric:		RSA-AES-256-CTR Seal/Open, RSA only Encrypt/Decrypt and RSA only Sign/Verify
- RNG: 				System RNG on POSIX and Windows
- OTHER: 			Constant Time Equality

## Why these Algorithms?

SHA2-384 is as fast as SHA2-512 but it's truncated design serves as an effective defense against length extensions attacks.

AES-256-CTR is an alternative for GCM that offers greater security for cold-stored data when paired with a strong HMAC. GCM use a 96-bit authentication tag where the HMAC tag is a full 384 bits.

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