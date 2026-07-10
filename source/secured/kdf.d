module secured.kdf;

import std.base64;
import std.conv;
import std.typecons;
import std.format;
import std.string;

import secured.hash;
import secured.provider;
import secured.random;
import secured.symmetric;
import secured.util;

static if (usesOpenSSL) {
    import secured.system.openssl : pbkdf2_impl_openssl, hkdf_impl_openssl, scrypt_impl_openssl;
}
static if (activeProvider == Provider.CNG) {
    import secured.system.windows : pbkdf2_impl_cng, cngSupportsHash;
}
static if (activeProvider == Provider.CommonCrypto) {
    import secured.system.macos : pbkdf2_impl_commoncrypto, commonCryptoSupportsHash;
}

/**
 * Default PBKDF2 iteration count and scrypt CPU/memory cost parameter N
 * ($(D 2^^20) = 1_048_576). Chosen as a high work factor that remains practical
 * on modern hardware while resisting offline password guessing.
 */
public enum uint defaultKdfIterations = 1_048_576;

/**
 * Default scrypt block size parameter `r`. The value 8 is the widely recommended
 * scrypt profile (memory ≈ 128·N·r bytes with N = $(D defaultKdfIterations)).
 */
public enum ushort defaultSCryptR = 8;

/**
 * Default scrypt parallelization parameter `p`. The value 1 is the common
 * single-lane profile used with r = 8.
 */
public enum ushort defaultSCryptP = 1;

/**
 * Upper bound on scrypt memory usage (bytes) passed to the OpenSSL implementation
 * as a safety limit (~1 GiB). Prevents pathological (N, r, p) combinations from
 * exhausting process memory.
 */
public enum ulong maxSCryptMemory = 1_074_790_400;

/**
 * Key-derivation algorithms available for password hashing and key stretching.
 *
 * The library default is $(D SCrypt): memory-hard, widely reviewed, and a strong
 * choice for password storage. PBKDF2 remains available for interoperability.
 * HKDF is for deriving keys from high-entropy material, not for password hashing.
 * Argon2 is reserved but not yet implemented.
 */
public enum KdfAlgorithm : ubyte {
    /// Sentinel / unused.
    None = 0,
    /// PBKDF2-HMAC with a configurable hash (default SHA2-384).
    PBKDF2 = 1,
    /// HKDF (RFC 5869); not valid for password storage APIs.
    HKDF = 2,
    /// scrypt (memory-hard); library default for password security.
    SCrypt = 3,
    /// Reserved; not currently implemented.
    Argon2 = 4,
    /// Default password KDF: scrypt (memory-hard, strong offline resistance).
    Default = SCrypt,
}

/**
 * Result of verifying a stored password hash against a supplied password.
 */
public enum VerifyPasswordResult
{
    /// The password verification was successful.
    Success,
    /// The password verification failed.
    Failure,
    /// The password matched, but the stored parameters are outdated and the
    /// password should be rehashed with current defaults.
    Rehash,
}

/**
 * Encoded password hash: algorithm, parameter version, salt, and derived key.
 *
 * Serialized form is `algorithm.version.saltB64.derivedB64` (dot-separated).
 */
@safe public struct HashedPassword
{
    /// The KDF used to secure the password.
    public KdfAlgorithm algorithm;
    /// Version of the hash parameters (used to signal rehash needs).
    public short parameterVersion;
    /// Random salt used by the KDF (does not include the application pepper).
    public ubyte[] salt;
    /// Derived key / password hash bytes.
    public ubyte[] derived;

    /**
     * Constructs a HashedPassword from hashing parameters (package use).
     *
     * Params:
     *   derived      = The hashed password / derived key.
     *   salt         = The salt used by the hashing function.
     *   algorithm    = The KDF used to secure the password.
     *   paramVersion = Parameter-set version for rehash detection.
     */
    package this(ubyte[] derived, ubyte[] salt, KdfAlgorithm algorithm, ushort paramVersion)
    {
        this.algorithm = algorithm;
        this.parameterVersion = paramVersion;
        this.salt = salt;
        this.derived = derived;
    }

    /**
     * Constructs a HashedPassword from an encoded string produced by
     * $(D toString).
     *
     * Params:
     *   encoded = Dot-separated encoding: algorithm, version, Base64 salt,
     *             Base64 derived key.
     *
     * Throws: $(D CryptographicException) if the string is malformed.
     */
    public this(string encoded) {
        auto parts = encoded.split(".");
        if (parts.length != 4) throw new CryptographicException("Invalid password string provided.");

        this.algorithm = to!KdfAlgorithm(to!int(parts[0]));
        this.parameterVersion = to!ushort(parts[1]);
        this.salt = Base64.decode(parts[2]);
        this.derived = Base64.decode(parts[3]);
    }

    /**
     * Encodes this password hash for storage.
     *
     * Returns: Dot-separated string of algorithm, version, Base64 salt, and
     *          Base64 derived key.
     */
    public string toString() {
        return to!string(join([to!string(to!int(algorithm)), to!string(parameterVersion), Base64.encode(salt), Base64.encode(derived)], "."));
    }
}

/**
 * Hashes a password for storage using a random salt and optional application
 * pepper.
 *
 * A fresh 32-byte salt is generated per call. The pepper is concatenated with
 * the salt before derivation so a server-side secret can harden stored hashes
 * without changing the public encoding format.
 *
 * Default algorithm is $(D KdfAlgorithm.SCrypt) (memory-hard). PBKDF2 uses
 * $(D HashAlgorithm.Default) (SHA2-384) and $(D defaultKdfIterations)
 * (1_048_576). Output length is 64 bytes.
 *
 * Params:
 *   password  = User password (UTF-8 string).
 *   pepper    = Optional application-wide secret mixed into the salt. May be
 *               empty if unused.
 *   algorithm = KDF to use. Default: $(D KdfAlgorithm.Default) (scrypt).
 *               HKDF, Argon2, and None are rejected.
 *
 * Returns: $(D HashedPassword) ready for encoding via $(D toString).
 *
 * Throws: $(D CryptographicException) for unsupported algorithms or KDF failure.
 */
@safe public HashedPassword securePassword(string password, const ubyte[] pepper, KdfAlgorithm algorithm = KdfAlgorithm.Default) {
    if (algorithm == KdfAlgorithm.HKDF) throw new CryptographicException("KdfAlgorithm.HKDF is not supported for password security.");

    if (algorithm == KdfAlgorithm.PBKDF2) {
        ubyte[] salt = random(32);
        return HashedPassword(pbkdf2_ex(password, salt ~ pepper, HashAlgorithm.Default, 64, defaultKdfIterations), salt, algorithm, 1);
    }

    if (algorithm == KdfAlgorithm.SCrypt) {
        ubyte[] salt = random(32);
        return HashedPassword(scrypt_ex(password, salt ~ pepper, 64), salt, algorithm, 1);
    }

    if (algorithm == KdfAlgorithm.Argon2) throw new CryptographicException("Argon2 is not supported.");

    throw new CryptographicException("KdfAlgorithm.None is not supported for password security.");
}

/**
 * Verifies a supplied password against a stored $(D HashedPassword).
 *
 * Uses constant-time comparison of derived keys. Parameter version 0 for
 * PBKDF2 indicates legacy parameters and returns $(D Rehash) on success so
 * callers can upgrade stored hashes.
 *
 * Params:
 *   suppliedPassword = Password presented by the user.
 *   storedPassword   = Previously stored hash (from $(D securePassword) or
 *                      decoded via $(D HashedPassword.this(string))).
 *   pepper           = Same application pepper used when hashing (may be empty).
 *
 * Returns: $(D Success), $(D Failure), or $(D Rehash).
 *
 * Throws: $(D CryptographicException) if the stored algorithm is unsupported
 *         for password verification (HKDF, Argon2).
 */
@safe public VerifyPasswordResult verifyPassword(string suppliedPassword, HashedPassword storedPassword, const ubyte[] pepper) {
    if (storedPassword.algorithm == KdfAlgorithm.HKDF) throw new CryptographicException("KdfAlgorithm.HKDF is not supported for password security.");

    if (storedPassword.algorithm == KdfAlgorithm.PBKDF2 && storedPassword.parameterVersion == 1) {
        if (pbkdf2_verify_ex(storedPassword.derived, suppliedPassword, storedPassword.salt ~ pepper, HashAlgorithm.Default, 64, defaultKdfIterations)) return VerifyPasswordResult.Success;
    }
    else if (storedPassword.algorithm == KdfAlgorithm.PBKDF2 && storedPassword.parameterVersion == 0) {
        if (pbkdf2_verify_ex(storedPassword.derived, suppliedPassword, storedPassword.salt ~ pepper, HashAlgorithm.SHA2_512, to!uint(storedPassword.derived.length), 100000)) return VerifyPasswordResult.Rehash;
    }

    if (storedPassword.algorithm == KdfAlgorithm.SCrypt && storedPassword.parameterVersion == 1) {
        ubyte[] supplied = scrypt_ex(suppliedPassword, storedPassword.salt ~ pepper, 64);
        if (supplied.constantTimeEquality(storedPassword.derived)) return VerifyPasswordResult.Success;
    }

    if (storedPassword.algorithm == KdfAlgorithm.Argon2) throw new CryptographicException("Argon2 is not supported.");

    return VerifyPasswordResult.Failure;
}

unittest {
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    ubyte[48] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    writeln("Successful Password Test");
    HashedPassword successTest = securePassword("TestPassword!@#$%", salt);
    writeln("Encoded: ", successTest.toString());
    auto verifyResult = verifyPassword("TestPassword!@#$%", successTest, salt);
    assert (verifyResult == VerifyPasswordResult.Success);

    writeln("Failure Password Test");
    HashedPassword failTest = securePassword("TestPassword!@#$%", salt);
    writeln("Encoded: ", failTest.toString());
    verifyResult = verifyPassword("TestPassword!@#$", failTest, salt);
    assert (verifyResult == VerifyPasswordResult.Failure);

    writeln("PBKDF2 Password Test");
    HashedPassword pbkdf2Test = securePassword("TestPassword!@#$%", salt, KdfAlgorithm.PBKDF2);
    writeln("Encoded: ", pbkdf2Test.toString());
    verifyResult = verifyPassword("TestPassword!@#$%", pbkdf2Test, salt);
    assert (verifyResult == VerifyPasswordResult.Success);
    });
}

/**
 * Result of a key-derivation operation that generates its own salt.
 *
 * Fields:
 *   salt = Random salt used during derivation (must be stored with the key).
 *   key  = Derived key material.
 */
public struct KdfResult {
    /// Random salt used during derivation.
    public ubyte[] salt;
    /// Derived key material.
    public ubyte[] key;
}

/**
 * Derives a key from `password` using PBKDF2-HMAC with the library defaults.
 *
 * Generates a random salt of length equal to the default hash output
 * (SHA2-384 → 48 bytes). Uses $(D HashAlgorithm.Default) and produces a key of
 * the same length. Default iterations are $(D defaultKdfIterations)
 * (1_048_576) for a high work factor against offline guessing.
 *
 * Params:
 *   password   = Password string to stretch.
 *   iterations = PBKDF2 iteration count. Default: $(D defaultKdfIterations).
 *
 * Returns: $(D KdfResult) containing the salt and derived key. Persist both.
 *
 * Throws: $(D AlgorithmNotSupportedException) / $(D CryptographicException) on
 *         provider failure.
 */
@safe public KdfResult pbkdf2(string password, uint iterations = defaultKdfIterations) {
    KdfResult result;
    result.salt = random(getHashLength(HashAlgorithm.Default));
    result.key = pbkdf2_ex(password, result.salt, HashAlgorithm.Default, getHashLength(HashAlgorithm.Default), iterations);
    return result;
}

/**
 * Verifies that `key` was derived from `password` and `salt` with the default
 * PBKDF2 parameters (SHA2-384, key length = hash length).
 *
 * Params:
 *   key        = Expected derived key.
 *   salt       = Salt used during original derivation.
 *   password   = Password to re-derive from.
 *   iterations = PBKDF2 iteration count. Default: $(D defaultKdfIterations).
 *
 * Returns: `true` if the re-derived key matches `key` (constant-time).
 */
@safe public bool pbkdf2_verify(const ubyte[] key, const ubyte[] salt, string password, uint iterations = defaultKdfIterations) {
    ubyte[] test = pbkdf2_ex(password, salt, HashAlgorithm.Default, getHashLength(HashAlgorithm.Default), iterations);
    return constantTimeEquality(key, test);
}

package(secured) string unsupportedKdfMessage(string name) {
    return "KDF '" ~ name ~ "' is not supported by the active cryptographic provider. Enable the 'polyfill' configuration to use OpenSSL as a fallback.";
}

/**
 * Derives a key from `password` using PBKDF2-HMAC with full parameter control.
 *
 * Params:
 *   password   = Password string to stretch.
 *   salt       = Salt bytes (should be unique and random per password).
 *   func       = Underlying hash for HMAC (e.g. $(D HashAlgorithm.SHA2_384)).
 *   outputLen  = Desired derived-key length in bytes.
 *   iterations = PBKDF2 iteration count (higher = slower offline attacks).
 *
 * Returns: Derived key of length `outputLen`.
 *
 * Throws:
 *   $(D AlgorithmNotSupportedException) if the hash/KDF is unavailable.
 *   $(D CryptographicException) on provider failure.
 */
@trusted public ubyte[] pbkdf2_ex(string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
    static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
        return pbkdf2_impl_openssl(password, salt, func, outputLen, iterations);
    } else static if (activeProvider == Provider.CNG) {
        if (cngSupportsHash(func)) {
            return pbkdf2_impl_cng(password, salt, func, outputLen, iterations);
        } else static if (polyfillEnabled) {
            return pbkdf2_impl_openssl(password, salt, func, outputLen, iterations);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedKdfMessage("PBKDF2"));
        }
    } else static if (activeProvider == Provider.CommonCrypto) {
        if (commonCryptoSupportsHash(func)) {
            return pbkdf2_impl_commoncrypto(password, salt, func, outputLen, iterations);
        } else static if (polyfillEnabled) {
            return pbkdf2_impl_openssl(password, salt, func, outputLen, iterations);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedKdfMessage("PBKDF2"));
        }
    } else static if (polyfillEnabled) {
        return pbkdf2_impl_openssl(password, salt, func, outputLen, iterations);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedKdfMessage("PBKDF2"));
    }
}

/**
 * Verifies a PBKDF2-derived key with full parameter control using constant-time
 * comparison.
 *
 * Params:
 *   test       = Expected derived key.
 *   password   = Password to re-derive from.
 *   salt       = Salt used during original derivation.
 *   func       = Hash algorithm used in PBKDF2-HMAC.
 *   outputLen  = Derived-key length in bytes.
 *   iterations = PBKDF2 iteration count.
 *
 * Returns: `true` if the re-derived key matches `test`.
 */
@safe public bool pbkdf2_verify_ex(const ubyte[] test, string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
    ubyte[] key = pbkdf2_ex(password, salt, func, outputLen, iterations);
    return constantTimeEquality(test, key);
}

unittest
{
    skipIfUnsupported({
    import std.datetime.stopwatch;
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Basic Methods:");

    //Test basic methods
    auto sw = StopWatch(AutoStart.no);
    sw.start();
    auto result = pbkdf2("password");
    sw.stop();
    writefln("PBKDF2 took %sms for 1,000,000 iterations", sw.peek.total!"msecs");

    assert(result.key.length == 48);
    assert(pbkdf2_verify(result.key, result.salt, "password"));
    writeln(toHexString!(LetterCase.lower)(result.key));

    //Test extended methods
    ubyte[32] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] key = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, HashAlgorithm.SHA2_384, 64, 100000);
    assert(pbkdf2_verify_ex(key, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, HashAlgorithm.SHA2_384, 64, 100000));
    writeln(toHexString!(LetterCase.lower)(key));
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Extended with Defaults:");

    ubyte[48] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec1 = pbkdf2_ex("", key, HashAlgorithm.SHA2_384, 48, 25000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashAlgorithm.SHA2_384, 48, 25000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashAlgorithm.SHA2_384, 48, 25000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bde9db7c8ccf14df26f8305fc8634572f9");
    assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff45417d47d84db06a12b8ea49377a7c7cb");
    assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520b2834d7bf22b83bb5c21c4bccb423be2");
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Extended with Custom Iterations:");

    ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                     0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                     0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec1 = pbkdf2_ex("", key, HashAlgorithm.SHA2_384, 48, 150000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashAlgorithm.SHA2_384, 48, 150000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashAlgorithm.SHA2_384, 48, 150000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "babdcbbf4ff89367ed223d2edd06ef5473ac9cdc827783ed0b4b5eafd9e4097beb2ef66d6fc92d24dbf4b86aa51b4a0f");
    assert(toHexString!(LetterCase.lower)(vec2) == "8894348ccea06d79f80382ae7d4434c0f2ef41f871d936604f426518ab23bde4410fddce6dad943c95de75dbece9b54a");
    assert(toHexString!(LetterCase.lower)(vec3) == "fba55e91818c35b1e4cc753fbd01a6cd138c49da472b58b2d7c4860ba39a3dd9032f8f641aadcd74a819361ed27c9a0f");
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Extended with Custom Output Length:");

    ubyte[48] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec1 = pbkdf2_ex("", key, HashAlgorithm.SHA2_384, 32, 25000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashAlgorithm.SHA2_384, 32, 25000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashAlgorithm.SHA2_384, 32, 25000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bd");
    assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff4");
    assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520");
    });
}

/**
 * Derives a new key from a $(D SymmetricKey) via HKDF using the cipher's native
 * key length as the output size.
 *
 * Generates a random salt of default-hash length (SHA2-384 → 48 bytes). Empty
 * `info` is used. Prefer this for expanding high-entropy key material—not for
 * password hashing.
 *
 * Params:
 *   key = Source symmetric key (high-entropy input keying material).
 *
 * Returns: $(D KdfResult) with salt and derived key. Persist the salt if the
 *          derived key must be reproducible.
 *
 * Throws: $(D AlgorithmNotSupportedException) if HKDF is unavailable (requires
 *         OpenSSL-family or polyfill).
 */
@safe public KdfResult hkdf(const SymmetricKey key) {
    return hkdf(key, getCipherKeyLength(key.algorithm));
}

/**
 * Derives a new key from a $(D SymmetricKey) via HKDF with an explicit output
 * length.
 *
 * Params:
 *   key       = Source symmetric key (high-entropy IKM).
 *   outputLen = Desired derived-key length in bytes.
 *
 * Returns: $(D KdfResult) with random salt and derived key.
 */
@safe public KdfResult hkdf(const SymmetricKey key, size_t outputLen) {
    KdfResult result;
    result.salt = random(getHashLength(HashAlgorithm.Default));
    result.key = hkdf_ex(key.value, result.salt, string.init, outputLen, HashAlgorithm.Default);
    return result;
}

/**
 * HKDF-Extract-and-Expand (RFC 5869) with full parameter control.
 *
 * Params:
 *   key       = Input keying material (IKM). Must be non-empty.
 *   salt      = Optional salt for Extract (may be empty; random salt preferred).
 *   info      = Optional context/application-specific info for Expand.
 *   outputLen = Desired output keying material length in bytes.
 *   func      = Hash algorithm for HMAC-based HKDF (default elsewhere is
 *               SHA2-384 for length-extension resilience and OS availability).
 *
 * Returns: Derived key of length `outputLen`.
 *
 * Throws:
 *   $(D CryptographicException) if `key` is empty.
 *   $(D AlgorithmNotSupportedException) if HKDF is unavailable on this build.
 */
@trusted public ubyte[] hkdf_ex(const ubyte[] key, const ubyte[] salt, string info, size_t outputLen, HashAlgorithm func) {
    if (key.length == 0) {
        throw new CryptographicException("HKDF key cannot be an empty array.");
    }

    static if (usesOpenSSL) {
        return hkdf_impl_openssl(key, salt, info, outputLen, func);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedKdfMessage("HKDF"));
    }
}

unittest
{
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    writeln("Testing HKDF Extended with Defaults:");

    ubyte[48] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec2 = hkdf_ex(cast(ubyte[])"abc", salt, "", 64, HashAlgorithm.SHA2_384);
    ubyte[] vec3 = hkdf_ex(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, "test", 64, HashAlgorithm.SHA2_384);

    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec2) == "65e464a5d7026678a3af78bf0282592472f85ccd7d1040e2dea5cea9218276a960367d418154a1e95019182a3c857286860aa0711955829e896b5bcdb1224794");
    assert(toHexString!(LetterCase.lower)(vec3) == "12a82466f85ead03f50bb502475b47ec50e7224a90f0219955bf09846ed72791206f6e713a529a0082bf7229093f2b4e6c6b467119518a2579a5b091ebe8ba12");
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    writeln("Testing HKDF Extended with SHA3_384:");

    ubyte[48] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec2 = hkdf_ex(cast(ubyte[])"abc", salt, "", 64, HashAlgorithm.SHA3_384);
    ubyte[] vec3 = hkdf_ex(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, "test", 64, HashAlgorithm.SHA3_384);

    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec2) == "41999e49a273f7f1367c7b3c7bd80d56fa27307cdfdf0274c022a0185080ddaa36410a93098f325785e5c27c406df535c91cc47096dc846d5c1dea671a40f944");
    assert(toHexString!(LetterCase.lower)(vec3) == "15addd263fdab613056a7a82804c1d1c158ea901424d277c25407c15be4b7aa8cad52251de18b3151145035e94c8f360517bda7912d2249f80c9662c1a1cd345");
    });
}

/**
 * Derives a 64-byte key from a password string using scrypt with library
 * defaults and a fresh 32-byte random salt.
 *
 * Defaults: N = $(D defaultKdfIterations) (2^20), r = $(D defaultSCryptR) (8),
 * p = $(D defaultSCryptP) (1). These match the common memory-hard scrypt
 * profile and provide strong resistance to GPU/ASIC offline attacks.
 *
 * Params:
 *   password = Password string to stretch.
 *
 * Returns: $(D KdfResult) with salt and 64-byte derived key. Persist both.
 *
 * Throws: $(D AlgorithmNotSupportedException) if scrypt is unavailable
 *         (requires OpenSSL-family or polyfill).
 */
@safe public KdfResult scrypt(string password) {
    KdfResult result;
    result.salt = random(32);
    // N must be a large power of two (defaultKdfIterations = 2^20). Using
    // defaultSCryptR for N was a parameter mix-up that made scrypt trivial.
    result.key = scrypt_ex(password, result.salt, defaultKdfIterations, defaultSCryptR, defaultSCryptP, maxSCryptMemory, 64);
    return result;
}

/**
 * Derives a 64-byte key from raw password bytes using scrypt with library
 * defaults and a fresh 32-byte random salt.
 *
 * Params:
 *   password = Password bytes to stretch.
 *
 * Returns: $(D KdfResult) with salt and 64-byte derived key.
 */
@safe public KdfResult scrypt(const ubyte[] password) {
    KdfResult result;
    result.salt = random(32);
    result.key = scrypt_ex(password, result.salt, defaultKdfIterations, defaultSCryptR, defaultSCryptP, maxSCryptMemory, 64);
    return result;
}

/**
 * scrypt with default N/r/p and an explicit output length.
 *
 * Params:
 *   password = Password string.
 *   salt     = Salt bytes (unique per password).
 *   length   = Desired derived-key length in bytes.
 *
 * Returns: Derived key of length `length`.
 */
@trusted public ubyte[] scrypt_ex(string password, const ubyte[] salt, size_t length) {
    return scrypt_ex(cast(ubyte[])password, salt, defaultKdfIterations, defaultSCryptR, defaultSCryptP, maxSCryptMemory, length);
}

/**
 * scrypt with full parameter control (string password).
 *
 * Params:
 *   password  = Password string (converted via $(D representation)).
 *   salt      = Salt bytes.
 *   n         = CPU/memory cost (must be a power of two).
 *   r         = Block size parameter.
 *   p         = Parallelization parameter.
 *   maxMemory = Soft memory cap passed to the provider.
 *   length    = Desired derived-key length in bytes.
 *
 * Returns: Derived key of length `length`.
 */
@trusted public ubyte[] scrypt_ex(string password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, size_t length) {
    import std.string;
    return scrypt_ex(cast(ubyte[])password.representation, salt, n, r, p, maxMemory, length);
}

/**
 * scrypt with full parameter control (raw password bytes).
 *
 * Params:
 *   password  = Password bytes.
 *   salt      = Salt bytes.
 *   n         = CPU/memory cost (must be a power of two).
 *   r         = Block size parameter.
 *   p         = Parallelization parameter.
 *   maxMemory = Soft memory cap passed to the provider.
 *   length    = Desired derived-key length in bytes.
 *
 * Returns: Derived key of length `length`.
 *
 * Throws: $(D AlgorithmNotSupportedException) if scrypt is unavailable.
 */
@trusted public ubyte[] scrypt_ex(const ubyte[] password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, size_t length) {
    static if (usesOpenSSL) {
        return scrypt_impl_openssl(password, salt, n, r, p, maxMemory, length);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedKdfMessage("SCrypt"));
    }
}

unittest
{
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    writeln("Testing SCrypt Extended with Defaults:");

    ubyte[48] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec2 = scrypt_ex("abc", salt, 1_048_576, 8, 1, 1_074_790_400, 64);
    ubyte[] vec3 = scrypt_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, 1_048_576, 8, 1, 1_074_790_400, 64);

    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec2) == "134fca5087e04c2a79e0ea2c793660f19d466db74a069e1f2e4da2b177d51402501bd39ffc592b9419ec0280cc17dca7af8df54f836179d69a4b9e9f6b9467fd");
    assert(toHexString!(LetterCase.lower)(vec3) == "45397ec370eb31f3155ad162d83ec165ff8e363bc4e03c1c61c5a31ad17d0dac51d9e8911f32e9b588adf284a9de24561483dbaf0ea519b6a29ecae77eab5b90");
    });
}
