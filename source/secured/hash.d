module secured.hash;

import std.stdio;

import secured.provider;
import secured.util;

static if (usesOpenSSL) {
    import secured.system.openssl : hash_impl_openssl;
}
static if (activeProvider == Provider.CNG) {
    import secured.system.windows : hash_impl_cng, cngSupportsHash;
}
static if (activeProvider == Provider.CommonCrypto) {
    import secured.system.macos : hash_impl_commoncrypto, commonCryptoSupportsHash;
}

/**
 * Cryptographic hash algorithms supported by SecureD.
 *
 * Defaults to $(D SHA2_384): a 384-bit SHA-2 digest that is widely available on
 * every supported OS provider, resists length-extension attacks better than
 * SHA-256 in truncated-MAC constructions, and provides a comfortable security
 * margin for long-lived data without the larger cost of SHA-512.
 *
 * SHA-3 variants require provider support (OpenSSL always; CNG only on recent
 * Windows; CommonCrypto requires the polyfill configuration).
 */
public enum HashAlgorithm : ubyte {
    /// Sentinel / unused.
    None,
    /// SHA-2 with 256-bit output.
    SHA2_256,
    /// SHA-2 with 384-bit output (library default).
    SHA2_384,
    /// SHA-2 with 512-bit output.
    SHA2_512,
    /// SHA-512 truncated to 224 bits.
    SHA2_512_224,
    /// SHA-512 truncated to 256 bits.
    SHA2_512_256,
    /// SHA-3 with 224-bit output.
    SHA3_224,
    /// SHA-3 with 256-bit output.
    SHA3_256,
    /// SHA-3 with 384-bit output.
    SHA3_384,
    /// SHA-3 with 512-bit output.
    SHA3_512,
    /// Default hash: SHA2-384 (length-extension resilience + broad OS support).
	Default = SHA2_384,
}

package(secured) string unsupportedHashMessage(HashAlgorithm func) {
    import std.conv : to;
    return "Hash algorithm '" ~ to!string(func) ~ "' is not supported by the active cryptographic provider. Enable the 'polyfill' configuration to use OpenSSL as a fallback.";
}

/**
 * Hashes `data` with the library default algorithm ($(D HashAlgorithm.Default),
 * SHA2-384).
 *
 * Params:
 *   data = Input bytes to hash. May be empty.
 *
 * Returns: Digest bytes (48 bytes for the default SHA2-384).
 *
 * Throws: $(D AlgorithmNotSupportedException) if the active provider cannot
 *         perform the default hash and polyfill is disabled.
 */
@safe public ubyte[] hash(const ubyte[] data) {
    return hash_ex(data, HashAlgorithm.Default);
}

/**
 * Verifies that `test` equals the default hash of `data` using a constant-time
 * comparison.
 *
 * Params:
 *   test = Expected digest to compare against.
 *   data = Input bytes that will be hashed with $(D HashAlgorithm.Default).
 *
 * Returns: `true` if digests match; `false` otherwise.
 */
@safe public bool hash_verify(ubyte[] test, ubyte[] data) {
    ubyte[] hash = hash_ex(data, HashAlgorithm.Default);
    return constantTimeEquality(hash, test);
}

/**
 * Hashes `data` with an explicit hash algorithm.
 *
 * Params:
 *   data = Input bytes to hash. May be empty.
 *   func = Hash algorithm to use. Defaults are not applied here; callers must
 *          pass a concrete algorithm (use $(D hash) for the library default).
 *
 * Returns: Digest bytes whose length is $(D getHashLength(func)).
 *
 * Throws:
 *   $(D AlgorithmNotSupportedException) if `func` is unavailable on the active
 *   provider and polyfill is disabled.
 *   $(D CryptographicException) for provider-level failures.
 */
@trusted public ubyte[] hash_ex(const ubyte[] data, HashAlgorithm func)
{
    static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
        return hash_impl_openssl(data, func);
    } else static if (activeProvider == Provider.CNG) {
        if (cngSupportsHash(func)) {
            return hash_impl_cng(data, func);
        } else static if (polyfillEnabled) {
            return hash_impl_openssl(data, func);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
        }
    } else static if (activeProvider == Provider.CommonCrypto) {
        if (commonCryptoSupportsHash(func)) {
            return hash_impl_commoncrypto(data, func);
        } else static if (polyfillEnabled) {
            return hash_impl_openssl(data, func);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
        }
    } else static if (polyfillEnabled) {
        return hash_impl_openssl(data, func);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
    }
}

/**
 * Verifies that `test` equals the hash of `data` under `func`, using a
 * constant-time comparison.
 *
 * Params:
 *   test = Expected digest to compare against.
 *   data = Input bytes that will be hashed.
 *   func = Hash algorithm used to produce the digest.
 *
 * Returns: `true` if digests match; `false` otherwise.
 */
@safe public bool hash_verify_ex(const ubyte[] test, const ubyte[] data, HashAlgorithm func) {
    ubyte[] hash = hash_ex(data, func);
    return constantTimeEquality(hash, test);
}

unittest {
    skipIfUnsupported({
    import std.digest;

    writeln("Testing SHA2 Byte Array Hash:");

    ubyte[] vec1 = hash_ex(cast(ubyte[])"", HashAlgorithm.SHA2_384);
    ubyte[] vec2 = hash_ex(cast(ubyte[])"abc", HashAlgorithm.SHA2_384);
    ubyte[] vec3 = hash_ex(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", HashAlgorithm.SHA2_384);
    ubyte[] vec4 = hash_ex(cast(ubyte[])"The quick brown fox jumps over the lazy dog.", HashAlgorithm.SHA2_384);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));
    writeln(toHexString!(LetterCase.lower)(vec4));

    assert(toHexString!(LetterCase.lower)(vec1) == "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    assert(toHexString!(LetterCase.lower)(vec2) == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    assert(toHexString!(LetterCase.lower)(vec3) == "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
    assert(toHexString!(LetterCase.lower)(vec4) == "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7");
    });
}

unittest {
    skipIfUnsupported({
    import std.digest;

    writeln("Testing SHA3 Byte Array Hash:");

    ubyte[] vec1 = hash_ex(cast(ubyte[])"", HashAlgorithm.SHA3_384);
    ubyte[] vec2 = hash_ex(cast(ubyte[])"abc", HashAlgorithm.SHA3_384);
    ubyte[] vec3 = hash_ex(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", HashAlgorithm.SHA3_384);
    ubyte[] vec4 = hash_ex(cast(ubyte[])"The quick brown fox jumps over the lazy dog.", HashAlgorithm.SHA3_384);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));
    writeln(toHexString!(LetterCase.lower)(vec4));

    assert(toHexString!(LetterCase.lower)(vec1) == "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    assert(toHexString!(LetterCase.lower)(vec2) == "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    assert(toHexString!(LetterCase.lower)(vec3) == "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22");
    assert(toHexString!(LetterCase.lower)(vec4) == "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9");
    });
}

/**
 * Hashes the contents of the file at `path` with the library default algorithm
 * ($(D HashAlgorithm.Default), SHA2-384).
 *
 * Params:
 *   path = Filesystem path of the file to hash.
 *
 * Returns: Digest bytes (48 bytes for the default SHA2-384).
 *
 * Throws: $(D CryptographicException) if the file cannot be read, or
 *         $(D AlgorithmNotSupportedException) if the hash is unavailable.
 */
@safe public ubyte[] hash(string path) {
    return hash_ex(path, HashAlgorithm.Default);
}

/**
 * Verifies that `test` equals the default hash of the file at `path`.
 *
 * Params:
 *   path = Filesystem path of the file to hash.
 *   test = Expected digest to compare against.
 *
 * Returns: `true` if digests match; `false` otherwise.
 */
@safe public bool hash_verify(string path, ubyte[] test) {
    ubyte[] hash = hash_ex(path, HashAlgorithm.Default);
    return constantTimeEquality(hash, test);
}

/**
 * Hashes the contents of the file at `path` with an explicit hash algorithm.
 *
 * Params:
 *   path = Filesystem path of the file to hash.
 *   func = Hash algorithm to use.
 *
 * Returns: Digest bytes whose length is $(D getHashLength(func)).
 *
 * Throws:
 *   $(D AlgorithmNotSupportedException) if `func` is unavailable.
 *   $(D CryptographicException) if the file cannot be read or hashing fails.
 */
@trusted public ubyte[] hash_ex(string path, HashAlgorithm func)
{
    static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
        return hash_impl_openssl(path, func);
    } else static if (activeProvider == Provider.CNG) {
        if (cngSupportsHash(func)) {
            return hash_impl_cng(path, func);
        } else static if (polyfillEnabled) {
            return hash_impl_openssl(path, func);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
        }
    } else static if (activeProvider == Provider.CommonCrypto) {
        if (commonCryptoSupportsHash(func)) {
            return hash_impl_commoncrypto(path, func);
        } else static if (polyfillEnabled) {
            return hash_impl_openssl(path, func);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
        }
    } else static if (polyfillEnabled) {
        return hash_impl_openssl(path, func);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
    }
}

/**
 * Verifies that `test` equals the hash of the file at `path` under `func`.
 *
 * Params:
 *   path = Filesystem path of the file to hash.
 *   func = Hash algorithm used to produce the digest.
 *   test = Expected digest to compare against.
 *
 * Returns: `true` if digests match; `false` otherwise.
 */
@safe public bool hash_verify_ex(string path, HashAlgorithm func, ubyte[] test) {
    ubyte[] hash = hash_ex(path, func);
    return constantTimeEquality(hash, test);
}

unittest {
    skipIfUnsupported({
    import std.digest;

    writeln("Testing File Hash:");

    auto f = File("hashtest.txt", "wb");
    f.rawWrite("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    f.close();

    ubyte[] vec = hash_ex("hashtest.txt", HashAlgorithm.SHA2_384);
    writeln(toHexString!(LetterCase.lower)(vec));
    assert(toHexString!(LetterCase.lower)(vec) == "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");

    remove("hashtest.txt");
    });
}

@safe package(secured) uint getHashLength(HashAlgorithm func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashAlgorithm.None: return 0;
        case HashAlgorithm.SHA2_256: return 32;
        case HashAlgorithm.SHA2_384: return 48;
        case HashAlgorithm.SHA2_512: return 64;
        case HashAlgorithm.SHA2_512_224: return 24;
        case HashAlgorithm.SHA2_512_256: return 32;
        case HashAlgorithm.SHA3_224: return 24;
        case HashAlgorithm.SHA3_256: return 32;
        case HashAlgorithm.SHA3_384: return 48;
        case HashAlgorithm.SHA3_512: return 64;
        default:
            throw new CryptographicException(format("Hash Function '%s' is not supported.", to!string(func)));
    }
}
