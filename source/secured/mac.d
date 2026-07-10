module secured.mac;

import std.stdio;
import std.format;

import secured.hash;
import secured.provider;
import secured.util;

static if (usesOpenSSL) {
    import secured.system.openssl : hmac_impl_openssl;
}
static if (activeProvider == Provider.CNG) {
    import secured.system.windows : hmac_impl_cng, cngSupportsHash;
}
static if (activeProvider == Provider.CommonCrypto) {
    import secured.system.macos : hmac_impl_commoncrypto, commonCryptoSupportsHash;
}

/**
 * Computes an HMAC over `data` using the library default hash
 * ($(D HashAlgorithm.Default), SHA2-384).
 *
 * SHA2-384 is the default because it is available on every supported OS
 * provider and, as a truncated SHA-512 construction, is not vulnerable to the
 * classic length-extension attacks that affect unkeyed SHA-256 digests.
 *
 * Params:
 *   key  = Secret HMAC key. Must be non-empty; any length is accepted (keys
 *          longer than the hash block size are reduced per RFC 2104).
 *   data = Message bytes to authenticate. May be empty.
 *
 * Returns: HMAC tag (48 bytes for the default SHA2-384).
 *
 * Throws: $(D CryptographicException) if `key` is empty, or
 *         $(D AlgorithmNotSupportedException) if the hash is unavailable.
 */
@safe public ubyte[] hmac(const ubyte[] key, const ubyte[] data) {
    return hmac_ex(key, data, HashAlgorithm.Default);
}

/**
 * Verifies an HMAC tag against `data` using the library default hash and a
 * constant-time comparison.
 *
 * Params:
 *   test = Expected HMAC tag.
 *   key  = Secret HMAC key (must be non-empty).
 *   data = Message bytes that were authenticated.
 *
 * Returns: `true` if the tag is valid; `false` otherwise.
 */
@safe public bool hmac_verify(const ubyte[] test, const ubyte[] key, const ubyte[] data) {
    ubyte[] hash = hmac_ex(key, data, HashAlgorithm.Default);
    return constantTimeEquality(test, hash);
}

/**
 * Computes an HMAC over `data` with an explicit underlying hash algorithm.
 *
 * Params:
 *   key  = Secret HMAC key. Must be non-empty; any length is accepted.
 *   data = Message bytes to authenticate. May be empty.
 *   func = Hash algorithm used inside HMAC (e.g. SHA2-256, SHA2-384, SHA3-256).
 *
 * Returns: HMAC tag whose length matches the digest size of `func`.
 *
 * Throws:
 *   $(D CryptographicException) if `key` is empty.
 *   $(D AlgorithmNotSupportedException) if `func` is unavailable on the active
 *   provider and polyfill is disabled.
 */
@trusted public ubyte[] hmac_ex(const ubyte[] key, const ubyte[] data, HashAlgorithm func)
{
    // HMAC keys may be any length. Keys longer than the hash block size are
    // reduced by the underlying provider (HMAC-Hash(K) as the effective key).
    // Rejecting long keys was incorrect and broke legitimate uses such as
    // encrypt-then-MAC over concatenated digests.
    if (key.length == 0) {
        throw new CryptographicException("HMAC key must not be empty.");
    }

    static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
        return hmac_impl_openssl(key, data, func);
    } else static if (activeProvider == Provider.CNG) {
        if (cngSupportsHash(func)) {
            return hmac_impl_cng(key, data, func);
        } else static if (polyfillEnabled) {
            return hmac_impl_openssl(key, data, func);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedHmacMessage(func));
        }
    } else static if (activeProvider == Provider.CommonCrypto) {
        if (commonCryptoSupportsHash(func)) {
            return hmac_impl_commoncrypto(key, data, func);
        } else static if (polyfillEnabled) {
            return hmac_impl_openssl(key, data, func);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedHmacMessage(func));
        }
    } else static if (polyfillEnabled) {
        return hmac_impl_openssl(key, data, func);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedHmacMessage(func));
    }
}

package(secured) string unsupportedHmacMessage(HashAlgorithm func) {
    import std.conv : to;
    return "HMAC algorithm '" ~ to!string(func) ~ "' is not supported by the active cryptographic provider. Enable the 'polyfill' configuration to use OpenSSL as a fallback.";
}

/**
 * Verifies an HMAC tag against `data` under an explicit hash algorithm, using a
 * constant-time comparison.
 *
 * Params:
 *   test = Expected HMAC tag.
 *   key  = Secret HMAC key (must be non-empty).
 *   data = Message bytes that were authenticated.
 *   func = Hash algorithm used inside HMAC (must match the tag producer).
 *
 * Returns: `true` if the tag is valid; `false` otherwise.
 */
@safe public bool hmac_verify_ex(const ubyte[] test, const ubyte[] key, const ubyte[] data, HashAlgorithm func){
    ubyte[] hash = hmac_ex(key, data, func);
    return constantTimeEquality(test, hash);
}

unittest {
    skipIfUnsupported({
    import std.digest;

    ubyte[48] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    writeln("Testing HMAC Basic:");

    ubyte[] verify_basic_hash = hmac(key, cast(ubyte[])"");
    assert(hmac_verify(verify_basic_hash, key, cast(ubyte[])""));

    writeln(toHexString!(LetterCase.lower)(verify_basic_hash));

    writeln("Testing HMAC Extended:");

    ubyte[] vec1 = hmac_ex(key, cast(ubyte[])"", HashAlgorithm.SHA2_384);
    ubyte[] vec2 = hmac_ex(key, cast(ubyte[])"abc", HashAlgorithm.SHA2_384);
    ubyte[] vec3 = hmac_ex(key, cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", HashAlgorithm.SHA2_384);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "440b0d5f59c32cbee090c3d9f524b81a9b9708e9b65a46bbc189842b0ab0759d3bf118acca58eda0813fd346e8ccfde4");
    assert(toHexString!(LetterCase.lower)(vec2) == "cb5da1048feb76fd75752dc1b699caba124090feac21adb5b4c0f6600e7b626e08d7415660aa0ee79ca5b83e56669a60");
    assert(toHexString!(LetterCase.lower)(vec3) == "460b59c0bd8ae48133431185a4583376738be3116cafce47aff7696bd19501b0cf1f1850c3e5fa2992882997493d1c99");

    ubyte[32] keyshort = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] verify_hash = hmac_ex(keyshort, cast(ubyte[])"", HashAlgorithm.SHA2_256);
    assert(hmac_verify_ex(verify_hash, keyshort, cast(ubyte[])"", HashAlgorithm.SHA2_256));

    writeln(toHexString!(LetterCase.lower)(verify_hash));
    });
}
