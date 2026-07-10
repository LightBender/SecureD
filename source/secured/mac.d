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

@safe public ubyte[] hmac(const ubyte[] key, const ubyte[] data) {
    return hmac_ex(key, data, HashAlgorithm.Default);
}

@safe public bool hmac_verify(const ubyte[] test, const ubyte[] key, const ubyte[] data) {
    ubyte[] hash = hmac_ex(key, data, HashAlgorithm.Default);
    return constantTimeEquality(test, hash);
}

@trusted public ubyte[] hmac_ex(const ubyte[] key, const ubyte[] data, HashAlgorithm func)
{
    if (key.length > getHashLength(func)) {
        throw new CryptographicException(format("HMAC key must be less than or equal to %s bytes in length.", getHashLength(func)));
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
