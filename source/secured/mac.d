module secured.mac;

import std.stdio;
import std.format;

import secured.openssl;
import deimos.openssl.evp;
import secured.hash;
import secured.util;


@safe public ubyte[] hmac(ubyte[] key, ubyte[] data) {
    return hmac_ex(key, data, HashAlgorithm.SHA2_384);
}

@safe public bool hmac_verify(ubyte[] test, ubyte[] key, ubyte[] data) {
    ubyte[] hash = hmac_ex(key, data, HashAlgorithm.SHA2_384);
    return constantTimeEquality(test, hash);
}

@trusted public ubyte[] hmac_ex(ubyte[] key, ubyte[] data, HashAlgorithm func)
{
    if (key.length > getHashLength(func)) {
        throw new CryptographicException(format("HMAC key must be less than or equal to %s bytes in length.", getHashLength(func)));
    }

    //Create the OpenSSL context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == null) {
        throw new CryptographicException("Unable to create OpenSSL context.");
    }
    scope(exit) {
        if(mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    //Initialize the hash algorithm
    auto md = getOpenSSLHashAlgorithm(func);
    if (EVP_DigestInit_ex(mdctx, md, null) != 1) {
        throw new CryptographicException("Unable to create hash context.");
    }

    //Create the HMAC key context
    auto pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, null, key.ptr, cast(int)key.length);
    scope(exit) {
        if(pkey !is null) {
            EVP_PKEY_free(pkey);
        }
    }
    if (EVP_DigestSignInit(mdctx, null, md, null, pkey) != 1) {
        throw new CryptographicException("Unable to create HMAC key context.");
    }

    //Run the provided data through the digest algorithm
    if (EVP_DigestSignUpdate(mdctx, data.ptr, data.length) != 1) {
        throw new CryptographicException("Error while updating digest.");
    }

    //Copy the OpenSSL digest to our D buffer.
    size_t digestlen;
    ubyte[] digest = new ubyte[getHashLength(func)];
    if (EVP_DigestSignFinal(mdctx, digest.ptr, &digestlen) < 0) {
        throw new CryptographicException("Error while retrieving the digest.");
    }

    return digest;
}

@safe public bool hmac_verify_ex(ubyte[] test, ubyte[] key, ubyte[] data, HashAlgorithm func){
    ubyte[] hash = hmac_ex(key, data, func);
    return constantTimeEquality(test, hash);
}

unittest {
    import std.digest;

    ubyte[48] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    writeln("Testing HMAC Basic:");

    ubyte[] verify_basic_hash = hmac(key, cast(ubyte[])"");
    assert(hmac_verify(verify_basic_hash, key, cast(ubyte[])""));

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
}
