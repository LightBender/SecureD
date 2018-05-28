module secured.kdf;

import std.typecons;
import std.format;

version(OpenSSL)
{
import deimos.openssl.evp;
import secured.openssl;
}

version(Botan)
{
import botan.hash.sha2_32;
import botan.hash.sha2_64;
import botan.mac.hmac;
import botan.pbkdf.pbkdf2;
import core.time;
}

import secured.hash;
import secured.random;
import secured.util;

public struct KdfResult {
    public ubyte[] salt;
    public ubyte[] key;
}

@safe public KdfResult pbkdf2(string password) {
    KdfResult result;
    result.salt = random(getHashLength(HashFunction.SHA2_384));
    result.key = pbkdf2_ex(password, result.salt, HashFunction.SHA2_384, getHashLength(HashFunction.SHA2_384), 250_000);
    return result;
}

@safe public bool pbkdf2_verify(KdfResult test, string password) {
    ubyte[] key = pbkdf2_ex(password, test.salt, HashFunction.SHA2_384, getHashLength(HashFunction.SHA2_384), 250_000);
    return constantTimeEquality(test.key, key);
}

@trusted public ubyte[] pbkdf2_ex(string password, ubyte[] salt, HashFunction func, uint outputLen, uint iterations)
{
    if (salt.length != getHashLength(func)) {
        throw new CryptographicException(format("The PBKDF2 salt must be %s bytes in length.", getHashLength(func)));
    }
    if (outputLen > getHashLength(func)) {
        throw new CryptographicException(format("The PBKDF2 output length must be less than or equal to %s bytes in length.", getHashLength(func)));
    }

    version(OpenSSL)
    {
        ubyte[] output = new ubyte[outputLen];
        if(PKCS5_PBKDF2_HMAC(password.ptr, cast(int)password.length, salt.ptr, cast(int)salt.length, iterations, getOpenSSLHashFunction(func), outputLen, output.ptr) == 0) {
            throw new CryptographicException("Unable to execute PBKDF2 hash function.");
        }
        return output;
    }

    version(Botan)
    {
        auto kdf = new PKCS5_PBKDF2(new HMAC(getBotanHashFunction(func)));
        auto result = kdf.keyDerivation(cast(ulong)outputLen, cast(const(string))password, salt.ptr, salt.length, cast(ulong)iterations, Duration.zero);
        auto octet = result.second();

        ubyte[] output = new ubyte[octet.length()];
        ubyte* octetptr = octet.ptr();
        for(int i = 0; i < octet.length(); i++) {
            output[i] = octetptr[i];
        }
        return output;
    }
}

@safe public bool pbkdf2_verify_ex(ubyte[] test, string password, ubyte[] salt, HashFunction func, uint outputLen, uint iterations) {
    ubyte[] key = pbkdf2_ex(password, salt, func, outputLen, iterations);
    return constantTimeEquality(test, key);
}

unittest
{
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Verify Methods:");

    //Test basic methods
    auto result = pbkdf2("password");
    assert(result.key.length == 48);
    assert(pbkdf2_verify(result, "password"));
    writeln(toHexString!(LetterCase.lower)(result.key));

    //Test extended methods
    ubyte[64] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] key = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, HashFunction.SHA2_512, 64, 100000);
    assert(pbkdf2_verify_ex(key, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, HashFunction.SHA2_512, 64, 100000));
    writeln(toHexString!(LetterCase.lower)(key));
}

unittest
{
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Extended with Defaults:");

    ubyte[48] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec1 = pbkdf2_ex("", key, HashFunction.SHA2_384, 48, 25000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashFunction.SHA2_384, 48, 25000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashFunction.SHA2_384, 48, 25000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bde9db7c8ccf14df26f8305fc8634572f9");
    assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff45417d47d84db06a12b8ea49377a7c7cb");
    assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520b2834d7bf22b83bb5c21c4bccb423be2");
}

unittest
{
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Extended with Custom Iterations:");

    ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                     0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                     0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec1 = pbkdf2_ex("", key, HashFunction.SHA2_384, 48, 150000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashFunction.SHA2_384, 48, 150000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashFunction.SHA2_384, 48, 150000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "babdcbbf4ff89367ed223d2edd06ef5473ac9cdc827783ed0b4b5eafd9e4097beb2ef66d6fc92d24dbf4b86aa51b4a0f");
    assert(toHexString!(LetterCase.lower)(vec2) == "8894348ccea06d79f80382ae7d4434c0f2ef41f871d936604f426518ab23bde4410fddce6dad943c95de75dbece9b54a");
    assert(toHexString!(LetterCase.lower)(vec3) == "fba55e91818c35b1e4cc753fbd01a6cd138c49da472b58b2d7c4860ba39a3dd9032f8f641aadcd74a819361ed27c9a0f");
}

unittest
{
    import std.digest;
    import std.stdio;

    writeln("Testing PBKDF2 Extended with Custom Output Length:");

    ubyte[48] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec1 = pbkdf2_ex("", key, HashFunction.SHA2_384, 32, 25000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashFunction.SHA2_384, 32, 25000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashFunction.SHA2_384, 32, 25000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bd");
    assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff4");
    assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520");
}

@safe public KdfResult hkdf(ubyte[] key, ulong outputLen) {
    KdfResult result;
    result.salt = random(getHashLength(HashFunction.SHA2_384));
    result.key = hkdf_ex(key, result.salt, outputLen, HashFunction.SHA2_384);
    return result;
}

@trusted public ubyte[] hkdf_ex(ubyte[] key, ubyte[] salt, ulong outputLen, HashFunction func) {
    if (key.length == 0) {
        throw new CryptographicException("HKDF key cannot be an empty array.");
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);
    scope(exit) {
        if(pctx !is null) {
            EVP_PKEY_CTX_free(pctx);
        }
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        throw new CryptographicException("Unable to create HKDF function.");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, getOpenSSLHashFunction(func)) <= 0) {
        throw new CryptographicException("Unable to create HKDF hash function.");
    }

    if (salt.length != 0 && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt) <= 0) {
        throw new CryptographicException("Unable to set HKDF salt.");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key) <= 0) {
        throw new CryptographicException("Unable to set HKDF key.");
    }

    ubyte[] keyMaterial = new ubyte[outputLen];
    if (EVP_PKEY_derive(pctx, keyMaterial.ptr, &outputLen) <= 0) {
        throw new CryptographicException("Unable to generate the requested key material.");
    }

    return keyMaterial;
}

unittest
{
    import std.digest;
    import std.stdio;

    writeln("Testing HKDF Extended with Defaults:");

    ubyte[48] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] vec2 = hkdf_ex(cast(ubyte[])"abc", salt, 64, HashFunction.SHA2_224);
    ubyte[] vec3 = hkdf_ex(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, 64, HashFunction.SHA2_224);

    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec2) == "0fcc4d227bb180f4a2631da9bf158203ced36a73752d1f6fb05be764cbd13460556e6ddd69b0d3b2cdf08457a18253811e38d8059177e5dc22b5b52a6b1cb30a");
    assert(toHexString!(LetterCase.lower)(vec3) == "c2bf93ca7706228a03f8362d2b6f726030db408319172dfab0da4ea496d9bb5d380d6ff0bddafec45ef2307a9a5980b9fb7c7c405993e4145534c5ae1521e996");
}
