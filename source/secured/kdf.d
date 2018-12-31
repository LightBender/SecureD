module secured.kdf;

import std.typecons;
import std.format;

import deimos.openssl.evp;
import secured.openssl;

import secured.hash;
import secured.random;
import secured.util;

public struct KdfResult {
    public ubyte[] salt;
    public ubyte[] key;
}

@safe public KdfResult pbkdf2(string password, uint iterations = 1_000_000) {
    KdfResult result;
    result.salt = random(getHashLength(HashAlgorithm.SHA2_384));
    result.key = pbkdf2_ex(password, result.salt, HashAlgorithm.SHA2_384, getHashLength(HashAlgorithm.SHA2_384), iterations);
    return result;
}

@safe public bool pbkdf2_verify(KdfResult test, string password, uint iterations = 1_000_000) {
    ubyte[] key = pbkdf2_ex(password, test.salt, HashAlgorithm.SHA2_384, getHashLength(HashAlgorithm.SHA2_384), iterations);
    return constantTimeEquality(test.key, key);
}

@trusted public ubyte[] pbkdf2_ex(string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations)
{
    if (salt.length != getHashLength(func)) {
        throw new CryptographicException(format("The PBKDF2 salt must be %s bytes in length.", getHashLength(func)));
    }
    if (outputLen > getHashLength(func)) {
        throw new CryptographicException(format("The PBKDF2 output length must be less than or equal to %s bytes in length.", getHashLength(func)));
    }

    ubyte[] output = new ubyte[outputLen];
    if(PKCS5_PBKDF2_HMAC(password.ptr, cast(int)password.length, salt.ptr, cast(int)salt.length, iterations, getOpenSSLHashAlgorithm(func), outputLen, output.ptr) == 0) {
        throw new CryptographicException("Unable to execute PBKDF2 hash function.");
    }
    return output;
}

@safe public bool pbkdf2_verify_ex(const ubyte[] test, string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
    ubyte[] key = pbkdf2_ex(password, salt, func, outputLen, iterations);
    return constantTimeEquality(test, key);
}

unittest
{
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
    assert(pbkdf2_verify(result, "password"));
    writeln(toHexString!(LetterCase.lower)(result.key));

    //Test extended methods
    ubyte[64] salt = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] key = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, HashAlgorithm.SHA2_512, 64, 100000);
    assert(pbkdf2_verify_ex(key, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, HashAlgorithm.SHA2_512, 64, 100000));
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

    ubyte[] vec1 = pbkdf2_ex("", key, HashAlgorithm.SHA2_384, 48, 25000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashAlgorithm.SHA2_384, 48, 25000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashAlgorithm.SHA2_384, 48, 25000);

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

    ubyte[] vec1 = pbkdf2_ex("", key, HashAlgorithm.SHA2_384, 48, 150000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashAlgorithm.SHA2_384, 48, 150000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashAlgorithm.SHA2_384, 48, 150000);

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

    ubyte[] vec1 = pbkdf2_ex("", key, HashAlgorithm.SHA2_384, 32, 25000);
    ubyte[] vec2 = pbkdf2_ex("abc", key, HashAlgorithm.SHA2_384, 32, 25000);
    ubyte[] vec3 = pbkdf2_ex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", key, HashAlgorithm.SHA2_384, 32, 25000);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bd");
    assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff4");
    assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520");
}

@safe public KdfResult hkdf(const ubyte[] key, ulong outputLen) {
    KdfResult result;
    result.salt = random(getHashLength(HashAlgorithm.SHA2_384));
    result.key = hkdf_ex(key, result.salt, string.init, outputLen, HashAlgorithm.SHA2_384);
    return result;
}

@trusted public ubyte[] hkdf_ex(const ubyte[] key, const ubyte[] salt, string info, ulong outputLen, HashAlgorithm func) {
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
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, getOpenSSLHashAlgorithm(func)) <= 0) {
        throw new CryptographicException("Unable to create HKDF hash function.");
    }

    if (salt.length != 0 && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt) <= 0) {
        throw new CryptographicException("Unable to set HKDF salt.");
    }

    if (info.length != 0 && EVP_PKEY_CTX_add1_hkdf_info(pctx, info) <= 0) {
        throw new CryptographicException("Unable to set HKDF info.");
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

    ubyte[] vec2 = hkdf_ex(cast(ubyte[])"abc", salt, "", 64, HashAlgorithm.SHA2_224);
    ubyte[] vec3 = hkdf_ex(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", salt, "test", 64, HashAlgorithm.SHA2_224);

    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));

    assert(toHexString!(LetterCase.lower)(vec2) == "0fcc4d227bb180f4a2631da9bf158203ced36a73752d1f6fb05be764cbd13460556e6ddd69b0d3b2cdf08457a18253811e38d8059177e5dc22b5b52a6b1cb30a");
    assert(toHexString!(LetterCase.lower)(vec3) == "d05e4ba15e07095b8b6dc3abbdde3f790fb4c1d6146e93e12312fbf54b5a1aff4c9c9108046fc390f2bef5fbcbf44d57ac05732525ccbf0a856821fe178f47c2");
}

@safe public KdfResult scrypt(string password) {
    KdfResult result;
    result.salt = random(32);
    result.key = scrypt_ex(password, result.salt, 1_048_576, 8, 1, 1_074_790_400, 64);
    return result;
}

@safe public KdfResult scrypt(const ubyte[] password) {
    KdfResult result;
    result.salt = random(32);
    result.key = scrypt_ex(password, result.salt, 1_048_576, 8, 1, 1_074_790_400, 64);
    return result;
}

@trusted public ubyte[] scrypt_ex(string password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, ulong length) {
    import std.string;
    return scrypt_ex(cast(ubyte[])password.representation, salt, n, r, p, maxMemory, length);
}

@trusted public ubyte[] scrypt_ex(const ubyte[] password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, ulong length) {
    ubyte[] hash = new ubyte[length];

    if (EVP_PBE_scrypt((cast(char[])password).ptr, password.length, salt.ptr, salt.length, n, r, p, maxMemory, hash.ptr, length) <= 0) {
        throw new CryptographicException("Unable to calculate SCrypt hash.");
    }

    return hash;
}

unittest
{
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
}
