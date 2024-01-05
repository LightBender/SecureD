module secured.kdf;

import std.conv;
import std.typecons;
import std.format;
import std.string;

import deimos.openssl.evp;
import deimos.openssl.kdf;
import secured.openssl;

import secured.hash;
import secured.random;
import secured.symmetric;
import secured.util;

public enum uint defaultKdfIterations = 1_048_576;
public enum ushort defaultSCryptR = 8;
public enum ushort defaultSCryptP = 1;
public enum ulong maxSCryptMemory = 1_074_790_400;

public enum KdfAlgorithm : ubyte {
    None,
    PBKDF2,
    HKDF,
    SCrypt,
    Default = SCrypt,
}

public struct KdfResult {
    public ubyte[] salt;
    public ubyte[] key;
}

@trusted public KdfResult deriveKey(const ubyte[] key, uint bytes, const ubyte[] salt = null, KdfAlgorithm kdf = KdfAlgorithm.Default, uint n = defaultKdfIterations, ushort r = defaultSCryptR, ushort p = defaultSCryptP, HashAlgorithm hash = HashAlgorithm.Default) {
    ubyte[] derivedKey;
    ubyte[] _salt = salt is null ? random(getHashLength(hash)) : cast(ubyte[])salt;

    if (kdf == KdfAlgorithm.PBKDF2) {
        //derivedKey = pbkdf2_ex(to!string(key), _salt, hash, bytes, n);
		import secured.windows.windows;
        derivedKey = pbkdf2_winapi(to!string(key), _salt, hash, bytes, n);
    }
    if (kdf == KdfAlgorithm.HKDF) {
        derivedKey = hkdf_ex(key, _salt, string.init, bytes, hash);
    }
    if (kdf == KdfAlgorithm.SCrypt) {
        derivedKey = scrypt_ex(key, _salt, n, r, p, maxSCryptMemory,bytes);
    }
    return KdfResult(_salt, derivedKey);
}

@safe public KdfResult pbkdf2(string password, uint iterations = 1_000_000) {
    KdfResult result;
    result.salt = random(getHashLength(HashAlgorithm.Default));
    result.key = pbkdf2_ex(password, result.salt, HashAlgorithm.Default, getHashLength(HashAlgorithm.Default), iterations);
    return result;
}

@safe public bool pbkdf2_verify(const ubyte[] key, const ubyte[] salt, string password, uint iterations = 1_000_000) {
    ubyte[] test = pbkdf2_ex(password, salt, HashAlgorithm.Default, getHashLength(HashAlgorithm.Default), iterations);
    return constantTimeEquality(key, test);
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
    assert(pbkdf2_verify(result.key, result.salt, "password"));
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

@safe public KdfResult hkdf(const SymmetricKey key) {
    return hkdf(key, getCipherKeyLength(key.algorithm));
}

@safe public KdfResult hkdf(const SymmetricKey key, size_t outputLen) {
    KdfResult result;
    result.salt = random(getHashLength(HashAlgorithm.Default));
    result.key = hkdf_ex(key.value, result.salt, string.init, outputLen, HashAlgorithm.Default);
    return result;
}

@trusted public ubyte[] hkdf_ex(const ubyte[] key, const ubyte[] salt, string info, size_t outputLen, HashAlgorithm func) {
    if (key.length == 0) {
        throw new CryptographicException("HKDF key cannot be an empty array.");
    }

	import secured.windows.windows;
	return hkdf_winapi(key, salt, info, outputLen, func);
/*
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = null;
    ubyte[] derived = new ubyte[outputLen];
    ossl_param_st[5] params;

    // Find and allocate a context for the HKDF algorithm
    if ((kdf = EVP_KDF_fetch(null, "hkdf", null)) == null) {
        throw new CryptographicException("Unable to create HKDF function.");
    }
    kctx = EVP_KDF_CTX_new(kdf);
    scope(exit) {
        if (kctx !is null) {
            EVP_KDF_CTX_free(kctx);
        }
    }

    // Build up the parameters for the derivation
    string hashName = getOpenSSLHashAlgorithmString(func);
    params[0] = OSSL_PARAM_construct_utf8_string("digest".toStringz(), cast(char*)hashName.toStringz(), hashName.length+1);
    params[1] = OSSL_PARAM_construct_octet_string("salt".toStringz(), cast(void*)salt, salt.length);
    params[2] = OSSL_PARAM_construct_octet_string("key".toStringz(), cast(void*)key, key.length);
    params[3] = OSSL_PARAM_construct_octet_string("info".toStringz(), cast(void*)info, info.length);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params.ptr) <= 0) {
        throw new CryptographicException("Unable to set the HKDF parameters.");
    }

    // Do the derivation
    if (EVP_KDF_derive(kctx, derived.ptr, outputLen, null) <= 0) {
        throw new CryptographicException("Unable to generate the requested key material.");
    }

	return derived;
*/
}

unittest
{
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
}

unittest
{
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
}

@safe public KdfResult scrypt(string password) {
    KdfResult result;
    result.salt = random(32);
    result.key = scrypt_ex(password, result.salt, defaultSCryptR, defaultSCryptR, defaultSCryptP, maxSCryptMemory, 64);
    return result;
}

@safe public KdfResult scrypt(const ubyte[] password) {
    KdfResult result;
    result.salt = random(32);
    result.key = scrypt_ex(password, result.salt, defaultKdfIterations, defaultSCryptR, defaultSCryptP, maxSCryptMemory, 64);
    return result;
}

@trusted public ubyte[] scrypt_ex(string password, const ubyte[] salt, size_t length) {
    return scrypt_ex(cast(ubyte[])password, salt, defaultKdfIterations, defaultSCryptR, defaultSCryptP, maxSCryptMemory, length);
}

@trusted public ubyte[] scrypt_ex(string password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, size_t length) {
    import std.string;
    return scrypt_ex(cast(ubyte[])password.representation, salt, n, r, p, maxMemory, length);
}

@trusted public ubyte[] scrypt_ex(const ubyte[] password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, size_t length) {
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
