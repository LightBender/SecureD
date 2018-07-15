module secured.hash;

import std.stdio;

import secured.openssl;
import deimos.openssl.evp;

import secured.util;

public enum HashAlgorithm : ubyte {
    None,
    SHA2_224,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA2_512_224,
    SHA2_512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

@safe public ubyte[] hash(ubyte[] data) {
    return hash_ex(data, HashAlgorithm.SHA2_384);
}

@safe public bool hash_verify(ubyte[] test, ubyte[] data) {
    ubyte[] hash = hash_ex(data, HashAlgorithm.SHA2_384);
    return constantTimeEquality(hash, test);
}

@trusted public ubyte[] hash_ex(ubyte[] data, HashAlgorithm func)
{
    //Create the OpenSSL context
    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == null) {
        throw new CryptographicException("Unable to create OpenSSL context.");
    }
    scope(exit) {
        if(mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    //Initialize the hash algorithm
    if (EVP_DigestInit_ex(mdctx, getOpenSSLHashAlgorithm(func), null) < 0) {
        throw new CryptographicException("Unable to create hash context.");
    }

    //Run the provided data through the digest algorithm
    if (EVP_DigestUpdate(mdctx, data.ptr, data.length) < 0) {
        throw new CryptographicException("Error while updating digest.");
    }

    //Copy the OpenSSL digest to our D buffer.
    uint digestlen;
    ubyte[] digest = new ubyte[getHashLength(func)];
    if (EVP_DigestFinal_ex(mdctx, digest.ptr, &digestlen) < 0) {
        throw new CryptographicException("Error while retrieving the digest.");
    }

    return digest;
}

@safe public bool hash_verify_ex(ubyte[] test, ubyte[] data, HashAlgorithm func) {
    ubyte[] hash = hash_ex(data, func);
    return constantTimeEquality(hash, test);
}

unittest {
    import std.digest;

    writeln("Testing Byte Array Hash:");

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
}


@safe public ubyte[] hash(string path) {
    return hash_ex(path, HashAlgorithm.SHA2_384);
}

@safe public bool hash_verify(string path, ubyte[] test) {
    ubyte[] hash = hash_ex(path, HashAlgorithm.SHA2_384);
    return constantTimeEquality(hash, test);
}

@trusted public ubyte[] hash_ex(string path, HashAlgorithm func)
{
    //Open the file for reading
    auto fsfile = File(path, "rb");
    scope(exit) {
        if(fsfile.isOpen()) {
            fsfile.close();
        }
    }

    //Create the OpenSSL context
    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == null) {
        throw new CryptographicException("Unable to create OpenSSL context.");
    }
    scope(exit) {
        if(mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    //Initialize the hash algorithm
    if (EVP_DigestInit_ex(mdctx, getOpenSSLHashAlgorithm(func), null) < 0) {
        throw new CryptographicException("Unable to create hash context.");
    }

    //Read the file in chunks and update the Digest
    foreach(ubyte[] data; fsfile.byChunk(FILE_BUFFER_SIZE)) {
        if (EVP_DigestUpdate(mdctx, data.ptr, data.length) < 0) {
            throw new CryptographicException("Error while updating digest.");
        }
    }

    //Copy the OpenSSL digest to our D buffer.
    uint digestlen;
    ubyte[] digest = new ubyte[getHashLength(func)];
    if (EVP_DigestFinal_ex(mdctx, digest.ptr, &digestlen) < 0) {
        throw new CryptographicException("Error while retrieving the digest.");
    }

    return digest;
}

@safe public bool hash_verify_ex(string path, HashAlgorithm func, ubyte[] test) {
    ubyte[] hash = hash_ex(path, func);
    return constantTimeEquality(hash, test);
}

unittest {
    import std.digest;

    writeln("Testing File Hash:");

    auto f = File("hashtest.txt", "wb");
    f.rawWrite("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    f.close();

    ubyte[] vec = hash_ex("hashtest.txt", HashAlgorithm.SHA2_384);
    writeln(toHexString!(LetterCase.lower)(vec));
    assert(toHexString!(LetterCase.lower)(vec) == "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");

    remove("hashtest.txt");
}

@trusted package const(EVP_MD)* getOpenSSLHashAlgorithm(HashAlgorithm func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashAlgorithm.SHA2_224: return EVP_sha224();
        case HashAlgorithm.SHA2_256: return EVP_sha256();
        case HashAlgorithm.SHA2_384: return EVP_sha384();
        case HashAlgorithm.SHA2_512: return EVP_sha512();
        default:
            throw new CryptographicException(format("Hash Function '%s' is not supported by OpenSSL.", to!string(func)));
    }
}

@safe package int getHashLength(HashAlgorithm func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashAlgorithm.SHA2_224: return 24;
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
            throw new CryptographicException(format("Hash Function '%s'", to!string(func)));
    }
}
