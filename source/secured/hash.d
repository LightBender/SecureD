module secured.hash;

import std.stdio;

version(OpenSSL)
{
import secured.openssl;
import deimos.openssl.evp;
}
version(Botan)
{
import botan.hash.sha2_32;
import botan.hash.sha2_64;
}

import secured.util;

public enum HashFunction : ubyte {
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

@trusted public ubyte[] hash(ubyte[] data, HashFunction func)
{
    version(OpenSSL)
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

        //Initialize the SHA2 algorithm
        if (EVP_DigestInit_ex(mdctx, getOpenSSLHashFunction(func), null) < 0) {
            throw new CryptographicException("Unable to create SHA2 hash context.");
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

    version(Botan)
    {
        auto sha = getBotanHashFunction(func);
        scope(exit) {
            sha.clear();
        }

        sha.update(data.ptr, data.length);

        auto digestvec = sha.finished();
        ubyte[] digest = new ubyte[digestvec.length];
        for(int i = 0; i<digestvec.length; i++) {
            digest[i] = digestvec[i];
        }

        return digest;
    }
}

unittest {
    import std.digest;

    writeln("Testing Byte Array Hash:");

    ubyte[] vec1 = hash(cast(ubyte[])"", HashFunction.SHA2_384);
    ubyte[] vec2 = hash(cast(ubyte[])"abc", HashFunction.SHA2_384);
    ubyte[] vec3 = hash(cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", HashFunction.SHA2_384);
    ubyte[] vec4 = hash(cast(ubyte[])"The quick brown fox jumps over the lazy dog.", HashFunction.SHA2_384);

    writeln(toHexString!(LetterCase.lower)(vec1));
    writeln(toHexString!(LetterCase.lower)(vec2));
    writeln(toHexString!(LetterCase.lower)(vec3));
    writeln(toHexString!(LetterCase.lower)(vec4));

    assert(toHexString!(LetterCase.lower)(vec1) == "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    assert(toHexString!(LetterCase.lower)(vec2) == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    assert(toHexString!(LetterCase.lower)(vec3) == "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
    assert(toHexString!(LetterCase.lower)(vec4) == "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7");
}

@trusted public ubyte[] hash(string path, HashFunction func = HashFunction.SHA2_384)
{
    //Open the file for reading
    auto fsfile = File(path, "rb");
    scope(exit) {
        if(fsfile.isOpen()) {
            fsfile.close();
        }
    }

    version(OpenSSL)
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

        //Initialize the SHA-384 algorithm
        if (EVP_DigestInit_ex(mdctx, getOpenSSLHashFunction(func), null) < 0) {
            throw new CryptographicException("Unable to create SHA-384 hash context.");
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

    version(Botan)
    {
        auto sha = getBotanHashFunction(func);
        scope(exit) {
            sha.clear();
        }

        //Read the file in chunks and update the Digest
        foreach(ubyte[] data; fsfile.byChunk(FILE_BUFFER_SIZE)) {
            sha.update(data.ptr, data.length);
        }

        auto digestvec = sha.finished();
        ubyte[] digest = new ubyte[digestvec.length];
        for(int i = 0; i<digestvec.length; i++) {
            digest[i] = digestvec[i];
        }

        return digest;
    }
}

unittest {
    import std.digest;

    writeln("Testing File Hash:");

    auto f = File("hashtest.txt", "wb");
    f.rawWrite("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    f.close();

    ubyte[] vec = hash("hashtest.txt", HashFunction.SHA2_384);
    writeln(toHexString!(LetterCase.lower)(vec));
    assert(toHexString!(LetterCase.lower)(vec) == "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");

    remove("hashtest.txt");
}

version(OpenSSL) {
package const(EVP_MD)* getOpenSSLHashFunction(HashFunction func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashFunction.SHA2_224: return EVP_sha224();
        case HashFunction.SHA2_256: return EVP_sha256();
        case HashFunction.SHA2_384: return EVP_sha384();
        case HashFunction.SHA2_512: return EVP_sha512();
        default:
            throw new CryptographicException(format("Hash Function '%s' is not supported by OpenSSL.", to!string(func)));
    }
}

package int getHashLength(HashFunction func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashFunction.SHA2_224: return 24;
        case HashFunction.SHA2_256: return 32;
        case HashFunction.SHA2_384: return 48;
        case HashFunction.SHA2_512: return 64;
        case HashFunction.SHA2_512_224: return 24;
        case HashFunction.SHA2_512_256: return 32;
        case HashFunction.SHA3_224: return 24;
        case HashFunction.SHA3_256: return 32;
        case HashFunction.SHA3_384: return 48;
        case HashFunction.SHA3_512: return 64;
        default:
            throw new CryptographicException(format("Hash Function '%s'", to!string(func)));
    }
}
}

version(Botan) {
package auto getBotanHashFunction(HashFunction func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashFunction.SHA2_224: return new SHA224();
        case HashFunction.SHA2_256: return new SHA256();
        case HashFunction.SHA2_384: return new SHA384();
        case HashFunction.SHA2_512: return new SHA512();
        case HashFunction.SHA3_224: return new Keccak_1600(224);
        case HashFunction.SHA3_256: return new Keccak_1600(256);
        case HashFunction.SHA3_384: return new Keccak_1600(384);
        case HashFunction.SHA3_512: return new Keccak_1600(512);
        default:
            throw new CryptographicException(format("Hash Function '%s' is not supported by Botan.", to!string(func)));
    }
}
}


