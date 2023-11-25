module secured.rsa;

import core.memory;

import secured.openssl;
import deimos.openssl.evp;
import deimos.openssl.rand;
import deimos.openssl.pem;
import deimos.openssl.bio;
import deimos.openssl.rsa;
import deimos.openssl.engine;

import secured.random;
import secured.symmetric;
import secured.util;

// ----------------------------------------------------------

@trusted:

public class RSA
{
    private bool _hasPrivateKey;
    public @property bool hasPrivateKey() { return _hasPrivateKey; }

    static EVP_PKEY *keypair;

    public this(const int RSA_KEYLEN = 4096)
    {
        // Reseed the OpenSSL RNG every time we create a new RSA Key to ensure that the result is truely random in threading/forking scenarios.
        ubyte[] seedbuf = random(32);
        RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null);
        if (ctx is null) {
            throw new CryptographicException("EVP_PKEY_CTX_new_id failed.");
        }
        scope(exit) {
            if (ctx !is null)
                EVP_PKEY_CTX_free(ctx);
        }

        if(EVP_PKEY_keygen_init(ctx) <= 0) {
            throw new CryptographicException("EVP_PKEY_keygen_init failed.");
        }

        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
            throw new CryptographicException("EVP_PKEY_CTX_set_rsa_keygen_bits failed.");
        }

        if(EVP_PKEY_keygen(ctx, &keypair) <= 0) {
            throw new CryptographicException("EVP_PKEY_keygen failed.");
        }

        _hasPrivateKey = true;
    }

    public this(ubyte[] privateKey, ubyte[] password)
    {
        // Reseed the OpenSSL RNG every time we load an existing RSA key to ensure that the result is truely random in threading/forking scenarios.
        ubyte[] seedbuf = random(32);
        RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

        _hasPrivateKey = true;
        ubyte[] pk = cast(ubyte[])privateKey;

        BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
        if (password is null) {
            keypair = PEM_read_bio_PrivateKey(bio, null, null, null);
        } else {
            ubyte[] pwd = cast(ubyte[])password;
            pwd = pwd ~ '\0';

            keypair = PEM_read_bio_PrivateKey(bio, null, null, pwd.ptr);
        }
        BIO_free_all(bio);
    }

    public this(ubyte[] publicKey)
    {
        // Reseed the OpenSSL RNG every time we load an existing RSA key to ensure that the result is truely random in threading/forking scenarios.
        ubyte[] seedbuf = random(32);
        RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

        _hasPrivateKey = false;
        ubyte[] pk = cast(ubyte[])publicKey;

        BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
        keypair = PEM_read_bio_PUBKEY(bio, null, null, null);
        BIO_free_all(bio);
    }

    public ~this()
    {
    }

    ubyte[] seal(const ubyte[] plaintext)
    {
        return this.seal(plaintext, SymmetricAlgorithm.AES256_CTR);
    }

    ubyte[] seal(const ubyte[] plaintext, SymmetricAlgorithm algorithm)
    {
        ubyte* _encMsg;
        ubyte* _ek;
        size_t _ekl;
        ubyte* _iv;
        size_t _ivl;

        ubyte** encMsg    = &_encMsg;
        ubyte** ek        = &_ek;
        size_t* ekl        = &_ekl;
        ubyte** iv        = &_iv;
        size_t* ivl        = &_ivl;

        // The header, symmetric encryption key ek and initialisation vector iv are prefixed the encrypted message
        // Having four length bytes in header imposes a 4 GB limit on the plaintext

        const ubyte* msg    = plaintext.ptr;
        size_t msgLen         = plaintext.length;

        static if(size_t.sizeof == 8) {
            size_t maxHeaderL    = 2 + 2 + 4; // 2 bytes for actual ekl, 2 bytes for actual ivl and 4 bytes for actual length
            size_t maxEKL        = EVP_PKEY_get_size(keypair);
            size_t maxIVL        = EVP_MAX_IV_LENGTH;
            size_t maxEncMsgLen    = msgLen + EVP_MAX_IV_LENGTH;
            size_t maxTotalSize    = maxHeaderL + maxEKL + maxIVL + maxEncMsgLen;

            size_t encMsgLen = 0;
            size_t blockLen  = 0;

            *ivl = EVP_MAX_IV_LENGTH;

            ubyte* buffer = cast(ubyte*)GC.malloc(maxTotalSize);
            if(buffer == null)
                throw new CryptographicException("Malloc failed.");

            *ek = buffer + maxHeaderL;
            *iv = buffer + maxHeaderL + maxEKL;
            *encMsg = buffer + maxHeaderL + maxEKL + maxIVL;
version(OpenSSL10) {
            EVP_CIPHER_CTX *rsaEncryptCtx = cast(EVP_CIPHER_CTX*)GC.malloc(EVP_CIPHER_CTX.sizeof);
            if(rsaEncryptCtx == null)
                throw new CryptographicException("Malloc failed.");
            EVP_CIPHER_CTX_init(rsaEncryptCtx);
} else {
            EVP_CIPHER_CTX *rsaEncryptCtx = EVP_CIPHER_CTX_new();
}
            scope(exit) {
                if (rsaEncryptCtx !is null) {
version(OpenSSL10) {
                    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
} else {
                    EVP_CIPHER_CTX_free(rsaEncryptCtx);
}
                }
            }

            if(!EVP_SealInit(rsaEncryptCtx, getOpenSslCipher(algorithm), ek, cast(int*)ekl, *iv, &keypair, 1))
                throw new CryptographicException("CEVP_SealInit failed.");

            if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, cast(int*)&blockLen, cast(const ubyte*)msg, cast(int)msgLen))
                throw new CryptographicException("EVP_SealUpdate failed.");
            encMsgLen += blockLen;

            if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, cast(int*)&blockLen))
                throw new CryptographicException("EVP_SealFinal failed.");
            encMsgLen += blockLen;

            buffer[0 .. 2] = (cast(ubyte*)ekl)[0..2];
            buffer[2 .. 4] = (cast(ubyte*)ivl)[0..2];

            ubyte* encMsgLenTemp = cast(ubyte*)(&encMsgLen);
            buffer[4..8] = encMsgLenTemp[0..4];

            assert(*ekl == maxEKL);
            assert(*ivl == maxIVL);

            return buffer[0 .. maxHeaderL + maxEKL + maxIVL + encMsgLen];
        }
        else
            assert(0);
    }

    ubyte[] open(ubyte[] encMessage)
    {
        return this.open(encMessage, SymmetricAlgorithm.AES256_CTR);
    }

    ubyte[] open(ubyte[] encMessage, SymmetricAlgorithm algorithm)
    {
        assert(encMessage.length > 8); // Encrypted message must be larger than header = ekl + ivl + messageLength
        static if(size_t.sizeof == 8) {
            // Header: 2 bytes for actual ekl, 2 bytes for actual ivl and 4 bytes for actual length
            size_t maxHeaderL    = 2 + 2 + 4;
            size_t maxEKL        = EVP_PKEY_get_size(keypair);
            size_t maxIVL        = EVP_MAX_IV_LENGTH;

            ubyte* ek            = encMessage.ptr + maxHeaderL;
            ubyte[8] temp        = 0;
            temp[0..2]            = encMessage[0..2];
            int ekl                = (cast(int[])temp)[0];

            ubyte* iv            = encMessage.ptr + maxHeaderL + maxEKL;
            temp                = 0;
            temp[0..2]            = encMessage[2..4];
            size_t ivl            = (cast(int[])temp)[0];

            ubyte* encMsg        = encMessage.ptr + maxHeaderL + maxEKL + maxIVL;
            temp                = 0;
            temp[0..4]            = encMessage[4..8];
            size_t encMsgLen    = (cast(size_t[])temp)[0];

            size_t decLen   = 0;
            size_t blockLen = 0;
            EVP_PKEY *key;
            ubyte* _decMsg;
            auto decMsg = &_decMsg;
            *decMsg = cast(ubyte*)GC.malloc(encMsgLen + ivl);
            if(decMsg == null) {
                throw new CryptographicException("Malloc failed.");
            }

version(OpenSSL10) {
            EVP_CIPHER_CTX *rsaDecryptCtx = cast(EVP_CIPHER_CTX*)GC.malloc(EVP_CIPHER_CTX.sizeof);
            if(rsaDecryptCtx == null) {
                throw new CryptographicException("Malloc failed.");
            }
            EVP_CIPHER_CTX_init(rsaDecryptCtx);
} else {
            EVP_CIPHER_CTX *rsaDecryptCtx = EVP_CIPHER_CTX_new();
}
            scope(exit) {
                if (rsaDecryptCtx !is null) {
version(OpenSSL10) {
                    EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
} else {
                    EVP_CIPHER_CTX_free(rsaDecryptCtx);
}
                }
            }

            if(!EVP_OpenInit(rsaDecryptCtx, getOpenSslCipher(algorithm), ek, ekl, iv, keypair))
                throw new CryptographicException("EVP_OpenInit failed.");

            if(!EVP_OpenUpdate(rsaDecryptCtx, cast(ubyte*)*decMsg + decLen, cast(int*)&blockLen, encMsg, cast(int)encMsgLen))
                throw new CryptographicException("EVP_OpenUpdate failed.");
            decLen += blockLen;

            if(!EVP_OpenFinal(rsaDecryptCtx, cast(ubyte*)*decMsg + decLen, cast(int*)&blockLen))
                throw new CryptographicException("EVP_OpenFinal failed.");
            decLen += blockLen;

            return (*decMsg)[0 .. decLen];
        }
        else
            assert(0);
    }

    ubyte[] getPublicKey()
    {
        BIO* bio = BIO_new(BIO_s_mem());

        PEM_write_bio_PUBKEY(bio, keypair);

        ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
        BIO_read(bio, buffer.ptr, cast(int)buffer.length);
        BIO_free_all(bio);

        return buffer;
    }

    public ubyte[] getPrivateKey(string password, int iterations = 25000, bool use3Des = false)
    {
        if (!_hasPrivateKey) {
            return null;
        }

        BIO* bio = BIO_new(BIO_s_mem());

        if (password is null) {
            PEM_write_bio_PKCS8PrivateKey(bio, keypair, null, null, 0, null, null);
        } else {
            ubyte[] pwd = cast(ubyte[])password;
            pwd = pwd ~ '\0';

            PEM_write_bio_PKCS8PrivateKey(
                bio,
                keypair,
                !use3Des ? EVP_aes_256_cbc() : EVP_des_ede3_cbc(),
                null,
                0,
                null,
                pwd.ptr);
        }

        if(BIO_ctrl_pending(bio) == 0) {
            throw new CryptographicException("No private key written.");
        }

        ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
        BIO_read(bio, buffer.ptr, cast(int)buffer.length);
        BIO_free_all(bio);

        return buffer;
    }

    ubyte[] encrypt(const ubyte[] inMessage)
    in
    {
        import std.exception: enforce;
        enforce(inMessage.length <= (EVP_PKEY_get_size(keypair) - 42), new CryptographicException("Plainttext length exceeds allowance")); // 42 being the padding overhead for OAEP padding using SHA-1
    }
    body
    {
        EVP_PKEY_CTX *ctx;
        ENGINE *eng = null; // Use default RSA implementation
        ubyte *out2;
        const ubyte *in2 = inMessage.ptr;
        size_t outlen;
        size_t inlen = inMessage.length;

        ctx = EVP_PKEY_CTX_new(keypair,eng);
        if (!ctx)  {
            throw new CryptographicException("EVP_PKEY_CTX_new.");
        }
        scope(exit) {
            if (ctx !is null) {
                EVP_PKEY_CTX_free(ctx);
            }
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            throw new CryptographicException("EVP_PKEY_encrypt_init failed.");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw new CryptographicException("EVP_PKEY_CTX_set_rsa_padding failed.");
        }

        if (EVP_PKEY_encrypt(ctx, null, &outlen, in2, inlen) <= 0) {
            throw new CryptographicException("EVP_PKEY_encrypt failed.");
        }

        out2 = cast(ubyte*)GC.malloc(outlen);
        if(out2 == null) {
            throw new CryptographicException("Malloc failed.");
        }

        if (EVP_PKEY_encrypt(ctx, out2, &outlen, in2, inlen) <= 0) {
            throw new CryptographicException("EVP_PKEY_encrypt failed.");
        }

        return (out2)[0 .. outlen];
    }

    ubyte[] decrypt(const ubyte[] inMessage)
    in
    {
        assert(inMessage.length == EVP_PKEY_get_size(keypair));  // Should always hold as padding was added during encryption
    }
    body
    {
        EVP_PKEY_CTX *ctx;
        ENGINE *eng = null; // Use default RSA implementation
        ubyte *out2;
        const ubyte *in2 = inMessage.ptr;
        size_t outlen;
        size_t inlen = inMessage.length;

        ctx = EVP_PKEY_CTX_new(keypair,eng);
        if (!ctx) {
            throw new CryptographicException("EVP_PKEY_CTX_new failed");
        }
        scope(exit) {
            if (ctx !is null) {
                EVP_PKEY_CTX_free(ctx);
            }
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            throw new CryptographicException("EVP_PKEY_decrypt_init failed.");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw new CryptographicException("EVP_PKEY_CTX_set_rsa_padding failed.");
        }

        if (EVP_PKEY_decrypt(ctx, null, &outlen, in2, inlen) <= 0) {
            throw new CryptographicException("EVP_PKEY_decrypt failed.");
        }

        out2 = cast(ubyte*)GC.malloc(outlen);
        if(out2 == null) {
            throw new CryptographicException("Malloc failed.");
        }

        if (EVP_PKEY_decrypt(ctx, out2, &outlen, in2, inlen) <= 0) {
            throw new CryptographicException("EVP_PKEY_encrypt failed.");
        }

        return (out2)[0 .. outlen];
    }

    public ubyte[] sign(ubyte[] data, bool useSha256 = false)
    out (signature)
    {
        assert(signature.length == EVP_PKEY_get_size(keypair));
    }
    body
    {
        EVP_MD_CTX *mdctx = null;

        mdctx = EVP_MD_CTX_new();
        if (mdctx is null) {
            throw new CryptographicException("Unable to create the MD signing context.");
        }
        scope(exit) {
            if (mdctx !is null) {
                EVP_MD_CTX_free(mdctx);
            }
        }

        auto alg = (!useSha256 ? EVP_sha384() : EVP_sha256());

        if (EVP_DigestSignInit(mdctx, null, alg, null, keypair) != 1) {
            throw new CryptographicException("Unable to initialize the signing digest.");
        }

        if (EVP_DigestSignUpdate(mdctx, data.ptr, data.length) != 1) {
            throw new CryptographicException("Unable to set sign data.");
        }

        size_t signlen = 0;
        if (EVP_DigestSignFinal(mdctx, null, &signlen) != 1) {
            throw new CryptographicException("Unable to calculate signature length.");
        }

        ubyte[] sign = new ubyte[signlen];
        if (EVP_DigestSignFinal(mdctx, sign.ptr, &signlen) != 1) {
            throw new CryptographicException("Unable to finalize signature");
        }


        return sign[0..signlen];
    }

    public bool verify(ubyte[] data, ubyte[] signature, bool useSha256 = false)
    in
    {
        assert(signature.length == EVP_PKEY_get_size(keypair));
    }
    body
    {
        EVP_MD_CTX *mdctx = null;

        mdctx = EVP_MD_CTX_new();
        if (mdctx is null) {
            throw new CryptographicException("Unable to create the MD signing context.");
        }
        scope(exit) {
            if (mdctx !is null) {
                EVP_MD_CTX_free(mdctx);
            }
        }

        auto alg = (!useSha256 ? EVP_sha384() : EVP_sha256());

        if (EVP_DigestVerifyInit(mdctx, null, alg, null, keypair) != 1) {
            throw new CryptographicException("Unable to initialize the verification digest.");
        }

        if (EVP_DigestVerifyUpdate(mdctx, data.ptr, data.length) != 1) {
            throw new CryptographicException("Unable to set verify data.");
        }

        int ret = EVP_DigestVerifyFinal(mdctx, signature.ptr, signature.length);

        return ret == 1;
    } // verify()

} // class RSA


// ----------------------------------------------------------
// UNITTESTING BELOW
// ----------------------------------------------------------

unittest
{
    import std.stdio;
    writeln("Testing seal and open functions:");

    auto keypair = new RSA();
    scope(exit) keypair.destroy();

       ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";

    ubyte[] encMessage = keypair.seal(plaintext);
    ubyte[] decMessage = keypair.open(encMessage);

    assert(plaintext.length    == decMessage.length);
    assert(plaintext        == decMessage);
}

// ----------------------------------------------------------

unittest
{
    import std.stdio;
    writeln("Testing getXxxKey functions and constructors:");

    auto keypairA = new RSA();
    scope(exit) keypairA.destroy();

    auto privateKeyA = keypairA.getPrivateKey(null);
    auto publicKeyA  = keypairA.getPublicKey();

       ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";

    // Creating key from public key only
    auto keypairB = new RSA(publicKeyA);
    scope(exit) keypairB.destroy();

    auto privateKeyB = keypairB.getPrivateKey(null);
    auto publicKeyB  = keypairB.getPublicKey();

    assert(privateKeyA    != privateKeyB,    "Private keys A and B match - they should NOT do so");
    assert(publicKeyA     == publicKeyB,    "Public  keys A and B does not match");

    //  Creating key from private key only
    auto keypairC = new RSA(privateKeyA, null);
    scope(exit) keypairC.destroy();

    auto publicKeyC     = keypairC.getPublicKey();
    auto privateKeyC = keypairC.getPrivateKey(null);

    assert(privateKeyA    == privateKeyC,    "Private keys A and C does not match");
    assert(publicKeyA     == publicKeyC,    "Public  keys A and C does not match");
}

// ----------------------------------------------------------

unittest
{
    import std.stdio;
    writeln("Testing sealing and opening with keys, which have been constructed on getXxxKey output:");

    auto keypairA = new RSA();
    scope(exit)        keypairA.destroy();

    auto privateKeyA = keypairA.getPrivateKey(null);
    auto publicKeyA  = keypairA.getPublicKey();

       ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";

    // Creating key from public key only
    auto keypairB        =  new RSA(publicKeyA);
    scope(exit)               keypairB.destroy();

    auto publicKeyB        =  keypairB.getPublicKey();
    assert(publicKeyA     == publicKeyB,    "Public  keys A and B does not match");

    //  Creating key from private key only
    auto keypairC        =  new RSA(privateKeyA, null);
    scope(exit)               keypairC.destroy();

    auto privateKeyC    =  keypairC.getPrivateKey(null);
    assert(privateKeyA    == privateKeyC,    "Private keys A and C does not match");

    // Sealing plaintext using public key
    ubyte[] encMessage    = keypairB.seal(plaintext);
    // Opening encrypted message using private key
    ubyte[] decMessage    = keypairC.open(encMessage);

    assert(plaintext.length    == decMessage.length);
    assert(plaintext        == decMessage);
}

// ----------------------------------------------------------

unittest
{
    import std.stdio;
    writeln("Testing RSA only encrypt/decrypt functions:");

    auto keypair = new RSA();
    scope(exit) keypair.destroy();

    ubyte[48] plaintext = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] encMessage = keypair.encrypt(plaintext);
    ubyte[] decMessage = keypair.decrypt(encMessage);

    assert(plaintext.length    == decMessage.length);
    assert(plaintext        == decMessage);
}

// ----------------------------------------------------------

unittest
{
    import std.stdio;
    writeln("Testing RSA encrypt/decrypt limit:");

    auto keypair = new RSA(2048);  // Only allows for (2048/8)-42 = 214 bytes to be asymmetrically RSA encrypted
    scope(exit) keypair.destroy();

    // This should work
    ubyte[214] plaintext214 = 2; // 2 being an arbitrary value

    ubyte[] encMessage214 = keypair.encrypt(plaintext214);
    assert(encMessage214.length == 2048 / 8);

    ubyte[] decMessage214 = keypair.decrypt(encMessage214);

    assert(plaintext214.length    == decMessage214.length);
    assert(plaintext214            == decMessage214);

    // This should NOT work, as the plaintext is larger that allowed for this 2048 bit RSA keypair
    ubyte[215] plaintext215 = 2; // 2 being an arbitrary value

    import std.exception: assertThrown;
    assertThrown!CryptographicException(keypair.encrypt(plaintext215));
}

// ----------------------------------------------------------

unittest
{
    import std.stdio;
    writeln("Testing RSA Signing/Verification:");

    import std.digest;

    auto keypair = new RSA();
    scope(exit) keypair.destroy();

    ubyte[48] data = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[48] data2 = [ 0x1, 0x2, 0x3, 0x4, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] sig = keypair.sign(data);
    writeln("Signature: ", toHexString!(LetterCase.lower)(sig));
    assert(keypair.verify(data, sig));
    assert(!keypair.verify(data2, sig));
}
