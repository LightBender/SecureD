module secured.system.openssl;

/*
 * OpenSSL provider implementations.
 *
 * All OpenSSL FFI for hashing, HMAC, key derivation and symmetric encryption
 * lives here. This module is compiled only when an OpenSSL-family provider
 * (OpenSSL, LibreSSL, BoringSSL) is the active provider, or when the polyfill
 * is enabled. The public dispatchers in the algorithm modules forward here.
 */

import secured.provider;

static if (usesOpenSSL) {

import std.conv : to;
import std.stdio : File;
import std.string : toStringz;
import std.exception : enforce;
import core.memory : GC;

import secured.bindings.openssl;
import secured.ecc : EccCurve;
import secured.hash : HashAlgorithm, getHashLength, unsupportedHashMessage;
import secured.random : random;
import secured.symmetric : SymmetricAlgorithm, isAeadCipher, getAuthLength, getCipherKeyLength, getCipherIVLength, unsupportedCipherMessage;
import secured.util : CryptographicException, AlgorithmNotSupportedException, FILE_BUFFER_SIZE;

package(secured):

// ---------------------------------------------------------------------------
// Hash algorithm mapping
// ---------------------------------------------------------------------------
@trusted const(EVP_MD)* getOpenSSLHashAlgorithm(HashAlgorithm func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashAlgorithm.SHA2_256: return EVP_sha256();
        case HashAlgorithm.SHA2_384: return EVP_sha384();
        case HashAlgorithm.SHA2_512: return EVP_sha512();
        case HashAlgorithm.SHA2_512_224: return EVP_sha512_224();
        case HashAlgorithm.SHA2_512_256: return EVP_sha512_256();
        case HashAlgorithm.SHA3_224: return EVP_sha3_224();
        case HashAlgorithm.SHA3_256: return EVP_sha3_256();
        case HashAlgorithm.SHA3_384: return EVP_sha3_384();
        case HashAlgorithm.SHA3_512: return EVP_sha3_512();
        default:
            throw new CryptographicException(format("Hash Function '%s' is not supported by OpenSSL.", to!string(func)));
    }
}

@trusted string getOpenSSLHashAlgorithmString(HashAlgorithm func) {
    import std.conv;
    import std.format;

    switch (func) {
        case HashAlgorithm.SHA2_256: return "sha256";
        case HashAlgorithm.SHA2_384: return "sha384";
        case HashAlgorithm.SHA2_512: return "sha512";
        case HashAlgorithm.SHA2_512_224: return "sha512-224";
        case HashAlgorithm.SHA2_512_256: return "sha512-256";
        case HashAlgorithm.SHA3_224: return "sha3-224";
        case HashAlgorithm.SHA3_256: return "sha3-256";
        case HashAlgorithm.SHA3_384: return "sha3-384";
        case HashAlgorithm.SHA3_512: return "sha3-512";
        default:
            throw new CryptographicException(format("Hash Function '%s' is not supported by OpenSSL.", to!string(func)));
    }
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------
@trusted ubyte[] hash_impl_openssl(const ubyte[] data, HashAlgorithm func)
{
    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == null) {
        throw new CryptographicException("Unable to create OpenSSL context.");
    }
    scope(exit) {
        if(mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    if (EVP_DigestInit_ex(mdctx, getOpenSSLHashAlgorithm(func), null) < 0) {
        throw new CryptographicException("Unable to create hash context.");
    }

    if (EVP_DigestUpdate(mdctx, data.ptr, data.length) < 0) {
        throw new CryptographicException("Error while updating digest.");
    }

    uint digestlen;
    ubyte[] digest = new ubyte[getHashLength(func)];
    if (EVP_DigestFinal_ex(mdctx, digest.ptr, &digestlen) < 0) {
        throw new CryptographicException("Error while retrieving the digest.");
    }

    return digest;
}

@trusted ubyte[] hash_impl_openssl(string path, HashAlgorithm func)
{
    auto fsfile = File(path, "rb");
    scope(exit) {
        if(fsfile.isOpen()) {
            fsfile.close();
        }
    }

    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == null) {
        throw new CryptographicException("Unable to create OpenSSL context.");
    }
    scope(exit) {
        if(mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    if (EVP_DigestInit_ex(mdctx, getOpenSSLHashAlgorithm(func), null) < 0) {
        throw new CryptographicException("Unable to create hash context.");
    }

    foreach(ubyte[] data; fsfile.byChunk(FILE_BUFFER_SIZE)) {
        if (EVP_DigestUpdate(mdctx, data.ptr, data.length) < 0) {
            throw new CryptographicException("Error while updating digest.");
        }
    }

    uint digestlen;
    ubyte[] digest = new ubyte[getHashLength(func)];
    if (EVP_DigestFinal_ex(mdctx, digest.ptr, &digestlen) < 0) {
        throw new CryptographicException("Error while retrieving the digest.");
    }

    return digest;
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------
@trusted ubyte[] hmac_impl_openssl(const ubyte[] key, const ubyte[] data, HashAlgorithm func)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == null) {
        throw new CryptographicException("Unable to create OpenSSL context.");
    }
    scope(exit) {
        if(mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    auto md = getOpenSSLHashAlgorithm(func);
    if (EVP_DigestInit_ex(mdctx, md, null) != 1) {
        throw new CryptographicException("Unable to create hash context.");
    }

    auto pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, null, key.ptr, cast(int)key.length);
    scope(exit) {
        if(pkey !is null) {
            EVP_PKEY_free(pkey);
        }
    }
    if (EVP_DigestSignInit(mdctx, null, md, null, pkey) != 1) {
        throw new CryptographicException("Unable to create HMAC key context.");
    }

    if (EVP_DigestSignUpdate(mdctx, data.ptr, data.length) != 1) {
        throw new CryptographicException("Error while updating digest.");
    }

    size_t digestlen = getHashLength(func);
    ubyte[] digest = new ubyte[getHashLength(func)];
    if (EVP_DigestSignFinal(mdctx, digest.ptr, &digestlen) < 0) {
        throw new CryptographicException("Error while retrieving the digest.");
    }

    return digest;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------
@trusted ubyte[] pbkdf2_impl_openssl(string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
    ubyte[] output = new ubyte[outputLen];
    if(PKCS5_PBKDF2_HMAC(password.ptr, cast(int)password.length, salt.ptr, cast(int)salt.length, iterations, getOpenSSLHashAlgorithm(func), outputLen, output.ptr) == 0) {
        throw new CryptographicException("Unable to execute PBKDF2 hash function.");
    }
    return output;
}

@trusted ubyte[] hkdf_impl_openssl(const ubyte[] key, const ubyte[] salt, string info, size_t outputLen, HashAlgorithm func) {
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = null;
    ubyte[] derived = new ubyte[outputLen];
    ossl_param_st[5] params;

    if ((kdf = EVP_KDF_fetch(null, "hkdf", null)) == null) {
        throw new CryptographicException("Unable to create HKDF function.");
    }
    // EVP_KDF_fetch returns a reference-counted object that must be freed.
    scope(exit) {
        if (kdf !is null) {
            EVP_KDF_free(kdf);
        }
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx is null) {
        throw new CryptographicException("Unable to create HKDF context.");
    }
    scope(exit) {
        if (kctx !is null) {
            EVP_KDF_CTX_free(kctx);
        }
    }

    // Keep the digest name alive for the duration of the OSSL_PARAM call.
    // toStringz() returns a temporary that must not be used after the
    // expression ends; store it in a local first.
    string hashName = getOpenSSLHashAlgorithmString(func);
    auto digestZ = hashName.toStringz();
    params[0] = OSSL_PARAM_construct_utf8_string("digest".toStringz(), cast(char*)digestZ, 0);
    params[1] = OSSL_PARAM_construct_octet_string("salt".toStringz(), cast(void*)salt.ptr, salt.length);
    params[2] = OSSL_PARAM_construct_octet_string("key".toStringz(), cast(void*)key.ptr, key.length);
    params[3] = OSSL_PARAM_construct_octet_string("info".toStringz(), cast(void*)info.ptr, info.length);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params.ptr) <= 0) {
        throw new CryptographicException("Unable to set the HKDF parameters.");
    }

    if (EVP_KDF_derive(kctx, derived.ptr, outputLen, null) <= 0) {
        throw new CryptographicException("Unable to generate the requested key material.");
    }

    return derived;
}

@trusted ubyte[] scrypt_impl_openssl(const ubyte[] password, const ubyte[] salt, ulong n, ulong r, ulong p, ulong maxMemory, size_t length) {
    ubyte[] hash = new ubyte[length];

    if (EVP_PBE_scrypt((cast(char[])password).ptr, password.length, salt.ptr, salt.length, n, r, p, maxMemory, hash.ptr, length) <= 0) {
        throw new CryptographicException("Unable to calculate SCrypt hash.");
    }

    return hash;
}

// ---------------------------------------------------------------------------
// Symmetric ciphers
// ---------------------------------------------------------------------------
@trusted const(EVP_CIPHER*) getOpenSslCipher(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return EVP_aes_128_gcm();
        case SymmetricAlgorithm.AES192_GCM: return EVP_aes_192_gcm();
        case SymmetricAlgorithm.AES256_GCM: return EVP_aes_256_gcm();
        case SymmetricAlgorithm.AES128_CTR: return EVP_aes_128_ctr();
        case SymmetricAlgorithm.AES192_CTR: return EVP_aes_192_ctr();
        case SymmetricAlgorithm.AES256_CTR: return EVP_aes_256_ctr();
        case SymmetricAlgorithm.AES128_CFB: return EVP_aes_128_cfb();
        case SymmetricAlgorithm.AES192_CFB: return EVP_aes_192_cfb();
        case SymmetricAlgorithm.AES256_CFB: return EVP_aes_256_cfb();
        case SymmetricAlgorithm.AES128_CBC: return EVP_aes_128_cbc();
        case SymmetricAlgorithm.AES192_CBC: return EVP_aes_192_cbc();
        case SymmetricAlgorithm.AES256_CBC: return EVP_aes_256_cbc();
        case SymmetricAlgorithm.ChaCha20: return EVP_chacha20();
        case SymmetricAlgorithm.ChaCha20_Poly1305: return EVP_chacha20_poly1305();
        default: return EVP_aes_256_gcm();
    }
}

@trusted ubyte[] encrypt_impl_openssl(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx is null) {
        throw new CryptographicException("Cannot get an OpenSSL cipher context.");
    }
    scope(exit) {
        if (ctx !is null) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    if (EVP_EncryptInit_ex(ctx, getOpenSslCipher(algorithm), null, encryptionKey.ptr, iv.ptr) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    // Treat null and empty AAD identically so encrypt/decrypt stay consistent.
    if (associatedData.length != 0 && isAeadCipher(algorithm)) {
        int aadLen = 0;
        if (EVP_EncryptUpdate(ctx, null, &aadLen, associatedData.ptr, cast(int)associatedData.length) != 1) {
            throw new CryptographicException("Unable to write bytes to cipher context.");
        }
    }

    int written = 0;
    int len = 0;
    ubyte[] output = new ubyte[data.length + 32];
    if (EVP_EncryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    if (EVP_EncryptFinal_ex(ctx, &output[written], &len) != 1) {
        throw new CryptographicException("Unable to extract the ciphertext from the cipher context.");
    }

    written += len;
    ubyte[] result = output[0..written];

    if (isAeadCipher(algorithm)) {
        ubyte[] _auth = new ubyte[getAuthLength(algorithm)];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, getAuthLength(algorithm), _auth.ptr) != 1) {
            throw new CryptographicException("Unable to extract the authentication tag from the cipher context.");
        }
        authTag = _auth;
    }

    return result;
}

@trusted ubyte[] decrypt_impl_openssl(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx is null) {
        throw new CryptographicException("Cannot get an OpenSSL cipher context.");
    }
    scope(exit) {
        if (ctx !is null) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    if (!EVP_DecryptInit_ex(ctx, getOpenSslCipher(algorithm), null, encryptionKey.ptr, iv.ptr)) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    if (associatedData.length != 0 && isAeadCipher(algorithm)) {
        int aadLen = 0;
        if (!EVP_DecryptUpdate(ctx, null, &aadLen, associatedData.ptr, cast(int)associatedData.length)) {
            throw new CryptographicException("Unable to write bytes to cipher context.");
        }
    }

    if (isAeadCipher(algorithm)) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, cast(int)authTag.length, (cast(ubyte[])authTag).ptr)) {
            throw new CryptographicException("Unable to set the authentication tag on the cipher context.");
        }
    }

    int written = 0;
    int len = 0;
    ubyte[] output = new ubyte[data.length + 32];
    if (!EVP_DecryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length)) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    if (EVP_DecryptFinal_ex(ctx, &output[written], &len) <= 0) {
        throw new CryptographicException("Unable to extract the plaintext from the cipher context.");
    }
    written += len;

    return output[0..written];
}

// ---------------------------------------------------------------------------
// RSA
//
// The RSA key context is an OpenSSL EVP_PKEY*. The public RSA class in
// secured.rsa holds one of these and forwards to these free functions.
// ---------------------------------------------------------------------------
alias RsaKey = EVP_PKEY*;

RsaKey rsaGenerate(int keylen) {
    // Reseed the OpenSSL RNG to ensure randomness in threading/forking scenarios.
    ubyte[] seedbuf = random(32);
    RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null);
    if (ctx is null) {
        throw new CryptographicException("EVP_PKEY_CTX_new_id failed.");
    }
    scope(exit) {
        if (ctx !is null)
            EVP_PKEY_CTX_free(ctx);
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        throw new CryptographicException("EVP_PKEY_keygen_init failed.");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylen) <= 0) {
        throw new CryptographicException("EVP_PKEY_CTX_set_rsa_keygen_bits failed.");
    }

    EVP_PKEY* keypair;
    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        throw new CryptographicException("EVP_PKEY_keygen failed.");
    }
    return keypair;
}

RsaKey rsaLoadPrivateKey(ubyte[] privateKey, ubyte[] password) {
    ubyte[] seedbuf = random(32);
    RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

    ubyte[] pk = cast(ubyte[])privateKey;
    BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
    if (bio is null) {
        throw new CryptographicException("Unable to create BIO for RSA private key.");
    }
    scope(exit) BIO_free_all(bio);

    EVP_PKEY* keypair;
    if (password is null) {
        keypair = PEM_read_bio_PrivateKey(bio, null, null, null);
    } else {
        ubyte[] pwd = cast(ubyte[])password;
        pwd = pwd ~ '\0';
        keypair = PEM_read_bio_PrivateKey(bio, null, null, pwd.ptr);
    }
    if (keypair is null) {
        throw new CryptographicException("Unable to load RSA private key.");
    }
    return keypair;
}

RsaKey rsaLoadPublicKey(ubyte[] publicKey) {
    ubyte[] seedbuf = random(32);
    RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

    ubyte[] pk = cast(ubyte[])publicKey;
    BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
    if (bio is null) {
        throw new CryptographicException("Unable to create BIO for RSA public key.");
    }
    scope(exit) BIO_free_all(bio);

    EVP_PKEY* keypair = PEM_read_bio_PUBKEY(bio, null, null, null);
    if (keypair is null) {
        throw new CryptographicException("Unable to load RSA public key.");
    }
    return keypair;
}

void rsaFree(RsaKey keypair) {
    if (keypair !is null) {
        EVP_PKEY_free(keypair);
    }
}

private void opensslRequireSealHash(HashAlgorithm hashAlgorithm) {
    // OpenSSL supports the full SHA-2 / SHA-3 set used by SecureD. Reject only
    // the sentinel / unsupported enum values so callers get a clear error.
    switch (hashAlgorithm) {
        case HashAlgorithm.SHA2_256:
        case HashAlgorithm.SHA2_384:
        case HashAlgorithm.SHA2_512:
        case HashAlgorithm.SHA2_512_224:
        case HashAlgorithm.SHA2_512_256:
        case HashAlgorithm.SHA3_224:
        case HashAlgorithm.SHA3_256:
        case HashAlgorithm.SHA3_384:
        case HashAlgorithm.SHA3_512:
            return;
        default:
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }
}

private size_t opensslOaepOverhead(HashAlgorithm hashAlgorithm) {
    // OAEP overhead is 2 * hashLen + 2.
    return 2 * getHashLength(hashAlgorithm) + 2;
}

private void opensslConfigureOaep(EVP_PKEY_CTX* ctx, HashAlgorithm hashAlgorithm) {
    opensslRequireSealHash(hashAlgorithm);
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        throw new CryptographicException("EVP_PKEY_CTX_set_rsa_padding failed.");
    }
    auto md = cast(const(EVP_MD)*)getOpenSSLHashAlgorithm(hashAlgorithm);
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
        throw new CryptographicException("EVP_PKEY_CTX_set_rsa_oaep_md failed.");
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
        throw new CryptographicException("EVP_PKEY_CTX_set_rsa_mgf1_md failed.");
    }
}

private ubyte[] opensslRsaEncryptWithHash(RsaKey keypair, const ubyte[] inMessage, HashAlgorithm hashAlgorithm) {
    immutable size_t overhead = opensslOaepOverhead(hashAlgorithm);
    enforce(inMessage.length <= (EVP_PKEY_get_size(keypair) - overhead),
        new CryptographicException("Plainttext length exceeds allowance"));

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, null);
    if (ctx is null) {
        throw new CryptographicException("EVP_PKEY_CTX_new failed.");
    }
    scope(exit) {
        if (ctx !is null) {
            EVP_PKEY_CTX_free(ctx);
        }
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        throw new CryptographicException("EVP_PKEY_encrypt_init failed.");
    }
    opensslConfigureOaep(ctx, hashAlgorithm);

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, null, &outlen, inMessage.ptr, inMessage.length) <= 0) {
        throw new CryptographicException("EVP_PKEY_encrypt failed.");
    }

    ubyte* out2 = cast(ubyte*)GC.malloc(outlen);
    if (out2 is null) {
        throw new CryptographicException("Malloc failed.");
    }
    if (EVP_PKEY_encrypt(ctx, out2, &outlen, inMessage.ptr, inMessage.length) <= 0) {
        throw new CryptographicException("EVP_PKEY_encrypt failed.");
    }
    return out2[0 .. outlen];
}

private ubyte[] opensslRsaDecryptWithHash(RsaKey keypair, const ubyte[] inMessage, HashAlgorithm hashAlgorithm) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, null);
    if (ctx is null) {
        throw new CryptographicException("EVP_PKEY_CTX_new failed.");
    }
    scope(exit) {
        if (ctx !is null) {
            EVP_PKEY_CTX_free(ctx);
        }
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        throw new CryptographicException("EVP_PKEY_decrypt_init failed.");
    }
    opensslConfigureOaep(ctx, hashAlgorithm);

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, null, &outlen, inMessage.ptr, inMessage.length) <= 0) {
        throw new CryptographicException("EVP_PKEY_decrypt failed.");
    }

    ubyte* out2 = cast(ubyte*)GC.malloc(outlen);
    if (out2 is null) {
        throw new CryptographicException("Malloc failed.");
    }
    if (EVP_PKEY_decrypt(ctx, out2, &outlen, inMessage.ptr, inMessage.length) <= 0) {
        throw new CryptographicException("EVP_PKEY_decrypt failed.");
    }
    return out2[0 .. outlen];
}

ubyte[] rsaSeal(RsaKey keypair, const ubyte[] plaintext, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
    // Hybrid encryption with explicit OAEP hash selection. EVP_Seal* always uses
    // RSA PKCS#1 v1.5 for the key wrap, so we assemble the envelope ourselves:
    // encrypt with the requested symmetric algorithm, then RSA-OAEP wrap the key.
    opensslRequireSealHash(hashAlgorithm);
    getOpenSslCipher(algorithm); // validates the cipher enum

    immutable uint keyLen = getCipherKeyLength(algorithm);
    immutable uint ivLen = getCipherIVLength(algorithm);
    ubyte[] aesKey = random(keyLen);
    ubyte[] iv = random(ivLen);
    ubyte[] tag;
    ubyte[] ciphertext = encrypt_impl_openssl(plaintext, null, aesKey, iv, tag, algorithm);
    ubyte[] wrappedKey = opensslRsaEncryptWithHash(keypair, aesKey, hashAlgorithm);

    // Layout: [4-byte wrappedKeyLen][wrappedKey][iv][tagLen:1][tag][ciphertext]
    // tag is empty for non-AEAD ciphers; AEAD tags are 16 bytes.
    uint wkl = cast(uint)wrappedKey.length;
    ubyte[] output;
    output ~= (cast(ubyte*)&wkl)[0 .. 4];
    output ~= wrappedKey;
    output ~= iv;
    output ~= cast(ubyte)tag.length;
    output ~= tag;
    output ~= ciphertext;
    return output;
}

ubyte[] rsaOpen(RsaKey keypair, ubyte[] encMessage, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
    opensslRequireSealHash(hashAlgorithm);
    getOpenSslCipher(algorithm);

    immutable uint ivLen = getCipherIVLength(algorithm);
    if (encMessage.length < 4) {
        throw new CryptographicException("Invalid sealed message.");
    }
    uint wkl = *(cast(uint*)encMessage.ptr);
    size_t off = 4;
    if (encMessage.length < off + wkl + ivLen + 1) {
        throw new CryptographicException("Invalid sealed message.");
    }
    ubyte[] wrappedKey = encMessage[off .. off + wkl].dup; off += wkl;
    ubyte[] iv = encMessage[off .. off + ivLen].dup; off += ivLen;
    immutable size_t tagLen = encMessage[off]; off += 1;
    if (encMessage.length < off + tagLen) {
        throw new CryptographicException("Invalid sealed message.");
    }
    ubyte[] tag = encMessage[off .. off + tagLen].dup; off += tagLen;
    ubyte[] ciphertext = encMessage[off .. $].dup;

    ubyte[] aesKey = opensslRsaDecryptWithHash(keypair, wrappedKey, hashAlgorithm);
    return decrypt_impl_openssl(ciphertext, null, aesKey, iv, tag, algorithm);
}

ubyte[] rsaGetPublicKey(RsaKey keypair) {
    BIO* bio = BIO_new(BIO_s_mem());

    PEM_write_bio_PUBKEY(bio, keypair);

    ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
    BIO_read(bio, buffer.ptr, cast(int)buffer.length);
    BIO_free_all(bio);

    return buffer;
}

ubyte[] rsaGetPrivateKey(RsaKey keypair, string password, int iterations, bool use3Des) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio is null) {
        throw new CryptographicException("Unable to create BIO for RSA private key export.");
    }
    scope(exit) BIO_free_all(bio);

    if (password is null) {
        if (PEM_write_bio_PKCS8PrivateKey(bio, keypair, null, null, 0, null, null) != 1) {
            throw new CryptographicException("Unable to write unencrypted RSA private key.");
        }
    } else {
        // PEM_write_bio_PKCS8PrivateKey always uses PKCS5_DEFAULT_ITER (2048).
        // Reject any other requested count so callers are not silently given a
        // weaker (or different) work factor than they asked for.
        if (iterations != PKCS5_DEFAULT_ITER) {
            throw new CryptographicException(
                "OpenSSL PKCS#8 private-key encryption only supports " ~
                to!string(PKCS5_DEFAULT_ITER) ~
                " PBKDF2 iterations (PKCS5_DEFAULT_ITER); requested " ~
                to!string(iterations) ~ ".");
        }
        ubyte[] pwd = cast(ubyte[])password;
        pwd = pwd ~ '\0';

        if (PEM_write_bio_PKCS8PrivateKey(
                bio,
                keypair,
                !use3Des ? EVP_aes_256_cbc() : EVP_des_ede3_cbc(),
                null,
                0,
                null,
                pwd.ptr) != 1) {
            throw new CryptographicException("Unable to write encrypted RSA private key.");
        }
    }

    if (BIO_ctrl_pending(bio) == 0) {
        throw new CryptographicException("No private key written.");
    }

    ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
    BIO_read(bio, buffer.ptr, cast(int)buffer.length);

    return buffer;
}

ubyte[] rsaEncrypt(RsaKey keypair, const ubyte[] inMessage) {
    // 42 is the padding overhead for OAEP padding using SHA-1.
    enforce(inMessage.length <= (EVP_PKEY_get_size(keypair) - 42), new CryptographicException("Plainttext length exceeds allowance"));

    EVP_PKEY_CTX *ctx;
    ENGINE *eng = null; // Use default RSA implementation
    ubyte *out2;
    const ubyte *in2 = inMessage.ptr;
    size_t outlen;
    size_t inlen = inMessage.length;

    ctx = EVP_PKEY_CTX_new(keypair, eng);
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

ubyte[] rsaDecrypt(RsaKey keypair, const ubyte[] inMessage) {
    EVP_PKEY_CTX *ctx;
    ENGINE *eng = null; // Use default RSA implementation
    ubyte *out2;
    const ubyte *in2 = inMessage.ptr;
    size_t outlen;
    size_t inlen = inMessage.length;

    ctx = EVP_PKEY_CTX_new(keypair, eng);
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

ubyte[] rsaSign(RsaKey keypair, ubyte[] data, bool useSha256) {
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

bool rsaVerify(RsaKey keypair, ubyte[] data, ubyte[] signature, bool useSha256) {
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
}

// ---------------------------------------------------------------------------
// Elliptic Curve
//
// The EC key context is an OpenSSL EVP_PKEY*. The public EllipticCurve class in
// secured.ecc holds one of these and forwards to these free functions.
// ---------------------------------------------------------------------------
alias EccKey = EVP_PKEY*;

private int getOpenSSLCurveId(EccCurve curve) {
    import std.conv;
    import std.format;

    switch (curve) {
        case EccCurve.P256: return NID_X9_62_prime256v1;
        case EccCurve.P384: return NID_secp384r1;
        case EccCurve.P521: return NID_secp521r1;
        default:
            throw new CryptographicException(format("ECC Curve '%s' not supported.", to!string(curve)));
    }
}

EccKey eccGenerate(EccCurve curve) {
    // Reseed the OpenSSL RNG to ensure randomness in threading/forking scenarios.
    ubyte[] seedbuf = random(32);
    RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

    // Generate the key parameters.
    EVP_PKEY_CTX* paramsctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null);
    if (paramsctx is null) {
        throw new CryptographicException("Cannot get an OpenSSL public key context.");
    }
    scope(exit) {
        if (paramsctx !is null)
            EVP_PKEY_CTX_free(paramsctx);
    }

    EVP_PKEY* params;
    if (EVP_PKEY_paramgen_init(paramsctx) < 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL public key context.");
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsctx, getOpenSSLCurveId(curve)) < 1) {
        throw new CryptographicException("Cannot set the requested curve.");
    }
    if (EVP_PKEY_paramgen(paramsctx, &params) < 1) {
        throw new CryptographicException("Unable to generate the key parameters.");
    }
    scope(exit) {
        if (params !is null)
            EVP_PKEY_free(params);
    }

    // Generate the public and private keys.
    EVP_PKEY_CTX* keyctx = EVP_PKEY_CTX_new(params, null);
    if (keyctx is null) {
        throw new CryptographicException("Cannot get an OpenSSL private key context.");
    }
    scope(exit) {
        if (keyctx !is null)
            EVP_PKEY_CTX_free(keyctx);
    }

    EVP_PKEY* key;
    if (EVP_PKEY_keygen_init(keyctx) < 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL private key context.");
    }
    if (EVP_PKEY_keygen(keyctx, &key) < 1) {
        throw new CryptographicException("Unable to generate the private key.");
    }

    return key;
}

EccKey eccLoadPrivateKey(string privateKey, string password) {
    ubyte[] seedbuf = random(32);
    RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

    ubyte[] pk = cast(ubyte[])privateKey;
    BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
    if (bio is null) {
        throw new CryptographicException("Unable to create BIO for EC private key.");
    }
    scope(exit) BIO_free_all(bio);

    EVP_PKEY* key;
    if (password is null) {
        key = PEM_read_bio_PrivateKey(bio, null, null, null);
    } else {
        ubyte[] pwd = cast(ubyte[])password;
        pwd = pwd ~ '\0';

        key = PEM_read_bio_PrivateKey(bio, null, null, pwd.ptr);
    }
    if (key is null) {
        throw new CryptographicException("Unable to load EC private key.");
    }
    return key;
}

EccKey eccLoadPublicKey(string publicKey) {
    ubyte[] seedbuf = random(32);
    RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

    ubyte[] pk = cast(ubyte[])publicKey;
    BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
    if (bio is null) {
        throw new CryptographicException("Unable to create BIO for EC public key.");
    }
    scope(exit) BIO_free_all(bio);

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, null, null, null);
    if (key is null) {
        throw new CryptographicException("Unable to load EC public key.");
    }
    return key;
}

void eccFree(EccKey key) {
    if (key !is null) {
        EVP_PKEY_free(key);
    }
}

ubyte[] eccDerive(EccKey key, string peerKey) {
    ubyte[] pk = cast(ubyte[])peerKey;
    BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
    EVP_PKEY* peer = PEM_read_bio_PUBKEY(bio, null, null, null);
    BIO_free_all(bio);
    if (peer is null) {
        throw new CryptographicException("Unable to read the peer public key.");
    }
    scope(exit) EVP_PKEY_free(peer);

    // Initialize the key derivation context.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, null);
    if (ctx is null) {
        throw new CryptographicException("Unable to create the key derivation context.");
    }
    scope(exit) EVP_PKEY_CTX_free(ctx);
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        throw new CryptographicException("Unable to initialize the key derivation context.");
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        throw new CryptographicException("Unable to set the peer key.");
    }

    // Derive the key.
    size_t dklen = 0;
    if (EVP_PKEY_derive(ctx, null, &dklen) <= 0) {
        throw new CryptographicException("Unable to determine the length of the derived key.");
    }
    ubyte[] derivedKey = new ubyte[dklen];
    if (EVP_PKEY_derive(ctx, derivedKey.ptr, &dklen) <= 0) {
        throw new CryptographicException("Unable to determine the length of the derived key.");
    }

    return derivedKey;
}

ubyte[] eccSign(EccKey key, ubyte[] data, bool useSha256) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx is null) {
        throw new CryptographicException("Unable to create the MD signing context.");
    }
    scope(exit) {
        if (mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    auto alg = (!useSha256 ? EVP_sha384() : EVP_sha256());

    if (EVP_DigestSignInit(mdctx, null, alg, null, key) != 1) {
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
        throw new CryptographicException("Unable to calculate signature.");
    }

    return sign[0 .. signlen];
}

bool eccVerify(EccKey key, ubyte[] data, ubyte[] signature, bool useSha256) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx is null) {
        throw new CryptographicException("Unable to create the MD verification context.");
    }
    scope(exit) {
        if (mdctx !is null) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    auto alg = (!useSha256 ? EVP_sha384() : EVP_sha256());

    if (EVP_DigestVerifyInit(mdctx, null, alg, null, key) != 1) {
        throw new CryptographicException("Unable to initialize the verification digest.");
    }
    if (EVP_DigestVerifyUpdate(mdctx, data.ptr, data.length) != 1) {
        throw new CryptographicException("Unable to set verify data.");
    }

    int ret = EVP_DigestVerifyFinal(mdctx, signature.ptr, signature.length);

    return ret == 1;
}

string eccGetPublicKey(EccKey key) {
    BIO* bio = BIO_new(BIO_s_mem());

    PEM_write_bio_PUBKEY(bio, key);

    ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
    BIO_read(bio, buffer.ptr, cast(int)buffer.length);
    BIO_free_all(bio);

    return cast(string)buffer;
}

string eccGetPrivateKey(EccKey key, string password, bool use3Des) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (password is null) {
        PEM_write_bio_PKCS8PrivateKey(bio, key, null, null, 0, null, null);
    } else {
        ubyte[] pwd = cast(ubyte[])password;
        pwd = pwd ~ '\0';

        PEM_write_bio_PKCS8PrivateKey(
            bio,
            key,
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

    return cast(string)buffer;
}

} // static if (usesOpenSSL)
