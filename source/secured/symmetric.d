module secured.symmetric;

import deimos.openssl.evp;

import secured.mac;
import secured.random;
import secured.util;

public enum KdfAlgorithm : ubyte {
    None,
    PBKDF2,
    SCrypt,
    PBKDF2_HKDF,
    SCrypt_HKDF,
    Default = SCrypt_HKDF,
}

public enum SymmetricAlgorithm : ubyte {
    AES128_GCM,
    AES128_CCM,
    AES128_CTR,
    AES128_OFB,
    AES128_CFB,
    AES128_CBC,
    AES192_GCM,
    AES192_CCM,
    AES192_CTR,
    AES192_OFB,
    AES192_CFB,
    AES192_CBC,
    AES256_GCM,
    AES256_CCM,
    AES256_CTR,
    AES256_OFB,
    AES256_CFB,
    AES256_CBC,
    Default = AES256_GCM,
}

private struct cryptoHeader {
    public ubyte v;             // The version of the header
    public ubyte sa;            // The Symmetric algorithm
    public ubyte ka;            // The KDF algorithm
    public ubyte ha;            // The Hash algorithm
    public uint n;              // The number of KDF iterations
    public ushort r;            // The amount SCrypt memory to use
    public ushort p;            // The SCrypt parallelism

    public ushort sc;           // The total number of sections
    public ushort sn;           // The section number
    public uint ss;             // The size of the current section

    public uint el;             // The length of the encrypted data
    public uint al;             // The length of the additional data
}

public ubyte[] encrypt(ubyte[] key, ubyte[] iv, ubyte[] data, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default) {
    ubyte[] output = new ubyte[data.length];

    //Get the OpenSSL cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx is null) {
        throw new CryptographicException("Cannot get an OpenSSL cipher context.");
    }
    scope(exit) {
        if (ctx !is null) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    //Initialize the cipher context
    if (EVP_EncryptInit_ex(ctx, getOpenSslCipher(algorithm), null, key.ptr, iv.ptr) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Write data to the cipher context
    int written = 0;
    int len = 0;
    if (EVP_EncryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    //Extract the complete ciphertext
    if (EVP_EncryptFinal_ex(ctx, &output[written-1], &len) != 1) {
        throw new CryptographicException("Unable to extract the ciphertext from the cipher context.");
    }
    written += len;

    return output;
}

public const(EVP_CIPHER*) getOpenSslCipher(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return EVP_aes_128_gcm();
        case SymmetricAlgorithm.AES192_GCM: return EVP_aes_192_gcm();
        case SymmetricAlgorithm.AES256_GCM: return EVP_aes_256_gcm();
        case SymmetricAlgorithm.AES128_CCM: return EVP_aes_128_ccm();
        case SymmetricAlgorithm.AES192_CCM: return EVP_aes_192_ccm();
        case SymmetricAlgorithm.AES256_CCM: return EVP_aes_256_ccm();
        case SymmetricAlgorithm.AES128_CTR: return EVP_aes_128_ctr();
        case SymmetricAlgorithm.AES192_CTR: return EVP_aes_192_ctr();
        case SymmetricAlgorithm.AES256_CTR: return EVP_aes_256_ctr();
        case SymmetricAlgorithm.AES128_CFB: return EVP_aes_128_cfb();
        case SymmetricAlgorithm.AES192_CFB: return EVP_aes_192_cfb();
        case SymmetricAlgorithm.AES256_CFB: return EVP_aes_256_cfb();
        case SymmetricAlgorithm.AES128_OFB: return EVP_aes_128_ofb();
        case SymmetricAlgorithm.AES192_OFB: return EVP_aes_192_ofb();
        case SymmetricAlgorithm.AES256_OFB: return EVP_aes_256_ofb();
        case SymmetricAlgorithm.AES128_CBC: return EVP_aes_128_cbc();
        case SymmetricAlgorithm.AES192_CBC: return EVP_aes_192_cbc();
        case SymmetricAlgorithm.AES256_CBC: return EVP_aes_256_cbc();
        default: return EVP_aes_256_gcm();
    }
}
