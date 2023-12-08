module secured.symmetric;

import std.conv;

import deimos.openssl.evp;

import secured.hash;
import secured.mac;
import secured.kdf;
import secured.random;
import secured.util;
import secured.openssl;

public enum uint defaultKdfIterations = 1_048_576;
public enum ushort defaultSCryptR = 8;
public enum ushort defaultSCryptP = 1;
public enum ulong maxSCryptMemory = 4_294_967_296;

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
    AES128_CTR,
    AES128_OFB,
    AES128_CFB,
    AES128_CBC,
    AES192_GCM,
    AES192_CTR,
    AES192_OFB,
    AES192_CFB,
    AES192_CBC,
    AES256_GCM,
    AES256_CTR,
    AES256_OFB,
    AES256_CFB,
    AES256_CBC,
    ChaCha20,
    ChaCha20_Poly1305,
    Default = AES256_GCM,
}

public immutable struct SymmetricResult {
    public immutable ubyte[] cipherText;
    public immutable ubyte[] authTag;
    public immutable ubyte[] keySalt;
    public immutable ubyte[] iv;

    @trusted this(const ubyte[] cipherText, const ubyte[] authTag, const ubyte[] keySalt, const ubyte[] iv) {
        this.cipherText = cast(immutable)cipherText;
        this.authTag = cast(immutable)authTag;
        this.keySalt = cast(immutable)keySalt;
        this.iv = cast(immutable)iv;
    }
}

@safe public SymmetricResult encrypt(const ubyte[] data, const ubyte[] key) {
    KdfResult derived = deriveKey(key, null, getCipherKeyLength(SymmetricAlgorithm.Default) * 2, KdfAlgorithm.Default, defaultKdfIterations, defaultSCryptR, defaultSCryptP, HashAlgorithm.Default);
    ubyte[] iv = random(getCipherIVLength(SymmetricAlgorithm.Default));
    ubyte[] authTag;
    ubyte[] result = encrypt_ex(data, null, derived.key[0..getCipherKeyLength(SymmetricAlgorithm.Default)], derived.key[getCipherKeyLength(SymmetricAlgorithm.Default)..$], iv, SymmetricAlgorithm.Default, authTag);
    return SymmetricResult(result, authTag, derived.salt, iv) ;
}

@safe public SymmetricResult encrypt(const ubyte[] data, const ubyte[] associatedData, const ubyte[] key) {
    KdfResult derived = deriveKey(key, null, getCipherKeyLength(SymmetricAlgorithm.Default) * 2, KdfAlgorithm.Default, defaultKdfIterations, defaultSCryptR, defaultSCryptP, HashAlgorithm.Default);
    ubyte[] iv = random(getCipherIVLength(SymmetricAlgorithm.Default));
    ubyte[] authTag;
    ubyte[] result = encrypt_ex(data, associatedData, derived.key[0..getCipherKeyLength(SymmetricAlgorithm.Default)], derived.key[getCipherKeyLength(SymmetricAlgorithm.Default)..$], iv, SymmetricAlgorithm.Default, authTag);
    return SymmetricResult(result, authTag, derived.salt, iv) ;
}

@trusted public ubyte[] encrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] hmacKey, const ubyte[] iv, SymmetricAlgorithm algorithm, out ubyte[] authTag) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    if (!isAeadCipher(algorithm) && hmacKey.length > 0 && hmacKey.length < 16) {
        throw new CryptographicException("Hash Key must be at least 16 bytes in length.");
    }
    if (iv.length != getCipherIVLength(algorithm)) {
        throw new CryptographicException("IV must be " ~ to!string(getCipherIVLength(algorithm)) ~ " bytes in length.");
    }

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
    if (EVP_EncryptInit_ex(ctx, getOpenSslCipher(algorithm), null, null, null) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Initialize the AEAD context
    if (isAeadCipher(algorithm)) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, cast(int)iv.length, null) != 1) {
            throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
        }
    }

    //Set the Key and IV
    if (EVP_EncryptInit_ex(ctx, null, null, encryptionKey.ptr, iv.ptr) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Write the additional data to the cipher context, if any
    if (associatedData !is null && isAeadCipher(algorithm)) {
        int aadLen = 0;
        if (EVP_EncryptUpdate(ctx, null, &aadLen, associatedData.ptr, cast(int)associatedData.length) != 1) {
            throw new CryptographicException("Unable to write bytes to cipher context.");
        }
    }

    //Write data to the cipher context
    int written = 0;
    int len = 0;
    ubyte[] output = new ubyte[data.length + 32];
    if (EVP_EncryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    //Extract the complete ciphertext
    if (EVP_EncryptFinal_ex(ctx, &output[written-1], &len) != 1) {
        throw new CryptographicException("Unable to extract the ciphertext from the cipher context.");
    }
    written += len;

    ubyte[] result = output[0..written];

    //Extract the auth tag
    if (isAeadCipher(algorithm)) {
        ubyte[] _auth = new ubyte[getAuthLength(algorithm)];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, getAuthLength(algorithm), _auth.ptr) != 1) {
            throw new CryptographicException("Unable to extract the authentication tag from the cipher context.");
        }
        authTag = _auth;
    } else if (hmacKey.length > 0) {
        authTag = hmac(hmacKey, result ~ associatedData);
    }

    return result;
}
@safe public ubyte[] decrypt(const ubyte[] data, const ubyte[] key, const ubyte[] keySalt, const ubyte[] iv, const ubyte[] authTag) {
    KdfResult derived = deriveKey(key, keySalt, getCipherKeyLength(SymmetricAlgorithm.Default) * 2, KdfAlgorithm.Default, defaultKdfIterations, defaultSCryptR, defaultSCryptP, HashAlgorithm.Default);
    return decrypt_ex(data, null, derived.key[0..getCipherKeyLength(SymmetricAlgorithm.Default)], derived.key[getCipherKeyLength(SymmetricAlgorithm.Default)..$], iv, SymmetricAlgorithm.Default, authTag);
}

@safe public ubyte[] decrypt(const ubyte[] data, const ubyte[] associatedData, const ubyte[] key, const ubyte[] keySalt, const ubyte[] iv, const ubyte[] authTag) {
    KdfResult derived = deriveKey(key, keySalt, getCipherKeyLength(SymmetricAlgorithm.Default) * 2, KdfAlgorithm.Default, defaultKdfIterations, defaultSCryptR, defaultSCryptP, HashAlgorithm.Default);
    return decrypt_ex(data, associatedData, derived.key[0..getCipherKeyLength(SymmetricAlgorithm.Default)], derived.key[getCipherKeyLength(SymmetricAlgorithm.Default)..$], iv, SymmetricAlgorithm.Default, authTag);
}

@trusted public ubyte[] decrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] hmacKey, const ubyte[] iv, SymmetricAlgorithm algorithm, const ubyte[] authTag) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    if (!isAeadCipher(algorithm) && hmacKey.length > 0 && hmacKey.length < 16) {
        throw new CryptographicException("Hash Key must be at least 16 bytes in length.");
    }
    if (iv.length != getCipherIVLength(algorithm)) {
        throw new CryptographicException("IV must be " ~ to!string(getCipherIVLength(algorithm)) ~ " bytes in length.");
    }

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
    if (!EVP_DecryptInit_ex(ctx, getOpenSslCipher(algorithm), null, null, null)) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Initialize the AEAD context
    if (isAeadCipher(algorithm)) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, cast(int)iv.length, null)) {
            throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
        }
    }

    //Set the Key and IV
    if (!EVP_DecryptInit_ex(ctx, null, null, encryptionKey.ptr, iv.ptr)) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Write the additional data to the cipher context, if any
    if (associatedData.length != 0 && isAeadCipher(algorithm)) {
        int aadLen = 0;
        if (!EVP_DecryptUpdate(ctx, null, &aadLen, associatedData.ptr, cast(int)associatedData.length)) {
            throw new CryptographicException("Unable to write bytes to cipher context.");
        }
    }

    //Write data to the cipher context
    int written = 0;
    int len = 0;
    ubyte[] output = new ubyte[data.length];
    if (!EVP_DecryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length)) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    //Use the supplied tag to verify the message
    if (isAeadCipher(algorithm)) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, cast(int)authTag.length, (cast(ubyte[])authTag).ptr)) {
            throw new CryptographicException("Unable to extract the authentication tag from the cipher context.");
        }
    }

    //Extract the complete plaintext
    if (EVP_DecryptFinal_ex(ctx, &output[written-1], &len) <= 0) {
        throw new CryptographicException("Unable to extract the plaintext from the cipher context.");
    }
    written += len;

    ubyte[] result = output[0..written];

    if (!isAeadCipher(algorithm) && !hmac_verify(authTag, hmacKey, result ~ associatedData)) {
        throw new CryptographicException("Failed to verify the authTag.");
    }

    return result;
}

@trusted private KdfResult deriveKey(const ubyte[] key, const ubyte[] salt, uint bytes, KdfAlgorithm kdf, uint n, ushort r, ushort p, HashAlgorithm hash) {
    ubyte[] derivedKey;
    ubyte[] _salt = salt is null ? random(getHashLength(hash)) : cast(ubyte[])salt;

    if (kdf == KdfAlgorithm.PBKDF2) {
        derivedKey = pbkdf2_ex(to!string(key), _salt, hash, bytes, n);
    }
    if (kdf == KdfAlgorithm.PBKDF2_HKDF) {
        derivedKey = pbkdf2_ex(to!string(key), _salt, hash, bytes, n);
        derivedKey = hkdf_ex(derivedKey, _salt, string.init, bytes, hash);
    }
    if (kdf == KdfAlgorithm.SCrypt) {
        derivedKey = scrypt_ex(key, _salt, n, r, p, maxSCryptMemory,bytes);
    }
    if (kdf == KdfAlgorithm.SCrypt_HKDF) {
        derivedKey = scrypt_ex(key, _salt, n, r, p, maxSCryptMemory, bytes);
        derivedKey = hkdf_ex(derivedKey, _salt, string.init, bytes, hash);
    }
    return KdfResult(_salt, derivedKey);
}

@trusted package const(EVP_CIPHER*) getOpenSslCipher(SymmetricAlgorithm algo) {
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
        case SymmetricAlgorithm.AES128_OFB: return EVP_aes_128_ofb();
        case SymmetricAlgorithm.AES192_OFB: return EVP_aes_192_ofb();
        case SymmetricAlgorithm.AES256_OFB: return EVP_aes_256_ofb();
        case SymmetricAlgorithm.AES128_CBC: return EVP_aes_128_cbc();
        case SymmetricAlgorithm.AES192_CBC: return EVP_aes_192_cbc();
        case SymmetricAlgorithm.AES256_CBC: return EVP_aes_256_cbc();
        case SymmetricAlgorithm.ChaCha20: return EVP_chacha20();
        case SymmetricAlgorithm.ChaCha20_Poly1305: return EVP_chacha20_poly1305();
        default: return EVP_aes_256_gcm();
    }
}

@safe package bool isAeadCipher(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return true;
        case SymmetricAlgorithm.AES192_GCM: return true;
        case SymmetricAlgorithm.AES256_GCM: return true;
        case SymmetricAlgorithm.ChaCha20_Poly1305: return true;
        default: return false;
    }
}

@safe package uint getCipherKeyLength(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return 16;
        case SymmetricAlgorithm.AES192_GCM: return 24;
        case SymmetricAlgorithm.AES256_GCM: return 32;
        case SymmetricAlgorithm.AES128_CTR: return 16;
        case SymmetricAlgorithm.AES192_CTR: return 24;
        case SymmetricAlgorithm.AES256_CTR: return 32;
        case SymmetricAlgorithm.AES128_CFB: return 16;
        case SymmetricAlgorithm.AES192_CFB: return 24;
        case SymmetricAlgorithm.AES256_CFB: return 32;
        case SymmetricAlgorithm.AES128_OFB: return 16;
        case SymmetricAlgorithm.AES192_OFB: return 24;
        case SymmetricAlgorithm.AES256_OFB: return 32;
        case SymmetricAlgorithm.AES128_CBC: return 16;
        case SymmetricAlgorithm.AES192_CBC: return 24;
        case SymmetricAlgorithm.AES256_CBC: return 32;
        case SymmetricAlgorithm.ChaCha20: return 32;
        case SymmetricAlgorithm.ChaCha20_Poly1305: return 32;
        default: return 16;
    }
}

@safe package uint getCipherIVLength(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return 12;
        case SymmetricAlgorithm.AES192_GCM: return 12;
        case SymmetricAlgorithm.AES256_GCM: return 12;
        case SymmetricAlgorithm.ChaCha20: return 12;
        case SymmetricAlgorithm.ChaCha20_Poly1305: return 12;
        default: return 16;
    }
}

@safe package uint getAuthLength(SymmetricAlgorithm symmetric, HashAlgorithm hash = HashAlgorithm.None) {
    switch(symmetric) {
        case SymmetricAlgorithm.AES128_GCM: return 16;
        case SymmetricAlgorithm.AES192_GCM: return 16;
        case SymmetricAlgorithm.AES256_GCM: return 16;
        case SymmetricAlgorithm.ChaCha20_Poly1305: return 16;
        default: return getHashLength(hash);
    }
}

unittest
{
    import std.digest;
    import std.stdio;
    immutable string input = "The quick brown fox jumps over the lazy dog.";
    immutable ubyte[32] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                                0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    writeln("Testing Encryption (No Additional Data)");
    SymmetricResult enc = encrypt(cast(ubyte[])input, key);
    writeln("Encryption Input: ", input);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc.cipherText));

    writeln("Testing Decryption (No Additional Data)");
    ubyte[] dec = decrypt(enc.cipherText, key, enc.keySalt, enc.iv, enc.authTag);
    writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc.cipherText));
    writeln("Decryption Output: ", cast(string)dec);

    assert((cast(string)dec) == input);

	ubyte[] ad = cast(ubyte[])"Additional Data";

    writeln("Testing Encryption (With Additional Data)");
    SymmetricResult enc2 = encrypt(cast(ubyte[])input, cast(ubyte[])ad, key);
    writeln("Encryption Input: ", input);
    writeln("Encryption AD: ", cast(string)ad);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc2.cipherText));

    writeln("Testing Decryption (With Additional Data)");
    ubyte[] dec2 = decrypt(enc2.cipherText, ad, key, enc2.keySalt, enc2.iv, enc2.authTag);
    writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc2.cipherText));
    writeln("Decryption AD: ", cast(string)ad);
    writeln("Decryption Output: ", cast(string)dec2);

    assert((cast(string)dec2) == input);
}
