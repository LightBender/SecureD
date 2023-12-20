module secured.symmetric;

import std.base64;
import std.conv;
import std.stdio;
import std.string;

import deimos.openssl.evp;

import secured.hash;
import secured.mac;
import secured.kdf;
import secured.random;
import secured.util;
import secured.openssl;

public enum SymmetricAlgorithm : ubyte {
    AES128_GCM,
    AES128_CTR,
    AES128_CFB,
    AES128_CBC,
    AES192_GCM,
    AES192_CTR,
    AES192_CFB,
    AES192_CBC,
    AES256_GCM,
    AES256_CTR,
    AES256_CFB,
    AES256_CBC,
    ChaCha20,
    ChaCha20_Poly1305,
    Default = AES256_GCM,
}

public immutable struct EncryptedData {
    public immutable ubyte[] cipherText;
    public immutable SymmetricMetadata metadata;

    @safe public this(const string encoded) {
        string[] parts = encoded.split("~");
        this.metadata = SymmetricMetadata(parts[0]);
        this.cipherText = Base64.decode(parts[1]);
    }

    @trusted public this(const ubyte[] cipherText, const SymmetricMetadata metadata) {
        this.cipherText = cast(immutable)cipherText;
        this.metadata = cast(immutable)metadata;
    }

    public string toString() {
        return metadata.toString() ~ "~" ~ to!string(Base64.encode(cipherText));
    }
}

public immutable struct SymmetricMetadata {
    private immutable ubyte[] keySalt;
    private immutable ubyte[] iv;
    private immutable ubyte[] authTag;

    @trusted public this(const string encoded) {
        string[] parts = encoded.split(".");
        this.keySalt = Base64.decode(parts[0]);
        this.iv = Base64.decode(parts[1]);
        this.authTag = Base64.decode(parts[2]);
    }

    @trusted private this(const ubyte[] keySalt, const ubyte[] iv, const ubyte[] authTag) {
        this.authTag = cast(immutable)authTag;
        this.keySalt = cast(immutable)keySalt;
        this.iv = cast(immutable)iv;
    }

    public string toString() {
        return to!string(Base64.encode(keySalt) ~ "." ~  Base64.encode(iv)  ~ "." ~  Base64.encode(authTag));
    }
}

public struct SymmetricKey {
    package ubyte[] value;
    package SymmetricAlgorithm algorithm;
    @disable this();

    public @property ubyte[] key() { return value; }

    public string toString() {
        return Base64.encode(value);
    }
}

@safe public SymmetricKey generateSymmetricKey(SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default) {
    SymmetricKey key = SymmetricKey.init;
    key.value = random(getCipherKeyLength(algorithm));
    key.algorithm = algorithm;
    return key;
}

@safe public SymmetricKey generateSymmetricKey(const string password, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, KdfAlgorithm kdf = KdfAlgorithm.Default) {
    SymmetricKey key = SymmetricKey.init;
    key.value = scrypt_ex(password, null, getCipherKeyLength(algorithm));
    key.algorithm = algorithm;
    return key;
}

@trusted public SymmetricKey initializeSymmetricKey(const ubyte[] bytes, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default) {
    if (bytes.length != (getCipherKeyLength(algorithm))) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    SymmetricKey key = SymmetricKey.init;
    key.value = cast(ubyte[])bytes;
    key.algorithm = algorithm;
    return key;
}

@safe public EncryptedData encrypt(const SymmetricKey key, const ubyte[] data, const ubyte[] associatedData = null) {
    KdfResult derived = deriveKey(key.value, getCipherKeyLength(key.algorithm) * 2, null, KdfAlgorithm.HKDF);
    ubyte[] iv = random(getCipherIVLength(key.algorithm));
    ubyte[] authTag;
    ubyte[] result = encrypt_ex(data, associatedData, derived.key[0..getCipherKeyLength(key.algorithm)], derived.key[getCipherKeyLength(key.algorithm)..$], iv, authTag, key.algorithm);
    return EncryptedData(result, SymmetricMetadata(derived.salt, iv, authTag));
}

@trusted public ubyte[] encrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] hmacKey, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
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
    if (EVP_EncryptInit_ex(ctx, getOpenSslCipher(algorithm), null, encryptionKey.ptr, iv.ptr) != 1) {
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
    if (EVP_EncryptFinal_ex(ctx, &output[written], &len) != 1) {
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
        authTag = hmac(hmacKey, hmac(hmacKey, result) ~ hmac(hmacKey, associatedData));
    }

    return result;
}

@safe public ubyte[] decrypt(const SymmetricKey key, const EncryptedData data, const ubyte[] associatedData = null) {
    return decrypt(key, data.cipherText, data.metadata, associatedData);
}

@safe public ubyte[] decrypt(const SymmetricKey key, const ubyte[] data, const SymmetricMetadata metadata, const ubyte[] associatedData = null) {
    KdfResult derived = deriveKey(key.value, getCipherKeyLength(key.algorithm) * 2, metadata.keySalt, KdfAlgorithm.HKDF);
    return decrypt_ex(data, associatedData, derived.key[0..getCipherKeyLength(key.algorithm)], derived.key[getCipherKeyLength(key.algorithm)..$], metadata.iv, metadata.authTag, key.algorithm);
}

@trusted public ubyte[] decrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] hmacKey, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    if (!isAeadCipher(algorithm) && hmacKey.length > 0 && hmacKey.length < 16) {
        throw new CryptographicException("Hash Key must be at least 16 bytes in length.");
    }
    if (iv.length != getCipherIVLength(algorithm)) {
        throw new CryptographicException("IV must be " ~ to!string(getCipherIVLength(algorithm)) ~ " bytes in length.");
    }

    if (!isAeadCipher(algorithm) && !hmac_verify(authTag, hmacKey, hmac(hmacKey, data) ~ hmac(hmacKey, associatedData))) {
        throw new CryptographicException("Failed to verify the authTag.");
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
    if (!EVP_DecryptInit_ex(ctx, getOpenSslCipher(algorithm), null, encryptionKey.ptr, iv.ptr)) {
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
    ubyte[] output = new ubyte[data.length + 32];
    if (!EVP_DecryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length)) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    //Use the supplied tag to verify the message
    if (isAeadCipher(algorithm)) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, cast(int)authTag.length, (cast(ubyte[])authTag).ptr)) {
            throw new CryptographicException("Unable to set the authentication tag on the cipher context.");
        }
    }

    //Extract the complete plaintext
    if (EVP_DecryptFinal_ex(ctx, &output[written], &len) <= 0) {
        throw new CryptographicException("Unable to extract the plaintext from the cipher context.");
    }
    written += len;

    return output[0..written];
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

    ubyte[] input = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";
    SymmetricKey key = initializeSymmetricKey([ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                                                0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ]);

    SymmetricKey generateTest = generateSymmetricKey();
	assert(generateTest.value.length == 32);
    SymmetricKey passwordTest = generateSymmetricKey("Test Password");
    writeln("Password Key: ", toHexString!(LetterCase.lower)(passwordTest.value));
	assert(toHexString!(LetterCase.lower)(passwordTest.value) == "76ae6c580be5e707a5cef313d2161899cd596c8c635671c9904602f8312cca34");

    writeln("Testing Encryption (No Additional Data)");
    writeln("Encryption Input: ", cast(string)input);
    EncryptedData enc = encrypt(key, input);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc.cipherText));
    writeln("AuthTag: ", toHexString!(LetterCase.lower)(enc.metadata.authTag));

    writeln("Testing Decryption (No Additional Data)");
    writeln("Decryption Input:  ", toHexString!(LetterCase.lower)(enc.cipherText));
    ubyte[] dec = decrypt(key, enc.cipherText, enc.metadata);
    writeln("Decryption Output: ", cast(string)dec);

    assert((cast(string)dec) == cast(string)input);

    writeln("Metadata Bytes: ", enc.metadata.toString());
    string encoded = enc.toString();
    writeln("Base64 Encoded: ", encoded);
    EncryptedData test = EncryptedData(encoded);
    ubyte[] eddec = decrypt(key, test);
    writeln("Decryption Output:  ", cast(string)eddec);
    assert((cast(string)eddec) == cast(string)input);

    ubyte[] ad = cast(ubyte[])"Associated Data";

    writeln("Testing Encryption (With Additional Data)");
    writeln("Encryption Input: ", cast(string)input);
    writeln("Encryption AD: ", cast(string)ad);
    EncryptedData enc2 = encrypt(key, input, ad);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc2.cipherText));
    writeln("AuthTag: ", toHexString!(LetterCase.lower)(enc2.metadata.authTag));

    writeln("Testing Decryption (With Additional Data)");
    writeln("Decryption Input:  ", toHexString!(LetterCase.lower)(enc2.cipherText));
    writeln("Decryption AD: ", cast(string)ad);
    ubyte[] dec2 = decrypt(key, enc2.cipherText, enc2.metadata, ad);
    writeln("Decryption Output: ", cast(string)dec2);

    assert((cast(string)dec2) == cast(string)input);

    writeln("Testing Non-AEAD Encryption (With Additional Data)");
    ubyte[] test4iv = random(getCipherIVLength(SymmetricAlgorithm.AES256_CBC));
    ubyte[] test4tag;
    writeln("Encryption Input: ", cast(string)input);
    writeln("Encryption AD: ", cast(string)ad);
    ubyte[] enc3 = encrypt_ex(input, ad, key.value, key.value, test4iv, test4tag, SymmetricAlgorithm.AES256_CBC);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc3));
    writeln("AuthTag: ", toHexString!(LetterCase.lower)(test4tag));

    writeln("Testing Non-AEAD Decryption (With Additional Data)");
    writeln("Decryption Input:  ", toHexString!(LetterCase.lower)(enc3));
    writeln("Decryption AD: ", cast(string)ad);
    ubyte[] dec3 = decrypt_ex(enc3, ad, key.value, key.value, test4iv, test4tag, SymmetricAlgorithm.AES256_CBC);
    writeln("Decryption Output: ", cast(string)dec3);

    assert((cast(string)dec3) == cast(string)input);
}
