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
    public immutable ubyte[] iv;
    public immutable ubyte[] cipherText;
    public immutable ubyte[] authTag;

    private immutable SymmetricAlgorithm algorithm;
    private immutable HashAlgorithm hashAlgorithm;

    @safe public this(const string encoded, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
        this.algorithm = algorithm;
        this.hashAlgorithm = hashAlgorithm;
        this(Base64.decode(encoded), getCipherIVLength(algorithm), getAuthLength(algorithm, hashAlgorithm), algorithm, hashAlgorithm);
    }

    @trusted public this(const ubyte[] rawCiphertext, size_t ivLength, size_t authTagLength, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
        if (rawCiphertext.length <= ivLength + authTagLength)
            throw new CryptographicException("Incorrect ciphertext length");

        this.algorithm = algorithm;
        this.hashAlgorithm = hashAlgorithm;

        this.iv         = cast(immutable) rawCiphertext[0 .. ivLength];
        this.cipherText = cast(immutable) rawCiphertext[ivLength .. $-authTagLength];
        this.authTag    = cast(immutable) rawCiphertext[$-authTagLength .. $];
    }

    @trusted public this(const ubyte[] cipherText, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
        this.iv            = cast(immutable) iv;
        this.cipherText    = cast(immutable) cipherText;
        this.authTag       = cast(immutable) authTag;
        this.algorithm     = algorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public string toString() {
        return to!string(Base64.encode(iv ~ cipherText ~ authTag));
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
    key.algorithm = algorithm;
    if (kdf == KdfAlgorithm.SCrypt) {
        key.value = scrypt_ex(password, null, getCipherKeyLength(algorithm));
    } else if (kdf == KdfAlgorithm.PBKDF2) {
        key.value = pbkdf2_ex(password, null, HashAlgorithm.Default, getCipherKeyLength(algorithm), defaultKdfIterations);
    } else {
        throw new CryptographicException("Specified KDF '" ~ to!string(kdf) ~ "' is not supported.");
    }
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

pragma(inline) @safe private ubyte[] deriveKey(const ubyte[] key, uint bytes, const ubyte[] salt, HashAlgorithm hash = HashAlgorithm.Default) {
    return hkdf_ex(key, salt, string.init, bytes, hash);
}

@safe public EncryptedData encrypt(const SymmetricKey key, const ubyte[] data, const ubyte[] associatedData = null) {
    ubyte[] iv = random(getCipherIVLength(key.algorithm));
    ubyte[] derived = deriveKey(key.value, getCipherKeyLength(key.algorithm), iv);
    ubyte[] authTag;
    ubyte[] result = encrypt_ex(data, associatedData, derived, iv, authTag, key.algorithm);
    return EncryptedData(result, iv, authTag, key.algorithm);
}

@trusted public ubyte[] encrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
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
    } else {
        authTag = hmac(iv, hash(result) ~ hash(associatedData));
    }

    return result;
}

@safe public ubyte[] decrypt(const SymmetricKey key, const EncryptedData data, const ubyte[] associatedData = null) {
    if (data.algorithm != key.algorithm)
        throw new CryptographicException("Key and data algorithms don't match");
    ubyte[] derived = deriveKey(key.value, getCipherKeyLength(key.algorithm), data.iv);
    return decrypt_ex(data.cipherText, associatedData, derived, data.iv, data.authTag, key.algorithm);
}

@trusted public ubyte[] decrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    if (iv.length != getCipherIVLength(algorithm)) {
        throw new CryptographicException("IV must be " ~ to!string(getCipherIVLength(algorithm)) ~ " bytes in length.");
    }

    if (!isAeadCipher(algorithm) && !hmac_verify(authTag, iv, hash(data) ~ hash(associatedData))) {
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

    //Use the supplied tag to verify the message
    if (isAeadCipher(algorithm)) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, cast(int)authTag.length, (cast(ubyte[])authTag).ptr)) {
            throw new CryptographicException("Unable to set the authentication tag on the cipher context.");
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

@safe package uint getAuthLength(SymmetricAlgorithm symmetric, HashAlgorithm hash = HashAlgorithm.Default) {
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
    writeln("AuthTag: ", toHexString!(LetterCase.lower)(enc.authTag));

    writeln("Testing Decryption (No Additional Data)");
    writeln("Decryption Input:  ", toHexString!(LetterCase.lower)(enc.cipherText));
    ubyte[] dec = decrypt(key, enc);
    writeln("Decryption Output: ", cast(string)dec);

    assert((cast(string)dec) == cast(string)input);

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
    writeln("AuthTag: ", toHexString!(LetterCase.lower)(enc2.authTag));

    writeln("Testing Decryption (With Additional Data)");
    writeln("Decryption Input:  ", toHexString!(LetterCase.lower)(enc2.cipherText));
    writeln("Decryption AD: ", cast(string)ad);
    ubyte[] dec2 = decrypt(key, enc2, ad);
    writeln("Decryption Output: ", cast(string)dec2);

    assert((cast(string)dec2) == cast(string)input);

    writeln("Testing Non-AEAD Encryption (With Additional Data)");
    writeln("Encryption Input: ", cast(string)input);
    writeln("Encryption AD: ", cast(string)ad);
    SymmetricKey nonAeadKey = generateSymmetricKey(SymmetricAlgorithm.AES256_CBC);
    EncryptedData enc3 = encrypt(nonAeadKey, input, ad);
    writeln("Encryption Output: ", enc3);
    writeln("IV: ", toHexString!(LetterCase.lower)(enc3.iv));
    writeln("AuthTag: ", toHexString!(LetterCase.lower)(enc3.authTag));

    writeln("Testing Non-AEAD Decryption (With Additional Data)");
    writeln("Decryption Input:  ", enc3);
    writeln("Decryption AD: ", cast(string)ad);
    ubyte[] dec3 = decrypt(nonAeadKey, enc3, ad);
    writeln("Decryption Output: ", cast(string)dec3);

    assert((cast(string)dec3) == cast(string)input);
}
