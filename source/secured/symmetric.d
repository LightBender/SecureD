module secured.symmetric;

import std.base64;
import std.conv;
import std.stdio;
import std.string;

import secured.hash;
import secured.mac;
import secured.kdf;
import secured.provider;
import secured.random;
import secured.util;

static if (usesOpenSSL) {
    import secured.system.openssl : encrypt_impl_openssl, decrypt_impl_openssl;
}
static if (activeProvider == Provider.CNG) {
    import secured.system.windows : encrypt_impl_cng, decrypt_impl_cng, cngSupportsCipher;
}
static if (activeProvider == Provider.CommonCrypto) {
    import secured.system.macos : encrypt_impl_commoncrypto, decrypt_impl_commoncrypto, commonCryptoSupportsCipher;
}

/**
 * Symmetric ciphers supported by SecureD.
 *
 * The library default is $(D AES256_GCM): an AEAD mode that provides both
 * confidentiality and integrity, is ubiquitous in hardware and OS crypto APIs
 * (including Windows CNG), and is the recommended choice for new applications.
 * Non-AEAD modes (CTR/CFB/CBC/ChaCha20) are authenticated by SecureD with an
 * encrypt-then-MAC construction using HMAC over the default hash.
 *
 * ChaCha20-Poly1305 is a strong AEAD alternative where AES hardware is absent;
 * availability depends on the active provider (OpenSSL always; may need polyfill
 * on CNG/CommonCrypto).
 */
public enum SymmetricAlgorithm : ubyte {
    /// AES-128 in Galois/Counter Mode (AEAD).
    AES128_GCM,
    /// AES-128 in Counter mode (non-AEAD; encrypt-then-MAC applied).
    AES128_CTR,
    /// AES-128 in Cipher Feedback mode (non-AEAD; encrypt-then-MAC applied).
    AES128_CFB,
    /// AES-128 in Cipher Block Chaining mode (non-AEAD; encrypt-then-MAC applied).
    AES128_CBC,
    /// AES-192 in Galois/Counter Mode (AEAD).
    AES192_GCM,
    /// AES-192 in Counter mode (non-AEAD; encrypt-then-MAC applied).
    AES192_CTR,
    /// AES-192 in Cipher Feedback mode (non-AEAD; encrypt-then-MAC applied).
    AES192_CFB,
    /// AES-192 in Cipher Block Chaining mode (non-AEAD; encrypt-then-MAC applied).
    AES192_CBC,
    /// AES-256 in Galois/Counter Mode (AEAD); library default.
    AES256_GCM,
    /// AES-256 in Counter mode (non-AEAD; encrypt-then-MAC applied).
    AES256_CTR,
    /// AES-256 in Cipher Feedback mode (non-AEAD; encrypt-then-MAC applied).
    AES256_CFB,
    /// AES-256 in Cipher Block Chaining mode (non-AEAD; encrypt-then-MAC applied).
    AES256_CBC,
    /// ChaCha20 stream cipher (non-AEAD; encrypt-then-MAC applied).
    ChaCha20,
    /// ChaCha20 with Poly1305 AEAD.
    ChaCha20_Poly1305,
    /// Default cipher: AES-256-GCM (AEAD, ubiquitous, solid security).
    Default = AES256_GCM,
}

/**
 * Immutable container for encrypted payload components: IV, ciphertext, and
 * authentication tag.
 *
 * Wire format used by $(D toString) / Base64 constructor is
 * `iv || cipherText || authTag`.
 */
public immutable struct EncryptedData {
    /// Initialization vector / nonce used for this ciphertext.
    public immutable ubyte[] iv;
    /// Encrypted payload bytes.
    public immutable ubyte[] cipherText;
    /// AEAD tag or encrypt-then-MAC tag.
    public immutable ubyte[] authTag;

    private immutable SymmetricAlgorithm algorithm;
    private immutable HashAlgorithm hashAlgorithm;

    /**
     * Decodes a Base64 string produced by $(D toString) into IV, ciphertext, and
     * auth tag using the given algorithm sizes.
     *
     * Params:
     *   encoded       = Base64 of `iv || cipherText || authTag`.
     *   algorithm     = Cipher used when encrypting. Default:
     *                   $(D SymmetricAlgorithm.Default) (AES-256-GCM).
     *   hashAlgorithm = Hash used for non-AEAD MAC length. Default:
     *                   $(D HashAlgorithm.Default) (SHA2-384).
     *
     * Throws: $(D CryptographicException) if the decoded length is too short.
     */
    @safe public this(const string encoded, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
        this.algorithm = algorithm;
        this.hashAlgorithm = hashAlgorithm;
        this(Base64.decode(encoded), getCipherIVLength(algorithm), getAuthLength(algorithm, hashAlgorithm), algorithm, hashAlgorithm);
    }

    /**
     * Splits a raw concatenated buffer into IV, ciphertext, and auth tag.
     *
     * Params:
     *   rawCiphertext = Buffer laid out as `iv || cipherText || authTag`.
     *   ivLength      = Length of the IV prefix in bytes.
     *   authTagLength = Length of the auth-tag suffix in bytes.
     *   algorithm     = Cipher algorithm metadata. Default: AES-256-GCM.
     *   hashAlgorithm = Hash metadata for non-AEAD tags. Default: SHA2-384.
     *
     * Throws: $(D CryptographicException) if the buffer is too short.
     */
    @trusted public this(const ubyte[] rawCiphertext, size_t ivLength, size_t authTagLength, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
        if (rawCiphertext.length <= ivLength + authTagLength)
            throw new CryptographicException("Incorrect ciphertext length");

        this.algorithm = algorithm;
        this.hashAlgorithm = hashAlgorithm;

        this.iv         = cast(immutable) rawCiphertext[0 .. ivLength];
        this.cipherText = cast(immutable) rawCiphertext[ivLength .. $-authTagLength];
        this.authTag    = cast(immutable) rawCiphertext[$-authTagLength .. $];
    }

    /**
     * Constructs from separately supplied components.
     *
     * Params:
     *   cipherText    = Encrypted payload.
     *   iv            = Initialization vector / nonce.
     *   authTag       = Authentication tag.
     *   algorithm     = Cipher algorithm. Default: AES-256-GCM.
     *   hashAlgorithm = Hash for non-AEAD MAC metadata. Default: SHA2-384.
     */
    @trusted public this(const ubyte[] cipherText, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
        this.iv            = cast(immutable) iv;
        this.cipherText    = cast(immutable) cipherText;
        this.authTag       = cast(immutable) authTag;
        this.algorithm     = algorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Encodes this payload as Base64 of `iv || cipherText || authTag`.
     *
     * Returns: Base64 string suitable for storage or transport.
     */
    public string toString() {
        return to!string(Base64.encode(iv ~ cipherText ~ authTag));
    }
}

/**
 * Holds a symmetric encryption key and, when the key was derived from a
 * password, the random salt that was used during derivation.
 *
 * When `generateSymmetricKey(password, ...)` is used, the returned
 * `SymmetricKey.salt` value MUST be stored alongside the ciphertext (or other
 * long-term material). Without the same salt the password cannot be re-derived
 * into the same key and decryption will fail.
 */
public struct SymmetricKey {
    package ubyte[] value;
    package ubyte[] _salt;
    package SymmetricAlgorithm algorithm;
    @disable this();

    /// Raw key bytes (length depends on the associated cipher).
    public @property ubyte[] key() { return value; }
    /// Random salt used when this key was password-derived; empty for random keys.
    public @property ubyte[] salt() { return _salt; }

    /**
     * Base64-encodes the raw key bytes.
     *
     * Returns: Base64 representation of the key material.
     */
    public string toString() {
        return Base64.encode(value);
    }
}

/**
 * Generates a cryptographically random symmetric key for the given cipher.
 *
 * Params:
 *   algorithm = Target cipher. Default: $(D SymmetricAlgorithm.Default)
 *               (AES-256-GCM), chosen for AEAD security and universal provider
 *               support.
 *
 * Returns: $(D SymmetricKey) with random key material and empty salt.
 */
@safe public SymmetricKey generateSymmetricKey(SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default) {
    SymmetricKey key = SymmetricKey.init;
    key.value = random(getCipherKeyLength(algorithm));
    key.algorithm = algorithm;
    return key;
}

/**
 * Derives a symmetric key from a password using the selected KDF.
 *
 * A fresh random salt is generated and returned in `SymmetricKey.salt`. Callers
 * MUST persist that salt with any data encrypted under the resulting key; the
 * same password and salt are required to reconstruct the key later.
 *
 * Default KDF is scrypt (memory-hard). PBKDF2 uses SHA2-384 and
 * $(D defaultKdfIterations) (1_048_576). Salt length is 32 bytes.
 *
 * Params:
 *   password  = Password to derive from.
 *   algorithm = Target cipher (determines key length). Default: AES-256-GCM.
 *   kdf       = Key-derivation function. Default: $(D KdfAlgorithm.Default)
 *               (scrypt). Only SCrypt and PBKDF2 are accepted.
 *
 * Returns: $(D SymmetricKey) with derived key material and the random salt.
 *
 * Throws: $(D CryptographicException) if `kdf` is unsupported.
 */
@safe public SymmetricKey generateSymmetricKey(const string password, SymmetricAlgorithm algorithm = SymmetricAlgorithm.Default, KdfAlgorithm kdf = KdfAlgorithm.Default) {
    SymmetricKey key = SymmetricKey.init;
    key.algorithm = algorithm;
    // 32-byte salt matches the password-hashing helpers and is large enough for
    // both PBKDF2 and scrypt.
    key._salt = random(32);
    if (kdf == KdfAlgorithm.SCrypt) {
        key.value = scrypt_ex(password, key._salt, getCipherKeyLength(algorithm));
    } else if (kdf == KdfAlgorithm.PBKDF2) {
        key.value = pbkdf2_ex(password, key._salt, HashAlgorithm.Default, getCipherKeyLength(algorithm), defaultKdfIterations);
    } else {
        throw new CryptographicException("Specified KDF '" ~ to!string(kdf) ~ "' is not supported.");
    }
    return key;
}

/**
 * Wraps existing key bytes as a $(D SymmetricKey) for the given cipher.
 *
 * Params:
 *   bytes     = Exact key material; length must match the cipher key size
 *               (e.g. 32 bytes for AES-256).
 *   algorithm = Cipher the key will be used with. Default: AES-256-GCM.
 *
 * Returns: $(D SymmetricKey) referencing `bytes` (no salt).
 *
 * Throws: $(D CryptographicException) if `bytes.length` is wrong for `algorithm`.
 */
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

/**
 * Encrypts `data` under `key`, generating a fresh random IV and returning an
 * $(D EncryptedData) envelope (IV, ciphertext, auth tag).
 *
 * The session encryption key is derived from `key` via HKDF using the IV as
 * salt so each message uses unique key material. AEAD ciphers produce a native
 * tag; non-AEAD ciphers receive an encrypt-then-MAC tag.
 *
 * Params:
 *   key            = Symmetric key (algorithm is taken from the key).
 *   data           = Plaintext to encrypt.
 *   associatedData = Optional AAD bound into the AEAD/MAC (not encrypted).
 *                    Default: `null` (no AAD).
 *
 * Returns: $(D EncryptedData) containing IV, ciphertext, and authentication tag.
 *
 * Throws: $(D AlgorithmNotSupportedException) / $(D CryptographicException) on
 *         provider or parameter errors.
 */
@safe public EncryptedData encrypt(const SymmetricKey key, const ubyte[] data, const ubyte[] associatedData = null) {
    ubyte[] iv = random(getCipherIVLength(key.algorithm));
    ubyte[] derived = deriveKey(key.value, getCipherKeyLength(key.algorithm), iv);
    ubyte[] authTag;
    ubyte[] result = encrypt_ex(data, associatedData, derived, iv, authTag, key.algorithm);
    return EncryptedData(result, iv, authTag, key.algorithm);
}

package(secured) string unsupportedCipherMessage(SymmetricAlgorithm algorithm) {
    return "Symmetric algorithm '" ~ to!string(algorithm) ~ "' is not supported by the active cryptographic provider. Enable the 'polyfill' configuration to use OpenSSL as a fallback.";
}

/**
 * Low-level encrypt with caller-supplied key and IV.
 *
 * For non-AEAD algorithms, `authTag` is filled with an encrypt-then-MAC HMAC
 * over `iv || hash(ciphertext) || hash(associatedData)` using a MAC key derived
 * as `hash(encryptionKey)` so the public IV is never used as the HMAC secret.
 *
 * Params:
 *   data           = Plaintext to encrypt.
 *   associatedData = Optional AAD (may be `null`/empty).
 *   encryptionKey  = Raw key bytes; length must match `algorithm`.
 *   iv             = IV/nonce; length must match `algorithm`.
 *   authTag        = Output: AEAD tag or encrypt-then-MAC tag.
 *   algorithm      = Cipher to use.
 *
 * Returns: Ciphertext bytes (does not include IV or tag).
 *
 * Throws: $(D CryptographicException) for bad key/IV lengths;
 *         $(D AlgorithmNotSupportedException) if the cipher is unavailable.
 */
@trusted public ubyte[] encrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    if (iv.length != getCipherIVLength(algorithm)) {
        throw new CryptographicException("IV must be " ~ to!string(getCipherIVLength(algorithm)) ~ " bytes in length.");
    }

    ubyte[] result;
    static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
        result = encrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
    } else static if (activeProvider == Provider.CNG) {
        if (cngSupportsCipher(algorithm)) {
            result = encrypt_impl_cng(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else static if (polyfillEnabled) {
            result = encrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
        }
    } else static if (activeProvider == Provider.CommonCrypto) {
        if (commonCryptoSupportsCipher(algorithm)) {
            result = encrypt_impl_commoncrypto(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else static if (polyfillEnabled) {
            result = encrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
        }
    } else static if (polyfillEnabled) {
        result = encrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
    }

    // Non-AEAD ciphers are authenticated with encrypt-then-MAC.
    // The MAC key is derived from the secret encryption key; the IV is public
    // and must never be used as the HMAC secret. The IV is bound into the MAC
    // input so ciphertext/IV swaps are detected.
    if (!isAeadCipher(algorithm)) {
        ubyte[] macKey = hash(encryptionKey);
        authTag = hmac(macKey, iv ~ hash(result) ~ hash(associatedData));
    }

    return result;
}

/**
 * Decrypts an $(D EncryptedData) envelope under `key`.
 *
 * Re-derives the per-message key via HKDF (IV as salt), verifies the auth tag
 * (AEAD or encrypt-then-MAC), and returns the plaintext.
 *
 * Params:
 *   key            = Symmetric key used for encryption (algorithm must match).
 *   data           = Envelope from $(D encrypt).
 *   associatedData = Same AAD used during encryption, if any. Default: `null`.
 *
 * Returns: Decrypted plaintext.
 *
 * Throws: $(D CryptographicException) if algorithms mismatch, the tag fails, or
 *         decryption fails; $(D AlgorithmNotSupportedException) if unavailable.
 */
@safe public ubyte[] decrypt(const SymmetricKey key, const EncryptedData data, const ubyte[] associatedData = null) {
    if (data.algorithm != key.algorithm)
        throw new CryptographicException("Key and data algorithms don't match");
    ubyte[] derived = deriveKey(key.value, getCipherKeyLength(key.algorithm), data.iv);
    return decrypt_ex(data.cipherText, associatedData, derived, data.iv, data.authTag, key.algorithm);
}

/**
 * Low-level decrypt with caller-supplied key, IV, and auth tag.
 *
 * For non-AEAD algorithms the encrypt-then-MAC tag is verified before
 * decryption; failure throws without releasing plaintext.
 *
 * Params:
 *   data           = Ciphertext only (no IV/tag prefix).
 *   associatedData = Optional AAD used at encryption time.
 *   encryptionKey  = Raw key bytes; length must match `algorithm`.
 *   iv             = IV/nonce used at encryption time.
 *   authTag        = AEAD or encrypt-then-MAC tag to verify.
 *   algorithm      = Cipher used at encryption time.
 *
 * Returns: Decrypted plaintext.
 *
 * Throws: $(D CryptographicException) for bad lengths, failed MAC, or decrypt
 *         errors; $(D AlgorithmNotSupportedException) if unavailable.
 */
@trusted public ubyte[] decrypt_ex(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (encryptionKey.length != getCipherKeyLength(algorithm)) {
        throw new CryptographicException("Encryption Key must be " ~ to!string(getCipherKeyLength(algorithm)) ~ " bytes in length.");
    }
    if (iv.length != getCipherIVLength(algorithm)) {
        throw new CryptographicException("IV must be " ~ to!string(getCipherIVLength(algorithm)) ~ " bytes in length.");
    }

    if (!isAeadCipher(algorithm)) {
        ubyte[] macKey = hash(encryptionKey);
        if (!hmac_verify(authTag, macKey, iv ~ hash(data) ~ hash(associatedData))) {
            throw new CryptographicException("Failed to verify the authTag.");
        }
    }

    static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
        return decrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
    } else static if (activeProvider == Provider.CNG) {
        if (cngSupportsCipher(algorithm)) {
            return decrypt_impl_cng(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else static if (polyfillEnabled) {
            return decrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
        }
    } else static if (activeProvider == Provider.CommonCrypto) {
        if (commonCryptoSupportsCipher(algorithm)) {
            return decrypt_impl_commoncrypto(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else static if (polyfillEnabled) {
            return decrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
        } else {
            throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
        }
    } else static if (polyfillEnabled) {
        return decrypt_impl_openssl(data, associatedData, encryptionKey, iv, authTag, algorithm);
    } else {
        throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
    }
}

@safe package(secured) bool isAeadCipher(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return true;
        case SymmetricAlgorithm.AES192_GCM: return true;
        case SymmetricAlgorithm.AES256_GCM: return true;
        case SymmetricAlgorithm.ChaCha20_Poly1305: return true;
        default: return false;
    }
}

@safe package(secured) uint getCipherKeyLength(SymmetricAlgorithm algo) {
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

@safe package(secured) uint getCipherIVLength(SymmetricAlgorithm algo) {
    switch(algo) {
        case SymmetricAlgorithm.AES128_GCM: return 12;
        case SymmetricAlgorithm.AES192_GCM: return 12;
        case SymmetricAlgorithm.AES256_GCM: return 12;
        case SymmetricAlgorithm.ChaCha20: return 12;
        case SymmetricAlgorithm.ChaCha20_Poly1305: return 12;
        default: return 16;
    }
}

@safe package(secured) uint getAuthLength(SymmetricAlgorithm symmetric, HashAlgorithm hash = HashAlgorithm.Default) {
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
    skipIfUnsupported({
    import std.digest;
    import std.stdio;

    ubyte[] input = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";
    SymmetricKey key = initializeSymmetricKey([ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                                                0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ]);

    SymmetricKey generateTest = generateSymmetricKey();
	assert(generateTest.value.length == 32);
    SymmetricKey passwordTest = generateSymmetricKey("Test Password");
    writeln("Password Key: ", toHexString!(LetterCase.lower)(passwordTest.value));
    writeln("Password Salt: ", toHexString!(LetterCase.lower)(passwordTest.salt));
    // Password-derived keys must use a random salt; the same password+salt must
    // re-derive the same key. A fixed null-salt vector would be insecure.
    assert(passwordTest.salt.length == 32);
    assert(passwordTest.value == scrypt_ex("Test Password", passwordTest.salt, getCipherKeyLength(SymmetricAlgorithm.Default)));

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
    });
}
