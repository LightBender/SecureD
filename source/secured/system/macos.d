module secured.system.macos;

/*
 * Apple CommonCrypto provider implementations.
 *
 * All CommonCrypto FFI for hashing, HMAC, PBKDF2 and symmetric encryption lives
 * here. This module is compiled only when CommonCrypto is the active provider
 * (macOS). The public dispatchers in the algorithm modules forward here.
 *
 * Only the public CommonCrypto API is used for symmetric primitives. RSA is
 * implemented against the public Security framework SecKey API; ECC on macOS is
 * handled by the OpenSSL polyfill (CommonCrypto's asymmetric API is SPI).
 */

import secured.provider;

static if (activeProvider == Provider.CommonCrypto) {

import std.stdio : File;
import std.exception : enforce;

import secured.bindings.commoncrypto;
import secured.bindings.security;
import secured.ecc : EccCurve;
import secured.hash : HashAlgorithm, getHashLength, unsupportedHashMessage;
import secured.mac : unsupportedHmacMessage;
import secured.kdf : unsupportedKdfMessage;
import secured.symmetric : SymmetricAlgorithm, isAeadCipher, getAuthLength, getCipherKeyLength, getCipherIVLength, unsupportedCipherMessage;
import secured.util : CryptographicException, AlgorithmNotSupportedException, FILE_BUFFER_SIZE;

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------
@safe package(secured) bool commonCryptoSupportsHash(HashAlgorithm func) {
    switch (func) {
        case HashAlgorithm.SHA2_256:
        case HashAlgorithm.SHA2_384:
        case HashAlgorithm.SHA2_512:
            return true;
        default:
            // SHA2_512_224, SHA2_512_256 and the SHA3 family are not provided by CommonCrypto.
            return false;
    }
}

@trusted package(secured) ubyte[] hash_impl_commoncrypto(const ubyte[] data, HashAlgorithm func) {
    ubyte[] digest = new ubyte[getHashLength(func)];
    switch (func) {
        case HashAlgorithm.SHA2_256: CC_SHA256(data.ptr, cast(uint)data.length, digest.ptr); break;
        case HashAlgorithm.SHA2_384: CC_SHA384(data.ptr, cast(uint)data.length, digest.ptr); break;
        case HashAlgorithm.SHA2_512: CC_SHA512(data.ptr, cast(uint)data.length, digest.ptr); break;
        default:
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
    }
    return digest;
}

@trusted package(secured) ubyte[] hash_impl_commoncrypto(string path, HashAlgorithm func) {
    auto fsfile = File(path, "rb");
    scope(exit) {
        if (fsfile.isOpen()) {
            fsfile.close();
        }
    }

    ubyte[] digest = new ubyte[getHashLength(func)];
    switch (func) {
        case HashAlgorithm.SHA2_256:
            CC_SHA256_CTX ctx256;
            CC_SHA256_Init(&ctx256);
            foreach (ubyte[] chunk; fsfile.byChunk(FILE_BUFFER_SIZE)) {
                CC_SHA256_Update(&ctx256, chunk.ptr, cast(uint)chunk.length);
            }
            CC_SHA256_Final(digest.ptr, &ctx256);
            break;
        case HashAlgorithm.SHA2_384:
            CC_SHA512_CTX ctx384;
            CC_SHA384_Init(&ctx384);
            foreach (ubyte[] chunk; fsfile.byChunk(FILE_BUFFER_SIZE)) {
                CC_SHA384_Update(&ctx384, chunk.ptr, cast(uint)chunk.length);
            }
            CC_SHA384_Final(digest.ptr, &ctx384);
            break;
        case HashAlgorithm.SHA2_512:
            CC_SHA512_CTX ctx512;
            CC_SHA512_Init(&ctx512);
            foreach (ubyte[] chunk; fsfile.byChunk(FILE_BUFFER_SIZE)) {
                CC_SHA512_Update(&ctx512, chunk.ptr, cast(uint)chunk.length);
            }
            CC_SHA512_Final(digest.ptr, &ctx512);
            break;
        default:
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
    }
    return digest;
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------
private CCHmacAlgorithm getCCHmacAlg(HashAlgorithm func) {
    switch (func) {
        case HashAlgorithm.SHA2_256: return kCCHmacAlgSHA256;
        case HashAlgorithm.SHA2_384: return kCCHmacAlgSHA384;
        case HashAlgorithm.SHA2_512: return kCCHmacAlgSHA512;
        default:
            throw new AlgorithmNotSupportedException(unsupportedHmacMessage(func));
    }
}

@trusted package(secured) ubyte[] hmac_impl_commoncrypto(const ubyte[] key, const ubyte[] data, HashAlgorithm func) {
    ubyte[] digest = new ubyte[getHashLength(func)];
    CCHmac(getCCHmacAlg(func), key.ptr, key.length, data.ptr, data.length, digest.ptr);
    return digest;
}

// ---------------------------------------------------------------------------
// PBKDF2
// ---------------------------------------------------------------------------
private CCPseudoRandomAlgorithm getCCPrf(HashAlgorithm func) {
    switch (func) {
        case HashAlgorithm.SHA2_256: return kCCPRFHmacAlgSHA256;
        case HashAlgorithm.SHA2_384: return kCCPRFHmacAlgSHA384;
        case HashAlgorithm.SHA2_512: return kCCPRFHmacAlgSHA512;
        default:
            throw new AlgorithmNotSupportedException(unsupportedKdfMessage("PBKDF2"));
    }
}

@trusted package(secured) ubyte[] pbkdf2_impl_commoncrypto(string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
    ubyte[] output = new ubyte[outputLen];
    if (CCKeyDerivationPBKDF(kCCPBKDF2, password.ptr, password.length, salt.ptr, salt.length, getCCPrf(func), iterations, output.ptr, outputLen) != kCCSuccess) {
        throw new CryptographicException("Unable to derive PBKDF2 key with CommonCrypto.");
    }
    return output;
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869)
//
// CommonCrypto exposes HMAC (CCHmac) but no standalone HKDF entry point, so the
// extract-and-expand construction is built directly on the CommonCrypto HMAC
// primitive (via hmac_impl_commoncrypto). Output is identical to any RFC 5869
// implementation for the same inputs.
// ---------------------------------------------------------------------------
@trusted package(secured) ubyte[] hkdf_impl_commoncrypto(const ubyte[] key, const ubyte[] salt, string info, size_t outputLen, HashAlgorithm func) {
    immutable size_t hashLen = getHashLength(func);

    // Extract: PRK = HMAC-Hash(salt, IKM). An empty salt defaults to hashLen zero bytes.
    const(ubyte)[] extractSalt = salt.length > 0 ? salt : new ubyte[hashLen];
    ubyte[] prk = hmac_impl_commoncrypto(extractSalt, key, func);

    // Expand: T(i) = HMAC-Hash(PRK, T(i-1) | info | i), OKM = T(1) | T(2) | ...
    ubyte[] infoBytes = cast(ubyte[])info;
    ubyte[] okm;
    ubyte[] previous;
    ubyte counter = 1;
    while (okm.length < outputLen) {
        ubyte[] input = previous ~ infoBytes ~ [counter];
        previous = hmac_impl_commoncrypto(prk, input, func);
        okm ~= previous;
        counter++;
    }
    return okm[0 .. outputLen];
}

// ---------------------------------------------------------------------------
// Symmetric ciphers (AES GCM one-shot; CBC/CTR/CFB via CCCryptor; ChaCha20 -> polyfill)
// ---------------------------------------------------------------------------
@safe package(secured) bool commonCryptoSupportsCipher(SymmetricAlgorithm algo) {
    switch (algo) {
        case SymmetricAlgorithm.AES128_GCM: case SymmetricAlgorithm.AES192_GCM: case SymmetricAlgorithm.AES256_GCM:
        case SymmetricAlgorithm.AES128_CBC: case SymmetricAlgorithm.AES192_CBC: case SymmetricAlgorithm.AES256_CBC:
        case SymmetricAlgorithm.AES128_CTR: case SymmetricAlgorithm.AES192_CTR: case SymmetricAlgorithm.AES256_CTR:
        case SymmetricAlgorithm.AES128_CFB: case SymmetricAlgorithm.AES192_CFB: case SymmetricAlgorithm.AES256_CFB:
            return true;
        default:
            // ChaCha20 and ChaCha20-Poly1305 are provided by the polyfill.
            return false;
    }
}

private CCMode getCCMode(SymmetricAlgorithm algo) {
    switch (algo) {
        case SymmetricAlgorithm.AES128_CBC: case SymmetricAlgorithm.AES192_CBC: case SymmetricAlgorithm.AES256_CBC: return kCCModeCBC;
        case SymmetricAlgorithm.AES128_CTR: case SymmetricAlgorithm.AES192_CTR: case SymmetricAlgorithm.AES256_CTR: return kCCModeCTR;
        case SymmetricAlgorithm.AES128_CFB: case SymmetricAlgorithm.AES192_CFB: case SymmetricAlgorithm.AES256_CFB: return kCCModeCFB;
        default: return kCCModeGCM;
    }
}

private CCPadding getCCPadding(SymmetricAlgorithm algo) {
    switch (algo) {
        case SymmetricAlgorithm.AES128_CBC: case SymmetricAlgorithm.AES192_CBC: case SymmetricAlgorithm.AES256_CBC: return ccPKCS7Padding;
        default: return ccNoPadding;
    }
}

private CCModeOptions getCCModeOptions(SymmetricAlgorithm algo) {
    switch (algo) {
        case SymmetricAlgorithm.AES128_CTR: case SymmetricAlgorithm.AES192_CTR: case SymmetricAlgorithm.AES256_CTR: return kCCModeOptionCTR_BE;
        default: return cast(CCModeOptions)0;
    }
}

@trusted package(secured) ubyte[] encrypt_impl_commoncrypto(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (isAeadCipher(algorithm)) {
        ubyte[] output = new ubyte[data.length];
        ubyte[] tag = new ubyte[getAuthLength(algorithm)];
        if (CCCryptorGCMOneshotEncrypt(kCCAlgorithmAES, encryptionKey.ptr, encryptionKey.length,
                iv.ptr, iv.length, associatedData.ptr, associatedData.length,
                data.ptr, data.length, output.ptr, tag.ptr, tag.length) != kCCSuccess) {
            throw new CryptographicException("Unable to encrypt data with CommonCrypto.");
        }
        authTag = tag;
        return output;
    } else {
        CCCryptorRef cryptor;
        if (CCCryptorCreateWithMode(kCCEncrypt, getCCMode(algorithm), kCCAlgorithmAES, getCCPadding(algorithm),
                iv.ptr, encryptionKey.ptr, encryptionKey.length, null, 0, 0, getCCModeOptions(algorithm), &cryptor) != kCCSuccess) {
            throw new CryptographicException("Unable to create the CommonCrypto cryptor.");
        }
        scope(exit) CCCryptorRelease(cryptor);

        ubyte[] output = new ubyte[data.length + 16];
        size_t moved1, moved2;
        if (CCCryptorUpdate(cryptor, data.ptr, data.length, output.ptr, output.length, &moved1) != kCCSuccess) {
            throw new CryptographicException("Unable to encrypt data with CommonCrypto.");
        }
        if (CCCryptorFinal(cryptor, output.ptr + moved1, output.length - moved1, &moved2) != kCCSuccess) {
            throw new CryptographicException("Unable to finalize CommonCrypto encryption.");
        }
        return output[0 .. moved1 + moved2];
    }
}

@trusted package(secured) ubyte[] decrypt_impl_commoncrypto(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
    if (isAeadCipher(algorithm)) {
        ubyte[] output = new ubyte[data.length];
        if (CCCryptorGCMOneshotDecrypt(kCCAlgorithmAES, encryptionKey.ptr, encryptionKey.length,
                iv.ptr, iv.length, associatedData.ptr, associatedData.length,
                data.ptr, data.length, output.ptr, authTag.ptr, authTag.length) != kCCSuccess) {
            throw new CryptographicException("Unable to decrypt data with CommonCrypto. The authentication tag may be invalid.");
        }
        return output;
    } else {
        CCCryptorRef cryptor;
        if (CCCryptorCreateWithMode(kCCDecrypt, getCCMode(algorithm), kCCAlgorithmAES, getCCPadding(algorithm),
                iv.ptr, encryptionKey.ptr, encryptionKey.length, null, 0, 0, getCCModeOptions(algorithm), &cryptor) != kCCSuccess) {
            throw new CryptographicException("Unable to create the CommonCrypto cryptor.");
        }
        scope(exit) CCCryptorRelease(cryptor);

        ubyte[] output = new ubyte[data.length + 16];
        size_t moved1, moved2;
        if (CCCryptorUpdate(cryptor, data.ptr, data.length, output.ptr, output.length, &moved1) != kCCSuccess) {
            throw new CryptographicException("Unable to decrypt data with CommonCrypto.");
        }
        if (CCCryptorFinal(cryptor, output.ptr + moved1, output.length - moved1, &moved2) != kCCSuccess) {
            throw new CryptographicException("Unable to finalize CommonCrypto decryption.");
        }
        return output[0 .. moved1 + moved2];
    }
}

// ---------------------------------------------------------------------------
// RSA (Security framework / SecKey)
//
// CommonCrypto's asymmetric API is SPI, so RSA on macOS is implemented against
// the public Security framework SecKey API instead. The RSA key context is a
// SecKeyRef (private when available, else public). The public RSA class in
// secured.rsa holds one of these and forwards here.
// ---------------------------------------------------------------------------
struct RsaKey {
    SecKeyRef key;
    bool hasPrivate;
}

// Container magic for the exported private key blob (SecureD macOS RSA).
private immutable ubyte[8] SD_MAC_RSA_MAGIC = ['S', 'D', 'M', 'A', 'C', 'R', 'S', 'A'];

@trusted private ubyte[] cfDataToBytes(CFDataRef data) {
    scope(exit) CFRelease(data);
    immutable len = cast(size_t)CFDataGetLength(data);
    const(ubyte)* ptr = CFDataGetBytePtr(data);
    ubyte[] result = new ubyte[len];
    result[] = ptr[0 .. len];
    return result;
}

@trusted private CFDataRef bytesToCFData(const ubyte[] bytes) {
    CFDataRef data = CFDataCreate(null, bytes.ptr, cast(CFIndex)bytes.length);
    if (data is null) {
        throw new CryptographicException("Unable to allocate a CFData buffer.");
    }
    return data;
}

@trusted private ubyte[] secRandom(size_t n) {
    ubyte[] buffer = new ubyte[n];
    if (SecRandomCopyBytes(kSecRandomDefault, n, buffer.ptr) != 0) {
        throw new CryptographicException("Unable to generate random bytes with the Security framework.");
    }
    return buffer;
}

@trusted private SecKeyRef secKeyPublic(RsaKey key) {
    if (key.hasPrivate) {
        SecKeyRef pub = SecKeyCopyPublicKey(key.key);
        if (pub is null) {
            throw new CryptographicException("Unable to derive the RSA public key.");
        }
        return pub;
    }
    return key.key;
}

@trusted private SecKeyRef secKeyLoad(const ubyte[] keyData, CFStringRef keyClass) {
    CFDataRef data = bytesToCFData(keyData);
    scope(exit) CFRelease(data);

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(null, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attrs is null) {
        throw new CryptographicException("Unable to allocate the RSA key attributes.");
    }
    scope(exit) CFRelease(attrs);

    CFDictionaryAddValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionaryAddValue(attrs, kSecAttrKeyClass, keyClass);

    CFErrorRef error;
    SecKeyRef key = SecKeyCreateWithData(data, attrs, &error);
    if (key is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to import the Security framework RSA key.");
    }
    return key;
}

@trusted package(secured) RsaKey rsaGenerate(int keylen) {
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(null, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params is null) {
        throw new CryptographicException("Unable to allocate the RSA key parameters.");
    }
    scope(exit) CFRelease(params);

    CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeRSA);

    int bits = keylen;
    CFNumberRef bitsNumber = CFNumberCreate(null, kCFNumberIntType, &bits);
    scope(exit) CFRelease(bitsNumber);
    CFDictionaryAddValue(params, kSecAttrKeySizeInBits, bitsNumber);

    CFErrorRef error;
    SecKeyRef key = SecKeyCreateRandomKey(params, &error);
    if (key is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to generate the Security framework RSA key pair.");
    }

    RsaKey result;
    result.key = key;
    result.hasPrivate = true;
    return result;
}

@trusted package(secured) RsaKey rsaLoadPublicKey(ubyte[] publicKey) {
    RsaKey result;
    result.key = secKeyLoad(publicKey, kSecAttrKeyClassPublic);
    result.hasPrivate = false;
    return result;
}

@trusted package(secured) RsaKey rsaLoadPrivateKey(ubyte[] privateKey, ubyte[] password) {
    if (privateKey.length < SD_MAC_RSA_MAGIC.length + 1 || privateKey[0 .. SD_MAC_RSA_MAGIC.length] != SD_MAC_RSA_MAGIC[]) {
        throw new CryptographicException("Invalid macOS RSA private key container.");
    }

    immutable ubyte flag = privateKey[SD_MAC_RSA_MAGIC.length];
    ubyte[] blob;
    if (flag == 0) {
        blob = privateKey[SD_MAC_RSA_MAGIC.length + 1 .. $].dup;
    } else if (flag == 1 || flag == 2) {
        // flag 1: fixed 25000 iterations (legacy). flag 2: iterations stored as LE uint32.
        if (password is null) {
            throw new CryptographicException("A password is required to load this private key.");
        }
        size_t off = SD_MAC_RSA_MAGIC.length + 1;
        uint iterations = 25000;
        if (flag == 2) {
            if (privateKey.length < off + 4) {
                throw new CryptographicException("Invalid macOS RSA private key container.");
            }
            iterations = privateKey[off] | (privateKey[off + 1] << 8) |
                (privateKey[off + 2] << 16) | (privateKey[off + 3] << 24);
            off += 4;
        }
        if (privateKey.length < off + 16 + 12 + 16) {
            throw new CryptographicException("Invalid macOS RSA private key container.");
        }
        ubyte[] salt = privateKey[off .. off + 16].dup; off += 16;
        ubyte[] iv   = privateKey[off .. off + 12].dup; off += 12;
        ubyte[] tag  = privateKey[off .. off + 16].dup; off += 16;
        ubyte[] ciphertext = privateKey[off .. $].dup;
        ubyte[] derived = pbkdf2_impl_commoncrypto(cast(string)password, salt, HashAlgorithm.SHA2_256, 32, iterations);
        blob = decrypt_impl_commoncrypto(ciphertext, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    } else {
        throw new CryptographicException("Invalid macOS RSA private key container.");
    }

    RsaKey result;
    result.key = secKeyLoad(blob, kSecAttrKeyClassPrivate);
    result.hasPrivate = true;
    return result;
}

@trusted package(secured) void rsaFree(RsaKey key) {
    if (key.key !is null) {
        CFRelease(key.key);
    }
}

@trusted package(secured) ubyte[] rsaGetPublicKey(RsaKey key) {
    SecKeyRef pub = secKeyPublic(key);
    scope(exit) { if (key.hasPrivate) CFRelease(pub); }

    CFErrorRef error;
    CFDataRef data = SecKeyCopyExternalRepresentation(pub, &error);
    if (data is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to export the RSA public key.");
    }
    return cfDataToBytes(data);
}

@trusted package(secured) ubyte[] rsaGetPrivateKey(RsaKey key, string password, int iterations, bool use3Des) {
    if (!key.hasPrivate) {
        return null;
    }

    CFErrorRef error;
    CFDataRef data = SecKeyCopyExternalRepresentation(key.key, &error);
    if (data is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to export the RSA private key.");
    }
    ubyte[] blob = cfDataToBytes(data);

    if (password is null) {
        return SD_MAC_RSA_MAGIC[] ~ cast(ubyte)0 ~ blob;
    }

    // The Security framework only exports unencrypted PKCS#1, so protect the
    // raw blob with AES-256-GCM under a PBKDF2-SHA256 derived key inside a
    // self-describing container. This mirrors the API's password contract.
    // flag 1 = legacy fixed 25000 iterations; flag 2 embeds a custom count.
    if (use3Des) {
        throw new CryptographicException(
            "use3Des is not supported by the CommonCrypto/Security backend; AES-256-GCM is used instead.");
    }
    if (iterations <= 0) {
        throw new CryptographicException("PBKDF2 iteration count must be positive.");
    }
    ubyte[] salt = secRandom(16);
    ubyte[] iv = secRandom(12);
    ubyte[] tag;
    ubyte[] derived = pbkdf2_impl_commoncrypto(password, salt, HashAlgorithm.SHA2_256, 32, cast(uint)iterations);
    ubyte[] ciphertext = encrypt_impl_commoncrypto(blob, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    if (iterations == 25000) {
        return SD_MAC_RSA_MAGIC[] ~ cast(ubyte)1 ~ salt ~ iv ~ tag ~ ciphertext;
    }
    ubyte[4] iterBytes = [
        cast(ubyte)(iterations),
        cast(ubyte)(iterations >> 8),
        cast(ubyte)(iterations >> 16),
        cast(ubyte)(iterations >> 24),
    ];
    return SD_MAC_RSA_MAGIC[] ~ cast(ubyte)2 ~ iterBytes[] ~ salt ~ iv ~ tag ~ ciphertext;
}

private SecKeyAlgorithm macOaepAlgorithm(HashAlgorithm hashAlgorithm) {
    // SHA-3 OAEP is not available through SecKey; SHA-2 family is.
    if (!commonCryptoSupportsHash(hashAlgorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }
    switch (hashAlgorithm) {
        case HashAlgorithm.SHA2_256: return kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
        case HashAlgorithm.SHA2_384: return kSecKeyAlgorithmRSAEncryptionOAEPSHA384;
        case HashAlgorithm.SHA2_512: return kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
        default:
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }
}

private size_t macOaepOverhead(HashAlgorithm hashAlgorithm) {
    return 2 * getHashLength(hashAlgorithm) + 2;
}

@trusted package(secured) ubyte[] rsaEncryptWithHash(RsaKey key, const ubyte[] inMessage, HashAlgorithm hashAlgorithm) {
    SecKeyRef pub = secKeyPublic(key);
    scope(exit) { if (key.hasPrivate) CFRelease(pub); }

    immutable size_t blockSize = SecKeyGetBlockSize(pub);
    immutable size_t overhead = macOaepOverhead(hashAlgorithm);
    enforce(inMessage.length <= (blockSize - overhead), new CryptographicException("Plainttext length exceeds allowance"));

    CFDataRef plain = bytesToCFData(inMessage);
    scope(exit) CFRelease(plain);

    CFErrorRef error;
    CFDataRef encrypted = SecKeyCreateEncryptedData(pub, macOaepAlgorithm(hashAlgorithm), plain, &error);
    if (encrypted is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to RSA-encrypt data with the Security framework.");
    }
    return cfDataToBytes(encrypted);
}

@trusted package(secured) ubyte[] rsaDecryptWithHash(RsaKey key, const ubyte[] inMessage, HashAlgorithm hashAlgorithm) {
    CFDataRef cipher = bytesToCFData(inMessage);
    scope(exit) CFRelease(cipher);

    CFErrorRef error;
    CFDataRef decrypted = SecKeyCreateDecryptedData(key.key, macOaepAlgorithm(hashAlgorithm), cipher, &error);
    if (decrypted is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to RSA-decrypt data with the Security framework.");
    }
    return cfDataToBytes(decrypted);
}

@trusted package(secured) ubyte[] rsaEncrypt(RsaKey key, const ubyte[] inMessage) {
    SecKeyRef pub = secKeyPublic(key);
    scope(exit) { if (key.hasPrivate) CFRelease(pub); }

    // Legacy direct RSA encrypt keeps OAEP-SHA1 for interop with existing data.
    // 42 bytes is the OAEP overhead for a SHA-1 label (2*20 + 2).
    immutable size_t blockSize = SecKeyGetBlockSize(pub);
    enforce(inMessage.length <= (blockSize - 42), new CryptographicException("Plainttext length exceeds allowance"));

    CFDataRef plain = bytesToCFData(inMessage);
    scope(exit) CFRelease(plain);

    CFErrorRef error;
    CFDataRef encrypted = SecKeyCreateEncryptedData(pub, kSecKeyAlgorithmRSAEncryptionOAEPSHA1, plain, &error);
    if (encrypted is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to RSA-encrypt data with the Security framework.");
    }
    return cfDataToBytes(encrypted);
}

@trusted package(secured) ubyte[] rsaDecrypt(RsaKey key, const ubyte[] inMessage) {
    CFDataRef cipher = bytesToCFData(inMessage);
    scope(exit) CFRelease(cipher);

    CFErrorRef error;
    CFDataRef decrypted = SecKeyCreateDecryptedData(key.key, kSecKeyAlgorithmRSAEncryptionOAEPSHA1, cipher, &error);
    if (decrypted is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to RSA-decrypt data with the Security framework.");
    }
    return cfDataToBytes(decrypted);
}

@trusted package(secured) ubyte[] rsaSeal(RsaKey key, const ubyte[] plaintext, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
    // Hybrid encryption: encrypt with the requested symmetric algorithm, then
    // RSA-OAEP wrap the session key using the selected hash.
    if (!commonCryptoSupportsCipher(algorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
    }
    if (!commonCryptoSupportsHash(hashAlgorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }

    immutable uint keyLen = getCipherKeyLength(algorithm);
    immutable uint ivLen = getCipherIVLength(algorithm);
    ubyte[] aesKey = secRandom(keyLen);
    ubyte[] iv = secRandom(ivLen);
    ubyte[] tag;
    ubyte[] ciphertext = encrypt_impl_commoncrypto(plaintext, null, aesKey, iv, tag, algorithm);
    ubyte[] wrappedKey = rsaEncryptWithHash(key, aesKey, hashAlgorithm);

    // Layout: [4-byte wrappedKeyLen][wrappedKey][iv][tagLen:1][tag][ciphertext]
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

@trusted package(secured) ubyte[] rsaOpen(RsaKey key, ubyte[] encMessage, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
    if (!commonCryptoSupportsCipher(algorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
    }
    if (!commonCryptoSupportsHash(hashAlgorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }

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

    ubyte[] aesKey = rsaDecryptWithHash(key, wrappedKey, hashAlgorithm);
    return decrypt_impl_commoncrypto(ciphertext, null, aesKey, iv, tag, algorithm);
}

@trusted package(secured) ubyte[] rsaSign(RsaKey key, ubyte[] data, bool useSha256) {
    SecKeyAlgorithm alg = useSha256
        ? kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
        : kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;

    CFDataRef toSign = bytesToCFData(data);
    scope(exit) CFRelease(toSign);

    CFErrorRef error;
    CFDataRef signature = SecKeyCreateSignature(key.key, alg, toSign, &error);
    if (signature is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to RSA-sign data with the Security framework.");
    }
    return cfDataToBytes(signature);
}

@trusted package(secured) bool rsaVerify(RsaKey key, ubyte[] data, ubyte[] signature, bool useSha256) {
    SecKeyRef pub = secKeyPublic(key);
    scope(exit) { if (key.hasPrivate) CFRelease(pub); }

    SecKeyAlgorithm alg = useSha256
        ? kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
        : kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;

    CFDataRef signedData = bytesToCFData(data);
    scope(exit) CFRelease(signedData);
    CFDataRef sig = bytesToCFData(signature);
    scope(exit) CFRelease(sig);

    CFErrorRef error;
    Boolean ok = SecKeyVerifySignature(pub, alg, signedData, sig, &error);
    if (error !is null) CFRelease(error);
    return ok != 0;
}

// ---------------------------------------------------------------------------
// Elliptic Curve (ECDSA + ECDH via the Security framework)
//
// The EC key context is a SecKeyRef (private when available, else public). Keys
// are serialised as ANSI X9.63 (SecKeyCopyExternalRepresentation) inside a
// self-describing container. The public EllipticCurve class in secured.ecc holds
// one of these and forwards here.
//
// EccCurve.P256/P384/P521 are the NIST prime curves (P-256/P-384/P-521) on every
// backend. Keys never cross providers in the test suite (each round-trips within
// its own provider).
// ---------------------------------------------------------------------------
struct EccKey {
    SecKeyRef key;
    EccCurve curve;
    bool hasPrivate;
}

private immutable ubyte[8] SD_MAC_ECC_PUB_MAGIC  = ['S', 'D', 'M', 'A', 'C', 'E', 'C', 'P'];
private immutable ubyte[8] SD_MAC_ECC_PRIV_MAGIC = ['S', 'D', 'M', 'A', 'C', 'E', 'C', 'K'];

private int eccCurveBits(EccCurve curve) {
    final switch (curve) {
        case EccCurve.P256: return 256;
        case EccCurve.P384: return 384;
        case EccCurve.P521: return 521;
    }
}

@trusted private SecKeyRef secEcLoad(const ubyte[] keyData, EccCurve curve, CFStringRef keyClass) {
    CFDataRef data = bytesToCFData(keyData);
    scope(exit) CFRelease(data);

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(null, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attrs is null) {
        throw new CryptographicException("Unable to allocate the EC key attributes.");
    }
    scope(exit) CFRelease(attrs);

    CFDictionaryAddValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(attrs, kSecAttrKeyClass, keyClass);

    int bits = eccCurveBits(curve);
    CFNumberRef bitsNumber = CFNumberCreate(null, kCFNumberIntType, &bits);
    scope(exit) CFRelease(bitsNumber);
    CFDictionaryAddValue(attrs, kSecAttrKeySizeInBits, bitsNumber);

    CFErrorRef error;
    SecKeyRef key = SecKeyCreateWithData(data, attrs, &error);
    if (key is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to import the Security framework EC key.");
    }
    return key;
}

@trusted package(secured) EccKey eccGenerate(EccCurve curve) {
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(null, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params is null) {
        throw new CryptographicException("Unable to allocate the EC key parameters.");
    }
    scope(exit) CFRelease(params);

    CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

    int bits = eccCurveBits(curve);
    CFNumberRef bitsNumber = CFNumberCreate(null, kCFNumberIntType, &bits);
    scope(exit) CFRelease(bitsNumber);
    CFDictionaryAddValue(params, kSecAttrKeySizeInBits, bitsNumber);

    CFErrorRef error;
    SecKeyRef key = SecKeyCreateRandomKey(params, &error);
    if (key is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to generate the Security framework EC key pair.");
    }

    EccKey result;
    result.key = key;
    result.curve = curve;
    result.hasPrivate = true;
    return result;
}

@trusted package(secured) EccKey eccLoadPrivateKey(string privateKey, string password) {
    ubyte[] data = cast(ubyte[])privateKey;
    if (data.length < SD_MAC_ECC_PRIV_MAGIC.length + 2 || data[0 .. SD_MAC_ECC_PRIV_MAGIC.length] != SD_MAC_ECC_PRIV_MAGIC[]) {
        throw new CryptographicException("Invalid macOS EC private key container.");
    }

    immutable ubyte flag = data[SD_MAC_ECC_PRIV_MAGIC.length];
    EccCurve curve = cast(EccCurve)data[SD_MAC_ECC_PRIV_MAGIC.length + 1];
    ubyte[] raw;
    if (flag == 0) {
        raw = data[SD_MAC_ECC_PRIV_MAGIC.length + 2 .. $].dup;
    } else {
        if (password is null) {
            throw new CryptographicException("A password is required to load this private key.");
        }
        size_t off = SD_MAC_ECC_PRIV_MAGIC.length + 2;
        ubyte[] salt = data[off .. off + 16].dup; off += 16;
        ubyte[] iv   = data[off .. off + 12].dup; off += 12;
        ubyte[] tag  = data[off .. off + 16].dup; off += 16;
        ubyte[] ciphertext = data[off .. $].dup;
        ubyte[] derived = pbkdf2_impl_commoncrypto(password, salt, HashAlgorithm.SHA2_256, 32, 25000);
        raw = decrypt_impl_commoncrypto(ciphertext, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    }

    EccKey key;
    key.key = secEcLoad(raw, curve, kSecAttrKeyClassPrivate);
    key.curve = curve;
    key.hasPrivate = true;
    return key;
}

@trusted package(secured) EccKey eccLoadPublicKey(string publicKey) {
    ubyte[] data = cast(ubyte[])publicKey;
    if (data.length < SD_MAC_ECC_PUB_MAGIC.length + 1 || data[0 .. SD_MAC_ECC_PUB_MAGIC.length] != SD_MAC_ECC_PUB_MAGIC[]) {
        throw new CryptographicException("Invalid macOS EC public key container.");
    }

    EccCurve curve = cast(EccCurve)data[SD_MAC_ECC_PUB_MAGIC.length];
    ubyte[] raw = data[SD_MAC_ECC_PUB_MAGIC.length + 1 .. $].dup;

    EccKey key;
    key.key = secEcLoad(raw, curve, kSecAttrKeyClassPublic);
    key.curve = curve;
    key.hasPrivate = false;
    return key;
}

@trusted package(secured) void eccFree(EccKey key) {
    if (key.key !is null) {
        CFRelease(key.key);
    }
}

@trusted package(secured) string eccGetPublicKey(EccKey key) {
    SecKeyRef pub = key.hasPrivate ? SecKeyCopyPublicKey(key.key) : key.key;
    scope(exit) { if (key.hasPrivate && pub !is null) CFRelease(pub); }
    if (pub is null) {
        throw new CryptographicException("Unable to derive the EC public key.");
    }

    CFErrorRef error;
    CFDataRef data = SecKeyCopyExternalRepresentation(pub, &error);
    if (data is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to export the EC public key.");
    }
    ubyte[] raw = cfDataToBytes(data);
    ubyte[] container = SD_MAC_ECC_PUB_MAGIC[] ~ cast(ubyte)key.curve ~ raw;
    return cast(string)container;
}

@trusted package(secured) string eccGetPrivateKey(EccKey key, string password, bool use3Des) {
    if (!key.hasPrivate) {
        return null;
    }

    CFErrorRef error;
    CFDataRef data = SecKeyCopyExternalRepresentation(key.key, &error);
    if (data is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to export the EC private key.");
    }
    ubyte[] raw = cfDataToBytes(data);

    if (password is null) {
        ubyte[] container = SD_MAC_ECC_PRIV_MAGIC[] ~ cast(ubyte)0 ~ cast(ubyte)key.curve ~ raw;
        return cast(string)container;
    }

    ubyte[] salt = secRandom(16);
    ubyte[] iv = secRandom(12);
    ubyte[] tag;
    ubyte[] derived = pbkdf2_impl_commoncrypto(password, salt, HashAlgorithm.SHA2_256, 32, 25000);
    ubyte[] ciphertext = encrypt_impl_commoncrypto(raw, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    ubyte[] container = SD_MAC_ECC_PRIV_MAGIC[] ~ cast(ubyte)1 ~ cast(ubyte)key.curve ~ salt ~ iv ~ tag ~ ciphertext;
    return cast(string)container;
}

@trusted package(secured) ubyte[] eccSign(EccKey key, ubyte[] data, bool useSha256) {
    SecKeyAlgorithm alg = useSha256
        ? kSecKeyAlgorithmECDSASignatureMessageX962SHA256
        : kSecKeyAlgorithmECDSASignatureMessageX962SHA384;

    CFDataRef toSign = bytesToCFData(data);
    scope(exit) CFRelease(toSign);

    CFErrorRef error;
    CFDataRef signature = SecKeyCreateSignature(key.key, alg, toSign, &error);
    if (signature is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to EC-sign data with the Security framework.");
    }
    return cfDataToBytes(signature);
}

@trusted package(secured) bool eccVerify(EccKey key, ubyte[] data, ubyte[] signature, bool useSha256) {
    SecKeyRef pub = key.hasPrivate ? SecKeyCopyPublicKey(key.key) : key.key;
    scope(exit) { if (key.hasPrivate && pub !is null) CFRelease(pub); }
    if (pub is null) {
        throw new CryptographicException("Unable to derive the EC public key.");
    }

    SecKeyAlgorithm alg = useSha256
        ? kSecKeyAlgorithmECDSASignatureMessageX962SHA256
        : kSecKeyAlgorithmECDSASignatureMessageX962SHA384;

    CFDataRef signedData = bytesToCFData(data);
    scope(exit) CFRelease(signedData);
    CFDataRef sig = bytesToCFData(signature);
    scope(exit) CFRelease(sig);

    CFErrorRef error;
    Boolean ok = SecKeyVerifySignature(pub, alg, signedData, sig, &error);
    if (error !is null) CFRelease(error);
    return ok != 0;
}

@trusted package(secured) ubyte[] eccDerive(EccKey key, string peerKey) {
    ubyte[] peerData = cast(ubyte[])peerKey;
    if (peerData.length < SD_MAC_ECC_PUB_MAGIC.length + 1 || peerData[0 .. SD_MAC_ECC_PUB_MAGIC.length] != SD_MAC_ECC_PUB_MAGIC[]) {
        throw new CryptographicException("Invalid macOS EC public key container.");
    }
    EccCurve peerCurve = cast(EccCurve)peerData[SD_MAC_ECC_PUB_MAGIC.length];
    ubyte[] peerRaw = peerData[SD_MAC_ECC_PUB_MAGIC.length + 1 .. $].dup;

    SecKeyRef peerPub = secEcLoad(peerRaw, peerCurve, kSecAttrKeyClassPublic);
    scope(exit) CFRelease(peerPub);

    CFErrorRef error;
    CFDataRef secret = SecKeyCopyKeyExchangeResult(key.key, kSecKeyAlgorithmECDHKeyExchangeStandard, peerPub, null, &error);
    if (secret is null) {
        if (error !is null) CFRelease(error);
        throw new CryptographicException("Unable to compute the Security framework ECDH secret.");
    }
    return cfDataToBytes(secret);
}

} // static if (activeProvider == Provider.CommonCrypto)
