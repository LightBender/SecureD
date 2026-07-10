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
import secured.symmetric : SymmetricAlgorithm, isAeadCipher, getAuthLength;
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
    } else {
        if (password is null) {
            throw new CryptographicException("A password is required to load this private key.");
        }
        size_t off = SD_MAC_RSA_MAGIC.length + 1;
        ubyte[] salt = privateKey[off .. off + 16].dup; off += 16;
        ubyte[] iv   = privateKey[off .. off + 12].dup; off += 12;
        ubyte[] tag  = privateKey[off .. off + 16].dup; off += 16;
        ubyte[] ciphertext = privateKey[off .. $].dup;
        ubyte[] derived = pbkdf2_impl_commoncrypto(cast(string)password, salt, HashAlgorithm.SHA2_256, 32, 25000);
        blob = decrypt_impl_commoncrypto(ciphertext, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
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

@trusted package(secured) ubyte[] rsaGetPrivateKey(RsaKey key, string password, bool use3Des) {
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
    ubyte[] salt = secRandom(16);
    ubyte[] iv = secRandom(12);
    ubyte[] tag;
    ubyte[] derived = pbkdf2_impl_commoncrypto(password, salt, HashAlgorithm.SHA2_256, 32, 25000);
    ubyte[] ciphertext = encrypt_impl_commoncrypto(blob, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    return SD_MAC_RSA_MAGIC[] ~ cast(ubyte)1 ~ salt ~ iv ~ tag ~ ciphertext;
}

@trusted package(secured) ubyte[] rsaEncrypt(RsaKey key, const ubyte[] inMessage) {
    SecKeyRef pub = secKeyPublic(key);
    scope(exit) { if (key.hasPrivate) CFRelease(pub); }

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

@trusted package(secured) ubyte[] rsaSeal(RsaKey key, const ubyte[] plaintext, SymmetricAlgorithm algorithm) {
    // Hybrid encryption: encrypt the data with a fresh AES-256-GCM key, then
    // RSA-OAEP wrap the AES key. AES-256-GCM is always used for the data leg
    // since the envelope is only ever opened by this same provider.
    ubyte[] aesKey = secRandom(32);
    ubyte[] iv = secRandom(12);
    ubyte[] tag;
    ubyte[] ciphertext = encrypt_impl_commoncrypto(plaintext, null, aesKey, iv, tag, SymmetricAlgorithm.AES256_GCM);
    ubyte[] wrappedKey = rsaEncrypt(key, aesKey);

    // Layout: [4-byte wrappedKeyLen][wrappedKey][12-byte iv][16-byte tag][ciphertext]
    uint wkl = cast(uint)wrappedKey.length;
    ubyte[] output;
    output ~= (cast(ubyte*)&wkl)[0 .. 4];
    output ~= wrappedKey;
    output ~= iv;
    output ~= tag;
    output ~= ciphertext;
    return output;
}

@trusted package(secured) ubyte[] rsaOpen(RsaKey key, ubyte[] encMessage, SymmetricAlgorithm algorithm) {
    if (encMessage.length < 4) {
        throw new CryptographicException("Invalid sealed message.");
    }
    uint wkl = *(cast(uint*)encMessage.ptr);
    size_t off = 4;
    if (encMessage.length < off + wkl + 12 + 16) {
        throw new CryptographicException("Invalid sealed message.");
    }
    ubyte[] wrappedKey = encMessage[off .. off + wkl].dup; off += wkl;
    ubyte[] iv = encMessage[off .. off + 12].dup; off += 12;
    ubyte[] tag = encMessage[off .. off + 16].dup; off += 16;
    ubyte[] ciphertext = encMessage[off .. $].dup;

    ubyte[] aesKey = rsaDecrypt(key, wrappedKey);
    return decrypt_impl_commoncrypto(ciphertext, null, aesKey, iv, tag, SymmetricAlgorithm.AES256_GCM);
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
