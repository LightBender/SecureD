module secured.system.windows;

/*
 * Windows CNG (bcrypt) provider implementations.
 *
 * All CNG FFI for hashing, HMAC, PBKDF2 and symmetric encryption lives here.
 * This module is compiled only when CNG is the active provider (Windows). The
 * public dispatchers in the algorithm modules forward here.
 */

import secured.provider;

static if (activeProvider == Provider.CNG) {

import core.sys.windows.windows : PUCHAR, ULONG;
import std.exception : enforce;
import std.stdio : File;

import secured.bindings.cng;
import secured.ecc : EccCurve;
import secured.hash : HashAlgorithm, getHashLength, unsupportedHashMessage;
import secured.symmetric : SymmetricAlgorithm, isAeadCipher, getAuthLength, getCipherKeyLength, getCipherIVLength, unsupportedCipherMessage;
import secured.util : CryptographicException, AlgorithmNotSupportedException, FILE_BUFFER_SIZE;

// ---------------------------------------------------------------------------
// Hash / HMAC / PBKDF2 algorithm support
// ---------------------------------------------------------------------------
package(secured) const(wchar)* getCngHashAlgId(HashAlgorithm func) {
    switch (func) {
        case HashAlgorithm.SHA2_256: return BCRYPT_SHA256_ALGORITHM.ptr;
        case HashAlgorithm.SHA2_384: return BCRYPT_SHA384_ALGORITHM.ptr;
        case HashAlgorithm.SHA2_512: return BCRYPT_SHA512_ALGORITHM.ptr;
        case HashAlgorithm.SHA3_256: return BCRYPT_SHA3_256_ALGORITHM.ptr;
        case HashAlgorithm.SHA3_384: return BCRYPT_SHA3_384_ALGORITHM.ptr;
        case HashAlgorithm.SHA3_512: return BCRYPT_SHA3_512_ALGORITHM.ptr;
        default:
            throw new AlgorithmNotSupportedException(unsupportedHashMessage(func));
    }
}

// CNG only gained SHA-3 support in Windows 11 24H2 / Server 2025. Probe once at
// runtime and cache the result so callers on older Windows fall back or throw.
@trusted private bool cngSha3Available() {
    import core.atomic;
    static shared int cached = 0; // 0 = unknown, 1 = available, 2 = unavailable
    immutable c = atomicLoad(cached);
    if (c != 0) {
        return c == 1;
    }

    BCRYPT_ALG_HANDLE hAlg;
    immutable bool ok = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA3_256_ALGORITHM.ptr, null, 0) == STATUS_SUCCESS;
    if (ok) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    atomicStore(cached, ok ? 1 : 2);
    return ok;
}

@trusted package(secured) bool cngSupportsHash(HashAlgorithm func) {
    switch (func) {
        case HashAlgorithm.SHA2_256:
        case HashAlgorithm.SHA2_384:
        case HashAlgorithm.SHA2_512:
            return true;
        case HashAlgorithm.SHA3_256:
        case HashAlgorithm.SHA3_384:
        case HashAlgorithm.SHA3_512:
            return cngSha3Available();
        default:
            // SHA2_512_224, SHA2_512_256 and SHA3_224 are not provided by CNG.
            return false;
    }
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------
@trusted package(secured) ubyte[] hash_impl_cng(const ubyte[] data, HashAlgorithm func) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, getCngHashAlgId(func), null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG hash algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    BCRYPT_HASH_HANDLE hHash;
    if (BCryptCreateHash(hAlg, &hHash, null, 0, null, 0, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to create the CNG hash object.");
    }
    scope(exit) BCryptDestroyHash(hHash);

    if (data.length > 0 && BCryptHashData(hHash, cast(PUCHAR)data.ptr, cast(ULONG)data.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to hash data with CNG.");
    }

    ubyte[] digest = new ubyte[getHashLength(func)];
    if (BCryptFinishHash(hHash, digest.ptr, cast(ULONG)digest.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to finalize the CNG hash.");
    }
    return digest;
}

@trusted package(secured) ubyte[] hash_impl_cng(string path, HashAlgorithm func) {
    auto fsfile = File(path, "rb");
    scope(exit) {
        if (fsfile.isOpen()) {
            fsfile.close();
        }
    }

    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, getCngHashAlgId(func), null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG hash algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    BCRYPT_HASH_HANDLE hHash;
    if (BCryptCreateHash(hAlg, &hHash, null, 0, null, 0, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to create the CNG hash object.");
    }
    scope(exit) BCryptDestroyHash(hHash);

    foreach (ubyte[] chunk; fsfile.byChunk(FILE_BUFFER_SIZE)) {
        if (chunk.length > 0 && BCryptHashData(hHash, cast(PUCHAR)chunk.ptr, cast(ULONG)chunk.length, 0) != STATUS_SUCCESS) {
            throw new CryptographicException("Unable to hash data with CNG.");
        }
    }

    ubyte[] digest = new ubyte[getHashLength(func)];
    if (BCryptFinishHash(hHash, digest.ptr, cast(ULONG)digest.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to finalize the CNG hash.");
    }
    return digest;
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------
@trusted package(secured) ubyte[] hmac_impl_cng(const ubyte[] key, const ubyte[] data, HashAlgorithm func) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, getCngHashAlgId(func), null, BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG HMAC algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    BCRYPT_HASH_HANDLE hHash;
    if (BCryptCreateHash(hAlg, &hHash, null, 0, cast(PUCHAR)key.ptr, cast(ULONG)key.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to create the CNG HMAC object.");
    }
    scope(exit) BCryptDestroyHash(hHash);

    if (data.length > 0 && BCryptHashData(hHash, cast(PUCHAR)data.ptr, cast(ULONG)data.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to HMAC data with CNG.");
    }

    ubyte[] digest = new ubyte[getHashLength(func)];
    if (BCryptFinishHash(hHash, digest.ptr, cast(ULONG)digest.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to finalize the CNG HMAC.");
    }
    return digest;
}

// ---------------------------------------------------------------------------
// PBKDF2
// ---------------------------------------------------------------------------
@trusted package(secured) ubyte[] pbkdf2_impl_cng(string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, getCngHashAlgId(func), null, BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG PBKDF2 PRF provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    ubyte[] output = new ubyte[outputLen];
    if (BCryptDeriveKeyPBKDF2(hAlg, cast(PUCHAR)password.ptr, cast(ULONG)password.length,
            cast(PUCHAR)salt.ptr, cast(ULONG)salt.length, iterations, output.ptr, cast(ULONG)output.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to derive PBKDF2 key with CNG.");
    }
    return output;
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869)
//
// CNG's BCRYPT_HKDF provider requires a fragile property-ordering dance for the
// info parameter, so the extract-and-expand construction is built directly on
// the CNG HMAC primitive (via hmac_impl_cng) instead. Output is identical to any
// RFC 5869 implementation for the same inputs.
// ---------------------------------------------------------------------------
@trusted package(secured) ubyte[] hkdf_impl_cng(const ubyte[] key, const ubyte[] salt, string info, size_t outputLen, HashAlgorithm func) {
    immutable size_t hashLen = getHashLength(func);

    // Extract: PRK = HMAC-Hash(salt, IKM). An empty salt defaults to hashLen zero bytes.
    const(ubyte)[] extractSalt = salt.length > 0 ? salt : new ubyte[hashLen];
    ubyte[] prk = hmac_impl_cng(extractSalt, key, func);

    // Expand: T(i) = HMAC-Hash(PRK, T(i-1) | info | i), OKM = T(1) | T(2) | ...
    ubyte[] infoBytes = cast(ubyte[])info;
    ubyte[] okm;
    ubyte[] previous;
    ubyte counter = 1;
    while (okm.length < outputLen) {
        ubyte[] input = previous ~ infoBytes ~ [counter];
        previous = hmac_impl_cng(prk, input, func);
        okm ~= previous;
        counter++;
    }
    return okm[0 .. outputLen];
}

// ---------------------------------------------------------------------------
// Symmetric ciphers (AES-GCM / AES-CBC; CTR/CFB/ChaCha20 -> polyfill)
// ---------------------------------------------------------------------------
@safe package(secured) bool cngSupportsCipher(SymmetricAlgorithm algo) {
    switch (algo) {
        case SymmetricAlgorithm.AES128_GCM:
        case SymmetricAlgorithm.AES192_GCM:
        case SymmetricAlgorithm.AES256_GCM:
        case SymmetricAlgorithm.AES128_CBC:
        case SymmetricAlgorithm.AES192_CBC:
        case SymmetricAlgorithm.AES256_CBC:
            return true;
        default:
            // AES-CTR, AES-CFB, ChaCha20 and ChaCha20-Poly1305 are provided by the polyfill.
            return false;
    }
}

private wstring cngChainMode(SymmetricAlgorithm algo) {
    return isAeadCipher(algo) ? BCRYPT_CHAIN_MODE_GCM : BCRYPT_CHAIN_MODE_CBC;
}

@trusted private BCRYPT_KEY_HANDLE cngPrepareKey(SymmetricAlgorithm algorithm, const ubyte[] encryptionKey, out BCRYPT_ALG_HANDLE hAlg, out ubyte[] keyObject) {
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM.ptr, null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG AES algorithm provider.");
    }

    wstring mode = cngChainMode(algorithm);
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE.ptr, cast(PUCHAR)mode.ptr, cast(ULONG)((mode.length + 1) * wchar.sizeof), 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to set the CNG chaining mode.");
    }

    ULONG objLen, cbData;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH.ptr, cast(PUCHAR)&objLen, ULONG.sizeof, &cbData, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to query the CNG key object length.");
    }
    keyObject = new ubyte[objLen];

    BCRYPT_KEY_HANDLE hKey;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.ptr, objLen, cast(PUCHAR)encryptionKey.ptr, cast(ULONG)encryptionKey.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to create the CNG symmetric key.");
    }
    return hKey;
}

@trusted package(secured) ubyte[] encrypt_impl_cng(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
    BCRYPT_ALG_HANDLE hAlg;
    ubyte[] keyObject;
    BCRYPT_KEY_HANDLE hKey = cngPrepareKey(algorithm, encryptionKey, hAlg, keyObject);
    scope(exit) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    ULONG resultLen;
    if (isAeadCipher(algorithm)) {
        // Zero-initialize so unused AEAD fields (pbMacContext, cbAAD, etc.) are
        // not left with stack garbage that CNG may interpret.
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.init;
        authInfo.cbSize = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.sizeof;
        authInfo.dwInfoVersion = 1;
        authInfo.pbNonce = cast(PUCHAR)iv.ptr;
        authInfo.cbNonce = cast(ULONG)iv.length;
        if (associatedData.length > 0) {
            authInfo.pbAuthData = cast(PUCHAR)associatedData.ptr;
            authInfo.cbAuthData = cast(ULONG)associatedData.length;
        }
        ubyte[] tag = new ubyte[getAuthLength(algorithm)];
        authInfo.pbTag = tag.ptr;
        authInfo.cbTag = cast(ULONG)tag.length;

        ubyte[] output = new ubyte[data.length];
        if (BCryptEncrypt(hKey, cast(PUCHAR)data.ptr, cast(ULONG)data.length, &authInfo, null, 0,
                output.ptr, cast(ULONG)output.length, &resultLen, 0) != STATUS_SUCCESS) {
            throw new CryptographicException("Unable to encrypt data with CNG.");
        }
        authTag = tag;
        return output[0 .. resultLen];
    } else {
        ubyte[] ivCopy = iv.dup;
        ubyte[] output = new ubyte[data.length + 16];
        if (BCryptEncrypt(hKey, cast(PUCHAR)data.ptr, cast(ULONG)data.length, null, ivCopy.ptr, cast(ULONG)ivCopy.length,
                output.ptr, cast(ULONG)output.length, &resultLen, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
            throw new CryptographicException("Unable to encrypt data with CNG.");
        }
        return output[0 .. resultLen];
    }
}

@trusted package(secured) ubyte[] decrypt_impl_cng(const ubyte[] data, const ubyte[] associatedData, const ubyte[] encryptionKey, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
    BCRYPT_ALG_HANDLE hAlg;
    ubyte[] keyObject;
    BCRYPT_KEY_HANDLE hKey = cngPrepareKey(algorithm, encryptionKey, hAlg, keyObject);
    scope(exit) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    ULONG resultLen;
    if (isAeadCipher(algorithm)) {
        // Zero-initialize so unused AEAD fields are not left with stack garbage.
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.init;
        authInfo.cbSize = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.sizeof;
        authInfo.dwInfoVersion = 1;
        authInfo.pbNonce = cast(PUCHAR)iv.ptr;
        authInfo.cbNonce = cast(ULONG)iv.length;
        if (associatedData.length > 0) {
            authInfo.pbAuthData = cast(PUCHAR)associatedData.ptr;
            authInfo.cbAuthData = cast(ULONG)associatedData.length;
        }
        authInfo.pbTag = cast(PUCHAR)authTag.ptr;
        authInfo.cbTag = cast(ULONG)authTag.length;

        ubyte[] output = new ubyte[data.length];
        if (BCryptDecrypt(hKey, cast(PUCHAR)data.ptr, cast(ULONG)data.length, &authInfo, null, 0,
                output.ptr, cast(ULONG)output.length, &resultLen, 0) != STATUS_SUCCESS) {
            throw new CryptographicException("Unable to decrypt data with CNG. The authentication tag may be invalid.");
        }
        return output[0 .. resultLen];
    } else {
        ubyte[] ivCopy = iv.dup;
        ubyte[] output = new ubyte[data.length];
        if (BCryptDecrypt(hKey, cast(PUCHAR)data.ptr, cast(ULONG)data.length, null, ivCopy.ptr, cast(ULONG)ivCopy.length,
                output.ptr, cast(ULONG)output.length, &resultLen, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
            throw new CryptographicException("Unable to decrypt data with CNG.");
        }
        return output[0 .. resultLen];
    }
}

// ---------------------------------------------------------------------------
// RSA
//
// The RSA key context bundles the CNG algorithm provider handle with the key
// handle. CNG requires the algorithm provider to outlive any key created from
// (or imported into) it, so both are carried together and released in rsaFree.
// The public RSA class in secured.rsa holds one of these and forwards here.
// ---------------------------------------------------------------------------
struct RsaKey {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    uint keyBits;
    bool hasPrivate;
}

// Container magic for the exported private key blob (SecureD CNG RSA).
private immutable ubyte[8] SD_CNG_RSA_MAGIC = ['S', 'D', 'C', 'N', 'G', 'R', 'S', 'A'];

@trusted private BCRYPT_ALG_HANDLE cngOpenRsa() {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM.ptr, null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG RSA algorithm provider.");
    }
    return hAlg;
}

@trusted private ubyte[] cngRandom(size_t n) {
    ubyte[] buffer = new ubyte[n];
    if (BCryptGenRandom(null, buffer.ptr, cast(ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to generate random bytes with CNG.");
    }
    return buffer;
}

@trusted private ubyte[] cngExportBlob(BCRYPT_KEY_HANDLE hKey, const(wchar)* blobType) {
    ULONG cb;
    if (BCryptExportKey(hKey, null, blobType, null, 0, &cb, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG RSA key blob.");
    }
    ubyte[] blob = new ubyte[cb];
    if (BCryptExportKey(hKey, null, blobType, blob.ptr, cb, &cb, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to export the CNG RSA key blob.");
    }
    return blob[0 .. cb];
}

@trusted private uint cngReadBitLength(const ubyte[] blob) {
    if (blob.length < BCRYPT_RSAKEY_BLOB.sizeof) {
        throw new CryptographicException("Invalid CNG RSA key blob.");
    }
    auto header = cast(const(BCRYPT_RSAKEY_BLOB)*)blob.ptr;
    return header.BitLength;
}

@trusted package(secured) RsaKey rsaGenerate(int keylen) {
    RsaKey key;
    key.hAlg = cngOpenRsa();
    if (BCryptGenerateKeyPair(key.hAlg, &key.hKey, cast(ULONG)keylen, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(key.hAlg, 0);
        throw new CryptographicException("Unable to generate the CNG RSA key pair.");
    }
    if (BCryptFinalizeKeyPair(key.hKey, 0) != STATUS_SUCCESS) {
        BCryptDestroyKey(key.hKey);
        BCryptCloseAlgorithmProvider(key.hAlg, 0);
        throw new CryptographicException("Unable to finalize the CNG RSA key pair.");
    }
    key.keyBits = cast(uint)keylen;
    key.hasPrivate = true;
    return key;
}

@trusted package(secured) RsaKey rsaLoadPublicKey(ubyte[] publicKey) {
    RsaKey key;
    key.hAlg = cngOpenRsa();
    if (BCryptImportKeyPair(key.hAlg, null, BCRYPT_RSAPUBLIC_BLOB.ptr, &key.hKey,
            publicKey.ptr, cast(ULONG)publicKey.length, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(key.hAlg, 0);
        throw new CryptographicException("Unable to import the CNG RSA public key.");
    }
    key.keyBits = cngReadBitLength(publicKey);
    key.hasPrivate = false;
    return key;
}

@trusted package(secured) RsaKey rsaLoadPrivateKey(ubyte[] privateKey, ubyte[] password) {
    if (privateKey.length < SD_CNG_RSA_MAGIC.length + 1 || privateKey[0 .. SD_CNG_RSA_MAGIC.length] != SD_CNG_RSA_MAGIC[]) {
        throw new CryptographicException("Invalid CNG RSA private key container.");
    }

    immutable ubyte flag = privateKey[SD_CNG_RSA_MAGIC.length];
    ubyte[] blob;
    if (flag == 0) {
        blob = privateKey[SD_CNG_RSA_MAGIC.length + 1 .. $].dup;
    } else if (flag == 1 || flag == 2) {
        // flag 1: fixed 25000 iterations (legacy). flag 2: iterations stored as LE uint32.
        if (password is null) {
            throw new CryptographicException("A password is required to load this private key.");
        }
        size_t off = SD_CNG_RSA_MAGIC.length + 1;
        uint iterations = 25000;
        if (flag == 2) {
            if (privateKey.length < off + 4) {
                throw new CryptographicException("Invalid CNG RSA private key container.");
            }
            iterations = privateKey[off] | (privateKey[off + 1] << 8) |
                (privateKey[off + 2] << 16) | (privateKey[off + 3] << 24);
            off += 4;
        }
        if (privateKey.length < off + 16 + 12 + 16) {
            throw new CryptographicException("Invalid CNG RSA private key container.");
        }
        ubyte[] salt = privateKey[off .. off + 16].dup; off += 16;
        ubyte[] iv   = privateKey[off .. off + 12].dup; off += 12;
        ubyte[] tag  = privateKey[off .. off + 16].dup; off += 16;
        ubyte[] ciphertext = privateKey[off .. $].dup;
        ubyte[] derived = pbkdf2_impl_cng(cast(string)password, salt, HashAlgorithm.SHA2_256, 32, iterations);
        blob = decrypt_impl_cng(ciphertext, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    } else {
        throw new CryptographicException("Invalid CNG RSA private key container.");
    }

    RsaKey key;
    key.hAlg = cngOpenRsa();
    if (BCryptImportKeyPair(key.hAlg, null, BCRYPT_RSAFULLPRIVATE_BLOB.ptr, &key.hKey,
            blob.ptr, cast(ULONG)blob.length, 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(key.hAlg, 0);
        throw new CryptographicException("Unable to import the CNG RSA private key.");
    }
    key.keyBits = cngReadBitLength(blob);
    key.hasPrivate = true;
    return key;
}

@trusted package(secured) void rsaFree(RsaKey key) {
    if (key.hKey !is null) {
        BCryptDestroyKey(key.hKey);
    }
    if (key.hAlg !is null) {
        BCryptCloseAlgorithmProvider(key.hAlg, 0);
    }
}

@trusted package(secured) ubyte[] rsaGetPublicKey(RsaKey key) {
    return cngExportBlob(key.hKey, BCRYPT_RSAPUBLIC_BLOB.ptr);
}

@trusted package(secured) ubyte[] rsaGetPrivateKey(RsaKey key, string password, int iterations, bool use3Des) {
    if (!key.hasPrivate) {
        return null;
    }

    ubyte[] blob = cngExportBlob(key.hKey, BCRYPT_RSAFULLPRIVATE_BLOB.ptr);

    if (password is null) {
        return SD_CNG_RSA_MAGIC[] ~ cast(ubyte)0 ~ blob;
    }

    // CNG has no PKCS#8 encryption primitive, so protect the raw blob with
    // AES-256-GCM under a PBKDF2-SHA256 derived key inside a self-describing
    // container. This mirrors the password-protection contract of the API.
    // flag 1 = legacy fixed 25000 iterations; flag 2 embeds a custom count.
    if (use3Des) {
        throw new CryptographicException(
            "use3Des is not supported by the CNG backend; AES-256-GCM is used instead.");
    }
    if (iterations <= 0) {
        throw new CryptographicException("PBKDF2 iteration count must be positive.");
    }
    ubyte[] salt = cngRandom(16);
    ubyte[] iv = cngRandom(12);
    ubyte[] tag;
    ubyte[] derived = pbkdf2_impl_cng(password, salt, HashAlgorithm.SHA2_256, 32, cast(uint)iterations);
    ubyte[] ciphertext = encrypt_impl_cng(blob, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    if (iterations == 25000) {
        return SD_CNG_RSA_MAGIC[] ~ cast(ubyte)1 ~ salt ~ iv ~ tag ~ ciphertext;
    }
    ubyte[4] iterBytes = [
        cast(ubyte)(iterations),
        cast(ubyte)(iterations >> 8),
        cast(ubyte)(iterations >> 16),
        cast(ubyte)(iterations >> 24),
    ];
    return SD_CNG_RSA_MAGIC[] ~ cast(ubyte)2 ~ iterBytes[] ~ salt ~ iv ~ tag ~ ciphertext;
}

private const(wchar)* cngOaepHashAlgId(HashAlgorithm hashAlgorithm) {
    // OAEP for seal uses SHA-2 / SHA-3. SHA-1 remains only for the legacy
    // rsaEncrypt/rsaDecrypt path for interop.
    if (!cngSupportsHash(hashAlgorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }
    return getCngHashAlgId(hashAlgorithm);
}

private size_t cngOaepOverhead(HashAlgorithm hashAlgorithm) {
    return 2 * getHashLength(hashAlgorithm) + 2;
}

@trusted package(secured) ubyte[] rsaEncryptWithHash(RsaKey key, const ubyte[] inMessage, HashAlgorithm hashAlgorithm) {
    immutable size_t overhead = cngOaepOverhead(hashAlgorithm);
    enforce(inMessage.length <= (key.keyBits / 8 - overhead), new CryptographicException("Plainttext length exceeds allowance"));

    BCRYPT_OAEP_PADDING_INFO pad;
    pad.pszAlgId = cngOaepHashAlgId(hashAlgorithm);
    pad.pbLabel = null;
    pad.cbLabel = 0;

    ULONG cb;
    if (BCryptEncrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            null, 0, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG RSA ciphertext.");
    }
    ubyte[] output = new ubyte[cb];
    if (BCryptEncrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            output.ptr, cb, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to RSA-encrypt data with CNG.");
    }
    return output[0 .. cb];
}

@trusted package(secured) ubyte[] rsaDecryptWithHash(RsaKey key, const ubyte[] inMessage, HashAlgorithm hashAlgorithm) {
    BCRYPT_OAEP_PADDING_INFO pad;
    pad.pszAlgId = cngOaepHashAlgId(hashAlgorithm);
    pad.pbLabel = null;
    pad.cbLabel = 0;

    ULONG cb;
    if (BCryptDecrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            null, 0, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG RSA plaintext.");
    }
    ubyte[] output = new ubyte[cb];
    if (BCryptDecrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            output.ptr, cb, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to RSA-decrypt data with CNG.");
    }
    return output[0 .. cb];
}

@trusted package(secured) ubyte[] rsaEncrypt(RsaKey key, const ubyte[] inMessage) {
    // Legacy direct RSA encrypt keeps OAEP-SHA1 for interop with existing data.
    // 42 bytes is the OAEP overhead for a SHA-1 label (2*20 + 2).
    enforce(inMessage.length <= (key.keyBits / 8 - 42), new CryptographicException("Plainttext length exceeds allowance"));

    BCRYPT_OAEP_PADDING_INFO pad;
    pad.pszAlgId = BCRYPT_SHA1_ALGORITHM.ptr;
    pad.pbLabel = null;
    pad.cbLabel = 0;

    ULONG cb;
    if (BCryptEncrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            null, 0, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG RSA ciphertext.");
    }
    ubyte[] output = new ubyte[cb];
    if (BCryptEncrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            output.ptr, cb, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to RSA-encrypt data with CNG.");
    }
    return output[0 .. cb];
}

@trusted package(secured) ubyte[] rsaDecrypt(RsaKey key, const ubyte[] inMessage) {
    BCRYPT_OAEP_PADDING_INFO pad;
    pad.pszAlgId = BCRYPT_SHA1_ALGORITHM.ptr;
    pad.pbLabel = null;
    pad.cbLabel = 0;

    ULONG cb;
    if (BCryptDecrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            null, 0, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG RSA plaintext.");
    }
    ubyte[] output = new ubyte[cb];
    if (BCryptDecrypt(key.hKey, cast(PUCHAR)inMessage.ptr, cast(ULONG)inMessage.length, &pad, null, 0,
            output.ptr, cb, &cb, BCRYPT_PAD_OAEP) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to RSA-decrypt data with CNG.");
    }
    return output[0 .. cb];
}

@trusted package(secured) ubyte[] rsaSeal(RsaKey key, const ubyte[] plaintext, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm = HashAlgorithm.Default) {
    // Hybrid encryption: encrypt with the requested symmetric algorithm, then
    // RSA-OAEP wrap the session key using the selected hash.
    if (!cngSupportsCipher(algorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
    }
    if (!cngSupportsHash(hashAlgorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedHashMessage(hashAlgorithm));
    }

    immutable uint keyLen = getCipherKeyLength(algorithm);
    immutable uint ivLen = getCipherIVLength(algorithm);
    ubyte[] aesKey = cngRandom(keyLen);
    ubyte[] iv = cngRandom(ivLen);
    ubyte[] tag;
    ubyte[] ciphertext = encrypt_impl_cng(plaintext, null, aesKey, iv, tag, algorithm);
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
    if (!cngSupportsCipher(algorithm)) {
        throw new AlgorithmNotSupportedException(unsupportedCipherMessage(algorithm));
    }
    if (!cngSupportsHash(hashAlgorithm)) {
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
    return decrypt_impl_cng(ciphertext, null, aesKey, iv, tag, algorithm);
}

@trusted package(secured) ubyte[] rsaSign(RsaKey key, ubyte[] data, bool useSha256) {
    HashAlgorithm func = useSha256 ? HashAlgorithm.SHA2_256 : HashAlgorithm.SHA2_384;
    ubyte[] digest = hash_impl_cng(data, func);

    BCRYPT_PKCS1_PADDING_INFO pad;
    pad.pszAlgId = useSha256 ? BCRYPT_SHA256_ALGORITHM.ptr : BCRYPT_SHA384_ALGORITHM.ptr;

    ULONG cb;
    if (BCryptSignHash(key.hKey, &pad, digest.ptr, cast(ULONG)digest.length, null, 0, &cb, BCRYPT_PAD_PKCS1) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG RSA signature.");
    }
    ubyte[] signature = new ubyte[cb];
    if (BCryptSignHash(key.hKey, &pad, digest.ptr, cast(ULONG)digest.length, signature.ptr, cb, &cb, BCRYPT_PAD_PKCS1) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to RSA-sign data with CNG.");
    }
    return signature[0 .. cb];
}

@trusted package(secured) bool rsaVerify(RsaKey key, ubyte[] data, ubyte[] signature, bool useSha256) {
    HashAlgorithm func = useSha256 ? HashAlgorithm.SHA2_256 : HashAlgorithm.SHA2_384;
    ubyte[] digest = hash_impl_cng(data, func);

    BCRYPT_PKCS1_PADDING_INFO pad;
    pad.pszAlgId = useSha256 ? BCRYPT_SHA256_ALGORITHM.ptr : BCRYPT_SHA384_ALGORITHM.ptr;

    return BCryptVerifySignature(key.hKey, &pad, digest.ptr, cast(ULONG)digest.length,
        signature.ptr, cast(ULONG)signature.length, BCRYPT_PAD_PKCS1) == STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Elliptic Curve (ECDSA + ECDH)
//
// CNG separates ECDSA and ECDH into distinct algorithm handles, so a key must
// support both signing and key agreement. The key material is therefore stored
// as raw CNG blobs and re-imported under whichever algorithm an operation needs
// (the blob magic is patched to match). The public EllipticCurve class in
// secured.ecc holds one of these and forwards here.
//
// EccCurve.P256/P384/P521 are the NIST prime curves (P-256/P-384/P-521) on every
// backend. Keys never cross providers in the test suite (each round-trips within
// its own provider).
// ---------------------------------------------------------------------------
struct EccKey {
    EccCurve curve;
    ubyte[] privateBlob;   // BCRYPT_ECCPRIVATE_BLOB (ECDSA magic); null if public-only
    ubyte[] publicBlob;    // BCRYPT_ECCPUBLIC_BLOB (ECDSA magic)
    bool hasPrivate;
}

private immutable ubyte[8] SD_CNG_ECC_PUB_MAGIC  = ['S', 'D', 'C', 'N', 'G', 'E', 'C', 'P'];
private immutable ubyte[8] SD_CNG_ECC_PRIV_MAGIC = ['S', 'D', 'C', 'N', 'G', 'E', 'C', 'K'];

private const(wchar)* cngEcdsaAlg(EccCurve curve) {
    final switch (curve) {
        case EccCurve.P256: return BCRYPT_ECDSA_P256_ALGORITHM.ptr;
        case EccCurve.P384: return BCRYPT_ECDSA_P384_ALGORITHM.ptr;
        case EccCurve.P521: return BCRYPT_ECDSA_P521_ALGORITHM.ptr;
    }
}

private const(wchar)* cngEcdhAlg(EccCurve curve) {
    final switch (curve) {
        case EccCurve.P256: return BCRYPT_ECDH_P256_ALGORITHM.ptr;
        case EccCurve.P384: return BCRYPT_ECDH_P384_ALGORITHM.ptr;
        case EccCurve.P521: return BCRYPT_ECDH_P521_ALGORITHM.ptr;
    }
}

private ULONG cngCurveBits(EccCurve curve) {
    final switch (curve) {
        case EccCurve.P256: return 256;
        case EccCurve.P384: return 384;
        case EccCurve.P521: return 521;
    }
}

private ULONG cngEccMagic(EccCurve curve, bool ecdh, bool isPublic) {
    final switch (curve) {
        case EccCurve.P256:
            if (ecdh) return isPublic ? BCRYPT_ECDH_PUBLIC_P256_MAGIC : BCRYPT_ECDH_PRIVATE_P256_MAGIC;
            return isPublic ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC : BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        case EccCurve.P384:
            if (ecdh) return isPublic ? BCRYPT_ECDH_PUBLIC_P384_MAGIC : BCRYPT_ECDH_PRIVATE_P384_MAGIC;
            return isPublic ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC : BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        case EccCurve.P521:
            if (ecdh) return isPublic ? BCRYPT_ECDH_PUBLIC_P521_MAGIC : BCRYPT_ECDH_PRIVATE_P521_MAGIC;
            return isPublic ? BCRYPT_ECDSA_PUBLIC_P521_MAGIC : BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
    }
}

private ubyte[] cngPatchEccMagic(const ubyte[] blob, ULONG magic) {
    ubyte[] copy = blob.dup;
    *(cast(ULONG*)copy.ptr) = magic;
    return copy;
}

private ubyte[] cngPublicFromPrivate(const ubyte[] privateBlob, EccCurve curve) {
    // ECCPRIVATE_BLOB = [magic][cbKey][X][Y][d]; ECCPUBLIC_BLOB = [magic][cbKey][X][Y].
    if (privateBlob.length < BCRYPT_ECCKEY_BLOB.sizeof) {
        throw new CryptographicException("Invalid CNG EC private key blob.");
    }
    uint cbKey = *(cast(const(uint)*)(privateBlob.ptr + 4));
    size_t pubLen = BCRYPT_ECCKEY_BLOB.sizeof + 2 * cbKey;
    if (privateBlob.length < pubLen) {
        throw new CryptographicException("Invalid CNG EC private key blob.");
    }
    ubyte[] pub = privateBlob[0 .. pubLen].dup;
    *(cast(ULONG*)pub.ptr) = cngEccMagic(curve, false, true);
    return pub;
}

@trusted package(secured) EccKey eccGenerate(EccCurve curve) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, cngEcdsaAlg(curve), null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG ECDSA algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    BCRYPT_KEY_HANDLE hKey;
    if (BCryptGenerateKeyPair(hAlg, &hKey, cngCurveBits(curve), 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to generate the CNG EC key pair.");
    }
    scope(exit) BCryptDestroyKey(hKey);
    if (BCryptFinalizeKeyPair(hKey, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to finalize the CNG EC key pair.");
    }

    EccKey key;
    key.curve = curve;
    key.privateBlob = cngExportBlob(hKey, BCRYPT_ECCPRIVATE_BLOB.ptr);
    key.publicBlob = cngExportBlob(hKey, BCRYPT_ECCPUBLIC_BLOB.ptr);
    key.hasPrivate = true;
    return key;
}

@trusted package(secured) EccKey eccLoadPrivateKey(string privateKey, string password) {
    ubyte[] data = cast(ubyte[])privateKey;
    if (data.length < SD_CNG_ECC_PRIV_MAGIC.length + 2 || data[0 .. SD_CNG_ECC_PRIV_MAGIC.length] != SD_CNG_ECC_PRIV_MAGIC[]) {
        throw new CryptographicException("Invalid CNG EC private key container.");
    }

    immutable ubyte flag = data[SD_CNG_ECC_PRIV_MAGIC.length];
    EccCurve curve = cast(EccCurve)data[SD_CNG_ECC_PRIV_MAGIC.length + 1];
    ubyte[] blob;
    if (flag == 0) {
        blob = data[SD_CNG_ECC_PRIV_MAGIC.length + 2 .. $].dup;
    } else {
        if (password is null) {
            throw new CryptographicException("A password is required to load this private key.");
        }
        size_t off = SD_CNG_ECC_PRIV_MAGIC.length + 2;
        ubyte[] salt = data[off .. off + 16].dup; off += 16;
        ubyte[] iv   = data[off .. off + 12].dup; off += 12;
        ubyte[] tag  = data[off .. off + 16].dup; off += 16;
        ubyte[] ciphertext = data[off .. $].dup;
        ubyte[] derived = pbkdf2_impl_cng(password, salt, HashAlgorithm.SHA2_256, 32, 25000);
        blob = decrypt_impl_cng(ciphertext, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    }

    EccKey key;
    key.curve = curve;
    key.privateBlob = blob;
    key.publicBlob = cngPublicFromPrivate(blob, curve);
    key.hasPrivate = true;
    return key;
}

@trusted package(secured) EccKey eccLoadPublicKey(string publicKey) {
    ubyte[] data = cast(ubyte[])publicKey;
    if (data.length < SD_CNG_ECC_PUB_MAGIC.length + 1 || data[0 .. SD_CNG_ECC_PUB_MAGIC.length] != SD_CNG_ECC_PUB_MAGIC[]) {
        throw new CryptographicException("Invalid CNG EC public key container.");
    }

    EccKey key;
    key.curve = cast(EccCurve)data[SD_CNG_ECC_PUB_MAGIC.length];
    key.publicBlob = data[SD_CNG_ECC_PUB_MAGIC.length + 1 .. $].dup;
    key.hasPrivate = false;
    return key;
}

@trusted package(secured) void eccFree(EccKey key) {
    // Key material is stored as GC-managed blobs; nothing to release.
}

@trusted package(secured) string eccGetPublicKey(EccKey key) {
    ubyte[] container = SD_CNG_ECC_PUB_MAGIC[] ~ cast(ubyte)key.curve ~ key.publicBlob;
    return cast(string)container;
}

@trusted package(secured) string eccGetPrivateKey(EccKey key, string password, bool use3Des) {
    if (!key.hasPrivate) {
        return null;
    }

    if (password is null) {
        ubyte[] container = SD_CNG_ECC_PRIV_MAGIC[] ~ cast(ubyte)0 ~ cast(ubyte)key.curve ~ key.privateBlob;
        return cast(string)container;
    }

    ubyte[] salt = cngRandom(16);
    ubyte[] iv = cngRandom(12);
    ubyte[] tag;
    ubyte[] derived = pbkdf2_impl_cng(password, salt, HashAlgorithm.SHA2_256, 32, 25000);
    ubyte[] ciphertext = encrypt_impl_cng(key.privateBlob, null, derived, iv, tag, SymmetricAlgorithm.AES256_GCM);
    ubyte[] container = SD_CNG_ECC_PRIV_MAGIC[] ~ cast(ubyte)1 ~ cast(ubyte)key.curve ~ salt ~ iv ~ tag ~ ciphertext;
    return cast(string)container;
}

@trusted package(secured) ubyte[] eccSign(EccKey key, ubyte[] data, bool useSha256) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, cngEcdsaAlg(key.curve), null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG ECDSA algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    BCRYPT_KEY_HANDLE hKey;
    if (BCryptImportKeyPair(hAlg, null, BCRYPT_ECCPRIVATE_BLOB.ptr, &hKey,
            key.privateBlob.ptr, cast(ULONG)key.privateBlob.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to import the CNG EC private key.");
    }
    scope(exit) BCryptDestroyKey(hKey);

    // Hash the message first (SHA-384 by default), matching the OpenSSL provider.
    HashAlgorithm func = useSha256 ? HashAlgorithm.SHA2_256 : HashAlgorithm.SHA2_384;
    ubyte[] digest = hash_impl_cng(data, func);

    ULONG cb;
    if (BCryptSignHash(hKey, null, digest.ptr, cast(ULONG)digest.length, null, 0, &cb, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG EC signature.");
    }
    ubyte[] signature = new ubyte[cb];
    if (BCryptSignHash(hKey, null, digest.ptr, cast(ULONG)digest.length, signature.ptr, cb, &cb, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to EC-sign data with CNG.");
    }
    return signature[0 .. cb];
}

@trusted package(secured) bool eccVerify(EccKey key, ubyte[] data, ubyte[] signature, bool useSha256) {
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, cngEcdsaAlg(key.curve), null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG ECDSA algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    BCRYPT_KEY_HANDLE hKey;
    if (BCryptImportKeyPair(hAlg, null, BCRYPT_ECCPUBLIC_BLOB.ptr, &hKey,
            key.publicBlob.ptr, cast(ULONG)key.publicBlob.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to import the CNG EC public key.");
    }
    scope(exit) BCryptDestroyKey(hKey);

    HashAlgorithm func = useSha256 ? HashAlgorithm.SHA2_256 : HashAlgorithm.SHA2_384;
    ubyte[] digest = hash_impl_cng(data, func);

    return BCryptVerifySignature(hKey, null, digest.ptr, cast(ULONG)digest.length,
        cast(PUCHAR)signature.ptr, cast(ULONG)signature.length, 0) == STATUS_SUCCESS;
}

@trusted package(secured) ubyte[] eccDerive(EccKey key, string peerKey) {
    ubyte[] peerData = cast(ubyte[])peerKey;
    if (peerData.length < SD_CNG_ECC_PUB_MAGIC.length + 1 || peerData[0 .. SD_CNG_ECC_PUB_MAGIC.length] != SD_CNG_ECC_PUB_MAGIC[]) {
        throw new CryptographicException("Invalid CNG EC public key container.");
    }
    EccCurve peerCurve = cast(EccCurve)peerData[SD_CNG_ECC_PUB_MAGIC.length];
    ubyte[] peerPublicBlob = peerData[SD_CNG_ECC_PUB_MAGIC.length + 1 .. $].dup;

    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, cngEcdhAlg(key.curve), null, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to open the CNG ECDH algorithm provider.");
    }
    scope(exit) BCryptCloseAlgorithmProvider(hAlg, 0);

    // Re-import our private key and the peer public key as ECDH keys.
    ubyte[] priv = cngPatchEccMagic(key.privateBlob, cngEccMagic(key.curve, true, false));
    BCRYPT_KEY_HANDLE hPriv;
    if (BCryptImportKeyPair(hAlg, null, BCRYPT_ECCPRIVATE_BLOB.ptr, &hPriv, priv.ptr, cast(ULONG)priv.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to import the CNG ECDH private key.");
    }
    scope(exit) BCryptDestroyKey(hPriv);

    ubyte[] peerPub = cngPatchEccMagic(peerPublicBlob, cngEccMagic(peerCurve, true, true));
    BCRYPT_KEY_HANDLE hPeer;
    if (BCryptImportKeyPair(hAlg, null, BCRYPT_ECCPUBLIC_BLOB.ptr, &hPeer, peerPub.ptr, cast(ULONG)peerPub.length, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to import the CNG ECDH public key.");
    }
    scope(exit) BCryptDestroyKey(hPeer);

    BCRYPT_SECRET_HANDLE secret;
    if (BCryptSecretAgreement(hPriv, hPeer, &secret, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to compute the CNG ECDH secret agreement.");
    }
    scope(exit) BCryptDestroySecret(secret);

    ULONG cb;
    if (BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET.ptr, null, null, 0, &cb, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to size the CNG ECDH derived secret.");
    }
    ubyte[] derived = new ubyte[cb];
    if (BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET.ptr, null, derived.ptr, cb, &cb, 0) != STATUS_SUCCESS) {
        throw new CryptographicException("Unable to derive the CNG ECDH secret.");
    }
    return derived[0 .. cb];
}

} // static if (activeProvider == Provider.CNG)
