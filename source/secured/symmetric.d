module secured.symmetric;

import std.conv;
import std.outbuffer;

import deimos.openssl.evp;

import secured.hash;
import secured.mac;
import secured.kdf;
import secured.random;
import secured.util;
import secured.openssl;

public enum CryptoHeaderVersion = 1;
public enum uint defaultKdfIterations = 1_048_576;
public enum ushort defaultSCryptR = 8;
public enum ushort defaultSCryptP = 1;
public enum uint defaultChunkSize = 1_073_741_824;
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

public immutable struct CryptographicResult {
    public immutable ubyte[] data;
    public immutable ubyte[] auth;

    private this(ubyte[] data, ubyte[] auth) {
        this.data = cast(immutable)data;
        this.auth = cast(immutable)auth;
    }
}

private struct CryptoBlock {
    public immutable ubyte headerVersion;           // The version of the block header
    public immutable SymmetricAlgorithm symmetric;  // The Symmetric algorithm
    public immutable HashAlgorithm hash;            // The Hash algorithm
    public immutable KdfAlgorithm kdf;              // The KDF algorithm
    public immutable uint kdfIterations;            // The number of KDF iterations
    public immutable ushort scryptMemory;           // The amount SCrypt memory to use
    public immutable ushort scryptParallelism;      // The SCrypt parallelism

    public immutable ushort sectionCount;           // The total number of sections
    public immutable ushort sectionNumber;          // The current section number
    public immutable uint sectionSize;              // The size of the current section

    public immutable uint additionalLength;         // The length of the additional data
    public immutable uint encryptedLength;          // The length of the encrypted data+

    public immutable ubyte[] salt;
    public immutable ubyte[] iv;
    public immutable ubyte[] auth;
    public immutable ubyte[] additional;
    public immutable ubyte[] encrypted;

    @trusted public this(SymmetricAlgorithm symAlg, HashAlgorithm hashAlg, KdfAlgorithm kdfAlg,
        uint n, ushort r, ushort p, ushort sc, ushort sn,
        const ubyte[] salt, const ubyte[] iv, const ubyte[] auth, const ubyte[] additional, const ubyte[] encrypted) {
        this.headerVersion = 1;
        this.symmetric = symAlg;
        this.hash = hashAlg;
        this.kdf = kdfAlg;
        this.kdfIterations = n;
        this.scryptMemory = r;
        this.scryptParallelism = p;
        this.sectionCount = sc;
        this.sectionNumber = sn;
        this.sectionSize = cast(uint)(salt.length + iv.length + auth.length + additional.length + encrypted.length);
        this.additionalLength = cast(uint)additional.length;
        this.encryptedLength = cast(uint)encrypted.length;

        this.salt = cast(immutable)salt;
        this.iv = cast(immutable)iv;
        this.auth = cast(immutable)auth;
        this.additional = cast(immutable)additional;
        this.encrypted = cast(immutable)encrypted;
    }

    @trusted public this(const ubyte[] data) {
        import std.stdio;
        import std.bitmanip : read;
        ubyte[] bytes = cast(ubyte[])data;

        this.headerVersion = cast(immutable)bytes.read!ubyte();
        this.symmetric = cast(immutable SymmetricAlgorithm)bytes.read!ubyte();
        this.hash = cast(immutable HashAlgorithm)bytes.read!ubyte();
        this.kdf = cast(immutable KdfAlgorithm)bytes.read!ubyte();

        this.kdfIterations = cast(immutable)bytes.read!uint();
        this.scryptMemory = cast(immutable)bytes.read!ushort();
        this.scryptParallelism = cast(immutable)bytes.read!ushort();

        this.sectionCount = cast(immutable)bytes.read!ushort();
        this.sectionNumber = cast(immutable)bytes.read!ushort();
        this.sectionSize = cast(immutable)bytes.read!uint();

        this.additionalLength = cast(immutable)bytes.read!uint();
        this.encryptedLength = cast(immutable)bytes.read!uint();

        const uint saltLen = getHashLength(this.hash);
        const uint ivLen = getCipherIVLength(this.symmetric);
        const uint authLen = getAuthLength(this.symmetric, this.hash);

        writeln("Salt Length: ", saltLen);
        writeln("IV Length: ", ivLen);
        writeln("Auth Length: ", authLen);
        writeln("AAD Length: ", additionalLength);
        writeln("Encrypted Length: ", encryptedLength);
        writeln("Total Length: ", (saltLen + ivLen + authLen + additionalLength + encryptedLength));
        writeln("Data Length: ", data.length);

        this.salt = cast(immutable)bytes[0..saltLen];
        bytes = bytes[saltLen..$];
        this.iv = cast(immutable)bytes[0..ivLen];
        bytes = bytes[ivLen..$];
        this.auth = cast(immutable)bytes[0..authLen];
        bytes = bytes[authLen..$];
        this.additional = cast(immutable)bytes[0..additionalLength];
        bytes = bytes[additionalLength..$];
        this.encrypted = cast(immutable)bytes[0..encryptedLength];
    }

    @trusted private ubyte[] toBytes() {
        import std.bitmanip : write;

        ubyte[] header = new ubyte[28];
        
        header[0] = this.headerVersion;
        header[1] = this.symmetric;
        header[2] = this.hash;
        header[3] = this.kdf;

        header.write(this.kdfIterations, 4);
        header.write(this.scryptMemory, 8);
        header.write(this.scryptParallelism, 10);

        header.write(this.sectionCount, 12);
        header.write(this.sectionNumber, 14);
        header.write(this.sectionSize, 16);

        header.write(this.additionalLength, 20);
        header.write(this.encryptedLength, 24);

        OutBuffer buffer = new OutBuffer();
        buffer.reserve(this.sectionSize + 28);
        buffer.write(header);
        buffer.write(salt);
        buffer.write(iv);
        buffer.write(auth);
        buffer.write(additional);
        buffer.write(encrypted);

        return buffer.toBytes();
    }
}

@safe public ubyte[] encrypt(const ubyte[] key, const ubyte[] data, const ubyte[] additional = null) {
    return encrypt_ex(key, data, additional, defaultChunkSize, SymmetricAlgorithm.Default, KdfAlgorithm.Default, defaultKdfIterations, defaultSCryptR, defaultSCryptP, HashAlgorithm.SHA2_384);
}

@safe public ubyte[] encrypt_ex(const ubyte[] key, const ubyte[] data, const ubyte[] additional, uint chunkSize, SymmetricAlgorithm symmetric, KdfAlgorithm kdf, uint n, ushort r, ushort p, HashAlgorithm hash) {
    import std.math : floor;
    const real tcc = data.length / chunkSize;
    const ushort chunks = to!ushort(floor(tcc)+1);

    //Get Derived Key
    KdfResult derivedKey = deriveKey(key, symmetric, kdf, n, r, p, hash);

    CryptoBlock[] blocks;
    ulong processed = 0;
    ulong totalSize = additional.length;
    for(ushort i = 0; i < chunks; i++) {
        const ulong chunkLen = (data.length-processed) >= chunkSize ? chunkSize : (data.length-processed);
        const ubyte[] ad = (chunkLen < chunkSize) ? additional : null;
        ubyte[] iv = random(getCipherIVLength(symmetric));
        const ubyte[] ep = data[processed..processed+chunkLen];
        CryptographicResult result = encrypt_ex(derivedKey.key, iv, ep, ad, symmetric);
        ubyte[] auth = !isAeadCipher(symmetric) ? hmac_ex(derivedKey.key, result.data, hash) : null;
        blocks ~= CryptoBlock(symmetric, hash, kdf, n, r, p, chunks, i, derivedKey.salt, iv, auth !is null ? auth : result.auth, ad, result.data);
        totalSize += (blocks[i].sectionSize + 28);
        processed += chunkLen;
    }

    OutBuffer buffer = new OutBuffer();
    buffer.reserve(totalSize);
    foreach(CryptoBlock block; blocks) {
        buffer.write(block.toBytes());
    }
    return buffer.toBytes();
}

@trusted public CryptographicResult encrypt_ex(const ubyte[] key, const ubyte[] iv, const ubyte[] data, const ubyte[] additional, SymmetricAlgorithm algorithm) {
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
    if (EVP_EncryptInit_ex(ctx, null, null, key.ptr, iv.ptr) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Write the additional data to the cipher context, if any
    if (additional !is null && isAeadCipher(algorithm)) {
        int aadLen = 0;
        if (EVP_EncryptUpdate(ctx, null, &aadLen, additional.ptr, cast(int)additional.length) != 1) {
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

    //Extract the auth tag
    ubyte[] auth = isAeadCipher(algorithm) ? new ubyte[getAuthLength(algorithm)] : null;
    if (isAeadCipher(algorithm)) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, getAuthLength(algorithm), auth.ptr) != 1) {
            throw new CryptographicException("Unable to extract the authentication tag from the cipher context.");
        }
    }

    return CryptographicResult(output[0..written], auth);
}

@trusted public ubyte[] decrypt(const ubyte[] key, const ubyte[] data) {
    //Get Derived Key
    CryptoBlock block = CryptoBlock(data);
    const ushort totalSections = block.sectionCount;
    KdfResult derivedKey = deriveKey(key, block.symmetric, block.kdf, block.kdfIterations, block.scryptMemory, block.scryptParallelism, block.hash);

    OutBuffer buffer = new OutBuffer();
    for(ushort i = 0; i < totalSections; i++) {
        ubyte[] auth = !isAeadCipher(block.symmetric) ? hmac_ex(derivedKey.key, block.encrypted, block.hash) : null;
        if (auth !is null && !constantTimeEquality(block.auth, auth)) {
            throw new CryptographicException("Block authentication failed!");
        }

        ubyte[] result = decrypt_ex(derivedKey.key, block.iv, block.encrypted, block.auth, block.additional, block.symmetric);

        buffer.write(result);
    }

    return buffer.toBytes();
}

@trusted public ubyte[] decrypt_ex(const ubyte[] key, const ubyte[] iv, const ubyte[] data, const ubyte[] auth, const ubyte[] additional, SymmetricAlgorithm algorithm) {
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
    if (EVP_DecryptInit_ex(ctx, getOpenSslCipher(algorithm), null, null, null) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Initialize the AEAD context
    if (isAeadCipher(algorithm)) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, cast(int)iv.length, null) != 1) {
            throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
        }
    }

    //Set the Key and IV
    if (EVP_DecryptInit_ex(ctx, null, null, key.ptr, iv.ptr) != 1) {
        throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");
    }

    //Write the additional data to the cipher context, if any
    if (additional !is null && isAeadCipher(algorithm)) {
        int aadLen = 0;
        if (EVP_DecryptUpdate(ctx, null, &aadLen, additional.ptr, cast(int)additional.length) != 1) {
            throw new CryptographicException("Unable to write bytes to cipher context.");
        }
    }

    //Write data to the cipher context
    int written = 0;
    int len = 0;
    ubyte[] output = new ubyte[data.length];
    if (EVP_DecryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1) {
        throw new CryptographicException("Unable to write bytes to cipher context.");
    }
    written += len;

    //Use the supplied tag to verify the message
    if (isAeadCipher(algorithm)) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, cast(int)auth.length, (cast(ubyte[])auth).ptr) != 1) {
            throw new CryptographicException("Unable to extract the authentication tag from the cipher context.");
        }
    }

    //Extract the complete plaintext
    if (EVP_DecryptFinal_ex(ctx, &output[written-1], &len) != 1) {
        throw new CryptographicException("Unable to extract the plaintext from the cipher context.");
    }
    written += len;

    return output[0..written];
}

@safe private KdfResult deriveKey(const ubyte[] key, SymmetricAlgorithm symmetric, KdfAlgorithm kdf, uint n, ushort r, ushort p, HashAlgorithm hash) {
    ubyte[] derivedKey;
    ubyte[] salt = random(getHashLength(hash));
    if (kdf == KdfAlgorithm.PBKDF2) {
        derivedKey = pbkdf2_ex(to!string(key), salt, hash, getCipherKeyLength(symmetric), n);
    }
    if (kdf == KdfAlgorithm.PBKDF2_HKDF) {
        derivedKey = pbkdf2_ex(to!string(key), salt, hash, getCipherKeyLength(symmetric), n);
        derivedKey = hkdf_ex(derivedKey, salt, string.init, getCipherKeyLength(symmetric), hash);
    }
    if (kdf == KdfAlgorithm.SCrypt) {
        derivedKey = scrypt_ex(key, salt, n, r, p, maxSCryptMemory, getCipherKeyLength(symmetric));
    }
    if (kdf == KdfAlgorithm.SCrypt_HKDF) {
        derivedKey = scrypt_ex(key, salt, n, r, p, maxSCryptMemory, getCipherKeyLength(symmetric));
        derivedKey = hkdf_ex(derivedKey, salt, string.init, getCipherKeyLength(symmetric), hash);
    }
    return KdfResult(salt, derivedKey);
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

    writeln("Testing Encryption (No Additional Data)");

    ubyte[32] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    string input = "The quick brown fox jumps over the lazy dog.";
    writeln("Encryption Input: ", input);
    ubyte[] enc = encrypt(key, cast(ubyte[])input);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc));

    writeln("Testing Decryption (No Additional Data)");
    ubyte[] dec = decrypt(key, enc);
    writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc));
    writeln("Decryption Output: ", cast(string)dec);

    assert((cast(string)dec) == input);
}
