module secured.symmetric;

import secured.mac;
import secured.random;
import secured.util;

public enum MacFunction : ubyte {
    None,
    HMAC_SHA2_224,
    HMAC_SHA2_256,
    HMAC_SHA2_384,
    HMAC_SHA2_512,
    HMAC_SHA2_512_224,
    HMAC_SHA2_512_256,
    HMAC_SHA3_224,
    HMAC_SHA3_256,
    HMAC_SHA3_384,
    HMAC_SHA3_512,
}

// Anatomy of an Algorithm ID
// AES256_CTR_PBKDF2_HKDF_HMAC_SHA2_384
// ------ --- ------ ---- ---- --------
//    1    2     3     4    5      6
// 1. Cipher + Strength
// 2. Cipher Mode
// 3. Key Deriviation Key Generator
// 4. Key Material Extractor
// 5. (Optional) Message Authentication Code (if Cipher does not provide one)
// 6. Hash Algorithm used by 4, 5, and 6 (used as salt size if no salt provided)

public enum SafeAlgorithms : ushort {
    Default = AES256_GCM_PBKDF2_HKDF_SHA2_384,
    AES256_GCM_PBKDF2_HKDF_SHA2_384 = 0,
    AES256_CCM_PBKDF2_HKDF_SHA2_384 = 1,
    AES256_CTR_PBKDF2_HKDF_HMAC_SHA2_384 = 2,
}

public enum EncryptionAlgorithms : ushort {
    Default = AES256_GCM_PBKDF2_HKDF_SHA2_384,
    AES256_GCM_PBKDF2_HKDF_SHA2_384 = 0,
    AES256_CCM_PBKDF2_HKDF_SHA2_384 = 1,
    AES256_CTR_PBKDF2_HKDF_HMAC_SHA2_384 = 2,
    AES128_GCM_NONE,
    AES128_CCM_NONE,
    AES128_CTR_NONE,
    AES128_CBC_NONE,
    AES192_GCM_NONE,
    AES192_CCM_NONE,
    AES192_CTR_NONE,
    AES192_CBC_NONE,
    AES256_GCM_NONE,
    AES256_CCM_NONE,
    AES256_CTR_NONE,
    AES256_CBC_NONE,
}

private struct cryptoHeader {
    public ubyte hdrVersion;    // The version of the header
    public ushort algo;         // The hash algorithm used
    public uint kdfIters;       // The number of PBKDF2 iterations

    public ubyte saltLen;       // The length of the KDK Salt
    public uint encLen;         // The length of the encrypted data
    public uint adLen;          // The length of the additional data
}
