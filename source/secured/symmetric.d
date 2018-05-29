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

public enum EncryptionAlgorithm : ubyte {
    AES128_CTR,
    AES192_CTR,
    AES256_CTR,
    AES128_CBC,
    AES192_CBC,
    AES256_CBC,
}

private struct cryptoHeader {
    public ubyte hdrVersion;    // The version of the header
    public ubyte encAlg;        // The encryption algorithm used
    public ubyte hashAlg;       // The hash algorithm used
    public uint kdfIters;       // The number of PBKDF2 iterations

    public ubyte saltLen;       // The length of the KDK/MAC/KEY Salts
    public ubyte ivLen;         // The length of the IV
    public ulong encLen;        // The length of the encrypted data
    public ulong adLen;         // The length of the additional data
    public ubyte authLen;       // The length of the authentication value
}


