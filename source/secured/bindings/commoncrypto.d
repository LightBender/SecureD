module secured.bindings.commoncrypto;

/*
 * Bindings for Apple's CommonCrypto library (libcommonCrypto, part of libSystem).
 *
 * Only the PUBLIC CommonCrypto API is declared here. The private/SPI asymmetric
 * interfaces (CCECCryptor and CCRSACryptor) are intentionally NOT used because
 * they trigger App Store rejections. RSA on macOS is implemented against the
 * public Security framework SecKey API (see secured.bindings.security); ECC is
 * handled by the OpenSSL polyfill instead.
 *
 * These declarations are only present on macOS; on other platforms this module
 * compiles to an empty translation unit.
 */

version (OSX):

import core.stdc.config : c_ulong;

extern (C):
nothrow:
@nogc:

// ---- Digests (CommonDigest.h) ---------------------------------------------
enum CC_SHA256_DIGEST_LENGTH = 32;
enum CC_SHA384_DIGEST_LENGTH = 48;
enum CC_SHA512_DIGEST_LENGTH = 64;

ubyte* CC_SHA256(const(void)* data, uint len, ubyte* md);
ubyte* CC_SHA384(const(void)* data, uint len, ubyte* md);
ubyte* CC_SHA512(const(void)* data, uint len, ubyte* md);

// Streaming digest contexts
struct CC_SHA256_CTX { ubyte[104] opaque; }
struct CC_SHA512_CTX { ubyte[216] opaque; }

int CC_SHA256_Init(CC_SHA256_CTX* c);
int CC_SHA256_Update(CC_SHA256_CTX* c, const(void)* data, uint len);
int CC_SHA256_Final(ubyte* md, CC_SHA256_CTX* c);

int CC_SHA384_Init(CC_SHA512_CTX* c);
int CC_SHA384_Update(CC_SHA512_CTX* c, const(void)* data, uint len);
int CC_SHA384_Final(ubyte* md, CC_SHA512_CTX* c);

int CC_SHA512_Init(CC_SHA512_CTX* c);
int CC_SHA512_Update(CC_SHA512_CTX* c, const(void)* data, uint len);
int CC_SHA512_Final(ubyte* md, CC_SHA512_CTX* c);

// ---- HMAC (CommonHMAC.h) --------------------------------------------------
alias CCHmacAlgorithm = uint;
enum : CCHmacAlgorithm {
    kCCHmacAlgSHA1   = 0,
    kCCHmacAlgMD5    = 1,
    kCCHmacAlgSHA256 = 2,
    kCCHmacAlgSHA384 = 3,
    kCCHmacAlgSHA512 = 4,
    kCCHmacAlgSHA224 = 5,
}

void CCHmac(CCHmacAlgorithm algorithm, const(void)* key, size_t keyLength, const(void)* data, size_t dataLength, void* macOut);

// ---- Symmetric ciphers (CommonCryptor.h) ----------------------------------
alias CCCryptorStatus = int;
alias CCOperation = uint;
alias CCAlgorithm = uint;
alias CCOptions = uint;
alias CCMode = uint;
alias CCModeOptions = uint;
alias CCPadding = uint;
alias CCCryptorRef = void*;

enum CCCryptorStatus kCCSuccess = 0;

enum : CCOperation {
    kCCEncrypt = 0,
    kCCDecrypt = 1,
}

enum : CCAlgorithm {
    kCCAlgorithmAES = 0,
}

enum : CCMode {
    kCCModeECB = 1,
    kCCModeCBC = 2,
    kCCModeCFB = 3,
    kCCModeCTR = 4,
    kCCModeGCM = 11,
}

enum : CCPadding {
    ccNoPadding   = 0,
    ccPKCS7Padding = 1,
}

enum CCModeOptions kCCModeOptionCTR_BE = 2;

CCCryptorStatus CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,
    const(void)* iv, const(void)* key, size_t keyLength, const(void)* tweak, size_t tweakLength,
    int numRounds, CCModeOptions options, CCCryptorRef* cryptorRef);
CCCryptorStatus CCCryptorUpdate(CCCryptorRef cryptorRef, const(void)* dataIn, size_t dataInLength, void* dataOut, size_t dataOutAvailable, size_t* dataOutMoved);
CCCryptorStatus CCCryptorFinal(CCCryptorRef cryptorRef, void* dataOut, size_t dataOutAvailable, size_t* dataOutMoved);
CCCryptorStatus CCCryptorRelease(CCCryptorRef cryptorRef);
CCCryptorStatus CCCryptorGCMSetIV(CCCryptorRef cryptorRef, const(void)* iv, size_t ivLen);
CCCryptorStatus CCCryptorGCMAddAAD(CCCryptorRef cryptorRef, const(void)* aData, size_t aDataLen);
CCCryptorStatus CCCryptorGCMFinalize(CCCryptorRef cryptorRef, void* tag, size_t tagLength);

// One-shot AES-GCM (macOS 10.13+/iOS 11+). The decrypt variant verifies the tag
// internally and returns a non-success status on mismatch.
CCCryptorStatus CCCryptorGCMOneshotEncrypt(CCAlgorithm alg, const(void)* key, size_t keyLength,
    const(void)* iv, size_t ivLen, const(void)* aData, size_t aDataLen,
    const(void)* dataIn, size_t dataInLength, void* dataOut, void* tagOut, size_t tagLength);
CCCryptorStatus CCCryptorGCMOneshotDecrypt(CCAlgorithm alg, const(void)* key, size_t keyLength,
    const(void)* iv, size_t ivLen, const(void)* aData, size_t aDataLen,
    const(void)* dataIn, size_t dataInLength, void* dataOut, const(void)* tagIn, size_t tagLength);

// ---- Key derivation (CommonKeyDerivation.h) -------------------------------
alias CCPBKDFAlgorithm = uint;
alias CCPseudoRandomAlgorithm = uint;

enum CCPBKDFAlgorithm kCCPBKDF2 = 2;

enum : CCPseudoRandomAlgorithm {
    kCCPRFHmacAlgSHA256 = 3,
    kCCPRFHmacAlgSHA384 = 4,
    kCCPRFHmacAlgSHA512 = 5,
}

int CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm, const(char)* password, size_t passwordLen,
    const(ubyte)* salt, size_t saltLen, CCPseudoRandomAlgorithm prf, uint rounds, ubyte* derivedKey, size_t derivedKeyLen);
