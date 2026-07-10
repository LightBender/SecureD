module secured.bindings.security;

/*
 * Bindings for Apple's Security framework (SecKey) and the minimal subset of
 * CoreFoundation required to drive it.
 *
 * Unlike CommonCrypto's asymmetric interfaces (CCRSACryptor), the Security
 * framework's SecKey API is a PUBLIC, App-Store-safe API for RSA key
 * generation, import/export, OAEP encryption and PKCS#1 signatures. SecureD
 * uses it as the native RSA backend on macOS.
 *
 * These declarations are only present on macOS; on other platforms this module
 * compiles to an empty translation unit.
 */

version (OSX):

import core.stdc.config : c_long;

extern (C):
nothrow:
@nogc:

// ---- CoreFoundation --------------------------------------------------------
alias CFTypeRef             = void*;
alias CFAllocatorRef        = void*;
alias CFDataRef             = void*;
alias CFStringRef           = void*;
alias CFDictionaryRef       = void*;
alias CFMutableDictionaryRef = void*;
alias CFNumberRef           = void*;
alias CFErrorRef            = void*;
alias CFIndex               = c_long;
alias CFNumberType          = CFIndex;
alias Boolean               = ubyte;

enum CFNumberType kCFNumberIntType = 9;

struct CFDictionaryKeyCallBacks {
    CFIndex version_;
    void*   retain;
    void*   release;
    void*   copyDescription;
    void*   equal;
    void*   hash;
}

struct CFDictionaryValueCallBacks {
    CFIndex version_;
    void*   retain;
    void*   release;
    void*   copyDescription;
    void*   equal;
}

extern __gshared CFDictionaryKeyCallBacks   kCFTypeDictionaryKeyCallBacks;
extern __gshared CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;

void          CFRelease(CFTypeRef cf);
CFDataRef     CFDataCreate(CFAllocatorRef allocator, const(ubyte)* bytes, CFIndex length);
const(ubyte)* CFDataGetBytePtr(CFDataRef theData);
CFIndex       CFDataGetLength(CFDataRef theData);
CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity,
    const(CFDictionaryKeyCallBacks)* keyCallBacks, const(CFDictionaryValueCallBacks)* valueCallBacks);
void          CFDictionaryAddValue(CFMutableDictionaryRef theDict, const(void)* key, const(void)* value);
CFNumberRef   CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const(void)* valuePtr);

// ---- Security framework ----------------------------------------------------
alias SecKeyRef       = void*;
alias SecKeyAlgorithm = CFStringRef;
alias SecRandomRef    = void*;

// Key attribute keys and values (CFStringRef globals).
extern __gshared CFStringRef kSecAttrKeyType;
extern __gshared CFStringRef kSecAttrKeyTypeRSA;
extern __gshared CFStringRef kSecAttrKeyTypeECSECPrimeRandom;
extern __gshared CFStringRef kSecAttrKeySizeInBits;
extern __gshared CFStringRef kSecAttrKeyClass;
extern __gshared CFStringRef kSecAttrKeyClassPublic;
extern __gshared CFStringRef kSecAttrKeyClassPrivate;

// SecKeyAlgorithm identifiers (CFStringRef globals).
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmRSAEncryptionOAEPSHA1;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmRSAEncryptionOAEPSHA384;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
extern __gshared SecKeyAlgorithm kSecKeyAlgorithmECDHKeyExchangeStandard;

// System CSPRNG.
extern __gshared SecRandomRef kSecRandomDefault;

SecKeyRef SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef* error);
SecKeyRef SecKeyCreateWithData(CFDataRef keyData, CFDictionaryRef attributes, CFErrorRef* error);
CFDataRef SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef* error);
SecKeyRef SecKeyCopyPublicKey(SecKeyRef key);
size_t    SecKeyGetBlockSize(SecKeyRef key);
CFDataRef SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef* error);
CFDataRef SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef* error);
CFDataRef SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef* error);
Boolean   SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef signedData, CFDataRef signature, CFErrorRef* error);
CFDataRef SecKeyCopyKeyExchangeResult(SecKeyRef privateKey, SecKeyAlgorithm algorithm, SecKeyRef publicKey, CFDictionaryRef parameters, CFErrorRef* error);
int       SecRandomCopyBytes(SecRandomRef rnd, size_t count, void* bytes);
