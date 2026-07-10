module secured.bindings.cng;

/*
 * Bindings for the Windows Cryptography API: Next Generation (CNG).
 *
 * These declarations map to bcrypt.dll (BCrypt*) and ncrypt.dll (NCrypt*). They
 * are only declared on Windows; on other platforms this module compiles to an
 * empty translation unit so that it can live in the shared source tree.
 *
 * Only the surface required by SecureD's provider implementations is declared
 * here. Symbols are not linked unless actually referenced by a compiled code
 * path, so importing this module is safe on builds that do not use CNG.
 */

version (Windows):

import core.sys.windows.windows : PUCHAR, ULONG, LONG, PWSTR, PVOID, LPCWSTR;

extern (Windows):
nothrow:
@nogc:

alias NTSTATUS = LONG;
alias BCRYPT_HANDLE = PVOID;
alias BCRYPT_ALG_HANDLE = PVOID;
alias BCRYPT_HASH_HANDLE = PVOID;
alias BCRYPT_KEY_HANDLE = PVOID;

// Status codes
enum NTSTATUS STATUS_SUCCESS = 0x00000000;

// BCryptOpenAlgorithmProvider flags
enum ULONG BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;

// Property names (LPCWSTR)
enum wstring BCRYPT_OBJECT_LENGTH    = "ObjectLength"w;
enum wstring BCRYPT_HASH_LENGTH      = "HashDigestLength"w;
enum wstring BCRYPT_CHAINING_MODE    = "ChainingMode"w;
enum wstring BCRYPT_BLOCK_LENGTH     = "BlockLength"w;
enum wstring BCRYPT_KEY_LENGTH       = "KeyLength"w;

// Chaining mode values (LPCWSTR)
enum wstring BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC"w;
enum wstring BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB"w;
enum wstring BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"w;
enum wstring BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB"w;

// BCryptEncrypt/BCryptDecrypt flags
enum ULONG BCRYPT_BLOCK_PADDING = 0x00000001;

// Algorithm identifiers (LPCWSTR)
enum wstring BCRYPT_SHA256_ALGORITHM = "SHA256"w;
enum wstring BCRYPT_SHA384_ALGORITHM = "SHA384"w;
enum wstring BCRYPT_SHA512_ALGORITHM = "SHA512"w;
enum wstring BCRYPT_SHA3_256_ALGORITHM = "SHA3-256"w;
enum wstring BCRYPT_SHA3_384_ALGORITHM = "SHA3-384"w;
enum wstring BCRYPT_SHA3_512_ALGORITHM = "SHA3-512"w;
enum wstring BCRYPT_AES_ALGORITHM    = "AES"w;
enum wstring BCRYPT_RNG_ALGORITHM    = "RNG"w;

// AEAD auth info structure for GCM
struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG   cbSize;
    ULONG   dwInfoVersion;
    PUCHAR  pbNonce;
    ULONG   cbNonce;
    PUCHAR  pbAuthData;
    ULONG   cbAuthData;
    PUCHAR  pbTag;
    ULONG   cbTag;
    PUCHAR  pbMacContext;
    ULONG   cbMacContext;
    ULONG   cbAAD;
    ulong   cbData;
    ULONG   dwFlags;
}

enum ULONG BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x00000001;

// Algorithm provider management
NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);

// Property access
NTSTATUS BCryptGetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS BCryptSetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);

// Hash / HMAC
NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);

// Symmetric encryption
NTSTATUS BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
NTSTATUS BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, PVOID pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, PVOID pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);

// Random
NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
enum ULONG BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;

// Key derivation
NTSTATUS BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ulong cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags);

// RSA algorithm identifier (LPCWSTR)
enum wstring BCRYPT_RSA_ALGORITHM  = "RSA"w;
enum wstring BCRYPT_SHA1_ALGORITHM = "SHA1"w;

// RSA key blob types (LPCWSTR)
enum wstring BCRYPT_RSAPUBLIC_BLOB      = "RSAPUBLICBLOB"w;
enum wstring BCRYPT_RSAPRIVATE_BLOB     = "RSAPRIVATEBLOB"w;
enum wstring BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB"w;

// Asymmetric padding flags for BCryptEncrypt/Decrypt/SignHash/VerifySignature
enum ULONG BCRYPT_PAD_PKCS1 = 0x00000002;
enum ULONG BCRYPT_PAD_OAEP  = 0x00000004;
enum ULONG BCRYPT_PAD_PSS   = 0x00000008;

// Padding info structures
struct BCRYPT_OAEP_PADDING_INFO {
    LPCWSTR pszAlgId;
    PUCHAR  pbLabel;
    ULONG   cbLabel;
}

struct BCRYPT_PKCS1_PADDING_INFO {
    LPCWSTR pszAlgId;
}

// Header shared by every RSA key blob; the key material follows immediately.
struct BCRYPT_RSAKEY_BLOB {
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
}

// RSA key pair management
NTSTATUS BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, ULONG dwLength, ULONG dwFlags);
NTSTATUS BCryptFinalizeKeyPair(BCRYPT_KEY_HANDLE hKey, ULONG dwFlags);
NTSTATUS BCryptExportKey(BCRYPT_KEY_HANDLE hKey, BCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS BCryptImportKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS BCryptSignHash(BCRYPT_KEY_HANDLE hKey, PVOID pPaddingInfo, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, PVOID pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags);

// ---- Elliptic Curve (ECDSA / ECDH) ----------------------------------------
alias BCRYPT_SECRET_HANDLE = PVOID;

// Named curve algorithm identifiers (LPCWSTR).
enum wstring BCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256"w;
enum wstring BCRYPT_ECDSA_P384_ALGORITHM = "ECDSA_P384"w;
enum wstring BCRYPT_ECDSA_P521_ALGORITHM = "ECDSA_P521"w;
enum wstring BCRYPT_ECDH_P256_ALGORITHM  = "ECDH_P256"w;
enum wstring BCRYPT_ECDH_P384_ALGORITHM  = "ECDH_P384"w;
enum wstring BCRYPT_ECDH_P521_ALGORITHM  = "ECDH_P521"w;

// EC key blob types (LPCWSTR).
enum wstring BCRYPT_ECCPUBLIC_BLOB  = "ECCPUBLICBLOB"w;
enum wstring BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB"w;

// Raw secret KDF: returns the shared secret unmodified (little-endian).
enum wstring BCRYPT_KDF_RAW_SECRET = "TRUNCATE"w;

// EC key blob magic values (curve + ECDSA/ECDH + public/private).
enum ULONG BCRYPT_ECDSA_PUBLIC_P256_MAGIC  = 0x31534345;
enum ULONG BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345;
enum ULONG BCRYPT_ECDSA_PUBLIC_P384_MAGIC  = 0x33534345;
enum ULONG BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345;
enum ULONG BCRYPT_ECDSA_PUBLIC_P521_MAGIC  = 0x35534345;
enum ULONG BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345;
enum ULONG BCRYPT_ECDH_PUBLIC_P256_MAGIC   = 0x314B4345;
enum ULONG BCRYPT_ECDH_PRIVATE_P256_MAGIC  = 0x324B4345;
enum ULONG BCRYPT_ECDH_PUBLIC_P384_MAGIC   = 0x334B4345;
enum ULONG BCRYPT_ECDH_PRIVATE_P384_MAGIC  = 0x344B4345;
enum ULONG BCRYPT_ECDH_PUBLIC_P521_MAGIC   = 0x354B4345;
enum ULONG BCRYPT_ECDH_PRIVATE_P521_MAGIC  = 0x364B4345;

// Header shared by every EC key blob; the key material (X, Y[, d]) follows.
struct BCRYPT_ECCKEY_BLOB {
    ULONG dwMagic;
    ULONG cbKey;
}

NTSTATUS BCryptSecretAgreement(BCRYPT_KEY_HANDLE hPrivKey, BCRYPT_KEY_HANDLE hPubKey, BCRYPT_SECRET_HANDLE* phAgreedSecret, ULONG dwFlags);
NTSTATUS BCryptDeriveKey(BCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF, PVOID pParameterList, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS BCryptDestroySecret(BCRYPT_SECRET_HANDLE hSecret);
