module secured.bindings.openssl;

/*
 * Vendored bindings for the OpenSSL 3.x libcrypto API.
 *
 * SecureD previously depended on the Deimos OpenSSL package. To remove that
 * external dependency, the (small) subset of the OpenSSL API actually used by
 * SecureD is declared directly here. These are plain declarations: they only
 * create a link dependency on libcrypto when they are actually called, which
 * happens exclusively from the OpenSSL provider implementations (gated by the
 * provider dispatch). Native-only builds therefore never pull in libcrypto.
 *
 * OpenSSL, LibreSSL and BoringSSL all expose these EVP symbols with the same
 * ABI, so this module serves all three providers as well as the polyfill.
 */

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------
struct EVP_MD;
struct EVP_MD_CTX;
struct EVP_PKEY;
struct EVP_PKEY_CTX;
struct EVP_CIPHER;
struct EVP_CIPHER_CTX;
struct EVP_KDF;
struct EVP_KDF_CTX;
struct BIO;
struct BIO_METHOD;
struct ENGINE;
struct OSSL_LIB_CTX;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
enum int EVP_MAX_IV_LENGTH = 16;

enum int EVP_PKEY_RSA  = 6;    // NID_rsaEncryption
enum int EVP_PKEY_EC   = 408;  // NID_X9_62_id_ecPublicKey
enum int EVP_PKEY_HMAC = 855;  // NID_hmac

enum int RSA_PKCS1_OAEP_PADDING = 4;

enum int NID_X9_62_prime256v1 = 415;  // NIST P-256 (secp256r1)
enum int NID_secp256k1 = 714;
enum int NID_secp384r1 = 715;
enum int NID_secp521r1 = 716;

enum int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
enum int EVP_CTRL_AEAD_GET_TAG   = 0x10;
enum int EVP_CTRL_AEAD_SET_TAG   = 0x11;

// OSSL_PARAM element used by the KDF (HKDF) parameter arrays.
struct ossl_param_st {
    char*  key;         // the name of the parameter
    uint   data_type;   // declares what kind of content is in buffer
    void*  data;        // value being passed in or out
    size_t data_size;   // data size
    size_t return_size; // returned content size
}

extern (C):
nothrow:

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------
ulong ERR_get_error();
ulong ERR_peek_error();
void  ERR_error_string_n(ulong e, char* buf, size_t len);

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------
void RAND_seed(const(void)* buf, int num);

// ---------------------------------------------------------------------------
// Message digests
// ---------------------------------------------------------------------------
EVP_MD_CTX* EVP_MD_CTX_new();
void        EVP_MD_CTX_free(EVP_MD_CTX* ctx);
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const(EVP_MD)* type, ENGINE* impl);
int EVP_DigestUpdate(EVP_MD_CTX* ctx, const(void)* d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, ubyte* md, uint* s);

int EVP_DigestSignInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int EVP_DigestSignFinal(EVP_MD_CTX* ctx, ubyte* sigret, size_t* siglen);
int EVP_DigestVerifyInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int EVP_DigestVerifyFinal(EVP_MD_CTX* ctx, ubyte* sig, size_t siglen);

// EVP_DigestSignUpdate/EVP_DigestVerifyUpdate are aliases for EVP_DigestUpdate.
alias EVP_DigestSignUpdate   = EVP_DigestUpdate;
alias EVP_DigestVerifyUpdate = EVP_DigestUpdate;

const(EVP_MD)* EVP_sha256();
const(EVP_MD)* EVP_sha384();
const(EVP_MD)* EVP_sha512();
const(EVP_MD)* EVP_sha512_224();
const(EVP_MD)* EVP_sha512_256();
const(EVP_MD)* EVP_sha3_224();
const(EVP_MD)* EVP_sha3_256();
const(EVP_MD)* EVP_sha3_384();
const(EVP_MD)* EVP_sha3_512();

// ---------------------------------------------------------------------------
// Public/private key operations
// ---------------------------------------------------------------------------
void EVP_PKEY_free(EVP_PKEY* pkey);
int  EVP_PKEY_get_size(EVP_PKEY* pkey);
EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY* pkey, ENGINE* e);
EVP_PKEY_CTX* EVP_PKEY_CTX_new_id(int id, ENGINE* e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX* ctx);
EVP_PKEY* EVP_PKEY_new_mac_key(int type, ENGINE* e, const(ubyte)* key, int keylen);

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);

int EVP_PKEY_derive_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX* ctx, EVP_PKEY* peer);
int EVP_PKEY_derive(EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);

int EVP_PKEY_sign_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const(ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX* ctx, const(ubyte)* sig, size_t siglen, const(ubyte)* tbs, size_t tbslen);

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);

// Real exported functions in OpenSSL 3.x (previously ctrl-based macros).
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX* ctx, void* md);
int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int bits);
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX* ctx, int pad);
int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX* ctx, const(EVP_MD)* md);
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX* ctx, const(EVP_MD)* md);
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX* ctx, int nid);

// Default PKCS#5/PKCS#8 PBKDF2 iteration count used by PEM_write_bio_PKCS8PrivateKey.
enum int PKCS5_DEFAULT_ITER = 2048;

// ---------------------------------------------------------------------------
// Symmetric ciphers
// ---------------------------------------------------------------------------
EVP_CIPHER_CTX* EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* a);
int  EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, ENGINE* impl, const(ubyte)* key, const(ubyte)* iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, ENGINE* impl, const(ubyte)* key, const(ubyte)* iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);

int EVP_SealInit(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type, ubyte** ek, int* ekl, ubyte* iv, EVP_PKEY** pubk, int npubk);
int EVP_SealFinal(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
int EVP_OpenInit(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type, const(ubyte)* ek, int ekl, const(ubyte)* iv, EVP_PKEY* priv);
int EVP_OpenFinal(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);

// EVP_SealUpdate/EVP_OpenUpdate are aliases for the cipher update functions.
alias EVP_SealUpdate = EVP_EncryptUpdate;
alias EVP_OpenUpdate = EVP_DecryptUpdate;

const(EVP_CIPHER)* EVP_aes_128_gcm();
const(EVP_CIPHER)* EVP_aes_192_gcm();
const(EVP_CIPHER)* EVP_aes_256_gcm();
const(EVP_CIPHER)* EVP_aes_128_ctr();
const(EVP_CIPHER)* EVP_aes_192_ctr();
const(EVP_CIPHER)* EVP_aes_256_ctr();
const(EVP_CIPHER)* EVP_aes_128_cfb128();
const(EVP_CIPHER)* EVP_aes_192_cfb128();
const(EVP_CIPHER)* EVP_aes_256_cfb128();
alias EVP_aes_128_cfb = EVP_aes_128_cfb128;
alias EVP_aes_192_cfb = EVP_aes_192_cfb128;
alias EVP_aes_256_cfb = EVP_aes_256_cfb128;
const(EVP_CIPHER)* EVP_aes_128_cbc();
const(EVP_CIPHER)* EVP_aes_192_cbc();
const(EVP_CIPHER)* EVP_aes_256_cbc();
const(EVP_CIPHER)* EVP_chacha20();
const(EVP_CIPHER)* EVP_chacha20_poly1305();
const(EVP_CIPHER)* EVP_des_ede3_cbc();

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------
int PKCS5_PBKDF2_HMAC(const(char)* pass, int passlen, const(ubyte)* salt, int saltlen, int iter, const(EVP_MD)* digest, int keylen, ubyte* out_);
int EVP_PBE_scrypt(const(char)* pass, size_t passlen, const(ubyte)* salt, size_t saltlen, ulong N, ulong r, ulong p, ulong maxmem, ubyte* key, size_t keylen);

EVP_KDF*     EVP_KDF_fetch(OSSL_LIB_CTX* libctx, const(char)* algorithm, const(char)* properties);
void         EVP_KDF_free(EVP_KDF* kdf);
EVP_KDF_CTX* EVP_KDF_CTX_new(EVP_KDF* kdf);
void         EVP_KDF_CTX_free(EVP_KDF_CTX* ctx);
int          EVP_KDF_derive(EVP_KDF_CTX* ctx, ubyte* key, size_t keylen, const(ossl_param_st)* params);
int          EVP_KDF_CTX_set_params(EVP_KDF_CTX* ctx, const(ossl_param_st)* params);

ossl_param_st OSSL_PARAM_construct_utf8_string(const(char)* key, char* buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_octet_string(const(char)* key, void* buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_utf8_ptr(const(char)* key, char** buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_octet_ptr(const(char)* key, void** buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_end();

// ---------------------------------------------------------------------------
// BIO (memory buffers used for PEM encode/decode)
// ---------------------------------------------------------------------------
BIO*        BIO_new(BIO_METHOD* type);
BIO_METHOD* BIO_s_mem();
BIO*        BIO_new_mem_buf(void* buf, int len);
void        BIO_free_all(BIO* a);
int         BIO_read(BIO* b, void* data, int len);
size_t      BIO_ctrl_pending(BIO* b);

// ---------------------------------------------------------------------------
// PEM serialization (password callback is always null at the call sites)
// ---------------------------------------------------------------------------
EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, void* cb, void* u);
EVP_PKEY* PEM_read_bio_PUBKEY(BIO* bp, EVP_PKEY** x, void* cb, void* u);
int PEM_write_bio_PUBKEY(BIO* bp, EVP_PKEY* x);
int PEM_write_bio_PKCS8PrivateKey(BIO* bp, EVP_PKEY* x, const(EVP_CIPHER)* enc, char* kstr, int klen, void* cb, void* u);
