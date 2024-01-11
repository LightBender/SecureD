module secured.openssl;

import deimos.openssl.evp;
import core.stdc.stdint;

private:

enum int EVP_PKEY_ALG_CTRL = 0x1000;
enum int EVP_PKEY_CTRL_HKDF_MD = (EVP_PKEY_ALG_CTRL + 3);
enum int EVP_PKEY_CTRL_HKDF_SALT = (EVP_PKEY_ALG_CTRL + 4);
enum int EVP_PKEY_CTRL_HKDF_KEY = (EVP_PKEY_ALG_CTRL + 5);
enum int EVP_PKEY_CTRL_HKDF_INFO = (EVP_PKEY_ALG_CTRL + 6);
enum int EVP_PKEY_CTRL_HKDF_MODE = (EVP_PKEY_ALG_CTRL + 7);
enum int EVP_PKEY_CTRL_PASS = (EVP_PKEY_ALG_CTRL + 8);
enum int EVP_PKEY_CTRL_SCRYPT_SALT = (EVP_PKEY_ALG_CTRL + 9);
enum int EVP_PKEY_CTRL_SCRYPT_N = (EVP_PKEY_ALG_CTRL + 10);
enum int EVP_PKEY_CTRL_SCRYPT_R = (EVP_PKEY_ALG_CTRL + 11);
enum int EVP_PKEY_CTRL_SCRYPT_P = (EVP_PKEY_ALG_CTRL + 12);
enum int EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES = (EVP_PKEY_ALG_CTRL + 13);

extern (C):
nothrow:
public:

ulong ERR_get_error();
ulong ERR_peek_error();
void ERR_error_string_n(ulong e, char *buf, size_t len);

void EVP_MD_CIPHER_free(EVP_CIPHER_CTX* free);

struct ossl_param_st {
    char *key;                  /* the name of the parameter */
    uint data_type;             /* declare what kind of content is in buffer */
    void *data;                 /* value being passed in or out */
    size_t data_size;           /* data size */
    size_t return_size;         /* returned content size */
};

ossl_param_st OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_octet_ptr(const char *key, void **buf, size_t bsize);
ossl_param_st OSSL_PARAM_construct_end();

int EVP_KDF_CTX_set_params(EVP_KDF_CTX* ctx, const(ossl_param_st)* params);

const(EVP_MD)* EVP_sha512_224();
const(EVP_MD)* EVP_sha512_256();
const(EVP_MD)* EVP_sha3_224();
const(EVP_MD)* EVP_sha3_256();
const(EVP_MD)* EVP_sha3_384();
const(EVP_MD)* EVP_sha3_512();

extern(D):

enum int EVP_PKEY_HKDF = 1036;
enum int EVP_PKEY_SCRYPT = 973;
enum int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
enum int EVP_CTRL_AEAD_GET_TAG = 0x10;
enum int EVP_CTRL_AEAD_SET_TAG = 0x11;

int EVP_PKEY_CTX_set1_pbe_pass(EVP_PKEY_CTX *pctx, const ubyte[] password) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_PASS, cast(int)password.length, cast(void *)(password));
}

int EVP_PKEY_CTX_set1_scrypt_salt(EVP_PKEY_CTX *pctx, const ubyte[] salt) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_SALT, cast(int)salt.length, cast(void *)(salt));
}

int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX *pctx, ulong n) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, 0, cast(void*)n);
}

int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX *pctx, ulong r) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_R, 0, cast(void*)r);
}

int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX *pctx, ulong p) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_P, 0, cast(void*)p);
}
