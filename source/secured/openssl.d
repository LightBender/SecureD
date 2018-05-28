module secured.openssl;

version(OpenSSL):
import deimos.openssl.evp;

private:

enum int EVP_PKEY_ALG_CTRL = 0x1000;
enum int EVP_PKEY_CTRL_HKDF_MD = (EVP_PKEY_ALG_CTRL + 3);
enum int EVP_PKEY_CTRL_HKDF_SALT = (EVP_PKEY_ALG_CTRL + 4);
enum int EVP_PKEY_CTRL_HKDF_KEY = (EVP_PKEY_ALG_CTRL + 5);
enum int EVP_PKEY_CTRL_HKDF_INFO = (EVP_PKEY_ALG_CTRL + 6);

public:
extern (C):
nothrow:

EVP_MD_CTX* EVP_MD_CTX_new();
void EVP_MD_CTX_free(EVP_MD_CTX* free);
void EVP_MD_CIPHER_free(EVP_CIPHER_CTX* free);

enum int EVP_PKEY_HKDF = 1036;

int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *pctx, const EVP_MD *md) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD, 0, cast(void *)(md));
}

int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, ubyte[] salt) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_SALT, cast(int)salt.length, cast(void *)salt.ptr);
}

int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, ubyte[] key) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_KEY, cast(int)key.length, cast(void *)key.ptr);
}

int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *pctx, string info) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_INFO, cast(int)(cast(ubyte[])info).length, cast(void *)info);
}
