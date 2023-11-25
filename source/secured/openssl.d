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
//nothrow:
public:

ulong ERR_get_error();
ulong ERR_peek_error();
void ERR_error_string_n(ulong e, char *buf, size_t len);

EVP_MD_CTX* EVP_MD_CTX_new();
void EVP_MD_CTX_free(EVP_MD_CTX* free);
void EVP_MD_CIPHER_free(EVP_CIPHER_CTX* free);
int EVP_PBE_scrypt(const char *pass, size_t passlen, const ubyte *salt, size_t saltlen, ulong N, ulong r, ulong p, ulong maxmem, ubyte *key, size_t keylen);
int EVP_PKEY_get_size(EVP_PKEY* pkey);
int EVP_PKEY_CTX_hkdf_mode(EVP_PKEY_CTX *pctx, int mode);

const(EVP_CIPHER)* EVP_chacha20();
const(EVP_CIPHER)* EVP_chacha20_poly1305();

extern(D):

enum int EVP_PKEY_HKDF = 1036;
enum int EVP_PKEY_SCRYPT = 973;
enum int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
enum int EVP_CTRL_AEAD_GET_TAG = 0x10;
enum int EVP_CTRL_AEAD_SET_TAG = 0x11;

int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *pctx, int mode) {
    auto res = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MODE, 0, cast(void *)(mode));
	while (ERR_peek_error() > 0) {
		char[1024] errMsg;
		ERR_error_string_n(ERR_get_error(), errMsg.ptr, 1024);
		import std.stdio;
		writeln(errMsg);
	}
	return res;
}

int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *pctx, const EVP_MD *md) {
    auto res = EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD, 0, cast(void *)(md));
	while (ERR_peek_error() > 0) {
		char[1024] errMsg;
		ERR_error_string_n(ERR_get_error(), errMsg.ptr, 1024);
		import std.stdio;
		writeln(errMsg);
	}
	return res;
}

int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, const ubyte[] salt) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_SALT, cast(int)salt.length, cast(void *)salt.ptr);
}

int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, const ubyte[] key) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_KEY, cast(int)key.length, cast(void *)key.ptr);
}

int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *pctx, string info) {
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_INFO, cast(int)(cast(ubyte[])info).length, cast(void *)info);
}

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
