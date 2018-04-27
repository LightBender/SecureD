module secured.openssl;

version(OpenSSL):
import deimos.openssl.evp;

public:
extern (C):
nothrow:

version(OpenSSL10) {
alias EVP_MD_CTX_new = EVP_MD_CTX_create;
alias EVP_MD_CTX_free = EVP_MD_CTX_destroy;
} else {
EVP_MD_CTX* EVP_MD_CTX_new();
void EVP_MD_CTX_free(EVP_MD_CTX* free);
void EVP_MD_CIPHER_free(EVP_CIPHER_CTX* free);
}
