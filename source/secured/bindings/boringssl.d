module secured.bindings.boringssl;

/*
 * BoringSSL exposes an OpenSSL-compatible libcrypto EVP ABI, so SecureD's shared
 * EVP-based implementation is reused for BoringSSL. This module re-exports the
 * OpenSSL bindings and serves as the home for any BoringSSL-specific shims.
 *
 * BoringSSL omits some algorithms (for example EVP_PBE_scrypt and certain SHA3
 * variants). Those gaps are handled by the provider dispatch/capability layer,
 * which routes unsupported algorithms to the polyfill.
 */

public import secured.bindings.openssl;
