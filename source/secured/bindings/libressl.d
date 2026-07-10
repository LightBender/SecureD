module secured.bindings.libressl;

/*
 * LibreSSL exposes the same libcrypto EVP ABI as OpenSSL, so SecureD's shared
 * EVP-based implementation is reused for LibreSSL. This module re-exports the
 * OpenSSL bindings and serves as the home for any LibreSSL-specific shims.
 *
 * Capability differences (for example, older LibreSSL releases lack some SHA3
 * variants) are handled by the provider dispatch/capability layer, not here.
 */

public import secured.bindings.openssl;
