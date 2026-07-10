/**
 * SecureD — high-level, provider-agnostic cryptography for D.
 *
 * Public API surface re-exported by this package:
 *   - $(D secured.ecc)       — ECDH / ECDSA (default curve P-384)
 *   - $(D secured.hash)      — cryptographic hashes (default SHA2-384)
 *   - $(D secured.kdf)       — PBKDF2, HKDF, scrypt, password helpers
 *   - $(D secured.mac)       — HMAC (default SHA2-384)
 *   - $(D secured.random)    — OS CSPRNG
 *   - $(D secured.rsa)       — RSA seal/open, encrypt/decrypt, sign/verify
 *   - $(D secured.symmetric) — AEAD and authenticated non-AEAD ciphers
 *                              (default AES-256-GCM)
 *   - $(D secured.util)      — exceptions and constant-time equality
 *
 * Defaults favour algorithms that are widely available on Windows CNG, Apple
 * CommonCrypto, and OpenSSL, with solid modern security margins (SHA2-384,
 * AES-256-GCM, P-384, RSA-4096).
 */
module secured;

public import secured.ecc;
public import secured.hash;
public import secured.kdf;
public import secured.mac;
public import secured.random;
public import secured.rsa;
public import secured.symmetric;
public import secured.util;

