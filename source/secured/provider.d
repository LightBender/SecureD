module secured.provider;

/*
 * Central compile-time provider selection for SecureD.
 *
 * The active cryptographic provider is chosen at build time via version
 * identifiers set by the dub configurations (see dub.sdl). When no provider is
 * explicitly selected the OS-native provider is used:
 *   - Windows -> CNG
 *   - macOS   -> CommonCrypto
 *   - else    -> OpenSSL
 *
 * The "polyfill" configuration additionally defines Secured_Polyfill which
 * enables the OpenSSL implementation to fill in any algorithm the selected
 * provider cannot supply.
 *
 * This module intentionally has NO dependency on the algorithm modules so that
 * it can be imported everywhere without creating import cycles.
 */

/**
 * Cryptographic backend selected at build time via dub configurations.
 *
 * SecureD never implements primitives itself; every operation is dispatched to
 * one of these providers (or to OpenSSL as a polyfill for missing algorithms).
 */
public enum Provider : ubyte {
    /// OpenSSL (libcrypto) EVP API.
    OpenSSL,
    /// LibreSSL (OpenSSL-compatible EVP API).
    LibreSSL,
    /// BoringSSL (OpenSSL-compatible EVP API).
    BoringSSL,
    /// Windows Cryptography API: Next Generation (bcrypt).
    CNG,
    /// Apple CommonCrypto + Security framework (macOS).
    CommonCrypto,
}

/**
 * The cryptographic provider selected for this build.
 *
 * Chosen at compile time via dub version identifiers (`Secured_OpenSSL`,
 * `Secured_CNG`, etc.). When none is set, defaults to the OS-native backend:
 * CNG on Windows, CommonCrypto on macOS, OpenSSL elsewhere.
 */
version (Secured_OpenSSL)             enum Provider activeProvider = Provider.OpenSSL;
else version (Secured_LibreSSL)       enum Provider activeProvider = Provider.LibreSSL;
else version (Secured_BoringSSL)      enum Provider activeProvider = Provider.BoringSSL;
else version (Secured_CNG)            enum Provider activeProvider = Provider.CNG;
else version (Secured_CommonCrypto)   enum Provider activeProvider = Provider.CommonCrypto;
else {
    version (Windows)  enum Provider activeProvider = Provider.CNG;
    else version (OSX) enum Provider activeProvider = Provider.CommonCrypto;
    else               enum Provider activeProvider = Provider.OpenSSL;
}

/**
 * `true` when the OpenSSL polyfill may fill algorithm gaps left by the active
 * native provider (enabled by the `polyfill` dub configuration).
 */
version (Secured_Polyfill) enum bool polyfillEnabled = true;
else                       enum bool polyfillEnabled = false;

/**
 * `true` when the OpenSSL/EVP binding is part of this build.
 *
 * OpenSSL, LibreSSL and BoringSSL all expose the same EVP_* symbols via their
 * "crypto" library, and the polyfill links real OpenSSL. All OpenSSL symbol
 * usage MUST be gated behind this flag (via `static if`) so that native-only
 * builds do not force libcrypto to be linked.
 */
enum bool usesOpenSSL =
    activeProvider == Provider.OpenSSL ||
    activeProvider == Provider.LibreSSL ||
    activeProvider == Provider.BoringSSL ||
    polyfillEnabled;
