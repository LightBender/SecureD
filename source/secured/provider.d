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

public enum Provider : ubyte {
    OpenSSL,
    LibreSSL,
    BoringSSL,
    CNG,
    CommonCrypto,
}

// Explicit provider selection, otherwise OS-native default.
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

// True when the polyfill (OpenSSL) may be used to fill algorithm gaps.
version (Secured_Polyfill) enum bool polyfillEnabled = true;
else                       enum bool polyfillEnabled = false;

/*
 * True when the OpenSSL/EVP binding is part of this build. OpenSSL, LibreSSL and
 * BoringSSL all expose the same EVP_* symbols via their "crypto" library, and
 * the polyfill links real OpenSSL. All OpenSSL symbol usage MUST be gated behind
 * this flag (via `static if`) so that native-only builds do not force libcrypto
 * to be linked.
 */
enum bool usesOpenSSL =
    activeProvider == Provider.OpenSSL ||
    activeProvider == Provider.LibreSSL ||
    activeProvider == Provider.BoringSSL ||
    polyfillEnabled;
