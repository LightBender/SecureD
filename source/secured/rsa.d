module secured.rsa;

import secured.hash;
import secured.provider;
import secured.symmetric;
import secured.util;

/*
 * The public RSA class is a provider-agnostic dispatcher. It holds an opaque,
 * provider-specific key context (RsaKey) and forwards each operation to the
 * package-private free functions implemented by the active provider's system
 * module. This keeps a single unified API while the platform-specific FFI lives
 * entirely under secured.system.*.
 */
static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
    import secured.system.openssl : RsaKey, rsaGenerate, rsaLoadPrivateKey, rsaLoadPublicKey, rsaFree,
        rsaSeal, rsaOpen, rsaGetPublicKey, rsaGetPrivateKey, rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify;
} else static if (activeProvider == Provider.CNG) {
    import secured.system.windows : RsaKey, rsaGenerate, rsaLoadPrivateKey, rsaLoadPublicKey, rsaFree,
        rsaSeal, rsaOpen, rsaGetPublicKey, rsaGetPrivateKey, rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify;
} else static if (activeProvider == Provider.CommonCrypto) {
    import secured.system.macos : RsaKey, rsaGenerate, rsaLoadPrivateKey, rsaLoadPublicKey, rsaFree,
        rsaSeal, rsaOpen, rsaGetPublicKey, rsaGetPrivateKey, rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify;
}

@trusted:

/**
 * Provider-agnostic RSA keypair wrapper.
 *
 * Supports hybrid seal/open (RSA-OAEP + symmetric AEAD), direct RSA encrypt /
 * decrypt (OAEP), and RSA signatures. Key material is held in an opaque
 * provider-specific context and released in the destructor.
 */
public class RSA
{
    private RsaKey keypair;

    private bool _hasPrivateKey;
    /**
     * Whether this instance holds a private key (generated or loaded).
     *
     * Returns: `true` if private-key operations (open, decrypt, sign, export
     *          private key) are available.
     */
    public @property bool hasPrivateKey() { return _hasPrivateKey; }

    /**
     * Generates a new RSA keypair.
     *
     * Params:
     *   RSA_KEYLEN = Modulus size in bits. Default: 4096, a conservative
     *                long-term size with a comfortable security margin over
     *                2048-bit keys for data that must remain confidential for
     *                many years.
     */
    public this(const int RSA_KEYLEN = 4096)
    {
        keypair = rsaGenerate(RSA_KEYLEN);
        _hasPrivateKey = true;
    }

    /**
     * Loads an RSA private key from a serialized blob (PEM/provider format).
     *
     * Params:
     *   privateKey = Serialized private key bytes (as produced by
     *                $(D getPrivateKey)).
     *   password   = Password used to decrypt the private key container, or
     *                empty/null if the key is unencrypted.
     */
    public this(ubyte[] privateKey, ubyte[] password)
    {
        keypair = rsaLoadPrivateKey(privateKey, password);
        _hasPrivateKey = true;
    }

    /**
     * Loads an RSA public key only (no private key).
     *
     * Params:
     *   publicKey = Serialized public key bytes (as produced by
     *               $(D getPublicKey)).
     */
    public this(ubyte[] publicKey)
    {
        keypair = rsaLoadPublicKey(publicKey);
        _hasPrivateKey = false;
    }

    /// Releases the underlying provider key material.
    public ~this()
    {
        rsaFree(keypair);
    }

    /**
     * Hybrid-encrypts `plaintext` under a fresh AES-256-GCM session key, then
     * RSA-OAEP wraps that key using SHA2-384.
     *
     * AES-256-GCM is the default so the call succeeds on every native provider
     * (CNG does not support AES-CTR). SHA2-384 is used for OAEP/MGF1 for
     * length-extension resilience and universal OS availability.
     *
     * Params:
     *   plaintext = Data to seal (any length; bulk data is encrypted
     *               symmetrically).
     *
     * Returns: Opaque sealed envelope bytes.
     */
    ubyte[] seal(const ubyte[] plaintext)
    {
        return rsaSeal(keypair, plaintext, SymmetricAlgorithm.AES256_GCM, HashAlgorithm.Default);
    }

    /**
     * Hybrid-encrypts `plaintext` with a caller-selected symmetric algorithm
     * and RSA-OAEP using SHA2-384.
     *
     * Params:
     *   plaintext = Data to seal.
     *   algorithm = Symmetric cipher for the session key. Must be supported by
     *               the active provider (AES-256-GCM is universally available).
     *
     * Returns: Opaque sealed envelope bytes.
     *
     * Throws: $(D AlgorithmNotSupportedException) if `algorithm` is unavailable.
     */
    ubyte[] seal(const ubyte[] plaintext, SymmetricAlgorithm algorithm)
    {
        return rsaSeal(keypair, plaintext, algorithm, HashAlgorithm.Default);
    }

    /**
     * Hybrid-encrypts `plaintext` under a fresh symmetric key, then RSA-OAEP
     * wraps that key using the selected hash algorithm for OAEP/MGF1.
     *
     * The default hash is SHA2-384, which is available on every supported OS.
     * SHA-3 variants require runtime support from the active provider and throw
     * `AlgorithmNotSupportedException` when unavailable. The requested
     * `algorithm` must also be supported by the active provider; otherwise
     * `AlgorithmNotSupportedException` is thrown.
     *
     * Params:
     *   plaintext     = Data to seal.
     *   algorithm     = Symmetric cipher for the session key.
     *   hashAlgorithm = Hash for RSA-OAEP and MGF1 (and related envelope
     *                   hashing). Prefer SHA2-384 unless interoperability
     *                   requires another digest.
     *
     * Returns: Opaque sealed envelope bytes.
     */
    ubyte[] seal(const ubyte[] plaintext, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm)
    {
        return rsaSeal(keypair, plaintext, algorithm, hashAlgorithm);
    }

    /**
     * Opens a sealed message produced by the default $(D seal) overload
     * (AES-256-GCM + SHA2-384).
     *
     * Params:
     *   encMessage = Envelope from $(D seal).
     *
     * Returns: Original plaintext.
     *
     * Throws: $(D CryptographicException) if the private key is missing or
     *         decryption/authentication fails.
     */
    ubyte[] open(ubyte[] encMessage)
    {
        return rsaOpen(keypair, encMessage, SymmetricAlgorithm.AES256_GCM, HashAlgorithm.Default);
    }

    /**
     * Opens a sealed message with an explicit symmetric algorithm (hash =
     * SHA2-384).
     *
     * Params:
     *   encMessage = Envelope from $(D seal).
     *   algorithm  = Symmetric algorithm used when sealing.
     *
     * Returns: Original plaintext.
     */
    ubyte[] open(ubyte[] encMessage, SymmetricAlgorithm algorithm)
    {
        return rsaOpen(keypair, encMessage, algorithm, HashAlgorithm.Default);
    }

    /**
     * Opens a sealed message produced by `seal`. `algorithm` and `hashAlgorithm`
     * must match the values used when sealing.
     *
     * Params:
     *   encMessage    = Envelope from $(D seal).
     *   algorithm     = Symmetric algorithm used when sealing.
     *   hashAlgorithm = Hash used for OAEP/MGF1 when sealing.
     *
     * Returns: Original plaintext.
     */
    ubyte[] open(ubyte[] encMessage, SymmetricAlgorithm algorithm, HashAlgorithm hashAlgorithm)
    {
        return rsaOpen(keypair, encMessage, algorithm, hashAlgorithm);
    }

    /**
     * Exports the public key in the provider's serialization format.
     *
     * Returns: Public key bytes suitable for $(D RSA.this(ubyte[])).
     */
    ubyte[] getPublicKey()
    {
        return rsaGetPublicKey(keypair);
    }

    /**
     * Exports the private key, optionally password-encrypted.
     *
     * Params:
     *   password   = Password to encrypt the private key container. Empty/null
     *                may yield an unencrypted export depending on the provider.
     *   iterations = PBKDF2 iteration count for password-based encryption.
     *                Default: 25000 — a substantial work factor for key export
     *                without the multi-second cost of the full KDF default
     *                (1_048_576). OpenSSL PEM encryption only supports 2048
     *                iterations and throws if a different count is requested.
     *                CNG/CommonCrypto honour the requested count.
     *   use3Des    = If `true`, request 3DES for PEM encryption (OpenSSL only).
     *                Default: `false` because 3DES is obsolete; AES is preferred.
     *                CNG/CommonCrypto reject `true`.
     *
     * Returns: Serialized private key bytes, or `null` if this instance has no
     *          private key.
     *
     * Throws: $(D CryptographicException) for unsupported iteration counts or
     *         3DES on backends that do not offer it.
     */
    public ubyte[] getPrivateKey(string password, int iterations = 25000, bool use3Des = false)
    {
        if (!_hasPrivateKey) {
            return null;
        }
        // iterations / use3Des are forwarded to the provider. OpenSSL PEM
        // encryption only supports PKCS5_DEFAULT_ITER (2048) and throws if a
        // different count is requested. CNG/CommonCrypto password containers
        // use AES-256-GCM with PBKDF2 and honour iterations; use3Des is rejected
        // on those backends because 3DES is not offered.
        return rsaGetPrivateKey(keypair, password, iterations, use3Des);
    }

    /**
     * Encrypts a small message with RSA-OAEP (provider default hash, typically
     * SHA-1 for legacy OAEP interoperability).
     *
     * Prefer $(D seal) for bulk data; RSA encrypt is limited by modulus size.
     *
     * Params:
     *   inMessage = Plaintext small enough for a single RSA block under OAEP.
     *
     * Returns: RSA ciphertext.
     */
    ubyte[] encrypt(const ubyte[] inMessage)
    {
        return rsaEncrypt(keypair, inMessage);
    }

    /**
     * Decrypts a message produced by $(D encrypt). Requires a private key.
     *
     * Params:
     *   inMessage = RSA ciphertext.
     *
     * Returns: Original plaintext.
     *
     * Throws: $(D CryptographicException) if decryption fails or no private key.
     */
    ubyte[] decrypt(const ubyte[] inMessage)
    {
        return rsaDecrypt(keypair, inMessage);
    }

    /**
     * Signs `data` with RSASSA-PKCS1-v1_5 (or provider equivalent) over a hash
     * of the message.
     *
     * Params:
     *   data       = Message bytes to sign.
     *   useSha256  = If `true`, hash with SHA-256; if `false` (default), hash
     *                with SHA-384. SHA-384 is the default to align with the
     *                library-wide preference for SHA2-384 (stronger margin and
     *                length-extension resilience vs SHA-256).
     *
     * Returns: Signature bytes.
     *
     * Throws: $(D CryptographicException) if no private key or signing fails.
     */
    public ubyte[] sign(ubyte[] data, bool useSha256 = false)
    {
        return rsaSign(keypair, data, useSha256);
    }

    /**
     * Verifies an RSA signature over `data`.
     *
     * Params:
     *   data       = Message bytes that were signed.
     *   signature  = Signature from $(D sign).
     *   useSha256  = Must match the hash used when signing. Default: `false`
     *                (SHA-384).
     *
     * Returns: `true` if the signature is valid; `false` otherwise.
     */
    public bool verify(ubyte[] data, ubyte[] signature, bool useSha256 = false)
    {
        return rsaVerify(keypair, data, signature, useSha256);
    }
}


// ----------------------------------------------------------
// UNITTESTING BELOW
// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing seal and open functions:");

    auto keypair = new RSA();
    scope(exit) keypair.destroy();

       ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";

    ubyte[] encMessage = keypair.seal(plaintext);
    ubyte[] decMessage = keypair.open(encMessage);

    assert(plaintext.length    == decMessage.length);
    assert(plaintext        == decMessage);
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing getXxxKey functions and constructors:");

    auto keypairA = new RSA();
    scope(exit) keypairA.destroy();

    auto privateKeyA = keypairA.getPrivateKey(null);
    auto publicKeyA  = keypairA.getPublicKey();

       ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";

    // Creating key from public key only
    auto keypairB = new RSA(publicKeyA);
    scope(exit) keypairB.destroy();

    auto privateKeyB = keypairB.getPrivateKey(null);
    auto publicKeyB  = keypairB.getPublicKey();

    assert(privateKeyA    != privateKeyB,    "Private keys A and B match - they should NOT do so");
    assert(publicKeyA     == publicKeyB,    "Public  keys A and B does not match");

    //  Creating key from private key only
    auto keypairC = new RSA(privateKeyA, null);
    scope(exit) keypairC.destroy();

    auto publicKeyC     = keypairC.getPublicKey();
    auto privateKeyC = keypairC.getPrivateKey(null);

    assert(privateKeyA    == privateKeyC,    "Private keys A and C does not match");
    assert(publicKeyA     == publicKeyC,    "Public  keys A and C does not match");
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing sealing and opening with keys, which have been constructed on getXxxKey output:");

    auto keypairA = new RSA();
    scope(exit)        keypairA.destroy();

    auto privateKeyA = keypairA.getPrivateKey(null);
    auto publicKeyA  = keypairA.getPublicKey();

       ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";

    // Creating key from public key only
    auto keypairB        =  new RSA(publicKeyA);
    scope(exit)               keypairB.destroy();

    auto publicKeyB        =  keypairB.getPublicKey();
    assert(publicKeyA     == publicKeyB,    "Public  keys A and B does not match");

    //  Creating key from private key only
    auto keypairC        =  new RSA(privateKeyA, null);
    scope(exit)               keypairC.destroy();

    auto privateKeyC    =  keypairC.getPrivateKey(null);
    assert(privateKeyA    == privateKeyC,    "Private keys A and C does not match");

    // Sealing plaintext using public key
    ubyte[] encMessage    = keypairB.seal(plaintext);
    // Opening encrypted message using private key
    ubyte[] decMessage    = keypairC.open(encMessage);

    assert(plaintext.length    == decMessage.length);
    assert(plaintext        == decMessage);
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA only encrypt/decrypt functions:");

    auto keypair = new RSA();
    scope(exit) keypair.destroy();

    ubyte[48] plaintext = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] encMessage = keypair.encrypt(plaintext);
    ubyte[] decMessage = keypair.decrypt(encMessage);

    assert(plaintext.length    == decMessage.length);
    assert(plaintext        == decMessage);
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA encrypt/decrypt limit:");

    auto keypair = new RSA(2048);  // Only allows for (2048/8)-42 = 214 bytes to be asymmetrically RSA encrypted
    scope(exit) keypair.destroy();

    // This should work
    ubyte[214] plaintext214 = 2; // 2 being an arbitrary value

    ubyte[] encMessage214 = keypair.encrypt(plaintext214);
    assert(encMessage214.length == 2048 / 8);

    ubyte[] decMessage214 = keypair.decrypt(encMessage214);

    assert(plaintext214.length    == decMessage214.length);
    assert(plaintext214            == decMessage214);

    // This should NOT work, as the plaintext is larger that allowed for this 2048 bit RSA keypair
    ubyte[215] plaintext215 = 2; // 2 being an arbitrary value

    import std.exception: assertThrown;
    assertThrown!CryptographicException(keypair.encrypt(plaintext215));
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA Signing/Verification:");

    import std.digest;

    auto keypair = new RSA();
    scope(exit) keypair.destroy();

    ubyte[48] data = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[48] data2 = [ 0x1, 0x2, 0x3, 0x4, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] sig = keypair.sign(data);
    writeln("Signature: ", toHexString!(LetterCase.lower)(sig));
    assert(keypair.verify(data, sig));
    assert(!keypair.verify(data2, sig));
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA hasPrivateKey property:");

    auto full = new RSA(2048);
    scope(exit) full.destroy();
    assert(full.hasPrivateKey);

    auto pubOnly = new RSA(full.getPublicKey());
    scope(exit) pubOnly.destroy();
    assert(!pubOnly.hasPrivateKey);

    // A public-only key cannot export a private key.
    assert(pubOnly.getPrivateKey(null) is null);
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA password-protected private key round-trip:");

    auto keypair = new RSA(2048);
    scope(exit) keypair.destroy();

    // AES-256 protected. OpenSSL PEM encryption only supports PKCS5_DEFAULT_ITER
    // (2048); CNG/CommonCrypto honour the requested iteration count.
    import secured.provider : activeProvider, Provider;
    immutable int iterations = (activeProvider == Provider.OpenSSL ||
                                activeProvider == Provider.LibreSSL ||
                                activeProvider == Provider.BoringSSL) ? 2048 : 25000;
    ubyte[] encPrivate = keypair.getPrivateKey("Test Password", iterations);
    assert(encPrivate !is null);

    auto restored = new RSA(encPrivate, cast(ubyte[])"Test Password");
    scope(exit) restored.destroy();
    assert(keypair.getPublicKey() == restored.getPublicKey());

    // 3DES protected variant is only available on OpenSSL-family backends.
    if (activeProvider == Provider.OpenSSL ||
        activeProvider == Provider.LibreSSL ||
        activeProvider == Provider.BoringSSL) {
        ubyte[] encPrivate3Des = keypair.getPrivateKey("Test Password", 2048, true);
        assert(encPrivate3Des !is null);

        auto restored3Des = new RSA(encPrivate3Des, cast(ubyte[])"Test Password");
        scope(exit) restored3Des.destroy();
        assert(keypair.getPublicKey() == restored3Des.getPublicKey());
    }
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA seal/open with an explicit symmetric algorithm:");

    auto keypair = new RSA(2048);
    scope(exit) keypair.destroy();

    ubyte[] plaintext = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";

    ubyte[] encMessage = keypair.seal(plaintext, SymmetricAlgorithm.AES256_CBC);
    ubyte[] decMessage = keypair.open(encMessage, SymmetricAlgorithm.AES256_CBC);

    assert(plaintext.length == decMessage.length);
    assert(plaintext == decMessage);

    // Explicit OAEP hash (default SHA2-384) round-trip.
    ubyte[] encMessage2 = keypair.seal(plaintext, SymmetricAlgorithm.AES256_CBC, HashAlgorithm.SHA2_384);
    ubyte[] decMessage2 = keypair.open(encMessage2, SymmetricAlgorithm.AES256_CBC, HashAlgorithm.SHA2_384);
    assert(plaintext == decMessage2);
    });
}

// ----------------------------------------------------------

unittest
{
    skipIfUnsupported({
    import std.stdio;
    writeln("Testing RSA Signing/Verification with SHA-256:");

    auto keypair = new RSA(2048);
    scope(exit) keypair.destroy();

    ubyte[] data  = cast(ubyte[])"A message that will be signed using SHA-256.";
    ubyte[] data2 = cast(ubyte[])"A different message that was never signed.";

    ubyte[] sig = keypair.sign(data, true);
    assert(keypair.verify(data, sig, true));
    assert(!keypair.verify(data2, sig, true));
    });
}
