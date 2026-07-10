module secured.ecc;

import std.stdio;

import secured.provider;
import secured.util;

/**
 * NIST prime elliptic curves supported for ECDH and ECDSA.
 *
 * The library default for key generation is $(D P384), which matches the
 * security level of SHA2-384 (~192-bit classical security) and is widely
 * available on all SecureD providers.
 */
public enum EccCurve
{
    /// NIST P-256 (secp256r1); ~128-bit security.
    P256,
    /// NIST P-384 (secp384r1); ~192-bit security; library default.
    P384,
    /// NIST P-521 (secp521r1); ~256-bit security.
    P521,
}

/*
 * The public EllipticCurve class is a provider-agnostic dispatcher. It holds an
 * opaque, provider-specific key context (EccKey) and forwards each operation to
 * the package-private free functions implemented by the active provider's system
 * module (OpenSSL, CNG or the Security framework).
 */
static if (activeProvider == Provider.OpenSSL || activeProvider == Provider.LibreSSL || activeProvider == Provider.BoringSSL) {
    import secured.system.openssl : EccKey, eccGenerate, eccLoadPrivateKey, eccLoadPublicKey, eccFree,
        eccDerive, eccSign, eccVerify, eccGetPublicKey, eccGetPrivateKey;
} else static if (activeProvider == Provider.CNG) {
    import secured.system.windows : EccKey, eccGenerate, eccLoadPrivateKey, eccLoadPublicKey, eccFree,
        eccDerive, eccSign, eccVerify, eccGetPublicKey, eccGetPrivateKey;
} else static if (activeProvider == Provider.CommonCrypto) {
    import secured.system.macos : EccKey, eccGenerate, eccLoadPrivateKey, eccLoadPublicKey, eccFree,
        eccDerive, eccSign, eccVerify, eccGetPublicKey, eccGetPrivateKey;
}

@trusted:

/**
 * Provider-agnostic elliptic-curve key wrapper for ECDH key agreement and ECDSA
 * signatures.
 *
 * Key material is held in an opaque provider-specific context and released in
 * the destructor.
 */
public class EllipticCurve
{
    private EccKey key;

    private bool _hasPrivateKey;
    /**
     * Whether this instance holds a private key.
     *
     * Returns: `true` if derive (as initiator with private key), sign, and
     *          private-key export are available.
     */
    public @property bool hasPrivateKey() { return _hasPrivateKey; }

    /**
     * Generates a new elliptic-curve keypair on the given curve.
     *
     * Params:
     *   curve = NIST curve to use. Default: $(D EccCurve.P384), chosen to match
     *           the security level of SHA2-384 and for broad OS support.
     */
    public this(EccCurve curve = EccCurve.P384)
    {
        key = eccGenerate(curve);
        _hasPrivateKey = true;
    }

    /**
     * Loads an ECC private key from a serialized string (PEM/provider format).
     *
     * Params:
     *   privateKey = Serialized private key (as produced by $(D getPrivateKey)).
     *   password   = Password used to decrypt the key container, or empty/null
     *                if unencrypted.
     */
    public this(string privateKey, string password)
    {
        key = eccLoadPrivateKey(privateKey, password);
        _hasPrivateKey = true;
    }

    /**
     * Loads an ECC public key only (no private key).
     *
     * Params:
     *   publicKey = Serialized public key (as produced by $(D getPublicKey)).
     */
    public this(string publicKey)
    {
        key = eccLoadPublicKey(publicKey);
        _hasPrivateKey = false;
    }

    /// Releases the underlying provider key material.
    public ~this()
    {
        eccFree(key);
    }

    /**
     * Performs ECDH key agreement with a peer's public key.
     *
     * Params:
     *   peerKey = Peer's serialized public key (same curve as this key).
     *
     * Returns: Shared secret bytes (raw ECDH output; apply a KDF such as HKDF
     *          before using as a symmetric key).
     *
     * Throws: $(D CryptographicException) if agreement fails or no private key.
     */
    public ubyte[] derive(string peerKey)
    {
        return eccDerive(key, peerKey);
    }

    /**
     * Signs `data` with ECDSA over a hash of the message.
     *
     * Params:
     *   data      = Message bytes to sign.
     *   useSha256 = If `true`, hash with SHA-256; if `false` (default), hash
     *               with SHA-384 to align with P-384 and the library-wide
     *               SHA2-384 preference.
     *
     * Returns: DER or provider-format signature bytes.
     *
     * Throws: $(D CryptographicException) if no private key or signing fails.
     */
    public ubyte[] sign(ubyte[] data, bool useSha256 = false)
    {
        return eccSign(key, data, useSha256);
    }

    /**
     * Verifies an ECDSA signature over `data`.
     *
     * Params:
     *   data      = Message bytes that were signed.
     *   signature = Signature from $(D sign).
     *   useSha256 = Must match the hash used when signing. Default: `false`
     *               (SHA-384).
     *
     * Returns: `true` if the signature is valid; `false` otherwise.
     */
    public bool verify(ubyte[] data, ubyte[] signature, bool useSha256 = false)
    {
        return eccVerify(key, data, signature, useSha256);
    }

    /**
     * Exports the public key as a serialized string (PEM/provider format).
     *
     * Returns: Public key string suitable for $(D EllipticCurve.this(string))
     *          or $(D derive).
     */
    public string getPublicKey()
    {
        return eccGetPublicKey(key);
    }

    /**
     * Exports the private key, optionally password-encrypted.
     *
     * Params:
     *   password = Password to encrypt the private key container. Empty/null may
     *              yield an unencrypted export depending on the provider.
     *   use3Des  = If `true`, request 3DES for PEM encryption where supported
     *              (OpenSSL). Default: `false` because 3DES is obsolete; AES is
     *              preferred. Other backends may ignore or reject this flag.
     *
     * Returns: Serialized private key string, or `null` if this instance has no
     *          private key.
     */
    public string getPrivateKey(string password, bool use3Des = false)
    {
        if (!_hasPrivateKey) {
            return null;
        }
        return eccGetPrivateKey(key, password, use3Des);
    }
}

unittest
{
    skipIfUnsupported({
    import std.digest;

    writeln("Testing EllipticCurve Private Key Extraction/Recreation:");

    EllipticCurve eckey = new EllipticCurve();
    string pub = eckey.getPublicKey();

    writeln("Extracting No Password");
    string pkNoPwd = eckey.getPrivateKey(null);
    writeln("Extracting With Password");
    string pkPwd = eckey.getPrivateKey("Test Password");

    writeln("Private Key Without Password: ");
    writeln(pkNoPwd);
    writeln("Private Key With Password:");
    writeln(pkPwd);

    assert(pkNoPwd !is null);
    assert(pkPwd !is null);

    EllipticCurve eckeyr1 = new EllipticCurve(pkNoPwd, null);
    EllipticCurve eckeyr2 = new EllipticCurve(pkPwd, "Test Password");

    string pkRecPwd = eckeyr2.getPrivateKey("Test Password");
    string pkRecNoPwd = eckeyr1.getPrivateKey(null);

    writeln("Recreated Private Key Without Password: ");
    writeln(pkRecNoPwd);
    writeln("Recreated Private Key With Password:");
    writeln(pkRecPwd);

    assert(pkNoPwd == pkRecNoPwd);
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;

    writeln("Testing EllipticCurve Key Derivation:");

    EllipticCurve eckey1 = new EllipticCurve();
    writeln("Created Key 1");
    EllipticCurve eckey2 = new EllipticCurve();
    writeln("Created Key 2");

    string privKey1 = eckey1.getPrivateKey(null);
    writeln("Retrieved Private Key 1");


    string pubKey1 = eckey1.getPublicKey();
    writeln("Retrieved Public Key 1");
    string pubKey2 = eckey2.getPublicKey();
    writeln("Retrieved Public Key 2");
    ubyte[] key1 = eckey1.derive(pubKey2);
    writeln("Derived Key 1");
    ubyte[] key2 = eckey2.derive(pubKey1);
    writeln("Derived Key 2");

    writeln("Derived Key 1: ", toHexString!(LetterCase.lower)(key1));
    writeln("Derived Key 2: ", toHexString!(LetterCase.lower)(key2));

    assert(key1 !is null);
    assert(key2 !is null);
    assert(constantTimeEquality(key1, key2));
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;

    writeln("Testing EllipticCurve Signing/Verification:");

    EllipticCurve eckey = new EllipticCurve();
    ubyte[48] data = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] sig = eckey.sign(data);
    writeln("Signature: ", toHexString!(LetterCase.lower)(sig));
    assert(eckey.verify(data, sig));
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;

    writeln("Testing EllipticCurve Signing/Verification with SHA-256:");

    EllipticCurve eckey = new EllipticCurve();

    ubyte[] data  = cast(ubyte[])"A message signed with ECDSA over SHA-256.";
    ubyte[] data2 = cast(ubyte[])"A different message that was never signed.";

    ubyte[] sig = eckey.sign(data, true);
    writeln("Signature: ", toHexString!(LetterCase.lower)(sig));
    assert(eckey.verify(data, sig, true));
    assert(!eckey.verify(data2, sig, true));
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;

    writeln("Testing EllipticCurve public-key-only operations:");

    EllipticCurve eckey = new EllipticCurve();
    assert(eckey.hasPrivateKey);

    ubyte[] data = cast(ubyte[])"Data signed by the private key.";
    ubyte[] sig = eckey.sign(data);

    // Reconstruct from the public key only.
    string pubKey = eckey.getPublicKey();
    EllipticCurve pubOnly = new EllipticCurve(pubKey);

    assert(!pubOnly.hasPrivateKey);
    assert(pubOnly.getPrivateKey(null) is null);
    assert(pubOnly.verify(data, sig));
    });
}

unittest
{
    skipIfUnsupported({
    import std.digest;

    writeln("Testing EllipticCurve signing across all curves:");

    foreach (curve; [EccCurve.P256, EccCurve.P384, EccCurve.P521]) {
        EllipticCurve eckey = new EllipticCurve(curve);

        ubyte[] data = cast(ubyte[])"Curve round-trip test data.";
        ubyte[] sig = eckey.sign(data);
        assert(eckey.verify(data, sig));

        // Key agreement between two keys on the same curve.
        EllipticCurve peer = new EllipticCurve(curve);
        ubyte[] secretA = eckey.derive(peer.getPublicKey());
        ubyte[] secretB = peer.derive(eckey.getPublicKey());
        assert(constantTimeEquality(secretA, secretB));
    }
    });
}
