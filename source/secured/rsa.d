module secured.rsa;

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

public class RSA
{
    private RsaKey keypair;

    private bool _hasPrivateKey;
    public @property bool hasPrivateKey() { return _hasPrivateKey; }

    public this(const int RSA_KEYLEN = 4096)
    {
        keypair = rsaGenerate(RSA_KEYLEN);
        _hasPrivateKey = true;
    }

    public this(ubyte[] privateKey, ubyte[] password)
    {
        keypair = rsaLoadPrivateKey(privateKey, password);
        _hasPrivateKey = true;
    }

    public this(ubyte[] publicKey)
    {
        keypair = rsaLoadPublicKey(publicKey);
        _hasPrivateKey = false;
    }

    public ~this()
    {
        rsaFree(keypair);
    }

    ubyte[] seal(const ubyte[] plaintext)
    {
        return rsaSeal(keypair, plaintext, SymmetricAlgorithm.AES256_CTR);
    }

    ubyte[] seal(const ubyte[] plaintext, SymmetricAlgorithm algorithm)
    {
        return rsaSeal(keypair, plaintext, algorithm);
    }

    ubyte[] open(ubyte[] encMessage)
    {
        return rsaOpen(keypair, encMessage, SymmetricAlgorithm.AES256_CTR);
    }

    ubyte[] open(ubyte[] encMessage, SymmetricAlgorithm algorithm)
    {
        return rsaOpen(keypair, encMessage, algorithm);
    }

    ubyte[] getPublicKey()
    {
        return rsaGetPublicKey(keypair);
    }

    public ubyte[] getPrivateKey(string password, int iterations = 25000, bool use3Des = false)
    {
        if (!_hasPrivateKey) {
            return null;
        }
        return rsaGetPrivateKey(keypair, password, use3Des);
    }

    ubyte[] encrypt(const ubyte[] inMessage)
    {
        return rsaEncrypt(keypair, inMessage);
    }

    ubyte[] decrypt(const ubyte[] inMessage)
    {
        return rsaDecrypt(keypair, inMessage);
    }

    public ubyte[] sign(ubyte[] data, bool useSha256 = false)
    {
        return rsaSign(keypair, data, useSha256);
    }

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

    // AES-256 protected (default)
    ubyte[] encPrivate = keypair.getPrivateKey("Test Password");
    assert(encPrivate !is null);

    auto restored = new RSA(encPrivate, cast(ubyte[])"Test Password");
    scope(exit) restored.destroy();
    assert(keypair.getPublicKey() == restored.getPublicKey());

    // 3DES protected variant
    ubyte[] encPrivate3Des = keypair.getPrivateKey("Test Password", 25000, true);
    assert(encPrivate3Des !is null);

    auto restored3Des = new RSA(encPrivate3Des, cast(ubyte[])"Test Password");
    scope(exit) restored3Des.destroy();
    assert(keypair.getPublicKey() == restored3Des.getPublicKey());
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
