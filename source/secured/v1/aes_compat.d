// Alternative implementation of version 1 secured.aes using newer secured version 2 primitives

module aes_compat;

static import secured.symmetric;
static import secured.mac;
static import secured.random;
static import secured.util;

import std.stdio;

@trusted public ubyte[] encrypt (ubyte[] key, ubyte[] data)
in
{
    assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
    //Generate a random IV
    ubyte[] iv = secured.random.random(16);
    assert(iv.length == 16);

    secured.symmetric.SymmetricAlgorithm algorithm = secured.symmetric.SymmetricAlgorithm.AES256_CTR;

    const ubyte[] _additional = null;
    ubyte[]       _auth       = null;

    ubyte[] output = secured.symmetric.encrypt_ex(algorithm, key, iv, data, _additional, _auth);

    assert(_auth.length == 0);

    //HMAC the combined cipher text
    ubyte[] hashdata = iv ~ output;

    // secured.mac.hmac uses HashAlgorithm.SHA2_384
    ubyte[] hash = secured.mac.hmac(key, hashdata);
    assert(hash.length == 384/8);

    //Return the HMAC + IV + Ciphertext as a single byte array.
    return hash ~ iv ~ output;
}

@trusted public bool validate (ubyte[] key, ubyte[] data)
in
{
    assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
    ubyte[] datahash = data[0..48];

    // secured.mac.hmac uses HashAlgorithm.SHA2_384
    ubyte[] computed = secured.mac.hmac(key, data[48..$]);

    assert(computed.length == 384/8);

    return secured.util.constantTimeEquality(datahash, computed);
}

@trusted public ubyte[] decrypt (ubyte[] key, ubyte[] data)
in
{
    assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
    //Validate the data
    if (!validate(key, data))
        throw new secured.util.CryptographicException("Cannot get an OpenSSL cipher context.");

    ubyte[] iv = data[48..64];
    assert(iv.length == 16);

    ubyte[] payload = data[64..$];

    const ubyte[] _auth       =[];
    const ubyte[] _additional =[];
    secured.symmetric.SymmetricAlgorithm algorithm = secured.symmetric.SymmetricAlgorithm.AES256_CTR;

    ubyte[] output = secured.symmetric.decrypt_ex(key, iv, payload, _auth, _additional, algorithm);

    assert(output.length == payload.length);

    return output;
}

// Direct copy from secured.aes
unittest
{
    import std.digest;
    import std.stdio;

    writeln("Testing Encryption (No Additional Data)");

    ubyte[32] key = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    string input = "The quick brown fox jumps over the lazy dog.";
    writeln("Encryption Input: ", input);
    ubyte[] enc = encrypt(key, cast(ubyte[])input);
    writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc));

    writeln("Testing Validation (No Additional Data): ");
    assert(validate(key, enc));
    writeln("Success!");

    writeln("Testing Decryption (No Additional Data)");
    ubyte[] dec = decrypt(key, enc);
    writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc));
    writeln("Decryption Output: ", cast(string)dec);

    assert((cast(string)dec) == input);
}
