module secured.ecc;

import std.stdio;
import std.string;

version(OpenSSL)
{
import deimos.openssl.evp;
import deimos.openssl.rand;
import deimos.openssl.pem;
import deimos.openssl.bio;
}
version(Botan)
{
import core.time;
import botan.filters.data_src;
import botan.rng.auto_rng;
import botan.pubkey.algo.ecc_key;
import botan.pubkey.algo.ec_group;
import botan.pubkey.algo.ecdh;
import botan.pubkey.algo.ecdsa;
}

import secured.hash;
import secured.kdf;
import secured.random;
import secured.util;

@trusted:

public class EllipticCurve
{
    version(OpenSSL)
    {
    private EVP_PKEY_CTX* paramsctx;
    private EVP_PKEY* params;
    private EVP_PKEY_CTX* keyctx;
    private EVP_PKEY* key;
    }
    version(Botan)
    {
    private ECPublicKey pubKey;
    private ECPrivateKey privKey;
    }

    private bool _hasPrivateKey;
    public @property bool hasPrivateKey() { return _hasPrivateKey; }

    public this()
    {
        version(OpenSSL)
        {
            //Reseed the OpenSSL RNG every time we create a new ECC Key to ensure that the result is truely random in threading/forking scenarios.
            ubyte[] seedbuf = random(32);
            RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

            //Generate the key parameters
            paramsctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null);
            if (paramsctx is null)
                throw new CryptographicException("Cannot get an OpenSSL public key context.");
            if (EVP_PKEY_paramgen_init(paramsctx) < 1)
                throw new CryptographicException("Cannot initialize the OpenSSL public key context.");
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsctx, NID_secp384r1) < 1)
                throw new CryptographicException("Cannot set the required curve: P-384.");
            if (EVP_PKEY_paramgen(paramsctx, &params) < 1)
                throw new CryptographicException("Unable to generate the key parameters.");

            //Generate the public and private keys
            keyctx = EVP_PKEY_CTX_new(params, null);
            if (keyctx is null)
                throw new CryptographicException("Cannot get an OpenSSL private key context.");
            if (EVP_PKEY_keygen_init(keyctx) < 1)
                throw new CryptographicException("Cannot initialize the OpenSSL private key context.");
            if (EVP_PKEY_keygen(keyctx, &key) < 1)
                throw new CryptographicException("Unable to generate the private key.");
        }

        version(Botan)
        {
            auto rng = new AutoSeededRNG();
            auto ecg = ECGroup("secp384r1");
            auto key = ECDHPrivateKey(rng, ecg);
            privKey = key.m_priv;
            pubKey = cast(ECPublicKey)key.m_priv;
    }

        _hasPrivateKey = true;
    }

    public this(string privateKey, string password)
    {
        version(OpenSSL)
        {
            //Reseed the OpenSSL RNG every time we load an existing ECC Key to ensure that the result is truely random in threading/forking scenarios.
            ubyte[] seedbuf = random(32);
            RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

            _hasPrivateKey = true;
            ubyte[] pk = cast(ubyte[])privateKey;

            BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
            if (password is null)
            {
                key = PEM_read_bio_PrivateKey(bio, null, null, null);
            }
            else
            {
                ubyte[] pwd = cast(ubyte[])password;
                pwd = pwd ~ '\0';

                key = PEM_read_bio_PrivateKey(bio, null, null, pwd.ptr);
            }
            BIO_free_all(bio);
        }

        version(Botan)
        {
            import botan.pubkey.pkcs8 : loadKey;
            auto rng = new AutoSeededRNG();
            if(password is null || password == "")
            {
                auto pk = loadKey(cast(DataSource) DataSourceMemory(privateKey), rng, "");
                privKey = cast(ECPrivateKey)pk;
            }
            else
            {
                auto pk = loadKey(cast(DataSource) DataSourceMemory(privateKey), rng, {return password;});
                privKey = cast(ECPrivateKey)pk;
            }
            pubKey = cast(ECPublicKey)privKey;
        }
    }

    public this(string publicKey)
    {
        version(OpenSSL)
        {
            //Reseed the OpenSSL RNG every time we load an existing ECC Key to ensure that the result is truely random in threading/forking scenarios.
            ubyte[] seedbuf = random(32);
            RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

            _hasPrivateKey = false;
            ubyte[] pk = cast(ubyte[])publicKey;

            BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
            key = PEM_read_bio_PUBKEY(bio, null, null, null);
            BIO_free_all(bio);
        }

        version(Botan)
        {
            import botan.pubkey.x509_key : loadKey;
            auto pk = loadKey(cast(DataSource) DataSourceMemory(publicKey));
            pubKey = cast(ECPublicKey)pk;
        }
    }

    public ~this()
    {
        version(OpenSSL)
        {
            if (key !is null)
                EVP_PKEY_free(key);
            if (keyctx !is null)
                EVP_PKEY_CTX_free(keyctx);
            if (params !is null)
                EVP_PKEY_free(params);
            if (paramsctx !is null)
                EVP_PKEY_CTX_free(paramsctx);
        }
    }

    public ubyte[] derive(string peerKey)
    {
        version(OpenSSL)
        {
            ubyte[] pk = cast(ubyte[])peerKey;
            BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
            EVP_PKEY* peer = PEM_read_bio_PUBKEY(bio, null, null, null);
            BIO_free_all(bio);

            //Initialize the key derivation context.
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, null);
            if (ctx is null)
                throw new CryptographicException("Unable to create the key derivation context.");
            if (EVP_PKEY_derive_init(ctx) <= 0)
                throw new CryptographicException("Unable to initialize the key derivation context.");
            if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0)
                throw new CryptographicException("Unable to set the peer key.");

            //Derive the key
            size_t dklen = 0;
            if (EVP_PKEY_derive(ctx, null, &dklen) <= 0)
                throw new CryptographicException("Unable to determine the length of the derived key.");
            ubyte[] derivedKey = new ubyte[dklen];
            if (EVP_PKEY_derive(ctx, derivedKey.ptr, &dklen) <= 0)
                throw new CryptographicException("Unable to determine the length of the derived key.");

            return derivedKey;
        }

        version(Botan)
        {
            if(privKey is null)
                throw new CryptographicException("Key derivation requires a private key.");

            //Import the peer key
            import botan.pubkey.x509_key : loadKey;
            auto pk = cast(ECDHPublicKey)loadKey(cast(DataSource) DataSourceMemory(peerKey));

            //Derive the key
            auto rng = new AutoSeededRNG();
            auto keyAgreement = new PKKeyAgreement(privKey, "KDF2(SHA-384)");
            auto key = keyAgreement.deriveKey(48, pk.publicValue).bitsOf();

            ubyte[] output = new ubyte[key.length];
            for(int i=0; i<key.length; i++)
                output[i]=key[i];
            return output;
        }
    }

    public ubyte[] sign(ubyte[] data, bool useSha256 = false)
    {
        version(OpenSSL)
        {
            EVP_PKEY_CTX* pkeyctx = null;

            pkeyctx = EVP_PKEY_CTX_new(key, null);
            if (pkeyctx is null)
                throw new CryptographicException("Unable to create the key signing context.");
            scope(exit)
            {
                if (pkeyctx !is null)
                    EVP_PKEY_CTX_free(pkeyctx);
            }

            if (EVP_PKEY_sign_init(pkeyctx) <= 0)
                throw new CryptographicException("Unable to initialize the signing digest.");

            if (EVP_PKEY_CTX_set_signature_md(pkeyctx, cast(void*)(!useSha256 ? EVP_sha384() : EVP_sha256())) <= 0)
                throw new CryptographicException("Unable to set the signing digest.");

            size_t signlen = 0;
            if (EVP_PKEY_sign(pkeyctx, null, &signlen, data.ptr, data.length) <= 0)
                throw new CryptographicException("Unable to calculate signature length.");

            ubyte[] sign = new ubyte[signlen];
            if (EVP_PKEY_sign(pkeyctx, sign.ptr, &signlen, data.ptr, data.length) <= 0)
                throw new CryptographicException("Unable to calculate signature.");

            return sign;
        }

        version(Botan)
        {
            auto rng = new AutoSeededRNG();
            auto signer = new PKSigner(privKey, "EMSA1(SHA-256)");
            auto sig = signer.signMessage(data.ptr, data.length, rng);

            ubyte[] output = new ubyte[sig.length];
            for(int i=0; i<sig.length; i++)
                output[i]=sig[i];
            return output;
        }
    }

    public bool verify(ubyte[] data, ubyte[] signature, bool useSha256 = false)
    {
        version(OpenSSL)
        {
            EVP_PKEY_CTX* pkeyctx = null;

            pkeyctx = EVP_PKEY_CTX_new(key, null);
            if (pkeyctx is null)
                throw new CryptographicException("Unable to create the key signing context.");
            scope(exit)
            {
                if (pkeyctx !is null)
                    EVP_PKEY_CTX_free(pkeyctx);
            }

            if (EVP_PKEY_verify_init(pkeyctx) <= 0)
                throw new CryptographicException("Unable to initialize the signing digest.");

            if (EVP_PKEY_CTX_set_signature_md(pkeyctx, cast(void*)(!useSha256 ? EVP_sha384() : EVP_sha256())) <= 0)
                throw new CryptographicException("Unable to set the signing digest.");

            int ret = EVP_PKEY_verify(pkeyctx, data.ptr, cast(long)data.length, signature.ptr, cast(long)signature.length);

            return ret != 1;
        }

        version(Botan)
        {
            auto rng = new AutoSeededRNG();
            auto verifier = new PKVerifier(pubKey, "EMSA1(SHA-256)");
            return verifier.verifyMessage(data.ptr, data.length, signature.ptr, signature.length);
        }
    }

    public string getPublicKey()
    {
        version(OpenSSL)
        {
            BIO* bio = BIO_new(BIO_s_mem());

            PEM_write_bio_PUBKEY(bio, key);

            ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
            BIO_read(bio, buffer.ptr, cast(int)buffer.length);
            BIO_free_all(bio);

            return cast(string)buffer;
        }

        version(Botan)
        {
            import botan.pubkey.x509_key : PEM_encode;
            import botan.pubkey.x509_key : BER_encode;

            writeln("Extracting Public Key in BER.");
            auto ber = BER_encode(pubKey);
            writeln("Extracting Public Key in PEM.");
            auto pem = PEM_encode(pubKey);
            writeln(pem);
            return pem;
        }
    }

    public string getPrivateKey(string password, int iterations = 25000, bool use3Des = false)
    {
        if (!_hasPrivateKey)
            return null;

        version(OpenSSL)
        {
            BIO* bio = BIO_new(BIO_s_mem());

            if (password is null)
                PEM_write_bio_PKCS8PrivateKey(bio, key, null, null, 0, null, null);
            else
            {
                ubyte[] pwd = cast(ubyte[])password;
                pwd = pwd ~ '\0';

                PEM_write_bio_PKCS8PrivateKey(
                    bio,
                    key,
                    !use3Des ? EVP_aes_256_cbc() : EVP_des_ede3_cbc(),
                    null,
                    0,
                    null,
                    pwd.ptr);
            }

            if(BIO_ctrl_pending(bio) == 0)
                throw new CryptographicException("No private key written.");

            ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
            BIO_read(bio, buffer.ptr, cast(int)buffer.length);
            BIO_free_all(bio);

            return cast(string)buffer;
        }

        version(Botan)
        {
            import botan.pubkey.pkcs8 : PEM_encode;
            if (password is null || password == "")
            {
                writeln("Private Key With Password:");
                return PEM_encode(privKey);
            }
            else
            {
                auto rng = new AutoSeededRNG();
                return PEM_encode(privKey, rng, password, 300.msecs, !use3Des ? "AES-256/CBC" : "TripleDES/CBC");
            }
        }
    }
}

unittest
{
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
}

unittest
{
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
}

unittest
{
    import std.digest;

    writeln("Testing EllipticCurve Signing/Verification:");

    EllipticCurve eckey = new EllipticCurve();
    ubyte[48] data = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

    ubyte[] sig = eckey.sign(data);
    writeln("Signature: ", toHexString!(LetterCase.lower)(sig));
    assert(eckey.verify(data, sig));
}
