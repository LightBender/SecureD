module secured.ecc;

import std.stdio;
import std.string;

import deimos.openssl.evp;
import deimos.openssl.rand;
import deimos.openssl.pem;
import deimos.openssl.bio;

import secured.hash;
import secured.kdf;
import secured.random;
import secured.util;

public class EllipticCurve
{
	private EVP_PKEY_CTX* paramsctx;
	private EVP_PKEY* params;
	private EVP_PKEY_CTX* keyctx;
	private EVP_PKEY* key;

	private bool _hasPrivateKey;
	public @property bool hasPrivateKey() { return _hasPrivateKey; }

	public this()
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

		_hasPrivateKey = true;
	}

	public this(string privateKey, string password)
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

	public this(string publicKey)
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

	public ~this()
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

	public ubyte[] derive(string peerKey)
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
		ulong dklen = 0;
		if (EVP_PKEY_derive(ctx, null, &dklen) <= 0)
			throw new CryptographicException("Unable to determine the length of the derived key.");
		ubyte[] derivedKey = new ubyte[dklen];
		if (EVP_PKEY_derive(ctx, derivedKey.ptr, &dklen) <= 0)
			throw new CryptographicException("Unable to determine the length of the derived key.");

		return derivedKey;
	}

	public ubyte[] sign(ubyte[] data, bool useSha256 = false)
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

		ulong signlen = 0;
		if (EVP_PKEY_sign(pkeyctx, null, &signlen, data.ptr, data.length) <= 0)
			throw new CryptographicException("Unable to calculate signature length.");

		ubyte[] sign = new ubyte[signlen];
		if (EVP_PKEY_sign(pkeyctx, sign.ptr, &signlen, data.ptr, data.length) <= 0)
			throw new CryptographicException("Unable to calculate signature.");

		return sign;
	}

	public bool verify(ubyte[] data, ubyte[] signature, bool useSha256 = false)
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

	public string getPublicKey()
	{
		BIO* bio = BIO_new(BIO_s_mem());

		PEM_write_bio_PUBKEY(bio, key);

		ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
		BIO_read(bio, buffer.ptr, cast(int)buffer.length);
		BIO_free_all(bio);

		return cast(string)buffer;
	}

	public string getPrivateKey(string password, int iterations = 25000, bool use3Des = false)
	{
		if (!_hasPrivateKey)
			return null;

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
}

unittest
{
	import std.digest.digest;

	writeln("Testing EllipticCurve Key Derivation:");

	EllipticCurve eckey1 = new EllipticCurve();
	EllipticCurve eckey2 = new EllipticCurve();

	string pubKey1 = eckey1.getPublicKey();
	string pubKey2 = eckey2.getPublicKey();
	ubyte[] key1 = eckey1.derive(pubKey2);
	ubyte[] key2 = eckey2.derive(pubKey1);

	writeln("Derived Key 1: ", toHexString!(LetterCase.lower)(key1));
	writeln("Derived Key 2: ", toHexString!(LetterCase.lower)(key2));

	assert(key1 !is null);
	assert(key2 !is null);
	assert(constantTimeEquality(key1, key2));
}

unittest
{
	import std.digest.digest;

	writeln("Testing EllipticCurve Signing/Verification:");

	EllipticCurve eckey = new EllipticCurve();
	ubyte[48] data = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	ubyte[] sig = eckey.sign(data);
	writeln("Signature: ", toHexString!(LetterCase.lower)(sig));
	assert(eckey.verify(data, sig));
}

unittest
{
	import std.digest.digest;

	writeln("Testing EllipticCurve Private Key Extraction/Recreation:");

	EllipticCurve eckey = new EllipticCurve();
	string pkPwd = eckey.getPrivateKey("Test Password");
	string pkNoPwd = eckey.getPrivateKey(null);

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
