module secured.ecc;

import std.stdio;
import deimos.openssl.ec;
import deimos.openssl.evp;
import deimos.openssl.rand;
import deimos.openssl.pem;
import deimos.openssl.bio;

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

	public this(string privateKeyPath, string password)
	{
		//Reseed the OpenSSL RNG every time we load an existing ECC Key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		_hasPrivateKey = true;

		BIO* bio = BIO_new_file(privateKeyPath.ptr, "r");
		PEM_read_bio_PrivateKey(bio, null, null, password !is null ?cast(ubyte*)password.ptr : null);
		BIO_free_all(bio);
	}

	public this(string publicKeyPath)
	{
		//Reseed the OpenSSL RNG every time we load an existing ECC Key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		_hasPrivateKey = false;

		BIO* bio = BIO_new_file(publicKeyPath.ptr, "r");
		key = PEM_read_bio_PUBKEY(bio, null, null, null);
		BIO_free_all(bio);
	}

	public this(ubyte[] privateKey, string password)
	{
		//Reseed the OpenSSL RNG every time we load an existing ECC Key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		_hasPrivateKey = true;

		BIO* bio = BIO_new_mem_buf(privateKey.ptr, cast(int)privateKey.length);
		PEM_read_bio_PrivateKey(bio, null, null, password !is null ?cast(ubyte*)password.ptr : null);
		BIO_free_all(bio);
	}

	public this(ubyte[] publicKey)
	{
		//Reseed the OpenSSL RNG every time we load an existing ECC Key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		_hasPrivateKey = false;

		BIO* bio = BIO_new_mem_buf(publicKey.ptr, cast(int)publicKey.length);
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

	public ubyte[] derive(ubyte[] peerKey)
	{
		BIO* bio = BIO_new_mem_buf(peerKey.ptr, cast(int)peerKey.length);
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
		EVP_MD_CTX* mdctx = null;

		mdctx = EVP_MD_CTX_create();
		if (mdctx is null)
			throw new CryptographicException("Unable to create the message digest context.");
		scope(exit)
		{
			if (mdctx !is null)
				EVP_MD_CTX_destroy(mdctx);
		}

		if (EVP_SignInit_ex(mdctx, !useSha256 ? EVP_sha384() : EVP_sha256(), null) != 1)
			throw new CryptographicException("Unable to initialize the signing operation.");

		if (EVP_SignUpdate(mdctx, data.ptr, cast(long)data.length) != 1)
			throw new CryptographicException("Unable to update the signing data.");

		uint signlen = 0;
		if (EVP_SignFinal(mdctx, null, &signlen, key) != 1)
			throw new CryptographicException("Unable to sign the data.");

		ubyte[] sign = new ubyte[signlen];
		if (EVP_SignFinal(mdctx, sign.ptr, &signlen, key) != 1)
			throw new CryptographicException("Unable to sign the data.");

		return sign;
	}

	public bool verify(ubyte[] data, ubyte[] signature, bool useSha256 = false)
	{
		EVP_MD_CTX* mdctx = null;

		mdctx = EVP_MD_CTX_create();
		if (mdctx is null)
			throw new CryptographicException("Unable to create the message digest context.");
		scope(exit)
		{
			if (mdctx !is null)
				EVP_MD_CTX_destroy(mdctx);
		}

		if (EVP_VerifyInit_ex(mdctx, !useSha256 ? EVP_sha384() : EVP_sha256(), null) != 1)
			throw new CryptographicException("Unable to initialize the signing operation.");

		if (EVP_VerifyUpdate(mdctx, data.ptr, cast(long)data.length) != 1)
			throw new CryptographicException("Unable to update the signing data.");

		if (EVP_VerifyFinal(mdctx, signature.ptr, cast(uint)signature.length, key) == 1)
			return true;

		return false;
	}

	public void save(string path, string password, bool use3Des = false)
	{
		BIO* bio = BIO_new_file(path.ptr, "w");

		if (!_hasPrivateKey)
		{
			PEM_write_bio_PUBKEY(bio, key);
		}
		else
		{
			if (password is null)
				PEM_write_bio_PrivateKey(bio, key, null, null, 0, null, null);
			else
			{
				PEM_write_bio_PrivateKey(
					bio,
					key,
					!use3Des ? EVP_aes_256_ctr() : EVP_des_ede3_cbc(),
					cast(ubyte*)password.ptr,
					cast(int)password.length,
					null,
					null);
			}
		}

		BIO_free_all(bio);
	}

	public ubyte[] getPublicKey()
	{
		BIO* bio = BIO_new(BIO_s_mem());

		PEM_write_bio_PUBKEY(bio, key);

		ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
		BIO_read(bio, buffer.ptr, cast(int)buffer.length);
		BIO_free_all(bio);

		return buffer;
	}

	public ubyte[] getPrivateKey(string password, bool use3Des = false)
	{
		if (!_hasPrivateKey)
			return null;

		BIO* bio = BIO_new(BIO_s_mem());

		if (password is null)
			PEM_write_bio_PrivateKey(bio, key, null, null, 0, null, null);
		else
		{
			PEM_write_bio_PrivateKey(
				bio,
				key,
				!use3Des ? EVP_aes_256_ctr() : EVP_des_ede3_cbc(),
				cast(ubyte*)password.ptr,
				cast(int)password.length,
				null,
				null);
		}

		ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
		BIO_read(bio, buffer.ptr, cast(int)buffer.length);
		BIO_free_all(bio);

		return buffer;
	}
}

unittest
{
	import std.digest.digest;

	writeln("Testing PKI Key Derivation:");

	EllipticCurve localKey = new EllipticCurve();
	EllipticCurve peerKey = new EllipticCurve();

	ubyte[] peer = peerKey.getPublicKey();
	ubyte[] key = localKey.derive(peer);
	writeln("Derived Key: ", toHexString!(LetterCase.lower)(key));

	assert(key !is null);
}
