// Author: Adam Williams. 2016-2017.

// Implements evp encrypting and decrypting functionality using only RSA.
// Implements sealing and opening envelope functionality using a combination of RSA and AES.
// This file depends on the openssl library. Please note: Currently no support for the Botan library.

module secured.rsa;  

import core.memory;

version(OpenSSL)
{
import deimos.openssl.evp;
import deimos.openssl.rand;
import deimos.openssl.pem;
import deimos.openssl.bio;
import deimos.openssl.rsa;
import deimos.openssl.engine;
}
version(Botan)
{
	static assert(0, "Botan is not support in module secured.rsa.");
}

import secured.random;
import secured.util;

// CONSTANTS
const ulong RSA_KEYLEN = 2048;

// ----------------------------------------------------------

public class RSA
{
	private bool _hasPrivateKey;
	public @property bool hasPrivateKey() { return _hasPrivateKey; }

	static EVP_PKEY *keypair;

	public this()
	{ 
		// Reseed the OpenSSL RNG every time we create a new RSA Key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null);
		if (ctx is null)
			throw new CryptographicException("EVP_PKEY_CTX_new_id failed.");

		if(EVP_PKEY_keygen_init(ctx) <= 0)
			throw new CryptographicException("EVP_PKEY_keygen_init failed.");

		if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0)
			throw new CryptographicException("EVP_PKEY_CTX_set_rsa_keygen_bits failed.");

		if(EVP_PKEY_keygen(ctx, &keypair) <= 0) 
			throw new CryptographicException("EVP_PKEY_keygen failed.");

		EVP_PKEY_CTX_free(ctx);

		_hasPrivateKey = true;
	} // this()

// ----------------------------------------------------------

	public this(ubyte[] privateKey, ubyte[] password)
	{
		// Reseed the OpenSSL RNG every time we load an existing RSA key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		_hasPrivateKey = true;
		ubyte[] pk = cast(ubyte[])privateKey;

		BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
		if (password is null)
		{
			keypair = PEM_read_bio_PrivateKey(bio, null, null, null);
		}
		else
		{
			ubyte[] pwd = cast(ubyte[])password;
			pwd = pwd ~ '\0';

			keypair = PEM_read_bio_PrivateKey(bio, null, null, pwd.ptr);
		}
		BIO_free_all(bio);
	} // this()

// ----------------------------------------------------------

	public this(ubyte[] publicKey)
	{
		// Reseed the OpenSSL RNG every time we load an existing RSA key to ensure that the result is truely random in threading/forking scenarios.
		ubyte[] seedbuf = random(32);
		RAND_seed(seedbuf.ptr, cast(int)seedbuf.length);

		_hasPrivateKey = false;
		ubyte[] pk = cast(ubyte[])publicKey;

		BIO* bio = BIO_new_mem_buf(pk.ptr, cast(int)pk.length);
		keypair = PEM_read_bio_PUBKEY(bio, null, null, null);
		BIO_free_all(bio);
	} // this()

// ----------------------------------------------------------

	public ~this()
	{
		// ToDo: Should these lines be included? Investigate!
		// if (keypair !is null)
		//	EVP_PKEY_free(keypair);
	}

// ---------------------------------------------------------- // ----------------------------------------------------------

	ubyte[] seal(const ubyte[] plaintext)
	{
		ubyte* _encMsg;
		ubyte* _ek;
		size_t _ekl;
		ubyte* _iv;
		size_t _ivl;

		ubyte** encMsg	= &_encMsg;
		ubyte** ek		= &_ek;
		size_t* ekl		= &_ekl;
		ubyte** iv		= &_iv;
		size_t* ivl		= &_ivl;
		
		// The header, symmetric encryption key ek and initialisation vector iv are prefixed the encrypted message

		const ubyte* msg	= plaintext.ptr;
		size_t msgLen 		= plaintext.length;
		
		assert(size_t.sizeof == 8);
		
		size_t maxHeaderL	= 2 + 2 + 4; // 2 bytes for actual ekl, 2 bytes for actual ivl and 4 bytes for actual length
		size_t maxEKL		= EVP_PKEY_size(keypair);
		size_t maxIVL		= EVP_MAX_IV_LENGTH;
		size_t maxEncMsgLen	= msgLen + EVP_MAX_IV_LENGTH;
		size_t maxTotalSize	= maxHeaderL + maxEKL + maxIVL + maxEncMsgLen; 

		size_t encMsgLen = 0;
		size_t blockLen  = 0;
	   
		*ivl = EVP_MAX_IV_LENGTH;

		ubyte* buffer = cast(ubyte*)GC.malloc(maxTotalSize);
		if(buffer == null)
			throw new CryptographicException("Malloc failed.");
		
		*ek = buffer + maxHeaderL;
		*iv = buffer + maxHeaderL + maxEKL;
		*encMsg = buffer + maxHeaderL + maxEKL + maxIVL;

		EVP_CIPHER_CTX *rsaEncryptCtx = cast(EVP_CIPHER_CTX*)GC.malloc(EVP_CIPHER_CTX.sizeof);	
		if(rsaEncryptCtx == null)
			throw new CryptographicException("Malloc failed.");

		EVP_CIPHER_CTX_init(rsaEncryptCtx);

		if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_ctr(), ek, cast(int*)ekl, *iv, &keypair, 1))
			throw new CryptographicException("CEVP_SealInit failed.");

		if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, cast(int*)&blockLen, cast(const ubyte*)msg, cast(int)msgLen))
			throw new CryptographicException("EVP_SealUpdate failed.");
		encMsgLen += blockLen;

		if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, cast(int*)&blockLen))
			throw new CryptographicException("EVP_SealFinal failed.");
		encMsgLen += blockLen;

		EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);

		buffer[0 .. 2] = (cast(ubyte*)ekl)[0..2];
		buffer[2 .. 4] = (cast(ubyte*)ivl)[0..2];

		ubyte* encMsgLenTemp = cast(ubyte*)(&encMsgLen);
		buffer[4..8] = encMsgLenTemp[0..4];
			
		assert(*ekl == maxEKL);
		assert(*ivl == maxIVL);
		
		return buffer[0 .. maxHeaderL + maxEKL + maxIVL + encMsgLen];
	} // seal()

// ----------------------------------------------------------

	ubyte[] open(ubyte[] encMessage)
	{
		assert(encMessage.length > 8); // Encrypted message must be larger than header = ekl + ivl + messageLength
		assert(size_t.sizeof == 8);
		
		// Header: 2 bytes for actual ekl, 2 bytes for actual ivl and 4 bytes for actual length
		size_t maxHeaderL	= 2 + 2 + 4;
		size_t maxEKL		= EVP_PKEY_size(keypair);
		size_t maxIVL		= EVP_MAX_IV_LENGTH;

		ubyte* ek			= encMessage.ptr + maxHeaderL;
		ubyte[8] temp		= 0;
		temp[0..2]			= encMessage[0..2];
		int ekl				= (cast(int[])temp)[0];
			
		ubyte* iv			= encMessage.ptr + maxHeaderL + maxEKL;
		temp				= 0;
		temp[0..2]			= encMessage[2..4];
		size_t ivl			= (cast(int[])temp)[0];

		ubyte* encMsg		= encMessage.ptr + maxHeaderL + maxEKL + maxIVL;
		temp				= 0;
		temp[0..4]			= encMessage[4..8];
		size_t encMsgLen	= (cast(size_t[])temp)[0];
		
		size_t decLen   = 0;
		size_t blockLen = 0;
		EVP_PKEY *key;
		ubyte* _decMsg;
		auto decMsg = &_decMsg;
		*decMsg = cast(ubyte*)GC.malloc(encMsgLen + ivl);
		if(decMsg == null)
			throw new CryptographicException("Malloc failed.");

		EVP_CIPHER_CTX *rsaDecryptCtx = cast(EVP_CIPHER_CTX*)GC.malloc(EVP_CIPHER_CTX.sizeof);	
		if(rsaDecryptCtx == null)
			throw new CryptographicException("Malloc failed.");

		EVP_CIPHER_CTX_init(rsaDecryptCtx);

		if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_ctr(), ek, ekl, iv, keypair))
			throw new CryptographicException("EVP_OpenInit failed.");

		if(!EVP_OpenUpdate(rsaDecryptCtx, cast(ubyte*)*decMsg + decLen, cast(int*)&blockLen, encMsg, cast(int)encMsgLen))
			throw new CryptographicException("EVP_OpenUpdate failed.");
		decLen += blockLen;

		if(!EVP_OpenFinal(rsaDecryptCtx, cast(ubyte*)*decMsg + decLen, cast(int*)&blockLen))
			throw new CryptographicException("EVP_OpenFinal failed.");
		decLen += blockLen;

		EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);

		return (*decMsg)[0 .. decLen];
	} // open()

// ----------------------------------------------------------

	ubyte[] getPublicKey()
	{
		BIO* bio = BIO_new(BIO_s_mem());

		PEM_write_bio_PUBKEY(bio, keypair);

		ubyte[] buffer = new ubyte[BIO_ctrl_pending(bio)];
		BIO_read(bio, buffer.ptr, cast(int)buffer.length);
		BIO_free_all(bio);

		return buffer;
	} // getPublicKey()

// ----------------------------------------------------------

	public ubyte[] getPrivateKey(string password, int iterations = 25000, bool use3Des = false)
	{
		if (!_hasPrivateKey)
			return null;

		BIO* bio = BIO_new(BIO_s_mem());

		if (password is null)
			PEM_write_bio_PKCS8PrivateKey(bio, keypair, null, null, 0, null, null);
		else
		{
			ubyte[] pwd = cast(ubyte[])password;
			pwd = pwd ~ '\0';

			PEM_write_bio_PKCS8PrivateKey(
				bio,
				keypair,
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

		return buffer;
	} // getPrivateKey()

// ----------------------------------------------------------

	ubyte[] encrypt(const ubyte[] inMessage)
	{
		EVP_PKEY_CTX *ctx;
		ENGINE *eng = null; // Use default RSA implementation
		ubyte *out2;
		const ubyte *in2 = inMessage.ptr;
		size_t outlen;
		size_t inlen = inMessage.length; 
			
		ctx = EVP_PKEY_CTX_new(keypair,eng);
		if (!ctx) 
			throw new CryptographicException("EVP_PKEY_CTX_new.");
		
		if (EVP_PKEY_encrypt_init(ctx) <= 0)
			throw new CryptographicException("EVP_PKEY_encrypt_init failed.");
		
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
			throw new CryptographicException("EVP_PKEY_CTX_set_rsa_padding failed.");

		if (EVP_PKEY_encrypt(ctx, null, &outlen, in2, inlen) <= 0)
			throw new CryptographicException("EVP_PKEY_encrypt failed.");

		out2 = cast(ubyte*)GC.malloc(outlen);
		if(out2 == null)
			throw new CryptographicException("Malloc failed.");
			
		if (EVP_PKEY_encrypt(ctx, out2, &outlen, in2, inlen) <= 0)
			throw new CryptographicException("EVP_PKEY_encrypt failed.");

		EVP_PKEY_CTX_free(ctx);
		
		return (out2)[0 .. outlen];
	} // encrypt()

// ----------------------------------------------------------

	ubyte[] decrypt(const ubyte[] inMessage)
	{
		EVP_PKEY_CTX *ctx;
		ENGINE *eng = null; // Use default RSA implementation
		ubyte *out2;
		const ubyte *in2 = inMessage.ptr;
		size_t outlen;
		size_t inlen = inMessage.length; 
			
		ctx = EVP_PKEY_CTX_new(keypair,eng);
		if (!ctx) 
			throw new CryptographicException("EVP_PKEY_CTX_new failed");
		
		if (EVP_PKEY_decrypt_init(ctx) <= 0)
			throw new CryptographicException("EVP_PKEY_decrypt_init failed.");

		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
			throw new CryptographicException("EVP_PKEY_CTX_set_rsa_padding failed.");

		if (EVP_PKEY_decrypt(ctx, null, &outlen, in2, inlen) <= 0)
			throw new CryptographicException("EVP_PKEY_decrypt failed.");

		out2 = cast(ubyte*)GC.malloc(outlen);
		if(out2 == null)
			throw new CryptographicException("Malloc failed.");

		if (EVP_PKEY_decrypt(ctx, out2, &outlen, in2, inlen) <= 0)
			throw new CryptographicException("EVP_PKEY_encrypt failed.");

		EVP_PKEY_CTX_free(ctx);

		return (out2)[0 .. outlen];
	} // decrypt()

} // class RSA

// ----------------------------------------------------------
// ----------------------------------------------------------

unittest
{
	import std.stdio;
	writeln("Testing seal and open functions");

	auto keypair = new RSA();

   	ubyte[] plaintext = cast(ubyte[])"This is a test This is a test This is a test This is a test";
	
	ubyte[] encMessage = keypair.seal(plaintext);
	ubyte[] decMessage = keypair.open(encMessage);

    assert(plaintext.length	== decMessage.length);
    assert(plaintext		== decMessage);

	delete keypair;
}

// ----------------------------------------------------------

unittest
{
	import std.stdio;
	writeln("Testing getXxxKey functions and constructors");

	auto keypairA = new RSA();

	auto privateKeyA = keypairA.getPrivateKey(null);
	auto publicKeyA  = keypairA.getPublicKey();
	
  	const ubyte[] plaintext	= cast(ubyte[])"This is a test";

	// Creating key from public key only
	auto keypairB = new RSA(publicKeyA);

	auto privateKeyB = keypairB.getPrivateKey(null);
	auto publicKeyB  = keypairB.getPublicKey();

	assert(privateKeyA	!= privateKeyB,	"Private keys A and B match - they should NOT do so");
	assert(publicKeyA 	== publicKeyB,	"Public  keys A and B does not match");

	//  Creating key from private key only
	auto keypairC = new RSA(privateKeyA, null);

	auto publicKeyC	 = keypairC.getPublicKey();
	auto privateKeyC = keypairC.getPrivateKey(null);

	assert(privateKeyA	== privateKeyC,	"Private keys A and C does not match");
	assert(publicKeyA 	== publicKeyC,	"Public  keys A and C does not match");
	
	delete keypairA;
	delete keypairB;
	delete keypairC;
}

// ----------------------------------------------------------

unittest
{
	import std.stdio;
	writeln("Testing sealing and opening with keys, which have been constructed on getXxxKey output");

	auto keypairA = new RSA();

	auto privateKeyA = keypairA.getPrivateKey(null);
	auto publicKeyA  = keypairA.getPublicKey();
	
  	const ubyte[] plaintext	= cast(ubyte[])"This is a test";

	// Creating key from public key only
	auto keypairB		=  new RSA(publicKeyA);
	auto publicKeyB		=  keypairB.getPublicKey();
	assert(publicKeyA 	== publicKeyB,	"Public  keys A and B does not match");

	//  Creating key from private key only
	auto keypairC		=  new RSA(privateKeyA, null);
	auto privateKeyC	=  keypairC.getPrivateKey(null);
	assert(privateKeyA	== privateKeyC,	"Private keys A and C does not match");

	// Sealing plaintext using public key
	ubyte[] encMessageC = keypairB.seal(plaintext);
	// Opening encrypted message using private key
	ubyte[] decMessageC = keypairC.open(encMessageC);
	
    assert(plaintext.length	== decMessageC.length);
    assert(plaintext		== decMessageC);

	delete keypairA;
	delete keypairB;
	delete keypairC;
}

// ----------------------------------------------------------

unittest
{
	// Only RSA asymmetric encryption!

	import std.stdio;
	writeln("Testing encrypt/decrypt functions");

	auto keypair = new RSA();

   	//const ubyte[] plaintext = cast(ubyte[])"abc";
	ubyte[48] plaintext = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
							0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
							0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
	
	ubyte[] encMessage = keypair.encrypt(plaintext);
	ubyte[] decMessage = keypair.decrypt(encMessage);

    assert(plaintext.length	== decMessage.length);
    assert(plaintext		== decMessage);

	delete keypair;
}

// ----------------------------------------------------------
