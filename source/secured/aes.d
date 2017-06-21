module secured.aes;

version(OpenSSL)
{
import deimos.openssl.evp;
}
version(Botan)
{
import memutils.vector;
import botan.stream.ctr;
import botan.block.aes;
import botan.block.aes_ssse3;
import botan.block.aes_ni;
import botan.utils.cpuid;
}

import secured.hmac;
import secured.random;
import secured.util;

@trusted public ubyte[] encrypt (ubyte[] key, ubyte[] data)
in
{
	assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
	ubyte[] output = new ubyte[data.length];

	//Generate a random IV
	ubyte[] iv = random(16);

	version(OpenSSL)
	{
		//Get the OpenSSL cipher context
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (ctx is null)
			throw new CryptographicException("Cannot get an OpenSSL cipher context.");
		scope(exit)
			if (ctx !is null)
				EVP_CIPHER_CTX_free(ctx);

		//Initialize the cipher context
		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), null, key.ptr, iv.ptr) != 1)
			throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");

		//Write data to the cipher context
		int written = 0;
		int len = 0;
		if (EVP_EncryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1)
			throw new CryptographicException("Unable to write bytes to cipher context.");
		written += len;

		//Extract the complete ciphertext
		if (EVP_EncryptFinal_ex(ctx, &output[written-1], &len) != 1)
			throw new CryptographicException("Unable to extract the ciphertext from the cipher context.");
		written += len;
	}

	version(Botan)
	{
		auto payload = SecureVector!ubyte(data);

		auto ctr = new CTRBE(
			CPUID.hasAesNi() ? new AES256NI() :
			CPUID.hasSsse3() ? new AES256_SSSE3() :
			new AES256()
			);

		ctr.setKey(key.ptr, key.length);
		ctr.setIv(iv.ptr, iv.length);
		ctr.encrypt(payload);

		for(int i=0; i<data.length; i++)
			output[i]=payload[i];
	}

	//HMAC the combined cipher text
	ubyte[] hashdata = iv ~ output;
	ubyte[] hash = hmac(key, hashdata);

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
	ubyte[] computed = hmac(key, data[48..$]);

	return constantTimeEquality(datahash, computed);
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
		throw new CryptographicException("Cannot get an OpenSSL cipher context.");

	ubyte[] iv = data[48..64];
	ubyte[] payload = data[64..$];
	ubyte[] output = new ubyte[payload.length];

	version(OpenSSL)
	{
		//Get the OpenSSL cipher context
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (ctx is null)
			throw new CryptographicException("Cannot get an OpenSSL cipher context.");
		scope(exit)
			EVP_CIPHER_CTX_free(ctx);

		//Initialize the cipher context
		if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), null, key.ptr, iv.ptr) != 1)
			throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");

		//Write data to the cipher context
		int written = 0;
		int len = 0;
		if (EVP_DecryptUpdate(ctx, &output[written], &len, payload.ptr, cast(int)payload.length) != 1)
			throw new CryptographicException("Unable to write bytes to cipher context.");
		written += len;

		//Extract the complete plaintext
		if (EVP_DecryptFinal_ex(ctx, &output[written-1], &len) != 1)
			throw new CryptographicException("Unable to extract the plaintext from the cipher context.");
		written += len;
	}

	version(Botan)
	{
		auto dec = SecureVector!ubyte(payload);

		auto ctr = new CTRBE(
			CPUID.hasAesNi() ? new AES256NI() :
			CPUID.hasSsse3() ? new AES256_SSSE3() :
			new AES256()
			);

		ctr.setKey(key.ptr, key.length);
		ctr.setIv(iv.ptr, iv.length);
		ctr.decrypt(dec);

		for(int i=0; i<payload.length; i++)
			output[i]=dec[i];
	}

	return output;
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing Encryption (No Additional Data)");

	ubyte[32] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	string input = "The quick brown fox jumps over the lazy dog.";
	writeln("Encryption Input: ", input);
	ubyte[] enc = encrypt(key, cast(ubyte[])input);
	writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc));

	write("Testing Validation (No Additional Data): ");
	assert(validate(key, enc));
	writeln("Success!");

	writeln("Testing Decryption (No Additional Data)");
	ubyte[] dec = decrypt(key, enc);
	writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc));
	writeln("Decryption Output: ", cast(string)dec);

	assert((cast(string)dec) == input);
}
