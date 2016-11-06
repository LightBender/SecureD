module secured.aes;

import deimos.openssl.evp;

import secured.hmac;
import secured.random;
import secured.util;

public ubyte[] encrypt (ubyte[] key, ubyte[] data, ubyte[] additionalData)
in
{
	assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
	//Get the OpenSSL cipher context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx is null)
		throw new CryptographicException("Cannot get an OpenSSL cipher context.");
	scope(exit)
		if (ctx !is null)
			EVP_CIPHER_CTX_free(ctx);

	//Generate a random IV
	ubyte[] iv = random(16);

	//Initialize the cipher context
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), null, key.ptr, iv.ptr) != 1)
		throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");

	//Write data to the cipher context
	int written = 0;
	int len = 0;
	ubyte[] output = new ubyte[data.length+1];
	if (EVP_EncryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1)
		throw new CryptographicException("Unable to write bytes to cipher context.");
	written += len;

	//Extract the complete ciphertext
	if (EVP_EncryptFinal_ex(ctx, &output[written], &len) != 1)
		throw new CryptographicException("Unable to extract the ciphertext from the cipher context.");
	written += len;

	//Workaround for extra byte required
	output = output[0..$-1];

	//HMAC the combined cipher text
	ubyte[] hashdata = additionalData !is null ? iv ~ output ~ additionalData : iv ~ output;
	ubyte[] hash = hmac(key, hashdata);

	//Return the HMAC + IV + Ciphertext as a single byte array.
	return hash ~ iv ~ output;
}

public bool validate (ubyte[] key, ubyte[] data, ubyte[] additionalData)
in
{
	assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
	ubyte[] datahash = data[0..48];
	ubyte[] dataad = additionalData !is null ? data[48..$] ~ additionalData : data[48..$];
	ubyte[] computed = hmac(key, dataad);

	return constantTimeEquality(datahash, computed);
}

public ubyte[] decrypt (ubyte[] key, ubyte[] data, ubyte[] additionalData)
in
{
	assert(key.length == 32, "Encryption key must be 32 bytes in length.");
}
body
{
	//Validate the data
	if (!validate(key, data, additionalData))
		throw new CryptographicException("Cannot get an OpenSSL cipher context.");

	ubyte[] iv = data[48..64];
	ubyte[] payload = data[64..$];

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
	ubyte[] output = new ubyte[data.length];
	if (EVP_DecryptUpdate(ctx, &output[written], &len, payload.ptr, cast(int)payload.length) != 1)
		throw new CryptographicException("Unable to write bytes to cipher context.");
	written += len;

	//Extract the complete plaintext
	if (EVP_DecryptFinal_ex(ctx, &output[written], &len) != 1)
		throw new CryptographicException("Unable to extract the plaintext from the cipher context.");
	written += len;

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
	ubyte[] enc = encrypt(key, cast(ubyte[])input, null);
	writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc));

	write("Testing Validation (No Additional Data): ");
	assert(validate(key, enc, null));
	writeln("Success!");

	writeln("Testing Decryption (No Additional Data)");
	ubyte[] dec = decrypt(key, enc, null);
	writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc));
	writeln("Decryption Output: ", cast(string)dec);
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing Encryption (With Additional Data)");

	ubyte[32] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	string input = "The quick brown fox jumps over the lazy dog.";
	string ad = "Hello world!";
	writefln("Encryption Input: %s - Additional Data: %s", input, ad);
	ubyte[] enc = encrypt(key, cast(ubyte[])input, cast(ubyte[])ad);
	writeln("Encryption Output: ", toHexString!(LetterCase.lower)(enc));

	write("Testing Validation (With Additional Data): ");
	assert(validate(key, enc, cast(ubyte[])ad));
	writeln("Success!");

	writeln("Testing Decryption (With Additional Data)");
	ubyte[] dec = decrypt(key, enc, cast(ubyte[])ad);
	writeln("Decryption Input: ", toHexString!(LetterCase.lower)(enc));
	writeln("Decryption Output: ", cast(string)dec);
}
