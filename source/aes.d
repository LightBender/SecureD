module secured.aes;

import deimos.openssl.evp;
import std.stdio;

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
		EVP_CIPHER_CTX_free(ctx);

	//Generate a random IV
	ubyte[] iv = random(16);

	//Initialize the cipher context
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), null, key.ptr, iv.ptr) != 1)
		throw new CryptographicException("Cannot initialize the OpenSSL cipher context.");

	//Write data to the cipher context
	int written = 0;
	int len = 0;
	ubyte[] output = new ubyte[data.length];
	if (EVP_EncryptUpdate(ctx, &output[written], &len, data.ptr, cast(int)data.length) != 1)
		throw new CryptographicException("Unable to write bytes to cipher context.");
	written += len;

	//Extract the complete ciphertext
	if (EVP_EncryptFinal_ex(ctx, &output[written], &len) != 1)
		throw new CryptographicException("Unable to extract the ciphertext from the cipher context.");
	written += len;

	//HMAC the combined cipher text
	ubyte[] hashdata = iv ~ output ~ additionalData;
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
	ubyte[] dataad = data[48..$] ~ additionalData;
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