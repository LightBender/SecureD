module secured.kdf;

import deimos.openssl.evp;

import secured.util;

public ubyte[] pbkdf2(string password, ubyte[] key, int iterations = 25000, int outputLen = 48)
in
{
	assert(key.length == 48, "The key must be 48 bytes in length.");
	assert(outputLen <= 48, "The output length must be less than or equal to 48 bytes in length.");
}
body
{
	ubyte* outputptr;
	if(PKCS5_PBKDF2_HMAC(password.ptr, cast(int)password.length, key.ptr, cast(int)key.length, iterations, EVP_sha384(), outputLen, outputptr) != 1)
		throw new CryptographicException("Execute PBKDF2 hash function.");

	//Copy the OpenSSL digest to our D buffer.
	ubyte[] output = new ubyte[outputLen];
	for(int i = 0; i < outputLen; i++)
		output[i] = outputptr[i];

	return output;
}
