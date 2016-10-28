module secured.pbkdf2;

import deimos.openssl.evp;

import secured.util;

public ubyte[] pbkdf2(string password, ubyte[] key, int iterations = 25000, int outputLen = 48)
{
	if(outputLen > 48)
		throw new CryptographicException("outputLen cannot be greater than 48.");

	ubyte* outputptr;
	if(PKCS5_PBKDF2_HMAC(password.ptr, cast(int)password.length, key.ptr, cast(int)key.length, iterations, EVP_sha384(), outputLen, outputptr) != 1)
		throw new CryptographicException("Execute PBKDF2 hash function.");

	//Copy the OpenSSL digest to our D buffer.
	ubyte[] output = new ubyte[outputLen];
	for(int i = 0; i < outputLen; i++)
		output[i] = outputptr[i];

	return output;
}
