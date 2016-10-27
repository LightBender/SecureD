module secured.hmac;

import std.stdio;
import deimos.openssl.evp;

import secured.util;

public ubyte[] hmac(ubyte[] data, ubyte[] key)
{
	//Create the OpenSSL context
	EVP_MD_CTX *mdctx;
	if ((mdctx = EVP_MD_CTX_create()) == null)
		throw new CryptographicException("Unable to create OpenSSL context.");
	scope(exit)
		if(mdctx !is null)
			EVP_MD_CTX_destroy(mdctx);

	//Initialize the SHA-384 algorithm
	const(EVP_MD)* md = EVP_sha384();
	if (EVP_DigestInit_ex(mdctx, md, null) != 1)
		throw new CryptographicException("Unable to create SHA-384 hash context.");

	//Create the HMAC key context
	auto pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, null, key.ptr, cast(int)key.length);
	scope(exit)
		if(pkey !is null)
			EVP_PKEY_free(pkey);
	if (EVP_DigestSignInit(mdctx, null, md, null, pkey) != 1)
		throw new CryptographicException("Unable to create SHA-384 HMAC key context.");

	//Run the provided data through the digest algorithm
	if (EVP_DigestSignUpdate(mdctx, data.ptr, data.length) != 1)
		throw new CryptographicException("Error while updating digest.");

	//Read the digest from OpenSSL
	ubyte* digestptr = null;
	ulong* digestlen = null;
	if (EVP_DigestSignFinal(mdctx, digestptr, digestlen) != 1)
		throw new CryptographicException("Error while retrieving the digest.");

	//Copy the OpenSSL digest to our D buffer.
	ubyte[] digest = new ubyte[*digestlen];
	for(int i = 0; i < *digestlen; i++)
		digest[i] = digestptr[i];

	return digest;
}

public ubyte[] hmac(string path, ubyte[] key)
{
	//Open the file for reading
	auto fsfile = File(path, "rb");
	scope(exit)
		if(fsfile.isOpen())
			fsfile.close();

	//Create the OpenSSL context
	EVP_MD_CTX *mdctx;
	if ((mdctx = EVP_MD_CTX_create()) == null)
		throw new CryptographicException("Unable to create OpenSSL context.");
	scope(exit)
		if(mdctx !is null)
			EVP_MD_CTX_destroy(mdctx);

	//Initialize the SHA-384 algorithm
	const(EVP_MD)* md = EVP_sha384();
	if (EVP_DigestInit_ex(mdctx, md, null) != 1)
		throw new CryptographicException("Unable to create SHA-384 hash context.");

	//Create the HMAC key context
	auto pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, null, key.ptr, cast(int)key.length);
	scope(exit)
		if(pkey !is null)
			EVP_PKEY_free(pkey);
	if (EVP_DigestSignInit(mdctx, null, md, null, pkey) != 1)
		throw new CryptographicException("Unable to create SHA-384 HMAC key context.");

	//Read the file in chunks and update the Digest
	foreach(ubyte[] data; fsfile.byChunk(FILE_BUFFER_SIZE))
	{
		if (EVP_DigestSignUpdate(mdctx, data.ptr, data.length) != 1)
			throw new CryptographicException("Error while updating digest.");
	}

	//Read the digest from OpenSSL
	ubyte* digestptr = null;
	ulong* digestlen = null;
	if (EVP_DigestSignFinal(mdctx, digestptr, digestlen) != 1)
		throw new CryptographicException("Error while retrieving the digest.");

	//Copy the OpenSSL digest to our D buffer.
	ubyte[] digest = new ubyte[*digestlen];
	for(int i = 0; i < *digestlen; i++)
		digest[i] = digestptr[i];

	return digest;
}
