module secured.hash;

import std.stdio;
import deimos.openssl.evp;

import secured.util;

public ubyte[] hash(ubyte[] data)
{
	//Create the OpenSSL context
	EVP_MD_CTX *mdctx;
	if ((mdctx = EVP_MD_CTX_create()) == null)
		throw new CryptographicException("Unable to create OpenSSL context.");
	scope(exit)
		if(mdctx !is null)
			EVP_MD_CTX_destroy(mdctx);

	//Initialize the SHA-384 algorithm
	if (EVP_DigestInit_ex(mdctx, EVP_sha384(), null) != 1)
		throw new CryptographicException("Unable to create SHA-384 hash context.");

	//Run the provided data through the digest algorithm
	if (EVP_DigestUpdate(mdctx, data.ptr, data.length) != 1)
		throw new CryptographicException("Error while updating digest.");

	//Read the digest from OpenSSL
	ubyte* digestptr = null;
	uint* digestlen = null;
	if (EVP_DigestFinal_ex(mdctx, digestptr, digestlen) != 1)
		throw new CryptographicException("Error while retrieving the digest.");

	//Copy the OpenSSL digest to our D buffer.
	ubyte[] digest = new ubyte[*digestlen];
	for(int i = 0; i < *digestlen; i++)
		digest[i] = digestptr[i];

	return digest;
}

public ubyte[] hash(string path)
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
	if (EVP_DigestInit_ex(mdctx, EVP_sha384(), null) != 1)
		throw new CryptographicException("Unable to create SHA-384 hash context.");

	//Read the file in chunks and update the Digest
	foreach(ubyte[] data; fsfile.byChunk(FILE_BUFFER_SIZE))
	{
		if (EVP_DigestUpdate(mdctx, data.ptr, data.length) != 1)
			throw new CryptographicException("Error while updating digest.");
	}

	//Read the digest from OpenSSL
	ubyte* digestptr = null;
	uint* digestlen = null;
	if (EVP_DigestFinal_ex(mdctx, digestptr, digestlen) != 1)
		throw new CryptographicException("Error while retrieving the digest.");

	//Copy the OpenSSL digest to our D buffer.
	ubyte[] digest = new ubyte[*digestlen];
	for(int i = 0; i < *digestlen; i++)
		digest[i] = digestptr[i];

	return digest;
}
