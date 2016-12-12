module secured.hmac;

import std.stdio;

version(OpenSSL)
{
import deimos.openssl.evp;
}
version(Botan)
{
import botan.mac.hmac;
import botan.hash.sha2_64;
}
import secured.util;

public ubyte[] hmac(ubyte[] key, ubyte[] data)
in
{
	assert(key.length <= 48, "HMAC key must be less than or equal to 48 bytes in length.");
}
body
{
	version(OpenSSL)
	{
		//Create the OpenSSL context
		EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
		if (mdctx == null)
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

		//Copy the OpenSSL digest to our D buffer.
		ulong digestlen;
		ubyte[] digest = new ubyte[48];
		if (EVP_DigestSignFinal(mdctx, digest.ptr, &digestlen) < 0)
			throw new CryptographicException("Error while retrieving the digest.");

		return digest;
	}

	version(Botan)
	{
		auto sha = new HMAC(new SHA384());
		scope(exit)
			sha.clear();
		sha.setKey(key.ptr, key.length);

		sha.update(data);

		auto digestvec = sha.finished();
		ubyte[] digest = new ubyte[digestvec.length];
		for(int i = 0; i<digestvec.length; i++)
			digest[i] = digestvec[i];
		return digest;
	}
}

unittest {
	import std.digest.digest;

	writeln("Testing Byte Array HMAC:");

	ubyte[48] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	ubyte[] vec1 = hmac(key, cast(ubyte[])"");
	ubyte[] vec2 = hmac(key, cast(ubyte[])"abc");
	ubyte[] vec3 = hmac(key, cast(ubyte[])"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

	writeln(toHexString!(LetterCase.lower)(vec1));
	writeln(toHexString!(LetterCase.lower)(vec2));
	writeln(toHexString!(LetterCase.lower)(vec3));

	assert(toHexString!(LetterCase.lower)(vec1) == "440b0d5f59c32cbee090c3d9f524b81a9b9708e9b65a46bbc189842b0ab0759d3bf118acca58eda0813fd346e8ccfde4");
	assert(toHexString!(LetterCase.lower)(vec2) == "cb5da1048feb76fd75752dc1b699caba124090feac21adb5b4c0f6600e7b626e08d7415660aa0ee79ca5b83e56669a60");
	assert(toHexString!(LetterCase.lower)(vec3) == "460b59c0bd8ae48133431185a4583376738be3116cafce47aff7696bd19501b0cf1f1850c3e5fa2992882997493d1c99");
}

public ubyte[] hmac(ubyte[] key, string path)
in
{
	assert(key.length <= 48, "HMAC key must be less than or equal to 48 bytes in length.");
}
body
{
	//Open the file for reading
	auto fsfile = File(path, "rb");
	scope(exit)
		if(fsfile.isOpen())
			fsfile.close();

	version(OpenSSL)
	{
		//Create the OpenSSL context
		EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
		if (mdctx == null)
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

		//Copy the OpenSSL digest to our D buffer.
		ulong digestlen;
		ubyte[] digest = new ubyte[48];
		if (EVP_DigestSignFinal(mdctx, digest.ptr, &digestlen) < 0)
			throw new CryptographicException("Error while retrieving the digest.");

		return digest;
	}

	version(Botan)
	{
		auto sha = new HMAC(new SHA384());
		scope(exit)
			sha.clear();
		sha.setKey(key.ptr, key.length);

		foreach(ubyte[] data; fsfile.byChunk(FILE_BUFFER_SIZE))
		{
			sha.update(data);
		}

		auto digestvec = sha.finished();
		ubyte[] digest = new ubyte[digestvec.length];
		for(int i = 0; i<digestvec.length; i++)
			digest[i] = digestvec[i];
		return digest;
	}
}

unittest {
	import std.digest.digest;

	ubyte[48] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	writeln("Testing File HMAC:");

	auto f = File("hashtest.txt", "wb");
	f.rawWrite("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	f.close();

	ubyte[] vec = hmac(key, "hashtest.txt");
	writeln(toHexString!(LetterCase.lower)(vec));
	assert(toHexString!(LetterCase.lower)(vec) == "460b59c0bd8ae48133431185a4583376738be3116cafce47aff7696bd19501b0cf1f1850c3e5fa2992882997493d1c99");

	remove("hashtest.txt");
}
