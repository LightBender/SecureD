module secured.kdf;

version(OpenSSL)
{
import deimos.openssl.evp;
}

version(Botan)
{
import botan.hash.sha2_64;
import botan.mac.hmac;
import botan.pbkdf.pbkdf2;
import core.time;
}

import secured.util;

@trusted public ubyte[] pbkdf2(ubyte[] key, string password, uint iterations = 25000, uint outputLen = 48)
in
{
	assert(key.length == 48, "The key must be 48 bytes in length.");
	assert(outputLen <= 48, "The output length must be less than or equal to 48 bytes in length.");
}
body
{
	version(OpenSSL)
	{
		ubyte[] output = new ubyte[outputLen];
		if(PKCS5_PBKDF2_HMAC(password.ptr, cast(int)password.length, key.ptr, cast(int)key.length, iterations, EVP_sha384(), outputLen, output.ptr) == 0)
			throw new CryptographicException("Unable to execute PBKDF2 hash function.");
		return output;
	}

	version(Botan)
	{
		auto kdf = new PKCS5_PBKDF2(new HMAC(new SHA384()));
		auto result = kdf.keyDerivation(cast(ulong)outputLen, cast(const(string))password, key.ptr, key.length, cast(ulong)iterations, Duration.zero);
		auto octet = result.second();

		ubyte[] output = new ubyte[octet.length()];
		ubyte* octetptr = octet.ptr();
		for(int i = 0; i < octet.length(); i++)
			output[i] = octetptr[i];
		return output;
	}
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing PBKDF2 with Defaults:");

	ubyte[48] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	ubyte[] vec1 = pbkdf2(key, "");
	ubyte[] vec2 = pbkdf2(key, "abc");
	ubyte[] vec3 = pbkdf2(key, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

	writeln(toHexString!(LetterCase.lower)(vec1));
	writeln(toHexString!(LetterCase.lower)(vec2));
	writeln(toHexString!(LetterCase.lower)(vec3));

	assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bde9db7c8ccf14df26f8305fc8634572f9");
	assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff45417d47d84db06a12b8ea49377a7c7cb");
	assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520b2834d7bf22b83bb5c21c4bccb423be2");
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing PBKDF2 with Custom Iterations:");

	ubyte[48] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	ubyte[] vec1 = pbkdf2(key, "", 150000);
	ubyte[] vec2 = pbkdf2(key, "abc", 150000);
	ubyte[] vec3 = pbkdf2(key, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 150000);

	writeln(toHexString!(LetterCase.lower)(vec1));
	writeln(toHexString!(LetterCase.lower)(vec2));
	writeln(toHexString!(LetterCase.lower)(vec3));

	assert(toHexString!(LetterCase.lower)(vec1) == "babdcbbf4ff89367ed223d2edd06ef5473ac9cdc827783ed0b4b5eafd9e4097beb2ef66d6fc92d24dbf4b86aa51b4a0f");
	assert(toHexString!(LetterCase.lower)(vec2) == "8894348ccea06d79f80382ae7d4434c0f2ef41f871d936604f426518ab23bde4410fddce6dad943c95de75dbece9b54a");
	assert(toHexString!(LetterCase.lower)(vec3) == "fba55e91818c35b1e4cc753fbd01a6cd138c49da472b58b2d7c4860ba39a3dd9032f8f641aadcd74a819361ed27c9a0f");
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing PBKDF2 with Custom Output Length:");

	ubyte[48] key = [	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];

	ubyte[] vec1 = pbkdf2(key, "", 25000, 32);
	ubyte[] vec2 = pbkdf2(key, "abc", 25000, 32);
	ubyte[] vec3 = pbkdf2(key, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 25000, 32);

	writeln(toHexString!(LetterCase.lower)(vec1));
	writeln(toHexString!(LetterCase.lower)(vec2));
	writeln(toHexString!(LetterCase.lower)(vec3));

	assert(toHexString!(LetterCase.lower)(vec1) == "b0ddf56b90903d638ec8d07a4205ba2bcfa944955d553e1ef3f91cba84e8e3bd");
	assert(toHexString!(LetterCase.lower)(vec2) == "b0a5e09a38bee3eb2b84d477d5259ef7bebf0e48d9512178f7e26cc330278ff4");
	assert(toHexString!(LetterCase.lower)(vec3) == "d1aacafea3a9fdf3ee6236b1b45527974ea01539b4a7cc493bba56e15e14d520");
}
