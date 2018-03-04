module secured.random;

import secured.util;

version(CRuntime_Bionic)
	version = SecureARC4Random;//ChaCha20
else version(OSX)
	version = SecureARC4Random;//AES
else version(OpenBSD)
	version = SecureARC4Random;//ChaCha20
else version(NetBSD)
	version = SecureARC4Random;//ChaCha20
// Can uncomment following two lines if Solaris versions prior to 11.3 are unsupported:
//else version (Solaris)
//	version = SecureARC4Random;

version(SecureARC4Random)
extern(C) @nogc nothrow private @system
{
	void arc4random_buf(scope void* buf, size_t nbytes);
}

@trusted public ubyte[] random(uint bytes)
{
	if (bytes == 0)
	{
		throw new CryptographicException("The number of requested bytes must be greater than zero.");
	}
	ubyte[] buffer = new ubyte[bytes];

	version(SecureARC4Random)
	{
		arc4random_buf(buffer.ptr, bytes);
	}
	else version(Posix)
	{
		import std.exception;
		import std.format;
		import std.stdio;

		try
		{
			//Initialize the system random file buffer
			File urandom = File("/dev/urandom", "rb");
			urandom.setvbuf(null, _IONBF);
			scope(exit) urandom.close();

			//Read into the buffer
			try
			{
				buffer = urandom.rawRead(buffer);
			}
			catch(ErrnoException ex)
			{
				throw new CryptographicException(format("Cannot get the next random bytes. Error ID: %d, Message: %s", ex.errno, ex.msg));
			}
			catch(Exception ex)
			{
				throw new CryptographicException(format("Cannot get the next random bytes. Message: %s", ex.msg));
			}
		}
		catch(ErrnoException ex)
		{
			throw new CryptographicException(format("Cannot initialize the system RNG. Error ID: %d, Message: %s", ex.errno, ex.msg));
		}
		catch(Exception ex)
		{
			throw new CryptographicException(format("Cannot initialize the system RNG. Message: %s", ex.msg));
		}
	}
	else version(Windows)
	{
		import core.sys.windows.windows;
		import std.format;
		HCRYPTPROV hCryptProv;

		//Get the cryptographic context from Windows
		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			throw new CryptographicException("Unable to acquire Cryptographic Context.");
		}
		//Release the context when finished
		scope(exit) CryptReleaseContext(hCryptoProv, 0);

		//Generate the random bytes
		if (!CryptGenRandom(hCryptProv, cast(DWORD)buffer.length, buffer.ptr))
		{
			throw new CryptographicException(format("Cannot get the next random bytes. Error ID: %d", GetLastError()));
		}
	}
	else
	{
		static assert(0, "SecureD does not support this OS.");
	}

	return buffer;
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing Random Number Generator with 32/64/512/2048 bytes:");

	//Test 32 bytes
	ubyte[] rnd1 = random(32);
	writeln("32 Bytes:");
	writeln(toHexString!(LetterCase.lower)(rnd1));
	assert(rnd1.length == 32);

	//Test 128 bytes
	ubyte[] rnd2 = random(128);
	writeln("128 Bytes:");
	writeln(toHexString!(LetterCase.lower)(rnd2));
	assert(rnd2.length == 128);

	//Test 512 bytes
	ubyte[] rnd3 = random(512);
	writeln("512 Bytes:");
	writeln(toHexString!(LetterCase.lower)(rnd3));
	assert(rnd3.length == 512);

	//Test 2048 bytes
	ubyte[] rnd4 = random(2048);
	writeln("2048 Bytes:");
	writeln(toHexString!(LetterCase.lower)(rnd4));
	assert(rnd4.length == 2048);
}

unittest
{
	import std.digest.digest;
	import std.stdio;

	writeln("Testing Random Number Generator for Equality:");

	//Test 32 bytes
	ubyte[] rnd1 = random(32);
	ubyte[] rnd2 = random(32);
	writeln("Testing with 32 Bytes");
	assert(!constantTimeEquality(rnd1, rnd2));

	//Test 128 bytes
	rnd1 = random(128);
	rnd2 = random(128);
	writeln("Testing with 128 Bytes");
	assert(!constantTimeEquality(rnd1, rnd2));

	//Test 512 bytes
	rnd1 = random(512);
	rnd2 = random(512);
	writeln("Testing with 512 Bytes");
	assert(!constantTimeEquality(rnd1, rnd2));

	//Test 2048 bytes
	rnd1 = random(2048);
	rnd2 = random(2048);
	writeln("Testing with 2048 Bytes");
	assert(!constantTimeEquality(rnd1, rnd2));
}
