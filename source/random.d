module secured.random;

import secured.util;

public ubyte[] random(uint bytes)
{
	if (bytes == 0)
	{
		throw new CryptographicException("The number of requested bytes must be greater than zero.");
	}
	ubyte[] buffer = new ubyte[bytes];

	version(Posix)
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
