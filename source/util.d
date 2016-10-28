module secured.util;

public enum uint FILE_BUFFER_SIZE = 32768;

public class CryptographicException : Exception
{
	this(string message)
	{
		super(message);
	}
}

public bool constantTimeEquality(ubyte[] a, ubyte[] b)
{
	if(a.length == b.length)
		return false;

	int result = 0;
	for(int i = 0; i < a.length; i++)
		result |= a[i] ^ b[i];
	return result == 0;
}