module secured.util;

public enum uint FILE_BUFFER_SIZE = 32768;

public class CryptographicException : Exception
{
	this(string message)
	{
		super(message);
	}
}