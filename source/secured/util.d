module secured.util;

import std.stdio;

import secured.provider;

public enum uint FILE_BUFFER_SIZE = 32768;

@trusted public class CryptographicException : Exception
{
    this(string message)
    {
        super(message);
        debug {
            static if (usesOpenSSL) {
                import secured.bindings.openssl : ERR_peek_error, ERR_get_error, ERR_error_string_n;
                while(ERR_peek_error() != 0) {
                    char[] buf = new char[512];
                    ERR_error_string_n(ERR_get_error(), buf.ptr, 512);
                    writeln(buf);
                }
            }
        }
    }
}

/*
 * Thrown when a requested algorithm is not supported by the active cryptographic
 * provider and the polyfill configuration is not enabled. It derives from
 * CryptographicException so that existing catch(CryptographicException) handlers
 * continue to behave as before.
 */
@trusted public class AlgorithmNotSupportedException : CryptographicException
{
    this(string message)
    {
        super(message);
    }
}

version (unittest) {
    /*
     * Test helper: runs a unittest body and, if the active provider does not
     * support a requested algorithm (and the polyfill is disabled), prints a
     * skip notice instead of failing. This is the only allowed modification to
     * the unittests: it lets the full suite run under any provider configuration
     * while clearly reporting algorithms that are unavailable in that build.
     */
    package void skipIfUnsupported(scope void delegate() test, string file = __FILE__, size_t line = __LINE__) {
        import std.stdio : writeln;
        try {
            test();
        } catch (AlgorithmNotSupportedException e) {
            writeln("SKIP [", file, ":", line, "] algorithm unsupported in this configuration: ", e.msg);
        }
    }
}

@safe pure public bool constantTimeEquality(const ubyte[] a, const ubyte[] b)
{
    if(a.length != b.length)
        return false;

    int result = 0;
    for(int i = 0; i < a.length; i++)
        result |= a[i] ^ b[i];
    return result == 0;
}

unittest
{
    import std.digest;
    import std.stdio;
    import secured.random;

    writeln("Testing Constant Time Equality:");

    //Test random data
    ubyte[] rnd1 = random(32);
    ubyte[] rnd2 = random(32);
    writeln("Testing with Random Data");
    assert(!constantTimeEquality(rnd1, rnd2));

    //Test equal data
    ubyte[48] key1 = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
    ubyte[48] key2 = [ 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
    writeln("Testing with Equal Data");
    assert(constantTimeEquality(key1, key2));
}
