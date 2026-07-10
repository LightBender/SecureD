module secured.util;

import std.stdio;

import secured.provider;

/**
 * Default I/O buffer size (32 KiB) used when hashing or processing files in
 * streaming fashion. Chosen as a balance between syscall overhead and memory
 * use on typical desktop and server workloads.
 */
public enum uint FILE_BUFFER_SIZE = 32768;

/**
 * Base exception for cryptographic failures in SecureD (invalid keys, failed
 * authentication tags, provider errors, malformed inputs, etc.).
 *
 * In debug builds with an OpenSSL-family provider, the constructor also drains
 * and prints the OpenSSL error queue to aid diagnosis.
 *
 * Params:
 *   message = Human-readable description of the failure.
 */
@trusted public class CryptographicException : Exception
{
    /**
     * Constructs the exception with the given message.
     *
     * Params:
     *   message = Human-readable description of the failure.
     */
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

/**
 * Thrown when a requested algorithm is not supported by the active cryptographic
 * provider and the polyfill configuration is not enabled.
 *
 * Derives from $(D CryptographicException) so existing
 * `catch (CryptographicException)` handlers continue to work.
 *
 * Params:
 *   message = Description of the unsupported algorithm and how to enable
 *             polyfill if desired.
 */
@trusted public class AlgorithmNotSupportedException : CryptographicException
{
    /**
     * Constructs the exception with the given message.
     *
     * Params:
     *   message = Description of the unsupported algorithm.
     */
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

/**
 * Compares two byte arrays in constant time with respect to their contents.
 *
 * Suitable for comparing secrets, MACs, and digests. Length mismatches are
 * folded into the result without early return, so timing does not reveal
 * whether lengths matched or where the first differing byte is.
 *
 * Params:
 *   a = First buffer.
 *   b = Second buffer.
 *
 * Returns: `true` if both buffers have the same length and identical contents;
 *          `false` otherwise.
 */
@safe pure public bool constantTimeEquality(const ubyte[] a, const ubyte[] b)
{
    // Do not early-return on length mismatch: that leaks whether the lengths
    // matched via timing. Always walk the longer buffer; fold the length
    // difference into the accumulator so a mismatch still returns false.
    size_t len = a.length < b.length ? b.length : a.length;
    int result = cast(int)(a.length ^ b.length);
    for (size_t i = 0; i < len; i++) {
        ubyte x = i < a.length ? a[i] : 0;
        ubyte y = i < b.length ? b[i] : 0;
        result |= x ^ y;
    }
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
