module secured.threading;

import deimos.openssl.crypto;
import core.thread;

shared static this()
{
	CRYPTO_set_locking_callback(&thread_locking_function);
	CRYPTO_set_id_callback(&thread_id_function);
}
shared static ~this()
{
	CRYPTO_set_locking_callback(null);
	CRYPTO_set_id_callback(null);
}

extern(C) public static void thread_locking_function(int mode, int n, const(char)* file, int line)
{
	if(mode & CRYPTO_LOCK){
		thread_enterCriticalRegion();
	} else {
		thread_exitCriticalRegion();
	}
}

extern(C) public static ulong thread_id_function()
{
	return cast(ulong)Thread.getThis().id;
}