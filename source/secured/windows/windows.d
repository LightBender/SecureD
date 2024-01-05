module secured.windows.windows;
version(Windows):
pragma (lib, "bcrypt.lib");

import std.conv;
import std.string;
import std.utf;

import secured.hash;
import secured.symmetric;
import secured.util;
import secured.windows.bcrypt;

public @trusted ubyte[] pbkdf2_winapi(string password, const ubyte[] salt, HashAlgorithm func, uint outputLen, uint iterations) {
	ubyte[] keyRef = cast(ubyte[])password.representation;
	ubyte[] output = new ubyte[outputLen];
	void* phAlgorithm = null;
	string algName = getWindowsHashAlgoName(func);

	long ret = BCryptOpenAlgorithmProvider(&phAlgorithm, algName.toWinApiWideChars(), MS_PRIMITIVE_PROVIDER.toWinApiWideChars(), BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (ret == 0xC0000225) throw new CryptographicException("Hash Function '"~to!string(func)~"' is not supported.");
	BCryptDeriveKeyPBKDF2(phAlgorithm, keyRef.ptr, cast(uint)keyRef.length, cast(ubyte*)salt.ptr, cast(uint)salt.length, iterations, output.ptr, outputLen, 0);
	scope(exit) {
		if (phAlgorithm != null) BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}

	return output;
}

public @trusted ubyte[] hash_winapi(const ubyte[] data, HashAlgorithm func) {
	ubyte[] output = new ubyte[getHashLength(func)];
	void* phAlgorithm = null;
	string algName = getWindowsHashAlgoName(func);

	long ret = BCryptOpenAlgorithmProvider(&phAlgorithm, algName.toWinApiWideChars(), MS_PRIMITIVE_PROVIDER.toWinApiWideChars(), 0);
	if (ret == 0xC0000225) throw new CryptographicException("Hash Function '"~to!string(func)~"' is not supported.");
	BCryptHash(phAlgorithm, null, 0, cast(ubyte*)data.ptr, cast(uint)data.length, output.ptr, getHashLength(func));
	scope(exit) {
		if (phAlgorithm != null) BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}

	return output;
}

public @trusted ubyte[] hmac_winapi(const ubyte[] key, const ubyte[] data, HashAlgorithm func) {
	ubyte[] output = new ubyte[getHashLength(func)];
	void* phAlgorithm = null;
	string algName = getWindowsHashAlgoName(func);

	long ret = BCryptOpenAlgorithmProvider(&phAlgorithm, algName.toWinApiWideChars(), MS_PRIMITIVE_PROVIDER.toWinApiWideChars(), BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (ret == 0xC0000225) throw new CryptographicException("Hash Function '"~to!string(func)~"' is not supported.");
	BCryptHash(phAlgorithm, cast(ubyte*)key.ptr, cast(uint)key.length, cast(ubyte*)data.ptr, cast(uint)data.length, output.ptr, getHashLength(func));
	scope(exit) {
		if (phAlgorithm != null) BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}

	return output;
}

@trusted public ubyte[] hkdf_winapi(const ubyte[] key, const ubyte[] salt, string info, size_t outputLen, HashAlgorithm func) {
	import std.algorithm.comparison;

	if(outputLen > 255 * getHashLength(func)) {
		throw new CryptographicException("Output length must " ~ to!string(255 * getHashLength(func)) ~" bytes or less.");
	}

	void* phAlgorithm = null;
	string algName = getWindowsHashAlgoName(func);

	long ret = BCryptOpenAlgorithmProvider(&phAlgorithm, algName.toWinApiWideChars(), MS_PRIMITIVE_PROVIDER.toWinApiWideChars(), BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (ret == 0xC0000225) throw new CryptographicException("Hash Function '"~to!string(func)~"' is not supported.");
	scope(exit) {
		if (phAlgorithm != null) BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}

	//Extract
	ubyte[] extract = new ubyte[getHashLength(func)];
	BCryptHash(phAlgorithm, cast(ubyte*)salt.ptr, cast(uint)salt.length, cast(ubyte*)key.ptr, cast(uint)key.length, extract.ptr, getHashLength(func));

	//Expand
	ubyte[] tinfo = cast(ubyte[])info.representation;
	int outputIndex = 0;
	ubyte count = 1;
	int bytesToCopy = 0;
	ubyte[] output;
	ubyte[] result;
	ubyte[] buffer;

	while(outputIndex < outputLen) {
		//Setup buffer to hash
		buffer = result ~ tinfo ~ count++;

		result = new ubyte[getHashLength(func)];
		BCryptHash(phAlgorithm, cast(ubyte*)extract.ptr, cast(uint)extract.length, cast(ubyte*)buffer.ptr, cast(uint)buffer.length, cast(ubyte*)result.ptr, cast(uint)result.length);

		//Copy as much of the hash as we need to the final output
		bytesToCopy = min(cast(int)(outputLen - outputIndex), cast(int)result.length);
		output ~= result[0..bytesToCopy];
		outputIndex += bytesToCopy;
	}

	return output;
}

@trusted public ubyte[] encrypt_aead_winapi(const ubyte[] data, const ubyte[] associatedData, const ubyte[] key, const ubyte[] iv, out ubyte[] authTag, SymmetricAlgorithm algorithm) {
	auto algName = BCRYPT_AES_ALGORITHM;
	if (algorithm == SymmetricAlgorithm.ChaCha20_Poly1305) algName = BCRYPT_CHACHA20_POLY1305_ALGORITHM;

	void* phAlgorithm = null;
	void* phKey = null;

	ubyte[] output = new ubyte[data.length];
	ubyte[] tag = new ubyte[12];
	//ubyte[] context = new ubyte[12];
	uint outputLen = 0;

	_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(
		_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.sizeof,
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
		cast(ubyte*)iv.ptr,
		cast(uint)iv.length,
		cast(ubyte*)associatedData.ptr,
		cast(uint)associatedData.length,
		tag.ptr,
		cast(uint)tag.length,
		null,//context.ptr,
		0,//context.length,
		0,0,0
	);

	long ret = BCryptOpenAlgorithmProvider(&phAlgorithm, algName.toWinApiWideChars(), MS_PRIMITIVE_PROVIDER.toWinApiWideChars(), 0);
	if (ret == 0xC0000225) throw new CryptographicException("Symmetric Algorithm '"~to!string(algorithm)~"' is not supported.");
	ret = BCryptSetProperty(phAlgorithm, BCRYPT_CHAINING_MODE.toWinApiWideChars(), cast(ubyte*)BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAIN_MODE_GCM.sizeof, 0);
	ret = BCryptGenerateSymmetricKey(phAlgorithm, &phKey, null, 0, cast(ubyte*)key.ptr, cast(uint)key.length, 0);
	ret = BCryptEncrypt(phKey, cast(ubyte*)data.ptr, cast(uint)data.length, cast(void*)&info, cast(ubyte*)iv.ptr, cast(uint)iv.length, output.ptr, cast(uint)output.length, &outputLen, 0);
	scope(exit) {
		if (phKey != null) BCryptDestroyKey(phKey);
		if (phAlgorithm != null) BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}

	authTag = tag;
	return output[0.. outputLen];
}

@trusted public ubyte[] decrypt_aead_winapi(const ubyte[] data, const ubyte[] associatedData, const ubyte[] key, const ubyte[] iv, const ubyte[] authTag, SymmetricAlgorithm algorithm) {
	auto algName = BCRYPT_AES_ALGORITHM;
	if (algorithm == SymmetricAlgorithm.ChaCha20_Poly1305) algName = BCRYPT_CHACHA20_POLY1305_ALGORITHM;

	void* phAlgorithm = null;
	void* phKey = null;

	ubyte[] output = new ubyte[data.length];
	ubyte[] tag = new ubyte[12];
	//ubyte[] context = new ubyte[12];
	uint outputLen = 0;

	_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(
		_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.sizeof,
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
		cast(ubyte*)iv.ptr,
		cast(uint)iv.length,
		cast(ubyte*)associatedData.ptr,
		cast(uint)associatedData.length,
		cast(ubyte*)tag.ptr,
		cast(uint)tag.length,
		null,//context.ptr,
		0,//context.length,
		0,0,0
	);

	long ret = BCryptOpenAlgorithmProvider(&phAlgorithm, algName.toWinApiWideChars(), MS_PRIMITIVE_PROVIDER.toWinApiWideChars(), 0);
	if (ret == 0xC0000225) throw new CryptographicException("Symmetric Algorithm '"~to!string(algorithm)~"' is not supported.");
	ret = BCryptSetProperty(phAlgorithm, BCRYPT_CHAINING_MODE.toWinApiWideChars(), cast(ubyte*)BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAIN_MODE_GCM.sizeof, 0);
	ret = BCryptGenerateSymmetricKey(phAlgorithm, &phKey, null, 0, cast(ubyte*)key.ptr, cast(uint)key.length, 0);
	ret = BCryptDecrypt(phKey, cast(ubyte*)data.ptr, cast(uint)data.length, cast(void*)&info, cast(ubyte*)iv.ptr, cast(uint)iv.length, output.ptr, cast(uint)output.length, &outputLen, 0);
	scope(exit) {
		if (phKey != null) BCryptDestroyKey(phKey);
		if (phAlgorithm != null) BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}

	return output[0.. outputLen];
}

private @safe string getWindowsHashAlgoName(HashAlgorithm func) {
	switch (func)
	{
		case HashAlgorithm.SHA2_256: return "SHA256";
		case HashAlgorithm.SHA2_384: return "SHA384";
		case HashAlgorithm.SHA2_512: return "SHA512";
		case HashAlgorithm.SHA3_256: return "SHA3-256";
		case HashAlgorithm.SHA3_384: return "SHA3-384";
		case HashAlgorithm.SHA3_512: return "SHA3-512";
		default:
			throw new CryptographicException("Hash Function '"~to!string(func)~"' is not supported.");
	}
}

pragma(inline) private @system const(ushort*) toWinApiWideChars(string str) {
	return toWinApiWideChars(to!wstring(str));
}

pragma(inline) private @system const(ushort*) toWinApiWideChars(wstring str) {
	return cast(const(ushort)*)str.toUTF16z();
}