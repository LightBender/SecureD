module secured.windows.bcrypt;
package:

// D import file generated from 'source\secured\windows\bcrypt.c'
extern (C)
{
	struct __BCRYPT_KEY_LENGTHS_STRUCT
	{
		uint dwMinLength = void;
		uint dwMaxLength = void;
		uint dwIncrement = void;
	}
//	struct __BCRYPT_KEY_LENGTHS_STRUCT;
	struct _BCRYPT_OID
	{
		uint cbOID = void;
		ubyte* pbOID = void;
	}
	struct _BCRYPT_OID_LIST
	{
		uint dwOIDCount = void;
		_BCRYPT_OID* pOIDs = void;
	}
	struct _BCRYPT_PKCS1_PADDING_INFO
	{
		const(ushort)* pszAlgId = void;
	}
	struct _BCRYPT_PSS_PADDING_INFO
	{
		const(ushort)* pszAlgId = void;
		uint cbSalt = void;
	}
	struct _BCRYPT_OAEP_PADDING_INFO
	{
		const(ushort)* pszAlgId = void;
		ubyte* pbLabel = void;
		uint cbLabel = void;
	}
	struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
	{
		uint cbSize = void;
		uint dwInfoVersion = void;
		ubyte* pbNonce = void;
		uint cbNonce = void;
		ubyte* pbAuthData = void;
		uint cbAuthData = void;
		ubyte* pbTag = void;
		uint cbTag = void;
		ubyte* pbMacContext = void;
		uint cbMacContext = void;
		uint cbAAD = void;
		ulong cbData = void;
		uint dwFlags = void;
	}
	struct _BCryptBuffer
	{
		uint cbBuffer = void;
		uint BufferType = void;
		void* pvBuffer = void;
	}
	struct _BCryptBufferDesc
	{
		uint ulVersion = void;
		uint cBuffers = void;
		_BCryptBuffer* pBuffers = void;
	}
	struct _BCRYPT_KEY_BLOB
	{
		uint Magic = void;
	}
	struct _BCRYPT_RSAKEY_BLOB
	{
		uint Magic = void;
		uint BitLength = void;
		uint cbPublicExp = void;
		uint cbModulus = void;
		uint cbPrime1 = void;
		uint cbPrime2 = void;
	}
	struct _BCRYPT_ECCKEY_BLOB
	{
		uint dwMagic = void;
		uint cbKey = void;
	}
	struct _SSL_ECCKEY_BLOB
	{
		uint dwCurveType = void;
		uint cbKey = void;
	}
	enum ECC_CURVE_TYPE_ENUM
	{
		BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE = 1,
		BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE = 2,
		BCRYPT_ECC_PRIME_MONTGOMERY_CURVE = 3,
	}
	alias BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE = ECC_CURVE_TYPE_ENUM.BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE;
	alias BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE = ECC_CURVE_TYPE_ENUM.BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE;
	alias BCRYPT_ECC_PRIME_MONTGOMERY_CURVE = ECC_CURVE_TYPE_ENUM.BCRYPT_ECC_PRIME_MONTGOMERY_CURVE;
	enum ECC_CURVE_ALG_ID_ENUM
	{
		BCRYPT_NO_CURVE_GENERATION_ALG_ID = 0,
	}
	alias BCRYPT_NO_CURVE_GENERATION_ALG_ID = ECC_CURVE_ALG_ID_ENUM.BCRYPT_NO_CURVE_GENERATION_ALG_ID;
	struct _BCRYPT_ECCFULLKEY_BLOB
	{
		uint dwMagic = void;
		uint dwVersion = void;
		ECC_CURVE_TYPE_ENUM dwCurveType = void;
		ECC_CURVE_ALG_ID_ENUM dwCurveGenerationAlgId = void;
		uint cbFieldLength = void;
		uint cbSubgroupOrder = void;
		uint cbCofactor = void;
		uint cbSeed = void;
	}
	struct _BCRYPT_DH_KEY_BLOB
	{
		uint dwMagic = void;
		uint cbKey = void;
	}
	struct _BCRYPT_DH_PARAMETER_HEADER
	{
		uint cbLength = void;
		uint dwMagic = void;
		uint cbKeyLength = void;
	}
	struct _BCRYPT_DSA_KEY_BLOB
	{
		uint dwMagic = void;
		uint cbKey = void;
		ubyte[4] Count = void;
		ubyte[20] Seed = void;
		ubyte[20] q = void;
	}
	enum HASHALGORITHM_ENUM
	{
		DSA_HASH_ALGORITHM_SHA1,
		DSA_HASH_ALGORITHM_SHA256,
		DSA_HASH_ALGORITHM_SHA512,
	}
	alias DSA_HASH_ALGORITHM_SHA1 = HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA1;
	alias DSA_HASH_ALGORITHM_SHA256 = HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA256;
	alias DSA_HASH_ALGORITHM_SHA512 = HASHALGORITHM_ENUM.DSA_HASH_ALGORITHM_SHA512;
	enum DSAFIPSVERSION_ENUM
	{
		DSA_FIPS186_2,
		DSA_FIPS186_3,
	}
	alias DSA_FIPS186_2 = DSAFIPSVERSION_ENUM.DSA_FIPS186_2;
	alias DSA_FIPS186_3 = DSAFIPSVERSION_ENUM.DSA_FIPS186_3;
	struct _BCRYPT_DSA_KEY_BLOB_V2
	{
		uint dwMagic = void;
		uint cbKey = void;
		HASHALGORITHM_ENUM hashAlgorithm = void;
		DSAFIPSVERSION_ENUM standardVersion = void;
		uint cbSeedLength = void;
		uint cbGroupSize = void;
		ubyte[4] Count = void;
	}
	struct _BCRYPT_KEY_DATA_BLOB_HEADER
	{
		uint dwMagic = void;
		uint dwVersion = void;
		uint cbKeyData = void;
	}
	struct _BCRYPT_DSA_PARAMETER_HEADER
	{
		uint cbLength = void;
		uint dwMagic = void;
		uint cbKeyLength = void;
		ubyte[4] Count = void;
		ubyte[20] Seed = void;
		ubyte[20] q = void;
	}
	struct _BCRYPT_DSA_PARAMETER_HEADER_V2
	{
		uint cbLength = void;
		uint dwMagic = void;
		uint cbKeyLength = void;
		HASHALGORITHM_ENUM hashAlgorithm = void;
		DSAFIPSVERSION_ENUM standardVersion = void;
		uint cbSeedLength = void;
		uint cbGroupSize = void;
		ubyte[4] Count = void;
	}
	struct _BCRYPT_ECC_CURVE_NAMES
	{
		uint dwEccCurveNames = void;
		ushort** pEccCurveNames = void;
	}
	enum BCRYPT_HASH_OPERATION_TYPE
	{
		BCRYPT_HASH_OPERATION_HASH_DATA = 1,
		BCRYPT_HASH_OPERATION_FINISH_HASH = 2,
	}
	alias BCRYPT_HASH_OPERATION_HASH_DATA = BCRYPT_HASH_OPERATION_TYPE.BCRYPT_HASH_OPERATION_HASH_DATA;
	alias BCRYPT_HASH_OPERATION_FINISH_HASH = BCRYPT_HASH_OPERATION_TYPE.BCRYPT_HASH_OPERATION_FINISH_HASH;
	struct _BCRYPT_MULTI_HASH_OPERATION
	{
		uint iHash = void;
		BCRYPT_HASH_OPERATION_TYPE hashOperation = void;
		ubyte* pbBuffer = void;
		uint cbBuffer = void;
	}
	enum BCRYPT_MULTI_OPERATION_TYPE
	{
		BCRYPT_OPERATION_TYPE_HASH = 1,
	}
	alias BCRYPT_OPERATION_TYPE_HASH = BCRYPT_MULTI_OPERATION_TYPE.BCRYPT_OPERATION_TYPE_HASH;
	struct _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT
	{
		uint cbPerObject = void;
		uint cbPerElement = void;
	}
	long BCryptOpenAlgorithmProvider(void** phAlgorithm, const(ushort)* pszAlgId, const(ushort)* pszImplementation, uint dwFlags);
	struct _BCRYPT_ALGORITHM_IDENTIFIER
	{
		ushort* pszName = void;
		uint dwClass = void;
		uint dwFlags = void;
	}
	long BCryptEnumAlgorithms(uint dwAlgOperations, uint* pAlgCount, _BCRYPT_ALGORITHM_IDENTIFIER** ppAlgList, uint dwFlags);
	struct _BCRYPT_PROVIDER_NAME
	{
		ushort* pszProviderName = void;
	}
	long BCryptEnumProviders(const(ushort)* pszAlgId, uint* pImplCount, _BCRYPT_PROVIDER_NAME** ppImplList, uint dwFlags);
	long BCryptGetProperty(void* hObject, const(ushort)* pszProperty, ubyte* pbOutput, uint cbOutput, uint* pcbResult, uint dwFlags);
	long BCryptSetProperty(void* hObject, const(ushort)* pszProperty, ubyte* pbInput, uint cbInput, uint dwFlags);
	long BCryptCloseAlgorithmProvider(void* hAlgorithm, uint dwFlags);
	void BCryptFreeBuffer(void* pvBuffer);
	long BCryptGenerateSymmetricKey(void* hAlgorithm, void** phKey, ubyte* pbKeyObject, uint cbKeyObject, ubyte* pbSecret, uint cbSecret, uint dwFlags);
	long BCryptGenerateKeyPair(void* hAlgorithm, void** phKey, uint dwLength, uint dwFlags);
	long BCryptEncrypt(void* hKey, ubyte* pbInput, uint cbInput, void* pPaddingInfo, ubyte* pbIV, uint cbIV, ubyte* pbOutput, uint cbOutput, uint* pcbResult, uint dwFlags);
	long BCryptDecrypt(void* hKey, ubyte* pbInput, uint cbInput, void* pPaddingInfo, ubyte* pbIV, uint cbIV, ubyte* pbOutput, uint cbOutput, uint* pcbResult, uint dwFlags);
	long BCryptExportKey(void* hKey, void* hExportKey, const(ushort)* pszBlobType, ubyte* pbOutput, uint cbOutput, uint* pcbResult, uint dwFlags);
	long BCryptImportKey(void* hAlgorithm, void* hImportKey, const(ushort)* pszBlobType, void** phKey, ubyte* pbKeyObject, uint cbKeyObject, ubyte* pbInput, uint cbInput, uint dwFlags);
	long BCryptImportKeyPair(void* hAlgorithm, void* hImportKey, const(ushort)* pszBlobType, void** phKey, ubyte* pbInput, uint cbInput, uint dwFlags);
	long BCryptDuplicateKey(void* hKey, void** phNewKey, ubyte* pbKeyObject, uint cbKeyObject, uint dwFlags);
	long BCryptFinalizeKeyPair(void* hKey, uint dwFlags);
	long BCryptDestroyKey(void* hKey);
	long BCryptDestroySecret(void* hSecret);
	long BCryptSignHash(void* hKey, void* pPaddingInfo, ubyte* pbInput, uint cbInput, ubyte* pbOutput, uint cbOutput, uint* pcbResult, uint dwFlags);
	long BCryptVerifySignature(void* hKey, void* pPaddingInfo, ubyte* pbHash, uint cbHash, ubyte* pbSignature, uint cbSignature, uint dwFlags);
	long BCryptSecretAgreement(void* hPrivKey, void* hPubKey, void** phAgreedSecret, uint dwFlags);
	long BCryptDeriveKey(void* hSharedSecret, const(ushort)* pwszKDF, _BCryptBufferDesc* pParameterList, ubyte* pbDerivedKey, uint cbDerivedKey, uint* pcbResult, uint dwFlags);
	long BCryptKeyDerivation(void* hKey, _BCryptBufferDesc* pParameterList, ubyte* pbDerivedKey, uint cbDerivedKey, uint* pcbResult, uint dwFlags);
	long BCryptCreateHash(void* hAlgorithm, void** phHash, ubyte* pbHashObject, uint cbHashObject, ubyte* pbSecret, uint cbSecret, uint dwFlags);
	long BCryptHashData(void* hHash, ubyte* pbInput, uint cbInput, uint dwFlags);
	long BCryptFinishHash(void* hHash, ubyte* pbOutput, uint cbOutput, uint dwFlags);
	long BCryptDuplicateHash(void* hHash, void** phNewHash, ubyte* pbHashObject, uint cbHashObject, uint dwFlags);
	long BCryptDestroyHash(void* hHash);
	long BCryptHash(void* hAlgorithm, ubyte* pbSecret, uint cbSecret, ubyte* pbInput, uint cbInput, ubyte* pbOutput, uint cbOutput);
	long BCryptGenRandom(void* hAlgorithm, ubyte* pbBuffer, uint cbBuffer, uint dwFlags);
	long BCryptDeriveKeyCapi(void* hHash, void* hTargetAlg, ubyte* pbDerivedKey, uint cbDerivedKey, uint dwFlags);
	long BCryptDeriveKeyPBKDF2(void* hPrf, ubyte* pbPassword, uint cbPassword, ubyte* pbSalt, uint cbSalt, ulong cIterations, ubyte* pbDerivedKey, uint cbDerivedKey, uint dwFlags);
	struct _BCRYPT_INTERFACE_VERSION
	{
		ushort MajorVersion = void;
		ushort MinorVersion = void;
	}
	struct _CRYPT_INTERFACE_REG
	{
		uint dwInterface = void;
		uint dwFlags = void;
		uint cFunctions = void;
		ushort** rgpszFunctions = void;
	}
	struct _CRYPT_IMAGE_REG
	{
		ushort* pszImage = void;
		uint cInterfaces = void;
		_CRYPT_INTERFACE_REG** rgpInterfaces = void;
	}
	struct _CRYPT_PROVIDER_REG
	{
		uint cAliases = void;
		ushort** rgpszAliases = void;
		_CRYPT_IMAGE_REG* pUM = void;
		_CRYPT_IMAGE_REG* pKM = void;
	}
	struct _CRYPT_PROVIDERS
	{
		uint cProviders = void;
		ushort** rgpszProviders = void;
	}
	struct _CRYPT_CONTEXT_CONFIG
	{
		uint dwFlags = void;
		uint dwReserved = void;
	}
	struct _CRYPT_CONTEXT_FUNCTION_CONFIG
	{
		uint dwFlags = void;
		uint dwReserved = void;
	}
	struct _CRYPT_CONTEXTS
	{
		uint cContexts = void;
		ushort** rgpszContexts = void;
	}
	struct _CRYPT_CONTEXT_FUNCTIONS
	{
		uint cFunctions = void;
		ushort** rgpszFunctions = void;
	}
	struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS
	{
		uint cProviders = void;
		ushort** rgpszProviders = void;
	}
	struct _CRYPT_PROPERTY_REF
	{
		ushort* pszProperty = void;
		uint cbValue = void;
		ubyte* pbValue = void;
	}
	struct _CRYPT_IMAGE_REF
	{
		ushort* pszImage = void;
		uint dwFlags = void;
	}
	struct _CRYPT_PROVIDER_REF
	{
		uint dwInterface = void;
		ushort* pszFunction = void;
		ushort* pszProvider = void;
		uint cProperties = void;
		_CRYPT_PROPERTY_REF** rgpProperties = void;
		_CRYPT_IMAGE_REF* pUM = void;
		_CRYPT_IMAGE_REF* pKM = void;
	}
	struct _CRYPT_PROVIDER_REFS
	{
		uint cProviders = void;
		_CRYPT_PROVIDER_REF** rgpProviders = void;
	}
	long BCryptQueryProviderRegistration(const(ushort)* pszProvider, uint dwMode, uint dwInterface, uint* pcbBuffer, _CRYPT_PROVIDER_REG** ppBuffer);
	long BCryptEnumRegisteredProviders(uint* pcbBuffer, _CRYPT_PROVIDERS** ppBuffer);
	long BCryptCreateContext(uint dwTable, const(ushort)* pszContext, _CRYPT_CONTEXT_CONFIG* pConfig);
	long BCryptDeleteContext(uint dwTable, const(ushort)* pszContext);
	long BCryptEnumContexts(uint dwTable, uint* pcbBuffer, _CRYPT_CONTEXTS** ppBuffer);
	long BCryptConfigureContext(uint dwTable, const(ushort)* pszContext, _CRYPT_CONTEXT_CONFIG* pConfig);
	long BCryptQueryContextConfiguration(uint dwTable, const(ushort)* pszContext, uint* pcbBuffer, _CRYPT_CONTEXT_CONFIG** ppBuffer);
	long BCryptAddContextFunction(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, uint dwPosition);
	long BCryptRemoveContextFunction(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction);
	long BCryptEnumContextFunctions(uint dwTable, const(ushort)* pszContext, uint dwInterface, uint* pcbBuffer, _CRYPT_CONTEXT_FUNCTIONS** ppBuffer);
	long BCryptConfigureContextFunction(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, _CRYPT_CONTEXT_FUNCTION_CONFIG* pConfig);
	long BCryptQueryContextFunctionConfiguration(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, uint* pcbBuffer, _CRYPT_CONTEXT_FUNCTION_CONFIG** ppBuffer);
	long BCryptEnumContextFunctionProviders(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, uint* pcbBuffer, _CRYPT_CONTEXT_FUNCTION_PROVIDERS** ppBuffer);
	long BCryptSetContextFunctionProperty(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, const(ushort)* pszProperty, uint cbValue, ubyte* pbValue);
	long BCryptQueryContextFunctionProperty(uint dwTable, const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, const(ushort)* pszProperty, uint* pcbValue, ubyte** ppbValue);
	long BCryptRegisterConfigChangeNotify(void** phEvent);
	long BCryptUnregisterConfigChangeNotify(void* hEvent);
	long BCryptResolveProviders(const(ushort)* pszContext, uint dwInterface, const(ushort)* pszFunction, const(ushort)* pszProvider, uint dwMode, uint dwFlags, uint* pcbBuffer, _CRYPT_PROVIDER_REFS** ppBuffer);
	long BCryptGetFipsAlgorithmMode(int* pfEnabled);
	int CngGetFipsAlgorithmMode();
	enum BCRYPT_DH_PRIVATE_BLOB = "DHPRIVATEBLOB"w;
	enum BCRYPT_RC2_ALGORITHM = "RC2"w;
	enum BCRYPT_ECC_CURVE_EC192WAPI = "ec192wapi"w;
	enum int BCRYPT_DSA_PRIVATE_MAGIC = 1448104772;
	enum int __IMPORTC__ = 1;
	enum int KDF_HKDF_INFO = 20;
	enum LEGACY_RSAPRIVATE_BLOB = "CAPIPRIVATEBLOB"w;
	enum int BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 844317509;
	enum int BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 877871941;
	enum int BCRYPT_KEY_VALIDATION_RANGE = 16;
	enum BCRYPT_3DES_ALGORITHM = "3DES"w;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP256T1 = "brainpoolP256t1"w;
	enum int BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG = 2;
	enum MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider"w;
	enum BCRYPT_HASH_BLOCK_LENGTH = "HashBlockLength"w;
	enum BCRYPT_TLS1_1_KDF_ALGORITHM = "TLS1_1_KDF"w;
	enum int KDF_ITERATION_COUNT = 16;
	enum int BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 861094725;
	enum int BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 1;
	enum BCRYPT_ECC_CURVE_SECP521R1 = "secP521r1"w;
	enum int BCRYPT_SUPPORTED_PAD_ROUTER = 1;
	enum LEGACY_DSA_PUBLIC_BLOB = "CAPIDSAPUBLICBLOB"w;
	enum int _M_X64 = 100;
	enum int BCRYPT_ECC_FULLKEY_BLOB_V1 = 1;
	enum LEGACY_DSA_V2_PUBLIC_BLOB = "V2CAPIDSAPUBLICBLOB"w;
	enum BCRYPT_GLOBAL_PARAMETERS = "SecretAgreementParam"w;
	enum int _MSC_EXTENSIONS = 1;
	enum int BCRYPT_EXTENDED_KEYSIZE = 128;
	enum int BCRYPT_ALG_HANDLE_HMAC_FLAG = 8;
	enum int BCRYPT_KEY_VALIDATION_REGENERATE = 32;
	enum BCRYPT_ECC_CURVE_SECP384R1 = "secP384r1"w;
	enum int _USE_ATTRIBUTES_FOR_SAL = 0;
	enum int BCRYPT_PRIVATE_KEY_FLAG = 2;
	enum int BCRYPT_DH_PUBLIC_MAGIC = 1112557636;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP192T1 = "brainpoolP192t1"w;
	enum CRYPT_DEFAULT_CONTEXT = "Default"w;
	enum int BCRYPT_KEY_DERIVATION_INTERFACE = 7;
	enum int BCRYPT_RNG_USE_ENTROPY_IN_BUFFER = 1;
	enum BCRYPT_DSA_ALGORITHM = "DSA"w;
	enum BCRYPT_ECDH_P256_ALGORITHM = "ECDH_P256"w;
	enum BCRYPT_KEY_DATA_BLOB = "KeyDataBlob"w;
	enum int WINAPI_FAMILY_GAMES = 6;
	enum BCRYPT_ECC_CURVE_NISTP192 = "nistP192"w;
	enum BCRYPT_PROVIDER_HANDLE = "ProviderHandle"w;
	enum BCRYPT_PADDING_SCHEMES = "PaddingSchemes"w;
	enum BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB"w;
	enum int _MSC_BUILD = 0;
	enum BCRYPT_KEY_LENGTHS = "KeyLengths"w;
	enum int KDF_TLS_PRF_LABEL = 4;
	enum int BCRYPT_PUBLIC_KEY_FLAG = 1;
	enum LEGACY_DSA_PRIVATE_BLOB = "CAPIDSAPRIVATEBLOB"w;
	enum int BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE = 3;
	enum int KDF_SUPPPUBINFO = 11;
	enum BCRYPT_ECC_CURVE_NISTP384 = "nistP384"w;
	enum BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB"w;
	enum int BCRYPT_GENERATE_IV = 32;
	enum BCRYPT_SP80056A_CONCAT_ALGORITHM = "SP800_56A_CONCAT"w;
	enum int BCRYPT_PAD_PKCS1 = 2;
	enum BCRYPT_PCP_PROVIDER_VERSION_PROPERTY = "PCP_PROVIDER_VERSION"w;
	enum int BCRYPT_ECC_PARAMETERS_MAGIC = 1346585413;
	enum BCRYPT_CHAIN_MODE_NA = "ChainingModeN/A"w;
	enum int KDF_PARTYUINFO = 9;
	enum BCRYPT_ECC_CURVE_NUMSP256T1 = "numsP256t1"w;
	enum BCRYPT_SHA384_ALGORITHM = "SHA384"w;
	enum int BCRYPT_SUPPORTED_PAD_OAEP = 8;
	enum BCRYPT_ECDH_P384_ALGORITHM = "ECDH_P384"w;
	enum BCRYPT_SHA256_ALGORITHM = "SHA256"w;
	enum BCRYPT_AES_CMAC_ALGORITHM = "AES-CMAC"w;
	enum BCRYPT_KEY_STRENGTH = "KeyStrength"w;
	enum int KDF_PARTYVINFO = 10;
	enum int BCRYPT_SIGNATURE_OPERATION = 16;
	enum int BCRYPTBUFFER_VERSION = 0;
	enum BCRYPT_EFFECTIVE_KEY_LENGTH = "EffectiveKeyLength"w;
	enum BCRYPT_KDF_RAW_SECRET = "TRUNCATE"w;
	enum BCRYPT_PBKDF2_ALGORITHM = "PBKDF2"w;
	enum BCRYPT_ECC_CURVE_X962P239V1 = "x962P239v1"w;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP512R1 = "brainpoolP512r1"w;
	enum BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC"w;
	enum int BCRYPT_HASH_INTERFACE = 2;
	enum BCRYPT_RNG_DUAL_EC_ALGORITHM = "DUALECRNG"w;
	enum int _WIN64 = 1;
	enum BCRYPT_CHAIN_MODE_CCM = "ChainingModeCCM"w;
	enum int BCRYPT_SUPPORTED_PAD_PKCS1_ENC = 2;
	enum BCRYPT_ECC_CURVE_SECP192R1 = "secP192r1"w;
	enum BCRYPT_RSA_ALGORITHM = "RSA"w;
	enum int BCRYPT_SUPPORTED_PAD_PKCS1_SIG = 4;
	enum BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"w;
	enum BCRYPT_ECCFULLPRIVATE_BLOB = "ECCFULLPRIVATEBLOB"w;
	enum BCRYPT_CHAINING_MODE = "ChainingMode"w;
	enum int BCRYPT_CAPI_AES_FLAG = 16;
	enum BCRYPT_ECDSA_P521_ALGORITHM = "ECDSA_P521"w;
	enum int _IS_ASSIGNABLE_NOCHECK_SUPPORTED = 1;
	enum BCRYPT_MD4_ALGORITHM = "MD4"w;
	enum int _CRT_SECURE_NO_WARNINGS = 1;
	enum int BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = 1347109701;
	enum BCRYPT_TLS1_2_KDF_ALGORITHM = "TLS1_2_KDF"w;
	enum BCRYPT_SHA1_ALGORITHM = "SHA1"w;
	enum BCRYPT_ECC_CURVE_X962P239V3 = "x962P239v3"w;
	enum int BCRYPT_CIPHER_INTERFACE = 1;
	enum int BCRYPT_DSA_PRIVATE_MAGIC_V2 = 844517444;
	enum BCRYPT_DH_PARAMETERS = "DHParameters"w;
	enum int KDF_SECRET_HANDLE = 6;
	enum int BCRYPT_CIPHER_OPERATION = 1;
	enum int BCRYPT_ECDH_PUBLIC_P521_MAGIC = 894124869;
	enum BCRYPT_RSA_SIGN_ALGORITHM = "RSA_SIGN"w;
	enum BCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256"w;
	enum BCRYPT_SP800108_CTR_HMAC_ALGORITHM = "SP800_108_CTR_HMAC"w;
	enum BCRYPT_OPAQUE_KEY_BLOB = "OpaqueKeyBlob"w;
	enum int __STDC_NO_VLA__ = 1;
	enum int BCRYPT_SECRET_AGREEMENT_OPERATION = 8;
	enum int BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 911426373;
	enum BCRYPT_ECC_CURVE_X962P192V2 = "x962P192v2"w;
	enum BCRYPT_DH_PUBLIC_BLOB = "DHPUBLICBLOB"w;
	enum BCRYPT_ECC_CURVE_25519 = "curve25519"w;
	enum BCRYPT_RC4_ALGORITHM = "RC4"w;
	enum BCRYPT_ECC_CURVE_WTLS12 = "wtls12"w;
	enum int _CRT_NONSTDC_NO_DEPRECATE = 1;
	enum BCRYPT_AES_ALGORITHM = "AES"w;
	enum int _M_AMD64 = 100;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP192R1 = "brainpoolP192r1"w;
	enum int __SAL_H_VERSION = 180000000;
	enum BCRYPT_ECDSA_P384_ALGORITHM = "ECDSA_P384"w;
	enum int _USE_DECLSPECS_FOR_SAL = 0;
	enum BCRYPT_ECC_CURVE_NISTP224 = "nistP224"w;
	enum BCRYPT_AES_WRAP_KEY_BLOB = "Rfc3565KeyWrapBlob"w;
	enum BCRYPT_BLOCK_LENGTH = "BlockLength"w;
	enum BCRYPT_ALGORITHM_NAME = "AlgorithmName"w;
	enum BCRYPT_CHACHA20_POLY1305_ALGORITHM = "CHACHA20_POLY1305"w;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP384T1 = "brainpoolP384t1"w;
	enum BCRYPT_AES_GMAC_ALGORITHM = "AES-GMAC"w;
	enum int KDF_SECRET_APPEND = 2;
	enum BCRYPT_ECC_PARAMETERS = "ECCParameters"w;
	enum int BCRYPT_RSAPUBLIC_MAGIC = 826364754;
	enum BCRYPT_IS_KEYED_HASH = "IsKeyedHash"w;
	enum int BCRYPT_RSAFULLPRIVATE_MAGIC = 859919186;
	enum int WINAPI_FAMILY_PHONE_APP = 3;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP384R1 = "brainpoolP384r1"w;
	enum BCRYPT_SIGNATURE_LENGTH = "SignatureLength"w;
	enum int BCRYPT_KEY_DATA_BLOB_VERSION1 = 1;
	enum int BCRYPT_RSAPRIVATE_MAGIC = 843141970;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP224T1 = "brainpoolP224t1"w;
	enum BCRYPT_SHA512_ALGORITHM = "SHA512"w;
	enum BCRYPT_PRIVATE_KEY_BLOB = "PRIVATEBLOB"w;
	enum BCRYPT_PUBLIC_KEY_BLOB = "PUBLICBLOB"w;
	enum int BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG = 4;
	enum int BCRYPT_KEY_VALIDATION_RANGE_AND_ORDER = 24;
	enum BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB"w;
	enum int BCRYPT_SUPPORTED_PAD_PSS = 16;
	enum int BCRYPT_DSA_PUBLIC_MAGIC_V2 = 843206724;
	enum LEGACY_DH_PRIVATE_BLOB = "CAPIDHPRIVATEBLOB"w;
	enum BCRYPT_XTS_AES_ALGORITHM = "XTS-AES"w;
	enum int KDF_SECRET_PREPEND = 1;
	enum BCRYPT_KDF_SP80056A_CONCAT = "SP800_56A_CONCAT"w;
	enum int BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC = 1447314245;
	enum int BCRYPT_PAD_PSS = 8;
	enum int KDF_HMAC_KEY = 3;
	enum BCRYPT_KEY_LENGTH = "KeyLength"w;
	enum int BCRYPT_KEY_DATA_BLOB_MAGIC = 1296188491;
	enum BCRYPT_ECDH_P521_ALGORITHM = "ECDH_P521"w;
	enum int _NO_CRT_STDIO_INLINE = 1;
	enum BCRYPT_DH_ALGORITHM = "DH"w;
	enum BCRYPT_KDF_HKDF = "HKDF"w;
	enum BCRYPT_MESSAGE_BLOCK_LENGTH = "MessageBlockLength"w;
	enum BCRYPT_ECC_CURVE_NUMSP384T1 = "numsP384t1"w;
	enum int BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC = 1346650949;
	enum BCRYPT_ECC_CURVE_WTLS9 = "wtls9"w;
	enum BCRYPT_DESX_ALGORITHM = "DESX"w;
	enum int _MT = 1;
	enum BCRYPT_HKDF_SALT_AND_FINALIZE = "HkdfSaltAndFinalize"w;
	enum int BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2;
	enum int BCRYPT_HASH_REUSABLE_FLAG = 32;
	enum int BCRYPT_SIGNATURE_INTERFACE = 5;
	enum BCRYPT_HKDF_PRK_AND_FINALIZE = "HkdfPrkAndFinalize"w;
	enum int KDF_ALGORITHMID = 8;
	enum BCRYPT_PUBLIC_KEY_LENGTH = "PublicKeyLength"w;
	enum BCRYPT_RNG_ALGORITHM = "RNG"w;
	enum int _MSVC_WARNING_LEVEL = 1;
	enum BCRYPT_ECC_CURVE_WTLS7 = "wtls7"w;
	enum BCRYPT_ECC_CURVE_X962P192V3 = "x962P192v3"w;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP160T1 = "brainpoolP160t1"w;
	enum int KDF_GENERIC_PARAMETER = 17;
	enum LEGACY_DSA_V2_PRIVATE_BLOB = "V2CAPIDSAPRIVATEBLOB"w;
	enum BCRYPT_ECC_CURVE_NAME = "ECCCurveName"w;
	enum MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"w;
	enum BCRYPT_ECC_CURVE_NAME_LIST = "ECCCurveNameList"w;
	enum BCRYPT_ECC_CURVE_X962P239V2 = "x962P239v2"w;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP256R1 = "brainpoolP256r1"w;
	enum BCRYPT_ECC_CURVE_SECP192K1 = "secP192k1"w;
	enum BCRYPT_DSA_PARAMETERS = "DSAParameters"w;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP512T1 = "brainpoolP512t1"w;
	enum BCRYPT_DES_ALGORITHM = "DES"w;
	enum BCRYPT_MD5_ALGORITHM = "MD5"w;
	enum BCRYPT_HKDF_ALGORITHM = "HKDF"w;
	enum BCRYPT_3DES_112_ALGORITHM = "3DES_112"w;
	enum BCRYPT_IS_REUSABLE_HASH = "IsReusableHash"w;
	enum BCRYPT_ECC_CURVE_SECP256K1 = "secP256k1"w;
	enum int KDF_KEYBITLENGTH = 18;
	enum int __STDC_HOSTED__ = 1;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP320R1 = "brainpoolP320r1"w;
	enum int BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 827540293;
	enum int BCRYPT_KEY_DERIVATION_OPERATION = 64;
	enum BCRYPT_KDF_HASH = "HASH"w;
	enum int BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 4;
	enum int WINAPI_FAMILY_SERVER = 5;
	enum BCRYPT_ECC_CURVE_SECP160K1 = "secP160k1"w;
	enum int BCRYPT_PAD_PKCS1_OPTIONAL_HASH_OID = 16;
	enum int BCRYPT_BLOCK_PADDING = 1;
	enum int BCRYPT_BUFFERS_LOCKED_FLAG = 64;
	enum int WINAPI_FAMILY_SYSTEM = 4;
	enum int BCRYPT_SECRET_AGREEMENT_INTERFACE = 4;
	enum BCRYPT_BLOCK_SIZE_LIST = "BlockSizeList"w;
	enum BCRYPT_DSA_PUBLIC_BLOB = "DSAPUBLICBLOB"w;
	enum int KDF_TLS_PRF_PROTOCOL = 7;
	enum int BCRYPT_DH_PRIVATE_MAGIC = 1448101956;
	enum BCRYPT_ECC_CURVE_NISTP521 = "nistP521"w;
	enum int KDF_CONTEXT = 14;
	enum BCRYPT_ECDH_ALGORITHM = "ECDH"w;
	enum int BCRYPT_ENABLE_INCOMPATIBLE_FIPS_CHECKS = 256;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP160R1 = "brainpoolP160r1"w;
	enum int BCRYPT_ECDH_PRIVATE_P256_MAGIC = 843793221;
	enum LEGACY_RSAPUBLIC_BLOB = "CAPIPUBLICBLOB"w;
	enum BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB"w;
	enum BCRYPT_ECC_CURVE_SECP256R1 = "secP256r1"w;
	enum int WINAPI_FAMILY_PC_APP = 2;
	enum BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB"w;
	enum int BCRYPT_ECDH_PUBLIC_P256_MAGIC = 827016005;
	enum BCRYPT_KEY_OBJECT_LENGTH = "KeyObjectLength"w;
	enum LEGACY_DH_PUBLIC_BLOB = "CAPIDHPUBLICBLOB"w;
	enum BCRYPT_ECCFULLPUBLIC_BLOB = "ECCFULLPUBLICBLOB"w;
	enum int BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 894649157;
	enum BCRYPT_ECC_CURVE_SECP224R1 = "secP224r1"w;
	enum int BCRYPT_ECDH_PUBLIC_P384_MAGIC = 860570437;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP224R1 = "brainpoolP224r1"w;
	enum BCRYPT_PCP_PLATFORM_TYPE_PROPERTY = "PCP_PLATFORM_TYPE"w;
	enum int _MSC_FULL_VER = 193833133;
	enum BCRYPT_ECC_CURVE_NISTP256 = "nistP256"w;
	enum BCRYPT_ECC_CURVE_SECP160R1 = "secP160r1"w;
	enum int BCRYPT_ECDH_PRIVATE_P521_MAGIC = 910902085;
	enum int _MSC_VER = 1938;
	enum int _MSVC_TRADITIONAL = 0;
	enum BCRYPT_ECC_CURVE_SECP224K1 = "secP224k1"w;
	enum BCRYPT_IS_IFX_TPM_WEAK_KEY = "IsIfxTpmWeakKey"w;
	enum BCRYPT_DSA_PRIVATE_BLOB = "DSAPRIVATEBLOB"w;
	enum BCRYPT_ECC_CURVE_SECP160R2 = "secP160r2"w;
	enum BCRYPT_MD2_ALGORITHM = "MD2"w;
	enum BCRYPT_OBJECT_LENGTH = "ObjectLength"w;
	enum BCRYPT_HASH_LENGTH = "HashDigestLength"w;
	enum BCRYPT_ECDSA_ALGORITHM = "ECDSA"w;
	enum BCRYPT_KDF_TLS_PRF = "TLS_PRF"w;
	enum BCRYPT_RSAPRIVATE_BLOB = "RSAPRIVATEBLOB"w;
	enum int BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = 1447772997;
	enum int BCRYPT_RNG_INTERFACE = 6;
	enum BCRYPT_HASH_OID_LIST = "HashOIDList"w;
	enum int KDF_LABEL = 13;
	enum BCRYPT_CAPI_KDF_ALGORITHM = "CAPI_KDF"w;
	enum int BCRYPT_HASH_OPERATION = 2;
	enum BCRYPT_RNG_FIPS186_DSA_ALGORITHM = "FIPS186DSARNG"w;
	enum int BCRYPT_NO_KEY_VALIDATION = 8;
	enum int BCRYPT_RNG_OPERATION = 32;
	enum BCRYPT_ECC_CURVE_BRAINPOOLP320T1 = "brainpoolP320t1"w;
	enum int BCRYPT_DSA_PARAMETERS_MAGIC_V2 = 843927620;
	enum int WINAPI_FAMILY_DESKTOP_APP = 100;
	enum SSL_ECCPUBLIC_BLOB = "SSLECCPUBLICBLOB"w;
	enum BCRYPT_PRIVATE_KEY = "PrivKeyVal"w;
	enum int KDF_TLS_PRF_SEED = 5;
	enum int BCRYPT_ECDH_PRIVATE_P384_MAGIC = 877347653;
	enum int BCRYPT_DSA_PARAMETERS_MAGIC = 1297109828;
	enum int BCRYPT_PROV_DISPATCH = 1;
	enum BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB"w;
	enum BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength"w;
	enum int KDF_USE_SECRET_AS_HMAC_KEY_FLAG = 1;
	enum int KDF_SALT = 15;
	enum int KDF_HKDF_SALT = 19;
	enum int BCRYPT_OBJECT_ALIGNMENT = 16;
	enum BCRYPT_KDF_HMAC = "HMAC"w;
	enum int _MSVC_EXECUTION_CHARACTER_SET = 1252;
	enum int BCRYPT_PAD_OAEP = 4;
	enum int BCRYPT_DSA_PUBLIC_MAGIC = 1112560452;
	enum int BCRYPT_PAD_NONE = 1;
	enum int _SAL_VERSION = 20;
	enum int _INTEGRAL_MAX_BITS = 64;
	enum int KDF_HASH_ALGORITHM = 0;
	enum BCRYPT_INITIALIZATION_VECTOR = "IV"w;
	enum int KDF_SUPPPRIVINFO = 12;
	enum int BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;
	enum int BCRYPT_DH_PARAMETERS_MAGIC = 1297107012;
	enum int _WIN32 = 1;
	enum BCRYPT_ECC_CURVE_X962P256V1 = "x962P256v1"w;
	enum BCRYPT_ECC_CURVE_NUMSP512T1 = "numsP512t1"w;
	enum BCRYPT_ECC_CURVE_X962P192V1 = "x962P192v1"w;
	enum BCRYPT_HKDF_HASH_ALGORITHM = "HkdfHashAlgorithm"w;
	enum BCRYPT_PRIMITIVE_TYPE = "PrimitiveType"w;
}
