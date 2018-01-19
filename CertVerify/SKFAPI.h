
#ifndef _SKFAPI_H_
#define _SKFAPI_H_

#include <windows.h>

#pragma pack(1)

//返回值定义
#define SAR_OK							0x00000000
#define SAR_FAIL						0x0A000001
#define SAR_UNKNOWNERR					0x0A000002
#define SAR_NOTSUPPORTYETERR			0x0A000003
#define SAR_FILEERR						0x0A000004
#define SAR_INVALIDHANDLEERR			0x0A000005
#define SAR_INVALIDPARAMERR				0x0A000006
#define SAR_READFILEERR					0x0A000007
#define SAR_WRITEFILEERR				0x0A000008
#define SAR_NAMELENERR					0x0A000009
#define SAR_KEYUSAGEERR					0x0A00000A
#define SAR_MODULUSLENERR				0x0A00000B
#define SAR_NOTINITIALIZEERR			0x0A00000C
#define SAR_OBJERR						0x0A00000D
#define SAR_MEMORYERR					0x0A00000E
#define SAR_TIMEOUTERR					0x0A00000F
#define SAR_INDATALENERR				0x0A000010
#define SAR_INDATAERR					0x0A000011
#define SAR_GENRANDERR					0x0A000012
#define SAR_HASHOBJERR					0x0A000013
#define SAR_HASHERR						0x0A000014
#define SAR_GENRSAKEYERR				0x0A000015
#define SAR_RSAMODULUSLENERR			0x0A000016
#define SAR_CSPIMPRTPUBKEYERR			0x0A000017
#define SAR_RSAENCERR					0x0A000018
#define SAR_RSADECERR					0x0A000019
#define SAR_HASHNOTEQUALERR				0x0A00001A
#define SAR_KEYNOTFOUNTERR				0x0A00001B
#define SAR_CERTNOTFOUNTERR				0x0A00001C
#define SAR_NOTEXPORTERR				0x0A00001D
#define SAR_DECRYPTPADERR				0x0A00001E
#define SAR_MACLENERR					0x0A00001F
#define SAR_BUFFER_TOO_SMALL			0x0A000020
#define SAR_KEYINFOTYPEERR				0x0A000021
#define SAR_NOT_EVENTERR				0x0A000022
#define SAR_DEVICE_REMOVED				0x0A000023
#define SAR_PIN_INCORRECT				0x0A000024
#define SAR_PIN_LOCKED					0x0A000025
#define SAR_PIN_INVALID					0x0A000026
#define SAR_PIN_LEN_RANGE				0x0A000027
#define SAR_USER_ALREADY_LOGGED_IN		0x0A000028
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029
#define SAR_USER_TYPE_INVALID			0x0A00002A
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B
#define SAR_APPLICATION_EXISTS			0x0A00002C
#define SAR_USER_NOT_LOGGED_IN			0x0A00002D
#define SAR_APPLICATION_NOT_EXISTS		0x0A00002E
#define SAR_FILE_ALREADY_EXIST			0x0A00002F
#define SAR_NO_ROOM						0x0A000030

//Add extern return value
#define SAR_IMPORTKEYERR				0x0A000031		//导入密钥错误
#define SAR_GENERATESYMKEYERR			0x0A000032	//生成对称密钥错误
#define SAR_CONTAINER_ALREADY_EXIST		0x0A000033		//容器已经存在
#define SAR_CONTAINER_NOT_EXIST			0x0A000034	//容器不存在
#define SAR_CONTAINER_NOT_OPEN			0x0A000035	//容器没有打开

//分组加密算法标识
#define SGD_SM1_ECB						0x00000101
#define SGD_SM1_CBC						0x00000102
#define SGD_SM1_CFB						0x00000104
#define SGD_SM1_OFB						0x00000108
#define SGD_SM1_MAC						0x00000110
#define SGD_SSF33_ECB					0x00000201
#define SGD_SSF33_CBC					0x00000202
#define SGD_SSF33_CFB					0x00000204
#define SGD_SSF33_OFB					0x00000208
#define SGD_SSF33_MAC					0x00000210
#define SGD_SMS4_ECB					0x00000401
#define SGD_SMS4_CBC					0x00000402
#define SGD_SMS4_CFB					0x00000404
#define SGD_SMS4_OFB					0x00000408
#define SGD_SMS4_MAC					0x00000410

//非对称密码算法标识
#define SGD_RSA							0x00010000
#define SGD_SM2_1						0x00020100
#define SGD_SM2_2						0x00020200
#define SGD_SM2_3						0x00020400

//密码杂凑算法标识
#define SGD_SM3							0x00000001
#define SGD_SHA1						0x00000002
#define SGD_SHA256						0x00000004
//not in gm spec
#define SGD_MD5							0x00000003

//权限类型
#define SECURE_NEVER_ACCOUNT			0x00000000	//不允许
#define SECURE_ADM_ACCOUNT				0x00000001	//管理员权限
#define SECURE_USER_ACCOUNT				0x00000010	//用户权限
#define SECURE_ANYONE_ACCOUNT			0x000000FF	//任何人

/*
*权限类型
*/
#define SECURE_NEVER_ACCOUNT	0x00000000		//不允许
#define SECURE_ADM_ACCOUNT		0x00000001		//管理员权限
#define SECURE_USER_ACCOUNT		0x00000010		//用户权限
#define SECURE_EVERYONE_ACCOUNT	0x000000FF		//任何人


//PIN码类型
#define	ADMIN_TYPE						0x00000000	// 管理员PIN
#define USER_TYPE						0x00000001	// 用户PIN

//设备状态
#define DEV_ABSENT_STATE				0x00000000	//设备不存在	
#define DEV_PRESENT_STATE				0x00000001//设备存在
#define DEV_UNKNOW_STATE				0x00000002

#define MAX_IV_LEN 32
#define APPFILE 0x7430
#define ALG_SSF33	1
#define ALG_SM1		2

#define TRANS_TYPE_PUBKEY_SKF2HS	1
#define TRANS_TYPE_PUBKEY_HS2SKF	2
#define TRANS_TYPE_PRIKEY_SKF2HS	3
#define TRANS_TYPE_PRIKEY_HS2SKF	4

#define ALG_SM3		0x40
#define ALG_SHA1	0x80
#define ALG_SHA256	0x100
#define ALG_MD5		0x8003

// 版本
typedef struct Struct_Version{
	BYTE major;		//主版本号
	BYTE minor;		//次版本号
}VERSION;


// 设备信息
typedef struct Struct_DEVINFO{
	VERSION Version;
	CHAR Manufacturer[64];
	CHAR Issuer[64];
	CHAR Label[32];
	CHAR SerialNumber[32];
	VERSION HWVersion;
	VERSION FirmwareVersion;
	ULONG AlgSymCap;
	ULONG AlgAsymCap;
	ULONG AlgHashCap;
	ULONG DevAuthAlgId;
	ULONG TotalSpace;
	ULONG FreeSpace;
	BYTE Reserved[64];
}DEVINFO, *PDEVINFO;


typedef struct IndexSt
{
	DWORD dwID;
	char szName[32];
}INDEXFILETABLE, *PINDEXFILETABLE;


// 设备初始化信息设备类型：
typedef struct Struct_DEVINITINFO
{
	VERSION AppVersion;
	CHAR Manufacturer[64];	//设备厂商信息,最长64个字符，不足64个字符以空白字符(ASCII码为0xFF)填充，不能以null（0x00）结束。
	CHAR Label[64];	//SIC/SZD标签,最长64个字符，不足64个字符以空白字符(ASCII码为0xFF)填充，不能以null（0x00）结束。
}DEVINITINFO, *PDEVINITINFO;


#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4

// RSA公钥交换数据块
typedef struct Struct_RSAPUBLICKEYBLOB{
	ULONG	AlgID;
	ULONG	BitLen;
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];
}RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

// RSA私钥交换数据块
typedef struct Struct_RSAPRIVATEKEYBLOB{
	ULONG	AlgID;
	ULONG	BitLen;
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];
	BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];
	BYTE	Prime1[MAX_RSA_MODULUS_LEN / 2];
	BYTE	Prime2[MAX_RSA_MODULUS_LEN / 2];
	BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN / 2];
	BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN / 2];
	BYTE	Coefficient[MAX_RSA_MODULUS_LEN / 2];
}RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;


////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////


#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512

// ECC公钥交换数据块
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

#define ECC_MAX_MODULUS_BITS_LEN 512

// ECC私钥交换数据块
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG	BitLen;
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;


// ECC密文数据结构
typedef struct Struct_ECCCIPHERBLOB{
	BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
	BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
	BYTE  Hash[32];
	ULONG CipherLen;
	BYTE  Cipher[1];
}ECCCIPHERBLOB, *PECCCIPHERBLOB;


// ECC签名数据结构
typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
	BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
}ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;


typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;                  // 当前版本为 1
	ULONG ulSymmAlgID;              // 规范中的算法标识，限定ECB模式
	ULONG ulBits;					// 加密密钥对的密钥位长度
	BYTE cbEncryptedPriKey[64];     // 加密保护的加密私钥
	ECCPUBLICKEYBLOB PubKey;        // 加密公钥
	ECCCIPHERBLOB ECCCipherBlob;    // SM2 公钥加密的密钥加密密钥
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;


////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////


// 分组密码参数
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];
	ULONG	IVLen;
	ULONG	PaddingType;
	ULONG	FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

// 文件属性
typedef struct Struct_FILEATTRIBUTE{
	CHAR	FileName[32];
	ULONG	FileSize;
	ULONG	ReadRights;
	ULONG	WriteRights;
}FILEATTRIBUTE, *PFILEATTRIBUTE;



typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;


#define DEVAPI __stdcall

#ifdef __cplusplus
extern "C" {
#endif



	/*****************() *****************/

	ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName, ULONG *pulDevNameLen, ULONG *pulEvent);
	ULONG DEVAPI SKF_CancelWaitForDevEvent();
	ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
	ULONG DEVAPI SKF_ConnectDev(LPSTR szName, DEVHANDLE *phDev);
	ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev);
	ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState);
	ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev, LPSTR szLabel);
	ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO *pDevInfo);
	ULONG DEVAPI SKF_LockDev(DEVHANDLE hDev, ULONG ulTimeOut);
	ULONG DEVAPI SKF_UnlockDev(DEVHANDLE hDev);

	ULONG DEVAPI SKF_ChangeDevAuthKey(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);
	ULONG DEVAPI SKF_DevAuth(DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);
	ULONG DEVAPI SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);
	ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG  ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);
	ULONG DEVAPI SKF_VerifyPIN(HAPPLICATION hApplication, ULONG  ulPINType, LPSTR szPIN, ULONG *pulRetryCount);
	ULONG DEVAPI SKF_UnblockPIN(HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN, ULONG *pulRetryCount);
	ULONG DEVAPI SKF_ClearSecureState(HAPPLICATION hApplication);

	ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount, LPSTR szUserPin, DWORD dwUserPinRetryCount, DWORD dwCreateFileRights, HAPPLICATION *phApplication);
	ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName, ULONG *pulSize);
	ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);
	ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);
	ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication);

	ULONG DEVAPI SKF_CreateFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);
	ULONG DEVAPI SKF_DeleteFile(HAPPLICATION hApplication, LPSTR szFileName);
	ULONG DEVAPI SKF_EnumFiles(HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize);
	ULONG DEVAPI SKF_GetFileInfo(HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo);
	ULONG DEVAPI SKF_ReadFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE * pbOutData, ULONG *pulOutLen);
	ULONG DEVAPI SKF_WriteFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG  ulOffset, BYTE *pbData, ULONG ulSize);

	ULONG DEVAPI SKF_CreateContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
	ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName);
	ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
	ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer);
	ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication, LPSTR szContainerName, ULONG *pulSize);
	ULONG DEVAPI SKF_GetConProperty(IN HCONTAINER hContainer, OUT ULONG *pulConProperty);

	ULONG DEVAPI SKF_GenRandom(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen);
	ULONG DEVAPI SKF_GenExtRSAKey(DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob);
	ULONG DEVAPI SKF_GenRSAKeyPair(HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob);
	ULONG DEVAPI SKF_ImportRSAKeyPair(HCONTAINER hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen, BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);
	ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen);
	ULONG DEVAPI SKF_RSAVerify(DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG ulSignLen);
	ULONG DEVAPI SKF_RSAExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey);
	ULONG DEVAPI SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen);
	ULONG DEVAPI SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob, BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen);

	ULONG DEVAPI SKF_RSADecrypt(HCONTAINER hContainer, BYTE *pbIn, ULONG  ulInLen, BYTE *pbOut, ULONG *pulOutLen);

	ULONG DEVAPI SKF_GenECCKeyPair(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);

	ULONG DEVAPI SKF_ImportECCKeyPair(IN HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	ULONG DEVAPI SKF_ECCSignData(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
	ULONG DEVAPI SKF_ECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob,
		BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	ULONG DEVAPI SKF_ECCExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId,
		ECCPUBLICKEYBLOB *pPubKey,
		PECCCIPHERBLOB pData, HANDLE *phSessionKey);

	ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob,
		BYTE* pbPlainText, ULONG ulPlainTextLen,
		PECCCIPHERBLOB pCipherText);

	ULONG DEVAPI SKF_ExtECCDecrypt(IN DEVHANDLE hDev, IN ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
		IN PECCCIPHERBLOB pCipherText,
		OUT BYTE *pbPlainText, IN OUT ULONG *pulPlainTextLen);

	ULONG DEVAPI SKF_ExtECCSign(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
		BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
	ULONG DEVAPI SKF_ExtECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob,
		BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
	ULONG DEVAPI SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);
	ULONG DEVAPI SKF_GenerateKeyWithECC(HANDLE hAgreementHandle, ECCPUBLICKEYBLOB*  pECCPubKeyBlob, ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE *phKeyHandle);

	ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob, ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen, HANDLE *phKeyHandle);

	ULONG DEVAPI SKF_ExportPublicKey(HCONTAINER hContainer, BOOL bSignFlag,
		BYTE* pbBlob, ULONG* pulBlobLen);

	ULONG DEVAPI SKF_ImportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, BYTE *pbWrapedData, ULONG ulWrapedLen, HANDLE *phKey);
	ULONG DEVAPI SKF_SetSymmKey(DEVHANDLE hDev, BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey);

	ULONG DEVAPI SKF_EncryptInit(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);

	ULONG DEVAPI SKF_Encrypt(HANDLE hKey, BYTE * pbData, ULONG ulDataLen,
		BYTE *pbEncryptedData, ULONG *pulEncryptedLen);

	ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
	ULONG DEVAPI SKF_EncryptFinal(HANDLE hKey, BYTE *pbEncryptedData, ULONG *ulEncryptedDataLen);
	ULONG DEVAPI SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);
	ULONG DEVAPI SKF_Decrypt(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);
	ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);
	ULONG DEVAPI SKF_DecryptFinal(HANDLE hKey, BYTE *pbPlainText, ULONG *pulPlainTextLen);


	ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey,
		unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);
	ULONG DEVAPI SKF_Digest(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
	ULONG DEVAPI SKF_DigestUpdate(HANDLE hHash, BYTE *pbData, ULONG  ulDataLen);
	ULONG DEVAPI SKF_DigestFinal(HANDLE hHash, BYTE *pHashData, ULONG  *pulHashLen);

	ULONG DEVAPI SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE *phMac);
	ULONG DEVAPI SKF_Mac(HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen);
	ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, BYTE * pbData, ULONG ulDataLen);
	ULONG DEVAPI SKF_MacFinal(HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen);
	ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle);
	ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen, BYTE* pbData, ULONG* pulDataLen);
	ULONG DEVAPI SKF_ImportCertificate(IN HCONTAINER hContainer, IN BOOL bSignFlag,
		IN BYTE* pbCert, IN ULONG ulCertLen);
	ULONG DEVAPI SKF_ExportCertificate(IN HCONTAINER hContainer, IN BOOL bSignFlag,
		IN BYTE *pbCert, IN ULONG *pulCertLen);

	ULONG DEVAPI SKF_PrvKeyDecrypt(IN HCONTAINER hContainer, IN DWORD dwKeySpec,
		IN PECCCIPHERBLOB pCipherText,
		OUT BYTE *pbData, IN OUT DWORD *pdwDataLen);

#ifdef __cplusplus
}
#endif

#endif //_SKFAPI_H_