#ifndef TG_ECCAPI_H
#define TG_ECCAPI_H

#include "SKFAPI.h"

#define DLLEXPORT_TGSM2_API __declspec(dllexport)

#ifdef __cplusplus
extern "C"{
#endif
	/************************************
	 * Function:  ECC外来私钥签名;
	 * FullName:  TG_ECCSign;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK：成功,其他：错误码;
	 * Parameter: ECCPRIVATEKEYBLOB * pECCPriKeyBlob [IN] ECC 私钥数据结构;
	 * Parameter: BYTE * pbData [IN] 待签名的数据;
	 * Parameter: ULONG ulDataLen [IN] 待签名数据长度;
	 * Parameter: ECCSIGNATUREBLOB * pSignature [OUT] 签名值;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCSign(ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
		BYTE *pbData,
		ULONG ulDataLen,
		ECCSIGNATUREBLOB *pSignature);

	/************************************
	 * Function:  ECC外来公钥验签;
	 * FullName:  TG_ECCVerify;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK：成功,SAR_ BAD_SIGNATURE：验证失败,其他： 错误码;
	 * Parameter: ECCPUBLICKEYBLOB * pECCPubKeyBlob [IN] ECC 公钥数据结构;
	 * Parameter: BYTE * pbData [IN] 待验证数据;
	 * Parameter: ULONG ulDataLen [IN] 待验证数据的长度;
	 * Parameter: ECCSIGNATUREBLOB * pSignature [IN] 签名值;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCVerify(ECCPUBLICKEYBLOB *pECCPubKeyBlob,
		BYTE *pbData,
		ULONG ulDataLen,
		ECCSIGNATUREBLOB *pSignature);

	/************************************
	* Function:  ECC外来公钥加密;
	* FullName:  TG_ECCPubKeyEncrypt;
	* Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK：成功,其他：错误码;
	* Parameter: ECCPUBLICKEYBLOB * pECCPubKeyBlob [IN] ECC 公钥数据结构;
	* Parameter: BYTE * pbPlainText [IN] 待加密的明文数据;
	* Parameter: ULONG ulPlainTextLen [IN] 待加密明文数据的长度;
	* Parameter: OUT PECCCIPHERBLOB pCipherText;
	* author:	  shwl;
	* date:	  2017/02/09;
	************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCPubKeyEncrypt(ECCPUBLICKEYBLOB *pECCPubKeyBlob,
		BYTE* pbPlainText,
		ULONG ulPlainTextLen,
		PECCCIPHERBLOB pCipherText);

	/************************************
	* Function:  ECC外来私钥解密;
	* FullName:  TG_ECCPriKeyDecrypt;
	* Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK：成功,其他：错误码;
	* Parameter: ECCPRIVATEKEYBLOB * pECCPriKeyBlob [IN] ECC 私钥数据结构;
	* Parameter: PECCCIPHERBLOB pCipherText [IN] 待解密的密文数据;
	* Parameter: OUT BYTE * pbPlainText [OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen 返回明文数据的实际长度;
	* Parameter: IN OUT ULONG * pulPlainTextLen [IN,OUT] 调用前表示pbPlainText 缓冲区的长度，返回明文数据的实际长度;
	* author:	  shwl;
	* date:	  2017/02/09;
	************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCPriKeyDecrypt(ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
		PECCCIPHERBLOB pCipherText,
		BYTE *pbPlainText,
		ULONG *pulPlainTextLen);

	/************************************
	* Function:  生成SM2公私玥对;
	* FullName:  Tg_GenECCKeyPair;
	* Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK：成功,其他：错误码;
	* Parameter: ULONG ulAlgId [IN] 算法标识;
	* Parameter: ECCPRIVATEKEYBLOB * [OUT] priKey 私钥;
	* Parameter: ECCPUBLICKEYBLOB * [OUT] pubKey 公钥;
	* author:	  shwl;
	* date:	  2017/02/09;
	************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_GenECCKeyPair(ULONG ulAlgId,
		ECCPRIVATEKEYBLOB *priKey,
		ECCPUBLICKEYBLOB *pubKey);

	/************************************
	 * Function:  明文导入会话密钥;
	 * FullName:  TG_SetSymmKey;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: BYTE * pbKey [IN] 指向会话密钥值的缓冲区;
	 * Parameter: ULONG ulAlgID [IN] 会话密钥算法标识;
	 * Parameter: HANDLE * phKey [OUT] 返回会话密钥句柄;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_SetSymmKey(BYTE *pbKey,
		ULONG ulAlgID,
		HANDLE *phKey);

	/************************************
	 * Function:  加密初始化;
	 * FullName:  TG_EncryptInit;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey [IN] 加密密钥句柄;
	 * Parameter: BLOCKCIPHERPARAM EncryptParam [IN] 分组密码算法相关参数：初始向量、初始向量长度、填充方法、反馈值的位长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_EncryptInit(HANDLE hKey,
		BLOCKCIPHERPARAM EncryptParam);

	/************************************
	 * Function:  单组数据加密;
	 * FullName:  TG_Encrypt;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey [IN] 加密密钥句柄;
	 * Parameter: BYTE * pbData [IN] 待加密数据;
	 * Parameter: ULONG ulDataLen [IN] 待加密数据长度;
	 * Parameter: BYTE * pbEncryptedData [OUT] 加密后的数据缓冲区指针，可以为 NULL，用于获得加密后数据长度;
	 * Parameter: ULONG * pulEncryptedLen [IN，OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_Encrypt(HANDLE hKey,
		BYTE *pbData,
		ULONG ulDataLen,
		BYTE *pbEncryptedData,
		ULONG *pulEncryptedLen);

	/************************************
	 * Function:  多组数据加密;
	 * FullName:  TG_EncryptUpdate;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey [IN] 加密密钥句柄;
	 * Parameter: BYTE * pbData [IN] 待加密数据;
	 * Parameter: ULONG ulDataLen [IN] 待加密数据长度;
	 * Parameter: BYTE * pbEncryptedData [OUT] 加密后的数据缓冲区指针;
	 * Parameter: ULONG * pulEncryptedLen [OUT] 返回加密后的数据长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_EncryptUpdate(HANDLE hKey,
		BYTE *pbData,
		ULONG ulDataLen,
		BYTE *pbEncryptedData,
		ULONG *pulEncryptedLen);

	/************************************
	 * Function:  结束加密;
	 * FullName:  TG_EncryptFinal;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey [IN] 加密密钥句柄;
	 * Parameter: BYTE * pbEncryptedData [OUT] 加密结果的缓冲区;
	 * Parameter: ULONG * pulEncryptedDataLen [OUT] 加密结果的长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_EncryptFinal(HANDLE hKey,
		BYTE *pbEncryptedData,
		ULONG *pulEncryptedDataLen);

	/************************************
	 * Function:  解密初始化;
	 * FullName:  TG_DecryptInit;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey [IN] 解密密钥句柄;
	 * Parameter: BLOCKCIPHERPARAM DecryptParam [IN] 分组密码算法相关参数：初始向量、初始向量长度、填充方法、反馈值的位长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DecryptInit(HANDLE hKey,
		BLOCKCIPHERPARAM DecryptParam);

	/************************************
	 * Function:  单组数据解密;
	 * FullName:  TG_Decrypt;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey  [IN] 解密密钥句柄;
	 * Parameter: BYTE * pbEncryptedData [IN] 待解密数据;
	 * Parameter: ULONG ulEncryptedLen [IN] 待解密数据长度;
	 * Parameter: BYTE * pbData [OUT] 指向解密后的数据缓冲区指针，当为 NULL 时可获得解密后的数据长度;
	 * Parameter: ULONG * pulDataLen [IN，OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_Decrypt(HANDLE hKey,
		BYTE *pbEncryptedData,
		ULONG ulEncryptedLen,
		BYTE *pbData,
		ULONG *pulDataLen);

	/************************************
	 * Function:  多组数据解密;
	 * FullName:  TG_DecryptUpdate;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey  [IN] 解密密钥句柄;
	 * Parameter: BYTE * pbEncryptedData [IN] 待解密数据;
	 * Parameter: ULONG ulEncryptedLen [IN] 待解密数据长度;
	 * Parameter: BYTE * pbData [OUT] 指向解密后的数据缓冲区指针;
	 * Parameter: ULONG * pulDataLen [IN，OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DecryptUpdate(HANDLE hKey,
		BYTE *pbEncryptedData,
		ULONG ulEncryptedLen,
		BYTE *pbData,
		ULONG *pulDataLen);

	/************************************
	 * Function:  结束解密;
	 * FullName:  TG_DecryptFinal;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hKey  [IN] 解密密钥句柄;
	 * Parameter: BYTE * pbDecryptedData [OUT] 指向解密结果的缓冲区，如果此参数为 NULL 时，由pulDecryptedDataLen 返回解密结果的长度;
	 * Parameter: ULONG * pulDecryptedDataLen [IN，OUT] 输入时表示 pbDecryptedData 缓冲区的长度，输出时表示解密结果的长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DecryptFinal(HANDLE hKey,
		BYTE *pbDecryptedData,
		ULONG *pulDecryptedDataLen);

	/************************************
	 * Function:  密码杂凑初始化;
	 * FullName:  TG_DigestInit;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: ULONG ulAlgID [IN] 密码杂凑算法标识;
	 * Parameter: ECCPUBLICKEYBLOB * pPubKey [IN] 签名者公钥。当 ulAlgID 为 SGD_SM3 时有效;
	 * Parameter: BYTE * pbID [IN] 签名者的 ID 值，当 ulAlgID 为 SGD_SM3 时有效;
	 * Parameter: ULONG ulIDLen [IN] 签名者 ID 的长度，当 ulAlgID 为 SGD_SM3 时有效;
	 * Parameter: HANDLE * phHash [OUT] 密码杂凑对象句柄;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DigestInit(ULONG ulAlgID,
		ECCPUBLICKEYBLOB *pPubKey,
		BYTE *pbID,
		ULONG ulIDLen,
		HANDLE *phHash);

	/************************************
	 * Function:  单组数据密码杂凑;
	 * FullName:  TG_Digest;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hHash [IN] 密码杂凑对象句柄;
	 * Parameter: BYTE * pbData [IN] 指向消息数据的缓冲区;
	 * Parameter: ULONG ulDataLen [IN] 消息数据的长度;
	 * Parameter: BYTE * pbHashData [OUT] 密码杂凑数据缓冲区指针，当此参数为 NULL 时，由pulHashLen 返回密码杂凑结果的长度;
	 * Parameter: ULONG * pulHashLen [IN，OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_Digest(HANDLE hHash,
		BYTE *pbData,
		ULONG ulDataLen,
		BYTE *pbHashData,
		ULONG *pulHashLen);

	/************************************
	 * Function:  多组数据密码杂凑;
	 * FullName:  TG_DigestUpdate;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hHash [IN] 密码杂凑对象句柄;
	 * Parameter: BYTE * pbData [IN] 指向消息数据的缓冲区;
	 * Parameter: ULONG ulDataLen [IN] 消息数据的长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DigestUpdate(HANDLE hHash,
		BYTE *pbData,
		ULONG ulDataLen);

	/************************************
	 * Function:  结束密码杂凑;
	 * FullName:  TG_DigestFinal;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: HANDLE hHash [IN] 密码杂凑对象句柄;
	 * Parameter: BYTE * pHashData [OUT] 返回的密码杂凑结果缓冲区指针，如果此参数 NULL 时，由pulHashLen 返回杂凑结果的长度;
	 * Parameter: ULONG * pulHashLen [IN，OUT] 输入时表示杂凑结果缓冲区的长度，输出时表示密码杂凑结果的长度;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DigestFinal(HANDLE hHash,
		BYTE *pHashData,
		ULONG *pulHashLen);

	/************************************
	 * Function:  生成随机数;
	 * FullName:  TG_GenRandom;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: BYTE * pbRandom [OUT]返回的随机数;
	 * Parameter: ULONG ulRandomLen [IN] 随机数长度;
	 * author:	  shwl;
	 * date:	  2017/02/16;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_GenRandom(BYTE *pbRandom,
		ULONG ulRandomLen);

	/************************************
	 * Function:  ECC生成并导出会话密钥;
	 * FullName:  TG_ECCExportSessionKey;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK：成功,其他：错误码;
	 * Parameter: ULONG ulAlgId [IN] 会话密钥算法标识,只支持SM4算法;
	 * Parameter: ECCPUBLICKEYBLOB * pPubKey [IN] 用来导出密钥的密钥结构;
	 * Parameter: ECCCIPHERBLOB * pData [OUT]导出的加密会话密钥密文;
	 * Parameter: HANDLE * phSessionKey [OUT]会话密钥句柄;
	 * author:	  shwl;
	 * date:	  2017/02/16;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCExportSessionKey(ULONG ulAlgId,
		ECCPUBLICKEYBLOB *pPubKey,
		ECCCIPHERBLOB *pData,
		HANDLE *phSessionKey);

	/************************************
	 * Function:  关闭密码对象句柄;
	 * FullName:  TG_CloseHandle;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI;
	 * Parameter: HANDLE hHandle [IN]要关闭的对象句柄;
	 * Parameter: ULONG ulFlag [IN]保留,传0;
	 * author:	  shwl;
	 * date:	  2017/02/17;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_CloseHandle(HANDLE hHandle, ULONG ulFlag);

#ifdef __cplusplus
}
#endif

#endif