#ifndef TG_ECCAPI_H
#define TG_ECCAPI_H

#include "SKFAPI.h"

#define DLLEXPORT_TGSM2_API __declspec(dllexport)

#ifdef __cplusplus
extern "C"{
#endif
	/************************************
	 * Function:  ECC����˽Կǩ��;
	 * FullName:  TG_ECCSign;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK���ɹ�,������������;
	 * Parameter: ECCPRIVATEKEYBLOB * pECCPriKeyBlob [IN] ECC ˽Կ���ݽṹ;
	 * Parameter: BYTE * pbData [IN] ��ǩ��������;
	 * Parameter: ULONG ulDataLen [IN] ��ǩ�����ݳ���;
	 * Parameter: ECCSIGNATUREBLOB * pSignature [OUT] ǩ��ֵ;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCSign(ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
		BYTE *pbData,
		ULONG ulDataLen,
		ECCSIGNATUREBLOB *pSignature);

	/************************************
	 * Function:  ECC������Կ��ǩ;
	 * FullName:  TG_ECCVerify;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK���ɹ�,SAR_ BAD_SIGNATURE����֤ʧ��,������ ������;
	 * Parameter: ECCPUBLICKEYBLOB * pECCPubKeyBlob [IN] ECC ��Կ���ݽṹ;
	 * Parameter: BYTE * pbData [IN] ����֤����;
	 * Parameter: ULONG ulDataLen [IN] ����֤���ݵĳ���;
	 * Parameter: ECCSIGNATUREBLOB * pSignature [IN] ǩ��ֵ;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCVerify(ECCPUBLICKEYBLOB *pECCPubKeyBlob,
		BYTE *pbData,
		ULONG ulDataLen,
		ECCSIGNATUREBLOB *pSignature);

	/************************************
	* Function:  ECC������Կ����;
	* FullName:  TG_ECCPubKeyEncrypt;
	* Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK���ɹ�,������������;
	* Parameter: ECCPUBLICKEYBLOB * pECCPubKeyBlob [IN] ECC ��Կ���ݽṹ;
	* Parameter: BYTE * pbPlainText [IN] �����ܵ���������;
	* Parameter: ULONG ulPlainTextLen [IN] �������������ݵĳ���;
	* Parameter: OUT PECCCIPHERBLOB pCipherText;
	* author:	  shwl;
	* date:	  2017/02/09;
	************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCPubKeyEncrypt(ECCPUBLICKEYBLOB *pECCPubKeyBlob,
		BYTE* pbPlainText,
		ULONG ulPlainTextLen,
		PECCCIPHERBLOB pCipherText);

	/************************************
	* Function:  ECC����˽Կ����;
	* FullName:  TG_ECCPriKeyDecrypt;
	* Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK���ɹ�,������������;
	* Parameter: ECCPRIVATEKEYBLOB * pECCPriKeyBlob [IN] ECC ˽Կ���ݽṹ;
	* Parameter: PECCCIPHERBLOB pCipherText [IN] �����ܵ���������;
	* Parameter: OUT BYTE * pbPlainText [OUT] �����������ݣ�����ò���ΪNULL������pulPlainTextLen �����������ݵ�ʵ�ʳ���;
	* Parameter: IN OUT ULONG * pulPlainTextLen [IN,OUT] ����ǰ��ʾpbPlainText �������ĳ��ȣ������������ݵ�ʵ�ʳ���;
	* author:	  shwl;
	* date:	  2017/02/09;
	************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCPriKeyDecrypt(ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
		PECCCIPHERBLOB pCipherText,
		BYTE *pbPlainText,
		ULONG *pulPlainTextLen);

	/************************************
	* Function:  ����SM2��˽�h��;
	* FullName:  Tg_GenECCKeyPair;
	* Returns:   DLLEXPORT_TGSM2_API ULONG SAR_OK���ɹ�,������������;
	* Parameter: ULONG ulAlgId [IN] �㷨��ʶ;
	* Parameter: ECCPRIVATEKEYBLOB * [OUT] priKey ˽Կ;
	* Parameter: ECCPUBLICKEYBLOB * [OUT] pubKey ��Կ;
	* author:	  shwl;
	* date:	  2017/02/09;
	************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_GenECCKeyPair(ULONG ulAlgId,
		ECCPRIVATEKEYBLOB *priKey,
		ECCPUBLICKEYBLOB *pubKey);

	/************************************
	 * Function:  ���ĵ���Ự��Կ;
	 * FullName:  TG_SetSymmKey;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: BYTE * pbKey [IN] ָ��Ự��Կֵ�Ļ�����;
	 * Parameter: ULONG ulAlgID [IN] �Ự��Կ�㷨��ʶ;
	 * Parameter: HANDLE * phKey [OUT] ���ػỰ��Կ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_SetSymmKey(BYTE *pbKey,
		ULONG ulAlgID,
		HANDLE *phKey);

	/************************************
	 * Function:  ���ܳ�ʼ��;
	 * FullName:  TG_EncryptInit;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey [IN] ������Կ���;
	 * Parameter: BLOCKCIPHERPARAM EncryptParam [IN] ���������㷨��ز�������ʼ��������ʼ�������ȡ���䷽��������ֵ��λ����;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_EncryptInit(HANDLE hKey,
		BLOCKCIPHERPARAM EncryptParam);

	/************************************
	 * Function:  �������ݼ���;
	 * FullName:  TG_Encrypt;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey [IN] ������Կ���;
	 * Parameter: BYTE * pbData [IN] ����������;
	 * Parameter: ULONG ulDataLen [IN] ���������ݳ���;
	 * Parameter: BYTE * pbEncryptedData [OUT] ���ܺ�����ݻ�����ָ�룬����Ϊ NULL�����ڻ�ü��ܺ����ݳ���;
	 * Parameter: ULONG * pulEncryptedLen [IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_Encrypt(HANDLE hKey,
		BYTE *pbData,
		ULONG ulDataLen,
		BYTE *pbEncryptedData,
		ULONG *pulEncryptedLen);

	/************************************
	 * Function:  �������ݼ���;
	 * FullName:  TG_EncryptUpdate;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey [IN] ������Կ���;
	 * Parameter: BYTE * pbData [IN] ����������;
	 * Parameter: ULONG ulDataLen [IN] ���������ݳ���;
	 * Parameter: BYTE * pbEncryptedData [OUT] ���ܺ�����ݻ�����ָ��;
	 * Parameter: ULONG * pulEncryptedLen [OUT] ���ؼ��ܺ�����ݳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_EncryptUpdate(HANDLE hKey,
		BYTE *pbData,
		ULONG ulDataLen,
		BYTE *pbEncryptedData,
		ULONG *pulEncryptedLen);

	/************************************
	 * Function:  ��������;
	 * FullName:  TG_EncryptFinal;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey [IN] ������Կ���;
	 * Parameter: BYTE * pbEncryptedData [OUT] ���ܽ���Ļ�����;
	 * Parameter: ULONG * pulEncryptedDataLen [OUT] ���ܽ���ĳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_EncryptFinal(HANDLE hKey,
		BYTE *pbEncryptedData,
		ULONG *pulEncryptedDataLen);

	/************************************
	 * Function:  ���ܳ�ʼ��;
	 * FullName:  TG_DecryptInit;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey [IN] ������Կ���;
	 * Parameter: BLOCKCIPHERPARAM DecryptParam [IN] ���������㷨��ز�������ʼ��������ʼ�������ȡ���䷽��������ֵ��λ����;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DecryptInit(HANDLE hKey,
		BLOCKCIPHERPARAM DecryptParam);

	/************************************
	 * Function:  �������ݽ���;
	 * FullName:  TG_Decrypt;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey  [IN] ������Կ���;
	 * Parameter: BYTE * pbEncryptedData [IN] ����������;
	 * Parameter: ULONG ulEncryptedLen [IN] ���������ݳ���;
	 * Parameter: BYTE * pbData [OUT] ָ����ܺ�����ݻ�����ָ�룬��Ϊ NULL ʱ�ɻ�ý��ܺ�����ݳ���;
	 * Parameter: ULONG * pulDataLen [IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_Decrypt(HANDLE hKey,
		BYTE *pbEncryptedData,
		ULONG ulEncryptedLen,
		BYTE *pbData,
		ULONG *pulDataLen);

	/************************************
	 * Function:  �������ݽ���;
	 * FullName:  TG_DecryptUpdate;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey  [IN] ������Կ���;
	 * Parameter: BYTE * pbEncryptedData [IN] ����������;
	 * Parameter: ULONG ulEncryptedLen [IN] ���������ݳ���;
	 * Parameter: BYTE * pbData [OUT] ָ����ܺ�����ݻ�����ָ��;
	 * Parameter: ULONG * pulDataLen [IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DecryptUpdate(HANDLE hKey,
		BYTE *pbEncryptedData,
		ULONG ulEncryptedLen,
		BYTE *pbData,
		ULONG *pulDataLen);

	/************************************
	 * Function:  ��������;
	 * FullName:  TG_DecryptFinal;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hKey  [IN] ������Կ���;
	 * Parameter: BYTE * pbDecryptedData [OUT] ָ����ܽ���Ļ�����������˲���Ϊ NULL ʱ����pulDecryptedDataLen ���ؽ��ܽ���ĳ���;
	 * Parameter: ULONG * pulDecryptedDataLen [IN��OUT] ����ʱ��ʾ pbDecryptedData �������ĳ��ȣ����ʱ��ʾ���ܽ���ĳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DecryptFinal(HANDLE hKey,
		BYTE *pbDecryptedData,
		ULONG *pulDecryptedDataLen);

	/************************************
	 * Function:  �����Ӵճ�ʼ��;
	 * FullName:  TG_DigestInit;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: ULONG ulAlgID [IN] �����Ӵ��㷨��ʶ;
	 * Parameter: ECCPUBLICKEYBLOB * pPubKey [IN] ǩ���߹�Կ���� ulAlgID Ϊ SGD_SM3 ʱ��Ч;
	 * Parameter: BYTE * pbID [IN] ǩ���ߵ� ID ֵ���� ulAlgID Ϊ SGD_SM3 ʱ��Ч;
	 * Parameter: ULONG ulIDLen [IN] ǩ���� ID �ĳ��ȣ��� ulAlgID Ϊ SGD_SM3 ʱ��Ч;
	 * Parameter: HANDLE * phHash [OUT] �����Ӵն�����;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DigestInit(ULONG ulAlgID,
		ECCPUBLICKEYBLOB *pPubKey,
		BYTE *pbID,
		ULONG ulIDLen,
		HANDLE *phHash);

	/************************************
	 * Function:  �������������Ӵ�;
	 * FullName:  TG_Digest;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hHash [IN] �����Ӵն�����;
	 * Parameter: BYTE * pbData [IN] ָ����Ϣ���ݵĻ�����;
	 * Parameter: ULONG ulDataLen [IN] ��Ϣ���ݵĳ���;
	 * Parameter: BYTE * pbHashData [OUT] �����Ӵ����ݻ�����ָ�룬���˲���Ϊ NULL ʱ����pulHashLen ���������Ӵս���ĳ���;
	 * Parameter: ULONG * pulHashLen [IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_Digest(HANDLE hHash,
		BYTE *pbData,
		ULONG ulDataLen,
		BYTE *pbHashData,
		ULONG *pulHashLen);

	/************************************
	 * Function:  �������������Ӵ�;
	 * FullName:  TG_DigestUpdate;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hHash [IN] �����Ӵն�����;
	 * Parameter: BYTE * pbData [IN] ָ����Ϣ���ݵĻ�����;
	 * Parameter: ULONG ulDataLen [IN] ��Ϣ���ݵĳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DigestUpdate(HANDLE hHash,
		BYTE *pbData,
		ULONG ulDataLen);

	/************************************
	 * Function:  ���������Ӵ�;
	 * FullName:  TG_DigestFinal;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: HANDLE hHash [IN] �����Ӵն�����;
	 * Parameter: BYTE * pHashData [OUT] ���ص������Ӵս��������ָ�룬����˲��� NULL ʱ����pulHashLen �����Ӵս���ĳ���;
	 * Parameter: ULONG * pulHashLen [IN��OUT] ����ʱ��ʾ�Ӵս���������ĳ��ȣ����ʱ��ʾ�����Ӵս���ĳ���;
	 * author:	  shwl;
	 * date:	  2017/02/13;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_DigestFinal(HANDLE hHash,
		BYTE *pHashData,
		ULONG *pulHashLen);

	/************************************
	 * Function:  ���������;
	 * FullName:  TG_GenRandom;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: BYTE * pbRandom [OUT]���ص������;
	 * Parameter: ULONG ulRandomLen [IN] ���������;
	 * author:	  shwl;
	 * date:	  2017/02/16;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_GenRandom(BYTE *pbRandom,
		ULONG ulRandomLen);

	/************************************
	 * Function:  ECC���ɲ������Ự��Կ;
	 * FullName:  TG_ECCExportSessionKey;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI SAR_OK���ɹ�,������������;
	 * Parameter: ULONG ulAlgId [IN] �Ự��Կ�㷨��ʶ,ֻ֧��SM4�㷨;
	 * Parameter: ECCPUBLICKEYBLOB * pPubKey [IN] ����������Կ����Կ�ṹ;
	 * Parameter: ECCCIPHERBLOB * pData [OUT]�����ļ��ܻỰ��Կ����;
	 * Parameter: HANDLE * phSessionKey [OUT]�Ự��Կ���;
	 * author:	  shwl;
	 * date:	  2017/02/16;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_ECCExportSessionKey(ULONG ulAlgId,
		ECCPUBLICKEYBLOB *pPubKey,
		ECCCIPHERBLOB *pData,
		HANDLE *phSessionKey);

	/************************************
	 * Function:  �ر����������;
	 * FullName:  TG_CloseHandle;
	 * Returns:   DLLEXPORT_TGSM2_API ULONG DEVAPI;
	 * Parameter: HANDLE hHandle [IN]Ҫ�رյĶ�����;
	 * Parameter: ULONG ulFlag [IN]����,��0;
	 * author:	  shwl;
	 * date:	  2017/02/17;
	 ************************************/
	DLLEXPORT_TGSM2_API ULONG DEVAPI TG_CloseHandle(HANDLE hHandle, ULONG ulFlag);

#ifdef __cplusplus
}
#endif

#endif