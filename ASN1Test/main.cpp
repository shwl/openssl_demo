#include "esl.h"
#include <crtdbg.h>

#include <fstream>
long WriteDataToFile(const char* data, long dataLen = -1, char* fileName = nullptr)
{
	bool bFlag = false;
	long lRes = 0;
	if (!fileName)
	{
		fileName = "c:\\test.log";
		bFlag = true;
	}

	fstream writeFile;
	writeFile.open(fileName, ios::out | ios::binary | ios::app);
	if (!writeFile.is_open()){
		lRes = 403;
	}

	if (0 == lRes)
	{
		dataLen = (-1 == dataLen) ? strlen(data) : dataLen;
		writeFile.write(data, dataLen);
		if (bFlag){
			writeFile.write("\r\n", 2);
		}
		writeFile.close();
	}

	return lRes;
}

#define ECCref_MAX_BITS 256 

#define ECCref_MAX_LEN ((ECCref_MAX_BITS+7) / 8)

typedef struct ECCrefPublicKey_st

{

	unsigned int bits;

	unsigned char x[ECCref_MAX_LEN];

	unsigned char y[ECCref_MAX_LEN];

} ECCrefPublicKey;

typedef struct ASN_ECCPUBLICKEY_st

{

	ASN1_OCTET_STRING *X;

	ASN1_OCTET_STRING *Y;

}ASN_ECCPUBLICKEY;

DECLARE_ASN1_FUNCTIONS(ASN_ECCPUBLICKEY)

ASN1_SEQUENCE(ASN_ECCPUBLICKEY) = {

	ASN1_SIMPLE(ASN_ECCPUBLICKEY, X, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ASN_ECCPUBLICKEY, Y, ASN1_OCTET_STRING),

} ASN1_SEQUENCE_END(ASN_ECCPUBLICKEY);

IMPLEMENT_ASN1_FUNCTIONS(ASN_ECCPUBLICKEY)

int i2d_ECC_PublicKey(const ECCrefPublicKey *cipher, unsigned char **out)
{
	ASN_ECCPUBLICKEY *ec = NULL;
	int             len = 0;

	ec = ASN_ECCPUBLICKEY_new();
	if (ec == NULL) {
		return 0;
	}

	do {
		if (!ASN1_OCTET_STRING_set(ec->X, cipher->x, 32))
			break;

		if (!ASN1_OCTET_STRING_set(ec->Y, cipher->y, 32))
			break;

		/* i2d */
		len = i2d_ASN_ECCPUBLICKEY(ec, out);

	} while (0);

	ASN_ECCPUBLICKEY_free(ec);

	return len;
}

int d2i_ECC_PublicKey(ECCrefPublicKey *ins, const unsigned char **ppin, long pplen)
{
	ASN_ECCPUBLICKEY *ec = NULL;

	/* DECODE */
	ec = d2i_ASN_ECCPUBLICKEY(NULL, ppin, pplen);
	if (ec == NULL) {
		return 0;
	}

	/* check version ? */
	do {
		if (ec->X->length <= 0 || ec->Y->length <= 0)
			break;
		memcpy(ins->x, ec->X->data, ec->X->length);

		memcpy(ins->y, ec->Y->data, ec->Y->length);

		ASN_ECCPUBLICKEY_free(ec);
		return 1;

	} while (0);

	ASN_ECCPUBLICKEY_free(ec);
	return 1;
}

int main(int argv, char* argc[])
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
	//_CrtSetBreakAlloc(727);

	ECCrefPublicKey cipher;
	unsigned char* out = nullptr;
	int nLen = i2d_ECC_PublicKey(&cipher, &out);
	WriteDataToFile((char*)out, nLen, "c:\\test.cer");

	SESeal* pSESeal = nullptr;

	ESL::Init();

	if (argv > 1)
	{
		//pSESeal = ESL::Parse(argc[1]);
		
		TGSealInfo tgseal;
		tgseal.strID = "TGSealID";
		tgseal.strSealVersion = "1";
		tgseal.strSealVid = "TGSealVid";
		tgseal.strSealSignAlgo = "1.3.14.3.2.29";
		pSESeal = ESL::TGSealToSESeal(tgseal);
	}
	
	delete pSESeal;
	ESL::CleanUp();

	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	return 0;
}