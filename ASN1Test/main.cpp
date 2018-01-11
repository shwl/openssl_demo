#include "esl.h"
#include <crtdbg.h>
#include <openssl/asn1_mac.h>
#include "Base64Tools.h"

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
	ios_base::openmode _Mode = ios::out | ios::binary | ios::ate;
	if (bFlag){
		_Mode = ios::out | ios::binary | ios::app;
	}
	fstream writeFile;
	writeFile.open(fileName, _Mode);
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

string ReadFile(const char* fileName)
{
	string data;
	fstream readFile;
	char buf[1024] = {};
	long len = _countof(buf);
	readFile.open(fileName, ios::in | ios::binary);
	if (readFile.is_open())
	{
		while (!readFile.eof())
		{
			readFile.read(buf, len);
			streamsize readLen = readFile.gcount();
			data.append(buf, readLen);
		}

		readFile.close();
	}

	return data;
}

#if 0

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
#endif

#if 0

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <openssl/safestack.h>



#define sk_Student_new(st) SKM_sk_new(Student, (st))

#define sk_Student_new_null() SKM_sk_new_null(Student)

#define sk_Student_free(st) SKM_sk_free(Student, (st))

#define sk_Student_num(st) SKM_sk_num(Student, (st))

#define sk_Student_value(st, i) SKM_sk_value(Student, (st), (i))

#define sk_Student_set(st, i, val) SKM_sk_set(Student, (st), (i), (val))

#define sk_Student_zero(st) SKM_sk_zero(Student, (st))

#define sk_Student_push(st, val) SKM_sk_push(Student, (st), (val))

#define sk_Student_unshift(st, val) SKM_sk_unshift(Student, (st), (val))

#define sk_Student_find(st, val) SKM_sk_find(Student, (st), (val))

#define sk_Student_delete(st, i) SKM_sk_delete(Student, (st), (i))

#define sk_Student_delete_ptr(st, ptr) SKM_sk_delete_ptr(Student, (st), (ptr))

#define sk_Student_insert(st, val, i) SKM_sk_insert(Student, (st), (val), (i))

#define sk_Student_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(Student, (st), (cmp))

#define sk_Student_dup(st) SKM_sk_dup(Student, st)

#define sk_Student_pop_free(st, free_func) SKM_sk_pop_free(Student, (st), (free_func))

#define sk_Student_shift(st) SKM_sk_shift(Student, (st))

#define sk_Student_pop(st) SKM_sk_pop(Student, (st))

#define sk_Student_sort(st) SKM_sk_sort(Student, (st))



typedef	struct	Student_st

{

	char	*name;

	int	age;

	char	*otherInfo;

}Student;

typedef	STACK_OF(Student)	Students;

Student *Student_Malloc()

{

	Student *a = (Student*)malloc(sizeof(Student));

	a->name = (char*)malloc(20);

	strcpy(a->name, "zcp");

	a->otherInfo = (char*)malloc(20);

	strcpy(a->otherInfo, "no info");

	return a;

}

void	Student_Free(Student *a)

{

	free(a->name);

	free(a->otherInfo);

	free(a);

}

static	int Student_cmp(Student *a, Student *b)

{

	int	ret;



	ret = strcmp(a->name, b->name);

	return ret;

}



int	test()
{

	Students	*s, *snew;

	Student	*s1, *one, *s2;

	int	i, num;



	s = sk_Student_new_null();

	snew = sk_Student_new_null();

	s2 = Student_Malloc();

	sk_Student_push(snew, s2);

	i = sk_Student_find(snew, s2);

	s1 = Student_Malloc();

	sk_Student_push(s, s1);

	num = sk_Student_num(s);

	for (i = 0; i < num; i++)

	{

		one = sk_Student_value(s, i);

		printf("student name :	%s\n", one->name);

		printf("sutdent	age  :	%d\n", one->age);

		printf("student otherinfo :	%s\n\n\n", one->otherInfo);

	}

	sk_Student_pop_free(s, Student_Free);

	sk_Student_pop_free(snew, Student_Free);

	return 0;

}
#endif

void SES_SignInfoTest(const string& signValueB64)
{
	SES_SignInfo* sessigninfo = ESL::DecodeSignInfo(signValueB64, true);
	if (sessigninfo)
	{
		string strSignCertB64 = ESL::GetInnerValue(sessigninfo->cert, true);
		string alg = ESL::GetInnerValue(sessigninfo->signatureAlgorithm);
		string signValue = ESL::GetInnerValue(sessigninfo->signData);
// 		string signcertalg = TGCertTools::GetCertInfo(strSignCertB64, SGD_GET_CERT_SIGNALGOID);
// 		if (0 == alg.compare(signcertalg)){
// 			lRes = 0;
// 		}
// 		else{
// 			lRes = -1;
// 		}
		ESL::Free(&sessigninfo);
	}
}
int main(int argc, char* argv[])
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
//	_CrtSetBreakAlloc(302);
// 	ECCrefPublicKey cipher;
// 	unsigned char* out = nullptr;
// 	int nLen = i2d_ECC_PublicKey(&cipher, &out);
// 	WriteDataToFile((char*)out, nLen, "c:\\test.cer");

	SESeal* pSESeal = nullptr;
	SESealList* pSESealList = nullptr;
	const char* seallistfile = "c:\\seseallist.cer";
	if (argc > 1)
	{
#if 0
		pSESealList = SESealList_new();
		if (argc > 2)
		{
			for (int i = 1; i < argc; ++i)
			{
				auto seal = ESL::Parse(argv[i]);
				if (seal)
				{
					SKM_sk_push(SESeal, pSESealList, seal);
				}
			}
			string strseseallist = ESL::GetValue(pSESealList);
			WriteDataToFile(strseseallist.c_str(), strseseallist.length(), (char*)seallistfile);
		}
#else
		string sealliststr = ReadFile(seallistfile);
		pSESealList = ESL::DecodeSESealList(sealliststr);
		if (pSESealList)
		{
			int num = SKM_sk_num(SESeal, pSESealList);
			for (int i = 0; i < num; ++i)
			{
				SESeal* seal = SKM_sk_value(SESeal, pSESealList, i);
				char buf[MAX_PATH] = {};
				sprintf(buf, "c:\\outseal_%d.cer", i);
				string sealstr = ESL::GetValue(seal);
				WriteDataToFile(sealstr.c_str(), sealstr.length(), buf);
			}
		}
#endif

		//pSESeal = ESL::Parse(argv[1]);
		string str = ReadFile(argv[1]);
		//str = Base64Tools::base64_decode(str);
 		pSESeal = ESL::Parse((char*)str.c_str(), str.length());
// 		ESL::Free(&pSESeal);

// 		pSESeal = SESeal_new();
// 		SES_SealInfo* pSealInfo = ESL::DecodeSealInfo((char*)str1.c_str(), str1.length());
// 		ESL::Free(&pSESeal->sealInfo);
// 		pSESeal->sealInfo = pSealInfo;
		string sealinfostr = ESL::GetValue(pSESeal->sealInfo);
		int ncmp = sealinfostr.compare(str);
		SEQUENCE_CERTLIST* certList = pSESeal->sealInfo->property->certList;
		//int certnum = certList->stack.num;
		string strseseal = ESL::GetValue(pSESeal);
		WriteDataToFile(strseseal.c_str(), strseseal.length(), "c:\\seseal.cer");

		ESL::Free(&pSESeal);
		//ESL::Free(&pSealInfo);
		//SES_SignInfoTest(str);
#if 1
		TGSealInfo tgseal;
		tgseal.strSealCertID = "strSealCertID";
		tgseal.strSealCertB64 = "strSealCertB64";
		tgseal.strName = "strName";
		tgseal.strID = "TGSealID";
		tgseal.strBase64Url = "strBase64Url";
		tgseal.strImgBase64 = "strImgBase64";
		tgseal.strSealCreateData = "strSealCreateData";
		tgseal.strSealValidStart = "strSealValidStart";
		tgseal.strSealValidEnd = "strSealValidEnd";
		tgseal.strSealVersion = "1";
		tgseal.strSealVid = "TGSealVid";
		tgseal.strSealSignAlgo = "1.2.156.10197.1.501";
		tgseal.strMaker = "strMaker";
		tgseal.strSealSignRes = "strSealSignRes";
		tgseal.nType = 2;
		tgseal.nImageWidth = 159;
		tgseal.nImageHeight = 159;
		pSESeal = ESL::TGSealToSESeal(tgseal);
		if (pSESeal)
		{
			string str = ESL::GetValue(pSESeal);
			WriteDataToFile(str.c_str(), str.length(), "c:\\seseal.cer");

			long version = 1;
			string sealData = str;
			string timeInfo = "timeInfo";
			string dataHash = "dataHash";
			string propertyInfo = "propertyInfo";
			string cert = "cert";
			string signatureAlgorithm = "signatureAlgorithm";
			string signatureValue = "signatureValue";
			SES_Signature* sessignature = ESL::EncodeSignature(1, str, timeInfo, dataHash, propertyInfo, cert, signatureAlgorithm, signatureValue);
			if (sessignature)
			{
				string str = ESL::GetValue(sessignature);
				WriteDataToFile(str.c_str(), str.length(), "c:\\sessignature.cer");

				str = ESL::GetValue(sessignature->toSign);
				WriteDataToFile(str.c_str(), str.length(), "c:\\tbssign.cer");
			}
			ESL::Free(&sessignature);
			ESL::Free(&pSESeal);
		}
#endif
	}
	SESealList_free(pSESealList);
	ESL::CleanUp();
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	return 0;
}