#ifndef ESL_H
#define ESL_H
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <string>
#include <iostream>
#include "TGSignCommonInfo.h"
using namespace std;

struct SES_Header {
    ASN1_IA5STRING* ID;
    ASN1_INTEGER* version;
    ASN1_IA5STRING* vid;
};
DECLARE_ASN1_FUNCTIONS(SES_Header)

struct ExtData {
    ASN1_OBJECT* extnID;
    ASN1_BOOLEAN critical /*= false*/;
    ASN1_OCTET_STRING* extnValue;
};
DECLARE_ASN1_FUNCTIONS(ExtData)

typedef STACK_OF(ExtData) ExtDatas;
DECLARE_ASN1_FUNCTIONS(ExtDatas)

typedef STACK_OF(ASN1_OCTET_STRING) SEQUENCE_CERTLIST;
DECLARE_ASN1_FUNCTIONS(SEQUENCE_CERTLIST)

struct SES_ESPropertyInfo {
    ASN1_INTEGER* type;
    ASN1_UTF8STRING* name;
	SEQUENCE_CERTLIST* certList;
    ASN1_UTCTIME* createDate;
    ASN1_UTCTIME* validStart;
    ASN1_UTCTIME* validEnd;
};
DECLARE_ASN1_FUNCTIONS(SES_ESPropertyInfo)

struct SES_ESPictureInfo {
    ASN1_IA5STRING* type;
    ASN1_OCTET_STRING* data;
    ASN1_INTEGER* width;
    ASN1_INTEGER* height;
};
DECLARE_ASN1_FUNCTIONS(SES_ESPictureInfo)

struct SES_SealInfo {
    SES_Header* header;
    ASN1_IA5STRING* esID;
    SES_ESPropertyInfo* property;
	SES_ESPictureInfo* picture;
	ExtDatas* extDatas;
};
DECLARE_ASN1_FUNCTIONS(SES_SealInfo)

struct SES_SignInfo {
    ASN1_OCTET_STRING* cert;
    ASN1_OBJECT* signatureAlgorithm;
    ASN1_BIT_STRING* signData;
};
DECLARE_ASN1_FUNCTIONS(SES_SignInfo)

struct SESeal {
    SES_SealInfo* sealInfo;
    SES_SignInfo* signInfo;
};
DECLARE_ASN1_FUNCTIONS(SESeal)

struct TBS_Sign {
    ASN1_INTEGER* version;
    SESeal* seal;
    ASN1_BIT_STRING* timeInfo;
    ASN1_BIT_STRING* dataHash;
    ASN1_IA5STRING* propertyInfo;
    ASN1_OCTET_STRING* cert;
    ASN1_OBJECT* signatureAlgorithm;
};
DECLARE_ASN1_FUNCTIONS(TBS_Sign)

struct SES_Signature {
    TBS_Sign* toSign;
    ASN1_BIT_STRING* signature;
};
DECLARE_ASN1_FUNCTIONS(SES_Signature)

class ESL
{
public:
    ESL();
	~ESL();
	static void Init();
	static void CleanUp();

	static SESeal* TGSealToSESeal(const TGSealInfo& sealInfo);
	static SESeal* Parse(string path);
	static SESeal* Parse(char* data, int len);
	static SES_Signature* EncodeSignature(long version, const string& sealData, const string& timeInfo, const string& dataHash,
		const string& propertyInfo, const string& cert, const string& signatureAlgorithm, const string& signatureValue);
	static SES_Signature* DecodeSignature(char* data, int len);

	static string GetValue(SESeal* seseal);
	static string GetValue(TBS_Sign* tbssign);
	static string GetValue(SES_Signature* sessignature);

	static void Free(SESeal** seseal);
	static void Free(SES_Signature** sessignature);
};

#endif // ESL_H
