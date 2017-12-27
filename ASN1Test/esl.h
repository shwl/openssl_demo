#ifndef ESL_H
#define ESL_H
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <list>
#include <string>
#include <iostream>
#include "TGSignCommonInfo.h"
using namespace std;

enum StringType {
    IA5,
    UTF8,
    OCTET,
    BIT
};

struct SES_String {
    SES_String(const unsigned char* d, int length, StringType t = IA5)
    {
        this->data = string((const char*)d, length);
        this->type = t;
    }

    SES_String(unsigned char* d, int length, StringType t = IA5)
    {
        this->data = string((const char*)d, length);
        this->type = t;
    }

    SES_String(const char* d, int length, StringType t = IA5)
    {
        this->data = string(d, length);
        this->type = t;
    }

    SES_String(string d, StringType t = IA5)
    {
        this->data = d;
        this->type = t;
    }

    string data;
    StringType type/* = IA5*/;
};

struct SES_UTCTime {

    static SES_UTCTime* Parse(unsigned char* d, int length)
    {
        string utc((const char*)d, length);
        if (utc.at(utc.length() - 1) == 'Z')
        { //YYMMDDhhmmssZ
            SES_UTCTime* ut = new SES_UTCTime();
            sscanf(utc.data(), "%2d%2d%2d%2d%2d%2d",
                   &(ut->year), &(ut->month), &(ut->day),
                   &(ut->hour), &(ut->minute), &(ut->second));
            ut->year += 2000;
            return ut;
        }
        else if (utc.length() == 14)
        { //Unrecognized time: YYYYMMDDhhmmss
            SES_UTCTime* ut = new SES_UTCTime();
            sscanf(utc.data(), "%4d%2d%2d%2d%2d%2d",
                   &(ut->year), &(ut->month), &(ut->day),
                   &(ut->hour), &(ut->minute), &(ut->second));
            return ut;
        }
        cout << "Unrecognized time: " << utc << endl;
        return NULL;
    }

    int year, month, day;
    int hour, minute, second;

    void debug()
    {
        printf("20%d-%d-%d %d:%d:%d UTC\n", year, month, day, hour, minute, second);
    }
};

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

struct SES_ESPropertyInfo {
    ASN1_INTEGER* type;
    ASN1_UTF8STRING* name;
    list<ASN1_OCTET_STRING*> certList;
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
    list<ExtData*> extDatas;
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

    static void Init();
	static void CleanUp();
    static SESeal* Parse(string path);
    static SESeal* Parse(char* data, int len);
    static int EncodeSignature(long version, unsigned char* sealData, int sealDataLen,
		unsigned char* timeInfo, unsigned char* dataHash, unsigned char* propertyInfo,
		unsigned char* cert, unsigned char* signatureAlgorithm, unsigned char* signatureValue,
		string &SESSignature);
    static SES_Signature* DecodeSignature(char* data, int len);
    static string OIDToText(ASN1_OBJECT* oid);

	static SESeal* TGSealToSESeal(const TGSealInfo& sealInfo);
	static TGSealInfo* SESealToTGSeal(const SESeal& sealInfo);
private:
    static SES_SealInfo* DecodeSealInfo(ASN1_TYPE* at);
    static SES_SignInfo* DecodeSignInfo(ASN1_TYPE* at);
    static SES_Header* DecodeHeader(ASN1_TYPE* at);
    static SES_ESPropertyInfo* DecodeProperty(ASN1_TYPE* at);
    static SES_ESPictureInfo* DecodePicture(ASN1_TYPE* at);
    static ExtData* DecodeExtData(ASN1_TYPE* at);
    static TBS_Sign* DecodeTBSSign(ASN1_TYPE* at);
};

#endif // ESL_H
