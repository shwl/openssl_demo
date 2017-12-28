#include "esl.h"
#include "Base64Tools.h"

inline asn1_string_st* toAsn1String(asn1_string_st** str, const string& value, int type = V_ASN1_IA5STRING)
{
	if (!*str){
		*str = ASN1_STRING_type_new(type);
	}
	int len = value.length();
	ASN1_STRING_set(*str, (void*)value.c_str(), len);
	return *str;
}

inline asn1_string_st* toAsn1String(asn1_string_st** str, const int value, int type = V_ASN1_INTEGER)
{
	char buf[256] = {};
	sprintf(buf, "%d", value);
	return toAsn1String(str, buf, type);
}

inline asn1_object_st* toAsn1Object(asn1_object_st** obj, const string& value)
{
	if (!*obj){
		*obj = ASN1_OBJECT_new();
	}
	const unsigned char* buf = (unsigned char*)value.c_str();
	c2i_ASN1_OBJECT(obj, &buf, value.length());
	return *obj;
}

ASN1_SEQUENCE(SES_Header) = {
	ASN1_SIMPLE(SES_Header, ID, ASN1_IA5STRING),
	ASN1_SIMPLE(SES_Header, version, ASN1_INTEGER),
	ASN1_SIMPLE(SES_Header, vid, ASN1_IA5STRING),
} ASN1_SEQUENCE_END(SES_Header);
IMPLEMENT_ASN1_FUNCTIONS(SES_Header)

ASN1_SEQUENCE(ExtData) = {
	ASN1_SIMPLE(ExtData, extnID, ASN1_OBJECT),
	ASN1_SIMPLE(ExtData, critical, ASN1_BOOLEAN),
	ASN1_SIMPLE(ExtData, extnValue, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(ExtData);
IMPLEMENT_ASN1_FUNCTIONS(ExtData)

ASN1_ITEM_TEMPLATE(ExtDatas) =
ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, TGExtData, ExtData)
ASN1_ITEM_TEMPLATE_END(ExtDatas)
IMPLEMENT_ASN1_FUNCTIONS(ExtDatas)

ASN1_ITEM_TEMPLATE(SEQUENCE_CERTLIST) =
ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, TGCertList, ASN1_OCTET_STRING)
ASN1_ITEM_TEMPLATE_END(SEQUENCE_CERTLIST)
IMPLEMENT_ASN1_FUNCTIONS(SEQUENCE_CERTLIST)

ASN1_SEQUENCE(SES_ESPropertyInfo) = {
	ASN1_SIMPLE(SES_ESPropertyInfo, type, ASN1_INTEGER),
	ASN1_SIMPLE(SES_ESPropertyInfo, name, ASN1_UTF8STRING),
	ASN1_SIMPLE(SES_ESPropertyInfo, certList, SEQUENCE_CERTLIST),
	ASN1_SIMPLE(SES_ESPropertyInfo, createDate, ASN1_UTCTIME),
	ASN1_SIMPLE(SES_ESPropertyInfo, validStart, ASN1_UTCTIME),
	ASN1_SIMPLE(SES_ESPropertyInfo, validEnd, ASN1_UTCTIME),
} ASN1_SEQUENCE_END(SES_ESPropertyInfo);
IMPLEMENT_ASN1_FUNCTIONS(SES_ESPropertyInfo)

ASN1_SEQUENCE(SES_ESPictureInfo) = {
	ASN1_SIMPLE(SES_ESPictureInfo, type, ASN1_IA5STRING),
	ASN1_SIMPLE(SES_ESPictureInfo, data, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SES_ESPictureInfo, width, ASN1_INTEGER),
	ASN1_SIMPLE(SES_ESPictureInfo, height, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SES_ESPictureInfo);
IMPLEMENT_ASN1_FUNCTIONS(SES_ESPictureInfo)

ASN1_SEQUENCE(SES_SealInfo) = {
	ASN1_SIMPLE(SES_SealInfo, header, SES_Header),
	ASN1_SIMPLE(SES_SealInfo, esID, ASN1_IA5STRING),
	ASN1_SIMPLE(SES_SealInfo, property, SES_ESPropertyInfo),
	ASN1_SIMPLE(SES_SealInfo, picture, SES_ESPictureInfo),
	ASN1_SIMPLE(SES_SealInfo, extDatas, ExtDatas),
} ASN1_SEQUENCE_END(SES_SealInfo);
IMPLEMENT_ASN1_FUNCTIONS(SES_SealInfo)

ASN1_SEQUENCE(SES_SignInfo) = {
	ASN1_SIMPLE(SES_SignInfo, cert, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SES_SignInfo, signatureAlgorithm, ASN1_OBJECT),
	ASN1_SIMPLE(SES_SignInfo, signData, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SES_SignInfo);
IMPLEMENT_ASN1_FUNCTIONS(SES_SignInfo)

ASN1_SEQUENCE(SESeal) = {
	ASN1_SIMPLE(SESeal, sealInfo, SES_SealInfo),
	ASN1_SIMPLE(SESeal, signInfo, SES_SignInfo),
} ASN1_SEQUENCE_END(SESeal);
IMPLEMENT_ASN1_FUNCTIONS(SESeal)

ASN1_SEQUENCE(TBS_Sign) = {
	ASN1_SIMPLE(TBS_Sign, version, ASN1_INTEGER),
	ASN1_SIMPLE(TBS_Sign, seal, SESeal),
	ASN1_SIMPLE(TBS_Sign, timeInfo, ASN1_BIT_STRING),
	ASN1_SIMPLE(TBS_Sign, dataHash, ASN1_BIT_STRING),
	ASN1_SIMPLE(TBS_Sign, propertyInfo, ASN1_IA5STRING),
	ASN1_SIMPLE(TBS_Sign, cert, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TBS_Sign, signatureAlgorithm, ASN1_OBJECT),
} ASN1_SEQUENCE_END(TBS_Sign);
IMPLEMENT_ASN1_FUNCTIONS(TBS_Sign)

ASN1_SEQUENCE(SES_Signature) = {
	ASN1_SIMPLE(SES_Signature, toSign, TBS_Sign),
	ASN1_SIMPLE(SES_Signature, signature, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SES_Signature);
IMPLEMENT_ASN1_FUNCTIONS(SES_Signature)

ESL::ESL()
{
	Init();
}

ESL::~ESL()
{
	CleanUp();
}

void ESL::Init()
{
    CRYPTO_malloc_init();
    OpenSSL_add_all_algorithms();
}

void ESL::CleanUp()
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

SESeal* ESL::Parse(string path)
{
    BIO* in = BIO_new(BIO_s_file());
    if (in == NULL)
    {
        return NULL;
    }
    if (BIO_read_filename(in, path.data()) <= 0)
    {
        return NULL;
    }
    BUF_MEM* buf = BUF_MEM_new();
    if (buf == NULL)
    {
        return NULL;
    }
    if (!BUF_MEM_grow(buf, BUFSIZ * 8))
    {
        return NULL; /* Pre-allocate :-) */
    }
    long num = 0;
    for (;;)
    {
        if (!BUF_MEM_grow(buf, (int)num + BUFSIZ))
        {
            return NULL;
        }
        int i = BIO_read(in, &(buf->data[num]), BUFSIZ);
        if (i <= 0)
        {
            break;
        }
        num += i;
    }
    char* data = buf->data;

	SESeal* seal = Parse(data, num);

    BIO_free(in);
    BUF_MEM_free(buf);

    return seal;
}

SESeal* ESL::Parse(char* data, int len)
{
	SESeal* seal = nullptr;
	d2i_SESeal(&seal, (const unsigned char**)&data, len);
    return seal;
}

SES_Signature* ESL::EncodeSignature(long version, const string& sealData, const string& timeInfo, const string& dataHash,
	const string& propertyInfo, const string& cert, const string& signatureAlgorithm, const string& signatureValue)
{
	SES_Signature* sessignature = SES_Signature_new();
	TBS_Sign* pToSign = sessignature->toSign;
	toAsn1String(&pToSign->cert, version);
	const char* pSealData = sealData.c_str();
	d2i_SESeal(&pToSign->seal, (const unsigned char**)&pSealData, sealData.length());
	toAsn1String(&pToSign->timeInfo, timeInfo, V_ASN1_BIT_STRING);
	toAsn1String(&pToSign->dataHash, dataHash, V_ASN1_BIT_STRING);
	toAsn1String(&pToSign->propertyInfo, propertyInfo, V_ASN1_IA5STRING);
	toAsn1String(&pToSign->cert, cert, V_ASN1_OCTET_STRING);
	toAsn1Object(&pToSign->signatureAlgorithm, signatureAlgorithm);

	toAsn1String(&sessignature->signature, signatureValue, V_ASN1_BIT_STRING);
	return sessignature;
}

SES_Signature* ESL::DecodeSignature(char* data, int len)
{
	SES_Signature* signatureses = nullptr;
	d2i_SES_Signature(&signatureses, (const unsigned char**)&data, len);
    return signatureses;
}

SESeal* ESL::TGSealToSESeal(const TGSealInfo &sealInfo)
{
	SESeal* seSeal = SESeal_new();
	SES_SealInfo *sesSealInfo = seSeal->sealInfo;
	SES_Header *header = sesSealInfo->header;
	SES_ESPropertyInfo* property = sesSealInfo->property;
	SES_ESPictureInfo* picture = sesSealInfo->picture;
	SES_SignInfo *sesSignInfo = seSeal->signInfo;

	header->ID = toAsn1String(&header->ID, sealInfo.strID, V_ASN1_IA5STRING);
	header->version = toAsn1String(&header->version, sealInfo.strSealVersion, V_ASN1_INTEGER);
	header->vid = toAsn1String(&header->vid, sealInfo.strSealVid, V_ASN1_IA5STRING);

	sesSealInfo->esID = toAsn1String(&sesSealInfo->esID, sealInfo.strSealVid, V_ASN1_IA5STRING);
	
	property->type = toAsn1String(&property->type, sealInfo.nType, V_ASN1_INTEGER);
	property->name = toAsn1String(&property->name, sealInfo.strName, V_ASN1_UTF8STRING);
	ASN1_OCTET_STRING* cert = nullptr;
	cert = toAsn1String(&cert, sealInfo.strSealCertB64, V_ASN1_OCTET_STRING);
	SKM_sk_push(ASN1_OCTET_STRING, property->certList, cert);
	property->createDate = toAsn1String(&property->createDate, sealInfo.strSealCreateData, V_ASN1_UTCTIME);
	property->validStart = toAsn1String(&property->validStart, sealInfo.strSealValidStart, V_ASN1_UTCTIME);
	property->validEnd = toAsn1String(&property->validEnd, sealInfo.strSealValidEnd, V_ASN1_UTCTIME);

	picture->type = toAsn1String(&picture->type, sealInfo.nType, V_ASN1_INTEGER);
	string strImgData = Base64Tools::base64_decode(sealInfo.strImgBase64);
	picture->data = toAsn1String(&picture->data, strImgData, V_ASN1_OCTET_STRING);
	picture->width = toAsn1String(&picture->width, sealInfo.nImageWidth, V_ASN1_INTEGER);
	picture->height = toAsn1String(&picture->height, sealInfo.nImageHeight, V_ASN1_INTEGER);
	
	string strCertData = Base64Tools::base64_decode(sealInfo.strSealCertB64);
	sesSignInfo->cert = toAsn1String(&sesSignInfo->cert, strCertData, V_ASN1_OCTET_STRING);
	sesSignInfo->signatureAlgorithm = toAsn1Object(&sesSignInfo->signatureAlgorithm, sealInfo.strSealSignAlgo);
	sesSignInfo->signData = toAsn1String(&sesSignInfo->signData, sealInfo.strSealSignRes, V_ASN1_BIT_STRING);

	ExtData* ext = ExtData_new();
	ext->extnID = toAsn1Object(&ext->extnID, "TG_Extn_ID");
	ext->critical = 0;
	ext->extnValue = toAsn1String(&ext->extnValue, "TG_Extn_Value", V_ASN1_OCTET_STRING);
	SKM_sk_push(ExtData, sesSealInfo->extDatas, ext);

	return seSeal;
}

#define TG_GETASN1VALUE(data, i2dfunc) string str; \
	unsigned char* out = nullptr; \
	int nLen = i2dfunc(data, &out); \
	str.append((char*)out, nLen); \
	OPENSSL_free(out); \
	return str;

string ESL::GetValue(SESeal* seseal)
{
	TG_GETASN1VALUE(seseal, i2d_SESeal);
}

string ESL::GetValue(TBS_Sign* tbssign)
{
	TG_GETASN1VALUE(tbssign, i2d_TBS_Sign);
}

string ESL::GetValue(SES_Signature* sessignature)
{
	TG_GETASN1VALUE(sessignature, i2d_SES_Signature);
}

void ESL::Free(SESeal** seseal)
{
	SESeal_free(*seseal);
	*seseal = nullptr;
}

void ESL::Free(SES_Signature** sessignature)
{
	SES_Signature_free(*sessignature);
	*sessignature = nullptr;
}