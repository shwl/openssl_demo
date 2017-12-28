#include "esl.h"
#include "Base64Tools.h"

extern long WriteDataToFile(const char* data, long dataLen, char* fileName);

inline asn1_string_st* toAsn1String(asn1_string_st** str, const string& value, int type)
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
    STACK_OF(ASN1_TYPE) *root = ASN1_seq_unpack_ASN1_TYPE((const unsigned char*)data, len, d2i_ASN1_TYPE, ASN1_TYPE_free);

	SESeal* seal = nullptr;

    if (SKM_sk_num(ASN1_TYPE, root) == 2)
    {
		seal = new SESeal();
		seal->sealInfo = DecodeSealInfo(sk_ASN1_TYPE_value(root, 0));
		seal->signInfo = DecodeSignInfo(sk_ASN1_TYPE_value(root, 1));
    }
	else
	{
		cout << "ESL root must has 2 sequences" << endl;
	}

    SKM_sk_free(ASN1_TYPE, root);

    return seal;
}

SES_SealInfo* ESL::DecodeSealInfo(ASN1_TYPE* at)
{
    SES_SealInfo* info = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count >= 4 || count <= 5)
        {
            info = new SES_SealInfo();

            info->header = DecodeHeader(sk_ASN1_TYPE_value(st, 0));

//            ASN1_STRING* esID = sk_ASN1_TYPE_value(st, 1)->value.ia5string;
            info->esID = sk_ASN1_TYPE_value(st, 1)->value.ia5string;

            info->property = DecodeProperty(sk_ASN1_TYPE_value(st, 2));

            info->picture = DecodePicture(sk_ASN1_TYPE_value(st, 3));

            if (count == 5)
            {
                ASN1_TYPE* atc = sk_ASN1_TYPE_value(st, 4);
                if (ASN1_TYPE_get(atc) == V_ASN1_SEQUENCE)
                {
                    ASN1_STRING* seqc = atc->value.sequence;
                    const unsigned char* dc = (const unsigned char*)(seqc->data);
                    int lc = seqc->length;
                    STACK_OF(ASN1_TYPE) *stc = ASN1_seq_unpack_ASN1_TYPE(dc, lc, d2i_ASN1_TYPE, ASN1_TYPE_free);
                    int c = SKM_sk_num(ASN1_TYPE, stc);
                    for(int i = 0; i < c; i++)
                    {
                        ASN1_TYPE* extData = sk_ASN1_TYPE_value(stc, i);
                        //info->extDatas.push_back(DecodeExtData(extData));
                    }
                    SKM_sk_free(ASN1_TYPE, stc);
                }
                ASN1_TYPE_free(atc);
            }
        }
        SKM_sk_free(ASN1_TYPE, st);
    }
    ASN1_TYPE_free(at);
    return info;
}

SES_SignInfo* ESL::DecodeSignInfo(ASN1_TYPE* at)
{
    SES_SignInfo* info = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count == 3)
        {
            info = new SES_SignInfo();            
            info->cert = sk_ASN1_TYPE_value(st, 0)->value.octet_string;

            info->signatureAlgorithm = sk_ASN1_TYPE_value(st, 1)->value.object;

            info->signData = sk_ASN1_TYPE_value(st, 2)->value.bit_string;
        }
    }
    ASN1_TYPE_free(at);
    return info;
}

SES_Header* ESL::DecodeHeader(ASN1_TYPE* at)
{
    SES_Header* header = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count == 3)
        {
            header = new SES_Header();

            header->ID = sk_ASN1_TYPE_value(st, 0)->value.ia5string;

            ASN1_INTEGER* version = sk_ASN1_TYPE_value(st, 1)->value.integer;
            long v = ASN1_INTEGER_get(version);
            if (v == 0xffffffffL)
            {
                cout << "The ASN1 Integer is too large to fit in a long" << endl;
            }
            else
            {
                header->version = version;
            }

            header->vid = sk_ASN1_TYPE_value(st, 2)->value.ia5string;
        }

        SKM_sk_free(ASN1_TYPE, st);
    }
    ASN1_TYPE_free(at);
    return header;
}

SES_ESPropertyInfo* ESL::DecodeProperty(ASN1_TYPE* at)
{
    SES_ESPropertyInfo* property = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count == 6)
        {
            property = new SES_ESPropertyInfo();

            ASN1_INTEGER* type = sk_ASN1_TYPE_value(st, 0)->value.integer;
            long v = ASN1_INTEGER_get(type);
            if (v == 0xffffffffL)
            {
                cout << "The ASN1 Integer is too large to fit in a long" << endl;
            }
            else
            {
                property->type = type;
            }

            property->name = sk_ASN1_TYPE_value(st, 1)->value.utf8string;
            ASN1_TYPE* atc = sk_ASN1_TYPE_value(st, 2);
            if (ASN1_TYPE_get(atc) == V_ASN1_SEQUENCE)
            {
                ASN1_STRING* seqc = atc->value.sequence;
                const unsigned char* dc = (const unsigned char*)(seqc->data);
                int lc = seqc->length;
                STACK_OF(ASN1_TYPE) *stc = ASN1_seq_unpack_ASN1_TYPE(dc, lc, d2i_ASN1_TYPE, ASN1_TYPE_free);
                for(int i = 0; i < SKM_sk_num(ASN1_TYPE, stc); i++)
                {                    
                    //property->certList.push_back(sk_ASN1_TYPE_value(stc, i)->value.octet_string);
                }
                SKM_sk_free(ASN1_TYPE, stc);
            }
            ASN1_TYPE_free(atc);

            property->createDate = sk_ASN1_TYPE_value(st, 3)->value.utctime;

            property->validStart = sk_ASN1_TYPE_value(st, 4)->value.utctime;

            property->validEnd = sk_ASN1_TYPE_value(st, 5)->value.utctime;
        }

        SKM_sk_free(ASN1_TYPE, st);
    }
    ASN1_TYPE_free(at);
    return property;
}

SES_ESPictureInfo* ESL::DecodePicture(ASN1_TYPE* at)
{
    SES_ESPictureInfo* info = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count == 4)
        {
            info = new SES_ESPictureInfo();

            info->type = sk_ASN1_TYPE_value(st, 0)->value.ia5string;

            info->data = sk_ASN1_TYPE_value(st, 1)->value.octet_string;

            ASN1_INTEGER* width = sk_ASN1_TYPE_value(st, 2)->value.integer;
            long vw = ASN1_INTEGER_get(width);
            if (vw == 0xffffffffL)
            {
                cout << "The ASN1 Integer is too large to fit in a long" << endl;
            }
            else
            {
                info->width = width;
            }

            ASN1_INTEGER* height = sk_ASN1_TYPE_value(st, 3)->value.integer;
            long vh = ASN1_INTEGER_get(height);
            if (vh == 0xffffffffL)
            {
                cout << "The ASN1 Integer is too large to fit in a long" << endl;
            }
            else
            {
                info->height = height;
            }
        }

        SKM_sk_free(ASN1_TYPE, st);
    }
    ASN1_TYPE_free(at);
    return info;
}

ExtData* ESL::DecodeExtData(ASN1_TYPE* at)
{
    ExtData* ext = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count == 3)
        {
            ext = new ExtData();            
            ext->extnID = sk_ASN1_TYPE_value(st, 0)->value.object;
            ext->critical = sk_ASN1_TYPE_value(st, 1)->value.boolean;
            ext->extnValue = sk_ASN1_TYPE_value(st, 2)->value.octet_string;
        }

        SKM_sk_free(ASN1_TYPE, st);
    }
    ASN1_TYPE_free(at);
    return ext;
}

string ESL::OIDToText(ASN1_OBJECT *oid)
{
    char buff[1024];
    int l = OBJ_obj2txt(buff, 1024, oid, 0);
    return string((const char*)buff, l);
}

int ESL::EncodeSignature(long version, unsigned char* sealData, int sealDataLen,
	unsigned char* timeInfo, unsigned char* dataHash, unsigned char* propertyInfo,
	unsigned char* cert, unsigned char* signatureAlgorithm, unsigned char* signatureValue,
	string &SESSignature)
{
    SES_Signature* sessignature = new SES_Signature();
    TBS_Sign* pToSign = new TBS_Sign();

    pToSign->cert->data = cert;
    pToSign->cert->type = OCTET;
    pToSign->dataHash->data = dataHash;
    pToSign->dataHash->type = OCTET;
    pToSign->propertyInfo->data = propertyInfo;
    pToSign->propertyInfo->type = OCTET;
    SESeal* seal = Parse((char*)sealData, sealDataLen);
    pToSign->seal = seal;
    string s((const char*)signatureAlgorithm);
    pToSign->signatureAlgorithm->data = signatureAlgorithm;
    pToSign->timeInfo->data = timeInfo;
    pToSign->version->data = (unsigned char*)version;

    sessignature->toSign = pToSign;
    sessignature->signature->data = signatureValue;
    sessignature->signature->type = OCTET;
    return 0;
}

SES_Signature* ESL::DecodeSignature(char* data, int len)
{
    STACK_OF(ASN1_TYPE) *root = ASN1_seq_unpack_ASN1_TYPE((const unsigned char*)data, len, d2i_ASN1_TYPE, ASN1_TYPE_free);

    if (SKM_sk_num(ASN1_TYPE, root) != 2)
    {
        cout << "Signature root must has 2 sequences" << endl;
        return NULL;
    }

    SES_Signature* signatureses = new SES_Signature();
    signatureses->toSign = DecodeTBSSign(sk_ASN1_TYPE_value(root, 0));    
    signatureses->signature = sk_ASN1_TYPE_value(root, 1)->value.octet_string;
    SKM_sk_free(ASN1_TYPE, root);

    return signatureses;
}

TBS_Sign* ESL::DecodeTBSSign(ASN1_TYPE* at)
{
    TBS_Sign* tbs_sign = NULL;
    if (ASN1_TYPE_get(at) == V_ASN1_SEQUENCE)
    {
        ASN1_STRING* seq = at->value.sequence;
        const unsigned char* d = (const unsigned char*)(seq->data);
        int l = seq->length;

        STACK_OF(ASN1_TYPE) *st = ASN1_seq_unpack_ASN1_TYPE(d, l, d2i_ASN1_TYPE, ASN1_TYPE_free);

        int count = SKM_sk_num(ASN1_TYPE, st);
        if (count == 7)
        {
            tbs_sign = new TBS_Sign();

            ASN1_INTEGER* ver = sk_ASN1_TYPE_value(st, 0)->value.integer;
            long v = ASN1_INTEGER_get(ver);
            if (v == 0xffffffffL)
            {
                cout << "The ASN1 Integer is too large to fit in a long" << endl;
            }
            else
            {
                tbs_sign->version = ver;
            }
            ASN1_OCTET_STRING* sealA = sk_ASN1_TYPE_value(st, 1)->value.octet_string;
            tbs_sign->seal = Parse((char*)sealA->data,sealA->length);            
            tbs_sign->timeInfo = sk_ASN1_TYPE_value(st, 2)->value.utctime;
            tbs_sign->dataHash = sk_ASN1_TYPE_value(st, 3)->value.octet_string;
            tbs_sign->propertyInfo = sk_ASN1_TYPE_value(st, 4)->value.octet_string;
            tbs_sign->cert = sk_ASN1_TYPE_value(st, 5)->value.octet_string;
            tbs_sign->signatureAlgorithm = sk_ASN1_TYPE_value(st, 6)->value.object;
        }

        SKM_sk_free(ASN1_TYPE, st);
    }
    ASN1_TYPE_free(at);
    return tbs_sign;
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