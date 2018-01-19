#include <iostream>
#include <crtdbg.h>
#include <vector>
#include <windows.h>
#include <fstream>
#include <string>
#include <comutil.h>
#pragma comment(lib, "comsuppw.lib")

#include "openssl/x509v3.h"
#include "openssl/err.h"
#include "openssl/pem.h"

#include "../ASN1Test/FileTools.h"
#include "../ASN1Test/Base64Tools.h"

#include "TG_SM2Api.h"
#pragma comment(lib, "TG_SM2Api.lib")
#include "SKFAPI.h"

#define szOID_SM2_SM3	"1.2.156.10197.1.501"

using namespace std;

#define TG_GETASN1VALUE(data, i2dfunc, isToBase64) string str; \
	unsigned char* out = nullptr; \
	int nLen = i2dfunc(data, &out); \
    if(isToBase64){ \
        str = Base64Tools::base64_encode(out, nLen); \
    } \
    else{ \
        str.append((char*)out, nLen); \
    } \
	OPENSSL_free(out); \
	return str;

string GetValue(X509_CINF* cert_info, bool isToBase64)
{
	TG_GETASN1VALUE(cert_info, i2d_X509_CINF, isToBase64);
}

string GetValue(X509* cert, bool isToBase64)
{
	TG_GETASN1VALUE(cert, i2d_X509, true);
}

LONG BYTE2ECCSignature(BYTE* verify, ULONG iverifylen, PECCSIGNATUREBLOB signature)
{
	int i = 0;
	char* verify_FM = (char*)malloc(64 * sizeof(char));
	if (iverifylen == 64)
	{
		memcpy_s(verify_FM, 64, verify, iverifylen);
	}
	else if ((verify[4] == 0) && ((verify[5] & 0x80) != 0))
	{
		memcpy(verify_FM, verify + 5, 32);
		if ((verify[39] == 0) && ((verify[40] & 0x80) != 0))
		{
			memcpy(verify_FM + 32, verify + 40, 32);
		}
		else
		{
			memcpy(verify_FM + 32, verify + 39, 32);
		}
	}
	else
	{
		memcpy(verify_FM, verify + 4, 32);
		if ((verify[38] == 0) && ((verify[39] & 0x80) != 0))
		{
			memcpy(verify_FM + 32, verify + 39, 32);
		}
		else
		{
			memcpy(verify_FM + 32, verify + 38, 32);
		}
	}
	//转为国标可以识别的签名值;
	for (i = 0; i < ECC_MAX_XCOORDINATE_BITS_LEN / 8; i++)
	{
		signature->r[i] = 0;
		signature->s[i] = 0;
	}
	for (i = 0; i < 32; i++)
	{
		signature->r[i + 32] = verify_FM[i];
		signature->s[i + 32] = verify_FM[i + 32];
	}
	free(verify_FM);//释放堆内存;
	return 0;
}

LONG GetPubKey(ECCPUBLICKEYBLOB& ecc_pub_st, BYTE* szPubKeyData)
{
	LONG lRes = 0;
	memcpy(ecc_pub_st.XCoordinate + 32, szPubKeyData + 1, 32);
	memcpy(ecc_pub_st.YCoordinate + 32, szPubKeyData + 33, 32);
	ecc_pub_st.BitLen = 256;
	return lRes;
}

void GetHash(unsigned char* buf, int len, EVP_PKEY *pkey, ASN1_BIT_STRING *signature)
{
	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	
	const EVP_MD *type = EVP_get_digestbynid(NID_sha256);
	EVP_DigestInit_ex(&ctx, type, nullptr);
	EVP_DigestUpdate(&ctx, buf, len);
	unsigned char md[256] = {};
	unsigned int mdlen = _countof(md);
	int ret = EVP_DigestFinal_ex(&ctx, md, &mdlen);

	ret = EVP_DigestVerifyInit(&ctx, NULL, type, NULL, pkey);
	ret = EVP_DigestVerifyUpdate(&ctx, buf, len);
	ret = EVP_DigestVerifyFinal(&ctx, signature->data, (size_t)signature->length);

	EVP_MD_CTX_cleanup(&ctx);
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	if (!ok)
	{
		/* check the error code and current cert*/
		int depth = X509_STORE_CTX_get_error_depth(ctx);
#if 0
		X509 *currentCert = X509_STORE_CTX_get_current_cert(ctx);
#else
		X509 *currentCert = sk_X509_value(ctx->chain, depth);
#endif
		bool bFlag = false;
		if (currentCert)
		{
			char oid[128] = { 0 };
			ASN1_OBJECT* salg = currentCert->sig_alg->algorithm;
			if (salg)
			{
				OBJ_obj2txt(oid, _countof(oid), salg, 1);
				if (0 == strcmp(oid, szOID_SM2_SM3))
				{
					bFlag = true;
				}
			}
		}
		
		if (bFlag)
		{
			int certError = X509_STORE_CTX_get_error(ctx);
			
			printf("Error depth %d, certError %d\r\n", depth, certError);
			const char* errMsg = X509_verify_cert_error_string(certError);
			cout << "error code:" << certError << "\r\nerror msg:" << errMsg << endl;

			if (X509_V_ERR_CERT_SIGNATURE_FAILURE == certError ||
				X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY == certError)
			{
				int n = sk_X509_num(ctx->chain);
				X509 *issue = NULL;
				int ret = 0;
				for (size_t i = n - 1; i >= 0; i--)
				{
					issue = sk_X509_value(ctx->chain, i);
					ret = ctx->check_issued(ctx, currentCert, issue);
					if (1 == ret){
						break;
					}
				}

				if (1 == ret)
				{
					auto certb64 = GetValue(currentCert, true);
					string cinf = GetValue(currentCert->cert_info, false);
					ECCPUBLICKEYBLOB ecc_pub_st0 = { 0 };
					ECCSIGNATUREBLOB ecc_sign_st = { 0 };
					GetPubKey(ecc_pub_st0, issue->cert_info->key->public_key->data);
					auto errcode = BYTE2ECCSignature(currentCert->signature->data, currentCert->signature->length, &ecc_sign_st);
					auto signvalueb64 = Base64Tools::base64_encode(currentCert->signature->data, currentCert->signature->length);
					BYTE szHashData[256] = { 0 };
					DWORD dwHashDataLen = _countof(szHashData);
					const ULONG g_KeyLen = 16;
					BYTE m_bKey[64] = {};
					memcpy(m_bKey, "1234567812345678", g_KeyLen);
					HANDLE hHash = NULL;
					errcode |= TG_DigestInit(SGD_SM3, &ecc_pub_st0, m_bKey, g_KeyLen, &hHash);
					errcode |= TG_DigestUpdate(hHash, (BYTE*)cinf.c_str(), cinf.length());
					errcode |= TG_DigestFinal(hHash, szHashData, &dwHashDataLen);
					TG_CloseHandle(hHash, 0);
					errcode |= TG_ECCVerify(&ecc_pub_st0, szHashData, dwHashDataLen, &ecc_sign_st);
					if (0 == errcode){
						ok = 1;
					}
				}
			}
		}
	}

	return(ok);
}

#define BEGIN_CERTIFICATE		"-----BEGIN CERTIFICATE-----"
#define END_CERTIFICATE			"-----END CERTIFICATE-----"
//获取本地信任根证书;
X509_STORE *GetLocalRootCert(X509_STORE **cert_store)
{
	const char* lrcFile = R"(D:\Users\shwl\Desktop\tls-ca-bundle.pem)";

	ifstream readFile(lrcFile, ios::in);
	if (!readFile.is_open()){
		return NULL;
	}

	if (!*cert_store){
		*cert_store = X509_STORE_new();
	}
	if (!*cert_store){
		return NULL;
	}

	char buf[1024] = {};
	long len = _countof(buf);
	string tmp;
	while (!readFile.eof())
	{
		readFile.read(buf, len);
		streamsize readLen = readFile.gcount();
		tmp.append(buf, readLen);
		int pos = tmp.find(END_CERTIFICATE);
		if (string::npos != pos)
		{
			pos += strlen(END_CERTIFICATE);
			string tmp2 = tmp.substr(0, pos);
			tmp = tmp.substr(pos + 1, tmp.length());
			auto a = tmp2.length();
			int beglen = strlen(BEGIN_CERTIFICATE);
			int beginpos = tmp2.rfind(BEGIN_CERTIFICATE);
			if (string::npos != beginpos)
			{
				string certdata = tmp2.substr(beginpos, tmp2.length());
				BIO *bio = BIO_new_mem_buf((void*)certdata.c_str(), certdata.length());
				X509 *ca = PEM_read_bio_X509(bio, NULL, 0, NULL);
				if (ca)
				{
					if (1 != X509_STORE_add_cert(*cert_store, ca)){
						X509_free(ca);
					}
				}
				BIO_free_all(bio);
			}
		}
	}
	readFile.close();

	return *cert_store;
}

int VerifyCert(const unsigned char* usercert, long usercertLen)
{
	OpenSSL_add_all_algorithms();
	int ret = 0;
	X509_STORE_CTX *ctx = X509_STORE_CTX_new(); //证书上下文;
	X509_STORE *cert_store = NULL; //证书库，存在证书链;
	X509* user = NULL; //待验证X509证书;
	
	d2i_X509(&user, &usercert, usercertLen);
	if (!user){
		goto _error;
	}

	GetLocalRootCert(&cert_store);
	if (!cert_store)
	{
		ret = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
		goto _error;
	}
	X509_STORE_set_verify_cb(cert_store, verify_cb);

	ret = X509_STORE_CTX_init(ctx, cert_store, user, NULL);
	if (ret != 1){
		goto _error;
	}
	ret = X509_verify_cert(ctx);//根据返回值可以确认X509证书是否有效，也可以根据X509_STORE_CTX_get_error和X509_verify_cert_error_string函数来确认无效原因;
_error:
	if (1 == ret){
		ret = 0;
		cout << "Verification passed..." << endl;
	}
	else
	{
		cout << "Verification does not pass..." << endl;
		int err = X509_STORE_CTX_get_error(ctx);
		if (0 != err){
			ret = err;
		}
		const char* errMsg = X509_verify_cert_error_string(ret);
		cout << "error code:" << ret << "\r\nerror msg:" << errMsg << endl;
	}

	X509_free(user);
	X509_STORE_CTX_cleanup(ctx);
	X509_STORE_CTX_free(ctx);
	if (cert_store && cert_store->objs)
	{
		int n = SKM_sk_num(X509_OBJECT, cert_store->objs);
		for (int i = 0; i < n; i++)
		{
			X509_OBJECT* obj = SKM_sk_value(X509_OBJECT, cert_store->objs, i);
			if (obj){
				X509_OBJECT_free_contents(obj);
			}
		}
	}
	X509_STORE_free(cert_store);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return ret;
}

int main(int argc, char* argv[])
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);

	int index = 1;
	if (argc > index + 1)
	{
		int count = 0;
		do 
		{
			string certB64 = ReadFile(argv[index]);
			string cert = Base64Tools::base64_decode(certB64);
			VerifyCert((unsigned char*)cert.c_str(), cert.length());
		} while (count++ < 0);
	}
	
	getchar();
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	return 0;
}