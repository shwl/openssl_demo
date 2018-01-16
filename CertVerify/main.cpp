#include <iostream>
#include <crtdbg.h>
#include <vector>
#include <windows.h>

#include "openssl/x509v3.h"
#include "openssl/err.h"

#include "../ASN1Test/FileTools.h"
#include "../ASN1Test/Base64Tools.h"

using namespace std;

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	if (!ok)
	{
		/* check the error code and current cert*/
		X509 *currentCert = X509_STORE_CTX_get_current_cert(ctx);
		int certError = X509_STORE_CTX_get_error(ctx);
		int depth = X509_STORE_CTX_get_error_depth(ctx);
		printf("Error depth %d, certError %d\r\n", depth, certError);
		if (X509_V_ERR_CERT_SIGNATURE_FAILURE == certError)
		{
			unsigned char* out = NULL;
			int n = i2d_X509(currentCert, &out);
			char szFile[MAX_PATH] = {};
			static int index = 0;
			sprintf(szFile, "c:\\curcert_%d.cer", index++);
			WriteDataToFile((char*)out, n, szFile);
			OPENSSL_free(out);
			ok = 1;
		}
	}

	return(ok);
}


ULONG _GetExtCRLDistPoints(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen)
{
	int i = 0;
	int crit = 0;
	char value[512] = { 0 };
	CRL_DIST_POINTS *crlpoints = NULL;

	if (!pX509Cert)
	{
		return 1;
	}
	if (!pulLen)
	{
		return 2;
	}

	crlpoints = (CRL_DIST_POINTS*)X509_get_ext_d2i(pX509Cert, NID_crl_distribution_points, &crit, NULL);
	if (!crlpoints)
	{
		return 3;
	}

	for (i = 0; i < sk_DIST_POINT_num(crlpoints); i++)
	{
		int j, gtype;
		GENERAL_NAMES *gens;
		GENERAL_NAME *gen;
		ASN1_STRING *uri;
		DIST_POINT *dp = sk_DIST_POINT_value(crlpoints, i);
		if (!dp->distpoint || dp->distpoint->type != 0)
			continue;

		gens = dp->distpoint->name.fullname;
		for (j = 0; j < sk_GENERAL_NAME_num(gens); j++)
		{
			gen = sk_GENERAL_NAME_value(gens, j);
			uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);
			if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6)
			{
				char *uptr = (char *)ASN1_STRING_data(uri);
				if (strlen(value) > 0)
				{
					strcat_s(value, 512, " | ");
				}
				strcat_s(value, 512, uptr);
			}
		}
	}
	CRL_DIST_POINTS_free(crlpoints);

	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return 4;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return 0;
}

bool VerifyCert(const unsigned char* usercert, long usercertLen, const vector<string>& cacert)
{
	OpenSSL_add_all_algorithms();
	bool bRet = false;
	int ret = 0;
	X509_STORE_CTX *ctx = X509_STORE_CTX_new(); //证书上下文;
	X509_STORE *cert_store = X509_STORE_new(); //证书库，存在证书链;
	X509* user = NULL; //待验证X509证书;
	vector<X509*> cavec;
	char crlbuf[1024] = {};
	ULONG ulLen = _countof(crlbuf);
	
	d2i_X509(&user, &usercert, usercertLen);
	if (!user)
	{
		cout << "!x509" << endl;
		goto _error;
	}

	ret = _GetExtCRLDistPoints(user, crlbuf, &ulLen);

	X509_STORE_set_verify_cb(cert_store, verify_cb);
	for (auto it = cacert.begin(); it < cacert.end(); ++it)
	{
		const unsigned char* cdata = (const unsigned char*)it->c_str();
		long len = it->length();
		X509 *ca = NULL;
		d2i_X509(&ca, &cdata, len);
		if (!ca)
		{
			cout << "!ca" << endl;
			goto _error;
		}

		cavec.push_back(ca);
		//加入证书存储区;
		ret = X509_STORE_add_cert(cert_store, ca);
		if (ret != 1)
		{
			fprintf(stderr, "X509_STORE_add_cert fail, ret = %d\n", ret);
			goto _error;
		}
	}
// 	d2i_X509(&ca, &cacert, cacertLen);
// 	if (!ca)
// 	{
// 		cout << "!ca" << endl;
// 		goto _error;
// 	}
// 
// 	//加入证书存储区;
// 	ret = X509_STORE_add_cert(cert_store, ca);
// 	if (ret != 1)
// 	{
// 		fprintf(stderr, "X509_STORE_add_cert fail, ret = %d\n", ret);
// 		goto _error;
// 	}

	ret = X509_STORE_CTX_init(ctx, cert_store, user, NULL);
	if (ret != 1)
	{
		cout << "X509_STORE_CTX_init res:" << ret << endl;
		goto _error;
	}
	X509_STORE_CTX_set_flags(ctx, 0);
	ret = X509_verify_cert(ctx);//根据返回值可以确认X509证书是否有效，也可以根据X509_STORE_CTX_get_error和X509_verify_cert_error_string函数来确认无效原因;
	cout << "X509_verify_cert res:" << ret << endl;
	bRet = (1 == ret);
_error:
	if (1 != ret)
	{
		int err = X509_STORE_CTX_get_error(ctx);
		const char* errMsg = X509_verify_cert_error_string(err);
		cout << "error code:" << err << "\r\nerror msg:" << errMsg << endl;
	}

	X509_free(user);

	for (auto it = cavec.begin(); it < cavec.end(); ++it)
	{
		X509_free(*it._Ptr);
	}
	cavec.clear();
	
	//X509_free(ca);
	X509_STORE_CTX_cleanup(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(cert_store);
	
	return bRet;
}

int tX509_Verify()
{
	unsigned char usrCertificate1[4096];
	unsigned long usrCertificate1Len;
	unsigned char usrCertificate2[4096];
	unsigned long usrCertificate2Len;

	unsigned char derCrl[4096];
	unsigned long derCrlLen;
	unsigned char derRootCert[4096];
	unsigned long derRooCertLen;
	int i, rv;

	X509_STORE_CTX *ctx = NULL;
	X509 *usrCert1 = NULL;
	X509 *usrCert2 = NULL;
	X509 *caCert = NULL;
	X509 *rootCert = NULL;
	X509_CRL *Crl = NULL;
	STACK_OF(X509) *caCertStack = NULL;
	X509_STORE *rootCertStore = NULL;
	int j = 0;
	unsigned char *pTmp = NULL;
	FILE *fp;

	fp = fopen("RayCA.cert.cer", "rb");
	if (fp == NULL){
		perror("open file failed\n");
		return -1;
	}

	derRooCertLen = fread(derRootCert, 1, 4096, fp);
	fclose(fp);

	fp = fopen("crl.crl", "rb");
	if (fp == NULL){
		perror("open file failed\n");
		return -1;
	}

	derCrlLen = fread(derCrl, 1, 4096, fp);
	fclose(fp);


	fp = fopen("sangerhoo_req.pem.cert.cer", "rb");
	if (fp == NULL){
		perror("open file failed\n");
		return -1;
	}
	usrCertificate1Len = fread(usrCertificate1, 1, 4096, fp);
	fclose(fp);


	fp = fopen("myserver.cert.cer", "rb");
	if (fp == NULL){
		perror("open file failed\n");
		return -1;
	}

	usrCertificate2Len = fread(usrCertificate2, 1, 4096, fp);
	fclose(fp);


	printf("1\n");
	pTmp = derRootCert;
	rootCert = d2i_X509(NULL, (unsigned const char **)&pTmp, derRooCertLen);
	if (NULL == rootCert){
		printf("d2i_X509 failed1,ERR_get_error=%s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	printf("2\n");
	pTmp = usrCertificate1;
	usrCert1 = d2i_X509(NULL, (unsigned const char **)&pTmp, usrCertificate1Len);
	if (usrCert1 == NULL){
		perror("d2i_X509 failed\n");
		return -1;
	}
	printf("3\n");
	pTmp = usrCertificate2;
	usrCert2 = d2i_X509(NULL, (unsigned const char **)&pTmp, usrCertificate2Len);
	if (usrCert2 == NULL){
		perror("d2i_X509 failed\n");
		return -1;
	}
	printf("4\n");
	pTmp = derCrl;
	Crl = d2i_X509_CRL(NULL, (unsigned const char **)&pTmp, derCrlLen);
	if (Crl == NULL){
		perror("d2i_X509 failed\n");
		return -1;
	}
	printf("5\n");
	rootCertStore = X509_STORE_new();
	X509_STORE_add_cert(rootCertStore, rootCert);
	X509_STORE_set_flags(rootCertStore, X509_V_FLAG_CRL_CHECK);
	X509_STORE_add_crl(rootCertStore, Crl);
	printf("6\n");
	rv = X509_STORE_CTX_init(ctx, rootCertStore, usrCert1, caCertStack);
	printf("1234\n");
	if (rv != 1){
		perror("X509_STORE_CTX_init failed\n");
		X509_free(usrCert1);
		X509_free(usrCert2);
		X509_free(rootCert);
		X509_STORE_CTX_cleanup(ctx);
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(rootCertStore);
		return -1;
	}


	rv = X509_verify_cert(ctx);
	if (rv != 1){
		printf("verify usercert1 failed err=%d,info:%s\n", ctx->error, X509_verify_cert_error_string(ctx->error));
	}
	else{
		printf("verify usercert1 ok\n");
	}


	rv = X509_STORE_CTX_init(ctx, rootCertStore, usrCert2, caCertStack);
	if (rv != 1){
		perror("X509_STORE_CTX_init failed\n");
		X509_free(usrCert1);
		X509_free(usrCert2);
		X509_free(rootCert);
		X509_STORE_CTX_cleanup(ctx);
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(rootCertStore);
		return -1;
	}


	rv = X509_verify_cert(ctx);
	if (rv != 1){
		printf("verify usercert2 failed err=%d,info:%s\n", ctx->error, X509_verify_cert_error_string(ctx->error));
	}
	else{
		printf("verify usercert2 ok\n");
	}


	X509_free(usrCert1);
	X509_free(usrCert2);
	X509_free(rootCert);
	X509_STORE_CTX_cleanup(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(rootCertStore);
	return 0;

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
			vector<string> vacertvec;
			do 
			{
				string cacertB64 = ReadFile(argv[++index]);
				string cacert = Base64Tools::base64_decode(cacertB64);
				vacertvec.push_back(cacert);
			} while (index + 1 < argc);
			
			VerifyCert((unsigned char*)cert.c_str(), cert.length(), vacertvec);
		} while (count++ < 0);
	}
	
	getchar();
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	return 0;
}