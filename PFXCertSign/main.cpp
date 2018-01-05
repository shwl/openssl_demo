
#define  _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/applink.c>

bool DoSignData(const char* szPKCS12FileName, const char* szPKCS12Password,
	const char* szUnSignData, char* szSignData)
{
	if (szPKCS12FileName == NULL || szUnSignData == NULL || szSignData == NULL) {
		return false;
	}
	/*变量*/
	int            err;
	unsigned int   sig_len;
	unsigned char sig_buf[256];
	EVP_MD_CTX     md_ctx;
	EVP_PKEY *     pkey = NULL;
	FILE *     fp = NULL;
	X509 *     x509 = NULL;
	PKCS12*     p12 = NULL;
	STACK_OF(X509) *ca = NULL;
	/*初始化*/
	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();
	/*读取个人信息证书并分解出密钥和证书*/
	if (!(fp = fopen(szPKCS12FileName, "rb"))) {
		return false;
	}
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		fprintf(stderr, "Error reading PKCS#12 file/n");
		ERR_print_errors_fp(stderr);
		return false;
	}
	if (!PKCS12_parse(p12, szPKCS12Password, &pkey, &x509, &ca)) {
		fprintf(stderr, "Error parsing PKCS#12 file/n");
		ERR_print_errors_fp(stderr);
		PKCS12_free(p12);
		return false;
	}
	PKCS12_free(p12);
	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		return false;
	}
	/*签名数据*/
	EVP_SignInit(&md_ctx, EVP_sha1());
	EVP_SignUpdate(&md_ctx, szUnSignData, strlen(szUnSignData));
	sig_len = _countof(sig_buf);
	err = EVP_SignFinal(&md_ctx, sig_buf, &sig_len, pkey);
	if (err != 1) {
		ERR_print_errors_fp(stderr);
		/*释放相关变量*/
		if (pkey) {
			EVP_PKEY_free(pkey);
		}
		if (x509) {
			X509_free(x509);
		}
		return false;
	}
	memcpy(szSignData, sig_buf, sig_len);
	/*释放相关变量*/
	if (pkey) {
		EVP_PKEY_free(pkey);
	}
	if (x509) {
		X509_free(x509);
	}
	return true;
}
bool DoVerifyData(const char* szPKCS12FileName, const char* szPKCS12Password,
	const char* szUnSignData, const char* szSignData)
{
	if (szPKCS12FileName == NULL || szSignData == NULL) {
		return false;
	}
	/*变量*/
	int            err;
	unsigned int   sig_len;
	EVP_MD_CTX     md_ctx;
	EVP_PKEY *     pkey = NULL;
	FILE *     fp = NULL;
	X509 *     x509 = NULL;
	PKCS12*     p12 = NULL;
	STACK_OF(X509) *ca = NULL;
	/*初始化*/
	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();
	/*读取个人信息证书并分解出密钥和证书*/
	if (!(fp = fopen(szPKCS12FileName, "rb"))) {
		return false;
	}
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		fprintf(stderr, "Error reading PKCS#12 file/n");
		ERR_print_errors_fp(stderr);
		return false;
	}
	if (!PKCS12_parse(p12, szPKCS12Password, &pkey, &x509, &ca)) {
		fprintf(stderr, "Error parsing PKCS#12 file/n");
		ERR_print_errors_fp(stderr);
		PKCS12_free(p12);
		return false;
	}
	PKCS12_free(p12);
	if (x509 == NULL) {
		ERR_print_errors_fp(stderr);
		return false;
	}
	/*验证签名*/
	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		if (x509) {
			X509_free(x509);
		}
		return false;
	}
	/* Verify the signature */
	sig_len = 256;
	EVP_VerifyInit(&md_ctx, EVP_sha1());
	EVP_VerifyUpdate(&md_ctx, szUnSignData, strlen(szUnSignData));
	err = EVP_VerifyFinal(&md_ctx, (const BYTE*)szSignData, sig_len, pkey);
	EVP_PKEY_free(pkey);
	if (err != 1) {
		ERR_print_errors_fp(stderr);
		/*释放相关变量*/
		if (pkey) {
			EVP_PKEY_free(pkey);
		}
		return false;
	}
	/*释放相关变量*/
	if (pkey) {
		EVP_PKEY_free(pkey);
	}
	return true;
}
int main(int argc, char* argv[])
{
	char sig_buf[256];
	const char* certFile = "1.Pfx";
	const char* certPsw = "";
	if (!DoSignData(certFile, certPsw, "hi there, i love juan.", sig_buf)) {
		printf("Signature Data Failed./n");
	}
	else{
		printf("Signature Data Success./n");
		printf(">------------after sign data--------------begin/n");
		for (int i = 0; i < 256; i++)
		{
			printf("%02x", sig_buf[i]);
		}
		printf("/n>------------after sign data--------------end/n");
		if (!DoVerifyData(certFile, certPsw, "hi there, i love juan.", sig_buf)) {
			printf("Signature Verified Failed./n");
		}
		else{
			printf("Signature Verified Ok./n");
		}
	}
	return 0;
}