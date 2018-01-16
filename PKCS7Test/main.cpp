#define  _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <crtdbg.h>

#include <openssl/pkcs7.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include "Base64Tools.h"

using namespace std;

long WriteDataToFile(const char* data, long dataLen = -1, char* fileName = nullptr)
{
	bool bFlag = false;
	long lRes = 0;
	if (!fileName)
	{
		fileName = "c:\\pkcs7test.log";
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

int Openssl_Verify(unsigned char* signature_msg, unsigned int length)
{
	unsigned char message[1024] = "12345678";
	int message_length = 0;

	const unsigned char* p_signature_msg = signature_msg; //这里很重要，不然会修改signature_msg指针地址导致释放出问题;

	//DER编码转换为PKCS7结构体
	PKCS7* p7 = d2i_PKCS7(NULL, &p_signature_msg, length);

	if (p7 == NULL)
	{
		printf("error.\n");

		return 0;
	}

	//解析出原始数据;
	BIO *p7bio = PKCS7_dataDecode(p7, NULL, NULL, NULL);
	if (!p7bio)
	{
		p7bio = BIO_new_mem_buf(message, strlen((char*)message));
	}
	//从BIO中读取原始数据,这里是明文;
	message_length = BIO_read(p7bio, message, 1024);

	//获得签名者信息stack;
	STACK_OF(PKCS7_SIGNER_INFO) *sk = PKCS7_get_signer_info(p7);

	//获得签名者个数，可以有多个签名者;
	int signCount = sk_PKCS7_SIGNER_INFO_num(sk);

	for (int i = 0; i < signCount; i++)
	{
		//获得签名者信息;
		PKCS7_SIGNER_INFO *signInfo = sk_PKCS7_SIGNER_INFO_value(sk, i);

		//获得签名者证书;
		X509 *cert = PKCS7_cert_from_signer_info(p7, signInfo);

		//验证签名;
		if (PKCS7_signatureVerify(p7bio, p7, signInfo, cert) != 1)
		{
			printf("signature verify error.\n");

			return 0;
		}
	}

	return 1;
}

/*
PKCS7Sign.cpp
Auth：Kagula
功能：调用OpenSSL实现数字签名功能例程（二）
环境：VS2008+SP1,OpenSSL1.0.1
*/

/*
功能：初始化OpenSSL
*/
void InitOpenSSL()
{
	CRYPTO_malloc_init();
	/* Just load the crypto library error strings,
	* SSL_load_error_strings() loads the crypto AND the SSL ones */
	/* SSL_load_error_strings();*/
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
}

/*
功能：对明文进行签名
入口：
char*certFile    证书（例如：xxx.pfx）
char* pwd        证书的密码
char* plainText  待签名的字符串
int flag         签名方式
出口：
char *           签名后的数据以BASE64形式返回
使用完毕后，必须用free函数释放。
*/

string PKCS7_GetSign(char*certFile, char* pwd, char* plainText, int flag)
{
	//取PKCS12對象
	FILE* fp;
	if (!(fp = fopen(certFile, "rb")))
	{
		fprintf(stderr, "Error opening file %s\n", certFile);
		return NULL;
	}
	PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		fprintf(stderr, "Error reading PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	//取pkey對象、X509證書、證書鏈
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	STACK_OF(X509) *ca = NULL;
	if (!PKCS12_parse(p12, pwd, &pkey, &x509, &ca)) {
		fprintf(stderr, "Error parsing PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	PKCS12_free(p12);

	//明文轉為BIO對象
	//《vc++网络安全编程范例（14）-openssl bio编程 》   http://www.2cto.com/kf/201112/115018.html
// 	BIO *bio = BIO_new(BIO_s_mem());
// 	BIO_puts(bio, plainText);
	int textLen = strlen(plainText);
	BIO *bio = BIO_new_mem_buf(plainText, textLen);

	//數字簽名
	//PKCS7_NOCHAIN:签名中不包含证书链，第三个参数为NULL值的话，可不加这个FLAG标记
	//PKCS7_NOSMIMECAP:签名不需要支持SMIME
	PKCS7* pkcs7 = PKCS7_sign(x509, pkey, ca, bio, flag);
	if (pkcs7 == NULL)
	{
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	//共有两种编码，一种是ASN1，另一种是DER编码。
	//取數據簽名(DER格式)
	//openssl学习笔记之pkcs7-data内容类型的编码解码
	//http://ipedo.i.sohu.com/blog/view/114822358.htm
	//入口：pkcs7对象
	//出口:der对象
	unsigned char *der;
	unsigned char *derTmp;
	unsigned long derlen;
	derlen = i2d_PKCS7(pkcs7, NULL);

	der = (unsigned char *)malloc(derlen);
	memset(der, 0, derlen);
	derTmp = der;
	i2d_PKCS7(pkcs7, &derTmp);

	auto a = Openssl_Verify(der, derlen);
	//DER转BASE64
	string str = Base64Tools::base64_encode(der, derlen);
	free(der);
	return str;
}

/*
功能：验证签名
入口：
char*certFile    证书（含匙）
char* plainText  明文
char* cipherText 签名
出口：
bool true  签名验证成功
bool false 验证失败
*/
bool PKCS7_VerifySign(char*certFile, char* plainText, char* cipherText)
{
	/* Get X509 */
// 	FILE* fp = fopen(certFile, "r");
// 	if (fp == NULL)
// 		return false;
// 	X509* x509 = PEM_read_X509(fp, NULL, NULL, NULL);
// 	fclose(fp);
// 
// 	if (x509 == NULL) {
// 		ERR_print_errors_fp(stderr);
// 		return false;
// 	}

	//BASE64解码
	unsigned char *retBuf[1024 * 8];
	int retBufLen = sizeof(retBuf);
	memset(retBuf, 0, sizeof(retBuf));
	string str = Base64Tools::base64_decode(cipherText);
	memcpy_s(retBuf, retBufLen, str.c_str(), str.length());
	retBufLen = str.length();

	//从签名中取PKCS7对象
	BIO* vin = BIO_new_mem_buf(retBuf, retBufLen);
	PKCS7 *p7 = d2i_PKCS7_bio(vin, NULL);



	//取STACK_OF(X509)对象
// 	STACK_OF(X509) *stack = sk_X509_new_null();//X509_STORE_new()
// 	sk_X509_push(stack, x509);


	//明码数据转为BIO
// 	BIO *bio = BIO_new(BIO_s_mem());
// 	BIO_puts(bio, plainText);
	int textLen = strlen(plainText);
	BIO *bio = BIO_new_mem_buf(plainText, textLen);

	//获得签名者信息stack;
	STACK_OF(PKCS7_SIGNER_INFO) *sk = PKCS7_get_signer_info(p7);

	//获得签名者个数，可以有多个签名者;
	int signCount = sk_PKCS7_SIGNER_INFO_num(sk);

	for (int i = 0; i < signCount; i++)
	{
		//获得签名者信息;
		PKCS7_SIGNER_INFO *signInfo = sk_PKCS7_SIGNER_INFO_value(sk, i);

		//获得签名者证书;
		X509 *cert = PKCS7_cert_from_signer_info(p7, signInfo);

		STACK_OF(X509) *stack = sk_X509_new_null();//X509_STORE_new()
		sk_X509_push(stack, cert);

		//验证签名
		int err = PKCS7_verify(p7, stack, NULL, bio, NULL, 0);

		if (err != 1) {
			ERR_print_errors_fp(stderr);
			return false;
		}
	}

	return true;
}

string PKCS7_Test(const char* signCertData, unsigned long ulCertLen)
{
	string strRes;
	unsigned char *der = NULL;
	unsigned long derlen = 0;
	X509 * signcert = NULL;
	EVP_MD *md = NULL;
	PKCS7_SIGNER_INFO *si = NULL;

	PKCS7 *p7 = PKCS7_new();

	if (!PKCS7_set_type(p7, NID_pkcs7_signed))
		goto err;

	if (!PKCS7_content_new(p7, NID_pkcs7_data))
		goto err;

	if (!d2i_X509(&signcert, (const unsigned char**)&signCertData, ulCertLen))
		goto err;

	if (!PKCS7_add_certificate(p7, signcert))
		goto err;

	md = (EVP_MD*)EVP_sha1();
	
	if ((si = PKCS7_SIGNER_INFO_new()) == NULL)
		goto err;

// 	if (!PKCS7_SIGNER_INFO_set(si, signcert, pkey, md))
// 		goto err;

	if (!PKCS7_add_signer(p7, si))
		goto err;

	derlen = i2d_PKCS7(p7, &der);
	strRes = Base64Tools::base64_encode(der, derlen);
	
err:
	if (signcert){
		X509_free(signcert);
	}
	if (der){
		OPENSSL_free(der);
	}
	if (p7){
		PKCS7_free(p7);
	}
	
	return strRes;
}
int main(int argc, char* argv[])
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
	//_CrtSetBreakAlloc(219);
	string signcert;
	const int signcertID = 2;
	if (argc > signcertID)
	{
		string signcertB64 = ReadFile(argv[signcertID]);
		signcert = Base64Tools::base64_decode(signcertB64);
	}
	string res = PKCS7_Test(signcert.c_str(), signcert.length());
	cout << res.c_str() << endl;
#if 1
	char certFile[] = "1.pfx";
	char plainText[] = "Hello,World!";

	InitOpenSSL();

	//數字簽名
	//PKCS7_NOCHAIN:签名中不包含证书链
	//PKCS7_NOSMIMECAP:签名不需要支持SMIME
	string cipherText = PKCS7_GetSign(certFile, "", plainText, PKCS7_NOSMIMECAP);

	//打印出BASE64编码后的签名
	std::cout << cipherText << std::endl;

	string strB64 = cipherText;

	//验证数字签名
	if (PKCS7_VerifySign("", plainText, (char*)strB64.c_str()))
		std::cout << "Verify OK 1!" << std::endl;
	else
		std::cout << "Verify Failed 1!" << std::endl;

	if (argc > 1)
	{
		strB64 = ReadFile(argv[1]);

		//验证数字签名
		if (PKCS7_VerifySign("", plainText, (char*)strB64.c_str()))
			std::cout << "Verify OK 2!" << std::endl;
		else
			std::cout << "Verify Failed 2!" << std::endl;
	}
#endif
	
	//释放签名字符串（缓存）
/*	free(cipherText);*/

	//输入任意字符继续
	getchar();
	CRYPTO_cleanup_all_ex_data();
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	return 0;
}