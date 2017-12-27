//定义签名控件通用数据;
#ifndef _TGCommonInfo_H_
#define _TGCommonInfo_H_

#include "tgcommonbase.h"
#include "TGStringUtil.h"
#include  <string>
#include <list>
using namespace std;
#ifdef WIN32
#define TG_DLL_EXPORT	__declspec(dllexport)
#else
#define TG_DLL_EXPORT __attribute ((visibility("default")))
#endif

// ------------签名类型-begin------------;
//数据类型;
#define TGSIGN_TYPE_HASH	0x00000000		//哈希数据;
#define TGSIGN_TYPE_DATA	0x00000001		//二进制;
#define TGSIGN_TYPE_FILE	0x00000002		//文件;

#define TGSIGN_TYPE_SHA1	0x00000004		//哈希-SHA1;
#define TGSIGN_TYPE_SHA256	0x00000008		//哈希-SHA256;
#define TGSIGN_TYPE_SM3		0x00000010		//哈希-SM3;

//签名结果输出格式类型;
#define TGSIGN_TYPE_PKCS1 0x00010000
#define TGSIGN_TYPE_PKCS7 0x00020000
// ------------签名类型-end------------;

//摘要源数据类型;
#define TGDIGEST_TYPE_BASE64	0x00000000		//原文Base64;
#define TGDIGEST_TYPE_DATA		0x00000001		//二进制;
#define TGDIGEST_TYPE_FILE		0x00000002		//文件;

//----------------中正指纹相关-begin-------------;
#define FINGER_X 152		//指纹图片宽度;
#define FINGER_Y 200		//指纹图片高度;
#define FINGERINF_SIZE  344	//指纹特征/模板长度;
//----------------中正指纹相关-end-------------;

//签名、加解密、摘要等接口数据最大长度,如果大于该值,则需使用文件方式;
#define TGSIGN_DATA_MAX_LEN		1024 * 1024		//1M;

//Ukey类型;
#define TG_UKEY_TYPE_DEFAULT	0		//默认;
#define TG_UKEY_TYPE_ZJCA		1		//ZJCAUkey;
#define TG_UKEY_TYPE_NORM		2		//标准Ukey;

//证书算法类型;
#define TG_UKEY_CERTALG_RSA		1
#define TG_UKEY_CERTALG_SM2		2

//证书密钥长度;
#define TG_UKEY_CERTKEYLEN_256	256
#define TG_UKEY_CERTKEYLEN_1024	1024
#define TG_UKEY_CERTKEYLEN_2048	2048


typedef struct _seal_Info_s
{
    char* sealRequestId;		//印章id;
    char* sealUrl;				//印章路径;
    char* sealName;				//印章名字;
    int   sealwidth;		    //印章宽 ;
    int   sealheight;		    //印章高;
    int   sealType;			    //印章类型;

    _seal_Info_s()
    {
        sealRequestId = NULL;
        sealUrl = NULL;
        sealwidth = 0;
        sealheight = 0;
        sealType = 0;
    }
}S_SEAL_INFO;

struct TGSealInfo
{
	std::string strSealCertID;     //印章的证书ID
	std::string strSealCertB64;    //印章的证书Base64
	std::string strName;           //印章名称
	std::string strID;             //印章ID
	std::string strBase64Url;      //印章链接
	std::string strImgBase64;      //印章数据b64
	std::string strSealCreateData; //印章创建时间
	std::string strSealValidStart; //印章开始时间
	std::string strSealValidEnd;   //印章结束时间
	std::string strSealVersion;    //印章版本
	std::string strSealVid;        //印章Vid
	std::string strSealSignAlgo;   //印章签名算法
	std::string strMaker;	       //制作者
	std::string strSealSignRes;	   //印章签名结果
	int nType;
	int nImageWidth;
	int nImageHeight;

	TGSealInfo() : nType(0)
		, nImageHeight(0)
		, nImageWidth(0)
    {
    }
};

//印章过滤条件;
struct SealFilter
{
    int sealType; //法人、个人等;
    //BSTR certID; //证书ID
    char * m_authRecordId; //获取印章时效验证意愿认证id
    bool m_isDefault;
};

//控件初始化信息结构;
typedef struct _init_Info_s
{
    int SerType;		//服务器类型:1-ESignPro;
    std::string ProjectID;	//项目ID;
    std::string Prokey;		//项目秘钥 ;
    std::string ServerIp;		//服务器IP;
    int Port;			//端口;

    char* accountUniqueId;	//当前操作用户标识;
    char* authRecordId;		//意愿认证id,必须是36位字符串;

    char* ukeyDllName;	//Ukey驱动名称;

    _init_Info_s()
    {
        SerType = 0;
        ProjectID = "";
        Prokey = "";
        ServerIp = "";
        Port = 0;
        accountUniqueId = NULL;
        authRecordId = NULL;
        ukeyDllName = NULL;
    }
}S_INIT_INFO;

//指定类型认证方式参数
typedef struct AuthTypeParam
{
    int devType;

    char* AuthType;

    char* authTypeId;
    AuthTypeParam()
    {

        devType = 0;

        AuthType = "";

        authTypeId = "";
    }

}AUTHTYPEPARAM;

//印章来源枚举;
enum TGSealSourceType
{
    LOCAL = 1,		//二进制;
    CLOUD,			//16进制;
    UNKNOW,
};

//摘要算法枚举;
enum TGHashAlg
{
    _MD5 = 1,
    _SHA1,
    _SHA256,
    _SM3,
};

//数据编码格式;
enum TGDataEncoding
{
    BINARY = 1,		//二进制;
    HEX,			//16进制;
    BASE64,
    SIGNLOGID,
};

//数据编码转码;
std::string byte_to_str(unsigned char* pData, unsigned int pDataLen, TGDataEncoding encode);
std::string str_to_byte(const std::string& str, TGDataEncoding encode);

//签章服务器类型;
enum TG_SIGNSERVER_TYPE
{
    TGPRIVATECLOUD = 1,		//私有云服务器:ESignPro;
    TGOPENAPI,				//OpenApi服务器;
    DEFAULT,
};

//对称加密算法类型;
enum TG_SYMCRYPT
{
    SM1_CBC = 1,
    SM4_CBC,
    SM1_ECB,
    SM4_ECB,
    AES,
    DES,
    RC4,
};

//待签名数据;
struct TG_SignInfo
{
    TG_SignInfo()
        : pbData(NULL)
        , dwDataLen(0)
        , lType(TGSIGN_TYPE_DATA)
        , pUserData(NULL)
        , pSealRequestId(NULL)
        , pExtendedData(NULL)
        , resEncoding(BINARY)
        , pFileKey(NULL)
    {}
    BYTE*	pbData;			//待签名数据,如果是文件类型,则是文件路径;
    DWORD	dwDataLen;		//待签名数据长度;
    LONG	lType;			//签名类型,服务器签名必须是SHA256;
    char*	pUserData;		//内容简称,服务器签名时使用,长度不超过40个字符;
    char*	pSealRequestId;	//印章id,服务器签名时使用,必须是36位字符串;
    char*	pExtendedData;	//扩展字段,暂无用,传空,jsonKey为"extenedData";
    TGDataEncoding	resEncoding;	//签名结果编码格式;
    char*	pFileKey;		//文件Key,服务器签名时有效,可为空（注：手写图片签名使用该值）;
};

//证书信息;
struct cert_info_s
{
    cert_info_s()
        : m_ver(0)
        , m_certB64(NULL)
        , m_certName(NULL)
        , m_licenseNumber(NULL)
        , m_licenseType(0)
        , m_certSN(NULL)
        , m_certIssue(NULL)
        , m_certInfoId(NULL)
        , m_certType(0)
        , m_isCloud(false)
        , m_isDeful(false)
        , m_NotBefore(NULL)
        , m_NotAfter(NULL)
        , m_isSignCert(true)
        , m_CertAlgOid(NULL)
        , next(NULL)
    {}
    ~cert_info_s()
    {
        release();
    }

    void release()
    {
        delete m_certB64;
        m_certB64 = NULL;

        delete m_certName;
        m_certName = NULL;

        delete m_licenseNumber;
        m_licenseNumber = NULL;

        delete m_certSN;
        m_certSN = NULL;

        delete m_certIssue;
        m_certIssue = NULL;

        delete m_certInfoId;
        m_certInfoId = NULL;

        delete m_NotBefore;
        m_NotBefore = NULL;

        delete m_NotAfter;
        m_NotAfter = NULL;

        delete m_CertAlgOid;
        m_CertAlgOid = NULL;

        delete next;
        next = NULL;
    }

    //复制证书;
    void copy_cert(const cert_info_s& certInf)
    {
        release();
        m_ver = certInf.m_ver;
        m_certB64 = tgstr::copy(certInf.m_certB64);
        m_certName = tgstr::copy(certInf.m_certName);
        m_licenseNumber = tgstr::copy(certInf.m_licenseNumber);
        m_licenseType = certInf.m_licenseType;
        m_certSN = tgstr::copy(certInf.m_certSN);
        m_certIssue = tgstr::copy(certInf.m_certIssue);
        m_certType = certInf.m_certType;
        m_isCloud = certInf.m_isCloud;
        m_certInfoId = tgstr::copy(certInf.m_certInfoId);
        m_isDeful = certInf.m_isDeful;
        m_NotBefore = tgstr::copy(certInf.m_NotBefore);
        m_NotAfter = tgstr::copy(certInf.m_NotAfter);
        m_isSignCert = certInf.m_isSignCert;
        m_CertAlgOid = tgstr::copy(certInf.m_CertAlgOid);
    }

    int     m_ver;              //证书版本;
    char*	m_certB64;			//证书源数据base64加密;
    char*	m_certName;			//证书名称;
    int 	m_licenseType;		//证件类型;
    char*	m_licenseNumber;	//证件号码;
    char*	m_certSN;			//证书序列号;
    char*	m_certIssue;		//证书颁发者名称;
    char*	m_certInfoId;		//证书id(服务器证书标识);
    int		m_certType;			//证书类型;
    bool	m_isCloud;			//是否云端证书;
    bool	m_isDeful;			//是否默认证书(注:云端证书有效);

    char*	m_NotBefore;		//起始日期,格式:年-月-日 时:分:秒;
    char*	m_NotAfter;			//终止日期;
    bool	m_isSignCert;		//是否签名证书;

    char*   m_CertAlgOid;       //证书算法Oid;

    cert_info_s *next;			//下一个证书;
};
typedef struct cert_info_s s_cert_info;

struct cloudFilter_s
{
    cloudFilter_s()
        : token(NULL)
        , userId(NULL)
        , isDefault(false)
    {}
    char* token;
    char* userId;
    bool isDefault;
};

struct localFilter_s
{
    localFilter_s()
        : certFilter(NULL)
    {

    }
    char* certFilter;		//根据颁发者过滤条件;
};

struct cert_config_s
{
    cert_config_s()
        : get_cert_way(way_all)
        , cert_type(signature)
        , cert_cn(NULL)
        , cert_sn(NULL)
        , algo_type(sm2andrsa)
        , m_isDefault(false)
        , m_authRecordId(NULL)
        , isShowDlg(false)
    {}

    bool isShowDlg;		//是否弹出证书选择界面;

    //证书来源:0-本地,1-网络,2-本地和网络;
    enum _cert_ways{
        way_local,
        way_cloud,
        way_all,
    }get_cert_way;

    //证书用途类型;0-签名,1-加密;
    enum  _cert_type{
        signature,
        encrypt,
    }cert_type;

    char* cert_cn;	//证书名称;
    char* cert_sn;	//证书序列号;
    bool m_isDefault;
    char* m_authRecordId;//获取证书认证id;

    //证书算法类型:0-SM2,1-RSA,2-SM2ANDRSA;
    enum _algo_type{
        sm2,
        rsa,
        sm2andrsa,
    } algo_type;

    cloudFilter_s cloudFilter;		//云端证书过滤条件;
    localFilter_s localFilter;		//本地证书过滤条件;
};
typedef struct cert_config_s cert_config;

//certType 证书类型:1签名,2加密,3签名证书对应的加密证书;
#define CERTTYPE_SIGN       1
#define CERTTYPE_ENCRYPT    2
#define CERTTYPE_EXCHANGE   3

#endif
