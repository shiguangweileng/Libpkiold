#ifndef IMP_CERT_H
#define IMP_CERT_H

#include <time.h>
#include "common.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>


#define SERIAL_NUM_FORMAT "SN%06d"       // 序列号格式，6位数字前缀为SN
#define SERIAL_NUM_MAX 999999            // 序列号最大值
#define SUBJECT_ID_LEN 4                 // 主体ID实际长度
#define SUBJECT_ID_SIZE 5                // 主体ID长度为5字节
#define CERT_HASH_SIZE 32                // 证书哈希值长度

// 证书版本
#define CERT_V1 0x01
#define CERT_V2 0x02

// 哈希算法类型
typedef enum {
    HASH_NONE = 0x00,
    HASH_SM3  = 0x01,     // SM3哈希算法
    HASH_SHA256 = 0x02,   // SHA256哈希算法
    HASH_SHA384 = 0x03    // SHA384哈希算法
} HashAlgType;

// 签名算法类型
typedef enum {
    SIGN_NONE = 0x00,
    SIGN_SM2  = 0x01,     // SM2椭圆曲线签名算法
    SIGN_ECDSA = 0x02,    // ECDSA椭圆曲线签名算法
    SIGN_RSA = 0x03       // RSA签名算法
} SignAlgType;

// 证书用途类型
typedef enum {
    USAGE_GENERAL = 0x00,     // 通用证书
    USAGE_IDENTITY = 0x01,    // 身份认证
} CertUsageType;

// 证书扩展结构
typedef struct {
    unsigned char Usage;                // 用途
    unsigned char SignAlg;              // 签名算法
    unsigned char HashAlg;              // 哈希算法
    unsigned char ExtraInfo[11];        // 额外信息
} ImpCertExt;

// 通用证书结构
typedef struct {
    unsigned char Version;              // 证书版本
    unsigned char SerialNum[9];         // 证书序列号
    unsigned char IssuerID[4];          // 颁发者ID
    unsigned char SubjectID[4];         // 主体ID
    unsigned char Validity[16];         // 有效期: 前8字节开始时间，后8字节结束时间
    unsigned char PubKey[33];           // 公钥
    ImpCertExt *Extensions;             // 扩展信息，V1为NULL，V2为扩展对象
} ImpCert;

// ASN.1结构定义 - DER编码所需
typedef struct ImpCertAsn1_st {
    ASN1_INTEGER *version;
    ASN1_UTF8STRING *serialNum;
    ASN1_UTF8STRING *issuerID;
    ASN1_UTF8STRING *subjectID;
    ASN1_INTEGER *startTime;
    ASN1_INTEGER *endTime;
    ASN1_OCTET_STRING *pubKey;
    ASN1_INTEGER *usage;
    ASN1_INTEGER *signAlg;
    ASN1_INTEGER *hashAlg;
    ASN1_OCTET_STRING *extraInfo;
} ImpCertAsn1;

// ASN.1序列化声明
DECLARE_ASN1_FUNCTIONS(ImpCertAsn1)

EXPORT int validate_cert(const ImpCert *cert);
EXPORT int set_cert(ImpCert *cert,
                    unsigned char version,
                    const unsigned char *serial_num,
                    const unsigned char *issuer_id, 
                    const unsigned char *subject_id,
                    time_t start_time,
                    time_t end_time,
                    const EC_POINT *Pu,
                    const ImpCertExt *extensions);

EXPORT int save_cert(const ImpCert *cert, const char *filename);
EXPORT int load_cert(ImpCert *cert, const char *filename);
EXPORT void print_cert_info(const ImpCert *cert);
EXPORT int getPu(const ImpCert *cert, EC_POINT *Pu);
EXPORT void free_cert(ImpCert *cert);
EXPORT int calc_cert_hash(const ImpCert *cert, unsigned char *hash_out);

#endif