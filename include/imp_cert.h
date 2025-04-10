#ifndef IMP_CERT_H
#define IMP_CERT_H

#include <time.h>
#include "common.h"

/**
 * 隐式证书结构
 */
typedef struct {
    unsigned char SerialNum[9];  // 证书序列号
    unsigned char IssuerID[9];   // 颁发者ID
    unsigned char SubjectID[9];  // 主体ID
    unsigned char Validity[16];  // 有效期: 前8字节开始时间，后8字节结束时间
    unsigned char PubKey[33];    // 公钥
} ImpCert;


EXPORT int validate_cert(const ImpCert *cert);

/**
 * 设置证书信息，包括基本信息和部分公钥
 * 
 * @param cert        要设置的证书对象
 * @param serial_num  证书序列号
 * @param issuer_id     颁发者ID
 * @param subject_id  主体ID
 * @param start_time  证书有效期起始时间
 * @param end_time    证书有效期结束时间
 * @param pub_key     部分公钥
 * @return            成功返回1，失败返回0
 */
EXPORT int set_cert(ImpCert *cert, 
                    const unsigned char *serial_num,
                    const unsigned char *issuer_id, 
                    const unsigned char *subject_id,
                    time_t start_time,
                    time_t end_time,
                    const EC_POINT *Pu);

EXPORT int save_cert(const ImpCert *cert, const char *filename);

EXPORT int load_cert(ImpCert *cert, const char *filename);

EXPORT void print_cert_info(const ImpCert *cert);

EXPORT int getPu(const ImpCert *cert, EC_POINT *Pu);

#endif