#ifndef COMMON_H
#define COMMON_H

#include <openssl/ec.h>
#include <openssl/bn.h>

// 定义EXPORT宏 (仅Linux)
#define EXPORT __attribute__((visibility("default")))

// 时间戳验证最大允许时间差(秒)
#define TS_MAX_DIFF 2 // 最大允许2秒的时间差

// 实体初始化
EXPORT int CA_init(unsigned char *pub, unsigned char *priv);
EXPORT int User_init(unsigned char *pub);

// 调试类
EXPORT void print_hex(const char *name, const unsigned char *data, int data_len);
EXPORT void print_bn(const char *name, const BIGNUM *bn);
EXPORT int parse_hex_hash(unsigned char *cert_hash, int hash_size);
EXPORT void clear_input_buffer();

// 计算r=e×k+d (mod n)
EXPORT int calculate_r(unsigned char *r, const unsigned char *e, const BIGNUM *k, 
                const unsigned char *d, const BIGNUM *n);

//公钥重构 Qu=e×Pu+Q_ca
EXPORT int rec_pubkey(unsigned char *Qu, const unsigned char *e, const EC_POINT *Pu, const unsigned char *Q_ca);

EXPORT int verify_key_pair(const EC_GROUP *group, const EC_POINT *pub_key, const BIGNUM *pri_key);
EXPORT int verify_key_pair_bytes(const EC_GROUP *group, const unsigned char *pub_key, const unsigned char *pri_key);

// 验证时间戳是否在合理范围内(当前时间前后TS_MAX_DIFF秒内)
EXPORT int validate_timestamp(uint64_t timestamp);

// 安全删除文件 - 通过多次随机数据覆写确保文件内容不可恢复
EXPORT int secure_delete_file(const char *filename);

#endif