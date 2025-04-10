#ifndef SM2_H
#define SM2_H

#include "common.h"
#include <openssl/evp.h>

/**
 * @brief SM2签名上下文结构体
 * 
 * 用于存储签名/验签过程中的各种OpenSSL上下文对象
 */
typedef struct sm2_sig_ctx_st
{
    int is_pri;           // 标识是否为私钥操作：1-签名(私钥)，0-验证(公钥)
    EVP_PKEY *pkey;      // OpenSSL密钥对象
    EVP_PKEY_CTX *pctx;  // 密钥操作上下文
    EVP_MD_CTX *mctx;    // 消息摘要上下文
} SM2_SIG_CTX;

/**
 * @brief 将SM2签名从ASN.1格式转换为RS格式
 * 
 * @param out [out] 输出缓冲区，用于存储转换后的签名
 * @param out_len [out] 输出签名的长度
 * @param in [in] 输入的ASN.1格式签名
 * @param in_len [in] 输入签名的长度
 * @return int 成功返回1，失败返回0
 * 
 * @note RS格式为：r || s，直接拼接签名的r和s值
 */
EXPORT int sm2_sig_to_rs(unsigned char *out, const unsigned char *in, int in_len);

/**
 * @brief 生成SM2密钥对
 * 
 * @param pub [out] 输出缓冲区，用于存储生成的公钥
 * @param pub_len [out] 输出公钥的长度
 * @param pri [out] 输出缓冲区，用于存储生成的私钥
 * @param pri_len [out] 输出私钥的长度
 * @return int 成功返回1，失败返回0
 */
EXPORT int sm2_key_pair_new(unsigned char *pub, unsigned char *pri);

//签名验签

/**
 * @brief SM2签名操作(一次性完成)
 * 
 * @param sig [out] 输出缓冲区，用于存储生成的签名，必须至少有64字节
 * @param in [in] 要签名的数据
 * @param in_len [in] 要签名的数据长度
 * @param pri [in] 私钥数据，必须是SM2_PRI_MAX_SIZE字节
 * @return int 成功返回1并在sig中保存R||S格式签名，失败返回0
 * 
 * @note 输出的签名为R||S格式，固定长度为64字节，前32字节为R值，后32字节为S值
 */
EXPORT int sm2_sign(unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pri);

/**
 * @brief SM2签名验证操作(一次性完成)
 * 
 * @param sig [in] 要验证的签名数据，必须是R||S格式，长度为64字节
 * @param in [in] 原始数据
 * @param in_len [in] 原始数据长度
 * @param pub [in] 公钥数据，必须是SM2_PUB_MAX_SIZE字节
 * @return int 验证成功返回1，失败返回0
 * 
 * @note 输入的签名必须是R||S格式，前32字节为R值，后32字节为S值
 */
EXPORT int sm2_verify(const unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pub);

#endif