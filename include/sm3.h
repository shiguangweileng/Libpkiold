#ifndef SM3_H
#define SM3_H
#include "common.h"
#include <openssl/evp.h>

#define SM3_MD_SIZE 32

/**
 * @brief 计算输入数据的SM3哈希值
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @param md [out] 输出的哈希值缓冲区，长度应至少为SM3_MD_SIZE(32字节)
 * @return int 成功返回1，失败返回0
 */
EXPORT int sm3_hash(const unsigned char *in, size_t in_len, unsigned char *md);

/**
 * @brief 创建并初始化一个新的SM3上下文
 * @return EVP_MD_CTX* 成功返回上下文指针，失败返回NULL
 */
EXPORT EVP_MD_CTX *sm3_md_ctx_new();

/**
 * @brief 释放SM3上下文资源
 * @param ctx [in] 要释放的上下文指针
 */
EXPORT void sm3_md_ctx_free(EVP_MD_CTX *ctx);

/**
 * @brief 向SM3上下文中更新数据
 * @param ctx [in,out] SM3上下文
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @return int 成功返回1，失败返回0
 */
EXPORT int sm3_md_update(EVP_MD_CTX *ctx, const unsigned char *in, size_t in_len);

/**
 * @brief 完成SM3哈希计算并输出结果
 * @param ctx [in] SM3上下文
 * @param md [out] 输出的哈希值缓冲区
 * @param md_len [out] 输出的哈希值长度
 * @return int 成功返回1，失败返回0
 */
EXPORT int sm3_md_final(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *md_len);

#endif