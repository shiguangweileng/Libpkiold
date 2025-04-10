#include "sm3.h"
#include <string.h>

/**
 * @brief 创建并初始化一个新的SM3上下文
 * 
 * 该函数完成以下操作：
 * 1. 创建一个新的EVP_MD_CTX上下文
 * 2. 使用SM3算法初始化该上下文
 * 
 * @return EVP_MD_CTX* 成功返回初始化好的上下文指针，失败返回NULL
 */
EVP_MD_CTX *sm3_md_ctx_new()
{
    EVP_MD_CTX *ctx = NULL;
    int success =
        (ctx = EVP_MD_CTX_new()) &&    /* 创建新的消息摘要上下文 */
        EVP_DigestInit(ctx, EVP_sm3()); /* 使用SM3算法初始化上下文 */
    
    /* 如果创建或初始化失败，释放资源并返回NULL */
    if (!success)
    {
        sm3_md_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

/**
 * @brief 释放SM3上下文资源
 * 
 * 安全地释放上下文资源，并将指针置为NULL
 * 
 * @param ctx [in] 要释放的上下文指针
 */
void sm3_md_ctx_free(EVP_MD_CTX *ctx)
{
    if (ctx)
    {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
}

/**
 * @brief 向SM3上下文中更新数据
 * 
 * 将新的数据块添加到哈希计算中
 * 
 * @param ctx [in,out] SM3上下文
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @return int 成功返回1，失败返回0
 */
int sm3_md_update(EVP_MD_CTX *ctx, const unsigned char *in, size_t in_len)
{
    /* 验证参数有效性并更新哈希计算 */
    return ctx && in &&
           EVP_DigestUpdate(ctx, in, in_len);
}

/**
 * @brief 完成SM3哈希计算并输出结果
 * 
 * @param ctx [in] SM3上下文
 * @param md [out] 输出的哈希值缓冲区
 * @param md_len [out] 输出的哈希值长度
 * @return int 成功返回1，失败返回0
 */
int sm3_md_final(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *md_len)
{
    /* 验证参数有效性并完成哈希计算 */
    return ctx && md && md_len &&
           EVP_DigestFinal(ctx, md, md_len);
}

/**
 * @brief 计算输入数据的SM3哈希值
 * 
 * 这是一个便捷函数，它完成完整的哈希计算过程：
 * 1. 创建并初始化上下文
 * 2. 更新数据
 * 3. 完成计算并输出结果
 * 4. 释放资源
 * 
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @param md [out] 输出的哈希值缓冲区，长度应至少为SM3_MD_SIZE(32字节)
 * @return int 成功返回1，失败返回0
 */
int sm3_hash(const unsigned char *in, size_t in_len, unsigned char *md)
{
    /* 参数有效性检查 */
    if (!md || !in)
        return 0;

    EVP_MD_CTX *ctx = NULL;
    unsigned int md_len; // 内部处理哈希长度
    int success =
        (ctx = sm3_md_ctx_new()) &&               /* 创建并初始化上下文 */
        sm3_md_update(ctx, in, in_len) &&         /* 更新数据 */
        sm3_md_final(ctx, md, &md_len);           /* 完成计算并输出结果 */

    /* 释放资源 */
    if (ctx)
    {
        sm3_md_ctx_free(ctx);
        ctx = NULL;
    }
    return success;
}

