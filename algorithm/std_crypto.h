#ifndef STD_CRYPTO_H
#define STD_CRYPTO_H

#include "common.h"
#include <openssl/evp.h>

/* ========ECC P-256相关定义======== */
// ECC全局参数(使用NID_X9_62_prime256v1)
extern EC_GROUP *std_group;
extern BIGNUM  *std_order;

#define ECC_PUB_MAX_SIZE 65   // 0x04 || x(32B) || y(32B)
#define ECC_PRI_MAX_SIZE 32   // 私钥长度
#define ECC_SIG_SIZE     64   // R||S 固定64字节签名

/* 全局参数初始化/释放 */
EXPORT int global_params_init();
EXPORT void global_params_cleanup();

/**
 * @brief 生成ECC(P-256)密钥对
 * @param pub [out] 输出缓冲区，用于存储生成的公钥
 * @param pri [out] 输出缓冲区，用于存储生成的私钥
 * @return int 成功返回1，失败返回0
 */
EXPORT int ecc_key_pair_new(unsigned char *pub, unsigned char *pri);

/**
 * @brief ECC(P-256)签名(一次性完成)
 * @param sig [out] 输出缓冲区，存储签名R||S，需64字节
 * @param in  [in]  待签名数据
 * @param in_len [in] 数据长度
 * @param pri [in]  私钥字节串(32字节)
 * @return int 成功返回1，失败返回0
 */
EXPORT int ecc_sign(unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pri);

/**
 * @brief ECC(P-256)验签(一次性完成)
 * @param sig [in]  R||S格式签名，64字节
 * @param in  [in]  原始数据
 * @param in_len [in] 数据长度
 * @param pub [in]  公钥字节串(65字节，0x04||x||y)
 * @return int 验证成功返回1，失败返回0
 */
EXPORT int ecc_verify(const unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pub);


/* ===============SHA256相关定义============== */
#define SHA256_MD_SIZE 32

/**
 * @brief 计算输入数据的SHA256哈希值
 * 
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @param md [out] 输出的哈希值缓冲区，长度应至少为SHA256_MD_SIZE(32字节)
 * @return int 成功返回1，失败返回0
 */
EXPORT int sha256_hash(const unsigned char *in, size_t in_len, unsigned char *md);

/**
 * @brief 基于SHA256的KDF(Key Derivation Function)
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @param out [out] 输出密钥缓冲区
 * @param out_len [in] 期望输出密钥长度，<=32
 * @return int 成功返回1，失败返回0
 */
EXPORT int sha256_kdf(const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len);


/* ===============AES-GCM-128相关定义============== */
#define AES_KEY_SIZE 16      // 128位密钥
#define AES_IV_SIZE 12       // 96位IV（GCM推荐）
#define AES_TAG_SIZE 16      // 128位认证标签

/**
 * @brief 生成随机AES密钥
 * @param key [out] 输出的16字节密钥缓冲区
 * @return 成功返回1，失败返回0
 */
EXPORT int aes_generate_key(unsigned char *key);

/**
 * @brief 生成随机IV
 * @param iv [out] 输出的12字节IV缓冲区
 * @return 成功返回1，失败返回0
 */
EXPORT int aes_generate_iv(unsigned char *iv);

/**
 * @brief AES-GCM模式加密
 * @param out [out] 输出缓冲区（密文，长度与明文相同）
 * @param tag [out] 输出的16字节认证标签
 * @param in [in] 输入明文数据
 * @param in_len [in] 输入数据长度
 * @param key [in] 16字节密钥
 * @param iv [in] 12字节初始化向量
 * @return 成功返回1，失败返回0
 */
EXPORT int aes_encrypt(unsigned char *out, unsigned char *tag,
                const unsigned char *in, int in_len,
                const unsigned char *key, const unsigned char *iv);

/**
 * @brief AES-GCM模式解密
 * @param out [out] 输出缓冲区（明文，长度与密文相同）
 * @param in [in] 输入密文数据
 * @param in_len [in] 输入数据长度
 * @param tag [in] 16字节认证标签
 * @param key [in] 16字节密钥
 * @param iv [in] 12字节初始化向量
 * @return 成功返回1，失败返回0（包括认证失败）
 */
EXPORT int aes_decrypt(unsigned char *out,
                const unsigned char *in, int in_len,
                const unsigned char *tag,
                const unsigned char *key, const unsigned char *iv);

#endif /* STD_CRYPTO_H */