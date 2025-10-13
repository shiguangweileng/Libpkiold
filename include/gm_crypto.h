#ifndef GM_CRYPTO_H
#define GM_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#define EXPORT __attribute__((visibility("default")))

/* ===============SM2相关定义============== */
// SM2全局参数
extern EC_GROUP *group;
extern BIGNUM *order;

//SM2算法相关参数定义
#define SM2_PUB_MAX_SIZE 65   // SM2公钥最大长度(字节)：0x04 || x || y
#define SM2_PRI_MAX_SIZE 32   // SM2私钥最大长度(字节)
#define SM2_SIG_MAX_SIZE 72   // SM2签名最大长度(字节)：DER编码的r和s

// SM2参数初始化和释放
EXPORT int global_params_init();
EXPORT void global_params_cleanup();

typedef struct sm2_sig_ctx_st
{
    int is_pri;           // 标识是否为私钥操作：1-签名(私钥)，0-验证(公钥)
    EVP_PKEY *pkey;      // OpenSSL密钥对象
    EVP_PKEY_CTX *pctx;  // 密钥操作上下文
    EVP_MD_CTX *mctx;    // 消息摘要上下文
} SM2_SIG_CTX;

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

/* ===============SM4相关定义============== */

#define SM4_KEY_SIZE 16      // 128位密钥
#define SM4_IV_SIZE 16       // 128位IV
#define SM4_BLOCK_SIZE 16    // 128位块大小

/* SM4 密钥和IV生成 */
EXPORT int sm4_generate_key(unsigned char *key);
EXPORT int sm4_generate_iv(unsigned char *iv);

/* SM4 CBC模式加解密 */
EXPORT int sm4_encrypt(unsigned char *out, int *out_len,
                       const unsigned char *in, int in_len,
                       const unsigned char *key, const unsigned char *iv);
EXPORT int sm4_decrypt(unsigned char *out, int *out_len,
                       const unsigned char *in, int in_len,
                       const unsigned char *key, const unsigned char *iv);


/* ===============SM3相关定义============== */
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
 * @brief 基于SM3的KDF(Key Derivation Function)
 * @param in [in] 输入数据
 * @param in_len [in] 输入数据长度
 * @param out [out] 输出密钥缓冲区
 * @param out_len [in] 期望输出密钥长度，<=32
 * @return int 成功返回1，失败返回0
 */
EXPORT int sm3_kdf(const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len);


#endif