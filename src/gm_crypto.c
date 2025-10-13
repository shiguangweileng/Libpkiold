#include "gm_crypto.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

// 全局参数
EC_GROUP *group = NULL;
BIGNUM *order = NULL;

/* SM2相关函数实现 */
int global_params_init() {
    // 创建SM2椭圆曲线组
    group = EC_GROUP_new_by_curve_name(1172);
    if (!group) {
        printf("初始化SM2曲线参数失败！\n");
        return 0;
    }
    
    order = BN_new();
    if (!order || !EC_GROUP_get_order(group, order, NULL)) {
        printf("获取SM2曲线阶失败！\n");
        global_params_cleanup();
        return 0;
    }
    
    return 1;
}

void global_params_cleanup() {
    if (order) {
        BN_free(order);
        order = NULL;
    }
    
    if (group) {
        EC_GROUP_free(group);
        group = NULL;
    }
}

/**
 * SM2签名结构体定义
 * 用于存储SM2签名的r和s值
 */
typedef struct sm2_signature_st
{
    BIGNUM *r;    // 签名的r值
    BIGNUM *s;    // 签名的s值
} SM2_SIGNATURE;

// 声明SM2_SIGNATURE结构体的ASN1编解码函数
DECLARE_ASN1_FUNCTIONS(SM2_SIGNATURE)

// 定义SM2_SIGNATURE的ASN1序列化结构
ASN1_SEQUENCE(SM2_SIGNATURE) = {
    ASN1_SIMPLE(SM2_SIGNATURE, r, BIGNUM),
    ASN1_SIMPLE(SM2_SIGNATURE, s, BIGNUM),
} ASN1_SEQUENCE_END(SM2_SIGNATURE)

// 实现SM2_SIGNATURE的ASN1编解码函数
IMPLEMENT_ASN1_FUNCTIONS(SM2_SIGNATURE);

/**
 * 从私钥导出公钥
 * 
 * @param pub [out] 输出缓冲区，用于存储导出的公钥
 * @param pub_len [out] 输出公钥的长度
 * @param pri [in] 输入的私钥值
 * @return 成功返回1，失败返回0
 * 
 * 说明：使用SM2椭圆曲线参数，通过私钥计算对应的公钥点
 */
static int export_pub(unsigned char **pub, size_t *pub_len, BIGNUM *pri)
{
    if (!pub || !pub_len || !pri)
        return 0;
    EC_GROUP *group   = NULL;  // SM2椭圆曲线群组
    EC_POINT *pub_key = NULL;  // 公钥点
    int success =
        (group = EC_GROUP_new_by_curve_name(NID_sm2)) &&     // 创建SM2曲线群组
        (pub_key = EC_POINT_new(group)) &&                   // 创建新的曲线点
        EC_POINT_mul(group, pub_key, pri, NULL, NULL, NULL) &&  // 计算公钥点 = 私钥 * 基点
        (*pub_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL)) &&  // 获取序列化后的长度
        (*pub = malloc(*pub_len)) &&                         // 分配内存
        EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, *pub, *pub_len, NULL);  // 将公钥点转换为字节串

    // 错误处理：释放内存
    if (!success)
    {
        free(*pub);
        *pub = NULL;
    }
    if (pub_key)
    {
        EC_POINT_free(pub_key);
        pub_key = NULL;
    }
    if (group)
    {
        EC_GROUP_free(group);
        group = NULL;
    }
    return success;
}

/**
 * 创建新的密钥对象
* 
 * @param key [in] 输入的密钥数据
 * @param key_len [in] 密钥数据的长度
 * @param is_pri [in] 是否为私钥(1:私钥, 0:公钥)
 * @return 成功返回EVP_PKEY对象指针，失败返回NULL
 * 
 * 说明：根据输入的密钥数据创建OpenSSL的EVP_PKEY对象
 */
static EVP_PKEY *new_key(const unsigned char *key, size_t key_len, int is_pri)
{
    if (!key)
        return NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();  // 创建参数构建器
    if (!bld)
    {
        return NULL;
    }
    int selection          = 0;
    OSSL_PARAM *params     = NULL;
    BIGNUM *pri_d          = NULL;
    size_t exp_pub_len     = 0;
    unsigned char *exp_pub = NULL;

    // 处理私钥情况
    if (is_pri)
    {
        if ((pri_d = BN_bin2bn(key, key_len, NULL)) &&                    // 转换私钥为BIGNUM
            OSSL_PARAM_BLD_push_BN(bld, "priv", pri_d) &&                 // 添加私钥参数
            export_pub(&exp_pub, &exp_pub_len, pri_d) &&                  // 导出对应的公钥
            OSSL_PARAM_BLD_push_octet_string(bld, "pub", exp_pub, exp_pub_len))  // 添加公钥参数
        {
            selection = EVP_PKEY_KEYPAIR;  // 设置为密钥对
        }
    }
    // 处理公钥情况
    else
    {
        if (OSSL_PARAM_BLD_push_octet_string(bld, "pub", key, key_len))  // 添加公钥参数
        {
            selection = EVP_PKEY_PUBLIC_KEY;  // 设置为公钥
        }
    }

    // 设置SM2曲线参数
    if (OSSL_PARAM_BLD_push_utf8_string(bld, "group", SN_sm2, 0))
    {
        params = OSSL_PARAM_BLD_to_param(bld);
    }

    // 清理临时资源
    if (exp_pub)
    {
        free(exp_pub);
        exp_pub = NULL;
    }
    if (pri_d)
    {
        BN_free(pri_d);
        pri_d = NULL;
    }
    OSSL_PARAM_BLD_free(bld);
    bld = NULL;
    if (!params)
    {
        return NULL;
    }

    // 创建EVP_PKEY对象
    EVP_PKEY *pkey    = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int success =
        (ctx = EVP_PKEY_CTX_new_from_name(NULL, SN_sm2, NULL)) &&  // 创建SM2上下文
        EVP_PKEY_fromdata_init(ctx) &&                              // 初始化fromdata操作
        EVP_PKEY_fromdata(ctx, &pkey, selection, params);           // 从参数创建密钥对象

    if (!success)
    {
        pkey = NULL;
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }
    OSSL_PARAM_free(params);
    params = NULL;
    return pkey;
}

// 用于签名的固定ID值
static unsigned char id[] = "1234567812345678";

/**
 * 将SM2签名从RS格式转换为ASN.1格式
* 
 * @param out [out] 输出缓冲区，用于存储转换后的签名
 * @param out_len [out] 输出签名的长度
 * @param in [in] 输入的RS格式签名(r||s)，长度为64字节
 * @return 成功返回1，失败返回0
 * 
 * 说明：将RS格式的签名转换为ASN.1编码的签名
 */
static int rs_to_asn1(unsigned char *out, size_t *out_len, const unsigned char *in)
{
    if (!out || !out_len || !in)
        return 0;
    
    SM2_SIGNATURE *sig = SM2_SIGNATURE_new();
    if (!sig)
        return 0;
    
    // 转换R值(前32字节)
    sig->r = BN_bin2bn(in, 32, NULL);
    
    // 转换S值(后32字节)
    sig->s = BN_bin2bn(in + 32, 32, NULL);
    
    if (!sig->r || !sig->s) {
        SM2_SIGNATURE_free(sig);
        return 0;
    }
    
    // 编码为ASN.1格式
    unsigned char *p = out;
    int len = i2d_SM2_SIGNATURE(sig, &p);
    if (len <= 0) {
        SM2_SIGNATURE_free(sig);
        return 0;
    }
    
    *out_len = len;
    SM2_SIGNATURE_free(sig);
    return 1;
}

/**
 * 将SM2签名从ASN.1格式转换为RS格式
* 
 * @param out [out] 输出缓冲区，用于存储转换后的签名
 * @param out_len [out] 输出签名的长度
 * @param in [in] 输入的ASN.1格式签名
 * @param in_len [in] 输入签名的长度
 * @return 成功返回1，失败返回0
 * 
 * 说明：将ASN.1编码的SM2签名转换为RS格式，即签名值r和s的连接
 */
static int sm2_sig_to_rs(unsigned char *out, const unsigned char *in, int in_len)
{
    if (!out || !in)
        return 0;
    SM2_SIGNATURE *seq = NULL;
    int success =
        d2i_SM2_SIGNATURE(&seq, &in, in_len) &&
        BN_bn2bin(seq->r, out) &&
        BN_bn2bin(seq->s, out += 32);
    if (seq)
    {
        SM2_SIGNATURE_free(seq);
        seq = NULL;
    }
    return success;
}

int sm2_key_pair_new(unsigned char *pub, unsigned char *pri)
{
    // 生成SM2密钥对
    EVP_PKEY *pkey = EVP_EC_gen(SN_sm2);
    if (!pkey) {
        printf("EVP_EC_gen失败: \n");
        return 0;
    }

    // // 打印密钥详细信息（用于调试）
    // BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    // printf("\n===== SM2密钥详细信息 =====\n");
    // EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
    // BIO_free(bio_out);
    
    int success = 0;
    size_t pub_len = SM2_PUB_MAX_SIZE;
    BIGNUM *priv_bn = NULL;
    if (!EVP_PKEY_get_octet_string_param(pkey, "pub", pub, pub_len, &pub_len)) {
        printf("获取公钥数据失败\n");
        goto cleanup;
    }
    
    // 获取私钥数据
    if (!EVP_PKEY_get_bn_param(pkey, "priv", &priv_bn)) {
        printf("获取私钥数据失败\n");
        goto cleanup;
    }
    
    // 将私钥转换为二进制形式
    BN_bn2bin(priv_bn, pri);
    
    success = 1;
    
cleanup:
    if (priv_bn) {
        BN_free(priv_bn);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return success;
}


int sm2_sign(unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pri)
{
    if (!sig || !in || !pri)
        return 0;
        
    // 临时存储DER格式签名
    unsigned char der_sig[SM2_SIG_MAX_SIZE];
    size_t der_sig_len = SM2_SIG_MAX_SIZE;
    
    // 使用EVP高级接口直接完成签名
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int success = 0;
    
    do {
        // 创建私钥对象
        if (!(pkey = new_key(pri, SM2_PRI_MAX_SIZE, 1)))
            break;
            
        // 创建摘要上下文
        if (!(md_ctx = EVP_MD_CTX_new()))
            break;
            
        // 初始化签名
        if (!EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey))
            break;
            
        // 设置SM2签名ID
        if (!EVP_PKEY_CTX_set1_id(pctx, id, 16))
            break;
            
        // 更新数据
        if (!EVP_DigestSignUpdate(md_ctx, in, in_len))
            break;
            
        // 生成签名
        if (!EVP_DigestSignFinal(md_ctx, der_sig, &der_sig_len))
            break;
            
        // 将ASN.1格式转换为RS格式
        success = sm2_sig_to_rs(sig, der_sig, der_sig_len);
    } while (0);
    
    // 清理资源
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    
    return success;
}


int sm2_verify(const unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pub)
{
    if (!sig || !in || !pub)
        return 0;
    
    // 将RS格式转换为ASN.1格式
    unsigned char der_sig[SM2_SIG_MAX_SIZE];
    size_t der_sig_len = 0;
    
    if (!rs_to_asn1(der_sig, &der_sig_len, sig))
        return 0;
    
    // 使用EVP高级接口直接完成验证，避免创建中间上下文
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int ret = 0;
    
    do {
        // 创建公钥对象
        if (!(pkey = new_key(pub, SM2_PUB_MAX_SIZE, 0)))
            break;
            
        // 创建摘要上下文
        if (!(md_ctx = EVP_MD_CTX_new()))
            break;
            
        // 初始化验证
        if (!EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey))
            break;
            
        // 设置SM2签名ID
        if (!EVP_PKEY_CTX_set1_id(pctx, id, 16))
            break;
            
        // 更新并验证
        if (!EVP_DigestVerifyUpdate(md_ctx, in, in_len))
            break;
            
        ret = EVP_DigestVerifyFinal(md_ctx, der_sig, der_sig_len);
    } while (0);
    
    // 清理资源
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    
    return ret;
}

/* =============== SM3相关函数实现 ============== */


int sm3_hash(const unsigned char *in, size_t in_len, unsigned char *md)
{
    if (!in || !md)
    {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return 0;
    }

    int ret = 0;
    unsigned int md_len = 0;

    do
    {
        if (!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL))
        {
            break;
        }

        if (!EVP_DigestUpdate(ctx, in, in_len))
        {
            break;
        }

        if (!EVP_DigestFinal_ex(ctx, md, &md_len))
        {
            break;
        }

        ret = 1;
    } while (0);

    EVP_MD_CTX_free(ctx);

    return ret;
}

int sm3_kdf(const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
    if (!in || !out || out_len == 0 || out_len > SM3_MD_SIZE)
        return 0;

    unsigned char digest[SM3_MD_SIZE];
    unsigned char *buf = NULL;
    size_t buf_len = in_len + 4; // Z || ct

    buf = (unsigned char *)malloc(buf_len);
    if (!buf) return 0;

    memcpy(buf, in, in_len);
    // ct = 0x00000001 (big-endian)
    buf[in_len]     = 0x00;
    buf[in_len + 1] = 0x00;
    buf[in_len + 2] = 0x00;
    buf[in_len + 3] = 0x01;

    int ret = sm3_hash(buf, buf_len, digest);
    free(buf);
    if (!ret) return 0;

    memcpy(out, digest, out_len);
    return 1;
}

/* =====================================================================
 * SM4 相关函数实现
 * ===================================================================== */

int sm4_generate_key(unsigned char *key)
{
    if (!key) return 0;
    return RAND_bytes(key, SM4_KEY_SIZE);
}

int sm4_generate_iv(unsigned char *iv)
{
    if (!iv) return 0;
    return RAND_bytes(iv, SM4_IV_SIZE);
}

int sm4_encrypt(unsigned char *out, int *out_len,
                const unsigned char *in, int in_len,
                const unsigned char *key, const unsigned char *iv)
{
    if (!out || !out_len || !in || !key || !iv) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, total_len = 0;
    int success = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);

        if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) == 1) {
            total_len = len;
            if (EVP_EncryptFinal_ex(ctx, out + len, &len) == 1) {
                total_len += len;
                *out_len = total_len;
                success = 1;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

int sm4_decrypt(unsigned char *out, int *out_len,
                const unsigned char *in, int in_len,
                const unsigned char *key, const unsigned char *iv)
{
    if (!out || !out_len || !in || !key || !iv) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0, total_len = 0;
    int success = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);

        if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) == 1) {
            total_len = len;
            if (EVP_DecryptFinal_ex(ctx, out + len, &len) == 1) {
                total_len += len;
                *out_len = total_len;
                success = 1;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}