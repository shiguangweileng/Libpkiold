#include "std_crypto.h"
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* 全局参数 */
EC_GROUP *std_group = NULL;
BIGNUM   *std_order = NULL;

int std_params_init()
{
    if (std_group && std_order) return 1; /* 已初始化 */

    std_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!std_group) return 0;

    std_order = BN_new();
    if (!std_order || !EC_GROUP_get_order(std_group, std_order, NULL))
        return 0;

    return 1;
}

void std_params_cleanup()
{
    if (std_order) { BN_free(std_order); std_order = NULL; }
    if (std_group) { EC_GROUP_free(std_group); std_group = NULL; }
}

typedef struct ecc_signature_st {
    BIGNUM *r;
    BIGNUM *s;
} ECC_SIGNATURE;

DECLARE_ASN1_FUNCTIONS(ECC_SIGNATURE)
ASN1_SEQUENCE(ECC_SIGNATURE) = {
    ASN1_SIMPLE(ECC_SIGNATURE, r, BIGNUM),
    ASN1_SIMPLE(ECC_SIGNATURE, s, BIGNUM)
} ASN1_SEQUENCE_END(ECC_SIGNATURE)
IMPLEMENT_ASN1_FUNCTIONS(ECC_SIGNATURE);

static EVP_PKEY *ecc_new_key(const unsigned char *key, size_t key_len, int is_pri)
{
    if (!key) return NULL;
    if (!std_params_init()) return NULL;

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) return NULL;

    EVP_PKEY *ret = NULL;
    BIGNUM *bn = NULL;
    int selection = 0;

    int ok = 0;
    do {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0)) break;

        if (is_pri) {
            /* 私钥创建：仅提供 priv 字段即可，由于选择 KEYPAIR，OpenSSL 会自动推导公钥 */
            bn = BN_bin2bn(key, key_len, NULL);
            if (!bn) break;
            if (!OSSL_PARAM_BLD_push_BN(bld, "priv", bn)) break;
            selection = EVP_PKEY_KEYPAIR;
        } else {
            if (!OSSL_PARAM_BLD_push_octet_string(bld, "pub", key, key_len)) break;
            selection = EVP_PKEY_PUBLIC_KEY;
        }

        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        if (!params) break;

        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!pctx) { OSSL_PARAM_free(params); break; }

        if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); OSSL_PARAM_free(params); break; }
        if (EVP_PKEY_fromdata(pctx, &ret, selection, params) <= 0) {
            EVP_PKEY_CTX_free(pctx); OSSL_PARAM_free(params); break; }

        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
        ok = 1;
    } while (0);

    if (!ok && ret) { EVP_PKEY_free(ret); ret = NULL; }
    if (bn) BN_free(bn);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int ecc_rs_to_asn1(unsigned char *out, size_t *out_len, const unsigned char *in)
{
    if (!out || !out_len || !in) return 0;
    ECC_SIGNATURE *sig = ECC_SIGNATURE_new();
    if (!sig) return 0;

    sig->r = BN_bin2bn(in, 32, NULL);
    sig->s = BN_bin2bn(in + 32, 32, NULL);
    int len = i2d_ECC_SIGNATURE(sig, &out);
    if (len <= 0) { ECC_SIGNATURE_free(sig); return 0; }
    *out_len = len;
    ECC_SIGNATURE_free(sig);
    return 1;
}

static int ecc_sig_to_rs(unsigned char *out, const unsigned char *in, int in_len)
{
    if (!out || !in) return 0;
    ECC_SIGNATURE *sig = NULL;
    const unsigned char *p = in;
    int success = d2i_ECC_SIGNATURE(&sig, &p, in_len) &&
                  BN_bn2binpad(sig->r, out, 32) &&
                  BN_bn2binpad(sig->s, out + 32, 32);
    if (sig) ECC_SIGNATURE_free(sig);
    return success;
}

int ecc_key_pair_new(unsigned char *pub, unsigned char *pri)
{
    if (!pub || !pri) return 0;
    /* 使用OpenSSL 3.2 EVP_EC_gen 高级接口生成 prime256v1 密钥对 */

    EVP_PKEY *pkey = EVP_EC_gen("prime256v1");
    if (!pkey) return 0;

    int success = 0;
    BIGNUM *priv_bn = NULL;
    size_t pub_len  = ECC_PUB_MAX_SIZE;

    do {
        /* 获取公钥 */
        if (!EVP_PKEY_get_octet_string_param(pkey, "pub", pub, pub_len, &pub_len))
            break;
        if (pub_len != ECC_PUB_MAX_SIZE) break;

        /* 获取私钥 */
        if (!EVP_PKEY_get_bn_param(pkey, "priv", &priv_bn)) break;
        if (BN_bn2binpad(priv_bn, pri, ECC_PRI_MAX_SIZE) != ECC_PRI_MAX_SIZE) break;

        success = 1;
    } while (0);

    if (priv_bn) BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    return success;
}

int ecc_sign(unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pri)
{
    if (!sig || !in || !pri) return 0;
    if (!std_params_init()) return 0;

    unsigned char der_sig[80];
    size_t der_len = sizeof(der_sig);
    int success = 0;

    EVP_PKEY *pkey = ecc_new_key(pri, ECC_PRI_MAX_SIZE, 1);
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    do {
        if (!pkey) break;
        mdctx = EVP_MD_CTX_new();
        if (!mdctx) break;
        if (!EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey)) break;
        if (!EVP_DigestSignUpdate(mdctx, in, in_len)) break;
        if (!EVP_DigestSignFinal(mdctx, der_sig, &der_len)) break;
        success = ecc_sig_to_rs(sig, der_sig, (int)der_len);
    } while (0);

    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey) EVP_PKEY_free(pkey);
    return success;
}

int ecc_verify(const unsigned char *sig, const unsigned char *in, size_t in_len, const unsigned char *pub)
{
    if (!sig || !in || !pub) return 0;
    if (!std_params_init()) return 0;

    /* 将RS转为ASN.1 */
    unsigned char der[80];
    size_t der_len = sizeof(der);
    if (!ecc_rs_to_asn1(der, &der_len, sig)) return 0;

    int success = 0;
    EVP_PKEY *pkey = ecc_new_key(pub, ECC_PUB_MAX_SIZE, 0);
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    do {
        if (!pkey) break;
        mdctx = EVP_MD_CTX_new();
        if (!mdctx) break;
        if (!EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pkey)) break;
        if (!EVP_DigestVerifyUpdate(mdctx, in, in_len)) break;
        success = EVP_DigestVerifyFinal(mdctx, der, der_len);
    } while (0);

    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey) EVP_PKEY_free(pkey);
    return success == 1;
}

int sha256_hash(const unsigned char *in, size_t in_len, unsigned char *md)
{
    /* 参数有效性检查 */
    if (!md || !in)
        return 0;

    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        return 0;
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if(1 != EVP_DigestUpdate(mdctx, in, in_len)) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, md, &md_len)) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);

    if (md_len != SHA256_MD_SIZE) {
        return 0;
    }

    return 1;
}

int sha256_kdf(const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
    if (!in || !out || out_len == 0 || out_len > SHA256_MD_SIZE)
        return 0;

    unsigned char digest[SHA256_MD_SIZE];
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

    int ret = sha256_hash(buf, buf_len, digest);
    free(buf);
    if (!ret) return 0;

    memcpy(out, digest, out_len);
    return 1;
}

int aes_generate_key(unsigned char *key)
{
    if (!key) return 0;
    return RAND_bytes(key, AES_KEY_SIZE);
}

int aes_generate_iv(unsigned char *iv)
{
    if (!iv) return 0;
    return RAND_bytes(iv, AES_IV_SIZE);
}

int aes_encrypt(unsigned char *out, unsigned char *tag,
                const unsigned char *in, int in_len,
                const unsigned char *key, const unsigned char *iv)
{
    if (!out || !tag || !in || !key || !iv) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0;
    int success = 0;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1)
            break;

        if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1)
            break;

        if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) != 1)
            break;

        success = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

int aes_decrypt(unsigned char *out,
                const unsigned char *in, int in_len,
                const unsigned char *tag,
                const unsigned char *key, const unsigned char *iv)
{
    if (!out || !in || !tag || !key || !iv) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0;
    int success = 0;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1)
            break;

        if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void*)tag) != 1)
            break;

        if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1)
            break;

        success = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}