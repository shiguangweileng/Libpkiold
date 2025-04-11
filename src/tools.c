#include "tools.h"
#include "gm_crypto.h"

void print_hex(const char *name, const unsigned char *data, int data_len)
{
    printf("%s: (%d字节) ", name, data_len);
    for (int i = 0; i < data_len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_bn(const char *name, const BIGNUM *bn)
{
    char *hex = BN_bn2hex(bn);
    printf("%s: %s\n", name, hex);
    OPENSSL_free(hex);
}

//计算r=e×k+d_ca (mod n)
int calculate_r(unsigned char *r_bytes, const unsigned char *e_bytes, const BIGNUM *k, 
                const unsigned char *d_bytes, const BIGNUM *n) 
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return 0;
    }
    
    // 转换字节串为BIGNUM
    BIGNUM *e = BN_bin2bn(e_bytes, 32, NULL);
    BIGNUM *d = BN_bin2bn(d_bytes, 32, NULL);
    BIGNUM *r = BN_new();
    
    if (!e || !d || !r) {
        BN_CTX_free(ctx);
        BN_free(e);
        BN_free(d);
        BN_free(r);
        return 0;
    }
    
    // 计算 r = (e*k + d) mod n
    int success = 0;
    BN_CTX_start(ctx);
    BIGNUM *temp = BN_CTX_get(ctx);
    if (temp &&
        BN_mod_mul(temp, e, k, n, ctx) &&
        BN_mod_add(r, temp, d, n, ctx)) {
        // 转换结果为字节串
        success = BN_bn2bin(r, r_bytes) > 0;
    }
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(e);
    BN_free(d);
    BN_free(r);
    
    return success;
}

int verify_key_pair(const EC_GROUP *group, const EC_POINT *pub_key, const BIGNUM *pri_key)
{
    EC_POINT *check_point = EC_POINT_new(group);
    if (!check_point)
    {
        return 0;
    }
    // 计算公钥
    if (!EC_POINT_mul(group, check_point, pri_key, NULL, NULL, NULL))
    {
        EC_POINT_free(check_point);
        return 0;
    }

    // 相等会返回0
    int result = EC_POINT_cmp(group, pub_key, check_point, NULL);

    EC_POINT_free(check_point);
    return result == 0;
}

int verify_key_pair_bytes(const EC_GROUP *group, const unsigned char *pub_key, const unsigned char *pri_key)
{
    EC_POINT *pub_point = EC_POINT_new(group);
    BIGNUM *pri_bn = BN_bin2bn(pri_key, SM2_PRI_MAX_SIZE, NULL);
    if (!pub_point || !pri_bn)
    {
        return 0;
    }
    // 将字节串转换为EC_POINT
    if (!EC_POINT_oct2point(group, pub_point, pub_key, SM2_PUB_MAX_SIZE, NULL))
    {
        EC_POINT_free(pub_point);
        BN_free(pri_bn);
        return 0;
    }
    int result = verify_key_pair(group, pub_point, pri_bn);
    EC_POINT_free(pub_point);
    BN_free(pri_bn);
    return result;
}

int rec_pubkey(unsigned char *Qu_bytes, const unsigned char *e_bytes, 
               const EC_POINT *Pu, const unsigned char *Q_ca_bytes)
{
    int success = 0;
    EC_POINT *Qu = EC_POINT_new(group);
    EC_POINT *Q_ca = EC_POINT_new(group);
    BIGNUM *e = BN_bin2bn(e_bytes, 32, NULL);
    
    if (!Qu || !Q_ca || !e) {
        goto cleanup;
    }
    
    // 转换Q_ca字节串为EC_POINT
    if (!EC_POINT_oct2point(group, Q_ca, Q_ca_bytes, SM2_PUB_MAX_SIZE, NULL)) {
        goto cleanup;
    }
    
    // 计算 Qu = e*Pu + Q_ca
    if (!EC_POINT_mul(group, Qu, NULL, Pu, e, NULL) ||
        !EC_POINT_add(group, Qu, Qu, Q_ca, NULL)) {
        goto cleanup;
    }
    
    // 转换结果为字节串
    success = EC_POINT_point2oct(group, Qu, POINT_CONVERSION_UNCOMPRESSED, 
                                Qu_bytes, SM2_PUB_MAX_SIZE, NULL) > 0;
    
cleanup:
    EC_POINT_free(Qu);
    EC_POINT_free(Q_ca);
    BN_free(e);
    
    return success;
}







