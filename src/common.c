#include "common.h"
#include "gm_crypto.h"
#include <endian.h>
#include <time.h>

// 全局SM2参数
EC_GROUP *group = NULL;
BIGNUM *order = NULL;

int sm2_params_init() {
    // 创建SM2椭圆曲线组
    group = EC_GROUP_new_by_curve_name(1172);
    if (!group) {
        printf("初始化SM2曲线参数失败！\n");
        return 0;
    }
    
    order = BN_new();
    if (!order || !EC_GROUP_get_order(group, order, NULL)) {
        printf("获取SM2曲线阶失败！\n");
        sm2_params_cleanup();
        return 0;
    }
    
    return 1;
}

void sm2_params_cleanup() {
    if (order) {
        BN_free(order);
        order = NULL;
    }
    
    if (group) {
        EC_GROUP_free(group);
        group = NULL;
    }
}

int CA_init(unsigned char *pub, unsigned char *priv)
{
    // SM2椭圆曲线参数初始化
    if(!sm2_params_init()){
        printf("SM2参数初始化失败！\n");
        return -1;
    }
    // 从文件读取CA公钥
    FILE *pub_fp = fopen("ca_pub.key", "rb");
    if (pub_fp == NULL) {
        return 0;
    }
    size_t read_bytes = fread(pub, 1, SM2_PUB_MAX_SIZE, pub_fp);
    fclose(pub_fp);
    if (read_bytes != SM2_PUB_MAX_SIZE) {
        return 0;
    }
    // 从文件读取CA私钥
    FILE *priv_fp = fopen("ca_priv.key", "rb");
    if (priv_fp == NULL) {
        return 0;
    }
    read_bytes = fread(priv, 1, SM2_PRI_MAX_SIZE, priv_fp);
    fclose(priv_fp);
    if (read_bytes != SM2_PRI_MAX_SIZE) {
        return 0;
    }
    return 1;
}

int User_init(unsigned char *pub){

    // SM2椭圆曲线参数初始化
    if(!sm2_params_init()){
        printf("SM2参数初始化失败！\n");
        return -1;
    }
    // 从文件读取CA公钥
    FILE *pub_fp = fopen("ca_pub.key", "rb");
    if (pub_fp == NULL) {
        return 0;
    }
    size_t read_bytes = fread(pub, 1, SM2_PUB_MAX_SIZE, pub_fp);
    fclose(pub_fp);
    if (read_bytes != SM2_PUB_MAX_SIZE) {
        return 0;
    }
    return 1;
}


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

int validate_timestamp(uint64_t timestamp) {
    // 获取当前时间
    time_t current_time = time(NULL);
    time_t ts_time = (time_t)timestamp;
    
    // 检查时间戳是否来自未来
    if (ts_time > current_time) {
        printf("时间戳验证失败：时间戳来自未来 (当前: %ld, 收到: %ld)\n", 
               (long)current_time, (long)ts_time);
        return 0;
    }
    
    // 检查时间戳是否过期（与当前时间相差超过TS_MAX_DIFF秒）
    time_t time_diff = current_time - ts_time;
    if (time_diff > TS_MAX_DIFF) {
        printf("时间戳验证失败：时间戳过期 (超时: %ld秒)\n", (long)time_diff);
        return 0;
    }
    
    return 1;
}

// 从十六进制字符串读取证书哈希值
int parse_hex_hash(unsigned char *cert_hash, int hash_size) {
    char hex_hash[hash_size * 2 + 1]; // 十六进制字符串加上\0
    memset(hex_hash, 0, sizeof(hex_hash));
    
    // 请求用户输入证书哈希值（十六进制形式）
    printf("请输入证书哈希值（十六进制格式，%d字符）: ", hash_size * 2);
    if (scanf("%s", hex_hash) != 1) {
        printf("输入格式错误\n");
        return 0;
    }
    
    // 检查输入的哈希值长度是否正确
    if (strlen(hex_hash) != hash_size * 2) {
        printf("哈希值长度错误，应为%d字符\n", hash_size * 2);
        return 0;
    }
    
    // 将十六进制字符串转换为二进制形式
    for (int i = 0; i < hash_size; i++) {
        char byte_str[3] = {hex_hash[i*2], hex_hash[i*2+1], '\0'};
        cert_hash[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }
    
    return 1;
}

// 清空输入缓冲区
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}


