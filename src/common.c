#include "common.h"
#include "gm_crypto.h"
#include <endian.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int CA_init(unsigned char *pub, unsigned char *priv)
{
    // SM2椭圆曲线参数初始化
    if(!global_params_init()){
        printf("SM2参数初始化失败！\n");
        return -1;
    }
    // 从文件读取CA公钥
    FILE *pub_fp = fopen("ca_pub.key", "rb");
    if (pub_fp == NULL) {
        return 0;
    }
    int read_bytes = fread(pub, 1, SM2_PUB_MAX_SIZE, pub_fp);
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
    if(!global_params_init()){
        printf("SM2参数初始化失败！\n");
        return -1;
    }
    // 从文件读取CA公钥
    FILE *pub_fp = fopen("ca_pub.key", "rb");
    if (pub_fp == NULL) {
        return 0;
    }
    int read_bytes = fread(pub, 1, SM2_PUB_MAX_SIZE, pub_fp);
    fclose(pub_fp);
    if (read_bytes != SM2_PUB_MAX_SIZE) {
        return 0;
    }
    return 1;
}

void print_hex(const char *name, const unsigned char *data, int data_len)
{
    printf("%s(%d字节) ", name, data_len);
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
        if (e) BN_free(e);
        if (d) BN_free(d);
        if (r) BN_free(r);
        return 0;
    }
    
    // 计算 r = (e*k + d) mod n
    int success = 0;
    BN_CTX_start(ctx);
    BIGNUM *temp = BN_CTX_get(ctx);
    if (temp &&
        BN_mod_mul(temp, e, k, n, ctx) &&
        BN_mod_add(r, temp, d, n, ctx)) {
        
        // 先清零输出缓冲区
        memset(r_bytes, 0, SM2_PRI_MAX_SIZE);
        
        // 获取实际需要的字节数
        int r_bytes_len = BN_num_bytes(r);
        
        // 确保BIGNUM转换为固定长度的字节数组（32字节），处理前导零的问题
        if (r_bytes_len <= SM2_PRI_MAX_SIZE) {
            // 将数据写入缓冲区的尾部，保留前导零
            BN_bn2bin(r, r_bytes + (SM2_PRI_MAX_SIZE - r_bytes_len));
            success = 1;
        }
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
    EC_POINT *e_Pu = EC_POINT_new(group);
    BIGNUM *e = BN_bin2bn(e_bytes, 32, NULL);
    BN_CTX *ctx = BN_CTX_new();
    
    if (!Qu || !Q_ca || !e || !ctx) {
        goto cleanup;
    }
    
    // 转换Q_ca字节串为EC_POINT
    if (!EC_POINT_oct2point(group, Q_ca, Q_ca_bytes, SM2_PUB_MAX_SIZE, ctx)) {
        goto cleanup;
    }
    
    // 计算 Qu = e*Pu + Q_ca，使用ctx提高精度
    if (!EC_POINT_mul(group, e_Pu, NULL, Pu, e, ctx) ||
        !EC_POINT_add(group, Qu, e_Pu, Q_ca, ctx)) {
        goto cleanup;
    }
    
    // 转换结果为字节串，使用ctx提高精度
    success = EC_POINT_point2oct(group, Qu, POINT_CONVERSION_UNCOMPRESSED, 
                                Qu_bytes, SM2_PUB_MAX_SIZE, ctx) > 0;
    
cleanup:
    if (ctx) BN_CTX_free(ctx);
    if (Qu) EC_POINT_free(Qu);
    if (Q_ca) EC_POINT_free(Q_ca);
    if (e) BN_free(e);
    
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

// 安全删除文件 - 通过5次随机数据覆写确保文件内容不可恢复
int secure_delete_file(const char *filename) {
    FILE *file = fopen(filename, "r+b");
    if (!file) {
        // 文件不存在或无法打开，不需要安全删除
        return 1;
    }
    
    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(file);
        remove(filename);
        return 1;
    }
    
    // 分配覆写缓冲区
    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(file);
        printf("内存分配失败，无法安全删除文件: %s\n", filename);
        return 0;
    }
    
    int pass_count = 5;  // 使用随机数据覆写5次
    int ret = 1;
    
    // 覆写文件内容
    for (int pass = 0; pass < pass_count; pass++) {
        // 生成随机数据
        for (long i = 0; i < file_size; i++) {
            buffer[i] = rand() & 0xFF;
        }
        
        // 覆写文件
        fseek(file, 0, SEEK_SET);
        if (fwrite(buffer, 1, file_size, file) != (size_t)file_size) {
            printf("覆写文件失败: %s\n", filename);
            ret = 0;
            goto cleanup;
        }
        
        // 确保数据写入磁盘
        fflush(file);
        fsync(fileno(file));
    }
    
cleanup:
    if (buffer) {
        free(buffer);
    }
    fclose(file);
    
    // 最后删除文件
    if (remove(filename) != 0) {
        printf("删除文件失败: %s\n", filename);
        return 0;
    }
    
    return ret;
}

