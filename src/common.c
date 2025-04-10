#include "common.h"

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


