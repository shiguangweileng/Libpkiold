#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/gm_crypto.h"
#include "../include/common.h"

// 十六进制字符串转换为二进制数据
int hex_to_bin(const char *hex, unsigned char *bin, int bin_size) {
    int hex_len = strlen(hex);
    int i, j;
    
    // 检查输入是否有效
    if (hex_len % 2 != 0 || bin_size < hex_len / 2) {
        return 0;
    }
    
    for (i = 0, j = 0; i < hex_len; i += 2, j++) {
        char byte[3] = {hex[i], hex[i + 1], '\0'};
        bin[j] = (unsigned char)strtol(byte, NULL, 16);
    }
    
    return j;
}

int main() {
    // 初始化SM2参数
    if (!sm2_params_init()) {
        printf("SM2参数初始化失败\n");
        return -1;
    }
    
    // 定义公私钥
    const char *priv_key_hex = "6c23d0ae31f661186014748fb35f428cb341d27c02bdf8ba3edc4c3ee8c617b4";
    const char *pub_key_hex = "04d50c1b596c5fa3d830ef68357181fb8edb8fd095f91600739fb87a36c3ee7f0bdb045d4a82c58e96d1f76e71fb725c70a29f0da4a9903db7dc981deefa79cf11";
    
    unsigned char priv_key[32] = {0};
    unsigned char pub_key[65] = {0};
    
    // 转换十六进制字符串到二进制
    if (!hex_to_bin(priv_key_hex, priv_key, sizeof(priv_key))) {
        printf("私钥转换失败\n");
        sm2_params_cleanup();
        return -1;
    }
    
    if (!hex_to_bin(pub_key_hex, pub_key, sizeof(pub_key))) {
        printf("公钥转换失败\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 打印转换后的密钥（确认转换正确）
    printf("私钥: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", priv_key[i]);
    }
    printf("\n");
    
    printf("公钥: ");
    for (int i = 0; i < 65; i++) {
        printf("%02x", pub_key[i]);
    }
    printf("\n\n");
    
    // 创建测试消息
    unsigned char test_msg[32];
    memset(test_msg, 0xAA, sizeof(test_msg));
    
    printf("测试消息: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", test_msg[i]);
    }
    printf("\n\n");
    
    // 方法1：使用签名验签测试
    printf("方法1: 使用签名验签测试\n");
    unsigned char signature[64] = {0};
    
    // 使用私钥签名
    if (!sm2_sign(signature, test_msg, sizeof(test_msg), priv_key)) {
        printf("签名失败\n");
        sm2_params_cleanup();
        return -1;
    }
    
    printf("签名结果: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    
    // 使用公钥验证签名
    if (sm2_verify(signature, test_msg, sizeof(test_msg), pub_key)) {
        printf("验证成功: 公钥和私钥是配对的!\n");
    } else {
        printf("验证失败: 公钥和私钥不匹配!\n");
    }
    
    // 方法2：使用verify_key_pair_bytes函数测试
    printf("\n方法2: 使用verify_key_pair_bytes函数测试\n");
    if (verify_key_pair_bytes(group, pub_key, priv_key)) {
        printf("验证成功: 公钥和私钥是配对的!\n");
    } else {
        printf("验证失败: 公钥和私钥不匹配!\n");
    }
    
    // 清理资源
    sm2_params_cleanup();
    
    return 0;
}
