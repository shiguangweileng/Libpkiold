#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "gm_crypto.h"

// gcc ../src/gm_crypto.c sm4-test.c -I../include -lcrypto -o sm4-test
// 打印十六进制数据
void print_hex(const char *label, const unsigned char *data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main()
{
    // 测试数据
    const char *plaintext = "123";
    int plaintext_len = strlen(plaintext);

    unsigned char *encrypted = NULL;
    unsigned char *decrypted = NULL;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char iv[SM4_IV_SIZE];

    /* 动态申请内存，考虑填充，预留一个块大小 */
    encrypted = (unsigned char *)malloc(plaintext_len + SM4_BLOCK_SIZE);
    if (!encrypted) {
        printf("错误：申请加密缓冲区失败\n");
        return 1;
    }
    decrypted = (unsigned char *)malloc(plaintext_len + SM4_BLOCK_SIZE);
    if (!decrypted) {
        printf("错误：申请解密缓冲区失败\n");
        free(encrypted);
        return 1;
    }
    int encrypted_len = 0;
    int decrypted_len = 0;
    printf("=== SM4 加密库测试 ===\n\n");
    
    // 1. 生成密钥和IV
    printf("1. 生成密钥和IV\n");
    if (!sm4_generate_key(key)) {
        printf("错误：生成密钥失败\n");
        return 1;
    }
    
    if (!sm4_generate_iv(iv)) {
        printf("错误：生成IV失败\n");
        return 1;
    }
    
    print_hex("密钥", key, SM4_KEY_SIZE);
    print_hex("IV", iv, SM4_IV_SIZE);
    printf("\n");
    
    // 2. 显示原始数据
    printf("2. 原始数据\n");
    printf("明文: %s\n", plaintext);
    printf("明文长度: %d 字节\n\n", plaintext_len);
    
    // 3. 加密
    printf("3. 加密\n");
    if (!sm4_encrypt(encrypted, &encrypted_len, 
                     (unsigned char*)plaintext, plaintext_len, 
                     key, iv)) {
        printf("错误：加密失败\n");
        return 1;
    }
    
    printf("加密成功，密文长度: %d 字节\n", encrypted_len);
    print_hex("密文", encrypted, encrypted_len);
    printf("\n");
    
    // 4. 解密
    printf("4. 解密\n");
    if (!sm4_decrypt(decrypted, &decrypted_len,
                     encrypted, encrypted_len,
                     key, iv)) {
        printf("错误：解密失败\n");
        return 1;
    }
    
    // 添加字符串结束符
    decrypted[decrypted_len] = '\0';
    
    printf("解密成功，明文长度: %d 字节\n", decrypted_len);
    printf("解密结果: %s\n\n", decrypted);
    
    // 5. 验证结果
    printf("5. 验证结果\n");
    if (decrypted_len == plaintext_len && 
        memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("✓ 测试成功！加密和解密正确！\n");
    } else {
        printf("✗ 测试失败！解密结果与原文不符！\n");
        return 1;
    }
    free(encrypted);
    free(decrypted);
    return 0;
}