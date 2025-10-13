#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#define SYSTEM_KEY_SIZE 32  // 256位 = 32字节
#define KEK_SIZE 32         // 密钥加密密钥大小(256位)
#define KEK_SEGMENTS 4      // KEK分段数量，修改为4，使32能被整除
#define IV_SIZE 16          // 初始化向量大小
#define AUTH_TAG_SIZE 16    // GCM认证标签大小

// 生成随机密钥
int generate_random_key(unsigned char *key, size_t key_size) {
    if (RAND_bytes(key, key_size) != 1) {
        fprintf(stderr, "生成随机密钥时出错\n");
        return 0;
    }
    return 1;
}

// 将KEK分割为多个段
int split_kek(const unsigned char *kek, size_t kek_size, 
              unsigned char segments[KEK_SEGMENTS][KEK_SIZE/KEK_SEGMENTS + 1], 
              size_t *segment_size) {
    if (kek_size % KEK_SEGMENTS != 0) {
        fprintf(stderr, "KEK大小必须能被分段数整除\n");
        return 0;
    }

    *segment_size = kek_size / KEK_SEGMENTS;
    for (int i = 0; i < KEK_SEGMENTS; i++) {
        memcpy(segments[i], kek + i * (*segment_size), *segment_size);
    }
    return 1;
}

// 重组KEK
int combine_kek(const unsigned char segments[KEK_SEGMENTS][KEK_SIZE/KEK_SEGMENTS + 1], 
                size_t segment_size, unsigned char *kek) {
    for (int i = 0; i < KEK_SEGMENTS; i++) {
        memcpy(kek + i * segment_size, segments[i], segment_size);
    }
    return 1;
}

// 使用KEK加密系统密钥 (GCM模式)
int encrypt_system_key(const unsigned char *system_key, size_t system_key_size, 
                       const unsigned char *kek, size_t kek_size, 
                       unsigned char *iv, unsigned char *tag,
                       unsigned char *encrypted_key, size_t *encrypted_key_size) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "创建密码上下文失败\n");
        return 0;
    }

    // 生成随机IV
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "生成随机IV失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 初始化加密操作，使用GCM模式
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "初始化加密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 设置IV长度 (对GCM很重要)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        fprintf(stderr, "设置IV长度失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 设置密钥和IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, kek, iv) != 1) {
        fprintf(stderr, "设置密钥和IV失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    // 加密系统密钥
    if (EVP_EncryptUpdate(ctx, encrypted_key, &len, system_key, system_key_size) != 1) {
        fprintf(stderr, "加密系统密钥失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *encrypted_key_size = len;

    // 完成加密操作
    if (EVP_EncryptFinal_ex(ctx, encrypted_key + len, &len) != 1) {
        fprintf(stderr, "完成加密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *encrypted_key_size += len;

    // 获取认证标签
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "获取认证标签失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// 使用KEK解密系统密钥 (GCM模式)
int decrypt_system_key(const unsigned char *encrypted_key, size_t encrypted_key_size, 
                       const unsigned char *kek, size_t kek_size, 
                       const unsigned char *iv, const unsigned char *tag,
                       unsigned char *system_key, size_t *system_key_size) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "创建密码上下文失败\n");
        return 0;
    }

    // 初始化解密操作，使用GCM模式
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "初始化解密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 设置IV长度
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        fprintf(stderr, "设置IV长度失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 设置密钥和IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, kek, iv) != 1) {
        fprintf(stderr, "设置密钥和IV失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    // 解密系统密钥
    if (EVP_DecryptUpdate(ctx, system_key, &len, encrypted_key, encrypted_key_size) != 1) {
        fprintf(stderr, "解密系统密钥失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *system_key_size = len;

    // 设置预期的认证标签
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_SIZE, (void*)tag) != 1) {
        fprintf(stderr, "设置认证标签失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 完成解密操作并验证认证标签
    int ret = EVP_DecryptFinal_ex(ctx, system_key + len, &len);
    if (ret <= 0) {
        // 认证失败 - 数据可能被篡改
        fprintf(stderr, "认证失败! 密钥可能已被篡改\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *system_key_size += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// 将数据保存到文件
int save_to_file(const char *filename, const unsigned char *data, size_t data_size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "打开文件 %s 写入失败\n", filename);
        return 0;
    }

    size_t written = fwrite(data, 1, data_size, file);
    fclose(file);

    if (written != data_size) {
        fprintf(stderr, "写入所有数据到文件 %s 失败\n", filename);
        return 0;
    }

    return 1;
}

// 从文件加载数据
int load_from_file(const char *filename, unsigned char *data, size_t *data_size, size_t max_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "打开文件 %s 读取失败\n", filename);
        return 0;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size > max_size) {
        fprintf(stderr, "文件 %s 太大\n", filename);
        fclose(file);
        return 0;
    }

    size_t read = fread(data, 1, file_size, file);
    fclose(file);

    if (read != file_size) {
        fprintf(stderr, "从文件 %s 读取所有数据失败\n", filename);
        return 0;
    }

    *data_size = read;
    return 1;
}

// 以十六进制打印数据
void print_hex(const unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    OpenSSL_add_all_algorithms();
    
    // 1. 生成256位系统密钥
    unsigned char system_key[SYSTEM_KEY_SIZE];
    if (!generate_random_key(system_key, SYSTEM_KEY_SIZE)) {
        return 1;
    }
    printf("系统密钥 (十六进制): ");
    print_hex(system_key, SYSTEM_KEY_SIZE);

    // 2. 生成密钥加密密钥 (KEK)
    unsigned char kek[KEK_SIZE];
    if (!generate_random_key(kek, KEK_SIZE)) {
        return 1;
    }
    printf("密钥加密密钥 (十六进制): ");
    print_hex(kek, KEK_SIZE);

    // 3. 将KEK分成多个部分
    unsigned char kek_segments[KEK_SEGMENTS][KEK_SIZE/KEK_SEGMENTS + 1];
    size_t segment_size;
    if (!split_kek(kek, KEK_SIZE, kek_segments, &segment_size)) {
        return 1;
    }
    
    printf("KEK分段:\n");
    for (int i = 0; i < KEK_SEGMENTS; i++) {
        printf("段 %d: ", i + 1);
        print_hex(kek_segments[i], segment_size);
    }

    // 4. 使用KEK加密系统密钥
    unsigned char iv[IV_SIZE];
    unsigned char tag[AUTH_TAG_SIZE]; // 认证标签
    unsigned char encrypted_key[SYSTEM_KEY_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t encrypted_key_size;
    
    if (!encrypt_system_key(system_key, SYSTEM_KEY_SIZE, kek, KEK_SIZE, iv, tag, encrypted_key, &encrypted_key_size)) {
        return 1;
    }
    printf("加密后的系统密钥 (十六进制): ");
    print_hex(encrypted_key, encrypted_key_size);
    printf("认证标签 (十六进制): ");
    print_hex(tag, AUTH_TAG_SIZE);
    
    // 5. 将加密后的系统密钥、认证标签和分段KEK存储到文件
    if (!save_to_file("encrypted_system_key.bin", encrypted_key, encrypted_key_size)) {
        return 1;
    }
    printf("加密后的系统密钥已保存到 encrypted_system_key.bin\n");
    
    if (!save_to_file("auth_tag.bin", tag, AUTH_TAG_SIZE)) {
        return 1;
    }
    printf("认证标签已保存到 auth_tag.bin\n");
    
    if (!save_to_file("iv.bin", iv, IV_SIZE)) {
        return 1;
    }
    printf("初始化向量已保存到 iv.bin\n");
    
    for (int i = 0; i < KEK_SEGMENTS; i++) {
        char filename[32];
        snprintf(filename, sizeof(filename), "kek_segment_%d.bin", i + 1);
        if (!save_to_file(filename, kek_segments[i], segment_size)) {
            return 1;
        }
        printf("KEK段 %d 已保存到 %s\n", i + 1, filename);
    }
    
    // 测试: 重新加载密钥并解密
    printf("\n测试重新加载并解密:\n");
    
    // 重新加载加密的系统密钥、IV和认证标签
    unsigned char loaded_encrypted_key[SYSTEM_KEY_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t loaded_encrypted_key_size;
    unsigned char loaded_iv[IV_SIZE];
    size_t loaded_iv_size;
    unsigned char loaded_tag[AUTH_TAG_SIZE];
    size_t loaded_tag_size;
    
    if (!load_from_file("encrypted_system_key.bin", loaded_encrypted_key, &loaded_encrypted_key_size, sizeof(loaded_encrypted_key)) ||
        !load_from_file("iv.bin", loaded_iv, &loaded_iv_size, sizeof(loaded_iv)) ||
        !load_from_file("auth_tag.bin", loaded_tag, &loaded_tag_size, sizeof(loaded_tag))) {
        return 1;
    }
    
    // 重新加载KEK段
    unsigned char loaded_kek_segments[KEK_SEGMENTS][KEK_SIZE/KEK_SEGMENTS + 1];
    size_t loaded_segment_sizes[KEK_SEGMENTS];
    
    for (int i = 0; i < KEK_SEGMENTS; i++) {
        char filename[32];
        snprintf(filename, sizeof(filename), "kek_segment_%d.bin", i + 1);
        if (!load_from_file(filename, loaded_kek_segments[i], &loaded_segment_sizes[i], sizeof(loaded_kek_segments[i]))) {
            return 1;
        }
    }
    
    // 重组KEK
    unsigned char reconstructed_kek[KEK_SIZE];
    if (!combine_kek(loaded_kek_segments, segment_size, reconstructed_kek)) {
        return 1;
    }
    printf("重组的KEK (十六进制): ");
    print_hex(reconstructed_kek, KEK_SIZE);
    
    // 使用重组的KEK解密系统密钥
    unsigned char decrypted_system_key[SYSTEM_KEY_SIZE];
    size_t decrypted_system_key_size;
    
    if (!decrypt_system_key(loaded_encrypted_key, loaded_encrypted_key_size, 
                          reconstructed_kek, KEK_SIZE, 
                          loaded_iv, loaded_tag, 
                          decrypted_system_key, &decrypted_system_key_size)) {
        return 1;
    }
    
    printf("解密后的系统密钥 (十六进制): ");
    print_hex(decrypted_system_key, decrypted_system_key_size);
    
    // 验证原始系统密钥和解密后的系统密钥是否相同
    if (decrypted_system_key_size == SYSTEM_KEY_SIZE && 
        memcmp(system_key, decrypted_system_key, SYSTEM_KEY_SIZE) == 0) {
        printf("验证成功: 解密后的系统密钥与原始系统密钥匹配!\n");
    } else {
        printf("验证失败: 解密后的系统密钥与原始系统密钥不匹配!\n");
    }
    
    EVP_cleanup();
    return 0;
}
