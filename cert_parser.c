#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "include/imp_cert.h"

// 全局变量：证书文件路径
const char *cert_file = "server/ca-server/UserCerts/U001.crt";

// 函数声明
int save_cert_binary(const ImpCert *cert, const char *filename);
char* get_output_filename(const char *input_path);

int main() {
    
    // 创建证书结构
    ImpCert cert;
    memset(&cert, 0, sizeof(ImpCert));
    
    // 加载证书
    if (!load_cert(&cert, cert_file)) {
        fprintf(stderr, "错误：加载证书失败\n");
        return 1;
    }
    printf("成功加载证书文件: %s\n", cert_file);
    
    // 显示证书信息
    print_cert_info(&cert);
    
    // 生成输出文件名
    char *output_file = get_output_filename(cert_file);
    if (!output_file) {
        fprintf(stderr, "错误：生成输出文件名失败\n");
        free_cert(&cert);
        return 1;
    }
    
    // 保存为二进制格式
    if (!save_cert_binary(&cert, output_file)) {
        fprintf(stderr, "错误：保存二进制证书失败\n");
        free(output_file);
        free_cert(&cert);
        return 1;
    }
    
    printf("成功保存证书为二进制格式: %s\n", output_file);
    
    // 清理资源
    free(output_file);
    free_cert(&cert);
    
    return 0;
}

/**
 * 将证书以二进制形式保存到文件（不使用DER编码）
 * 直接写入75字节的基本数据，对于V2版本额外写入扩展数据
 */
int save_cert_binary(const ImpCert *cert, const char *filename) {
    if (!cert || !filename) {
        return 0;
    }
    
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "无法创建输出文件 %s: %s\n", filename, strerror(errno));
        return 0;
    }
    
    // 直接写入证书的前75字节（基本字段数据）
    if (fwrite(cert, 75, 1, fp) != 1) {
        fprintf(stderr, "写入证书基本数据失败\n");
        fclose(fp);
        return 0;
    }
    
    // 对于V2版本，写入扩展数据（不是指针）
    if (cert->Version == CERT_V2 && cert->Extensions) {
        if (fwrite(cert->Extensions, sizeof(ImpCertExt), 1, fp) != 1) {
            fprintf(stderr, "写入扩展信息失败\n");
            fclose(fp);
            return 0;
        }
    }
    
    fclose(fp);
    
    // 显示保存的数据大小
    long file_size = 0;
    fp = fopen(filename, "rb");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        fclose(fp);
        printf("二进制文件大小: %ld 字节\n", file_size);
    }
    
    return 1;
}

/**
 * 根据输入文件路径生成输出文件名
 * 将.crt扩展名改为.bin
 */
char* get_output_filename(const char *input_path) {
    if (!input_path) {
        return NULL;
    }
    
    // 获取文件名部分
    const char *base_name = strrchr(input_path, '/');
    if (base_name) {
        base_name++; // 跳过'/'
    } else {
        base_name = input_path;
    }
    
    // 分配内存用于输出文件名
    size_t len = strlen(base_name);
    char *output_name = malloc(len + 1);
    if (!output_name) {
        return NULL;
    }
    
    strcpy(output_name, base_name);
    
    // 查找.crt扩展名并替换为.bin
    char *dot = strrchr(output_name, '.');
    if (dot && strcmp(dot, ".crt") == 0) {
        strcpy(dot, ".bin");
    } else {
        // 如果没有.crt扩展名，直接添加.bin
        strcat(output_name, ".bin");
    }
    
    return output_name;
}
