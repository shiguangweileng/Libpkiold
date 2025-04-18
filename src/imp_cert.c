#include "imp_cert.h"
#include <string.h>
#include <stdio.h>

/**
 * 将公钥点保存到证书中（内部辅助函数）
 */
static int set_Pu2cert(ImpCert *cert, const EC_POINT *pub_key) {
    if (!cert || !pub_key || !group) {
        return 0;
    }

    // 提取公钥的x坐标和y坐标
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!EC_POINT_get_affine_coordinates(group, pub_key, x, y, NULL)) {
        BN_free(x);
        BN_free(y);
        return 0;
    }

    // 获取y坐标的奇偶性（用于后续重构）
    int y_is_odd = BN_is_odd(y);

    // 将x坐标转换为二进制
    unsigned char x_bin[32] = {0};
    int x_len = BN_bn2bin(x, x_bin);
    
    // 将x坐标拷贝到证书公钥字段
    memset(cert->PubKey, 0, sizeof(cert->PubKey));
    // 第一个字节存储y的奇偶性信息 (0x02表示y为偶数，0x03表示y为奇数)
    cert->PubKey[0] = y_is_odd ? 0x03 : 0x02;
    memcpy(cert->PubKey + 1, x_bin, x_len);
    
    BN_free(x);
    BN_free(y);
    return 1;
}

int set_cert(ImpCert *cert, 
             const unsigned char *serial_num,
             const unsigned char *issuer_id, 
             const unsigned char *subject_id,
             time_t start_time,
             time_t end_time,
             const EC_POINT *Pu)
{
    // 参数检查
    if (cert == NULL||serial_num == NULL|| 
        issuer_id == NULL || subject_id == NULL||Pu == NULL) {
        return 0;
    }
    // 逻辑检查 - 有效期
    if (end_time <= start_time) {
        return 0;
    }
    
    // 清空目标区域
    memset(cert->SerialNum, 0, sizeof(cert->SerialNum));
    memset(cert->IssuerID, 0, sizeof(cert->IssuerID));
    memset(cert->SubjectID, 0, sizeof(cert->SubjectID));
    
    // 复制数据，确保不会溢出，并且字符串以NULL结尾
    // 每个字段最多复制8个字节，留出1个字节用于NULL字符
    strncpy((char *)cert->SerialNum, (const char *)serial_num, sizeof(cert->SerialNum) - 1);
    strncpy((char *)cert->IssuerID, (const char *)issuer_id, sizeof(cert->IssuerID) - 1);
    strncpy((char *)cert->SubjectID, (const char *)subject_id, sizeof(cert->SubjectID) - 1);
    
    // 设置有效期
    memcpy(cert->Validity, &start_time, sizeof(time_t));
    memcpy(cert->Validity + sizeof(time_t), &end_time, sizeof(time_t));
    
    if (!set_Pu2cert(cert, Pu)) {
        return 0;
    }
    
    return 1;
}

//检查证书是否过期
int validate_cert(const ImpCert *cert)
{
    time_t start_time, end_time, current_time;
    // 参数检查
    if (cert == NULL) {
        return 0;
    }
    // 提取时间戳
    memcpy(&start_time, cert->Validity, sizeof(time_t));
    memcpy(&end_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    
    // 获取当前时间
    current_time = time(NULL);
    
    // 检查是否在有效期内
    return (current_time >= start_time && current_time <= end_time) ? 1 : 0;
}

int save_cert(const ImpCert *cert, const char *filename)
{
    // 参数检查
    if (cert == NULL || filename == NULL) {
        return 0;
    }
    
    // 打开文件
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        return 0;
    }
    
    // 写入证书数据
    int written = fwrite(cert, sizeof(ImpCert), 1, fp);
    
    // 关闭文件
    fclose(fp);
    
    return (written == 1) ? 1 : 0;
}
int load_cert(ImpCert *cert, const char *filename)
{
    // 参数检查
    if (cert == NULL || filename == NULL) {
        return 0;
    }
    
    // 打开文件
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        return 0;
    }
    
    // 读取证书数据
    int read = fread(cert, sizeof(ImpCert), 1, fp);
    
    // 关闭文件
    fclose(fp);
    
    return (read == 1) ? 1 : 0;
}

void print_cert_info(const ImpCert *cert) {
    time_t start_time, end_time;
    memcpy(&start_time, cert->Validity, sizeof(time_t));
    memcpy(&end_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    printf("---证书信息:\n");
    printf("---序列号: %s\n", cert->SerialNum);
    printf("---颁发者: %s\n", cert->IssuerID);
    printf("---主体ID: %s\n", cert->SubjectID);
    printf("---生效时间: %s", ctime(&start_time));
    printf("---到期时间: %s", ctime(&end_time));
    printf("---部分公钥: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", cert->PubKey[i]);
    }
    printf("\n");
}

int getPu(const ImpCert *cert, EC_POINT *Pu) {
    if (!cert || !group || !Pu) {
        return 0;
    }
    
    // 提取y的奇偶性信息
    int y_is_odd = (cert->PubKey[0] == 0x03);
    
    // 提取x坐标
    BIGNUM *x = BN_bin2bn(cert->PubKey + 1, 32, NULL);
    if (!x) {
        return 0;
    }
    
    // 根据x坐标和y的奇偶性重构点
    int success = EC_POINT_set_compressed_coordinates(group, Pu, x, y_is_odd, NULL);
    
    BN_free(x);
    return success;
}









