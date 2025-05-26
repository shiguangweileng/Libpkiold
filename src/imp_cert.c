#include "imp_cert.h"
#include <string.h>
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <errno.h>

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
    
    if (!x || !y || !EC_POINT_get_affine_coordinates(group, pub_key, x, y, NULL)) {
        if (x) BN_free(x);
        if (y) BN_free(y);
        return 0;
    }

    // 获取y坐标的奇偶性（用于后续重构）
    int y_is_odd = BN_is_odd(y);

    // 先清零缓冲区
    memset(cert->PubKey, 0, sizeof(cert->PubKey));
    // 第一个字节存储y的奇偶性信息 (0x02表示y为偶数，0x03表示y为奇偶)
    cert->PubKey[0] = y_is_odd ? 0x03 : 0x02;
    
    // 将x坐标转换为固定长度的二进制，处理前导零问题
    int x_bytes_len = BN_num_bytes(x);
    if (x_bytes_len <= 32) {
        // 固定32字节，将x放在末尾，保留前导零
        BN_bn2bin(x, cert->PubKey + 1 + (32 - x_bytes_len));
    } else {
        // 这种情况不应该发生，因为SM2曲线的x坐标不会超过32字节
        printf("错误：x坐标长度超过32字节！\n");
        BN_free(x);
        BN_free(y);
        return 0;
    }
    
    BN_free(x);
    BN_free(y);
    return 1;
}

int getPu(const ImpCert *cert, EC_POINT *Pu) {
    if (!cert || !group || !Pu) {
        return 0;
    }
    
    // 提取y的奇偶性信息
    int y_is_odd = (cert->PubKey[0] == 0x03);
    
    // 公钥字段的第一个字节是标识符，后32个字节是x坐标
    BIGNUM *x = BN_bin2bn(cert->PubKey + 1, 32, NULL);
    if (!x) {
        return 0;
    }
    
    // 根据x坐标和y的奇偶性重构点
    int success = EC_POINT_set_compressed_coordinates(group, Pu, x, y_is_odd, NULL);
    
    BN_free(x);
    return success;
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

// ASN.1序列化规则
ASN1_SEQUENCE(ImpCertAsn1) = {
    ASN1_SIMPLE(ImpCertAsn1, serialNum, ASN1_UTF8STRING),
    ASN1_SIMPLE(ImpCertAsn1, issuerID, ASN1_UTF8STRING),
    ASN1_SIMPLE(ImpCertAsn1, subjectID, ASN1_UTF8STRING),
    ASN1_SIMPLE(ImpCertAsn1, startTime, ASN1_INTEGER),
    ASN1_SIMPLE(ImpCertAsn1, endTime, ASN1_INTEGER),
    ASN1_SIMPLE(ImpCertAsn1, pubKey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ImpCertAsn1)

// 实现ASN.1函数
IMPLEMENT_ASN1_FUNCTIONS(ImpCertAsn1)

int save_cert(const ImpCert *cert, const char *filename)
{
    // 参数检查
    if (cert == NULL || filename == NULL) {
        fprintf(stderr, "保存证书失败: 无效的参数\n");
        return 0;
    }
    
    // 创建ASN.1结构
    ImpCertAsn1 *asn1_cert = ImpCertAsn1_new();
    if (!asn1_cert) {
        return 0;
    }
    
    // 填充ASN.1结构
    time_t start_time, end_time;
    int ret = 0;
    
    // 提取时间戳
    memcpy(&start_time, cert->Validity, sizeof(time_t));
    memcpy(&end_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    
    // 设置字符串字段
    asn1_cert->serialNum = ASN1_UTF8STRING_new();
    asn1_cert->issuerID = ASN1_UTF8STRING_new();
    asn1_cert->subjectID = ASN1_UTF8STRING_new();
    
    if (!asn1_cert->serialNum || !asn1_cert->issuerID || !asn1_cert->subjectID ||
        !ASN1_STRING_set(asn1_cert->serialNum, cert->SerialNum, strlen((char*)cert->SerialNum)) ||
        !ASN1_STRING_set(asn1_cert->issuerID, cert->IssuerID, strlen((char*)cert->IssuerID)) ||
        !ASN1_STRING_set(asn1_cert->subjectID, cert->SubjectID, strlen((char*)cert->SubjectID))) {
        goto cleanup;
    }
    
    // 设置时间字段
    asn1_cert->startTime = ASN1_INTEGER_new();
    asn1_cert->endTime = ASN1_INTEGER_new();
    if (!asn1_cert->startTime || !asn1_cert->endTime || 
        !ASN1_INTEGER_set_int64(asn1_cert->startTime, start_time) ||
        !ASN1_INTEGER_set_int64(asn1_cert->endTime, end_time)) {
        goto cleanup;
    }
    
    // 设置公钥
    asn1_cert->pubKey = ASN1_OCTET_STRING_new();
    if (!asn1_cert->pubKey || 
        !ASN1_OCTET_STRING_set(asn1_cert->pubKey, cert->PubKey, sizeof(cert->PubKey))) {
        goto cleanup;
    }
    
    // DER编码
    unsigned char *der_data = NULL;
    int der_len = i2d_ImpCertAsn1(asn1_cert, &der_data);
    if (der_len <= 0 || !der_data) {
        goto cleanup;
    }
    
    // 写入文件
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "保存证书失败: 无法打开文件 %s: %s\n", 
                filename, strerror(errno));
        OPENSSL_free(der_data);
        goto cleanup;
    }
    
    size_t written = fwrite(der_data, 1, der_len, fp);
    if (written != der_len) {
        fprintf(stderr, "保存证书失败: 文件写入错误: %s\n", strerror(errno));
        fclose(fp);
        OPENSSL_free(der_data);
        goto cleanup;
    }
    
    ret = 1;  // 成功标志
    fclose(fp);
    OPENSSL_free(der_data);

cleanup:
    ImpCertAsn1_free(asn1_cert);
    return ret;
}

int load_cert(ImpCert *cert, const char *filename)
{
    // 参数检查
    if (cert == NULL || filename == NULL) {
        return 0;
    }
    
    // 读取DER编码文件
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "加载证书失败: 无法打开文件 %s: %s\n", 
                filename, strerror(errno));
        return 0;
    }
    
    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(fp);
        return 0;
    }
    
    // 分配内存
    unsigned char *der_data = (unsigned char*)malloc(file_size);
    if (!der_data) {
        fprintf(stderr, "加载证书失败: 内存分配错误\n");
        fclose(fp);
        return 0;
    }
    
    // 读取DER数据
    size_t read_size = fread(der_data, 1, file_size, fp);
    fclose(fp);
    
    if (read_size != file_size) {
        fprintf(stderr, "加载证书失败: 文件读取错误: %s\n", strerror(errno));
        free(der_data);
        return 0;
    }
    
    // 解码DER数据
    const unsigned char *p = der_data;
    ImpCertAsn1 *asn1_cert = d2i_ImpCertAsn1(NULL, &p, file_size);
    free(der_data);
    
    if (!asn1_cert) {
        fprintf(stderr, "加载证书失败: DER解码失败\n");
        return 0;
    }
    
    // 清空证书结构
    memset(cert, 0, sizeof(ImpCert));
    
    // 复制字符串字段
    if (asn1_cert->serialNum && ASN1_STRING_length(asn1_cert->serialNum) > 0) {
        strncpy((char*)cert->SerialNum, (char*)ASN1_STRING_get0_data(asn1_cert->serialNum), 
                sizeof(cert->SerialNum) - 1);
    }
    
    if (asn1_cert->issuerID && ASN1_STRING_length(asn1_cert->issuerID) > 0) {
        strncpy((char*)cert->IssuerID, (char*)ASN1_STRING_get0_data(asn1_cert->issuerID), 
                sizeof(cert->IssuerID) - 1);
    }
    
    if (asn1_cert->subjectID && ASN1_STRING_length(asn1_cert->subjectID) > 0) {
        strncpy((char*)cert->SubjectID, (char*)ASN1_STRING_get0_data(asn1_cert->subjectID), 
                sizeof(cert->SubjectID) - 1);
    }
    
    // 复制时间字段
    time_t start_time = 0, end_time = 0;
    
    if (asn1_cert->startTime) {
        ASN1_INTEGER_get_int64(&start_time, asn1_cert->startTime);
    }
    
    if (asn1_cert->endTime) {
        ASN1_INTEGER_get_int64(&end_time, asn1_cert->endTime);
    }
    
    memcpy(cert->Validity, &start_time, sizeof(time_t));
    memcpy(cert->Validity + sizeof(time_t), &end_time, sizeof(time_t));
    
    // 复制公钥
    if (asn1_cert->pubKey && ASN1_STRING_length(asn1_cert->pubKey) == sizeof(cert->PubKey)) {
        memcpy(cert->PubKey, ASN1_STRING_get0_data(asn1_cert->pubKey), sizeof(cert->PubKey));
    }
    
    ImpCertAsn1_free(asn1_cert);
    return 1;
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









