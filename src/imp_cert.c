#include "imp_cert.h"
#include <string.h>
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <errno.h>
#include <stdlib.h>
#include "gm_crypto.h"

/**
 * 将公钥点保存到证书中（内部辅助函数）
 */
static int set_Pu2cert(unsigned char *pubKey, const EC_POINT *pub_key) {
    if (!pubKey || !pub_key || !group) {
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
    memset(pubKey, 0, 33);
    // 第一个字节存储y的奇偶性信息 (0x02表示y为偶数，0x03表示y为奇偶)
    pubKey[0] = y_is_odd ? 0x03 : 0x02;
    
    // 将x坐标转换为固定长度的二进制，处理前导零问题
    int x_bytes_len = BN_num_bytes(x);
    if (x_bytes_len <= 32) {
        // 固定32字节，将x放在末尾，保留前导零
        BN_bn2bin(x, pubKey + 1 + (32 - x_bytes_len));
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
    const unsigned char *pubKey = cert->PubKey;
    
    // 提取y的奇偶性信息
    int y_is_odd = (pubKey[0] == 0x03);
    // 公钥字段的第一个字节是标识符，后32个字节是x坐标
    BIGNUM *x = BN_bin2bn(pubKey + 1, 32, NULL);
    if (!x) {
        return 0;
    }
    // 根据x坐标和y的奇偶性重构点
    int success = EC_POINT_set_compressed_coordinates(group, Pu, x, y_is_odd, NULL);
    BN_free(x);
    return success;
}

// 释放证书资源
void free_cert(ImpCert *cert) {
    if (cert->Extensions) {
        free(cert->Extensions);
        cert->Extensions = NULL;
    }
}

// 通用证书设置函数
int set_cert(ImpCert *cert,
             unsigned char version,
             const unsigned char *serial_num,
             const unsigned char *issuer_id, 
             const unsigned char *subject_id,
             time_t start_time,
             time_t end_time,
             time_t issue_time,
             const EC_POINT *Pu,
             const ImpCertExt *extensions)
{
    // 参数检查与逻辑检查
    if (cert == NULL || serial_num == NULL || 
        issuer_id == NULL || subject_id == NULL || Pu == NULL ||
        end_time <= start_time ||
        (version != CERT_V1 && version != CERT_V2) ||
        (version == CERT_V2 && extensions == NULL)) {
        return 0;
    }
    
    // 设置证书版本
    cert->Version = version;
    
    // 清空并设置基础字段
    memset(cert->SerialNum, 0, sizeof(cert->SerialNum));
    memcpy(cert->IssuerID, issuer_id, SUBJECT_ID_LEN);
    memcpy(cert->SubjectID, subject_id, SUBJECT_ID_LEN);

    strncpy((char *)cert->SerialNum, (const char *)serial_num, sizeof(cert->SerialNum) - 1);
    
    memcpy(cert->Validity, &start_time, sizeof(time_t));
    memcpy(cert->Validity + sizeof(time_t), &end_time, sizeof(time_t));
    
    // 设置颁发时间
    memcpy(cert->IssueTime, &issue_time, sizeof(time_t));
    
    // 设置公钥
    if (!set_Pu2cert(cert->PubKey, Pu)) {
        return 0;
    }
    
    // 处理扩展信息
    if (version == CERT_V1) {
        // V1证书没有扩展信息
        cert->Extensions = NULL;
    } else if (version == CERT_V2) {
        // V2证书需要复制扩展信息
        cert->Extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!cert->Extensions) {
            return 0;
        }
        memcpy(cert->Extensions, extensions, sizeof(ImpCertExt));
    }
    
    return 1;
}

// 检查证书是否过期
int validate_cert(const ImpCert *cert)
{
    if (!cert) {
        return 0;
    }
    
    time_t start_time, end_time, current_time;
    
    // 获取存储的时间戳
    memcpy(&start_time, cert->Validity, sizeof(time_t));
    memcpy(&end_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    
    // 获取当前时间并检查有效期
    current_time = time(NULL);
    return (current_time >= start_time && current_time <= end_time) ? 1 : 0;
}

// ASN.1序列化规则
ASN1_SEQUENCE(ImpCertAsn1) = {
    ASN1_SIMPLE(ImpCertAsn1, version, ASN1_INTEGER),
    ASN1_SIMPLE(ImpCertAsn1, serialNum, ASN1_UTF8STRING),
    ASN1_SIMPLE(ImpCertAsn1, issuerID, ASN1_UTF8STRING),
    ASN1_SIMPLE(ImpCertAsn1, subjectID, ASN1_UTF8STRING),
    ASN1_SIMPLE(ImpCertAsn1, startTime, ASN1_INTEGER),
    ASN1_SIMPLE(ImpCertAsn1, endTime, ASN1_INTEGER),
    ASN1_SIMPLE(ImpCertAsn1, issueTime, ASN1_INTEGER),
    ASN1_SIMPLE(ImpCertAsn1, pubKey, ASN1_OCTET_STRING),
    ASN1_OPT(ImpCertAsn1, usage, ASN1_INTEGER),
    ASN1_OPT(ImpCertAsn1, signAlg, ASN1_INTEGER),
    ASN1_OPT(ImpCertAsn1, hashAlg, ASN1_INTEGER),
    ASN1_OPT(ImpCertAsn1, extraInfo, ASN1_OCTET_STRING)
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
    time_t start_time, end_time, issue_time;
    int ret = 0;
    
    // 获取版本和对应的字段
    const unsigned char *serialNum = cert->SerialNum;
    const unsigned char *issuerID = cert->IssuerID;
    const unsigned char *subjectID = cert->SubjectID;
    const unsigned char *validity = cert->Validity;
    const unsigned char *pubKey = cert->PubKey;
    unsigned char version = cert->Version;
    
    // 提取时间戳
    memcpy(&start_time, validity, sizeof(time_t));
    memcpy(&end_time, validity + sizeof(time_t), sizeof(time_t));
    memcpy(&issue_time, cert->IssueTime, sizeof(time_t));
    
    // 设置版本
    asn1_cert->version = ASN1_INTEGER_new();
    if (!asn1_cert->version || !ASN1_INTEGER_set(asn1_cert->version, version)) {
        goto cleanup;
    }
    
    // 设置字符串字段
    asn1_cert->serialNum = ASN1_UTF8STRING_new();
    asn1_cert->issuerID = ASN1_UTF8STRING_new();
    asn1_cert->subjectID = ASN1_UTF8STRING_new();
    
    if (!asn1_cert->serialNum || !asn1_cert->issuerID || !asn1_cert->subjectID ||
        !ASN1_STRING_set(asn1_cert->serialNum, serialNum, strlen((char*)serialNum)) ||
        !ASN1_STRING_set(asn1_cert->issuerID, issuerID, SUBJECT_ID_LEN) ||
        !ASN1_STRING_set(asn1_cert->subjectID, subjectID, SUBJECT_ID_LEN)) {
        goto cleanup;
    }
    
    // 设置时间字段
    asn1_cert->startTime = ASN1_INTEGER_new();
    asn1_cert->endTime = ASN1_INTEGER_new();
    asn1_cert->issueTime = ASN1_INTEGER_new();
    if (!asn1_cert->startTime || !asn1_cert->endTime || !asn1_cert->issueTime || 
        !ASN1_INTEGER_set_int64(asn1_cert->startTime, start_time) ||
        !ASN1_INTEGER_set_int64(asn1_cert->endTime, end_time) ||
        !ASN1_INTEGER_set_int64(asn1_cert->issueTime, issue_time)) {
        goto cleanup;
    }
    
    // 设置公钥
    asn1_cert->pubKey = ASN1_OCTET_STRING_new();
    if (!asn1_cert->pubKey || 
        !ASN1_OCTET_STRING_set(asn1_cert->pubKey, pubKey, 33)) {
        goto cleanup;
    }
    
    // 对于V2证书，设置额外字段
    if (version == CERT_V2 && cert->Extensions) {
        asn1_cert->usage = ASN1_INTEGER_new();
        asn1_cert->signAlg = ASN1_INTEGER_new();
        asn1_cert->hashAlg = ASN1_INTEGER_new();
        asn1_cert->extraInfo = ASN1_OCTET_STRING_new();
        
        if (!asn1_cert->usage || !asn1_cert->signAlg || !asn1_cert->hashAlg || !asn1_cert->extraInfo ||
            !ASN1_INTEGER_set(asn1_cert->usage, cert->Extensions->Usage) ||
            !ASN1_INTEGER_set(asn1_cert->signAlg, cert->Extensions->SignAlg) ||
            !ASN1_INTEGER_set(asn1_cert->hashAlg, cert->Extensions->HashAlg) ||
            !ASN1_OCTET_STRING_set(asn1_cert->extraInfo, cert->Extensions->ExtraInfo, sizeof(cert->Extensions->ExtraInfo))) {
            goto cleanup;
        }
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
    
    // 获取版本
    unsigned char version = 0;
    if (asn1_cert->version) {
        version = ASN1_INTEGER_get(asn1_cert->version);
    }
    
    if (version != CERT_V1 && version != CERT_V2) {
        fprintf(stderr, "加载证书失败: 不支持的证书版本\n");
        ImpCertAsn1_free(asn1_cert);
        return 0;
    }
    cert->Version = version;
    
    // 处理扩展字段
    if (version == CERT_V2) {
        cert->Extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!cert->Extensions) {
            fprintf(stderr, "加载证书失败: 内存分配错误\n");
            ImpCertAsn1_free(asn1_cert);
            return 0;
        }
        memset(cert->Extensions, 0, sizeof(ImpCertExt));
    } else {
        cert->Extensions = NULL;
    }
    
    // 复制字符串字段
    if (asn1_cert->serialNum && ASN1_STRING_length(asn1_cert->serialNum) > 0) {
        strncpy((char*)cert->SerialNum, (char*)ASN1_STRING_get0_data(asn1_cert->serialNum), 
                sizeof(cert->SerialNum) - 1);
    }
    if (asn1_cert->issuerID && ASN1_STRING_length(asn1_cert->issuerID) > 0) {
        memcpy(cert->IssuerID, ASN1_STRING_get0_data(asn1_cert->issuerID), 
                SUBJECT_ID_LEN);
    }
    if (asn1_cert->subjectID && ASN1_STRING_length(asn1_cert->subjectID) > 0) {
        memcpy(cert->SubjectID, ASN1_STRING_get0_data(asn1_cert->subjectID), 
                SUBJECT_ID_LEN);
    }
    
    // 复制时间字段
    time_t start_time = 0, end_time = 0, issue_time = 0;
    if (asn1_cert->startTime) {
        ASN1_INTEGER_get_int64(&start_time, asn1_cert->startTime);
    }
    if (asn1_cert->endTime) {
        ASN1_INTEGER_get_int64(&end_time, asn1_cert->endTime);
    }
    if (asn1_cert->issueTime) {
        ASN1_INTEGER_get_int64(&issue_time, asn1_cert->issueTime);
    }
    memcpy(cert->Validity, &start_time, sizeof(time_t));
    memcpy(cert->Validity + sizeof(time_t), &end_time, sizeof(time_t));
    memcpy(cert->IssueTime, &issue_time, sizeof(time_t));
    
    // 复制公钥
    if (asn1_cert->pubKey && ASN1_STRING_length(asn1_cert->pubKey) == 33) {
        memcpy(cert->PubKey, ASN1_STRING_get0_data(asn1_cert->pubKey), 33);
    }
    
    // 对于V2证书，还需要处理额外字段
    if (version == CERT_V2 && cert->Extensions) {
        if (asn1_cert->usage) {
            cert->Extensions->Usage = (unsigned char)ASN1_INTEGER_get(asn1_cert->usage);
        }
        if (asn1_cert->signAlg) {
            cert->Extensions->SignAlg = (unsigned char)ASN1_INTEGER_get(asn1_cert->signAlg);
        }
        if (asn1_cert->hashAlg) {
            cert->Extensions->HashAlg = (unsigned char)ASN1_INTEGER_get(asn1_cert->hashAlg);
        }
        if (asn1_cert->extraInfo && ASN1_STRING_length(asn1_cert->extraInfo) <= sizeof(cert->Extensions->ExtraInfo)) {
            memcpy(cert->Extensions->ExtraInfo, ASN1_STRING_get0_data(asn1_cert->extraInfo),
                   ASN1_STRING_length(asn1_cert->extraInfo));
        }
    }
    
    ImpCertAsn1_free(asn1_cert);
    return 1;
}

void print_cert_info(const ImpCert *cert) {
    if (!cert) {
        printf("错误：无效的证书\n");
        return;
    }
    
    time_t start_time, end_time, issue_time;
    unsigned char version = cert->Version;
    
    printf("---证书信息:\n");
    printf("---证书版本: V%d\n", version);
    
    printf("---序列号: %s\n", cert->SerialNum);
    
    // 使用定长打印，确保只打印4字节
    printf("---颁发者: ");
    for (int i = 0; i < SUBJECT_ID_LEN; i++) {
        printf("%c", cert->IssuerID[i]);
    }
    printf("\n");
    
    printf("---主体ID: ");
    for (int i = 0; i < SUBJECT_ID_LEN; i++) {
        printf("%c", cert->SubjectID[i]);
    }
    printf("\n");
    
    memcpy(&start_time, cert->Validity, sizeof(time_t));
    memcpy(&end_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    memcpy(&issue_time, cert->IssueTime, sizeof(time_t));
    
    printf("---颁发时间: %s", ctime(&issue_time));
    printf("---生效时间: %s", ctime(&start_time));
    printf("---到期时间: %s", ctime(&end_time));
    printf("---部分公钥: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", cert->PubKey[i]);
    }
    printf("\n");
    
    // 打印V2特有信息
    if (version == CERT_V2 && cert->Extensions) {
        printf("---用途: 0x%02x\n", cert->Extensions->Usage);
        printf("---签名算法: 0x%02x\n", cert->Extensions->SignAlg);
        printf("---哈希算法: 0x%02x\n", cert->Extensions->HashAlg);
        printf("---额外信息: ");
        for (int i = 0; i < sizeof(cert->Extensions->ExtraInfo); i++) {
            printf("%02x", cert->Extensions->ExtraInfo[i]);
        }
        printf("\n");
    }
}

int calc_cert_hash(const ImpCert *cert, unsigned char *hash_out) {
    if (!cert || !hash_out) {
        return 0;
    }

    if (cert->Version == CERT_V1 || cert->Extensions == NULL) {
        // V1证书或没有扩展信息的情况，直接计算证书结构体的哈希
        sm3_hash((const unsigned char *)cert, sizeof(ImpCert), hash_out);
        return 1;
    }
    else if (cert->Version == CERT_V2) {
        // 证书基本信息长度（不包含Extensions指针）
        size_t base_len = sizeof(ImpCert) - sizeof(ImpCertExt*);
        unsigned char temp_buffer[base_len + sizeof(ImpCertExt)];
        
        // 复制ImpCert结构体中除Extensions指针外的所有字段
        memcpy(temp_buffer, cert, base_len);
        
        // 将扩展数据内容复制到临时缓冲区的后半部分
        memcpy(temp_buffer + base_len, cert->Extensions, sizeof(ImpCertExt));
        
        // 计算组合数据的哈希
        sm3_hash(temp_buffer, base_len + sizeof(ImpCertExt), hash_out);
        return 1;
    }
    return 0;
}






