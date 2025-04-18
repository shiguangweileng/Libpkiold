#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "../../include/common.h"
#include "../../include/gm_crypto.h"
#include "../../include/imp_cert.h"
#include "../../include/hashmap.h"
#include "../../include/crlmanager.h"
#include "../../include/network.h"

// 存储相关信息的全局变量
ImpCert loaded_cert;
hashmap* local_crl = NULL;
CRLManager* crl_manager = NULL;
unsigned char priv_key[SM2_PRI_MAX_SIZE];
unsigned char pub_key[SM2_PUB_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];
int has_cert = 0;

// 函数声明
int init_crl_manager();
int load_keys_and_cert(const char *user_id);
int request_registration(int sock, const char *user_id);
int request_cert_update(int sock, const char *user_id);

int main() {
    char server_ip[16] = "127.0.0.1";
    char user_id[9] = "U0000003";
    int sock = -1;
    int result = 0;
    int update_count = 0;
    
    printf("启动自动证书更新测试程序\n");
    
    // 初始化SM2参数
    if (!sm2_params_init()) {
        printf("SM2参数初始化失败\n");
        return -1;
    }
    
    // 初始化CA公钥
    if (!User_init(Q_ca)) {
        printf("加载CA公钥失败！\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 初始化CRL管理器
    if (!init_crl_manager()) {
        printf("初始化CRL管理器失败！\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 尝试加载现有证书
    has_cert = load_keys_and_cert(user_id);
    
    // 如果没有证书，需要先注册
    if (!has_cert) {
        printf("未找到证书，首先执行注册操作...\n");
        sock = connect_to_server(server_ip, PORT);
        if (sock < 0) {
            printf("无法连接到服务器\n");
            return -1;
        }
        
        result = request_registration(sock, user_id);
        close(sock);
        
        if (!result) {
            printf("注册失败，退出程序\n");
            if (crl_manager) CRLManager_free(crl_manager);
            if (local_crl) hashmap_destroy(local_crl);
            sm2_params_cleanup();
            return -1;
        }
        
        printf("注册成功，加载新证书\n");
        has_cert = load_keys_and_cert(user_id);
        if (!has_cert) {
            printf("无法加载新证书，退出程序\n");
            return -1;
        }
    }
    
    // 开始自动更新循环
    printf("开始证书自动更新测试，每隔0.5秒更新一次\n");
    printf("按Ctrl+C终止程序\n\n");
    
    while (1) {
        update_count++;
        
        // 连接到服务器
        sock = connect_to_server(server_ip, PORT);
        if (sock < 0) {
            printf("第%d次，更新失败 - 无法连接到服务器\n", update_count);
            usleep(500000); // 等待0.5秒
            continue;
        }
        
        // 执行证书更新
        result = request_cert_update(sock, user_id);
        close(sock);
        
        // 输出结果
        if (result) {
            printf("第%d次，更新成功\n", update_count);
            has_cert = load_keys_and_cert(user_id);
        } else {
            printf("第%d次，更新失败\n", update_count);
        }
        
        // 等待0.5秒
        usleep(1000000);
    }
    
    // 释放资源（实际上永远不会执行到这里，除非循环被中断）
    if (crl_manager) CRLManager_free(crl_manager);
    if (local_crl) hashmap_destroy(local_crl);
    sm2_params_cleanup();
    
    return 0;
}

// 初始化CRL管理器
int init_crl_manager() {
    // 初始化local_crl哈希表，初始大小为512
    local_crl = crl_hashmap_create(512);
    if (!local_crl) {
        printf("创建local_crl哈希表失败！\n");
        return 0;
    }
    
    // 创建新的CRL管理器
    crl_manager = CRLManager_init(512, 0);
    if (!crl_manager) {
        printf("创建CRL管理器失败！\n");
        hashmap_destroy(local_crl);
        local_crl = NULL;
        return 0;
    }
    
    return 1;
}

// 加载证书和密钥
int load_keys_and_cert(const char *user_id) {
    char cert_filename[SUBJECT_ID_SIZE + 5] = {0}; // ID + ".crt"
    char priv_key_filename[SUBJECT_ID_SIZE + 11] = {0}; // ID + "_priv.key"
    char pub_key_filename[SUBJECT_ID_SIZE + 10] = {0}; // ID + "_pub.key"
    
    sprintf(cert_filename, "%s.crt", user_id);
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    
    // 检查证书文件是否存在
    FILE *cert_file = fopen(cert_filename, "rb");
    if (!cert_file) {
        return 0;
    }
    
    // 加载证书
    if (!load_cert(&loaded_cert, cert_filename)) {
        fclose(cert_file);
        return 0;
    }
    fclose(cert_file);
    
    // 加载私钥
    FILE *priv_file = fopen(priv_key_filename, "rb");
    if (!priv_file) {
        return 0;
    }
    
    if (fread(priv_key, 1, SM2_PRI_MAX_SIZE, priv_file) != SM2_PRI_MAX_SIZE) {
        fclose(priv_file);
        return 0;
    }
    fclose(priv_file);
    
    // 加载公钥
    FILE *pub_file = fopen(pub_key_filename, "rb");
    if (!pub_file) {
        return 0;
    }
    if (fread(pub_key, 1, SM2_PUB_MAX_SIZE, pub_file) != SM2_PUB_MAX_SIZE) {
        fclose(pub_file);
        return 0;
    }
    fclose(pub_file);
    
    return 1;
}

// 注册函数（简化版）
int request_registration(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    
    // 设置秘密值Ku
    BIGNUM *Ku = BN_new();
    BN_rand_range(Ku, order);

    // 计算临时公钥Ru=Ku*G
    EC_POINT *Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        BN_free(Ku);
        if (Ru) EC_POINT_free(Ru);
        return 0;
    }
    
    // 将Ru转换为字节数组以便发送
    unsigned char Ru_bytes[SM2_PUB_MAX_SIZE];
    int ru_len = EC_POINT_point2oct(group, Ru, POINT_CONVERSION_UNCOMPRESSED, 
                                    Ru_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 准备发送数据：ID + Ru
    unsigned char send_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(send_data, user_id, SUBJECT_ID_LEN);
    memcpy(send_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 发送ID和Ru给CA
    if (!send_message(sock, CMD_SEND_ID_AND_RU, send_data, SUBJECT_ID_LEN + ru_len)) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 接收CA发送的证书和部分私钥r
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0 || cmd != CMD_SEND_CERT_AND_R || 
        data_len != sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 解析证书和部分私钥r
    ImpCert cert;
    unsigned char r[SM2_PRI_MAX_SIZE];
    memcpy(&cert, buffer, sizeof(ImpCert));
    memcpy(r, buffer + sizeof(ImpCert), SM2_PRI_MAX_SIZE);

    // 准备文件名
    char cert_filename[SUBJECT_ID_SIZE + 5] = {0};
    char priv_key_filename[SUBJECT_ID_SIZE + 11] = {0};
    char pub_key_filename[SUBJECT_ID_SIZE + 10] = {0};
    
    sprintf(cert_filename, "%s.crt", user_id);
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    
    // 保存证书
    if(!save_cert(&cert, cert_filename)) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 获取隐式证书中的Pu
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&cert, Pu);

    // 计算隐式证书哈希值e
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);

    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)) {
        // 使用签名-验签方式验证
        unsigned char test_msg[32];
        memset(test_msg, 0xAA, sizeof(test_msg));
        
        unsigned char signature[64] = {0};
        if (!sm2_sign(signature, test_msg, sizeof(test_msg), d_u) ||
            !sm2_verify(signature, test_msg, sizeof(test_msg), Qu)) {
            BN_free(Ku);
            EC_POINT_free(Ru);
            EC_POINT_free(Pu);
            return 0;
        }
    }
    
    // 更新全局变量
    memcpy(priv_key, d_u, SM2_PRI_MAX_SIZE);
    memcpy(pub_key, Qu, SM2_PUB_MAX_SIZE);
    
    // 保存私钥和公钥
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
    // 释放资源
    BN_free(Ku);
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    
    return 1;
}

// 证书更新函数（简化版）
int request_cert_update(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};

    // 设置新的秘密值Ku
    BIGNUM *Ku = BN_new();
    BN_rand_range(Ku, order);

    // 计算临时公钥Ru=Ku*G
    EC_POINT *Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        BN_free(Ku);
        if (Ru) EC_POINT_free(Ru);
        return 0;
    }
    
    // 将Ru转换为字节数组以便发送
    unsigned char Ru_bytes[SM2_PUB_MAX_SIZE];
    int ru_len = EC_POINT_point2oct(group, Ru, POINT_CONVERSION_UNCOMPRESSED, 
                                    Ru_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 准备要签名的数据：ID + Ru
    unsigned char sign_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(sign_data, user_id, SUBJECT_ID_LEN);
    memcpy(sign_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 用私钥对数据签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, SUBJECT_ID_LEN + ru_len, priv_key)) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 准备发送的完整数据：ID + Ru + 签名
    unsigned char send_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE + 64];
    memcpy(send_data, sign_data, SUBJECT_ID_LEN + ru_len);
    memcpy(send_data + SUBJECT_ID_LEN + ru_len, signature, 64);
    
    // 发送更新请求给CA
    if (!send_message(sock, CMD_REQUEST_UPDATE, send_data, SUBJECT_ID_LEN + ru_len + 64)) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 接收CA发送的新证书和部分私钥r
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0 || cmd != CMD_SEND_UPDATED_CERT || 
        data_len != sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 解析新证书和部分私钥r
    ImpCert new_cert;
    unsigned char r[SM2_PRI_MAX_SIZE];
    memcpy(&new_cert, buffer, sizeof(ImpCert));
    memcpy(r, buffer + sizeof(ImpCert), SM2_PRI_MAX_SIZE);
    
    // 保存新证书
    char cert_filename[SUBJECT_ID_SIZE + 5] = {0};
    sprintf(cert_filename, "%s.crt", user_id);
    if (!save_cert(&new_cert, cert_filename)) {
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 获取隐式证书中的Pu
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&new_cert, Pu);

    // 计算隐式证书哈希值
    unsigned char e[32];
    sm3_hash((const unsigned char *)&new_cert, sizeof(ImpCert), e);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);

    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)) {
        // 使用签名-验签方式验证
        unsigned char test_msg[32];
        memset(test_msg, 0xAA, sizeof(test_msg));
        
        unsigned char signature[64] = {0};
        if (!sm2_sign(signature, test_msg, sizeof(test_msg), d_u) ||
            !sm2_verify(signature, test_msg, sizeof(test_msg), Qu)) {
            BN_free(Ku);
            EC_POINT_free(Ru);
            EC_POINT_free(Pu);
            return 0;
        }
    }
    
    // 更新全局变量
    memcpy(priv_key, d_u, SM2_PRI_MAX_SIZE);
    memcpy(pub_key, Qu, SM2_PUB_MAX_SIZE);
    memcpy(&loaded_cert, &new_cert, sizeof(ImpCert));
    
    // 保存用户新私钥
    char priv_key_filename[SUBJECT_ID_SIZE + 11] = {0};
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
    // 保存用户新公钥
    char pub_key_filename[SUBJECT_ID_SIZE + 10] = {0};
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
    // 释放资源
    BN_free(Ku);
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    
    return 1;
} 