#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "common.h"
#include "gm_crypto.h"
#include "imp_cert.h"
#include "hashmap.h"
#include "crlmanager.h"
#include "network.h"
#include "user.h"


//----------------证书处理函数实现-------------------
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
        printf("未找到证书文件: %s\n", cert_filename);
        return 0;
    }
    
    // 加载证书
    if (!load_cert(&loaded_cert, cert_filename)) {
        printf("无法加载证书文件: %s\n", cert_filename);
        fclose(cert_file);
        return 0;
    }
    fclose(cert_file);
    
    //print_cert_info(&loaded_cert);
    
    // 加载私钥
    FILE *priv_file = fopen(priv_key_filename, "rb");
    if (!priv_file) {
        printf("未找到私钥文件: %s\n", priv_key_filename);
        return 0;
    }
    
    if (fread(priv_key, 1, SM2_PRI_MAX_SIZE, priv_file) != SM2_PRI_MAX_SIZE) {
        printf("读取私钥文件失败\n");
        fclose(priv_file);
        return 0;
    }
    fclose(priv_file);
    
    // 加载公钥
    FILE *pub_file = fopen(pub_key_filename, "rb");
    if (!pub_file) {
        printf("未找到公钥文件: %s\n", pub_key_filename);
        return 0;
    }
    if (fread(pub_key, 1, SM2_PUB_MAX_SIZE, pub_file) != SM2_PUB_MAX_SIZE) {
        printf("读取公钥文件失败\n");
        fclose(pub_file);
        return 0;
    }
    fclose(pub_file);
    
    printf("[[[成功加载证书和密钥对]]]\n");
    return 1;
}

//----------------用户证书操作函数实现-------------------
int request_registration(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    BIGNUM *Ku = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    int ret = 0;
    
    //--------step1:用户端-----------
    // 设置秘密值Ku
    Ku = BN_new();
    BN_rand_range(Ku, order);

    // 计算临时公钥Ru=Ku*G
    Ru = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        goto cleanup;
    }
    
    // 将Ru转换为字节数组以便发送
    unsigned char Ru_bytes[SM2_PUB_MAX_SIZE];
    int ru_len = EC_POINT_point2oct(group, Ru, POINT_CONVERSION_UNCOMPRESSED, 
                                     Ru_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 准备发送数据：ID + Ru（先ID后Ru）
    unsigned char send_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(send_data, user_id, SUBJECT_ID_LEN);
    memcpy(send_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 发送ID和Ru给CA
    if (!send_message(sock, CMD_SEND_ID_AND_RU, send_data, SUBJECT_ID_LEN + ru_len)) {
        printf("发送ID和临时公钥失败\n");
        goto cleanup;
    }
    
    // 接收CA发送的证书和部分私钥r
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0) {
        printf("接收数据失败\n");
        goto cleanup;
    }
    // 验证命令类型
    if (cmd != CMD_SEND_CERT_AND_R) {
        printf("接收到错误的命令类型: %d\n", cmd);
        goto cleanup;
    }
    // 解析证书和部分私钥r
    ImpCert cert;
    unsigned char r[SM2_PRI_MAX_SIZE];
    if (data_len != sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        printf("接收到的数据长度错误: %d\n", data_len);
        goto cleanup;
    }
    memcpy(&cert, buffer, sizeof(ImpCert));
    memcpy(r, buffer + sizeof(ImpCert), SM2_PRI_MAX_SIZE);

    // 准备文件名
    char pub_key_filename[SUBJECT_ID_SIZE + 10] = {0}; // ID + "_pub.key"
    char priv_key_filename[SUBJECT_ID_SIZE + 11] = {0}; // ID + "_priv.key"
    char cert_filename[SUBJECT_ID_SIZE + 5] = {0}; // ID + ".crt"
    
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    sprintf(cert_filename, "%s.crt", user_id);

    printf("已成功接收证书和部分私钥r\n");
    // 保存证书供后续使用
    if(!save_cert(&cert, cert_filename)){
        printf("保存证书失败\n");
        goto cleanup;
    }
    
    //--------step3:用户端生成最终的公私钥对-------------
    // 获取隐式证书中的Pu
    Pu = EC_POINT_new(group);
    if (!getPu(&cert, Pu)) {
        printf("获取Pu失败\n");
        goto cleanup;
    }
    
    // 计算隐式证书哈希值
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    print_hex("隐式证书哈希值e", e, 32);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, e, Pu, Q_ca)) {
        printf("重构公钥失败\n");
        goto cleanup;
    }

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);
    print_hex("用户私钥d_u", d_u, SM2_PRI_MAX_SIZE);
    
    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)){
        printf("密钥对验证失败！\n");
        goto cleanup;
    }

    // 更新全局变量
    memcpy(priv_key, d_u, SM2_PRI_MAX_SIZE);
    memcpy(pub_key, Qu, SM2_PUB_MAX_SIZE);
    
    // 保存用户私钥供后续使用
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存用户私钥到文件\n");
    }
    
    // 保存用户公钥供后续使用
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存用户公钥到文件\n");
    }
    
    printf("注册过程完成\n");
    ret = 1;
    
cleanup:
    if (Ku) BN_free(Ku);
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    return ret;
}

int request_cert_update(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    BIGNUM *Ku = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    int ret = 0;

    //--------step1:用户端-----------
    // 设置新的秘密值Ku
    Ku = BN_new();
    BN_rand_range(Ku, order);

    // 计算临时公钥Ru=Ku*G
    Ru = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        goto cleanup;
    }

    // 将Ru转换为字节数组以便发送
    unsigned char Ru_bytes[SM2_PUB_MAX_SIZE];
    int ru_len = EC_POINT_point2oct(group, Ru, POINT_CONVERSION_UNCOMPRESSED, 
                                     Ru_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 准备要签名的数据：ID + Ru（先ID后Ru）
    unsigned char sign_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(sign_data, user_id, SUBJECT_ID_LEN);
    memcpy(sign_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 用私钥对数据签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, SUBJECT_ID_LEN + ru_len, priv_key)) {
        printf("签名失败\n");
        goto cleanup;
    }
    
    // 准备发送的完整数据：ID + Ru + 签名
    unsigned char send_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE + 64];
    memcpy(send_data, sign_data, SUBJECT_ID_LEN + ru_len);
    memcpy(send_data + SUBJECT_ID_LEN + ru_len, signature, 64);
    
    // 发送更新请求给CA
    if (!send_message(sock, CMD_REQUEST_UPDATE, send_data, SUBJECT_ID_LEN + ru_len + 64)) {
        printf("发送更新请求失败\n");
        goto cleanup;
    }
    
    // 接收CA发送的新证书和部分私钥r
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0) {
        printf("接收数据失败\n");
        goto cleanup;
    }
    
    // 验证命令类型
    if (cmd != CMD_SEND_UPDATED_CERT) {
        printf("接收到错误的命令类型: %d\n", cmd);
        goto cleanup;
    }
    
    // 解析新证书和部分私钥r
    ImpCert new_cert;
    unsigned char r[SM2_PRI_MAX_SIZE];
    if (data_len != sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        printf("接收到的数据长度错误: %d\n", data_len);
        goto cleanup;
    }
    memcpy(&new_cert, buffer, sizeof(ImpCert));
    memcpy(r, buffer + sizeof(ImpCert), SM2_PRI_MAX_SIZE);
    print_hex("新部分私钥r", r, SM2_PRI_MAX_SIZE);
    
    // 保存新证书供后续使用
    char cert_filename[SUBJECT_ID_SIZE + 5] = {0}; // ID + ".crt"
    sprintf(cert_filename, "%s.crt", user_id);
    if (!save_cert(&new_cert, cert_filename)) {
        printf("保存新证书失败\n");
        goto cleanup;
    }
    
    //--------step3:用户端生成最终的公私钥对-------------
    // 获取隐式证书中的Pu
    Pu = EC_POINT_new(group);
    if (!getPu(&new_cert, Pu)) {
        printf("获取Pu失败\n");
        goto cleanup;
    }

    // 计算隐式证书哈希值
    unsigned char e[32];
    sm3_hash((const unsigned char *)&new_cert, sizeof(ImpCert), e);
    print_hex("新隐式证书哈希值e", e, 32);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, e, Pu, Q_ca)) {
        printf("重构公钥失败\n");
        goto cleanup;
    }

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);

    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)) {
        printf("新密钥对验证失败！\n");
        goto cleanup;
    }
    
    // 更新全局变量
    memcpy(priv_key, d_u, SM2_PRI_MAX_SIZE);
    memcpy(pub_key, Qu, SM2_PUB_MAX_SIZE);

    // 保存用户新私钥供后续使用
    char priv_key_filename[SUBJECT_ID_SIZE + 11] = {0}; // ID + "_priv.key"
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存更新后的用户私钥到文件\n");
    }
    
    // 保存用户新公钥供后续使用
    char pub_key_filename[SUBJECT_ID_SIZE + 10] = {0}; // ID + "_pub.key"
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存更新后的用户公钥到文件\n");
    }
    
    printf("证书更新过程完成\n");
    ret = 1;
    
cleanup:
    if (Ku) BN_free(Ku);
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    return ret;
}

int send_signed_message(int sock, const char *user_id, const char *message) {
    // 检查消息长度
    int message_len = strlen(message);
    if (message_len > MAX_MESSAGE_SIZE) {
        printf("消息过长，最大允许%d字节\n", MAX_MESSAGE_SIZE);
        return 0;
    }
    
    if (!has_cert) {
        printf("错误：需要先加载证书才能发送消息\n");
        return 0;
    }
    
    // 对消息进行签名
    unsigned char signature[64];
    if (!sm2_sign(signature, (const unsigned char *)message, message_len, priv_key)) {
        printf("签名失败\n");
        return 0;
    }
    
    // 准备要发送的数据：消息长度(2字节) + 消息内容 + 签名(64字节) + 证书
    // 总长度：2 + message_len + 64 + sizeof(ImpCert)
    int data_size = 2 + message_len + 64 + sizeof(ImpCert);
    unsigned char *send_data = (unsigned char *)malloc(data_size);
    if (!send_data) {
        printf("内存分配失败\n");
        return 0;
    }
    
    // 填充消息长度（网络字节序）
    send_data[0] = (message_len >> 8) & 0xFF;  // 高字节
    send_data[1] = message_len & 0xFF;         // 低字节
    
    // 填充消息内容
    memcpy(send_data + 2, message, message_len);
    
    // 填充签名
    memcpy(send_data + 2 + message_len, signature, 64);
    
    // 填充证书
    memcpy(send_data + 2 + message_len + 64, &loaded_cert, sizeof(ImpCert));
    
    // 发送数据
    int result = send_message(sock, CMD_SEND_MESSAGE, send_data, data_size);
    free(send_data);
    
    if (result) {
        printf("已成功发送签名消息\n");
        return 1;
    } else {
        printf("发送签名消息失败\n");
        return 0;
    }
}

int online_csp(int sock, const unsigned char *cert_hash) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    
    // 发送证书哈希值到CA进行验证
    if (!send_message(sock, CMD_VERIFY_CERT, cert_hash, CERT_HASH_SIZE)) {
        printf("发送证书验证请求失败\n");
        return -1;
    }
    
    // 接收CA的响应
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0) {
        printf("接收数据失败\n");
        return -1;
    }
    
    // 验证命令类型
    if (cmd != CMD_CERT_STATUS) {
        printf("接收到错误的命令类型: %d\n", cmd);
        return -1;
    }
    
    // 解析响应数据：状态(1字节) + 时间戳(8字节) + 签名(64字节)
    if (data_len != 1 + 8 + 64) {
        printf("接收到的数据长度错误: %d\n", data_len);
        return -1;
    }
    
    // 提取状态和时间戳
    uint8_t status = buffer[0];
    uint64_t timestamp;
    memcpy(&timestamp, buffer + 1, 8);
    
    // 转换为主机字节序
    timestamp = be64toh(timestamp);
    
    // 使用validate_timestamp函数验证时间戳
    if (!validate_timestamp(timestamp)) {
        printf("证书状态响应中的时间戳无效\n");
        return -1;
    }
    
    // 验证CA签名
    // 签名数据：证书哈希 + 状态 + 时间戳
    unsigned char signed_data[CERT_HASH_SIZE + 1 + 8];
    memcpy(signed_data, cert_hash, CERT_HASH_SIZE);
    signed_data[CERT_HASH_SIZE] = status;
    uint64_t ts_network = htobe64(timestamp);
    memcpy(signed_data + CERT_HASH_SIZE + 1, &ts_network, 8);
    
    // 提取签名
    unsigned char signature[64];
    memcpy(signature, buffer + 1 + 8, 64);
    
    // 用CA公钥验证签名
    if (!sm2_verify(signature, signed_data, CERT_HASH_SIZE + 1 + 8, Q_ca)) {
        printf("CA签名验证失败！此响应可能不是来自合法CA\n");
        return -1;
    }

    return status;
}

int request_cert_revoke(int sock, const char *user_id) {
    // 检查证书和私钥是否已加载
    if (!has_cert) {
        printf("错误：找不到用户证书\n");
        return 0;
    }
    
    // 获取当前时间戳
    time_t now = time(NULL);
    uint64_t timestamp = (uint64_t)now;
    uint64_t ts_network = htobe64(timestamp);  // 转换为网络字节序
    
    // 准备要签名的数据：用户ID + 时间戳
    unsigned char sign_data[SUBJECT_ID_LEN + 8];
    memcpy(sign_data, user_id, SUBJECT_ID_LEN);
    memcpy(sign_data + SUBJECT_ID_LEN, &ts_network, 8);
    
    // 使用用户私钥对数据签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, SUBJECT_ID_LEN + 8, priv_key)) {
        printf("撤销请求签名失败\n");
        return 0;
    }
    
    // 准备发送的数据：ID + 时间戳 + 签名
    unsigned char request_data[SUBJECT_ID_LEN + 8 + 64];
    memcpy(request_data, user_id, SUBJECT_ID_LEN);
    memcpy(request_data + SUBJECT_ID_LEN, &ts_network, 8);
    memcpy(request_data + SUBJECT_ID_LEN + 8, signature, 64);
    
    // 发送撤销请求
    if (!send_message(sock, CMD_REQUEST_REVOKE, request_data, sizeof(request_data))) {
        printf("发送撤销请求失败\n");
        return 0;
    }
     
    // 接收撤销响应
    unsigned char response[BUFFER_SIZE];
    uint8_t resp_cmd;
    int resp_len = recv_message(sock, &resp_cmd, response, BUFFER_SIZE);
    
    if (resp_len < 0 || resp_cmd != CMD_REVOKE_RESPONSE) {
        printf("接收撤销响应失败或响应命令错误\n");
        return 0;
    }
    
    // 检查响应长度
    if (resp_len < 1 + 8 + 64) {  // 状态 + 时间戳 + 签名
        printf("撤销响应数据长度错误\n");
        return 0;
    }
    
    // 解析响应状态
    uint8_t status = response[0];
    
    // 解析时间戳
    uint64_t resp_timestamp;
    memcpy(&resp_timestamp, response + 1, 8);
    resp_timestamp = be64toh(resp_timestamp);  // 网络字节序转为主机字节序
    
    // 使用validate_timestamp函数验证时间戳
    if (!validate_timestamp(resp_timestamp)) {
        printf("撤销响应中的时间戳无效\n");
        return 0;
    }
    
    // 获取签名
    unsigned char resp_signature[64];
    memcpy(resp_signature, response + 1 + 8, 64);
    
    // 验证签名
    unsigned char resp_sign_data[1 + 8];
    resp_sign_data[0] = status;
    uint64_t ts_network_copy = htobe64(resp_timestamp);
    memcpy(resp_sign_data + 1, &ts_network_copy, 8);
    
    if (!sm2_verify(resp_signature, resp_sign_data, 1 + 8, Q_ca)) {
        printf("撤销响应签名验证失败\n");
        return 0;
    }
    
    // 检查状态
    if (status != 1) {
        printf("撤销失败，CA返回状态: %d\n", status);
        return 0;
    }
    
    printf("证书撤销成功！正在清理本地证书文件...\n");
    
    // 删除本地证书文件
    char cert_filename[100];
    sprintf(cert_filename, "%s.crt", user_id);
    remove(cert_filename);
    
    // 删除本地私钥文件
    char priv_key_filename[100];
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    remove(priv_key_filename);
    
    // 删除本地公钥文件
    char pub_key_filename[100];
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    remove(pub_key_filename);
    
    printf("本地证书文件清理完成\n");
    
    return 1;
}

//----------------CRL相关函数实现-------------------
int init_crl_manager() {
    // 初始化local_crl哈希表，初始大小为512
    local_crl = crl_hashmap_create(512);
    if (!local_crl) {
        printf("创建local_crl哈希表失败！\n");
        return 0;
    }
    
    // 尝试从文件加载CRL管理器
    crl_manager = CRLManager_load_from_file(CRL_MANAGER_FILE);
    if (!crl_manager) {
        printf("无法加载CRL管理器，创建新的管理器...\n");
        // 用户端的CRL管理器不需要存储已删除节点的版本号，所以removed_capacity=0
        crl_manager = CRLManager_init(512, 0);
        if (!crl_manager) {
            printf("创建CRL管理器失败！\n");
            hashmap_destroy(local_crl);
            local_crl = NULL;
            return 0;
        }
    } else {
        // 从crl_manager加载有效节点到local_crl
        if (!load_crl_manager_to_hashmap()) {
            printf("从CRL管理器加载数据到哈希表失败！\n");
            hashmap_destroy(local_crl);
            local_crl = NULL;
            CRLManager_free(crl_manager);
            crl_manager = NULL;
            return 0;
        }
    }
    
    return 1;
}

int load_crl_manager_to_hashmap() {
    if (!crl_manager || !local_crl) return 0;
    
    // 遍历crl_manager中的所有节点
    for (int i = 0; i < crl_manager->base_v; i++) {
        // 只处理有效节点
        if (crl_manager->nodes[i].is_valid && crl_manager->nodes[i].hash) {
            // 分配内存用于存储哈希值的副本
            unsigned char* hash_copy = malloc(32);
            if (!hash_copy) return 0;
            
            // 复制哈希值
            memcpy(hash_copy, crl_manager->nodes[i].hash, 32);
            
            // 将哈希值加入local_crl，不存储值
            if (!hashmap_put(local_crl, hash_copy, NULL, 0)) {
                free(hash_copy);
                return 0;
            }
        }
    }
    return 1;
}

// 本地检查证书是否在CRL中
int check_cert_in_local_crl(const unsigned char *cert_hash) {
    if (!local_crl || !cert_hash) return 0;
    
    // 使用哈希表快速检查证书哈希是否存在
    return hashmap_exists(local_crl, cert_hash);
}

// 与CA同步CRL数据
int sync_crl_with_ca(int sock) {

    int version_info[2];
    version_info[0] = crl_manager->base_v;      // 当前节点基础版本号
    version_info[1] = crl_manager->removed_v;   // 当前已删除节点版本号
    
    printf("current_v:(%d,%d)\n",version_info[0],version_info[1]);
    
    if (!send_message(sock, CMD_REQUEST_CRL_UPDATE, version_info, sizeof(version_info))) {
        printf("发送CRL同步请求失败\n");
        return 0;
    }
    
    unsigned char buffer[BUFFER_SIZE] = {0};
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0) {
        printf("接收CRL更新数据失败\n");
        return 0;
    }
    
    if (cmd != CMD_SEND_CRL_UPDATE) {
        printf("接收到错误的命令类型: %d\n", cmd);
        return 0;
    }
    
    if (data_len == 0) {
        printf("当前CRL已是最新版本\n");
        return 1;
    }
    
    // 检查数据长度是否至少包含时间戳(8字节)和签名(64字节)
    if (data_len <= 8 + 64) {
        printf("接收到的CRL更新数据长度错误\n");
        return 0;
    }
    
    // 提取时间戳和签名
    int crl_data_len = data_len - 8 - 64;
    uint64_t timestamp;
    unsigned char signature[64];
    
    memcpy(&timestamp, buffer + crl_data_len, 8);
    memcpy(signature, buffer + crl_data_len + 8, 64);
    
    // 将时间戳从网络字节序转换为主机字节序
    timestamp = be64toh(timestamp);
    
    // 验证时间戳是否有效
    if (!validate_timestamp(timestamp)) {
        printf("CRL更新中的时间戳无效\n");
        return 0;
    }
    
    // 准备签名验证数据：CRL数据 + 时间戳(网络字节序)
    unsigned char *verify_data = malloc(crl_data_len + 8);
    if (!verify_data) {
        printf("内存分配失败\n");
        return 0;
    }
    
    memcpy(verify_data, buffer, crl_data_len);
    // 时间戳使用网络字节序
    uint64_t ts_network = htobe64(timestamp);
    memcpy(verify_data + crl_data_len, &ts_network, 8);
    
    // 用CA公钥验证签名
    if (!sm2_verify(signature, verify_data, crl_data_len + 8, Q_ca)) {
        printf("CA签名验证失败！此CRL更新可能不是来自合法CA\n");
        free(verify_data);
        return 0;
    }
    
    free(verify_data);
    printf("CRL更新数据的签名验证成功\n");
    
    // 反序列化更新数据
    UpdatedCRL* updated_crl = CRLManager_deserialize_update(buffer, crl_data_len);
    if (!updated_crl) {
        printf("解析CRL更新数据失败\n");
        return 0;
    }
    
    printf("收到CRL更新：新增节点=%d, 删除节点=%d\n", 
           updated_crl->added_count, updated_crl->del_count);
    
    // 应用更新到本地CRL管理器和local_crl哈希表
    if (!CRLManager_apply_update(crl_manager, updated_crl, local_crl)) {
        printf("应用CRL更新失败\n");
        CRLManager_free_update(updated_crl);
        return 0;
    }
    CRLManager_free_update(updated_crl);
    
    // 保存更新后的CRL管理器
    if (!CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE)) {
        printf("保存更新后的CRL管理器失败\n");
        return 0;
    }
    
    printf("current_v:(%d,%d)\n",crl_manager->base_v,crl_manager->removed_v);
    
    return 1;
}

// 本地证书状态检查
int local_csp(const unsigned char *cert_hash) {
    return !check_cert_in_local_crl(cert_hash);
}
