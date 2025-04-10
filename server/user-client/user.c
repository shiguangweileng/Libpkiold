#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ec.h>
#include <sys/time.h>
#include "common.h"
#include "sm2.h"
#include "sm3.h"
#include "tools.h"
#include "imp_cert.h"

#define PORT 8000
#define BUFFER_SIZE 2048

// 通信协议常量
#define CMD_SEND_ID_AND_RU    0x01    // 用户发送ID和Ru
#define CMD_SEND_CERT_AND_R   0x02    // CA发送证书和部分私钥r
#define CMD_REQUEST_UPDATE    0x03    // 用户请求更新证书
#define CMD_SEND_UPDATED_CERT 0x04    // CA发送更新后的证书
#define CMD_SEND_MESSAGE      0x05    // 用户发送消息、签名和证书
#define CMD_VERIFY_CERT       0x06    // 用户查询证书有效性
#define CMD_CERT_STATUS       0x07    // CA返回证书状态

// 消息头部结构: 命令(1字节) + 数据长度(2字节)
#define MSG_HEADER_SIZE 3
#define SUBJECT_ID_LEN 8     // 主体ID实际长度
#define SUBJECT_ID_SIZE 9    // 主体ID存储长度
#define MAX_MESSAGE_SIZE 1024 // 最大消息长度
#define CERT_HASH_SIZE 32    // 证书哈希值长度

// 存储相关信息的全局变量
ImpCert loaded_cert;
unsigned char priv_key[SM2_PRI_MAX_SIZE];
unsigned char pub_key[SM2_PUB_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];
int has_cert = 0;

//----------------函数声明-------------------

// 证书处理函数
int check_and_load_cert(const char *user_id);

// 用户证书操作函数
int request_registration(int sock, const char *user_id);
int request_cert_update(int sock, const char *user_id);
int send_signed_message(int sock, const char *user_id, const char *message);
int online_csp(int sock, const unsigned char *cert_hash);

// 网络通信函数
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len);
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len);
int connect_to_server(const char *ip, int port);

// 辅助函数
void clear_input_buffer();

//----------------主函数-------------------
int main() {
    char server_ip[16] = {0}; // 存储用户输入的服务器IP地址
    char user_id[SUBJECT_ID_SIZE] = {0};
    int choice = 0;
    int sock = -1;
    int running = 1; // 控制主循环
    int result = 0;
    struct timeval start_time, end_time;
    
    if (!User_init(Q_ca)) {
        printf("加载CA公钥失败！\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 请求用户输入服务器IP地址
    printf("请输入服务器IP地址(输入1使用127.0.0.1): ");
    if (scanf("%15s", server_ip) != 1) {
        printf("IP地址输入错误\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 如果输入"1"，则使用默认IP地址127.0.0.1
    if (strcmp(server_ip, "1") == 0) {
        strcpy(server_ip, "127.0.0.1");
        printf("使用默认IP地址: %s\n", server_ip);
    }
    
    // 外层循环 - 处理不同用户
    while (running) {
        // 重置变量
        has_cert = 0;
        memset(user_id, 0, SUBJECT_ID_SIZE);
        
        // 请求用户输入ID
        printf("\n请输入用户ID (必须是8个字符): ");
        if (scanf("%8s", user_id) != 1) {
            printf("ID输入错误\n");
            clear_input_buffer();
            continue;
        }
        
        // 检查本地是否存在该ID的证书
        has_cert = check_and_load_cert(user_id);
        
        // 内层循环 - 处理当前用户的多次操作
        int user_session = 1;
        while (user_session) {
            // 用户选择操作
            printf("\n用户 [%s] 请选择操作:\n", user_id);
            printf("1. 注册新证书\n");
            printf("2. 更新现有证书\n");
            printf("3. 发送消息\n");
            printf("4. 查询证书有效性\n");
            printf("5. 切换用户\n");

            printf("请输入选择: ");
            if (scanf("%d", &choice) != 1) {
                printf("输入错误\n");
                clear_input_buffer();
                continue;
            }
            
            // 检查是否要返回上一级菜单
            if (choice == 5) {
                user_session = 0; // 退出内层循环，返回到用户ID输入
                continue;
            }
            
            // 连接到服务器
            sock = connect_to_server(server_ip, PORT);
            if (sock < 0) {
                printf("无法连接到服务器 %s，请检查网络或服务器状态\n", server_ip);
                continue;
            }
            
            // 根据用户选择执行相应操作
            result = 0;
            
            switch (choice) {
                case 1:
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = request_registration(sock, user_id);
                    break;
                case 2:
                    if (!has_cert) {
                        printf("错误：需要先有证书才能更新\n");
                        close(sock);
                        continue;
                    }
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = request_cert_update(sock, user_id);
                    break;
                case 3:
                    if (!has_cert) {
                        printf("错误：需要先有证书才能发送消息\n");
                        close(sock);
                        continue;
                    }
                    
                    // 清空输入缓冲区
                    clear_input_buffer();
                    
                    // 获取要发送的消息
                    char message[MAX_MESSAGE_SIZE] = {0};
                    printf("请输入要发送的消息: ");
                    if (fgets(message, MAX_MESSAGE_SIZE, stdin) == NULL) {
                        printf("消息输入错误\n");
                        close(sock);
                        continue;
                    }
                    
                    // 移除消息末尾的换行符
                    size_t len = strlen(message);
                    if (len > 0 && message[len-1] == '\n') {
                        message[len-1] = '\0';
                    }
                    
                    // 在用户完成输入后再开始计时
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = send_signed_message(sock, user_id, message);
                    break;
                case 4:
                    {
                        // 处理证书状态查询
                        unsigned char cert_hash[CERT_HASH_SIZE];
                        char hex_hash[CERT_HASH_SIZE * 2 + 1] = {0}; // 十六进制字符串加上\0
                        
                        // 清空输入缓冲区
                        clear_input_buffer();
                        
                        // 请求用户输入证书哈希值（十六进制形式）
                        printf("请输入证书哈希值（十六进制格式，64字符）: ");
                        if (scanf("%64s", hex_hash) != 1) {
                            printf("输入格式错误\n");
                            close(sock);
                            continue;
                        }
                        
                        // 检查输入的哈希值长度是否正确
                        if (strlen(hex_hash) != CERT_HASH_SIZE * 2) {
                            printf("哈希值长度错误，应为64字符\n");
                            close(sock);
                            continue;
                        }
                        
                        // 将十六进制字符串转换为二进制形式
                        for (int i = 0; i < CERT_HASH_SIZE; i++) {
                            char byte_str[3] = {hex_hash[i*2], hex_hash[i*2+1], '\0'};
                            cert_hash[i] = (unsigned char)strtol(byte_str, NULL, 16);
                        }
                        
                        // 在用户完成输入后再开始计时
                        gettimeofday(&start_time, NULL); // 记录开始时间
                        int cert_status = online_csp(sock, cert_hash);
                        if (cert_status >= 0) {
                            // 查询成功
                            result = 1;
                            printf("证书状态: %s\n", cert_status ? "有效" : "无效（已撤销）");
                        } else {
                            // 查询失败
                            result = 0;
                            printf("证书状态查询失败\n");
                        }
                    }
                    break;
                default:
                    printf("无效的选择\n");
                    result = 0;
                    break;
            }

            // 关闭连接
            close(sock);
            
            if (result) {
                gettimeofday(&end_time, NULL);
                long seconds = end_time.tv_sec - start_time.tv_sec;
                long microseconds = end_time.tv_usec - start_time.tv_usec;
                double elapsed_ms = seconds * 1000.0 + microseconds / 1000.0;
                
                if (choice == 1) {
                    printf("注册证书的时间开销: %.2f ms\n", elapsed_ms);
                    // 操作完成后重新加载证书
                    has_cert = check_and_load_cert(user_id);
                } else if (choice == 2) {
                    printf("更新证书的时间开销: %.2f ms\n", elapsed_ms);
                    // 更新后重新加载证书
                    has_cert = check_and_load_cert(user_id);
                } else if (choice == 3) {
                    printf("发送消息的时间开销: %.2f ms\n", elapsed_ms);
                } else if (choice == 4) {
                    printf("查询证书状态的时间开销: %.2f ms\n", elapsed_ms);
                }
            }
        }
    }
    
    sm2_params_cleanup();
    return 0;
}

//----------------辅助函数实现-------------------
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

//----------------证书处理函数实现-------------------
int check_and_load_cert(const char *user_id) {
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
    
    print_cert_info(&loaded_cert);
    
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
    
    printf("已成功加载证书和密钥对\n");
    return 1;
}

//----------------用户证书操作函数实现-------------------
int request_registration(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    
    //--------step1:用户端-----------
    // 设置秘密值Ku
    BIGNUM *Ku = BN_new();
    BN_rand_range(Ku, order);

    // 计算临时公钥Ru=Ku*G
    EC_POINT *Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        BN_free(Ku);
        if (Ru) EC_POINT_free(Ru);
        return 0;
    }
    
    // 将Ru转换为字节数组以便发送
    unsigned char Ru_bytes[SM2_PUB_MAX_SIZE];
    size_t ru_len = EC_POINT_point2oct(group, Ru, POINT_CONVERSION_UNCOMPRESSED, 
                                     Ru_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 准备发送数据：ID + Ru（先ID后Ru）
    unsigned char send_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(send_data, user_id, SUBJECT_ID_LEN);
    memcpy(send_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 发送ID和Ru给CA
    if (!send_message(sock, CMD_SEND_ID_AND_RU, send_data, SUBJECT_ID_LEN + ru_len)) {
        printf("发送ID和临时公钥失败\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 接收CA发送的证书和部分私钥r
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0) {
        printf("接收数据失败\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    // 验证命令类型
    if (cmd != CMD_SEND_CERT_AND_R) {
        printf("接收到错误的命令类型: %d\n", cmd);
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    // 解析证书和部分私钥r
    ImpCert cert;
    unsigned char r[SM2_PRI_MAX_SIZE];
    if (data_len != sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        printf("接收到的数据长度错误: %d\n", data_len);
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
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
    save_cert(&cert, cert_filename);
    printf("用户证书已保存到 %s\n", cert_filename);
    
    //--------step3:用户端生成最终的公私钥对-------------
    // 获取隐式证书中的Pu
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&cert, Pu);

    // 计算隐式证书哈希值
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    print_hex("隐式证书哈希值e", e, 32);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);
    print_hex("公钥重构值Qu", Qu, SM2_PUB_MAX_SIZE);

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);
    print_hex("用户私钥d_u", d_u, SM2_PRI_MAX_SIZE);

    // 验证密钥对
    if(verify_key_pair_bytes(group, Qu, d_u)){
        printf("密钥对验证成功！\n");
    }else{
        printf("密钥对验证失败！\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
    // 保存用户私钥供后续使用
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
        printf("用户私钥已保存到 %s\n", priv_key_filename);
    } else {
        printf("警告：无法保存用户私钥到文件\n");
    }
    
    // 保存用户公钥供后续使用
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
        printf("用户公钥已保存到 %s\n", pub_key_filename);
    } else {
        printf("警告：无法保存用户公钥到文件\n");
    }
    
    // 释放资源
    BN_free(Ku);
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    
    printf("注册过程完成\n");
    
    return 1;
}

int request_cert_update(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};

    //--------step1:用户端-----------
    // 设置新的秘密值Ku
    BIGNUM *Ku = BN_new();
    BN_rand_range(Ku, order);

    // 计算临时公钥Ru=Ku*G
    EC_POINT *Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        BN_free(Ku);
        if (Ru) EC_POINT_free(Ru);
        return 0;
    }
    
    // 将Ru转换为字节数组以便发送
    unsigned char Ru_bytes[SM2_PUB_MAX_SIZE];
    size_t ru_len = EC_POINT_point2oct(group, Ru, POINT_CONVERSION_UNCOMPRESSED, 
                                     Ru_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 准备要签名的数据：ID + Ru（先ID后Ru）
    unsigned char sign_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(sign_data, user_id, SUBJECT_ID_LEN);
    memcpy(sign_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 用私钥对数据签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, SUBJECT_ID_LEN + ru_len, priv_key)) {
        printf("签名失败\n");
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
        printf("发送更新请求失败\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 接收CA发送的新证书和部分私钥r
    uint8_t cmd;
    int data_len = recv_message(sock, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0) {
        printf("接收数据失败\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 验证命令类型
    if (cmd != CMD_SEND_UPDATED_CERT) {
        printf("接收到错误的命令类型: %d\n", cmd);
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    
    // 解析新证书和部分私钥r
    ImpCert new_cert;
    unsigned char r[SM2_PRI_MAX_SIZE];
    if (data_len != sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        printf("接收到的数据长度错误: %d\n", data_len);
        BN_free(Ku);
        EC_POINT_free(Ru);
        return 0;
    }
    memcpy(&new_cert, buffer, sizeof(ImpCert));
    memcpy(r, buffer + sizeof(ImpCert), SM2_PRI_MAX_SIZE);

    printf("已成功接收更新后的证书和部分私钥r\n");
    
    // 保存新证书供后续使用
    char cert_filename[SUBJECT_ID_SIZE + 5] = {0}; // ID + ".crt"
    sprintf(cert_filename, "%s.crt", user_id);
    save_cert(&new_cert, cert_filename);
    
    //--------step3:用户端生成最终的公私钥对-------------
    // 获取隐式证书中的Pu
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&new_cert, Pu);

    // 计算隐式证书哈希值
    unsigned char e[32];
    sm3_hash((const unsigned char *)&new_cert, sizeof(ImpCert), e);
    print_hex("新隐式证书哈希值e", e, 32);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);
    print_hex("新公钥重构值Qu", Qu, SM2_PUB_MAX_SIZE);

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);

    // 验证密钥对
    if(verify_key_pair_bytes(group, Qu, d_u)) {
        printf("新密钥对验证成功！\n");
    } else {
        printf("新密钥对验证失败！\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
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
    
    // 释放资源
    BN_free(Ku);
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    
    printf("证书更新过程完成\n");
    
    return 1;
}

int send_signed_message(int sock, const char *user_id, const char *message) {
    // 检查消息长度
    size_t message_len = strlen(message);
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
    size_t data_size = 2 + message_len + 64 + sizeof(ImpCert);
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
    
    // 验证时间戳是否在有效范围内（当前时间与消息时间戳相差不超过3秒）
    time_t current_time = time(NULL);
    time_t time_diff = labs((long)(current_time - (time_t)timestamp));
    
    if (time_diff > 3) {
        printf("时间戳验证失败！消息时间戳与当前时间相差 %ld 秒，超过阈值(3秒)\n", time_diff);
        return -1;
    }
    
    // 返回证书状态
    return status;
}

//----------------网络通信函数实现-------------------
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len) {
    if (data_len + MSG_HEADER_SIZE > BUFFER_SIZE) {
        printf("错误：消息长度超出缓冲区大小\n");
        return 0;
    }
    
    unsigned char buffer[BUFFER_SIZE] = {0};
    
    // 填充消息头
    buffer[0] = cmd;
    buffer[1] = (data_len >> 8) & 0xFF;  // 高字节
    buffer[2] = data_len & 0xFF;         // 低字节
    
    // 复制数据
    if (data && data_len > 0) {
        memcpy(buffer + MSG_HEADER_SIZE, data, data_len);
    }
    
    // 发送消息
    if (send(sock, buffer, data_len + MSG_HEADER_SIZE, 0) < 0) {
        perror("发送消息失败");
        return 0;
    }
    
    return 1;
}

int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len) {
    unsigned char header[MSG_HEADER_SIZE] = {0};
    
    // 接收消息头
    if (recv(sock, header, MSG_HEADER_SIZE, 0) != MSG_HEADER_SIZE) {
        perror("接收消息头失败");
        return -1;
    }
    
    // 解析消息头
    *cmd = header[0];
    uint16_t data_len = (header[1] << 8) | header[2];
    
    if (data_len > max_len) {
        printf("错误：接收的数据长度(%d)超出缓冲区大小(%d)\n", data_len, max_len);
        return -1;
    }
    
    // 接收消息体
    if (data_len > 0) {
        int received = 0;
        int total = 0;
        
        while (total < data_len) {
            received = recv(sock, (unsigned char*)data + total, data_len - total, 0);
            if (received <= 0) {
                perror("接收消息体失败");
                return -1;
            }
            total += received;
        }
    }
    
    return data_len;
}

int connect_to_server(const char *ip, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    // 创建socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket创建失败");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // 将IP地址从文本转换为二进制形式
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("无效的地址");
        close(sock);
        return -1;
    }
    
    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("连接失败");
        close(sock);
        return -1;
    }
    return sock;
}
