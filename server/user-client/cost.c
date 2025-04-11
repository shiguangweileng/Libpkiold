#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ec.h>
#include <sys/time.h>

#include "common.h"
#include "gm_crypto.h"
#include "tools.h"
#include "imp_cert.h"

#define PORT 8000
#define BUFFER_SIZE 2048
#define SERVER_IP "127.0.0.1"

// 通信协议常量
#define CMD_SEND_ID_AND_RU    0x01    // 用户发送ID和Ru
#define CMD_SEND_CERT_AND_R   0x02    // CA发送证书和部分私钥r
#define CMD_REQUEST_UPDATE    0x03    // 用户请求更新证书
#define CMD_SEND_UPDATED_CERT 0x04    // CA发送更新后的证书

// 消息头部结构: 命令(1字节) + 数据长度(2字节)
#define MSG_HEADER_SIZE 3
#define SUBJECT_ID_LEN 8     // 主体ID实际长度
#define SUBJECT_ID_SIZE 9    // 主体ID存储长度
#define USERS_COUNT 10       // 测试的用户数量

// 预声明函数
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len);
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len);
int connect_to_server();
int request_registration(int sock, const char *user_id);
int request_cert_update(int sock, const char *user_id);

// 存储CA公钥的全局变量
unsigned char Q_ca[SM2_PUB_MAX_SIZE];

// 一个用户的请求注册函数
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

    // 保存证书供后续使用
    save_cert(&cert, cert_filename);
    
    //--------step3:用户端生成最终的公私钥对-------------
    // 获取隐式证书中的Pu
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&cert, Pu);

    // 计算隐式证书哈希值
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);

    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)){
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
    
    // 释放资源
    BN_free(Ku);
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    
    return 1;
}

// 一个用户的请求更新函数
int request_cert_update(int sock, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    unsigned char priv_key[SM2_PRI_MAX_SIZE];
    
    // 先加载用户的私钥
    char priv_key_filename[SUBJECT_ID_SIZE + 11] = {0}; // ID + "_priv.key"
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    
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
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);

    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, e, Ku, r, order);

    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)) {
        printf("新密钥对验证失败！\n");
        BN_free(Ku);
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return 0;
    }
    
    // 保存用户新私钥
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存更新后的用户私钥到文件\n");
    }
    
    // 保存用户新公钥
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
    
    return 1;
}

// 连接到服务器函数
int connect_to_server() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    // 创建socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket创建失败");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // 将IP地址从文本转换为二进制形式
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
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

// 发送消息函数
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

// 接收消息函数
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

int main() {
    int sock = -1;
    char user_id[SUBJECT_ID_SIZE] = {0};
    struct timeval start_time, end_time;
    double elapsed_ms[USERS_COUNT];
    
    // 初始化SM2参数
    if (!User_init(Q_ca)) {
        printf("加载CA公钥失败！\n");
        sm2_params_cleanup();
        return -1;
    }
    
    printf("======== 测量10次证书注册的时间开销 ========\n");
    
    // 执行10次注册并测量时间
    for (int i = 0; i < USERS_COUNT; i++) {
        // 生成用户ID (U0000001-U0000010)
        sprintf(user_id, "U%07d", i + 1);
        // 开始计时
        gettimeofday(&start_time, NULL);        
        // 连接到服务器
        sock = connect_to_server();
        if (sock < 0) {
            printf("连接服务器失败，跳过用户 %s\n", user_id);
            elapsed_ms[i] = -1;
            continue;
        }
        

        
        // 执行注册
        int result = request_registration(sock, user_id);
        // 关闭连接
        close(sock);        
        // 结束计时
        gettimeofday(&end_time, NULL);
        
        // 计算时间差（毫秒）
        long seconds = end_time.tv_sec - start_time.tv_sec;
        long microseconds = end_time.tv_usec - start_time.tv_usec;
        elapsed_ms[i] = seconds * 1000.0 + microseconds / 1000.0;
        

        
        if (!result) {
            printf("用户 %s 注册失败\n", user_id);
            elapsed_ms[i] = -1;
        }
        
        // 等待一小段时间，让服务器处理完毕
        usleep(100000);  // 100ms
    }
    
    // 打印注册时间开销
    printf("\n注册时间开销 (ms):\n");
    for (int i = 0; i < USERS_COUNT; i++) {
        if (elapsed_ms[i] >= 0) {
            printf("U%07d: %.2f\n", i + 1, elapsed_ms[i]);
        } else {
            printf("U%07d: 失败\n", i + 1);
        }
    }
    
    printf("\n======== 测量10次证书更新的时间开销 ========\n");
    
    // 执行10次更新并测量时间
    for (int i = 0; i < USERS_COUNT; i++) {
        // 生成用户ID (U0000001-U0000010)
        sprintf(user_id, "U%07d", i + 1);
        
        // 开始计时
        gettimeofday(&start_time, NULL);        
        // 连接到服务器
        sock = connect_to_server();
        if (sock < 0) {
            printf("连接服务器失败，跳过用户 %s\n", user_id);
            elapsed_ms[i] = -1;
            continue;
        }

        
        // 执行更新
        int result = request_cert_update(sock, user_id);
        // 关闭连接
        close(sock);
        // 结束计时
        gettimeofday(&end_time, NULL);
        
        // 计算时间差（毫秒）
        long seconds = end_time.tv_sec - start_time.tv_sec;
        long microseconds = end_time.tv_usec - start_time.tv_usec;
        elapsed_ms[i] = seconds * 1000.0 + microseconds / 1000.0;
        

        
        if (!result) {
            printf("用户 %s 更新失败\n", user_id);
            elapsed_ms[i] = -1;
        }
        
        // 等待一小段时间，让服务器处理完毕
        usleep(100000);  // 100ms
    }
    
    // 打印更新时间开销
    printf("\n更新时间开销 (ms):\n");
    for (int i = 0; i < USERS_COUNT; i++) {
        if (elapsed_ms[i] >= 0) {
            printf("U%07d: %.2f\n", i + 1, elapsed_ms[i]);
        } else {
            printf("U%07d: 失败\n", i + 1);
        }
    }
    
    // 清理SM2参数
    sm2_params_cleanup();
    
    return 0;
}