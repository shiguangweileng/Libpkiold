#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "common.h"
#include "gm_crypto.h"
#include "tools.h"
#include "imp_cert.h"
#include "hashmap.h"

#define PORT 8000
#define BUFFER_SIZE 2048
#define CRL_FILE "CRL.txt"
#define USERDATA_DIR "UserData"          // 本地模式下存储用户数据的目录
#define USERCERTS_DIR "UserCerts"        // 存储用户证书的目录
#define USERLIST_FILE "UserList.txt"
#define SERIAL_NUM_FILE "SerialNum.txt"  // 序列号持久化文件
#define SERIAL_NUM_FORMAT "SN%06d"       // 序列号格式，6位数字前缀为SN
#define SERIAL_NUM_MAX 999999            // 序列号最大值
// 通信协议常量
#define CMD_SEND_ID_AND_RU    0x01    // 用户发送ID和Ru
#define CMD_SEND_CERT_AND_R   0x02    // CA发送证书和部分私钥r
#define CMD_REQUEST_UPDATE    0x03    // 用户请求更新证书
#define CMD_SEND_UPDATED_CERT 0x04    // CA发送更新后的证书
#define CMD_SEND_MESSAGE      0x05    // 用户发送消息、签名和证书
#define CMD_VERIFY_CERT       0x06    // 用户查询证书有效性
#define CMD_CERT_STATUS       0x07    // CA返回证书状态

// 消息头部结构: 命令(1字节) + 长度(2字节)
#define MSG_HEADER_SIZE 3
#define SUBJECT_ID_LEN 8     // 主体ID实际长度
#define SUBJECT_ID_SIZE 9    // 主体ID长度为9字节
#define CERT_HASH_SIZE 32    // 证书哈希值长度

unsigned char d_ca[SM2_PRI_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];

hashmap* user_map = NULL;           // 存储用户ID和证书哈希
hashmap* crl_map = NULL;            // 存储被撤销的证书哈希和其到期时间
unsigned int current_serial_num = 1;  // 当前证书序列号，默认从1开始

// 网络通信
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len);
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len);
int setup_server(int port);
void handle_client(int client_socket);

// 证书处理
void handle_registration(int client_socket, const unsigned char *buffer, int data_len);
void handle_cert_update(int client_socket, const unsigned char *buffer, int data_len);
void handle_message(int client_socket, const unsigned char *buffer, int data_len);
void handle_online_csp(int client_socket, const unsigned char *buffer, int data_len);
int local_generate_cert(const char *subject_id);
int local_update_cert(const char *subject_id);

// 用户数据管理
int check_user_exists(const char *subject_id);
int save_user_list(const char *subject_id, const unsigned char *cert_hash);
int update_user_list(const char *subject_id, const unsigned char *new_cert_hash);

// CRL管理
int check_cert_in_crl(const unsigned char *cert_hash);
int add_cert_to_crl(const unsigned char *cert_hash, time_t expire_time);

// 序列号管理
int load_serial_num();
int save_serial_num();
char* generate_serial_num();

// 运行模式
void run_local_mode();
void run_online_mode();

int ensure_directory_exists(const char *dir_path) {
    struct stat st = {0};
    if (stat(dir_path, &st) == -1) {
        // 目录不存在，创建它，设置权限为755
        if (mkdir(dir_path, 0755) == -1) {
            printf("无法创建目录: %s\n", dir_path);
            return 0;
        }
        printf("已创建目录: %s\n", dir_path);
    }
    return 1;
}

int main() {
    int mode_choice = 0;
    
    // 初始化CA
    if(!CA_init(Q_ca, d_ca)){
        printf("CA初始化失败！\n");
        return -1;
    }
    
    // 确保必要的目录存在
    if (!ensure_directory_exists(USERDATA_DIR) || 
        !ensure_directory_exists(USERCERTS_DIR)) {
        printf("无法确保必要目录存在！\n");
        return -1;
    }
    
    // 加载证书序列号
    current_serial_num = load_serial_num();
    
    // 加载用户列表到哈希表中，初始大小为256
    user_map = ul_hashmap_load(USERLIST_FILE, 256);
    if (!user_map) {
        printf("无法初始化用户哈希表！\n");
        sm2_params_cleanup();
        return -1;
    }

    // 加载证书撤销列表到哈希表中，初始大小为512
    crl_map = crl_hashmap_load(CRL_FILE, 512);
    if (!crl_map) {
        printf("无法初始化CRL哈希表！\n");
        hashmap_destroy(user_map);
        sm2_params_cleanup();
        return -1;
    }

    printf("CA服务器初始化完成...\n\n");
    
    // 选择运行模式
    printf("请选择CA服务器运行模式:\n");
    printf("1. 本地模式 - 提供本地证书生成和更新功能\n");
    printf("2. 线上模式 - 启动监听服务器与用户交互\n");
    printf("请输入选择: ");
    
    if (scanf("%d", &mode_choice) != 1) {
        printf("输入错误\n");
        hashmap_destroy(crl_map);
        hashmap_destroy(user_map);
        sm2_params_cleanup();
        return -1;
    }
    
    // 清空输入缓冲区
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    // 根据选择进入相应模式
    if (mode_choice == 1) {
        run_local_mode();
    } else if (mode_choice == 2) {
        run_online_mode();
    } else {
        printf("无效的选择\n");
    }
    
    // 程序结束时清理资源
    hashmap_destroy(user_map);
    hashmap_destroy(crl_map);
    sm2_params_cleanup();
    
    return 0;
}

// ============ 函数实现部分，按功能分组 ============

// ---- 网络通信相关函数 ----
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len)
{
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

int setup_server(int port) {
    int server_fd;
    struct sockaddr_in address;
    
    // 创建socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket创建失败");
        return -1;
    }
    
    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("设置socket选项失败");
        close(server_fd);
        return -1;
    }
    
    // 绑定地址和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("绑定失败");
        close(server_fd);
        return -1;
    }
    
    // 开始监听
    if (listen(server_fd, 30) < 0) {
        perror("监听失败");
        close(server_fd);
        return -1;
    }
    
    printf("CA服务器启动成功，等待用户连接...\n");
    return server_fd;
}

void handle_client(int client_socket) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    uint8_t cmd;
    int data_len;
    
    data_len = recv_message(client_socket, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0) {
        printf("接收客户端消息失败\n");
        return;
    }
    
    switch (cmd) {
        case CMD_SEND_ID_AND_RU:
            handle_registration(client_socket, buffer, data_len);
            break;
        case CMD_REQUEST_UPDATE:
            handle_cert_update(client_socket, buffer, data_len);
            break;
        case CMD_SEND_MESSAGE:
            handle_message(client_socket, buffer, data_len);
            break;
        case CMD_VERIFY_CERT:
            handle_online_csp(client_socket, buffer, data_len);
            break;
        default:
            printf("未知命令: 0x%02X\n", cmd);
            break;
    }
}

// ---- 证书处理相关函数 ----
void handle_registration(int client_socket, const unsigned char *buffer, int data_len) {
    // 验证接收的数据长度
    if (data_len < SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE) {
        printf("接收到的数据长度错误\n");
        return;
    }
    
    // 先提取用户ID（前8个字节）
    char subject_id[SUBJECT_ID_SIZE] = {0}; // 确保null结尾
    memcpy(subject_id, buffer, SUBJECT_ID_LEN);
    
    // 检查ID长度是否为8个字符
    if (strlen(subject_id) != 8) {
        printf("用户ID长度错误，必须为8个字符\n");
        return;
    }
    
    // 解析Ru（位于ID之后）
    EC_POINT *Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_oct2point(group, Ru, buffer + SUBJECT_ID_LEN, 
                                   data_len - SUBJECT_ID_LEN, NULL)) {
        printf("解析临时公钥失败\n");
        if (Ru) EC_POINT_free(Ru);
        return;
    }
    
    printf("%s---证书注册\n", subject_id);
    
    // 检查用户是否存在
    if (check_user_exists(subject_id)) {
        printf("用户ID '%s' 已存在，拒绝注册\n", subject_id);
        EC_POINT_free(Ru);
        return;
    }
    
    // --------step2:CA端生成隐式证书计算部分重构值-----------
    // CA选取随机值k
    BIGNUM *k = BN_new();
    BN_rand_range(k, order);

    // 计算公钥重构值Pu=Ru+k*G
    EC_POINT *Pu = EC_POINT_new(group);
    EC_POINT_mul(group, Pu, k, NULL, NULL, NULL);
    EC_POINT_add(group, Pu, Ru, Pu, NULL);

    // 生成新的证书序列号
    char* serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", serial_num);

    // 生成隐式证书
    ImpCert cert;
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60; // 1h有效期
    if(!set_cert(&cert, 
              (unsigned char *)serial_num,
              (unsigned char *)"CA000001", 
              (unsigned char *)subject_id,  // 使用用户提供的ID
              current_time,
              expire_time,
              Pu)){
        printf("证书设置失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        BN_free(k);
        return;
    }
    
    // 保存证书到文件系统，使用用户ID命名
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0}; // ID + ".crt"
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    if (!save_cert(&cert, cert_filename)) {
        printf("警告：无法保存用户证书到文件\n");
    }
    
    // 计算隐式证书的哈希值
    unsigned char cert_hash[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), cert_hash);
    print_hex("隐式证书哈希值e", cert_hash, 32);

    // 保存用户信息到UserList
    if (!save_user_list(subject_id, cert_hash)) {
        printf("保存用户数据失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        BN_free(k);
        return;
    }
    
    printf("用户 '%s' 成功注册并保存到UserList\n", subject_id);

    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, cert_hash, k, d_ca, order);
    print_hex("部分私钥r", r, SM2_PRI_MAX_SIZE);
    
    // 准备响应数据：证书+部分私钥r
    unsigned char response[sizeof(ImpCert) + SM2_PRI_MAX_SIZE];
    memcpy(response, &cert, sizeof(ImpCert));
    memcpy(response + sizeof(ImpCert), r, SM2_PRI_MAX_SIZE);
    
    // 发送证书和部分私钥r给客户端
    if (send_message(client_socket, CMD_SEND_CERT_AND_R, response, sizeof(response))) {
        printf("已成功发送证书和部分私钥r给用户\n");
        printf("--------------------------------\n");
    }
    else
    {
        printf("发送证书和部分私钥失败\n");
    }
    // 释放资源
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    BN_free(k);
}

void handle_cert_update(int client_socket, const unsigned char *buffer, int data_len) {
    // 验证接收的数据长度
    if (data_len < SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 64) {
        printf("接收到的数据长度错误\n");
        return;
    }
    
    // 先提取用户ID（前8个字节）
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, buffer, SUBJECT_ID_LEN);
    if (strlen(subject_id) != 8) {
        printf("用户ID长度错误，必须为8个字符\n");
        return;
    }
    printf("%s---证书更新\n", subject_id);
    
    // 检查用户是否存在
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，拒绝更新\n", subject_id);
        return;
    }
    
    // 加载用户的现有证书
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    ImpCert old_cert;
    if (!load_cert(&old_cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        return;
    }
    
    // 验证证书有效性
    if (!validate_cert(&old_cert)) {
        printf("用户证书已过期，请重新注册\n");
        return;
    }
    
    // 直接从用户哈希表获取证书哈希
    unsigned char *old_cert_hash = hashmap_get(user_map, subject_id);
    if (!old_cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        return;
    }
    
    // 检查证书是否在撤销列表中
    if (check_cert_in_crl(old_cert_hash)) {
        printf("用户证书已被撤销，请重新注册\n");
        return;
    }
    
    // 解析Ru（位于ID之后）
    EC_POINT *Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_oct2point(group, Ru, buffer + SUBJECT_ID_LEN, 
                                   SM2_PUB_MAX_SIZE, NULL)) {
        printf("解析临时公钥失败\n");
        if (Ru) EC_POINT_free(Ru);
        return;
    }
    
    // 重构用户的公钥用于验证签名
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&old_cert, Pu);
    
    // 重构用户公钥 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, old_cert_hash, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return;
    }
    
    // 提取签名数据和签名
    unsigned char sign_data[SUBJECT_ID_SIZE + SM2_PUB_MAX_SIZE];
    memcpy(sign_data, buffer, SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE);
    unsigned char signature[64];
    memcpy(signature, buffer + SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE, 64);
    // 验证签名
    if (!sm2_verify(signature, sign_data, SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE, Qu)) {
        printf("签名验证失败，拒绝更新请求\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        return;
    }
    
    printf("签名验证成功，处理更新请求...\n");
    
    // --------步骤与证书注册类似:CA端生成新隐式证书-----------
    // CA选取随机值k
    BIGNUM *k = BN_new();
    BN_rand_range(k, order);

    // 计算公钥重构值Pu=Ru+k*G
    EC_POINT *new_Pu = EC_POINT_new(group);
    EC_POINT_mul(group, new_Pu, k, NULL, NULL, NULL);
    EC_POINT_add(group, new_Pu, Ru, new_Pu, NULL);

    // 生成新的证书序列号
    char* serial_num = generate_serial_num();
    printf("生成更新证书，序列号: %s\n", serial_num);

    // 生成新隐式证书
    ImpCert new_cert;
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 30; // 30s有效期
    if(!set_cert(&new_cert, 
              (unsigned char *)serial_num,
              (unsigned char *)"CA000001", 
              (unsigned char *)subject_id,
              current_time,
              expire_time,
              new_Pu)){
        printf("新证书设置失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        EC_POINT_free(new_Pu);
        BN_free(k);
        return;
    }

    // 计算新隐式证书的哈希值
    unsigned char new_cert_hash[32];
    sm3_hash((const unsigned char *)&new_cert, sizeof(ImpCert), new_cert_hash);
    print_hex("新隐式证书哈希值e", new_cert_hash, 32);

    // 获取旧证书的到期时间
    time_t old_expire_time;
    memcpy(&old_expire_time, old_cert.Validity + sizeof(time_t), sizeof(time_t));

    // 将旧证书加入撤销列表
    if (!add_cert_to_crl(old_cert_hash, old_expire_time)) {
        printf("警告：无法将旧证书添加到撤销列表\n");
    }
    
    // 更新用户信息到UserList.txt
    if (!update_user_list(subject_id, new_cert_hash)) {
        printf("更新用户数据失败！\n");
    } else {
        printf("用户 '%s' 的数据已在UserList.txt中更新\n", subject_id);
    }

    // 保存新证书到文件系统，覆盖现有文件
    if (save_cert(&new_cert, cert_filename)) {
        printf("新用户证书已保存为 %s\n", cert_filename);
    } else {
        printf("警告：无法保存新用户证书到文件\n");
    }

    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, new_cert_hash, k, d_ca, order);
    print_hex("新部分私钥r", r, SM2_PRI_MAX_SIZE);
    
    // 准备响应数据：新证书+部分私钥r
    unsigned char response[sizeof(ImpCert) + SM2_PRI_MAX_SIZE];
    memcpy(response, &new_cert, sizeof(ImpCert));
    memcpy(response + sizeof(ImpCert), r, SM2_PRI_MAX_SIZE);
    
    // 发送新证书和部分私钥r给客户端
    if (send_message(client_socket, CMD_SEND_UPDATED_CERT, response, sizeof(response))) {
        printf("已成功发送新证书和部分私钥r给用户\n");
        printf("--------------------------------\n");
    } else {
        printf("发送新证书和部分私钥失败\n");
    }
    
    // 释放资源
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    EC_POINT_free(new_Pu);
    BN_free(k);
}

void handle_message(int client_socket, const unsigned char *buffer, int data_len) {
    if (data_len < 2) {  // 至少需要2字节的消息长度字段
        printf("接收到的数据长度错误\n");
        return;
    }
    
    // 解析消息长度（网络字节序）
    uint16_t message_len = (buffer[0] << 8) | buffer[1];
    
    // 验证数据长度是否足够
    if (data_len < 2 + message_len + 64 + sizeof(ImpCert)) {
        printf("接收到的数据长度不足，无法解析完整消息\n");
        return;
    }
    
    // 提取消息内容
    char *message = (char *)malloc(message_len + 1);  // +1 用于null结尾
    if (!message) {
        printf("内存分配失败\n");
        return;
    }
    memcpy(message, buffer + 2, message_len);
    message[message_len] = '\0';
    
    // 提取签名
    unsigned char signature[64];
    memcpy(signature, buffer + 2 + message_len, 64);
    
    // 提取证书
    ImpCert cert;
    memcpy(&cert, buffer + 2 + message_len + 64, sizeof(ImpCert));
    
    // 从证书中提取发送者ID
    char sender_id[SUBJECT_ID_SIZE] = {0};
    memcpy(sender_id, cert.SubjectID, SUBJECT_ID_LEN);
    printf("收到 %s 的消息\n", sender_id);
    
    // 检验证书是否过期
    if (!validate_cert(&cert)) {
        printf("拒绝消息：证书已过期\n");
        free(message);
        return;
    }
    
    // 检查证书是否在CRL中
    unsigned char cert_hash[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), cert_hash);
    if (check_cert_in_crl(cert_hash)) {
        printf("拒绝消息：证书已被撤销\n");
        free(message);
        return;
    }
    
    // 从证书恢复用户公钥
    EC_POINT *Pu = EC_POINT_new(group);
    getPu(&cert, Pu);
    
    // 计算证书哈希值e
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    
    // 重构用户公钥 Qu = e*Pu + Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, e, Pu, Q_ca);
    
    // 验证消息签名
    if (sm2_verify(signature, (const unsigned char *)message, message_len, Qu)) {
        printf("签名验证成功！消息内容：%s\n", message);
        printf("--------------------------------\n");
    } else {
        printf("签名验证失败，拒绝消息\n");
    }
    
    // 释放资源
    free(message);
    EC_POINT_free(Pu);
}

void handle_online_csp(int client_socket, const unsigned char *buffer, int data_len) {
    if (data_len != CERT_HASH_SIZE) {
        printf("错误：证书哈希长度不正确\n");
        return;
    }
    
    // 从请求中获取证书哈希
    unsigned char cert_hash[CERT_HASH_SIZE];
    memcpy(cert_hash, buffer, CERT_HASH_SIZE);
    
    
    // 检查证书是否在撤销列表中
    uint8_t cert_status = !check_cert_in_crl(cert_hash); // 1=有效，0=已撤销

    // 获取当前时间戳
    time_t current_time = time(NULL);
    uint64_t timestamp = (uint64_t)current_time;
    uint64_t ts_network = htobe64(timestamp); // 转换为网络字节序
    
    // 准备要签名的数据：证书哈希 + 状态 + 时间戳
    unsigned char sign_data[CERT_HASH_SIZE + 1 + 8];
    memcpy(sign_data, cert_hash, CERT_HASH_SIZE);
    sign_data[CERT_HASH_SIZE] = cert_status;
    memcpy(sign_data + CERT_HASH_SIZE + 1, &ts_network, 8);
    
    // 用CA私钥对数据签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, CERT_HASH_SIZE + 1 + 8, d_ca)) {
        printf("签名失败\n");
        return;
    }
    
    // 准备响应数据：状态(1字节) + 时间戳(8字节) + 签名(64字节)
    unsigned char resp_data[1 + 8 + 64];
    resp_data[0] = cert_status;
    memcpy(resp_data + 1, &ts_network, 8);
    memcpy(resp_data + 1 + 8, signature, 64);
    
    // 发送响应
    if (!send_message(client_socket, CMD_CERT_STATUS, resp_data, 1 + 8 + 64)) {
        printf("发送证书状态响应失败\n");
        return;
    }
    
    printf("已发送证书状态响应\n");
}

int local_generate_cert(const char *subject_id) { 
    // 检查用户是否存在
    if (check_user_exists(subject_id)) {
        printf("用户ID '%s' 已存在，拒绝注册\n", subject_id);
        return 0;
    }
    
    //--------step1:用户端(现在由CA模拟)-----------
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
    
    // --------step2:CA端生成隐式证书计算部分重构值-----------
    // CA选取随机值k
    BIGNUM *k = BN_new();
    BN_rand_range(k, order);

    // 计算公钥重构值Pu=Ru+k*G
    EC_POINT *Pu = EC_POINT_new(group);
    EC_POINT_mul(group, Pu, k, NULL, NULL, NULL);
    EC_POINT_add(group, Pu, Ru, Pu, NULL);

    // 生成新的证书序列号
    char* serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", serial_num);

    // 生成隐式证书
    ImpCert cert;
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60; // 1h有效期
    if(!set_cert(&cert, 
              (unsigned char *)serial_num,
              (unsigned char *)"CA000001", 
              (unsigned char *)subject_id,  // 使用用户提供的ID
              current_time,
              expire_time,
              Pu)){
        printf("证书设置失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        BN_free(k);
        BN_free(Ku);
        return 0;
    }

    
    // 保存证书到UserCerts目录下
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    if (!save_cert(&cert, cert_filename)) {
        printf("警告：无法保存用户证书到文件\n");
    }
    
    // 计算隐式证书的哈希值
    unsigned char cert_hash[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), cert_hash);
    print_hex("隐式证书哈希值e", cert_hash, 32);

    // 保存用户信息到UserList
    if (!save_user_list(subject_id, cert_hash)) {
        printf("保存用户数据失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        BN_free(k);
        BN_free(Ku);
        return 0;
    }
    
    printf("用户 '%s' 成功注册并保存到UserList\n", subject_id);

    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, cert_hash, k, d_ca, order);
    
    //--------step3:用户端生成最终的公私钥对(现在由CA模拟)-------------
    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, cert_hash, Ku, r, order);
    print_hex("用户私钥d_u", d_u, SM2_PRI_MAX_SIZE);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, cert_hash, Pu, Q_ca);
    print_hex("用户公钥Qu", Qu, SM2_PUB_MAX_SIZE);
    
    // 验证密钥对
    if(verify_key_pair_bytes(group, Qu, d_u)){
        printf("密钥对验证成功！\n");
    }else{
        printf("密钥对验证失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(Pu);
        BN_free(k);
        BN_free(Ku);
        return 0;
    }
    
    // 保存用户私钥
    char priv_key_filename[100] = {0};
    sprintf(priv_key_filename, "%s/%s_priv.key", USERDATA_DIR, subject_id);
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存用户私钥到文件\n");
    }
    
    // 保存用户公钥
    char pub_key_filename[100] = {0};
    sprintf(pub_key_filename, "%s/%s_pub.key", USERDATA_DIR, subject_id);
    
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存用户公钥到文件\n");
    }
    
    // 释放资源
    EC_POINT_free(Ru);
    EC_POINT_free(Pu);
    BN_free(k);
    BN_free(Ku);
    
    printf("--------------------------------\n");
    
    return 1;
}

int local_update_cert(const char *subject_id) {
    
    // 检查用户是否存在
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，拒绝更新\n", subject_id);
        return 0;
    }
    
    // 加载用户的现有证书
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    ImpCert old_cert;
    if (!load_cert(&old_cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        return 0;
    }
    
    // 验证证书有效性
    if (!validate_cert(&old_cert)) {
        printf("用户证书已过期，请重新注册\n");
        return 0;
    }
    
    // 直接从用户哈希表获取证书哈希
    unsigned char *old_cert_hash = hashmap_get(user_map, subject_id);
    if (!old_cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        return 0;
    }
    
    // 检查证书是否在撤销列表中
    if (check_cert_in_crl(old_cert_hash)) {
        printf("用户证书已被撤销，请重新注册\n");
        return 0;
    }
    
    //--------step1:用户端(现在由CA模拟)-----------
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
    
    // --------步骤与证书注册类似:CA端生成新隐式证书-----------
    // CA选取随机值k
    BIGNUM *k = BN_new();
    BN_rand_range(k, order);

    // 计算公钥重构值Pu=Ru+k*G
    EC_POINT *new_Pu = EC_POINT_new(group);
    EC_POINT_mul(group, new_Pu, k, NULL, NULL, NULL);
    EC_POINT_add(group, new_Pu, Ru, new_Pu, NULL);

    // 生成新的证书序列号
    char* serial_num = generate_serial_num();
    printf("生成更新证书，序列号: %s\n", serial_num);

    // 生成新隐式证书
    ImpCert new_cert;
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60; // 1h有效期
    if(!set_cert(&new_cert, 
              (unsigned char *)serial_num,
              (unsigned char *)"CA000001", 
              (unsigned char *)subject_id,
              current_time,
              expire_time,
              new_Pu)){
        printf("新证书设置失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(new_Pu);
        BN_free(k);
        BN_free(Ku);
        return 0;
    }

    // 计算新隐式证书的哈希值
    unsigned char new_cert_hash[32];
    sm3_hash((const unsigned char *)&new_cert, sizeof(ImpCert), new_cert_hash);
    print_hex("新隐式证书哈希值e", new_cert_hash, 32);

    // 获取旧证书的到期时间
    time_t old_expire_time;
    memcpy(&old_expire_time, old_cert.Validity + sizeof(time_t), sizeof(time_t));

    // 将旧证书加入撤销列表
    if (!add_cert_to_crl(old_cert_hash, old_expire_time)) {
        printf("警告：无法将旧证书添加到撤销列表\n");
    }
    
    // 更新用户信息到UserList.txt
    if (!update_user_list(subject_id, new_cert_hash)) {
        printf("更新用户数据失败！\n");
    }

    // 保存新证书到文件系统，覆盖现有文件
    if (!save_cert(&new_cert, cert_filename)) {
        printf("警告：无法保存新用户证书到文件\n");
    }

    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, new_cert_hash, k, d_ca, order);
    
    //--------step3:用户端生成最终的公私钥对(现在由CA模拟)-------------
    // 计算最终私钥d_u=e×Ku+r (mod n)
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, new_cert_hash, Ku, r, order);
    print_hex("用户新私钥d_u", d_u, SM2_PRI_MAX_SIZE);
    
    // 公钥重构 Qu=e×Pu+Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, new_cert_hash, new_Pu, Q_ca);
    print_hex("用户新公钥Qu", Qu, SM2_PUB_MAX_SIZE);
    
    // 验证密钥对
    if(verify_key_pair_bytes(group, Qu, d_u)){
        printf("新密钥对验证成功！\n");
    }else{
        printf("新密钥对验证失败！\n");
        EC_POINT_free(Ru);
        EC_POINT_free(new_Pu);
        BN_free(k);
        BN_free(Ku);
        return 0;
    }
    
    // 保存用户新私钥供后续使用
    char priv_key_filename[100] = {0};
    sprintf(priv_key_filename, "%s/%s_priv.key", USERDATA_DIR, subject_id);
    
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存更新后的用户私钥到文件\n");
    }
    
    // 保存用户新公钥供后续使用
    char pub_key_filename[100] = {0};
    sprintf(pub_key_filename, "%s/%s_pub.key", USERDATA_DIR, subject_id);
    
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存更新后的用户公钥到文件\n");
    }
    
    // 释放资源
    EC_POINT_free(Ru);
    EC_POINT_free(new_Pu);
    BN_free(k);
    BN_free(Ku);
    
    printf("--------------------------------\n");
    
    return 1;
}

// ---- 用户数据管理相关函数 ----
int check_user_exists(const char *subject_id) {
    return hashmap_exists(user_map, subject_id) ? 1 : 0;
}

int save_user_list(const char *subject_id, const unsigned char *cert_hash) {
    return hashmap_put(user_map, strdup(subject_id), (void*)cert_hash, CERT_HASH_LEN) ? 1 : 0;
}

int update_user_list(const char *subject_id, const unsigned char *new_cert_hash) {
    return hashmap_put(user_map, strdup(subject_id), (void*)new_cert_hash, CERT_HASH_LEN) ? 1 : 0;
}

// ---- CRL管理相关函数 ----
int check_cert_in_crl(const unsigned char *cert_hash) {
    return hashmap_exists(crl_map, cert_hash) ? 1 : 0;
}

int add_cert_to_crl(const unsigned char *cert_hash, time_t expire_time) {
    unsigned char* cert_hash_copy = malloc(CERT_HASH_LEN);
    if (!cert_hash_copy) return 0;
    
    memcpy(cert_hash_copy, cert_hash, CERT_HASH_LEN);
    
    // 分配存储到期时间的内存
    time_t* expire_time_copy = malloc(sizeof(time_t));
    if (!expire_time_copy) {
        free(cert_hash_copy);
        return 0;
    }
    
    *expire_time_copy = expire_time;
    return hashmap_put(crl_map, cert_hash_copy, expire_time_copy, sizeof(time_t)) ? 1 : 0;
}

// ---- 序列号管理相关函数 ----
int load_serial_num() {
    FILE *file = fopen(SERIAL_NUM_FILE, "r");
    if (!file) {
        printf("序列号文件不存在，将使用默认值1\n");
        return 1;  // 文件不存在，使用默认值1
    }
    
    unsigned int serial_num;
    if (fscanf(file, "%u", &serial_num) != 1) {
        printf("读取序列号失败，将使用默认值1\n");
        fclose(file);
        return 1;  // 读取失败，使用默认值1
    }
    
    fclose(file);
    return serial_num;
}

int save_serial_num() {
    FILE *file = fopen(SERIAL_NUM_FILE, "w");
    if (!file) {
        printf("无法创建序列号文件\n");
        return 0;
    }
    
    fprintf(file, "%u", current_serial_num);
    fclose(file);
    return 1;
}

char* generate_serial_num() {
    static char serial_str[9];  // SN + 6位数字 + 结束符
    
    // 格式化序列号
    snprintf(serial_str, sizeof(serial_str), SERIAL_NUM_FORMAT, current_serial_num);
    
    // 递增序列号
    current_serial_num++;
    if (current_serial_num > SERIAL_NUM_MAX) {
        current_serial_num = 1;  // 超过最大值，重置为1
        printf("警告：序列号已达到最大值，重置为1\n");
    }
    
    // 保存序列号到文件
    save_serial_num();
    
    return serial_str;
}

// ---- 运行模式相关函数 ----
void run_local_mode() {
    int choice = 0;
    char subject_id[SUBJECT_ID_SIZE] = {0};
    int running = 1;
    
    printf("===== CA服务器-本地模式 =====\n");
    
    while (running) {
        // 显示菜单
        printf("\n请选择操作:\n");
        printf("1. 本地证书注册\n");
        printf("2. 本地证书更新\n");
        printf("0. 退出\n");
        printf("请输入选择: ");
        
        if (scanf("%d", &choice) != 1) {
            printf("输入错误，请重新输入\n");
            // 清空输入缓冲区
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }
        
        if (choice == 0) {
            running = 0;
            printf("正在退出本地模式...\n");
            continue;
        }
        
        // 清空输入缓冲区
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        // 获取用户ID
        printf("请输入用户ID (必须是8个字符): ");
        if (scanf("%8s", subject_id) != 1 || strlen(subject_id) != 8) {
            printf("ID输入错误，必须是8个字符\n");
            // 清空输入缓冲区
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }
        
        // 清空输入缓冲区
        while ((c = getchar()) != '\n' && c != EOF);
        
        switch (choice) {
            case 1:
                printf("--------------------------------\n");
                local_generate_cert(subject_id);
                break;
            case 2:
                printf("--------------------------------\n");
                local_update_cert(subject_id);
                break;
            default:
                printf("无效的选择\n");
                break;
        }
        
        // 保存信息
        if(!ul_hashmap_save(user_map, USERLIST_FILE)){
            printf("保存用户列表失败！\n");
        }
        if(!crl_hashmap_save(crl_map, CRL_FILE)){
            printf("保存CRL列表失败！\n");
        }
        // 保存序列号
        if(!save_serial_num()){
            printf("保存序列号失败！\n");
        }
    }
}

void run_online_mode() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    printf("===== CA服务器-线上模式 =====\n");
    
    // 服务器初始化
    server_fd = setup_server(PORT);
    if (server_fd < 0) {
        return;
    }
    
    while(1) {
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("接受连接失败");
            continue;
        }
        handle_client(client_socket);
        close(client_socket);
        // 保存信息
        if(!ul_hashmap_save(user_map, USERLIST_FILE)){
            printf("保存用户列表失败！\n");
        }
        if(!crl_hashmap_save(crl_map, CRL_FILE)){
            printf("保存CRL列表失败！\n");
        }
        // 保存序列号
        if(!save_serial_num()){
            printf("保存序列号失败！\n");
        }
    }
    
    // 程序结束时清理资源
    close(server_fd);
}

