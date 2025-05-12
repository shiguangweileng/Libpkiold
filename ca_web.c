#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <json-c/json.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include "include/common.h"
#include "include/imp_cert.h"
#include "include/gm_crypto.h"

#define PORT 8888
#define CA_PORT 8001
#define CA_IP "127.0.0.1"
#define BUFFER_SIZE 8192
#define MSG_HEADER_SIZE 3
#define USER_DATA_DIR "server/ca-server/UserData/"
#define USER_CERTS_DIR "server/ca-server/UserCerts/"

// Web通信协议命令（需要与ca.c中定义的一致）
#define WEB_CMD_GET_USERS      0x81    // ca_web请求获取用户列表
#define WEB_CMD_USER_LIST      0x82    // ca向ca_web发送用户列表
#define WEB_CMD_GET_CERT       0x83    // ca_web请求获取特定用户证书
#define WEB_CMD_CERT_DATA      0x84    // ca向ca_web发送证书数据
#define WEB_CMD_GET_CRL        0x85    // ca_web请求获取证书撤销列表
#define WEB_CMD_CRL_DATA       0x86    // ca向ca_web发送证书撤销列表数据
#define WEB_CMD_CLEANUP_CERTS  0x87    // ca_web请求清理过期证书
#define WEB_CMD_CLEANUP_RESULT 0x88    // ca向ca_web发送清理结果
#define WEB_CMD_LOCAL_GEN_CERT 0x89    // ca_web请求本地生成证书
#define WEB_CMD_LOCAL_UPD_CERT 0x8A    // ca_web请求本地更新证书
#define WEB_CMD_LOCAL_RESULT   0x8B    // ca向ca_web发送本地操作结果
#define WEB_CMD_REVOKE_CERT    0x8C    // ca_web请求撤销证书
#define WEB_CMD_REVOKE_RESULT  0x8D    // ca向ca_web发送撤销结果

// 用户数据结构
#define SUBJECT_ID_SIZE 9   // 8字符ID + 结束符
#define CERT_HASH_SIZE 32   // 证书哈希32字节

typedef struct {
    char id[SUBJECT_ID_SIZE];
    unsigned char cert_hash[CERT_HASH_SIZE];
} UserInfo;

// CRL数据结构
typedef struct {
    unsigned char cert_hash[CERT_HASH_SIZE];
    time_t expire_time;
} CRLEntry;

// 版本信息数据结构
typedef struct {
    int base_v;       // 基础版本号
    int removed_v;    // 已删除版本号
} CRLVersion;

// 全局变量
int ca_socket = -1;               // 与CA服务器的连接socket
pthread_mutex_t ca_socket_mutex = PTHREAD_MUTEX_INITIALIZER; // CA连接互斥锁
UserInfo* users = NULL;           // 用户列表数据
int user_count = 0;               // 用户数量
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER; // 用户数据互斥锁
CRLEntry* crl_entries = NULL;     // CRL列表数据
int crl_count = 0;                // CRL条目数量
CRLVersion crl_version = {0, 0};  // CRL版本信息
pthread_mutex_t crl_mutex = PTHREAD_MUTEX_INITIALIZER; // CRL数据互斥锁
unsigned char Q_ca[SM2_PUB_MAX_SIZE]; // CA公钥，用于重构用户公钥

// ============ 函数声明部分，按功能分组 ============

// 网络通信相关函数
int connect_to_ca();
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len);
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len);

// CA通信请求函数
int request_user_list();
int request_user_certificate(const char *user_id, unsigned char *cert_data, int max_size);
int request_crl_list();
int request_cleanup_expired_certs();
int request_local_gen_cert(const char *user_id);
int request_local_upd_cert(const char *user_id);
int request_revoke_cert(const char *user_id);

// HTTP处理函数
int handle_cors_preflight(struct MHD_Connection *connection);
int handle_user_list(struct MHD_Connection *connection);
int handle_crl_list(struct MHD_Connection *connection);
int handle_user_certificate(struct MHD_Connection *connection, const char *url);
int handle_cleanup_expired_certs(struct MHD_Connection *connection);
int handle_local_cert_operation(struct MHD_Connection *connection, const char *url, const char *upload_data, size_t *upload_data_size, int is_generate);
int handle_keypair_with_param(struct MHD_Connection *connection);
int handle_sign_message(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
int handle_verify_signature(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
int handle_revoke_certificate(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
// 工具函数
int hex_decode(const char *hex_str, unsigned char *bin_data, int max_size);
char* hex_encode(const unsigned char *bin_data, int bin_size);
// 错误响应函数
int send_error_response(struct MHD_Connection *connection, int status_code, const char *message);
int send_json_error(struct MHD_Connection *connection, int status_code, const char *message);
int send_json_response(struct MHD_Connection *connection, int status_code, struct json_object *json_obj, const char *allowed_methods);
struct json_object* parse_post_data(struct MHD_Connection *connection, 
                                   char **request_buffer, 
                                   const char *upload_data, 
                                   size_t *upload_data_size);

enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                              const char *url, const char *method,
                              const char *version, const char *upload_data,
                              size_t *upload_data_size, void **con_cls);

// 线程函数
void* ca_comm_thread_func(void* arg);

// ============ main函数 ============

int main() {
    struct MHD_Daemon *daemon;
    pthread_t ca_thread;
    
    // 初始化SM2参数
    if (!sm2_params_init()) {
        fprintf(stderr, "初始化SM2参数失败\n");
        return 1;
    }
    
    // 加载CA公钥
    FILE *fp = fopen("server/ca-server/ca_pub.key", "rb");
    if (fp) {
        fread(Q_ca, 1, SM2_PUB_MAX_SIZE, fp);
        fclose(fp);
        printf("已加载CA公钥\n");
    } else {
        fprintf(stderr, "无法加载CA公钥，某些功能可能不可用\n");
    }
    
    // 启动CA通信线程
    if (pthread_create(&ca_thread, NULL, ca_comm_thread_func, NULL) != 0) {
        fprintf(stderr, "无法创建CA通信线程\n");
        return 1;
    }
    
    // 启动HTTP服务器
    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                             &request_handler, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "无法启动HTTP服务器\n");
        return 1;
    }
    
    printf("CA Web服务器已启动，监听端口: %d\n", PORT);
    printf("按Enter键停止服务器...\n");
    getchar();
    
    // 停止HTTP服务器
    MHD_stop_daemon(daemon);
    
    // 关闭与CA的连接
    pthread_mutex_lock(&ca_socket_mutex);
    if (ca_socket >= 0) {
        close(ca_socket);
        ca_socket = -1;
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
    // 等待CA通信线程结束
    pthread_cancel(ca_thread);
    pthread_join(ca_thread, NULL);
    
    // 释放用户数据
    pthread_mutex_lock(&users_mutex);
    if (users) {
        free(users);
        users = NULL;
    }
    pthread_mutex_unlock(&users_mutex);
    
    // 释放CRL数据
    pthread_mutex_lock(&crl_mutex);
    if (crl_entries) {
        free(crl_entries);
        crl_entries = NULL;
    }
    pthread_mutex_unlock(&crl_mutex);
    
    // 清理SM2参数
    sm2_params_cleanup();
    
    return 0;
}

// ============ 函数实现部分 ============

// ---- 错误处理辅助函数 ----

// 发送简单错误响应
int send_error_response(struct MHD_Connection *connection, int status_code, const char *message) {
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(message), (void*)message, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Content-Type", "text/plain");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

// 发送JSON格式错误响应
int send_json_error(struct MHD_Connection *connection, int status_code, const char *message) {
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(0));
    json_object_object_add(response_obj, "message", json_object_new_string(message));
    
    const char *response_str = json_object_to_json_string(response_obj);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(response_str), (void*)response_str, MHD_RESPMEM_MUST_COPY);
    
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    json_object_put(response_obj);
    return ret;
}

// 添加通用的JSON响应函数
int send_json_response(struct MHD_Connection *connection, int status_code, struct json_object *json_obj, const char *allowed_methods) {
    const char *response_str = json_object_to_json_string(json_obj);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(response_str), (void*)response_str, MHD_RESPMEM_MUST_COPY);
    
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    if (allowed_methods) {
        MHD_add_response_header(response, "Access-Control-Allow-Methods", allowed_methods);
    }
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
    
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

// 解析POST请求中的JSON数据
struct json_object* parse_post_data(struct MHD_Connection *connection, 
                                   char **request_buffer, 
                                   const char *upload_data, 
                                   size_t *upload_data_size) {
    // 第一次调用，分配请求缓冲区
    if (*upload_data_size != 0) {
        if (!*request_buffer) {
            *request_buffer = malloc(*upload_data_size + 1);
            if (!*request_buffer) {
                return NULL;
            }
            memcpy(*request_buffer, upload_data, *upload_data_size);
            (*request_buffer)[*upload_data_size] = '\0';
            *upload_data_size = 0;
            return NULL; // 返回NULL表示需要再次调用
        }
    } else if (!*request_buffer) {
        // 没有POST数据
        return NULL;
    }
    
    // 解析JSON请求
    struct json_object *request_obj = json_tokener_parse(*request_buffer);
    
    return request_obj;
}

// ---- 网络通信相关函数 ----

// 连接到CA服务器
int connect_to_ca() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket创建失败");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(CA_PORT);
    
    if (inet_pton(AF_INET, CA_IP, &serv_addr.sin_addr) <= 0) {
        perror("IP地址无效");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("连接CA失败");
        close(sock);
        return -1;
    }
    
    return sock;
}

// 发送消息到指定socket
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len) {
    unsigned char header[MSG_HEADER_SIZE];
    
    // 构建消息头：命令(1字节) + 数据长度(2字节，网络字节序)
    header[0] = cmd;
    header[1] = (data_len >> 8) & 0xFF;
    header[2] = data_len & 0xFF;
    
    // 发送消息头
    if (send(sock, header, MSG_HEADER_SIZE, 0) != MSG_HEADER_SIZE) {
        perror("发送消息头失败");
        return 0;
    }
    
    // 发送消息体（如果有）
    if (data_len > 0 && data != NULL) {
        if (send(sock, data, data_len, 0) != data_len) {
            perror("发送消息体失败");
            return 0;
        }
    }
    
    return 1;
}

// 从指定socket接收消息
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len) {
    unsigned char header[MSG_HEADER_SIZE];
    
    // 接收消息头
    int bytes_received = recv(sock, header, MSG_HEADER_SIZE, 0);
    if (bytes_received != MSG_HEADER_SIZE) {
        if (bytes_received == 0) {
            // 连接已关闭
            return -1;
        }
        perror("接收消息头失败");
        return -1;
    }
    
    // 解析消息头
    *cmd = header[0];
    uint16_t data_len = (header[1] << 8) | header[2];
    
    // 验证数据长度
    if (data_len > max_len) {
        fprintf(stderr, "数据太长: %d > %d\n", data_len, max_len);
        return -1;
    }
    
    // 接收消息体（如果有）
    if (data_len > 0) {
        bytes_received = recv(sock, data, data_len, 0);
        if (bytes_received != data_len) {
            perror("接收消息体失败");
            return -1;
        }
    }
    
    return data_len;
}

// ---- CA通信请求函数 ----

// 请求用户列表
int request_user_list() {
    int result = 0;
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查连接是否有效
    if (ca_socket < 0) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 发送请求
    if (!send_message(ca_socket, WEB_CMD_GET_USERS, NULL, 0)) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_USER_LIST) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 解析响应数据
    if (data_len >= sizeof(int)) {
        int new_user_count = 0;
        memcpy(&new_user_count, buffer, sizeof(int));
        
        // 检查数据大小是否合理
        if (data_len == sizeof(int) + new_user_count * (SUBJECT_ID_SIZE + CERT_HASH_SIZE)) {
            // 锁定用户数据
            pthread_mutex_lock(&users_mutex);
            
            // 释放旧数据
            if (users) {
                free(users);
                users = NULL;
                user_count = 0;
            }
            
            // 分配新内存
            if (new_user_count > 0) {
                users = (UserInfo*)malloc(sizeof(UserInfo) * new_user_count);
                if (users) {
                    user_count = new_user_count;
                    
                    // 解析用户数据
                    int offset = sizeof(int);
                    for (int i = 0; i < user_count; i++) {
                        // 复制用户ID
                        memcpy(users[i].id, buffer + offset, SUBJECT_ID_SIZE);
                        offset += SUBJECT_ID_SIZE;
                        
                        // 复制证书哈希
                        memcpy(users[i].cert_hash, buffer + offset, CERT_HASH_SIZE);
                        offset += CERT_HASH_SIZE;
                    }
                    
                    result = 1;
                }
            } else {
                // 空列表
                result = 1;
            }
            
            // 解锁用户数据
            pthread_mutex_unlock(&users_mutex);
        }
    }
    
    // 解锁CA连接
    pthread_mutex_unlock(&ca_socket_mutex);
    
    return result;
}

// 请求CRL列表
int request_crl_list() {
    int result = 0;
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查连接是否有效
    if (ca_socket < 0) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 发送请求
    if (!send_message(ca_socket, WEB_CMD_GET_CRL, NULL, 0)) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_CRL_DATA) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 解析响应数据
    if (data_len >= sizeof(int) * 3) { // 至少包含基础版本号、删除版本号和CRL条目数
        int offset = 0;
        
        // 读取基础版本号
        memcpy(&crl_version.base_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        
        // 读取删除版本号
        memcpy(&crl_version.removed_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        
        // 读取CRL条目数
        int new_crl_count = 0;
        memcpy(&new_crl_count, buffer + offset, sizeof(int));
        offset += sizeof(int);
        
        // 检查数据大小是否合理
        if (data_len == sizeof(int) * 3 + new_crl_count * (CERT_HASH_SIZE + sizeof(time_t))) {
            // 锁定CRL数据
            pthread_mutex_lock(&crl_mutex);
            
            // 释放旧数据
            if (crl_entries) {
                free(crl_entries);
                crl_entries = NULL;
                crl_count = 0;
            }
            
            // 分配新内存
            if (new_crl_count > 0) {
                crl_entries = (CRLEntry*)malloc(sizeof(CRLEntry) * new_crl_count);
                if (crl_entries) {
                    crl_count = new_crl_count;
                    
                    // 解析CRL数据
                    for (int i = 0; i < crl_count; i++) {
                        // 复制证书哈希
                        memcpy(crl_entries[i].cert_hash, buffer + offset, CERT_HASH_SIZE);
                        offset += CERT_HASH_SIZE;
                        
                        // 复制到期时间
                        memcpy(&crl_entries[i].expire_time, buffer + offset, sizeof(time_t));
                        offset += sizeof(time_t);
                    }
                    
                    result = 1;
                }
            } else {
                // 空列表
                result = 1;
            }
            
            // 解锁CRL数据
            pthread_mutex_unlock(&crl_mutex);
        }
    }
    
    // 解锁CA连接
    pthread_mutex_unlock(&ca_socket_mutex);
    
    return result;
}

// 请求获取用户证书
int request_user_certificate(const char *user_id, unsigned char *cert_data, int max_size) {
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    int result = 0;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查连接是否有效
    if (ca_socket < 0) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 发送请求，包含用户ID
    if (!send_message(ca_socket, WEB_CMD_GET_CERT, user_id, strlen(user_id) + 1)) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len <= 0 || cmd != WEB_CMD_CERT_DATA) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 响应数据为空，表示没有找到证书或出错
    if (data_len == 0) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 复制证书数据
    if (data_len <= max_size) {
        memcpy(cert_data, buffer, data_len);
        result = data_len;
    }
    
    // 解锁CA连接
    pthread_mutex_unlock(&ca_socket_mutex);
    
    return result;
}

// 请求清理过期证书
int request_cleanup_expired_certs() {
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    int cleaned_count = 0;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查连接是否有效
    if (ca_socket < 0) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return -1;
    }
    
    // 发送清理请求
    if (!send_message(ca_socket, WEB_CMD_CLEANUP_CERTS, NULL, 0)) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return -1;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_CLEANUP_RESULT) {
        pthread_mutex_unlock(&ca_socket_mutex);
        return -1;
    }
    
    // 解析响应数据（清理的证书数量）
    if (data_len >= sizeof(int)) {
        memcpy(&cleaned_count, buffer, sizeof(int));
    }
    
    // 解锁CA连接
    pthread_mutex_unlock(&ca_socket_mutex);
    
    return cleaned_count;
}

// 请求本地生成证书
int request_local_gen_cert(const char *user_id) {
    int result = 0;
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查是否需要重新连接CA
    if (ca_socket < 0) {
        ca_socket = connect_to_ca();
        if (ca_socket < 0) {
            pthread_mutex_unlock(&ca_socket_mutex);
            return 0;
        }
    }
    
    // 发送请求
    if (!send_message(ca_socket, WEB_CMD_LOCAL_GEN_CERT, user_id, strlen(user_id) + 1)) {
        close(ca_socket);
        ca_socket = -1;
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_LOCAL_RESULT) {
        close(ca_socket);
        ca_socket = -1;
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    pthread_mutex_unlock(&ca_socket_mutex);
    return result;
}

// 请求本地更新证书
int request_local_upd_cert(const char *user_id) {
    int result = 0;
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查是否需要重新连接CA
    if (ca_socket < 0) {
        ca_socket = connect_to_ca();
        if (ca_socket < 0) {
            pthread_mutex_unlock(&ca_socket_mutex);
            return 0;
        }
    }
    
    // 发送请求
    if (!send_message(ca_socket, WEB_CMD_LOCAL_UPD_CERT, user_id, strlen(user_id) + 1)) {
        close(ca_socket);
        ca_socket = -1;
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_LOCAL_RESULT) {
        close(ca_socket);
        ca_socket = -1;
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    pthread_mutex_unlock(&ca_socket_mutex);
    return result;
}

// 请求撤销证书
int request_revoke_cert(const char *user_id) {
    int result = 0;
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    
    // 锁定CA连接
    pthread_mutex_lock(&ca_socket_mutex);
    
    // 检查是否需要重新连接CA
    if (ca_socket < 0) {
        ca_socket = connect_to_ca();
        if (ca_socket < 0) {
            pthread_mutex_unlock(&ca_socket_mutex);
            return 0;
        }
    }
    
    // 发送撤销请求
    if (!send_message(ca_socket, WEB_CMD_REVOKE_CERT, user_id, strlen(user_id) + 1)) {
        close(ca_socket);
        ca_socket = -1;
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_REVOKE_RESULT) {
        close(ca_socket);
        ca_socket = -1;
        pthread_mutex_unlock(&ca_socket_mutex);
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    pthread_mutex_unlock(&ca_socket_mutex);
    return result;
}

// ---- HTTP处理函数 ----

// 处理CORS预检请求
int handle_cors_preflight(struct MHD_Connection *connection) {
    struct MHD_Response *response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    MHD_add_response_header(response, "Access-Control-Max-Age", "86400");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

// 处理用户列表请求
int handle_user_list(struct MHD_Connection *connection) {
    struct json_object *response_obj = json_object_new_array();
    
    // 锁定用户数据
    pthread_mutex_lock(&users_mutex);
    
    // 将实际用户数据转换为JSON
    for (int i = 0; i < user_count; i++) {
        struct json_object *user = json_object_new_object();
        
        // 用户ID
        json_object_object_add(user, "id", json_object_new_string(users[i].id));
        
        char hash_hex[CERT_HASH_SIZE * 2 + 1] = {0};
        for (int j = 0; j < CERT_HASH_SIZE; j++) {
            sprintf(hash_hex + j * 2, "%02x", users[i].cert_hash[j]);
        }
        json_object_object_add(user, "certHash", json_object_new_string(hash_hex));
        
        json_object_array_add(response_obj, user);
    }
    
    // 解锁用户数据
    pthread_mutex_unlock(&users_mutex);
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理证书撤销列表请求
int handle_crl_list(struct MHD_Connection *connection) {
    // 先从CA请求最新的CRL数据
    request_crl_list();
    
    // 创建一个包含版本信息和CRL数据的对象
    struct json_object *response_obj = json_object_new_object();
    
    // 添加版本信息
    pthread_mutex_lock(&crl_mutex);
    json_object_object_add(response_obj, "baseVersion", json_object_new_int(crl_version.base_v));
    json_object_object_add(response_obj, "removedVersion", json_object_new_int(crl_version.removed_v));
    
    // 添加CRL数据数组
    struct json_object *crl_array = json_object_new_array();
    
    // 将实际CRL数据转换为JSON
    for (int i = 0; i < crl_count; i++) {
        struct json_object *crl_item = json_object_new_object();
        
        // 证书哈希（转为十六进制字符串）
        char hash_hex[CERT_HASH_SIZE * 2 + 1] = {0};
        for (int j = 0; j < CERT_HASH_SIZE; j++) {
            sprintf(hash_hex + j * 2, "%02x", crl_entries[i].cert_hash[j]);
        }
        json_object_object_add(crl_item, "certHash", json_object_new_string(hash_hex));
        
        // 到期时间（转为ISO 8601格式）
        char time_str[32] = {0};
        struct tm *tm_info = localtime(&crl_entries[i].expire_time);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        json_object_object_add(crl_item, "expireTime", json_object_new_string(time_str));
        
        json_object_array_add(crl_array, crl_item);
    }
    
    // 添加CRL数组到响应对象
    json_object_object_add(response_obj, "crlItems", crl_array);
    
    // 解锁CRL数据
    pthread_mutex_unlock(&crl_mutex);
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理获取单个用户证书请求
int handle_user_certificate(struct MHD_Connection *connection, const char *url) {
    // 获取userId参数
    const char *user_id = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "userId");
    if (!user_id || strlen(user_id) != 8) {
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "无效的用户ID");
    }
    // 请求证书数据，格式：证书结构体 + 哈希值(32字节) + 有效性标志(1字节) + 撤销标志(1字节)
    unsigned char cert_data[BUFFER_SIZE];
    int data_len = request_user_certificate(user_id, cert_data, BUFFER_SIZE);
    if (data_len <= 0) {
        return send_json_error(connection, MHD_HTTP_NOT_FOUND, "无法获取用户证书");
    }
    
    // 解析证书数据
    ImpCert cert;
    unsigned char cert_hash[32];
    uint8_t is_valid, is_revoked;
    
    // 证书结构体
    memcpy(&cert, cert_data, sizeof(ImpCert));
    // 证书哈希
    memcpy(cert_hash, cert_data + sizeof(ImpCert), 32);
    // 有效性标志
    is_valid = cert_data[sizeof(ImpCert) + 32];
    // 撤销标志
    is_revoked = cert_data[sizeof(ImpCert) + 32 + 1];
    
    // 提取证书有效期
    time_t start_time, end_time;
    memcpy(&start_time, cert.Validity, sizeof(time_t));
    memcpy(&end_time, cert.Validity + sizeof(time_t), sizeof(time_t));
    
    // 转换证书数据为JSON
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "serialNum", json_object_new_string((const char*)cert.SerialNum));
    json_object_object_add(response_obj, "issuerID", json_object_new_string((const char*)cert.IssuerID));
    json_object_object_add(response_obj, "subjectID", json_object_new_string((const char*)cert.SubjectID));
    json_object_object_add(response_obj, "validFrom", json_object_new_int64((int64_t)start_time));
    json_object_object_add(response_obj, "validTo", json_object_new_int64((int64_t)end_time));
    // 公钥（转为十六进制字符串）
    char *pubkey_hex = hex_encode(cert.PubKey, 33);
    json_object_object_add(response_obj, "pubKey", json_object_new_string(pubkey_hex));
    free(pubkey_hex);
    // 证书哈希（转为十六进制字符串）
    char *hash_hex = hex_encode(cert_hash, 32);
    json_object_object_add(response_obj, "certHash", json_object_new_string(hash_hex));
    free(hash_hex);
    
    // 状态标志
    json_object_object_add(response_obj, "isValid", json_object_new_boolean(is_valid));
    json_object_object_add(response_obj, "isRevoked", json_object_new_boolean(is_revoked));
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理清理过期证书请求
int handle_cleanup_expired_certs(struct MHD_Connection *connection) {
    // 请求清理过期证书
    int cleaned_count = request_cleanup_expired_certs();
    
    // 创建JSON响应
    struct json_object *response_obj = json_object_new_object();
    
    if (cleaned_count >= 0) {
        json_object_object_add(response_obj, "success", json_object_new_boolean(1));
        json_object_object_add(response_obj, "cleanedCount", json_object_new_int(cleaned_count));
    } else {
        json_object_object_add(response_obj, "success", json_object_new_boolean(0));
        json_object_object_add(response_obj, "error", json_object_new_string("无法清理证书，请确保CA服务器运行正常"));
    }
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理本地证书操作（生成或更新）
int handle_local_cert_operation(struct MHD_Connection *connection, const char *url, const char *upload_data, size_t *upload_data_size, int is_generate) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;
    struct json_object *user_id_obj = NULL;
    struct json_object *response_obj = NULL;
    const char *user_id = NULL;
    int result = 0;
    
    // 解析POST数据
    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }
    
    // 没有POST数据
    if (request_obj == NULL) {
        response_obj = json_object_new_object();
        json_object_object_add(response_obj, "success", json_object_new_boolean(0));
        json_object_object_add(response_obj, "message", json_object_new_string("缺少必要的用户ID数据"));
        
        int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, response_obj, "POST, OPTIONS");
        json_object_put(response_obj);
        
        free(request_buffer);
        request_buffer = NULL;
        
        return ret;
    }
    
    // 获取用户ID
    if (!json_object_object_get_ex(request_obj, "userId", &user_id_obj) || 
        !json_object_is_type(user_id_obj, json_type_string)) {
        
        response_obj = json_object_new_object();
        json_object_object_add(response_obj, "success", json_object_new_boolean(0));
        json_object_object_add(response_obj, "message", json_object_new_string("缺少必要的用户ID字段"));
        
        int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, response_obj, "POST, OPTIONS");
        json_object_put(response_obj);
        json_object_put(request_obj);
        
        free(request_buffer);
        request_buffer = NULL;
        
        return ret;
    }
    
    user_id = json_object_get_string(user_id_obj);
    
    // 检查用户ID格式
    if (strlen(user_id) != 8) {
        response_obj = json_object_new_object();
        json_object_object_add(response_obj, "success", json_object_new_boolean(0));
        json_object_object_add(response_obj, "message", json_object_new_string("用户ID必须是8个字符"));
        
        int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, response_obj, "POST, OPTIONS");
        json_object_put(response_obj);
        json_object_put(request_obj);
        
        free(request_buffer);
        request_buffer = NULL;
        
        return ret;
    }
    
    // 执行本地证书操作
    if (is_generate) {
        result = request_local_gen_cert(user_id);
    } else {
        result = request_local_upd_cert(user_id);
    }
    
    // 构建响应
    response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(result));
    
    if (result) {
        json_object_object_add(response_obj, "message", 
            json_object_new_string(is_generate ? "证书生成成功" : "证书更新成功"));
    } else {
        json_object_object_add(response_obj, "message", 
            json_object_new_string(is_generate ? "证书生成失败" : "证书更新失败"));
    }
    
    // 发送响应
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");
    
    // 清理资源
    json_object_put(response_obj);
    json_object_put(request_obj);
    
    free(request_buffer);
    request_buffer = NULL;
    
    return ret;
}

// 处理通过GET参数获取用户公私钥对的请求
int handle_keypair_with_param(struct MHD_Connection *connection) {
    // 获取userId查询参数
    const char *user_id = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "userId");
    if (!user_id || strlen(user_id) != 8) {
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "无效的用户ID");
    }
    
    // 构建文件路径
    char priv_path[256] = {0};
    char pub_path[256] = {0};
    snprintf(priv_path, sizeof(priv_path), "%s%s_priv.key", USER_DATA_DIR, user_id);
    snprintf(pub_path, sizeof(pub_path), "%s%s_pub.key", USER_DATA_DIR, user_id);
    
    // 检查目录是否存在
    struct stat st = {0};
    if (stat(USER_DATA_DIR, &st) == -1) {
        return send_json_error(connection, MHD_HTTP_NOT_FOUND, "用户数据目录不存在");
    }
    
    // 读取私钥文件
    FILE *fp = fopen(priv_path, "rb");
    if (!fp) {
        return send_json_error(connection, MHD_HTTP_NOT_FOUND, "读取私钥文件失败");
    }
    
    // 读取私钥数据
    unsigned char priv_key[SM2_PRI_MAX_SIZE];
    size_t priv_size = fread(priv_key, 1, SM2_PRI_MAX_SIZE, fp);
    fclose(fp);
    
    // 读取公钥文件
    fp = fopen(pub_path, "rb");
    if (!fp) {
        return send_json_error(connection, MHD_HTTP_NOT_FOUND, "读取公钥文件失败");
    }
    
    // 读取公钥数据
    unsigned char pub_key[SM2_PUB_MAX_SIZE];
    size_t pub_size = fread(pub_key, 1, SM2_PUB_MAX_SIZE, fp);
    fclose(fp);
    
    // 将二进制密钥转换为十六进制字符串
    char *priv_hex = hex_encode(priv_key, priv_size);
    char *pub_hex = hex_encode(pub_key, pub_size);
    
    // 构建JSON响应
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(1));
    json_object_object_add(response_obj, "privateKey", json_object_new_string(priv_hex));
    json_object_object_add(response_obj, "publicKey", json_object_new_string(pub_hex));
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    
    // 释放资源
    json_object_put(response_obj);
    free(priv_hex);
    free(pub_hex);
    
    return ret;
}

// 处理签名消息请求
int handle_sign_message(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;
    
    // 解析POST数据
    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }
    
    // 没有POST数据
    if (request_obj == NULL) {
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的请求数据");
    }
    
    // 获取请求参数
    struct json_object *user_id_obj, *private_key_obj, *message_obj;
    if (!json_object_object_get_ex(request_obj, "userId", &user_id_obj) ||
        !json_object_object_get_ex(request_obj, "privateKey", &private_key_obj) ||
        !json_object_object_get_ex(request_obj, "message", &message_obj)) {
        
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的请求参数");
    }
    
    const char *user_id = json_object_get_string(user_id_obj);
    const char *private_key_hex = json_object_get_string(private_key_obj);
    const char *message = json_object_get_string(message_obj);
    
    // 将十六进制私钥转换为二进制
    unsigned char private_key[SM2_PRI_MAX_SIZE];
    int private_key_len = hex_decode(private_key_hex, private_key, SM2_PRI_MAX_SIZE);
    
    if (private_key_len <= 0) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "无效的私钥格式");
    }
    
    // 使用SM2算法对消息进行签名
    unsigned char signature[64]; // SM2签名为64字节(R||S格式)
    int result = sm2_sign(signature, (const unsigned char*)message, strlen(message), private_key);
    
    struct json_object *response_obj = json_object_new_object();
    
    if (result) {
        // 将签名转为十六进制字符串
        char *signature_hex = hex_encode(signature, 64);
        
        json_object_object_add(response_obj, "success", json_object_new_boolean(1));
        json_object_object_add(response_obj, "signature", json_object_new_string(signature_hex));
        
        free(signature_hex);
    } else {
        json_object_object_add(response_obj, "success", json_object_new_boolean(0));
        json_object_object_add(response_obj, "message", json_object_new_string("签名失败"));
    }
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");
    
    // 释放资源
    json_object_put(response_obj);
    json_object_put(request_obj);
    
    free(request_buffer);
    request_buffer = NULL;
    
    return ret;
}

// 处理验证签名请求
int handle_verify_signature(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;
    
    // 解析POST数据
    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }
    
    // 没有POST数据
    if (request_obj == NULL) {
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的请求数据");
    }
    
    // 获取请求参数
    struct json_object *user_id_obj, *message_obj, *signature_obj;
    if (!json_object_object_get_ex(request_obj, "userId", &user_id_obj) ||
        !json_object_object_get_ex(request_obj, "message", &message_obj) ||
        !json_object_object_get_ex(request_obj, "signature", &signature_obj)) {
        
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的请求参数");
    }
    
    const char *user_id = json_object_get_string(user_id_obj);
    const char *message = json_object_get_string(message_obj);
    const char *signature_hex = json_object_get_string(signature_obj);
    
    // 将十六进制签名转换为二进制
    unsigned char signature[64];
    int signature_len = hex_decode(signature_hex, signature, 64);
    
    if (signature_len != 64) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "无效的签名格式");
    }
    
    // 读取用户证书
    char cert_path[256] = {0};
    snprintf(cert_path, sizeof(cert_path), "%s%s.crt", USER_CERTS_DIR, user_id);
    
    ImpCert cert;
    if (!load_cert(&cert, cert_path)) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_NOT_FOUND, "无法加载用户证书");
    }
    
    // 从证书获取部分公钥 Pu
    EC_POINT *Pu = EC_POINT_new(group);
    if (!Pu || !getPu(&cert, Pu)) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        EC_POINT_free(Pu);
        return send_json_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "无法从证书获取公钥");
    }
    
    // 计算证书哈希值 e
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    
    // 重构用户公钥 Qu = e*Pu + Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, e, Pu, Q_ca)) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        EC_POINT_free(Pu);
        return send_json_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "重构公钥失败");
    }
    
    // 验证签名
    int result = sm2_verify(signature, (const unsigned char*)message, strlen(message), Qu);
    
    struct json_object *response_obj = json_object_new_object();
    
    json_object_object_add(response_obj, "success", json_object_new_boolean(1));
    json_object_object_add(response_obj, "verified", json_object_new_boolean(result));
    
    // 将重构的公钥转为十六进制字符串
    char *pubkey_hex = hex_encode(Qu, SM2_PUB_MAX_SIZE);
    json_object_object_add(response_obj, "reconstructedPublicKey", json_object_new_string(pubkey_hex));
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");
    
    // 释放资源
    json_object_put(response_obj);
    json_object_put(request_obj);
    free(pubkey_hex);
    EC_POINT_free(Pu);
    
    free(request_buffer);
    request_buffer = NULL;
    
    return ret;
}

// 处理撤销证书请求
int handle_revoke_certificate(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;
    
    // 解析POST数据
    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }
    
    // 没有POST数据
    if (request_obj == NULL) {
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的请求数据");
    }
    
    // 获取请求参数
    struct json_object *user_id_obj;
    if (!json_object_object_get_ex(request_obj, "userId", &user_id_obj) ||
        !json_object_is_type(user_id_obj, json_type_string)) {
        
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的用户ID字段");
    }
    
    const char *user_id = json_object_get_string(user_id_obj);
    
    // 检查用户ID格式
    if (strlen(user_id) != 8) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "用户ID必须是8个字符");
    }
    
    // 请求撤销证书
    int result = request_revoke_cert(user_id);
    
    // 构建响应
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(result));
    
    if (result) {
        json_object_object_add(response_obj, "message", json_object_new_string("证书撤销成功"));
    } else {
        json_object_object_add(response_obj, "message", json_object_new_string("证书撤销失败"));
    }
    
    // 发送响应
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");
    
    // 清理资源
    json_object_put(response_obj);
    json_object_put(request_obj);
    
    free(request_buffer);
    request_buffer = NULL;
    
    return ret;
}

// HTTP请求处理回调函数
enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    // 处理CORS预检请求
    if (strcmp(method, "OPTIONS") == 0) {
        return handle_cors_preflight(connection);
    }
    
    // GET请求处理
    if (strcmp(method, "GET") == 0) {
        if (strcmp(url, "/api/users") == 0) {
            // 先从CA请求最新的用户列表数据
            request_user_list();
            return handle_user_list(connection);
        } else if (strcmp(url, "/api/crl") == 0) {
            return handle_crl_list(connection);
        } else if (strcmp(url, "/api/keypair") == 0) {
            return handle_keypair_with_param(connection);
        } else if (strcmp(url, "/api/users/certificate") == 0) {
            return handle_user_certificate(connection, url);
        }
    }
    
    // POST请求处理
    if (strcmp(method, "POST") == 0) {
        // 首次调用，设置con_cls
        if (*con_cls == NULL) {
            *con_cls = connection;
            return MHD_YES;
        }
        
        if (strcmp(url, "/api/cleanup-expired-certs") == 0) {
            return handle_cleanup_expired_certs(connection);
        } else if (strcmp(url, "/api/local/generate-cert") == 0) {
            return handle_local_cert_operation(connection, url, upload_data, upload_data_size, 1);
        } else if (strcmp(url, "/api/local/update-cert") == 0) {
            return handle_local_cert_operation(connection, url, upload_data, upload_data_size, 0);
        } else if (strcmp(url, "/api/sign-message") == 0) {
            return handle_sign_message(connection, upload_data, upload_data_size);
        } else if (strcmp(url, "/api/verify-signature") == 0) {
            return handle_verify_signature(connection, upload_data, upload_data_size);
        } else if (strcmp(url, "/api/revoke-certificate") == 0) {
            return handle_revoke_certificate(connection, upload_data, upload_data_size);
        }
    }
    
    // 未匹配的请求返回404
    return send_error_response(connection, MHD_HTTP_NOT_FOUND, "404 Not Found");
}

// 与CA通信的线程函数
void* ca_comm_thread_func(void* arg) {
    int retry_count = 0;
    const int max_retries = 5;
    while (1) {
        // 尝试连接CA服务器
        pthread_mutex_lock(&ca_socket_mutex);
        if (ca_socket < 0) {
            printf("正在连接CA服务器...\n");
            ca_socket = connect_to_ca();
            
            if (ca_socket < 0) {
                retry_count++;
                pthread_mutex_unlock(&ca_socket_mutex);
                
                if (retry_count >= max_retries) {
                    printf("连接CA服务器失败，已达到最大重试次数\n");
                    break;
                }
                
                printf("连接CA服务器失败，%d秒后重试...\n", retry_count);
                sleep(retry_count); // 指数退避
                continue;
            }
            printf("已成功连接到CA服务器\n");
            retry_count = 0;
        }
        
        pthread_mutex_unlock(&ca_socket_mutex);
        
        // 定期请求用户列表和CRL列表更新
        request_user_list();
        request_crl_list();
        // 每60秒更新一次
        sleep(60);
    }
    
    return NULL;
}

// 辅助函数

// 十六进制字符串转二进制
int hex_decode(const char *hex_str, unsigned char *bin_data, int max_size) {
    int len = strlen(hex_str);
    int bin_len = len / 2;
    
    if (bin_len > max_size) return -1;
    
    for (int i = 0; i < bin_len; i++) {
        unsigned int value;
        sscanf(hex_str + i * 2, "%02x", &value);
        bin_data[i] = (unsigned char)value;
    }
    
    return bin_len;
}

// 二进制转十六进制字符串
char* hex_encode(const unsigned char *bin_data, int bin_size) {
    char *hex_str = (char*)malloc(bin_size * 2 + 1);
    if (!hex_str) return NULL;
    
    for (int i = 0; i < bin_size; i++) {
        sprintf(hex_str + i * 2, "%02x", bin_data[i]);
    }
    hex_str[bin_size * 2] = '\0';
    
    return hex_str;
}
