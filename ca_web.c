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
#include "include/web_protocol.h"

#define WEB_PORT 8888
#define CA_PORT 8001
#define CA_IP "127.0.0.1"
#define USER_DATA_DIR "server/ca-server/UserData/"
#define USER_CERTS_DIR "server/ca-server/UserCerts/"

typedef struct {
    char id[SUBJECT_ID_SIZE];
    unsigned char cert_hash[CERT_HASH_SIZE];
} UserInfo;

// CRL数据结构
typedef struct {
    unsigned char cert_hash[CERT_HASH_SIZE]; // 证书哈希
    time_t expire_time;      // 证书到期时间
    time_t revoke_time;      // 证书撤销时间
    char revoke_by[SUBJECT_ID_SIZE]; // 撤销人ID
    unsigned char reason;    // 撤销原因代码
} WebCRLEntry; // 前端使用的CRL结构体，包含证书哈希

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
WebCRLEntry* crl_entries = NULL;  // CRL列表数据
int crl_count = 0;                // CRL条目数量
CRLVersion crl_version = {0, 0};  // CRL版本信息
pthread_mutex_t crl_mutex = PTHREAD_MUTEX_INITIALIZER; // CRL数据互斥锁
unsigned char Q_ca[SM2_PUB_MAX_SIZE]; // CA公钥，用于重构用户公钥

// ============ 函数声明部分，按功能分组 ============

// CA通信请求函数 - 使用web_protocol.h中的函数

// HTTP处理函数
int handle_cors_preflight(struct MHD_Connection *connection);
int handle_user_list(struct MHD_Connection *connection);
int handle_crl_list(struct MHD_Connection *connection);
int handle_user_cert(struct MHD_Connection *connection, const char *url);
int handle_cleanup_expired_certs(struct MHD_Connection *connection);
int handle_local_cert_operation(struct MHD_Connection *connection, const char *url, const char *upload_data, size_t *upload_data_size, int is_generate);
int handle_keypair_with_param(struct MHD_Connection *connection);
int handle_sign_message(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
int handle_verify_signature(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
int handle_revoke_cert(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
int handle_cert_version(struct MHD_Connection *connection);
int handle_set_cert_version(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size);
// 工具函数
int hex_decode(const char *hex_str, unsigned char *bin_data, int max_size);
char* hex_encode(const unsigned char *bin_data, int bin_size);
// 响应函数
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
    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, WEB_PORT, NULL, NULL,
                             &request_handler, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "无法启动HTTP服务器\n");
        return 1;
    }
    
    printf("CA Web服务器已启动，监听端口: %d\n", WEB_PORT);
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
    // 先从CA请求最新的用户列表数据
    pthread_mutex_lock(&ca_socket_mutex);
    void *new_users = NULL;
    int new_user_count = 0;
    if (ca_socket >= 0) {
        if (request_user_list(ca_socket, &new_users, &new_user_count)) {
            pthread_mutex_lock(&users_mutex);
            if (users) {
                free(users);
            }
            users = (UserInfo*)new_users;
            user_count = new_user_count;
            pthread_mutex_unlock(&users_mutex);
        }
    }
    pthread_mutex_unlock(&ca_socket_mutex);

    struct json_object *response_obj = json_object_new_array();

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
    pthread_mutex_unlock(&users_mutex);
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理证书撤销列表请求
int handle_crl_list(struct MHD_Connection *connection) {
    // 先从CA请求最新的CRL数据
    pthread_mutex_lock(&ca_socket_mutex);
    void *new_crl_entries = NULL;
    int new_crl_count = 0;
    int new_base_v = 0;
    int new_removed_v = 0;
    
    if (ca_socket >= 0) {
        request_crl_list(ca_socket, &new_crl_entries, &new_crl_count, &new_base_v, &new_removed_v);
        
            pthread_mutex_lock(&crl_mutex);
    // 更新版本信息
    crl_version.base_v = new_base_v;
    crl_version.removed_v = new_removed_v;
    
    // 释放旧数据
    if (crl_entries) {
        free(crl_entries);
        crl_entries = NULL; // 防止释放后使用指针
    }
    
    // 更新CRL数据
    crl_entries = (WebCRLEntry*)new_crl_entries;
    crl_count = new_crl_count;
    
    pthread_mutex_unlock(&crl_mutex);
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
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
        char expire_time_str[32] = {0};
        struct tm *tm_info = localtime(&crl_entries[i].expire_time);
        strftime(expire_time_str, sizeof(expire_time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        json_object_object_add(crl_item, "expireTime", json_object_new_string(expire_time_str));
        
        // 撤销时间
        char revoke_time_str[32] = {0};
        tm_info = localtime(&crl_entries[i].revoke_time);
        strftime(revoke_time_str, sizeof(revoke_time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        json_object_object_add(crl_item, "revokeTime", json_object_new_string(revoke_time_str));
        
        // 撤销人ID
        json_object_object_add(crl_item, "revokeBy", json_object_new_string(crl_entries[i].revoke_by));
        
        // 撤销原因
        const char *reason_str = "";
        switch (crl_entries[i].reason) {
            case 1: reason_str = "证书过期"; break;
            case 2: reason_str = "证书更新"; break;
            case 3: reason_str = "密钥泄露"; break;
            case 4: reason_str = "业务终止"; break;
            case 5: reason_str = "其他"; break;
            default: reason_str = "未知原因";
        }
        json_object_object_add(crl_item, "reason", json_object_new_string(reason_str));
        
        json_object_array_add(crl_array, crl_item);
    }
    
    // 添加CRL数组到响应对象
    json_object_object_add(response_obj, "crlItems", crl_array);

    pthread_mutex_unlock(&crl_mutex);
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理获取单个用户证书请求
int handle_user_cert(struct MHD_Connection *connection, const char *url) {
    // 获取userId参数
    const char *user_id = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "userId");
    if (!user_id || strlen(user_id) != 4) {
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "无效的用户ID");
    }
    
    // 请求证书数据
    unsigned char cert_data[BUFFER_SIZE];
    
    pthread_mutex_lock(&ca_socket_mutex);
    int data_len = 0;
    if (ca_socket >= 0) {
        data_len = request_user_cert(ca_socket, user_id, cert_data, BUFFER_SIZE);
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
    if (data_len <= 0) {
        return send_json_error(connection, MHD_HTTP_NOT_FOUND, "无法获取用户证书");
    }
    
    // 解析证书数据
    ImpCert cert;
    unsigned char cert_hash[32];
    uint8_t is_valid;
    
    // 证书结构体
    memcpy(&cert, cert_data, sizeof(ImpCert));
    
    // 根据证书版本处理不同格式的数据
    int offset = sizeof(ImpCert);
    ImpCertExt extensions;
    
    if (cert.Version == CERT_V2) {
        // V2版本包含扩展信息
        memcpy(&extensions, cert_data + offset, sizeof(ImpCertExt));
        offset += sizeof(ImpCertExt);
    }
    
    // 证书哈希
    memcpy(cert_hash, cert_data + offset, 32);
    offset += 32;
    
    // 有效性标志
    is_valid = cert_data[offset];
    
    // 提取证书有效期
    time_t start_time, end_time;
    memcpy(&start_time, cert.Validity, sizeof(time_t));
    memcpy(&end_time, cert.Validity + sizeof(time_t), sizeof(time_t));
    
    // 转换证书数据为JSON
    struct json_object *response_obj = json_object_new_object();
    
    // 基本信息
    json_object_object_add(response_obj, "version", json_object_new_int(cert.Version));
    json_object_object_add(response_obj, "serialNum", json_object_new_string((const char*)cert.SerialNum));
    char issuer_id[SUBJECT_ID_SIZE] = {0};  // 确保初始化为0
    char subject_id[SUBJECT_ID_SIZE] = {0};  // 确保初始化为0
    memcpy(issuer_id, cert.IssuerID, SUBJECT_ID_LEN);
    memcpy(subject_id, cert.SubjectID, SUBJECT_ID_LEN);
    json_object_object_add(response_obj, "issuerID", json_object_new_string(issuer_id));
    json_object_object_add(response_obj, "subjectID", json_object_new_string(subject_id));
    
    // 转换时间为易读格式
    char start_time_str[32] = {0};
    char end_time_str[32] = {0};
    struct tm *tm_info;
    
    tm_info = localtime(&start_time);
    strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    tm_info = localtime(&end_time);
    strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    json_object_object_add(response_obj, "validFrom", json_object_new_string(start_time_str));
    json_object_object_add(response_obj, "validTo", json_object_new_string(end_time_str));
    
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
    
    // 如果是V2版本证书，添加扩展信息
    if (cert.Version == CERT_V2) {
        struct json_object *ext_obj = json_object_new_object();
        
        // 证书用途
        const char *usage_str = "未知";
        switch (extensions.Usage) {
            case USAGE_GENERAL:
                usage_str = "通用证书";
                break;
            case USAGE_IDENTITY:
                usage_str = "身份认证";
                break;
            default:
                usage_str = "未知用途";
                break;
        }
        json_object_object_add(ext_obj, "usage", json_object_new_string(usage_str));
        
        // 签名算法
        const char *sign_alg_str = "未知";
        switch (extensions.SignAlg) {
            case SIGN_SM2:
                sign_alg_str = "SM2";
                break;
            case SIGN_ECDSA:
                sign_alg_str = "ECDSA";
                break;
            case SIGN_RSA:
                sign_alg_str = "RSA";
                break;
            default:
                sign_alg_str = "未知";
                break;
        }
        json_object_object_add(ext_obj, "signAlg", json_object_new_string(sign_alg_str));
        
        // 哈希算法
        const char *hash_alg_str = "未知";
        switch (extensions.HashAlg) {
            case HASH_SM3:
                hash_alg_str = "SM3";
                break;
            case HASH_SHA256:
                hash_alg_str = "SHA256";
                break;
            case HASH_SHA384:
                hash_alg_str = "SHA384";
                break;
            default:
                hash_alg_str = "未知";
                break;
        }
        json_object_object_add(ext_obj, "hashAlg", json_object_new_string(hash_alg_str));
        
        // 额外信息
        char extra_info[12] = {0};
        memcpy(extra_info, extensions.ExtraInfo, 11);
        json_object_object_add(ext_obj, "extraInfo", json_object_new_string(extra_info));
        
        // 将扩展信息添加到响应中
        json_object_object_add(response_obj, "extensions", ext_obj);
    }
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理清理过期证书请求
int handle_cleanup_expired_certs(struct MHD_Connection *connection) {
    // 请求清理过期证书
    int cleaned_count = -1;
    
    pthread_mutex_lock(&ca_socket_mutex);
    if (ca_socket >= 0) {
        cleaned_count = request_cleanup_expired_certs(ca_socket);
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
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
    if (strlen(user_id) != 4) {
        response_obj = json_object_new_object();
        json_object_object_add(response_obj, "success", json_object_new_boolean(0));
        json_object_object_add(response_obj, "message", json_object_new_string("用户ID必须是4个字符"));
        
        int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, response_obj, "POST, OPTIONS");
        json_object_put(response_obj);
        json_object_put(request_obj);
        
        free(request_buffer);
        request_buffer = NULL;
        
        return ret;
    }
    
    // 执行本地证书操作
    pthread_mutex_lock(&ca_socket_mutex);
    if (ca_socket < 0) {
        ca_socket = connect_to_server(CA_IP, CA_PORT);
    }
    
    if (ca_socket >= 0) {
        if (is_generate) {
            result = request_local_gen_cert(ca_socket, user_id);
        } else {
            result = request_local_upd_cert(ca_socket, user_id);
        }
        
        // 如果请求失败，尝试重新连接
        if (result == 0) {
            close(ca_socket);
            ca_socket = -1;
        }
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
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
    
    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");

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

    json_object_put(response_obj);
    free(priv_hex);
    free(pub_hex);
    
    return ret;
}

// 处理签名消息请求
int handle_sign_message(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;

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

    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }

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

    json_object_put(response_obj);
    json_object_put(request_obj);
    free(pubkey_hex);
    EC_POINT_free(Pu);
    
    free(request_buffer);
    request_buffer = NULL;
    
    return ret;
}

// 处理撤销证书请求
int handle_revoke_cert(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;
    
    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }
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
    if (strlen(user_id) != SUBJECT_ID_LEN) {
        json_object_put(request_obj);
        free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "用户ID必须是4个字符");
    }
    
    // 请求撤销证书
    int result = 0;
    pthread_mutex_lock(&ca_socket_mutex);
    if (ca_socket < 0) {
        ca_socket = connect_to_server(CA_IP, CA_PORT);
    }
    
    if (ca_socket >= 0) {
        result = request_revoke_cert(ca_socket, user_id);
        
        // 如果请求失败，尝试重新连接
        if (result == 0) {
            close(ca_socket);
            ca_socket = -1;
        }
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
    // 构建响应
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(result));
    
    if (result) {
        json_object_object_add(response_obj, "message", json_object_new_string("证书撤销成功"));
    } else {
        json_object_object_add(response_obj, "message", json_object_new_string("证书撤销失败"));
    }

    int ret = send_json_response(connection, MHD_HTTP_OK, response_obj, "POST, OPTIONS");

    json_object_put(response_obj);
    json_object_put(request_obj);
    
    free(request_buffer);
    request_buffer = NULL;
    
    return ret;
}

int handle_cert_version(struct MHD_Connection *connection) {
    unsigned char current_version = CERT_V1; // 默认版本
    int success = 0;

    pthread_mutex_lock(&ca_socket_mutex);
    if (ca_socket < 0) {
        ca_socket = connect_to_server(CA_IP, CA_PORT);
    }
    
    if (ca_socket >= 0) {
        // 调用获取当前证书版本的函数
        int version = request_get_cert_version(ca_socket);
        if (version > 0) {
            current_version = (unsigned char)version;
            success = 1;
        }
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
    // 构建响应
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(success));
    json_object_object_add(response_obj, "version", json_object_new_int(current_version));
    
    int ret = send_json_response(connection, success ? MHD_HTTP_OK : MHD_HTTP_SERVICE_UNAVAILABLE, 
                               response_obj, "GET, OPTIONS");
    json_object_put(response_obj);
    
    return ret;
}

// 处理设置证书版本请求
int handle_set_cert_version(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size) {
    static char *request_buffer = NULL;
    struct json_object *request_obj = NULL;
    struct json_object *version_obj = NULL;
    int success = 0;
    
    // 解析POST数据
    request_obj = parse_post_data(connection, &request_buffer, upload_data, upload_data_size);
    
    // 如果是第一次调用或者没有POST数据，直接返回
    if (request_obj == NULL && request_buffer != NULL) {
        return MHD_YES;
    }
    
    // 没有POST数据或解析失败
    if (request_obj == NULL) {
        if (request_buffer) free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的请求数据");
    }
    
    // 获取要设置的版本
    if (!json_object_object_get_ex(request_obj, "version", &version_obj) ||
        !json_object_is_type(version_obj, json_type_int)) {
        
        json_object_put(request_obj);
        if (request_buffer) free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "缺少必要的版本字段");
    }
    
    int version = json_object_get_int(version_obj);
    
    // 验证版本有效性
    if (version != CERT_V1 && version != CERT_V2) {
        json_object_put(request_obj);
        if (request_buffer) free(request_buffer);
        request_buffer = NULL;
        return send_json_error(connection, MHD_HTTP_BAD_REQUEST, "无效的证书版本");
    }
    
    // 发送版本设置请求到CA
    pthread_mutex_lock(&ca_socket_mutex);
    if (ca_socket < 0) {
        ca_socket = connect_to_server(CA_IP, CA_PORT);
    }
    
    if (ca_socket >= 0) {
        success = request_set_cert_version(ca_socket, (unsigned char)version);
    }
    pthread_mutex_unlock(&ca_socket_mutex);
    
    // 构建响应
    struct json_object *response_obj = json_object_new_object();
    json_object_object_add(response_obj, "success", json_object_new_boolean(success));
    
    if (success) {
        json_object_object_add(response_obj, "message", json_object_new_string("证书版本设置成功"));
    } else {
        json_object_object_add(response_obj, "message", json_object_new_string("证书版本设置失败"));
    }
    
    int ret = send_json_response(connection, success ? MHD_HTTP_OK : MHD_HTTP_SERVICE_UNAVAILABLE, 
                               response_obj, "POST, OPTIONS");
    
    json_object_put(response_obj);
    json_object_put(request_obj);
    
    if (request_buffer) free(request_buffer);
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
            return handle_user_list(connection);
        } else if (strcmp(url, "/api/crl") == 0) {
            return handle_crl_list(connection);
        } else if (strcmp(url, "/api/keypair") == 0) {
            return handle_keypair_with_param(connection);
        } else if (strcmp(url, "/api/users/certificate") == 0) {
            return handle_user_cert(connection, url);
        } else if (strcmp(url, "/api/cert-version") == 0) {
            return handle_cert_version(connection);
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
            return handle_revoke_cert(connection, upload_data, upload_data_size);
        } else if (strcmp(url, "/api/set-cert-version") == 0) {
            return handle_set_cert_version(connection, upload_data, upload_data_size);
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
            ca_socket = connect_to_server(CA_IP, CA_PORT);
            
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
        pthread_mutex_lock(&ca_socket_mutex);
        if (ca_socket >= 0) {
            void *new_users = NULL;
            int new_user_count = 0;
            if (request_user_list(ca_socket, &new_users, &new_user_count)) {
                pthread_mutex_lock(&users_mutex);
                if (users) {
                    free(users);
                    users = NULL; // 防止释放后使用指针
                }
                users = (UserInfo*)new_users;
                user_count = new_user_count;
                pthread_mutex_unlock(&users_mutex);
            }
            
            void *new_crl_entries = NULL;
            int new_crl_count = 0;
            int new_base_v = 0;
            int new_removed_v = 0;
            if (request_crl_list(ca_socket, &new_crl_entries, &new_crl_count, &new_base_v, &new_removed_v)) {
                pthread_mutex_lock(&crl_mutex);
                crl_version.base_v = new_base_v;
                crl_version.removed_v = new_removed_v;
                if (crl_entries) {
                    free(crl_entries);
                }
                crl_entries = (WebCRLEntry*)new_crl_entries;
                crl_count = new_crl_count;
                pthread_mutex_unlock(&crl_mutex);
            }
        }
        pthread_mutex_unlock(&ca_socket_mutex);
        
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
