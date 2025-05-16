#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <microhttpd.h>
#include <signal.h>
#include <errno.h>
#include "common.h"
#include "gm_crypto.h"
#include "imp_cert.h"
#include "hashmap.h"
#include "crlmanager.h"
#include "web_protocol.h"

#define CRL_FILE "CRL.dat"               // 撤销列表文件
#define USERDATA_DIR "UserData"          // 本地模式下存储用户数据的目录
#define USERCERTS_DIR "UserCerts"        // 存储用户证书的目录
#define USERLIST_FILE "UserList.dat"     // 用户列表文件
#define SERIAL_NUM_FILE "SerialNum.txt"  // 序列号持久化文件
#define CRL_MANAGER_FILE "CRLManager.dat" // CRL管理器文件

// HTTP服务器相关定义
#define HTTP_PORT 8080                   // HTTP服务器端口
#define UPLOAD_DATA_SIZE 8192            // 上传数据缓冲区大小

struct MHD_Daemon *http_daemon = NULL;   // HTTP服务器实例
// HTTP连接信息结构体
struct connection_info_struct {
    int status;
    unsigned char *upload_data;
    unsigned long upload_data_size;
};

// Web通信相关定义
#define WEB_PORT 8001   // 与ca_web通信的端口
pthread_t web_server_thread;       // Web服务器监听线程
volatile int web_server_running = 0; // Web服务器运行状态标志
pthread_mutex_t user_map_mutex = PTHREAD_MUTEX_INITIALIZER; // 用户表互斥锁

//ca核心数据
unsigned char d_ca[SM2_PRI_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];

hashmap* user_map = NULL;           // 存储用户ID和证书哈希
hashmap* crl_map = NULL;            // 存储被撤销的证书哈希和其到期时间
CRLManager* crl_manager = NULL;     // CA端的CRL管理器
unsigned int current_serial_num = 1;  // 当前证书序列号，默认从1开始


// 信号处理函数
void signal_handler(int sig) {
    printf("\n接收到信号 %d，准备关闭服务器\n", sig);
    web_server_running = 0;  // 设置为0通知Web线程退出循环
}

// Web服务器通信(与ca_web)
void* web_server_thread_func(void* arg); // Web-socket服务器监听线程函数
void handle_web_client(int client_socket); // 处理Web客户端请求

// HTTP服务器相关函数
int start_http_server();
void stop_http_server();
enum MHD_Result http_request_handler(void *cls, struct MHD_Connection *connection,
                         const char *url, const char *method,
                         const char *version, const char *upload_data,
                         unsigned long *upload_data_size, void **con_cls);

enum MHD_Result send_http_error_response(struct MHD_Connection *connection,
                                         unsigned int status_code,
                                         const char *error_msg);
enum MHD_Result send_http_success_response(struct MHD_Connection *connection,
                                          unsigned char *data,
                                          int data_len);


// 处理HTTP请求
enum MHD_Result handle_http_register(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);
enum MHD_Result handle_http_update(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);
enum MHD_Result handle_http_revoke(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);
enum MHD_Result handle_http_message(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);
enum MHD_Result handle_http_cert_status(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);
enum MHD_Result handle_http_crl_update(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);

// CA本地功能
int local_generate_cert(const char *subject_id);
int local_update_cert(const char *subject_id);
int cleanup_expired_certificates();

// Web前端通信处理
void handle_web_get_users(int client_socket);
void handle_web_get_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_get_crl(int client_socket);
void handle_web_cleanup_certs(int client_socket);
void handle_web_local_gen_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_local_upd_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_revoke_cert(int client_socket, const unsigned char *buffer, int data_len);

// 用户数据管理
int check_user_exists(const char *subject_id);
int save_user_list(const char *subject_id, const unsigned char *cert_hash);
int update_user_list(const char *subject_id, const unsigned char *new_cert_hash);
int delete_user_from_list(const char *subject_id);

// CRL管理
int check_cert_in_crl(const unsigned char *cert_hash);
int add_cert_to_crl(const unsigned char *cert_hash, time_t expire_time);
int add_cert_to_crlmanager(const unsigned char *cert_hash);
int cleanup_expired_certificates();

// 序列号管理
int load_serial_num();
int save_serial_num();
char* generate_serial_num();

// 运行和调试
void run_online_mode();
int ensure_directory_exists(const char *dir_path);

int main() {
    if(!CA_init(Q_ca, d_ca)){
        printf("CA初始化失败！\n");
        return -1;
    }
    
    if (!ensure_directory_exists(USERDATA_DIR) || 
        !ensure_directory_exists(USERCERTS_DIR)) {
        printf("无法确保必要目录存在！\n");
        return -1;
    }
    
    current_serial_num = load_serial_num();
    user_map = ul_hashmap_load(USERLIST_FILE);
    crl_map = crl_hashmap_load(CRL_FILE);
    crl_manager = CRLManager_load_from_file(CRL_MANAGER_FILE);
    
    if(user_map == NULL || crl_map == NULL || crl_manager == NULL){
        printf("初始化失败！\n");
        sm2_params_cleanup();
        hashmap_destroy(user_map);
        hashmap_destroy(crl_map);
        CRLManager_free(crl_manager);
        return -1;
    }

    run_online_mode();
    
    hashmap_destroy(user_map);
    hashmap_destroy(crl_map);
    if (crl_manager) {
        CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE);
        CRLManager_free(crl_manager);
    }
    sm2_params_cleanup();
    printf("OK！\n");
    
    return 0;
}

// ---- 证书处理相关函数 ----

int local_generate_cert(const char *subject_id) { 
    BIGNUM *Ku = NULL;
    BIGNUM *k = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    char* serial_num = NULL;
    int ret = 0;

    if (check_user_exists(subject_id)) {
        printf("用户ID '%s' 已存在，拒绝注册\n", subject_id);
        return 0;
    }
    
    //--------step1:用户端(现在由CA模拟)-----------
    Ku = BN_new();
    BN_rand_range(Ku, order);

    Ru = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        goto cleanup;
    }
    
    // --------step2:CA端生成隐式证书计算部分重构值-----------
    k = BN_new();
    BN_rand_range(k, order);

    Pu = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Pu, k, NULL, NULL, NULL) ||
        !EC_POINT_add(group, Pu, Ru, Pu, NULL)) {
        printf("计算Pu失败\n");
        goto cleanup;
    }

    serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", serial_num);
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
        goto cleanup;
    }
    
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    if (!save_cert(&cert, cert_filename)) {
        printf("警告：无法保存用户证书到文件\n");
    }
    
    unsigned char cert_hash[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), cert_hash);
    print_hex("隐式证书哈希值e", cert_hash, 32);

    if (!save_user_list(subject_id, cert_hash)) {
        printf("保存用户数据失败！\n");
        goto cleanup;
    }
    
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, cert_hash, k, d_ca, order);
    
    //--------step3:用户端生成最终的公私钥对(现在由CA模拟)-------------
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, cert_hash, Ku, r, order);
    
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, cert_hash, Pu, Q_ca);

    if(!verify_key_pair_bytes(group, Qu, d_u)){
        printf("密钥对验证失败！\n");
        goto cleanup;
    }

    char priv_key_filename[100] = {0};
    sprintf(priv_key_filename, "%s/%s_priv.key", USERDATA_DIR, subject_id);
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存用户私钥到文件\n");
    }
    
    char pub_key_filename[100] = {0};
    sprintf(pub_key_filename, "%s/%s_pub.key", USERDATA_DIR, subject_id);
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存用户公钥到文件\n");
    }
    printf("用户 '%s' 本地证书注册成功\n", subject_id);
    printf("--------------------------------\n");
    ret = 1;
    
cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    if (k) BN_free(k);
    if (Ku) BN_free(Ku);
    
    return ret;
}

int local_update_cert(const char *subject_id) {
    BIGNUM *Ku = NULL;
    BIGNUM *k = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *new_Pu = NULL;
    int ret = 0;
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，拒绝更新\n", subject_id);
        return 0;
    }
    
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    ImpCert old_cert;
    if (!load_cert(&old_cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        return 0;
    }
    
    if (!validate_cert(&old_cert)) {
        printf("用户证书已过期，请重新注册\n");
        return 0;
    }
    
    unsigned char *old_cert_hash = hashmap_get(user_map, subject_id);
    if (!old_cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        return 0;
    }
    
    if (check_cert_in_crl(old_cert_hash)) {
        printf("用户证书已被撤销，请重新注册\n");
        return 0;
    }
    
    //--------step1:用户端(现在由CA模拟)-----------
    Ku = BN_new();
    BN_rand_range(Ku, order);

    Ru = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        goto cleanup;
    }
    
    // --------步骤与证书注册类似:CA端生成新隐式证书-----------
    k = BN_new();
    BN_rand_range(k, order);

    new_Pu = EC_POINT_new(group);
    if (!EC_POINT_mul(group, new_Pu, k, NULL, NULL, NULL) ||
        !EC_POINT_add(group, new_Pu, Ru, new_Pu, NULL)) {
        printf("计算new_Pu失败\n");
        goto cleanup;
    }

    char* serial_num = generate_serial_num();
    printf("生成更新证书，序列号: %s\n", serial_num);
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
        goto cleanup;
    }

    unsigned char new_cert_hash[32];
    sm3_hash((const unsigned char *)&new_cert, sizeof(ImpCert), new_cert_hash);
    print_hex("新隐式证书哈希值e", new_cert_hash, 32);

    time_t old_expire_time;
    memcpy(&old_expire_time, old_cert.Validity + sizeof(time_t), sizeof(time_t));

    if (!add_cert_to_crl(old_cert_hash, old_expire_time)) {
        printf("警告：无法将旧证书添加到撤销列表\n");
    }
    
    if (!add_cert_to_crlmanager(old_cert_hash)) {
        printf("警告：无法将旧证书添加到CRL管理器\n");
    }
    
    if (!update_user_list(subject_id, new_cert_hash)) {
        printf("更新用户数据失败！\n");
        goto cleanup;
    }

    if (save_cert(&new_cert, cert_filename)) {
        printf("新用户证书已保存为 %s\n", cert_filename);
    } else {
        printf("警告：无法保存新用户证书到文件\n");
    }

    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, new_cert_hash, k, d_ca, order);
    
    //--------step3:用户端生成最终的公私钥对(现在由CA模拟)-------------
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, new_cert_hash, Ku, r, order);
    
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, new_cert_hash, new_Pu, Q_ca);
    
    if(!verify_key_pair_bytes(group, Qu, d_u)){
        printf("新密钥对验证失败！\n");
        goto cleanup;
    }
    
    printf("新密钥对验证成功！\n");
    
    char priv_key_filename[100] = {0};
    sprintf(priv_key_filename, "%s/%s_priv.key", USERDATA_DIR, subject_id);
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存更新后的用户私钥到文件\n");
    }
    
    char pub_key_filename[100] = {0};
    sprintf(pub_key_filename, "%s/%s_pub.key", USERDATA_DIR, subject_id);
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存更新后的用户公钥到文件\n");
    }
    
    printf("--------------------------------\n");
    ret = 1;
    
cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (new_Pu) EC_POINT_free(new_Pu);
    if (k) BN_free(k);
    if (Ku) BN_free(Ku);
    return ret;
}

// ---- 用户数据管理相关函数 ----
int check_user_exists(const char *subject_id) {
    return hashmap_exists(user_map, subject_id) ? 1 : 0;
}

int save_user_list(const char *subject_id, const unsigned char *cert_hash) {
    return hashmap_put(user_map, strdup(subject_id), (void*)cert_hash, CERT_HASH_SIZE) ? 1 : 0;
}

int update_user_list(const char *subject_id, const unsigned char *new_cert_hash) {
    return hashmap_put(user_map, strdup(subject_id), (void*)new_cert_hash, CERT_HASH_SIZE) ? 1 : 0;
}

int delete_user_from_list(const char *subject_id) {
    if (!hashmap_remove(user_map, subject_id)) {
        printf("用户 '%s' 不存在于哈希表中\n", subject_id);
        return 0;  // 删除失败
    }
    
    return ul_hashmap_save(user_map, USERLIST_FILE);
}

// ---- CRL管理相关函数 ----
int check_cert_in_crl(const unsigned char *cert_hash) {
    return hashmap_exists(crl_map, cert_hash) ? 1 : 0;
}

int add_cert_to_crl(const unsigned char *cert_hash, time_t expire_time) {
    unsigned char* cert_hash_copy = malloc(CERT_HASH_SIZE);
    if (!cert_hash_copy) return 0;
    
    memcpy(cert_hash_copy, cert_hash, CERT_HASH_SIZE);
    
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

void run_online_mode() {
    int web_server_fd;
    
    // 设置信号处理器
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    // Web服务器初始化
    web_server_fd = setup_server(WEB_PORT);
    if (web_server_fd < 0) {
        return;
    }
    
    // 启动Web服务器监听线程
    web_server_running = 1;
    if (pthread_create(&web_server_thread, NULL, web_server_thread_func, &web_server_fd) != 0) {
        perror("创建Web服务器线程失败");
        close(web_server_fd);
        return;
    }
    
    // 启动HTTP服务器
    if (!start_http_server()) {
        perror("启动HTTP服务器失败");
        web_server_running = 0;
        pthread_join(web_server_thread, NULL);
        close(web_server_fd);
        return;
    }
    
    printf("CA服务器已成功启动\n");
    printf("Web通信端口: %d, HTTP端口: %d\n", WEB_PORT, HTTP_PORT);
    printf("按Ctrl+C可安全关闭服务器\n");
    
    pthread_join(web_server_thread, NULL);

    stop_http_server();
    
    close(web_server_fd);
    printf("CA服务器已安全关闭\n");
}

int add_cert_to_crlmanager(const unsigned char *cert_hash) {
    if (!crl_manager || !cert_hash) {
        return 0;
    }
    
    return CRLManager_add_node(crl_manager, cert_hash);
}

// Web服务器监听线程函数
void* web_server_thread_func(void* arg) {
    int server_fd = *((int*)arg);
    int client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    fd_set readfds;
    struct timeval tv;
    int activity;
    
    while(web_server_running) {
        // 使用select进行非阻塞监听，便于检测终止标志
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        
        // 设置超时为1秒
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        activity = select(server_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0 && errno != EINTR) {
            perror("选择错误");
            continue;
        }
        
        // 检查终止标志
        if (!web_server_running) {
            break;
        }
        
        // 没有活动，继续等待
        if (activity == 0) {
            continue;
        }
        
        // 输入就绪，接受连接
        if (FD_ISSET(server_fd, &readfds)) {
            client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            if (client_socket < 0) {
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    perror("接受Web连接失败");
                }
                continue;
            }
            
            handle_web_client(client_socket);
        }
    }
    
    printf("Web监听线程已退出\n");
    return NULL;
}

// 处理来自ca_web的客户端请求
void handle_web_client(int client_socket) {
    unsigned char buffer[BUFFER_SIZE] = {0};
    uint8_t cmd;
    int data_len;
    
    while(web_server_running) {
        data_len = recv_message(client_socket, &cmd, buffer, BUFFER_SIZE);
        if (data_len < 0) {
            printf("接收ca_web消息失败，连接可能已断开\n");
            close(client_socket);
            return;
        }
        
        // 处理命令
        switch (cmd) {
            case WEB_CMD_GET_USERS:
                handle_web_get_users(client_socket);
                break;
                
            case WEB_CMD_GET_CERT:
                handle_web_get_cert(client_socket, buffer, data_len);
                break;
                
            case WEB_CMD_GET_CRL:
                handle_web_get_crl(client_socket);
                break;
                
            case WEB_CMD_CLEANUP_CERTS:
                handle_web_cleanup_certs(client_socket);
                break;
                
            case WEB_CMD_LOCAL_GEN_CERT:
                handle_web_local_gen_cert(client_socket, buffer, data_len);
                break;
                
            case WEB_CMD_LOCAL_UPD_CERT:
                handle_web_local_upd_cert(client_socket, buffer, data_len);
                break;
                
            case WEB_CMD_REVOKE_CERT:
                handle_web_revoke_cert(client_socket, buffer, data_len);
                break;
                
            default:
                printf("收到未知Web命令: 0x%02X\n", cmd);
                break;
        }
    }
}

// 处理获取用户列表的请求
void handle_web_get_users(int client_socket) {
    int user_count = 0;
    unsigned char *response_data = NULL;
    int response_len = 0;
    int offset = 0;
    
    pthread_mutex_lock(&user_map_mutex);
    
    // 计算用户数量
    user_count = user_map->count;
    
    // 准备响应数据：用户数量(4字节) + 多个(用户ID(9字节) + 证书哈希(32字节))
    response_len = sizeof(int) + user_count * (SUBJECT_ID_SIZE + CERT_HASH_SIZE);
    response_data = (unsigned char *)malloc(response_len);
    
    if (!response_data) {
        pthread_mutex_unlock(&user_map_mutex);
        printf("内存分配失败\n");
        return;
    }
    
    // 写入用户数量
    memcpy(response_data, &user_count, sizeof(int));
    offset = sizeof(int);
    
    // 遍历哈希表，将所有用户ID和证书哈希写入响应
    for (int i = 0; i < user_map->size; i++) {
        hashmap_entry* entry = user_map->entries[i];
        while (entry) {
            // 写入用户ID
            memcpy(response_data + offset, entry->key, SUBJECT_ID_SIZE);
            offset += SUBJECT_ID_SIZE;
            
            // 写入证书哈希
            memcpy(response_data + offset, entry->value, CERT_HASH_SIZE);
            offset += CERT_HASH_SIZE;
            
            entry = entry->next;
        }
    }
    
    pthread_mutex_unlock(&user_map_mutex);
    

    if (!send_message(client_socket, WEB_CMD_USER_LIST, response_data, response_len)) {
        printf("发送用户列表失败\n");
    }
    
    free(response_data);
}

// 处理获取单个用户证书的请求
void handle_web_get_cert(int client_socket, const unsigned char *buffer, int data_len) {
    if (data_len < SUBJECT_ID_SIZE) {
        printf("接收到的数据长度错误，无法识别用户ID\n");
        send_message(client_socket, WEB_CMD_CERT_DATA, NULL, 0);
        return;
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, buffer, SUBJECT_ID_SIZE - 1); // 确保null结尾
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在\n", subject_id);
        send_message(client_socket, WEB_CMD_CERT_DATA, NULL, 0);
        return;
    }
    
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    ImpCert cert;
    if (!load_cert(&cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        // 发送空数据表示错误
        send_message(client_socket, WEB_CMD_CERT_DATA, NULL, 0);
        return;
    }
    
    // 提取证书哈希
    unsigned char cert_hash[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), cert_hash);
    
    int cert_revoked = check_cert_in_crl(cert_hash);
    int cert_valid = validate_cert(&cert) && !cert_revoked;
    
    time_t start_time, end_time;
    memcpy(&start_time, cert.Validity, sizeof(time_t));
    memcpy(&end_time, cert.Validity + sizeof(time_t), sizeof(time_t));
    
    // 组装响应数据
    // 格式：证书结构体 + 哈希值(32字节) + 有效性标志(1字节) + 撤销标志(1字节)
    unsigned char response[sizeof(ImpCert) + 32 + 1 + 1];
    
    // 复制证书数据
    memcpy(response, &cert, sizeof(ImpCert));
    
    // 添加证书哈希
    memcpy(response + sizeof(ImpCert), cert_hash, 32);
    
    // 添加有效性标志
    response[sizeof(ImpCert) + 32] = cert_valid ? 1 : 0;
    
    // 添加撤销标志
    response[sizeof(ImpCert) + 32 + 1] = cert_revoked ? 1 : 0;

    if (!send_message(client_socket, WEB_CMD_CERT_DATA, response, sizeof(response))) {
        printf("发送证书数据失败\n");
    }
}

// 处理获取CRL列表的请求
void handle_web_get_crl(int client_socket) {
    int crl_count = 0;
    unsigned char *response_data = NULL;
    int response_len = 0;
    int offset = 0;
    
    pthread_mutex_lock(&user_map_mutex);  // 复用user_map_mutex锁
    
    // 计算CRL条目数量
    crl_count = crl_map->count;
    
    // 准备响应数据：基础版本号(4字节) + 删除版本号(4字节) + CRL条目数量(4字节) + 多个(证书哈希(32字节) + 到期时间(8字节))
    response_len = sizeof(int) * 3 + crl_count * (CERT_HASH_SIZE + sizeof(time_t));
    response_data = (unsigned char *)malloc(response_len);
    
    if (!response_data) {
        pthread_mutex_unlock(&user_map_mutex);
        printf("内存分配失败\n");
        return;
    }
    
    // 写入基础版本号
    memcpy(response_data, &crl_manager->base_v, sizeof(int));
    offset += sizeof(int);
    
    // 写入删除版本号
    memcpy(response_data + offset, &crl_manager->removed_v, sizeof(int));
    offset += sizeof(int);
    
    // 写入CRL条目数量
    memcpy(response_data + offset, &crl_count, sizeof(int));
    offset += sizeof(int);
    
    // 遍历哈希表，将所有证书哈希和到期时间写入响应
    for (int i = 0; i < crl_map->size; i++) {
        hashmap_entry* entry = crl_map->entries[i];
        while (entry) {
            // 写入证书哈希
            memcpy(response_data + offset, entry->key, CERT_HASH_SIZE);
            offset += CERT_HASH_SIZE;
            
            // 写入到期时间
            time_t expire_time = *(time_t*)entry->value;
            memcpy(response_data + offset, &expire_time, sizeof(time_t));
            offset += sizeof(time_t);
            
            entry = entry->next;
        }
    }

    pthread_mutex_unlock(&user_map_mutex);
    
    // 发送响应
    if (!send_message(client_socket, WEB_CMD_CRL_DATA, response_data, response_len)) {
        printf("发送CRL列表失败\n");
    }
    
    free(response_data);
}

// 处理从ca_web收到的清理过期证书请求
void handle_web_cleanup_certs(int client_socket) {
    printf("收到清理过期证书请求\n");
    int cleaned_count = cleanup_expired_certificates();
    
    unsigned char response[sizeof(int)];
    memcpy(response, &cleaned_count, sizeof(int));
    
    if (!send_message(client_socket, WEB_CMD_CLEANUP_RESULT, response, sizeof(int))) {
        printf("发送清理结果失败\n");
    }
}

// 处理从ca_web收到的本地证书生成请求
void handle_web_local_gen_cert(int client_socket, const unsigned char *buffer, int data_len) {
    if (data_len < SUBJECT_ID_SIZE) {
        printf("接收到的数据长度错误，无法识别用户ID\n");
        // 发送失败结果
        unsigned char response = 0; // 0表示失败
        send_message(client_socket, WEB_CMD_LOCAL_RESULT, &response, 1);
        return;
    }
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, buffer, SUBJECT_ID_SIZE - 1); // 确保null结尾
    // 锁定用户哈希表
    pthread_mutex_lock(&user_map_mutex);
    
    // 调用本地证书生成函数
    int result = local_generate_cert(subject_id);
    
    // 保存信息
    if(!ul_hashmap_save(user_map, USERLIST_FILE)){
        printf("保存用户列表失败！\n");
    }
    if(!crl_hashmap_save(crl_map, CRL_FILE)){
        printf("保存CRL列表失败！\n");
    }
    if(!save_serial_num()){
        printf("保存序列号失败！\n");
    }
    if(!CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE)){
        printf("保存CRL管理器失败！\n");
    }
    
    // 解锁用户哈希表
    pthread_mutex_unlock(&user_map_mutex);
    
    // 发送结果
    unsigned char response = result ? 1 : 0; // 1表示成功，0表示失败
    send_message(client_socket, WEB_CMD_LOCAL_RESULT, &response, 1);
}

// 处理从ca_web收到的本地证书更新请求
void handle_web_local_upd_cert(int client_socket, const unsigned char *buffer, int data_len) {
    if (data_len < SUBJECT_ID_SIZE) {
        printf("接收到的数据长度错误，无法识别用户ID\n");
        // 发送失败结果
        unsigned char response = 0; // 0表示失败
        send_message(client_socket, WEB_CMD_LOCAL_RESULT, &response, 1);
        return;
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, buffer, SUBJECT_ID_SIZE - 1); // 确保null结尾
    
    printf("收到web请求，为用户 '%s' 本地更新证书\n", subject_id);
    
    pthread_mutex_lock(&user_map_mutex);
    
    // 调用本地证书更新函数
    int result = local_update_cert(subject_id);
    
    // 保存信息
    if(!ul_hashmap_save(user_map, USERLIST_FILE)){
        printf("保存用户列表失败！\n");
    }
    if(!crl_hashmap_save(crl_map, CRL_FILE)){
        printf("保存CRL列表失败！\n");
    }
    if(!save_serial_num()){
        printf("保存序列号失败！\n");
    }
    if(!CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE)){
        printf("保存CRL管理器失败！\n");
    }
    
    pthread_mutex_unlock(&user_map_mutex);
    
    unsigned char response = result ? 1 : 0; // 1表示成功，0表示失败
    send_message(client_socket, WEB_CMD_LOCAL_RESULT, &response, 1);
}

void handle_web_revoke_cert(int client_socket, const unsigned char *buffer, int data_len) {
    unsigned char response = 0; // 默认为失败
    char subject_id[SUBJECT_ID_SIZE] = {0};
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    unsigned char *cert_hash = NULL;
    ImpCert cert;
    
    if (data_len < SUBJECT_ID_SIZE) {
        printf("接收到的数据长度错误，无法识别用户ID\n");
        goto fail;
    }
    
    memcpy(subject_id, buffer, SUBJECT_ID_SIZE - 1);
    printf("收到web请求，撤销用户 '%s' 的证书\n", subject_id);
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，无法撤销\n", subject_id);
        goto fail;
    }
    
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    cert_hash = hashmap_get(user_map, subject_id);
    
    if (!cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        goto fail;
    }
    
    if (!load_cert(&cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        goto fail;
    }
    
    time_t expire_time;
    memcpy(&expire_time, cert.Validity + sizeof(time_t), sizeof(time_t));
    
    if (!add_cert_to_crl(cert_hash, expire_time)) {
        printf("警告：无法将证书添加到撤销列表\n");
    }
    
    if (!add_cert_to_crlmanager(cert_hash)) {
        printf("警告：无法将证书添加到CRL管理器\n");
    }
    
    if (!delete_user_from_list(subject_id)) {
        printf("警告：更新用户列表文件失败，但用户已从内存中移除\n");
    }
    
    if (remove(cert_filename) == 0) {
        printf("已删除用户证书文件: %s\n", cert_filename);
    } else {
        printf("警告：无法删除用户证书文件: %s\n", cert_filename);
    }
    
    printf("用户 '%s' 的证书已成功撤销\n", subject_id);
    printf("--------------------------------\n");
    
    response = 1;

fail:
    send_message(client_socket, WEB_CMD_REVOKE_RESULT, &response, 1);
}

// 清理过期证书函数实现
int cleanup_expired_certificates() {
    time_t current_time = time(NULL);
    int cleaned_count = 0;
    int i;
    pthread_mutex_lock(&user_map_mutex);  // 复用user_map_mutex锁
    
    // 遍历CRL管理器中的节点并清理过期的证书
    for (i = 0; i < crl_manager->base_v; i++) {
        if (crl_manager->nodes[i].is_valid && crl_manager->nodes[i].hash) {
            time_t *expire_time = (time_t *)hashmap_get(crl_map, crl_manager->nodes[i].hash);
            if (expire_time && *expire_time < current_time) {
                hashmap_remove(crl_map, crl_manager->nodes[i].hash);
                CRLManager_remove_node(crl_manager, i);
                cleaned_count++;
            }
        }
    }
    pthread_mutex_unlock(&user_map_mutex);
    if (!crl_hashmap_save(crl_map, CRL_FILE)) {
        printf("保存CRL列表失败！\n");
    }
    if (!CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE)) {
        printf("保存CRL管理器失败！\n");
    }
    
    return cleaned_count;
}

int ensure_directory_exists(const char *dir_path) {
    struct stat st = {0};
    if (stat(dir_path, &st) == -1) {
        if (mkdir(dir_path, 0755) == -1) {
            printf("无法创建目录: %s\n", dir_path);
            return 0;
        }
        printf("已创建目录: %s\n", dir_path);
    }
    return 1;
}

// HTTP请求处理函数
enum MHD_Result http_request_handler(void *cls, struct MHD_Connection *connection,
                         const char *url, const char *method,
                         const char *version, const char *upload_data,
                         unsigned long *upload_data_size, void **con_cls) {
    
    if (*con_cls == NULL) {
        // 第一次调用 - 分配连接信息结构
        struct connection_info_struct *con_info = malloc(sizeof(struct connection_info_struct));
        if (con_info == NULL) return MHD_NO;
        
        con_info->status = 0;
        con_info->upload_data = NULL;
        con_info->upload_data_size = 0;
        
        *con_cls = con_info;
        return MHD_YES;
    }
    
    if (strcmp(method, "POST") != 0) {
        // 只处理POST请求
        return MHD_NO;
    }
    
    struct connection_info_struct *con_info = *con_cls;
    
    if (*upload_data_size != 0) {
        // 还有数据要接收
        if (con_info->upload_data == NULL) {
            // 第一次接收数据
            con_info->upload_data = malloc(UPLOAD_DATA_SIZE);
            if (con_info->upload_data == NULL) return MHD_NO;
            con_info->upload_data_size = 0;
        }
        
        // 确保缓冲区足够大
        if (con_info->upload_data_size + *upload_data_size > UPLOAD_DATA_SIZE) {
            return MHD_NO; // 数据太大
        }
        
        // 复制这批数据
        memcpy(con_info->upload_data + con_info->upload_data_size, 
               upload_data, *upload_data_size);
        con_info->upload_data_size += *upload_data_size;
        
        *upload_data_size = 0; // 表示已处理此批数据
        return MHD_YES;
    }
    
    // 请求处理完毕，根据URL路径分发给不同的处理函数
    enum MHD_Result ret;
    pthread_mutex_lock(&user_map_mutex);
    
    if (strcmp(url, "/register") == 0) {
        ret = handle_http_register(connection, con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/update") == 0) {
        ret = handle_http_update(connection, con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/revoke") == 0) {
        ret = handle_http_revoke(connection, con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/message") == 0) {
        ret = handle_http_message(connection, con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/cert_status") == 0) {
        ret = handle_http_cert_status(connection, con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/crl_update") == 0) {
        ret = handle_http_crl_update(connection, con_info->upload_data, con_info->upload_data_size);
    } else {
        // 不支持的路径
        ret = send_http_error_response(connection, MHD_HTTP_NOT_FOUND, "Unsupported URL");
    }
    
    // 保存信息
    ul_hashmap_save(user_map, USERLIST_FILE);
    crl_hashmap_save(crl_map, CRL_FILE);
    save_serial_num();
    CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE);
    
    pthread_mutex_unlock(&user_map_mutex);
    
    if (con_info->upload_data) free(con_info->upload_data);
    free(con_info);
    *con_cls = NULL;
    
    return ret;
}

// 处理注册请求
enum MHD_Result handle_http_register(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    if (!upload_data || upload_data_size < SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE) {
        printf("接收到的数据长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Registration failed: Invalid data length");
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0}; // 确保null结尾
    memcpy(subject_id, upload_data, SUBJECT_ID_LEN);

    if (strlen(subject_id) != 8) {
        printf("用户ID长度错误，必须为8个字符\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Registration failed: Invalid user ID length");
    }
    
    EC_POINT *Ru = NULL;
    BIGNUM *k = NULL;
    EC_POINT *Pu = NULL;
    char* serial_num = NULL;
    unsigned char *response_data = NULL;
    int response_len = 0;
    enum MHD_Result ret = MHD_NO;
    
    Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_oct2point(group, Ru, (const unsigned char *)upload_data + SUBJECT_ID_LEN, 
                                   upload_data_size - SUBJECT_ID_LEN, NULL)) {
        printf("解析临时公钥失败\n");
        goto cleanup;
    }
    
    printf("%s---证书注册(HTTP)\n", subject_id);
    
    // 检查用户是否存在
    if (check_user_exists(subject_id)) {
        printf("用户ID '%s' 已存在，拒绝注册\n", subject_id);
        goto cleanup;
    }
    
    // --------step2:CA端生成隐式证书计算部分重构值-----------

    // CA选取随机值k
    k = BN_new();
    BN_rand_range(k, order);

    // 计算公钥重构值Pu=Ru+k*G
    Pu = EC_POINT_new(group);
    if (!Pu) {
        printf("无法分配内存给Pu\n");
        goto cleanup;
    }
    
    if (!EC_POINT_mul(group, Pu, k, NULL, NULL, NULL) ||
        !EC_POINT_add(group, Pu, Ru, Pu, NULL)) {
        printf("计算Pu失败\n");
        goto cleanup;
    }

    // 生成新的证书序列号
    serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", serial_num);

    // 生成隐式证书
    ImpCert cert;
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60;
    if(!set_cert(&cert, 
              (unsigned char *)serial_num,
              (unsigned char *)"CA000001", 
              (unsigned char *)subject_id,  // 使用用户提供的ID
              current_time,
              expire_time,
              Pu)){
        printf("证书设置失败！\n");
        goto cleanup;
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
        goto cleanup;
    }
    
    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, cert_hash, k, d_ca, order);
    print_hex("部分私钥r", r, SM2_PRI_MAX_SIZE);
    
    // 准备响应数据：证书+部分私钥r
    response_len = sizeof(ImpCert) + SM2_PRI_MAX_SIZE;
    response_data = (unsigned char*)malloc(response_len);
    if (!response_data) {
        printf("内存分配失败\n");
        goto cleanup;
    }
    
    memcpy(response_data, &cert, sizeof(ImpCert));
    memcpy(response_data + sizeof(ImpCert), r, SM2_PRI_MAX_SIZE);
    
    printf("用户 '%s' 成功注册并保存到UserList\n", subject_id);
    printf("--------------------------------\n");

    // 发送HTTP成功响应
    ret = send_http_success_response(connection, response_data, response_len);
    response_data = NULL; // 防止二次释放

cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (k) BN_free(k);
    if (Pu) EC_POINT_free(Pu);
    
    if (response_data) {
        free(response_data);
    }
    
    if (ret == MHD_NO) {
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Registration failed");
    }
    
    return ret;
}

// 处理更新请求
enum MHD_Result handle_http_update(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    if (!upload_data || upload_data_size < SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 64) {
        printf("接收到的数据长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Update failed: Invalid data length");
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, upload_data, SUBJECT_ID_LEN);
    if (strlen(subject_id) != 8) {
        printf("用户ID长度错误，必须为8个字符\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Update failed: Invalid user ID length");
    }
    
    printf("%s---证书更新(HTTP)\n", subject_id);
    
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    EC_POINT *new_Pu = NULL;
    BIGNUM *k = NULL;
    unsigned char *response_data = NULL;
    int response_len = 0;
    enum MHD_Result ret = MHD_NO;
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，拒绝更新\n", subject_id);
        goto cleanup;
    }
    
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    ImpCert old_cert;
    if (!load_cert(&old_cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        goto cleanup;
    }
    
    if (!validate_cert(&old_cert)) {
        printf("用户证书已过期，请重新注册\n");
        goto cleanup;
    }
    
    // 直接从用户哈希表获取证书哈希
    unsigned char *old_cert_hash = hashmap_get(user_map, subject_id);
    if (!old_cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        goto cleanup;
    }
    
    // 检查证书是否在撤销列表中
    if (check_cert_in_crl(old_cert_hash)) {
        printf("用户证书已被撤销，请重新注册\n");
        goto cleanup;
    }
    
    // 解析Ru（位于ID之后）
    Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_oct2point(group, Ru, (const unsigned char *)upload_data + SUBJECT_ID_LEN, 
                                 SM2_PUB_MAX_SIZE, NULL)) {
        printf("解析临时公钥失败\n");
        goto cleanup;
    }
    
    // --------step2:CA端生成隐式证书计算部分重构值-----------

    // CA选取随机值k
    k = BN_new();
    BN_rand_range(k, order);

    // 计算公钥重构值Pu=Ru+k*G
    new_Pu = EC_POINT_new(group);
    if (!new_Pu) {
        printf("无法分配内存给new_Pu\n");
        goto cleanup;
    }
    
    if (!EC_POINT_mul(group, new_Pu, k, NULL, NULL, NULL) ||
        !EC_POINT_add(group, new_Pu, Ru, new_Pu, NULL)) {
        printf("计算new_Pu失败\n");
        goto cleanup;
    }

    // 生成隐式证书
    ImpCert new_cert;
    
    // 获取旧证书的序列号和到期时间
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60;
    
    // 生成新的证书序列号
    char* serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", serial_num);

    if(!set_cert(&new_cert, 
              (unsigned char *)serial_num,
              (unsigned char *)"CA000001", 
              (unsigned char *)subject_id,  // 使用用户提供的ID
              current_time,
              expire_time,
              new_Pu)){
        printf("新证书设置失败！\n");
        goto cleanup;
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
    
    // 将旧证书加入CRL管理器
    if (!add_cert_to_crlmanager(old_cert_hash)) {
        printf("警告：无法将旧证书添加到CRL管理器\n");
    }
    
    // 更新用户信息到UserList.dat
    if (!update_user_list(subject_id, new_cert_hash)) {
        printf("更新用户数据失败！\n");
        goto cleanup;
    }

    // 保存新证书到文件系统，覆盖现有文件
    if (!save_cert(&new_cert, cert_filename)) {
        printf("警告：无法保存新用户证书到文件\n");
        goto cleanup;
    }

    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, new_cert_hash, k, d_ca, order);

    // 准备响应数据：新证书+部分私钥r
    response_len = sizeof(ImpCert) + SM2_PRI_MAX_SIZE;
    response_data = (unsigned char*)malloc(response_len);
    if (!response_data) {
        printf("内存分配失败\n");
        goto cleanup;
    }
    
    memcpy(response_data, &new_cert, sizeof(ImpCert));
    memcpy(response_data + sizeof(ImpCert), r, SM2_PRI_MAX_SIZE);
    
    printf("用户 '%s' 成功更新证书\n", subject_id);
    printf("--------------------------------\n");
    
    // 发送HTTP成功响应
    ret = send_http_success_response(connection, response_data, response_len);
    response_data = NULL; // 防止二次释放
    
cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    if (new_Pu) EC_POINT_free(new_Pu);
    if (k) BN_free(k);
    
    if (response_data) {
        free(response_data);
    }
    
    if (ret == MHD_NO) {
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Update failed");
    }
    
    return ret;
}

// 处理撤销请求
enum MHD_Result handle_http_revoke(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    if (!upload_data || upload_data_size < SUBJECT_ID_LEN + 8 + 64) {
        printf("接收到的数据长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Revoke failed: Invalid data length");
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, upload_data, SUBJECT_ID_LEN);
    if (strlen(subject_id) != 8) {
        printf("用户ID长度错误，必须为8个字符\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Revoke failed: Invalid user ID length");
    }
    
    printf("%s---证书撤销(HTTP)\n", subject_id);
    
    // 检查用户是否存在
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，无法撤销\n", subject_id);
        return send_http_error_response(connection, MHD_HTTP_NOT_FOUND, 
                                      "User not found");
    }
    
    // 获取时间戳
    uint64_t timestamp;
    memcpy(&timestamp, upload_data + SUBJECT_ID_LEN, 8);
    timestamp = be64toh(timestamp);  // 网络字节序转为主机字节序
    
    // 验证时间戳
    if (!validate_timestamp(timestamp)) {
        printf("撤销请求中的时间戳无效\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Invalid timestamp");
    }
    
    // 获取签名
    unsigned char signature[64];
    memcpy(signature, upload_data + SUBJECT_ID_LEN + 8, 64);
    
    // 加载用户证书
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    // 从用户哈希表获取证书哈希
    unsigned char *cert_hash = hashmap_get(user_map, subject_id);
    if (!cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        return send_http_error_response(connection, MHD_HTTP_NOT_FOUND, 
                                      "Certificate hash not found");
    }
    
    ImpCert cert;
    if (!load_cert(&cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        return send_http_error_response(connection, MHD_HTTP_NOT_FOUND, 
                                      "Certificate not found");
    }
    
    // 从证书恢复用户公钥
    EC_POINT *Pu = EC_POINT_new(group);
    if (!getPu(&cert, Pu)) {
        printf("无法从证书中获取Pu\n");
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to get public key from certificate");
    }
    
    // 重构用户公钥 Qu = e*Pu + Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, cert_hash, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to reconstruct public key");
    }
    
    // 验证签名
    unsigned char sign_data[SUBJECT_ID_LEN + 8];
    memcpy(sign_data, upload_data, SUBJECT_ID_LEN + 8);
    
    if (!sm2_verify(signature, sign_data, SUBJECT_ID_LEN + 8, Qu)) {
        printf("签名验证失败，拒绝撤销请求\n");
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_UNAUTHORIZED, 
                                      "Signature verification failed");
    }
    
    // 获取用户证书的到期时间
    time_t expire_time;
    memcpy(&expire_time, cert.Validity + sizeof(time_t), sizeof(time_t));
    
    // 将证书加入撤销列表
    if (!add_cert_to_crl(cert_hash, expire_time)) {
        printf("警告：无法将证书添加到撤销列表\n");
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to revoke certificate");
    }
    
    // 将证书加入CRL管理器
    if (!add_cert_to_crlmanager(cert_hash)) {
        printf("警告：无法将证书添加到CRL管理器\n");
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to add certificate to CRL manager");
    }
    
    // 从用户列表中删除用户
    if (!delete_user_from_list(subject_id)) {
        printf("警告：更新用户列表文件失败，但用户已从内存中移除\n");
    }
    
    // 删除用户证书文件
    if (remove(cert_filename) == 0) {
        printf("已删除用户证书文件: %s\n", cert_filename);
    } else {
        printf("警告：无法删除用户证书文件: %s\n", cert_filename);
    }
    
    printf("用户 '%s' 的证书已成功撤销\n", subject_id);
    printf("--------------------------------\n");
    
    // 准备响应数据：状态(1字节) + 时间戳(8字节) + 签名(64字节)
    // 状态：1=成功，0=失败
    uint8_t status = 1;  // 成功
    uint64_t response_time = time(NULL);
    uint64_t ts_network = htobe64(response_time);  // 转换为网络字节序
    
    // 准备要签名的数据：状态 + 时间戳
    unsigned char resp_sign_data[1 + 8];
    resp_sign_data[0] = status;
    memcpy(resp_sign_data + 1, &ts_network, 8);
    
    // 用CA私钥对数据签名
    unsigned char resp_signature[64];
    if (!sm2_sign(resp_signature, resp_sign_data, 1 + 8, d_ca)) {
        printf("签名失败\n");
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to sign response");
    }
    
    // 准备完整响应数据
    unsigned char* response = (unsigned char*)malloc(1 + 8 + 64);
    response[0] = status;
    memcpy(response + 1, &ts_network, 8);
    memcpy(response + 1 + 8, resp_signature, 64);
    
    EC_POINT_free(Pu);
    
    // 发送HTTP成功响应
    return send_http_success_response(connection, response, 1 + 8 + 64);
}

// 处理消息请求
enum MHD_Result handle_http_message(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    // 检查数据长度
    if (!upload_data || upload_data_size < 2) {
        printf("接收到的数据长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Message failed: Invalid data length");
    }
    
    // 解析消息长度（网络字节序）
    uint16_t message_len = (upload_data[0] << 8) | upload_data[1];
    
    // 验证数据长度是否足够
    if (upload_data_size < 2 + message_len + 64 + sizeof(ImpCert)) {
        printf("接收到的数据长度不足，无法解析完整消息\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Message failed: Incomplete message data");
    }
    
    // 提取消息内容
    char *message = (char *)malloc(message_len + 1);  // +1 用于null结尾
    if (!message) {
        printf("内存分配失败\n");
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Memory allocation failed");
    }
    memcpy(message, upload_data + 2, message_len);
    message[message_len] = '\0';
    
    // 提取签名和证书
    unsigned char signature[64];
    memcpy(signature, upload_data + 2 + message_len, 64);
    ImpCert cert;
    memcpy(&cert, upload_data + 2 + message_len + 64, sizeof(ImpCert));
    
    // 从证书中提取发送者ID
    char sender_id[SUBJECT_ID_SIZE] = {0};
    memcpy(sender_id, cert.SubjectID, SUBJECT_ID_LEN);
    printf("收到 %s 的消息(HTTP)\n", sender_id);
    
    if (!validate_cert(&cert)) {
        printf("拒绝消息：证书已过期\n");
        free(message);
        return send_http_error_response(connection, MHD_HTTP_UNAUTHORIZED, 
                                      "Certificate expired");
    }
    
    // 检查证书是否在CRL中
    unsigned char cert_hash[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), cert_hash);
    if (check_cert_in_crl(cert_hash)) {
        printf("拒绝消息：证书已被撤销\n");
        free(message);
        return send_http_error_response(connection, MHD_HTTP_UNAUTHORIZED, 
                                      "Certificate revoked");
    }
    
    // 从证书恢复用户公钥
    EC_POINT *Pu = EC_POINT_new(group);
    if (!getPu(&cert, Pu)) {
        printf("获取Pu失败\n");
        free(message);
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to get public key from certificate");
    }
    
    // 计算证书哈希值e
    unsigned char e[32];
    sm3_hash((const unsigned char *)&cert, sizeof(ImpCert), e);
    
    // 重构用户公钥 Qu = e*Pu + Q_ca
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, e, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        free(message);
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Failed to reconstruct public key");
    }
    
    // 验证消息签名
    if (sm2_verify(signature, (const unsigned char *)message, message_len, Qu)) {
        printf("签名验证成功！消息内容：%s\n", message);
        printf("--------------------------------\n");
        
        // 构造成功响应
        const char *success_msg = "Message verification successful";
        free(message);
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_OK, success_msg);
    } else {
        printf("签名验证失败，拒绝消息\n");
        free(message);
        EC_POINT_free(Pu);
        return send_http_error_response(connection, MHD_HTTP_UNAUTHORIZED, 
                                      "Signature verification failed");
    }
}



// 启动HTTP服务器
int start_http_server() {
    http_daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, HTTP_PORT, NULL, NULL,
        &http_request_handler, NULL, MHD_OPTION_END);
    
    if (http_daemon == NULL) {
        printf("无法启动HTTP服务器\n");
        return 0;
    }
    return 1;
}

// 停止HTTP服务器
void stop_http_server() {
    if (http_daemon) {
        MHD_stop_daemon(http_daemon);
        http_daemon = NULL;
        printf("HTTP服务器已停止\n");
    }
}

// HTTP响应辅助函数
enum MHD_Result send_http_error_response(struct MHD_Connection *connection, 
                                      unsigned int status_code, 
                                      const char *error_msg) {
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result send_http_success_response(struct MHD_Connection *connection, 
                                        unsigned char *data, 
                                        int data_len) {
    if (!data || data_len <= 0) {
        return send_http_error_response(connection, 
                                     MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                     "Internal server error");
    }
    
    struct MHD_Response *response = MHD_create_response_from_buffer(
        data_len, data, MHD_RESPMEM_MUST_FREE);
    
    MHD_add_response_header(response, "Content-Type", "application/octet-stream");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    
    return ret;
}

// 处理证书状态查询的HTTP请求
enum MHD_Result handle_http_cert_status(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    if (!upload_data || upload_data_size != CERT_HASH_SIZE) {
        printf("接收到的数据长度错误，无法处理证书状态查询\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "Certificate status query failed: Invalid data length");
    }
    
    // 从请求中获取证书哈希
    unsigned char cert_hash[CERT_HASH_SIZE];
    memcpy(cert_hash, upload_data, CERT_HASH_SIZE);
    
    // 检查证书是否在撤销列表中
    int cert_status = !check_cert_in_crl(cert_hash); // 1=有效，0=已撤销

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
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Certificate status query failed: Signature error");
    }
    
    // 使用malloc分配内存，使send_http_success_response可以安全释放
    unsigned char *resp_data = (unsigned char *)malloc(1 + 8 + 64);
    if (!resp_data) {
        printf("内存分配失败\n");
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "Certificate status query failed: Memory allocation error");
    }
    
    // 准备响应数据：状态(1字节) + 时间戳(8字节) + 签名(64字节)
    resp_data[0] = cert_status;
    memcpy(resp_data + 1, &ts_network, 8);
    memcpy(resp_data + 1 + 8, signature, 64);
    
    printf("已发送证书状态响应\n");
    
    // 发送响应
    return send_http_success_response(connection, resp_data, 1 + 8 + 64);
}

// 处理CRL更新的HTTP请求
enum MHD_Result handle_http_crl_update(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    UpdatedCRL* updated_crl = NULL;
    unsigned char *sign_data = NULL;
    unsigned char *send_data = NULL;
    enum MHD_Result ret = MHD_NO;
    
    // 验证接收到的数据长度
    if (upload_data_size != sizeof(int) * 2) {
        printf("接收到的CRL版本信息长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST, 
                                      "CRL update failed: Invalid data length");
    }
    
    // 解析用户的版本信息
    int user_base_v, user_removed_v;
    memcpy(&user_base_v, upload_data, sizeof(int));
    memcpy(&user_removed_v, upload_data + sizeof(int), sizeof(int));
    printf("user_v:(%d,%d)\nca_v:(%d,%d)\n", user_base_v, user_removed_v, crl_manager->base_v, crl_manager->removed_v);
    
    // 检查用户版本是否为最新
    if (user_base_v == crl_manager->base_v && 
        user_removed_v == crl_manager->removed_v) {
        printf("用户CRL已是最新版本，无需更新\n");

        unsigned char *status_data = malloc(1);
        status_data[0] = 1;
        return send_http_success_response(connection, status_data, 1);
    }

    updated_crl = CRLManager_generate_update(crl_manager, 
                                            user_base_v, 
                                            user_removed_v);
    if (!updated_crl) {
        printf("生成CRL增量更新失败\n");
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "CRL update failed: Could not generate update");
    }
    
    printf("生成CRL增量更新：新增节点=%d, 删除节点=%d\n", 
           updated_crl->added_count, updated_crl->del_count);
    
    unsigned char update_buffer[BUFFER_SIZE];
    int serialized_size = CRLManager_serialize_update(updated_crl, update_buffer, BUFFER_SIZE);
    
    if (serialized_size < 0) {
        printf("序列化CRL增量更新失败\n");
        CRLManager_free_update(updated_crl);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "CRL update failed: Serialization error");
    }
    
    // 获取当前时间戳
    time_t now = time(NULL);
    uint64_t timestamp = (uint64_t)now;
    uint64_t ts_network = htobe64(timestamp);  // 转换为网络字节序
    
    // 准备要签名的数据：序列化数据 + 时间戳
    sign_data = malloc(serialized_size + 8);
    if (!sign_data) {
        printf("内存分配失败\n");
        CRLManager_free_update(updated_crl);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "CRL update failed: Memory allocation error");
    }
    
    // 复制序列化数据和时间戳到签名数据中
    memcpy(sign_data, update_buffer, serialized_size);
    memcpy(sign_data + serialized_size, &ts_network, 8);
    
    // 计算签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, serialized_size + 8, d_ca)) {
        printf("计算CRL更新签名失败\n");
        free(sign_data);
        CRLManager_free_update(updated_crl);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "CRL update failed: Signature error");
    }
    
    // 准备完整的发送数据：序列化数据 + 时间戳 + 签名
    send_data = malloc(serialized_size + 8 + 64);
    if (!send_data) {
        printf("内存分配失败\n");
        free(sign_data);
        CRLManager_free_update(updated_crl);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, 
                                      "CRL update failed: Memory allocation error");
    }
    
    memcpy(send_data, update_buffer, serialized_size);
    memcpy(send_data + serialized_size, &ts_network, 8);
    memcpy(send_data + serialized_size + 8, signature, 64);
    
    // 发送增量更新给用户
    printf("成功发送CRL增量更新，大小=%d字节\n", serialized_size + 8 + 64);
    printf("--------------------------------\n");
    ret = send_http_success_response(connection, send_data, serialized_size + 8 + 64);
    
    free(sign_data);
    CRLManager_free_update(updated_crl);
    
    return ret;
}

