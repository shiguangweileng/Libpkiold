#include <openssl/ec.h>
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
#include <zlog.h>
#include "common.h"
#include "gm_crypto.h"
#include "imp_cert.h"
#include "hashmap.h"
#include "crlmanager.h"
#include "web_protocol.h"

#define CA_ID "CA01"
#define CRL_FILE "CRL.dat"               // 撤销列表文件
#define USERDATA_DIR "UserData"          // 本地模式下存储用户数据的目录
#define USERCERTS_DIR "UserCerts"        // 存储用户证书的目录
#define USERLIST_FILE "UserList.dat"     // 用户列表文件
#define SERIAL_NUM_FILE "SerialNum.txt"  // 序列号持久化文件
#define CRL_MANAGER_FILE "CRLManager.dat" // CRL管理器文件
#define SESSION_MAP_FILE "SessionKeys.dat"

#define LOG_JSON "{\"operator\":\"%s\",\"operation\":\"%s\"}"

// HTTP服务器相关定义
#define HTTP_PORT 8080                   // HTTP服务器端口
#define UPLOAD_DATA_SIZE 8192            // 上传数据缓冲区大小

//ca核心数据
unsigned char d_ca[SM2_PRI_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];
unsigned char cert_version = CERT_V1;    // 当前使用的证书版本，默认为V1

hashmap* user_map = NULL;           // 存储用户ID和证书哈希
hashmap* crl_map = NULL;            // 存储被撤销的证书哈希和条目结构体
hashmap* session_map = NULL;        // 会话密钥表
CRLManager* crl_manager = NULL;     // CA端的CRL管理器
unsigned int current_serial_num = 1;  // 当前证书序列号，默认从1开始
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
                                         unsigned int status_code);
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
enum MHD_Result handle_http_key_agreement(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size);

// CA本地功能
int local_generate_cert(const char *subject_id);
int local_update_cert(const char *subject_id);
int cleanup_expired_cert();

// Web前端通信处理
void handle_web_get_users(int client_socket);
void handle_web_get_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_get_crl(int client_socket);
void handle_web_cleanup_certs(int client_socket);
void handle_web_local_gen_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_local_upd_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_revoke_cert(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_set_cert_version(int client_socket, const unsigned char *buffer, int data_len);
void handle_web_get_cert_version(int client_socket);

// 用户数据管理
int check_user_exists(const char *subject_id);
int save_user_list(const char *subject_id, const unsigned char *cert_hash);
int update_user_list(const char *subject_id, const unsigned char *new_cert_hash);
int delete_user_from_list(const char *subject_id);

// CRL管理
int check_cert_in_crl(const unsigned char *cert_hash);
int add_cert_to_crl(const unsigned char *cert_hash, const CRLEntry *entry);
int add_cert_to_crlmanager(const unsigned char *cert_hash);

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
    
    int dzlog = dzlog_init("zlog.conf", "my_cat");
    current_serial_num = load_serial_num();
    user_map = ul_hashmap_load(USERLIST_FILE);
    crl_map = crl_hashmap_load(CRL_FILE);
    crl_manager = CRLManager_load_from_file(CRL_MANAGER_FILE);
    
    /* 初始化会话密钥表 */
    session_map = session_hashmap_load(SESSION_MAP_FILE);
    if (!session_map) session_map = session_hashmap_create(256);
    
    if(dzlog != 0 || user_map == NULL || crl_map == NULL || crl_manager == NULL){
        printf("初始化失败！\n");
        global_params_cleanup();
        hashmap_destroy(user_map);
        hashmap_destroy(crl_map);
        CRLManager_free(crl_manager);
        return -1;
    }

    run_online_mode();
    
    hashmap_destroy(user_map);
    /* 保存并销毁会话密钥表 */
    if (session_map) {
        session_hashmap_save(session_map, SESSION_MAP_FILE);
        hashmap_destroy(session_map);
    }
    
    hashmap_destroy(crl_map);
    if (crl_manager) {
        CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE);
        CRLManager_free(crl_manager);
    }
    global_params_cleanup();
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
    ImpCertExt *extensions = NULL;
    ImpCert *cert = NULL;
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

    // 如果是V2证书，需要准备扩展信息
    if (cert_version == CERT_V2) {
        extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!extensions) {
            printf("分配扩展信息内存失败\n");
            goto cleanup;
        }
        // 设置扩展字段
        extensions->Usage = USAGE_IDENTITY;
        extensions->SignAlg = SIGN_SM2;
        extensions->HashAlg = HASH_SM3;
        
        // 填充额外信息
        memset(extensions->ExtraInfo, 0, 11);
        strcpy((char *)extensions->ExtraInfo, "ExtraInfo");
    }

    cert = (ImpCert *)malloc(sizeof(ImpCert));
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60*24; // 1天有效期
    if(!set_cert(cert, 
              cert_version,
              (unsigned char *)serial_num,
              (unsigned char *)CA_ID, 
              (unsigned char *)subject_id,
              current_time, expire_time,
              current_time,
              Pu, extensions)){
        printf("证书设置失败！\n");
        goto cleanup;
    }
    
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    if (!save_cert(cert, cert_filename)) {
        printf("警告：无法保存用户证书到文件\n");
    }
    
    unsigned char cert_hash[32];
    calc_cert_hash(cert, cert_hash);
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
    if (cert) free_cert(cert);
    return ret;
}

int local_update_cert(const char *subject_id) {
    BIGNUM *Ku = NULL;
    BIGNUM *k = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *new_Pu = NULL;
    ImpCertExt *extensions = NULL;
    ImpCert *old_cert = NULL;
    ImpCert *new_cert = NULL;
    int ret = 0;
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，拒绝更新\n", subject_id);
        return 0;
    }
    
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    old_cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!load_cert(old_cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        goto cleanup;
    }
    
    if (!validate_cert(old_cert)) {
        printf("用户证书已过期，请重新注册\n");
        goto cleanup;
    }
    
    unsigned char *old_cert_hash = hashmap_get(user_map, subject_id);
    if (!old_cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        goto cleanup;
    }
    
    if (check_cert_in_crl(old_cert_hash)) {
        printf("用户证书已被撤销，请重新注册\n");
        goto cleanup;
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

    // 如果是V2证书，需要准备扩展信息
    if (cert_version == CERT_V2) {
        extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!extensions) {
            printf("分配扩展信息内存失败\n");
            goto cleanup;
        }
        
        // 设置扩展字段
        extensions->Usage = USAGE_IDENTITY;
        extensions->SignAlg = SIGN_SM2;
        extensions->HashAlg = HASH_SM3;
        
        // 填充额外信息
        memset(extensions->ExtraInfo, 0, 11);
        // 这里可以根据需要设置额外信息
        strcpy((char *)extensions->ExtraInfo, "ExtraInfo");
    }
    
    new_cert = (ImpCert *)malloc(sizeof(ImpCert));
    char* new_serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", new_serial_num);
    
    // 设置证书有效期
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60*24; // 1天有效期
    
    if(!set_cert(new_cert, 
             cert_version,
             (unsigned char *)new_serial_num,
             (unsigned char *)CA_ID, 
             (unsigned char *)subject_id,
             current_time, expire_time,
             current_time,
             new_Pu, extensions)) {
        printf("新证书设置失败！\n");
        goto cleanup;
    }

    unsigned char new_cert_hash[32];
    calc_cert_hash(new_cert, new_cert_hash);
    print_hex("新隐式证书哈希值e", new_cert_hash, 32);

    time_t old_expire_time;
    memcpy(&old_expire_time, old_cert->Validity + sizeof(time_t), sizeof(time_t));
    CRLEntry crl_entry;
    crl_entry.expire_time = old_expire_time;
    crl_entry.revoke_time = time(NULL);
    strcpy(crl_entry.revoke_by, CA_ID);
    crl_entry.reason = REASON_CERT_UPDATED;

    if (!add_cert_to_crl(old_cert_hash, &crl_entry)) {
        printf("警告：无法将旧证书添加到撤销列表\n");
    }
    
    if (!add_cert_to_crlmanager(old_cert_hash)) {
        printf("警告：无法将旧证书添加到CRL管理器\n");
    }
    
    if (!update_user_list(subject_id, new_cert_hash)) {
        printf("更新用户数据失败！\n");
        goto cleanup;
    }

    if (!save_cert(new_cert, cert_filename)) {
        printf("警告：无法保存新用户证书到文件\n");
        goto cleanup;
    }

    // 计算部分私钥r=e×k+d_ca (mod n)
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
    if (old_cert) free_cert(old_cert);
    if (new_cert) free_cert(new_cert);
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

int add_cert_to_crl(const unsigned char *cert_hash, const CRLEntry *entry) {
    
    // 复制证书哈希
    unsigned char* cert_hash_copy = malloc(CERT_HASH_SIZE);
    
    if (!cert_hash_copy) {
        printf("添加证书到CRL失败：内存分配失败\n");
        return 0;
    }
    memcpy(cert_hash_copy, cert_hash, CERT_HASH_SIZE);
    
    // 复制CRLEntry结构体
    CRLEntry* entry_copy = malloc(sizeof(CRLEntry));
    if (!entry_copy) {
        printf("添加证书到CRL失败：内存分配失败\n");
        free(cert_hash_copy);
        return 0;
    }
    
    // 复制CRLEntry内容
    memcpy(entry_copy, entry, sizeof(CRLEntry));

    // 添加到哈希表
    if (!hashmap_put(crl_map, cert_hash_copy, entry_copy, sizeof(CRLEntry))) {
        printf("添加证书到CRL失败：哈希表操作失败\n");
        free(cert_hash_copy);
        free(entry_copy);
        return 0;
    }

    return 1;
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
                
            case WEB_CMD_SET_CERT_VERSION:
                handle_web_set_cert_version(client_socket, buffer, data_len);
                break;
                
            case WEB_CMD_GET_CERT_VERSION:
                handle_web_get_cert_version(client_socket);
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
    
    // 准备响应数据：用户数量(4字节) + 多个(用户ID(4字节) + 证书哈希(32字节))
    response_len = sizeof(int) + user_count * (SUBJECT_ID_LEN + CERT_HASH_SIZE);
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
            memcpy(response_data + offset, entry->key, SUBJECT_ID_LEN);
            offset += SUBJECT_ID_LEN;
            
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
    memcpy(subject_id, buffer, SUBJECT_ID_LEN); // 确保null结尾
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在\n", subject_id);
        send_message(client_socket, WEB_CMD_CERT_DATA, NULL, 0);
        return;
    }
    
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    ImpCert *cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!load_cert(cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        free_cert(cert);
        send_message(client_socket, WEB_CMD_CERT_DATA, NULL, 0);
        return;
    }
    
    // 提取证书哈希
    unsigned char cert_hash[32];
    calc_cert_hash(cert, cert_hash);
    
    // 检查证书有效性（仅保留有效性判断，移除撤销判断）
    int cert_valid = validate_cert(cert);
    
    // 计算响应数据大小和偏移量
    int response_size = sizeof(ImpCert); // 基础证书结构
    
    // 如果是V2证书且有扩展信息，增加相应大小
    if (cert->Version == CERT_V2 && cert->Extensions != NULL) {
        response_size += sizeof(ImpCertExt);
    }
    
    // 添加哈希和有效性标志
    response_size += 32 + 1; // 去掉了撤销标志的1字节
    
    // 分配响应内存
    unsigned char *response = (unsigned char *)malloc(response_size);
    if (!response) {
        printf("内存分配失败\n");
        send_message(client_socket, WEB_CMD_CERT_DATA, NULL, 0);
        free_cert(cert);
        return;
    }
    
    // 填充响应数据
    int offset = 0;
    
    // 复制证书基本数据
    memcpy(response + offset, cert, sizeof(ImpCert));
    offset += sizeof(ImpCert);
    
    // 如果是V2证书且有扩展信息，复制扩展数据
    if (cert->Version == CERT_V2 && cert->Extensions != NULL) {
        memcpy(response + offset, cert->Extensions, sizeof(ImpCertExt));
        offset += sizeof(ImpCertExt);
    }
    
    // 添加证书哈希
    memcpy(response + offset, cert_hash, 32);
    offset += 32;
    
    // 添加有效性标志
    response[offset] = cert_valid ? 1 : 0;
    
    // 发送响应数据
    if (!send_message(client_socket, WEB_CMD_CERT_DATA, response, response_size)) {
        printf("发送证书数据失败\n");
    }
    
    free(response);
    if(cert) free_cert(cert);
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
    
    // 准备响应数据：基础版本号(4字节) + 删除版本号(4字节) + CRL条目数量(4字节) + 多个(证书哈希(32字节) + CRLEntry结构体)
    response_len = sizeof(int) * 3 + crl_count * (CERT_HASH_SIZE + sizeof(CRLEntry));
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
    
    // 遍历哈希表，将所有证书哈希和CRLEntry数据写入响应
    for (int i = 0; i < crl_map->size; i++) {
        hashmap_entry* entry = crl_map->entries[i];
        while (entry) {
            // 首先写入证书哈希
            memcpy(response_data + offset, entry->key, CERT_HASH_SIZE);
            offset += CERT_HASH_SIZE;
            
            // 获取并写入CRLEntry结构体数据(不含哈希)
            CRLEntry *crl_entry = (CRLEntry*)entry->value;
            memcpy(response_data + offset, crl_entry, sizeof(CRLEntry));
            offset += sizeof(CRLEntry);
            
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
    int cleaned_count = cleanup_expired_cert();
    
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
    memcpy(subject_id, buffer, SUBJECT_ID_LEN); // 确保null结尾
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
    memcpy(subject_id, buffer, SUBJECT_ID_LEN); // 确保null结尾
    
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
    ImpCert *cert = NULL;
    
    if (data_len < SUBJECT_ID_SIZE) {
        printf("接收到的数据长度错误，无法识别用户ID\n");
        goto fail;
    }
    
    memcpy(subject_id, buffer, SUBJECT_ID_LEN);
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
    
    cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!load_cert(cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        goto fail;
    }
    
    time_t expire_time;
    memcpy(&expire_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    CRLEntry crl_entry;
    crl_entry.expire_time = expire_time;
    crl_entry.revoke_time = time(NULL);
    strcpy(crl_entry.revoke_by, CA_ID);
    crl_entry.reason = REASON_BUSINESS_END;
    
    if (!add_cert_to_crl(cert_hash, &crl_entry)) {
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
    if (cert) free_cert(cert);
    send_message(client_socket, WEB_CMD_REVOKE_RESULT, &response, 1);
}

// 清理过期证书函数实现
int cleanup_expired_cert() {
    time_t current_time = time(NULL);
    int cleaned_count = 0;
    int i;
    pthread_mutex_lock(&user_map_mutex);  // 复用user_map_mutex锁
    
    // 遍历CRL管理器中的节点并清理过期的证书
    for (i = 0; i < crl_manager->base_v; i++) {
        if (crl_manager->nodes[i].is_valid && crl_manager->nodes[i].hash) {
            CRLEntry *crl_entry = (CRLEntry *)hashmap_get(crl_map, crl_manager->nodes[i].hash);
            if (crl_entry && crl_entry->expire_time < current_time) {
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
        ret = handle_http_register(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/update") == 0) {
        ret = handle_http_update(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/revoke") == 0) {
        ret = handle_http_revoke(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/message") == 0) {
        ret = handle_http_message(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/cert_status") == 0) {
        ret = handle_http_cert_status(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/crl_update") == 0) {
        ret = handle_http_crl_update(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else if (strcmp(url, "/key_agreement") == 0) {
        ret = handle_http_key_agreement(connection, (const char *)con_info->upload_data, con_info->upload_data_size);
    } else {
        // 不支持的路径
        ret = send_http_error_response(connection, MHD_HTTP_NOT_FOUND);
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
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0}; // 确保null结尾
    memcpy(subject_id, upload_data, SUBJECT_ID_LEN);

    if (strlen(subject_id) != 4) {
        printf("用户ID长度错误，必须为4个字符\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }
    
    EC_POINT *Ru = NULL;
    BIGNUM *k = NULL;
    EC_POINT *Pu = NULL;
    char* serial_num = NULL;
    unsigned char *response_data = NULL;
    int response_len = 0;
    enum MHD_Result ret = MHD_NO;
    ImpCertExt *extensions = NULL;
    ImpCert *cert = NULL;
    
    Ru = EC_POINT_new(group);
    if (!Ru || !EC_POINT_oct2point(group, Ru, (const unsigned char *)upload_data + SUBJECT_ID_LEN, 
                                   upload_data_size - SUBJECT_ID_LEN, NULL)) {
        printf("解析临时公钥失败\n");
        goto cleanup;
    }
    
    printf("%s---证书注册(HTTP)\n", subject_id);
    dzlog_info(LOG_JSON, subject_id, "证书注册");
    
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
    char *Pu_hex = EC_POINT_point2hex(group, Pu, POINT_CONVERSION_COMPRESSED, NULL);
    // printf("Pu: %s\n", Pu_hex);
    OPENSSL_free(Pu_hex);
    // print_hex("Q_ca", Q_ca, SM2_PUB_MAX_SIZE);

    // 生成新的证书序列号
    serial_num = generate_serial_num();

    // 如果是V2证书，需要准备扩展信息
    if (cert_version == CERT_V2) {
        extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!extensions) {
            printf("分配扩展信息内存失败\n");
            goto cleanup;
        }
        
        // 设置扩展字段
        extensions->Usage = USAGE_IDENTITY;
        extensions->SignAlg = SIGN_SM2;
        extensions->HashAlg = HASH_SM3;
        
        // 填充额外信息
        memset(extensions->ExtraInfo, 0, 11);
        strcpy((char *)extensions->ExtraInfo, "ExtraInfo");
    }

    // 生成隐式证书
    cert = (ImpCert *)malloc(sizeof(ImpCert));
    
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60*24;
    if(!set_cert(cert, 
              cert_version,
              (unsigned char *)serial_num,
              (unsigned char *)CA_ID, 
              (unsigned char *)subject_id,
              current_time, expire_time, current_time, Pu, extensions)) {
        printf("证书设置失败！\n");
        goto cleanup;
    }
    
    // 保存证书到文件系统，使用用户ID命名
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    if (!save_cert(cert, cert_filename)) {
        printf("警告：无法保存用户证书到文件\n");
    }
    
    // 计算隐式证书的哈希值
    unsigned char cert_hash[32];
    calc_cert_hash(cert, cert_hash);
    print_hex("隐式证书哈希值e", cert_hash, 32);

    // 保存用户信息到UserList
    if (!save_user_list(subject_id, cert_hash)) {
        printf("保存用户数据失败！\n");
        goto cleanup;
    }
    
    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, cert_hash, k, d_ca, order);
    // print_hex("部分私钥r", r, SM2_PRI_MAX_SIZE);
    
    // 准备响应数据
    if (cert_version == CERT_V1) {
        // V1证书：证书结构体+部分私钥r
        response_len = sizeof(ImpCert) + SM2_PRI_MAX_SIZE;
        response_data = (unsigned char*)malloc(response_len);
        if (!response_data) {
            printf("内存分配失败\n");
            goto cleanup;
        }
        
        memcpy(response_data, cert, sizeof(ImpCert));
        memcpy(response_data + sizeof(ImpCert), r, SM2_PRI_MAX_SIZE);
    } else if (cert_version == CERT_V2) {
        // V2证书：证书结构体+扩展信息+部分私钥r
        response_len = sizeof(ImpCert) + sizeof(ImpCertExt) + SM2_PRI_MAX_SIZE;
        response_data = (unsigned char*)malloc(response_len);
        if (!response_data) {
            printf("内存分配失败\n");
            goto cleanup;
        }
        
        // 拷贝证书基本信息
        memcpy(response_data, cert, sizeof(ImpCert));
        // 拷贝扩展信息
        memcpy(response_data + sizeof(ImpCert), extensions, sizeof(ImpCertExt));
        // 拷贝部分私钥r
        memcpy(response_data + sizeof(ImpCert) + sizeof(ImpCertExt), r, SM2_PRI_MAX_SIZE);
    } else {
        printf("不支持的证书版本\n");
        goto cleanup;
    }
    
    // printf("用户 '%s' 成功注册并保存到UserList\n", subject_id);
    // printf("--------------------------------\n");
    dzlog_info(LOG_JSON, subject_id, "证书注册成功");

    // 发送HTTP成功响应
    ret = send_http_success_response(connection, response_data, response_len);
    response_data = NULL; // 防止二次释放

cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (k) BN_free(k);
    if (Pu) EC_POINT_free(Pu);
    if (response_data) free(response_data);
    if (cert) free_cert(cert);
    if (ret == MHD_NO) {
        dzlog_error(LOG_JSON, subject_id, "证书注册失败");
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    return ret;
}

// 处理更新请求
enum MHD_Result handle_http_update(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    if (!upload_data || upload_data_size < SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8 + 64) {
        printf("接收到的数据长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }
    
    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, upload_data, SUBJECT_ID_LEN);
    if (strlen(subject_id) != 4) {  // 现在主体ID长度为4
        printf("用户ID长度错误，必须为4个字符\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }
    
    // 提取时间戳并验证
    uint64_t timestamp;
    memcpy(&timestamp, upload_data + SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE, 8);
    timestamp = be64toh(timestamp);  // 网络字节序转为主机字节序
    
    if (!validate_timestamp(timestamp)) {
        printf("更新请求中的时间戳无效\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }
    
    printf("%s---证书更新(HTTP)\n", subject_id);
    dzlog_info(LOG_JSON, subject_id, "证书更新");
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    EC_POINT *new_Pu = NULL;
    BIGNUM *k = NULL;
    unsigned char *response_data = NULL;
    int response_len = 0;
    enum MHD_Result ret = MHD_NO;
    ImpCertExt *extensions = NULL;
    ImpCert *old_cert = NULL;
    ImpCert *new_cert = NULL;
    
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，拒绝更新\n", subject_id);
        goto cleanup;
    }
    
    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);
    
    old_cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!load_cert(old_cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        goto cleanup;
    }
    if (!validate_cert(old_cert)) {
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
    
    // 重构用户公钥Qu=e×Pu+Q_ca 用于验证签名
    Pu = EC_POINT_new(group);
    if (!getPu(old_cert, Pu)) {
        printf("获取Pu失败\n");
        goto cleanup;
    }
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, old_cert_hash, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        goto cleanup;
    }

    // 提取签名数据和签名
    unsigned char sign_data[SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8];
    memcpy(sign_data, upload_data, SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8);
    unsigned char signature[64];
    memcpy(signature, upload_data + SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8, 64);
    // 验证签名
    if(!sm2_verify(signature, sign_data, SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8, Qu)) {
        printf("签名验证失败，拒绝更新请求\n");
        ret = send_http_error_response(connection, MHD_HTTP_UNAUTHORIZED);
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
    
    // 如果是V2证书，需要准备扩展信息
    if (cert_version == CERT_V2) {
        extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!extensions) {
            printf("分配扩展信息内存失败\n");
            goto cleanup;
        }
        
        // 设置扩展字段
        extensions->Usage = USAGE_IDENTITY;
        extensions->SignAlg = SIGN_SM2;
        extensions->HashAlg = HASH_SM3;
        
        // 填充额外信息
        memset(extensions->ExtraInfo, 0, 11);
        // 这里可以根据需要设置额外信息
        strcpy((char *)extensions->ExtraInfo, "ExtraInfo");
    }

    // 生成隐式证书
    new_cert = (ImpCert *)malloc(sizeof(ImpCert));
    char* new_serial_num = generate_serial_num();
    
    // 设置证书有效期
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60*24; // 1天有效期
    
    if(!set_cert(new_cert, 
             cert_version,
             (unsigned char *)new_serial_num,
             (unsigned char *)CA_ID, 
             (unsigned char *)subject_id,
             current_time, expire_time,
             current_time, new_Pu, extensions)) {
        printf("新证书设置失败！\n");
        goto cleanup;
    }
    
    // 计算新隐式证书的哈希值
    unsigned char new_cert_hash[32];
    calc_cert_hash(new_cert, new_cert_hash);

    // 获取旧证书的到期时间
    time_t old_expire_time;
    memcpy(&old_expire_time, old_cert->Validity + sizeof(time_t), sizeof(time_t));
    CRLEntry crl_entry;
    crl_entry.expire_time = old_expire_time;
    crl_entry.revoke_time = time(NULL);
    strcpy(crl_entry.revoke_by, CA_ID);
    crl_entry.reason = REASON_CERT_UPDATED;

    if (!add_cert_to_crl(old_cert_hash, &crl_entry)) {
        printf("警告：无法将旧证书添加到撤销列表\n");
        goto cleanup;
    }
    
    if (!add_cert_to_crlmanager(old_cert_hash)) {
        printf("警告：无法将旧证书添加到CRL管理器\n");
        goto cleanup;
    }
    
    if (!update_user_list(subject_id, new_cert_hash)) {
        printf("更新用户数据失败！\n");
        goto cleanup;
    }

    if (!save_cert(new_cert, cert_filename)) {
        printf("警告：无法保存新用户证书到文件\n");
        goto cleanup;
    }

    // 计算部分私钥r=e×k+d_ca (mod n)
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, new_cert_hash, k, d_ca, order);

    // 准备响应数据 
    if (cert_version == CERT_V1) {
        // V1证书：证书结构体+部分私钥r
        response_len = sizeof(ImpCert) + SM2_PRI_MAX_SIZE;
        response_data = (unsigned char*)malloc(response_len);
        if (!response_data) {
            printf("内存分配失败\n");
            goto cleanup;
        }
        
        memcpy(response_data, new_cert, sizeof(ImpCert));
        memcpy(response_data + sizeof(ImpCert), r, SM2_PRI_MAX_SIZE);
    } else if (cert_version == CERT_V2) {
        // V2证书：证书结构体+扩展信息+部分私钥r
        response_len = sizeof(ImpCert) + sizeof(ImpCertExt) + SM2_PRI_MAX_SIZE;
        response_data = (unsigned char*)malloc(response_len);
        if (!response_data) {
            printf("内存分配失败\n");
            goto cleanup;
        }
        
        // 拷贝证书基本信息
        memcpy(response_data, new_cert, sizeof(ImpCert));
        // 拷贝扩展信息
        memcpy(response_data + sizeof(ImpCert), extensions, sizeof(ImpCertExt));
        // 拷贝部分私钥r
        memcpy(response_data + sizeof(ImpCert) + sizeof(ImpCertExt), r, SM2_PRI_MAX_SIZE);
    } else {
        printf("不支持的证书版本\n");
        goto cleanup;
    }
    
    printf("用户 '%s' 成功更新证书\n", subject_id);
    printf("--------------------------------\n");
    dzlog_info(LOG_JSON, subject_id, "证书更新成功");
    
    // 发送HTTP成功响应
    ret = send_http_success_response(connection, response_data, response_len);
    response_data = NULL; // 防止二次释放
    
cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    if (new_Pu) EC_POINT_free(new_Pu);
    if (k) BN_free(k);
    if (response_data) free(response_data);
    if (old_cert) free_cert(old_cert);
    if (new_cert) free_cert(new_cert);
    if (ret == MHD_NO) {
        dzlog_error(LOG_JSON, subject_id, "证书更新失败");
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    return ret;
}

// 处理撤销请求
enum MHD_Result handle_http_revoke(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    ImpCert *cert = NULL;
    EC_POINT *Pu = NULL;
    unsigned char *response = NULL;
    enum MHD_Result ret = MHD_NO;
    int error_code = MHD_HTTP_INTERNAL_SERVER_ERROR;

    if (!upload_data || upload_data_size < SUBJECT_ID_LEN + 8 + 64) {
        printf("接收到的数据长度错误\n");
        goto cleanup;
    }

    char subject_id[SUBJECT_ID_SIZE] = {0};
    memcpy(subject_id, upload_data, SUBJECT_ID_LEN);
    if (strlen(subject_id) != SUBJECT_ID_LEN) {
        printf("用户ID长度错误，必须为4个字符\n");
        goto cleanup;
    }

    printf("%s---证书撤销(HTTP)\n", subject_id);
    dzlog_info(LOG_JSON, subject_id, "证书撤销");
    if (!check_user_exists(subject_id)) {
        printf("用户ID '%s' 不存在，无法撤销\n", subject_id);
        goto cleanup;
    }

    uint64_t timestamp;
    memcpy(&timestamp, upload_data + SUBJECT_ID_LEN, 8);
    timestamp = be64toh(timestamp);
    if (!validate_timestamp(timestamp)) {
        printf("撤销请求中的时间戳无效\n");
        goto cleanup;
    }

    unsigned char signature[64];
    memcpy(signature, upload_data + SUBJECT_ID_LEN + 8, 64);

    char cert_filename[SUBJECT_ID_SIZE + 15] = {0};
    sprintf(cert_filename, "%s/%s.crt", USERCERTS_DIR, subject_id);

    unsigned char *cert_hash = hashmap_get(user_map, subject_id);
    if (!cert_hash) {
        printf("无法从用户列表中获取证书哈希\n");
        goto cleanup;
    }

    cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!load_cert(cert, cert_filename)) {
        printf("无法加载用户证书: %s\n", cert_filename);
        goto cleanup;
    }

    Pu = EC_POINT_new(group);
    if (!getPu(cert, Pu)) {
        printf("无法从证书中获取Pu\n");
        goto cleanup;
    }

    unsigned char Qu[SM2_PUB_MAX_SIZE];
    if (!rec_pubkey(Qu, cert_hash, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        goto cleanup;
    }

    unsigned char sign_data[SUBJECT_ID_LEN + 8];
    memcpy(sign_data, upload_data, SUBJECT_ID_LEN + 8);
    if (!sm2_verify(signature, sign_data, SUBJECT_ID_LEN + 8, Qu)) {
        printf("签名验证失败，拒绝撤销请求\n");
        error_code = MHD_HTTP_FORBIDDEN;
        goto cleanup;
    }

    time_t expire_time;
    memcpy(&expire_time, cert->Validity + sizeof(time_t), sizeof(time_t));
    CRLEntry crl_entry;
    crl_entry.expire_time = expire_time;
    crl_entry.revoke_time = time(NULL);
    strcpy(crl_entry.revoke_by, CA_ID);
    crl_entry.reason = REASON_BUSINESS_END;

    if (!add_cert_to_crl(cert_hash, &crl_entry)) {
        printf("警告：无法将证书添加到撤销列表\n");
        goto cleanup;
    }

    if (!add_cert_to_crlmanager(cert_hash)) {
        printf("警告：无法将证书添加到CRL管理器\n");
        goto cleanup;
    }

    if (!delete_user_from_list(subject_id)) {
        printf("警告：更新用户列表文件失败，但用户已从内存中移除\n");
        goto cleanup;
    }

    if (remove(cert_filename) == 0) {
        printf("已删除用户证书文件: %s\n", cert_filename);
    } else {
        printf("警告：无法删除用户证书文件: %s\n", cert_filename);
    }

    printf("用户 '%s' 的证书已成功撤销\n", subject_id);
    printf("--------------------------------\n");
    dzlog_info(LOG_JSON, subject_id, "证书撤销成功");

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
        goto cleanup;
    }
    
    // 准备完整响应数据
    response = (unsigned char*)malloc(1 + 8 + 64);
    response[0] = status;
    memcpy(response + 1, &ts_network, 8);
    memcpy(response + 1 + 8, resp_signature, 64);

    ret = send_http_success_response(connection, response, 1 + 8 + 64);
    response = NULL;
    
cleanup:
    if (response) free(response);
    if (Pu) EC_POINT_free(Pu);
    if (cert) free_cert(cert);
    if (ret == MHD_NO) {
        dzlog_error(LOG_JSON, subject_id, "证书撤销失败");
        return send_http_error_response(connection, error_code);
    }
    return ret;
}

// 处理消息请求
enum MHD_Result handle_http_message(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    /* 数据包格式: [4字节SenderID] [16字节IV] [2字节密文长度] [密文] */
    if (!upload_data || upload_data_size < SUBJECT_ID_LEN + SM4_IV_SIZE + 2) {
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }

    const unsigned char *ptr = (const unsigned char*)upload_data;

    char sender_id[SUBJECT_ID_LEN + 1] = {0};
    memcpy(sender_id, ptr, SUBJECT_ID_LEN);
    sender_id[SUBJECT_ID_LEN] = '\0';
    ptr += SUBJECT_ID_LEN;

    unsigned char iv[SM4_IV_SIZE];
    memcpy(iv, ptr, SM4_IV_SIZE);
    ptr += SM4_IV_SIZE;

    uint16_t cipher_len = ((uint16_t)ptr[0] << 8) | ptr[1];
    ptr += 2;

    if (upload_data_size < SUBJECT_ID_LEN + SM4_IV_SIZE + 2 + cipher_len) {
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }

    const unsigned char *ciphertext = ptr;

    // 获取会话密钥
    SessionKey *session_key = session_key_get(session_map, sender_id);
    if (!session_key || !session_key_is_valid(session_key)) {
        printf("会话密钥无效或不存在: %s\n", sender_id);
        return send_http_error_response(connection, MHD_HTTP_FORBIDDEN);
    }

    int plain_buf_len = cipher_len;
    unsigned char *plaintext = (unsigned char*)malloc(plain_buf_len + 1);
    int plain_len = 0;
    if (!plaintext) {
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    print_hex("ciphertext:", ciphertext, cipher_len);
    if (!sm4_decrypt(plaintext, &plain_len, ciphertext, cipher_len, session_key->key, iv)) {
        free(plaintext);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    plaintext[plain_len] = '\0';
    // print_hex("plaintext:", plaintext, plain_len);
    printf("收到来自 %s 的加密消息: %s\n", sender_id, plaintext);
    if (plaintext) free(plaintext);
    printf("OK\n");
    return send_http_error_response(connection, MHD_HTTP_OK);
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
                                      unsigned int status_code) {
    struct MHD_Response *response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result send_http_success_response(struct MHD_Connection *connection, 
                                        unsigned char *data, 
                                        int data_len) {
    if (!data || data_len <= 0) {
        return send_http_error_response(connection, 
                                     MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    struct MHD_Response *response = MHD_create_response_from_buffer(
        data_len, data, MHD_RESPMEM_MUST_FREE);
    
    MHD_add_response_header(response, "Content-Type", "application/octet-stream");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    
    return ret;
}

// 处理证书状态查询的HTTP请求，1表示有效，0表示无效
enum MHD_Result handle_http_cert_status(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size) {
    if (!upload_data || upload_data_size != CERT_HASH_SIZE) {
        printf("接收到的数据长度错误，无法处理证书状态查询\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
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
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    // 使用malloc分配内存，使send_http_success_response可以安全释放
    unsigned char *resp_data = (unsigned char *)malloc(1 + 8 + 64);
    if (!resp_data) {
        printf("内存分配失败\n");
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    // 准备响应数据：状态(1字节) + 时间戳(8字节) + 签名(64字节)
    resp_data[0] = cert_status;
    memcpy(resp_data + 1, &ts_network, 8);
    memcpy(resp_data + 1 + 8, signature, 64);
    
    // printf("已发送证书状态响应\n");
    
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
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
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
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    printf("生成CRL增量更新：新增节点=%d, 删除节点=%d\n", 
           updated_crl->added_count, updated_crl->del_count);
    
    unsigned char update_buffer[BUFFER_SIZE];
    int serialized_size = CRLManager_serialize_update(updated_crl, update_buffer, BUFFER_SIZE);
    
    if (serialized_size < 0) {
        printf("序列化CRL增量更新失败\n");
        CRLManager_free_update(updated_crl);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
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
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
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
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    // 准备完整的发送数据：序列化数据 + 时间戳 + 签名
    send_data = malloc(serialized_size + 8 + 64);
    if (!send_data) {
        printf("内存分配失败\n");
        free(sign_data);
        CRLManager_free_update(updated_crl);
        return send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
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

// 处理设置证书版本
void handle_web_set_cert_version(int client_socket, const unsigned char *buffer, int data_len) {
    unsigned char response = 0; // 默认为失败
    
    if (data_len != 1) {
        printf("接收到的数据长度错误，无法设置证书版本\n");
        goto fail;
    }
    
    unsigned char new_version = buffer[0];
    
    // 验证版本号的有效性
    if (new_version != CERT_V1 && new_version != CERT_V2) {
        printf("无效的证书版本: %d\n", new_version);
        goto fail;
    }
    
    pthread_mutex_lock(&user_map_mutex); // 加锁保护共享变量
    
    // 设置新的证书版本
    cert_version = new_version;
    
    printf("证书版本已更改为: V%d\n", cert_version);
    
    pthread_mutex_unlock(&user_map_mutex);
    
    response = 1; // 设置成功

fail:
    if (!send_message(client_socket, WEB_CMD_VERSION_RESULT, &response, 1)) {
        printf("发送证书版本设置结果失败\n");
    }
}

void handle_web_get_cert_version(int client_socket) {
    unsigned char response = cert_version;
    send_message(client_socket, WEB_CMD_CERT_VERSION_DATA, &response, 1);
}

enum MHD_Result handle_http_key_agreement(struct MHD_Connection *connection, const char *upload_data, unsigned long upload_data_size)
{
    enum MHD_Result ret = MHD_NO;
    char subject_id[SUBJECT_ID_SIZE] = {0};
    ImpCert *a_cert = NULL;
    ImpCertExt *extensions = NULL;
    EC_POINT *Pu = NULL;
    EC_POINT *PA = NULL;
    unsigned char cert_hash[32] = {0};
    unsigned char Qu[SM2_PUB_MAX_SIZE] = {0};
    
    // 检查数据长度是否足够
    if (!upload_data || upload_data_size < sizeof(ImpCert) - sizeof(ImpCertExt*) + SM2_PUB_MAX_SIZE + 8 + 64) {
        printf("接收到的数据长度错误\n");
        return send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
    }

    //==================步骤一：接收用户A的密钥协商请求====================
    // 提取基本证书信息（不包括扩展指针）
    a_cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!a_cert) {
        printf("内存分配失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    int cert_base_size = sizeof(ImpCert) - sizeof(ImpCertExt*);
    memcpy(a_cert, upload_data, cert_base_size);
    a_cert->Extensions = NULL;  // 先设置为NULL
    
    // 获取用户ID
    memcpy(subject_id, a_cert->SubjectID, SUBJECT_ID_LEN);
    // printf("%s---密钥协商请求(HTTP)\n", subject_id);
    dzlog_info(LOG_JSON, subject_id, "密钥协商请求");
    
    int offset = cert_base_size;
    int ext_size = 0;
    
    // 处理扩展信息（如果是V2证书）
    if (a_cert->Version == CERT_V2) {
        if (upload_data_size < offset + sizeof(ImpCertExt) + SM2_PUB_MAX_SIZE + 8 + 64) {
            printf("接收到的数据长度错误，无法解析V2证书扩展信息\n");
            ret = send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
            goto cleanup;
        }
        
        extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!extensions) {
            printf("扩展信息内存分配失败\n");
            ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
            goto cleanup;
        }
        
        memcpy(extensions, upload_data + offset, sizeof(ImpCertExt));
        a_cert->Extensions = extensions;
        ext_size = sizeof(ImpCertExt);
        offset += ext_size;
    }
    
    // 提取PA
    PA = EC_POINT_new(group);
    if (!PA || !EC_POINT_oct2point(group, PA, (const unsigned char *)upload_data + offset, 
                           SM2_PUB_MAX_SIZE, NULL)) {
        printf("解析PA失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
        goto cleanup;
    }
    
    offset += SM2_PUB_MAX_SIZE;
    
    // 提取时间戳
    uint64_t timestamp_A;
    memcpy(&timestamp_A, upload_data + offset, 8);
    timestamp_A = be64toh(timestamp_A);  // 网络字节序转为主机字节序
    
    // ====================步骤二：验证用户A的合法性====================
    if (!validate_timestamp(timestamp_A)) {
        printf("密钥协商请求中的时间戳无效\n");
        ret = send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
        goto cleanup;
    }
    
    // 查询证书有效性
    if (!validate_cert(a_cert)) {
        printf("证书已过期，拒绝密钥协商请求\n");
        ret = send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
        goto cleanup;
    }
    
    // 计算证书哈希值
    calc_cert_hash(a_cert, cert_hash);
    
    // 查询证书是否在撤销列表中
    if (check_cert_in_crl(cert_hash)) {
        printf("证书已被撤销，拒绝密钥协商请求\n");
        ret = send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
        goto cleanup;
    }
    

    // 重构用户公钥 Qu = e*Pu + Q_ca
    Pu = EC_POINT_new(group);
    getPu(a_cert, Pu);
    if (!rec_pubkey(Qu, cert_hash, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // 提取签名
    unsigned char sig_A[64];
    memcpy(sig_A, upload_data + offset + 8, 64);
    
    // 验证签名
    int ma_size = cert_base_size + ext_size + SM2_PUB_MAX_SIZE + 8;
    if (!sm2_verify(sig_A, (const unsigned char *)upload_data, ma_size, Qu)) {
        printf("签名验证失败，拒绝密钥协商请求\n");
        ret = send_http_error_response(connection, MHD_HTTP_BAD_REQUEST);
        goto cleanup;
    }
    
    
    // ====================步骤三: 继续密钥协商过程====================
    BIGNUM *sB = NULL;
    EC_POINT *PB = NULL;
    EC_POINT *PAB = NULL;
    BIGNUM *xu = NULL;
    BIGNUM *yu = NULL;
    BIGNUM *pa_x = NULL;
    BIGNUM *pa_y = NULL;
    BIGNUM *pb_x = NULL;
    BIGNUM *pb_y = NULL;
    ImpCert *b_cert = NULL;
    unsigned char *response_data = NULL;
    unsigned char *mb_data = NULL;
    int response_len = 0;
    int mb_size = 0;
    int pb_len = 0;
    
    // (1) 生成随机整数sB，计算PB=sB·G
    sB = BN_new();
    BN_rand_range(sB, order);
    PB = EC_POINT_new(group);
    if (!PB || !EC_POINT_mul(group, PB, sB, NULL, NULL, NULL)) {
        printf("计算PB=sB·G失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // 生成时间戳
    time_t now = time(NULL);
    uint64_t timestamp = (uint64_t)now;
    uint64_t ts_network = htobe64(timestamp);  // 转换为网络字节序

    // 这里用CA模拟加载用户B的信息
    unsigned char b_privkey[SM2_PRI_MAX_SIZE];
    FILE *priv_file = fopen("U002_priv.key", "rb");
    if (!priv_file) {
        printf("打开用户B的私钥文件失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    fread(b_privkey, 1, SM2_PRI_MAX_SIZE, priv_file);
    fclose(priv_file);

    // 打印测试B的公钥
    unsigned char b_pubkey[SM2_PUB_MAX_SIZE];
    FILE *pub_file = fopen("U002_pub.key", "rb");
    if (!pub_file) {
        printf("打开用户B的公钥文件失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    fread(b_pubkey, 1, SM2_PUB_MAX_SIZE, pub_file);
    fclose(pub_file);
    // print_hex("b_pubkey", b_pubkey, SM2_PUB_MAX_SIZE);

    b_cert = (ImpCert *)malloc(sizeof(ImpCert));
    load_cert(b_cert, "U002.crt");
    unsigned char b_cert_hash[32];
    calc_cert_hash(b_cert, b_cert_hash);
    // print_hex("b_cert_hash", b_cert_hash, 32);
    // EC_POINT *tPu = EC_POINT_new(group);
    // getPu(b_cert, tPu);
    // // 重构用户公钥 Qu = e*Pu + Q_ca
    // unsigned char tPu_bytes[SM2_PUB_MAX_SIZE];
    // EC_POINT_point2oct(group, tPu, POINT_CONVERSION_UNCOMPRESSED, tPu_bytes, SM2_PUB_MAX_SIZE, NULL);
    // print_hex("Pu", tPu_bytes, SM2_PUB_MAX_SIZE);
    // unsigned char tQu[SM2_PUB_MAX_SIZE];
    // if(!rec_pubkey(tQu, b_cert_hash, tPu, Q_ca)) {
    //     printf("重构用户公钥失败\n");
    //     goto cleanup;
    // }
    // print_hex("Qu", tQu, SM2_PUB_MAX_SIZE);
    

    ext_size = 0;
    // 如果是V2证书，添加扩展信息大小
    if (b_cert->Version == CERT_V2 && b_cert->Extensions) {
        ext_size = sizeof(ImpCertExt);
    }
    // 将PB转换为字节数组
    unsigned char PB_bytes[SM2_PUB_MAX_SIZE];
    pb_len = EC_POINT_point2oct(group, PB, POINT_CONVERSION_UNCOMPRESSED, 
                               PB_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 构造认证消息MB={CertB,PB,T}
    mb_size = cert_base_size + ext_size + pb_len + 8;  // 证书 + 公钥PB + 时间戳
    mb_data = (unsigned char *)malloc(mb_size);
    if (!mb_data) {
        printf("内存分配失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // 填充MB数据
    offset = 0;
    
    // 填充证书基本信息
    memcpy(mb_data + offset, b_cert, cert_base_size);
    offset += cert_base_size;
    
    // 如果是V2证书，填充扩展信息
    if (b_cert->Version == CERT_V2 && b_cert->Extensions) {
        memcpy(mb_data + offset, b_cert->Extensions, sizeof(ImpCertExt));
        offset += sizeof(ImpCertExt);
    }
    
    // 填充PB
    memcpy(mb_data + offset, PB_bytes, pb_len);
    offset += pb_len;
    
    // 填充时间戳
    memcpy(mb_data + offset, &ts_network, 8);
    
    // 用私钥对MB进行签名
    unsigned char sig_B[64];
    if (!sm2_sign(sig_B, mb_data, mb_size, b_privkey)) {
        printf("签名失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // (2) 计算共享点PAB=PA·sB
    PAB = EC_POINT_new(group);
    if (!PAB || !EC_POINT_mul(group, PAB, NULL, PA, sB, NULL)) {
        printf("计算共享点PAB=PA·sB失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // 提取共享点坐标
    xu = BN_new();
    yu = BN_new();
    if (!xu || !yu || !EC_POINT_get_affine_coordinates(group, PAB, xu, yu, NULL)) {
        printf("获取共享点坐标失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // 将坐标转换为字节数组
    unsigned char xu_bytes[32] = {0};
    unsigned char yu_bytes[32] = {0};
    BN_bn2bin(xu, xu_bytes + (32 - BN_num_bytes(xu)));
    BN_bn2bin(yu, yu_bytes + (32 - BN_num_bytes(yu)));

    /* -------- 生成并保存会话密钥 -------- */
    {
        unsigned char Z[32 + 32 + 4 + 4];
        memcpy(Z, xu_bytes, 32);
        memcpy(Z + 32, yu_bytes, 32);
        memcpy(Z + 64, a_cert->SubjectID, 4);          /* ID_A = 请求方ID */
        memcpy(Z + 68, CA_ID, 4);         /* ID_B */
        
        unsigned char sess_key[SESSION_KEY_LEN];
        if (!sm3_kdf(Z, sizeof(Z), sess_key, SESSION_KEY_LEN)) {
            printf("SM3 KDF失败\n");
            ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
            goto cleanup;
        }
        char id_str[5];
        memcpy(id_str, a_cert->SubjectID, 4);
        id_str[4] = '\0';
        session_key_put(session_map, id_str, sess_key);
        SessionKey *t_key = session_key_get(session_map, id_str);
        printf("和%s的会话密钥为：", id_str);
        if (t_key) print_hex("key", t_key->key, SESSION_KEY_LEN);
    }
    
    // 计算SM3(xu)
    unsigned char sm3_xu[32];
    sm3_hash(xu_bytes, 32, sm3_xu);
    
    // (3) 计算会话密钥确认值 XB
    // XB=SM3(0x02||yu||SM3(xu)||PAx||PAy||PBx||PBy)
    unsigned char xb_data[1 + 32 + 32 + 32*4];
    unsigned char PA_x_bytes[32] = {0};
    unsigned char PA_y_bytes[32] = {0};
    unsigned char PB_x_bytes[32] = {0};
    unsigned char PB_y_bytes[32] = {0};
    
    // 提取PA的坐标
    pa_x = BN_new();
    pa_y = BN_new();
    if (!pa_x || !pa_y || !EC_POINT_get_affine_coordinates(group, PA, pa_x, pa_y, NULL)) {
        printf("获取PA坐标失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    BN_bn2bin(pa_x, PA_x_bytes + (32 - BN_num_bytes(pa_x)));
    BN_bn2bin(pa_y, PA_y_bytes + (32 - BN_num_bytes(pa_y)));
    
    // 提取PB的坐标
    pb_x = BN_new();
    pb_y = BN_new();
    if (!pb_x || !pb_y || !EC_POINT_get_affine_coordinates(group, PB, pb_x, pb_y, NULL)) {
        printf("获取PB坐标失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    BN_bn2bin(pb_x, PB_x_bytes + (32 - BN_num_bytes(pb_x)));
    BN_bn2bin(pb_y, PB_y_bytes + (32 - BN_num_bytes(pb_y)));
    
    // 构造XB计算数据
    xb_data[0] = 0x02;  // 常量0x02
    memcpy(xb_data + 1, yu_bytes, 32);  // yu
    memcpy(xb_data + 1 + 32, sm3_xu, 32);  // SM3(xu)
    memcpy(xb_data + 1 + 32 + 32, PA_x_bytes, 32);  // PAx
    memcpy(xb_data + 1 + 32 + 32 + 32, PA_y_bytes, 32);  // PAy
    memcpy(xb_data + 1 + 32 + 32 + 32 + 32, PB_x_bytes, 32);  // PBx
    memcpy(xb_data + 1 + 32 + 32 + 32 + 32 + 32, PB_y_bytes, 32);  // PBy

    // 计算XB
    unsigned char XB[32];
    sm3_hash(xb_data, sizeof(xb_data), XB);
    
    // (4) 构造响应数据: MB + 签名 + XB
    response_len = mb_size + 64 + 32;  // MB大小 + 签名大小 + XB大小
    response_data = (unsigned char *)malloc(response_len);
    if (!response_data) {
        printf("内存分配失败\n");
        ret = send_http_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
        goto cleanup;
    }
    
    // 复制MB数据
    memcpy(response_data, mb_data, mb_size);
    // 复制签名
    memcpy(response_data + mb_size, sig_B, 64);
    // 复制XB
    memcpy(response_data + mb_size + 64, XB, 32);
    
    // 发送响应
    ret = send_http_success_response(connection, response_data, response_len);
    response_data = NULL; // 防止二次释放
    
cleanup:
    if (PA) EC_POINT_free(PA);
    if (PB) EC_POINT_free(PB);
    if (Pu) EC_POINT_free(Pu);
    if (PAB) EC_POINT_free(PAB);
    if (sB) BN_free(sB);
    if (xu) BN_free(xu);
    if (yu) BN_free(yu);
    if (pa_x) BN_free(pa_x);
    if (pa_y) BN_free(pa_y);
    if (pb_x) BN_free(pb_x);
    if (pb_y) BN_free(pb_y);
    if (a_cert) free_cert(a_cert);
    if (b_cert) free_cert(b_cert);
    if (mb_data) free(mb_data);
    if (response_data) free(response_data);

    
    return ret;
}


