#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <curl/curl.h>
#include <openssl/rand.h>
#include "common.h"
#include "gm_crypto.h"
#include "imp_cert.h"
#include "hashmap.h"
#include "crlmanager.h"

#define CRL_MANAGER_FILE "CRLManager.dat"
#define SESSION_MAP_FILE "SessionKeys.dat"
#define MAX_MESSAGE_SIZE 1024 // 最大消息长度
#define NETWORK_TIMEOUT 1000  // 网络超时时间（毫秒）

// HTTP通信相关定义
#define CA_PORT 8080       // HTTP服务器端口
#define HTTP_TIMEOUT 10L     // HTTP请求超时时间（秒）

// 存储服务器IP地址的全局变量
static char CA_IP[16] = "127.0.0.1";

// 存储相关信息的全局变量
ImpCert *loaded_cert = NULL;
hashmap *local_crl = NULL; // 本地CRL哈希表，只存储证书哈希值
hashmap* session_map = NULL; /* 会话密钥表 */
CRLManager* crl_manager = NULL;
unsigned char priv_key[SM2_PRI_MAX_SIZE];
unsigned char pub_key[SM2_PUB_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];
char user_id[SUBJECT_ID_SIZE] = {0};
int has_cert = 0;

// CRL相关函数
int init_crl_manager();
int load_crl_manager_to_hashmap();
int check_cert_in_local_crl(const unsigned char *cert_hash);
int sync_crl_with_ca();
int online_csp(const unsigned char *cert_hash);
int local_csp(const unsigned char *cert_hash);

// 用户操作

// ----------------- 会话密钥保存函数 -------------------
void save_session_map(void) {
    if (session_map) {
        session_hashmap_save(session_map, SESSION_MAP_FILE);
        hashmap_destroy(session_map);
        session_map = NULL;
    }
}

int load_keys_and_cert(const char *user_id);
int request_registration(const char *user_id);
int request_cert_update(const char *user_id);
int request_cert_revoke(const char *user_id);
void save_session_map(void);
int send_encrypt_message(const char *sender_id, const char *server_ip, int port, const char *plaintext);
int request_key_agreement();

// HTTP通信相关函数
typedef struct {
    unsigned char *data;
    size_t size;
} MemoryStruct;

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;
    
    mem->data = realloc(mem->data, mem->size + realsize);
    if (mem->data == NULL) {
        printf("内存分配失败\n");
        return 0;
    }
    
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    
    return realsize;
}

// 使用HTTP发送请求（用于替代socket通信）
int http_send_request(const char *url, const unsigned char *data, int data_len, 
                     unsigned char **response, int *response_len) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk;
    chunk.data = NULL;
    chunk.size = 0;
    
    // 初始化libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        printf("初始化curl失败\n");
        curl_global_cleanup();
        return 0;
    }
    
    // 设置URL
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    // 设置HTTP POST
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data_len);
    
    // 设置响应数据回调
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
    // 设置超时
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);
    
    // 设置内容类型
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // 执行请求
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("curl_easy_perform() 失败: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        curl_global_cleanup();
        if (chunk.data) free(chunk.data);
        return 0;
    }
    
    // 检查HTTP响应状态码
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        printf("HTTP错误: %ld\n", http_code);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        curl_global_cleanup();
        if (chunk.data) free(chunk.data);
        return 0;
    }
    
    // 返回响应数据
    *response = chunk.data;
    *response_len = chunk.size;
    
    // 清理
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();
    
    return 1;
}

int main() {
    char server_ip[16] = {0};
    int choice = 0;
    int running = 1; // 控制主循环
    int result = 0;
    struct timeval start_time, end_time;
    /* 初始化会话密钥表 */
    session_map = session_hashmap_load(SESSION_MAP_FILE);
    if (!session_map) session_map = session_hashmap_create(256);

    /* 程序退出时保存会话密钥 */
    atexit(save_session_map);
    if (!User_init(Q_ca)) {
        printf("加载CA公钥失败！\n");
        global_params_cleanup();
        return -1;
    }
    
    // 初始化CRL管理器和哈希表
    if (!init_crl_manager()) {
        printf("初始化CRL管理器失败！\n");
        global_params_cleanup();
        return -1;
    }
    
    // 请求用户输入服务器IP地址
    printf("请输入服务器IP地址(输入1使用127.0.0.1): ");
    if (scanf("%15s", server_ip) != 1) {
        printf("IP地址输入错误\n");
        global_params_cleanup();
        return -1;
    }
    
    // 如果输入"1"，则使用默认IP地址127.0.0.1
    if (strcmp(server_ip, "1") == 0) {
        strcpy(server_ip, "127.0.0.1");
        printf("使用默认IP地址: %s\n", server_ip);
    }
    
    // 保存IP地址到全局变量
    strcpy(CA_IP, server_ip);
    
    // 外层循环 - 处理不同用户
    while (running) {
        // 重置变量
        has_cert = 0;
        memset(user_id, 0, SUBJECT_ID_SIZE);
        
        // 请求用户输入ID
        printf("\n请输入用户ID (必须是4个字符): ");
        if (scanf("%4s", user_id) != 1) {
            printf("ID输入错误\n");
            clear_input_buffer();
            continue;
        }
        
        // 检查本地是否存在该ID的证书
        has_cert = load_keys_and_cert(user_id);
        
        // 内层循环 - 处理当前用户的多次操作
        int user_session = 1;
        while (user_session) {
            // 用户选择操作
            printf("\n用户 [%s] 请选择操作:\n", user_id);
            printf("1. 注册新证书\n");
            printf("2. 更新现有证书\n");
            printf("3. 发送加密消息\n");
            printf("4. 撤销证书\n");
            printf("5. 同步CRL\n");
            printf("6. 证书状态查询\n");
            printf("7. 证书状态比对(在线+本地)\n");
            printf("8. 密钥协商\n");
            printf("9. 切换用户\n");
            printf("0. 退出程序\n");

            printf("请输入选择: ");
            if (scanf("%d", &choice) != 1) {
                printf("输入错误\n");
                clear_input_buffer();
                continue;
            }
            
            // 检查是否要切换用户或退出
            if (choice == 9) {
                user_session = 0; // 退出当前用户会话，返回到用户ID输入
                continue;
            } else if (choice == 0) {
                user_session = 0;
                running = 0; // 退出程序
                continue;
            }
            
            result = 0;
            switch (choice) {
                case 1: // 注册
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = request_registration(user_id);
                    if (result) {
                        // 操作完成后重新加载证书
                        has_cert = load_keys_and_cert(user_id);
                    }
                    break;
                    
                case 2: // 更新
                    if (!has_cert) {
                        printf("错误：需要先有证书才能更新\n");
                        continue;
                    }
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = request_cert_update(user_id);
                    if (result) {
                        // 更新后重新加载证书
                        has_cert = load_keys_and_cert(user_id);
                    }
                    break;
                    
                case 3:{ // 发送加密消息
                    char *peer_id = "U002";
                    char message[MAX_MESSAGE_SIZE] = {0};
                    clear_input_buffer();
                    printf("请输入要发送的消息: ");
                    if (fgets(message, MAX_MESSAGE_SIZE, stdin) == NULL) {
                        printf("消息输入错误\n");
                        break;
                    }
                    // 去除尾部换行
                    size_t msg_len = strlen(message);
                    if (msg_len > 0 && message[msg_len - 1] == '\n') {
                        message[msg_len - 1] = '\0';
                    }
                    // char *message = "Hello, World!";
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = send_encrypt_message(peer_id, server_ip, CA_PORT, message);
                    break;
                }
                case 4: // 撤销证书
                    if (!has_cert) {
                        printf("错误：需要先有证书才能撤销\n");
                        continue;
                    }
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = request_cert_revoke(user_id);
                    if (result) {
                        has_cert = 0; // 撤销成功后，清除本地证书状态
                    }
                    break;
                    
                case 5: // 同步CRL
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = sync_crl_with_ca();
                    break;
                    
                case 6: // 证书状态查询
                {
                    unsigned char cert_hash[CERT_HASH_SIZE];
                    clear_input_buffer();
                    if (!parse_hex_hash(cert_hash, CERT_HASH_SIZE)) {
                        printf("证书哈希输入错误\n");
                        continue;
                    }
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    int online_status = online_csp(cert_hash);
                    printf("online_csp:%s\n", online_status ? "有效" : "无效（已撤销）");
                    result = 1;
                    break;
                }
                    
                case 7: // 证书状态比对
                {
                    unsigned char cert_hash2[CERT_HASH_SIZE];
                    clear_input_buffer();
                    
                    if (!parse_hex_hash(cert_hash2, CERT_HASH_SIZE)) {
                        printf("证书哈希输入错误\n");
                        continue;
                    }
                    
                    gettimeofday(&start_time, NULL);
                    
                    int online_status2 = online_csp(cert_hash2);
                    printf("online_csp:%s\n", online_status2 ? "有效" : "无效（已撤销）");
                    
                    int local_status = local_csp(cert_hash2);
                    printf("local_csp:%s\n", local_status ? "有效" : "无效（已撤销）");
                    result = 1;
                    break;
                }
                    
                case 8: // 密钥协商
                    gettimeofday(&start_time, NULL); // 记录开始时间
                    result = request_key_agreement();
                    break;
                    
                default:
                    printf("无效的选择\n");
                    break;
            }
            
            if (result) {
                gettimeofday(&end_time, NULL);
                long seconds = end_time.tv_sec - start_time.tv_sec;
                long microseconds = end_time.tv_usec - start_time.tv_usec;
                double elapsed_ms = seconds * 1000.0 + microseconds / 1000.0;
                
                const char* operation_names[] = {
                    "未知操作", "注册证书", "更新证书", "发送消息", 
                    "撤销证书", "同步证书撤销列表", "查询证书状态", "证书状态比对", "密钥协商"
                };
                
                if (choice >= 1 && choice <= 9) {
                    printf("%s的时间开销: %.2f ms\n", operation_names[choice], elapsed_ms);
                }
            }
        }
    }
    
    // 程序结束时释放资源
    if (crl_manager) {
        // 保存CRL管理器
        if (!CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE)) {
            printf("保存CRL管理器失败！\n");
        }
        CRLManager_free(crl_manager);
    }
    
    if (local_crl) {
        hashmap_destroy(local_crl);
    }
    global_params_cleanup();
    return 0;
}

//----------------证书处理函数实现-------------------
int load_keys_and_cert(const char *user_id) {
    char cert_filename[SUBJECT_ID_LEN + 5] = {0}; // ID + ".crt"
    char priv_key_filename[SUBJECT_ID_LEN + 10] = {0}; // ID + "_priv.key"
    char pub_key_filename[SUBJECT_ID_LEN + 9] = {0}; // ID + "_pub.key"
    
    sprintf(cert_filename, "%s.crt", user_id);
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    
    // 检查证书文件是否存在
    FILE *cert_file = fopen(cert_filename, "rb");
    if (!cert_file) {
        printf("未找到证书文件: %s\n", cert_filename);
        return 0;
    }
    
    // 为loaded_cert分配内存
    if (!loaded_cert) {
        loaded_cert = (ImpCert *)malloc(sizeof(ImpCert));
        if (!loaded_cert) {
            printf("内存分配失败\n");
            fclose(cert_file);
            return 0;
        }
        memset(loaded_cert, 0, sizeof(ImpCert));
    }
    // 加载证书
    if (!load_cert(loaded_cert, cert_filename)) {
        printf("无法加载证书文件: %s\n", cert_filename);
        fclose(cert_file);
        return 0;
    }
    fclose(cert_file);
    
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
int request_registration(const char *user_id) {
    BIGNUM *Ku = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    ImpCert cert = {0};
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
    unsigned char send_data[SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE];
    memcpy(send_data, user_id, SUBJECT_ID_LEN);
    memcpy(send_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    
    // 使用HTTP发送数据
    unsigned char *response_data = NULL;
    int response_len = 0;
    
    // 构建URL
    char url[100];
    sprintf(url, "http://%s:%d/register", CA_IP, CA_PORT);
    if (!http_send_request(url, send_data, SUBJECT_ID_LEN + ru_len, &response_data, &response_len)) {
        printf("发送注册请求失败\n");
        goto cleanup;
    }
    
    // 解析证书基本信息
    unsigned char r[SM2_PRI_MAX_SIZE];
    
    // 直接判断响应长度是否匹配某种证书类型
    if (response_len == sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        // V1证书格式：证书结构体 + 部分私钥r
        memcpy(&cert, response_data, sizeof(ImpCert));
        memcpy(r, response_data + sizeof(ImpCert), SM2_PRI_MAX_SIZE);
        // printf("已成功接收V1证书和部分私钥r\n");
    } 
    else if (response_len == sizeof(ImpCert) + sizeof(ImpCertExt) + SM2_PRI_MAX_SIZE) {
        // V2证书格式：证书结构体 + 扩展信息 + 部分私钥r
        memcpy(&cert, response_data, sizeof(ImpCert));
        
        // 为扩展信息分配内存
        cert.Extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!cert.Extensions) {
            printf("扩展信息内存分配失败\n");
            free(response_data);
            goto cleanup;
        }
        
        // 提取扩展信息
        memcpy(cert.Extensions, response_data + sizeof(ImpCert), sizeof(ImpCertExt));
        // 提取部分私钥r
        memcpy(r, response_data + sizeof(ImpCert) + sizeof(ImpCertExt), SM2_PRI_MAX_SIZE);
        
        printf("已成功接收V2证书和部分私钥r\n");
    } 
    else {
        printf("接收到的数据长度错误: %d\n", response_len);
        free(response_data);
        goto cleanup;
    }
    
    free(response_data);
    
    // 验证证书颁发时间戳
    time_t issue_time;
    memcpy(&issue_time, cert.IssueTime, sizeof(time_t));
    if (!validate_timestamp((uint64_t)issue_time)) {
        printf("验证证书颁发时间戳失败\n");
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
    calc_cert_hash(&cert, e);
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
    print_hex("用户公钥Qu", Qu, SM2_PUB_MAX_SIZE);
    print_hex("用户私钥d_u", d_u, SM2_PRI_MAX_SIZE);
    
    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)){
        printf("密钥对验证失败！\n");
        goto cleanup;
    }

    // 更新全局变量
    memcpy(priv_key, d_u, SM2_PRI_MAX_SIZE);
    memcpy(pub_key, Qu, SM2_PUB_MAX_SIZE);

    //--------step4:用户端保存证书和最终的公私钥对-------------
    
    // 准备文件名
    char pub_key_filename[SUBJECT_ID_LEN + 9] = {0}; // ID + "_pub.key"
    char priv_key_filename[SUBJECT_ID_LEN + 10] = {0}; // ID + "_priv.key"
    char cert_filename[SUBJECT_ID_LEN + 5] = {0}; // ID + ".crt"
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    sprintf(cert_filename, "%s.crt", user_id);
        
    // 保存证书供后续使用
    if(!save_cert(&cert, cert_filename)){
        printf("保存证书失败\n");
        goto cleanup;
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
    
    // printf("注册过程完成\n");
    ret = 1;
    
cleanup:
    if (Ku) BN_free(Ku);
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    if (cert.Extensions) free(cert.Extensions);
    return ret;
}

int request_cert_update(const char *user_id) {
    BIGNUM *Ku = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    ImpCert new_cert = {0};
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
    
    // 获取当前时间戳
    time_t now = time(NULL);
    uint64_t timestamp = (uint64_t)now;
    uint64_t ts_network = htobe64(timestamp);  // 转换为网络字节序
    
    // 准备要签名的数据：ID + Ru + 时间戳（先ID后Ru后时间戳）
    unsigned char sign_data[SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8];
    memcpy(sign_data, user_id, SUBJECT_ID_LEN);
    memcpy(sign_data + SUBJECT_ID_LEN, Ru_bytes, ru_len);
    memcpy(sign_data + SUBJECT_ID_LEN + ru_len, &ts_network, 8);
    
    // 用私钥对数据签名
    unsigned char signature[64];
    if (!sm2_sign(signature, sign_data, SUBJECT_ID_LEN + ru_len + 8, priv_key)) {
        printf("签名失败\n");
        goto cleanup;
    }
    
    // 准备发送的完整数据：ID + Ru + 时间戳 + 签名
    unsigned char send_data[SUBJECT_ID_LEN + SM2_PUB_MAX_SIZE + 8 + 64];
    memcpy(send_data, sign_data, SUBJECT_ID_LEN + ru_len + 8);
    memcpy(send_data + SUBJECT_ID_LEN + ru_len + 8, signature, 64);
    
    // 使用HTTP发送更新请求
    unsigned char *response_data = NULL;
    int response_len = 0;
    
    // 构建URL
    char url[100];
    sprintf(url, "http://%s:%d/update", CA_IP, CA_PORT);
    if (!http_send_request(url, send_data, SUBJECT_ID_LEN + ru_len + 8 + 64, &response_data, &response_len)) {
        printf("发送更新请求失败\n");
        goto cleanup;
    }
    
    // 解析新证书基本信息
    unsigned char r[SM2_PRI_MAX_SIZE];
    
    // 直接判断响应长度是否匹配某种证书类型
    if (response_len == sizeof(ImpCert) + SM2_PRI_MAX_SIZE) {
        // V1证书格式：证书结构体 + 部分私钥r
        memcpy(&new_cert, response_data, sizeof(ImpCert));
        memcpy(r, response_data + sizeof(ImpCert), SM2_PRI_MAX_SIZE);

        printf("已成功接收更新后的V1证书和部分私钥r\n");
    } 
    else if (response_len == sizeof(ImpCert) + sizeof(ImpCertExt) + SM2_PRI_MAX_SIZE) {
        // V2证书格式：证书结构体 + 扩展信息 + 部分私钥r
        memcpy(&new_cert, response_data, sizeof(ImpCert));

        // 为扩展信息分配内存
        new_cert.Extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!new_cert.Extensions) {
            printf("扩展信息内存分配失败\n");
            free(response_data);
            goto cleanup;
        }
        
        // 提取扩展信息
        memcpy(new_cert.Extensions, response_data + sizeof(ImpCert), sizeof(ImpCertExt));
        // 提取部分私钥r
        memcpy(r, response_data + sizeof(ImpCert) + sizeof(ImpCertExt), SM2_PRI_MAX_SIZE);
        
        printf("已成功接收更新后的V2证书和部分私钥r\n");
    } 
    else {
        printf("接收到的数据长度错误: %d\n", response_len);
        free(response_data);
        goto cleanup;
    }
    
    free(response_data);
    
    //--------step3:用户端生成最终的公私钥对-------------
    // 获取隐式证书中的Pu
    Pu = EC_POINT_new(group);
    if (!getPu(&new_cert, Pu)) {
        printf("获取Pu失败\n");
        goto cleanup;
    }

    // 计算隐式证书哈希值
    unsigned char e[32];
    calc_cert_hash(&new_cert, e);
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
    print_hex("用户公钥Qu", Qu, SM2_PUB_MAX_SIZE);
    print_hex("用户私钥d_u", d_u, SM2_PRI_MAX_SIZE);

    // 验证密钥对
    if(!verify_key_pair_bytes(group, Qu, d_u)) {
        printf("新密钥对验证失败！\n");
        goto cleanup;
    }
    
    // 更新全局变量
    memcpy(priv_key, d_u, SM2_PRI_MAX_SIZE);
    memcpy(pub_key, Qu, SM2_PUB_MAX_SIZE);

    //--------step4:用户端保存证书和最终的公私钥对-------------
    // 准备文件名
    char pub_key_filename[SUBJECT_ID_LEN + 9] = {0}; // ID + "_pub.key"
    char priv_key_filename[SUBJECT_ID_LEN + 10] = {0}; // ID + "_priv.key"
    char cert_filename[SUBJECT_ID_LEN + 5] = {0}; // ID + ".crt"
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    sprintf(cert_filename, "%s.crt", user_id);

    // 保存新证书供后续使用
    sprintf(cert_filename, "%s.crt", user_id);
    if (!save_cert(&new_cert, cert_filename)) {
        printf("保存新证书失败\n");
        goto cleanup;
    }

    // 保存用户新私钥供后续使用
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存更新后的用户私钥到文件\n");
    }
    
    // 保存用户新公钥供后续使用
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
    if (new_cert.Extensions) free(new_cert.Extensions);
    return ret;
}

// ----------------- 发送加密消息 -------------------
int send_encrypt_message(const char *peer_id, const char *server_ip, int port, const char *plaintext) {
    if (!peer_id || !server_ip || !plaintext) return 0;

    // 获取会话密钥
    SessionKey *session_key = session_key_get(session_map, peer_id);
    if (!session_key || !session_key_is_valid(session_key)) {
        printf("未找到有效会话密钥，请先完成密钥协商\n");
        return 0;
    }
    unsigned char iv[SM4_IV_SIZE];
    sm4_generate_iv(iv);
    int plaintext_len = strlen(plaintext);
    int cipher_buf_len = plaintext_len + SM4_BLOCK_SIZE; // 足够存储填充
    unsigned char *ciphertext = malloc(cipher_buf_len);
    if (!ciphertext) return 0;
    int cipher_len = 0;
    if (!sm4_encrypt(ciphertext, &cipher_len,
                     (unsigned char*)plaintext, plaintext_len, session_key->key, iv)) {
        printf("SM4加密失败\n");
        free(ciphertext);
        return 0;
    }

    // 构造数据包: [4字节ID] [16字节IV] [2字节密文长度] [密文]
    int packet_size = SUBJECT_ID_LEN + SM4_IV_SIZE + 2 + cipher_len;
    unsigned char *packet = malloc(packet_size);
    if (!packet) { free(ciphertext); return 0; }
    memcpy(packet, user_id, SUBJECT_ID_LEN);
    memcpy(packet + SUBJECT_ID_LEN, iv, SM4_IV_SIZE);
    packet[SUBJECT_ID_LEN + SM4_IV_SIZE] = (cipher_len >> 8) & 0xFF;
    packet[SUBJECT_ID_LEN + SM4_IV_SIZE + 1] = cipher_len & 0xFF;
    memcpy(packet + SUBJECT_ID_LEN + SM4_IV_SIZE + 2, ciphertext, cipher_len);

    // 构建URL
    char url[128];
    sprintf(url, "http://%s:%d/message", server_ip, port);

    unsigned char *response_data = NULL;
    int response_len = 0;
    int result = http_send_request(url, packet, packet_size, &response_data, &response_len);

    free(ciphertext);
    free(packet);
    if (response_data) free(response_data);

    if (result) {
        printf("加密消息已发送\n");
    } else {
        printf("发送失败\n");
    }
    return result;
}

// 使用HTTP请求撤销证书
int request_cert_revoke(const char *user_id) {
    
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
    
    // 使用HTTP发送数据
    unsigned char *response_data = NULL;
    int response_len = 0;
    
    // 构建URL
    char url[100];
    sprintf(url, "http://%s:%d/revoke", CA_IP, CA_PORT);
    
    if (!http_send_request(url, request_data, sizeof(request_data), &response_data, &response_len)) {
        printf("发送撤销请求失败\n");
        return 0;
    }
    
    // 验证响应数据
    if (response_len < 1 + 8 + 64) {  // 状态 + 时间戳 + 签名
        printf("撤销响应数据长度错误\n");
        free(response_data);
        return 0;
    }
    
    uint8_t status = response_data[0];
    
    uint64_t resp_timestamp;
    memcpy(&resp_timestamp, response_data + 1, 8);
    resp_timestamp = be64toh(resp_timestamp);  // 网络字节序转为主机字节序
    
    if (!validate_timestamp(resp_timestamp)) {
        printf("撤销响应中的时间戳无效\n");
        free(response_data);
        return 0;
    }
    
    // 获取签名
    unsigned char resp_signature[64];
    memcpy(resp_signature, response_data + 1 + 8, 64);
    
    // 验证签名
    unsigned char resp_sign_data[1 + 8];
    resp_sign_data[0] = status;
    uint64_t ts_network_copy = htobe64(resp_timestamp);
    memcpy(resp_sign_data + 1, &ts_network_copy, 8);
    
    if (!sm2_verify(resp_signature, resp_sign_data, 1 + 8, Q_ca)) {
        printf("撤销响应签名验证失败\n");
        free(response_data);
        return 0;
    }
    
    // 检查状态
    if (status != 1) {
        printf("撤销失败，CA返回状态: %d\n", status);
        free(response_data);
        return 0;
    }
    
    free(response_data);
    
    printf("证书撤销成功！正在安全删除本地证书文件...\n");
    
    // 删除本地证书文件
    char cert_filename[20];
    sprintf(cert_filename, "%s.crt", user_id);
    remove(cert_filename);
    
    // 安全删除本地私钥文件
    char priv_key_filename[20];
    sprintf(priv_key_filename, "%s_priv.key", user_id);
    secure_delete_file(priv_key_filename);
    
    // 删除本地公钥文件
    char pub_key_filename[20];
    sprintf(pub_key_filename, "%s_pub.key", user_id);
    remove(pub_key_filename);
    
    printf("本地证书文件安全清理完成\n");
    
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
    return hashmap_exists(local_crl, cert_hash);
}

// 与CA同步CRL数据
int sync_crl_with_ca() {
    // 准备版本信息数据
    int version_info[2];
    version_info[0] = crl_manager->base_v;      // 当前节点基础版本号
    version_info[1] = crl_manager->removed_v;   // 当前已删除节点版本号
    
    printf("current_v:(%d,%d)\n", version_info[0], version_info[1]);
    
    // 使用HTTP发送数据
    unsigned char *response_data = NULL;
    int response_len = 0;
    
    // 构建URL
    char url[100];
    sprintf(url, "http://%s:%d/crl_update", CA_IP, CA_PORT);
    
    if (!http_send_request(url, (unsigned char*)version_info, sizeof(version_info), 
                          &response_data, &response_len)) {
        printf("发送CRL同步请求失败\n");
        return 0;
    }
    
    // 处理响应，如果长度为1并且值为1表示当前CRL已经是最新的
    if (response_len == 1 && response_data && response_data[0] == 1) {
        printf("当前CRL已是最新版本\n");
        free(response_data);
        return 1;
    }
    
    // 检查数据长度是否至少包含时间戳(8字节)和签名(64字节)
    if (response_len <= 8 + 64) {
        printf("接收到的CRL更新数据长度错误\n");
        free(response_data);
        return 0;
    }
    
    // 提取时间戳和签名
    int crl_data_len = response_len - 8 - 64;
    uint64_t timestamp;
    unsigned char signature[64];
    
    memcpy(&timestamp, response_data + crl_data_len, 8);
    memcpy(signature, response_data + crl_data_len + 8, 64);
    
    // 将时间戳从网络字节序转换为主机字节序
    timestamp = be64toh(timestamp);
    
    // 验证时间戳是否有效
    if (!validate_timestamp(timestamp)) {
        printf("CRL更新中的时间戳无效\n");
        free(response_data);
        return 0;
    }
    
    // 准备签名验证数据：CRL数据 + 时间戳(网络字节序)
    unsigned char *verify_data = malloc(crl_data_len + 8);
    if (!verify_data) {
        printf("内存分配失败\n");
        free(response_data);
        return 0;
    }
    
    memcpy(verify_data, response_data, crl_data_len);
    // 时间戳使用网络字节序
    uint64_t ts_network = htobe64(timestamp);
    memcpy(verify_data + crl_data_len, &ts_network, 8);
    
    // 用CA公钥验证签名
    if (!sm2_verify(signature, verify_data, crl_data_len + 8, Q_ca)) {
        printf("CA签名验证失败！此CRL更新可能不是来自合法CA\n");
        free(verify_data);
        free(response_data);
        return 0;
    }
    
    free(verify_data);
    printf("CRL更新数据的签名验证成功\n");
    
    // 反序列化更新数据
    UpdatedCRL* updated_crl = CRLManager_deserialize_update(response_data, crl_data_len);
    if (!updated_crl) {
        printf("解析CRL更新数据失败\n");
        free(response_data);
        return 0;
    }
    
    printf("收到CRL更新：新增节点=%d, 删除节点=%d\n", 
           updated_crl->added_count, updated_crl->del_count);
    
    // 应用更新到本地CRL管理器和local_crl哈希表
    if (!CRLManager_apply_update(crl_manager, updated_crl, local_crl)) {
        printf("应用CRL更新失败\n");
        CRLManager_free_update(updated_crl);
        free(response_data);
        return 0;
    }
    CRLManager_free_update(updated_crl);
    free(response_data);
    
    // 保存更新后的CRL管理器
    if (!CRLManager_save_to_file(crl_manager, CRL_MANAGER_FILE)) {
        printf("保存更新后的CRL管理器失败\n");
        return 0;
    }
    
    printf("current_v:(%d,%d)\n", crl_manager->base_v, crl_manager->removed_v);
    
    return 1;
}

// 本地证书状态检查，1表示有效，0表示无效
int local_csp(const unsigned char *cert_hash) {
    return !check_cert_in_local_crl(cert_hash);
}

// 证书状态查询函数 - 先尝试在线查询，超时则使用本地查询，1表示有效，0表示无效
int online_csp(const unsigned char *cert_hash) {
    unsigned char *response_data = NULL;
    int response_len = 0;
    
    // 构建URL
    char url[100];
    sprintf(url, "http://%s:%d/cert_status", CA_IP, CA_PORT);
    
    // 发送证书哈希值到CA进行验证
    if (!http_send_request(url, cert_hash, CERT_HASH_SIZE, &response_data, &response_len)) {
        printf("发送证书验证请求失败，使用本地查询\n");
        return local_csp(cert_hash);
    }
    
    // 解析响应数据：状态(1字节) + 时间戳(8字节) + 签名(64字节)
    if (response_len != 1 + 8 + 64) {
        printf("接收到的数据长度错误: %d，使用本地查询\n", response_len);
        free(response_data);
        return local_csp(cert_hash);
    }
    
    // 提取状态和时间戳
    uint8_t status = response_data[0];
    uint64_t timestamp;
    memcpy(&timestamp, response_data + 1, 8);
    timestamp = be64toh(timestamp);
    
    if (!validate_timestamp(timestamp)) {
        printf("证书状态响应中的时间戳无效，使用本地查询\n");
        free(response_data);
        return local_csp(cert_hash);
    }
    
    // 验证CA签名
    // 签名数据：证书哈希 + 状态 + 时间戳
    unsigned char signed_data[CERT_HASH_SIZE + 1 + 8];
    memcpy(signed_data, cert_hash, CERT_HASH_SIZE);
    signed_data[CERT_HASH_SIZE] = status;
    uint64_t ts_network = htobe64(timestamp);
    memcpy(signed_data + CERT_HASH_SIZE + 1, &ts_network, 8);
    
    unsigned char signature[64];
    memcpy(signature, response_data + 1 + 8, 64);
    
    if (!sm2_verify(signature, signed_data, CERT_HASH_SIZE + 1 + 8, Q_ca)) {
        printf("CA签名验证失败！此响应可能不是来自合法CA，使用本地查询\n");
        free(response_data);
        return local_csp(cert_hash);
    }
    
    // 返回证书状态
    int cert_status = status;
    free(response_data);
    return cert_status;
}

int request_key_agreement()
{
    if (!loaded_cert) {
        printf("用户证书未加载\n");
        return -1;
    }
    //==================步骤一：用户A构造密钥协商请求 ====================
    BIGNUM *sA = NULL;
    EC_POINT *PA = NULL;
    
    int ret = 0;
    sA = BN_new();
    BN_rand_range(sA, order);
    
    // 计算PA=sA·G
    PA = EC_POINT_new(group);
    if (!EC_POINT_mul(group, PA, sA, NULL, NULL, NULL)) {
        printf("计算PA=sA·G失败\n");
        goto cleanup;
    }
    
    // 将PA转换为字节数组
    unsigned char PA_bytes[SM2_PUB_MAX_SIZE];
    int pa_len = EC_POINT_point2oct(group, PA, POINT_CONVERSION_UNCOMPRESSED, 
                                     PA_bytes, SM2_PUB_MAX_SIZE, NULL);
    
    // 生成时间戳T
    time_t now = time(NULL);
    uint64_t timestamp = (uint64_t)now;
    uint64_t ts_network = htobe64(timestamp);  // 转换为网络字节序
    
    // 计算数据大小
    int cert_base_size = sizeof(ImpCert) - sizeof(ImpCertExt*);
    int ext_size = 0;
    
    // 对于V2证书，要包含扩展信息
    if (loaded_cert->Version == CERT_V2 && loaded_cert->Extensions) {
        ext_size = sizeof(ImpCertExt);
    }
    
    // 构造认证消息MA={certA,PA,T}
    int ma_size = cert_base_size + ext_size + pa_len + 8;  // 证书 + 公钥PA + 时间戳
    unsigned char *ma_data = (unsigned char *)malloc(ma_size);
    if (!ma_data) {
        printf("内存分配失败\n");
        goto cleanup;
    }
    
    // 填充MA数据
    int offset = 0;
    // 填充证书基本信息
    memcpy(ma_data + offset, loaded_cert, cert_base_size);
    offset += cert_base_size;
    
    // 如果是V2证书，填充扩展信息
    if (loaded_cert->Version == CERT_V2 && loaded_cert->Extensions) {
        memcpy(ma_data + offset, loaded_cert->Extensions, sizeof(ImpCertExt));
        offset += sizeof(ImpCertExt);
    }
    
    // 填充PA
    memcpy(ma_data + offset, PA_bytes, pa_len);
    offset += pa_len;
    
    // 填充时间戳
    memcpy(ma_data + offset, &ts_network, 8);
    
    // 用私钥对MA进行签名
    unsigned char sig_A[64];
    if (!sm2_sign(sig_A, ma_data, ma_size, priv_key)) {
        printf("签名失败\n");
        free(ma_data);
        goto cleanup;
    }
    
    // 构造完整的发送数据：MA + 签名
    int total_size = ma_size + 64;  // MA + 64字节签名
    unsigned char *send_data = (unsigned char *)malloc(total_size);
    if (!send_data) {
        printf("内存分配失败\n");
        free(ma_data);
        goto cleanup;
    }
    
    // 复制MA和签名
    memcpy(send_data, ma_data, ma_size);
    memcpy(send_data + ma_size, sig_A, 64);
    free(ma_data);
    
    // 使用HTTP发送数据
    unsigned char *response_data = NULL;
    int response_len = 0;
    
    // 构建URL
    char url[100];
    sprintf(url, "http://%s:%d/key_agreement", CA_IP, CA_PORT);
    if (!http_send_request(url, send_data, total_size, &response_data, &response_len)) {
        printf("发送密钥协商请求失败\n");
        free(send_data);
        goto cleanup;
    }
    
    free(send_data);
    
    // ====================步骤二：接收提取{MB,签名,XB}====================
    EC_POINT *PB = NULL;
    EC_POINT *PAB = NULL;
    BIGNUM *xu = NULL;
    BIGNUM *yu = NULL;
    BIGNUM *pa_x = NULL;
    BIGNUM *pa_y = NULL;
    BIGNUM *pb_x = NULL;
    BIGNUM *pb_y = NULL;
    ImpCert *b_cert = NULL;
    EC_POINT *Pu = NULL;
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    unsigned char cert_hash[32];
    ImpCertExt *cert_ext = NULL;
    
    if (response_len <= 0) {
        printf("密钥协商响应无效\n");
        goto cleanup;
    }
    
    // 解析响应：MB数据包含：证书 + PB + 时间戳，验证证书的基本结构大小
    if (response_len < cert_base_size + SM2_PUB_MAX_SIZE + 8 + 64 + 32) {
        printf("响应数据长度不足\n");
        goto cleanup;
    }

    b_cert = (ImpCert *)malloc(sizeof(ImpCert));
    if (!b_cert) {
        printf("内存分配失败\n");
        goto cleanup;
    }
    // 解析MB中的证书信息    
    memcpy(b_cert, response_data, cert_base_size);
    b_cert->Extensions = NULL;
    
    // 确定证书版本和扩展信息偏移量
    offset = cert_base_size;
    ext_size = 0;
    // 对于V2证书，处理扩展信息
    if (b_cert->Version == CERT_V2) {
        if (response_len < offset + sizeof(ImpCertExt) + SM2_PUB_MAX_SIZE + 8 + 64 + 32) {
            printf("响应数据长度不足，无法解析V2证书扩展信息\n");
            goto cleanup;
        }
        
        cert_ext = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!cert_ext) {
            printf("扩展信息内存分配失败\n");
            goto cleanup;
        }
        
        memcpy(cert_ext, response_data + offset, sizeof(ImpCertExt));
        b_cert->Extensions = cert_ext;
        ext_size = sizeof(ImpCertExt);
        offset += ext_size;
    }
    
    // 提取PB
    PB = EC_POINT_new(group);
    if (!PB || !EC_POINT_oct2point(group, PB, response_data + offset, SM2_PUB_MAX_SIZE, NULL)) {
        printf("解析PB失败\n");
        goto cleanup;
    }
    
    offset += SM2_PUB_MAX_SIZE;
    
    // 提取时间戳
    uint64_t timestamp_B;
    memcpy(&timestamp_B, response_data + offset, 8);
    timestamp_B = be64toh(timestamp_B); // 网络字节序转为主机字节序
    offset += 8;

    //==================== 步骤三：验证用户B的合法性 ====================
    // 验证时间戳
    if (!validate_timestamp(timestamp_B)) {
        printf("响应中的时间戳无效\n");
        goto cleanup;
    }
    
    // 验证证书有效性
    if (!validate_cert(b_cert)) {
        printf("证书已过期，拒绝密钥协商请求\n");
        goto cleanup;
    }

    // 查询证书是否在撤销列表中
    calc_cert_hash(b_cert, cert_hash);
    if (online_csp(cert_hash)==0) {
        printf("证书已被撤销，拒绝密钥协商请求\n");
        goto cleanup;
    }

    // 验证签名
    Pu = EC_POINT_new(group);
    getPu(b_cert, Pu);
    // 重构用户公钥 Qu = e*Pu + Q_ca
    // print_hex("e", cert_hash, 32);
    unsigned char Pu_bytes[SM2_PUB_MAX_SIZE];
    EC_POINT_point2oct(group, Pu, POINT_CONVERSION_UNCOMPRESSED, Pu_bytes, SM2_PUB_MAX_SIZE, NULL);
    // print_hex("Pu", Pu_bytes, SM2_PUB_MAX_SIZE);
    
    if(!rec_pubkey(Qu, cert_hash, Pu, Q_ca)) {
        printf("重构用户公钥失败\n");
        goto cleanup;
    }
    // print_hex("Qu", Qu, SM2_PUB_MAX_SIZE);
    // 计算MB大小
    int mb_size = offset;
    
    // 提取签名
    unsigned char sig_B[64];
    memcpy(sig_B, response_data + mb_size, 64);
    
    // 验证签名
    if (!sm2_verify(sig_B, response_data, mb_size, Qu)) {
        printf("用户B的签名验证失败\n");
        goto cleanup;
    }
    
    // 提取XB
    unsigned char XB[32];
    memcpy(XB, response_data + mb_size + 64, 32);
    
    // 计算共享点PAB = PB·sA
    PAB = EC_POINT_new(group);
    if (!PAB || !EC_POINT_mul(group, PAB, NULL, PB, sA, NULL)) {
        printf("计算共享点PAB=PB·sA失败\n");
        goto cleanup;
    }
    
    // 提取共享点坐标
    xu = BN_new();
    yu = BN_new();
    if (!xu || !yu || !EC_POINT_get_affine_coordinates(group, PAB, xu, yu, NULL)) {
        printf("获取共享点坐标失败\n");
        goto cleanup;
    }
    
    // 将坐标转换为字节数组
    unsigned char xu_bytes[32] = {0};
    unsigned char yu_bytes[32] = {0};
    BN_bn2bin(xu, xu_bytes + (32 - BN_num_bytes(xu)));
    BN_bn2bin(yu, yu_bytes + (32 - BN_num_bytes(yu)));
    
    // 计算SM3(xu)
    unsigned char sm3_xu[32];
    sm3_hash(xu_bytes, 32, sm3_xu);
    
    // 提取PA和PB的坐标
    unsigned char PA_x_bytes[32] = {0};
    unsigned char PA_y_bytes[32] = {0};
    unsigned char PB_x_bytes[32] = {0};
    unsigned char PB_y_bytes[32] = {0};
    
    // 提取PA的坐标
    pa_x = BN_new();
    pa_y = BN_new();
    if (!pa_x || !pa_y || !EC_POINT_get_affine_coordinates(group, PA, pa_x, pa_y, NULL)) {
        printf("获取PA坐标失败\n");
        goto cleanup;
    }
    BN_bn2bin(pa_x, PA_x_bytes + (32 - BN_num_bytes(pa_x)));
    BN_bn2bin(pa_y, PA_y_bytes + (32 - BN_num_bytes(pa_y)));
    
    // 提取PB的坐标
    pb_x = BN_new();
    pb_y = BN_new();
    if (!pb_x || !pb_y || !EC_POINT_get_affine_coordinates(group, PB, pb_x, pb_y, NULL)) {
        printf("获取PB坐标失败\n");
        goto cleanup;
    }
    BN_bn2bin(pb_x, PB_x_bytes + (32 - BN_num_bytes(pb_x)));
    BN_bn2bin(pb_y, PB_y_bytes + (32 - BN_num_bytes(pb_y)));
    
    // 验证XB
    // 构造XB计算数据：XB=SM3(0x02||yu||SM3(xu)||PAx||PAy||PBx||PBy)
    unsigned char xb_data[1 + 32 + 32 + 32*4];
    xb_data[0] = 0x02;
    memcpy(xb_data + 1, yu_bytes, 32);
    memcpy(xb_data + 1 + 32, sm3_xu, 32);
    memcpy(xb_data + 1 + 32 + 32, PA_x_bytes, 32);
    memcpy(xb_data + 1 + 32 + 32 + 32, PA_y_bytes, 32);
    memcpy(xb_data + 1 + 32 + 32 + 32 + 32, PB_x_bytes, 32);
    memcpy(xb_data + 1 + 32 + 32 + 32 + 32 + 32, PB_y_bytes, 32);
    
    // 重新计算XB并验证
    unsigned char calc_XB[32];
    sm3_hash(xb_data, sizeof(xb_data), calc_XB);
    
    // 比较计算出的XB与接收到的XB
    if (memcmp(XB, calc_XB, 32) != 0) {
        printf("密钥确认值XB验证失败\n");
        goto cleanup;
    }
    
    // printf("密钥确认值XB验证成功\n");

    /* --------- 生成并保存会话密钥 --------- */
    {
        unsigned char Z[32 + 32 + 4 + 4];
        memcpy(Z, xu_bytes, 32);
        memcpy(Z + 32, yu_bytes, 32);
        memcpy(Z + 64, loaded_cert->SubjectID, 4);         /* ID_A */
        memcpy(Z + 68, b_cert->IssuerID, 4);               /* ID_B = CA ID */
        unsigned char sess_key[SESSION_KEY_LEN];
        if (!sm3_kdf(Z, sizeof(Z), sess_key, SESSION_KEY_LEN)) {
            printf("SM3 KDF失败\n");
            goto cleanup;
        }
        char id_str[5];
        memcpy(id_str, b_cert->SubjectID, 4);
        id_str[4] = '\0';
        session_key_put(session_map, id_str, sess_key);
        SessionKey *t_key = session_key_get(session_map, id_str);
        printf("和%s的会话密钥为：", id_str);
        if (t_key) print_hex("key", t_key->key, SESSION_KEY_LEN);
        ret = 1;
    }
    
cleanup:
    if (sA) BN_free(sA);
    if (PA) EC_POINT_free(PA);
    if (PB) EC_POINT_free(PB);
    if (PAB) EC_POINT_free(PAB);
    if (xu) BN_free(xu);
    if (yu) BN_free(yu);
    if (pa_x) BN_free(pa_x);
    if (pa_y) BN_free(pa_y);
    if (pb_x) BN_free(pb_x);
    if (pb_y) BN_free(pb_y);
    if (Pu) EC_POINT_free(Pu);
    if (b_cert) free_cert(b_cert);
    if (response_data) free(response_data);
    
    return ret;
}
