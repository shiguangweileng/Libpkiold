#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "common.h"
#include "gm_crypto.h"
#include "imp_cert.h"
#include "network.h"
#include "user.h"

// CA服务器配置
#define CA_SERVER_IP "127.0.0.1"

// 存储相关信息的全局变量
ImpCert loaded_cert;
hashmap* local_crl = NULL;                  // 本地CRL哈希表，只存储证书哈希值
CRLManager* crl_manager = NULL;
unsigned char priv_key[SM2_PRI_MAX_SIZE];
unsigned char pub_key[SM2_PUB_MAX_SIZE];
unsigned char Q_ca[SM2_PUB_MAX_SIZE];
int has_cert = 0;

// 保存撤销的证书哈希用于后续测试
unsigned char revoked_cert_hash[SM3_MD_SIZE];
int has_revoked_hash = 0;

// 函数声明
int load_cert_only(const char *user_id, ImpCert *cert);

// 时间测量函数
void start_timer(struct timeval *start_time) {
    gettimeofday(start_time, NULL);
}

double end_timer(struct timeval *start_time) {
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    return (end_time.tv_sec - start_time->tv_sec) * 1000.0 + 
           (end_time.tv_usec - start_time->tv_usec) / 1000.0;
}

// 测试10个用户注册并记录时间
int test_multi_user_registration() {
    int sock;
    int result;
    struct timeval start_time;
    double elapsed_ms;
    int success_count = 0;
    char user_id[SUBJECT_ID_SIZE];
    
    printf("\n===== 多用户注册测试 =====\n");
    printf("将注册10个用户 (U0000001-U0000010)\n\n");
    
    // 循环注册10个用户
    for (int i = 1; i <= 10; i++) {
        // 构造用户ID
        snprintf(user_id, SUBJECT_ID_SIZE, "U%07d", i);
        
        printf("正在注册用户 %s...\n", user_id);
        
        // 开始计时（在连接前）
        start_timer(&start_time);
        
        // 连接到服务器
        sock = connect_to_server(CA_SERVER_IP, PORT);
        if (sock < 0) {
            printf("无法连接到服务器，请确保CA服务器正在运行\n");
            return 0;
        }
        
        // 执行证书注册
        result = request_registration(sock, user_id);
        
        // 关闭连接
        close(sock);
        
        // 结束计时
        elapsed_ms = end_timer(&start_time);
        
        // 输出结果
        if (result) {
            printf("用户 %s 注册成功，耗时: %.2fms\n", user_id, elapsed_ms);
            success_count++;
        } else {
            printf("用户 %s 注册失败\n", user_id);
        }
        
        // 短暂等待，避免服务器负载过高
        usleep(100000);  // 等待0.1秒
    }
    
    printf("\n成功注册用户数: %d/10\n", success_count);
    return success_count;
}

// 测试用户证书更新10次
int test_user_cert_update() {
    int sock;
    int result;
    struct timeval start_time;
    double elapsed_ms;
    int success_count = 0;
    char user_id[SUBJECT_ID_SIZE] = "U0000002"; // 固定使用02用户
    
    printf("\n===== 用户证书更新测试 =====\n");
    printf("用户 %s 将进行10次证书更新\n\n", user_id);
    
    // 首先尝试加载证书，如果不存在则先注册
    has_cert = load_keys_and_cert(user_id);
    if (!has_cert) {
        printf("用户 %s 证书不存在，先进行注册...\n", user_id);
        
        // 连接到服务器
        sock = connect_to_server(CA_SERVER_IP, PORT);
        if (sock < 0) {
            printf("无法连接到服务器，请确保CA服务器正在运行\n");
            return 0;
        }
        
        // 执行证书注册
        result = request_registration(sock, user_id);
        close(sock);
        
        if (!result) {
            printf("用户 %s 注册失败，无法进行更新测试\n", user_id);
            return 0;
        }
        
        // 加载新注册的证书
        has_cert = load_keys_and_cert(user_id);
        if (!has_cert) {
            printf("用户 %s 证书加载失败，无法进行更新测试\n", user_id);
            return 0;
        }
        
        printf("用户 %s 注册成功，证书已加载\n", user_id);
    }
    
    // 循环更新10次
    for (int i = 1; i <= 10; i++) {
        printf("正在进行第 %d 次证书更新...\n", i);
        
        // 开始计时（在连接前）
        start_timer(&start_time);
        
        // 连接到服务器
        sock = connect_to_server(CA_SERVER_IP, PORT);
        if (sock < 0) {
            printf("无法连接到服务器，请确保CA服务器正在运行\n");
            return success_count;
        }
        
        // 执行证书更新
        result = request_cert_update(sock, user_id);
        
        // 关闭连接
        close(sock);
        
        // 结束计时
        elapsed_ms = end_timer(&start_time);
        
        // 输出结果
        if (result) {
            printf("第 %d 次更新成功，耗时: %.2fms\n", i, elapsed_ms);
            success_count++;
            
            // 重新加载更新后的证书
            has_cert = load_keys_and_cert(user_id);
            if (!has_cert) {
                printf("警告：证书已更新但无法加载\n");
            }
        } else {
            printf("第 %d 次更新失败\n", i);
        }
        
        // 短暂等待，避免服务器负载过高
        usleep(100000);  // 等待0.1秒
    }
    
    printf("\n成功更新次数: %d/10\n", success_count);
    return success_count;
}

// 测试用户证书撤销
int test_cert_revocation() {
    int sock;
    int result;
    struct timeval start_time;
    double elapsed_ms;
    char user_id[SUBJECT_ID_SIZE] = "U0000003"; // 固定使用03用户
    
    printf("\n===== 用户证书撤销测试 =====\n");
    printf("用户 %s 将申请证书撤销\n\n", user_id);
    
    // 首先尝试加载证书，如果不存在则先注册
    has_cert = load_keys_and_cert(user_id);
    if (!has_cert) {
        printf("用户 %s 证书不存在，先进行注册...\n", user_id);
        
        // 连接到服务器
        sock = connect_to_server(CA_SERVER_IP, PORT);
        if (sock < 0) {
            printf("无法连接到服务器，请确保CA服务器正在运行\n");
            return 0;
        }
        
        // 执行证书注册
        result = request_registration(sock, user_id);
        close(sock);
        
        if (!result) {
            printf("用户 %s 注册失败，无法进行撤销测试\n", user_id);
            return 0;
        }
        
        // 加载新注册的证书
        has_cert = load_keys_and_cert(user_id);
        if (!has_cert) {
            printf("用户 %s 证书加载失败，无法进行撤销测试\n", user_id);
            return 0;
        }
        
        printf("用户 %s 注册成功，证书已加载\n", user_id);
    }
    
    // 获取证书哈希值用于后续比对
    unsigned char cert_hash[SM3_MD_SIZE];
    if (!sm3_hash((const unsigned char *)&loaded_cert, sizeof(ImpCert), cert_hash)) {
        printf("计算证书哈希值失败\n");
        return 0;
    }
    
    // 保存证书哈希值用于后续测试
    memcpy(revoked_cert_hash, cert_hash, SM3_MD_SIZE);
    has_revoked_hash = 1;
    
    printf("证书哈希值: ");
    for (int i = 0; i < SM3_MD_SIZE; i++) {
        printf("%02x", cert_hash[i]);
    }
    printf("\n");
    
    // 开始计时
    start_timer(&start_time);
    
    // 连接到服务器
    sock = connect_to_server(CA_SERVER_IP, PORT);
    if (sock < 0) {
        printf("无法连接到服务器，请确保CA服务器正在运行\n");
        return 0;
    }
    
    // 执行证书撤销
    result = request_cert_revoke(sock, user_id);
    
    // 关闭连接
    close(sock);
    
    // 结束计时
    elapsed_ms = end_timer(&start_time);
    
    // 输出结果
    if (result) {
        printf("证书撤销成功，耗时: %.2fms\n", elapsed_ms);
        return 1;
    } else {
        printf("证书撤销失败\n");
        return 0;
    }
}

// 测试证书状态比对和CRL同步
int test_cert_status_check() {
    int sock;
    int result;
    int online_status,local_status;
    struct timeval start_time;
    double elapsed_ms;
    char checker_id[SUBJECT_ID_SIZE] = "U0000001"; // 使用01用户进行检查
    char target_id[SUBJECT_ID_SIZE] = "U0000003";  // 检查03用户的证书
    
    printf("\n===== 证书状态比对和CRL同步测试 =====\n");
    printf("用户 %s 将检查用户 %s 的证书状态\n\n", checker_id, target_id);
    
    // 加载检查者的证书
    has_cert = load_keys_and_cert(checker_id);
    if (!has_cert) {
        printf("用户 %s 证书不存在，无法进行检查\n", checker_id);
        return 0;
    }
    
    // 检查是否有保存的被撤销证书哈希值
    if (!has_revoked_hash) {
        printf("没有可用的被撤销证书哈希值，无法进行测试\n");
        return 0;
    }
    
    printf("使用之前保存的证书哈希值: ");
    for (int i = 0; i < SM3_MD_SIZE; i++) {
        printf("%02x", revoked_cert_hash[i]);
    }
    printf("\n");
    
    // 第一次在线+本地证书状态查询
    start_timer(&start_time);
    sock = connect_to_server(CA_SERVER_IP, PORT);
    if (sock < 0) {
        printf("无法连接到服务器，请确保CA服务器正在运行\n");
        return 0;
    }
    online_status = online_csp(sock, revoked_cert_hash);
    if (online_status >= 0) {
        printf("online_csp:%s\n", online_status ? "有效" : "无效（已撤销）");
    } else {
        printf("online_csp: 查询失败\n");
    }
    close(sock);
    local_status = local_csp(revoked_cert_hash);
    printf("local_csp:%s\n", local_status ? "有效" : "无效（已撤销）");
    elapsed_ms = end_timer(&start_time);
    printf("耗时: %.2fms\n", elapsed_ms);
    
    // 同步CRL
    printf("\n正在与CA服务器同步CRL...\n");
    sock = connect_to_server(CA_SERVER_IP, PORT);
    if (sock < 0) {
        printf("无法连接到服务器，请确保CA服务器正在运行\n");
        return 0;
    }
    start_timer(&start_time);
    result = sync_crl_with_ca(sock);
    elapsed_ms = end_timer(&start_time);
    close(sock);
    
    if (result) {
        printf("CRL同步成功，耗时: %.2fms\n", elapsed_ms);
    } else {
        printf("CRL同步失败，耗时: %.2fms\n", elapsed_ms);
        return 0;
    }
    
    // 第二次在线+本地证书状态查询
    start_timer(&start_time);
    sock = connect_to_server(CA_SERVER_IP, PORT);
    if (sock < 0) {
        printf("无法连接到服务器，请确保CA服务器正在运行\n");
        return 0;
    }
    online_status = online_csp(sock, revoked_cert_hash);
    if (online_status >= 0) {
        printf("online_csp:%s\n", online_status ? "有效" : "无效（已撤销）");
    } else {
        printf("online_csp: 查询失败\n");
    }
    close(sock);
    local_status = local_csp(revoked_cert_hash);
    printf("local_csp:%s\n", local_status ? "有效" : "无效（已撤销）");
    elapsed_ms = end_timer(&start_time);
    printf("耗时: %.2fms\n", elapsed_ms);
}

// 从文件中仅加载证书，不加载私钥
int load_cert_only(const char *user_id, ImpCert *cert) {
    char cert_file[256];
    snprintf(cert_file, sizeof(cert_file), "UserCerts/%s_cert.bin", user_id);
    return load_cert(cert, cert_file);
}

int main() {
    // 初始化SM2参数
    if (!sm2_params_init()) {
        printf("SM2参数初始化失败\n");
        return -1;
    }
    
    // 初始化CA公钥
    if (!User_init(Q_ca)) {
        printf("加载CA公钥失败\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 初始化CRL管理器
    if (!init_crl_manager()) {
        printf("初始化CRL管理器失败\n");
        sm2_params_cleanup();
        return -1;
    }
    
    // 执行多用户注册测试
    test_multi_user_registration();
    
    // 执行用户证书更新测试
    test_user_cert_update();
    
    // 执行用户证书撤销测试
    test_cert_revocation();
    
    // 执行证书状态比对和CRL同步测试
    test_cert_status_check();
    
    // 清理资源
    sm2_params_cleanup();
    return 0;
}
