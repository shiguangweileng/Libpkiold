#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "mongoose.h"

#define PORT "8888"
// 由于在main中执行了chdir(".."), 路径需要从libpki根目录开始
#define USERLIST_FILE "server/ca-server/UserList.txt"
#define CRL_FILE "server/ca-server/CRL.txt"
#define USERCERTS_DIR "server/ca-server/UserCerts"
#define POLL_INTERVAL_MS 1000  // 文件检查间隔(毫秒)

// 文件修改时间
time_t userlist_mtime = 0;
time_t crl_mtime = 0;
char *userlist_json = NULL;
char *crl_json = NULL;

// 获取文件修改时间
time_t get_file_mtime(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

// 为UserList生成JSON数据
char* generate_userlist_json() {
    FILE *file = fopen(USERLIST_FILE, "r");
    if (!file) {
        printf("错误：无法打开UserList文件：%s\n", USERLIST_FILE);
        return strdup("{\"error\":\"无法打开UserList文件\"}");
    }
    
    // 为JSON字符串分配初始内存
    size_t capacity = 1024;
    char *json = (char*)malloc(capacity);
    if (!json) {
        fclose(file);
        return strdup("{\"error\":\"内存分配失败\"}");
    }
    
    // 初始化JSON数组
    strcpy(json, "{\"users\":[");
    size_t json_len = strlen(json);
    
    char line[256];
    int first_user = 1;
    int count = 0;
    
    while (fgets(line, sizeof(line), file)) {
        // 移除换行符
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        // 确保行长度足够
        if (strlen(line) < 10) {
            printf("跳过行：长度不足\n");
            continue;
        }
        
        char user_id[9] = {0};
        strncpy(user_id, line, 8);
        
        // 提取哈希值
        char hash_hex[65] = {0};
        strncpy(hash_hex, line + 9, 64);
        
        // 扩展JSON缓冲区（如果需要）
        size_t required_len = json_len + 128 + strlen(user_id) + strlen(hash_hex);
        if (required_len > capacity) {
            capacity *= 2;
            char *new_json = (char*)realloc(json, capacity);
            if (!new_json) {
                free(json);
                fclose(file);
                return strdup("{\"error\":\"内存分配失败\"}");
            }
            json = new_json;
        }
        
        // 添加逗号（除第一个用户外）
        if (!first_user) {
            strcat(json, ",");
            json_len++;
        } else {
            first_user = 0;
        }
        
        // 添加用户条目
        json_len += sprintf(json + json_len, 
                           "{\"id\":\"%s\",\"hash\":\"%s\"}", 
                           user_id, hash_hex);
        count++;
    }
    
    // 完成JSON
    strcat(json, "]}");
    
    printf("成功读取UserList文件，总共%d条记录\n", count);
    fclose(file);
    return json;
}

// 为CRL生成JSON数据
char* generate_crl_json() {
    FILE *file = fopen(CRL_FILE, "r");
    if (!file) {
        printf("错误：无法打开CRL文件：%s\n", CRL_FILE);
        return strdup("{\"error\":\"无法打开CRL文件\"}");
    }
    
    // 为JSON字符串分配初始内存
    size_t capacity = 1024;
    char *json = (char*)malloc(capacity);
    if (!json) {
        fclose(file);
        return strdup("{\"error\":\"内存分配失败\"}");
    }
    
    // 初始化JSON数组
    strcpy(json, "{\"revoked_certs\":[");
    size_t json_len = strlen(json);
    
    char line[256];
    int first_cert = 1;
    int cert_counter = 0;
    
    while (fgets(line, sizeof(line), file)) {
        // 移除换行符
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        // 确保哈希值长度为64个字符
        if (strlen(line) != 64) {
            printf("跳过CRL条目：长度不为64\n");
            continue;
        }
        
        // 读取下一行以获取到期时间
        time_t expire_time = 0;
        if (fgets(line + 128, sizeof(line) - 128, file)) {
            newline = strchr(line + 128, '\n');
            if (newline) *newline = '\0';
            sscanf(line + 128, "%ld", &expire_time);
        } else {
            // 如果没有下一行，跳过此条目
            printf("跳过CRL条目：缺少到期时间\n");
            continue;
        }
        
        // 扩展JSON缓冲区（如果需要）
        size_t required_len = json_len + 120 + strlen(line);
        if (required_len > capacity) {
            capacity *= 2;
            char *new_json = (char*)realloc(json, capacity);
            if (!new_json) {
                free(json);
                fclose(file);
                return strdup("{\"error\":\"内存分配失败\"}");
            }
            json = new_json;
        }
        
        // 添加逗号（除第一个证书外）
        if (!first_cert) {
            strcat(json, ",");
            json_len++;
        } else {
            first_cert = 0;
        }
        
        // 添加证书条目，包括到期时间
        cert_counter++;
        json_len += sprintf(json + json_len, 
                           "{\"id\":%d,\"hash\":\"%s\",\"expire_time\":%ld}", 
                           cert_counter, line, expire_time);
    }
    
    // 完成JSON
    strcat(json, "]}");
    
    printf("成功读取CRL文件，总共%d条记录\n", cert_counter);
    fclose(file);
    return json;
}

// 清理过期证书
char* clean_expired_certs() {
    FILE *file = fopen(CRL_FILE, "r");
    if (!file) {
        return strdup("{\"error\":\"无法打开CRL文件\",\"success\":false}");
    }
    
    // 创建临时文件
    char temp_file[256];
    sprintf(temp_file, "%s.tmp", CRL_FILE);
    FILE *temp = fopen(temp_file, "w");
    if (!temp) {
        fclose(file);
        return strdup("{\"error\":\"无法创建临时文件\",\"success\":false}");
    }
    
    char line[256];
    time_t current_time = time(NULL);
    int total_count = 0;
    int cleaned_count = 0;
    
    while (fgets(line, sizeof(line), file)) {
        // 移除换行符
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        // 确保哈希值长度为64个字符
        if (strlen(line) != 64) {
            printf("清理时跳过CRL条目：长度不为64\n");
            continue;
        }
        
        // 读取下一行以获取到期时间
        char expire_line[256];
        time_t expire_time = 0;
        if (fgets(expire_line, sizeof(expire_line), file)) {
            newline = strchr(expire_line, '\n');
            if (newline) *newline = '\0';
            sscanf(expire_line, "%ld", &expire_time);
        } else {
            printf("清理时跳过CRL条目：缺少到期时间\n");
            continue;
        }
        
        total_count++;
        
        // 如果证书未过期，保留到新文件
        if (expire_time > current_time) {
            fprintf(temp, "%s\n%s\n", line, expire_line);
        } else {
            cleaned_count++;
            printf("清理过期证书：%s\n", line);
        }
    }
    
    fclose(file);
    fclose(temp);
    
    // 替换原始文件
    if (remove(CRL_FILE) != 0) {
        printf("无法删除原始CRL文件\n");
        remove(temp_file);
        return strdup("{\"error\":\"无法删除原始文件\",\"success\":false}");
    }
    
    if (rename(temp_file, CRL_FILE) != 0) {
        printf("无法重命名临时文件\n");
        return strdup("{\"error\":\"无法重命名临时文件\",\"success\":false}");
    }
    
    // 返回结果JSON
    char *result = (char*)malloc(256);
    if (result) {
        sprintf(result, "{\"success\":true,\"total_count\":%d,\"cleaned_count\":%d}", 
                total_count, cleaned_count);
    } else {
        result = strdup("{\"success\":true}");
    }
    
    return result;
}

// 读取证书文件并生成JSON响应
char* get_cert_json(const char *user_id) {
    char cert_path[512];
    snprintf(cert_path, sizeof(cert_path), "%s/%s.crt", USERCERTS_DIR, user_id);
    
    // 检查文件是否存在
    struct stat st;
    if (stat(cert_path, &st) != 0) {
        printf("证书文件不存在: %s\n", cert_path);
        return strdup("{\"error\":\"证书文件不存在\"}");
    }
    
    // 打开证书文件
    FILE *cert_file = fopen(cert_path, "rb");
    if (!cert_file) {
        printf("无法打开证书文件: %s\n", cert_path);
        return strdup("{\"error\":\"无法打开证书文件\"}");
    }
    
    // 读取证书结构体
    typedef struct {
        unsigned char SerialNum[9];  // 证书序列号
        unsigned char IssuerID[9];   // 颁发者ID
        unsigned char SubjectID[9];  // 主体ID
        unsigned char Validity[16];  // 有效期: 前8字节开始时间，后8字节结束时间
        unsigned char PubKey[33];    // 公钥
    } ImpCert;
    
    ImpCert cert;
    size_t read_size = fread(&cert, 1, sizeof(ImpCert), cert_file);
    fclose(cert_file);
    
    if (read_size != sizeof(ImpCert)) {
        printf("证书文件读取错误: %s\n", cert_path);
        return strdup("{\"error\":\"证书文件读取错误\"}");
    }
    
    // 确保字符串以NULL结尾
    cert.SerialNum[8] = '\0';
    cert.IssuerID[8] = '\0';
    cert.SubjectID[8] = '\0';
    
    // 提取时间信息
    time_t start_time, end_time;
    memcpy(&start_time, cert.Validity, sizeof(time_t));
    memcpy(&end_time, cert.Validity + sizeof(time_t), sizeof(time_t));
    
    // 将公钥转换为十六进制字符串
    char pubkey_hex[100] = {0};
    for (size_t i = 0; i < 33 && i < sizeof(cert.PubKey); i++) {
        sprintf(pubkey_hex + i*2, "%02x", cert.PubKey[i]);
    }
    
    // 创建JSON响应
    char *json = (char*)malloc(1024);
    if (!json) {
        return strdup("{\"error\":\"内存分配失败\"}");
    }
    
    sprintf(json, 
            "{\"serial_num\":\"%s\",\"issuer_id\":\"%s\",\"subject_id\":\"%s\","
            "\"start_time\":%ld,\"end_time\":%ld,\"pub_key\":\"%s\"}",
            cert.SerialNum, cert.IssuerID, cert.SubjectID,
            start_time, end_time, pubkey_hex);
    
    return json;
}

// 检查文件是否被修改，如果是则更新JSON缓存
void check_files_update() {
    time_t new_userlist_mtime = get_file_mtime(USERLIST_FILE);
    time_t new_crl_mtime = get_file_mtime(CRL_FILE);
    
    // 在首次运行时输出文件信息
    static int first_run = 1;
    if (first_run) {
        
        if (new_userlist_mtime == 0) {
            printf("警告: 无法获取UserList文件信息，文件可能不存在\n");
        }
        if (new_crl_mtime == 0) {
            printf("警告: 无法获取CRL文件信息，文件可能不存在\n");
        }
        first_run = 0;
    }
    
    // 检查UserList文件
    if (new_userlist_mtime != userlist_mtime) {
        userlist_mtime = new_userlist_mtime;
        if (userlist_json) free(userlist_json);
        userlist_json = generate_userlist_json();
    }
    
    // 检查CRL文件
    if (new_crl_mtime != crl_mtime) {
        crl_mtime = new_crl_mtime;
        if (crl_json) free(crl_json);
        crl_json = generate_crl_json();
    }
}

// HTTP事件处理函数 - 修改为符合要求的签名
static void http_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        struct mg_http_serve_opts opts = {
            .root_dir = "webmonitor",  // 设置为webmonitor目录
            .mime_types = "css=text/css,js=application/javascript,html=text/html"
        };

        // 处理API请求
        if (mg_match(hm->uri, mg_str("/api/users"), NULL)) {
            // 检查文件是否有更新
            check_files_update();
            // 发送用户列表数据
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", userlist_json);
        }
        else if (mg_match(hm->uri, mg_str("/api/crl"), NULL)) {
            // 检查文件是否有更新
            check_files_update();
            // 发送CRL数据
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", crl_json);
        }
        else if (mg_match(hm->uri, mg_str("/api/clean-crl"), NULL)) {
            // 处理清理CRL的请求（仅接受POST方法）
            if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
                // 执行清理操作
                char *result = clean_expired_certs();
                mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", result);
                free(result);
                
                // 更新CRL缓存
                if (crl_json) free(crl_json);
                crl_json = generate_crl_json();
            } else {
                // 非POST请求返回405
                mg_http_reply(c, 405, "", "Method Not Allowed");
            }
        }
        else if (mg_match(hm->uri, mg_str("/api/cert"), NULL)) {
            // 处理获取证书详情请求
            char user_id[10] = {0};
            if (mg_http_get_var(&hm->query, "id", user_id, sizeof(user_id)) > 0) {
                // 获取证书JSON
                char *cert_json = get_cert_json(user_id);
                mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", cert_json);
                free(cert_json);
            } else {
                mg_http_reply(c, 400, "", "Missing user ID parameter");
            }
        }
        // 处理根路径"/"请求，直接提供index.html
        else if (mg_match(hm->uri, mg_str("/"), NULL)) {
            // 重定向到index.html
            mg_http_reply(c, 302, "Location: /index.html\r\n", "");
        }
        else {
            // 静态文件
            mg_http_serve_dir(c, hm, &opts);
        }
    }
}

// 定时器回调函数，用于定期检查文件更新
void timer_callback(void *arg) {
    (void) arg;  // 消除未使用参数警告
    check_files_update();
}

int main(void) {
    struct mg_mgr mgr;
    struct mg_connection *c;
    char listen_addr[128];
    
    // 初始化mongoose管理器
    mg_mgr_init(&mgr);
    
    // 绑定HTTP监听器到8888端口
    snprintf(listen_addr, sizeof(listen_addr), "http://0.0.0.0:%s", PORT);
    // 确保工作目录在libpki根目录
    chdir("..");  // 回到上一层目录(libpki目录)
    c = mg_http_listen(&mgr, listen_addr, http_handler, NULL);
    if (c == NULL) {
        printf("无法启动服务器在端口 %s\n", PORT);
        return 1;
    }
    
    // 初始化JSON数据
    check_files_update();
    
    printf("Web监控服务器正在运行，端口: %s\n", PORT);
    printf("请在浏览器中访问: http://localhost:%s/\n", PORT);
    
    // 设置定时器，定期检查文件更新
    mg_timer_add(&mgr, POLL_INTERVAL_MS, MG_TIMER_REPEAT, timer_callback, NULL);
    
    // 服务器事件循环
    for (;;) {
        mg_mgr_poll(&mgr, 1000);  // 每秒轮询一次事件
    }
    
    // 释放资源
    if (userlist_json) free(userlist_json);
    if (crl_json) free(crl_json);
    mg_mgr_free(&mgr);
    
    return 0;
}
