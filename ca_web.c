#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <json-c/json.h>

#define PORT 8888

// 处理CORS预检请求
static int handle_cors_preflight(struct MHD_Connection *connection) {
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
static int handle_user_list(struct MHD_Connection *connection) {
    struct json_object *response_obj = json_object_new_array();
    
    // 添加示例用户数据
    for (int i = 0; i < 5; i++) {
        struct json_object *user = json_object_new_object();
        char id[10], name[20], email[30];
        
        sprintf(id, "user%d", i + 1);
        sprintf(name, "用户%d", i + 1);
        sprintf(email, "user%d@example.com", i + 1);
        
        json_object_object_add(user, "id", json_object_new_string(id));
        json_object_object_add(user, "name", json_object_new_string(name));
        json_object_object_add(user, "email", json_object_new_string(email));
        json_object_object_add(user, "status", json_object_new_string("有效"));
        json_object_object_add(user, "created_at", json_object_new_string("2023-10-15"));
        
        json_object_array_add(response_obj, user);
    }
    
    const char *response_str = json_object_to_json_string(response_obj);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(response_str), (void*)response_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, OPTIONS");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(response_obj);
    
    return ret;
}

// 处理证书撤销列表请求
static int handle_crl_list(struct MHD_Connection *connection) {
    struct json_object *response_obj = json_object_new_array();
    
    // 添加示例CRL数据
    for (int i = 0; i < 5; i++) {
        struct json_object *crl = json_object_new_object();
        char serial[20], subject[40];
        
        sprintf(serial, "SN%08X", 10000 + i);
        sprintf(subject, "CN=测试证书%d,O=测试组织,C=CN", i + 1);
        
        json_object_object_add(crl, "serial", json_object_new_string(serial));
        json_object_object_add(crl, "subject", json_object_new_string(subject));
        json_object_object_add(crl, "revoke_date", json_object_new_string("2023-11-20"));
        json_object_object_add(crl, "reason", json_object_new_string("密钥泄露"));
        
        json_object_array_add(response_obj, crl);
    }
    
    const char *response_str = json_object_to_json_string(response_obj);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(response_str), (void*)response_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, OPTIONS");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    json_object_put(response_obj);
    
    return ret;
}

// 请求处理回调函数
static enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                                      const char *url, const char *method,
                                      const char *version, const char *upload_data,
                                      size_t *upload_data_size, void **con_cls) {
    // 处理CORS预检请求
    if (strcmp(method, "OPTIONS") == 0) {
        return handle_cors_preflight(connection);
    }
    
    if (strcmp(method, "GET") != 0) {
        return MHD_NO;
    }
    
    if (strcmp(url, "/api/users") == 0) {
        return handle_user_list(connection);
    } else if (strcmp(url, "/api/crl") == 0) {
        return handle_crl_list(connection);
    } else {
        const char *not_found = "404 Not Found";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(not_found), (void*)not_found, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
        MHD_destroy_response(response);
        return ret;
    }
}

int main() {
    struct MHD_Daemon *daemon;
    
    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                             &request_handler, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "无法启动HTTP服务器\n");
        return 1;
    }
    
    printf("CA Web服务器已启动，监听端口: %d\n", PORT);
    printf("按Enter键停止服务器...\n");
    getchar();
    
    MHD_stop_daemon(daemon);
    return 0;
}
