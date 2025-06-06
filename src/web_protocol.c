#include "web_protocol.h"
#include "imp_cert.h"
#include "hashmap.h"

// 定义CA服务器的IP和端口
#define CA_IP "127.0.0.1"
#define CA_PORT 8001

// 用户数据结构
#define CERT_HASH_SIZE 32   // 证书哈希32字节

typedef struct {
    char id[SUBJECT_ID_SIZE];
    unsigned char cert_hash[CERT_HASH_SIZE];
} UserInfo;

// Web端使用的CRL数据结构，包含证书哈希
typedef struct {
    unsigned char cert_hash[CERT_HASH_SIZE]; // 证书哈希
    time_t expire_time;      // 证书到期时间
    time_t revoke_time;      // 证书撤销时间
    char revoke_by[SUBJECT_ID_SIZE]; // 撤销人ID
    unsigned char reason;    // 撤销原因代码
} WebCRLEntry;

int setup_server(int port) {
    int server_fd;
    int opt = 1;
    struct sockaddr_in address;
    
    // 创建socket文件描述符
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket创建失败");
        return -1;
    }
    
    // 设置socket选项 - 只使用SO_REUSEADDR
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        return -1;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // 绑定socket到指定端口
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind失败");
        return -1;
    }
    
    // 设置监听
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        return -1;
    }
    
    return server_fd;
} 

int connect_to_server(const char *ip, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    // 创建socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket创建失败");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // 将IP地址从文本转换为二进制形式
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
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
    
    // 发送消息 - 使用循环确保完整发送
    int total_sent = 0;
    int bytes_to_send = data_len + MSG_HEADER_SIZE;
    int bytes_sent = 0;
    
    while (total_sent < bytes_to_send) {
        bytes_sent = send(sock, buffer + total_sent, bytes_to_send - total_sent, 0);
        if (bytes_sent < 0) {
            perror("发送消息失败");
            return 0;
        }
        total_sent += bytes_sent;
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


// ============ CA Web客户端请求函数 ============

// 请求用户列表
int request_user_list(int ca_socket, void **users, int *user_count) {
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    int result = 0;
    
    // 检查参数
    if (users == NULL || user_count == NULL) {
        return 0;
    }
    
    // 检查连接是否有效
    if (ca_socket < 0) {
        return 0;
    }
    
    // 发送请求
    if (!send_message(ca_socket, WEB_CMD_GET_USERS, NULL, 0)) {
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_USER_LIST) {
        return 0;
    }
    
    // 解析响应数据
    if (data_len >= sizeof(int)) {
        int new_user_count = 0;
        memcpy(&new_user_count, buffer, sizeof(int));
        
        // 检查数据大小是否合理
        if (data_len == sizeof(int) + new_user_count * (SUBJECT_ID_LEN + CERT_HASH_SIZE)) {
            // 释放旧数据
            if (*users) {
                free(*users);
                *users = NULL;
                *user_count = 0;
            }
            
            // 分配新内存
            if (new_user_count > 0) {
                *users = (UserInfo*)malloc(sizeof(UserInfo) * new_user_count);
                if (*users) {
                    *user_count = new_user_count;
                    
                    // 解析用户数据
                    int offset = sizeof(int);
                    for (int i = 0; i < *user_count; i++) {
                        UserInfo *userInfo = (UserInfo*)*users;
                        // 复制用户ID（4字节）并添加字符串结尾符
                        memcpy(userInfo[i].id, buffer + offset, SUBJECT_ID_LEN);
                        userInfo[i].id[SUBJECT_ID_LEN] = '\0'; // 添加字符串结尾符
                        offset += SUBJECT_ID_LEN;
                        
                        // 复制证书哈希
                        memcpy(userInfo[i].cert_hash, buffer + offset, CERT_HASH_SIZE);
                        offset += CERT_HASH_SIZE;
                    }
                    result = 1;
                }
            } else {
                // 空列表
                result = 1;
            }
        }
    }
    
    return result;
}

// 请求用户证书
int request_user_cert(int ca_socket, const char *user_id, unsigned char *cert_data, int max_size) {
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    int result = 0;

    if (ca_socket < 0 || user_id == NULL || cert_data == NULL) {
        return 0;
    }
    
    // 发送请求，包含用户ID
    if (!send_message(ca_socket, WEB_CMD_GET_CERT, user_id, strlen(user_id) + 1)) {
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len <= 0 || cmd != WEB_CMD_CERT_DATA) {
        return 0;
    }
    
    // 响应数据为空，表示没有找到证书或出错
    if (data_len == 0) {
        return 0;
    }
    
    // 复制证书数据
    if (data_len <= max_size) {
        memcpy(cert_data, buffer, data_len);
        result = data_len;
    }

    return result;
}

// 请求CRL列表
int request_crl_list(int ca_socket, void **crl_entries, int *crl_count, int *base_v, int *removed_v) {
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    int result = 0;

    if (ca_socket < 0 || crl_entries == NULL || crl_count == NULL || 
        base_v == NULL || removed_v == NULL) {
        return 0;
    }
    
    if (!send_message(ca_socket, WEB_CMD_GET_CRL, NULL, 0)) {
        return 0;
    }
    
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_CRL_DATA) {
        return 0;
    }
    
    // 解析响应数据
    if (data_len >= sizeof(int) * 3) { // 至少包含基础版本号、删除版本号和CRL条目数
        int offset = 0;
        
        // 读取基础版本号
        memcpy(base_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        
        // 读取删除版本号
        memcpy(removed_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        
        // 读取CRL条目数
        int new_crl_count = 0;
        memcpy(&new_crl_count, buffer + offset, sizeof(int));
        offset += sizeof(int);
        
        // 检查数据大小是否合理
        // 计算CRL传输格式大小 (证书哈希 + CRLEntry)
        size_t crl_transfer_size = CERT_HASH_SIZE + sizeof(CRLEntry);
        if (data_len >= sizeof(int) * 3 && data_len >= sizeof(int) * 3 + new_crl_count * crl_transfer_size) {
            // 释放旧数据
            if (*crl_entries) {
                free(*crl_entries);
                *crl_entries = NULL;
                *crl_count = 0;
            }
            
            // 分配新内存
                            if (new_crl_count > 0) {
                    *crl_entries = (WebCRLEntry*)malloc(sizeof(WebCRLEntry) * new_crl_count);
                    if (*crl_entries) {
                        *crl_count = new_crl_count;
                        
                        // 解析CRL数据
                        for (int i = 0; i < *crl_count; i++) {
                            WebCRLEntry *webCRLEntries = (WebCRLEntry*)*crl_entries;
                            
                            // 复制证书哈希
                            memcpy(webCRLEntries[i].cert_hash, buffer + offset, CERT_HASH_SIZE);
                            offset += CERT_HASH_SIZE;
                            
                            // 复制CRLEntry结构体 (expire_time, revoke_time, revoke_by, reason)
                            memcpy(&webCRLEntries[i].expire_time, buffer + offset, sizeof(CRLEntry));
                            offset += sizeof(CRLEntry);
                    }
                    result = 1;
                }
            } else {
                // 空列表
                result = 1;
            }
        }
    }
    return result;
}

// 请求清理过期证书
int request_cleanup_expired_certs(int ca_socket) {
    unsigned char buffer[BUFFER_SIZE];
    int data_len;
    uint8_t cmd;
    int cleaned_count = -1;

    if (ca_socket < 0) {
        return -1;
    }
    
    if (!send_message(ca_socket, WEB_CMD_CLEANUP_CERTS, NULL, 0)) {
        return -1;
    }
    
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_CLEANUP_RESULT) {
        return -1;
    }
    
    // 解析响应数据（清理的证书数量）
    if (data_len >= sizeof(int)) {
        memcpy(&cleaned_count, buffer, sizeof(int));
    }
    
    return cleaned_count;
}

// 请求本地生成证书
int request_local_gen_cert(int ca_socket, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    int result = 0;
    
    if (ca_socket < 0 || user_id == NULL) {
        return 0;
    }

    if (!send_message(ca_socket, WEB_CMD_LOCAL_GEN_CERT, user_id, strlen(user_id) + 1)) {
        return 0;
    }
    
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    
    if (data_len < 0 || cmd != WEB_CMD_LOCAL_RESULT) {
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    return result;
}

// 请求本地更新证书
int request_local_upd_cert(int ca_socket, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    int result = 0;

    if (ca_socket < 0 || user_id == NULL) {
        return 0;
    }

    if (!send_message(ca_socket, WEB_CMD_LOCAL_UPD_CERT, user_id, strlen(user_id) + 1)) {
        return 0;
    }

    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0 || cmd != WEB_CMD_LOCAL_RESULT) {
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    return result;
}

// 请求撤销证书
int request_revoke_cert(int ca_socket, const char *user_id) {
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    int result = 0;

    if (ca_socket < 0 || user_id == NULL) {
        return 0;
    }

    if (!send_message(ca_socket, WEB_CMD_REVOKE_CERT, user_id, strlen(user_id) + 1)) {
        return 0;
    }
    
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0 || cmd != WEB_CMD_REVOKE_RESULT) {
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    return result;
}

// 请求设置证书版本
int request_set_cert_version(int ca_socket, unsigned char version) {
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    int result = 0;

    if (ca_socket < 0 || (version != CERT_V1 && version != CERT_V2)) {
        return 0;
    }

    // 发送版本号
    if (!send_message(ca_socket, WEB_CMD_SET_CERT_VERSION, &version, 1)) {
        return 0;
    }
    
    // 接收响应
    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0 || cmd != WEB_CMD_VERSION_RESULT) {
        return 0;
    }
    
    // 处理响应结果
    if (data_len > 0) {
        // 结果为1字节，1表示成功，0表示失败
        result = buffer[0];
    }
    
    return result;
}

// 请求获取当前证书版本
int request_get_cert_version(int ca_socket) {
    unsigned char buffer[BUFFER_SIZE];
    uint8_t cmd;
    int data_len;
    unsigned char version = 0;

    if (ca_socket < 0) {
        return 0;
    }

    if (!send_message(ca_socket, WEB_CMD_GET_CERT_VERSION, NULL, 0)) {
        return 0;
    }

    data_len = recv_message(ca_socket, &cmd, buffer, BUFFER_SIZE);
    if (data_len < 0 || cmd != WEB_CMD_CERT_VERSION_DATA) {
        return 0;
    }

    if (data_len == 1) {
        version = buffer[0];
        if (version != CERT_V1 && version != CERT_V2) {
            return 0;
        }
    } else {
        return 0;
    }
    return (int)version;
}

