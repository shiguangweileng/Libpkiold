#ifndef WEB_PROTOCOL_H
#define WEB_PROTOCOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

// 消息头大小（命令1字节 + 数据长度2字节）
#define MSG_HEADER_SIZE 3
#define BUFFER_SIZE 8192

// Web通信协议命令
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

// 基础通信相关函数
int setup_server(int port);
int connect_to_server(const char *ip, int port);
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len);
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len);

// ============ CA Web客户端请求函数 ============

int request_user_list(int ca_socket, void **users, int *user_count);

int request_user_certificate(int ca_socket, const char *user_id, unsigned char *cert_data, int max_size);

int request_crl_list(int ca_socket, void **crl_entries, int *crl_count, int *base_v, int *removed_v);

int request_cleanup_expired_certs(int ca_socket);

int request_local_gen_cert(int ca_socket, const char *user_id);

int request_local_upd_cert(int ca_socket, const char *user_id);

int request_revoke_cert(int ca_socket, const char *user_id);

#endif // WEB_PROTOCOL_H 