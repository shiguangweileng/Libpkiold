/**
 * @file network.h
 * @brief 网络通信模块，提供客户端和服务器端通用的网络通信功能
 */
#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

// 通信协议常量
#define CMD_SEND_ID_AND_RU    0x01    // 用户发送ID和Ru
#define CMD_SEND_CERT_AND_R   0x02    // CA发送证书和部分私钥r
#define CMD_REQUEST_UPDATE    0x03    // 用户请求更新证书
#define CMD_SEND_UPDATED_CERT 0x04    // CA发送更新后的证书
#define CMD_SEND_MESSAGE      0x05    // 用户发送消息、签名和证书
#define CMD_VERIFY_CERT       0x06    // 用户查询证书有效性
#define CMD_CERT_STATUS       0x07    // CA返回证书状态
#define CMD_REQUEST_REVOKE    0x08    // 用户请求撤销证书
#define CMD_REVOKE_RESPONSE   0x09    // CA返回撤销结果
#define CMD_REQUEST_CRL_UPDATE 0x0A   // 用户请求CRL增量更新
#define CMD_SEND_CRL_UPDATE   0x0B    // CA发送CRL增量更新

// 通用配置
#define PORT 8000
#define BUFFER_SIZE 8192
#define MSG_HEADER_SIZE 3

/**
 * @brief 发送消息到指定socket
 * 
 * @param sock 目标socket
 * @param cmd 命令类型
 * @param data 要发送的数据
 * @param data_len 数据长度
 * @return int 成功返回1，失败返回0
 */
int send_message(int sock, uint8_t cmd, const void *data, uint16_t data_len);

/**
 * @brief 从指定socket接收消息
 * 
 * @param sock 源socket
 * @param cmd 接收到的命令类型
 * @param data 接收数据的缓冲区
 * @param max_len 缓冲区最大长度
 * @return int 成功返回接收到的数据长度，失败返回-1
 */
int recv_message(int sock, uint8_t *cmd, void *data, uint16_t max_len);

/**
 * @brief 连接到服务器（客户端使用）
 * 
 * @param ip 服务器IP地址
 * @param port 服务器端口
 * @return int 成功返回socket描述符，失败返回-1
 */
int connect_to_server(const char *ip, int port);

/**
 * @brief 设置服务器（服务端使用）
 * 
 * @param port 监听端口
 * @return int 成功返回socket描述符，失败返回-1
 */
int setup_server(int port);

#endif /* NETWORK_H */ 