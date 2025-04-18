/**
 * @file network.c
 * @brief 网络通信模块的实现
 */
#include "network.h"

// 实现相关的头文件
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**
 * @brief 发送消息到指定socket
 */
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

/**
 * @brief 从指定socket接收消息
 */
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

/**
 * @brief 连接到服务器（客户端使用）
 */
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

/**
 * @brief 设置服务器（服务端使用）
 */
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