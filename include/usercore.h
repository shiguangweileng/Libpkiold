#ifndef USER_H
#define USER_H

#include <stdio.h>
#include <stdint.h>
#include "imp_cert.h"
#include "hashmap.h"
#include "crlmanager.h"

#define CRL_MANAGER_FILE "CRLManager.dat"
#define MAX_MESSAGE_SIZE 1024 // 最大消息长度

// 定义存储在user.c中的全局变量为外部变量
extern ImpCert loaded_cert;
extern hashmap* local_crl;
extern CRLManager* crl_manager;
extern unsigned char priv_key[SM2_PRI_MAX_SIZE];
extern unsigned char pub_key[SM2_PUB_MAX_SIZE];
extern unsigned char Q_ca[SM2_PUB_MAX_SIZE];
extern int has_cert;

// CRL相关函数
int init_crl_manager();
int load_crl_manager_to_hashmap();
int check_cert_in_local_crl(const unsigned char *cert_hash);
int sync_crl_with_ca(int sock);
int online_csp(int sock, const unsigned char *cert_hash);
int local_csp(const unsigned char *cert_hash);

// 用户操作
int load_keys_and_cert(const char *user_id);
int request_registration(int sock, const char *user_id);
int request_cert_update(int sock, const char *user_id);
int request_cert_revoke(int sock, const char *user_id);
int send_signed_message(int sock, const char *user_id, const char *message);

#endif /* USER_H */ 