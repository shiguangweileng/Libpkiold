#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

// 定义EXPORT宏
#if defined(_WIN32) || defined(_WIN64)
    #ifdef BUILDING_LIB
        #define EXPORT __declspec(dllexport)
    #else
        #define EXPORT __declspec(dllimport)
    #endif
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

// SM2全局参数
extern EC_GROUP *group;
extern BIGNUM *order;

//SM2算法相关参数定义
#define SM2_PUB_MAX_SIZE 65   // SM2公钥最大长度(字节)：0x04 || x || y
#define SM2_PRI_MAX_SIZE 32   // SM2私钥最大长度(字节)
#define SM2_SIG_MAX_SIZE 72   // SM2签名最大长度(字节)：DER编码的r和s

// SM2参数初始化和释放
EXPORT int sm2_params_init();
EXPORT void sm2_params_cleanup();
EXPORT int CA_init(unsigned char *pub, unsigned char *priv);
EXPORT int User_init(unsigned char *pub);

#endif