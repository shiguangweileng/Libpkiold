#ifndef HASHMAP_H
#define HASHMAP_H

#include <stddef.h>
#include <stdbool.h>
#include "imp_cert.h"

// 通用哈希表节点结构
typedef struct hashmap_entry {
    void* key;                     // 键可以是任何类型的指针
    void* value;                   // 值是二进制数据
    struct hashmap_entry* next;    // 链表下一节点
} hashmap_entry;

// 通用哈希表结构
typedef struct {
    int size;                      // 哈希表大小
    int count;                     // 当前元素数量
    hashmap_entry** entries;       // 哈希表桶数组
    
    // 函数指针，用于自定义键的哈希计算和比较
    int (*hash_func)(const void* key, int size);
    bool (*key_compare)(const void* key1, const void* key2);
    
    // 清理键和值的函数
    void (*key_free)(void* key);
    void (*value_free)(void* value);
} hashmap;

// CRL条目结构体
typedef struct {
    time_t expire_time;      // 证书到期时间
    time_t revoke_time;      // 证书撤销时间
    char revoke_by[SUBJECT_ID_SIZE]; // 撤销人ID
    unsigned char reason;    // 撤销原因代码
} CRLEntry;

typedef enum{
    REASON_CERT_EXPIRED = 1,    // 证书过期
    REASON_CERT_UPDATED = 2,    // 证书更新
    REASON_KEY_LEAKED = 3,      // 密钥泄露
    REASON_BUSINESS_END = 4,    // 业务终止
    REASON_OTHER = 5            // 其他
} RevokeReason;

// 哈希表操作函数
hashmap* hashmap_create(int size, 
                      int (*hash_func)(const void* key, int size),
                      bool (*key_compare)(const void* key1, const void* key2),
                      void (*key_free)(void* key),
                      void (*value_free)(void* value));
void hashmap_destroy(hashmap* map);
bool hashmap_exists(hashmap* map, const void* key);
void* hashmap_get(hashmap* map, const void* key);
bool hashmap_put(hashmap* map, void* key, void* value, int value_size);
bool hashmap_remove(hashmap* map, const void* key);

// 字符串键、二进制数据的哈希和比较函数
int string_hash(const void* key, int size);
bool string_compare(const void* key1, const void* key2);
int binary_hash(const void* key, int size);
bool binary_compare(const void* key1, const void* key2);

// CRL条目辅助函数
const char* get_revoke_reason_str(unsigned char reason);

// userlist特定函数
hashmap* ul_hashmap_create(int size);
hashmap* ul_hashmap_load(const char* filename);
bool ul_hashmap_save(hashmap* map, const char* filename);

// CRL特定函数
hashmap* crl_hashmap_create(int size);
hashmap* crl_hashmap_load(const char* filename);
bool crl_hashmap_save(hashmap* map, const char* filename);

#endif // HASHMAP_H
