#ifndef HASHMAP_H
#define HASHMAP_H

#include <stddef.h>
#include <stdbool.h>

// 证书哈希值的长度
#define CERT_HASH_LEN 32

// 通用哈希表节点结构
typedef struct hashmap_entry {
    void* key;                     // 键可以是任何类型的指针
    void* value;                   // 值是二进制数据
    struct hashmap_entry* next;    // 链表下一节点
} hashmap_entry;

// 通用哈希表结构
typedef struct {
    size_t size;                  // 哈希表大小
    size_t count;                 // 当前元素数量
    hashmap_entry** entries;      // 哈希表桶数组
    
    // 函数指针，用于自定义键的哈希计算和比较
    size_t (*hash_func)(const void* key, size_t size);
    bool (*key_compare)(const void* key1, const void* key2);
    
    // 清理键和值的函数
    void (*key_free)(void* key);
    void (*value_free)(void* value);
} hashmap;

// 哈希表操作函数
hashmap* hashmap_create(size_t size, 
                      size_t (*hash_func)(const void* key, size_t size),
                      bool (*key_compare)(const void* key1, const void* key2),
                      void (*key_free)(void* key),
                      void (*value_free)(void* value));
void hashmap_destroy(hashmap* map);
bool hashmap_exists(hashmap* map, const void* key);
void* hashmap_get(hashmap* map, const void* key);
bool hashmap_put(hashmap* map, void* key, void* value, size_t value_size);
bool hashmap_remove(hashmap* map, const void* key);

// 字符串键的哈希和比较函数
size_t string_hash(const void* key, size_t size);
bool string_compare(const void* key1, const void* key2);

// 二进制数据的哈希和比较函数
size_t binary_hash(const void* key, size_t size);
bool binary_compare(const void* key1, const void* key2);

// 用户列表特定函数
hashmap* ul_hashmap_create(size_t size);
hashmap* ul_hashmap_load(const char* filename, size_t size);
bool ul_hashmap_save(hashmap* map, const char* filename);

// CRL特定函数
hashmap* crl_hashmap_create(size_t size);
hashmap* crl_hashmap_load(const char* filename, size_t size);
bool crl_hashmap_save(hashmap* map, const char* filename);

#endif // HASHMAP_H
