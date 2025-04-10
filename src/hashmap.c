#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashmap.h"
#include <time.h>
// 字符串键的哈希函数
size_t string_hash(const void* key, size_t size) {
    const char* str = (const char*)key;
    size_t hash = 0;
    while (*str) {
        hash = (hash * 31 + *str) % size;
        str++;
    }
    return hash;
}

// 字符串键的比较函数
bool string_compare(const void* key1, const void* key2) {
    return strcmp((const char*)key1, (const char*)key2) == 0;
}

// 二进制数据的哈希函数
size_t binary_hash(const void* key, size_t size) {
    const unsigned char* bytes = (const unsigned char*)key;
    size_t hash = 0;
    for (size_t i = 0; i < CERT_HASH_LEN; i++) {
        hash = (hash * 31 + bytes[i]) % size;
    }
    return hash;
}

// 二进制数据的比较函数
bool binary_compare(const void* key1, const void* key2) {
    return memcmp(key1, key2, CERT_HASH_LEN) == 0;
}

// 字符串键释放函数
void string_key_free(void* key) {
    free(key);
}

// 二进制值释放函数
void binary_value_free(void* value) {
    free(value);
}

// 空释放函数（不需要释放内存）
void null_free(void* ptr) {
    // 不做任何事
}

// 创建通用哈希表
hashmap* hashmap_create(size_t size, 
                      size_t (*hash_func)(const void* key, size_t size),
                      bool (*key_compare)(const void* key1, const void* key2),
                      void (*key_free)(void* key),
                      void (*value_free)(void* value)) {
    hashmap* map = (hashmap*)malloc(sizeof(hashmap));
    if (!map) return NULL;
    
    map->size = size;
    map->count = 0;
    map->entries = (hashmap_entry**)calloc(size, sizeof(hashmap_entry*));
    map->hash_func = hash_func;
    map->key_compare = key_compare;
    map->key_free = key_free;
    map->value_free = value_free;
    
    if (!map->entries) {
        free(map);
        return NULL;
    }
    
    return map;
}

// 销毁通用哈希表
void hashmap_destroy(hashmap* map) {
    if (!map) return;
    
    // 释放所有节点内存
    for (size_t i = 0; i < map->size; i++) {
        hashmap_entry* entry = map->entries[i];
        while (entry) {
            hashmap_entry* next = entry->next;
            
            if (map->key_free) map->key_free(entry->key);
            if (map->value_free) map->value_free(entry->value);
            
            free(entry);
            entry = next;
        }
    }
    
    free(map->entries);
    free(map);
}

// 检查键是否存在
bool hashmap_exists(hashmap* map, const void* key) {
    if (!map || !key) return false;
    
    size_t index = map->hash_func(key, map->size);
    hashmap_entry* entry = map->entries[index];
    
    while (entry) {
        if (map->key_compare(entry->key, key)) {
            return true;
        }
        entry = entry->next;
    }
    
    return false;
}

// 获取键对应的值
void* hashmap_get(hashmap* map, const void* key) {
    if (!map || !key) return NULL;
    
    size_t index = map->hash_func(key, map->size);
    hashmap_entry* entry = map->entries[index];
    
    while (entry) {
        if (map->key_compare(entry->key, key)) {
            return entry->value;
        }
        entry = entry->next;
    }
    
    return NULL;
}

// 添加或更新键值对
bool hashmap_put(hashmap* map, void* key, void* value, size_t value_size) {
    if (!map || !key) return false;
    
    size_t index = map->hash_func(key, map->size);
    hashmap_entry* entry = map->entries[index];
    hashmap_entry* prev = NULL;
    
    // 查找是否存在相同key
    while (entry) {
        if (map->key_compare(entry->key, key)) {
            // 更新值
            if (map->value_free) map->value_free(entry->value);
            
            if (value && value_size > 0) {
                entry->value = malloc(value_size);
                if (!entry->value) return false;
                memcpy(entry->value, value, value_size);
            } else {
                entry->value = value; // 直接存储指针或NULL
            }
            return true;
        }
        prev = entry;
        entry = entry->next;
    }
    
    // 创建新节点
    hashmap_entry* new_entry = (hashmap_entry*)malloc(sizeof(hashmap_entry));
    if (!new_entry) return false;
    
    // 复制键
    if (map->key_free == string_key_free) {
        // 字符串键需要复制
        new_entry->key = strdup((const char*)key);
    } else {
        // 其他键类型直接存储指针
        new_entry->key = key;
    }
    
    // 复制值
    if (value && value_size > 0) {
        new_entry->value = malloc(value_size);
        if (!new_entry->value) {
            if (map->key_free == string_key_free) free(new_entry->key);
            free(new_entry);
            return false;
        }
        memcpy(new_entry->value, value, value_size);
    } else {
        new_entry->value = value; // 直接存储指针或NULL
    }
    
    new_entry->next = NULL;
    
    // 添加到哈希表中
    if (prev) {
        prev->next = new_entry;
    } else {
        map->entries[index] = new_entry;
    }
    
    map->count++;
    return true;
}

// 移除键值对
void hashmap_remove(hashmap* map, const void* key) {
    if (!map || !key) return;
    
    size_t index = map->hash_func(key, map->size);
    hashmap_entry* entry = map->entries[index];
    hashmap_entry* prev = NULL;
    
    while (entry) {
        if (map->key_compare(entry->key, key)) {
            if (prev) {
                prev->next = entry->next;
            } else {
                map->entries[index] = entry->next;
            }
            
            if (map->key_free) map->key_free(entry->key);
            if (map->value_free) map->value_free(entry->value);
            
            free(entry);
            map->count--;
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

// ======= 用户列表特定函数 =======

// 创建用户列表哈希表
hashmap* ul_hashmap_create(size_t size) {
    return hashmap_create(size, string_hash, string_compare, string_key_free, binary_value_free);
}

// 从文件加载用户列表哈希表
hashmap* ul_hashmap_load(const char* filename, size_t size) {
    FILE* file = fopen(filename, "r");
    hashmap* map = ul_hashmap_create(size);
    
    if (!map) {
        if (file) fclose(file);
        return NULL;
    }
    
    if (!file) {
        return map; // 返回空哈希表
    }
    
    char line[256];
    char key[9]; // 8字符ID + 结束符
    unsigned char* value = malloc(CERT_HASH_LEN);
    
    if (!value) {
        hashmap_destroy(map);
        fclose(file);
        return NULL;
    }
    
    while (fgets(line, sizeof(line), file)) {
        // 格式：ID + 空格 + 64位十六进制哈希值
        if (strlen(line) < 10) continue; // 至少要有ID(8) + 空格(1) + 部分哈希
        
        // 提取用户ID
        strncpy(key, line, 8);
        key[8] = '\0';
        
        // 提取哈希值（十六进制转二进制）
        char* hash_str = line + 9; // 跳过ID和空格
        for (int i = 0; i < CERT_HASH_LEN; i++) {
            sscanf(hash_str + i*2, "%2hhx", &value[i]);
        }
        
        // 添加到哈希表
        hashmap_put(map, strdup(key), value, CERT_HASH_LEN);
    }
    
    free(value); // 释放临时缓冲区
    fclose(file);
    return map;
}

// 保存用户列表哈希表到文件
bool ul_hashmap_save(hashmap* map, const char* filename) {
    if (!map || !filename) return false;
    
    FILE* file = fopen(filename, "w");
    if (!file) return false;
    
    // 遍历哈希表
    for (size_t i = 0; i < map->size; i++) {
        hashmap_entry* entry = map->entries[i];
        while (entry) {
            // 写入ID
            fprintf(file, "%s ", (char*)entry->key);
            
            // 写入哈希值（二进制转十六进制）
            unsigned char* value = (unsigned char*)entry->value;
            for (int j = 0; j < CERT_HASH_LEN; j++) {
                fprintf(file, "%02x", value[j]);
            }
            fprintf(file, "\n");
            
            entry = entry->next;
        }
    }
    
    fclose(file);
    return true;
}

// ======= CRL特定函数 =======

// 创建CRL哈希表
hashmap* crl_hashmap_create(size_t size) {
    // CRL中键是证书哈希，值为到期时间
    return hashmap_create(size, binary_hash, binary_compare, free, free);
}

// 从文件加载CRL哈希表
hashmap* crl_hashmap_load(const char* filename, size_t size) {
    FILE* file = fopen(filename, "r");
    hashmap* map = crl_hashmap_create(size);
    
    if (!map) {
        if (file) fclose(file);
        return NULL;
    }
    
    if (!file) {
        return map; // 返回空哈希表
    }
    
    char line[256];
    char next_line[256];
    
    while (fgets(line, sizeof(line), file)) {
        // 移除可能的尾部换行符
        char* newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        // 每行应该是64个十六进制字符（32字节的哈希值）
        if (strlen(line) != 64) continue;
        
        // 读取下一行，获取到期时间
        time_t expire_time = 0;
        if (fgets(next_line, sizeof(next_line), file)) {
            // 移除可能的尾部换行符
            newline = strchr(next_line, '\n');
            if (newline) *newline = '\0';
            
            // 将字符串转换为时间戳
            sscanf(next_line, "%ld", &expire_time);
        }
        
        // 将十六进制字符串转换为二进制哈希值
        unsigned char* cert_hash = malloc(CERT_HASH_LEN);
        if (!cert_hash) continue;
        
        for (int i = 0; i < CERT_HASH_LEN; i++) {
            sscanf(&line[i*2], "%2hhx", &cert_hash[i]);
        }
        
        // 分配存储到期时间的内存
        time_t* expire_time_ptr = malloc(sizeof(time_t));
        if (!expire_time_ptr) {
            free(cert_hash);
            continue;
        }
        
        *expire_time_ptr = expire_time;
        
        // 添加到哈希表，值为到期时间
        hashmap_put(map, cert_hash, expire_time_ptr, sizeof(time_t));
    }
    
    fclose(file);
    return map;
}

// 保存CRL哈希表到文件
bool crl_hashmap_save(hashmap* map, const char* filename) {
    if (!map || !filename) return false;
    
    FILE* file = fopen(filename, "w");
    if (!file) return false;
    
    // 遍历哈希表
    for (size_t i = 0; i < map->size; i++) {
        hashmap_entry* entry = map->entries[i];
        while (entry) {
            // 将哈希值转换为十六进制字符串并写入
            unsigned char* hash = (unsigned char*)entry->key;
            for (int j = 0; j < CERT_HASH_LEN; j++) {
                fprintf(file, "%02x", hash[j]);
            }
            fprintf(file, "\n");
            
            // 写入到期时间
            time_t expire_time = 0;
            if (entry->value) {
                expire_time = *((time_t*)entry->value);
            }
            fprintf(file, "%ld\n", expire_time);
            
            entry = entry->next;
        }
    }
    
    fclose(file);
    return true;
}
