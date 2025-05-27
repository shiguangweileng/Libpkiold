#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashmap.h"
#include <time.h>
// 字符串键的哈希函数
int string_hash(const void* key, int size) {
    const char* str = (const char*)key;
    int hash = 0;
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
int binary_hash(const void* key, int size) {
    const unsigned char* bytes = (const unsigned char*)key;
    int hash = 0;
    for (int i = 0; i < CERT_HASH_SIZE; i++) {
        hash = (hash * 31 + bytes[i]) % size;
    }
    return hash;
}

// 二进制数据的比较函数
bool binary_compare(const void* key1, const void* key2) {
    return memcmp(key1, key2, CERT_HASH_SIZE) == 0;
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
hashmap* hashmap_create(int size, 
                      int (*hash_func)(const void* key, int size),
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

void hashmap_destroy(hashmap* map) {
    if (!map) return;
    
    // 释放所有节点内存
    for (int i = 0; i < map->size; i++) {
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

bool hashmap_exists(hashmap* map, const void* key) {
    if (!map || !key) return false;
    
    int index = map->hash_func(key, map->size);
    hashmap_entry* entry = map->entries[index];
    
    while (entry) {
        if (map->key_compare(entry->key, key)) {
            return true;
        }
        entry = entry->next;
    }
    
    return false;
}

void* hashmap_get(hashmap* map, const void* key) {
    if (!map || !key) return NULL;
    
    int index = map->hash_func(key, map->size);
    hashmap_entry* entry = map->entries[index];
    
    while (entry) {
        if (map->key_compare(entry->key, key)) {
            return entry->value;
        }
        entry = entry->next;
    }
    
    return NULL;
}

bool hashmap_put(hashmap* map, void* key, void* value, int value_size) {
    if (!map || !key) return false;
    
    int index = map->hash_func(key, map->size);
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

bool hashmap_remove(hashmap* map, const void* key) {
    if (!map || !key) return false;
    
    int index = map->hash_func(key, map->size);
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
            return true;  // 成功删除
        }
        prev = entry;
        entry = entry->next;
    }
    
    return false;  // 未找到要删除的键
}

// ======= 用户列表特定函数 =======

// 创建用户列表哈希表
hashmap* ul_hashmap_create(int size) {
    return hashmap_create(size, string_hash, string_compare, string_key_free, binary_value_free);
}

// 从二进制文件加载用户列表哈希表
hashmap* ul_hashmap_load(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        // 文件不存在，创建一个新的哈希表
        return ul_hashmap_create(256); // 默认大小256
    }
    
    // 读取哈希表大小
    int size;
    if (fread(&size, sizeof(int), 1, file) != 1) {
        fclose(file);
        return ul_hashmap_create(256); // 读取失败，使用默认大小
    }
    
    // 读取条目数量
    int count;
    if (fread(&count, sizeof(int), 1, file) != 1) {
        fclose(file);
        return ul_hashmap_create(256); // 读取失败，使用默认大小
    }
    
    // 创建哈希表
    hashmap* map = ul_hashmap_create(size);
    if (!map) {
        fclose(file);
        return NULL;
    }
    
    // 读取所有条目
    for (int i = 0; i < count; i++) {
        char* key = malloc(SUBJECT_ID_SIZE);
        if (!key) break;
        
        if (fread(key, 1, SUBJECT_ID_LEN, file) != SUBJECT_ID_LEN) {
            free(key);
            break;
        }
        key[SUBJECT_ID_LEN] = '\0'; // 确保字符串结束
        
        // 读取值（证书哈希）
        unsigned char* value = malloc(CERT_HASH_SIZE);
        if (!value) {
            free(key);
            break;
        }
        
        if (fread(value, 1, CERT_HASH_SIZE, file) != CERT_HASH_SIZE) {
            free(key);
            free(value);
            break;
        }
        
        // 添加到哈希表
        hashmap_put(map, key, value, CERT_HASH_SIZE);
    }
    
    fclose(file);
    return map;
}

// 保存用户列表哈希表到二进制文件
bool ul_hashmap_save(hashmap* map, const char* filename) {
    if (!map || !filename) return false;
    
    FILE* file = fopen(filename, "wb");
    if (!file) return false;
    
    // 写入哈希表大小
    if (fwrite(&map->size, sizeof(int), 1, file) != 1) {
        fclose(file);
        return false;
    }
    
    // 写入条目数量
    if (fwrite(&map->count, sizeof(int), 1, file) != 1) {
        fclose(file);
        return false;
    }
    
    // 遍历哈希表写入所有条目
    for (int i = 0; i < map->size; i++) {
        hashmap_entry* entry = map->entries[i];
        while (entry) {
            // 写入键（用户ID，固定8字符）
            if (fwrite(entry->key, 1, SUBJECT_ID_LEN, file) != SUBJECT_ID_LEN) {
                fclose(file);
                return false;
            }
            
            // 写入值（证书哈希）
            if (fwrite(entry->value, 1, CERT_HASH_SIZE, file) != CERT_HASH_SIZE) {
                fclose(file);
                return false;
            }
            
            entry = entry->next;
        }
    }
    
    fclose(file);
    return true;
}

// ======= CRL特定函数 =======

// 创建CRL哈希表
hashmap* crl_hashmap_create(int size) {
    // CRL中键是证书哈希，值为到期时间
    return hashmap_create(size, binary_hash, binary_compare, free, free);
}

// 从二进制文件加载CRL哈希表
hashmap* crl_hashmap_load(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        // 文件不存在，创建一个新的哈希表
        return crl_hashmap_create(512); // 默认大小512
    }
    
    // 读取哈希表大小
    int size;
    if (fread(&size, sizeof(int), 1, file) != 1) {
        fclose(file);
        return crl_hashmap_create(512); // 读取失败，使用默认大小
    }
    
    // 读取条目数量
    int count;
    if (fread(&count, sizeof(int), 1, file) != 1) {
        fclose(file);
        return crl_hashmap_create(512); // 读取失败，使用默认大小
    }
    
    // 创建哈希表
    hashmap* map = crl_hashmap_create(size);
    if (!map) {
        fclose(file);
        return NULL;
    }
    
    // 读取所有条目
    for (int i = 0; i < count; i++) {
        // 读取键（证书哈希）
        unsigned char* cert_hash = malloc(CERT_HASH_SIZE);
        if (!cert_hash) break;
        
        if (fread(cert_hash, 1, CERT_HASH_SIZE, file) != CERT_HASH_SIZE) {
            free(cert_hash);
            break;
        }
        
        // 读取值（到期时间）
        time_t* expire_time = malloc(sizeof(time_t));
        if (!expire_time) {
            free(cert_hash);
            break;
        }
        
        if (fread(expire_time, sizeof(time_t), 1, file) != 1) {
            free(cert_hash);
            free(expire_time);
            break;
        }
        
        // 添加到哈希表
        hashmap_put(map, cert_hash, expire_time, sizeof(time_t));
    }
    
    fclose(file);
    return map;
}

// 保存CRL哈希表到二进制文件
bool crl_hashmap_save(hashmap* map, const char* filename) {
    if (!map || !filename) return false;
    
    FILE* file = fopen(filename, "wb");
    if (!file) return false;
    
    // 写入哈希表大小
    if (fwrite(&map->size, sizeof(int), 1, file) != 1) {
        fclose(file);
        return false;
    }
    
    // 写入条目数量
    if (fwrite(&map->count, sizeof(int), 1, file) != 1) {
        fclose(file);
        return false;
    }
    
    // 遍历哈希表写入所有条目
    for (int i = 0; i < map->size; i++) {
        hashmap_entry* entry = map->entries[i];
        while (entry) {
            // 写入键（证书哈希）
            if (fwrite(entry->key, 1, CERT_HASH_SIZE, file) != CERT_HASH_SIZE) {
                fclose(file);
                return false;
            }
            
            // 写入值（到期时间）
            time_t expire_time = 0;
            if (entry->value) {
                expire_time = *((time_t*)entry->value);
            }
            
            if (fwrite(&expire_time, sizeof(time_t), 1, file) != 1) {
                fclose(file);
                return false;
            }
            
            entry = entry->next;
        }
    }
    
    fclose(file);
    return true;
}
