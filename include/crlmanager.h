#ifndef CRLMANAGER_H
#define CRLMANAGER_H

#include <stdint.h>
#include "hashmap.h"

// CRL节点结构
typedef struct {
    unsigned char* hash;  // 改为指针，可以动态分配和释放
    int is_valid;
} CRLNode;

// CRL管理器基础结构
typedef struct {
    int base_v;        // 基础版本号
    CRLNode* nodes;    // CRL节点数组
    int capacity;      // 数组容量
    int removed_v;     // 已删除版本号
    int* RemovedCRL;   // 记录被删除节点的版本号
    int removed_capacity; // RemovedCRL数组容量
} CRLManager;

// 增量节点
typedef struct {
    int begin_v;       // 开始版本号
    int end_v;         // 结束版本号
    CRLNode* nodes;    // 新增的CRL节点
} AddedCRL;

// 删除节点
typedef struct {
    int begin_v;       // 开始版本号
    int end_v;         // 结束版本号
    int* del_versions; // 删除的版本号数组
} DelCRL;

// 总共更新的节点
typedef struct {
    int added_count;   // 新增节点数量
    int del_count;     // 删除节点数量
    AddedCRL* added;   // 新增的CRL
    DelCRL* del_crl;   // 删除的CRL
} UpdatedCRL;

// 基础函数声明（CA和User共用）
CRLManager* CRLManager_init(int initial_capacity, int removed_capacity);
void CRLManager_free(CRLManager* manager);
int CRLManager_add_node(CRLManager* manager, const unsigned char* hash);
int CRLManager_remove_node(CRLManager* manager, int version);
void CRLManager_print(CRLManager* manager);

// ca增量更新生成
AddedCRL* CRLManager_generate_added_crl(CRLManager* manager, int user_base_v);
DelCRL* CRLManager_generate_del_crl(CRLManager* manager, int user_removed_v);
UpdatedCRL* CRLManager_generate_update(CRLManager* manager, int user_base_v, int user_removed_v);
int CRLManager_serialize_update(const UpdatedCRL* updated_crl, unsigned char* buffer, int buffer_size);
void CRLManager_free_update(UpdatedCRL* updated_crl);

// user端增量更新解析
UpdatedCRL* CRLManager_deserialize_update(const unsigned char* buffer, int buffer_size);
int CRLManager_apply_update(CRLManager* manager, const UpdatedCRL* updated_crl, hashmap* local_crl);

// 持久化和加载函数声明
int CRLManager_save_to_file(const CRLManager* manager, const char* filename);
CRLManager* CRLManager_load_from_file(const char* filename);

#endif // CRLMANAGER_H