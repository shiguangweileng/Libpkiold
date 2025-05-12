#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crlmanager.h"

// 辅助函数：扩展CRLNode节点数组容量
static int expand_nodes_array(CRLManager* manager) {
    if (!manager) return 0;
    
    int new_capacity = manager->capacity * 2;
    CRLNode* new_nodes = (CRLNode*)realloc(manager->nodes, new_capacity * sizeof(CRLNode));
    if (!new_nodes) return 0;
    
    // 初始化新增节点
    for (int i = manager->capacity; i < new_capacity; i++) {
        new_nodes[i].hash = NULL;
        new_nodes[i].is_valid = 0;
    }
    
    manager->nodes = new_nodes;
    manager->capacity = new_capacity;
    return 1;
}

// 辅助函数：扩展删除记录数组容量
static int expand_removed_array(CRLManager* manager) {
    if (!manager || !manager->RemovedCRL) return 0;
    
    int new_capacity = manager->removed_capacity * 2;
    int* new_removed = (int*)realloc(manager->RemovedCRL, new_capacity * sizeof(int));
    if (!new_removed) return 0;
    
    manager->RemovedCRL = new_removed;
    manager->removed_capacity = new_capacity;
    return 1;
}

// 辅助函数：释放整个AddedCRL对象
static void free_added_crl(AddedCRL* added) {
    if (!added) return;
    
    if (added->nodes) {
        int count = added->end_v - added->begin_v;
        // 直接在这里释放节点内存
        for (int i = 0; i < count; i++) {
            if (added->nodes[i].hash) {
                free(added->nodes[i].hash);
            }
        }
        free(added->nodes);
    }
    free(added);
}

// 辅助函数：释放DelCRL对象
static void free_del_crl(DelCRL* del_crl) {
    if (!del_crl) return;
    
    if (del_crl->del_versions) {
        free(del_crl->del_versions);
    }
    free(del_crl);
}

// 初始化CRL管理器
// 用户端的CRL管理器不应该有removed_capacity,所以user初始化时removed_capacity=0
CRLManager* CRLManager_init(int initial_capacity, int removed_capacity) {
    CRLManager* manager = (CRLManager*)malloc(sizeof(CRLManager));
    if (!manager) return NULL;

    manager->base_v = 0;
    manager->removed_v = 0;
    manager->capacity = initial_capacity;
    manager->removed_capacity = removed_capacity;
    
    manager->nodes = (CRLNode*)calloc(initial_capacity, sizeof(CRLNode));
    if (!manager->nodes) {
        free(manager);
        return NULL;
    }

    // 初始化所有节点的hash指针为NULL
    for (int i = 0; i < initial_capacity; i++) {
        manager->nodes[i].hash = NULL;
        manager->nodes[i].is_valid = 0;
    }

    // 根据removed_capacity决定是否分配RemovedCRL
    if (removed_capacity > 0) {
        manager->RemovedCRL = (int*)calloc(removed_capacity, sizeof(int));
        if (!manager->RemovedCRL) {
            free(manager->nodes);
            free(manager);
            return NULL;
        }
    } else {
        manager->RemovedCRL = NULL;
    }

    return manager;
}

// 释放CRL管理器
void CRLManager_free(CRLManager* manager) {
    if (manager) {
        // 释放每个节点的哈希值内存
        for (int i = 0; i < manager->capacity; i++) {
            if (manager->nodes[i].hash) {
                free(manager->nodes[i].hash);
            }
        }
        free(manager->nodes);
        if (manager->RemovedCRL) {
            free(manager->RemovedCRL);
        }
        free(manager);
    }
}

// 添加新的CRL节点
int CRLManager_add_node(CRLManager* manager, const unsigned char* hash) {
    if (!manager || !hash) return 0;

    // 检查是否需要扩容
    if (manager->base_v >= manager->capacity) {
        if (!expand_nodes_array(manager)) return 0;
    }

    // 分配哈希值内存并复制
    manager->nodes[manager->base_v].hash = (unsigned char*)malloc(32);
    if (!manager->nodes[manager->base_v].hash) return 0;
    
    memcpy(manager->nodes[manager->base_v].hash, hash, 32);
    manager->nodes[manager->base_v].is_valid = 1;
    manager->base_v++;

    return 1; // 返回成功
}

// 删除CRL节点
int CRLManager_remove_node(CRLManager* manager, int version) {
    if (!manager || version < 0 || version >= manager->base_v) return 0;

    // 如果RemovedCRL已分配，则记录删除的版本号
    if (manager->RemovedCRL) {
        // 检查RemovedCRL是否需要扩容
        if (manager->removed_v >= manager->removed_capacity) {
            if (!expand_removed_array(manager)) return 0;
        }

        // 将版本号添加到RemovedCRL数组
        manager->RemovedCRL[manager->removed_v] = version;
    }

    // 释放哈希值内存并设置为NULL
    if (manager->nodes[version].hash) {
        free(manager->nodes[version].hash);
        manager->nodes[version].hash = NULL;
    }
    
    manager->nodes[version].is_valid = 0;
    manager->removed_v++;

    return 1;
}

// 生成AddedCRL增量包
AddedCRL* CRLManager_generate_added_crl(CRLManager* manager, int user_base_v) {
    if (!manager || user_base_v >= manager->base_v) return NULL;

    AddedCRL* added = (AddedCRL*)malloc(sizeof(AddedCRL));
    if (!added) return NULL;

    added->begin_v = user_base_v;
    added->end_v = manager->base_v;
    int count = added->end_v - added->begin_v;
    
    added->nodes = (CRLNode*)malloc(count * sizeof(CRLNode));
    if (!added->nodes) {
        free(added);
        return NULL;
    }

    // 初始化新节点的hash指针为NULL
    for (int i = 0; i < count; i++) {
        added->nodes[i].hash = NULL;
        added->nodes[i].is_valid = 0;
    }

    // 复制所有节点，为有效节点分配新的哈希值内存
    for (int i = 0; i < count; i++) {
        int src_idx = user_base_v + i;
        added->nodes[i].is_valid = manager->nodes[src_idx].is_valid;
        
        if (manager->nodes[src_idx].is_valid && manager->nodes[src_idx].hash) {
            added->nodes[i].hash = (unsigned char*)malloc(32);
            if (!added->nodes[i].hash) {
                // 清理已分配的内存
                for (int j = 0; j < i; j++) {
                    if (added->nodes[j].hash) {
                        free(added->nodes[j].hash);
                    }
                }
                free(added->nodes);
                free(added);
                return NULL;
            }
            memcpy(added->nodes[i].hash, manager->nodes[src_idx].hash, 32);
        }
    }

    return added;
}

// 生成DelCRL删除包
DelCRL* CRLManager_generate_del_crl(CRLManager* manager, int user_removed_v) {
    if (!manager || user_removed_v >= manager->removed_v) return NULL;

    DelCRL* del_crl = (DelCRL*)malloc(sizeof(DelCRL));
    if (!del_crl) return NULL;

    del_crl->begin_v = user_removed_v;
    del_crl->end_v = manager->removed_v;
    int count = del_crl->end_v - del_crl->begin_v;

    del_crl->del_versions = (int*)malloc(count * sizeof(int));
    if (!del_crl->del_versions) {
        free(del_crl);
        return NULL;
    }

    // 直接从RemovedCRL数组中复制版本号
    memcpy(del_crl->del_versions, 
           manager->RemovedCRL + user_removed_v, 
           count * sizeof(int));

    return del_crl;
}

// 生成完整的更新包
UpdatedCRL* CRLManager_generate_update(CRLManager* manager, int user_base_v, int user_removed_v) {
    if (!manager) return NULL;

    UpdatedCRL* updated_crl = (UpdatedCRL*)malloc(sizeof(UpdatedCRL));
    if (!updated_crl) return NULL;

    updated_crl->added = CRLManager_generate_added_crl(manager, user_base_v);
    updated_crl->del_crl = CRLManager_generate_del_crl(manager, user_removed_v);

    if (updated_crl->added) {
        updated_crl->added_count = updated_crl->added->end_v - updated_crl->added->begin_v;
    } else {
        updated_crl->added_count = 0;
    }

    if (updated_crl->del_crl) {
        updated_crl->del_count = updated_crl->del_crl->end_v - updated_crl->del_crl->begin_v;
    } else {
        updated_crl->del_count = 0;
    }

    return updated_crl;
}

// 释放更新包
void CRLManager_free_update(UpdatedCRL* updated_crl) {
    if (!updated_crl) return;

    free_added_crl(updated_crl->added);
    free_del_crl(updated_crl->del_crl);
    free(updated_crl);
}

// 序列化更新包
int CRLManager_serialize_update(const UpdatedCRL* updated_crl, unsigned char* buffer, int buffer_size) {
    if (!updated_crl || !buffer) return -1;

    int offset = 0;
    int required_size = sizeof(int) * 2; // added_count + del_count

    // 使用临时变量减少重复引用
    const AddedCRL* added = updated_crl->added;
    const DelCRL* del_crl = updated_crl->del_crl;
    int added_count = updated_crl->added_count;
    int del_count = updated_crl->del_count;

    if (added) {
        required_size += sizeof(int) * 2; // begin_v + end_v
        
        // 计算节点序列化大小，包括有效标志和哈希值
        for (int i = 0; i < added_count; i++) {
            required_size += sizeof(int); // is_valid
            if (added->nodes[i].is_valid && added->nodes[i].hash) {
                required_size += 32; // hash
            }
        }
    }

    if (del_crl) {
        required_size += sizeof(int) * 2; // begin_v + end_v
        required_size += del_count * sizeof(int);
    }

    if (buffer_size < required_size) return -1;

    // 序列化基本计数
    memcpy(buffer + offset, &added_count, sizeof(int));
    offset += sizeof(int);
    memcpy(buffer + offset, &del_count, sizeof(int));
    offset += sizeof(int);

    // 序列化AddedCRL
    if (added) {
        memcpy(buffer + offset, &added->begin_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, &added->end_v, sizeof(int));
        offset += sizeof(int);
        
        // 逐个序列化节点
        for (int i = 0; i < added_count; i++) {
            const CRLNode* node = &added->nodes[i];
            memcpy(buffer + offset, &node->is_valid, sizeof(int));
            offset += sizeof(int);
            
            if (node->is_valid && node->hash) {
                memcpy(buffer + offset, node->hash, 32);
                offset += 32;
            }
        }
    }

    // 序列化DelCRL
    if (del_crl) {
        memcpy(buffer + offset, &del_crl->begin_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, &del_crl->end_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, del_crl->del_versions, del_count * sizeof(int));
        offset += del_count * sizeof(int);
    }

    return offset;
}

// 反序列化更新包
UpdatedCRL* CRLManager_deserialize_update(const unsigned char* buffer, int buffer_size) {
    if (!buffer || buffer_size < sizeof(int) * 2) return NULL;

    UpdatedCRL* updated_crl = (UpdatedCRL*)malloc(sizeof(UpdatedCRL));
    if (!updated_crl) return NULL;

    int offset = 0;

    // 反序列化基本计数
    memcpy(&updated_crl->added_count, buffer + offset, sizeof(int));
    offset += sizeof(int);
    memcpy(&updated_crl->del_count, buffer + offset, sizeof(int));
    offset += sizeof(int);

    // 临时变量
    int added_count = updated_crl->added_count;
    int del_count = updated_crl->del_count;
    updated_crl->added = NULL;
    updated_crl->del_crl = NULL;

    // 反序列化AddedCRL
    if (added_count > 0) {
        AddedCRL* added = (AddedCRL*)malloc(sizeof(AddedCRL));
        if (!added) {
            free(updated_crl);
            return NULL;
        }
        updated_crl->added = added;

        memcpy(&added->begin_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        memcpy(&added->end_v, buffer + offset, sizeof(int));
        offset += sizeof(int);

        added->nodes = (CRLNode*)malloc(added_count * sizeof(CRLNode));
        if (!added->nodes) {
            free_added_crl(added);
            free(updated_crl);
            return NULL;
        }

        // 初始化所有hash指针为NULL
        for (int i = 0; i < added_count; i++) {
            added->nodes[i].hash = NULL;
            added->nodes[i].is_valid = 0;
        }

        // 逐个反序列化节点
        for (int i = 0; i < added_count; i++) {
            CRLNode* node = &added->nodes[i];
            memcpy(&node->is_valid, buffer + offset, sizeof(int));
            offset += sizeof(int);
            
            if (node->is_valid) {
                node->hash = (unsigned char*)malloc(32);
                if (!node->hash) {
                    // 清理已分配的内存
                    free_added_crl(added);
                    free(updated_crl);
                    return NULL;
                }
                
                memcpy(node->hash, buffer + offset, 32);
                offset += 32;
            }
        }
    }

    // 反序列化DelCRL
    if (del_count > 0) {
        DelCRL* del_crl = (DelCRL*)malloc(sizeof(DelCRL));
        if (!del_crl) {
            free_added_crl(updated_crl->added);
            free(updated_crl);
            return NULL;
        }
        updated_crl->del_crl = del_crl;

        memcpy(&del_crl->begin_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        memcpy(&del_crl->end_v, buffer + offset, sizeof(int));
        offset += sizeof(int);

        del_crl->del_versions = (int*)malloc(del_count * sizeof(int));
        if (!del_crl->del_versions) {
            free_added_crl(updated_crl->added);
            free_del_crl(del_crl);
            free(updated_crl);
            return NULL;
        }

        memcpy(del_crl->del_versions, buffer + offset, del_count * sizeof(int));
        offset += del_count * sizeof(int);
    }

    return updated_crl;
}

// 应用更新到本地CRL管理器和local_crl哈希表
int CRLManager_apply_update(CRLManager* manager, const UpdatedCRL* updated_crl, hashmap* local_crl) {
    if (!manager || !updated_crl) return 0;

    // 使用临时变量简化代码
    const AddedCRL* added = updated_crl->added;
    const DelCRL* del_crl = updated_crl->del_crl;
    int added_count = updated_crl->added_count;
    int del_count = updated_crl->del_count;

    // 应用新增节点
    if (added) {
        for (int i = 0; i < added_count; i++) {
            const CRLNode* node = &added->nodes[i];
            if (node->is_valid && node->hash) {
                // 添加到CRLManager
                if (!CRLManager_add_node(manager, node->hash)) {
                    return 0;
                }
                
                // 如果提供了local_crl哈希表，也添加到哈希表中
                if (local_crl) {
                    // 分配内存用于存储哈希值的副本
                    unsigned char* hash_copy = malloc(32);
                    if (!hash_copy) return 0;
                    
                    // 复制哈希值
                    memcpy(hash_copy, node->hash, 32);
                    
                    // 将哈希值加入local_crl，不存储值
                    if (!hashmap_put(local_crl, hash_copy, NULL, 0)) {
                        free(hash_copy);
                        return 0;
                    }
                }
            } else {
                // 添加无效节点以保持索引一致性
                if (manager->base_v >= manager->capacity) {
                    if (!expand_nodes_array(manager)) return 0;
                }
                
                manager->nodes[manager->base_v].hash = NULL;
                manager->nodes[manager->base_v].is_valid = 0;
                manager->base_v++;
            }
        }
    }

    // 应用删除节点
    if (del_crl) {
        for (int i = 0; i < del_count; i++) {
            int version = del_crl->del_versions[i];
            
            // 从local_crl中删除哈希值
            if (local_crl && version >= 0 && version < manager->base_v) {
                if (manager->nodes[version].hash) {
                    hashmap_remove(local_crl, manager->nodes[version].hash);
                }
            }
            
            // 从CRLManager中删除节点
            if (!CRLManager_remove_node(manager, version)) {
                return 0;
            }
        }
    }

    return 1;
}

// 打印CRL状态
void CRLManager_print(CRLManager* manager) {
    if (!manager) {
        printf("CRL Manager is NULL\n");
        return;
    }
    printf("--------------------------------\n");
    printf("Version(%d,%d)\n", manager->base_v, manager->removed_v);
    printf("Node Status: ");
    for (int i = 0; i < manager->base_v; i++) {
        printf("%d ", manager->nodes[i].is_valid);
    }
    printf("\n");
    printf("--------------------------------\n");
}

// 将CRLManager持久化到文件
int CRLManager_save_to_file(const CRLManager* manager, const char* filename) {
    if (!manager || !filename) return 0;
    
    FILE* file = fopen(filename, "wb");
    if (!file) return 0;
    
    // 写入基本信息
    if (fwrite(&manager->base_v, sizeof(int), 1, file) != 1 ||
        fwrite(&manager->capacity, sizeof(int), 1, file) != 1 ||
        fwrite(&manager->removed_v, sizeof(int), 1, file) != 1 ||
        fwrite(&manager->removed_capacity, sizeof(int), 1, file) != 1) {
        fclose(file);
        return 0;
    }
    
    // 写入节点数组，对于每个节点，先写入is_valid标志
    for (int i = 0; i < manager->base_v; i++) {
        // 写入有效标志
        if (fwrite(&manager->nodes[i].is_valid, sizeof(int), 1, file) != 1) {
            fclose(file);
            return 0;
        }
        
        // 如果节点有效且哈希值存在，则写入哈希值
        if (manager->nodes[i].is_valid && manager->nodes[i].hash) {
            if (fwrite(manager->nodes[i].hash, 32, 1, file) != 1) {
                fclose(file);
                return 0;
            }
        }
    }
    
    // 写入RemovedCRL数组（如果存在）
    if (manager->RemovedCRL && manager->removed_v > 0) {
        if (fwrite(manager->RemovedCRL, sizeof(int), manager->removed_v, file) != manager->removed_v) {
            fclose(file);
            return 0;
        }
    }
    
    fclose(file);
    return 1;
}

// 从文件加载CRLManager
CRLManager* CRLManager_load_from_file(const char* filename) {
    if (!filename) return NULL;
    
    FILE* file = fopen(filename, "rb");
    if (!file) return CRLManager_init(512, 512);
    
    // 读取基本信息
    int base_v, capacity, removed_v, removed_capacity;
    if (fread(&base_v, sizeof(int), 1, file) != 1 ||
        fread(&capacity, sizeof(int), 1, file) != 1 ||
        fread(&removed_v, sizeof(int), 1, file) != 1 ||
        fread(&removed_capacity, sizeof(int), 1, file) != 1) {
        fclose(file);
        return NULL;
    }
    
    // 创建CRLManager对象
    CRLManager* manager = CRLManager_init(capacity, removed_capacity);
    if (!manager) {
        fclose(file);
        return NULL;
    }
    
    // 更新版本号
    manager->base_v = base_v;
    manager->removed_v = removed_v;
    
    // 读取节点数组
    for (int i = 0; i < base_v; i++) {
        // 读取有效标志
        if (fread(&manager->nodes[i].is_valid, sizeof(int), 1, file) != 1) {
            CRLManager_free(manager);
            fclose(file);
            return NULL;
        }
        
        // 如果节点有效，则读取哈希值
        if (manager->nodes[i].is_valid) {
            manager->nodes[i].hash = (unsigned char*)malloc(32);
            if (!manager->nodes[i].hash) {
                CRLManager_free(manager);
                fclose(file);
                return NULL;
            }
            
            if (fread(manager->nodes[i].hash, 32, 1, file) != 1) {
                CRLManager_free(manager);
                fclose(file);
                return NULL;
            }
        }
    }
    
    // 读取RemovedCRL数组（如果存在）
    if (removed_capacity > 0 && removed_v > 0) {
        if (fread(manager->RemovedCRL, sizeof(int), removed_v, file) != removed_v) {
            CRLManager_free(manager);
            fclose(file);
            return NULL;
        }
    }
    
    fclose(file);
    return manager;
}