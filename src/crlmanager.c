#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crlmanager.h"

// 初始化CRL管理器
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
        free(manager->nodes);
        if (manager->RemovedCRL) {
            free(manager->RemovedCRL);
        }
        free(manager);
    }
}

// 添加新的CRL节点
int CRLManager_add_node(CRLManager* manager, const unsigned char* hash) {
    if (!manager || !hash) return -1;

    // 检查是否需要扩容
    if (manager->base_v >= manager->capacity) {
        int new_capacity = manager->capacity * 2;
        CRLNode* new_nodes = (CRLNode*)realloc(manager->nodes, new_capacity * sizeof(CRLNode));
        if (!new_nodes) return -1;
        manager->nodes = new_nodes;
        manager->capacity = new_capacity;
    }

    // 添加新节点
    memcpy(manager->nodes[manager->base_v].hash, hash, 32);
    manager->nodes[manager->base_v].is_valid = 1;
    manager->base_v++;

    return manager->base_v - 1; // 返回新节点的版本号
}

// 删除CRL节点
int CRLManager_remove_node(CRLManager* manager, int version) {
    if (!manager || version < 0 || version >= manager->base_v) return -1;

    // 如果RemovedCRL已分配，则记录删除的版本号
    if (manager->RemovedCRL) {
        // 检查RemovedCRL是否需要扩容
        if (manager->removed_v >= manager->removed_capacity) {
            int new_capacity = manager->removed_capacity * 2;
            int* new_removed = (int*)realloc(manager->RemovedCRL, new_capacity * sizeof(int));
            if (!new_removed) return -1;
            manager->RemovedCRL = new_removed;
            manager->removed_capacity = new_capacity;
        }

        // 将版本号添加到RemovedCRL数组
        manager->RemovedCRL[manager->removed_v] = version;
    }

    // 标记为无效
    memset(manager->nodes[version].hash, 0, 32);
    manager->nodes[version].is_valid = 0;
    manager->removed_v++;

    return 0;
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

    // 复制所有节点，无论是否有效，保留原始位置信息
    memcpy(added->nodes, &manager->nodes[user_base_v], count * sizeof(CRLNode));

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

// 序列化更新包
int CRLManager_serialize_update(const UpdatedCRL* updated_crl, unsigned char* buffer, int buffer_size) {
    if (!updated_crl || !buffer) return -1;

    int offset = 0;
    int required_size = sizeof(int) * 2; // added_count + del_count

    if (updated_crl->added) {
        required_size += sizeof(int) * 2; // begin_v + end_v
        required_size += (updated_crl->added->end_v - updated_crl->added->begin_v) * sizeof(CRLNode);
    }

    if (updated_crl->del_crl) {
        required_size += sizeof(int) * 2; // begin_v + end_v
        required_size += (updated_crl->del_crl->end_v - updated_crl->del_crl->begin_v) * sizeof(int);
    }

    if (buffer_size < required_size) return -1;

    // 序列化added_count和del_count
    memcpy(buffer + offset, &updated_crl->added_count, sizeof(int));
    offset += sizeof(int);
    memcpy(buffer + offset, &updated_crl->del_count, sizeof(int));
    offset += sizeof(int);

    // 序列化AddedCRL
    if (updated_crl->added) {
        memcpy(buffer + offset, &updated_crl->added->begin_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, &updated_crl->added->end_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, updated_crl->added->nodes, 
               (updated_crl->added->end_v - updated_crl->added->begin_v) * sizeof(CRLNode));
        offset += (updated_crl->added->end_v - updated_crl->added->begin_v) * sizeof(CRLNode);
    }

    // 序列化DelCRL
    if (updated_crl->del_crl) {
        memcpy(buffer + offset, &updated_crl->del_crl->begin_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, &updated_crl->del_crl->end_v, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer + offset, updated_crl->del_crl->del_versions,
               (updated_crl->del_crl->end_v - updated_crl->del_crl->begin_v) * sizeof(int));
        offset += (updated_crl->del_crl->end_v - updated_crl->del_crl->begin_v) * sizeof(int);
    }

    return offset;
}

// 释放更新包
void CRLManager_free_update(UpdatedCRL* updated_crl) {
    if (!updated_crl) return;

    if (updated_crl->added) {
        free(updated_crl->added->nodes);
        free(updated_crl->added);
    }

    if (updated_crl->del_crl) {
        free(updated_crl->del_crl->del_versions);
        free(updated_crl->del_crl);
    }

    free(updated_crl);
}

// 反序列化更新包
UpdatedCRL* CRLManager_deserialize_update(const unsigned char* buffer, int buffer_size) {
    if (!buffer || buffer_size < sizeof(int) * 2) return NULL;

    UpdatedCRL* updated_crl = (UpdatedCRL*)malloc(sizeof(UpdatedCRL));
    if (!updated_crl) return NULL;

    int offset = 0;

    // 反序列化added_count和del_count
    memcpy(&updated_crl->added_count, buffer + offset, sizeof(int));
    offset += sizeof(int);
    memcpy(&updated_crl->del_count, buffer + offset, sizeof(int));
    offset += sizeof(int);

    // 反序列化AddedCRL
    if (updated_crl->added_count > 0) {
        updated_crl->added = (AddedCRL*)malloc(sizeof(AddedCRL));
        if (!updated_crl->added) {
            free(updated_crl);
            return NULL;
        }

        memcpy(&updated_crl->added->begin_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        memcpy(&updated_crl->added->end_v, buffer + offset, sizeof(int));
        offset += sizeof(int);

        updated_crl->added->nodes = (CRLNode*)malloc(updated_crl->added_count * sizeof(CRLNode));
        if (!updated_crl->added->nodes) {
            free(updated_crl->added);
            free(updated_crl);
            return NULL;
        }

        memcpy(updated_crl->added->nodes, buffer + offset, updated_crl->added_count * sizeof(CRLNode));
        offset += updated_crl->added_count * sizeof(CRLNode);
    } else {
        updated_crl->added = NULL;
    }

    // 反序列化DelCRL
    if (updated_crl->del_count > 0) {
        updated_crl->del_crl = (DelCRL*)malloc(sizeof(DelCRL));
        if (!updated_crl->del_crl) {
            if (updated_crl->added) {
                free(updated_crl->added->nodes);
                free(updated_crl->added);
            }
            free(updated_crl);
            return NULL;
        }

        memcpy(&updated_crl->del_crl->begin_v, buffer + offset, sizeof(int));
        offset += sizeof(int);
        memcpy(&updated_crl->del_crl->end_v, buffer + offset, sizeof(int));
        offset += sizeof(int);

        updated_crl->del_crl->del_versions = (int*)malloc(updated_crl->del_count * sizeof(int));
        if (!updated_crl->del_crl->del_versions) {
            if (updated_crl->added) {
                free(updated_crl->added->nodes);
                free(updated_crl->added);
            }
            free(updated_crl->del_crl);
            free(updated_crl);
            return NULL;
        }

        memcpy(updated_crl->del_crl->del_versions, buffer + offset, updated_crl->del_count * sizeof(int));
        offset += updated_crl->del_count * sizeof(int);
    } else {
        updated_crl->del_crl = NULL;
    }

    return updated_crl;
}

// 应用更新到本地CRL管理器
int CRLManager_apply_update(CRLManager* manager, const UpdatedCRL* updated_crl) {
    if (!manager || !updated_crl) return -1;

    // 应用新增节点
    if (updated_crl->added) {
        for (int i = 0; i < updated_crl->added_count; i++) {
            if (CRLManager_add_node(manager, updated_crl->added->nodes[i].hash) < 0) {
                return -1;
            }
        }
    }

    // 应用删除节点
    if (updated_crl->del_crl) {
        for (int i = 0; i < updated_crl->del_count; i++) {
            if (CRLManager_remove_node(manager, updated_crl->del_crl->del_versions[i]) < 0) {
                return -1;
            }
        }
    }

    return 0;
}

// 打印CRL状态
void CRLManager_print(CRLManager* manager) {
    if (!manager) {
        printf("CRL Manager is NULL\n");
        return;
    }

    printf("Base_v: %d---Removed_v: %d\n", manager->base_v, manager->removed_v);
    printf("Node Status: ");
    for (int i = 0; i < manager->base_v; i++) {
        printf("%d ", manager->nodes[i].is_valid);
    }
    printf("\n");
}

// 将CRLManager持久化到文件
int CRLManager_save_to_file(const CRLManager* manager, const char* filename) {
    if (!manager || !filename) return -1;
    
    FILE* file = fopen(filename, "wb");
    if (!file) return -1;
    
    // 写入基本信息
    if (fwrite(&manager->base_v, sizeof(int), 1, file) != 1 ||
        fwrite(&manager->capacity, sizeof(int), 1, file) != 1 ||
        fwrite(&manager->removed_v, sizeof(int), 1, file) != 1 ||
        fwrite(&manager->removed_capacity, sizeof(int), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    // 写入节点数组
    if (fwrite(manager->nodes, sizeof(CRLNode), manager->base_v, file) != manager->base_v) {
        fclose(file);
        return -1;
    }
    
    // 写入RemovedCRL数组（如果存在）
    if (manager->RemovedCRL && manager->removed_v > 0) {
        if (fwrite(manager->RemovedCRL, sizeof(int), manager->removed_v, file) != manager->removed_v) {
            fclose(file);
            return -1;
        }
    }
    
    fclose(file);
    return 0;
}

// 从文件加载CRLManager
CRLManager* CRLManager_load_from_file(const char* filename) {
    if (!filename) return NULL;
    
    FILE* file = fopen(filename, "rb");
    if (!file) return NULL;
    
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
    if (fread(manager->nodes, sizeof(CRLNode), base_v, file) != base_v) {
        CRLManager_free(manager);
        fclose(file);
        return NULL;
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