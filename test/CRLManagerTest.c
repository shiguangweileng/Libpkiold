#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../include/crlmanager.h"

// 辅助函数：获取文件大小
long get_file_size(const char* filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

// 辅助函数：打印UpdatedCRL内容
void print_updated_crl(const UpdatedCRL* updated_crl) {
    if (!updated_crl) {
        printf("更新包为空\n");
        return;
    }
    
    printf("--------------------------------\n");
    printf("更新包内容：\n");
    printf("新增节点数量: %d, 删除节点数量: %d\n", updated_crl->added_count, updated_crl->del_count);
    
    if (updated_crl->added) {
        AddedCRL* added = updated_crl->added;
        printf("base_v变动: (%d->%d)\n", added->begin_v, added->end_v);
        printf("新增节点状态: ");
        for (int i = 0; i < updated_crl->added_count; i++) {
            printf("%d ", added->nodes[i].is_valid);
        }
        printf("\n");
    }
    
    if (updated_crl->del_crl) {
        DelCRL* del_crl = updated_crl->del_crl;
        printf("removed_v变动: (%d->%d)\n", del_crl->begin_v, del_crl->end_v);
        printf("删除节点版本: ");
        for (int i = 0; i < updated_crl->del_count; i++) {
            printf("%d ", del_crl->del_versions[i]);
        }
        printf("\n");
    }
    printf("--------------------------------\n");
}

// 辅助函数：保存用户CRL并打印文件大小
void save_and_print_user_crl(CRLManager* manager, const char* filename) {
    // 保存到文件
    if (CRLManager_save_to_file(manager, filename) != 0) {
        printf("保存CRL到文件失败: %s\n", filename);
        return;
    }
    
    // 获取并打印文件大小
    long file_size = get_file_size(filename);
    if (file_size >= 0) {
        printf("CRL文件大小: %ld 字节\n", file_size);
    } else {
        printf("获取文件大小失败: %s\n", filename);
    }
}

// 生成一个示例哈希值
void generate_hash(unsigned char* hash, int seed) {
    for (int i = 0; i < 32; i++) {
        hash[i] = (unsigned char)(i + seed) % 256;
    }
}

int main() {
    // 初始化CA和用户的CRL管理器
    CRLManager* ca_manager = CRLManager_init(10, 10);
    CRLManager* user_manager = CRLManager_init(10, 0);
    
    if (!ca_manager || !user_manager) {
        printf("初始化管理器失败\n");
        return -1;
    }
    
    const char* user_crl_file = "user_crl.dat";
    unsigned char hash[32];
    
    printf("\n步骤1: CA加入3个证书哈希，用户同步\n");
    // CA添加3个哈希
    for (int i = 0; i < 3; i++) {
        generate_hash(hash, i);
        CRLManager_add_node(ca_manager, hash);
    }
    
    printf("CA状态：\n");
    CRLManager_print(ca_manager);
    
    // 用户同步初始状态
    UpdatedCRL* update1 = CRLManager_generate_update(ca_manager, 0, 0);
    printf("用户获取初始同步包：\n");
    print_updated_crl(update1);
    
    // 应用更新
    CRLManager_apply_update(user_manager, update1);
    printf("用户同步后状态：\n");
    CRLManager_print(user_manager);
    
    // 保存用户CRL并打印文件大小
    save_and_print_user_crl(user_manager, user_crl_file);
    
    // 释放更新包
    CRLManager_free_update(update1);
    
    printf("\n步骤2: CA添加5个证书哈希，删除第5和第7个，用户同步\n");
    // CA添加5个新哈希
    for (int i = 3; i < 8; i++) {
        generate_hash(hash, i);
        CRLManager_add_node(ca_manager, hash);
    }
    
    // CA删除第5个和第7个（索引4和6）
    CRLManager_remove_node(ca_manager, 4);
    CRLManager_remove_node(ca_manager, 6);
    
    printf("CA状态：\n");
    CRLManager_print(ca_manager);
    
    // 用户发起同步请求
    UpdatedCRL* update2 = CRLManager_generate_update(ca_manager, user_manager->base_v, user_manager->removed_v);
    printf("用户获取第二次同步包：\n");
    print_updated_crl(update2);
    
    // 应用更新
    CRLManager_apply_update(user_manager, update2);
    printf("用户同步后状态：\n");
    CRLManager_print(user_manager);
    
    // 保存用户CRL并打印文件大小
    save_and_print_user_crl(user_manager, user_crl_file);
    
    // 释放更新包
    CRLManager_free_update(update2);
    
    printf("\n步骤3: CA删除第2和第3个，用户同步\n");
    // CA删除第2个和第3个（索引1和2）
    CRLManager_remove_node(ca_manager, 1);
    CRLManager_remove_node(ca_manager, 2);
    
    printf("CA状态：\n");
    CRLManager_print(ca_manager);
    
    // 用户发起同步请求
    UpdatedCRL* update3 = CRLManager_generate_update(ca_manager, user_manager->base_v, user_manager->removed_v);
    printf("用户获取第三次同步包：\n");
    print_updated_crl(update3);
    
    // 应用更新
    CRLManager_apply_update(user_manager, update3);
    printf("用户同步后状态：\n");
    CRLManager_print(user_manager);
    
    // 保存用户CRL并打印文件大小
    save_and_print_user_crl(user_manager, user_crl_file);
    
    // 释放更新包
    CRLManager_free_update(update3);
    
    // 测试从文件加载
    printf("\n测试从文件加载用户CRL\n");
    CRLManager* loaded_manager = CRLManager_load_from_file(user_crl_file);
    if (loaded_manager) {
        printf("从文件加载的CRL状态：\n");
        CRLManager_print(loaded_manager);
        CRLManager_free(loaded_manager);
    } else {
        printf("从文件加载CRL失败\n");
    }
    
    // 清理资源
    CRLManager_free(ca_manager);
    CRLManager_free(user_manager);
    
    return 0;
}
