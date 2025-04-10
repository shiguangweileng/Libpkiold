#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/crlmanager.h"

// 用于生成随机哈希的辅助函数
void generate_random_hash(unsigned char* hash) {
    for (int i = 0; i < 32; i++) {
        hash[i] = rand() % 256;
    }
}

// 用于打印哈希值的辅助函数
void print_hash(const unsigned char* hash) {
    for (int i = 0; i < 8; i++) { // 仅打印前8字节作为示例
        printf("%02x", hash[i]);
    }
}

// 打印更新包内容
void print_update(const UpdatedCRL* update) {
    printf("更新包内容:\n");
    printf("新增节点数量: %d\n", update->added_count);
    if (update->added_count > 0) {
        printf("新增节点版本范围: %d 到 %d\n", 
               update->added->begin_v, 
               update->added->end_v - 1);
        printf("新增节点详情:\n");
        for (int i = 0; i < update->added_count; i++) {
            printf("版本 %d: 哈希=", update->added->begin_v + i);
            print_hash(update->added->nodes[i].hash);
            printf(", 有效=%d\n", update->added->nodes[i].is_valid);
        }
    }
    
    printf("删除节点数量: %d\n", update->del_count);
    if (update->del_count > 0) {
        printf("删除的版本号: ");
        for (int i = 0; i < update->del_count; i++) {
            printf("%d ", update->del_crl->del_versions[i]);
        }
        printf("\n");
    }
}

int main() {
    srand((unsigned int)time(NULL));
    
    // 初始化CA和用户的CRL管理器
    CRLManager* ca_manager = CRLManager_init(10, 10);
    CRLManager* user_manager = CRLManager_init(10, 10);
    
    if (!ca_manager || !user_manager) {
        printf("初始化CRL管理器失败\n");
        return -1;
    }
    
    unsigned char hash[32];
    int buffer_size = 4096;
    unsigned char* buffer = (unsigned char*)malloc(buffer_size);
    if (!buffer) {
        printf("内存分配失败\n");
        CRLManager_free(ca_manager);
        CRLManager_free(user_manager);
        return -1;
    }
    
    printf("\n==== 步骤1: CA添加3个证书哈希，用户同步 ====\n");
    
    // CA添加3个证书哈希
    for (int i = 0; i < 3; i++) {
        generate_random_hash(hash);
        CRLManager_add_node(ca_manager, hash);
        printf("CA添加证书 #%d: ", i);
        print_hash(hash);
        printf("\n");
    }
    
    printf("\nCA状态: ");
    CRLManager_print(ca_manager);
    
    // 用户同步
    UpdatedCRL* update = CRLManager_generate_update(ca_manager, 0, 0);
    int serialized_size = CRLManager_serialize_update(update, buffer, buffer_size);
    
    printf("\n用户从CA获取更新包（初始同步）\n");
    UpdatedCRL* received_update = CRLManager_deserialize_update(buffer, serialized_size);
    CRLManager_apply_update(user_manager, received_update);
    
    printf("用户状态: ");
    CRLManager_print(user_manager);
    
    CRLManager_free_update(update);
    CRLManager_free_update(received_update);
    
    printf("\n==== 步骤2: CA添加5个证书，删除索引5和7的证书，用户同步 ====\n");
    
    // CA添加5个新证书
    for (int i = 0; i < 5; i++) {
        generate_random_hash(hash);
        CRLManager_add_node(ca_manager, hash);
        printf("CA添加证书 #%d: ", i + 3);
        print_hash(hash);
        printf("\n");
    }
    
    // CA删除索引为5和7的证书
    printf("CA删除索引为5的证书\n");
    CRLManager_remove_node(ca_manager, 5);
    printf("CA删除索引为7的证书\n");
    CRLManager_remove_node(ca_manager, 7);
    
    printf("\nCA状态: ");
    CRLManager_print(ca_manager);
    
    // 用户同步（用户当前base_v=3, removed_v=0）
    update = CRLManager_generate_update(ca_manager, 3, 0);
    serialized_size = CRLManager_serialize_update(update, buffer, buffer_size);
    
    printf("\n用户从CA获取更新包\n");
    received_update = CRLManager_deserialize_update(buffer, serialized_size);
    
    // 打印此次更新包内容
    print_update(received_update);
    
    CRLManager_apply_update(user_manager, received_update);
    
    printf("\n用户同步后状态: ");
    CRLManager_print(user_manager);
    
    CRLManager_free_update(update);
    CRLManager_free_update(received_update);
    
    printf("\n==== 步骤3: CA删除索引2和3的证书，用户同步 ====\n");
    
    // CA删除索引为2和3的证书
    printf("CA删除索引为2的证书\n");
    CRLManager_remove_node(ca_manager, 2);
    printf("CA删除索引为3的证书\n");
    CRLManager_remove_node(ca_manager, 3);
    
    printf("\nCA状态: ");
    CRLManager_print(ca_manager);
    
    // 用户同步（用户当前base_v=8, removed_v=2）
    update = CRLManager_generate_update(ca_manager, 8, 2);
    serialized_size = CRLManager_serialize_update(update, buffer, buffer_size);
    
    printf("\n用户从CA获取更新包\n");
    received_update = CRLManager_deserialize_update(buffer, serialized_size);
    
    // 打印此次更新包内容
    print_update(received_update);
    
    CRLManager_apply_update(user_manager, received_update);
    
    printf("\n用户同步后状态: ");
    CRLManager_print(user_manager);
    
    // 清理资源
    CRLManager_free_update(update);
    CRLManager_free_update(received_update);
    free(buffer);
    CRLManager_free(ca_manager);
    CRLManager_free(user_manager);
    
    return 0;
}

