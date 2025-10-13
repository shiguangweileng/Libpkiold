#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include "gm_crypto.h"
#include "imp_cert.h"
#include <sys/stat.h>
#include <unistd.h>

#define CA_KEY_DIR "server/ca-server"
#define CA_PUB_PATH CA_KEY_DIR "/ca_pub.key"
#define CA_PRI_PATH CA_KEY_DIR "/ca_priv.key"

// gcc -Iinclude admin.c src/common.c src/imp_cert.c src/gm_crypto.c -l:libcrypto.so.3 -o admin
#define CA_ID "CA01"   // 与CA保持一致

static unsigned char d_ca[SM2_PRI_MAX_SIZE];   // CA私钥
static unsigned char Q_ca[SM2_PUB_MAX_SIZE];   // CA公钥
unsigned char cert_version = CERT_V1;
unsigned int current_serial_num = 1;

/* 函数声明 */
int ensure_ca_keys();

char* generate_serial_num() {
    static char serial_str[9];  // SN + 6位数字 + 结束符
    
    // 格式化序列号
    snprintf(serial_str, sizeof(serial_str), SERIAL_NUM_FORMAT, current_serial_num);
    
    // 递增序列号
    current_serial_num++;
    if (current_serial_num > SERIAL_NUM_MAX) {
        current_serial_num = 1;  // 超过最大值，重置为1
        printf("警告：序列号已达到最大值，重置为1\n");
    }
    return serial_str;
}

/* 根据用户ID生成隐式证书并输出相关文件 */
int local_generate_cert(const char *subject_id) { 
    BIGNUM *Ku = NULL;
    BIGNUM *k = NULL;
    EC_POINT *Ru = NULL;
    EC_POINT *Pu = NULL;
    char* serial_num = NULL;
    ImpCertExt *extensions = NULL;
    ImpCert *cert = NULL;
    int ret = 0;
    
    //--------step1:用户端(现在由CA模拟)-----------
    Ku = BN_new();
    BN_rand_range(Ku, order);

    Ru = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Ru, Ku, NULL, NULL, NULL)) {
        printf("计算临时公钥Ru失败\n");
        goto cleanup;
    }
    
    // --------step2:CA端生成隐式证书计算部分重构值-----------
    k = BN_new();
    BN_rand_range(k, order);

    Pu = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Pu, k, NULL, NULL, NULL) ||
        !EC_POINT_add(group, Pu, Ru, Pu, NULL)) {
        printf("计算Pu失败\n");
        goto cleanup;
    }

    serial_num = generate_serial_num();
    printf("生成新证书，序列号: %s\n", serial_num);

    // 如果是V2证书，需要准备扩展信息
    if (cert_version == CERT_V2) {
        extensions = (ImpCertExt *)malloc(sizeof(ImpCertExt));
        if (!extensions) {
            printf("分配扩展信息内存失败\n");
            goto cleanup;
        }
        // 设置扩展字段
        extensions->Usage = USAGE_IDENTITY;
        extensions->SignAlg = SIGN_SM2;
        extensions->HashAlg = HASH_SM3;
        
        // 填充额外信息
        memset(extensions->ExtraInfo, 0, 11);
        strcpy((char *)extensions->ExtraInfo, "ExtraInfo");
    }

    cert = (ImpCert *)malloc(sizeof(ImpCert));
    time_t current_time = time(NULL);
    time_t expire_time = current_time + 60*60*24; // 1天有效期
    if(!set_cert(cert, 
              cert_version,
              (unsigned char *)serial_num,
              (unsigned char *)CA_ID, 
              (unsigned char *)subject_id,
              current_time, expire_time,
              current_time,
              Pu, extensions)){
        printf("证书设置失败！\n");
        goto cleanup;
    }
    
    char cert_filename[100] = {0};
    sprintf(cert_filename, "%s.crt", subject_id);
    if (!save_cert(cert, cert_filename)) {
        printf("警告：无法保存用户证书到文件\n");
    }
    
    unsigned char cert_hash[32];
    calc_cert_hash(cert, cert_hash);
    print_hex("隐式证书哈希值e", cert_hash, 32);
    
    unsigned char r[SM2_PRI_MAX_SIZE];
    calculate_r(r, cert_hash, k, d_ca, order);
    
    //--------step3:用户端生成最终的公私钥对(现在由CA模拟)-------------
    unsigned char d_u[SM2_PRI_MAX_SIZE];
    calculate_r(d_u, cert_hash, Ku, r, order);
    
    unsigned char Qu[SM2_PUB_MAX_SIZE];
    rec_pubkey(Qu, cert_hash, Pu, Q_ca);

    if(!verify_key_pair_bytes(group, Qu, d_u)){
        printf("密钥对验证失败！\n");
        goto cleanup;
    }

    char priv_key_filename[100] = {0};
    sprintf(priv_key_filename, "%s_priv.key", subject_id);
    FILE *key_file = fopen(priv_key_filename, "wb");
    if (key_file) {
        fwrite(d_u, 1, SM2_PRI_MAX_SIZE, key_file);
        fclose(key_file);
    } else {
        printf("警告：无法保存用户私钥到文件\n");
    }
    
    char pub_key_filename[100] = {0};
    sprintf(pub_key_filename, "%s_pub.key", subject_id);
    FILE *pub_key_file = fopen(pub_key_filename, "wb");
    if (pub_key_file) {
        fwrite(Qu, 1, SM2_PUB_MAX_SIZE, pub_key_file);
        fclose(pub_key_file);
    } else {
        printf("警告：无法保存用户公钥到文件\n");
    }
    ret = 1;
    
cleanup:
    if (Ru) EC_POINT_free(Ru);
    if (Pu) EC_POINT_free(Pu);
    if (k) BN_free(k);
    if (Ku) BN_free(Ku);
    if (cert) free_cert(cert);
    return ret;
}

/* 载入并打印证书信息 */
static void inspect_cert_file(const char *path)
{
    ImpCert cert={0};
    if(!load_cert(&cert, path)){
        printf("加载证书失败: %s\n", path);
        return;
    }
    print_cert_info(&cert);
    free_cert(&cert);
}

int main()
{
    // 初始化SM2全局参数并加载CA公私钥
    if (!ensure_ca_keys()) {
        printf("CA初始化失败！\n");
        return -1;
    }

    while(1){
        printf("\n===== Admin 工具 =====\n");
        printf("1. 输入ID生成证书及公私钥\n");
        printf("2. 输入证书文件路径查看信息\n");
        printf("0. 退出\n");
        printf("请选择: ");
        int choice = 0;
        if(scanf("%d", &choice)!=1){
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();
        if(choice==1){
            char id[SUBJECT_ID_SIZE]={0};
            printf("请输入4字节ID: ");
            if(scanf("%4s", id)!=1){ clear_input_buffer(); continue;} 
            clear_input_buffer();
            local_generate_cert(id);
        }else if(choice==2){
            char path[256]={0};
            printf("请输入证书文件路径: ");
            if(fgets(path, sizeof(path), stdin)==NULL) continue;
            // 去掉换行
            size_t len=strlen(path); if(len>0 && path[len-1]=='\n') path[len-1]='\0';
            inspect_cert_file(path);
        }else if(choice==0){
            break;
        }
    }
    global_params_cleanup();
    return 0;
}

/* ensure_ca_keys 实现 */
int ensure_ca_keys()
{
    // 初始化SM2全局参数
    if (!global_params_init()) {
        printf("SM2参数初始化失败！\n");
        return 0;
    }

    // 确保密钥目录存在
    struct stat st = {0};
    if (stat(CA_KEY_DIR, &st) == -1) {
        if (mkdir(CA_KEY_DIR, 0755) == -1) {
            printf("无法创建目录: %s\n", CA_KEY_DIR);
            return 0;
        }
    }

    FILE *pub_fp = fopen(CA_PUB_PATH, "rb");
    FILE *pri_fp = fopen(CA_PRI_PATH, "rb");
    int key_loaded = 0;
    if (pub_fp && pri_fp) {
        // 读取已有密钥
        if (fread(Q_ca, 1, SM2_PUB_MAX_SIZE, pub_fp) == SM2_PUB_MAX_SIZE &&
            fread(d_ca, 1, SM2_PRI_MAX_SIZE, pri_fp) == SM2_PRI_MAX_SIZE) {
            key_loaded = 1;
        }
    }
    if (pub_fp) fclose(pub_fp);
    if (pri_fp) fclose(pri_fp);

    // 若读取失败则生成新密钥对
    if (!key_loaded) {
        printf("未检测到CA密钥，正在生成新密钥对...\n");
        if (!sm2_key_pair_new(Q_ca, d_ca)) {
            printf("生成CA密钥对失败！\n");
            return 0;
        }
        // 保存到文件
        pub_fp = fopen(CA_PUB_PATH, "wb");
        pri_fp = fopen(CA_PRI_PATH, "wb");
        if (!pub_fp || !pri_fp ||
            fwrite(Q_ca, 1, SM2_PUB_MAX_SIZE, pub_fp) != SM2_PUB_MAX_SIZE ||
            fwrite(d_ca, 1, SM2_PRI_MAX_SIZE, pri_fp) != SM2_PRI_MAX_SIZE) {
            printf("保存CA密钥文件失败！\n");
            if (pub_fp) fclose(pub_fp);
            if (pri_fp) fclose(pri_fp);
            return 0;
        }
        fclose(pub_fp);
        fclose(pri_fp);
        printf("CA密钥对已生成并保存到 %s\n", CA_KEY_DIR);
    }
    return 1;
}