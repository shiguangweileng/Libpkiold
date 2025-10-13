#include "std_crypto.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// gcc std_crypto.c std-test.c -I../include -lcrypto -o std-test
static void hexdump(const char *label, const unsigned char *buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; ++i)
        printf("%02X", buf[i]);
    printf("\n");
}

static void test_aes_gcm(void)
{
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    unsigned char tag[AES_TAG_SIZE];
    const char *plaintext = "This is a test message for AES-GCM.";
    int plaintext_len = strlen(plaintext);

    unsigned char ciphertext[plaintext_len];
    unsigned char decryptedtext[plaintext_len];

    assert(aes_generate_key(key) == 1);
    assert(aes_generate_iv(iv) == 1);

    hexdump("AES Key: ", key, sizeof(key));
    hexdump("AES IV:  ", iv, sizeof(iv));

    /* 加密 */
    assert(aes_encrypt(ciphertext, tag, (const unsigned char *)plaintext, plaintext_len, key, iv) == 1);
    hexdump("Ciphertext: ", ciphertext, sizeof(ciphertext));
    hexdump("Tag: ", tag, sizeof(tag));

    /* 解密 */
    assert(aes_decrypt(decryptedtext, ciphertext, sizeof(ciphertext), tag, key, iv) == 1);
    printf("Decrypted Text: %s\n", decryptedtext);
    assert(memcmp(plaintext, decryptedtext, plaintext_len) == 0);

    /* 篡改tag应导致解密失败 */
    tag[0] ^= 0xFF;
    assert(aes_decrypt(decryptedtext, ciphertext, sizeof(ciphertext), tag, key, iv) == 0);
    tag[0] ^= 0xFF; // 恢复

    /* 篡改密文应导致解密失败 */
    ciphertext[0] ^= 0xFF;
    assert(aes_decrypt(decryptedtext, ciphertext, sizeof(ciphertext), tag, key, iv) == 0);

    printf("AES-GCM encrypt/decrypt tests passed!\n");
}

static void test_hash_kdf(void)
{
    const unsigned char msg[] = "abc";
    unsigned char hash[SHA256_MD_SIZE];
    const unsigned char expected_hash[SHA256_MD_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    assert(sha256_hash(msg, sizeof(msg) - 1, hash) == 1);
    hexdump("sha256(\"abc\")=", hash, sizeof(hash));
    assert(memcmp(hash, expected_hash, sizeof(hash)) == 0);

    /* KDF测试：验证其内部逻辑是否为 H(in || 0x00000001) */
    unsigned char kdf_out[16];
    unsigned char expected_kdf_calc[SHA256_MD_SIZE];
    unsigned char kdf_in[sizeof(msg) -1 + 4];
    memcpy(kdf_in, msg, sizeof(msg) - 1);
    kdf_in[sizeof(msg) - 1 + 0] = 0x00;
    kdf_in[sizeof(msg) - 1 + 1] = 0x00;
    kdf_in[sizeof(msg) - 1 + 2] = 0x00;
    kdf_in[sizeof(msg) - 1 + 3] = 0x01;

    assert(sha256_hash(kdf_in, sizeof(kdf_in), expected_kdf_calc) == 1);
    assert(sha256_kdf(msg, sizeof(msg) - 1, kdf_out, sizeof(kdf_out)) == 1);
    hexdump("sha256_kdf(\"abc\", 16)=", kdf_out, sizeof(kdf_out));
    assert(memcmp(kdf_out, expected_kdf_calc, sizeof(kdf_out)) == 0);

    printf("SHA256 hash/kdf tests passed!\n");
}

int main(void)
{
    test_aes_gcm();
    printf("\n");
    test_hash_kdf();

    unsigned char pub[ECC_PUB_MAX_SIZE] = {0};
    unsigned char pri[ECC_PRI_MAX_SIZE] = {0};

    /* 生成密钥对 */
    assert(ecc_key_pair_new(pub, pri) == 1);

    /* 打印密钥 */
    hexdump("pub=", pub, sizeof(pub));
    hexdump("pri=", pri, sizeof(pri));

    /* 准备随机消息 */
    unsigned char msg[128];
    RAND_bytes(msg, sizeof(msg));

    /* 签名并验证 */
    unsigned char sig[ECC_SIG_SIZE] = {0};
    assert(ecc_sign(sig, msg, sizeof(msg), pri) == 1);
    hexdump("sig=", sig, sizeof(sig));

    /* 正确验签应成功 */
    assert(ecc_verify(sig, msg, sizeof(msg), pub) == 1);

    /* 篡改消息应导致验签失败 */
    msg[0] ^= 0xFF;
    assert(ecc_verify(sig, msg, sizeof(msg), pub) == 0);

    printf("ECC P-256 sign/verify tests passed!\n");
    return 0;
}
