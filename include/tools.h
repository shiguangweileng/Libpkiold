#ifndef TOOLS_H
#define TOOLS_H
#include <stdio.h>
#include "common.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

EXPORT void print_hex(const char *name, const unsigned char *data, int data_len);
EXPORT void print_bn(const char *name, const BIGNUM *bn);

// 计算r=e×k+d (mod n)
EXPORT int calculate_r(unsigned char *r, const unsigned char *e, const BIGNUM *k, 
                const unsigned char *d, const BIGNUM *n);

EXPORT int verify_key_pair(const EC_GROUP *group, const EC_POINT *pub_key, const BIGNUM *pri_key);

EXPORT int verify_key_pair_bytes(const EC_GROUP *group, const unsigned char *pub_key, const unsigned char *pri_key);

//公钥重构 Qu=e×Pu+Q_ca
EXPORT int rec_pubkey(unsigned char *Qu, const unsigned char *e, const EC_POINT *Pu, const unsigned char *Q_ca);
#endif