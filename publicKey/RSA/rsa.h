/*
 * rsa.h — RSA 公钥密码算法接口（PKCS#1 教科书式，1024 位）
 *
 * 基于自研 1024 位大整数库 rsa_bn：大素数生成（Miller-Rabin）、
 * 快速指数（平方-乘）、密钥构造（标准扩展欧几里得求 d）。
 * 解密采用 CRT 加速（dp/dq/qinv）。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c rsa.c
 */

#ifndef RSA_H
#define RSA_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_bn.h"

#define RSA_MAX_BLOCK 128   /* 1024 位模数下最大明文块（m < n） */

/* RSA 密钥：公钥 (n, e)，私钥 (d, p, q) + CRT 参数 */
typedef struct {
    rbn_t n;        /* 模数，1024 位 */
    rbn_t e;        /* 公钥指数，默认 65537 */
    rbn_t d;        /* 私钥指数 */
    rbn_t p, q;     /* 素数因子（各 512 位） */
    rbn_t dp, dq;   /* CRT: dp = d mod (p-1), dq = d mod (q-1) */
    rbn_t qinv;     /* CRT: qinv = q⁻¹ mod p */
} RSA_KEY;

/* 生成 bits 位 RSA 密钥（bits 为 n 的位数，支持 512/1024）；成功返回 0 */
int rsa_keygen(RSA_KEY *key, int bits);

/* 公钥加密：m 为明文（≤128 字节且 < n），c 输出固定 128 字节；成功返回 0 */
int rsa_encrypt(const RSA_KEY *key, const uint8_t *m, size_t mlen,
                uint8_t *c);

/* 私钥解密（CRT）：c 为 128 字节密文，m 输出 128 字节大端，
 * 明文位于尾部，*mlen 为明文长度（取 m + 128 - *mlen 处） */
int rsa_decrypt(const RSA_KEY *key, const uint8_t *c,
                uint8_t *m, size_t *mlen);

#endif /* RSA_H */
