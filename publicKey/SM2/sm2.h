/*
 * sm2.h — SM2 椭圆曲线公钥密码算法接口（GB/T 32918-2016）
 *
 * 实现参考：GmSSL (github.com/guanzhi/GmSSL) 的算法流程与曲线参数，
 * 点运算基于本项目自研 256 位大整数库（bn.h），采用仿射坐标。
 * 密文格式：C1x(32) || C1y(32) || C2(明文长) || C3(32)，即 C1||C2||C3。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c sm2.c
 */

#ifndef SM2_H
#define SM2_H

#include <stddef.h>
#include <stdint.h>

#include "bn.h"

#define SM2_POINT_SIZE   64   /* 点坐标 x||y 各 32 字节 */
#define SM2_HASH_SIZE    32   /* SM3 摘要长度 */
#define SM2_MAX_PLAINTEXT 1024

/* 仿射坐标点：无穷远点用 infinity 标志表示 */
typedef struct {
    bn_t x;
    bn_t y;
    int infinity;
} SM2_POINT;

/* 密钥对：d 为私钥（[1, n-2]），P 为公钥（P = dG） */
typedef struct {
    bn_t d;
    SM2_POINT P;
} SM2_KEY;

/* 生成密钥对：d 从 /dev/urandom 随机，P = dG；成功返回 0，失败返回 -1 */
int sm2_keygen(SM2_KEY *key);

/* 加密：out = C1x||C1y||C2||C3，*outlen = 64 + inlen + 32；成功返回 0 */
int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen,
                uint8_t *out, size_t *outlen);

/* 解密：in 为 sm2_encrypt 的输出；成功返回 0，参数错误或校验失败返回 -1 */
int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen,
                uint8_t *out, size_t *outlen);

/* 测试用：注入随机数 k 的加密，用于官方向量对拍 */
int sm2_encrypt_with_k(const SM2_KEY *key, const bn_t k,
                       const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen);

/* 测试用：校验点是否在曲线上（y² ≡ x³ + ax + b mod p） */
int sm2_point_on_curve(const SM2_POINT *P);

#endif /* SM2_H */
