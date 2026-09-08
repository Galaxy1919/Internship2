/*
 * bn.h — 256 位定长大整数运算库接口
 *
 * 使用场景：SM2 椭圆曲线密码（GF(p) 上的大整数运算）
 * 表示约定：bn_t 为 4 × uint64_t 小端序数组（d[0] 为最低 64 位）
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c bn.c
 */

#ifndef BN_H
#define BN_H

#include <stdint.h>

#define BN_LIMBS 4              /* 256 / 64 */
#define BN_BITS (BN_LIMBS * 64) /* 256 */

typedef uint64_t bn_t[BN_LIMBS];

/* 比较：a>b 返回 1，a==b 返回 0，a<b 返回 -1 */
int  bn_cmp(const bn_t a, const bn_t b);

/* r = a + b；返回进位（0 或 1） */
int  bn_add(bn_t r, const bn_t a, const bn_t b);

/* r = a - b；返回借位（0 或 1） */
int  bn_sub(bn_t r, const bn_t a, const bn_t b);

/* r = a >> 1（整体右移一位） */
void bn_shr1(bn_t r, const bn_t a);

/* r[8] = a × b（512 位乘积） */
void bn_mul(uint64_t r[2 * BN_LIMBS], const bn_t a, const bn_t b);

/* r = t mod p（t 为 512 位乘积，p 为 256 位模数） */
void bn_mod(bn_t r, const uint64_t t[2 * BN_LIMBS], const bn_t p);

/* r = (a × b) mod p */
void bn_modmul(bn_t r, const bn_t a, const bn_t b, const bn_t p);

/* r = a^e mod p */
void bn_modpow(bn_t r, const bn_t a, const bn_t e, const bn_t p);

/* r = a⁻¹ mod p（前置条件：p 为奇素数，0 < a < p） */
void bn_modinv(bn_t r, const bn_t a, const bn_t p);

/* 解析十六进制到 bn_t（支持可选 0x 前缀）；失败返回 -1 */
int  bn_from_hex(bn_t r, const char *hex);

/* 输出 64 位十六进制（固定宽度）；out 需至少 65 字节 */
void bn_to_hex(const bn_t a, char *out);

#endif /* BN_H */
