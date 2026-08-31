/*
 * rsa_bn.h — RSA 用 1024 位定长大整数运算库接口
 *
 * SM2 的 bn.h 是 256 位定长（4×uint64），RSA-1024 需要 1024 位
 * （16×uint64），故单独提供本层。算法思路与 bn.c 一致：
 * 竖式乘法 / 二进制长除法取模 / 二进制扩展欧几里得求逆 /
 * 平方-乘模幂；另加 Miller-Rabin 素性检测与随机素数生成。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c rsa_bn.c
 */

#ifndef RSA_BN_H
#define RSA_BN_H

#include <stddef.h>
#include <stdint.h>

#define RBN_LIMBS 16            /* 16 × 64 = 1024 位 */
#define RBN_BITS (RBN_LIMBS * 64)

typedef uint64_t rbn_t[RBN_LIMBS];

/* 判断 a 是否为 0 / 1 */
int  rbn_is_zero(const rbn_t a);
int  rbn_is_one(const rbn_t a);

/* 比较：a>b 返回 1，a==b 返回 0，a<b 返回 -1 */
int  rbn_cmp(const rbn_t a, const rbn_t b);

/* r = a + b；返回进位（0 或 1） */
int  rbn_add(rbn_t r, const rbn_t a, const rbn_t b);

/* r = a - b；返回借位（0 或 1） */
int  rbn_sub(rbn_t r, const rbn_t a, const rbn_t b);

/* r = a >> 1 */
void rbn_shr1(rbn_t r, const rbn_t a);

/* r[32] = a × b（2048 位乘积） */
void rbn_mul(uint64_t r[2 * RBN_LIMBS], const rbn_t a, const rbn_t b);

/* r = t mod m（t 为 2048 位，m 为 1024 位模数） */
void rbn_mod(rbn_t r, const uint64_t t[2 * RBN_LIMBS], const rbn_t m);

/* q = a / b, r = a mod b（b 非零；恢复余数法长除法） */
void rbn_divmod(rbn_t q, rbn_t r, const rbn_t a, const rbn_t b);

/* r = (a × b) mod m */
void rbn_modmul(rbn_t r, const rbn_t a, const rbn_t b, const rbn_t m);

/* r = a^e mod m（e 可为 1024 位，如 RSA 私钥指数 d） */
void rbn_modpow(rbn_t r, const rbn_t a, const rbn_t e, const rbn_t m);

/* r = a⁻¹ mod m（前置：m 为奇数，0 < a < m，gcd(a,m)=1） */
void rbn_modinv(rbn_t r, const rbn_t a, const rbn_t m);

/* 小素数试除：n 被小素数整除返回 1，否则 0 */
int  rbn_divisible_small(const rbn_t n);

/* Miller-Rabin 单轮：以 base 为底；返回 1 可能素数，0 确定合数 */
int  rbn_miller_rabin(const rbn_t n, const rbn_t base);

/* 综合素性检测：小素数试除 + rounds 轮 Miller-Rabin；1 可能素数 */
int  rbn_is_prime(const rbn_t n, int rounds);

/* 生成 bits 位随机素数（设置最高位保证位数、最低位为奇数） */
int  rbn_gen_prime(rbn_t p, int bits);

/* 字节串（大端）与 rbn_t 互转，bytes 长度固定为 128 */
void rbn_from_bytes(rbn_t r, const uint8_t in[128]);
void rbn_to_bytes(const rbn_t a, uint8_t out[128]);

/* 十六进制与 rbn_t 互转（可选 0x 前缀）；失败返回 -1 */
int  rbn_from_hex(rbn_t r, const char *hex);
void rbn_to_hex(const rbn_t a, char *out);   /* out ≥ 257 字节 */

#endif /* RSA_BN_H */
