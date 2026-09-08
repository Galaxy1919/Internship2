/*
 * bn.c — 256 位定长大整数运算库实现
 *
 * 设计要点：
 *   - 定长 256 位（4 × uint64_t 小端序），面向 SM2 素数域 GF(p) 运算
 *   - 乘法进位用 GCC __uint128_t 承接，避免手工拆 32 位乘法
 *   - 取模用二进制长除法（恢复余数法），求逆用二进制扩展欧几里得
 *   - 本库不提供任意精度通用功能，接口以 SM2 需要的最小集合为准
 *
 * 详细设计说明见 docs/大整数库实现.md
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c bn.c
 */

#include "bn.h"

#include <stdio.h>
#include <string.h>

typedef __uint128_t u128;   /* 64×64 乘法与进位承接 */

/* 判断 a 是否等于 0 */
static int bn_is_zero(const bn_t a)
{
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/* 比较：a>b 返回 1，a==b 返回 0，a<b 返回 -1（从高位向低位比较） */
int bn_cmp(const bn_t a, const bn_t b)
{
    for (int i = BN_LIMBS - 1; i >= 0; i--)
        if (a[i] != b[i])
            return a[i] > b[i] ? 1 : -1;
    return 0;
}

/* r = a + b；返回进位（0 或 1），由调用者决定是否处理溢出 */
int bn_add(bn_t r, const bn_t a, const bn_t b)
{
    u128 c = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        c = (u128)a[i] + b[i] + c;
        r[i] = (uint64_t)c;
        c >>= 64;
    }
    return (int)c;
}

/* r = a - b；返回借位（0 或 1）。下溢时 r 为模 2^256 补码结果 */
int bn_sub(bn_t r, const bn_t a, const bn_t b)
{
    u128 borrow = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        u128 t = (u128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)t;
        borrow = (t >> 64) & 1;     /* 无符号下溢自动产生借位 */
    }
    return (int)borrow;
}

/* r = a >> 1：从高 limb 向低 limb 传递低位移出的 1 位 */
void bn_shr1(bn_t r, const bn_t a)
{
    uint64_t carry = 0;
    for (int i = BN_LIMBS - 1; i >= 0; i--) {
        uint64_t nc = a[i] & 1;
        r[i] = (a[i] >> 1) | (carry << 63);
        carry = nc;
    }
}

/* r = (a + p) >> 1：二进制扩展欧几里得中 x 为奇数时的半步操作
 * a ∈ [0,p) 时 a+p 可能 ≥ 2^256 溢出 256 位，进位以 2^255 补回 */
static void bn_half_add_p(bn_t r, const bn_t a, const bn_t p)
{
    int carry = bn_add(r, a, p);
    bn_shr1(r, r);
    if (carry)
        r[BN_LIMBS - 1] |= 0x8000000000000000ULL;
}

/* r[8] = a × b：竖式累积（operand scanning）
 * 单次内层累加 (2^64-1)² + 2×(2^64-1) ≤ 2^128-1，u128 恰好不溢出 */
void bn_mul(uint64_t r[2 * BN_LIMBS], const bn_t a, const bn_t b)
{
    memset(r, 0, 2 * BN_LIMBS * sizeof(uint64_t));
    for (int i = 0; i < BN_LIMBS; i++) {
        u128 carry = 0;
        for (int j = 0; j < BN_LIMBS; j++) {
            u128 t = (u128)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)t;
            carry = t >> 64;
        }
        r[i + BN_LIMBS] = (uint64_t)carry;
    }
}

/* r = t mod p：对 512 位被除数逐位做二进制长除法（恢复余数法）
 * 余数 rem 用 5 个 limb：不变量 rem < p < 2^256，但 rem×2+bit 可达
 * 2^257-1，4 个 limb 会溢出；且 rem' < 2p 恒成立，每轮至多减一次 p */
void bn_mod(bn_t r, const uint64_t t[2 * BN_LIMBS], const bn_t p)
{
    uint64_t rem[BN_LIMBS + 1] = {0};

    for (int bit = 2 * BN_LIMBS * 64 - 1; bit >= 0; bit--) {
        /* rem = rem × 2 + t 的第 bit 位 */
        u128 c = 0;
        for (int i = 0; i <= BN_LIMBS; i++) {
            u128 v = ((u128)rem[i] << 1) | c;
            rem[i] = (uint64_t)v;
            c = v >> 64;
        }
        if ((t[bit >> 6] >> (bit & 63)) & 1)
            rem[0] |= 1;

        /* rem >= p 则减一次 p；高位非零必 >= 2^256 > p */
        if (rem[BN_LIMBS] || bn_cmp(rem, p) >= 0) {
            bn_sub(rem, rem, p);
            rem[BN_LIMBS] = 0;      /* rem' < 2^256 + p，减一次后必 < 2^256 */
        }
    }
    memcpy(r, rem, sizeof(bn_t));
}

/* r = (a × b) mod p：乘法与约简的组合，点运算中最频繁的操作 */
void bn_modmul(bn_t r, const bn_t a, const bn_t b, const bn_t p)
{
    uint64_t prod[2 * BN_LIMBS];
    bn_mul(prod, a, b);
    bn_mod(r, prod, p);
}

/* r = a^e mod p：从左到右扫描指数位的平方-乘算法（指数 256 位满宽） */
void bn_modpow(bn_t r, const bn_t a, const bn_t e, const bn_t p)
{
    bn_t base, tmp;
    uint64_t prod[2 * BN_LIMBS];

    memcpy(base, a, sizeof(bn_t));
    memset(r, 0, sizeof(bn_t));
    r[0] = 1;                       /* 结果初值 1（e=0 时正确返回 1） */

    for (int bit = BN_BITS - 1; bit >= 0; bit--) {
        bn_mul(prod, r, r);         /* 每步先平方 */
        bn_mod(tmp, prod, p);
        memcpy(r, tmp, sizeof(bn_t));

        if ((e[bit >> 6] >> (bit & 63)) & 1) {
            bn_mul(prod, r, base);  /* 指数位为 1 再乘底数 */
            bn_mod(tmp, prod, p);
            memcpy(r, tmp, sizeof(bn_t));
        }
    }
}

/* r = a⁻¹ mod p：二进制扩展欧几里得算法
 * 只使用移位、加减和奇偶判断，无需实现大整数除法；
 * x1/x2 保持与 u/v 同步缩放，出现负值（下溢）时补回 +p
 * 结束条件：u、v 之一归零，另一个即 gcd（素数域下必为 1） */
void bn_modinv(bn_t r, const bn_t a, const bn_t p)
{
    bn_t u, v, x1, x2;

    memcpy(u, a, sizeof(bn_t));
    memcpy(v, p, sizeof(bn_t));
    memset(x1, 0, sizeof(bn_t));
    x1[0] = 1;
    memset(x2, 0, sizeof(bn_t));

    while (!bn_is_zero(u) && !bn_is_zero(v)) {
        while (!bn_is_zero(u) && !(u[0] & 1)) { /* u 偶数：u /= 2 */
            bn_shr1(u, u);
            if (x1[0] & 1)
                bn_half_add_p(x1, x1, p);   /* x1 为奇：(x1+p)/2 */
            else
                bn_shr1(x1, x1);
        }
        while (!bn_is_zero(v) && !(v[0] & 1)) { /* v 偶数：v /= 2 */
            bn_shr1(v, v);
            if (x2[0] & 1)
                bn_half_add_p(x2, x2, p);
            else
                bn_shr1(x2, x2);
        }
        if (bn_cmp(u, v) >= 0) {        /* 相等时 u 归零，外层循环退出 */
            bn_sub(u, u, v);
            if (bn_sub(x1, x1, x2))     /* x1 - x2 下溢则 +p 修正 */
                bn_add(x1, x1, p);
        } else {
            bn_sub(v, v, u);
            if (bn_sub(x2, x2, x1))
                bn_add(x2, x2, p);
        }
    }
    /* 归零的是 u 则取 x2，归零的是 v 则取 x1 */
    if (bn_is_zero(u))
        memcpy(r, x2, sizeof(bn_t));
    else
        memcpy(r, x1, sizeof(bn_t));
}

/* 解析十六进制字符串到 bn_t；支持可选 0x 前缀；非法字符/超长返回 -1 */
int bn_from_hex(bn_t r, const char *hex)
{
    const char *s = hex;
    size_t len;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    len = strlen(s);
    if (len == 0 || len > 2 * 8 * BN_LIMBS)
        return -1;

    memset(r, 0, sizeof(bn_t));
    for (size_t i = 0; i < len; i++) {
        char c = s[len - 1 - i];        /* 从最低位 nibble 开始解析 */
        int v;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        else
            return -1;
        r[i / 16] |= (uint64_t)v << ((i % 16) * 4);
    }
    return 0;
}

/* 输出固定 64 位十六进制（无 0x 前缀，高位补零）；out 至少 65 字节 */
void bn_to_hex(const bn_t a, char *out)
{
    for (int i = BN_LIMBS - 1; i >= 0; i--)
        sprintf(out + (BN_LIMBS - 1 - i) * 16, "%016llx",
                (unsigned long long)a[i]);
}
