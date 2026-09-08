/*
 * bn_test.c — 大整数库自测与随机对拍数据生成
 *
 * 用法：
 *   ./bn_test selftest   内置用例：hex 往返 / 特殊值取模 /
 *                        费马小定理 / 模逆往返 / 模幂已知值
 *   ./bn_test dump N     输出 N 组随机数据供 Python 对拍验证
 *                        每行格式：a b e mul pow inv（均为 64 位 hex）
 *
 * 对拍脚本：scripts/verify_bn.py
 *
 * compile: cd .. && gcc -Wall -Wextra -std=gnu99 -o test/bn_test test/bn_test.c bn.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../bn.h"

/* SM2 素数域模数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1（GB/T 32918-2016） */
static const char *SM2_P_HEX =
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

/* 简单 LCG 伪随机数：固定种子，测试结果可复现 */
static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rng_next(void)
{
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return rng_state;
}

/* 生成 0..p-1 的随机 256 位值（拒绝采样） */
static void rng_bn(bn_t r, const bn_t p)
{
    do {
        for (int i = 0; i < BN_LIMBS; i++)
            r[i] = rng_next();
    } while (bn_cmp(r, p) >= 0);
}

static int fail_count = 0;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("[PASS] %s\n", what);
    } else {
        printf("[FAIL] %s\n", what);
        fail_count++;
    }
}

static int selftest(void)
{
    bn_t p, a, e, r, t;
    char hex[65];
    uint64_t prod[2 * BN_LIMBS];

    bn_from_hex(p, SM2_P_HEX);

    /* 1. hex 解析与输出往返 */
    bn_from_hex(a, "0x123456789abcdef");
    bn_to_hex(a, hex);
    expect(strcmp(hex, "0000000000000000000000000000000000000000000000000123456789abcdef") == 0,
           "hex 往返");

    /* 2. 特殊值取模：p mod p == 0 */
    memcpy(prod, p, sizeof(bn_t));
    memset(prod + BN_LIMBS, 0, sizeof(bn_t));
    bn_mod(r, prod, p);
    expect(bn_cmp(r, (bn_t){0}) == 0, "p mod p == 0");

    /* 3. 特殊值取模：(p-1) mod p == p-1 */
    memcpy(a, p, sizeof(bn_t));
    bn_sub(a, a, (bn_t){1});
    memcpy(prod, a, sizeof(bn_t));
    memset(prod + BN_LIMBS, 0, sizeof(bn_t));
    bn_mod(r, prod, p);
    expect(bn_cmp(r, a) == 0, "(p-1) mod p == p-1");

    /* 4. 模幂已知值：2^10 mod p == 0x400 */
    bn_from_hex(a, "2");
    bn_from_hex(e, "a");
    bn_modpow(r, a, e, p);
    bn_from_hex(t, "400");
    expect(bn_cmp(r, t) == 0, "2^10 mod p == 0x400");

    /* 5. 模幂边界：a^0 == 1，0^e == 0 */
    bn_from_hex(a, "5");
    bn_from_hex(e, "0");
    bn_modpow(r, a, e, p);
    expect(bn_cmp(r, (bn_t){1}) == 0, "a^0 == 1");
    bn_from_hex(a, "0");
    bn_from_hex(e, "ffff");
    bn_modpow(r, a, e, p);
    expect(bn_cmp(r, (bn_t){0}) == 0, "0^e == 0");

    /* 6. 费马小定理：随机 a 满足 a^(p-1) ≡ 1 (mod p) */
    rng_bn(a, p);
    memcpy(e, p, sizeof(bn_t));
    bn_sub(e, e, (bn_t){1});
    bn_modpow(r, a, e, p);
    expect(bn_cmp(r, (bn_t){1}) == 0, "费马小定理 a^(p-1) ≡ 1");

    /* 7. 模逆往返：a × a⁻¹ ≡ 1 (mod p)，a 取非零随机值 */
    rng_bn(a, p);
    while (bn_cmp(a, (bn_t){0}) == 0)
        rng_bn(a, p);
    bn_modinv(t, a, p);
    bn_modmul(r, a, t, p);
    expect(bn_cmp(r, (bn_t){1}) == 0, "模逆往返 a·a⁻¹ ≡ 1");

    /* 8. 模逆边界：1⁻¹ == 1，(p-1)⁻¹ == p-1 */
    bn_modinv(t, (bn_t){1}, p);
    expect(bn_cmp(t, (bn_t){1}) == 0, "1⁻¹ == 1");
    memcpy(a, p, sizeof(bn_t));
    bn_sub(a, a, (bn_t){1});
    bn_modinv(t, a, p);
    expect(bn_cmp(t, a) == 0, "(p-1)⁻¹ == p-1");

    printf(fail_count ? "\n存在失败用例\n" : "\n全部测试通过\n");
    return fail_count ? 1 : 0;
}

/* 输出 N 组随机数据：a b e mul pow inv，全部 64 位 hex */
static void dump_random(int n)
{
    bn_t p, a, b, e, mul, pw, inv;

    bn_from_hex(p, SM2_P_HEX);
    printf("# a b e mul=a*b mod p pow=a^e mod p inv=a^-1 mod p\n");
    for (int i = 0; i < n; i++) {
        rng_bn(a, p);
        rng_bn(b, p);
        rng_bn(e, p);
        bn_modmul(mul, a, b, p);
        bn_modpow(pw, a, e, p);
        if (bn_cmp(a, (bn_t){0}) == 0)
            memset(inv, 0, sizeof(bn_t));
        else
            bn_modinv(inv, a, p);

        char ha[65], hb[65], he[65], hm[65], hp[65], hi[65];
        bn_to_hex(a, ha);
        bn_to_hex(b, hb);
        bn_to_hex(e, he);
        bn_to_hex(mul, hm);
        bn_to_hex(pw, hp);
        bn_to_hex(inv, hi);
        printf("%s %s %s %s %s %s\n", ha, hb, he, hm, hp, hi);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "selftest") == 0)
        return selftest();
    if (argc > 2 && strcmp(argv[1], "dump") == 0) {
        dump_random(atoi(argv[2]));
        return 0;
    }
    printf("usage: %s selftest | dump N\n", argv[0]);
    return 1;
}
