/*
 * rsa.c — RSA 公钥密码算法实现（PKCS#1 教科书式，1024 位）
 *
 * 密钥生成：
 *   1. 随机生成两个 bits/2 位大素数 p、q（Miller-Rabin 12 轮）
 *   2. n = p·q，φ(n) = (p-1)(q-1)
 *   3. e = 65537，d = e⁻¹ mod φ(n)（标准扩展欧几里得）
 *   4. CRT 参数：dp = d mod (p-1)，dq = d mod (q-1)，
 *      qinv = q⁻¹ mod p
 *
 * 加解密（教科书 RSA）：
 *   加密 c = m^e mod n；解密 m = c^d mod n
 *   解密用 CRT：m1 = c^dp mod p，m2 = c^dq mod q，
 *      h = qinv·(m1-m2) mod p，m = m2 + q·h mod n
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c rsa.c
 */

#include "rsa.h"

#include <stdio.h>
#include <string.h>

typedef __uint128_t u128;

/* 标准扩展欧几里得：d = e⁻¹ mod phi（系数全程模 phi，避免负号处理）
 * 迭代次数 O(log phi)，phi 为偶数时同样适用（rbn_modinv 仅限奇数模） */
static void rsa_egcd_inv(rbn_t d, const rbn_t phi, const rbn_t e)
{
    rbn_t r0, r1, q, r2, t0, t1, t2, tmp;

    memcpy(r0, phi, sizeof(rbn_t));
    memcpy(r1, e, sizeof(rbn_t));
    memset(t0, 0, sizeof(rbn_t));
    memset(t1, 0, sizeof(rbn_t));
    t1[0] = 1;

    while (!rbn_is_zero(r1)) {
        rbn_divmod(q, r2, r0, r1);
        rbn_modmul(tmp, q, t1, phi);        /* q·t1 mod phi */
        if (rbn_sub(t2, t0, tmp))           /* t0 - q·t1 mod phi */
            rbn_add(t2, t2, phi);

        memcpy(r0, r1, sizeof(rbn_t));
        memcpy(r1, r2, sizeof(rbn_t));
        memcpy(t0, t1, sizeof(rbn_t));
        memcpy(t1, t2, sizeof(rbn_t));
    }
    memcpy(d, t0, sizeof(rbn_t));           /* r0 = gcd = 1，t0 即逆元 */
}

int rsa_keygen(RSA_KEY *key, int bits)
{
    int half;
    uint64_t prod[2 * RBN_LIMBS];
    rbn_t p1, q1, phi, tmp;

    if (bits != 512 && bits != 1024)
        return -1;
    half = bits / 2;

    /* 1. 生成两个不同的大素数 p、q */
    do {
        rbn_gen_prime(key->p, half);
        do {
            rbn_gen_prime(key->q, half);
        } while (rbn_cmp(key->p, key->q) == 0);

        /* 2. n = p·q（乘积 ≤ bits 位，直接取低 16 limb） */
        rbn_mul(prod, key->p, key->q);
        memcpy(key->n, prod, sizeof(rbn_t));

        /* φ(n) = (p-1)(q-1) */
        memcpy(p1, key->p, sizeof(rbn_t));
        memcpy(q1, key->q, sizeof(rbn_t));
        rbn_sub(p1, p1, (rbn_t){1, 0});
        rbn_sub(q1, q1, (rbn_t){1, 0});
        rbn_mul(prod, p1, q1);
        memcpy(phi, prod, sizeof(rbn_t));

        /* 3. e = 65537，d = e⁻¹ mod φ(n)（gcd 必须为 1，否则重来） */
        memset(key->e, 0, sizeof(rbn_t));
        key->e[0] = 65537;
        rsa_egcd_inv(key->d, phi, key->e);
        /* 校验 e·d ≡ 1 (mod φ) */
        rbn_modmul(tmp, key->e, key->d, phi);
        if (rbn_is_one(tmp))
            break;
    } while (1);

    /* 4. CRT 参数 */
    /* dp = d mod (p-1) */
    memset(prod, 0, sizeof(prod));
    memcpy(prod, key->d, sizeof(rbn_t));
    rbn_mod(key->dp, prod, p1);
    /* dq = d mod (q-1) */
    memset(prod, 0, sizeof(prod));
    memcpy(prod, key->d, sizeof(rbn_t));
    rbn_mod(key->dq, prod, q1);
    /* qinv = q⁻¹ mod p（先规约 q mod p） */
    memset(prod, 0, sizeof(prod));
    memcpy(prod, key->q, sizeof(rbn_t));
    rbn_mod(tmp, prod, key->p);
    rbn_modinv(key->qinv, tmp, key->p);

    return 0;
}

int rsa_encrypt(const RSA_KEY *key, const uint8_t *m, size_t mlen,
                uint8_t *c)
{
    rbn_t mbn;
    uint8_t buf[128] = {0};

    if (mlen == 0 || mlen > RSA_MAX_BLOCK)
        return -1;
    memcpy(buf + 128 - mlen, m, mlen);      /* 大端补零 */
    rbn_from_bytes(mbn, buf);
    if (rbn_cmp(mbn, key->n) >= 0)          /* 必须 m < n */
        return -1;

    rbn_modpow(mbn, mbn, key->e, key->n);   /* c = m^e mod n */
    rbn_to_bytes(mbn, c);
    return 0;
}

int rsa_decrypt(const RSA_KEY *key, const uint8_t *c,
                uint8_t *m, size_t *mlen)
{
    rbn_t cbn, m1, m2, h, t, tmp;
    uint64_t prod[2 * RBN_LIMBS];

    rbn_from_bytes(cbn, c);
    if (rbn_cmp(cbn, key->n) >= 0)
        return -1;

    /* m1 = c^dp mod p，m2 = c^dq mod q */
    rbn_modpow(m1, cbn, key->dp, key->p);
    rbn_modpow(m2, cbn, key->dq, key->q);

    /* h = qinv·(m1 - m2) mod p */
    if (rbn_sub(tmp, m1, m2))               /* m1-m2 为负则 +p */
        rbn_add(tmp, tmp, key->p);
    rbn_modmul(h, key->qinv, tmp, key->p);

    /* m = (m2 + q·h) mod n（用 32 limb 缓冲防溢出） */
    rbn_mul(prod, key->q, h);               /* q·h ≤ 1024 位 */
    {
        u128 carry = 0;
        for (int i = 0; i < RBN_LIMBS; i++) {
            u128 v = (u128)prod[i] + m2[i] + carry;
            prod[i] = (uint64_t)v;
            carry = v >> 64;
        }
        prod[RBN_LIMBS] += (uint64_t)carry; /* m2 + q·h < 2^1025 可容纳 */
    }
    rbn_mod(t, prod, key->n);
    rbn_to_bytes(t, m);

    /* 明文长度 = 去掉前导零（至少 1 字节） */
    size_t len = 128;
    for (size_t i = 0; i < 128; i++)
        if (m[i] != 0) {
            len = 128 - i;
            break;
        }
    *mlen = len;
    return 0;
}
