/*
 * rsa_bn.c — RSA 用 1024 位定长大整数运算库实现
 *
 * 与 bn.c（256 位）同构：竖式乘法、二进制长除法取模、
 * 二进制扩展欧几里得求逆、平方-乘模幂。素性检测参考
 * libtommath（HAC 4.24 Miller-Rabin + 小素数试除）。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c rsa_bn.c
 */

#include "rsa_bn.h"

#include <stdio.h>
#include <string.h>

typedef __uint128_t u128;

/* 判断 a 是否为 0 / 1 / 2 */
int rbn_is_zero(const rbn_t a)
{
    for (int i = 0; i < RBN_LIMBS; i++)
        if (a[i] != 0)
            return 0;
    return 1;
}

int rbn_is_one(const rbn_t a)
{
    if (a[0] != 1)
        return 0;
    for (int i = 1; i < RBN_LIMBS; i++)
        if (a[i] != 0)
            return 0;
    return 1;
}

static int rbn_is_two(const rbn_t a)
{
    if (a[0] != 2)
        return 0;
    for (int i = 1; i < RBN_LIMBS; i++)
        if (a[i] != 0)
            return 0;
    return 1;
}

/* 比较：从高位向低位 */
int rbn_cmp(const rbn_t a, const rbn_t b)
{
    for (int i = RBN_LIMBS - 1; i >= 0; i--)
        if (a[i] != b[i])
            return a[i] > b[i] ? 1 : -1;
    return 0;
}

int rbn_add(rbn_t r, const rbn_t a, const rbn_t b)
{
    u128 c = 0;
    for (int i = 0; i < RBN_LIMBS; i++) {
        c = (u128)a[i] + b[i] + c;
        r[i] = (uint64_t)c;
        c >>= 64;
    }
    return (int)c;
}

int rbn_sub(rbn_t r, const rbn_t a, const rbn_t b)
{
    u128 borrow = 0;
    for (int i = 0; i < RBN_LIMBS; i++) {
        u128 t = (u128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)t;
        borrow = (t >> 64) & 1;
    }
    return (int)borrow;
}

void rbn_shr1(rbn_t r, const rbn_t a)
{
    uint64_t carry = 0;
    for (int i = RBN_LIMBS - 1; i >= 0; i--) {
        uint64_t nc = a[i] & 1;
        r[i] = (a[i] >> 1) | (carry << 63);
        carry = nc;
    }
}

/* r = (a + m) >> 1：二进制扩展欧几里得中 x 为奇数时的半步
 * a ∈ [0,m) 时 a+m 可 ≥ 2^1024 溢出，进位以 2^1023 补回 */
static void rbn_half_add_m(rbn_t r, const rbn_t a, const rbn_t m)
{
    int carry = rbn_add(r, a, m);
    rbn_shr1(r, r);
    if (carry)
        r[RBN_LIMBS - 1] |= 0x8000000000000000ULL;
}

/* 竖式乘法：r[32] = a × b */
void rbn_mul(uint64_t r[2 * RBN_LIMBS], const rbn_t a, const rbn_t b)
{
    memset(r, 0, 2 * RBN_LIMBS * sizeof(uint64_t));
    for (int i = 0; i < RBN_LIMBS; i++) {
        u128 carry = 0;
        for (int j = 0; j < RBN_LIMBS; j++) {
            u128 t = (u128)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)t;
            carry = t >> 64;
        }
        r[i + RBN_LIMBS] = (uint64_t)carry;
    }
}

/* r = t mod m：对 2048 位被除数逐位做二进制长除法（恢复余数法）
 * 余数用 RBN_LIMBS+1 个 limb：rem×2+bit 可达 2^1025-1，1024 位会溢出；
 * 且 rem' < 2m 恒成立，每轮至多减一次 m */
void rbn_mod(rbn_t r, const uint64_t t[2 * RBN_LIMBS], const rbn_t m)
{
    uint64_t rem[RBN_LIMBS + 1] = {0};

    for (int bit = 2 * RBN_LIMBS * 64 - 1; bit >= 0; bit--) {
        u128 c = 0;
        for (int i = 0; i <= RBN_LIMBS; i++) {
            u128 v = ((u128)rem[i] << 1) | c;
            rem[i] = (uint64_t)v;
            c = v >> 64;
        }
        if ((t[bit >> 6] >> (bit & 63)) & 1)
            rem[0] |= 1;

        if (rem[RBN_LIMBS] || rbn_cmp(rem, m) >= 0) {
            rbn_sub(rem, rem, m);
            rem[RBN_LIMBS] = 0;     /* rem' < 2^1024 + m，减一次后必 < 2^1024 */
        }
    }
    memcpy(r, rem, sizeof(rbn_t));
}

void rbn_modmul(rbn_t r, const rbn_t a, const rbn_t b, const rbn_t m)
{
    uint64_t prod[2 * RBN_LIMBS];
    rbn_mul(prod, a, b);
    rbn_mod(r, prod, m);
}

/* q = a / b, r = a mod b：恢复余数法长除法
 * 余数用 17 limb（rem×2+bit 可达 2^1025-1），每轮至多减一次 b */
void rbn_divmod(rbn_t q, rbn_t r, const rbn_t a, const rbn_t b)
{
    uint64_t rem[RBN_LIMBS + 1] = {0};

    memset(q, 0, sizeof(rbn_t));
    for (int bit = RBN_BITS - 1; bit >= 0; bit--) {
        u128 c = 0;
        for (int i = 0; i <= RBN_LIMBS; i++) {
            u128 v = ((u128)rem[i] << 1) | c;
            rem[i] = (uint64_t)v;
            c = v >> 64;
        }
        rem[0] |= (a[bit >> 6] >> (bit & 63)) & 1;

        if (rem[RBN_LIMBS] || rbn_cmp(rem, b) >= 0) {
            rbn_sub(rem, rem, b);
            rem[RBN_LIMBS] = 0;
            q[bit >> 6] |= 1ULL << (bit & 63);
        }
    }
    memcpy(r, rem, sizeof(rbn_t));
}

/* 平方-乘模幂：e 可为 1024 位（私钥指数 d） */
void rbn_modpow(rbn_t r, const rbn_t a, const rbn_t e, const rbn_t m)
{
    rbn_t base, tmp;
    uint64_t prod[2 * RBN_LIMBS];

    memcpy(base, a, sizeof(rbn_t));
    memset(r, 0, sizeof(rbn_t));
    r[0] = 1;

    for (int bit = RBN_BITS - 1; bit >= 0; bit--) {
        rbn_mul(prod, r, r);
        rbn_mod(tmp, prod, m);
        memcpy(r, tmp, sizeof(rbn_t));

        if ((e[bit >> 6] >> (bit & 63)) & 1) {
            rbn_mul(prod, r, base);
            rbn_mod(tmp, prod, m);
            memcpy(r, tmp, sizeof(rbn_t));
        }
    }
}

/* 二进制扩展欧几里得：u、v 之一归零时取另一方系数 */
void rbn_modinv(rbn_t r, const rbn_t a, const rbn_t m)
{
    rbn_t u, v, x1, x2;

    memcpy(u, a, sizeof(rbn_t));
    memcpy(v, m, sizeof(rbn_t));
    memset(x1, 0, sizeof(rbn_t));
    x1[0] = 1;
    memset(x2, 0, sizeof(rbn_t));

    while (!rbn_is_zero(u) && !rbn_is_zero(v)) {
        while (!rbn_is_zero(u) && !(u[0] & 1)) {
            rbn_shr1(u, u);
            if (x1[0] & 1)
                rbn_half_add_m(x1, x1, m);
            else
                rbn_shr1(x1, x1);
        }
        while (!rbn_is_zero(v) && !(v[0] & 1)) {
            rbn_shr1(v, v);
            if (x2[0] & 1)
                rbn_half_add_m(x2, x2, m);
            else
                rbn_shr1(x2, x2);
        }
        if (rbn_cmp(u, v) >= 0) {
            rbn_sub(u, u, v);
            if (rbn_sub(x1, x1, x2))
                rbn_add(x1, x1, m);
        } else {
            rbn_sub(v, v, u);
            if (rbn_sub(x2, x2, x1))
                rbn_add(x2, x2, m);
        }
    }
    if (rbn_is_zero(u))
        memcpy(r, x2, sizeof(rbn_t));
    else
        memcpy(r, x1, sizeof(rbn_t));
}

/* 小素数表：前 96 个素数（试除过滤用，公开数据） */
static const uint16_t SMALL_PRIMES[] = {
    2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,
    59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,
    137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,
    227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,
    313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,
    419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,
};

/* 小素数试除：n 能被任一表内素数整除（且 n 不等于该素数）返回 1 */
int rbn_divisible_small(const rbn_t n)
{
    for (size_t i = 0; i < sizeof(SMALL_PRIMES) / sizeof(SMALL_PRIMES[0]); i++) {
        uint64_t p = SMALL_PRIMES[i];
        /* 用模加迭代计算 n mod p（64 位逐段） */
        u128 rem = 0;
        for (int j = RBN_LIMBS - 1; j >= 0; j--)
            rem = ((rem << 64) | n[j]) % p;
        if (rem == 0) {
            /* n == p（小素数本身）不算合数 */
            int eq = 0;
            if (rbn_cmp(n, (rbn_t){p, 0}) == 0)
                eq = 1;
            if (!eq)
                return 1;
        }
    }
    return 0;
}

/* Miller-Rabin 单轮（HAC 4.24）：n 奇数，base ∈ [2, n-2] */
int rbn_miller_rabin(const rbn_t n, const rbn_t base)
{
    rbn_t n1, r, y;
    int s = 0;

    /* n1 = n - 1 = 2^s * r，r 奇数 */
    memcpy(n1, n, sizeof(rbn_t));
    rbn_sub(n1, n1, (rbn_t){1, 0});
    memcpy(r, n1, sizeof(rbn_t));
    while (!(r[0] & 1)) {
        rbn_shr1(r, r);
        s++;
    }

    /* y = base^r mod n */
    rbn_modpow(y, base, r, n);

    /* y == 1 或 y == n-1 则可能素数 */
    if (rbn_is_one(y) || rbn_cmp(y, n1) == 0)
        return 1;

    for (int j = 1; j < s; j++) {
        rbn_modmul(y, y, y, n);         /* y = y² mod n */
        if (rbn_is_one(y))
            return 0;                   /* 中途出现 1：确定合数 */
        if (rbn_cmp(y, n1) == 0)
            return 1;                   /* 出现 n-1：可能素数 */
    }
    return 0;                           /* 始终未到 n-1：合数 */
}

/* 综合素性检测：小素数试除 + rounds 轮 Miller-Rabin（随机底数） */
int rbn_is_prime(const rbn_t n, int rounds)
{
    /* 边界：0/1 合数，2 素数，偶数合数 */
    if (rbn_is_zero(n) || rbn_is_one(n))
        return 0;
    if (rbn_is_two(n))
        return 1;
    if (!(n[0] & 1))
        return 0;

    if (rbn_divisible_small(n))
        return 0;

    /* 随机底数 a ∈ [2, n-2]，跑 rounds 轮 */
    for (int i = 0; i < rounds; i++) {
        rbn_t base;
        uint8_t buf[128];
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f)
            return -1;
        fread(buf, 1, sizeof(buf), f);
        fclose(f);
        rbn_from_bytes(base, buf);
        /* 规约到 [2, n-2]：取模 n-3 后 +2 */
        {
            rbn_t n3;
            memcpy(n3, n, sizeof(rbn_t));
            rbn_sub(n3, n3, (rbn_t){3, 0});
            /* base = base mod (n-3) + 2（base 已是 1024 位，可能 ≥ n-3） */
            uint64_t prod[2 * RBN_LIMBS] = {0};
            memcpy(prod, base, sizeof(rbn_t));
            rbn_mod(base, prod, n3);
            rbn_add(base, base, (rbn_t){2, 0});
        }
        if (!rbn_miller_rabin(n, base))
            return 0;
    }
    return 1;
}

/* 从 /dev/urandom 读 bits 位随机数，设置最高位与最低位（奇数） */
static void rbn_rand_bits(rbn_t r, int bits)
{
    uint8_t buf[128];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, sizeof(buf), f);
        fclose(f);
    }
    rbn_from_bytes(r, buf);

    /* 清零 bits 及以上高位：从 limb=bits/64 起全部清（该 limb 的低
     * rem 位若在范围内则保留） */
    if (bits < RBN_BITS) {
        int limb = bits / 64;
        int rem = bits % 64;
        for (int i = limb; i < RBN_LIMBS; i++)
            r[i] = 0;
        if (rem)
            r[limb] &= ((1ULL << rem) - 1);
    }
    /* 最高位置 1（bit bits-1，保证位数），最低位置 1（奇数） */
    r[(bits - 1) / 64] |= 1ULL << ((bits - 1) % 64);
    r[0] |= 1;
}

/* 生成 bits 位随机素数：随机奇数 → 试除 + Miller-Rabin → 失败 +2 重试 */
int rbn_gen_prime(rbn_t p, int bits)
{
    if (bits < 8 || bits > RBN_BITS)
        return -1;

    for (;;) {
        rbn_rand_bits(p, bits);
        if (rbn_divisible_small(p))
            continue;
        if (rbn_is_prime(p, 12))
            return 0;
        /* 尝试下一个奇数（+2 保持奇数） */
        rbn_add(p, p, (rbn_t){2, 0});
        if (rbn_is_prime(p, 12))
            return 0;
    }
}

/* 字节串（大端）→ rbn_t：limb i = in[(15-i)*8 .. (15-i)*8+7] 大端 */
void rbn_from_bytes(rbn_t r, const uint8_t in[128])
{
    for (int i = 0; i < RBN_LIMBS; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v = (v << 8) | in[(RBN_LIMBS - 1 - i) * 8 + j];
        r[i] = v;
    }
}

void rbn_to_bytes(const rbn_t a, uint8_t out[128])
{
    for (int i = 0; i < RBN_LIMBS; i++)
        for (int j = 0; j < 8; j++)
            out[(RBN_LIMBS - 1 - i) * 8 + j] = (uint8_t)(a[i] >> (8 * (7 - j)));
}

int rbn_from_hex(rbn_t r, const char *hex)
{
    const char *s = hex;
    size_t len;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    len = strlen(s);
    if (len == 0 || len > 2 * 8 * RBN_LIMBS)
        return -1;

    memset(r, 0, sizeof(rbn_t));
    for (size_t i = 0; i < len; i++) {
        char c = s[len - 1 - i];
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

void rbn_to_hex(const rbn_t a, char *out)
{
    for (int i = RBN_LIMBS - 1; i >= 0; i--)
        sprintf(out + (RBN_LIMBS - 1 - i) * 16, "%016llx",
                (unsigned long long)a[i]);
}
