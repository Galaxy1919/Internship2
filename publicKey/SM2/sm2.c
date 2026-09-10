/*
 * sm2.c — SM2 椭圆曲线公钥密码算法实现（GB/T 32918-2016）
 *
 * 算法流程参考 GmSSL（github.com/guanzhi/GmSSL），实现要点：
 *   - 素数域 GF(p)，曲线 y² = x³ + ax + b，a = p - 3
 *   - 点运算采用仿射坐标：点加/点倍各需一次模逆，点乘用
 *     double-and-add（MSB 优先），256 次迭代
 *   - KDF 为 SM3 计数器模式（GB/T 32918.3），计数器 4 字节大端
 *   - 加解密流程（GB/T 32918.4）：
 *       加密 C1 = kG, (x2,y2) = kP, t = KDF(x2||y2, mlen),
 *            C2 = M⊕t, C3 = SM3(x2||M||y2)，输出 C1||C2||C3
 *       解密 d·C1 = (x2,y2) 恢复 t 得 M，校验 SM3(x2||M||y2) == C3
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c sm2.c
 */

#include "sm2.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <sys/random.h>
#endif

#include "sm3.h"

/* ── sm2p256v1 曲线参数（GB/T 32918-2016，与 GmSSL 一致） ── */
static const char *SM2_P_HEX =
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
static const char *SM2_A_HEX =
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
static const char *SM2_B_HEX =
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
static const char *SM2_N_HEX =
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
static const char *SM2_GX_HEX =
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
static const char *SM2_GY_HEX =
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

static bn_t SM2_P_BN, SM2_A_BN, SM2_B_BN, SM2_N_BN;
static SM2_POINT SM2_G_POINT;
static int SM2_PARAMS_READY = 0;

static void sm2_params_init(void)
{
    if (SM2_PARAMS_READY)
        return;
    bn_from_hex(SM2_P_BN, SM2_P_HEX);
    bn_from_hex(SM2_A_BN, SM2_A_HEX);
    bn_from_hex(SM2_B_BN, SM2_B_HEX);
    bn_from_hex(SM2_N_BN, SM2_N_HEX);
    bn_from_hex(SM2_G_POINT.x, SM2_GX_HEX);
    bn_from_hex(SM2_G_POINT.y, SM2_GY_HEX);
    SM2_G_POINT.infinity = 0;
    SM2_PARAMS_READY = 1;
}

static int sm2_point_equal(const SM2_POINT *a, const SM2_POINT *b)
{
    if (a->infinity || b->infinity)
        return a->infinity == b->infinity;
    return bn_cmp(a->x, b->x) == 0 && bn_cmp(a->y, b->y) == 0;
}

/* ── 模 p 加减辅助：规约到 [0, p) ── */
static void mod_add(bn_t r, const bn_t a, const bn_t b, const bn_t p)
{
    if (bn_add(r, a, b) || bn_cmp(r, p) >= 0)  /* 进位或 ≥p 则减一次 */
        bn_sub(r, r, p);
}

static void mod_sub(bn_t r, const bn_t a, const bn_t b, const bn_t p)
{
    if (bn_sub(r, a, b))                         /* 借位则补回 +p */
        bn_add(r, r, p);
}

/* ── 字节串与大整数互转（大端字节 ↔ 小端 limb） ── */
static void bn_from_bytes(bn_t r, const uint8_t in[32])
{
    for (int i = 0; i < BN_LIMBS; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v = (v << 8) | in[(BN_LIMBS - 1 - i) * 8 + j];
        r[i] = v;
    }
}

static void bn_to_bytes(const bn_t a, uint8_t out[32])
{
    for (int i = 0; i < BN_LIMBS; i++)
        for (int j = 0; j < 8; j++)
            out[31 - (i * 8 + j)] = (uint8_t)(a[i] >> (8 * j));
}

/* ── 点运算（仿射坐标，防 R 与 P/Q 别名：先拷贝输入） ── */

/* R = 2P：λ = (3x²+a)/(2y)，x3 = λ²-2x，y3 = λ(x-x3)-y */
static void sm2_point_double(SM2_POINT *R, const SM2_POINT *P)
{
    bn_t x, y, lam, num, den, t;

    if (P->infinity || bn_cmp(P->y, (bn_t){0}) == 0) {
        R->infinity = 1;
        return;
    }
    sm2_params_init();
    memcpy(x, P->x, sizeof(bn_t));
    memcpy(y, P->y, sizeof(bn_t));

    bn_modmul(num, x, x, SM2_P_BN);          /* x² */
    bn_modmul(num, num, (bn_t){3}, SM2_P_BN);/* 3x² */
    mod_add(num, num, SM2_A_BN, SM2_P_BN);   /* 3x² + a */
    bn_modmul(den, y, (bn_t){2}, SM2_P_BN);  /* 2y */
    bn_modinv(lam, den, SM2_P_BN);           /* (2y)⁻¹ */
    bn_modmul(lam, num, lam, SM2_P_BN);      /* λ */

    bn_modmul(R->x, lam, lam, SM2_P_BN);     /* x3 = λ² - 2x */
    bn_modmul(t, x, (bn_t){2}, SM2_P_BN);
    mod_sub(R->x, R->x, t, SM2_P_BN);

    mod_sub(t, x, R->x, SM2_P_BN);           /* y3 = λ(x - x3) - y */
    bn_modmul(t, lam, t, SM2_P_BN);
    mod_sub(R->y, t, y, SM2_P_BN);
    R->infinity = 0;
}

/* R = P + Q：λ = (y2-y1)/(x2-x1)，x3 = λ²-x1-x2，y3 = λ(x1-x3)-y1
 * x1 == x2 时：y1+y2 ≡ 0 为无穷远，否则退化为点倍 */
static void sm2_point_add(SM2_POINT *R, const SM2_POINT *P, const SM2_POINT *Q)
{
    bn_t x1, y1, x2, y2, lam, t, sy;

    if (P->infinity) {
        *R = *Q;
        return;
    }
    if (Q->infinity) {
        *R = *P;
        return;
    }
    sm2_params_init();
    memcpy(x1, P->x, sizeof(bn_t));
    memcpy(y1, P->y, sizeof(bn_t));
    memcpy(x2, Q->x, sizeof(bn_t));
    memcpy(y2, Q->y, sizeof(bn_t));

    if (bn_cmp(x1, x2) == 0) {
        mod_add(sy, y1, y2, SM2_P_BN);
        if (bn_cmp(sy, (bn_t){0}) == 0) {   /* P = -Q：结果为无穷远 */
            R->infinity = 1;
            return;
        }
        sm2_point_double(R, P);             /* P = Q：退化为点倍 */
        return;
    }

    mod_sub(t, y2, y1, SM2_P_BN);           /* λ = (y2-y1)/(x2-x1) */
    mod_sub(lam, x2, x1, SM2_P_BN);
    bn_modinv(lam, lam, SM2_P_BN);
    bn_modmul(lam, t, lam, SM2_P_BN);

    bn_modmul(R->x, lam, lam, SM2_P_BN);    /* x3 = λ² - x1 - x2 */
    mod_sub(R->x, R->x, x1, SM2_P_BN);
    mod_sub(R->x, R->x, x2, SM2_P_BN);

    mod_sub(t, x1, R->x, SM2_P_BN);         /* y3 = λ(x1 - x3) - y1 */
    bn_modmul(t, lam, t, SM2_P_BN);
    mod_sub(R->y, t, y1, SM2_P_BN);
    R->infinity = 0;
}

/* R = k·P：仿射 double-and-add，当前实现的稳定主路径 */
static void sm2_point_mul(SM2_POINT *R, const bn_t k, const SM2_POINT *P)
{
    SM2_POINT Q;
    Q.infinity = 1;
    for (int i = BN_BITS - 1; i >= 0; i--) {
        sm2_point_double(&Q, &Q);
        if ((k[i >> 6] >> (i & 63)) & 1)
            sm2_point_add(&Q, &Q, P);
    }
    *R = Q;
}

/* ── KDF（GB/T 32918.3）：SM3 计数器模式，计数器 4 字节大端 ── */
static void sm2_kdf(const uint8_t *z, size_t zlen, size_t klen, uint8_t *out)
{
    uint32_t ct = 1;
    size_t produced = 0;

    while (produced < klen) {
        SM3_CTX ctx;
        uint8_t dgst[SM3_DIGEST_SIZE];
        uint8_t ct_be[4] = {
            (uint8_t)(ct >> 24), (uint8_t)(ct >> 16),
            (uint8_t)(ct >> 8), (uint8_t)ct,
        };
        size_t n = klen - produced < SM3_DIGEST_SIZE
                   ? klen - produced : SM3_DIGEST_SIZE;

        sm3_init(&ctx);
        sm3_update(&ctx, z, zlen);
        sm3_update(&ctx, ct_be, 4);
        sm3_finish(&ctx, dgst);
        memcpy(out + produced, dgst, n);
        produced += n;
        ct++;
    }
}

/* 优先使用系统随机数接口，避免频繁打开 /dev/urandom；非 Linux 保留文件回退。 */
static int rand_bytes(uint8_t *buf, size_t len)
{
#ifdef __linux__
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom(buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        off += (size_t)n;
    }
    if (off == len)
        return 0;
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    size_t n;
    if (!f)
        return -1;
    n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

int sm2_point_on_curve(const SM2_POINT *P)
{
    bn_t t1, t2;

    if (P->infinity)
        return 1;
    sm2_params_init();
    if (bn_cmp(P->x, SM2_P_BN) >= 0 || bn_cmp(P->y, SM2_P_BN) >= 0)
        return 0;

    bn_modmul(t1, P->x, P->x, SM2_P_BN);     /* x³ + ax + b */
    bn_modmul(t1, t1, P->x, SM2_P_BN);
    bn_modmul(t2, SM2_A_BN, P->x, SM2_P_BN);
    mod_add(t1, t1, t2, SM2_P_BN);
    mod_add(t1, t1, SM2_B_BN, SM2_P_BN);

    bn_modmul(t2, P->y, P->y, SM2_P_BN);     /* y² */
    return bn_cmp(t1, t2) == 0;
}

/* 生成私钥 d ∈ [1, n-2]：拒绝采样 */
static int sm2_gen_private(bn_t d)
{
    bn_t n_minus_1;
    uint8_t buf[32];

    sm2_params_init();
    bn_sub(n_minus_1, SM2_N_BN, (bn_t){1});
    do {
        if (rand_bytes(buf, sizeof(buf)) != 0)
            return -1;
        bn_from_bytes(d, buf);
    } while (bn_cmp(d, n_minus_1) >= 0 || bn_cmp(d, (bn_t){0}) == 0);
    return 0;
}

int sm2_keygen(SM2_KEY *key)
{
    bn_t d;

    if (sm2_gen_private(d) != 0)
        return -1;
    sm2_params_init();
    if (bn_cmp(d, SM2_N_BN) >= 0)
        return -1;

    sm2_point_mul(&key->P, d, &SM2_G_POINT); /* P = dG */
    memcpy(key->d, d, sizeof(bn_t));
    return 0;
}

/* 加密核心：使用给定 k 计算（k 由调用者提供或随机生成） */
static int sm2_do_encrypt(const SM2_KEY *key, const bn_t k,
                          const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t *outlen)
{
    SM2_POINT C1, kP;
    uint8_t x2y2[64];
    uint8_t t[SM2_MAX_PLAINTEXT];
    uint8_t dgst[SM3_DIGEST_SIZE];
    SM3_CTX ctx;

    if (inlen < 1 || inlen > SM2_MAX_PLAINTEXT)
        return -1;

    /* C1 = kG */
    sm2_params_init();
    sm2_point_mul(&C1, k, &SM2_G_POINT);
    bn_to_bytes(C1.x, out);
    bn_to_bytes(C1.y, out + 32);

    /* (x2, y2) = kP */
    sm2_point_mul(&kP, k, &key->P);
    bn_to_bytes(kP.x, x2y2);
    bn_to_bytes(kP.y, x2y2 + 32);

    /* t = KDF(x2||y2, inlen) */
    sm2_kdf(x2y2, 64, inlen, t);

    /* t 全零需更换 k 重试（规范要求，概率 2^-256） */
    int t_all_zero = 1;
    for (size_t i = 0; i < inlen; i++)
        if (t[i] != 0) {
            t_all_zero = 0;
            break;
        }
    if (t_all_zero)
        return -2;

    /* C2 = M ⊕ t */
    for (size_t i = 0; i < inlen; i++)
        out[64 + i] = in[i] ^ t[i];

    /* C3 = SM3(x2 || M || y2) */
    sm3_init(&ctx);
    sm3_update(&ctx, x2y2, 32);
    sm3_update(&ctx, in, inlen);
    sm3_update(&ctx, x2y2 + 32, 32);
    sm3_finish(&ctx, dgst);
    memcpy(out + 64 + inlen, dgst, SM3_DIGEST_SIZE);

    *outlen = 64 + inlen + 32;
    return 0;
}

int sm2_encrypt_with_k(const SM2_KEY *key, const bn_t k,
                       const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen)
{
    return sm2_do_encrypt(key, k, in, inlen, out, outlen);
}

int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen,
                uint8_t *out, size_t *outlen)
{
    bn_t k;
    uint8_t buf[32];

    sm2_params_init();

    /* 随机 k ∈ [1, n-1]；t 全零（-2）时更换 k 重试 */
    for (;;) {
        if (rand_bytes(buf, sizeof(buf)) != 0)
            return -1;
        bn_from_bytes(k, buf);
        if (bn_cmp(k, SM2_N_BN) >= 0 || bn_cmp(k, (bn_t){0}) == 0)
            continue;
        int ret = sm2_do_encrypt(key, k, in, inlen, out, outlen);
        if (ret == -2)
            continue;                       /* t 全零，重选 k */
        if (ret != 0)
            return -1;
        return 0;
    }
}

int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen,
                uint8_t *out, size_t *outlen)
{
    SM2_POINT C1;
    uint8_t x2y2[64];
    uint8_t t[SM2_MAX_PLAINTEXT];
    uint8_t dgst[SM3_DIGEST_SIZE];
    SM3_CTX ctx;
    size_t clen;

    if (inlen < SM2_POINT_SIZE + 1 + SM3_DIGEST_SIZE)
        return -1;
    clen = inlen - SM2_POINT_SIZE - SM3_DIGEST_SIZE;
    if (clen > SM2_MAX_PLAINTEXT)
        return -1;

    /* 解析 C1 并校验在曲线上 */
    bn_from_bytes(C1.x, in);
    bn_from_bytes(C1.y, in + 32);
    C1.infinity = 0;
    if (!sm2_point_on_curve(&C1))
        return -1;

    /* (x2, y2) = d·C1 */
    sm2_point_mul(&C1, key->d, &C1);
    bn_to_bytes(C1.x, x2y2);
    bn_to_bytes(C1.y, x2y2 + 32);

    /* t = KDF(x2||y2, clen)，全零则失败 */
    sm2_kdf(x2y2, 64, clen, t);
    int all_zero = 1;
    for (size_t i = 0; i < clen; i++)
        if (t[i] != 0) {
            all_zero = 0;
            break;
        }
    if (all_zero)
        return -1;

    /* M = C2 ⊕ t */
    for (size_t i = 0; i < clen; i++)
        out[i] = in[64 + i] ^ t[i];

    /* 校验 u = SM3(x2||M||y2) == C3 */
    sm3_init(&ctx);
    sm3_update(&ctx, x2y2, 32);
    sm3_update(&ctx, out, clen);
    sm3_update(&ctx, x2y2 + 32, 32);
    sm3_finish(&ctx, dgst);
    if (memcmp(dgst, in + 64 + clen, SM3_DIGEST_SIZE) != 0)
        return -1;

    *outlen = clen;
    return 0;
}

int sm2_selftest(void)
{
    SM2_POINT r0, r1, r2a, r2b, r3a, r3b, rn;

    sm2_params_init();
    if (!sm2_point_on_curve(&SM2_G_POINT))
        return -1;

    sm2_point_mul(&r0, (bn_t){0}, &SM2_G_POINT);
    if (!r0.infinity)
        return -1;

    sm2_point_mul(&r1, (bn_t){1}, &SM2_G_POINT);
    if (!sm2_point_equal(&r1, &SM2_G_POINT) || !sm2_point_on_curve(&r1))
        return -1;

    sm2_point_mul(&r2a, (bn_t){2}, &SM2_G_POINT);
    sm2_point_double(&r2b, &SM2_G_POINT);
    if (!sm2_point_equal(&r2a, &r2b) || !sm2_point_on_curve(&r2a))
        return -1;

    sm2_point_mul(&r3a, (bn_t){3}, &SM2_G_POINT);
    sm2_point_add(&r3b, &r1, &r2a);
    if (!sm2_point_equal(&r3a, &r3b) || !sm2_point_on_curve(&r3a))
        return -1;

    sm2_point_mul(&rn, SM2_N_BN, &SM2_G_POINT);
    if (!rn.infinity)
        return -1;
    return 0;
}
