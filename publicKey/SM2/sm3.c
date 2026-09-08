/*
 * sm3.c — SM3 密码杂凑算法实现（GB/T 32905-2016）
 *
 * 算法结构：
 *   - 消息填充：0x80 补位 + 64 位大端比特长度
 *   - 消息扩展：16 字 → 68 字 W 与 64 字 W'
 *   - 压缩函数：64 轮，轮常量 T_j = 0x79cc4519<<<j (j<16) /
 *               0x7a879d8a<<<j (j≥16)，已展开为常量表
 *   - 初始向量 IV 与轮常量参考 GmSSL 实现（与国标一致）
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c sm3.c
 */

#include "sm3.h"

#include <string.h>

/* 32 位循环左移 */
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* 置换函数 */
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x), 17))
#define P1(x) ((x) ^ ROL32((x), 15) ^ ROL32((x), 23))

/* 布尔函数：前 16 轮与后 48 轮不同 */
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

/* 初始向量 IV（GB/T 32905-2016） */
static const uint32_t SM3_IV[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU,
};

/* 64 轮常量 K[j] = T_j <<< j（展开表，与国标/GmSSL 一致） */
static const uint32_t SM3_K[64] = {
    0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
    0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
    0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
    0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
    0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
    0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
    0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
    0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

/* 大端读取 32 位字 */
static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* 大端写入 32 位字 */
static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* 压缩一个 64 字节块：消息扩展 + 64 轮迭代，累加到 digest */
static void sm3_compress(uint32_t dgst[8], const uint8_t block[SM3_BLOCK_SIZE])
{
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

    /* 消息扩展：前 16 字直接取自块（大端），后 52 字递推生成 */
    for (int j = 0; j < 16; j++)
        W[j] = get_u32(block + 4 * j);
    for (int j = 16; j < 68; j++)
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
               ^ ROL32(W[j - 13], 7) ^ W[j - 6];
    for (int j = 0; j < 64; j++)
        W1[j] = W[j] ^ W[j + 4];

    A = dgst[0]; B = dgst[1]; C = dgst[2]; D = dgst[3];
    E = dgst[4]; F = dgst[5]; G = dgst[6]; H = dgst[7];

    for (int j = 0; j < 64; j++) {
        SS1 = ROL32((ROL32(A, 12) + E + SM3_K[j]) & 0xFFFFFFFFU, 7);
        SS2 = SS1 ^ ROL32(A, 12);
        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }
        D = C; C = ROL32(B, 9); B = A; A = TT1;
        H = G; G = ROL32(F, 19); F = E; E = P0(TT2);
    }

    dgst[0] ^= A; dgst[1] ^= B; dgst[2] ^= C; dgst[3] ^= D;
    dgst[4] ^= E; dgst[5] ^= F; dgst[6] ^= G; dgst[7] ^= H;
}

void sm3_init(SM3_CTX *ctx)
{
    memcpy(ctx->digest, SM3_IV, sizeof(SM3_IV));
    ctx->nblocks = 0;
    ctx->num = 0;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t datalen)
{
    if (ctx->num) {                     /* 先补满当前块 */
        size_t left = SM3_BLOCK_SIZE - ctx->num;
        if (datalen < left) {
            memcpy(ctx->block + ctx->num, data, datalen);
            ctx->num += datalen;
            return;
        }
        memcpy(ctx->block + ctx->num, data, left);
        sm3_compress(ctx->digest, ctx->block);
        ctx->nblocks++;
        data += left;
        datalen -= left;
        ctx->num = 0;
    }
    while (datalen >= SM3_BLOCK_SIZE) { /* 整块直接压缩 */
        sm3_compress(ctx->digest, data);
        ctx->nblocks++;
        data += SM3_BLOCK_SIZE;
        datalen -= SM3_BLOCK_SIZE;
    }
    if (datalen) {                      /* 剩余不足一块，缓存 */
        memcpy(ctx->block, data, datalen);
        ctx->num = datalen;
    }
}

void sm3_finish(SM3_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE])
{
    uint64_t bitlen = (ctx->nblocks * SM3_BLOCK_SIZE + ctx->num) * 8;
    uint8_t pad[SM3_BLOCK_SIZE * 2];
    size_t total, i = 0;

    /* 填充总长：使 num + total ≡ 0 (mod 64) 且 total ≥ 9
     * （0x80 一位 + 至少 0 位 + 8 字节长度字段） */
    total = (SM3_BLOCK_SIZE - ctx->num % SM3_BLOCK_SIZE) % SM3_BLOCK_SIZE;
    if (total < 9)
        total += SM3_BLOCK_SIZE;

    memset(pad, 0, total);
    pad[0] = 0x80;                      /* 补位：1 后跟 0 */
    for (int i = 0; i < 8; i++)         /* 最后 8 字节：大端比特长度 */
        pad[total - 1 - i] = (uint8_t)(bitlen >> (8 * i));

    /* 已有缓存数据与填充合并成整块压缩（填充后必为 64 的倍数） */
    while (i < total) {
        uint8_t blk[SM3_BLOCK_SIZE];
        size_t n = 0;
        if (ctx->num) {                 /* 第一块带上原缓存数据 */
            memcpy(blk, ctx->block, ctx->num);
            n = ctx->num;
            ctx->num = 0;
        }
        memcpy(blk + n, pad + i, SM3_BLOCK_SIZE - n);
        i += SM3_BLOCK_SIZE - n;
        sm3_compress(ctx->digest, blk);
    }

    for (int i = 0; i < 8; i++)         /* 输出 8 字大端摘要 */
        put_u32(dgst + 4 * i, ctx->digest[i]);
    memset(ctx, 0, sizeof(*ctx));       /* 清理敏感状态 */
}
