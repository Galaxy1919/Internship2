/*
 * sm3.h — SM3 密码杂凑算法接口（GB/T 32905-2016）
 *
 * 实现参考：GmSSL (github.com/guanzhi/GmSSL) 的 sm3.c 结构与轮常量，
 * 代码为本项目独立实现。SM3 输出 256 位摘要，SM2 加解密/签名依赖。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -c sm3.c
 */

#ifndef SM3_H
#define SM3_H

#include <stddef.h>
#include <stdint.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE  64

/* SM3 上下文：8 字状态 + 已处理块数 + 输入缓冲 */
typedef struct {
    uint32_t digest[8];
    uint64_t nblocks;
    uint8_t  block[SM3_BLOCK_SIZE];
    size_t   num;
} SM3_CTX;

/* 初始化：置初始向量 IV */
void sm3_init(SM3_CTX *ctx);

/* 吸收数据：可多次调用，内部按 64 字节分块压缩 */
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t datalen);

/* 收尾：填充 + 输出 32 字节摘要 */
void sm3_finish(SM3_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE]);

#endif /* SM3_H */
