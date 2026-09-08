/*
 * sm3_test.c — SM3 自测：国标标准向量 + 已知值
 *
 * 用法：
 *   ./sm3_test               跑标准向量测试
 *   ./sm3_test hex <消息>    计算十六进制消息的摘要
 *
 * 标准向量（GB/T 32905-2016 附录 A，空串值经 openssl dgst -sm3 确认）：
 *   SM3("")    = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
 *   SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
 *   SM3(abcd×16) = debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
 *
 * compile: cd .. && gcc -Wall -Wextra -std=gnu99 -o test/sm3_test test/sm3_test.c sm3.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sm3.h"

static int fail_count = 0;

static void expect_digest(const char *name, const uint8_t *data, size_t len,
                          const char *expect_hex)
{
    SM3_CTX ctx;
    uint8_t dgst[SM3_DIGEST_SIZE];
    char hex[SM3_DIGEST_SIZE * 2 + 1];

    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_finish(&ctx, dgst);

    for (int i = 0; i < SM3_DIGEST_SIZE; i++)
        sprintf(hex + 2 * i, "%02x", dgst[i]);

    if (strcmp(hex, expect_hex) == 0) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n  期望: %s\n  实际: %s\n", name, expect_hex, hex);
        fail_count++;
    }
}

static int selftest(void)
{
    /* 1. 空串 */
    expect_digest("空串", (const uint8_t *)"", 0,
                  "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");

    /* 2. "abc" */
    expect_digest("abc", (const uint8_t *)"abc", 3,
                  "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    /* 3. "abcd" 重复 16 次（恰好 64 字节，一块） */
    {
        uint8_t buf[64];
        for (int i = 0; i < 16; i++)
            memcpy(buf + 4 * i, "abcd", 4);
        expect_digest("abcd x16 (64B)", buf, 64,
                      "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
    }

    /* 4. 分两次 update，验证流式接口等价 */
    {
        SM3_CTX ctx;
        uint8_t dgst[SM3_DIGEST_SIZE];
        char hex[65];
        sm3_init(&ctx);
        sm3_update(&ctx, (const uint8_t *)"abc", 1);
        sm3_update(&ctx, (const uint8_t *)"bc", 2);
        sm3_finish(&ctx, dgst);
        for (int i = 0; i < SM3_DIGEST_SIZE; i++)
            sprintf(hex + 2 * i, "%02x", dgst[i]);
        if (strcmp(hex, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0") == 0)
            printf("[PASS] 分块 update 与整块等价\n");
        else {
            printf("[FAIL] 分块 update: %s\n", hex);
            fail_count++;
        }
    }

    printf(fail_count ? "\n存在失败用例\n" : "\n全部测试通过\n");
    return fail_count ? 1 : 0;
}

/* 计算十六进制字符串消息的摘要 */
static int cmd_hex(const char *hexstr)
{
    size_t len = strlen(hexstr);
    if (len % 2) {
        fprintf(stderr, "十六进制长度必须为偶数\n");
        return 1;
    }
    uint8_t *data = malloc(len / 2);
    if (!data)
        return 1;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int v;
        sscanf(hexstr + 2 * i, "%2x", &v);
        data[i] = (uint8_t)v;
    }
    SM3_CTX ctx;
    uint8_t dgst[SM3_DIGEST_SIZE];
    sm3_init(&ctx);
    sm3_update(&ctx, data, len / 2);
    sm3_finish(&ctx, dgst);
    for (int i = 0; i < SM3_DIGEST_SIZE; i++)
        printf("%02x", dgst[i]);
    printf("\n");
    free(data);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 2 && strcmp(argv[1], "hex") == 0)
        return cmd_hex(argv[2]);
    return selftest();
}
