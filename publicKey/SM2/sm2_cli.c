/*
 * sm2_cli.c — SM2 命令行接口（供 Python 桥接层 subprocess 调用）
 *
 * 与 test/sm2_test.c 的区别：sm2_test 是测试与对拍工具（selftest、enc_k 注入 k 等），
 * 本文件是面向「可被主程序调用」的精简接口，加密只需公钥、解密只需私钥：
 *
 *   ./sm2_cli keygen              生成密钥对 → 打印 "d <hex>\nPx <hex>\nPy <hex>"
 *   ./sm2_cli enc <Px> <Py> <明文hex>     公钥加密 → stdout 单行密文 hex
 *   ./sm2_cli dec <d> <密文hex>           私钥解密 → stdout 单行明文 hex
 *   ./sm2_cli selftest          点乘/曲线基本一致性自检
 *   ./sm2_cli bench [次数]        单进程内循环加解密，排除 subprocess 启动成本
 *   ./sm2_cli batch             从 stdin 连续读取 keygen/enc/dec/quit 命令
 *
 * 密文格式（与 sm2.h 一致）：C1x(32) || C1y(32) || C2(明文长) || C3(32)。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -o sm2_cli sm2_cli.c sm2.c sm3.c bn.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sm2.h"
#include "sm3.h"

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

/* hex 字符串 → 字节数组；返回长度，失败返回 -1 */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t maxlen)
{
    size_t len = strlen(hex);
    if (len % 2 || len / 2 > maxlen)
        return -1;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(len / 2);
}

/* keygen：随机生成密钥对，d / Px / Py 三行输出 */
static int cmd_keygen(void)
{
    SM2_KEY key;
    char hex[65];
    if (sm2_keygen(&key) != 0)
        return 1;
    bn_to_hex(key.d, hex);
    printf("d %s\n", hex);
    bn_to_hex(key.P.x, hex);
    printf("Px %s\n", hex);
    bn_to_hex(key.P.y, hex);
    printf("Py %s\n", hex);
    return 0;
}

/* enc <Px> <Py> <明文hex>：公钥加密（私钥域不参与，置零即可） */
static int cmd_enc(int argc, char **argv)
{
    SM2_KEY key;
    uint8_t plain[SM2_MAX_PLAINTEXT];
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    size_t clen;
    int plen;

    (void)argc;
    memset(&key, 0, sizeof(key));
    if (bn_from_hex(key.P.x, argv[2]) != 0 ||
        bn_from_hex(key.P.y, argv[3]) != 0)
        return 1;
    key.P.infinity = 0;
    plen = hex_to_bytes(argv[4], plain, sizeof(plain));
    if (plen <= 0)
        return 1;
    if (sm2_encrypt(&key, plain, (size_t)plen, cipher, &clen) != 0)
        return 1;
    print_hex(cipher, clen);
    printf("\n");
    return 0;
}

/* dec <d> <密文hex>：私钥解密 */
static int cmd_dec(int argc, char **argv)
{
    SM2_KEY key;
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    uint8_t plain[SM2_MAX_PLAINTEXT];
    size_t dlen;
    int clen;

    (void)argc;
    memset(&key, 0, sizeof(key));
    if (bn_from_hex(key.d, argv[2]) != 0)
        return 1;
    clen = hex_to_bytes(argv[3], cipher, sizeof(cipher));
    if (clen <= 0)
        return 1;
    if (sm2_decrypt(&key, cipher, (size_t)clen, plain, &dlen) != 0)
        return 1;
    print_hex(plain, dlen);
    printf("\n");
    return 0;
}

static double elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec) * 1000.0 +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
}

/* bench [次数]：在同一个 C 进程内循环，避免把进程启动/管道 I/O 算进算法耗时 */
static int cmd_bench(int argc, char **argv)
{
    SM2_KEY key;
    const uint8_t plain[] = "benchmark message 1234567890";
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    uint8_t recovered[SM2_MAX_PLAINTEXT];
    size_t clen, rlen;
    long iterations = 20;
    struct timespec start, end;

    if (argc >= 3) {
        char *endp = NULL;
        iterations = strtol(argv[2], &endp, 10);
        if (*argv[2] == '\0' || *endp != '\0' || iterations <= 0) {
            fprintf(stderr, "bench 次数必须是正整数\n");
            return 1;
        }
    }

    if (sm2_keygen(&key) != 0)
        return 1;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return 1;
    for (long i = 0; i < iterations; i++) {
        if (sm2_encrypt(&key, plain, sizeof(plain) - 1, cipher, &clen) != 0)
            return 1;
        if (sm2_decrypt(&key, cipher, clen, recovered, &rlen) != 0)
            return 1;
        if (rlen != sizeof(plain) - 1 || memcmp(recovered, plain, rlen) != 0) {
            fprintf(stderr, "bench 往返校验失败\n");
            return 1;
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
        return 1;

    double total = elapsed_ms(&start, &end);
    printf("iterations %ld\n", iterations);
    printf("total_ms %.3f\n", total);
    printf("per_round_ms %.3f\n", total / (double)iterations);
    return 0;
}

static int cmd_selftest(void)
{
    if (sm2_selftest() != 0) {
        printf("SM2_SELFTEST FAIL\n");
        return 1;
    }
    printf("SM2_SELFTEST PASS\n");
    return 0;
}

static void batch_keygen(void)
{
    SM2_KEY key;
    char d[65], px[65], py[65];
    if (sm2_keygen(&key) != 0) {
        printf("err keygen\n");
        return;
    }
    bn_to_hex(key.d, d);
    bn_to_hex(key.P.x, px);
    bn_to_hex(key.P.y, py);
    printf("ok %s %s %s\n", d, px, py);
}

static void batch_enc(const char *px, const char *py, const char *plain_hex)
{
    SM2_KEY key;
    uint8_t plain[SM2_MAX_PLAINTEXT];
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    size_t clen;
    int plen;

    memset(&key, 0, sizeof(key));
    if (bn_from_hex(key.P.x, px) != 0 || bn_from_hex(key.P.y, py) != 0) {
        printf("err public_key\n");
        return;
    }
    key.P.infinity = 0;
    plen = hex_to_bytes(plain_hex, plain, sizeof(plain));
    if (plen <= 0 || sm2_encrypt(&key, plain, (size_t)plen, cipher, &clen) != 0) {
        printf("err enc\n");
        return;
    }
    printf("ok ");
    print_hex(cipher, clen);
    printf("\n");
}

static void batch_dec(const char *d, const char *cipher_hex)
{
    SM2_KEY key;
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    uint8_t plain[SM2_MAX_PLAINTEXT];
    size_t plen;
    int clen;

    memset(&key, 0, sizeof(key));
    if (bn_from_hex(key.d, d) != 0) {
        printf("err private_key\n");
        return;
    }
    clen = hex_to_bytes(cipher_hex, cipher, sizeof(cipher));
    if (clen <= 0 || sm2_decrypt(&key, cipher, (size_t)clen, plain, &plen) != 0) {
        printf("err dec\n");
        return;
    }
    printf("ok ");
    print_hex(plain, plen);
    printf("\n");
}

/* batch：常驻进程批处理，供 Python 后续用 Popen 长连接调用，降低重复启动成本 */
static int cmd_batch(void)
{
    char line[4096];

    while (fgets(line, sizeof(line), stdin)) {
        char *cmd = strtok(line, " \t\r\n");
        if (cmd == NULL)
            continue;
        if (strcmp(cmd, "quit") == 0) {
            printf("ok bye\n");
            fflush(stdout);
            return 0;
        }
        if (strcmp(cmd, "keygen") == 0) {
            batch_keygen();
        } else if (strcmp(cmd, "enc") == 0) {
            char *px = strtok(NULL, " \t\r\n");
            char *py = strtok(NULL, " \t\r\n");
            char *plain_hex = strtok(NULL, " \t\r\n");
            if (px == NULL || py == NULL || plain_hex == NULL)
                printf("err usage_enc\n");
            else
                batch_enc(px, py, plain_hex);
        } else if (strcmp(cmd, "dec") == 0) {
            char *d = strtok(NULL, " \t\r\n");
            char *cipher_hex = strtok(NULL, " \t\r\n");
            if (d == NULL || cipher_hex == NULL)
                printf("err usage_dec\n");
            else
                batch_dec(d, cipher_hex);
        } else {
            printf("err unknown\n");
        }
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "keygen") == 0)
        return cmd_keygen();
    if (argc > 2 && strcmp(argv[1], "enc") == 0)
        return cmd_enc(argc, argv);
    if (argc > 2 && strcmp(argv[1], "dec") == 0)
        return cmd_dec(argc, argv);
    if (argc > 1 && strcmp(argv[1], "selftest") == 0)
        return cmd_selftest();
    if (argc > 1 && strcmp(argv[1], "bench") == 0)
        return cmd_bench(argc, argv);
    if (argc > 1 && strcmp(argv[1], "batch") == 0)
        return cmd_batch();
    fprintf(stderr, "usage: %s keygen | enc <Px> <Py> <明文hex> | dec <d> <密文hex> | selftest | bench [次数] | batch\n",
            argv[0]);
    return 1;
}
