/*
 * sm2_cli.c — SM2 命令行接口（供 Python 桥接层 subprocess 调用）
 *
 * 与 test/sm2_test.c 的区别：sm2_test 是测试与对拍工具（selftest、enc_k 注入 k 等），
 * 本文件是面向「可被主程序调用」的精简接口，加密只需公钥、解密只需私钥：
 *
 *   ./sm2_cli keygen              生成密钥对 → 打印 "d <hex>\nPx <hex>\nPy <hex>"
 *   ./sm2_cli enc <Px> <Py> <明文hex>     公钥加密 → stdout 单行密文 hex
 *   ./sm2_cli dec <d> <密文hex>           私钥解密 → stdout 单行明文 hex
 *
 * 密文格式（与 sm2.h 一致）：C1x(32) || C1y(32) || C2(明文长) || C3(32)。
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -o sm2_cli sm2_cli.c sm2.c sm3.c bn.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "keygen") == 0)
        return cmd_keygen();
    if (argc > 2 && strcmp(argv[1], "enc") == 0)
        return cmd_enc(argc, argv);
    if (argc > 2 && strcmp(argv[1], "dec") == 0)
        return cmd_dec(argc, argv);
    fprintf(stderr, "usage: %s keygen | enc <Px> <Py> <明文hex> | dec <d> <密文hex>\n",
            argv[0]);
    return 1;
}
