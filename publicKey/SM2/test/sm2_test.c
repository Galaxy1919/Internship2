/*
 * sm2_test.c — SM2 自测与对拍辅助工具
 *
 * 用法：
 *   ./sm2_test selftest              密钥生成 + 加密/解密往返自测
 *   ./sm2_test keygen                输出随机密钥对（d Px Py，hex）
 *   ./sm2_test enc <d> <Px> <Py> <明文hex>   指定密钥加密，输出密文 hex
 *   ./sm2_test dec <d> <密文hex>             指定私钥解密，输出明文 hex
 *
 * 对拍脚本：scripts/verify_sm2.py（使用 Python gmssl 库交叉验证）
 *
 * compile: cd .. && gcc -Wall -Wextra -std=gnu99 -o test/sm2_test test/sm2_test.c sm2.c sm3.c bn.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sm2.h"
#include "../sm3.h"

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

/* 生成随机明文（非零字节，避免全零干扰异或检查） */
static void gen_plain(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    }
    for (size_t i = 0; i < len; i++)
        if (buf[i] == 0)
            buf[i] = 0x5a;
}

static int selftest(void)
{
    SM2_KEY key;
    SM2_POINT G;
    uint8_t plain[SM2_MAX_PLAINTEXT];
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    uint8_t dec[SM2_MAX_PLAINTEXT];
    size_t clen, dlen;
    const size_t lens[] = {1, 2, 3, 16, 32, 63, 100, 255, 1024};

    /* 1. 密钥生成 */
    expect(sm2_keygen(&key) == 0, "密钥生成");
    expect(sm2_point_on_curve(&key.P) == 1, "公钥 P = dG 在曲线上");

    /* 2. 基点 G 在曲线上 */
    {
        bn_t gx, gy;
        bn_from_hex(gx, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
        bn_from_hex(gy, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
        G.infinity = 0;
        memcpy(G.x, gx, sizeof(bn_t));
        memcpy(G.y, gy, sizeof(bn_t));
        expect(sm2_point_on_curve(&G) == 1, "基点 G 在曲线上");
    }

    /* 3. 加解密往返：多种长度 */
    int roundtrip_ok = 1;
    for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        size_t len = lens[li];
        gen_plain(plain, len);
        if (sm2_encrypt(&key, plain, len, cipher, &clen) != 0 ||
            sm2_decrypt(&key, cipher, clen, dec, &dlen) != 0 ||
            dlen != len || memcmp(plain, dec, len) != 0) {
            printf("[FAIL] 往返 len=%zu\n", len);
            roundtrip_ok = 0;
        }
    }
    expect(roundtrip_ok, "加解密往返（9 种长度）");

    /* 4. 密文格式：64 + len + 32 */
    gen_plain(plain, 100);
    sm2_encrypt(&key, plain, 100, cipher, &clen);
    expect(clen == 64 + 100 + 32, "密文长度 = 64 + 明文长 + 32");

    /* 5. 篡改密文应解密失败（C3 校验） */
    {
        gen_plain(plain, 50);
        sm2_encrypt(&key, plain, 50, cipher, &clen);
        cipher[64] ^= 0x01;             /* 翻转 C2 一个字节 */
        expect(sm2_decrypt(&key, cipher, clen, dec, &dlen) != 0,
               "篡改 C2 解密失败（C3 校验生效）");
    }

    /* 6. 密钥生成分布：连续两次密钥不同 */
    {
        SM2_KEY k2;
        sm2_keygen(&k2);
        expect(bn_cmp(key.d, k2.d) != 0, "连续密钥生成不重复");
    }

    printf(fail_count ? "\n存在失败用例\n" : "\n全部测试通过\n");
    return fail_count ? 1 : 0;
}

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

static int cmd_enc(int argc, char **argv)
{
    /* enc <d> <Px> <Py> <明文hex> */
    SM2_KEY key;
    uint8_t plain[SM2_MAX_PLAINTEXT];
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    size_t clen;
    int plen;

    (void)argc;
    if (bn_from_hex(key.d, argv[2]) != 0 ||
        bn_from_hex(key.P.x, argv[3]) != 0 ||
        bn_from_hex(key.P.y, argv[4]) != 0)
        return 1;
    key.P.infinity = 0;
    plen = hex_to_bytes(argv[5], plain, sizeof(plain));
    if (plen <= 0)
        return 1;
    if (sm2_encrypt(&key, plain, (size_t)plen, cipher, &clen) != 0)
        return 1;
    print_hex(cipher, clen);
    printf("\n");
    return 0;
}

static int cmd_enc_k(int argc, char **argv)
{
    /* enc_k <d> <Px> <Py> <k> <明文hex>：注入随机数 k（官方向量对拍用） */
    SM2_KEY key;
    bn_t k;
    uint8_t plain[SM2_MAX_PLAINTEXT];
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    size_t clen;
    int plen;

    (void)argc;
    if (bn_from_hex(key.d, argv[2]) != 0 ||
        bn_from_hex(key.P.x, argv[3]) != 0 ||
        bn_from_hex(key.P.y, argv[4]) != 0 ||
        bn_from_hex(k, argv[5]) != 0)
        return 1;
    key.P.infinity = 0;
    plen = hex_to_bytes(argv[6], plain, sizeof(plain));
    if (plen <= 0)
        return 1;
    if (sm2_encrypt_with_k(&key, k, plain, (size_t)plen, cipher, &clen) != 0)
        return 1;
    print_hex(cipher, clen);
    printf("\n");
    return 0;
}

static int cmd_dec(int argc, char **argv)
{
    /* dec <d> <密文hex> */
    SM2_KEY key;
    uint8_t cipher[SM2_POINT_SIZE + SM2_MAX_PLAINTEXT + SM3_DIGEST_SIZE];
    uint8_t plain[SM2_MAX_PLAINTEXT];
    size_t dlen;
    int clen;

    (void)argc;
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
    if (argc > 1 && strcmp(argv[1], "selftest") == 0)
        return selftest();
    if (argc > 1 && strcmp(argv[1], "keygen") == 0)
        return cmd_keygen();
    if (argc > 2 && strcmp(argv[1], "enc") == 0)
        return cmd_enc(argc, argv);
    if (argc > 2 && strcmp(argv[1], "enc_k") == 0)
        return cmd_enc_k(argc, argv);
    if (argc > 2 && strcmp(argv[1], "dec") == 0)
        return cmd_dec(argc, argv);
    printf("usage: %s selftest | keygen | enc <d> <Px> <Py> <明文hex> | enc_k <d> <Px> <Py> <k> <明文hex> | dec <d> <密文hex>\n",
           argv[0]);
    return 1;
}
