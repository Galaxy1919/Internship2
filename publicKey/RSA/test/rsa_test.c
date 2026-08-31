/*
 * rsa_test.c — RSA 自测与对拍辅助工具
 *
 * 用法：
 *   ./rsa_test selftest [bits]   密钥生成 + 加解密往返自测（默认 1024）
 *   ./rsa_test keygen [bits]     生成密钥，输出 n e d p q dp dq qinv（hex）
 *   ./rsa_test enc <n> <e> <明文hex>      公钥加密，输出 128 字节密文 hex
 *   ./rsa_test dec <n> <d> <p> <q> <dp> <dq> <qinv> <密文hex>
 *                                    私钥解密（CRT），输出明文 hex
 *
 * 对拍脚本：scripts/verify_rsa.py（Python pow() 交叉验证）
 *
 * compile: gcc -Wall -Wextra -std=gnu99 -o rsa_test rsa_test.c rsa.c rsa_bn.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../rsa.h"
#include "../rsa_bn.h"

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

/* 生成随机明文（非全零） */
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

static int selftest(int bits)
{
    RSA_KEY key;
    uint8_t plain[RSA_MAX_BLOCK];
    uint8_t cipher[128];
    uint8_t dec[RSA_MAX_BLOCK];
    size_t dlen;
    rbn_t tmp;

    printf("=== RSA-%d 自测 ===\n", bits);

    /* 1. 密钥生成 */
    expect(rsa_keygen(&key, bits) == 0, "密钥生成");

    /* 2. p、q 素性：再跑 8 轮 Miller-Rabin 确认 */
    expect(rbn_is_prime(key.p, 8) == 1, "p 是素数");
    expect(rbn_is_prime(key.q, 8) == 1, "q 是素数");

    /* 3. n = p·q 验证：n == p·q */
    {
        uint64_t prod[2 * RBN_LIMBS];
        rbn_mul(prod, key.p, key.q);
        memcpy(tmp, prod, sizeof(rbn_t));
        expect(rbn_cmp(tmp, key.n) == 0, "n == p×q");
    }

    /* 4. e·d ≡ 1 (mod φ(n))：用 e·d mod (p-1)(q-1) 验证
     * 简化：验证 e·d ≡ 1 mod (p-1) 且 mod (q-1) */
    {
        rbn_t p1, q1, ed;
        memcpy(p1, key.p, sizeof(rbn_t));
        memcpy(q1, key.q, sizeof(rbn_t));
        rbn_sub(p1, p1, (rbn_t){1, 0});
        rbn_sub(q1, q1, (rbn_t){1, 0});
        rbn_modmul(ed, key.e, key.d, p1);
        expect(rbn_is_one(ed), "e·d ≡ 1 (mod p-1)");
        rbn_modmul(ed, key.e, key.d, q1);
        expect(rbn_is_one(ed), "e·d ≡ 1 (mod q-1)");
    }

    /* 5. 加解密往返：多种明文长度（解密输出 128 字节大端，明文在尾部）
     * 注意教科书 RSA 要求 m < n：512 位密钥最大 63 字节明文 */
    int roundtrip_ok = 1;
    const size_t lens_512[] = {1, 2, 16, 32, 62};
    const size_t lens_1024[] = {1, 2, 16, 64, 100, 127};
    const size_t *lens = (bits == 512) ? lens_512 : lens_1024;
    size_t n_lens = (bits == 512) ? 5 : 6;
    for (size_t li = 0; li < n_lens; li++) {
        size_t len = lens[li];
        gen_plain(plain, len);
        if (rsa_encrypt(&key, plain, len, cipher) != 0 ||
            rsa_decrypt(&key, cipher, dec, &dlen) != 0 ||
            dlen != len ||
            memcmp(plain, dec + RSA_MAX_BLOCK - len, len) != 0) {
            printf("[FAIL] 往返 len=%zu\n", len);
            roundtrip_ok = 0;
        }
    }
    expect(roundtrip_ok, "加解密往返（6 种长度）");

    /* 6. 密文长度固定 128 字节 */
    gen_plain(plain, 32);
    rsa_encrypt(&key, plain, 32, cipher);
    expect(cipher[0] < 0x80 || cipher[0] != 0, "密文为 128 字节固定长");

    /* 7. 明文必须 < n：128 字节全 0xFF 可能 ≥ n，应拒绝 */
    memset(plain, 0xFF, sizeof(plain));
    expect(rsa_encrypt(&key, plain, 128, cipher) == -1 || 
           rsa_encrypt(&key, plain, 127, cipher) == 0,
           "m ≥ n 拒绝或 127 字节可加密");

    printf(fail_count ? "\n存在失败用例\n" : "\n全部测试通过\n");
    return fail_count ? 1 : 0;
}

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

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

static void print_rbn(const char *tag, const rbn_t a)
{
    char hex[257];
    rbn_to_hex(a, hex);
    printf("%s %s\n", tag, hex);
}

static int cmd_keygen(int bits)
{
    RSA_KEY key;
    if (rsa_keygen(&key, bits) != 0)
        return 1;
    print_rbn("n", key.n);
    print_rbn("e", key.e);
    print_rbn("d", key.d);
    print_rbn("p", key.p);
    print_rbn("q", key.q);
    print_rbn("dp", key.dp);
    print_rbn("dq", key.dq);
    print_rbn("qinv", key.qinv);
    return 0;
}

static int cmd_enc(int argc, char **argv)
{
    /* enc <n> <e> <明文hex> */
    RSA_KEY key;
    uint8_t plain[RSA_MAX_BLOCK];
    uint8_t cipher[128];
    int plen;

    (void)argc;
    if (rbn_from_hex(key.n, argv[2]) != 0 ||
        rbn_from_hex(key.e, argv[3]) != 0)
        return 1;
    plen = hex_to_bytes(argv[4], plain, sizeof(plain));
    if (plen <= 0)
        return 1;
    if (rsa_encrypt(&key, plain, (size_t)plen, cipher) != 0)
        return 1;
    print_hex(cipher, 128);
    printf("\n");
    return 0;
}

static int cmd_dec(int argc, char **argv)
{
    /* dec <n> <d> <p> <q> <dp> <dq> <qinv> <密文hex> */
    RSA_KEY key;
    uint8_t cipher[128];
    uint8_t plain[RSA_MAX_BLOCK];
    size_t dlen;
    int clen;

    (void)argc;
    if (rbn_from_hex(key.n, argv[2]) != 0 ||
        rbn_from_hex(key.d, argv[3]) != 0 ||
        rbn_from_hex(key.p, argv[4]) != 0 ||
        rbn_from_hex(key.q, argv[5]) != 0 ||
        rbn_from_hex(key.dp, argv[6]) != 0 ||
        rbn_from_hex(key.dq, argv[7]) != 0 ||
        rbn_from_hex(key.qinv, argv[8]) != 0)
        return 1;
    clen = hex_to_bytes(argv[9], cipher, sizeof(cipher));
    if (clen != 128)
        return 1;
    if (rsa_decrypt(&key, cipher, plain, &dlen) != 0)
        return 1;
    print_hex(plain + 128 - dlen, dlen);    /* 明文在 128 字节大端输出的尾部 */
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "selftest") == 0) {
        int bits = (argc > 2) ? atoi(argv[2]) : 1024;
        return selftest(bits);
    }
    if (argc > 1 && strcmp(argv[1], "keygen") == 0) {
        int bits = (argc > 2) ? atoi(argv[2]) : 1024;
        return cmd_keygen(bits);
    }
    if (argc > 1 && strcmp(argv[1], "enc") == 0)
        return cmd_enc(argc, argv);
    if (argc > 1 && strcmp(argv[1], "dec") == 0)
        return cmd_dec(argc, argv);
    printf("usage: %s selftest [bits] | keygen [bits] | enc <n> <e> <明文hex> | dec <n> <d> <p> <q> <dp> <dq> <qinv> <密文hex>\n",
           argv[0]);
    return 1;
}
